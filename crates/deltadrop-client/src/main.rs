#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod config;
mod crypto;
mod ignore_rules;
mod manifest;
mod os_integration;
mod relay_client;
mod sync;
mod ui;
mod updater;

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use lumenic::sys::sandbox::StorageMode;
use lumenic::{inspect_to_files, InspectOptions, LoopMode, SafeDir, WindowConfig};

use crate::config::load_or_create_config;
use crate::os_integration::SingleInstanceGuard;
use crate::sync::spawn_sync_engine;

struct CliArgs {
    config_path: Option<PathBuf>,
    headless: bool,
    minimized: bool,
    restarted: bool,
    inspect: bool,
    out_png: PathBuf,
    out_json: PathBuf,
}

fn parse_cli() -> CliArgs {
    let mut args = std::env::args().skip(1);
    let mut cli = CliArgs {
        config_path: None,
        headless: false,
        minimized: false,
        restarted: false,
        inspect: false,
        out_png: PathBuf::from("inspect.png"),
        out_json: PathBuf::from("layout.json"),
    };

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                if let Some(p) = args.next() {
                    cli.config_path = Some(PathBuf::from(p));
                }
            }
            "--headless" => cli.headless = true,
            "--minimized" => cli.minimized = true,
            "--restarted" => cli.restarted = true,
            "--inspect" => cli.inspect = true,
            "--out-png" => {
                if let Some(p) = args.next() {
                    cli.out_png = PathBuf::from(p);
                }
            }
            "--out-json" => {
                if let Some(p) = args.next() {
                    cli.out_json = PathBuf::from(p);
                }
            }
            _ => {}
        }
    }
    cli
}

fn main() -> anyhow::Result<()> {
    updater::cleanup_old_windows_exe();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "deltadrop_client=info".into()),
        )
        .init();

    let cli = parse_cli();

    let safe_dir = SafeDir::from_mode(StorageMode::AppData {
        app_name: "deltadrop".to_string(),
    })
    .ok();
    let default_cfg_path = safe_dir
        .as_ref()
        .map(|sd| sd.root().join("deltadrop-config.json"))
        .unwrap_or_else(|| PathBuf::from("deltadrop-config.json"));
    let config_path = cli.config_path.unwrap_or(default_cfg_path);

    let cfg = load_or_create_config(&config_path)?;

    if cli.inspect {
        let focus_flag = Arc::new(AtomicBool::new(false));
        let handle = spawn_sync_engine(cfg.clone(), config_path);
        let mut ui_state = ui::UiState::from_config(&cfg, false, focus_flag);
        let opts = InspectOptions {
            width: 1000,
            height: 680,
            scale_factor: 1.0,
            out_png: cli.out_png,
            out_json: cli.out_json,
        };
        inspect_to_files(&opts, |ctx, app| {
            ui::render_ui(ctx, app, &handle, &mut ui_state);
        })
        .map_err(|e| anyhow::anyhow!("Inspect failed: {e}"))?;
        handle.send(sync::SyncCommand::Shutdown);
        return Ok(());
    }

    let lock_dir = config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let mut acquired = SingleInstanceGuard::acquire(lock_dir);
    if acquired.is_none() && cli.restarted {
        for _ in 0..20 {
            std::thread::sleep(Duration::from_millis(150));
            acquired = SingleInstanceGuard::acquire(lock_dir);
            if acquired.is_some() {
                break;
            }
        }
    }
    let mut instance_guard = match acquired {
        Some(g) => Some(g),
        None => {
            tracing::info!("DeltaDrop is already running; focused existing window.");
            return Ok(());
        }
    };

    if cli.headless {
        let _handle = spawn_sync_engine(cfg, config_path);
        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
    }

    let focus_flag = Arc::new(AtomicBool::new(false));
    let sync_handle = spawn_sync_engine(cfg.clone(), config_path);
    let mut waker_attached = false;
    let mut ui_state = ui::UiState::from_config(&cfg, cli.minimized, focus_flag.clone());
    let win_cfg = WindowConfig::new("DeltaDrop")
        .size(980, 660)
        .min_size(780, 520)
        .icon_ico(include_bytes!("../assets/logo.ico"));

    lumenic::run(win_cfg, LoopMode::Idle, move |ctx, app| {
        if let Some(guard) = instance_guard.take() {
            guard.spawn_focus_listener(app.waker(), focus_flag.clone());
        }
        if !waker_attached {
            sync_handle.attach_waker(app.waker());
            waker_attached = true;
        }
        ui::render_ui(ctx, app, &sync_handle, &mut ui_state);
    })
    .map_err(|e| anyhow::anyhow!("Lumenic error: {e}"))?;

    Ok(())
}
