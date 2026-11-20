#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod auth_client;
mod config;
mod ignore_rules;
mod manifest;
mod os_integration;
mod sync;
mod ui;
mod updater;

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use lumenic::sys::sandbox::StorageMode;
use lumenic::{LoopMode, SafeDir, WindowConfig};

use crate::config::load_or_create_config;
use crate::os_integration::SingleInstanceGuard;
use crate::sync::spawn_sync_engine;

fn parse_cli() -> (Option<PathBuf>, bool, bool, bool, bool) {
    let mut args = std::env::args().skip(1);
    let mut config_path: Option<PathBuf> = None;
    let mut headless = false;
    let mut minimized = false;
    let mut inspect = false;
    let mut restarted = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                if let Some(p) = args.next() {
                    config_path = Some(PathBuf::from(p));
                }
            }
            "--headless" => headless = true,
            "--minimized" => minimized = true,
            "--inspect" => inspect = true,
            "--restarted" => restarted = true,
            _ => {}
        }
    }
    (config_path, headless, minimized, inspect, restarted)
}

fn main() -> anyhow::Result<()> {
    updater::cleanup_old_windows_exe();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "deltadrop_client=info".into()),
        )
        .init();

    let (cli_config_path, headless, start_minimized, inspect_mode, restarted) = parse_cli();

    let safe_dir = SafeDir::from_mode(StorageMode::AppData {
        app_name: "deltadrop".to_string(),
    })
    .ok();
    let default_cfg_path = safe_dir
        .as_ref()
        .map(|sd| sd.root().join("deltadrop-config.json"))
        .unwrap_or_else(|| PathBuf::from("deltadrop-config.json"));
    let config_path = cli_config_path.unwrap_or(default_cfg_path);

    let cfg = load_or_create_config(&config_path)?;
    let manifest_db_path = cfg.manifest_db_path.clone().unwrap_or_else(|| {
        config_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("deltadrop-manifest.db")
    });

    let lock_dir = config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let mut instance_guard = if inspect_mode {
        None
    } else {
        let mut acquired = SingleInstanceGuard::acquire(lock_dir);
        if acquired.is_none() && restarted {
            for _ in 0..20 {
                std::thread::sleep(Duration::from_millis(150));
                acquired = SingleInstanceGuard::acquire(lock_dir);
                if acquired.is_some() {
                    break;
                }
            }
        }
        match acquired {
            Some(g) => Some(g),
            None => {
                tracing::info!("DeltaDrop is already running; focused existing window.");
                return Ok(());
            }
        }
    };

    if headless {
        let _handle = spawn_sync_engine(config_path, cfg, manifest_db_path, None);
        let stop = Arc::new(AtomicBool::new(false));
        while !stop.load(std::sync::atomic::Ordering::Relaxed) {
            std::thread::sleep(Duration::from_secs(60));
        }
        return Ok(());
    }

    let focus_flag = Arc::new(AtomicBool::new(false));
    let mut handle: Option<sync::SyncHandle> = None;
    let mut ui_state = ui::UiState::from_config(&cfg, start_minimized, focus_flag.clone());
    let win_cfg = WindowConfig::new("DeltaDrop")
        .size(920, 620)
        .min_size(720, 480)
        .icon_ico(include_bytes!("../assets/logo.ico"));

    lumenic::run(win_cfg, LoopMode::Idle, move |ctx, app| {
        if let Some(guard) = instance_guard.take() {
            guard.spawn_focus_listener(app.waker(), focus_flag.clone());
        }
        let sync_handle = handle.get_or_insert_with(|| {
            spawn_sync_engine(
                config_path.clone(),
                cfg.clone(),
                manifest_db_path.clone(),
                Some(app.waker()),
            )
        });
        ui::render_ui(ctx, app, sync_handle, &mut ui_state);
    })
    .map_err(|e| anyhow::anyhow!("Lumenic error: {e}"))?;

    Ok(())
}
