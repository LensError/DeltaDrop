pub mod dashboard;
pub mod theme;
pub mod topology;
pub mod views;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use deltadrop_common::UserRole;
use lumenic::{
    App, CsdAction, DialogHandle, TextEditState, TextureId, TrayConfig, TrayEvent, UiContext,
};

use crate::config::{resolve_safe_share_target, ClientConfig};
use crate::ignore_rules::detect_project_ignore_patterns;
use crate::sync::{RemoteSharePreview, SyncCommand, SyncHandle};
use theme::{dark_theme, Palette};

const LOGO_PNG: &[u8] = include_bytes!("../../assets/logo.png");

pub struct AssignModalState {
    pub share_id: String,
    pub share_name: String,
    pub file_count: usize,
    pub total_bytes: u64,
    pub target_path: TextEditState,
}

impl AssignModalState {
    pub fn from_preview(preview: &RemoteSharePreview) -> Self {
        Self {
            share_id: preview.share_id.clone(),
            share_name: preview.name.clone(),
            file_count: preview.file_count,
            total_bytes: preview.total_bytes,
            target_path: TextEditState::with_text(&preview.suggested_path.to_string_lossy()),
        }
    }
}

pub struct IgnoreEditorState {
    pub share_id: String,
    pub local_path: PathBuf,
    pub patterns: Vec<String>,
    pub new_pattern: TextEditState,
    pub test_path: TextEditState,
    pub last_tested_path: String,
    pub last_test_ignored: Option<bool>,
    pub test_cache_dirty: bool,
}

impl IgnoreEditorState {
    pub fn new(share_id: String, local_path: PathBuf, patterns: Vec<String>) -> Self {
        Self {
            share_id,
            local_path,
            patterns,
            new_pattern: TextEditState::new(),
            test_path: TextEditState::new(),
            last_tested_path: String::new(),
            last_test_ignored: None,
            test_cache_dirty: true,
        }
    }
}

pub struct UiState {
    pub start_minimized: bool,
    pub logo_tex: Option<TextureId>,
    pub active_tab: usize,
    pub relay_url: TextEditState,
    pub username: TextEditState,
    pub password: TextEditState,
    pub device_name: TextEditState,
    pub network_secret: TextEditState,
    pub default_sync_root: TextEditState,
    pub keep_unlocked: bool,
    pub auto_check_updates: bool,
    pub start_on_login: bool,
    pub topology: topology::TopologyState,
    pub assign_modal: Option<AssignModalState>,
    pub ignore_editor: Option<IgnoreEditorState>,
    pub confirm_delete_share: Option<String>,
    pub add_folder_picker: Option<DialogHandle>,
    pub assign_browse_picker: Option<DialogHandle>,
    pub default_root_picker: Option<DialogHandle>,
    pub new_user_name: TextEditState,
    pub new_user_pass: TextEditState,
    pub new_user_is_admin: bool,
    pub local_feedback: Option<String>,
    pub focus_requested: Arc<AtomicBool>,
}

impl UiState {
    pub fn from_config(
        cfg: &ClientConfig,
        start_minimized: bool,
        focus_requested: Arc<AtomicBool>,
    ) -> Self {
        let first_run = cfg.session_token.is_empty();
        Self {
            start_minimized: start_minimized && !first_run,
            logo_tex: None,
            active_tab: 0,
            relay_url: TextEditState::with_text(&cfg.relay_url),
            username: TextEditState::with_text(&cfg.username),
            password: TextEditState::new(),
            device_name: TextEditState::with_text(&cfg.device_name),
            network_secret: TextEditState::new(),
            default_sync_root: TextEditState::with_text(&cfg.default_sync_root.to_string_lossy()),
            keep_unlocked: cfg.keep_unlocked,
            auto_check_updates: cfg.auto_check_updates,
            start_on_login: crate::os_integration::is_autostart_enabled(),
            topology: topology::TopologyState::default(),
            assign_modal: None,
            ignore_editor: None,
            confirm_delete_share: None,
            add_folder_picker: None,
            assign_browse_picker: None,
            default_root_picker: None,
            new_user_name: TextEditState::new(),
            new_user_pass: TextEditState::new(),
            new_user_is_admin: false,
            local_feedback: None,
            focus_requested,
        }
    }
}

pub fn render_ui(ui: &mut UiContext, app: &mut App, sync: &SyncHandle, state: &mut UiState) {
    if state.logo_tex.is_none() {
        state.logo_tex = app.create_texture_png(LOGO_PNG).ok();
    }

    if !app.has_tray_icon() {
        app.set_tray_icon(
            TrayConfig::new()
                .tooltip("DeltaDrop")
                .icon_png(LOGO_PNG)
                .item("show", "Show DeltaDrop")
                .item("sync", "Sync Now")
                .item("pause", "Pause / Resume")
                .separator()
                .item("quit", "Quit"),
        );
    }

    for event in app.take_tray_events() {
        match event {
            TrayEvent::Click | TrayEvent::DoubleClick => {
                app.show_window();
                app.focus_window();
            }
            TrayEvent::Menu(id) => match id.as_str() {
                "show" => {
                    app.show_window();
                    app.focus_window();
                }
                "sync" => sync.send(SyncCommand::SyncNow(None)),
                "pause" => sync.send(SyncCommand::ToggleGlobalPause),
                "quit" => {
                    sync.send(SyncCommand::Shutdown);
                    app.remove_tray_icon();
                    app.request_exit();
                }
                _ => {}
            },
            TrayEvent::RightClick => {}
        }
    }

    if state.start_minimized {
        state.start_minimized = false;
        app.hide_window();
    }
    if state.focus_requested.swap(false, Ordering::SeqCst) {
        app.show_window();
        app.focus_window();
    }

    // Poll file dialogs
    if let Some(dlg) = state.add_folder_picker.take() {
        if let Some(res) = dlg.poll() {
            if let Some(path) = res {
                let pats = detect_project_ignore_patterns(&path);
                sync.send(SyncCommand::PublishLocalFolder {
                    local_path: path,
                    custom_name: None,
                    ignore_patterns: pats,
                });
            }
        } else {
            state.add_folder_picker = Some(dlg);
        }
    }

    if let Some(dlg) = state.assign_browse_picker.take() {
        if let Some(res) = dlg.poll() {
            if let Some(picked) = res {
                if let Some(ref mut modal) = state.assign_modal {
                    let safe_target = resolve_safe_share_target(&picked, &modal.share_name);
                    modal.target_path.set_text(&safe_target.to_string_lossy());
                }
            }
        } else {
            state.assign_browse_picker = Some(dlg);
        }
    }

    if let Some(dlg) = state.default_root_picker.take() {
        if let Some(res) = dlg.poll() {
            if let Some(picked) = res {
                state.default_sync_root.set_text(&picked.to_string_lossy());
            }
        } else {
            state.default_root_picker = Some(dlg);
        }
    }

    ui.set_theme(dark_theme());
    let p = Palette::default();
    let snap = sync.snapshot();

    ui.col(|ui| {
        // Custom CSD Header Bar
        let title = if snap.authenticated {
            format!("DeltaDrop - {} @ {}", snap.username, snap.device_name)
        } else {
            "DeltaDrop".to_string()
        };
        let csd = ui.csd_titlebar(&title);
        match csd {
            CsdAction::Minimize => app.minimize_window(),
            CsdAction::ToggleMaximize => app.toggle_maximize_window(),
            CsdAction::Close => app.hide_window(),
            CsdAction::StartDrag => app.drag_window(),
            CsdAction::None => {}
        }

        if !snap.authenticated {
            views::render_login_screen(ui, &snap, state, sync);
            return;
        }

        // Navigation + Global Actions Bar
        ui.row(|ui| {
            ui.row(|ui| {
                let is_admin = snap.user_role == Some(UserRole::Admin);
                let mut tabs: Vec<(usize, String)> = vec![
                    (
                        0,
                        if snap.unassigned_shares.is_empty() {
                            "Folders".to_string()
                        } else {
                            format!("Folders ({} new)", snap.unassigned_shares.len())
                        },
                    ),
                    (1, "Network".to_string()),
                    (
                        2,
                        if snap.conflicts.is_empty() {
                            "Conflicts".to_string()
                        } else {
                            format!("Conflicts ({})", snap.conflicts.len())
                        },
                    ),
                    (3, "Activity".to_string()),
                    (4, "Settings".to_string()),
                ];
                if is_admin {
                    tabs.push((5, "Users".to_string()));
                }

                for (idx, label) in tabs {
                    let active = state.active_tab == idx;
                    if ui
                        .btn(&label)
                        .sz(12.0)
                        .px(11.0)
                        .py(5.0)
                        .bg(if active { p.surface_alt } else { p.bg })
                        .bd(1.0, if active { p.accent } else { p.border })
                        .fg(if active { p.accent } else { p.muted })
                        .clicked()
                    {
                        state.active_tab = idx;
                        if idx == 1 {
                            sync.send(SyncCommand::RefreshDevices);
                        } else if idx == 5 {
                            sync.send(SyncCommand::AdminRefreshUsers);
                        }
                    }
                }
            })
            .gap(6.0);

            ui.row(|ui| {
                if ui
                    .btn(if snap.syncing_now {
                        "Syncing..."
                    } else {
                        "Sync Now"
                    })
                    .sz(12.0)
                    .px(12.0)
                    .py(5.0)
                    .bg(p.accent)
                    .fg(p.bg)
                    .clicked()
                {
                    sync.send(SyncCommand::SyncNow(None));
                }
                if ui
                    .btn(if snap.global_paused {
                        "Resume All"
                    } else {
                        "Pause All"
                    })
                    .sz(11.5)
                    .px(10.0)
                    .py(5.0)
                    .bg(p.surface_alt)
                    .bd(1.0, p.border)
                    .fg(p.text)
                    .clicked()
                {
                    sync.send(SyncCommand::ToggleGlobalPause);
                }
            })
            .gap(6.0);
        })
        .w_frac(1.0)
        .px(16.0)
        .py(8.0)
        .bg(p.surface)
        .bd(1.0, p.border)
        .justify_between()
        .align_center();

        // Notice / Error banner
        if let Some(ref err) = snap.last_error {
            ui.row(|ui| {
                ui.txt(err).sz(12.0).fg(p.err_red);
            })
            .w_frac(1.0)
            .px(16.0)
            .py(6.0)
            .bg(p.surface_alt);
        } else if let Some(ref msg) = state.local_feedback {
            ui.row(|ui| {
                ui.txt(msg).sz(12.0).fg(p.warn_amber);
            })
            .w_frac(1.0)
            .px(16.0)
            .py(6.0)
            .bg(p.surface_alt);
        }

        // Scrollable Main Content
        ui.scroll("main_scroll", |ui| {
            ui.col(|ui| match state.active_tab {
                0 => dashboard::render_folders_view(ui, app, &snap, state, sync),
                1 => views::render_devices_view(ui, &snap, state, sync),
                2 => views::render_conflicts_view(ui, &snap, sync),
                3 => views::render_activity_view(ui, &snap),
                4 => views::render_settings_view(ui, app, &snap, state, sync),
                5 => views::render_admin_users_view(ui, &snap, state, sync),
                _ => dashboard::render_folders_view(ui, app, &snap, state, sync),
            })
            .w_frac(1.0)
            .p(16.0)
            .gap(12.0);
        })
        .w_frac(1.0)
        .h_frac(1.0);
    })
    .w_frac(1.0)
    .h_frac(1.0)
    .bg(p.bg);
}
