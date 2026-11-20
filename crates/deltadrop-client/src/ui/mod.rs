pub mod dashboard;
pub mod theme;
pub mod topology;
pub mod views;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use deltadrop_common::{parse_user_relay_input, UserRole};
use lumenic::{
    App, Color, CsdAction, CsdStyle, DialogHandle, TextEditState, TextureId, TrayConfig, TrayEvent,
    UiContext,
};

use crate::config::{validate_config, ClientConfig, IgnoreRule, SyncFolderConfig, SyncMode};
use crate::ignore_rules::detect_project_ignore_rules;
use crate::sync::{SyncCommand, SyncHandle, UiSnapshot};
use theme::{dark_theme, Palette};

const LOGO_PNG: &[u8] = include_bytes!("../../assets/logo.png");

pub struct FolderDraft {
    pub id: TextEditState,
    pub label: TextEditState,
    pub path: TextEditState,
    pub mode: SyncMode,
    pub whitelist_subdirs: Vec<String>,
    pub show_ignore: bool,
    pub ignore_rules: Vec<IgnoreRule>,
    pub custom_ignore: TextEditState,
    pub new_rule_input: TextEditState,
}

impl FolderDraft {
    pub fn empty(idx: usize) -> Self {
        Self {
            id: TextEditState::with_text(&format!("folder-{idx}")),
            label: TextEditState::new(),
            path: TextEditState::new(),
            mode: SyncMode::Full,
            whitelist_subdirs: Vec::new(),
            show_ignore: false,
            ignore_rules: Vec::new(),
            custom_ignore: TextEditState::new(),
            new_rule_input: TextEditState::new(),
        }
    }

    pub fn add_pattern(&mut self, pat: &str) {
        let trimmed = pat.trim();
        if trimmed.is_empty() {
            return;
        }
        if !self.ignore_rules.iter().any(|r| r.pattern == trimmed) {
            self.ignore_rules.push(IgnoreRule {
                pattern: trimmed.to_string(),
                enabled: true,
            });
        }
    }
}

pub struct UiState {
    pub start_minimized: bool,
    pub logo_tex: Option<TextureId>,
    pub active_tab: usize,
    pub peer_id: TextEditState,
    pub device_name: TextEditState,
    pub username: TextEditState,
    pub password: TextEditState,
    pub network_secret: TextEditState,
    pub keep_unlocked: bool,
    pub onboarding_step: usize,
    pub topology: topology::TopologyState,
    pub show_conflict_modal: bool,
    pub new_subuser_name: TextEditState,
    pub new_subuser_pass: TextEditState,
    pub target_peers: TextEditState,
    pub auto_discover_peers: bool,
    pub relay_url: TextEditState,
    pub auth_token: TextEditState,
    pub workspace_id: String,
    pub encryption_key: TextEditState,
    pub poll_interval: TextEditState,
    pub manifest_db_path: Option<PathBuf>,
    pub folders: Vec<FolderDraft>,
    pub folder_picker: Option<(usize, DialogHandle)>,
    pub map_remote_picker: Option<(String, DialogHandle)>,
    pub save_feedback: Option<String>,
    pub dirty: bool,
    pub start_on_login: bool,
    pub focus_requested: Arc<AtomicBool>,
}

impl UiState {
    pub fn from_config(
        cfg: &ClientConfig,
        start_minimized: bool,
        focus_requested: Arc<AtomicBool>,
    ) -> Self {
        let folders = cfg
            .folders
            .iter()
            .map(|f| FolderDraft {
                id: TextEditState::with_text(&f.id),
                label: TextEditState::with_text(f.label.as_deref().unwrap_or("")),
                path: TextEditState::with_text(&f.path.to_string_lossy()),
                mode: f.mode,
                whitelist_subdirs: f.whitelist_subdirs.clone(),
                show_ignore: false,
                ignore_rules: f.ignore_rules.clone(),
                custom_ignore: TextEditState::with_text(&f.custom_ignore),
                new_rule_input: TextEditState::new(),
            })
            .collect();

        let first_run = cfg.session_token.is_empty() && cfg.auth_token.is_empty();

        Self {
            start_minimized: start_minimized && !first_run,
            logo_tex: None,
            active_tab: 0,
            peer_id: TextEditState::with_text(&cfg.peer_id),
            device_name: TextEditState::with_text(if cfg.device_name.is_empty() {
                &cfg.peer_id
            } else {
                &cfg.device_name
            }),
            username: TextEditState::with_text(&cfg.username),
            password: TextEditState::new(),
            network_secret: TextEditState::with_text(cfg.network_secret.as_deref().unwrap_or("")),
            keep_unlocked: cfg.keep_unlocked,
            onboarding_step: 0,
            topology: topology::TopologyState::default(),
            show_conflict_modal: false,
            new_subuser_name: TextEditState::new(),
            new_subuser_pass: TextEditState::new(),
            target_peers: TextEditState::with_text(&cfg.target_peers.join(", ")),
            auto_discover_peers: cfg.auto_discover_peers,
            relay_url: TextEditState::with_text(&cfg.relay_url),
            auth_token: TextEditState::with_text(&cfg.auth_token),
            workspace_id: cfg.workspace_id.clone(),
            encryption_key: TextEditState::with_text(cfg.encryption_key.as_deref().unwrap_or("")),
            poll_interval: TextEditState::with_text(&cfg.poll_interval_secs.to_string()),
            manifest_db_path: cfg.manifest_db_path.clone(),
            folders,
            folder_picker: None,
            map_remote_picker: None,
            save_feedback: None,
            dirty: false,
            start_on_login: crate::os_integration::is_autostart_enabled(),
            focus_requested,
        }
    }

    pub fn to_client_config(&self) -> Result<ClientConfig, String> {
        let peer_id = self.peer_id.text().trim().to_string();
        let target_peers: Vec<String> = self
            .target_peers
            .text()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let relay_url = self
            .relay_url
            .text()
            .trim()
            .trim_end_matches('/')
            .to_string();
        let poll_interval_secs = self
            .poll_interval
            .text()
            .trim()
            .parse::<u64>()
            .unwrap_or(5)
            .max(1);

        let mut folders = Vec::new();
        for f in &self.folders {
            let id = f.id.text().trim().to_string();
            let path_str = f.path.text().trim().to_string();
            let lbl = f.label.text().trim().to_string();
            folders.push(SyncFolderConfig {
                id,
                label: if lbl.is_empty() { None } else { Some(lbl) },
                path: PathBuf::from(path_str),
                mode: f.mode,
                whitelist_subdirs: f.whitelist_subdirs.clone(),
                ignore_rules: f.ignore_rules.clone(),
                custom_ignore: f.custom_ignore.text(),
            });
        }

        let enc_raw = self.encryption_key.text().trim().to_string();
        let cfg = ClientConfig {
            peer_id,
            device_name: self.device_name.text().trim().to_string(),
            username: self.username.text().trim().to_string(),
            keep_unlocked: self.keep_unlocked,
            network_secret: {
                let s = self.network_secret.text().trim().to_string();
                if s.is_empty() {
                    None
                } else {
                    Some(s)
                }
            },
            target_peers,
            auto_discover_peers: self.auto_discover_peers,
            relay_url,
            auth_token: self.auth_token.text().trim().to_string(),
            workspace_id: self.workspace_id.clone(),
            encryption_key: if enc_raw.is_empty() {
                None
            } else {
                Some(enc_raw)
            },
            poll_interval_secs,
            manifest_db_path: self.manifest_db_path.clone(),
            folders,
            ..ClientConfig::default()
        };
        validate_config(&cfg)?;
        Ok(cfg)
    }

    fn sync_folder_toggles_from_snapshot(&mut self, cfg: &ClientConfig) {
        if self.dirty {
            return;
        }
        if let Some(ref k) = cfg.encryption_key {
            if self.encryption_key.text().trim() != k.trim() {
                self.encryption_key.set_text(k);
            }
        }
        for active_f in &cfg.folders {
            if let Some(draft) = self
                .folders
                .iter_mut()
                .find(|d| d.id.text().trim() == active_f.id)
            {
                draft.mode = active_f.mode;
                draft.whitelist_subdirs = active_f.whitelist_subdirs.clone();
            }
        }
    }
}

pub fn render_ui(ui: &mut UiContext, app: &mut App, handle: &SyncHandle, state: &mut UiState) {
    if state.logo_tex.is_none() {
        state.logo_tex = app.create_texture_png(LOGO_PNG).ok();
    }

    if !app.has_tray_icon() {
        app.set_tray_icon(
            TrayConfig::new()
                .tooltip("DeltaDrop")
                .icon_png(LOGO_PNG)
                .item("show", "Show DeltaDrop")
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
                "pause" => {
                    let _ = handle.cmd_tx.send(SyncCommand::TogglePause);
                }
                "quit" => {
                    app.remove_tray_icon();
                    app.request_exit();
                }
                _ => {}
            },
            TrayEvent::RightClick => {}
        }
    }

    if let Some((idx, dlg)) = state.folder_picker.take() {
        if let Some(result) = dlg.poll() {
            if let Some(path) = result {
                let path_str = path.to_string_lossy().to_string();
                let detected_rules = detect_project_ignore_rules(&path);
                let base_name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("folder")
                    .to_lowercase()
                    .replace(' ', "-");
                if idx < state.folders.len() {
                    let f = &mut state.folders[idx];
                    f.path.set_text(&path_str);
                    if f.id.text().starts_with("folder-") {
                        f.id.set_text(&base_name);
                    }
                    if f.label.is_empty() {
                        if let Some(n) = path.file_name().and_then(|n| n.to_str()) {
                            f.label.set_text(n);
                        }
                    }
                    for rule in detected_rules {
                        f.add_pattern(&rule.pattern);
                    }
                }
                state.dirty = true;
            }
        } else {
            state.folder_picker = Some((idx, dlg));
        }
    }

    if let Some((folder_id, dlg)) = state.map_remote_picker.take() {
        if let Some(result) = dlg.poll() {
            if let Some(path) = result {
                let path_str = path.to_string_lossy().to_string();
                state.folders.push(FolderDraft {
                    id: TextEditState::with_text(&folder_id),
                    label: TextEditState::with_text(&folder_id),
                    path: TextEditState::with_text(&path_str),
                    mode: SyncMode::Full,
                    whitelist_subdirs: Vec::new(),
                    show_ignore: false,
                    ignore_rules: Vec::new(),
                    custom_ignore: TextEditState::new(),
                    new_rule_input: TextEditState::new(),
                });
                let _ = handle.cmd_tx.send(SyncCommand::MapRemoteFolder {
                    folder_id,
                    path,
                    mode: SyncMode::Full,
                });
            }
        } else {
            state.map_remote_picker = Some((folder_id, dlg));
        }
    }

    if state.focus_requested.swap(false, Ordering::SeqCst) {
        app.show_window();
        app.focus_window();
    }

    if state.start_minimized {
        state.start_minimized = false;
        app.hide_window();
    }

    ui.set_theme(dark_theme());
    let snap: UiSnapshot = handle
        .snapshot
        .lock()
        .map(|g| g.clone())
        .unwrap_or_default();
    if let Some(ref active_cfg) = snap.active_config {
        state.sync_folder_toggles_from_snapshot(active_cfg);
    }

    let pal = Palette::default();

    ui.col(|ui| {
        let mut csd_style = CsdStyle::ghost();
        csd_style.bg = Some(pal.bg);
        csd_style.border = Some((1.0, pal.border));
        csd_style.padding = (16.0, 0.0);
        csd_style.gap = 6.0;
        csd_style.control_size = (40.0, 38.0);
        csd_style.control_radius = 0.0;
        csd_style.control_hover_bg = Some(pal.surface_alt);
        csd_style.close_hover_bg = Some(Color::from_hex(0xC42B1C));

        let user_handle = if !snap.username.is_empty() {
            let host = state
                .relay_url
                .text()
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .to_string();
            format!("{}@{}", snap.username, host)
        } else {
            "not signed in".to_string()
        };

        let csd_action = ui.csd_titlebar_styled("", 38.0, csd_style, |ui| {
            ui.row(|ui| {
                ui.txt("DELTADROP")
                    .sz(12.5)
                    .bold()
                    .tracking(0.08)
                    .fg(pal.text);
                ui.col(|_| {}).w(7.0).h(7.0).r(3.5).bg(if snap.online {
                    pal.ok_green
                } else {
                    pal.offline_slate
                });
                ui.txt(&user_handle).sz(11.5).mono().fg(pal.muted);
            })
            .gap(10.0)
            .align_center();
        });

        match csd_action {
            CsdAction::Close => {
                if app.has_tray_icon() {
                    app.hide_window();
                } else {
                    app.request_exit();
                }
            }
            other => app.perform_csd(other),
        }

        let is_authenticated = snap.user_role.is_some()
            || snap
                .active_config
                .as_ref()
                .is_some_and(|c| !c.session_token.is_empty());

        if !is_authenticated {
            state.onboarding_step = 0;
            render_onboarding_overlay(ui, &snap, state, handle, pal);
        } else {
            // Minimalist flat text navigation tabs with 2px bottom accent indicator
            let is_admin = snap.user_role == Some(UserRole::Admin);
            let mut nav_items: Vec<(usize, &str)> = vec![
                (0, "Overview"),
                (1, "Folders"),
                (2, "Devices"),
                (3, "Settings"),
            ];
            if is_admin {
                nav_items.push((4, "Users"));
            }

            ui.row(|ui| {
                ui.row(|ui| {
                    for (tab_id, label) in &nav_items {
                        let active = state.active_tab == *tab_id;
                        if ui
                            .btn(label)
                            .no_bg()
                            .borderless()
                            .px(10.0)
                            .py(8.0)
                            .sz(12.5)
                            .fg(if active { pal.text } else { pal.muted })
                            .bd_bottom(
                                2.0,
                                if active {
                                    pal.accent
                                } else {
                                    Color::TRANSPARENT
                                },
                            )
                            .clicked()
                        {
                            state.active_tab = *tab_id;
                            if *tab_id == 2 {
                                let _ = handle.cmd_tx.send(SyncCommand::RefreshDevices);
                            } else if *tab_id == 4 {
                                let _ = handle.cmd_tx.send(SyncCommand::AdminRefreshUsers);
                            }
                        }
                    }
                })
                .gap(8.0)
                .align_center();

                ui.row(|ui| {
                    let pause_label = if snap.paused { "Resume" } else { "Pause" };
                    if ui
                        .btn(pause_label)
                        .no_bg()
                        .borderless()
                        .px(8.0)
                        .py(6.0)
                        .sz(11.5)
                        .fg(pal.muted)
                        .clicked()
                    {
                        let _ = handle.cmd_tx.send(SyncCommand::TogglePause);
                    }
                    if ui
                        .btn("Rescan")
                        .no_bg()
                        .borderless()
                        .px(8.0)
                        .py(6.0)
                        .sz(11.5)
                        .fg(pal.muted)
                        .clicked()
                    {
                        let _ = handle.cmd_tx.send(SyncCommand::ForceScan);
                    }
                })
                .gap(6.0)
                .align_center();
            })
            .w_frac(1.0)
            .px(16.0)
            .bg(pal.bg)
            .bd_bottom(1.0, pal.border)
            .justify_between()
            .align_center();

            ui.scroll("main-view-scroll", |ui| match state.active_tab {
                1 => views::render_folders_view(ui, app, &snap, state, handle),
                2 => views::render_devices_view(ui, &snap, state, handle),
                3 => views::render_settings_view(ui, &snap, state, handle),
                4 if is_admin => views::render_users_view(ui, &snap, state, handle),
                _ => dashboard::render_overview(ui, app, &snap, state, handle),
            })
            .grow(1.0);
        }
    })
    .bg(pal.bg)
    .grow(1.0);
}

fn render_onboarding_overlay(
    ui: &mut UiContext,
    snap: &UiSnapshot,
    state: &mut UiState,
    handle: &SyncHandle,
    pal: Palette,
) {
    ui.col(|ui| {
        ui.col(|ui| {
            ui.txt(&format!("STEP {} OF 3", state.onboarding_step + 1))
                .sz(10.5)
                .tracking(0.08)
                .fg(pal.accent);

            if state.onboarding_step == 0 {
                ui.txt("Sign in to your DeltaDrop Relay")
                    .sz(18.0)
                    .bold()
                    .fg(pal.text);

                ui.txt("RELAY ADDRESS")
                    .sz(10.5)
                    .tracking(0.08)
                    .fg(pal.muted);
                ui.input("ob-relay", &mut state.relay_url)
                    .placeholder("https://sync.example.com")
                    .w(380.0)
                    .px(10.0)
                    .py(8.0)
                    .bg(pal.surface)
                    .bd(1.0, pal.border);

                ui.txt("USERNAME (OR user@relay)")
                    .sz(10.5)
                    .tracking(0.08)
                    .fg(pal.muted);
                if ui
                    .input("ob-user", &mut state.username)
                    .placeholder("pauli@sync.example.com")
                    .w(380.0)
                    .px(10.0)
                    .py(8.0)
                    .bg(pal.surface)
                    .bd(1.0, pal.border)
                    .changed()
                {
                    if let Some((u, r)) = parse_user_relay_input(&state.username.text()) {
                        state.username.set_text(&u);
                        state.relay_url.set_text(&r);
                    }
                }

                ui.txt("PASSWORD").sz(10.5).tracking(0.08).fg(pal.muted);
                ui.input("ob-pass", &mut state.password)
                    .placeholder("••••••••••••")
                    .w(380.0)
                    .px(10.0)
                    .py(8.0)
                    .bg(pal.surface)
                    .bd(1.0, pal.border);

                ui.txt("DEVICE NAME").sz(10.5).tracking(0.08).fg(pal.muted);
                ui.input("ob-device", &mut state.device_name)
                    .placeholder("my-workstation")
                    .w(380.0)
                    .px(10.0)
                    .py(8.0)
                    .bg(pal.surface)
                    .bd(1.0, pal.border);

                ui.txt("NETWORK GATE (X-DeltaDrop-Gate, OPTIONAL)")
                    .sz(10.5)
                    .tracking(0.08)
                    .fg(pal.muted);
                ui.input("ob-gate", &mut state.network_secret)
                    .placeholder("leave blank if disabled on relay")
                    .w(380.0)
                    .px(10.0)
                    .py(8.0)
                    .bg(pal.surface)
                    .bd(1.0, pal.border);

                if let Some(ref err) = snap.last_error {
                    ui.txt(err).sz(12.0).fg(pal.err_red);
                }

                ui.row(|ui| {
                    if ui
                        .btn("Sign In")
                        .bg(pal.accent)
                        .fg(pal.bg)
                        .sz(12.5)
                        .px(18.0)
                        .py(8.0)
                        .clicked()
                    {
                        let _ = handle.cmd_tx.send(SyncCommand::Login {
                            relay_url: state.relay_url.text(),
                            username: state.username.text(),
                            password: state.password.text(),
                            device_name: state.device_name.text(),
                            network_secret: {
                                let s = state.network_secret.text();
                                if s.trim().is_empty() {
                                    None
                                } else {
                                    Some(s)
                                }
                            },
                            keep_unlocked: state.keep_unlocked,
                        });
                    }
                })
                .py(6.0);
            } else {
                ui.txt("Choose your first action")
                    .sz(18.0)
                    .bold()
                    .fg(pal.text);
                ui.row(|ui| {
                    if ui
                        .btn("Share a Local Folder")
                        .w(185.0)
                        .py(18.0)
                        .bg(pal.surface)
                        .bd(1.0, pal.border)
                        .fg(pal.text)
                        .clicked()
                    {
                        state.active_tab = 1;
                        state.onboarding_step = 2;
                    }
                    if ui
                        .btn("Pull from Another PC")
                        .w(185.0)
                        .py(18.0)
                        .bg(pal.surface)
                        .bd(1.0, pal.border)
                        .fg(pal.ok_green)
                        .clicked()
                    {
                        state.active_tab = 0;
                        state.onboarding_step = 2;
                    }
                })
                .gap(12.0);
            }
        })
        .w(420.0)
        .gap(10.0);
    })
    .w_frac(1.0)
    .grow(1.0)
    .center();
}
