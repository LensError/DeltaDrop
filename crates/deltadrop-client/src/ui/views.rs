use std::path::PathBuf;

use deltadrop_common::UserRole;
use lumenic::{App, UiContext};

use crate::sync::{SyncCommand, SyncHandle, UiSnapshot};
use crate::ui::theme::{is_insecure_http_url, Palette};
use crate::ui::topology::render_topology_canvas;
use crate::ui::UiState;
use crate::updater::{self, UpdateStatus};

pub fn render_login_screen(
    ui: &mut UiContext,
    snap: &UiSnapshot,
    state: &mut UiState,
    sync: &SyncHandle,
) {
    let p = Palette::default();

    ui.col(|ui| {
        ui.col(|ui| {
            ui.txt("Sign in to DeltaDrop")
                .sz(18.0)
                .bold()
                .fg(p.text);
            ui.txt("End-to-end encrypted two-way folder sync across your PCs via your relay.")
                .sz(12.0)
                .fg(p.muted);

            field_label(ui, "Relay URL", &p);
            ui.input("login_relay_url", &mut state.relay_url)
                .w_frac(1.0)
                .bg(p.bg)
                .bd(1.0, p.border)
                .px(10.0)
                .py(7.0);

            if is_insecure_http_url(&state.relay_url.text()) {
                ui.txt("Warning: plain HTTP over a public host exposes login traffic. Use HTTPS or Tailscale.")
                    .sz(11.0)
                    .fg(p.warn_amber);
            }

            field_label(ui, "Username", &p);
            ui.input("login_username", &mut state.username)
                .w_frac(1.0)
                .bg(p.bg)
                .bd(1.0, p.border)
                .px(10.0)
                .py(7.0);

            field_label(ui, "Password", &p);
            ui.password_input("login_password", &mut state.password)
                .w_frac(1.0)
                .bg(p.bg)
                .bd(1.0, p.border)
                .px(10.0)
                .py(7.0);

            field_label(ui, "This PC Name", &p);
            ui.input("login_device_name", &mut state.device_name)
                .w_frac(1.0)
                .bg(p.bg)
                .bd(1.0, p.border)
                .px(10.0)
                .py(7.0);

            field_label(ui, "Network Gate Secret (optional)", &p);
            ui.password_input("login_gate_secret", &mut state.network_secret)
                .w_frac(1.0)
                .bg(p.bg)
                .bd(1.0, p.border)
                .px(10.0)
                .py(7.0);

            ui.row(|ui| {
                ui.checkbox("Keep signed in on this PC", &mut state.keep_unlocked);
            });

            if let Some(ref err) = snap.last_error {
                ui.txt(err).sz(12.0).fg(p.err_red);
            } else if let Some(ref notice) = snap.last_notice {
                ui.txt(notice).sz(12.0).fg(p.ok_green);
            }

            if ui
                .btn("Sign In")
                .w_frac(1.0)
                .sz(13.0)
                .py(9.0)
                .bg(p.accent)
                .fg(p.bg)
                .clicked()
            {
                let secret = state.network_secret.text().trim().to_string();
                sync.send(SyncCommand::Login {
                    relay_url: state.relay_url.text().to_string(),
                    username: state.username.text().to_string(),
                    password: state.password.text().to_string(),
                    device_name: state.device_name.text().to_string(),
                    keep_unlocked: state.keep_unlocked,
                    network_secret: if secret.is_empty() { None } else { Some(secret) },
                });
                state.password.set_text("");
            }
        })
        .w(460.0)
        .p(24.0)
        .gap(10.0)
        .bg(p.surface)
        .bd(1.0, p.border)
        .r(8.0);
    })
    .w_frac(1.0)
    .h_frac(1.0)
    .align_center()
    .justify_center();
}

pub fn render_devices_view(
    ui: &mut UiContext,
    snap: &UiSnapshot,
    state: &mut UiState,
    sync: &SyncHandle,
) {
    let p = Palette::default();

    ui.row(|ui| {
        ui.txt(&format!("Network & Devices ({})", snap.devices.len()))
            .sz(14.0)
            .bold()
            .fg(p.text);
        if ui
            .btn("Refresh")
            .sz(11.5)
            .px(10.0)
            .py(5.0)
            .bg(p.surface_alt)
            .bd(1.0, p.border)
            .fg(p.text)
            .clicked()
        {
            sync.send(SyncCommand::RefreshDevices);
        }
    })
    .w_frac(1.0)
    .justify_between()
    .align_center();

    render_topology_canvas(ui, snap, &mut state.topology);

    for dev in &snap.devices {
        ui.row(|ui| {
            ui.col(|ui| {
                ui.row(|ui| {
                    ui.txt(&dev.name).sz(13.0).bold().fg(p.text);
                    if dev.is_self {
                        ui.txt("This PC")
                            .sz(10.5)
                            .fg(p.bg)
                            .bg(p.ok_green)
                            .px(6.0)
                            .py(2.0)
                            .r(3.0);
                    }
                    ui.txt(if dev.online { "Online" } else { "Offline" })
                        .sz(11.5)
                        .fg(if dev.online { p.ok_green } else { p.muted });
                })
                .gap(8.0)
                .align_center();

                ui.txt(&format!("ID: {}  -  OS: {}", dev.device_id, dev.os))
                    .sz(11.5)
                    .fg(p.muted);
            })
            .gap(2.0);

            if !dev.is_self {
                ui.row(|ui| {
                    if ui
                        .btn("Replace With This PC")
                        .sz(11.0)
                        .px(9.0)
                        .py(4.0)
                        .bg(p.surface_alt)
                        .bd(1.0, p.border)
                        .fg(p.text)
                        .clicked()
                    {
                        sync.send(SyncCommand::ReplaceDevice {
                            old_device_id: dev.device_id.clone(),
                        });
                    }
                    if ui
                        .btn("Remove")
                        .sz(11.0)
                        .px(9.0)
                        .py(4.0)
                        .bg(p.surface_alt)
                        .bd(1.0, p.err_red)
                        .fg(p.err_red)
                        .clicked()
                    {
                        sync.send(SyncCommand::DeleteDevice(dev.device_id.clone()));
                    }
                })
                .gap(6.0);
            }
        })
        .w_frac(1.0)
        .p(12.0)
        .bg(p.surface)
        .bd(1.0, p.border)
        .r(6.0)
        .justify_between()
        .align_center();
    }
}

pub fn render_conflicts_view(ui: &mut UiContext, snap: &UiSnapshot, sync: &SyncHandle) {
    let p = Palette::default();

    ui.txt(&format!("Sync Conflicts ({})", snap.conflicts.len()))
        .sz(14.0)
        .bold()
        .fg(p.text);

    if snap.conflicts.is_empty() {
        ui.col(|ui| {
            ui.txt("No unresolved conflicts.").sz(13.0).fg(p.ok_green);
            ui.txt("When two PCs edit the same file offline, DeltaDrop backs up your local copy as *.sync-conflict-* so nothing is ever lost.")
                .sz(12.0)
                .fg(p.muted);
        })
        .w_frac(1.0)
        .p(16.0)
        .gap(4.0)
        .bg(p.surface)
        .bd(1.0, p.border)
        .r(6.0);
        return;
    }

    for row in &snap.conflicts {
        ui.col(|ui| {
            ui.row(|ui| {
                ui.txt(&format!("{} / {}", row.share_name, row.rel_path))
                    .sz(13.0)
                    .bold()
                    .fg(p.warn_amber);
                ui.txt(&row.time_label).sz(11.0).fg(p.muted);
            })
            .w_frac(1.0)
            .justify_between();

            ui.txt(&format!("Backup copy: {}", row.conflict_path))
                .sz(11.5)
                .fg(p.muted);

            ui.row(|ui| {
                if ui
                    .btn("Keep Remote (Delete Backup)")
                    .sz(11.5)
                    .px(10.0)
                    .py(5.0)
                    .bg(p.surface_alt)
                    .bd(1.0, p.ok_green)
                    .fg(p.ok_green)
                    .clicked()
                {
                    sync.send(SyncCommand::ResolveConflict {
                        conflict_id: row.id,
                        keep_local_conflict: false,
                    });
                }
                if ui
                    .btn("Use Local Backup (Overwrite Main)")
                    .sz(11.5)
                    .px(10.0)
                    .py(5.0)
                    .bg(p.surface_alt)
                    .bd(1.0, p.accent)
                    .fg(p.accent)
                    .clicked()
                {
                    sync.send(SyncCommand::ResolveConflict {
                        conflict_id: row.id,
                        keep_local_conflict: true,
                    });
                }
                if ui
                    .btn("Dismiss")
                    .sz(11.5)
                    .px(10.0)
                    .py(5.0)
                    .bg(p.surface_alt)
                    .bd(1.0, p.border)
                    .fg(p.muted)
                    .clicked()
                {
                    sync.send(SyncCommand::DismissConflict(row.id));
                }
            })
            .gap(8.0);
        })
        .w_frac(1.0)
        .p(12.0)
        .gap(8.0)
        .bg(p.surface)
        .bd(1.0, p.warn_amber)
        .r(6.0);
    }
}

pub fn render_activity_view(ui: &mut UiContext, snap: &UiSnapshot) {
    let p = Palette::default();
    ui.txt("Recent Activity").sz(14.0).bold().fg(p.text);

    if snap.activity.is_empty() {
        ui.txt("No activity yet.").sz(12.0).fg(p.muted);
        return;
    }

    ui.col(|ui| {
        for entry in &snap.activity {
            ui.row(|ui| {
                ui.txt(&entry.time_label).sz(11.0).fg(p.muted).w(82.0);
                ui.txt(&entry.message)
                    .sz(12.0)
                    .fg(if entry.is_error { p.err_red } else { p.text });
            })
            .w_frac(1.0)
            .gap(10.0)
            .py(3.0);
        }
    })
    .w_frac(1.0)
    .p(12.0)
    .gap(2.0)
    .bg(p.surface)
    .bd(1.0, p.border)
    .r(6.0);
}

pub fn render_settings_view(
    ui: &mut UiContext,
    app: &mut App,
    snap: &UiSnapshot,
    state: &mut UiState,
    sync: &SyncHandle,
) {
    let p = Palette::default();

    ui.txt("Settings").sz(14.0).bold().fg(p.text);

    ui.col(|ui| {
        field_label(ui, "Relay URL", &p);
        ui.input("settings_relay_url", &mut state.relay_url)
            .w_frac(1.0)
            .bg(p.bg)
            .bd(1.0, p.border)
            .px(10.0)
            .py(6.0);

        field_label(ui, "This PC Name", &p);
        ui.input("settings_device_name", &mut state.device_name)
            .w_frac(1.0)
            .bg(p.bg)
            .bd(1.0, p.border)
            .px(10.0)
            .py(6.0);

        field_label(ui, "Default Sync Parent Folder", &p);
        ui.row(|ui| {
            ui.input("settings_default_root", &mut state.default_sync_root)
                .w_frac(1.0)
                .bg(p.bg)
                .bd(1.0, p.border)
                .px(10.0)
                .py(6.0);
            if ui
                .btn("Browse...")
                .sz(12.0)
                .px(12.0)
                .py(6.0)
                .bg(p.surface_alt)
                .bd(1.0, p.border)
                .fg(p.text)
                .clicked()
            {
                state.default_root_picker =
                    Some(app.pick_folder("Choose default parent folder for synced shares"));
            }
        })
        .w_frac(1.0)
        .gap(8.0);

        field_label(ui, "Network Gate Secret (leave blank to keep unchanged)", &p);
        ui.password_input("settings_gate_secret", &mut state.network_secret)
            .w_frac(1.0)
            .bg(p.bg)
            .bd(1.0, p.border)
            .px(10.0)
            .py(6.0);

        ui.checkbox("Keep signed in across restarts", &mut state.keep_unlocked);
        ui.checkbox("Automatically check for updates", &mut state.auto_check_updates);

        let prev_autostart = state.start_on_login;
        ui.checkbox("Start DeltaDrop on login (minimized)", &mut state.start_on_login);
        if state.start_on_login != prev_autostart {
            if let Err(e) = crate::os_integration::set_autostart(state.start_on_login) {
                state.start_on_login = prev_autostart;
                state.local_feedback = Some(format!("Autostart failed: {e}"));
            }
        }

        ui.row(|ui| {
            if ui
                .btn("Save Settings")
                .sz(12.5)
                .px(14.0)
                .py(6.0)
                .bg(p.ok_green)
                .fg(p.bg)
                .clicked()
            {
                let sec_txt = state.network_secret.text().trim().to_string();
                sync.send(SyncCommand::SaveSettings {
                    relay_url: state.relay_url.text().to_string(),
                    device_name: state.device_name.text().to_string(),
                    default_sync_root: PathBuf::from(state.default_sync_root.text().trim()),
                    keep_unlocked: state.keep_unlocked,
                    network_secret: if sec_txt.is_empty() {
                        None
                    } else {
                        Some(sec_txt)
                    },
                    auto_check_updates: state.auto_check_updates,
                });
            }
            if ui
                .btn("Sign Out")
                .sz(12.0)
                .px(12.0)
                .py(6.0)
                .bg(p.surface_alt)
                .bd(1.0, p.err_red)
                .fg(p.err_red)
                .clicked()
            {
                sync.send(SyncCommand::SignOut);
            }
        })
        .gap(8.0);
    })
    .w_frac(1.0)
    .p(14.0)
    .gap(8.0)
    .bg(p.surface)
    .bd(1.0, p.border)
    .r(6.0);

    // App Updates Card
    ui.col(|ui| {
        ui.row(|ui| {
            ui.txt(&format!("App Updates (v{})", updater::current_version()))
                .sz(13.0)
                .bold()
                .fg(p.text);
            if ui
                .btn("Check Now")
                .sz(11.5)
                .px(10.0)
                .py(4.0)
                .bg(p.surface_alt)
                .bd(1.0, p.border)
                .fg(p.text)
                .clicked()
            {
                sync.send(SyncCommand::CheckUpdates);
            }
        })
        .w_frac(1.0)
        .justify_between()
        .align_center();

        match &snap.update_status {
            UpdateStatus::Idle => {
                ui.txt("Ready to check for updates.").sz(12.0).fg(p.muted);
            }
            UpdateStatus::Checking => {
                ui.txt("Checking GitHub releases...").sz(12.0).fg(p.accent);
            }
            UpdateStatus::UpToDate(v) => {
                ui.txt(&format!("Up to date (v{v}).")).sz(12.0).fg(p.ok_green);
            }
            UpdateStatus::Available { version, .. } => {
                ui.row(|ui| {
                    ui.txt(&format!("Update available: {version}"))
                        .sz(12.0)
                        .fg(p.accent);
                    if ui
                        .btn("Download & Install")
                        .sz(11.5)
                        .px(10.0)
                        .py(4.0)
                        .bg(p.accent)
                        .fg(p.bg)
                        .clicked()
                    {
                        sync.send(SyncCommand::InstallUpdate);
                    }
                })
                .gap(10.0)
                .align_center();
            }
            UpdateStatus::Downloading(v) => {
                ui.txt(&format!("Downloading and verifying {v}..."))
                    .sz(12.0)
                    .fg(p.accent);
            }
            UpdateStatus::ReadyToRestart(v) => {
                ui.row(|ui| {
                    ui.txt(&format!("Update {v} staged and verified."))
                        .sz(12.0)
                        .fg(p.ok_green);
                    if ui
                        .btn("Restart to Apply")
                        .sz(11.5)
                        .px(12.0)
                        .py(4.0)
                        .bg(p.ok_green)
                        .fg(p.bg)
                        .clicked()
                        && updater::restart_self().is_ok()
                    {
                        app.remove_tray_icon();
                        app.request_exit();
                    }
                })
                .gap(10.0)
                .align_center();
            }
            UpdateStatus::Error(e) => {
                ui.txt(e).sz(12.0).fg(p.err_red);
            }
        }
    })
    .w_frac(1.0)
    .p(14.0)
    .gap(8.0)
    .bg(p.surface)
    .bd(1.0, p.border)
    .r(6.0);
}

pub fn render_admin_users_view(
    ui: &mut UiContext,
    snap: &UiSnapshot,
    state: &mut UiState,
    sync: &SyncHandle,
) {
    let p = Palette::default();

    ui.row(|ui| {
        ui.txt("Relay Users (Admin)").sz(14.0).bold().fg(p.text);
        if ui
            .btn("Refresh")
            .sz(11.5)
            .px(10.0)
            .py(4.0)
            .bg(p.surface_alt)
            .bd(1.0, p.border)
            .fg(p.text)
            .clicked()
        {
            sync.send(SyncCommand::AdminRefreshUsers);
        }
    })
    .w_frac(1.0)
    .justify_between()
    .align_center();

    // Create new user form
    ui.row(|ui| {
        ui.input("admin_new_user", &mut state.new_user_name)
            .w(180.0)
            .bg(p.bg)
            .bd(1.0, p.border)
            .px(8.0)
            .py(5.0);
        ui.password_input("admin_new_pass", &mut state.new_user_pass)
            .w(180.0)
            .bg(p.bg)
            .bd(1.0, p.border)
            .px(8.0)
            .py(5.0);
        ui.checkbox("Admin", &mut state.new_user_is_admin);
        if ui
            .btn("Create User")
            .sz(12.0)
            .px(12.0)
            .py(5.0)
            .bg(p.ok_green)
            .fg(p.bg)
            .clicked()
        {
            let uname = state.new_user_name.text().trim().to_string();
            let pw = state.new_user_pass.text().to_string();
            if !uname.is_empty() && pw.len() >= 8 {
                sync.send(SyncCommand::AdminCreateUser {
                    username: uname,
                    password: pw,
                    role: if state.new_user_is_admin {
                        UserRole::Admin
                    } else {
                        UserRole::User
                    },
                });
                state.new_user_name.set_text("");
                state.new_user_pass.set_text("");
                state.new_user_is_admin = false;
            } else {
                state.local_feedback =
                    Some("Username required and password must be at least 8 characters".to_string());
            }
        }
    })
    .w_frac(1.0)
    .p(12.0)
    .gap(8.0)
    .bg(p.surface)
    .bd(1.0, p.border)
    .r(6.0)
    .align_center();

    for u in &snap.admin_users {
        ui.row(|ui| {
            ui.col(|ui| {
                ui.row(|ui| {
                    ui.txt(&u.username).sz(13.0).bold().fg(p.text);
                    ui.txt(if u.role == UserRole::Admin {
                        "Admin"
                    } else {
                        "User"
                    })
                    .sz(11.0)
                    .fg(p.accent);
                    if u.disabled {
                        ui.txt("Disabled").sz(11.0).fg(p.err_red);
                    }
                })
                .gap(8.0);
                ui.txt(&format!("ID: {}", u.id))
                    .sz(11.5)
                    .fg(p.muted);
            })
            .gap(2.0);

            if u.id != snap.user_id {
                ui.row(|ui| {
                    if ui
                        .btn(if u.disabled { "Enable" } else { "Disable" })
                        .sz(11.0)
                        .px(8.0)
                        .py(4.0)
                        .bg(p.surface_alt)
                        .bd(1.0, p.border)
                        .fg(p.text)
                        .clicked()
                    {
                        sync.send(SyncCommand::AdminSetUserDisabled {
                            user_id: u.id.clone(),
                            disabled: !u.disabled,
                        });
                    }
                    if ui
                        .btn("Delete")
                        .sz(11.0)
                        .px(8.0)
                        .py(4.0)
                        .bg(p.surface_alt)
                        .bd(1.0, p.err_red)
                        .fg(p.err_red)
                        .clicked()
                    {
                        sync.send(SyncCommand::AdminDeleteUser(u.id.clone()));
                    }
                })
                .gap(6.0);
            }
        })
        .w_frac(1.0)
        .p(12.0)
        .bg(p.surface)
        .bd(1.0, p.border)
        .r(6.0)
        .justify_between()
        .align_center();
    }
}

fn field_label(ui: &mut UiContext, text: &str, p: &Palette) {
    ui.txt(text).sz(11.5).fg(p.muted);
}
