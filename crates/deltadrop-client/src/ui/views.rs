use deltadrop_common::UserRole;
use lumenic::{App, UiContext};

use crate::config::{IgnoreRule, SyncMode};
use crate::ignore_rules::{detect_project_ignore_rules, IgnoreFilter, IGNORE_PRESETS};
use crate::sync::{SyncCommand, SyncHandle, UiSnapshot};
use crate::ui::theme::Palette;
use crate::ui::{FolderDraft, UiState};
use crate::updater::{current_version, UpdateStatus};

pub fn render_folders_view(
    ui: &mut UiContext,
    app: &App,
    snap: &UiSnapshot,
    state: &mut UiState,
    sync: &SyncHandle,
) {
    let p = Palette::default();

    ui.row(|ui| {
        ui.txt("SYNCED FOLDERS").sz(11.0).tracking(0.08).fg(p.muted);
        ui.row(|ui| {
            if ui
                .btn("+ Add Local Folder")
                .bg(p.surface)
                .bd(1.0, p.border)
                .sz(12.0)
                .px(10.0)
                .py(5.0)
                .clicked()
            {
                let idx = state.folders.len() + 1;
                state.folders.push(FolderDraft::empty(idx));
                let new_idx = state.folders.len() - 1;
                let dialog = app.pick_folder("Select Folder to Sync");
                state.folder_picker = Some((new_idx, dialog));
                state.dirty = true;
            }
            if state.dirty
                && ui
                    .btn("Save Changes")
                    .bg(p.accent)
                    .fg(p.bg)
                    .sz(12.0)
                    .px(10.0)
                    .py(5.0)
                    .clicked()
            {
                match state.to_client_config() {
                    Ok(cfg) => {
                        let _ = sync.cmd_tx.send(SyncCommand::UpdateConfig(cfg));
                        state.dirty = false;
                        state.save_feedback = Some("Saved".to_string());
                    }
                    Err(e) => state.save_feedback = Some(e),
                }
            }
        })
        .gap(8.0);
    })
    .w_frac(1.0)
    .px(24.0)
    .py(14.0)
    .justify_between()
    .align_center();

    ui.divider().bg(p.border);

    if state.folders.is_empty() {
        ui.col(|ui| {
            ui.txt("No local folders configured yet.")
                .sz(13.0)
                .fg(p.muted);
        })
        .px(24.0)
        .py(28.0);
        return;
    }

    let mut remove_idx: Option<usize> = None;
    for idx in 0..state.folders.len() {
        let folder_id = state.folders[idx].id.text();
        let folder_path = state.folders[idx].path.text();
        let active_presets: Vec<&'static str> = IGNORE_PRESETS
            .iter()
            .filter(|preset| {
                preset.patterns.iter().any(|pat| {
                    state.folders[idx]
                        .ignore_rules
                        .iter()
                        .any(|r| r.enabled && r.pattern == *pat)
                })
            })
            .map(|p| p.name)
            .collect();

        ui.col(|ui| {
            ui.row(|ui| {
                ui.col(|ui| {
                    ui.txt(if folder_id.is_empty() {
                        "(unnamed)"
                    } else {
                        &folder_id
                    })
                    .sz(13.5)
                    .bold()
                    .fg(p.text);
                    ui.txt(if folder_path.is_empty() {
                        "No path selected"
                    } else {
                        &folder_path
                    })
                    .sz(11.5)
                    .mono()
                    .fg(p.muted);
                })
                .gap(2.0);

                ui.row(|ui| {
                    for tag in &active_presets {
                        ui.txt(tag)
                            .sz(10.5)
                            .px(6.0)
                            .py(2.0)
                            .bg(p.surface)
                            .bd(1.0, p.border)
                            .r(3.0)
                            .fg(p.muted);
                    }
                    if ui.btn("Ignore Rules").sz(11.5).px(8.0).py(4.0).clicked() {
                        state.folders[idx].show_ignore = !state.folders[idx].show_ignore;
                    }
                    let sel_label = if state.folders[idx].mode == SyncMode::Whitelist {
                        "Selective"
                    } else {
                        "Sync All"
                    };
                    if ui.btn(sel_label).sz(11.5).px(8.0).py(4.0).clicked() {
                        state.folders[idx].mode = match state.folders[idx].mode {
                            SyncMode::Full => SyncMode::Whitelist,
                            SyncMode::Whitelist => SyncMode::Full,
                        };
                        state.dirty = true;
                    }
                    if ui
                        .btn("Unlink")
                        .fg(p.err_red)
                        .sz(11.5)
                        .px(8.0)
                        .py(4.0)
                        .clicked()
                    {
                        remove_idx = Some(idx);
                    }
                })
                .gap(8.0)
                .align_center();
            })
            .w_frac(1.0)
            .justify_between()
            .align_center();

            if state.folders[idx].show_ignore {
                ui.col(|ui| {
                    ui.row(|ui| {
                        ui.txt("PRESETS").sz(10.5).tracking(0.08).fg(p.muted);
                        if ui.btn("Auto-Detect").sz(11.0).px(8.0).py(3.0).clicked() {
                            let path = std::path::PathBuf::from(state.folders[idx].path.text());
                            state.folders[idx].ignore_rules = detect_project_ignore_rules(&path);
                            state.dirty = true;
                        }
                    })
                    .gap(10.0)
                    .align_center();

                    ui.row(|ui| {
                        for preset in IGNORE_PRESETS {
                            let enabled = preset.patterns.iter().any(|pat| {
                                state.folders[idx]
                                    .ignore_rules
                                    .iter()
                                    .any(|r| r.enabled && r.pattern == *pat)
                            });
                            let btn_lbl = if enabled {
                                format!("✓ {}", preset.name)
                            } else {
                                preset.name.to_string()
                            };
                            if ui
                                .btn(&btn_lbl)
                                .bg(if enabled { p.surface_alt } else { p.bg })
                                .bd(1.0, if enabled { p.ok_green } else { p.border })
                                .fg(if enabled { p.ok_green } else { p.muted })
                                .sz(11.0)
                                .px(8.0)
                                .py(3.0)
                                .clicked()
                            {
                                toggle_preset(&mut state.folders[idx], preset.patterns, !enabled);
                                state.dirty = true;
                            }
                        }
                    })
                    .gap(6.0);

                    ui.txt(
                        ".deltadropignore CUSTOM RULES (gitignore globs, !negation, trailing /)",
                    )
                    .sz(10.5)
                    .tracking(0.08)
                    .fg(p.muted);
                    if ui
                        .textarea(
                            &format!("ignore-custom-{idx}"),
                            &mut state.folders[idx].custom_ignore,
                        )
                        .w_frac(1.0)
                        .h(76.0)
                        .mono()
                        .bg(p.bg)
                        .bd(1.0, p.border)
                        .p(8.0)
                        .changed()
                    {
                        state.dirty = true;
                    }

                    // Live Test Path preview
                    ui.row(|ui| {
                        ui.txt("TEST PATH").sz(10.5).tracking(0.08).fg(p.muted);
                        ui.input(
                            &format!("test-path-{idx}"),
                            &mut state.folders[idx].new_rule_input,
                        )
                        .placeholder("e.g. Library/cache.db or src/main.rs")
                        .w(280.0)
                        .px(8.0)
                        .py(5.0)
                        .bg(p.bg)
                        .bd(1.0, p.border);
                        let sample = state.folders[idx].new_rule_input.text();
                        if !sample.trim().is_empty() {
                            let temp_cfg = crate::config::SyncFolderConfig {
                                id: folder_id.clone(),
                                label: None,
                                path: std::path::PathBuf::from(&folder_path),
                                mode: state.folders[idx].mode,
                                whitelist_subdirs: state.folders[idx].whitelist_subdirs.clone(),
                                ignore_rules: state.folders[idx].ignore_rules.clone(),
                                custom_ignore: state.folders[idx].custom_ignore.text(),
                            };
                            let filter = IgnoreFilter::for_folder_config(&temp_cfg);
                            let ignored = filter.test_path_ignored(&temp_cfg, &sample);
                            ui.txt(if ignored { "IGNORED" } else { "SYNCED" })
                                .sz(11.0)
                                .bold()
                                .fg(if ignored { p.warn_amber } else { p.ok_green });
                        }
                    })
                    .gap(10.0)
                    .align_center();
                })
                .w_frac(1.0)
                .p(12.0)
                .gap(8.0)
                .bg(p.surface)
                .bd(1.0, p.border)
                .r(4.0);
            }

            if state.folders[idx].mode == SyncMode::Whitelist {
                if let Some(sv) = snap
                    .selective_folders
                    .iter()
                    .find(|s| s.folder_id == folder_id)
                {
                    ui.row(|ui| {
                        ui.txt("SUBFOLDERS:").sz(10.5).fg(p.muted);
                        for sub in &sv.subdirs {
                            let lbl = if sub.whitelisted {
                                format!("✓ {}", sub.name)
                            } else {
                                sub.name.clone()
                            };
                            if ui
                                .btn(&lbl)
                                .bd(
                                    1.0,
                                    if sub.whitelisted {
                                        p.ok_green
                                    } else {
                                        p.border
                                    },
                                )
                                .fg(if sub.whitelisted { p.ok_green } else { p.muted })
                                .sz(11.0)
                                .px(6.0)
                                .py(3.0)
                                .clicked()
                            {
                                let _ = sync.cmd_tx.send(SyncCommand::ToggleSubdir {
                                    folder_id: folder_id.clone(),
                                    source_peer: sv.source_peer.clone(),
                                    subdir: sub.name.clone(),
                                    enable: !sub.whitelisted,
                                });
                            }
                        }
                    })
                    .gap(6.0);
                }
            }
        })
        .w_frac(1.0)
        .px(24.0)
        .py(14.0)
        .gap(10.0);
        ui.divider().bg(p.border);
    }

    if let Some(idx) = remove_idx {
        state.folders.remove(idx);
        state.dirty = true;
    }
}

fn toggle_preset(draft: &mut FolderDraft, patterns: &[&str], enable: bool) {
    for &pat in patterns {
        if enable {
            if let Some(existing) = draft.ignore_rules.iter_mut().find(|r| r.pattern == pat) {
                existing.enabled = true;
            } else {
                draft.ignore_rules.push(IgnoreRule {
                    pattern: pat.to_string(),
                    enabled: true,
                });
            }
        } else if let Some(existing) = draft.ignore_rules.iter_mut().find(|r| r.pattern == pat) {
            existing.enabled = false;
        }
    }
}

pub fn render_devices_view(
    ui: &mut UiContext,
    snap: &UiSnapshot,
    state: &mut UiState,
    sync: &SyncHandle,
) {
    let p = Palette::default();

    ui.row(|ui| {
        ui.txt("DEVICES").sz(11.0).tracking(0.08).fg(p.muted);
        if ui.btn("Refresh").sz(11.5).px(10.0).py(4.0).clicked() {
            let _ = sync.cmd_tx.send(SyncCommand::RefreshDevices);
        }
    })
    .w_frac(1.0)
    .px(24.0)
    .py(14.0)
    .justify_between()
    .align_center();
    ui.divider().bg(p.border);

    if snap.devices.is_empty() {
        ui.col(|ui| {
            ui.txt("No devices registered on relay.")
                .sz(13.0)
                .fg(p.muted);
        })
        .px(24.0)
        .py(28.0);
        return;
    }

    for dev in &snap.devices {
        let is_self = dev.device_id == snap.peer_id;
        ui.row(|ui| {
            ui.col(|ui| {
                ui.row(|ui| {
                    ui.col(|_| {}).w(8.0).h(8.0).r(4.0).bg(if dev.online {
                        p.ok_green
                    } else {
                        p.offline_slate
                    });
                    ui.txt(&if is_self {
                        format!("{}  (THIS PC)", dev.device_id)
                    } else {
                        dev.device_id.clone()
                    })
                    .sz(13.0)
                    .bold()
                    .fg(p.text);
                })
                .gap(8.0)
                .align_center();
                ui.txt(&format!(
                    "OS: {}  ·  {}",
                    if dev.os.is_empty() {
                        "unknown"
                    } else {
                        &dev.os
                    },
                    if dev.online { "Online" } else { "Offline" }
                ))
                .sz(11.5)
                .fg(p.muted);
            })
            .gap(4.0);

            if !is_self {
                ui.row(|ui| {
                    if ui
                        .btn("Replace This Device")
                        .sz(11.5)
                        .px(8.0)
                        .py(4.0)
                        .clicked()
                    {
                        let _ = sync.cmd_tx.send(SyncCommand::ReplaceDevice {
                            old_device_id: dev.device_id.clone(),
                            new_device_name: state.device_name.text(),
                        });
                    }
                    if ui
                        .btn("Remove Dead Device")
                        .fg(p.err_red)
                        .sz(11.5)
                        .px(8.0)
                        .py(4.0)
                        .clicked()
                    {
                        let _ = sync
                            .cmd_tx
                            .send(SyncCommand::DeleteDevice(dev.device_id.clone()));
                    }
                })
                .gap(8.0);
            }
        })
        .w_frac(1.0)
        .px(24.0)
        .py(14.0)
        .justify_between()
        .align_center();
        ui.divider().bg(p.border);
    }
}

pub fn render_settings_view(
    ui: &mut UiContext,
    snap: &UiSnapshot,
    state: &mut UiState,
    sync: &SyncHandle,
) {
    let p = Palette::default();

    ui.col(|ui| {
        ui.txt("ACCOUNT & LOCK").sz(11.0).tracking(0.08).fg(p.muted);
        ui.row(|ui| {
            let account_label = if snap.username.is_empty() {
                format!("Not signed in  ·  {}", state.relay_url.text())
            } else {
                format!(
                    "Signed in as {} @ {}",
                    snap.username,
                    state.relay_url.text()
                )
            };
            ui.txt(&account_label).sz(12.5).fg(p.text);
            if ui
                .btn("Sign Out")
                .fg(p.warn_amber)
                .sz(11.5)
                .px(8.0)
                .py(4.0)
                .clicked()
            {
                state.onboarding_step = 0;
                let _ = sync.cmd_tx.send(SyncCommand::SignOut);
            }
        })
        .w_frac(1.0)
        .justify_between()
        .align_center();

        ui.row(|ui| {
            ui.txt("Device Name").sz(12.0).fg(p.muted).w(140.0);
            ui.input("settings-device-name", &mut state.device_name)
                .w(260.0)
                .px(8.0)
                .py(5.0)
                .bg(p.surface)
                .bd(1.0, p.border);
        })
        .gap(12.0)
        .align_center();

        ui.row(|ui| {
            ui.txt("Network Gate").sz(12.0).fg(p.muted).w(140.0);
            if ui
                .input("settings-network-gate", &mut state.network_secret)
                .placeholder("X-DeltaDrop-Gate (optional)")
                .w(260.0)
                .px(8.0)
                .py(5.0)
                .bg(p.surface)
                .bd(1.0, p.border)
                .changed()
            {
                state.dirty = true;
            }
        })
        .gap(12.0)
        .align_center();

        ui.row(|ui| {
            ui.txt("Keep Unlocked").sz(12.0).fg(p.muted).w(140.0);
            if ui
                .btn(if state.keep_unlocked {
                    "Enabled"
                } else {
                    "Disabled"
                })
                .sz(11.5)
                .px(10.0)
                .py(4.0)
                .clicked()
            {
                state.keep_unlocked = !state.keep_unlocked;
                state.dirty = true;
            }
        })
        .gap(12.0)
        .align_center();

        ui.divider().bg(p.border);

        ui.txt("SYNC & POLLING").sz(11.0).tracking(0.08).fg(p.muted);
        ui.row(|ui| {
            ui.txt("Poll Interval (s)").sz(12.0).fg(p.muted).w(140.0);
            if ui
                .input("settings-poll", &mut state.poll_interval)
                .w(100.0)
                .px(8.0)
                .py(5.0)
                .bg(p.surface)
                .bd(1.0, p.border)
                .changed()
            {
                state.dirty = true;
            }
            if ui
                .btn(if state.start_on_login {
                    "Start on Login: ON"
                } else {
                    "Start on Login: OFF"
                })
                .sz(11.5)
                .px(10.0)
                .py(4.0)
                .clicked()
            {
                state.start_on_login = !state.start_on_login;
                let _ = crate::os_integration::set_autostart(state.start_on_login);
            }
        })
        .gap(12.0)
        .align_center();

        if state.dirty
            && ui
                .btn("Save Settings")
                .bg(p.accent)
                .fg(p.bg)
                .sz(12.0)
                .px(12.0)
                .py(6.0)
                .clicked()
        {
            if let Ok(cfg) = state.to_client_config() {
                let _ = sync.cmd_tx.send(SyncCommand::UpdateConfig(cfg));
                state.dirty = false;
            }
        }

        ui.divider().bg(p.border);

        ui.txt("IN-APP UPDATES").sz(11.0).tracking(0.08).fg(p.muted);
        ui.row(|ui| {
            ui.txt(&format!("Current version: v{}", current_version()))
                .sz(12.5)
                .mono()
                .fg(p.text);

            match snap.update_status.as_ref() {
                Some(UpdateStatus::Checking) => {
                    ui.txt("Checking GitHub Releases...").sz(12.0).fg(p.muted);
                }
                Some(UpdateStatus::Downloading(v)) => {
                    ui.txt(&format!("Downloading {v}..."))
                        .sz(12.0)
                        .fg(p.ok_green);
                }
                Some(UpdateStatus::Available { version, .. }) => {
                    if ui
                        .btn(&format!("Download & Stage {version}"))
                        .bg(p.ok_green)
                        .fg(p.bg)
                        .sz(12.0)
                        .px(10.0)
                        .py(5.0)
                        .clicked()
                    {
                        let _ = sync.cmd_tx.send(SyncCommand::InstallUpdate);
                    }
                }
                Some(UpdateStatus::ReadyToRestart(v)) => {
                    ui.txt(&format!("Update {v} staged. Restart DeltaDrop to apply."))
                        .sz(12.0)
                        .fg(p.ok_green);
                }
                Some(UpdateStatus::UpToDate(_)) => {
                    ui.txt("Up to date").sz(12.0).fg(p.ok_green);
                    if ui.btn("Check Again").sz(11.5).px(8.0).py(4.0).clicked() {
                        let _ = sync.cmd_tx.send(SyncCommand::CheckUpdates);
                    }
                }
                Some(UpdateStatus::Error(err)) => {
                    ui.txt(err).sz(12.0).fg(p.err_red);
                    if ui.btn("Retry").sz(11.5).px(8.0).py(4.0).clicked() {
                        let _ = sync.cmd_tx.send(SyncCommand::CheckUpdates);
                    }
                }
                _ => {
                    if ui
                        .btn("Check for Updates")
                        .sz(11.5)
                        .px(10.0)
                        .py(5.0)
                        .clicked()
                    {
                        let _ = sync.cmd_tx.send(SyncCommand::CheckUpdates);
                    }
                }
            }
        })
        .w_frac(1.0)
        .justify_between()
        .align_center();
    })
    .w_frac(1.0)
    .px(24.0)
    .py(20.0)
    .gap(14.0);
}

pub fn render_users_view(
    ui: &mut UiContext,
    snap: &UiSnapshot,
    state: &mut UiState,
    sync: &SyncHandle,
) {
    let p = Palette::default();

    ui.col(|ui| {
        ui.row(|ui| {
            ui.txt("USER MANAGEMENT (ADMIN)")
                .sz(11.0)
                .tracking(0.08)
                .fg(p.muted);
            if ui.btn("Refresh").sz(11.5).px(10.0).py(4.0).clicked() {
                let _ = sync.cmd_tx.send(SyncCommand::AdminRefreshUsers);
            }
        })
        .w_frac(1.0)
        .justify_between()
        .align_center();

        ui.row(|ui| {
            ui.input("new-subuser-name", &mut state.new_subuser_name)
                .placeholder("username")
                .w(180.0)
                .px(8.0)
                .py(5.0)
                .bg(p.surface)
                .bd(1.0, p.border);
            ui.input("new-subuser-pass", &mut state.new_subuser_pass)
                .placeholder("password")
                .w(200.0)
                .px(8.0)
                .py(5.0)
                .bg(p.surface)
                .bd(1.0, p.border);
            if ui
                .btn("+ Add Sub-User")
                .bg(p.accent)
                .fg(p.bg)
                .sz(12.0)
                .px(10.0)
                .py(5.0)
                .clicked()
            {
                let u = state.new_subuser_name.text();
                let pw = state.new_subuser_pass.text();
                if !u.trim().is_empty() && !pw.is_empty() {
                    let _ = sync.cmd_tx.send(SyncCommand::AdminCreateUser {
                        username: u,
                        password: pw,
                        role: UserRole::User,
                    });
                    state.new_subuser_name.set_text("");
                    state.new_subuser_pass.set_text("");
                }
            }
        })
        .gap(10.0)
        .align_center();

        ui.divider().bg(p.border);

        for u in &snap.admin_users {
            ui.row(|ui| {
                ui.row(|ui| {
                    ui.txt(&u.username).sz(13.0).bold().fg(p.text);
                    ui.txt(u.role.as_str())
                        .sz(10.5)
                        .px(6.0)
                        .py(2.0)
                        .bg(p.surface)
                        .bd(1.0, p.border)
                        .fg(p.muted);
                    if u.disabled {
                        ui.txt("DISABLED").sz(10.5).fg(p.warn_amber);
                    }
                })
                .gap(8.0)
                .align_center();

                if u.username != snap.username {
                    ui.row(|ui| {
                        let toggle_lbl = if u.disabled { "Enable" } else { "Disable" };
                        if ui.btn(toggle_lbl).sz(11.5).px(8.0).py(4.0).clicked() {
                            let _ = sync.cmd_tx.send(SyncCommand::AdminToggleUserDisabled {
                                user_id: u.id.clone(),
                                disabled: !u.disabled,
                            });
                        }
                        if ui.btn("Reset PW").sz(11.5).px(8.0).py(4.0).clicked() {
                            let pw = state.new_subuser_pass.text();
                            if !pw.is_empty() {
                                let _ = sync.cmd_tx.send(SyncCommand::AdminResetUserPassword {
                                    user_id: u.id.clone(),
                                    new_password: pw,
                                });
                                state.new_subuser_pass.set_text("");
                            }
                        }
                        if ui
                            .btn("Delete")
                            .fg(p.err_red)
                            .sz(11.5)
                            .px(8.0)
                            .py(4.0)
                            .clicked()
                        {
                            let _ = sync.cmd_tx.send(SyncCommand::AdminDeleteUser(u.id.clone()));
                        }
                    })
                    .gap(8.0);
                }
            })
            .w_frac(1.0)
            .py(10.0)
            .justify_between()
            .align_center();
            ui.divider().bg(p.border);
        }
    })
    .w_frac(1.0)
    .px(24.0)
    .py(16.0)
    .gap(12.0);
}
