use std::path::PathBuf;

use deltadrop_common::format_bytes;
use lumenic::{App, UiContext};

use crate::config::{is_dangerous_root_path, validate_share_path, LocalShareBinding};
use crate::ignore_rules::{
    preset_is_enabled, toggle_preset_patterns, IgnoreFilter, IGNORE_PRESETS,
};
use crate::sync::{ShareSyncState, SyncCommand, SyncHandle, UiSnapshot};
use crate::ui::theme::{open_folder_in_os, Palette};
use crate::ui::{AssignModalState, IgnoreEditorState, UiState};

pub fn render_folders_view(
    ui: &mut UiContext,
    app: &App,
    snap: &UiSnapshot,
    state: &mut UiState,
    sync: &SyncHandle,
) {
    let p = Palette::default();

    // Compact live telemetry strip
    render_telemetry_strip(ui, snap, &p);

    // Inline Assign Remote Share Confirmation Panel
    if let Some(mut modal) = state.assign_modal.take() {
        let mut keep_open = true;
        let target_path = PathBuf::from(modal.target_path.text().trim());
        let existing_bindings: Vec<LocalShareBinding> = snap
            .shares
            .iter()
            .map(|s| LocalShareBinding {
                share_id: s.share_id.clone(),
                name: s.name.clone(),
                local_path: s.local_path.clone(),
                ignore_patterns: s.ignore_patterns.clone(),
                paused: s.paused,
            })
            .collect();
        let path_validation =
            validate_share_path(&target_path, &existing_bindings, Some(&modal.share_id));

        ui.col(|ui| {
            ui.row(|ui| {
                ui.txt(&format!("Assign Remote Share: {}", modal.share_name))
                    .sz(14.0)
                    .bold()
                    .fg(p.accent);
                if ui
                    .btn("Cancel")
                    .sz(11.5)
                    .px(10.0)
                    .py(4.0)
                    .bg(p.surface_alt)
                    .bd(1.0, p.border)
                    .fg(p.muted)
                    .clicked()
                {
                    keep_open = false;
                }
            })
            .w_frac(1.0)
            .justify_between()
            .align_center();

            ui.txt(&format!(
                "{} files ({}) - Picking a parent folder like Desktop automatically creates a '{}' subfolder.",
                modal.file_count,
                format_bytes(modal.total_bytes),
                modal.share_name
            ))
            .sz(12.0)
            .fg(p.muted);

            ui.row(|ui| {
                ui.input("assign_target_path", &mut modal.target_path)
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
                    let dlg = app.pick_folder(&format!(
                        "Choose parent folder for '{}'",
                        modal.share_name
                    ));
                    state.assign_browse_picker = Some(dlg);
                }
            })
            .w_frac(1.0)
            .gap(8.0)
            .align_center();

            match &path_validation {
                Ok(()) => {
                    ui.txt(&format!("Will sync into: {}", target_path.display()))
                        .sz(12.0)
                        .fg(p.ok_green);
                }
                Err(msg) => {
                    ui.txt(msg).sz(12.0).fg(p.err_red);
                }
            }

            ui.row(|ui| {
                let can_start = path_validation.is_ok() && !is_dangerous_root_path(&target_path);
                let btn = ui
                    .btn("Start Sync")
                    .sz(12.5)
                    .px(14.0)
                    .py(6.0)
                    .bg(if can_start { p.ok_green } else { p.surface_alt })
                    .fg(if can_start { p.bg } else { p.muted });
                if can_start && btn.clicked() {
                    sync.send(SyncCommand::AssignRemoteShare {
                        share_id: modal.share_id.clone(),
                        target_path,
                    });
                    keep_open = false;
                }
                if ui
                    .btn("Ignore on This PC")
                    .sz(12.0)
                    .px(12.0)
                    .py(6.0)
                    .bg(p.surface_alt)
                    .bd(1.0, p.border)
                    .fg(p.muted)
                    .clicked()
                {
                    sync.send(SyncCommand::IgnoreRemoteShare(modal.share_id.clone()));
                    keep_open = false;
                }
            })
            .gap(8.0);
        })
        .w_frac(1.0)
        .p(14.0)
        .gap(10.0)
        .bg(p.surface)
        .bd(1.5, p.accent)
        .r(6.0);

        if keep_open {
            state.assign_modal = Some(modal);
        }
    }

    // Banner: Unassigned Remote Shares
    if !snap.unassigned_shares.is_empty() {
        ui.col(|ui| {
            ui.txt(&format!(
                "Available Remote Shares ({})",
                snap.unassigned_shares.len()
            ))
            .sz(13.0)
            .bold()
            .fg(p.accent);
            ui.txt("Choose where to store these folders on this PC before syncing begins.")
                .sz(11.5)
                .fg(p.muted);

            for preview in &snap.unassigned_shares {
                ui.row(|ui| {
                    ui.col(|ui| {
                        ui.txt(&preview.name).sz(13.0).bold().fg(p.text);
                        ui.txt(&format!(
                            "v{} - {} files ({}) - Default: {}",
                            preview.version,
                            preview.file_count,
                            format_bytes(preview.total_bytes),
                            preview.suggested_path.display()
                        ))
                        .sz(11.5)
                        .fg(p.muted);
                    })
                    .gap(2.0);

                    ui.row(|ui| {
                        if ui
                            .btn("Assign Folder")
                            .sz(12.0)
                            .px(12.0)
                            .py(5.0)
                            .bg(p.accent)
                            .fg(p.bg)
                            .clicked()
                        {
                            state.assign_modal = Some(AssignModalState::from_preview(preview));
                        }
                        if ui
                            .btn("Ignore")
                            .sz(11.5)
                            .px(10.0)
                            .py(5.0)
                            .bg(p.surface_alt)
                            .bd(1.0, p.border)
                            .fg(p.muted)
                            .clicked()
                        {
                            sync.send(SyncCommand::IgnoreRemoteShare(preview.share_id.clone()));
                        }
                    })
                    .gap(6.0)
                    .align_center();
                })
                .w_frac(1.0)
                .p(10.0)
                .bg(p.bg)
                .bd(1.0, p.border)
                .r(4.0)
                .justify_between()
                .align_center();
            }
        })
        .w_frac(1.0)
        .p(14.0)
        .gap(8.0)
        .bg(p.surface)
        .bd(1.0, p.accent)
        .r(6.0);
    }

    // Synced Folders Header
    ui.row(|ui| {
        ui.txt(&format!("Synced Folders ({})", snap.shares.len()))
            .sz(14.0)
            .bold()
            .fg(p.text);
        if ui
            .btn("+ Add Local Folder")
            .sz(12.0)
            .px(12.0)
            .py(6.0)
            .bg(p.ok_green)
            .fg(p.bg)
            .clicked()
        {
            state.add_folder_picker = Some(app.pick_folder("Select a local project folder to sync"));
        }
    })
    .w_frac(1.0)
    .justify_between()
    .align_center();

    if snap.shares.is_empty() {
        ui.col(|ui| {
            ui.txt("No folders synced on this PC yet.")
                .sz(13.0)
                .bold()
                .fg(p.text);
            ui.txt("Click '+ Add Local Folder' to share a project from this PC, or assign an available remote share above.")
                .sz(12.0)
                .fg(p.muted);
        })
        .w_frac(1.0)
        .p(20.0)
        .gap(6.0)
        .bg(p.surface)
        .bd(1.0, p.border)
        .r(6.0);
    } else {
        for share in &snap.shares {
            let status_color = match &share.state {
                ShareSyncState::Idle => p.ok_green,
                ShareSyncState::Scanning | ShareSyncState::Syncing => p.accent,
                ShareSyncState::WaitingForHost | ShareSyncState::Paused => p.warn_amber,
                ShareSyncState::Error(_) => p.err_red,
            };

            ui.col(|ui| {
                ui.row(|ui| {
                    ui.col(|ui| {
                        ui.row(|ui| {
                            ui.txt(&share.name).sz(13.5).bold().fg(p.text);
                            ui.txt(&format!("v{}", share.version))
                                .sz(11.0)
                                .fg(p.muted)
                                .bg(p.bg)
                                .px(6.0)
                                .py(2.0)
                                .r(3.0);
                            ui.txt(&share.status_detail).sz(11.5).fg(status_color);
                        })
                        .gap(8.0)
                        .align_center();

                        ui.txt(&format!(
                            "{}  -  {} files ({})  -  {}",
                            share.local_path.display(),
                            share.file_count,
                            format_bytes(share.total_bytes),
                            share.last_sync_label
                        ))
                        .sz(11.5)
                        .fg(p.muted);
                    })
                    .gap(3.0);

                    ui.row(|ui| {
                        if ui
                            .btn("Sync Now")
                            .sz(11.5)
                            .px(10.0)
                            .py(5.0)
                            .bg(p.surface_alt)
                            .bd(1.0, p.ok_green)
                            .fg(p.ok_green)
                            .clicked()
                        {
                            sync.send(SyncCommand::SyncNow(Some(share.share_id.clone())));
                        }
                        if ui
                            .btn("Ignore Rules")
                            .sz(11.5)
                            .px(9.0)
                            .py(5.0)
                            .bg(p.surface_alt)
                            .bd(1.0, p.border)
                            .fg(p.text)
                            .clicked()
                        {
                            let already_open = state
                                .ignore_editor
                                .as_ref()
                                .is_some_and(|e| e.share_id == share.share_id);
                            if already_open {
                                state.ignore_editor = None;
                            } else {
                                state.ignore_editor = Some(IgnoreEditorState::new(
                                    share.share_id.clone(),
                                    share.local_path.clone(),
                                    share.ignore_patterns.clone(),
                                ));
                            }
                        }
                        if ui
                            .btn("Open")
                            .sz(11.5)
                            .px(8.0)
                            .py(5.0)
                            .bg(p.surface_alt)
                            .bd(1.0, p.border)
                            .fg(p.text)
                            .clicked()
                        {
                            open_folder_in_os(&share.local_path);
                        }
                        if ui
                            .btn(if share.paused { "Resume" } else { "Pause" })
                            .sz(11.5)
                            .px(8.0)
                            .py(5.0)
                            .bg(p.surface_alt)
                            .bd(1.0, p.border)
                            .fg(p.muted)
                            .clicked()
                        {
                            sync.send(SyncCommand::ToggleSharePause(share.share_id.clone()));
                        }
                        if ui
                            .btn("Unlink")
                            .sz(11.5)
                            .px(8.0)
                            .py(5.0)
                            .bg(p.surface_alt)
                            .bd(1.0, p.border)
                            .fg(p.muted)
                            .clicked()
                        {
                            sync.send(SyncCommand::UnlinkLocalShare(share.share_id.clone()));
                        }

                        let confirming = state.confirm_delete_share.as_deref()
                            == Some(share.share_id.as_str());
                        if confirming {
                            if ui
                                .btn("Confirm Delete")
                                .sz(11.5)
                                .px(9.0)
                                .py(5.0)
                                .bg(p.err_red)
                                .fg(p.text)
                                .clicked()
                            {
                                state.confirm_delete_share = None;
                                sync.send(SyncCommand::DeleteRemoteShare(share.share_id.clone()));
                            }
                        } else if ui
                            .btn("Delete")
                            .sz(11.5)
                            .px(8.0)
                            .py(5.0)
                            .bg(p.surface_alt)
                            .bd(1.0, p.err_red)
                            .fg(p.err_red)
                            .clicked()
                        {
                            state.confirm_delete_share = Some(share.share_id.clone());
                        }
                    })
                    .gap(5.0)
                    .align_center();
                })
                .w_frac(1.0)
                .justify_between()
                .align_center();

                if share.transfer_total_bytes > 0 {
                    let frac = (share.transferred_bytes as f32
                        / share.transfer_total_bytes as f32)
                        .clamp(0.0, 1.0);
                    ui.txt(&format!(
                        "{} / {} ({:.0}%)",
                        format_bytes(share.transferred_bytes),
                        format_bytes(share.transfer_total_bytes),
                        frac * 100.0
                    ))
                    .sz(11.0)
                    .fg(p.accent);
                }

                // Inline Ignore Rules Editor
                if state
                    .ignore_editor
                    .as_ref()
                    .is_some_and(|e| e.share_id == share.share_id)
                {
                    if let Some(ref mut editor) = state.ignore_editor {
                        render_ignore_editor(ui, editor, sync, &p);
                    }
                }
            })
            .w_frac(1.0)
            .p(12.0)
            .gap(8.0)
            .bg(p.surface)
            .bd(1.0, p.border)
            .r(6.0);
        }
    }

    // Ignored Remote Shares
    if !snap.ignored_shares.is_empty() {
        ui.col(|ui| {
            ui.txt(&format!("Ignored Remote Shares ({})", snap.ignored_shares.len()))
                .sz(12.0)
                .bold()
                .fg(p.muted);
            for preview in &snap.ignored_shares {
                ui.row(|ui| {
                    ui.txt(&preview.name).sz(12.0).fg(p.muted);
                    if ui
                        .btn("Show Again")
                        .sz(11.0)
                        .px(8.0)
                        .py(4.0)
                        .bg(p.surface_alt)
                        .bd(1.0, p.border)
                        .fg(p.text)
                        .clicked()
                    {
                        sync.send(SyncCommand::UnignoreRemoteShare(preview.share_id.clone()));
                    }
                })
                .w_frac(1.0)
                .justify_between()
                .align_center();
            }
        })
        .w_frac(1.0)
        .p(12.0)
        .gap(6.0)
        .bg(p.surface)
        .bd(1.0, p.border)
        .r(6.0);
    }
}

fn render_telemetry_strip(ui: &mut UiContext, snap: &UiSnapshot, p: &Palette) {
    let relay_val = if snap.relay_connected {
        let mode = if snap.ws_connected { "Live WS" } else { "HTTP" };
        match snap.relay_latency_ms {
            Some(ms) => format!("{ms} ms ({mode})"),
            None => format!("Connected ({mode})"),
        }
    } else {
        "Offline".to_string()
    };

    let speed_val = format!(
        "Up {}/s  |  Down {}/s",
        format_bytes(snap.upload_bps),
        format_bytes(snap.download_bps)
    );

    let cache_val = match &snap.cache_status {
        Some(c) => format!("{} / {}", format_bytes(c.used_bytes), format_bytes(c.max_bytes)),
        None => "-".to_string(),
    };

    let online_devices = snap.devices.iter().filter(|d| d.online).count();
    let devices_val = format!("{online_devices} / {} online", snap.devices.len().max(1));

    ui.row(|ui| {
        metric_cell(
            ui,
            "RELAY",
            &relay_val,
            if snap.relay_connected {
                p.ok_green
            } else {
                p.warn_amber
            },
            p,
        );
        metric_cell(ui, "THROUGHPUT", &speed_val, p.text, p);
        metric_cell(ui, "DEVICES", &devices_val, p.text, p);
        metric_cell(ui, "RELAY CACHE", &cache_val, p.text, p);
    })
    .w_frac(1.0)
    .p(12.0)
    .gap(16.0)
    .bg(p.surface)
    .bd(1.0, p.border)
    .r(6.0)
    .justify_between();
}

fn metric_cell(ui: &mut UiContext, label: &str, value: &str, color: lumenic::Color, p: &Palette) {
    ui.col(|ui| {
        ui.txt(label).sz(10.0).fg(p.muted);
        ui.txt(value).sz(12.5).bold().fg(color);
    })
    .gap(2.0);
}

fn render_ignore_editor(
    ui: &mut UiContext,
    editor: &mut IgnoreEditorState,
    sync: &SyncHandle,
    p: &Palette,
) {
    ui.divider().bg(p.border);

    ui.col(|ui| {
        ui.txt("Project Presets (synced to all devices):")
            .sz(11.5)
            .bold()
            .fg(p.text);

        ui.row(|ui| {
            for preset in IGNORE_PRESETS {
                let enabled = preset_is_enabled(&editor.patterns, preset);
                if ui
                    .btn(preset.name)
                    .sz(11.0)
                    .px(9.0)
                    .py(4.0)
                    .bg(if enabled { p.accent } else { p.bg })
                    .bd(1.0, if enabled { p.accent } else { p.border })
                    .fg(if enabled { p.bg } else { p.muted })
                    .clicked()
                {
                    toggle_preset_patterns(&mut editor.patterns, preset, !enabled);
                    editor.test_cache_dirty = true;
                }
            }
        })
        .gap(6.0)
        .wrap();

        ui.row(|ui| {
            ui.input("ignore_new_pat", &mut editor.new_pattern)
                .w_frac(1.0)
                .bg(p.bg)
                .bd(1.0, p.border)
                .px(8.0)
                .py(5.0);
            if ui
                .btn("Add Pattern")
                .sz(11.5)
                .px(10.0)
                .py(5.0)
                .bg(p.surface_alt)
                .bd(1.0, p.border)
                .fg(p.text)
                .clicked()
            {
                let pat = editor.new_pattern.text().trim().to_string();
                if !pat.is_empty() && !editor.patterns.iter().any(|x| x == &pat) {
                    editor.patterns.push(pat);
                    editor.new_pattern.set_text("");
                    editor.test_cache_dirty = true;
                }
            }
        })
        .w_frac(1.0)
        .gap(6.0)
        .align_center();

        if !editor.patterns.is_empty() {
            let mut remove_idx: Option<usize> = None;
            ui.row(|ui| {
                for (idx, pat) in editor.patterns.iter().enumerate() {
                    if ui
                        .btn(&format!("{pat} x"))
                        .sz(10.5)
                        .px(7.0)
                        .py(3.0)
                        .bg(p.bg)
                        .bd(1.0, p.border)
                        .fg(p.muted)
                        .clicked()
                    {
                        remove_idx = Some(idx);
                    }
                }
            })
            .gap(4.0)
            .wrap();
            if let Some(idx) = remove_idx {
                editor.patterns.remove(idx);
                editor.test_cache_dirty = true;
            }
        }

        // Cached Test Path preview
        ui.row(|ui| {
            ui.txt("Test path:").sz(11.5).fg(p.muted);
            ui.input("ignore_test_path", &mut editor.test_path)
                .w(240.0)
                .bg(p.bg)
                .bd(1.0, p.border)
                .px(8.0)
                .py(4.0);
            let cur_test = editor.test_path.text().to_string();
            if editor.test_cache_dirty || cur_test != editor.last_tested_path {
                editor.last_tested_path = cur_test.clone();
                editor.test_cache_dirty = false;
                editor.last_test_ignored = if cur_test.trim().is_empty() {
                    None
                } else {
                    let filter = IgnoreFilter::from_patterns(&editor.local_path, &editor.patterns);
                    Some(filter.test_path_ignored(&cur_test))
                };
            }
            if let Some(ignored) = editor.last_test_ignored {
                ui.txt(if ignored { "Ignored" } else { "Will Sync" })
                    .sz(11.5)
                    .bold()
                    .fg(if ignored { p.warn_amber } else { p.ok_green });
            }
        })
        .gap(8.0)
        .align_center();

        ui.row(|ui| {
            if ui
                .btn("Save Ignore Rules")
                .sz(11.5)
                .px(12.0)
                .py(5.0)
                .bg(p.ok_green)
                .fg(p.bg)
                .clicked()
            {
                sync.send(SyncCommand::UpdateShareIgnore {
                    share_id: editor.share_id.clone(),
                    patterns: editor.patterns.clone(),
                });
            }
        });
    })
    .w_frac(1.0)
    .p(10.0)
    .gap(8.0)
    .bg(p.surface_alt)
    .r(4.0);
}
