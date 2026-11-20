use deltadrop_common::format_bytes;
use lumenic::{App, UiContext};

use crate::sync::{SyncCommand, SyncHandle, UiSnapshot};
use crate::ui::theme::Palette;
use crate::ui::topology::render_topology_canvas;
use crate::ui::UiState;

pub fn render_overview(
    ui: &mut UiContext,
    app: &App,
    snap: &UiSnapshot,
    state: &mut UiState,
    sync: &SyncHandle,
) {
    let p = Palette::default();

    // Top 60%: Dynamic Shader Topology Canvas
    render_topology_canvas(ui, snap, &mut state.topology, &mut |folder_id, _peer_id| {
        let dialog = app.pick_folder(&format!("Sync '{folder_id}' to folder"));
        state.map_remote_picker = Some((folder_id.to_string(), dialog));
    });

    ui.divider().bg(p.border);

    // Bottom 40%: 4-Column Open Telemetry Row (no bordered cards, mono numbers)
    let relay_val = if snap.online {
        let ms = snap.relay_latency_ms.unwrap_or(0);
        let tls = if snap
            .active_config
            .as_ref()
            .is_some_and(|c| c.relay_url.starts_with("https://"))
        {
            "TLS"
        } else {
            "HTTP"
        };
        if ms > 0 {
            format!("{ms} ms  ·  {tls}")
        } else {
            format!("Connected  ·  {tls}")
        }
    } else {
        "Offline".to_string()
    };

    let throughput_val = format!(
        "↑ {}/s   ↓ {}/s",
        format_bytes(snap.upload_bps),
        format_bytes(snap.download_bps)
    );

    let folder_count = snap
        .active_config
        .as_ref()
        .map(|c| c.folders.len())
        .unwrap_or(0);
    let workspace_val = format!("{folder_count} folders");

    let cache_used = format_bytes(snap.cache_status.used_bytes);
    let cache_max = if snap.cache_status.max_bytes > 0 {
        format_bytes(snap.cache_status.max_bytes)
    } else {
        format_bytes(snap.relay_status.max_bytes)
    };
    let cache_val = format!("{cache_used} / {cache_max}");

    ui.row(|ui| {
        telemetry_col(
            ui,
            "RELAY",
            &relay_val,
            if snap.online {
                p.ok_green
            } else {
                p.warn_amber
            },
            &p,
        );
        telemetry_col(ui, "THROUGHPUT", &throughput_val, p.text, &p);
        telemetry_col(ui, "WORKSPACE", &workspace_val, p.text, &p);
        telemetry_col(ui, "TRANSIT CACHE", &cache_val, p.text, &p);
    })
    .w_frac(1.0)
    .px(24.0)
    .py(20.0)
    .gap(24.0)
    .justify_between();

    ui.divider().bg(p.border);

    // Single-Line Contextual Activity / Conflict Bar
    ui.col(|ui| {
        if !snap.conflicts.is_empty() {
            ui.row(|ui| {
                ui.txt(&format!(
                    "{} conflict(s) require resolution",
                    snap.conflicts.len()
                ))
                .sz(12.5)
                .fg(p.warn_amber);

                if ui
                    .btn("Review")
                    .bg(p.surface)
                    .bd(1.0, p.warn_amber)
                    .fg(p.warn_amber)
                    .sz(12.0)
                    .px(10.0)
                    .py(4.0)
                    .clicked()
                {
                    state.show_conflict_modal = true;
                }
            })
            .w_frac(1.0)
            .justify_between()
            .align_center();
        } else if snap.pending_uploads > 0 || snap.pending_downloads > 0 {
            let latest = snap
                .activity
                .first()
                .map(|a| format!("{} — {}", a.rel_path, a.detail))
                .unwrap_or_else(|| "Syncing changes...".to_string());
            ui.row(|ui| {
                ui.txt(&latest).sz(12.0).fg(p.text);
                ui.txt(&format!(
                    "↑ {}   ↓ {}",
                    snap.pending_uploads, snap.pending_downloads
                ))
                .sz(12.0)
                .mono()
                .fg(p.ok_green);
            })
            .w_frac(1.0)
            .justify_between();

            ui.row(|ui| {
                ui.col(|_| {}).w_frac(0.45).h(2.0).bg(p.ok_green);
            })
            .w_frac(1.0)
            .h(2.0)
            .bg(p.border);
        } else if let Some(ref err) = snap.last_error {
            ui.txt(err).sz(12.0).fg(p.err_red);
        } else {
            let status_line = if snap.paused {
                "Sync paused"
            } else {
                "All folders synchronized  ·  Up to date"
            };
            ui.txt(status_line).sz(12.0).fg(p.muted);
        }
    })
    .w_frac(1.0)
    .px(24.0)
    .py(14.0)
    .gap(8.0);

    // Conflict Resolution Modal
    if state.show_conflict_modal && !snap.conflicts.is_empty() {
        let mut open = state.show_conflict_modal;
        ui.modal("conflict-modal", &mut open, |ui| {
            ui.col(|ui| {
                ui.txt("CONFLICT RESOLUTION").sz(13.0).bold().fg(p.text);
                ui.divider().bg(p.border);

                for c in &snap.conflicts {
                    ui.col(|ui| {
                        ui.txt(&format!("[{}] {}", c.folder_id, c.rel_path))
                            .sz(12.5)
                            .fg(p.text);
                        ui.txt(&format!("Backup: {} ({})", c.conflict_path, c.time_label))
                            .sz(11.5)
                            .mono()
                            .fg(p.muted);
                        ui.row(|ui| {
                            if ui.btn("Keep Local").sz(11.5).px(8.0).py(4.0).clicked() {
                                let _ = sync.cmd_tx.send(SyncCommand::ResolveConflict {
                                    id: c.id,
                                    keep_conflict_file: false,
                                    folder_id: c.folder_id.clone(),
                                    rel_path: c.rel_path.clone(),
                                    conflict_path: c.conflict_path.clone(),
                                });
                            }
                            if ui
                                .btn("Keep Conflict Copy")
                                .sz(11.5)
                                .px(8.0)
                                .py(4.0)
                                .clicked()
                            {
                                let _ = sync.cmd_tx.send(SyncCommand::ResolveConflict {
                                    id: c.id,
                                    keep_conflict_file: true,
                                    folder_id: c.folder_id.clone(),
                                    rel_path: c.rel_path.clone(),
                                    conflict_path: c.conflict_path.clone(),
                                });
                            }
                            if ui.btn("Dismiss").sz(11.5).px(8.0).py(4.0).clicked() {
                                let _ = sync.cmd_tx.send(SyncCommand::DismissConflict(c.id));
                            }
                        })
                        .gap(8.0);
                    })
                    .w_frac(1.0)
                    .py(8.0)
                    .gap(6.0);
                    ui.divider().bg(p.border);
                }

                if ui.btn("Close").sz(12.0).px(10.0).py(5.0).clicked() {
                    state.show_conflict_modal = false;
                }
            })
            .w(540.0)
            .p(20.0)
            .gap(10.0)
            .bg(p.surface)
            .bd(1.0, p.border)
            .r(4.0);
        });
        if !open {
            state.show_conflict_modal = false;
        }
    }
}

fn telemetry_col(
    ui: &mut UiContext,
    label: &str,
    value: &str,
    val_color: lumenic::Color,
    p: &Palette,
) {
    ui.col(|ui| {
        ui.txt(label).sz(10.5).tracking(0.08).fg(p.muted);
        ui.txt(value).sz(14.0).mono().fg(val_color);
    })
    .grow(1.0)
    .gap(4.0);
}
