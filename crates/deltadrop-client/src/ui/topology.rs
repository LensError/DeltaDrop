use std::collections::HashMap;

use lumenic::{Rect, UiContext};

use crate::sync::UiSnapshot;
use crate::ui::theme::Palette;

const MAX_SHADER_PEERS: usize = 8;

const TOPOLOGY_FRAG_GLSL: &str = r#"
in vec2 v_uv;
out vec4 frag_color;

uniform vec4 u_rect;
uniform vec2 u_viewport;
uniform vec2 u_resolution;
uniform float u_time;
uniform vec2 u_pointer;
uniform vec2 u_scroll;
uniform float u_uniforms[38];

float sd_segment(vec2 p, vec2 a, vec2 b) {
    vec2 pa = p - a, ba = b - a;
    float h = clamp(dot(pa, ba) / max(dot(ba, ba), 1e-6), 0.0, 1.0);
    return length(pa - ba * h);
}

// Evaluates quadratic Bezier distance via 16-segment polyline approximation
float sd_qbezier(vec2 p, vec2 a, vec2 b, vec2 c, out float best_t) {
    float min_d = 1e6;
    best_t = 0.0;
    vec2 prev = a;
    for (int i = 1; i <= 16; i++) {
        float t = float(i) / 16.0;
        float it = 1.0 - t;
        vec2 cur = it * it * a + 2.0 * it * t * b + t * t * c;
        vec2 pa = p - prev, ba = cur - prev;
        float h = clamp(dot(pa, ba) / max(dot(ba, ba), 1e-6), 0.0, 1.0);
        float d = length(pa - ba * h);
        if (d < min_d) {
            min_d = d;
            best_t = (float(i - 1) + h) / 16.0;
        }
        prev = cur;
    }
    return min_d;
}

void main() {
    float aspect = u_resolution.x / max(u_resolution.y, 1.0);
    vec2 p = vec2(v_uv.x * aspect, v_uv.y);
    vec2 relay = vec2(0.5 * aspect, 0.46);
    vec2 local_pc = vec2(0.5 * aspect, 0.82);

    vec3 col = vec3(0.043, 0.051, 0.063); // #0B0D10
    vec3 emerald = vec3(0.220, 0.827, 0.624); // #38D39F
    vec3 amber = vec3(0.898, 0.663, 0.235); // #E5A93C
    vec3 slate = vec3(0.290, 0.333, 0.408); // #4A5568
    vec3 hairline = vec3(0.122, 0.141, 0.176); // #1F242D

    // Subtle concentric radar rings around relay
    float r_dist = length(p - relay);
    for (int r = 1; r <= 3; r++) {
        float rad = float(r) * 0.16;
        float ring = smoothstep(0.0025, 0.0, abs(r_dist - rad));
        col = mix(col, hairline, ring * 0.45);
    }

    float peer_count = u_uniforms[0];
    float up_int = u_uniforms[1];
    float down_int = u_uniforms[2];
    float queued_pull = u_uniforms[3];
    float hovered = u_uniforms[4];
    float relay_online = u_uniforms[5];

    // Local PC <-> Relay link
    vec2 ctrl_local = vec2(0.5 * aspect + 0.04, 0.64);
    float bt;
    float d_local_edge = sd_qbezier(p, local_pc, ctrl_local, relay, bt);
    float edge_mask = smoothstep(0.0035, 0.0008, d_local_edge);
    vec3 local_edge_col = (hovered == 1.0 || hovered == 0.0) ? emerald * 0.8 : hairline * 1.4;
    col = mix(col, local_edge_col, edge_mask * 0.8);

    if (up_int > 0.01 || down_int > 0.01) {
        float speed = 1.2 + (up_int + down_int) * 2.5;
        float pulse = pow(max(0.0, sin((bt - u_time * speed) * 18.0)), 6.0);
        col += emerald * pulse * edge_mask * (0.4 + 0.6 * max(up_int, down_int));
    } else if (queued_pull > 0.5) {
        float pulse = 0.5 + 0.5 * sin(u_time * 2.4 - bt * 8.0);
        col += amber * pulse * edge_mask * 0.75;
    }

    // Peer <-> Relay links
    int count = int(min(peer_count, 8.0));
    for (int i = 0; i < 8; i++) {
        if (i >= count) break;
        int base = 6 + i * 4;
        vec2 peer = vec2(u_uniforms[base] * aspect, u_uniforms[base + 1]);
        float p_online = u_uniforms[base + 2];
        float p_active = u_uniforms[base + 3];

        vec2 mid = 0.5 * (peer + relay);
        vec2 perp = normalize(vec2(-(relay.y - peer.y), relay.x - peer.x) + vec2(1e-4, 0.0));
        vec2 ctrl = mid + perp * 0.06;
        float pt;
        float d_edge = sd_qbezier(p, peer, ctrl, relay, pt);
        float em = smoothstep(0.003, 0.0008, d_edge);
        bool is_hov = (abs(hovered - float(i + 2)) < 0.1) || (abs(hovered) < 0.1);
        vec3 ec = p_online > 0.5 ? (is_hov ? emerald : hairline * 1.5) : slate * 0.5;
        col = mix(col, ec, em * (is_hov ? 0.9 : 0.65));

        if (p_active > 0.5 && p_online > 0.5) {
            float pulse = pow(max(0.0, sin((pt - u_time * 2.2) * 16.0)), 6.0);
            col += emerald * pulse * em * 0.85;
        }
    }

    // Relay node (center)
    vec3 r_col = relay_online > 0.5 ? emerald : amber;
    float r_glow = exp(-r_dist * 18.0) * 0.32;
    col += r_col * r_glow;
    float r_core = smoothstep(0.024, 0.020, r_dist);
    float r_ring = smoothstep(0.003, 0.0008, abs(r_dist - 0.038));
    col = mix(col, r_col, r_core);
    col = mix(col, r_col, r_ring * 0.8);

    // Local PC node (double-ring SDF)
    float l_dist = length(p - local_pc);
    col += emerald * exp(-l_dist * 22.0) * 0.25;
    float l_core = smoothstep(0.018, 0.014, l_dist);
    float l_ring1 = smoothstep(0.0025, 0.0007, abs(l_dist - 0.028));
    float l_ring2 = smoothstep(0.002, 0.0007, abs(l_dist - 0.039));
    col = mix(col, emerald, l_core);
    col = mix(col, emerald, max(l_ring1, l_ring2 * 0.65));

    // Peer nodes
    for (int i = 0; i < 8; i++) {
        if (i >= count) break;
        int base = 6 + i * 4;
        vec2 peer = vec2(u_uniforms[base] * aspect, u_uniforms[base + 1]);
        float p_online = u_uniforms[base + 2];
        vec2 d = p - peer;
        float dist = length(d);
        bool is_hov = abs(hovered - float(i + 2)) < 0.1;

        if (p_online > 0.5) {
            col += emerald * exp(-dist * 24.0) * (is_hov ? 0.42 : 0.22);
            float core = smoothstep(0.016, 0.012, dist);
            float ring = smoothstep(0.0025, 0.0007, abs(dist - 0.027));
            col = mix(col, emerald, core);
            col = mix(col, emerald, ring * (is_hov ? 1.0 : 0.7));
        } else {
            float angle = atan(d.y, d.x);
            float dash = step(0.0, sin(angle * 8.0));
            float core = smoothstep(0.014, 0.010, dist);
            float ring = smoothstep(0.0025, 0.0007, abs(dist - 0.026)) * dash;
            col = mix(col, slate, core * 0.85);
            col = mix(col, slate, ring * 0.85);
        }
    }

    frag_color = vec4(col, 1.0);
}
"#;

#[derive(Default)]
pub struct TopologyState {
    pub node_positions: HashMap<String, (f32, f32)>,
    pub hovered_node: Option<String>,
    pub selected_peer: Option<String>,
    pub last_rect: Option<Rect>,
}

#[derive(Clone)]
struct NodeHit {
    id: String,
    label: String,
    nx: f32,
    ny: f32,
    online: bool,
    shared_folders: usize,
    #[allow(dead_code)]
    last_seen_ms: i64,
}

pub fn render_topology_canvas(
    ui: &mut UiContext,
    snap: &UiSnapshot,
    state: &mut TopologyState,
    on_sync_folder: &mut dyn FnMut(&str, &str),
) {
    let p = Palette::default();

    // Build peer list excluding local device
    let peers: Vec<_> = snap
        .devices
        .iter()
        .filter(|d| d.device_id != snap.peer_id)
        .take(MAX_SHADER_PEERS)
        .collect();

    // Smoothly interpolate peer positions around the relay
    let count = peers.len().max(1);
    let mut hits = Vec::with_capacity(peers.len() + 2);
    hits.push(NodeHit {
        id: "__relay__".to_string(),
        label: "RELAY".to_string(),
        nx: 0.5,
        ny: 0.46,
        online: snap.online,
        shared_folders: 0,
        last_seen_ms: 0,
    });
    hits.push(NodeHit {
        id: "__local__".to_string(),
        label: "THIS PC".to_string(),
        nx: 0.5,
        ny: 0.82,
        online: true,
        shared_folders: snap
            .active_config
            .as_ref()
            .map(|c| c.folders.len())
            .unwrap_or(0),
        last_seen_ms: 0,
    });

    for (idx, dev) in peers.iter().enumerate() {
        let angle = -std::f32::consts::PI * 0.85
            + (idx as f32 / (count as f32)) * std::f32::consts::PI * 1.7;
        let target_x = (0.5 + 0.30 * angle.cos()).clamp(0.12, 0.88);
        let target_y = (0.44 + 0.26 * angle.sin()).clamp(0.14, 0.68);
        let entry = state
            .node_positions
            .entry(dev.device_id.clone())
            .or_insert((target_x, target_y));
        entry.0 += (target_x - entry.0) * 0.14;
        entry.1 += (target_y - entry.1) * 0.14;

        let shared_count = snap
            .unmapped_remote_folders
            .iter()
            .filter(|f| f.source_peer == dev.device_id)
            .count();

        hits.push(NodeHit {
            id: dev.device_id.clone(),
            label: dev.device_id.clone(),
            nx: entry.0,
            ny: entry.1,
            online: dev.online,
            shared_folders: shared_count,
            last_seen_ms: dev.last_seen_ms,
        });
    }

    // Hit-test pointer against last_rect
    state.hovered_node = None;
    let mut hovered_idx: f32 = -1.0;
    if let (Some([px, py]), Some(r)) = (ui.pointer_pos(), state.last_rect) {
        if r.w > 10.0 && r.h > 10.0 && px >= r.x && px <= r.x + r.w && py >= r.y && py <= r.y + r.h
        {
            let ux = (px - r.x) / r.w;
            let uy = (py - r.y) / r.h;
            for (i, h) in hits.iter().enumerate() {
                let dx = (ux - h.nx) * (r.w / r.h);
                let dy = uy - h.ny;
                if (dx * dx + dy * dy).sqrt() < 0.055 {
                    state.hovered_node = Some(h.id.clone());
                    hovered_idx = i as f32;
                    break;
                }
            }
        }
    }

    // Pack uniforms for GLSL shader
    let mut uniforms = [0.0f32; 38];
    uniforms[0] = peers.len() as f32;
    uniforms[1] = (snap.upload_bps as f32 / (10.0 * 1024.0 * 1024.0)).clamp(0.0, 1.0);
    uniforms[2] = (snap.download_bps as f32 / (10.0 * 1024.0 * 1024.0)).clamp(0.0, 1.0);
    uniforms[3] = if snap.pending_downloads > 0 && !snap.online {
        1.0
    } else {
        0.0
    };
    uniforms[4] = hovered_idx;
    uniforms[5] = if snap.online { 1.0 } else { 0.0 };

    for (i, hit) in hits.iter().skip(2).enumerate() {
        let base = 6 + i * 4;
        uniforms[base] = hit.nx;
        uniforms[base + 1] = hit.ny;
        uniforms[base + 2] = if hit.online { 1.0 } else { 0.0 };
        uniforms[base + 3] = if snap.pending_uploads > 0 || snap.pending_downloads > 0 {
            1.0
        } else {
            0.0
        };
    }

    let mut vp_resp = ui
        .viewport("topology_canvas", |canvas, _scene| {
            canvas.shader(0xDD_7090_0001, TOPOLOGY_FRAG_GLSL, &uniforms);

            // CPU-visible fallback primitives for --inspect mode and crisp node markers
            let [w, h] = canvas.size();
            if w > 1.0 && h > 1.0 {
                let relay_pt = [w * 0.5, h * 0.46];
                let local_pt = [w * 0.5, h * 0.82];
                canvas.line(local_pt, relay_pt, 1.0, p.border);
                for hit in hits.iter().skip(2) {
                    let pt = [w * hit.nx, h * hit.ny];
                    let col = if hit.online {
                        p.ok_green
                    } else {
                        p.offline_slate
                    };
                    canvas.line(pt, relay_pt, 1.0, p.border);
                    canvas.circle_stroke(pt, 9.0, 1.5, col);
                }
                canvas.circle_stroke(
                    relay_pt,
                    12.0,
                    1.5,
                    if snap.online {
                        p.ok_green
                    } else {
                        p.warn_amber
                    },
                );
                canvas.circle_stroke(local_pt, 10.0, 1.5, p.ok_green);
            }
        })
        .w_frac(1.0)
        .h(320.0)
        .bg(p.bg);

    state.last_rect = vp_resp.prev_rect();
    if vp_resp.clicked() {
        if let Some(ref hid) = state.hovered_node {
            if hid != "__relay__" && hid != "__local__" {
                state.selected_peer = Some(hid.clone());
            } else {
                state.selected_peer = None;
            }
        } else {
            state.selected_peer = None;
        }
    }

    // Minimal floating hover tooltip or micro-status strip below canvas
    if let Some(ref hid) = state.hovered_node {
        if let Some(hit) = hits.iter().find(|h| &h.id == hid) {
            let status_txt = if hit.online { "Online" } else { "Offline" };
            ui.row(|ui| {
                ui.txt(&format!(
                    "{}  ·  {}  ·  {} shared folders",
                    hit.label, status_txt, hit.shared_folders
                ))
                .sz(11.5)
                .fg(p.muted);
            })
            .px(16.0)
            .py(4.0);
        }
    }

    // Slide-over panel when a peer node is clicked
    if let Some(ref peer_id) = state.selected_peer.clone() {
        let peer_folders: Vec<_> = snap
            .unmapped_remote_folders
            .iter()
            .filter(|f| &f.source_peer == peer_id)
            .cloned()
            .collect();

        ui.col(|ui| {
            ui.row(|ui| {
                ui.txt(&format!("PEER // {}", peer_id))
                    .sz(12.0)
                    .bold()
                    .fg(p.text);
                if ui.btn("Close").sz(11.5).clicked() {
                    state.selected_peer = None;
                }
            })
            .w_frac(1.0)
            .justify_between()
            .align_center();

            ui.divider().bg(p.border);

            if peer_folders.is_empty() {
                ui.txt("No unmapped shared folders on this peer.")
                    .sz(12.0)
                    .fg(p.muted);
            } else {
                for rf in peer_folders {
                    ui.row(|ui| {
                        ui.txt(&format!("{} ({} subdirs)", rf.folder_id, rf.subdir_count))
                            .sz(12.5)
                            .fg(p.text);
                        if ui
                            .btn("Sync to This PC")
                            .bg(p.surface_alt)
                            .bd(1.0, p.ok_green)
                            .fg(p.ok_green)
                            .sz(11.5)
                            .clicked()
                        {
                            on_sync_folder(&rf.folder_id, &rf.source_peer);
                        }
                    })
                    .w_frac(1.0)
                    .py(6.0)
                    .justify_between()
                    .align_center();
                }
            }
        })
        .w_frac(1.0)
        .p(14.0)
        .gap(8.0)
        .bg(p.surface)
        .bd(1.0, p.border)
        .r(4.0);
    }
}
