use std::path::Path;

use lumenic::{Color, Theme};

#[derive(Clone, Copy)]
pub struct Palette {
    pub bg: Color,
    pub surface: Color,
    pub surface_alt: Color,
    pub border: Color,
    pub muted: Color,
    pub offline_slate: Color,
    pub ok_green: Color,
    pub warn_amber: Color,
    pub err_red: Color,
    pub accent: Color,
    pub text: Color,
}

impl Default for Palette {
    fn default() -> Self {
        Self {
            bg: Color::from_hex(0x0B0D10),
            surface: Color::from_hex(0x12151B),
            surface_alt: Color::from_hex(0x181C24),
            border: Color::from_hex(0x1F242D),
            muted: Color::from_hex(0x8B949E),
            offline_slate: Color::from_hex(0x4A5568),
            ok_green: Color::from_hex(0x38D39F),
            warn_amber: Color::from_hex(0xE5A93C),
            err_red: Color::from_hex(0xEF4444),
            accent: Color::from_hex(0xE5A93C),
            text: Color::from_hex(0xE6EDF3),
        }
    }
}

pub fn dark_theme() -> Theme {
    let p = Palette::default();
    Theme {
        background: p.bg,
        surface: p.surface,
        surface_alt: p.surface_alt,
        primary: p.accent,
        on_primary: Color::from_hex(0x0B0D10),
        text: p.text,
        text_muted: p.muted,
        border: p.border,
        focus_ring: p.accent,
        focus_ring_width: 1.5,
        focus_ring_offset: 2.0,
        radius: 4.0,
        font_size: 13.0,
        is_dark: true,
        ripple: false,
    }
}

#[allow(dead_code)]
pub fn is_insecure_http_url(url: &str) -> bool {
    let trimmed = url.trim();
    let Some(rest) = trimmed.strip_prefix("http://") else {
        return false;
    };
    let host_port = rest.split('/').next().unwrap_or("");
    let host = if let Some(h) = host_port.strip_prefix('[') {
        h.split(']').next().unwrap_or("")
    } else {
        host_port.split(':').next().unwrap_or("")
    };
    if matches!(host, "" | "localhost" | "127.0.0.1" | "::1") {
        return false;
    }
    if host.ends_with(".ts.net") {
        return false;
    }
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        let octets = ip.octets();
        if octets[0] == 100 && (64..=127).contains(&octets[1]) {
            return false;
        }
    }
    true
}

#[allow(dead_code)]
pub fn open_folder_in_os(path: &Path) {
    let dir = if path.is_file() {
        path.parent().unwrap_or(path)
    } else {
        path
    };
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("explorer").arg(dir).spawn();
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(dir).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let _ = std::process::Command::new("xdg-open").arg(dir).spawn();
}
