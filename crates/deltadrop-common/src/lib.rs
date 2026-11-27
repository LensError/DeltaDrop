use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: &str = "3";
pub const PROTOCOL_HEADER: &str = "X-DeltaDrop-Protocol";
pub const GATE_HEADER: &str = "X-DeltaDrop-Gate";
pub const MAX_CHUNK_HTTP_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_MANIFEST_HTTP_BYTES: usize = 16 * 1024 * 1024;

pub const CHUNK_MIN_SIZE: usize = 512 * 1024;
pub const CHUNK_AVG_SIZE: usize = 2 * 1024 * 1024;
pub const CHUNK_MAX_SIZE: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    Admin,
    User,
}

impl UserRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            UserRole::Admin => "admin",
            UserRole::User => "user",
        }
    }

    pub fn from_db(s: &str) -> Self {
        if s.eq_ignore_ascii_case("admin") {
            UserRole::Admin
        } else {
            UserRole::User
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthParamsResponse {
    pub username: String,
    pub salt_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub auth_key_hex: String,
    pub device_id: String,
    #[serde(default)]
    pub encrypted_device_name: String,
    #[serde(default)]
    pub os: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub user_id: String,
    pub username: String,
    pub role: UserRole,
    pub expires_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminUserInfo {
    pub id: String,
    pub username: String,
    pub role: UserRole,
    pub disabled: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub salt_hex: String,
    pub auth_key_hex: String,
    pub role: UserRole,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateUserRequest {
    #[serde(default)]
    pub disabled: Option<bool>,
    #[serde(default)]
    pub role: Option<UserRole>,
    #[serde(default)]
    pub salt_hex: Option<String>,
    #[serde(default)]
    pub auth_key_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: String,
    pub encrypted_name: String,
    pub os: String,
    pub last_seen_ms: i64,
    pub online: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplaceDeviceRequest {
    pub new_device_id: String,
    pub encrypted_name: String,
    pub os: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRef {
    pub chunk_id: String,
    pub raw_size: u64,
    pub plaintext_blake3: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestFileEntry {
    pub rel_path: String,
    pub size: u64,
    pub mtime_ms: i64,
    pub mode_bits: u32,
    pub blake3_hash: String,
    pub rev: u64,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default)]
    pub chunks: Vec<ChunkRef>,
}

/// Decrypted share manifest payload stored inside `ShareRecord.encrypted_manifest_b64`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareManifest {
    pub share_id: String,
    pub name: String,
    pub owner_device_id: String,
    #[serde(default)]
    pub ignore_patterns: Vec<String>,
    #[serde(default)]
    pub files: Vec<ManifestFileEntry>,
    #[serde(default)]
    pub empty_dirs: Vec<String>,
}

impl ShareManifest {
    pub fn active_file_count(&self) -> usize {
        self.files.iter().filter(|f| !f.deleted).count()
    }

    pub fn active_total_bytes(&self) -> u64 {
        self.files
            .iter()
            .filter(|f| !f.deleted)
            .map(|f| f.size)
            .sum()
    }
}

/// Wire representation of a user's encrypted share stored on the relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareRecord {
    pub share_id: String,
    pub owner_device_id: String,
    pub last_writer_device_id: String,
    pub version: u64,
    pub encrypted_manifest_b64: String,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutShareRequest {
    pub device_id: String,
    pub owner_device_id: String,
    pub base_version: u64,
    pub encrypted_manifest_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutShareResponse {
    pub version: u64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HasChunksRequest {
    pub chunk_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HasChunksResponse {
    pub missing: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReseedRequest {
    pub requester_device_id: String,
    pub chunk_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingReseed {
    pub share_id: String,
    pub chunk_ids: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RelayCacheStatus {
    pub used_bytes: u64,
    pub max_bytes: u64,
    pub chunk_count: u64,
    pub ttl_hours: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsClientMsg {
    Auth {
        token: String,
        device_id: String,
        #[serde(default)]
        gate: Option<String>,
    },
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsServerMsg {
    AuthOk,
    AuthError {
        message: String,
    },
    ShareUpdated {
        share_id: String,
        version: u64,
        writer_device_id: String,
    },
    ShareDeleted {
        share_id: String,
    },
    ReseedRequested {
        share_id: String,
        chunk_ids: Vec<String>,
    },
    DeviceStatus {
        device_id: String,
        online: bool,
    },
    Pong,
}

pub fn is_valid_chunk_id(chunk_id: &str) -> bool {
    (16..=128).contains(&chunk_id.len()) && chunk_id.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn is_valid_share_id(share_id: &str) -> bool {
    let trimmed = share_id.trim();
    !trimmed.is_empty()
        && trimmed.len() <= 96
        && trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn is_windows_reserved_name(seg: &str) -> bool {
    let base = seg.split('.').next().unwrap_or(seg);
    matches!(
        base.to_ascii_uppercase().as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

/// Normalizes a relative path to forward slashes and rejects traversal, absolute paths,
/// control chars, and Windows-illegal filenames/reserved names.
pub fn normalize_rel_path(raw: &str) -> Option<String> {
    let replaced = raw.replace('\\', "/");
    let trimmed = replaced.trim_start_matches("./");
    if trimmed.is_empty() || trimmed.starts_with('/') {
        return None;
    }
    let mut parts = Vec::new();
    for seg in trimmed.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return None;
        }
        if seg.ends_with('.') || seg.ends_with(' ') {
            return None;
        }
        if seg
            .chars()
            .any(|c| c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
        {
            return None;
        }
        if is_windows_reserved_name(seg) {
            return None;
        }
        parts.push(seg);
    }
    Some(parts.join("/"))
}

/// Sanitizes a human share folder name into a safe single directory component.
pub fn sanitize_folder_name(raw: &str) -> String {
    let cleaned: String = raw
        .trim()
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '/' | '\\' | '<' | '>' | ':' | '"' | '|' | '?' | '*') {
                '_'
            } else {
                c
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches(|c| c == '.' || c == ' ');
    if trimmed.is_empty() || is_windows_reserved_name(trimmed) {
        "DeltaDrop-Share".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Parses `username@relay-host` into `(username, relay_url)`.
/// Defaults to `https://` unless the host already includes `http://` or `https://`.
pub fn parse_user_relay_input(input: &str) -> Option<(String, String)> {
    let trimmed = input.trim();
    let (user, host) = trimmed.split_once('@')?;
    let user = user.trim();
    let host = host.trim();
    if user.is_empty() || host.is_empty() {
        return None;
    }
    let url = if host.starts_with("http://") || host.starts_with("https://") {
        host.to_string()
    } else {
        format!("https://{host}")
    };
    Some((user.to_string(), url))
}

/// Domain-separated key derivation from a 256-bit `master_secret`.
/// `auth_key` is sent to the relay for Argon2id verification; `vault_key` never leaves the client.
pub fn derive_auth_and_vault_keys(master_secret: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let auth_key = blake3::derive_key("deltadrop-auth-v1", master_secret);
    let vault_key = blake3::derive_key("deltadrop-vault-v1", master_secret);
    (auth_key, vault_key)
}

/// Constant-time comparison of two byte slices via fixed-size 32-byte BLAKE3 digests.
pub fn constant_time_eq_blake3(a: &[u8], b: &[u8]) -> bool {
    let ha = blake3::hash(a);
    let hb = blake3::hash(b);
    let mut diff = 0u8;
    for (x, y) in ha.as_bytes().iter().zip(hb.as_bytes().iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

pub fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let (chunks, _) = s.as_bytes().as_chunks::<2>();
    for (i, chunk) in chunks.iter().enumerate() {
        let hex_str = std::str::from_utf8(chunk).ok()?;
        out[i] = u8::from_str_radix(hex_str, 16).ok()?;
    }
    Some(out)
}

const B64URL_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn encode_base64url(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64URL_TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(B64URL_TABLE[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64URL_TABLE[((triple >> 6) & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64URL_TABLE[(triple & 0x3F) as usize] as char);
        }
    }
    out
}

pub fn decode_base64url(input: &str) -> Option<Vec<u8>> {
    let bytes = input.trim_end_matches('=').as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let decode_val = |b: u8| -> Option<u32> {
        match b {
            b'A'..=b'Z' => Some((b - b'A') as u32),
            b'a'..=b'z' => Some((b - b'a' + 26) as u32),
            b'0'..=b'9' => Some((b - b'0' + 52) as u32),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    };
    for chunk in bytes.chunks(4) {
        let v0 = decode_val(chunk[0])?;
        let v1 = decode_val(chunk[1])?;
        let v2 = if chunk.len() > 2 {
            decode_val(chunk[2])?
        } else {
            0
        };
        let v3 = if chunk.len() > 3 {
            decode_val(chunk[3])?
        } else {
            0
        };
        let triple = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;
        out.push(((triple >> 16) & 0xFF) as u8);
        if chunk.len() > 2 {
            out.push(((triple >> 8) & 0xFF) as u8);
        }
        if chunk.len() > 3 {
            out.push((triple & 0xFF) as u8);
        }
    }
    Some(out)
}

/// Returns the next FastCDC-style content-defined chunk boundary within `buf`
/// (bounded by `min_size`..=`max_size`, or `buf.len()` if shorter).
pub fn next_fastcdc_boundary(buf: &[u8], min_size: usize, max_size: usize) -> usize {
    let limit = buf.len().min(max_size);
    if limit <= min_size {
        return limit;
    }
    let mask_s: u64 = (1u64 << 22) - 1;
    let mask_l: u64 = (1u64 << 20) - 1;
    let normal_point = CHUNK_AVG_SIZE.min(limit);
    let mut fp: u64 = 0;

    for (i, &b) in buf[min_size..normal_point].iter().enumerate() {
        let g = (b as u64)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .rotate_left(13);
        fp = (fp << 1).wrapping_add(g);
        if (fp & mask_s) == 0 {
            return min_size + i + 1;
        }
    }
    for (i, &b) in buf[normal_point..limit].iter().enumerate() {
        let g = (b as u64)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .rotate_left(13);
        fp = (fp << 1).wrapping_add(g);
        if (fp & mask_l) == 0 {
            return normal_point + i + 1;
        }
    }
    limit
}

pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let b = bytes as f64;
    if b >= GB {
        format!("{:.2} GB", b / GB)
    } else if b >= MB {
        format!("{:.1} MB", b / MB)
    } else if b >= KB {
        format!("{:.1} KB", b / KB)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_path_traversal_and_normalizes_slashes() {
        assert_eq!(
            normalize_rel_path(r"Assets\Scripts\Player.cs"),
            Some("Assets/Scripts/Player.cs".to_string())
        );
        assert_eq!(normalize_rel_path("../secret"), None);
        assert_eq!(normalize_rel_path("a/../b"), None);
        assert_eq!(normalize_rel_path("/etc/passwd"), None);
        assert_eq!(normalize_rel_path("C:/Windows"), None);
        assert_eq!(normalize_rel_path("dir/CON.txt"), None);
        assert_eq!(normalize_rel_path("nul"), None);
        assert_eq!(normalize_rel_path("bad<name>.txt"), None);
        assert_eq!(normalize_rel_path("trailing."), None);
        assert_eq!(normalize_rel_path("trailing "), None);
        assert_eq!(normalize_rel_path("a\0b"), None);
        assert_eq!(
            normalize_rel_path("docs/café-メモ.md"),
            Some("docs/café-メモ.md".to_string())
        );
    }

    #[test]
    fn sanitizes_folder_names() {
        assert_eq!(sanitize_folder_name("My Unity Game"), "My Unity Game");
        assert_eq!(sanitize_folder_name("a/b:c*d"), "a_b_c_d");
        assert_eq!(sanitize_folder_name("CON"), "DeltaDrop-Share");
        assert_eq!(sanitize_folder_name("   ...  "), "DeltaDrop-Share");
    }

    #[test]
    fn parses_user_relay_shorthand() {
        assert_eq!(
            parse_user_relay_input("pauli@sync.example.com"),
            Some(("pauli".to_string(), "https://sync.example.com".to_string()))
        );
        assert_eq!(
            parse_user_relay_input("  alice@http://100.64.0.1:8787 "),
            Some(("alice".to_string(), "http://100.64.0.1:8787".to_string()))
        );
        assert_eq!(parse_user_relay_input("pauli"), None);
        assert_eq!(parse_user_relay_input("@example.com"), None);
        assert_eq!(parse_user_relay_input("pauli@"), None);
    }

    #[test]
    fn base64url_roundtrips() {
        let data = b"hello delta drop \x00\xff\xfe binary";
        let enc = encode_base64url(data);
        assert_eq!(decode_base64url(&enc).as_deref(), Some(data.as_slice()));
    }
}
