use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: &str = "2";
pub const PROTOCOL_HEADER: &str = "X-DeltaDrop-Protocol";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpType {
    Upsert,
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkRef {
    pub chunk_id: String,
    pub raw_size: u64,
    pub plaintext_blake3: String,
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
pub struct EventsResponse {
    pub pending: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRegistration {
    pub peer_id: String,
    pub workspace_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub workspace_id: String,
    pub last_seen_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingPayload {
    pub relay_url: String,
    pub auth_token: String,
    pub workspace_id: String,
    pub encryption_key: String,
}

impl PairingPayload {
    pub fn encode_pairing_code(&self) -> Result<String, serde_json::Error> {
        let json = serde_json::to_vec(self)?;
        Ok(format!("dd1://{}", encode_base64url(&json)))
    }

    pub fn decode_pairing_code(code: &str) -> Result<Self, String> {
        let trimmed = code.trim();
        let b64 = trimmed
            .strip_prefix("dd1://")
            .ok_or_else(|| "Pairing code must start with dd1://".to_string())?;
        let raw =
            decode_base64url(b64).ok_or_else(|| "Invalid pairing code encoding".to_string())?;
        serde_json::from_slice(&raw).map_err(|e| format!("Invalid pairing payload: {e}"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingDelta {
    pub id: i64,
    pub source_peer: String,
    pub target_peer: String,
    pub folder_id: String,
    pub rel_path: String,
    pub op_type: OpType,
    pub blake3_hash: String,
    #[serde(default)]
    pub base_hash: Option<String>,
    #[serde(default)]
    pub delta_version: u64,
    #[serde(default)]
    pub chunk_ids: Vec<String>,
    pub raw_size: u64,
    pub zst_size: u64,
    pub mtime_ms: i64,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaUploadMeta {
    pub source_peer: String,
    pub target_peer: String,
    pub folder_id: String,
    pub rel_path: String,
    #[serde(default = "default_upsert")]
    pub op_type: OpType,
    pub blake3_hash: String,
    #[serde(default)]
    pub base_hash: Option<String>,
    #[serde(default)]
    pub delta_version: u64,
    #[serde(default)]
    pub chunk_ids: Vec<String>,
    pub raw_size: u64,
    pub mtime_ms: i64,
}

fn default_upsert() -> OpType {
    OpType::Upsert
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub source_peer: String,
    pub target_peer: String,
    pub folder_id: String,
    pub rel_path: String,
    pub op_type: OpType,
    pub plaintext_blake3: String,
    pub raw_size: u64,
    pub mtime_ms: i64,
    pub mode_bits: u32,
    pub base_hash: Option<String>,
    pub delta_version: u64,
    pub payload: Vec<u8>,
    #[serde(default)]
    pub chunks: Vec<ChunkRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteRequest {
    pub source_peer: String,
    pub target_peer: String,
    pub folder_id: String,
    pub rel_path: String,
    #[serde(default)]
    pub base_hash: Option<String>,
    pub mtime_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckRequest {
    pub target_peer: String,
    pub delta_id: i64,
    pub verified_blake3: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RelayStatus {
    pub queued_count: u64,
    pub used_bytes: u64,
    pub max_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderIndexPayload {
    pub source_peer: String,
    pub folder_id: String,
    pub subdirs: Vec<String>,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullRequest {
    pub source_peer: String,
    pub target_peer: String,
    pub folder_id: String,
    pub subdir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingPullRequest {
    pub id: i64,
    pub source_peer: String,
    pub target_peer: String,
    pub folder_id: String,
    pub subdir: String,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckPullRequest {
    pub target_peer: String,
    pub request_id: i64,
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

pub fn encode_meta_header(meta: &DeltaUploadMeta) -> Result<String, serde_json::Error> {
    let json = serde_json::to_vec(meta)?;
    Ok(encode_base64url(&json))
}

pub fn decode_meta_header(raw: &str) -> Result<DeltaUploadMeta, String> {
    let trimmed = raw.trim();
    if trimmed.starts_with('{') {
        return serde_json::from_str(trimmed)
            .map_err(|e| format!("Invalid X-Delta-Meta JSON: {e}"));
    }
    let decoded =
        decode_base64url(trimmed).ok_or_else(|| "Invalid X-Delta-Meta base64url".to_string())?;
    serde_json::from_slice(&decoded).map_err(|e| format!("Invalid X-Delta-Meta payload: {e}"))
}

/// Constant-time comparison of two byte slices by comparing fixed-size 32-byte BLAKE3 digests.
/// Avoids leaking secret length via early return.
pub fn constant_time_eq_blake3(a: &[u8], b: &[u8]) -> bool {
    let ha = blake3::hash(a);
    let hb = blake3::hash(b);
    let mut diff = 0u8;
    for (x, y) in ha.as_bytes().iter().zip(hb.as_bytes().iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Derives a scoped per-peer bearer token from the relay's master auth token.
pub fn derive_peer_token(master_token: &str, peer_id: &str) -> String {
    let key = blake3::derive_key("deltadrop-peer-token-v1", master_token.as_bytes());
    let mac = blake3::keyed_hash(&key, peer_id.as_bytes()).to_hex();
    format!("ddp_{peer_id}_{mac}")
}

/// Verifies a scoped `ddp_<peer>_<mac>` token against the master token, returning the `peer_id`.
pub fn verify_peer_token(master_token: &str, candidate: &str) -> Option<String> {
    let rest = candidate.strip_prefix("ddp_")?;
    let (peer_id, _) = rest.rsplit_once('_')?;
    if peer_id.is_empty() {
        return None;
    }
    let expected = derive_peer_token(master_token, peer_id);
    if constant_time_eq_blake3(candidate.as_bytes(), expected.as_bytes()) {
        Some(peer_id.to_string())
    } else {
        None
    }
}

pub const CHUNK_THRESHOLD: u64 = 256 * 1024;
pub const CHUNK_MIN_SIZE: usize = 512 * 1024;
pub const CHUNK_AVG_SIZE: usize = 2 * 1024 * 1024;
pub const CHUNK_MAX_SIZE: usize = 4 * 1024 * 1024;

/// Returns the next FastCDC-style content-defined chunk boundary within `buf`
/// (bounded by `min_size`..=`max_size`, or `buf.len()` if shorter).
pub fn next_fastcdc_boundary(buf: &[u8], min_size: usize, max_size: usize) -> usize {
    let limit = buf.len().min(max_size);
    if limit <= min_size {
        return limit;
    }
    // 2 MiB average -> 21-bit mask (with normalized dual-mask around avg_size)
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
    fn meta_header_roundtrips_unicode() {
        let meta = DeltaUploadMeta {
            source_peer: "desktop".into(),
            target_peer: "laptop".into(),
            folder_id: "notes".into(),
            rel_path: "café/résumé-メモ.pdf".into(),
            op_type: OpType::Upsert,
            blake3_hash: "abc".into(),
            base_hash: Some("def".into()),
            delta_version: 7,
            chunk_ids: Vec::new(),
            raw_size: 42,
            mtime_ms: 12345,
        };
        let encoded = encode_meta_header(&meta).unwrap();
        assert!(encoded.is_ascii());
        let decoded = decode_meta_header(&encoded).unwrap();
        assert_eq!(decoded.rel_path, "café/résumé-メモ.pdf");
        assert_eq!(decoded.base_hash.as_deref(), Some("def"));
    }

    #[test]
    fn pairing_code_roundtrips() {
        let p = PairingPayload {
            relay_url: "https://relay.example.com".into(),
            auth_token: "tok-123".into(),
            workspace_id: "ws-abc".into(),
            encryption_key: "key-xyz".into(),
        };
        let code = p.encode_pairing_code().unwrap();
        assert!(code.starts_with("dd1://"));
        let decoded = PairingPayload::decode_pairing_code(&code).unwrap();
        assert_eq!(decoded.relay_url, p.relay_url);
        assert_eq!(decoded.auth_token, p.auth_token);
        assert_eq!(decoded.workspace_id, p.workspace_id);
        assert_eq!(decoded.encryption_key, p.encryption_key);
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
}

pub const GATE_HEADER: &str = "X-DeltaDrop-Gate";
pub const MAX_CHUNK_HTTP_BYTES: usize = 16 * 1024 * 1024;

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
pub struct RegisterDeviceRequest {
    pub device_id: String,
    pub encrypted_name: String,
    pub os: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderManifestPayload {
    pub device_id: String,
    pub folder_id: String,
    pub encrypted_meta_b64: String,
    pub version: u64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRequestPayload {
    pub source_device_id: String,
    pub target_device_id: String,
    pub folder_id: String,
    pub chunk_hashes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingSyncRequest {
    pub id: i64,
    pub source_device_id: String,
    pub target_device_id: String,
    pub folder_id: String,
    pub chunk_hashes: Vec<String>,
    pub status: String,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkAckRequest {
    pub device_id: String,
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
pub enum WsSignal {
    SyncRequest {
        request_id: i64,
        folder_id: String,
        target_device_id: String,
        chunk_hashes: Vec<String>,
    },
    ChunkAvailable {
        folder_id: String,
        chunk_id: String,
    },
    ManifestUpdated {
        device_id: String,
        folder_id: String,
        version: u64,
    },
}
