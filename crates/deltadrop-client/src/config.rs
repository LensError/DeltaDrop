use std::path::{Path, PathBuf};

use deltadrop_common::{sanitize_folder_name, UserRole};
use lumenic::sys::sandbox::SafeDir;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalShareBinding {
    pub share_id: String,
    pub name: String,
    pub local_path: PathBuf,
    #[serde(default)]
    pub ignore_patterns: Vec<String>,
    #[serde(default)]
    pub paused: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub device_id: String,
    #[serde(default)]
    pub device_name: String,
    #[serde(default)]
    pub relay_url: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub user_role: Option<UserRole>,
    #[serde(default)]
    pub session_token: String,
    #[serde(default)]
    pub vault_key_hex: Option<String>,
    #[serde(default = "default_true")]
    pub keep_unlocked: bool,
    #[serde(default)]
    pub network_secret: Option<String>,
    #[serde(default = "default_sync_root")]
    pub default_sync_root: PathBuf,
    #[serde(default = "default_true")]
    pub auto_check_updates: bool,
    #[serde(default)]
    pub manifest_db_path: Option<PathBuf>,
    #[serde(default)]
    pub ignored_share_ids: Vec<String>,
    #[serde(default)]
    pub shares: Vec<LocalShareBinding>,
}

fn default_true() -> bool {
    true
}

pub fn user_home_dir() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn default_sync_root() -> PathBuf {
    user_home_dir().join("DeltaDrop")
}

fn default_hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "My-PC".to_string())
}

pub fn generate_device_id(host: &str) -> String {
    let slug: String = host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = slug.trim_matches('-');
    let prefix = if trimmed.is_empty() { "pc" } else { trimmed };
    let short_uid = &Uuid::new_v4().simple().to_string()[..8];
    format!("{prefix}-{short_uid}")
}

pub fn generate_share_id(folder_name: &str) -> String {
    let slug: String = folder_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = slug.trim_matches('-');
    let prefix = if trimmed.is_empty() {
        "share"
    } else {
        &trimmed[..trimmed.len().min(32)]
    };
    let short_uid = &Uuid::new_v4().simple().to_string()[..8];
    format!("{prefix}-{short_uid}")
}

impl Default for ClientConfig {
    fn default() -> Self {
        let host = default_hostname();
        Self {
            device_id: generate_device_id(&host),
            device_name: host,
            relay_url: "http://127.0.0.1:8787".to_string(),
            username: String::new(),
            user_id: String::new(),
            user_role: None,
            session_token: String::new(),
            vault_key_hex: None,
            keep_unlocked: true,
            network_secret: None,
            default_sync_root: default_sync_root(),
            auto_check_updates: true,
            manifest_db_path: None,
            ignored_share_ids: Vec::new(),
            shares: Vec::new(),
        }
    }
}

/// Returns true if `path` is a raw OS root or standard top-level user folder
/// (such as Desktop, Documents, Downloads, Home root, or drive root) that must
/// never be used directly as a raw sync target without a dedicated subfolder.
pub fn is_dangerous_root_path(path: &Path) -> bool {
    if path.parent().is_none() {
        return true;
    }
    let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if canon.parent().is_none() {
        return true;
    }
    let home = user_home_dir();
    let home_canon = std::fs::canonicalize(&home).unwrap_or_else(|_| home.clone());
    if paths_equal(&canon, &home_canon) {
        return true;
    }
    let protected = [
        "Desktop",
        "Documents",
        "Downloads",
        "Pictures",
        "Videos",
        "Music",
        "OneDrive",
    ];
    for name in protected {
        let candidate = home.join(name);
        let cand_canon = std::fs::canonicalize(&candidate).unwrap_or(candidate);
        if paths_equal(&canon, &cand_canon) {
            return true;
        }
    }
    false
}

fn paths_equal(a: &Path, b: &Path) -> bool {
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    {
        a.to_string_lossy()
            .eq_ignore_ascii_case(&b.to_string_lossy())
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        a == b
    }
}

fn folder_name_matches(a: &str, b: &str) -> bool {
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    {
        a.eq_ignore_ascii_case(b)
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        a == b
    }
}

/// Resolves a user-picked destination directory for a remote share named `share_name`.
/// - Picking `C:\Users\you\Desktop` for `"MyGame"` ALWAYS resolves to `C:\Users\you\Desktop\MyGame`.
/// - Picking an existing folder already named `"MyGame"` (and not a protected OS root) re-links in place.
pub fn resolve_safe_share_target(picked_dir: &Path, share_name: &str) -> PathBuf {
    let safe_name = sanitize_folder_name(share_name);
    let already_named = picked_dir
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|base| folder_name_matches(base, &safe_name));
    if already_named && !is_dangerous_root_path(picked_dir) {
        picked_dir.to_path_buf()
    } else {
        picked_dir.join(safe_name)
    }
}

pub fn validate_share_path(
    target: &Path,
    existing: &[LocalShareBinding],
    ignore_share_id: Option<&str>,
) -> Result<(), String> {
    if target.as_os_str().is_empty() {
        return Err("Folder path cannot be empty".to_string());
    }
    if is_dangerous_root_path(target) {
        return Err(
            "Cannot sync directly into a drive root or Desktop/Documents root; choose a subfolder"
                .to_string(),
        );
    }
    let canon = std::fs::canonicalize(target).unwrap_or_else(|_| target.to_path_buf());
    for s in existing {
        if ignore_share_id == Some(s.share_id.as_str()) {
            continue;
        }
        let ex_canon =
            std::fs::canonicalize(&s.local_path).unwrap_or_else(|_| s.local_path.clone());
        if canon.starts_with(&ex_canon) || ex_canon.starts_with(&canon) {
            return Err(format!(
                "Path overlaps with existing synced folder '{}'",
                s.name
            ));
        }
    }
    Ok(())
}

pub fn load_or_create_config(path: &Path) -> anyhow::Result<ClientConfig> {
    if !path.exists() {
        let cfg = ClientConfig::default();
        save_config_atomic(path, &cfg)?;
        return Ok(cfg);
    }
    let raw = std::fs::read_to_string(path)?;
    let trimmed = raw.strip_prefix('\u{FEFF}').unwrap_or(&raw);
    let mut cfg: ClientConfig = match serde_json::from_str(trimmed) {
        Ok(c) => c,
        Err(_) => {
            // Migrate or reset incompatible legacy config safely while keeping a backup.
            let backup = path.with_extension("json.v1-backup");
            let _ = std::fs::copy(path, backup);
            let fresh = ClientConfig::default();
            save_config_atomic(path, &fresh)?;
            return Ok(fresh);
        }
    };
    let mut dirty = false;
    if cfg.device_id.trim().is_empty() {
        let host = default_hostname();
        cfg.device_id = generate_device_id(&host);
        dirty = true;
    }
    if cfg.device_name.trim().is_empty() {
        cfg.device_name = default_hostname();
        dirty = true;
    }
    if cfg.default_sync_root.as_os_str().is_empty() {
        cfg.default_sync_root = default_sync_root();
        dirty = true;
    }
    if dirty {
        let _ = save_config_atomic(path, &cfg);
    }
    Ok(cfg)
}

pub fn save_config_atomic(path: &Path, cfg: &ClientConfig) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("deltadrop-config.json");

    // Strip secrets on disk when keep_unlocked is disabled.
    let mut to_write = cfg.clone();
    if !to_write.keep_unlocked {
        to_write.session_token.clear();
        to_write.vault_key_hex = None;
    }
    let json = serde_json::to_vec_pretty(&to_write)?;
    let safe_dir = SafeDir::open(parent).map_err(|e| anyhow::anyhow!("SafeDir open failed: {e}"))?;
    safe_dir
        .write_atomic(file_name, &json)
        .map_err(|e| anyhow::anyhow!("SafeDir write_atomic failed: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_selection_always_creates_subfolder() {
        let home = user_home_dir();
        let desktop = home.join("Desktop");
        let resolved = resolve_safe_share_target(&desktop, "MyUnityGame");
        assert_eq!(resolved, desktop.join("MyUnityGame"));
        assert!(is_dangerous_root_path(&desktop));
        assert!(!is_dangerous_root_path(&resolved));
    }

    #[test]
    fn picking_already_named_folder_relinks_in_place() {
        let tmp = tempfile::tempdir().unwrap();
        let existing = tmp.path().join("MyUnityGame");
        std::fs::create_dir_all(&existing).unwrap();
        let resolved = resolve_safe_share_target(&existing, "MyUnityGame");
        assert_eq!(resolved, existing);
    }

    #[test]
    fn keep_unlocked_false_strips_secrets_on_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg_path = tmp.path().join("deltadrop-config.json");
        let cfg = ClientConfig {
            keep_unlocked: false,
            session_token: "secret-token".into(),
            vault_key_hex: Some("0123456789abcdef".repeat(4)),
            ..Default::default()
        };
        save_config_atomic(&cfg_path, &cfg).unwrap();
        let loaded = load_or_create_config(&cfg_path).unwrap();
        assert!(loaded.session_token.is_empty());
        assert!(loaded.vault_key_hex.is_none());
    }
}
