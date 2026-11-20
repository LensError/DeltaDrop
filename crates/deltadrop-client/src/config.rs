use std::path::{Path, PathBuf};

use deltadrop_common::UserRole;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncMode {
    Full,
    Whitelist,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IgnoreRule {
    pub pattern: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncFolderConfig {
    pub id: String,
    #[serde(default)]
    pub label: Option<String>,
    pub path: PathBuf,
    pub mode: SyncMode,
    #[serde(default)]
    pub whitelist_subdirs: Vec<String>,
    #[serde(default)]
    pub ignore_rules: Vec<IgnoreRule>,
    #[serde(default)]
    pub custom_ignore: String,
}

impl SyncFolderConfig {
    pub fn display_name(&self) -> &str {
        self.label.as_deref().unwrap_or(&self.id)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub peer_id: String,
    #[serde(default)]
    pub device_name: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub user_role: Option<UserRole>,
    #[serde(default)]
    pub session_token: String,
    #[serde(default = "default_true")]
    pub keep_unlocked: bool,
    #[serde(default)]
    pub network_secret: Option<String>,
    #[serde(default = "default_true")]
    pub auto_check_updates: bool,
    pub target_peers: Vec<String>,
    #[serde(default = "default_true")]
    pub auto_discover_peers: bool,
    pub relay_url: String,
    pub auth_token: String,
    #[serde(default = "default_workspace_id")]
    pub workspace_id: String,
    #[serde(default)]
    pub encryption_key: Option<String>,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    #[serde(default)]
    pub manifest_db_path: Option<PathBuf>,
    pub folders: Vec<SyncFolderConfig>,
}

pub fn generate_random_secret_hex() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut out = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

pub fn default_workspace_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut out = String::with_capacity(32);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn default_poll_interval() -> u64 {
    3
}

fn default_peer_id() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .map(|s| s.trim().to_lowercase().replace(' ', "-"))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "my-pc".to_string())
}

impl Default for ClientConfig {
    fn default() -> Self {
        let host = default_peer_id();
        Self {
            peer_id: host.clone(),
            device_name: host,
            username: String::new(),
            user_id: String::new(),
            user_role: None,
            session_token: String::new(),
            keep_unlocked: true,
            network_secret: None,
            auto_check_updates: true,
            target_peers: Vec::new(),
            auto_discover_peers: true,
            relay_url: "http://127.0.0.1:8787".to_string(),
            auth_token: String::new(),
            workspace_id: default_workspace_id(),
            encryption_key: Some(generate_random_secret_hex()),
            poll_interval_secs: default_poll_interval(),
            manifest_db_path: None,
            folders: Vec::new(),
        }
    }
}

pub fn validate_config(cfg: &ClientConfig) -> Result<(), String> {
    let peer = cfg.peer_id.trim();
    if peer.is_empty() {
        return Err("Peer ID cannot be empty".to_string());
    }
    if cfg.target_peers.iter().any(|p| p.trim() == peer) {
        return Err("Target Peers cannot include your own Peer ID".to_string());
    }
    let url = cfg.relay_url.trim();
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err("Relay URL must start with http:// or https://".to_string());
    }
    if cfg
        .encryption_key
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .is_empty()
    {
        return Err("E2E Encryption Key cannot be empty".to_string());
    }
    let mut seen_ids = std::collections::HashSet::new();
    let mut norm_paths: Vec<PathBuf> = Vec::new();
    for f in &cfg.folders {
        if f.id.trim().is_empty() {
            return Err("Folder ID cannot be empty".to_string());
        }
        if !seen_ids.insert(f.id.trim().to_string()) {
            return Err(format!("Duplicate Folder ID '{}'", f.id));
        }
        if f.path.as_os_str().is_empty() {
            return Err(format!("Folder '{}' path cannot be empty", f.id));
        }
        let canon = std::fs::canonicalize(&f.path).unwrap_or_else(|_| f.path.clone());
        for existing in &norm_paths {
            if canon.starts_with(existing) || existing.starts_with(&canon) {
                return Err(format!(
                    "Nested or overlapping folder paths are not allowed ('{}')",
                    f.id
                ));
            }
        }
        norm_paths.push(canon);
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
    let mut cfg: ClientConfig = serde_json::from_str(trimmed)?;
    let mut dirty = false;
    if cfg.workspace_id.trim().is_empty() {
        cfg.workspace_id = default_workspace_id();
        dirty = true;
    }
    if cfg
        .encryption_key
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .is_empty()
    {
        cfg.encryption_key = Some(generate_random_secret_hex());
        dirty = true;
    }
    if dirty {
        let _ = save_config_atomic(path, &cfg);
    }
    Ok(cfg)
}

pub fn save_config_atomic(path: &Path, cfg: &ClientConfig) -> anyhow::Result<()> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    static TMP_SEQ: AtomicU64 = AtomicU64::new(1);

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("deltadrop-config.json");
    let tmp = path.with_file_name(format!("{file_name}.deltadrop-tmp-{pid}-{seq}"));
    let json = serde_json::to_string_pretty(cfg)?;

    let write_res = (|| -> std::io::Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&tmp)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write_res {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }

    let mut last_err = None;
    for attempt in 0..5 {
        match std::fs::rename(&tmp, path) {
            Ok(()) => return Ok(()),
            Err(e) => {
                let is_sharing = e.kind() == std::io::ErrorKind::PermissionDenied
                    || matches!(e.raw_os_error(), Some(5) | Some(32));
                last_err = Some(e);
                if is_sharing && attempt < 4 {
                    std::thread::sleep(std::time::Duration::from_millis(20 * (attempt + 1)));
                    continue;
                }
                break;
            }
        }
    }
    let _ = std::fs::remove_file(&tmp);
    Err(last_err.unwrap().into())
}
