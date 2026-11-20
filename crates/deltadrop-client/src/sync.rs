use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use deltadrop_common::{
    encode_meta_header, next_fastcdc_boundary, normalize_rel_path, AckPullRequest, AckRequest,
    AdminUserInfo, ChunkRef, DeltaUploadMeta, DeviceInfo, EncryptedEnvelope, EventsResponse,
    FolderIndexPayload, HasChunksRequest, HasChunksResponse, OpType, PeerInfo, PeerRegistration,
    PendingDelta, PendingPullRequest, PullRequest, RelayCacheStatus, RelayStatus, UserRole,
    CHUNK_MAX_SIZE, CHUNK_MIN_SIZE, CHUNK_THRESHOLD, PROTOCOL_HEADER, PROTOCOL_VERSION,
};
use lumenic::Waker;
use notify::RecursiveMode;
use notify_debouncer_mini::{new_debouncer, DebounceEventResult};
use rand::RngCore;
use reqwest::Client;
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;
use tracing::{error, info, warn};

use crate::config::{
    save_config_atomic, validate_config, ClientConfig, SyncFolderConfig, SyncMode,
};
use crate::ignore_rules::{write_ignore_file_from_folder, IgnoreFilter};
use crate::manifest::LocalManifest;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivityDirection {
    Upload,
    Download,
    Delete,
    Conflict,
    Info,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ActivityItem {
    pub id: u64,
    pub time_label: String,
    pub direction: ActivityDirection,
    pub folder_id: String,
    pub rel_path: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct ConflictAlert {
    pub id: u64,
    pub folder_id: String,
    pub rel_path: String,
    pub conflict_path: String,
    pub time_label: String,
}

#[derive(Debug, Clone)]
pub struct SubdirToggleItem {
    pub name: String,
    pub whitelisted: bool,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SelectiveFolderView {
    pub folder_id: String,
    pub label: String,
    pub mode: SyncMode,
    pub source_peer: String,
    pub subdirs: Vec<SubdirToggleItem>,
}

#[derive(Debug, Clone)]
pub struct RemoteFolderStub {
    pub source_peer: String,
    pub folder_id: String,
    pub subdir_count: usize,
}

#[derive(Debug, Clone, Default)]
pub struct UiSnapshot {
    pub peer_id: String,
    pub username: String,
    pub user_role: Option<UserRole>,
    pub online: bool,
    pub paused: bool,
    pub last_error: Option<String>,
    pub relay_latency_ms: Option<u64>,
    pub upload_bps: u64,
    pub download_bps: u64,
    pub relay_status: RelayStatus,
    pub cache_status: RelayCacheStatus,
    pub devices: Vec<DeviceInfo>,
    pub admin_users: Vec<AdminUserInfo>,
    pub update_status: Option<crate::updater::UpdateStatus>,
    pub pending_uploads: usize,
    pub pending_downloads: usize,
    pub discovered_peers: Vec<String>,
    pub active_config: Option<ClientConfig>,
    pub selective_folders: Vec<SelectiveFolderView>,
    pub unmapped_remote_folders: Vec<RemoteFolderStub>,
    pub activity: Vec<ActivityItem>,
    pub conflicts: Vec<ConflictAlert>,
    pub connection_test_result: Option<String>,
}

#[derive(Debug)]
#[allow(dead_code, clippy::large_enum_variant)]
pub enum SyncCommand {
    TogglePause,
    ForceScan,
    TestConnection {
        relay_url: String,
        auth_token: String,
    },
    SetFolderMode {
        folder_id: String,
        mode: SyncMode,
    },
    MapRemoteFolder {
        folder_id: String,
        path: PathBuf,
        mode: SyncMode,
    },
    ToggleSubdir {
        folder_id: String,
        source_peer: String,
        subdir: String,
        enable: bool,
    },
    DismissConflict(u64),
    ResolveConflict {
        id: u64,
        keep_conflict_file: bool,
        folder_id: String,
        rel_path: String,
        conflict_path: String,
    },
    UpdateConfig(ClientConfig),
    Login {
        relay_url: String,
        username: String,
        password: String,
        device_name: String,
        network_secret: Option<String>,
        keep_unlocked: bool,
    },
    SignOut,
    CheckUpdates,
    InstallUpdate,
    RefreshDevices,
    DeleteDevice(String),
    ReplaceDevice {
        old_device_id: String,
        new_device_name: String,
    },
    AdminRefreshUsers,
    AdminCreateUser {
        username: String,
        password: String,
        role: UserRole,
    },
    AdminToggleUserDisabled {
        user_id: String,
        disabled: bool,
    },
    AdminResetUserPassword {
        user_id: String,
        new_password: String,
    },
    AdminDeleteUser(String),
}

pub struct SyncHandle {
    pub snapshot: Arc<Mutex<UiSnapshot>>,
    pub cmd_tx: mpsc::UnboundedSender<SyncCommand>,
}

fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let (chunks, _) = s.as_bytes().as_chunks::<2>();
    for (i, chunk) in chunks.iter().enumerate() {
        let hi = std::str::from_utf8(chunk).ok()?;
        out[i] = u8::from_str_radix(hi, 16).ok()?;
    }
    Some(out)
}

fn effective_bearer(cfg: &ClientConfig) -> &str {
    if !cfg.session_token.is_empty() {
        &cfg.session_token
    } else {
        &cfg.auth_token
    }
}

trait AuthReqExt {
    fn with_client_auth(self, cfg: &ClientConfig) -> Self;
}

impl AuthReqExt for reqwest::RequestBuilder {
    fn with_client_auth(self, cfg: &ClientConfig) -> Self {
        let rb = self.bearer_auth(effective_bearer(cfg));
        match cfg
            .network_secret
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(secret) => rb.header(deltadrop_common::GATE_HEADER, secret),
            None => rb,
        }
    }
}

fn derive_workspace_keys(config: &ClientConfig) -> anyhow::Result<([u8; 32], [u8; 32])> {
    let secret = config
        .encryption_key
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("E2E encryption key is not configured"))?;

    let master: [u8; 32] = if let Some(raw_32) = decode_hex_32(secret) {
        raw_32
    } else {
        type KdfCache = OnceLock<Mutex<HashMap<(String, String), [u8; 32]>>>;
        static KDF_CACHE: KdfCache = OnceLock::new();
        let cache = KDF_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
        let cache_key = (config.workspace_id.clone(), secret.to_string());
        if let Ok(guard) = cache.lock() {
            if let Some(hit) = guard.get(&cache_key) {
                let enc_key = blake3::derive_key("deltadrop-e2e-v2-enc", hit);
                let slot_key = blake3::derive_key("deltadrop-e2e-v2-slot", hit);
                return Ok((enc_key, slot_key));
            }
        }
        let salt_hash =
            blake3::hash(format!("deltadrop-salt-v2:{}", config.workspace_id).as_bytes());
        let mut derived = [0u8; 32];
        argon2::Argon2::default()
            .hash_password_into(secret.as_bytes(), &salt_hash.as_bytes()[..16], &mut derived)
            .map_err(|e| anyhow::anyhow!("Argon2id key derivation failed: {e}"))?;
        if let Ok(mut guard) = cache.lock() {
            guard.insert(cache_key, derived);
        }
        derived
    };

    let enc_key = blake3::derive_key("deltadrop-e2e-v2-enc", &master);
    let slot_key = blake3::derive_key("deltadrop-e2e-v2-slot", &master);
    Ok((enc_key, slot_key))
}

fn opaque_slot_path(slot_key: &[u8; 32], folder_id: &str, rel_path: &str) -> String {
    let tag = blake3::keyed_hash(slot_key, format!("{folder_id}\0{rel_path}").as_bytes()).to_hex();
    format!("slot/{tag}")
}

fn envelope_aad(workspace_id: &str, target_peer: &str, delta_version: u64) -> Vec<u8> {
    format!("dd-v2|{workspace_id}|{target_peer}|{delta_version}").into_bytes()
}

fn encrypt_envelope(config: &ClientConfig, env: &EncryptedEnvelope) -> anyhow::Result<Vec<u8>> {
    let (enc_key, _) = derive_workspace_keys(config)?;
    let cipher = ChaCha20Poly1305::new((&enc_key).into());
    let plaintext = serde_json::to_vec(env)?;
    let aad = envelope_aad(&config.workspace_id, &env.target_peer, env.delta_version);

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext.as_slice(),
                aad: aad.as_slice(),
            },
        )
        .map_err(|_| anyhow::anyhow!("AEAD envelope encryption failed"))?;

    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt_envelope(
    config: &ClientConfig,
    payload: &[u8],
    delta_version: u64,
) -> anyhow::Result<EncryptedEnvelope> {
    if payload.len() < 12 {
        anyhow::bail!("Encrypted payload too short");
    }
    let (enc_key, _) = derive_workspace_keys(config)?;
    let cipher = ChaCha20Poly1305::new((&enc_key).into());
    let nonce = Nonce::from_slice(&payload[..12]);
    let aad = envelope_aad(&config.workspace_id, &config.peer_id, delta_version);
    let pt = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &payload[12..],
                aad: aad.as_slice(),
            },
        )
        .map_err(|_| anyhow::anyhow!("AEAD envelope decryption failed (tampered or wrong key)"))?;
    let env: EncryptedEnvelope = serde_json::from_slice(&pt)?;
    Ok(env)
}

fn encrypt_chunk(
    enc_key: &[u8; 32],
    workspace_id: &str,
    chunk_id: &str,
    compressed: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let chunk_key = blake3::derive_key("deltadrop-chunk-v2", enc_key);
    let cipher = ChaCha20Poly1305::new((&chunk_key).into());
    let aad = format!("dd-chunk-v2|{workspace_id}|{chunk_id}");
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: compressed,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("Chunk encryption failed"))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt_chunk(
    enc_key: &[u8; 32],
    workspace_id: &str,
    chunk_id: &str,
    payload: &[u8],
    expected_raw_size: u64,
) -> anyhow::Result<Vec<u8>> {
    if payload.len() < 12 {
        anyhow::bail!("Encrypted chunk too short");
    }
    let chunk_key = blake3::derive_key("deltadrop-chunk-v2", enc_key);
    let cipher = ChaCha20Poly1305::new((&chunk_key).into());
    let nonce = Nonce::from_slice(&payload[..12]);
    let aad = format!("dd-chunk-v2|{workspace_id}|{chunk_id}");
    let zst_bytes = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &payload[12..],
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("Chunk decryption failed (tampered or wrong key)"))?;
    decompress_zstd_bounded(&zst_bytes, expected_raw_size)
}

fn stream_hash_file(path: &Path) -> anyhow::Result<(String, u64)> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hasher.finalize().to_hex().to_string(), total))
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn time_label_now() -> String {
    chrono::Local::now().format("%H:%M:%S").to_string()
}

fn file_mtime_ms(path: &Path) -> i64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
        .unwrap_or_else(now_ms)
}

fn make_conflict_path(target: &Path, peer_id: &str) -> PathBuf {
    let ts = now_ms();
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    let stem = target
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("file");
    let safe_peer: String = peer_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let ext = target.extension().and_then(|e| e.to_str());
    for suffix in 0u32..1000 {
        let tag = if suffix == 0 {
            format!("{safe_peer}-{ts}")
        } else {
            format!("{safe_peer}-{ts}-{suffix}")
        };
        let candidate = match ext {
            Some(e) => parent.join(format!("{stem}.sync-conflict-{tag}.{e}")),
            None => parent.join(format!("{stem}.sync-conflict-{tag}")),
        };
        if std::fs::symlink_metadata(&candidate).is_err() {
            return candidate;
        }
    }
    parent.join(format!("{stem}.sync-conflict-{safe_peer}-{ts}-overflow"))
}

const HARD_DECOMPRESS_CEILING: u64 = 512 * 1024 * 1024;

fn decompress_zstd_bounded(compressed: &[u8], expected_raw_size: u64) -> anyhow::Result<Vec<u8>> {
    if expected_raw_size > HARD_DECOMPRESS_CEILING {
        anyhow::bail!("Declared raw_size {expected_raw_size} exceeds safety ceiling");
    }
    let decoder = zstd::stream::read::Decoder::new(compressed)?;
    let mut limited = decoder.take(expected_raw_size.saturating_add(1));
    let mut out = Vec::with_capacity(expected_raw_size.min(8 * 1024 * 1024) as usize);
    limited.read_to_end(&mut out)?;
    if out.len() as u64 != expected_raw_size {
        anyhow::bail!(
            "Decompressed size {} does not match expected {expected_raw_size}",
            out.len()
        );
    }
    Ok(out)
}

fn make_temp_sibling(target: &Path) -> anyhow::Result<PathBuf> {
    static TMP_SEQ: AtomicU64 = AtomicU64::new(1);
    if let Ok(meta) = std::fs::symlink_metadata(target) {
        if meta.file_type().is_symlink() {
            anyhow::bail!("Refusing to overwrite symlink {}", target.display());
        }
    }
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let base_name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("payload");
    Ok(target.with_file_name(format!(".{base_name}.deltadrop-tmp-{pid}-{seq}")))
}

fn atomic_rename_temp(tmp_path: &Path, target: &Path) -> anyhow::Result<()> {
    let mut last_err = None;
    for attempt in 0..5 {
        match std::fs::rename(tmp_path, target) {
            Ok(()) => return Ok(()),
            Err(e) => {
                let is_sharing = e.kind() == std::io::ErrorKind::PermissionDenied
                    || matches!(e.raw_os_error(), Some(5) | Some(32));
                last_err = Some(e);
                if is_sharing && attempt < 4 {
                    std::thread::sleep(Duration::from_millis(20 * (attempt + 1)));
                    continue;
                }
                break;
            }
        }
    }
    let _ = std::fs::remove_file(tmp_path);
    Err(last_err.unwrap().into())
}

struct SharedTracker {
    snapshot: Arc<Mutex<UiSnapshot>>,
    waker: Option<Waker>,
    next_id: u64,
    activity_ring: VecDeque<ActivityItem>,
}

impl SharedTracker {
    fn new(snapshot: Arc<Mutex<UiSnapshot>>, waker: Option<Waker>) -> Self {
        Self {
            snapshot,
            waker,
            next_id: 1,
            activity_ring: VecDeque::with_capacity(64),
        }
    }

    fn wake(&self) {
        if let Some(w) = &self.waker {
            w.wake();
        }
    }

    fn push_activity(
        &mut self,
        direction: ActivityDirection,
        folder_id: &str,
        rel_path: &str,
        detail: impl Into<String>,
    ) {
        let id = self.next_id;
        self.next_id += 1;
        let item = ActivityItem {
            id,
            time_label: time_label_now(),
            direction,
            folder_id: folder_id.to_string(),
            rel_path: rel_path.to_string(),
            detail: detail.into(),
        };
        if self.activity_ring.len() >= 50 {
            self.activity_ring.pop_back();
        }
        self.activity_ring.push_front(item);
        if let Ok(mut guard) = self.snapshot.lock() {
            guard.activity = self.activity_ring.iter().cloned().collect();
        }
        self.wake();
    }

    fn push_conflict(
        &mut self,
        manifest: &Arc<Mutex<LocalManifest>>,
        folder_id: &str,
        rel_path: &str,
        conflict_path: &str,
    ) {
        let time_label = time_label_now();
        let id = manifest
            .lock()
            .ok()
            .and_then(|m| {
                m.push_conflict(folder_id, rel_path, conflict_path, &time_label)
                    .ok()
            })
            .unwrap_or_else(|| {
                let id = self.next_id;
                self.next_id += 1;
                id
            });
        let alert = ConflictAlert {
            id,
            folder_id: folder_id.to_string(),
            rel_path: rel_path.to_string(),
            conflict_path: conflict_path.to_string(),
            time_label,
        };
        if let Ok(mut guard) = self.snapshot.lock() {
            guard.conflicts.insert(0, alert);
        }
        self.wake();
    }

    fn update_status(
        &self,
        online: bool,
        paused: bool,
        err: Option<String>,
        relay_status: Option<RelayStatus>,
        pending_uploads: usize,
        pending_downloads: usize,
    ) {
        if let Ok(mut guard) = self.snapshot.lock() {
            guard.online = online;
            guard.paused = paused;
            guard.last_error = err;
            if let Some(st) = relay_status {
                guard.relay_status = st;
            }
            guard.pending_uploads = pending_uploads;
            guard.pending_downloads = pending_downloads;
        }
        self.wake();
    }

    fn set_folder_views(&self, views: Vec<SelectiveFolderView>, unmapped: Vec<RemoteFolderStub>) {
        if let Ok(mut guard) = self.snapshot.lock() {
            guard.selective_folders = views;
            guard.unmapped_remote_folders = unmapped;
        }
        self.wake();
    }
}

pub fn spawn_sync_engine(
    config_path: PathBuf,
    config: ClientConfig,
    manifest_db_path: PathBuf,
    waker: Option<Waker>,
) -> SyncHandle {
    let snapshot = Arc::new(Mutex::new(UiSnapshot {
        peer_id: config.peer_id.clone(),
        active_config: Some(config.clone()),
        ..Default::default()
    }));
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();

    let snap_clone = snapshot.clone();
    let cfg_path_clone = config_path.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async move {
            run_sync_loop(
                cfg_path_clone,
                config,
                manifest_db_path,
                snap_clone,
                cmd_rx,
                waker,
            )
            .await;
        });
    });

    SyncHandle { snapshot, cmd_tx }
}

type FilterCache = HashMap<String, Arc<IgnoreFilter>>;
type RecentWrites = Arc<Mutex<HashMap<(String, String), (i64, u64, Instant)>>>;

fn rebuild_filter_cache(config: &ClientConfig) -> FilterCache {
    config
        .folders
        .iter()
        .map(|f| (f.id.clone(), Arc::new(IgnoreFilter::for_folder_config(f))))
        .collect()
}

fn watch_folder_selective<T: notify::Watcher + ?Sized>(
    watcher: &mut T,
    folder: &SyncFolderConfig,
    filter: &IgnoreFilter,
    watched: &mut HashSet<PathBuf>,
) {
    let Ok(root_meta) = std::fs::symlink_metadata(&folder.path) else {
        return;
    };
    if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
        return;
    }
    let mut stack = vec![folder.path.clone()];
    while let Some(dir) = stack.pop() {
        if watched.insert(dir.clone()) {
            if let Err(e) = watcher.watch(&dir, RecursiveMode::NonRecursive) {
                warn!("Watch failed for {}: {e}", dir.display());
            }
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_symlink() || !ft.is_dir() {
                continue;
            }
            let p = entry.path();
            if let Ok(rel) = p.strip_prefix(&folder.path) {
                if let Some(norm) = normalize_rel_path(&rel.to_string_lossy()) {
                    if filter.should_sync(folder, &norm, true) {
                        stack.push(p);
                    }
                }
            }
        }
    }
}

fn rearm_watches(
    debouncer: &mut Option<notify_debouncer_mini::Debouncer<notify::RecommendedWatcher>>,
    config: &ClientConfig,
    filters: &FilterCache,
    watched: &mut HashSet<PathBuf>,
) {
    let Some(deb) = debouncer.as_mut() else {
        return;
    };
    for p in watched.drain() {
        let _ = deb.watcher().unwatch(&p);
    }
    for folder in &config.folders {
        if let Some(filter) = filters.get(&folder.id) {
            watch_folder_selective(deb.watcher(), folder, filter, watched);
        }
    }
}

async fn register_and_discover_peers(
    http: &Client,
    config: &mut ClientConfig,
) -> (Vec<String>, bool) {
    if effective_bearer(config).trim().is_empty() || config.peer_id.trim().is_empty() {
        return (Vec::new(), false);
    }
    let base = config.relay_url.trim_end_matches('/');
    let _ = http
        .post(format!("{base}/v1/peers/register"))
        .with_client_auth(config)
        .json(&PeerRegistration {
            peer_id: config.peer_id.clone(),
            workspace_id: config.workspace_id.clone(),
        })
        .send()
        .await;

    let Ok(resp) = http
        .get(format!("{base}/v1/peers"))
        .query(&[("workspace_id", config.workspace_id.as_str())])
        .with_client_auth(config)
        .send()
        .await
        .and_then(|r| r.error_for_status())
    else {
        return (Vec::new(), false);
    };
    let Ok(peers) = resp.json::<Vec<PeerInfo>>().await else {
        return (Vec::new(), false);
    };
    let discovered: Vec<String> = peers
        .into_iter()
        .map(|p| p.peer_id)
        .filter(|id| id != &config.peer_id)
        .collect();
    let mut added_new = false;
    if config.auto_discover_peers {
        for p in &discovered {
            if !config.target_peers.contains(p) {
                config.target_peers.push(p.clone());
                added_new = true;
            }
        }
    }
    (discovered, added_new)
}

fn populate_local_selective_views(config: &ClientConfig, tracker: &SharedTracker) {
    let mut views = Vec::new();
    let default_peer = config.target_peers.first().cloned().unwrap_or_default();
    for folder in &config.folders {
        let mut all_subdirs: HashSet<String> = folder.whitelist_subdirs.iter().cloned().collect();
        if let Ok(entries) = std::fs::read_dir(&folder.path) {
            for e in entries.flatten() {
                if let Ok(ft) = e.file_type() {
                    if ft.is_dir() && !ft.is_symlink() {
                        if let Some(name) = e.file_name().to_str() {
                            if !name.starts_with('.') {
                                all_subdirs.insert(name.to_string());
                            }
                        }
                    }
                }
            }
        }
        let mut sorted: Vec<String> = all_subdirs.into_iter().collect();
        sorted.sort();
        let subdirs = sorted
            .into_iter()
            .map(|name| SubdirToggleItem {
                whitelisted: folder.whitelist_subdirs.contains(&name),
                name,
            })
            .collect();
        views.push(SelectiveFolderView {
            folder_id: folder.id.clone(),
            label: folder.display_name().to_string(),
            mode: folder.mode,
            source_peer: default_peer.clone(),
            subdirs,
        });
    }
    tracker.set_folder_views(views, Vec::new());
}

async fn fetch_events_long_poll(
    http: &Client,
    config: &ClientConfig,
) -> Result<bool, reqwest::Error> {
    let base = config.relay_url.trim_end_matches('/');
    let resp = http
        .get(format!("{base}/v1/events"))
        .query(&[("peer", config.peer_id.as_str()), ("wait_secs", "25")])
        .with_client_auth(config)
        .send()
        .await?
        .error_for_status()?;
    let ev = resp.json::<EventsResponse>().await?;
    Ok(ev.pending)
}

async fn run_sync_loop(
    config_path: PathBuf,
    mut config: ClientConfig,
    manifest_db_path: PathBuf,
    snapshot: Arc<Mutex<UiSnapshot>>,
    mut cmd_rx: mpsc::UnboundedReceiver<SyncCommand>,
    waker: Option<Waker>,
) {
    let manifest = match LocalManifest::open(&manifest_db_path) {
        Ok(m) => Arc::new(Mutex::new(m)),
        Err(e) => {
            error!("Failed to open manifest DB: {e}");
            return;
        }
    };

    let mut default_headers = reqwest::header::HeaderMap::new();
    default_headers.insert(
        reqwest::header::HeaderName::from_static("x-deltadrop-protocol"),
        reqwest::header::HeaderValue::from_static(PROTOCOL_VERSION),
    );
    let http = Arc::new(
        Client::builder()
            .default_headers(default_headers)
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(Duration::from_secs(60))
            .build()
            .expect("reqwest client"),
    );
    let mut tracker = SharedTracker::new(snapshot.clone(), waker);
    let mut paused = false;
    let mut filter_cache = rebuild_filter_cache(&config);
    let recent_writes: RecentWrites = Arc::new(Mutex::new(HashMap::new()));
    let mut watched_dirs: HashSet<PathBuf> = HashSet::new();

    // Channel for debounced filesystem events
    let (fs_tx, mut fs_rx) = mpsc::unbounded_channel::<Vec<PathBuf>>();
    let mut _debouncer = new_debouncer(
        Duration::from_millis(500),
        move |res: DebounceEventResult| {
            if let Ok(events) = res {
                let paths: Vec<PathBuf> = events.into_iter().map(|e| e.path).collect();
                if !paths.is_empty() {
                    let _ = fs_tx.send(paths);
                }
            }
        },
    )
    .ok();

    rearm_watches(&mut _debouncer, &config, &filter_cache, &mut watched_dirs);

    // Load persisted conflicts & populate local folder views immediately (even while offline)
    if let Ok(m) = manifest.lock() {
        if let Ok(rows) = m.list_conflicts() {
            if let Ok(mut g) = snapshot.lock() {
                g.conflicts = rows
                    .into_iter()
                    .map(|r| ConflictAlert {
                        id: r.id,
                        folder_id: r.folder_id,
                        rel_path: r.rel_path,
                        conflict_path: r.conflict_path,
                        time_label: r.time_label,
                    })
                    .collect();
            }
        }
    }
    populate_local_selective_views(&config, &tracker);

    // Initial scan of all configured folders on startup
    let mut dirty_paths: HashSet<(String, String)> = HashSet::new();
    collect_initial_changes(&config, &manifest, &mut dirty_paths);

    let mut poll_secs = config.poll_interval_secs.max(5);
    let mut poll_tick = tokio::time::interval(Duration::from_secs(poll_secs));
    poll_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut last_reconcile = Instant::now();
    let mut last_status_refresh = Instant::now();
    let mut backoff_secs: u64 = 1;
    let mut online_known = false;

    // Long-poll wake channel
    let (lp_tx, mut lp_rx) = mpsc::channel::<bool>(4);
    let lp_http = http.clone();
    let (lp_cfg_tx, mut lp_cfg_rx) = tokio::sync::watch::channel((config.clone(), paused));
    tokio::spawn(async move {
        loop {
            let (lp_cfg, is_paused) = lp_cfg_rx.borrow().clone();
            if is_paused || lp_cfg.auth_token.trim().is_empty() {
                if lp_cfg_rx.changed().await.is_err() {
                    break;
                }
                continue;
            }
            match fetch_events_long_poll(&lp_http, &lp_cfg).await {
                Ok(true) => {
                    let _ = lp_tx.send(true).await;
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                Ok(false) => {
                    let _ = lp_tx.send(false).await;
                }
                Err(_) => {
                    tokio::time::sleep(Duration::from_secs(3)).await;
                }
            }
        }
    });

    loop {
        tokio::select! {
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    SyncCommand::TogglePause => {
                        paused = !paused;
                        let _ = lp_cfg_tx.send((config.clone(), paused));
                        tracker.push_activity(
                            ActivityDirection::Info,
                            "-",
                            "-",
                            if paused { "Sync paused" } else { "Sync resumed" },
                        );
                    }
                    SyncCommand::ForceScan => {
                        filter_cache = rebuild_filter_cache(&config);
                        rearm_watches(&mut _debouncer, &config, &filter_cache, &mut watched_dirs);
                        collect_initial_changes(&config, &manifest, &mut dirty_paths);
                        publish_all_folder_indices(&http, &config).await;
                        tracker.push_activity(ActivityDirection::Info, "-", "-", "Manual rescan queued");
                    }
                    SyncCommand::TestConnection { relay_url, auth_token } => {
                        let base = relay_url.trim().trim_end_matches('/').to_string();
                        let res = http
                            .get(format!("{base}/v1/status"))
                            .bearer_auth(auth_token.trim())
                            .send()
                            .await;
                        let msg = match res {
                            Ok(r) if r.status().is_success() => match r.json::<RelayStatus>().await {
                                Ok(st) => format!(
                                    "Connected ({} / {}, {} queued)",
                                    deltadrop_common::format_bytes(st.used_bytes),
                                    deltadrop_common::format_bytes(st.max_bytes),
                                    st.queued_count
                                ),
                                Err(e) => format!("Error parsing status: {e}"),
                            },
                            Ok(r) => format!("Error: HTTP {}", r.status()),
                            Err(e) => format!("Error: {e}"),
                        };
                        if let Ok(mut g) = snapshot.lock() {
                            g.connection_test_result = Some(msg);
                        }
                        tracker.wake();
                    }
                    SyncCommand::DismissConflict(id) => {
                        if let Ok(m) = manifest.lock() {
                            let _ = m.remove_conflict(id);
                        }
                        if let Ok(mut g) = snapshot.lock() {
                            g.conflicts.retain(|c| c.id != id);
                        }
                        tracker.wake();
                    }
                    SyncCommand::ResolveConflict {
                        id,
                        keep_conflict_file,
                        folder_id,
                        rel_path,
                        conflict_path,
                    } => {
                        if let Some(folder) = config.folders.iter().find(|f| f.id == folder_id) {
                            let target = folder.path.join(&rel_path);
                            let cp = PathBuf::from(&conflict_path);
                            if keep_conflict_file {
                                if cp.is_file() {
                                    if let Err(e) = std::fs::copy(&cp, &target) {
                                        warn!("Failed restoring conflict file {}: {e}", cp.display());
                                    } else {
                                        let _ = std::fs::remove_file(&cp);
                                        dirty_paths.insert((folder_id.clone(), rel_path.clone()));
                                    }
                                }
                            } else if cp.is_file() {
                                let _ = std::fs::remove_file(&cp);
                            }
                        }
                        if let Ok(m) = manifest.lock() {
                            let _ = m.remove_conflict(id);
                        }
                        if let Ok(mut g) = snapshot.lock() {
                            g.conflicts.retain(|c| c.id != id);
                        }
                        tracker.push_activity(
                            ActivityDirection::Info,
                            &folder_id,
                            &rel_path,
                            if keep_conflict_file {
                                "Resolved conflict (kept conflict copy)"
                            } else {
                                "Resolved conflict (kept synced file)"
                            },
                        );
                    }
                    SyncCommand::SetFolderMode { folder_id, mode } => {
                        if let Some(folder) = config.folders.iter_mut().find(|f| f.id == folder_id) {
                            folder.mode = mode;
                            if let Err(e) = save_config_atomic(&config_path, &config) {
                                warn!("Failed saving config: {e}");
                            }
                            if let Ok(mut g) = snapshot.lock() {
                                g.active_config = Some(config.clone());
                            }
                            filter_cache = rebuild_filter_cache(&config);
                            collect_initial_changes(&config, &manifest, &mut dirty_paths);
                            if mode == SyncMode::Full {
                                for peer in &config.target_peers {
                                    let _ = send_pull_request(&http, &config, peer, &folder_id, "*").await;
                                }
                            }
                            refresh_selective_views(&http, &config, &tracker).await;
                            tracker.push_activity(
                                ActivityDirection::Info,
                                &folder_id,
                                "-",
                                match mode {
                                    SyncMode::Full => "Switched to Sync All (requested snapshot)",
                                    SyncMode::Whitelist => "Switched to Selective",
                                },
                            );
                        }
                    }
                    SyncCommand::MapRemoteFolder { folder_id, path, mode } => {
                        if !config.folders.iter().any(|f| f.id == folder_id) {
                            let _ = std::fs::create_dir_all(&path);
                            config.folders.push(SyncFolderConfig {
                                id: folder_id.clone(),
                                label: None,
                                path,
                                mode,
                                whitelist_subdirs: Vec::new(),
                                ignore_rules: Vec::new(),
                                custom_ignore: String::new(),
                            });
                            if let Err(e) = save_config_atomic(&config_path, &config) {
                                warn!("Failed saving config: {e}");
                            }
                            if let Ok(mut g) = snapshot.lock() {
                                g.active_config = Some(config.clone());
                            }
                            filter_cache = rebuild_filter_cache(&config);
                            rearm_watches(&mut _debouncer, &config, &filter_cache, &mut watched_dirs);
                            collect_initial_changes(&config, &manifest, &mut dirty_paths);
                            if mode == SyncMode::Full {
                                for peer in &config.target_peers {
                                    let _ = send_pull_request(&http, &config, peer, &folder_id, "*").await;
                                }
                            }
                            publish_all_folder_indices(&http, &config).await;
                            refresh_selective_views(&http, &config, &tracker).await;
                            tracker.push_activity(
                                ActivityDirection::Info,
                                &folder_id,
                                "-",
                                match mode {
                                    SyncMode::Full => "Mapped remote folder (Sync All)",
                                    SyncMode::Whitelist => "Mapped remote folder (Selective)",
                                },
                            );
                        }
                    }
                    SyncCommand::ToggleSubdir { folder_id, source_peer, subdir, enable } => {
                        if let Some(folder) = config.folders.iter_mut().find(|f| f.id == folder_id) {
                            if enable {
                                if !folder.whitelist_subdirs.contains(&subdir) {
                                    folder.whitelist_subdirs.push(subdir.clone());
                                    folder.whitelist_subdirs.sort();
                                }
                            } else {
                                folder.whitelist_subdirs.retain(|s| s != &subdir);
                            }
                            if let Err(e) = save_config_atomic(&config_path, &config) {
                                warn!("Failed saving config: {e}");
                            }
                            if let Ok(mut g) = snapshot.lock() {
                                g.active_config = Some(config.clone());
                            }
                            filter_cache = rebuild_filter_cache(&config);
                            if enable {
                                collect_initial_changes(&config, &manifest, &mut dirty_paths);
                                if !source_peer.is_empty() && source_peer != config.peer_id {
                                    let _ = send_pull_request(&http, &config, &source_peer, &folder_id, &subdir).await;
                                    tracker.push_activity(
                                        ActivityDirection::Info,
                                        &folder_id,
                                        &subdir,
                                        format!("Scanning locally & requested pull from {source_peer}"),
                                    );
                                }
                            }
                            refresh_selective_views(&http, &config, &tracker).await;
                        }
                    }
                    SyncCommand::UpdateConfig(mut new_cfg) => {
                        new_cfg.auth_token = new_cfg.auth_token.trim().to_string();
                        if new_cfg.session_token.is_empty() && !config.session_token.is_empty() {
                            new_cfg.session_token = config.session_token.clone();
                        }
                        if new_cfg.user_id.is_empty() && !config.user_id.is_empty() {
                            new_cfg.user_id = config.user_id.clone();
                        }
                        if new_cfg.user_role.is_none() {
                            new_cfg.user_role = config.user_role;
                        }
                        if new_cfg.username.is_empty() && !config.username.is_empty() {
                            new_cfg.username = config.username.clone();
                        }
                        new_cfg.encryption_key = new_cfg
                            .encryption_key
                            .map(|k| k.trim().to_string())
                            .filter(|k| !k.is_empty())
                            .or_else(|| config.encryption_key.clone());
                        if let Err(msg) = validate_config(&new_cfg) {
                            tracker.push_activity(ActivityDirection::Info, "-", "-", format!("Config error: {msg}"));
                            if let Ok(mut g) = snapshot.lock() {
                                g.last_error = Some(msg);
                            }
                            tracker.wake();
                            continue;
                        }
                        let new_ids: HashSet<String> =
                            new_cfg.folders.iter().map(|f| f.id.clone()).collect();
                        let removed_ids: Vec<String> = config
                            .folders
                            .iter()
                            .filter(|f| !new_ids.contains(&f.id))
                            .map(|f| f.id.clone())
                            .collect();
                        for rid in &removed_ids {
                            if let Ok(m) = manifest.lock() {
                                let _ = m.remove_folder(rid);
                            }
                            let base = new_cfg.relay_url.trim_end_matches('/');
                            let _ = http
                                .delete(format!("{base}/v1/folder-index"))
                                .query(&[
                                    ("source_peer", new_cfg.peer_id.as_str()),
                                    ("folder_id", rid.as_str()),
                                ])
                                .with_client_auth(&new_cfg)
                                .send()
                                .await;
                        }
                        for f in &new_cfg.folders {
                            let _ = write_ignore_file_from_folder(f);
                        }
                        dirty_paths.clear();
                        config = new_cfg;
                        let new_poll = config.poll_interval_secs.max(5);
                        if new_poll != poll_secs {
                            poll_secs = new_poll;
                            poll_tick = tokio::time::interval(Duration::from_secs(poll_secs));
                            poll_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
                        }
                        filter_cache = rebuild_filter_cache(&config);
                        rearm_watches(&mut _debouncer, &config, &filter_cache, &mut watched_dirs);
                        let _ = lp_cfg_tx.send((config.clone(), paused));
                        if let Err(e) = save_config_atomic(&config_path, &config) {
                            warn!("Failed saving config: {e}");
                            tracker.push_activity(
                                ActivityDirection::Info,
                                "-",
                                "-",
                                format!("Config save error: {e}"),
                            );
                        }
                        if let Ok(mut g) = snapshot.lock() {
                            g.peer_id = config.peer_id.clone();
                            g.active_config = Some(config.clone());
                            g.last_error = None;
                        }
                        collect_initial_changes(&config, &manifest, &mut dirty_paths);
                        publish_all_folder_indices(&http, &config).await;
                        refresh_selective_views(&http, &config, &tracker).await;
                        tracker.push_activity(
                            ActivityDirection::Info,
                            "-",
                            "-",
                            "Configuration saved & reloaded",
                        );
                    }
                    other_cmd => {
                        handle_account_and_update_cmd(
                            other_cmd,
                            &http,
                            &mut config,
                            &config_path,
                            &snapshot,
                            &tracker,
                        )
                        .await;
                    }
                }
            }
            Some(paths) = fs_rx.recv() => {
                // Prune expired entries from recent_writes
                if let Ok(mut rw) = recent_writes.lock() {
                    rw.retain(|_, (_, _, t)| t.elapsed() < Duration::from_secs(5));
                }
                for p in paths {
                    for folder in &config.folders {
                        if let Ok(rel) = p.strip_prefix(&folder.path) {
                            if let Some(norm) = normalize_rel_path(&rel.to_string_lossy()) {
                                if norm == ".deltadropignore" {
                                    filter_cache.insert(
                                        folder.id.clone(),
                                        Arc::new(IgnoreFilter::for_folder_config(folder)),
                                    );
                                }
                                let filter = filter_cache
                                    .get(&folder.id)
                                    .cloned()
                                    .unwrap_or_else(|| Arc::new(IgnoreFilter::for_folder_config(folder)));
                                match std::fs::symlink_metadata(&p) {
                                    Ok(meta) => {
                                        if meta.file_type().is_symlink() {
                                            continue;
                                        }
                                        if meta.is_dir() {
                                            if filter.should_sync(folder, &norm, true) {
                                                if let Some(deb) = _debouncer.as_mut() {
                                                    watch_folder_selective(
                                                        deb.watcher(),
                                                        folder,
                                                        &filter,
                                                        &mut watched_dirs,
                                                    );
                                                }
                                            }
                                            continue;
                                        }
                                        // Suppress watcher feedback loop for recently downloaded files
                                        let mtime = file_mtime_ms(&p);
                                        let sz = meta.len();
                                        let is_echo = recent_writes
                                            .lock()
                                            .ok()
                                            .and_then(|rw| rw.get(&(folder.id.clone(), norm.clone())).copied())
                                            .is_some_and(|(wm, wsz, t)| {
                                                t.elapsed() < Duration::from_secs(5) && wm == mtime && wsz == sz
                                            });
                                        if is_echo {
                                            continue;
                                        }
                                        if filter.should_sync(folder, &norm, false) {
                                            dirty_paths.insert((folder.id.clone(), norm));
                                        }
                                    }
                                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                                        if filter.should_sync(folder, &norm, false) {
                                            dirty_paths.insert((folder.id.clone(), norm.clone()));
                                        }
                                        if let Ok(m) = manifest.lock() {
                                            if let Ok(children) = m.list_folder_prefix(&folder.id, &format!("{norm}/")) {
                                                for child_rel in children {
                                                    if filter.should_sync(folder, &child_rel, false) {
                                                        dirty_paths.insert((folder.id.clone(), child_rel));
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    Err(_) => {}
                                }
                            }
                        }
                    }
                }
            }
            Some(has_remote_work) = lp_rx.recv() => {
                if !paused && (has_remote_work || !dirty_paths.is_empty()) {
                    let (dl_remaining, sync_err) = run_sync_cycle(
                        &http,
                        &config,
                        &manifest,
                        &mut tracker,
                        &mut dirty_paths,
                        &recent_writes,
                    )
                    .await;
                    let relay_status = fetch_relay_status(&http, &config).await.ok();
                    online_known = relay_status.is_some();
                    if online_known {
                        backoff_secs = 1;
                    }
                    tracker.update_status(
                        online_known,
                        false,
                        sync_err,
                        relay_status,
                        dirty_paths.len(),
                        dl_remaining,
                    );
                }
            }
            _ = poll_tick.tick() => {
                if paused {
                    tracker.update_status(false, true, None, None, dirty_paths.len(), 0);
                    continue;
                }

                if last_reconcile.elapsed() >= Duration::from_secs(300) {
                    collect_initial_changes(&config, &manifest, &mut dirty_paths);
                    last_reconcile = Instant::now();
                }

                // Skip redundant status polling when idle and already online unless 30s elapsed
                if online_known && dirty_paths.is_empty() && last_status_refresh.elapsed() < Duration::from_secs(30) {
                    continue;
                }

                let status_res = fetch_relay_status(&http, &config).await;
                let online = status_res.is_ok();
                let err_msg = status_res.as_ref().err().map(|e| e.to_string());
                let relay_status = status_res.ok();
                online_known = online;
                last_status_refresh = Instant::now();

                if online {
                    backoff_secs = 1;
                    let (discovered, added_new) = register_and_discover_peers(&http, &mut config).await;
                    if let Ok(mut g) = snapshot.lock() {
                        g.discovered_peers = discovered;
                    }
                    if added_new {
                        collect_initial_changes(&config, &manifest, &mut dirty_paths);
                    }
                    let (dl_remaining, sync_err) = run_sync_cycle(
                        &http,
                        &config,
                        &manifest,
                        &mut tracker,
                        &mut dirty_paths,
                        &recent_writes,
                    )
                    .await;

                    refresh_selective_views(&http, &config, &tracker).await;
                    tracker.update_status(
                        true,
                        false,
                        sync_err,
                        relay_status,
                        dirty_paths.len(),
                        dl_remaining,
                    );
                } else {
                    backoff_secs = (backoff_secs * 2).min(30);
                    tracker.update_status(false, false, err_msg, None, dirty_paths.len(), 0);
                }
            }
        }
    }
}

async fn run_sync_cycle(
    http: &Arc<Client>,
    config: &ClientConfig,
    manifest: &Arc<Mutex<LocalManifest>>,
    tracker: &mut SharedTracker,
    dirty_paths: &mut HashSet<(String, String)>,
    recent_writes: &RecentWrites,
) -> (usize, Option<String>) {
    // 1. Download & reconcile incoming deltas BEFORE uploading local edits
    let dl_remaining =
        process_incoming_deltas(http, config, manifest, tracker, Some(recent_writes)).await;

    // 2. Upload dirty local changes with bounded concurrency (4 workers)
    let batch: Vec<(String, String)> = dirty_paths.drain().collect();
    let sem = Arc::new(Semaphore::new(4));
    let mut join_set = JoinSet::new();
    let cfg_arc = Arc::new(config.clone());
    let mut first_err: Option<String> = None;

    for (folder_id, rel_path) in batch {
        let Some(folder) = cfg_arc.folders.iter().find(|f| f.id == folder_id).cloned() else {
            continue;
        };
        let http_c = http.clone();
        let cfg_c = cfg_arc.clone();
        let manifest_c = manifest.clone();
        let sem_c = sem.clone();
        join_set.spawn(async move {
            let _permit = sem_c.acquire_owned().await.ok();
            let res = upload_one_path_item(&http_c, &cfg_c, &folder, &rel_path, &manifest_c).await;
            (folder_id, rel_path, res)
        });
    }

    while let Some(joined) = join_set.join_next().await {
        if let Ok((folder_id, rel_path, res)) = joined {
            match res {
                Ok(Some((dir, detail))) => {
                    tracker.push_activity(dir, &folder_id, &rel_path, detail);
                }
                Ok(None) => {}
                Err(e) => {
                    warn!("Upload failed for {folder_id}/{rel_path}: {e}");
                    if first_err.is_none() {
                        first_err = Some(format!("Upload {folder_id}/{rel_path}: {e}"));
                    }
                    dirty_paths.insert((folder_id, rel_path));
                }
            }
        }
    }

    // 3. Process incoming pull requests from peers
    process_pull_requests(http, config, manifest, dirty_paths).await;

    (dl_remaining, first_err)
}

fn collect_initial_changes(
    config: &ClientConfig,
    manifest: &Arc<Mutex<LocalManifest>>,
    dirty: &mut HashSet<(String, String)>,
) {
    for folder in &config.folders {
        let Ok(root_meta) = std::fs::symlink_metadata(&folder.path) else {
            continue;
        };
        if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
            continue;
        }
        let filter = IgnoreFilter::for_folder_config(folder);
        let peer_maps: Vec<HashMap<String, String>> = if let Ok(m) = manifest.lock() {
            config
                .target_peers
                .iter()
                .map(|p| m.list_peer_synced_folder(p, &folder.id).unwrap_or_default())
                .collect()
        } else {
            Vec::new()
        };
        let mut seen_files: HashSet<String> = HashSet::new();
        let mut stack = vec![folder.path.clone()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let Ok(ft) = entry.file_type() else {
                    continue;
                };
                if ft.is_symlink() {
                    continue;
                }
                let path = entry.path();
                let Ok(rel) = path.strip_prefix(&folder.path) else {
                    continue;
                };
                let Some(norm) = normalize_rel_path(&rel.to_string_lossy()) else {
                    continue;
                };
                if ft.is_dir() {
                    // For Whitelist mode, always descend into top-level dir only if whitelisted
                    if folder.mode == SyncMode::Whitelist && !norm.contains('/') {
                        if folder.whitelist_subdirs.iter().any(|s| s == &norm) {
                            stack.push(path);
                        }
                        continue;
                    }
                    if filter.should_sync(folder, &norm, true) {
                        stack.push(path);
                    }
                } else if ft.is_file() && filter.should_sync(folder, &norm, false) {
                    seen_files.insert(norm.clone());
                    let mtime = file_mtime_ms(&path);
                    let entry_opt = manifest
                        .lock()
                        .ok()
                        .and_then(|m| m.get(&folder.id, &norm).ok().flatten());
                    let changed = match entry_opt {
                        None => true,
                        Some(ref e) => {
                            e.mtime_ms != mtime
                                || peer_maps.iter().any(|pm| {
                                    pm.get(&norm).map(String::as_str)
                                        != Some(e.blake3_hash.as_str())
                                })
                        }
                    };
                    if changed {
                        dirty.insert((folder.id.clone(), norm));
                    }
                }
            }
        }

        // Queue deletes for tracked files that are no longer present on disk (offline/missed deletes).
        if let Ok(m) = manifest.lock() {
            if let Ok(tracked) = m.list_folder(&folder.id) {
                for (rel_path, _) in tracked {
                    if !seen_files.contains(&rel_path)
                        && filter.should_sync(folder, &rel_path, false)
                    {
                        dirty.insert((folder.id.clone(), rel_path));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
async fn upload_one_path(
    http: &Client,
    config: &ClientConfig,
    folder: &SyncFolderConfig,
    rel_path: &str,
    manifest: &Arc<Mutex<LocalManifest>>,
    tracker: &mut SharedTracker,
) -> anyhow::Result<()> {
    if let Some((dir, detail)) =
        upload_one_path_item(http, config, folder, rel_path, manifest).await?
    {
        tracker.push_activity(dir, &folder.id, rel_path, detail);
    }
    Ok(())
}

async fn upload_one_path_item(
    http: &Client,
    config: &ClientConfig,
    folder: &SyncFolderConfig,
    rel_path: &str,
    manifest: &Arc<Mutex<LocalManifest>>,
) -> anyhow::Result<Option<(ActivityDirection, String)>> {
    if !IgnoreFilter::for_folder_config(folder).should_sync(folder, rel_path, false) {
        return Ok(None);
    }
    let full_path = folder.path.join(rel_path);
    let base = config.relay_url.trim_end_matches('/');

    let (enc_key, slot_key) = derive_workspace_keys(config)?;
    let slot_path = opaque_slot_path(&slot_key, &folder.id, rel_path);

    let mode_bits: u32 = match std::fs::symlink_metadata(&full_path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let existing = manifest
                .lock()
                .ok()
                .and_then(|m| m.get(&folder.id, rel_path).ok().flatten());
            let Some(entry) = existing else {
                return Ok(None);
            };
            let delta_version = manifest
                .lock()
                .ok()
                .and_then(|m| m.next_delta_version().ok())
                .unwrap_or_else(|| now_ms().max(1) as u64);
            let del_mtime = now_ms();
            for target_peer in &config.target_peers {
                let env = EncryptedEnvelope {
                    source_peer: config.peer_id.clone(),
                    target_peer: target_peer.clone(),
                    folder_id: folder.id.clone(),
                    rel_path: rel_path.to_string(),
                    op_type: OpType::Delete,
                    plaintext_blake3: String::new(),
                    raw_size: 0,
                    mtime_ms: del_mtime,
                    mode_bits: 0,
                    base_hash: Some(entry.blake3_hash.clone()),
                    delta_version,
                    payload: Vec::new(),
                    chunks: Vec::new(),
                };
                let encrypted = encrypt_envelope(config, &env)?;
                let ct_hash = blake3::hash(&encrypted).to_hex().to_string();
                let meta = DeltaUploadMeta {
                    source_peer: config.peer_id.clone(),
                    target_peer: target_peer.clone(),
                    folder_id: "e2e".to_string(),
                    rel_path: slot_path.clone(),
                    op_type: OpType::Delete,
                    blake3_hash: ct_hash,
                    base_hash: None,
                    delta_version,
                    chunk_ids: Vec::new(),
                    raw_size: 0,
                    mtime_ms: del_mtime,
                };
                let meta_header = encode_meta_header(&meta)?;
                http.put(format!("{base}/v1/deltas"))
                    .with_client_auth(config)
                    .header("X-Delta-Meta", meta_header)
                    .body(encrypted)
                    .send()
                    .await?
                    .error_for_status()?;
                if let Ok(m) = manifest.lock() {
                    let _ = m.remove_peer_synced_path(target_peer, &folder.id, rel_path);
                }
            }
            if let Ok(m) = manifest.lock() {
                let _ = m.remove(&folder.id, rel_path);
            }
            return Ok(Some((ActivityDirection::Delete, "Sent delete".to_string())));
        }
        Err(e) => return Err(e.into()),
        Ok(meta) => {
            if meta.file_type().is_symlink() || meta.is_dir() {
                return Ok(None);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                meta.permissions().mode()
            }
            #[cfg(not(unix))]
            {
                0
            }
        }
    };

    if config.target_peers.is_empty() {
        return Ok(None);
    }

    let prev_entry = manifest
        .lock()
        .ok()
        .and_then(|m| m.get(&folder.id, rel_path).ok().flatten());
    let (hash, raw_size) = stream_hash_file(&full_path)?;
    let peers_needed: Vec<String> = config
        .target_peers
        .iter()
        .filter(|peer| {
            manifest
                .lock()
                .ok()
                .and_then(|m| m.get_peer_synced(peer, &folder.id, rel_path).ok().flatten())
                .as_deref()
                != Some(hash.as_str())
        })
        .cloned()
        .collect();
    if peers_needed.is_empty() {
        if let Some(ref entry) = prev_entry {
            if entry.blake3_hash == hash {
                return Ok(None);
            }
        }
        let mtime_ms = file_mtime_ms(&full_path);
        if let Ok(m) = manifest.lock() {
            let _ = m.upsert(&folder.id, rel_path, &hash, mtime_ms);
        }
        return Ok(None);
    }

    let base_hash = prev_entry.map(|e| e.blake3_hash);
    let mtime_ms = file_mtime_ms(&full_path);
    let delta_version = manifest
        .lock()
        .ok()
        .and_then(|m| m.next_delta_version().ok())
        .unwrap_or_else(|| now_ms().max(1) as u64);

    let (inline_payload, chunk_refs, sent_bytes) = if raw_size <= CHUNK_THRESHOLD {
        let raw_bytes = std::fs::read(&full_path)?;
        let compressed = zstd::encode_all(raw_bytes.as_slice(), 3)?;
        let len = compressed.len() as u64;
        (compressed, Vec::new(), len)
    } else {
        // Stream-chunk file using FastCDC without loading the full file into memory.
        let mut file = std::fs::File::open(&full_path)?;
        let mut window = vec![0u8; CHUNK_MAX_SIZE];
        let mut valid = 0usize;
        let mut offset = 0u64;
        let mut chunk_specs: Vec<(ChunkRef, u64)> = Vec::new();
        loop {
            while valid < CHUNK_MAX_SIZE {
                let n = file.read(&mut window[valid..])?;
                if n == 0 {
                    break;
                }
                valid += n;
            }
            if valid == 0 {
                break;
            }
            let cut = next_fastcdc_boundary(&window[..valid], CHUNK_MIN_SIZE, CHUNK_MAX_SIZE);
            let slice = &window[..cut];
            let chunk_id = blake3::keyed_hash(&slot_key, slice).to_hex().to_string();
            let plain_hash = blake3::hash(slice).to_hex().to_string();
            chunk_specs.push((
                ChunkRef {
                    chunk_id,
                    raw_size: cut as u64,
                    plaintext_blake3: plain_hash,
                },
                offset,
            ));
            offset += cut as u64;
            window.copy_within(cut..valid, 0);
            valid -= cut;
        }

        let all_ids: Vec<String> = chunk_specs
            .iter()
            .map(|(c, _)| c.chunk_id.clone())
            .collect();
        let has_resp: HasChunksResponse = http
            .post(format!("{base}/v1/chunks/has"))
            .with_client_auth(config)
            .json(&HasChunksRequest { chunk_ids: all_ids })
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let missing_set: HashSet<String> = has_resp.missing.into_iter().collect();

        let mut uploaded_bytes = 0u64;
        let mut seen_uploaded: HashSet<String> = HashSet::new();
        let mut chunk_buf = Vec::new();
        for (spec, off) in &chunk_specs {
            if !missing_set.contains(&spec.chunk_id) || !seen_uploaded.insert(spec.chunk_id.clone())
            {
                continue;
            }
            file.seek(SeekFrom::Start(*off))?;
            chunk_buf.resize(spec.raw_size as usize, 0);
            file.read_exact(&mut chunk_buf)?;
            let compressed = zstd::encode_all(chunk_buf.as_slice(), 3)?;
            let encrypted_chunk =
                encrypt_chunk(&enc_key, &config.workspace_id, &spec.chunk_id, &compressed)?;
            uploaded_bytes += encrypted_chunk.len() as u64;
            http.put(format!("{base}/v1/chunks/{}", spec.chunk_id))
                .with_client_auth(config)
                .body(encrypted_chunk)
                .send()
                .await?
                .error_for_status()?;
        }
        let refs: Vec<ChunkRef> = chunk_specs.into_iter().map(|(c, _)| c).collect();
        (Vec::new(), refs, uploaded_bytes)
    };

    let chunk_ids: Vec<String> = chunk_refs.iter().map(|c| c.chunk_id.clone()).collect();
    let mut last_ct_len = sent_bytes;
    for target_peer in &peers_needed {
        let env = EncryptedEnvelope {
            source_peer: config.peer_id.clone(),
            target_peer: target_peer.clone(),
            folder_id: folder.id.clone(),
            rel_path: rel_path.to_string(),
            op_type: OpType::Upsert,
            plaintext_blake3: hash.clone(),
            raw_size,
            mtime_ms,
            mode_bits,
            base_hash: base_hash.clone(),
            delta_version,
            payload: inline_payload.clone(),
            chunks: chunk_refs.clone(),
        };
        let encrypted = encrypt_envelope(config, &env)?;
        if chunk_ids.is_empty() {
            last_ct_len = encrypted.len() as u64;
        }
        let ct_hash = blake3::hash(&encrypted).to_hex().to_string();
        let meta = DeltaUploadMeta {
            source_peer: config.peer_id.clone(),
            target_peer: target_peer.clone(),
            folder_id: "e2e".to_string(),
            rel_path: slot_path.clone(),
            op_type: OpType::Upsert,
            blake3_hash: ct_hash,
            base_hash: None,
            delta_version,
            chunk_ids: chunk_ids.clone(),
            raw_size: 0,
            mtime_ms,
        };
        let meta_header = encode_meta_header(&meta)?;
        http.put(format!("{base}/v1/deltas"))
            .with_client_auth(config)
            .header("X-Delta-Meta", meta_header)
            .body(encrypted)
            .send()
            .await?
            .error_for_status()?;
        if let Ok(m) = manifest.lock() {
            let _ = m.set_peer_synced(target_peer, &folder.id, rel_path, &hash);
        }
    }

    if let Ok(m) = manifest.lock() {
        let _ = m.upsert(&folder.id, rel_path, &hash, mtime_ms);
    }
    let detail = if chunk_ids.is_empty() {
        format!(
            "{} -> {} e2e",
            deltadrop_common::format_bytes(raw_size),
            deltadrop_common::format_bytes(last_ct_len)
        )
    } else {
        format!(
            "{} ({} chunks, {} uploaded)",
            deltadrop_common::format_bytes(raw_size),
            chunk_ids.len(),
            deltadrop_common::format_bytes(last_ct_len)
        )
    };
    Ok(Some((ActivityDirection::Upload, detail)))
}

async fn process_incoming_deltas(
    http: &Client,
    config: &ClientConfig,
    manifest: &Arc<Mutex<LocalManifest>>,
    tracker: &mut SharedTracker,
    recent_writes: Option<&RecentWrites>,
) -> usize {
    let base = config.relay_url.trim_end_matches('/');
    let Ok(resp) = http
        .get(format!("{base}/v1/deltas"))
        .query(&[("peer", &config.peer_id)])
        .with_client_auth(config)
        .send()
        .await
        .and_then(|r| r.error_for_status())
    else {
        return 0;
    };
    let Ok(deltas) = resp.json::<Vec<PendingDelta>>().await else {
        return 0;
    };
    let total_deltas = deltas.len();
    let mut acked_count = 0usize;
    let Ok((enc_key, _)) = derive_workspace_keys(config) else {
        return total_deltas;
    };

    for delta in deltas {
        let Ok(blob_resp) = http
            .get(format!("{base}/v1/deltas/{}/blob", delta.id))
            .query(&[("peer", &config.peer_id)])
            .with_client_auth(config)
            .send()
            .await
            .and_then(|r| r.error_for_status())
        else {
            warn!(
                "Blob fetch failed for delta {} (unauthenticated or missing)",
                delta.id
            );
            continue;
        };
        let Ok(enc_bytes) = blob_resp.bytes().await else {
            continue;
        };
        if !delta.blake3_hash.is_empty() {
            let ct_hash = blake3::hash(enc_bytes.as_ref()).to_hex().to_string();
            if ct_hash != delta.blake3_hash {
                warn!("Ciphertext hash mismatch for delta {}", delta.id);
                continue;
            }
        }
        let env = match decrypt_envelope(config, enc_bytes.as_ref(), delta.delta_version) {
            Ok(e) => e,
            Err(e) => {
                warn!("Rejected tampered/unauthenticated delta {}: {e}", delta.id);
                continue;
            }
        };
        if env.target_peer != config.peer_id
            || env.source_peer != delta.source_peer
            || env.delta_version != delta.delta_version
        {
            warn!("Envelope metadata mismatch on delta {}", delta.id);
            continue;
        }
        let Some(folder) = config.folders.iter().find(|f| f.id == env.folder_id) else {
            continue;
        };
        let Some(rel) = normalize_rel_path(&env.rel_path) else {
            continue;
        };
        if let Ok(m) = manifest.lock() {
            if let Ok(Some(prev_ver)) = m.get_peer_version(&env.source_peer, &env.folder_id, &rel) {
                if env.delta_version <= prev_ver {
                    warn!(
                        "Rejected rolled-back delta {} for {}/{} (ver {} <= {})",
                        delta.id, env.folder_id, rel, env.delta_version, prev_ver
                    );
                    continue;
                }
            }
        }

        let filter = IgnoreFilter::for_folder_config(folder);

        if env.op_type == OpType::Delete {
            if filter.should_sync(folder, &rel, false) {
                let target = folder.path.join(&rel);
                let mut preserved_conflict = false;
                if let Ok(meta) = std::fs::symlink_metadata(&target) {
                    if meta.file_type().is_symlink() {
                        warn!("Skipping remote delete for symlink {}", target.display());
                        continue;
                    }
                    if meta.is_file() {
                        let local_hash = stream_hash_file(&target).ok().map(|(h, _)| h);
                        let last_synced = manifest
                            .lock()
                            .ok()
                            .and_then(|m| m.get(&folder.id, &rel).ok().flatten())
                            .map(|e| e.blake3_hash);
                        let locally_modified = match (&local_hash, &last_synced) {
                            (Some(lh), Some(ls)) => lh != ls,
                            (Some(_), None) => true,
                            _ => false,
                        };
                        let base_mismatch = match (&local_hash, &env.base_hash) {
                            (Some(lh), Some(bh)) => lh != bh,
                            _ => false,
                        };
                        if locally_modified || base_mismatch {
                            preserved_conflict = true;
                            if let Ok(m) = manifest.lock() {
                                let _ = m.remove(&folder.id, &rel);
                                let _ =
                                    m.remove_peer_synced_path(&env.source_peer, &folder.id, &rel);
                            }
                            let target_str = target.to_string_lossy().to_string();
                            tracker.push_conflict(manifest, &folder.id, &rel, &target_str);
                            tracker.push_activity(
                                ActivityDirection::Conflict,
                                &folder.id,
                                &rel,
                                "Kept locally edited file against remote delete",
                            );
                        } else if let Err(e) = std::fs::remove_file(&target) {
                            warn!("Failed removing {}: {e}", target.display());
                            continue;
                        }
                    }
                }
                if !preserved_conflict {
                    if let Ok(m) = manifest.lock() {
                        let _ = m.remove(&folder.id, &rel);
                        let _ = m.remove_peer_synced_path(&env.source_peer, &folder.id, &rel);
                    }
                    tracker.push_activity(
                        ActivityDirection::Delete,
                        &folder.id,
                        &rel,
                        "Applied remote delete",
                    );
                }
            }
            if let Ok(m) = manifest.lock() {
                let _ =
                    m.set_peer_version(&env.source_peer, &env.folder_id, &rel, env.delta_version);
            }
            if send_ack(http, config, delta.id, &delta.blake3_hash)
                .await
                .is_ok()
            {
                acked_count += 1;
            }
            continue;
        }

        if !filter.should_sync(folder, &rel, false) {
            if send_ack(http, config, delta.id, &delta.blake3_hash)
                .await
                .is_ok()
            {
                acked_count += 1;
            }
            continue;
        }

        let target = folder.path.join(&rel);
        let Ok(tmp_path) = make_temp_sibling(&target) else {
            continue;
        };

        // Try local rename/copy reuse first if another file in the same folder already has this hash.
        let mut assembled_ok = false;
        if let Ok(m) = manifest.lock() {
            if let Ok(Some(existing_rel)) =
                m.find_by_hash_in_folder(&folder.id, &env.plaintext_blake3)
            {
                let existing_path = folder.path.join(&existing_rel);
                if let Ok((eh, _)) = stream_hash_file(&existing_path) {
                    if eh == env.plaintext_blake3
                        && std::fs::copy(&existing_path, &tmp_path).is_ok()
                    {
                        assembled_ok = true;
                    }
                }
            }
        }

        if !assembled_ok {
            if !env.chunks.is_empty() {
                let write_res: anyhow::Result<()> = async {
                    let f = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&tmp_path)?;
                    let mut writer = std::io::BufWriter::new(f);
                    let mut whole_hasher = blake3::Hasher::new();
                    for chunk_ref in &env.chunks {
                        let c_resp = http
                            .get(format!("{base}/v1/chunks/{}", chunk_ref.chunk_id))
                            .with_client_auth(config)
                            .send()
                            .await?
                            .error_for_status()?;
                        let enc_chunk = c_resp.bytes().await?;
                        let plain_chunk = decrypt_chunk(
                            &enc_key,
                            &config.workspace_id,
                            &chunk_ref.chunk_id,
                            enc_chunk.as_ref(),
                            chunk_ref.raw_size,
                        )?;
                        let ch = blake3::hash(&plain_chunk).to_hex().to_string();
                        if ch != chunk_ref.plaintext_blake3 {
                            anyhow::bail!("Chunk checksum mismatch for {}", chunk_ref.chunk_id);
                        }
                        whole_hasher.update(&plain_chunk);
                        writer.write_all(&plain_chunk)?;
                    }
                    writer.flush()?;
                    writer.get_ref().sync_all()?;
                    let whole_hash = whole_hasher.finalize().to_hex().to_string();
                    if whole_hash != env.plaintext_blake3 {
                        anyhow::bail!("Assembled file checksum mismatch");
                    }
                    Ok(())
                }
                .await;
                if let Err(e) = write_res {
                    let _ = std::fs::remove_file(&tmp_path);
                    warn!("Chunked download failed for {}/{}: {e}", env.folder_id, rel);
                    continue;
                }
            } else {
                let raw_bytes = match decompress_zstd_bounded(env.payload.as_slice(), env.raw_size)
                {
                    Ok(b) => b,
                    Err(e) => {
                        let _ = std::fs::remove_file(&tmp_path);
                        warn!("Decompression failed for {}/{}: {e}", env.folder_id, rel);
                        continue;
                    }
                };
                let computed = blake3::hash(&raw_bytes).to_hex().to_string();
                if computed != env.plaintext_blake3 {
                    let _ = std::fs::remove_file(&tmp_path);
                    warn!("Checksum mismatch for {}/{}", env.folder_id, rel);
                    continue;
                }
                let write_res = (|| -> std::io::Result<()> {
                    let mut f = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&tmp_path)?;
                    f.write_all(&raw_bytes)?;
                    f.sync_all()?;
                    Ok(())
                })();
                if let Err(e) = write_res {
                    let _ = std::fs::remove_file(&tmp_path);
                    error!("Temp write failed for {}: {e}", target.display());
                    continue;
                }
            }
        }

        let computed = env.plaintext_blake3.clone();
        if let Ok(meta) = std::fs::symlink_metadata(&target) {
            if meta.file_type().is_symlink() {
                let _ = std::fs::remove_file(&tmp_path);
                warn!("Refusing to overwrite symlink {}", target.display());
                continue;
            }
            if meta.is_file() {
                if let Ok((local_hash, _)) = stream_hash_file(&target) {
                    if local_hash == computed {
                        let _ = std::fs::remove_file(&tmp_path);
                        let mtime = file_mtime_ms(&target);
                        if let Ok(m) = manifest.lock() {
                            let _ = m.upsert(&folder.id, &rel, &computed, mtime);
                            let _ =
                                m.set_peer_synced(&env.source_peer, &folder.id, &rel, &computed);
                            let _ = m.set_peer_version(
                                &env.source_peer,
                                &env.folder_id,
                                &rel,
                                env.delta_version,
                            );
                        }
                        if send_ack(http, config, delta.id, &delta.blake3_hash)
                            .await
                            .is_ok()
                        {
                            acked_count += 1;
                        }
                        continue;
                    }
                    let last_synced = manifest
                        .lock()
                        .ok()
                        .and_then(|m| m.get(&folder.id, &rel).ok().flatten())
                        .map(|e| e.blake3_hash);
                    let locally_modified = last_synced.as_deref() != Some(local_hash.as_str());
                    let concurrent_base = env.base_hash.as_deref() != Some(local_hash.as_str());
                    if locally_modified || concurrent_base {
                        let conflict_path = make_conflict_path(&target, &config.peer_id);
                        let remote_wins = computed.as_str() > local_hash.as_str();
                        if remote_wins {
                            if let Err(e) = std::fs::copy(&target, &conflict_path) {
                                let _ = std::fs::remove_file(&tmp_path);
                                error!(
                                    "Aborting overwrite of {}: failed to save conflict copy {}: {e}",
                                    target.display(),
                                    conflict_path.display()
                                );
                                continue;
                            }
                            let cp_str = conflict_path.to_string_lossy().to_string();
                            tracker.push_conflict(manifest, &folder.id, &rel, &cp_str);
                            tracker.push_activity(
                                ActivityDirection::Conflict,
                                &folder.id,
                                &rel,
                                "Saved .sync-conflict copy (remote kept)",
                            );
                        } else {
                            if let Err(e) = atomic_rename_temp(&tmp_path, &conflict_path) {
                                error!(
                                    "Aborting conflict handling for {}: failed to save conflict copy {}: {e}",
                                    target.display(),
                                    conflict_path.display()
                                );
                                continue;
                            }
                            let cp_str = conflict_path.to_string_lossy().to_string();
                            tracker.push_conflict(manifest, &folder.id, &rel, &cp_str);
                            tracker.push_activity(
                                ActivityDirection::Conflict,
                                &folder.id,
                                &rel,
                                "Saved .sync-conflict copy (local kept)",
                            );
                            if let Ok(m) = manifest.lock() {
                                let _ = m.upsert(&folder.id, &rel, &computed, -1);
                                let _ = m.set_peer_synced(
                                    &env.source_peer,
                                    &folder.id,
                                    &rel,
                                    &computed,
                                );
                                let _ = m.set_peer_version(
                                    &env.source_peer,
                                    &env.folder_id,
                                    &rel,
                                    env.delta_version,
                                );
                            }
                            if send_ack(http, config, delta.id, &delta.blake3_hash)
                                .await
                                .is_ok()
                            {
                                acked_count += 1;
                            }
                            continue;
                        }
                    }
                }
            }
        }

        if let Err(e) = atomic_rename_temp(&tmp_path, &target) {
            error!("Atomic rename failed for {}: {e}", target.display());
            continue;
        }
        #[cfg(unix)]
        if env.mode_bits != 0 {
            use std::os::unix::fs::PermissionsExt;
            let _ =
                std::fs::set_permissions(&target, std::fs::Permissions::from_mode(env.mode_bits));
        }
        let mtime = file_mtime_ms(&target);
        if let Some(rw_map) = recent_writes {
            if let Ok(mut rw) = rw_map.lock() {
                rw.insert(
                    (folder.id.clone(), rel.clone()),
                    (mtime, env.raw_size, Instant::now()),
                );
            }
        }
        if let Ok(m) = manifest.lock() {
            let _ = m.upsert(&folder.id, &rel, &computed, mtime);
            let _ = m.set_peer_synced(&env.source_peer, &folder.id, &rel, &computed);
            let _ = m.set_peer_version(&env.source_peer, &env.folder_id, &rel, env.delta_version);
        }
        if send_ack(http, config, delta.id, &delta.blake3_hash)
            .await
            .is_ok()
        {
            acked_count += 1;
            tracker.push_activity(
                ActivityDirection::Download,
                &folder.id,
                &rel,
                format!("{} verified", deltadrop_common::format_bytes(env.raw_size)),
            );
        }
    }

    total_deltas.saturating_sub(acked_count)
}

async fn send_ack(
    http: &Client,
    config: &ClientConfig,
    delta_id: i64,
    verified_blake3: &str,
) -> anyhow::Result<()> {
    let base = config.relay_url.trim_end_matches('/');
    http.post(format!("{base}/v1/ack"))
        .with_client_auth(config)
        .json(&AckRequest {
            target_peer: config.peer_id.clone(),
            delta_id,
            verified_blake3: verified_blake3.to_string(),
        })
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

async fn fetch_relay_status(http: &Client, config: &ClientConfig) -> anyhow::Result<RelayStatus> {
    let base = config.relay_url.trim_end_matches('/');
    let resp = http
        .get(format!("{base}/v1/status"))
        .with_client_auth(config)
        .send()
        .await?;
    if resp.status() == reqwest::StatusCode::UPGRADE_REQUIRED {
        anyhow::bail!("Protocol mismatch (client v{PROTOCOL_VERSION}) - update client or relay");
    }
    if let Some(ver) = resp
        .headers()
        .get(PROTOCOL_HEADER)
        .and_then(|v| v.to_str().ok())
    {
        if ver.trim() != PROTOCOL_VERSION {
            anyhow::bail!(
                "Protocol mismatch (client v{PROTOCOL_VERSION}, relay v{}) - update client or relay",
                ver.trim()
            );
        }
    }
    let st = resp.error_for_status()?.json::<RelayStatus>().await?;
    Ok(st)
}

async fn publish_all_folder_indices(http: &Client, config: &ClientConfig) {
    let base = config.relay_url.trim_end_matches('/');
    for folder in &config.folders {
        let Ok(root_meta) = std::fs::symlink_metadata(&folder.path) else {
            continue;
        };
        if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
            continue;
        }
        let mut subdirs = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&folder.path) {
            for entry in entries.flatten() {
                if let Ok(ft) = entry.file_type() {
                    if ft.is_dir() && !ft.is_symlink() {
                        if let Some(name) = entry.file_name().to_str() {
                            if !name.starts_with('.') {
                                subdirs.push(name.to_string());
                            }
                        }
                    }
                }
            }
        }
        subdirs.sort();
        let payload = FolderIndexPayload {
            source_peer: config.peer_id.clone(),
            folder_id: folder.id.clone(),
            subdirs,
            updated_at_ms: now_ms(),
        };
        let _ = http
            .put(format!("{base}/v1/folder-index"))
            .with_client_auth(config)
            .json(&payload)
            .send()
            .await;
    }
}

async fn send_pull_request(
    http: &Client,
    config: &ClientConfig,
    target_peer: &str,
    folder_id: &str,
    subdir: &str,
) -> anyhow::Result<()> {
    let base = config.relay_url.trim_end_matches('/');
    http.post(format!("{base}/v1/pull-requests"))
        .with_client_auth(config)
        .json(&PullRequest {
            source_peer: config.peer_id.clone(),
            target_peer: target_peer.to_string(),
            folder_id: folder_id.to_string(),
            subdir: subdir.to_string(),
        })
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

async fn process_pull_requests(
    http: &Client,
    config: &ClientConfig,
    manifest: &Arc<Mutex<LocalManifest>>,
    dirty_paths: &mut HashSet<(String, String)>,
) {
    let base = config.relay_url.trim_end_matches('/');
    let Ok(resp) = http
        .get(format!("{base}/v1/pull-requests"))
        .query(&[("peer", &config.peer_id)])
        .with_client_auth(config)
        .send()
        .await
    else {
        return;
    };
    let Ok(reqs) = resp.json::<Vec<PendingPullRequest>>().await else {
        return;
    };

    let processed_any = !reqs.is_empty();
    for req in reqs {
        if let Some(folder) = config.folders.iter().find(|f| f.id == req.folder_id) {
            let sub_root = if req.subdir == "*" {
                folder.path.clone()
            } else {
                folder.path.join(&req.subdir)
            };
            if std::fs::symlink_metadata(&sub_root)
                .map(|m| m.is_dir() && !m.file_type().is_symlink())
                .unwrap_or(false)
            {
                if let Ok(m) = manifest.lock() {
                    let pfx = if req.subdir == "*" {
                        None
                    } else {
                        Some(req.subdir.as_str())
                    };
                    let _ = m.clear_peer_synced_folder(&req.source_peer, &folder.id, pfx);
                }
                let filter = IgnoreFilter::for_folder_config(folder);
                let mut stack = vec![sub_root];
                while let Some(dir) = stack.pop() {
                    if let Ok(entries) = std::fs::read_dir(&dir) {
                        for entry in entries.flatten() {
                            let Ok(ft) = entry.file_type() else {
                                continue;
                            };
                            if ft.is_symlink() {
                                continue;
                            }
                            let p = entry.path();
                            if let Ok(rel) = p.strip_prefix(&folder.path) {
                                if let Some(norm) = normalize_rel_path(&rel.to_string_lossy()) {
                                    if ft.is_dir() {
                                        if filter.should_sync(folder, &norm, true) {
                                            stack.push(p);
                                        }
                                    } else if ft.is_file()
                                        && filter.should_sync(folder, &norm, false)
                                    {
                                        dirty_paths.insert((folder.id.clone(), norm));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        let _ = http
            .post(format!("{base}/v1/pull-requests/ack"))
            .with_client_auth(config)
            .json(&AckPullRequest {
                target_peer: config.peer_id.clone(),
                request_id: req.id,
            })
            .send()
            .await;
    }
    if processed_any {
        info!("Processed pull requests");
    }
}

async fn refresh_selective_views(http: &Client, config: &ClientConfig, tracker: &SharedTracker) {
    let base = config.relay_url.trim_end_matches('/');
    let mut views = Vec::new();
    let mut remote_map: std::collections::HashMap<String, FolderIndexPayload> =
        std::collections::HashMap::new();

    for peer in &config.target_peers {
        if let Ok(resp) = http
            .get(format!("{base}/v1/folder-indices"))
            .query(&[("source_peer", peer)])
            .with_client_auth(config)
            .send()
            .await
        {
            if let Ok(list) = resp.json::<Vec<FolderIndexPayload>>().await {
                for idx in list {
                    remote_map.insert(idx.folder_id.clone(), idx);
                }
            }
        }
    }

    for folder in &config.folders {
        let mut all_subdirs: HashSet<String> = folder.whitelist_subdirs.iter().cloned().collect();
        let mut source_peer = config.target_peers.first().cloned().unwrap_or_default();

        if let Ok(entries) = std::fs::read_dir(&folder.path) {
            for e in entries.flatten() {
                if let Ok(ft) = e.file_type() {
                    if ft.is_dir() && !ft.is_symlink() {
                        if let Some(name) = e.file_name().to_str() {
                            if !name.starts_with('.') {
                                all_subdirs.insert(name.to_string());
                            }
                        }
                    }
                }
            }
        }

        if let Some(idx) = remote_map.get(&folder.id) {
            source_peer = idx.source_peer.clone();
            for s in &idx.subdirs {
                all_subdirs.insert(s.clone());
            }
        }

        let mut sorted: Vec<String> = all_subdirs.into_iter().collect();
        sorted.sort();
        let subdirs = sorted
            .into_iter()
            .map(|name| SubdirToggleItem {
                whitelisted: folder.whitelist_subdirs.contains(&name),
                name,
            })
            .collect();

        views.push(SelectiveFolderView {
            folder_id: folder.id.clone(),
            label: folder.display_name().to_string(),
            mode: folder.mode,
            source_peer,
            subdirs,
        });
    }

    let local_ids: HashSet<&str> = config.folders.iter().map(|f| f.id.as_str()).collect();
    let mut unmapped: Vec<RemoteFolderStub> = remote_map
        .into_values()
        .filter(|idx| !local_ids.contains(idx.folder_id.as_str()))
        .map(|idx| RemoteFolderStub {
            source_peer: idx.source_peer,
            folder_id: idx.folder_id,
            subdir_count: idx.subdirs.len(),
        })
        .collect();
    unmapped.sort_by(|a, b| a.folder_id.cmp(&b.folder_id));

    tracker.set_folder_views(views, unmapped);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::load_or_create_config;
    use tempfile::TempDir;

    struct TestPeer {
        _dir: TempDir,
        folder_path: PathBuf,
        config: ClientConfig,
        manifest: Arc<Mutex<LocalManifest>>,
        tracker: SharedTracker,
        snapshot: Arc<Mutex<UiSnapshot>>,
    }

    impl TestPeer {
        fn new(peer_id: &str, target_peers: Vec<&str>, relay_url: &str) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let folder_path = dir.path().join("sync");
            std::fs::create_dir_all(&folder_path).unwrap();
            let db_path = dir.path().join("manifest.db");
            let manifest = Arc::new(Mutex::new(LocalManifest::open(&db_path).unwrap()));
            let config = ClientConfig {
                peer_id: peer_id.to_string(),
                target_peers: target_peers.into_iter().map(str::to_string).collect(),
                auto_discover_peers: false,
                relay_url: relay_url.to_string(),
                auth_token: "test-token".to_string(),
                workspace_id: "test-workspace".to_string(),
                encryption_key: Some(
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
                ),
                poll_interval_secs: 1,
                manifest_db_path: Some(db_path),
                folders: vec![SyncFolderConfig {
                    id: "shared".to_string(),
                    label: None,
                    path: folder_path.clone(),
                    mode: SyncMode::Full,
                    whitelist_subdirs: Vec::new(),
                    ignore_rules: Vec::new(),
                    custom_ignore: String::new(),
                }],
                ..ClientConfig::default()
            };
            let snapshot = Arc::new(Mutex::new(UiSnapshot::default()));
            let tracker = SharedTracker::new(snapshot.clone(), None);
            Self {
                _dir: dir,
                folder_path,
                config,
                manifest,
                tracker,
                snapshot,
            }
        }

        async fn sync_once(&mut self, http: &Client) {
            // Download & reconcile BEFORE upload, matching run_sync_loop
            let _ = process_incoming_deltas(
                http,
                &self.config,
                &self.manifest,
                &mut self.tracker,
                None,
            )
            .await;
            let mut dirty = HashSet::new();
            collect_initial_changes(&self.config, &self.manifest, &mut dirty);
            for (folder_id, rel_path) in dirty {
                if let Some(folder) = self.config.folders.iter().find(|f| f.id == folder_id) {
                    upload_one_path(
                        http,
                        &self.config,
                        folder,
                        &rel_path,
                        &self.manifest,
                        &mut self.tracker,
                    )
                    .await
                    .unwrap();
                }
            }
        }
    }

    async fn spawn_test_relay() -> (TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let blobs_dir = dir.path().join("blobs");
        std::fs::create_dir_all(&blobs_dir).unwrap();
        let conn = deltadrop_relay::init_db(&dir.path().join("relay.db")).unwrap();
        let state = deltadrop_relay::AppState::new(
            conn,
            blobs_dir,
            "test-token".to_string(),
            64 * 1024 * 1024,
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            deltadrop_relay::serve_on(listener, state).await.unwrap();
        });
        (dir, format!("http://{addr}"))
    }

    #[tokio::test]
    async fn concurrent_offline_edits_create_conflict_without_swap() {
        let (_relay_dir, relay_url) = spawn_test_relay().await;
        let http = Client::new();
        let mut peer_a = TestPeer::new("peer-a", vec!["peer-b"], &relay_url);
        let mut peer_b = TestPeer::new("peer-b", vec!["peer-a"], &relay_url);

        // 1. Initial sync of V0
        std::fs::write(peer_a.folder_path.join("notes.md"), b"base-v0").unwrap();
        peer_a.sync_once(&http).await;
        peer_b.sync_once(&http).await;
        assert_eq!(
            std::fs::read(peer_b.folder_path.join("notes.md")).unwrap(),
            b"base-v0"
        );

        // 2. Both edit offline concurrently
        std::thread::sleep(Duration::from_millis(15));
        std::fs::write(peer_a.folder_path.join("notes.md"), b"edit-from-A").unwrap();
        std::fs::write(peer_b.folder_path.join("notes.md"), b"edit-from-B").unwrap();

        // 3. A syncs first, then B syncs (Download before Upload catches conflict)
        peer_a.sync_once(&http).await;
        peer_b.sync_once(&http).await;
        peer_a.sync_once(&http).await;

        let content_a = std::fs::read(peer_a.folder_path.join("notes.md")).unwrap();
        let content_b = std::fs::read(peer_b.folder_path.join("notes.md")).unwrap();
        assert_eq!(content_a, content_b, "peers must converge to the same file");

        let conflicts_b = peer_b.snapshot.lock().unwrap().conflicts.clone();
        assert_eq!(conflicts_b.len(), 1, "peer B must record a conflict alert");
        let conflict_file = PathBuf::from(&conflicts_b[0].conflict_path);
        assert!(
            conflict_file.exists(),
            "conflict backup file must exist on disk"
        );
    }

    #[tokio::test]
    async fn offline_edit_vs_remote_delete_preserves_local_edit() {
        let (_relay_dir, relay_url) = spawn_test_relay().await;
        let http = Client::new();
        let mut peer_a = TestPeer::new("peer-a", vec!["peer-b"], &relay_url);
        let mut peer_b = TestPeer::new("peer-b", vec!["peer-a"], &relay_url);

        std::fs::write(peer_a.folder_path.join("doc.txt"), b"initial").unwrap();
        peer_a.sync_once(&http).await;
        peer_b.sync_once(&http).await;

        // A deletes doc.txt while B edits doc.txt
        std::fs::remove_file(peer_a.folder_path.join("doc.txt")).unwrap();
        std::thread::sleep(Duration::from_millis(15));
        std::fs::write(
            peer_b.folder_path.join("doc.txt"),
            b"important-offline-edit",
        )
        .unwrap();

        peer_a.sync_once(&http).await;
        peer_b.sync_once(&http).await;

        assert!(peer_b.folder_path.join("doc.txt").exists());
        assert_eq!(
            std::fs::read(peer_b.folder_path.join("doc.txt")).unwrap(),
            b"important-offline-edit"
        );
        assert_eq!(peer_b.snapshot.lock().unwrap().conflicts.len(), 1);

        // B's preserved edit should re-sync back to A
        peer_a.sync_once(&http).await;
        assert_eq!(
            std::fs::read(peer_a.folder_path.join("doc.txt")).unwrap(),
            b"important-offline-edit"
        );
    }

    #[tokio::test]
    async fn offline_and_unicode_and_dir_deletes_propagate() {
        let (_relay_dir, relay_url) = spawn_test_relay().await;
        let http = Client::new();
        let mut peer_a = TestPeer::new("peer-a", vec!["peer-b"], &relay_url);
        let mut peer_b = TestPeer::new("peer-b", vec!["peer-a"], &relay_url);

        // Non-ASCII / Unicode filename inside a nested folder
        let sub = peer_a.folder_path.join("café");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("résumé-メモ.txt"), b"hello unicode").unwrap();

        peer_a.sync_once(&http).await;
        peer_b.sync_once(&http).await;

        let b_file = peer_b.folder_path.join("café").join("résumé-メモ.txt");
        assert_eq!(std::fs::read(&b_file).unwrap(), b"hello unicode");

        // Offline directory deletion on A
        std::fs::remove_dir_all(&sub).unwrap();
        peer_a.sync_once(&http).await;
        peer_b.sync_once(&http).await;
        assert!(
            !b_file.exists(),
            "offline dir delete must propagate to peer B"
        );
    }

    #[test]
    fn config_handles_utf8_bom_and_bounded_zstd_rejects_bomb() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("deltadrop-config.json");
        let json = serde_json::to_string_pretty(&ClientConfig::default()).unwrap();
        let with_bom = format!("\u{FEFF}{json}");
        std::fs::write(&cfg_path, with_bom).unwrap();
        let loaded = load_or_create_config(&cfg_path).unwrap();
        assert_eq!(loaded.poll_interval_secs, 3);

        // Compress 4096 bytes but claim raw_size is 128 bytes
        let compressed = zstd::encode_all(&vec![b'A'; 4096][..], 3).unwrap();
        assert!(decompress_zstd_bounded(&compressed, 128).is_err());
        assert_eq!(
            decompress_zstd_bounded(&compressed, 4096).unwrap().len(),
            4096
        );
    }

    #[tokio::test]
    async fn symlinks_are_skipped_by_scanner() {
        let (_relay_dir, relay_url) = spawn_test_relay().await;
        let peer = TestPeer::new("peer-a", vec!["peer-b"], &relay_url);
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.txt"), b"secret").unwrap();
        let link_path = peer.folder_path.join("escape-link");

        #[cfg(unix)]
        let created = std::os::unix::fs::symlink(outside.path(), &link_path).is_ok();
        #[cfg(windows)]
        let created = std::os::windows::fs::symlink_dir(outside.path(), &link_path).is_ok();

        if created {
            let mut dirty = HashSet::new();
            collect_initial_changes(&peer.config, &peer.manifest, &mut dirty);
            assert!(
                !dirty.iter().any(|(_, p)| p.contains("secret.txt")),
                "scanner must never follow symlinks outside sync root"
            );
        }
    }

    #[test]
    fn encryption_never_falls_back_to_auth_token_and_argon2id_works() {
        let mut cfg = ClientConfig {
            peer_id: "a".into(),
            target_peers: vec!["b".into()],
            auto_discover_peers: false,
            relay_url: "http://127.0.0.1:8787".into(),
            auth_token: "relay-knows-this".into(),
            workspace_id: "ws-1".into(),
            encryption_key: None,
            poll_interval_secs: 3,
            manifest_db_path: None,
            folders: vec![],
            ..ClientConfig::default()
        };
        assert!(
            derive_workspace_keys(&cfg).is_err(),
            "empty encryption_key must error"
        );
        cfg.encryption_key = Some("   ".into());
        assert!(
            derive_workspace_keys(&cfg).is_err(),
            "blank encryption_key must error"
        );

        cfg.encryption_key = Some("correct horse battery staple".into());
        let (k1, s1) = derive_workspace_keys(&cfg).unwrap();
        let (k2, s2) = derive_workspace_keys(&cfg).unwrap();
        assert_eq!(k1, k2);
        assert_eq!(s1, s2);
    }

    #[tokio::test]
    async fn relay_tampering_forged_delete_and_rollback_are_rejected() {
        let (_relay_dir, relay_url) = spawn_test_relay().await;
        let http = Client::new();
        let mut peer_a = TestPeer::new("peer-a", vec!["peer-b"], &relay_url);
        let mut peer_b = TestPeer::new("peer-b", vec!["peer-a"], &relay_url);

        // 1. Sync valid V1 and V2
        std::fs::write(peer_a.folder_path.join("secret.txt"), b"v1").unwrap();
        peer_a.sync_once(&http).await;
        peer_b.sync_once(&http).await;
        assert_eq!(
            std::fs::read(peer_b.folder_path.join("secret.txt")).unwrap(),
            b"v1"
        );

        std::thread::sleep(Duration::from_millis(15));
        std::fs::write(peer_a.folder_path.join("secret.txt"), b"v2").unwrap();
        peer_a.sync_once(&http).await;
        peer_b.sync_once(&http).await;
        assert_eq!(
            std::fs::read(peer_b.folder_path.join("secret.txt")).unwrap(),
            b"v2"
        );

        // 2. Malicious relay attempts a forged unauthenticated delete via POST /v1/deletes
        let forged_del = deltadrop_common::DeleteRequest {
            source_peer: "peer-a".into(),
            target_peer: "peer-b".into(),
            folder_id: "shared".into(),
            rel_path: "secret.txt".into(),
            base_hash: None,
            mtime_ms: 999999,
        };
        http.post(format!("{relay_url}/v1/deletes"))
            .bearer_auth("test-token")
            .json(&forged_del)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();

        peer_b.sync_once(&http).await;
        assert_eq!(
            std::fs::read(peer_b.folder_path.join("secret.txt")).unwrap(),
            b"v2",
            "forged delete must be rejected"
        );

        // 3. Malicious relay replays an older delta_version (version 1) encrypted with valid key
        let old_env = EncryptedEnvelope {
            source_peer: "peer-a".into(),
            target_peer: "peer-b".into(),
            folder_id: "shared".into(),
            rel_path: "secret.txt".into(),
            op_type: OpType::Upsert,
            plaintext_blake3: blake3::hash(b"v1").to_hex().to_string(),
            raw_size: 2,
            mtime_ms: 1,
            mode_bits: 0,
            base_hash: None,
            delta_version: 1, // older than v2 (version 2)
            payload: zstd::encode_all(&b"v1"[..], 3).unwrap(),
            chunks: Vec::new(),
        };
        let ct = encrypt_envelope(&peer_a.config, &old_env).unwrap();
        let ct_hash = blake3::hash(&ct).to_hex().to_string();
        let replay_meta = encode_meta_header(&DeltaUploadMeta {
            source_peer: "peer-a".into(),
            target_peer: "peer-b".into(),
            folder_id: "e2e".into(),
            rel_path: "slot/replay".into(),
            op_type: OpType::Upsert,
            blake3_hash: ct_hash,
            base_hash: None,
            delta_version: 1,
            chunk_ids: Vec::new(),
            raw_size: 0,
            mtime_ms: 1,
        })
        .unwrap();
        http.put(format!("{relay_url}/v1/deltas"))
            .bearer_auth("test-token")
            .header("X-Delta-Meta", replay_meta)
            .body(ct)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();

        peer_b.sync_once(&http).await;
        assert_eq!(
            std::fs::read(peer_b.folder_path.join("secret.txt")).unwrap(),
            b"v2",
            "replayed older delta_version must be rejected"
        );
    }

    #[tokio::test]
    async fn chunked_large_file_syncs_and_reuses_unchanged_chunks() {
        let (relay_dir, relay_url) = spawn_test_relay().await;
        let http = Client::new();
        let mut peer_a = TestPeer::new("peer-a", vec!["peer-b"], &relay_url);
        let mut peer_b = TestPeer::new("peer-b", vec!["peer-a"], &relay_url);

        // 1.5 MiB deterministic incompressible data (> CHUNK_THRESHOLD)
        let mut data = vec![0u8; 1_536 * 1024];
        let mut x: u64 = 0x1234_5678_9abc_def0;
        for b in &mut data {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (x >> 32) as u8;
        }
        let big_a = peer_a.folder_path.join("big.bin");
        std::fs::write(&big_a, &data).unwrap();

        peer_a.sync_once(&http).await;
        let chunks_dir = relay_dir.path().join("chunks");
        assert!(
            std::fs::read_dir(&chunks_dir).unwrap().count() >= 1,
            "large file must upload content-addressed chunks"
        );

        peer_b.sync_once(&http).await;
        let big_b = peer_b.folder_path.join("big.bin");
        assert_eq!(std::fs::read(&big_b).unwrap(), data);
        assert_eq!(
            std::fs::read_dir(&chunks_dir).unwrap().count(),
            0,
            "chunks must be ref-count purged after ACK"
        );

        // Append 8 KiB on A and re-sync
        std::thread::sleep(Duration::from_millis(15));
        data.extend_from_slice(&vec![0xAB; 8192]);
        std::fs::write(&big_a, &data).unwrap();
        peer_a.sync_once(&http).await;
        peer_b.sync_once(&http).await;
        assert_eq!(std::fs::read(&big_b).unwrap(), data);
    }

    #[tokio::test]
    async fn whitelist_to_full_and_third_peer_sync_missing_files() {
        let (_relay_dir, relay_url) = spawn_test_relay().await;
        let http = Client::new();
        let mut peer_a = TestPeer::new("peer-a", vec!["peer-b"], &relay_url);
        let mut peer_b = TestPeer::new("peer-b", vec!["peer-a"], &relay_url);
        peer_b.config.folders[0].mode = SyncMode::Whitelist;
        peer_b.config.folders[0].whitelist_subdirs = vec!["src".to_string()];

        std::fs::create_dir_all(peer_a.folder_path.join("src")).unwrap();
        std::fs::create_dir_all(peer_a.folder_path.join("docs")).unwrap();
        std::fs::write(peer_a.folder_path.join("src/lib.rs"), b"pub fn hi() {}").unwrap();
        std::fs::write(peer_a.folder_path.join("docs/guide.md"), b"# Guide").unwrap();

        peer_a.sync_once(&http).await;
        peer_b.sync_once(&http).await;
        assert!(peer_b.folder_path.join("src/lib.rs").exists());
        assert!(!peer_b.folder_path.join("docs/guide.md").exists());

        // Peer B switches Whitelist -> Full and sends wildcard pull request
        peer_b.config.folders[0].mode = SyncMode::Full;
        send_pull_request(&http, &peer_b.config, "peer-a", "shared", "*")
            .await
            .unwrap();

        let mut dirty_a = HashSet::new();
        process_pull_requests(&http, &peer_a.config, &peer_a.manifest, &mut dirty_a).await;
        for (fid, rel) in dirty_a {
            if let Some(folder) = peer_a.config.folders.iter().find(|f| f.id == fid) {
                upload_one_path(
                    &http,
                    &peer_a.config,
                    folder,
                    &rel,
                    &peer_a.manifest,
                    &mut peer_a.tracker,
                )
                .await
                .unwrap();
            }
        }
        peer_b.sync_once(&http).await;
        assert_eq!(
            std::fs::read(peer_b.folder_path.join("docs/guide.md")).unwrap(),
            b"# Guide"
        );

        // Adding a 3rd peer ("peer-c") to peer-a's target_peers automatically syncs existing files
        let mut peer_c = TestPeer::new("peer-c", vec!["peer-a"], &relay_url);
        peer_a.config.target_peers.push("peer-c".to_string());
        // Force a scan (mtime unchanged on A, but peer_synced has no entries for peer-c)
        for rel in ["src/lib.rs", "docs/guide.md"] {
            upload_one_path(
                &http,
                &peer_a.config,
                &peer_a.config.folders[0],
                rel,
                &peer_a.manifest,
                &mut peer_a.tracker,
            )
            .await
            .unwrap();
        }
        peer_c.sync_once(&http).await;
        assert_eq!(
            std::fs::read(peer_c.folder_path.join("docs/guide.md")).unwrap(),
            b"# Guide"
        );
    }

    #[tokio::test]
    async fn concurrent_small_files_sync_fast() {
        let (_relay_dir, relay_url) = spawn_test_relay().await;
        let http = Arc::new(Client::new());
        let mut peer_a = TestPeer::new("peer-a", vec!["peer-b"], &relay_url);
        let mut peer_b = TestPeer::new("peer-b", vec!["peer-a"], &relay_url);

        let mut dirty_a = HashSet::new();
        for i in 0..200 {
            let rel = format!("file_{i:03}.txt");
            std::fs::write(peer_a.folder_path.join(&rel), format!("payload-{i}")).unwrap();
            dirty_a.insert(("shared".to_string(), rel));
        }

        let rw_a: RecentWrites = Arc::new(Mutex::new(HashMap::new()));
        let (_, err) = run_sync_cycle(
            &http,
            &peer_a.config,
            &peer_a.manifest,
            &mut peer_a.tracker,
            &mut dirty_a,
            &rw_a,
        )
        .await;
        assert!(err.is_none(), "unexpected upload error: {err:?}");
        assert!(dirty_a.is_empty());

        peer_b.sync_once(&http).await;
        for i in 0..200 {
            let rel = format!("file_{i:03}.txt");
            assert_eq!(
                std::fs::read_to_string(peer_b.folder_path.join(&rel)).unwrap(),
                format!("payload-{i}")
            );
        }
    }

    #[tokio::test]
    async fn peer_auto_discovery_and_config_validation_and_project_detection() {
        let (_relay_dir, relay_url) = spawn_test_relay().await;
        let http = Client::new();
        let mut peer_a = TestPeer::new("peer-a", vec![], &relay_url);
        let mut peer_b = TestPeer::new("peer-b", vec![], &relay_url);
        peer_a.config.auto_discover_peers = true;
        peer_b.config.auto_discover_peers = true;

        let _ = register_and_discover_peers(&http, &mut peer_a.config).await;
        let (disc_b, added_b) = register_and_discover_peers(&http, &mut peer_b.config).await;
        assert!(added_b);
        assert_eq!(disc_b, vec!["peer-a".to_string()]);
        assert!(peer_b.config.target_peers.contains(&"peer-a".to_string()));

        let (disc_a, added_a) = register_and_discover_peers(&http, &mut peer_a.config).await;
        assert!(added_a);
        assert_eq!(disc_a, vec!["peer-b".to_string()]);
        assert!(peer_a.config.target_peers.contains(&"peer-b".to_string()));

        // Config validation rejects self-targeting and duplicate folder IDs
        let mut bad = peer_a.config.clone();
        bad.target_peers.push("peer-a".into());
        assert!(validate_config(&bad).is_err());

        // Project ignore detection
        let proj = tempfile::tempdir().unwrap();
        std::fs::write(proj.path().join("Cargo.toml"), "[package]\n").unwrap();
        std::fs::create_dir_all(proj.path().join(".git")).unwrap();
        let rules = crate::ignore_rules::detect_project_ignore_rules(proj.path());
        assert!(rules.iter().any(|r| r.pattern == "target/"));
        assert!(rules.iter().any(|r| r.pattern == ".git/"));
    }

    #[test]
    fn stale_host_reconciliation_protects_newer_remote_state() {
        let mut local = HashMap::new();
        local.insert("doc.txt".to_string(), "local-stale-hash".to_string());
        local.insert(
            "deleted_remotely.txt".to_string(),
            "modified-offline-hash".to_string(),
        );

        let mut last_synced = HashMap::new();
        last_synced.insert("doc.txt".to_string(), ("base-hash".to_string(), 1u64));
        last_synced.insert(
            "deleted_remotely.txt".to_string(),
            ("base-del-hash".to_string(), 1u64),
        );

        let mut remote = HashMap::new();
        remote.insert(
            "doc.txt".to_string(),
            ("newer-remote-hash".to_string(), 2u64),
        );

        let plan = reconcile_stale_host_against_remote_manifest(&local, &remote, &last_synced);
        assert!(plan.conflict_backups.contains(&"doc.txt".to_string()));
        assert!(plan
            .conflict_backups
            .contains(&"deleted_remotely.txt".to_string()));
        assert!(!plan.safe_to_publish.contains(&"doc.txt".to_string()));
    }

    #[test]
    fn non_destructive_relink_skips_matching_chunks_and_preserves_conflicts() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("same.txt"), b"hello-world").unwrap();
        std::fs::write(dir.path().join("diff.txt"), b"local-version").unwrap();

        let same_hash = blake3::hash(b"hello-world").to_hex().to_string();
        let remote_diff_hash = blake3::hash(b"remote-version").to_hex().to_string();

        let mut remote = HashMap::new();
        remote.insert(
            "same.txt".to_string(),
            (same_hash, vec!["chunk-same".to_string()]),
        );
        remote.insert(
            "diff.txt".to_string(),
            (remote_diff_hash, vec!["chunk-diff".to_string()]),
        );
        remote.insert(
            "missing.txt".to_string(),
            ("h-miss".to_string(), vec!["chunk-miss".to_string()]),
        );

        let plan = plan_non_destructive_relink(dir.path(), &remote);
        assert!(plan
            .skipped_matching_files
            .contains(&"same.txt".to_string()));
        assert!(plan
            .conflict_preserve_files
            .contains(&"diff.txt".to_string()));
        assert!(plan.needed_chunks.contains(&"chunk-diff".to_string()));
        assert!(plan.needed_chunks.contains(&"chunk-miss".to_string()));
        assert!(!plan.needed_chunks.contains(&"chunk-same".to_string()));
    }
}

#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct ReconcilePlan {
    pub conflict_backups: Vec<String>,
    pub safe_to_publish: Vec<String>,
}

/// Reconciles a host waking up after offline downtime against the relay's latest folder manifest
/// before fulfilling queued SyncRequests. Never overwrites newer remote updates or deletions.
#[allow(dead_code)]
pub fn reconcile_stale_host_against_remote_manifest(
    local_hashes: &HashMap<String, String>,
    remote_manifest: &HashMap<String, (String, u64)>,
    last_synced: &HashMap<String, (String, u64)>,
) -> ReconcilePlan {
    let mut plan = ReconcilePlan::default();
    for (path, local_hash) in local_hashes {
        match (remote_manifest.get(path), last_synced.get(path)) {
            (Some((remote_hash, remote_ver)), Some((base_hash, base_ver))) => {
                if remote_ver > base_ver && remote_hash != local_hash && local_hash != base_hash {
                    plan.conflict_backups.push(path.clone());
                } else if remote_ver > base_ver && remote_hash != local_hash {
                    // Remote updated while local was untouched: pull remote, do not publish stale local
                } else if local_hash != remote_hash {
                    plan.safe_to_publish.push(path.clone());
                }
            }
            (None, Some((base_hash, _))) => {
                // Deleted remotely while we were offline; if modified locally, preserve via conflict backup
                if local_hash != base_hash {
                    plan.conflict_backups.push(path.clone());
                }
            }
            (Some((remote_hash, _)), None) => {
                if local_hash != remote_hash {
                    plan.conflict_backups.push(path.clone());
                }
            }
            (None, None) => {
                plan.safe_to_publish.push(path.clone());
            }
        }
    }
    plan
}

#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct RelinkPlan {
    pub skipped_matching_files: Vec<String>,
    pub conflict_preserve_files: Vec<String>,
    pub needed_chunks: Vec<String>,
}

/// Plans a non-destructive merge when linking a remote folder to an existing local directory
/// (e.g. after OS reinstall or USB pre-seed). Hashes local files first and skips matching chunks.
#[allow(dead_code)]
pub fn plan_non_destructive_relink(
    local_dir: &Path,
    remote_entries: &HashMap<String, (String, Vec<String>)>,
) -> RelinkPlan {
    let mut plan = RelinkPlan::default();
    for (rel_path, (remote_hash, chunk_ids)) in remote_entries {
        let local_path = local_dir.join(rel_path);
        if local_path.is_file() {
            if let Ok(bytes) = std::fs::read(&local_path) {
                let local_hash = blake3::hash(&bytes).to_hex().to_string();
                if &local_hash == remote_hash {
                    plan.skipped_matching_files.push(rel_path.clone());
                    continue;
                }
                plan.conflict_preserve_files.push(rel_path.clone());
                plan.needed_chunks.extend(chunk_ids.iter().cloned());
                continue;
            }
        }
        plan.needed_chunks.extend(chunk_ids.iter().cloned());
    }
    plan
}

async fn handle_account_and_update_cmd(
    cmd: SyncCommand,
    http: &Client,
    config: &mut ClientConfig,
    config_path: &Path,
    snapshot: &Arc<Mutex<UiSnapshot>>,
    tracker: &SharedTracker,
) {
    match cmd {
        SyncCommand::Login {
            relay_url,
            username,
            password,
            device_name,
            network_secret,
            keep_unlocked,
        } => {
            let (parsed_user, parsed_relay) =
                if let Some((u, r)) = deltadrop_common::parse_user_relay_input(&username) {
                    (u, r)
                } else {
                    (
                        username.trim().to_string(),
                        relay_url.trim().trim_end_matches('/').to_string(),
                    )
                };
            let dev_name = if device_name.trim().is_empty() {
                config.peer_id.clone()
            } else {
                device_name.trim().to_string()
            };
            match crate::auth_client::login_zero_knowledge(
                http,
                &parsed_relay,
                &parsed_user,
                &password,
                &config.peer_id,
                &dev_name,
                network_secret.as_deref(),
            )
            .await
            {
                Ok(session) => {
                    config.relay_url = parsed_relay;
                    config.username = session.username.clone();
                    config.user_id = session.user_id.clone();
                    config.user_role = Some(session.role);
                    config.device_name = dev_name;
                    config.keep_unlocked = keep_unlocked;
                    config.network_secret = network_secret.filter(|s| !s.trim().is_empty());
                    config.session_token = if keep_unlocked {
                        session.token.clone()
                    } else {
                        String::new()
                    };
                    config.encryption_key = Some(deltadrop_common::encode_hex(&session.vault_key));
                    let _ = save_config_atomic(config_path, config);

                    if let Ok(mut g) = snapshot.lock() {
                        g.username = session.username;
                        g.user_role = Some(session.role);
                        g.active_config = Some(config.clone());
                        g.last_error = None;
                        g.online = true;
                    }
                    if let Ok(devs) = crate::auth_client::list_devices(
                        http,
                        &config.relay_url,
                        &session.token,
                        config.network_secret.as_deref(),
                    )
                    .await
                    {
                        if let Ok(mut g) = snapshot.lock() {
                            g.devices = devs;
                        }
                    }
                    if let Ok(cache) = crate::auth_client::fetch_cache_status(
                        http,
                        &config.relay_url,
                        &session.token,
                        config.network_secret.as_deref(),
                    )
                    .await
                    {
                        if let Ok(mut g) = snapshot.lock() {
                            g.cache_status = cache;
                        }
                    }
                    if session.role == UserRole::Admin {
                        if let Ok(users) = crate::auth_client::admin_list_users(
                            http,
                            &config.relay_url,
                            &session.token,
                            config.network_secret.as_deref(),
                        )
                        .await
                        {
                            if let Ok(mut g) = snapshot.lock() {
                                g.admin_users = users;
                            }
                        }
                    }
                }
                Err(e) => {
                    if let Ok(mut g) = snapshot.lock() {
                        g.last_error = Some(format!("Sign-in failed: {e}"));
                    }
                }
            }
            tracker.wake();
        }
        SyncCommand::SignOut => {
            config.session_token.clear();
            config.auth_token.clear();
            config.user_role = None;
            let _ = save_config_atomic(config_path, config);
            if let Ok(mut g) = snapshot.lock() {
                g.username.clear();
                g.user_role = None;
                g.devices.clear();
                g.admin_users.clear();
                g.active_config = Some(config.clone());
            }
            tracker.wake();
        }
        SyncCommand::CheckUpdates => {
            if let Ok(mut g) = snapshot.lock() {
                g.update_status = Some(crate::updater::UpdateStatus::Checking);
            }
            tracker.wake();
            let res = crate::updater::check_for_updates(http).await;
            if let Ok(mut g) = snapshot.lock() {
                g.update_status = Some(match res {
                    Ok(st) => st,
                    Err(e) => crate::updater::UpdateStatus::Error(e),
                });
            }
            tracker.wake();
        }
        SyncCommand::InstallUpdate => {
            let avail = snapshot.lock().ok().and_then(|g| g.update_status.clone());
            if let Some(crate::updater::UpdateStatus::Available {
                version,
                asset_url,
                asset_name,
                sums_url,
            }) = avail
            {
                if let Ok(mut g) = snapshot.lock() {
                    g.update_status =
                        Some(crate::updater::UpdateStatus::Downloading(version.clone()));
                }
                tracker.wake();
                let res = crate::updater::download_and_stage_update(
                    http,
                    &version,
                    &asset_url,
                    &asset_name,
                    &sums_url,
                )
                .await;
                if let Ok(mut g) = snapshot.lock() {
                    g.update_status = Some(match res {
                        Ok(st) => st,
                        Err(e) => crate::updater::UpdateStatus::Error(e),
                    });
                }
                tracker.wake();
            }
        }
        SyncCommand::RefreshDevices => {
            if !config.session_token.is_empty() {
                if let Ok(devs) = crate::auth_client::list_devices(
                    http,
                    &config.relay_url,
                    &config.session_token,
                    config.network_secret.as_deref(),
                )
                .await
                {
                    if let Ok(mut g) = snapshot.lock() {
                        g.devices = devs;
                    }
                    tracker.wake();
                }
            }
        }
        SyncCommand::DeleteDevice(did) => {
            if !config.session_token.is_empty() {
                let _ = crate::auth_client::delete_device(
                    http,
                    &config.relay_url,
                    &config.session_token,
                    config.network_secret.as_deref(),
                    &did,
                )
                .await;
                if let Ok(devs) = crate::auth_client::list_devices(
                    http,
                    &config.relay_url,
                    &config.session_token,
                    config.network_secret.as_deref(),
                )
                .await
                {
                    if let Ok(mut g) = snapshot.lock() {
                        g.devices = devs;
                    }
                }
                tracker.wake();
            }
        }
        SyncCommand::ReplaceDevice {
            old_device_id,
            new_device_name,
        } => {
            if !config.session_token.is_empty() {
                if let Ok((enc_key, _)) = derive_workspace_keys(config) {
                    let _ = crate::auth_client::replace_device(
                        http,
                        &config.relay_url,
                        &config.session_token,
                        config.network_secret.as_deref(),
                        &old_device_id,
                        &config.peer_id,
                        &new_device_name,
                        &enc_key,
                    )
                    .await;
                    if let Ok(devs) = crate::auth_client::list_devices(
                        http,
                        &config.relay_url,
                        &config.session_token,
                        config.network_secret.as_deref(),
                    )
                    .await
                    {
                        if let Ok(mut g) = snapshot.lock() {
                            g.devices = devs;
                        }
                    }
                    tracker.wake();
                }
            }
        }
        SyncCommand::AdminRefreshUsers => {
            if !config.session_token.is_empty() {
                if let Ok(users) = crate::auth_client::admin_list_users(
                    http,
                    &config.relay_url,
                    &config.session_token,
                    config.network_secret.as_deref(),
                )
                .await
                {
                    if let Ok(mut g) = snapshot.lock() {
                        g.admin_users = users;
                    }
                    tracker.wake();
                }
            }
        }
        SyncCommand::AdminCreateUser {
            username,
            password,
            role,
        } => {
            if !config.session_token.is_empty() {
                if let Err(e) = crate::auth_client::admin_create_user(
                    http,
                    &config.relay_url,
                    &config.session_token,
                    config.network_secret.as_deref(),
                    &username,
                    &password,
                    role,
                )
                .await
                {
                    if let Ok(mut g) = snapshot.lock() {
                        g.last_error = Some(format!("Create user failed: {e}"));
                    }
                } else if let Ok(users) = crate::auth_client::admin_list_users(
                    http,
                    &config.relay_url,
                    &config.session_token,
                    config.network_secret.as_deref(),
                )
                .await
                {
                    if let Ok(mut g) = snapshot.lock() {
                        g.admin_users = users;
                    }
                }
                tracker.wake();
            }
        }
        SyncCommand::AdminToggleUserDisabled { user_id, disabled } => {
            if !config.session_token.is_empty() {
                let _ = crate::auth_client::admin_update_user(
                    http,
                    &config.relay_url,
                    &config.session_token,
                    config.network_secret.as_deref(),
                    &user_id,
                    Some(disabled),
                    None,
                )
                .await;
                if let Ok(users) = crate::auth_client::admin_list_users(
                    http,
                    &config.relay_url,
                    &config.session_token,
                    config.network_secret.as_deref(),
                )
                .await
                {
                    if let Ok(mut g) = snapshot.lock() {
                        g.admin_users = users;
                    }
                }
                tracker.wake();
            }
        }
        SyncCommand::AdminResetUserPassword {
            user_id,
            new_password,
        } => {
            if !config.session_token.is_empty() {
                let _ = crate::auth_client::admin_update_user(
                    http,
                    &config.relay_url,
                    &config.session_token,
                    config.network_secret.as_deref(),
                    &user_id,
                    None,
                    Some(&new_password),
                )
                .await;
                tracker.wake();
            }
        }
        SyncCommand::AdminDeleteUser(user_id) if !config.session_token.is_empty() => {
            let _ = crate::auth_client::admin_delete_user(
                http,
                &config.relay_url,
                &config.session_token,
                config.network_secret.as_deref(),
                &user_id,
            )
            .await;
            if let Ok(users) = crate::auth_client::admin_list_users(
                http,
                &config.relay_url,
                &config.session_token,
                config.network_secret.as_deref(),
            )
            .await
            {
                if let Ok(mut g) = snapshot.lock() {
                    g.admin_users = users;
                }
            }
            tracker.wake();
        }
        _ => {}
    }
}
