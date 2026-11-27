use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use deltadrop_common::{
    decode_hex_32, encode_hex, next_fastcdc_boundary, normalize_rel_path, sanitize_folder_name,
    AdminUserInfo, ChunkRef, DeviceInfo, ManifestFileEntry, PutShareRequest, RelayCacheStatus,
    ShareManifest, ShareRecord, UserRole, WsClientMsg, WsServerMsg, CHUNK_MAX_SIZE,
    CHUNK_MIN_SIZE,
};
use lumenic::{Waker, WsClient, WsMessage};
use notify_debouncer_mini::notify::{RecommendedWatcher, RecursiveMode};
use notify_debouncer_mini::{new_debouncer, DebounceEventResult, Debouncer};
use uuid::Uuid;

use crate::config::{
    generate_share_id, resolve_safe_share_target, save_config_atomic, validate_share_path,
    ClientConfig, LocalShareBinding,
};
use crate::crypto::{
    compute_chunk_id, decrypt_chunk, decrypt_device_name, decrypt_manifest, encrypt_chunk,
    encrypt_manifest,
};
use crate::ignore_rules::{detect_project_ignore_patterns, write_ignore_file, IgnoreFilter};
use crate::manifest::{BaselineEntry, ConflictRow, LocalStateDb};
use crate::relay_client::{PutShareResult, RelayClient};
use crate::updater::{self, UpdateStatus};

const MAX_ACTIVITY: usize = 80;
const CHUNK_WORKERS: usize = 4;
const MAX_CONFLICT_RETRIES: usize = 4;

#[derive(Debug, Clone)]
pub struct DecryptedDeviceInfo {
    pub device_id: String,
    pub name: String,
    pub os: String,
    pub online: bool,
    pub is_self: bool,
}

#[derive(Debug, Clone)]
pub struct RemoteSharePreview {
    pub share_id: String,
    pub name: String,
    pub version: u64,
    pub file_count: usize,
    pub total_bytes: u64,
    pub suggested_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareSyncState {
    Idle,
    Scanning,
    Syncing,
    WaitingForHost,
    Paused,
    Error(String),
}

#[derive(Debug, Clone)]
pub struct LocalShareStatus {
    pub share_id: String,
    pub name: String,
    pub local_path: PathBuf,
    pub version: u64,
    pub state: ShareSyncState,
    pub status_detail: String,
    pub file_count: usize,
    pub total_bytes: u64,
    pub transferred_bytes: u64,
    pub transfer_total_bytes: u64,
    pub last_sync_label: String,
    pub ignore_patterns: Vec<String>,
    pub paused: bool,
    pub missing_chunks: usize,
}

#[derive(Debug, Clone)]
pub struct ActivityEntry {
    pub time_label: String,
    pub message: String,
    pub is_error: bool,
}

#[derive(Debug, Clone)]
pub struct UiSnapshot {
    pub authenticated: bool,
    pub username: String,
    pub user_id: String,
    pub user_role: Option<UserRole>,
    pub device_name: String,
    pub relay_url: String,
    pub keep_unlocked: bool,
    pub network_secret_set: bool,
    pub default_sync_root: PathBuf,
    pub auto_check_updates: bool,
    pub relay_connected: bool,
    pub ws_connected: bool,
    pub relay_latency_ms: Option<u64>,
    pub global_paused: bool,
    pub syncing_now: bool,
    pub upload_bps: u64,
    pub download_bps: u64,
    pub shares: Vec<LocalShareStatus>,
    pub unassigned_shares: Vec<RemoteSharePreview>,
    pub ignored_shares: Vec<RemoteSharePreview>,
    pub devices: Vec<DecryptedDeviceInfo>,
    pub conflicts: Vec<ConflictRow>,
    pub activity: VecDeque<ActivityEntry>,
    pub cache_status: Option<RelayCacheStatus>,
    pub admin_users: Vec<AdminUserInfo>,
    pub update_status: UpdateStatus,
    pub last_error: Option<String>,
    pub last_notice: Option<String>,
}

impl UiSnapshot {
    pub fn from_config(cfg: &ClientConfig) -> Self {
        let authenticated = !cfg.session_token.trim().is_empty() && cfg.vault_key_hex.is_some();
        let shares = cfg
            .shares
            .iter()
            .map(|b| LocalShareStatus {
                share_id: b.share_id.clone(),
                name: b.name.clone(),
                local_path: b.local_path.clone(),
                version: 0,
                state: if b.paused {
                    ShareSyncState::Paused
                } else {
                    ShareSyncState::Idle
                },
                status_detail: if b.paused {
                    "Paused".to_string()
                } else {
                    "Ready".to_string()
                },
                file_count: 0,
                total_bytes: 0,
                transferred_bytes: 0,
                transfer_total_bytes: 0,
                last_sync_label: "Not synced yet".to_string(),
                ignore_patterns: b.ignore_patterns.clone(),
                paused: b.paused,
                missing_chunks: 0,
            })
            .collect();
        Self {
            authenticated,
            username: cfg.username.clone(),
            user_id: cfg.user_id.clone(),
            user_role: cfg.user_role,
            device_name: cfg.device_name.clone(),
            relay_url: cfg.relay_url.clone(),
            keep_unlocked: cfg.keep_unlocked,
            network_secret_set: cfg
                .network_secret
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty()),
            default_sync_root: cfg.default_sync_root.clone(),
            auto_check_updates: cfg.auto_check_updates,
            relay_connected: false,
            ws_connected: false,
            relay_latency_ms: None,
            global_paused: false,
            syncing_now: false,
            upload_bps: 0,
            download_bps: 0,
            shares,
            unassigned_shares: Vec::new(),
            ignored_shares: Vec::new(),
            devices: Vec::new(),
            conflicts: Vec::new(),
            activity: VecDeque::new(),
            cache_status: None,
            admin_users: Vec::new(),
            update_status: UpdateStatus::Idle,
            last_error: None,
            last_notice: None,
        }
    }

    pub fn push_activity(&mut self, msg: impl Into<String>, is_error: bool) {
        if self.activity.len() >= MAX_ACTIVITY {
            self.activity.pop_back();
        }
        self.activity.push_front(ActivityEntry {
            time_label: format_clock_now(),
            message: msg.into(),
            is_error,
        });
    }
}

#[derive(Debug, Clone)]
pub enum SyncCommand {
    Login {
        relay_url: String,
        username: String,
        password: String,
        device_name: String,
        keep_unlocked: bool,
        network_secret: Option<String>,
    },
    SignOut,
    PublishLocalFolder {
        local_path: PathBuf,
        custom_name: Option<String>,
        ignore_patterns: Vec<String>,
    },
    AssignRemoteShare {
        share_id: String,
        target_path: PathBuf,
    },
    IgnoreRemoteShare(String),
    UnignoreRemoteShare(String),
    UnlinkLocalShare(String),
    DeleteRemoteShare(String),
    ToggleSharePause(String),
    UpdateShareIgnore {
        share_id: String,
        patterns: Vec<String>,
    },
    SyncNow(Option<String>),
    ToggleGlobalPause,
    ResolveConflict {
        conflict_id: u64,
        keep_local_conflict: bool,
    },
    DismissConflict(u64),
    SaveSettings {
        relay_url: String,
        device_name: String,
        default_sync_root: PathBuf,
        keep_unlocked: bool,
        network_secret: Option<String>,
        auto_check_updates: bool,
    },
    RefreshDevices,
    DeleteDevice(String),
    ReplaceDevice {
        old_device_id: String,
    },
    AdminRefreshUsers,
    AdminCreateUser {
        username: String,
        password: String,
        role: UserRole,
    },
    AdminSetUserDisabled {
        user_id: String,
        disabled: bool,
    },
    AdminDeleteUser(String),
    CheckUpdates,
    InstallUpdate,
    Shutdown,
}

#[derive(Clone)]
pub struct SyncHandle {
    tx: mpsc::Sender<SyncCommand>,
    snapshot: Arc<RwLock<UiSnapshot>>,
    waker: Arc<Mutex<Option<Waker>>>,
}

impl SyncHandle {
    pub fn send(&self, cmd: SyncCommand) {
        let _ = self.tx.send(cmd);
    }

    pub fn snapshot(&self) -> UiSnapshot {
        self.snapshot
            .read()
            .map(|s| s.clone())
            .unwrap_or_else(|e| e.into_inner().clone())
    }

    pub fn attach_waker(&self, waker: Waker) {
        if let Ok(mut guard) = self.waker.lock() {
            *guard = Some(waker);
        }
    }
}

pub fn spawn_sync_engine(config: ClientConfig, config_path: PathBuf) -> SyncHandle {
    let snapshot = Arc::new(RwLock::new(UiSnapshot::from_config(&config)));
    let waker: Arc<Mutex<Option<Waker>>> = Arc::new(Mutex::new(None));
    let (tx, rx) = mpsc::channel();

    let snap_clone = snapshot.clone();
    let waker_clone = waker.clone();
    std::thread::Builder::new()
        .name("deltadrop-sync".to_string())
        .spawn(move || {
            let mut worker = SyncWorker::new(config, config_path, snap_clone, waker_clone);
            worker.run(rx);
        })
        .expect("failed to spawn deltadrop-sync thread");

    SyncHandle {
        tx,
        snapshot,
        waker,
    }
}

struct ThroughputTracker {
    upload_bytes: Arc<AtomicU64>,
    download_bytes: Arc<AtomicU64>,
    last_up: u64,
    last_down: u64,
    last_sample: Instant,
}

impl ThroughputTracker {
    fn new() -> Self {
        Self {
            upload_bytes: Arc::new(AtomicU64::new(0)),
            download_bytes: Arc::new(AtomicU64::new(0)),
            last_up: 0,
            last_down: 0,
            last_sample: Instant::now(),
        }
    }

    fn sample(&mut self) -> Option<(u64, u64)> {
        let elapsed = self.last_sample.elapsed();
        if elapsed < Duration::from_millis(500) {
            return None;
        }
        let up_now = self.upload_bytes.load(Ordering::Relaxed);
        let down_now = self.download_bytes.load(Ordering::Relaxed);
        let secs = elapsed.as_secs_f64().max(0.001);
        let up_bps = ((up_now.saturating_sub(self.last_up)) as f64 / secs) as u64;
        let down_bps = ((down_now.saturating_sub(self.last_down)) as f64 / secs) as u64;
        self.last_up = up_now;
        self.last_down = down_now;
        self.last_sample = Instant::now();
        Some((up_bps, down_bps))
    }
}

struct SyncWorker {
    config: ClientConfig,
    config_path: PathBuf,
    db: LocalStateDb,
    vault_key: Option<[u8; 32]>,
    snapshot: Arc<RwLock<UiSnapshot>>,
    waker: Arc<Mutex<Option<Waker>>>,
    ws: Option<WsClient>,
    last_ws_attempt: Instant,
    ws_backoff_secs: u64,
    last_ws_ping: Instant,
    watcher: Option<Debouncer<RecommendedWatcher>>,
    watch_rx: mpsc::Receiver<Vec<PathBuf>>,
    watched_roots: HashMap<String, PathBuf>,
    dirty_shares: HashSet<String>,
    self_write_until: HashMap<String, Instant>,
    remote_records: HashMap<String, ShareRecord>,
    remote_manifests: HashMap<String, ShareManifest>,
    last_poll: Instant,
    global_paused: bool,
    throughput: ThroughputTracker,
}

impl SyncWorker {
    fn new(
        config: ClientConfig,
        config_path: PathBuf,
        snapshot: Arc<RwLock<UiSnapshot>>,
        waker: Arc<Mutex<Option<Waker>>>,
    ) -> Self {
        let db_path = config.manifest_db_path.clone().unwrap_or_else(|| {
            config_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join("deltadrop-state.db")
        });
        let db = LocalStateDb::open(&db_path).expect("failed to open local state db");
        let vault_key = config
            .vault_key_hex
            .as_deref()
            .and_then(decode_hex_32);

        let (watch_tx, watch_rx) = mpsc::channel::<Vec<PathBuf>>();
        let watcher = new_debouncer(
            Duration::from_millis(350),
            move |res: DebounceEventResult| {
                if let Ok(events) = res {
                    let paths: Vec<PathBuf> = events.into_iter().map(|e| e.path).collect();
                    if !paths.is_empty() {
                        let _ = watch_tx.send(paths);
                    }
                }
            },
        )
        .ok();

        let mut worker = Self {
            config,
            config_path,
            db,
            vault_key,
            snapshot,
            waker,
            ws: None,
            last_ws_attempt: Instant::now() - Duration::from_secs(60),
            ws_backoff_secs: 3,
            last_ws_ping: Instant::now(),
            watcher,
            watch_rx,
            watched_roots: HashMap::new(),
            dirty_shares: HashSet::new(),
            self_write_until: HashMap::new(),
            remote_records: HashMap::new(),
            remote_manifests: HashMap::new(),
            last_poll: Instant::now() - Duration::from_secs(60),
            global_paused: false,
            throughput: ThroughputTracker::new(),
        };
        worker.reconcile_watchers();
        worker.refresh_conflicts_snapshot();
        worker
    }

    fn wake_ui(&self) {
        if let Ok(guard) = self.waker.lock() {
            if let Some(w) = guard.as_ref() {
                w.wake();
            }
        }
    }

    fn update_snapshot<F: FnOnce(&mut UiSnapshot)>(&self, f: F) {
        if let Ok(mut snap) = self.snapshot.write() {
            f(&mut snap);
        }
        self.wake_ui();
    }

    fn is_authenticated(&self) -> bool {
        !self.config.session_token.trim().is_empty() && self.vault_key.is_some()
    }

    fn relay_client(&self) -> RelayClient {
        RelayClient::new(
            &self.config.relay_url,
            &self.config.session_token,
            self.config.network_secret.as_deref(),
        )
    }

    fn run(&mut self, cmd_rx: mpsc::Receiver<SyncCommand>) {
        if self.config.auto_check_updates {
            self.spawn_update_check();
        }
        if self.is_authenticated() {
            self.refresh_remote_state();
            for b in &self.config.shares {
                if !b.paused {
                    self.dirty_shares.insert(b.share_id.clone());
                }
            }
        }

        loop {
            match cmd_rx.recv_timeout(Duration::from_millis(60)) {
                Ok(SyncCommand::Shutdown) => {
                    if let Some(ws) = self.ws.take() {
                        let _ = ws.close();
                    }
                    break;
                }
                Ok(cmd) => self.handle_command(cmd),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }

            if let Some((up_bps, down_bps)) = self.throughput.sample() {
                self.update_snapshot(|s| {
                    s.upload_bps = up_bps;
                    s.download_bps = down_bps;
                });
            }

            if !self.is_authenticated() {
                continue;
            }

            self.poll_ws();
            self.poll_file_watcher();

            if !self.global_paused && !self.dirty_shares.is_empty() {
                let pending: Vec<String> = self.dirty_shares.drain().collect();
                for share_id in pending {
                    self.sync_one_share(&share_id);
                }
            }

            if self.last_poll.elapsed() >= Duration::from_secs(15) {
                self.last_poll = Instant::now();
                self.refresh_remote_state();
                if !self.global_paused {
                    self.check_and_fulfill_reseeds();
                }
            }
        }
    }

    fn handle_command(&mut self, cmd: SyncCommand) {
        match cmd {
            SyncCommand::Login {
                relay_url,
                username,
                password,
                device_name,
                keep_unlocked,
                network_secret,
            } => {
                let clean_url = relay_url.trim().trim_end_matches('/').to_string();
                let clean_name = if device_name.trim().is_empty() {
                    self.config.device_name.clone()
                } else {
                    device_name.trim().to_string()
                };
                let client = RelayClient::new(&clean_url, "", network_secret.as_deref());
                self.update_snapshot(|s| {
                    s.last_error = None;
                    s.last_notice = Some("Signing in...".to_string());
                });
                match client.login_zero_knowledge(
                    &username,
                    &password,
                    &self.config.device_id,
                    &clean_name,
                ) {
                    Ok((session, ms)) => {
                        self.config.relay_url = clean_url;
                        self.config.device_name = clean_name;
                        self.config.username = session.username.clone();
                        self.config.user_id = session.user_id.clone();
                        self.config.user_role = Some(session.role);
                        self.config.session_token = session.token;
                        self.config.vault_key_hex = Some(encode_hex(&session.vault_key));
                        self.config.keep_unlocked = keep_unlocked;
                        self.config.network_secret = network_secret
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty());
                        self.vault_key = Some(session.vault_key);
                        let _ = save_config_atomic(&self.config_path, &self.config);
                        if let Some(ws) = self.ws.take() {
                            let _ = ws.close();
                        }
                        self.ws_backoff_secs = 3;
                        self.last_ws_attempt = Instant::now() - Duration::from_secs(60);
                        self.update_snapshot(|s| {
                            s.authenticated = true;
                            s.username = self.config.username.clone();
                            s.user_id = self.config.user_id.clone();
                            s.user_role = self.config.user_role;
                            s.device_name = self.config.device_name.clone();
                            s.relay_url = self.config.relay_url.clone();
                            s.keep_unlocked = self.config.keep_unlocked;
                            s.network_secret_set = self.config.network_secret.is_some();
                            s.relay_connected = true;
                            s.relay_latency_ms = Some(ms);
                            s.last_error = None;
                            s.last_notice = Some(format!("Signed in as {}", self.config.username));
                            s.push_activity(
                                format!("Signed in as {} ({ms} ms)", self.config.username),
                                false,
                            );
                        });
                        self.refresh_remote_state();
                        for b in &self.config.shares {
                            if !b.paused {
                                self.dirty_shares.insert(b.share_id.clone());
                            }
                        }
                    }
                    Err(e) => {
                        self.update_snapshot(|s| {
                            s.last_error = Some(e.to_string());
                            s.last_notice = None;
                            s.push_activity(format!("Sign-in failed: {e}"), true);
                        });
                    }
                }
            }
            SyncCommand::SignOut => {
                if let Some(ws) = self.ws.take() {
                    let _ = ws.close();
                }
                self.config.session_token.clear();
                self.config.vault_key_hex = None;
                self.config.user_role = None;
                self.vault_key = None;
                let _ = save_config_atomic(&self.config_path, &self.config);
                self.remote_records.clear();
                self.remote_manifests.clear();
                self.update_snapshot(|s| {
                    s.authenticated = false;
                    s.ws_connected = false;
                    s.relay_connected = false;
                    s.unassigned_shares.clear();
                    s.ignored_shares.clear();
                    s.devices.clear();
                    s.admin_users.clear();
                    s.last_notice = Some("Signed out".to_string());
                    s.push_activity("Signed out", false);
                });
            }
            SyncCommand::PublishLocalFolder {
                local_path,
                custom_name,
                ignore_patterns,
            } => {
                if let Err(msg) = validate_share_path(&local_path, &self.config.shares, None) {
                    self.update_snapshot(|s| {
                        s.last_error = Some(msg.clone());
                        s.push_activity(msg, true);
                    });
                    return;
                }
                let raw_name = custom_name
                    .filter(|n| !n.trim().is_empty())
                    .or_else(|| {
                        local_path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .map(str::to_string)
                    })
                    .unwrap_or_else(|| "SharedFolder".to_string());
                let name = sanitize_folder_name(&raw_name);
                let share_id = generate_share_id(&name);
                let patterns = if ignore_patterns.is_empty() {
                    detect_project_ignore_patterns(&local_path)
                } else {
                    ignore_patterns
                };
                let _ = write_ignore_file(&local_path, &patterns);
                let binding = LocalShareBinding {
                    share_id: share_id.clone(),
                    name: name.clone(),
                    local_path: local_path.clone(),
                    ignore_patterns: patterns.clone(),
                    paused: false,
                };
                self.config.shares.push(binding);
                let _ = save_config_atomic(&self.config_path, &self.config);
                self.reconcile_watchers();
                self.rebuild_shares_snapshot();
                self.update_snapshot(|s| {
                    s.last_error = None;
                    s.last_notice = Some(format!("Added folder '{name}'"));
                    s.push_activity(format!("Published local folder '{name}'"), false);
                });
                self.sync_one_share(&share_id);
            }
            SyncCommand::AssignRemoteShare {
                share_id,
                target_path,
            } => {
                let Some(manifest) = self.remote_manifests.get(&share_id).cloned() else {
                    self.update_snapshot(|s| {
                        s.last_error = Some("Remote share metadata not loaded yet".to_string());
                    });
                    return;
                };
                if let Err(msg) =
                    validate_share_path(&target_path, &self.config.shares, Some(&share_id))
                {
                    self.update_snapshot(|s| {
                        s.last_error = Some(msg.clone());
                        s.push_activity(msg, true);
                    });
                    return;
                }
                if let Err(e) = fs::create_dir_all(&target_path) {
                    let msg = format!("Could not create folder {}: {e}", target_path.display());
                    self.update_snapshot(|s| {
                        s.last_error = Some(msg.clone());
                        s.push_activity(msg, true);
                    });
                    return;
                }
                self.config.ignored_share_ids.retain(|id| id != &share_id);
                self.config.shares.retain(|b| b.share_id != share_id);
                let binding = LocalShareBinding {
                    share_id: share_id.clone(),
                    name: manifest.name.clone(),
                    local_path: target_path.clone(),
                    ignore_patterns: manifest.ignore_patterns.clone(),
                    paused: false,
                };
                let _ = write_ignore_file(&target_path, &binding.ignore_patterns);
                self.config.shares.push(binding);
                let _ = save_config_atomic(&self.config_path, &self.config);
                self.reconcile_watchers();
                self.rebuild_shares_snapshot();
                self.update_snapshot(|s| {
                    s.last_error = None;
                    s.last_notice = Some(format!(
                        "Assigned '{}' -> {}",
                        manifest.name,
                        target_path.display()
                    ));
                    s.push_activity(
                        format!(
                            "Assigned remote share '{}' to {}",
                            manifest.name,
                            target_path.display()
                        ),
                        false,
                    );
                });
                self.sync_one_share(&share_id);
            }
            SyncCommand::IgnoreRemoteShare(share_id) => {
                if !self.config.ignored_share_ids.iter().any(|id| id == &share_id) {
                    self.config.ignored_share_ids.push(share_id);
                    let _ = save_config_atomic(&self.config_path, &self.config);
                }
                self.rebuild_shares_snapshot();
            }
            SyncCommand::UnignoreRemoteShare(share_id) => {
                self.config.ignored_share_ids.retain(|id| id != &share_id);
                let _ = save_config_atomic(&self.config_path, &self.config);
                self.rebuild_shares_snapshot();
            }
            SyncCommand::UnlinkLocalShare(share_id) => {
                self.config.shares.retain(|b| b.share_id != share_id);
                let _ = self.db.remove_share(&share_id);
                let _ = save_config_atomic(&self.config_path, &self.config);
                self.reconcile_watchers();
                self.rebuild_shares_snapshot();
                self.refresh_conflicts_snapshot();
                self.update_snapshot(|s| {
                    s.last_notice = Some("Folder unlinked (local files kept)".to_string());
                    s.push_activity("Unlinked local folder (kept files on disk)", false);
                });
            }
            SyncCommand::DeleteRemoteShare(share_id) => {
                let client = self.relay_client();
                match client.delete_share(&share_id) {
                    Ok(()) => {
                        self.config.shares.retain(|b| b.share_id != share_id);
                        self.config.ignored_share_ids.retain(|id| id != &share_id);
                        self.remote_records.remove(&share_id);
                        self.remote_manifests.remove(&share_id);
                        let _ = self.db.remove_share(&share_id);
                        let _ = save_config_atomic(&self.config_path, &self.config);
                        self.reconcile_watchers();
                        self.rebuild_shares_snapshot();
                        self.update_snapshot(|s| {
                            s.last_error = None;
                            s.last_notice = Some("Deleted share from relay".to_string());
                            s.push_activity("Deleted share from relay", false);
                        });
                    }
                    Err(e) => {
                        self.update_snapshot(|s| {
                            s.last_error = Some(e.to_string());
                            s.push_activity(format!("Delete share failed: {e}"), true);
                        });
                    }
                }
            }
            SyncCommand::ToggleSharePause(share_id) => {
                if let Some(b) = self.config.shares.iter_mut().find(|s| s.share_id == share_id) {
                    b.paused = !b.paused;
                    let paused = b.paused;
                    let _ = save_config_atomic(&self.config_path, &self.config);
                    if !paused {
                        self.dirty_shares.insert(share_id);
                    }
                }
                self.rebuild_shares_snapshot();
            }
            SyncCommand::UpdateShareIgnore { share_id, patterns } => {
                if let Some(b) = self.config.shares.iter_mut().find(|s| s.share_id == share_id) {
                    b.ignore_patterns = patterns.clone();
                    let _ = write_ignore_file(&b.local_path, &patterns);
                    let _ = save_config_atomic(&self.config_path, &self.config);
                    self.dirty_shares.insert(share_id);
                }
                self.rebuild_shares_snapshot();
                self.update_snapshot(|s| {
                    s.last_notice = Some("Updated ignore rules".to_string());
                });
            }
            SyncCommand::SyncNow(target) => {
                if !self.is_authenticated() {
                    return;
                }
                self.refresh_remote_state();
                match target {
                    Some(share_id) => {
                        self.sync_one_share(&share_id);
                    }
                    None => {
                        let ids: Vec<String> = self
                            .config
                            .shares
                            .iter()
                            .filter(|b| !b.paused)
                            .map(|b| b.share_id.clone())
                            .collect();
                        for id in ids {
                            self.sync_one_share(&id);
                        }
                    }
                }
            }
            SyncCommand::ToggleGlobalPause => {
                self.global_paused = !self.global_paused;
                let paused = self.global_paused;
                self.update_snapshot(|s| {
                    s.global_paused = paused;
                    s.push_activity(
                        if paused {
                            "Sync paused"
                        } else {
                            "Sync resumed"
                        },
                        false,
                    );
                });
                if !paused {
                    for b in &self.config.shares {
                        if !b.paused {
                            self.dirty_shares.insert(b.share_id.clone());
                        }
                    }
                }
            }
            SyncCommand::ResolveConflict {
                conflict_id,
                keep_local_conflict,
            } => {
                if let Ok(rows) = self.db.list_conflicts() {
                    if let Some(row) = rows.into_iter().find(|r| r.id == conflict_id) {
                        if let Some(binding) = self
                            .config
                            .shares
                            .iter()
                            .find(|b| b.share_id == row.share_id)
                            .cloned()
                        {
                            let main_path = binding.local_path.join(&row.rel_path);
                            let conflict_path = PathBuf::from(&row.conflict_path);
                            let res = if keep_local_conflict {
                                if conflict_path.exists() {
                                    fs::rename(&conflict_path, &main_path)
                                        .or_else(|_| {
                                            fs::copy(&conflict_path, &main_path)
                                                .and_then(|_| fs::remove_file(&conflict_path))
                                        })
                                } else {
                                    Ok(())
                                }
                            } else if conflict_path.exists() {
                                fs::remove_file(&conflict_path)
                            } else {
                                Ok(())
                            };
                            match res {
                                Ok(()) => {
                                    let _ = self.db.remove_conflict(conflict_id);
                                    self.refresh_conflicts_snapshot();
                                    if keep_local_conflict {
                                        self.dirty_shares.insert(row.share_id);
                                    }
                                    self.update_snapshot(|s| {
                                        s.last_notice = Some("Conflict resolved".to_string());
                                    });
                                }
                                Err(e) => {
                                    self.update_snapshot(|s| {
                                        s.last_error =
                                            Some(format!("Conflict resolution failed: {e}"));
                                    });
                                }
                            }
                        }
                    }
                }
            }
            SyncCommand::DismissConflict(conflict_id) => {
                let _ = self.db.remove_conflict(conflict_id);
                self.refresh_conflicts_snapshot();
            }
            SyncCommand::SaveSettings {
                relay_url,
                device_name,
                default_sync_root,
                keep_unlocked,
                network_secret,
                auto_check_updates,
            } => {
                let clean_url = relay_url.trim().trim_end_matches('/').to_string();
                let url_changed = clean_url != self.config.relay_url;
                self.config.relay_url = clean_url;
                if !device_name.trim().is_empty() {
                    self.config.device_name = device_name.trim().to_string();
                }
                if !default_sync_root.as_os_str().is_empty() {
                    self.config.default_sync_root = default_sync_root;
                }
                self.config.keep_unlocked = keep_unlocked;
                if let Some(sec) = network_secret {
                    let trimmed = sec.trim().to_string();
                    self.config.network_secret = if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed)
                    };
                }
                self.config.auto_check_updates = auto_check_updates;
                let _ = save_config_atomic(&self.config_path, &self.config);
                if url_changed {
                    if let Some(ws) = self.ws.take() {
                        let _ = ws.close();
                    }
                    self.ws_backoff_secs = 3;
                    self.last_ws_attempt = Instant::now() - Duration::from_secs(60);
                }
                self.update_snapshot(|s| {
                    s.relay_url = self.config.relay_url.clone();
                    s.device_name = self.config.device_name.clone();
                    s.default_sync_root = self.config.default_sync_root.clone();
                    s.keep_unlocked = self.config.keep_unlocked;
                    s.network_secret_set = self.config.network_secret.is_some();
                    s.auto_check_updates = self.config.auto_check_updates;
                    s.last_notice = Some("Settings saved".to_string());
                });
                self.rebuild_shares_snapshot();
            }
            SyncCommand::RefreshDevices => self.refresh_devices(),
            SyncCommand::DeleteDevice(dev_id) => {
                let client = self.relay_client();
                match client.delete_device(&dev_id) {
                    Ok(()) => {
                        self.refresh_devices();
                        self.update_snapshot(|s| {
                            s.last_notice = Some("Device removed".to_string());
                        });
                    }
                    Err(e) => self.update_snapshot(|s| {
                        s.last_error = Some(e.to_string());
                    }),
                }
            }
            SyncCommand::ReplaceDevice { old_device_id } => {
                let Some(vk) = self.vault_key else {
                    return;
                };
                let client = self.relay_client();
                match client.replace_device(
                    &old_device_id,
                    &self.config.device_id,
                    &self.config.device_name,
                    &vk,
                ) {
                    Ok(()) => {
                        self.refresh_devices();
                        self.update_snapshot(|s| {
                            s.last_notice = Some("Replaced old device slot".to_string());
                        });
                    }
                    Err(e) => self.update_snapshot(|s| {
                        s.last_error = Some(e.to_string());
                    }),
                }
            }
            SyncCommand::AdminRefreshUsers => {
                let client = self.relay_client();
                match client.admin_list_users() {
                    Ok(users) => self.update_snapshot(|s| {
                        s.admin_users = users;
                    }),
                    Err(e) => self.update_snapshot(|s| {
                        s.last_error = Some(e.to_string());
                    }),
                }
            }
            SyncCommand::AdminCreateUser {
                username,
                password,
                role,
            } => {
                let client = self.relay_client();
                match client.admin_create_user(&username, &password, role) {
                    Ok(_) => {
                        self.update_snapshot(|s| {
                            s.last_notice = Some(format!("Created user '{username}'"));
                        });
                        if let Ok(users) = client.admin_list_users() {
                            self.update_snapshot(|s| s.admin_users = users);
                        }
                    }
                    Err(e) => self.update_snapshot(|s| {
                        s.last_error = Some(e.to_string());
                    }),
                }
            }
            SyncCommand::AdminSetUserDisabled { user_id, disabled } => {
                let client = self.relay_client();
                match client.admin_update_user(&user_id, Some(disabled), None) {
                    Ok(()) => {
                        if let Ok(users) = client.admin_list_users() {
                            self.update_snapshot(|s| s.admin_users = users);
                        }
                    }
                    Err(e) => self.update_snapshot(|s| {
                        s.last_error = Some(e.to_string());
                    }),
                }
            }
            SyncCommand::AdminDeleteUser(user_id) => {
                let client = self.relay_client();
                match client.admin_delete_user(&user_id) {
                    Ok(()) => {
                        if let Ok(users) = client.admin_list_users() {
                            self.update_snapshot(|s| s.admin_users = users);
                        }
                    }
                    Err(e) => self.update_snapshot(|s| {
                        s.last_error = Some(e.to_string());
                    }),
                }
            }
            SyncCommand::CheckUpdates => self.spawn_update_check(),
            SyncCommand::InstallUpdate => {
                let current = self.snapshot.read().ok().map(|s| s.update_status.clone());
                if let Some(UpdateStatus::Available {
                    version,
                    asset_url,
                    asset_name,
                    sums_url,
                }) = current
                {
                    let snap = self.snapshot.clone();
                    let waker = self.waker.clone();
                    if let Ok(mut s) = snap.write() {
                        s.update_status = UpdateStatus::Downloading(version.clone());
                    }
                    self.wake_ui();
                    std::thread::spawn(move || {
                        let res = updater::download_and_stage_update(
                            &version,
                            &asset_url,
                            &asset_name,
                            &sums_url,
                        );
                        if let Ok(mut s) = snap.write() {
                            s.update_status = match res {
                                Ok(status) => status,
                                Err(e) => UpdateStatus::Error(e),
                            };
                        }
                        if let Ok(g) = waker.lock() {
                            if let Some(w) = g.as_ref() {
                                w.wake();
                            }
                        }
                    });
                }
            }
            SyncCommand::Shutdown => {}
        }
    }

    fn spawn_update_check(&self) {
        let snap = self.snapshot.clone();
        let waker = self.waker.clone();
        if let Ok(mut s) = snap.write() {
            s.update_status = UpdateStatus::Checking;
        }
        self.wake_ui();
        std::thread::spawn(move || {
            let res = updater::check_for_updates();
            if let Ok(mut s) = snap.write() {
                s.update_status = match res {
                    Ok(st) => st,
                    Err(e) => UpdateStatus::Error(e),
                };
            }
            if let Ok(g) = waker.lock() {
                if let Some(w) = g.as_ref() {
                    w.wake();
                }
            }
        });
    }

    fn poll_ws(&mut self) {
        if self.ws.is_none() {
            if self.last_ws_attempt.elapsed() >= Duration::from_secs(self.ws_backoff_secs) {
                self.last_ws_attempt = Instant::now();
                let url = self.relay_client().ws_url();
                let waker = self
                    .waker
                    .lock()
                    .ok()
                    .and_then(|g| g.clone())
                    .unwrap_or_default();
                match WsClient::connect(&url, waker) {
                    Ok(client) => {
                        self.ws = Some(client);
                        self.last_ws_ping = Instant::now();
                    }
                    Err(_) => {
                        self.ws_backoff_secs = (self.ws_backoff_secs * 2).min(20);
                    }
                }
            }
            return;
        }

        let msgs = if let Some(ws) = self.ws.as_ref() {
            ws.drain()
        } else {
            Vec::new()
        };

        let mut drop_ws = false;
        for msg in msgs {
            match msg {
                WsMessage::Connected => {
                    let auth = WsClientMsg::Auth {
                        token: self.config.session_token.clone(),
                        device_id: self.config.device_id.clone(),
                        gate: self.config.network_secret.clone(),
                    };
                    if let (Some(ws), Ok(txt)) = (self.ws.as_ref(), serde_json::to_string(&auth)) {
                        let _ = ws.send_text(&txt);
                    }
                }
                WsMessage::Text(txt) => {
                    if let Ok(srv) = serde_json::from_str::<WsServerMsg>(&txt) {
                        match srv {
                            WsServerMsg::AuthOk => {
                                self.ws_backoff_secs = 3;
                                self.update_snapshot(|s| {
                                    s.ws_connected = true;
                                    s.relay_connected = true;
                                });
                                self.refresh_remote_state();
                            }
                            WsServerMsg::AuthError { message } => {
                                drop_ws = true;
                                self.update_snapshot(|s| {
                                    s.ws_connected = false;
                                    s.push_activity(format!("WebSocket auth error: {message}"), true);
                                });
                            }
                            WsServerMsg::ShareUpdated { share_id, .. } => {
                                if self.config.shares.iter().any(|b| b.share_id == share_id) {
                                    self.dirty_shares.insert(share_id);
                                } else {
                                    self.refresh_remote_state();
                                }
                            }
                            WsServerMsg::ShareDeleted { share_id } => {
                                self.remote_records.remove(&share_id);
                                self.remote_manifests.remove(&share_id);
                                self.rebuild_shares_snapshot();
                            }
                            WsServerMsg::ReseedRequested {
                                share_id,
                                chunk_ids,
                                ..
                            } => {
                                self.fulfill_reseed(&share_id, &chunk_ids);
                            }
                            WsServerMsg::DeviceStatus { .. } => {
                                self.refresh_devices();
                            }
                            WsServerMsg::Pong => {}
                        }
                    }
                }
                WsMessage::Binary(_) => {}
                WsMessage::Closed(_, _) | WsMessage::Error(_) => {
                    drop_ws = true;
                }
            }
        }

        if drop_ws {
            self.ws = None;
            self.ws_backoff_secs = (self.ws_backoff_secs * 2).min(20);
            self.update_snapshot(|s| s.ws_connected = false);
        } else if self.last_ws_ping.elapsed() >= Duration::from_secs(25) {
            self.last_ws_ping = Instant::now();
            if let (Some(ws), Ok(txt)) = (
                self.ws.as_ref(),
                serde_json::to_string(&WsClientMsg::Ping),
            ) {
                let _ = ws.send_text(&txt);
            }
        }
    }

    fn poll_file_watcher(&mut self) {
        let now = Instant::now();
        self.self_write_until.retain(|_, until| *until > now);

        while let Ok(paths) = self.watch_rx.try_recv() {
            for changed_path in paths {
                for b in &self.config.shares {
                    if b.paused {
                        continue;
                    }
                    if let Some(until) = self.self_write_until.get(&b.share_id) {
                        if *until > now {
                            continue;
                        }
                    }
                    if let Ok(rel) = changed_path.strip_prefix(&b.local_path) {
                        let rel_str = rel.to_string_lossy().replace('\\', "/");
                        if rel_str.is_empty() {
                            continue;
                        }
                        let filter = IgnoreFilter::from_patterns(&b.local_path, &b.ignore_patterns);
                        let is_dir = changed_path.is_dir();
                        if filter.should_sync(&rel_str, is_dir) {
                            self.dirty_shares.insert(b.share_id.clone());
                        }
                    }
                }
            }
        }
    }

    fn reconcile_watchers(&mut self) {
        let Some(watcher) = self.watcher.as_mut() else {
            return;
        };
        let desired: HashMap<String, PathBuf> = self
            .config
            .shares
            .iter()
            .filter(|b| b.local_path.is_dir())
            .map(|b| (b.share_id.clone(), b.local_path.clone()))
            .collect();

        let to_remove: Vec<String> = self
            .watched_roots
            .keys()
            .filter(|id| desired.get(*id) != self.watched_roots.get(*id))
            .cloned()
            .collect();
        for id in to_remove {
            if let Some(path) = self.watched_roots.remove(&id) {
                let _ = watcher.watcher().unwatch(&path);
            }
        }
        for (id, path) in desired {
            if !self.watched_roots.contains_key(&id)
                && watcher.watcher().watch(&path, RecursiveMode::Recursive).is_ok()
            {
                self.watched_roots.insert(id, path);
            }
        }
    }

    fn refresh_remote_state(&mut self) {
        let Some(vk) = self.vault_key else {
            return;
        };
        let client = self.relay_client();
        match client.list_shares() {
            Ok((records, ms)) => {
                self.remote_records.clear();
                self.remote_manifests.clear();
                for rec in records {
                    if let Ok(manifest) = decrypt_manifest(
                        &vk,
                        &self.config.user_id,
                        &rec.share_id,
                        &rec.encrypted_manifest_b64,
                    ) {
                        self.remote_manifests.insert(rec.share_id.clone(), manifest);
                    }
                    self.remote_records.insert(rec.share_id.clone(), rec);
                }

                // Mark any local share whose remote version is ahead as dirty.
                for b in &self.config.shares {
                    if b.paused {
                        continue;
                    }
                    let local_ver = self.db.get_synced_version(&b.share_id).unwrap_or(0);
                    if let Some(rec) = self.remote_records.get(&b.share_id) {
                        if rec.version > local_ver {
                            self.dirty_shares.insert(b.share_id.clone());
                        }
                    }
                }

                let cache = client.fetch_cache_status().ok().map(|(c, _)| c);
                self.update_snapshot(|s| {
                    s.relay_connected = true;
                    s.relay_latency_ms = Some(ms);
                    if let Some(c) = cache {
                        s.cache_status = Some(c);
                    }
                });
                self.rebuild_shares_snapshot();
                self.refresh_devices();
            }
            Err(e) => {
                self.update_snapshot(|s| {
                    s.relay_connected = false;
                    s.push_activity(format!("Relay refresh failed: {e}"), true);
                });
            }
        }
    }

    fn refresh_devices(&mut self) {
        let client = self.relay_client();
        if let Ok(raw_devices) = client.list_devices() {
            let vk = self.vault_key.as_ref();
            let my_id = self.config.device_id.clone();
            let devices: Vec<DecryptedDeviceInfo> = raw_devices
                .into_iter()
                .map(|d: DeviceInfo| {
                    let name = decrypt_device_name(vk, &d.encrypted_name, &d.device_id);
                    let is_self = d.device_id == my_id;
                    DecryptedDeviceInfo {
                        device_id: d.device_id,
                        name,
                        os: d.os,
                        online: d.online,
                        is_self,
                    }
                })
                .collect();
            self.update_snapshot(|s| s.devices = devices);
        }
    }

    fn refresh_conflicts_snapshot(&self) {
        if let Ok(rows) = self.db.list_conflicts() {
            self.update_snapshot(|s| s.conflicts = rows);
        }
    }

    fn rebuild_shares_snapshot(&self) {
        let bound_ids: HashSet<&str> = self
            .config
            .shares
            .iter()
            .map(|b| b.share_id.as_str())
            .collect();
        let ignored_ids: HashSet<&str> = self
            .config
            .ignored_share_ids
            .iter()
            .map(String::as_str)
            .collect();

        let mut unassigned = Vec::new();
        let mut ignored = Vec::new();
        for (share_id, manifest) in &self.remote_manifests {
            if bound_ids.contains(share_id.as_str()) {
                continue;
            }
            let rec = self.remote_records.get(share_id);
            let active_files: Vec<&ManifestFileEntry> =
                manifest.files.iter().filter(|f| !f.deleted).collect();
            let preview = RemoteSharePreview {
                share_id: share_id.clone(),
                name: manifest.name.clone(),
                version: rec.map(|r| r.version).unwrap_or(0),
                file_count: active_files.len(),
                total_bytes: active_files.iter().map(|f| f.size).sum(),
                suggested_path: resolve_safe_share_target(
                    &self.config.default_sync_root,
                    &manifest.name,
                ),
            };
            if ignored_ids.contains(share_id.as_str()) {
                ignored.push(preview);
            } else {
                unassigned.push(preview);
            }
        }
        unassigned.sort_by_key(|a| a.name.to_lowercase());
        ignored.sort_by_key(|a| a.name.to_lowercase());

        self.update_snapshot(|s| {
            let old_map: HashMap<String, LocalShareStatus> = s
                .shares
                .iter()
                .map(|st| (st.share_id.clone(), st.clone()))
                .collect();
            s.shares = self
                .config
                .shares
                .iter()
                .map(|b| {
                    let prev = old_map.get(&b.share_id);
                    let ver = self.db.get_synced_version(&b.share_id).unwrap_or(0);
                    LocalShareStatus {
                        share_id: b.share_id.clone(),
                        name: b.name.clone(),
                        local_path: b.local_path.clone(),
                        version: ver,
                        state: if b.paused {
                            ShareSyncState::Paused
                        } else {
                            prev.map(|p| p.state.clone()).unwrap_or(ShareSyncState::Idle)
                        },
                        status_detail: if b.paused {
                            "Paused".to_string()
                        } else {
                            prev.map(|p| p.status_detail.clone())
                                .unwrap_or_else(|| "Ready".to_string())
                        },
                        file_count: prev.map(|p| p.file_count).unwrap_or(0),
                        total_bytes: prev.map(|p| p.total_bytes).unwrap_or(0),
                        transferred_bytes: prev.map(|p| p.transferred_bytes).unwrap_or(0),
                        transfer_total_bytes: prev.map(|p| p.transfer_total_bytes).unwrap_or(0),
                        last_sync_label: prev
                            .map(|p| p.last_sync_label.clone())
                            .unwrap_or_else(|| "Not synced yet".to_string()),
                        ignore_patterns: b.ignore_patterns.clone(),
                        paused: b.paused,
                        missing_chunks: prev.map(|p| p.missing_chunks).unwrap_or(0),
                    }
                })
                .collect();
            s.unassigned_shares = unassigned;
            s.ignored_shares = ignored;
        });
    }

    fn set_share_progress(
        &self,
        share_id: &str,
        state: ShareSyncState,
        detail: String,
        transferred: u64,
        total: u64,
    ) {
        self.update_snapshot(|s| {
            s.syncing_now = matches!(state, ShareSyncState::Scanning | ShareSyncState::Syncing);
            if let Some(sh) = s.shares.iter_mut().find(|x| x.share_id == share_id) {
                sh.state = state;
                sh.status_detail = detail;
                sh.transferred_bytes = transferred;
                sh.transfer_total_bytes = total;
            }
        });
    }

    fn sync_one_share(&mut self, share_id: &str) {
        let Some(vk) = self.vault_key else {
            return;
        };
        let Some(mut binding) = self
            .config
            .shares
            .iter()
            .find(|b| b.share_id == share_id)
            .cloned()
        else {
            return;
        };
        if binding.paused {
            return;
        }

        self.set_share_progress(
            share_id,
            ShareSyncState::Scanning,
            "Scanning folder...".to_string(),
            0,
            0,
        );

        let client = self.relay_client();
        let up_counter = self.throughput.upload_bytes.clone();
        let down_counter = self.throughput.download_bytes.clone();
        let snap_ref = self.snapshot.clone();
        let waker_ref = self.waker.clone();
        let sid_owned = share_id.to_string();

        let progress_cb = move |detail: &str, done: u64, total: u64| {
            if let Ok(mut s) = snap_ref.write() {
                s.syncing_now = true;
                if let Some(sh) = s.shares.iter_mut().find(|x| x.share_id == sid_owned) {
                    sh.state = ShareSyncState::Syncing;
                    sh.status_detail = detail.to_string();
                    sh.transferred_bytes = done;
                    sh.transfer_total_bytes = total;
                }
            }
            if let Ok(g) = waker_ref.lock() {
                if let Some(w) = g.as_ref() {
                    w.wake();
                }
            }
        };

        let res = sync_share_once(
            &client,
            &mut self.db,
            &vk,
            &self.config.user_id,
            &self.config.device_id,
            &mut binding,
            Some(&up_counter),
            Some(&down_counter),
            &progress_cb,
        );

        // Suppress file-watcher echoes from our own downloaded files for 1.5s.
        self.self_write_until
            .insert(share_id.to_string(), Instant::now() + Duration::from_millis(1500));

        // Persist updated ignore patterns if remote manifest changed them.
        if let Some(cfg_b) = self.config.shares.iter_mut().find(|b| b.share_id == share_id) {
            if cfg_b.ignore_patterns != binding.ignore_patterns {
                cfg_b.ignore_patterns = binding.ignore_patterns.clone();
                let _ = save_config_atomic(&self.config_path, &self.config);
            }
        }

        match res {
            Ok(outcome) => {
                let clock = format_clock_now();
                let state = if outcome.missing_chunks > 0 {
                    ShareSyncState::WaitingForHost
                } else {
                    ShareSyncState::Idle
                };
                let detail = if outcome.missing_chunks > 0 {
                    format!(
                        "Waiting for another PC to re-upload {} evicted chunks",
                        outcome.missing_chunks
                    )
                } else if outcome.uploaded_files > 0 || outcome.downloaded_files > 0 {
                    format!(
                        "Up to date (+{} up, +{} down)",
                        outcome.uploaded_files, outcome.downloaded_files
                    )
                } else {
                    "Up to date".to_string()
                };
                self.update_snapshot(|s| {
                    s.syncing_now = false;
                    s.relay_connected = true;
                    if let Some(sh) = s.shares.iter_mut().find(|x| x.share_id == share_id) {
                        sh.version = outcome.version;
                        sh.state = state;
                        sh.status_detail = detail.clone();
                        sh.file_count = outcome.file_count;
                        sh.total_bytes = outcome.total_bytes;
                        sh.transferred_bytes = 0;
                        sh.transfer_total_bytes = 0;
                        sh.last_sync_label = clock;
                        sh.ignore_patterns = binding.ignore_patterns.clone();
                        sh.missing_chunks = outcome.missing_chunks;
                    }
                    if outcome.uploaded_files > 0
                        || outcome.downloaded_files > 0
                        || outcome.conflicts_created > 0
                    {
                        s.push_activity(
                            format!(
                                "'{}': v{} ({} up, {} down, {} conflicts)",
                                binding.name,
                                outcome.version,
                                outcome.uploaded_files,
                                outcome.downloaded_files,
                                outcome.conflicts_created
                            ),
                            false,
                        );
                    }
                });
                self.refresh_conflicts_snapshot();
            }
            Err(e) => {
                let err_msg = e.to_string();
                self.update_snapshot(|s| {
                    s.syncing_now = false;
                    if let Some(sh) = s.shares.iter_mut().find(|x| x.share_id == share_id) {
                        sh.state = ShareSyncState::Error(err_msg.clone());
                        sh.status_detail = err_msg.clone();
                    }
                    s.last_error = Some(format!("'{}': {err_msg}", binding.name));
                    s.push_activity(format!("Sync error for '{}': {err_msg}", binding.name), true);
                });
            }
        }
    }

    fn check_and_fulfill_reseeds(&self) {
        let client = self.relay_client();
        if let Ok(requests) = client.list_reseed_requests() {
            for req in requests {
                self.fulfill_reseed(&req.share_id, &req.chunk_ids);
            }
        }
    }

    fn fulfill_reseed(&self, share_id: &str, chunk_ids: &[String]) {
        let Some(vk) = self.vault_key else {
            return;
        };
        let Some(binding) = self.config.shares.iter().find(|b| b.share_id == share_id) else {
            return;
        };
        if chunk_ids.is_empty() || !binding.local_path.is_dir() {
            return;
        }
        let wanted: HashSet<&str> = chunk_ids.iter().map(String::as_str).collect();
        let filter = IgnoreFilter::from_patterns(&binding.local_path, &binding.ignore_patterns);
        let Ok((local_files, _)) = scan_local_dir(&binding.local_path, &filter, &HashMap::new())
        else {
            return;
        };
        let client = self.relay_client();
        let mut uploaded = 0usize;
        for rel in local_files.keys() {
            let full = binding.local_path.join(rel);
            let Ok(bytes) = fs::read(&full) else {
                continue;
            };
            for slice in chunk_bytes(&bytes) {
                let cid = compute_chunk_id(&vk, slice);
                if wanted.contains(cid.as_str()) {
                    if let Ok(ct) = encrypt_chunk(&vk, &self.config.user_id, &cid, slice) {
                        if client.put_chunk(&cid, ct).is_ok() {
                            uploaded += 1;
                        }
                    }
                }
            }
        }
        if uploaded > 0 {
            self.update_snapshot(|s| {
                s.push_activity(
                    format!("Re-uploaded {uploaded} evicted chunks for '{}'", binding.name),
                    false,
                );
            });
        }
    }
}

#[derive(Debug, Clone)]
pub struct ShareSyncOutcome {
    pub version: u64,
    pub file_count: usize,
    pub total_bytes: u64,
    pub uploaded_files: usize,
    pub downloaded_files: usize,
    pub conflicts_created: usize,
    pub missing_chunks: usize,
}

#[derive(Debug, Clone)]
struct LocalFileMeta {
    size: u64,
    mtime_ms: i64,
    blake3_hash: String,
}

fn scan_local_dir(
    root: &Path,
    filter: &IgnoreFilter,
    baseline: &HashMap<String, BaselineEntry>,
) -> anyhow::Result<(HashMap<String, LocalFileMeta>, BTreeSet<String>)> {
    let mut files = HashMap::new();
    let mut empty_dirs = BTreeSet::new();
    if !root.exists() {
        return Ok((files, empty_dirs));
    }
    scan_dir_rec(root, root, filter, baseline, &mut files, &mut empty_dirs)?;
    Ok((files, empty_dirs))
}

fn scan_dir_rec(
    root: &Path,
    dir: &Path,
    filter: &IgnoreFilter,
    baseline: &HashMap<String, BaselineEntry>,
    files: &mut HashMap<String, LocalFileMeta>,
    empty_dirs: &mut BTreeSet<String>,
) -> anyhow::Result<bool> {
    let mut has_synced_content = false;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            continue;
        }
        let path = entry.path();
        let Ok(rel_os) = path.strip_prefix(root) else {
            continue;
        };
        let Some(rel) = normalize_rel_path(&rel_os.to_string_lossy()) else {
            continue;
        };
        if ft.is_dir() {
            if !filter.should_sync(&rel, true) {
                continue;
            }
            let child_has_content = scan_dir_rec(root, &path, filter, baseline, files, empty_dirs)?;
            if !child_has_content {
                empty_dirs.insert(rel);
            }
            has_synced_content = true;
        } else if ft.is_file() {
            if !filter.should_sync(&rel, false) {
                continue;
            }
            let meta = entry.metadata()?;
            let size = meta.len();
            let mtime_ms = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);

            // Fast-path: reuse baseline hash when size and mtime match.
            let blake3_hash = match baseline.get(&rel) {
                Some(b) if !b.deleted && b.size == size && b.mtime_ms == mtime_ms => {
                    b.blake3_hash.clone()
                }
                _ => hash_file_blake3(&path)?,
            };
            files.insert(
                rel,
                LocalFileMeta {
                    size,
                    mtime_ms,
                    blake3_hash,
                },
            );
            has_synced_content = true;
        }
    }
    Ok(has_synced_content)
}

fn hash_file_blake3(path: &Path) -> anyhow::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(hasher.finalize().to_hex().to_string())
}

fn build_conflict_path(root: &Path, rel_path: &str, device_id: &str) -> PathBuf {
    let full = root.join(rel_path);
    let stamp = now_ms() / 1000;
    let short_dev: String = device_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(16)
        .collect();
    let stem = full
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("file");
    let ext = full.extension().and_then(|e| e.to_str());
    let conflict_name = match ext {
        Some(e) => format!("{stem}.sync-conflict-{short_dev}-{stamp}.{e}"),
        None => format!("{stem}.sync-conflict-{short_dev}-{stamp}"),
    };
    full.with_file_name(conflict_name)
}

#[allow(clippy::too_many_arguments)]
pub fn sync_share_once<F>(
    client: &RelayClient,
    db: &mut LocalStateDb,
    vault_key: &[u8; 32],
    user_id: &str,
    device_id: &str,
    binding: &mut LocalShareBinding,
    upload_counter: Option<&Arc<AtomicU64>>,
    download_counter: Option<&Arc<AtomicU64>>,
    on_progress: &F,
) -> anyhow::Result<ShareSyncOutcome>
where
    F: Fn(&str, u64, u64) + Sync,
{
    fs::create_dir_all(&binding.local_path)?;

    let mut total_uploaded_files = 0usize;
    let mut total_downloaded_files = 0usize;
    let mut total_conflicts = 0usize;

    for attempt in 0..MAX_CONFLICT_RETRIES {
        let remote_rec = client.get_share(&binding.share_id)?;
        let (base_version, remote_manifest) = match remote_rec {
            Some(rec) => {
                let m = decrypt_manifest(
                    vault_key,
                    user_id,
                    &binding.share_id,
                    &rec.encrypted_manifest_b64,
                )?;
                (rec.version, Some(m))
            }
            None => (0, None),
        };

        let synced_version = db.get_synced_version(&binding.share_id)?;
        // If we haven't synced this share yet and remote has ignore patterns, adopt them.
        if synced_version == 0 {
            if let Some(ref rm) = remote_manifest {
                if !rm.ignore_patterns.is_empty() && binding.ignore_patterns.is_empty() {
                    binding.ignore_patterns = rm.ignore_patterns.clone();
                    let _ = write_ignore_file(&binding.local_path, &binding.ignore_patterns);
                }
            }
        }

        let filter = IgnoreFilter::from_patterns(&binding.local_path, &binding.ignore_patterns);
        let baseline = db.list_baseline(&binding.share_id)?;
        let (local_files, local_empty_dirs) =
            scan_local_dir(&binding.local_path, &filter, &baseline)?;

        let remote_map: HashMap<String, ManifestFileEntry> = remote_manifest
            .as_ref()
            .map(|m| {
                m.files
                    .iter()
                    .cloned()
                    .map(|f| (f.rel_path.clone(), f))
                    .collect()
            })
            .unwrap_or_default();

        let mut all_paths: BTreeSet<String> = BTreeSet::new();
        all_paths.extend(local_files.keys().cloned());
        all_paths.extend(baseline.keys().cloned());
        all_paths.extend(remote_map.keys().cloned());

        let mut to_upload: Vec<String> = Vec::new();
        let mut to_download: Vec<ManifestFileEntry> = Vec::new();
        let mut to_delete_local: Vec<String> = Vec::new();
        let mut merged_files: BTreeMap<String, ManifestFileEntry> = BTreeMap::new();
        let mut need_push_manifest = remote_manifest.is_none();

        if let Some(ref rm) = remote_manifest {
            if rm.ignore_patterns != binding.ignore_patterns {
                need_push_manifest = true;
            }
        }

        for rel in all_paths {
            if !filter.should_sync(&rel, false) {
                continue;
            }
            let local = local_files.get(&rel);
            let base = baseline.get(&rel);
            let remote = remote_map.get(&rel);

            let base_alive = base.filter(|b| !b.deleted);
            let remote_alive = remote.filter(|r| !r.deleted);

            let local_changed = match (local, base_alive) {
                (Some(l), Some(b)) => l.blake3_hash != b.blake3_hash,
                (Some(_), None) => true,
                (None, _) => false,
            };
            let local_deleted = local.is_none() && base_alive.is_some();

            let remote_changed = match (remote_alive, base_alive) {
                (Some(r), Some(b)) => r.blake3_hash != b.blake3_hash,
                (Some(_), None) => true,
                (None, _) => false,
            };
            let remote_deleted = remote_alive.is_none() && base_alive.is_some();

            match (local, remote_alive) {
                (Some(l), Some(r)) if l.blake3_hash == r.blake3_hash => {
                    merged_files.insert(rel, r.clone());
                }
                (Some(_), Some(r)) => {
                    if local_changed && remote_changed {
                        // True 3-way conflict: back up local file first, abort if backup fails.
                        let conflict_path =
                            build_conflict_path(&binding.local_path, &rel, device_id);
                        let src_path = binding.local_path.join(&rel);
                        fs::copy(&src_path, &conflict_path).map_err(|e| {
                            anyhow::anyhow!(
                                "Aborting conflict overwrite for '{rel}': backup failed ({e})"
                            )
                        })?;
                        let _ = db.push_conflict(
                            &binding.share_id,
                            &binding.name,
                            &rel,
                            &conflict_path.display().to_string(),
                            &format_clock_now(),
                        );
                        total_conflicts += 1;
                        to_download.push(r.clone());
                        merged_files.insert(rel, r.clone());
                    } else if local_changed {
                        to_upload.push(rel.clone());
                        need_push_manifest = true;
                    } else {
                        to_download.push(r.clone());
                        merged_files.insert(rel, r.clone());
                    }
                }
                (Some(_), None) => {
                    if remote_deleted && !local_changed {
                        to_delete_local.push(rel.clone());
                        if let Some(r_tomb) = remote {
                            merged_files.insert(rel, r_tomb.clone());
                        }
                    } else {
                        // Local added, or local modified while remote deleted -> preserve & upload local.
                        to_upload.push(rel.clone());
                        need_push_manifest = true;
                    }
                }
                (None, Some(r)) => {
                    if local_deleted && !remote_changed {
                        // Local intentionally deleted an unmodified file -> push tombstone.
                        merged_files.insert(
                            rel.clone(),
                            ManifestFileEntry {
                                rel_path: rel,
                                size: 0,
                                mtime_ms: now_ms(),
                                mode_bits: 0,
                                blake3_hash: String::new(),
                                rev: r.rev.saturating_add(1),
                                deleted: true,
                                chunks: Vec::new(),
                            },
                        );
                        need_push_manifest = true;
                    } else {
                        to_download.push(r.clone());
                        merged_files.insert(rel, r.clone());
                    }
                }
                (None, None) => {
                    if let Some(r_tomb) = remote {
                        merged_files.insert(rel, r_tomb.clone());
                    }
                }
            }
        }

        // Apply local deletions first.
        for rel in &to_delete_local {
            let full = binding.local_path.join(rel);
            if full.is_file() {
                let _ = fs::remove_file(&full);
            }
        }

        // Download phase.
        let mut missing_chunks: Vec<String> = Vec::new();
        let mut incomplete_files: HashSet<String> = HashSet::new();
        if !to_download.is_empty() {
            let total_down_bytes: u64 = to_download.iter().map(|f| f.size).sum();
            let done_down = Arc::new(AtomicU64::new(0));
            on_progress("Downloading changes...", 0, total_down_bytes);

            // Map existing local file hashes so moved/renamed files reuse local disk bytes.
            let mut local_by_hash: HashMap<String, PathBuf> = HashMap::new();
            for (rel, meta) in &local_files {
                local_by_hash
                    .entry(meta.blake3_hash.clone())
                    .or_insert_with(|| binding.local_path.join(rel));
            }

            let mut files_needing_net = Vec::new();
            for entry in &to_download {
                if let Some(existing_src) = local_by_hash.get(&entry.blake3_hash) {
                    if existing_src.is_file() {
                        let dst = binding.local_path.join(&entry.rel_path);
                        if let Some(parent) = dst.parent() {
                            fs::create_dir_all(parent)?;
                        }
                        if fs::copy(existing_src, &dst).is_ok() {
                            set_mtime_ms(&dst, entry.mtime_ms);
                            total_downloaded_files += 1;
                            continue;
                        }
                    }
                }
                files_needing_net.push(entry.clone());
            }

            // Collect unique chunks to fetch.
            let mut unique_chunks: Vec<ChunkRef> = Vec::new();
            let mut seen_cids: HashSet<String> = HashSet::new();
            for entry in &files_needing_net {
                for c in &entry.chunks {
                    if seen_cids.insert(c.chunk_id.clone()) {
                        unique_chunks.push(c.clone());
                    }
                }
            }

            let fetched_chunks: Mutex<HashMap<String, Vec<u8>>> = Mutex::new(HashMap::new());
            let missing_cids: Mutex<Vec<String>> = Mutex::new(Vec::new());
            let first_err: Mutex<Option<anyhow::Error>> = Mutex::new(None);
            let next_idx = AtomicU64::new(0);

            std::thread::scope(|s| {
                let worker_count = CHUNK_WORKERS.min(unique_chunks.len().max(1));
                for _ in 0..worker_count {
                    s.spawn(|| loop {
                        let idx = next_idx.fetch_add(1, Ordering::Relaxed) as usize;
                        if idx >= unique_chunks.len() {
                            break;
                        }
                        let cref = &unique_chunks[idx];
                        match client.get_chunk(&cref.chunk_id) {
                            Ok(Some(ct)) => {
                                let ct_len = ct.len() as u64;
                                if let Some(counter) = download_counter {
                                    counter.fetch_add(ct_len, Ordering::Relaxed);
                                }
                                match decrypt_chunk(
                                    vault_key,
                                    user_id,
                                    &cref.chunk_id,
                                    &ct,
                                    cref.raw_size,
                                ) {
                                    Ok(plain) => {
                                        let done = done_down
                                            .fetch_add(cref.raw_size, Ordering::Relaxed)
                                            + cref.raw_size;
                                        on_progress("Downloading chunks...", done, total_down_bytes);
                                        if let Ok(mut map) = fetched_chunks.lock() {
                                            map.insert(cref.chunk_id.clone(), plain);
                                        }
                                    }
                                    Err(e) => {
                                        if let Ok(mut err) = first_err.lock() {
                                            if err.is_none() {
                                                *err = Some(e);
                                            }
                                        }
                                    }
                                }
                            }
                            Ok(None) => {
                                if let Ok(mut miss) = missing_cids.lock() {
                                    miss.push(cref.chunk_id.clone());
                                }
                            }
                            Err(e) => {
                                if let Ok(mut err) = first_err.lock() {
                                    if err.is_none() {
                                        *err = Some(e);
                                    }
                                }
                            }
                        }
                    });
                }
            });

            if let Some(err) = first_err.into_inner().unwrap_or(None) {
                return Err(err);
            }
            missing_chunks = missing_cids.into_inner().unwrap_or_default();
            let chunk_map = fetched_chunks.into_inner().unwrap_or_default();

            for entry in &files_needing_net {
                let all_present = entry
                    .chunks
                    .iter()
                    .all(|c| chunk_map.contains_key(&c.chunk_id));
                if !all_present {
                    incomplete_files.insert(entry.rel_path.clone());
                    continue;
                }
                let dst = binding.local_path.join(&entry.rel_path);
                if let Some(parent) = dst.parent() {
                    fs::create_dir_all(parent)?;
                }
                let tmp_name = format!(".deltadrop-tmp-{}", Uuid::new_v4().simple());
                let tmp_path = dst.with_file_name(tmp_name);
                let mut f = File::create(&tmp_path)?;
                let mut hasher = blake3::Hasher::new();
                for cref in &entry.chunks {
                    let bytes = &chunk_map[&cref.chunk_id];
                    f.write_all(bytes)?;
                    hasher.update(bytes);
                }
                f.sync_all()?;
                drop(f);
                let actual_hash = hasher.finalize().to_hex().to_string();
                if actual_hash != entry.blake3_hash {
                    let _ = fs::remove_file(&tmp_path);
                    anyhow::bail!("Hash mismatch after downloading '{}'", entry.rel_path);
                }
                set_mtime_ms(&tmp_path, entry.mtime_ms);
                if dst.exists() {
                    let _ = fs::remove_file(&dst);
                }
                fs::rename(&tmp_path, &dst)?;
                total_downloaded_files += 1;
            }

            if !missing_chunks.is_empty() {
                let _ = client.request_reseed(
                    &binding.share_id,
                    device_id,
                    missing_chunks.clone(),
                );
            }
        }

        // Sync empty directories.
        let mut merged_empty_dirs: BTreeSet<String> = local_empty_dirs.clone();
        if let Some(ref rm) = remote_manifest {
            for dir_rel in &rm.empty_dirs {
                if filter.should_sync(dir_rel, true) {
                    let full = binding.local_path.join(dir_rel);
                    if !full.exists() {
                        let _ = fs::create_dir_all(&full);
                    }
                    merged_empty_dirs.insert(dir_rel.clone());
                }
            }
            let remote_dir_set: BTreeSet<String> = rm.empty_dirs.iter().cloned().collect();
            if merged_empty_dirs != remote_dir_set {
                need_push_manifest = true;
            }
        }

        // Upload phase.
        if !to_upload.is_empty() {
            let total_up_bytes: u64 = to_upload
                .iter()
                .filter_map(|r| local_files.get(r))
                .map(|m| m.size)
                .sum();
            on_progress("Chunking local changes...", 0, total_up_bytes);

            let mut chunk_payloads: HashMap<String, Vec<u8>> = HashMap::new();
            for rel in &to_upload {
                let full = binding.local_path.join(rel);
                let bytes = fs::read(&full)?;
                let hash = blake3::hash(&bytes).to_hex().to_string();
                let meta = local_files.get(rel).cloned().unwrap_or(LocalFileMeta {
                    size: bytes.len() as u64,
                    mtime_ms: now_ms(),
                    blake3_hash: hash.clone(),
                });
                let mut refs = Vec::new();
                for slice in chunk_bytes(&bytes) {
                    let cid = compute_chunk_id(vault_key, slice);
                    let plain_hash = blake3::hash(slice).to_hex().to_string();
                    refs.push(ChunkRef {
                        chunk_id: cid.clone(),
                        raw_size: slice.len() as u64,
                        plaintext_blake3: plain_hash,
                    });
                    chunk_payloads.entry(cid).or_insert_with(|| slice.to_vec());
                }
                let prev_rev = remote_map
                    .get(rel)
                    .map(|r| r.rev)
                    .or_else(|| baseline.get(rel).map(|b| b.rev))
                    .unwrap_or(0);
                merged_files.insert(
                    rel.clone(),
                    ManifestFileEntry {
                        rel_path: rel.clone(),
                        size: bytes.len() as u64,
                        mtime_ms: meta.mtime_ms,
                        mode_bits: 0,
                        blake3_hash: hash,
                        rev: prev_rev.saturating_add(1),
                        deleted: false,
                        chunks: refs,
                    },
                );
            }

            let all_cids: Vec<String> = chunk_payloads.keys().cloned().collect();
            let mut missing_on_relay: Vec<String> = Vec::new();
            for batch in all_cids.chunks(256) {
                let miss = client.has_chunks(batch.to_vec())?;
                missing_on_relay.extend(miss);
            }

            if !missing_on_relay.is_empty() {
                let done_up = Arc::new(AtomicU64::new(0));
                let first_err: Mutex<Option<anyhow::Error>> = Mutex::new(None);
                let next_idx = AtomicU64::new(0);
                let upload_total: u64 = missing_on_relay
                    .iter()
                    .filter_map(|id| chunk_payloads.get(id))
                    .map(|v| v.len() as u64)
                    .sum();

                std::thread::scope(|s| {
                    let worker_count = CHUNK_WORKERS.min(missing_on_relay.len().max(1));
                    for _ in 0..worker_count {
                        s.spawn(|| loop {
                            let idx = next_idx.fetch_add(1, Ordering::Relaxed) as usize;
                            if idx >= missing_on_relay.len() {
                                break;
                            }
                            let cid = &missing_on_relay[idx];
                            let plain = &chunk_payloads[cid];
                            match encrypt_chunk(vault_key, user_id, cid, plain)
                                .and_then(|ct| {
                                    let ct_len = ct.len() as u64;
                                    client.put_chunk(cid, ct)?;
                                    Ok(ct_len)
                                }) {
                                Ok(ct_len) => {
                                    if let Some(counter) = upload_counter {
                                        counter.fetch_add(ct_len, Ordering::Relaxed);
                                    }
                                    let done = done_up.fetch_add(plain.len() as u64, Ordering::Relaxed)
                                        + plain.len() as u64;
                                    on_progress("Uploading chunks...", done, upload_total);
                                }
                                Err(e) => {
                                    if let Ok(mut err) = first_err.lock() {
                                        if err.is_none() {
                                            *err = Some(e);
                                        }
                                    }
                                }
                            }
                        });
                    }
                });

                if let Some(err) = first_err.into_inner().unwrap_or(None) {
                    return Err(err);
                }
            }
            total_uploaded_files += to_upload.len();
        }

        // Push updated manifest if anything changed locally.
        let owner_device_id = remote_manifest
            .as_ref()
            .map(|m| m.owner_device_id.clone())
            .unwrap_or_else(|| device_id.to_string());
        let final_version = if need_push_manifest {
            let manifest = ShareManifest {
                share_id: binding.share_id.clone(),
                name: binding.name.clone(),
                owner_device_id: owner_device_id.clone(),
                ignore_patterns: binding.ignore_patterns.clone(),
                files: merged_files.values().cloned().collect(),
                empty_dirs: merged_empty_dirs.into_iter().collect(),
            };
            let enc_manifest = encrypt_manifest(vault_key, user_id, &manifest)?;
            let req = PutShareRequest {
                device_id: device_id.to_string(),
                owner_device_id,
                base_version,
                encrypted_manifest_b64: enc_manifest,
            };
            match client.put_share(&binding.share_id, &req)? {
                PutShareResult::Ok(resp) => resp.version,
                PutShareResult::Conflict => {
                    if attempt + 1 < MAX_CONFLICT_RETRIES {
                        continue;
                    }
                    anyhow::bail!("Share version conflict after {MAX_CONFLICT_RETRIES} retries");
                }
            }
        } else {
            base_version
        };

        // Persist updated baseline (excluding any files whose chunks were missing for reseed).
        let mut new_baseline = HashMap::new();
        let mut active_count = 0usize;
        let mut active_bytes = 0u64;
        for (rel, entry) in &merged_files {
            if incomplete_files.contains(rel) {
                continue;
            }
            if !entry.deleted {
                active_count += 1;
                active_bytes += entry.size;
            }
            new_baseline.insert(
                rel.clone(),
                BaselineEntry {
                    blake3_hash: entry.blake3_hash.clone(),
                    size: entry.size,
                    mtime_ms: entry.mtime_ms,
                    rev: entry.rev,
                    deleted: entry.deleted,
                },
            );
        }
        db.replace_baseline(&binding.share_id, &new_baseline)?;
        if missing_chunks.is_empty() {
            db.set_synced_version(&binding.share_id, final_version, now_ms())?;
        }

        return Ok(ShareSyncOutcome {
            version: final_version,
            file_count: active_count,
            total_bytes: active_bytes,
            uploaded_files: total_uploaded_files,
            downloaded_files: total_downloaded_files,
            conflicts_created: total_conflicts,
            missing_chunks: missing_chunks.len(),
        });
    }

    anyhow::bail!("Sync loop exhausted retries")
}

fn chunk_bytes(buf: &[u8]) -> Vec<&[u8]> {
    if buf.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset < buf.len() {
        let len = next_fastcdc_boundary(&buf[offset..], CHUNK_MIN_SIZE, CHUNK_MAX_SIZE);
        let step = len.max(1).min(buf.len() - offset);
        out.push(&buf[offset..offset + step]);
        offset += step;
    }
    out
}

fn set_mtime_ms(path: &Path, mtime_ms: i64) {
    if mtime_ms <= 0 {
        return;
    }
    if let Ok(file) = fs::OpenOptions::new().write(true).open(path) {
        let ts = UNIX_EPOCH + Duration::from_millis(mtime_ms as u64);
        let _ = file.set_modified(ts);
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn format_clock_now() -> String {
    let secs = (now_ms() / 1000).rem_euclid(86_400);
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02} UTC")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::resolve_safe_share_target;
    use crate::ignore_rules::detect_project_ignore_patterns;

    fn start_test_relay() -> (tokio::runtime::Runtime, String, tempfile::TempDir) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let listener = rt
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let conn = deltadrop_relay::init_db(&dir.path().join("relay.db")).unwrap();
        deltadrop_relay::seed_user_in_db(&conn, "admin", "test-password-123", true).unwrap();
        let state = deltadrop_relay::AppState::new(conn, dir.path().to_path_buf(), 256 * 1024 * 1024);
        rt.spawn(async move {
            let _ = deltadrop_relay::serve_on(listener, state).await;
        });
        // Give axum a brief moment to begin accepting.
        std::thread::sleep(Duration::from_millis(60));
        (rt, format!("http://{addr}"), dir)
    }

    #[test]
    fn e2e_two_way_async_handoff_and_ignore_presets() {
        let (_rt, url, _relay_dir) = start_test_relay();

        // Host signs in
        let host_auth = RelayClient::new(&url, "", None)
            .login_zero_knowledge("admin", "test-password-123", "host-pc", "Main PC")
            .unwrap()
            .0;
        let host_client = RelayClient::new(&url, &host_auth.token, None);

        // Laptop signs in as same user
        let laptop_auth = RelayClient::new(&url, "", None)
            .login_zero_knowledge("admin", "test-password-123", "laptop-pc", "Travel Laptop")
            .unwrap()
            .0;
        let laptop_client = RelayClient::new(&url, &laptop_auth.token, None);

        // Host creates a Unity + Rust project folder
        let host_root = tempfile::tempdir().unwrap();
        let host_proj = host_root.path().join("MyGame");
        fs::create_dir_all(host_proj.join("Assets/Scripts")).unwrap();
        fs::create_dir_all(host_proj.join("ProjectSettings")).unwrap();
        fs::create_dir_all(host_proj.join("Library/Cache")).unwrap();
        fs::create_dir_all(host_proj.join("EmptyLevelDir")).unwrap();
        fs::write(host_proj.join("Assets/Scripts/Player.cs"), "class Player { int hp = 100; }").unwrap();
        fs::write(host_proj.join("Library/Cache/huge.bin"), vec![9u8; 4096]).unwrap();

        let pats = detect_project_ignore_patterns(&host_proj);
        let mut host_binding = LocalShareBinding {
            share_id: "mygame-1234".to_string(),
            name: "MyGame".to_string(),
            local_path: host_proj.clone(),
            ignore_patterns: pats,
            paused: false,
        };
        let mut host_db = LocalStateDb::open(&host_root.path().join("host.db")).unwrap();

        let noop = |_: &str, _: u64, _: u64| {};
        let out1 = sync_share_once(
            &host_client,
            &mut host_db,
            &host_auth.vault_key,
            &host_auth.user_id,
            "host-pc",
            &mut host_binding,
            None,
            None,
            &noop,
        )
        .unwrap();
        assert_eq!(out1.version, 1);
        assert_eq!(out1.uploaded_files, 1);

        // Laptop picks a parent folder (like Desktop) -> resolved safely to <Parent>/MyGame
        let laptop_root = tempfile::tempdir().unwrap();
        let laptop_parent = laptop_root.path().join("FakeDesktop");
        fs::create_dir_all(&laptop_parent).unwrap();
        let laptop_target = resolve_safe_share_target(&laptop_parent, "MyGame");
        assert_eq!(laptop_target, laptop_parent.join("MyGame"));

        let mut laptop_binding = LocalShareBinding {
            share_id: "mygame-1234".to_string(),
            name: "MyGame".to_string(),
            local_path: laptop_target.clone(),
            ignore_patterns: Vec::new(),
            paused: false,
        };
        let mut laptop_db = LocalStateDb::open(&laptop_root.path().join("laptop.db")).unwrap();

        let out2 = sync_share_once(
            &laptop_client,
            &mut laptop_db,
            &laptop_auth.vault_key,
            &laptop_auth.user_id,
            "laptop-pc",
            &mut laptop_binding,
            None,
            None,
            &noop,
        )
        .unwrap();
        assert_eq!(out2.downloaded_files, 1);
        // Verify Player.cs synced, Library/ ignored, EmptyLevelDir created, and parent untouched
        assert_eq!(
            fs::read_to_string(laptop_target.join("Assets/Scripts/Player.cs")).unwrap(),
            "class Player { int hp = 100; }"
        );
        assert!(!laptop_target.join("Library").exists());
        assert!(laptop_target.join("EmptyLevelDir").is_dir());
        assert!(!laptop_parent.join("Assets").exists());

        // Laptop edits Player.cs and adds Enemy.cs while Host is asleep
        fs::write(
            laptop_target.join("Assets/Scripts/Player.cs"),
            "class Player { int hp = 250; }",
        )
        .unwrap();
        fs::write(
            laptop_target.join("Assets/Scripts/Enemy.cs"),
            "class Enemy {}",
        )
        .unwrap();
        let out3 = sync_share_once(
            &laptop_client,
            &mut laptop_db,
            &laptop_auth.vault_key,
            &laptop_auth.user_id,
            "laptop-pc",
            &mut laptop_binding,
            None,
            None,
            &noop,
        )
        .unwrap();
        assert_eq!(out3.version, 2);
        assert_eq!(out3.uploaded_files, 2);

        // Host wakes up an hour later and syncs -> gets Laptop's edits!
        let out4 = sync_share_once(
            &host_client,
            &mut host_db,
            &host_auth.vault_key,
            &host_auth.user_id,
            "host-pc",
            &mut host_binding,
            None,
            None,
            &noop,
        )
        .unwrap();
        assert_eq!(out4.downloaded_files, 2);
        assert_eq!(
            fs::read_to_string(host_proj.join("Assets/Scripts/Player.cs")).unwrap(),
            "class Player { int hp = 250; }"
        );
        assert!(host_proj.join("Assets/Scripts/Enemy.cs").is_file());
    }

    #[test]
    fn e2e_concurrent_offline_edits_preserve_conflict_backup() {
        let (_rt, url, _relay_dir) = start_test_relay();

        let host_auth = RelayClient::new(&url, "", None)
            .login_zero_knowledge("admin", "test-password-123", "host-pc", "Main PC")
            .unwrap()
            .0;
        let host_client = RelayClient::new(&url, &host_auth.token, None);

        let laptop_auth = RelayClient::new(&url, "", None)
            .login_zero_knowledge("admin", "test-password-123", "laptop-pc", "Laptop")
            .unwrap()
            .0;
        let laptop_client = RelayClient::new(&url, &laptop_auth.token, None);

        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let folder_a = dir_a.path().join("Notes");
        let folder_b = dir_b.path().join("Notes");
        fs::create_dir_all(&folder_a).unwrap();
        fs::write(folder_a.join("todo.txt"), "v1").unwrap();

        let mut bind_a = LocalShareBinding {
            share_id: "notes-1".to_string(),
            name: "Notes".to_string(),
            local_path: folder_a.clone(),
            ignore_patterns: Vec::new(),
            paused: false,
        };
        let mut bind_b = LocalShareBinding {
            share_id: "notes-1".to_string(),
            name: "Notes".to_string(),
            local_path: folder_b.clone(),
            ignore_patterns: Vec::new(),
            paused: false,
        };
        let mut db_a = LocalStateDb::open(&dir_a.path().join("a.db")).unwrap();
        let mut db_b = LocalStateDb::open(&dir_b.path().join("b.db")).unwrap();
        let noop = |_: &str, _: u64, _: u64| {};

        sync_share_once(&host_client, &mut db_a, &host_auth.vault_key, &host_auth.user_id, "host-pc", &mut bind_a, None, None, &noop).unwrap();
        sync_share_once(&laptop_client, &mut db_b, &laptop_auth.vault_key, &laptop_auth.user_id, "laptop-pc", &mut bind_b, None, None, &noop).unwrap();

        // Both edit offline with different content
        fs::write(folder_a.join("todo.txt"), "host-edit-v2").unwrap();
        fs::write(folder_b.join("todo.txt"), "laptop-edit-v2").unwrap();

        // Host pushes first
        sync_share_once(&host_client, &mut db_a, &host_auth.vault_key, &host_auth.user_id, "host-pc", &mut bind_a, None, None, &noop).unwrap();
        // Laptop syncs second -> detects conflict, backs up laptop-edit-v2, pulls host-edit-v2
        let out_b = sync_share_once(&laptop_client, &mut db_b, &laptop_auth.vault_key, &laptop_auth.user_id, "laptop-pc", &mut bind_b, None, None, &noop).unwrap();
        assert_eq!(out_b.conflicts_created, 1);
        assert_eq!(fs::read_to_string(folder_b.join("todo.txt")).unwrap(), "host-edit-v2");

        let conflicts = db_b.list_conflicts().unwrap();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(
            fs::read_to_string(&conflicts[0].conflict_path).unwrap(),
            "laptop-edit-v2"
        );
    }
}
