mod api_v1;
mod auth;
mod db;
mod storage;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path as AxumPath, Query, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Extension, Json, Router};
use deltadrop_common::{
    decode_meta_header, normalize_rel_path, AckPullRequest, AckRequest, DeleteRequest,
    EventsResponse, FolderIndexPayload, HasChunksRequest, HasChunksResponse, OpType, PeerInfo,
    PeerRegistration, PendingDelta, PendingPullRequest, PullRequest, RelayStatus, PROTOCOL_HEADER,
    PROTOCOL_VERSION,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use tokio::sync::{broadcast, mpsc, Semaphore};
use tracing::{error, info, warn};
use uuid::Uuid;

use auth::{
    auth_middleware, derive_auth_key_for_cli, gate_middleware, generate_random_hex_32,
    hash_auth_key, AuthPeer, RateLimitEntry,
};
pub use db::init_db;
use db::{
    current_peer_usage, current_usage, is_blob_referenced, is_valid_chunk_id, release_delta_chunks,
};
pub use storage::{
    evict_lru_user_chunks, gc_expired_deltas, gc_expired_user_chunks, gc_orphan_blobs,
};
use storage::{now_ms, QuotaGuard};

pub type WsClientMap = Arc<Mutex<HashMap<(String, String), mpsc::UnboundedSender<String>>>>;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Mutex<Connection>>,
    pub blobs_dir: PathBuf,
    pub chunks_dir: PathBuf,
    pub auth_token: String,
    pub network_secret: Option<String>,
    pub max_bytes: u64,
    pub max_peer_bytes: u64,
    pub blob_ttl_secs: u64,
    pub reserved_bytes: Arc<AtomicU64>,
    pub concurrency: Arc<Semaphore>,
    pub notify_tx: broadcast::Sender<String>,
    pub auth_rate_limits: Arc<Mutex<HashMap<IpAddr, RateLimitEntry>>>,
    pub ws_clients: WsClientMap,
}

impl AppState {
    pub fn new(db: Connection, blobs_dir: PathBuf, auth_token: String, max_bytes: u64) -> Self {
        let chunks_dir = blobs_dir.parent().unwrap_or(&blobs_dir).join("chunks");
        let _ = std::fs::create_dir_all(&chunks_dir);
        let (notify_tx, _) = broadcast::channel(256);
        Self {
            db: Arc::new(Mutex::new(db)),
            blobs_dir,
            chunks_dir,
            auth_token,
            network_secret: None,
            max_bytes,
            max_peer_bytes: max_bytes,
            blob_ttl_secs: 72 * 3600,
            reserved_bytes: Arc::new(AtomicU64::new(0)),
            concurrency: Arc::new(Semaphore::new(64)),
            notify_tx,
            auth_rate_limits: Arc::new(Mutex::new(HashMap::new())),
            ws_clients: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[derive(Deserialize)]
struct PeerQuery {
    peer: String,
}

#[derive(Deserialize)]
struct WorkspaceQuery {
    workspace_id: String,
}

#[derive(Deserialize)]
struct EventsQuery {
    peer: String,
    wait_secs: Option<u64>,
}

#[derive(Deserialize)]
struct FolderIndexQuery {
    source_peer: String,
    folder_id: String,
}

#[derive(Deserialize)]
struct FolderIndicesQuery {
    source_peer: String,
}

async fn limit_and_timeout_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if let Some(ver) = req
        .headers()
        .get(PROTOCOL_HEADER)
        .and_then(|v| v.to_str().ok())
    {
        if ver.trim() != PROTOCOL_VERSION {
            return Err(StatusCode::UPGRADE_REQUIRED);
        }
    }
    let _permit = state
        .concurrency
        .clone()
        .try_acquire_owned()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let mut resp = tokio::time::timeout(Duration::from_secs(60), next.run(req))
        .await
        .map_err(|_| StatusCode::REQUEST_TIMEOUT)?;
    if let Ok(val) = axum::http::HeaderValue::from_str(PROTOCOL_VERSION) {
        resp.headers_mut().insert(PROTOCOL_HEADER, val);
    }
    Ok(resp)
}

async fn healthz() -> &'static str {
    "ok"
}

async fn get_status(State(state): State<AppState>) -> Result<Json<RelayStatus>, StatusCode> {
    let db = state
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let (queued_count, used_bytes) =
        current_usage(&db).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(RelayStatus {
        queued_count,
        used_bytes,
        max_bytes: state.max_bytes,
    }))
}

async fn put_delta(
    State(state): State<AppState>,
    Extension(auth_peer): Extension<AuthPeer>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<PendingDelta>, (StatusCode, String)> {
    let meta_raw = headers
        .get("X-Delta-Meta")
        .and_then(|v| v.to_str().ok())
        .ok_or((
            StatusCode::BAD_REQUEST,
            "Missing X-Delta-Meta header".to_string(),
        ))?;
    let meta = decode_meta_header(meta_raw).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    auth_peer
        .require_matches(&meta.source_peer)
        .map_err(|s| (s, "Token is not authorized for source_peer".to_string()))?;

    let rel_path = normalize_rel_path(&meta.rel_path)
        .ok_or((StatusCode::BAD_REQUEST, "Invalid rel_path".to_string()))?;
    let new_zst_size = body.len() as u64;
    let blob_name = format!("{}.zst", Uuid::new_v4());
    let blob_path = state.blobs_dir.join(&blob_name);
    let tmp_path = state.blobs_dir.join(format!("{}.tmp", Uuid::new_v4()));

    // Reserve quota atomically while holding the DB lock so concurrent uploads cannot exceed max_bytes.
    let _quota_guard = {
        let db = state
            .db
            .lock()
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB lock poisoned".into()))?;
        let (_, used_bytes) =
            current_usage(&db).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let peer_used = current_peer_usage(&db, &meta.target_peer)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let existing_size: u64 = db
            .query_row(
                "SELECT zst_size FROM pending_deltas WHERE target_peer = ?1 AND folder_id = ?2 AND rel_path = ?3",
                params![meta.target_peer, meta.folder_id, rel_path],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .map(|sz| sz as u64)
            .unwrap_or(0);

        let reserved = state.reserved_bytes.load(Ordering::SeqCst);
        let projected = used_bytes
            .saturating_sub(existing_size)
            .saturating_add(reserved)
            .saturating_add(new_zst_size);
        if projected > state.max_bytes {
            return Err((
                StatusCode::INSUFFICIENT_STORAGE,
                format!(
                    "Relay storage quota exceeded ({projected} > {})",
                    state.max_bytes
                ),
            ));
        }
        let projected_peer = peer_used
            .saturating_sub(existing_size)
            .saturating_add(new_zst_size);
        if projected_peer > state.max_peer_bytes {
            return Err((
                StatusCode::INSUFFICIENT_STORAGE,
                format!(
                    "Per-peer quota exceeded ({projected_peer} > {})",
                    state.max_peer_bytes
                ),
            ));
        }
        state
            .reserved_bytes
            .fetch_add(new_zst_size, Ordering::SeqCst);
        QuotaGuard {
            counter: state.reserved_bytes.clone(),
            amount: new_zst_size,
        }
    };

    // Write compressed blob atomically before committing DB row; clean up temp file on failure.
    if let Err(e) = tokio::fs::write(&tmp_path, &body).await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Write blob failed: {e}"),
        ));
    }
    if let Err(e) = tokio::fs::rename(&tmp_path, &blob_path).await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Rename blob failed: {e}"),
        ));
    }

    let created_at = now_ms();
    type PutDeltaDbResult = Result<(i64, Option<String>, Vec<String>), (StatusCode, String)>;
    let db_result: PutDeltaDbResult = (|| {
        let mut db = state
            .db
            .lock()
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB lock poisoned".into()))?;
        let tx = db
            .transaction()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let old_row: Option<(i64, String)> = tx
            .query_row(
                "SELECT id, blob_name FROM pending_deltas WHERE target_peer = ?1 AND folder_id = ?2 AND rel_path = ?3",
                params![meta.target_peer, meta.folder_id, rel_path],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let mut old_chunks = Vec::new();
        let old_blob = if let Some((old_id, blob)) = old_row {
            old_chunks = release_delta_chunks(&tx, old_id)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            if blob.is_empty() {
                None
            } else {
                Some(blob)
            }
        } else {
            None
        };

        // Delete + insert so every new version gets a fresh monotonic id (prevents stale ACK races).
        tx.execute(
            "DELETE FROM pending_deltas WHERE target_peer = ?1 AND folder_id = ?2 AND rel_path = ?3",
            params![meta.target_peer, meta.folder_id, rel_path],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let op_str = match meta.op_type {
            OpType::Upsert => "upsert",
            OpType::Delete => "delete",
        };
        let chunk_ids_json = serde_json::to_string(&meta.chunk_ids)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        tx.execute(
            "INSERT INTO pending_deltas
                (source_peer, target_peer, folder_id, rel_path, op_type, blake3_hash, base_hash, delta_version, chunk_ids_json, raw_size, zst_size, mtime_ms, created_at_ms, blob_name)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                meta.source_peer,
                meta.target_peer,
                meta.folder_id,
                rel_path,
                op_str,
                meta.blake3_hash,
                meta.base_hash,
                meta.delta_version as i64,
                chunk_ids_json,
                meta.raw_size as i64,
                new_zst_size as i64,
                meta.mtime_ms,
                created_at,
                blob_name,
            ],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let delta_id = tx.last_insert_rowid();
        for cid in &meta.chunk_ids {
            if is_valid_chunk_id(cid) {
                tx.execute(
                    "INSERT OR IGNORE INTO delta_chunks (delta_id, chunk_id) VALUES (?1, ?2)",
                    params![delta_id, cid],
                )
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            }
        }
        tx.commit()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let unlink_old = match old_blob {
            Some(ref old) if !is_blob_referenced(&db, old).unwrap_or(true) => Some(old.clone()),
            _ => None,
        };
        Ok((delta_id, unlink_old, old_chunks))
    })();

    let (delta_id, old_blob_to_remove, old_chunks_to_remove) = match db_result {
        Ok(v) => v,
        Err(e) => {
            let _ = tokio::fs::remove_file(&blob_path).await;
            return Err(e);
        }
    };

    if let Some(old_name) = old_blob_to_remove {
        let old_path = state.blobs_dir.join(old_name);
        if let Err(e) = tokio::fs::remove_file(&old_path).await {
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!(
                    "Failed to unlink superseded blob {}: {e}",
                    old_path.display()
                );
            }
        }
    }
    for cid in old_chunks_to_remove {
        let _ = tokio::fs::remove_file(state.chunks_dir.join(format!("{cid}.chk"))).await;
    }
    let _ = state.notify_tx.send(meta.target_peer.clone());

    Ok(Json(PendingDelta {
        id: delta_id,
        source_peer: meta.source_peer,
        target_peer: meta.target_peer,
        folder_id: meta.folder_id,
        rel_path,
        op_type: meta.op_type,
        blake3_hash: meta.blake3_hash,
        base_hash: meta.base_hash,
        delta_version: meta.delta_version,
        chunk_ids: meta.chunk_ids,
        raw_size: meta.raw_size,
        zst_size: new_zst_size,
        mtime_ms: meta.mtime_ms,
        created_at_ms: created_at,
    }))
}

async fn post_delete(
    State(state): State<AppState>,
    Extension(auth_peer): Extension<AuthPeer>,
    Json(req): Json<DeleteRequest>,
) -> Result<Json<PendingDelta>, (StatusCode, String)> {
    auth_peer
        .require_matches(&req.source_peer)
        .map_err(|s| (s, "Token is not authorized for source_peer".to_string()))?;
    let rel_path = normalize_rel_path(&req.rel_path)
        .ok_or((StatusCode::BAD_REQUEST, "Invalid rel_path".to_string()))?;
    let created_at = now_ms();

    let (delta_id, old_blob_to_remove) = {
        let mut db = state
            .db
            .lock()
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB lock poisoned".into()))?;
        let tx = db
            .transaction()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let old_blob: Option<String> = tx
            .query_row(
                "SELECT blob_name FROM pending_deltas WHERE target_peer = ?1 AND folder_id = ?2 AND rel_path = ?3",
                params![req.target_peer, req.folder_id, rel_path],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .filter(|b| !b.is_empty());

        // Delete + insert so a Delete always gets a fresh monotonic id.
        tx.execute(
            "DELETE FROM pending_deltas WHERE target_peer = ?1 AND folder_id = ?2 AND rel_path = ?3",
            params![req.target_peer, req.folder_id, rel_path],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        tx.execute(
            "INSERT INTO pending_deltas
                (source_peer, target_peer, folder_id, rel_path, op_type, blake3_hash, base_hash, raw_size, zst_size, mtime_ms, created_at_ms, blob_name)
             VALUES (?1, ?2, ?3, ?4, 'delete', '', ?5, 0, 0, ?6, ?7, '')",
            params![
                req.source_peer,
                req.target_peer,
                req.folder_id,
                rel_path,
                req.base_hash,
                req.mtime_ms,
                created_at,
            ],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let delta_id = tx.last_insert_rowid();
        tx.commit()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let unlink_old = match old_blob {
            Some(ref old) if !is_blob_referenced(&db, old).unwrap_or(true) => Some(old.clone()),
            _ => None,
        };
        (delta_id, unlink_old)
    };

    if let Some(old_name) = old_blob_to_remove {
        let old_path = state.blobs_dir.join(old_name);
        let _ = tokio::fs::remove_file(&old_path).await;
    }

    Ok(Json(PendingDelta {
        id: delta_id,
        source_peer: req.source_peer,
        target_peer: req.target_peer,
        folder_id: req.folder_id,
        rel_path,
        op_type: OpType::Delete,
        blake3_hash: String::new(),
        base_hash: req.base_hash,
        delta_version: 0,
        chunk_ids: Vec::new(),
        raw_size: 0,
        zst_size: 0,
        mtime_ms: req.mtime_ms,
        created_at_ms: created_at,
    }))
}

async fn get_deltas(
    State(state): State<AppState>,
    Extension(auth_peer): Extension<AuthPeer>,
    Query(query): Query<PeerQuery>,
) -> Result<Json<Vec<PendingDelta>>, StatusCode> {
    auth_peer.require_matches(&query.peer)?;
    let db = state
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut stmt = db
        .prepare(
            "SELECT id, source_peer, target_peer, folder_id, rel_path, op_type, blake3_hash, base_hash, delta_version, chunk_ids_json, raw_size, zst_size, mtime_ms, created_at_ms
             FROM pending_deltas WHERE target_peer = ?1 ORDER BY id ASC",
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let rows = stmt
        .query_map(params![query.peer], |r| {
            let op_str: String = r.get(5)?;
            let op_type = if op_str == "delete" {
                OpType::Delete
            } else {
                OpType::Upsert
            };
            let chunk_json: String = r.get(9)?;
            let chunk_ids: Vec<String> = serde_json::from_str(&chunk_json).unwrap_or_default();
            Ok(PendingDelta {
                id: r.get(0)?,
                source_peer: r.get(1)?,
                target_peer: r.get(2)?,
                folder_id: r.get(3)?,
                rel_path: r.get(4)?,
                op_type,
                blake3_hash: r.get(6)?,
                base_hash: r.get(7)?,
                delta_version: r.get::<_, i64>(8)? as u64,
                chunk_ids,
                raw_size: r.get::<_, i64>(10)? as u64,
                zst_size: r.get::<_, i64>(11)? as u64,
                mtime_ms: r.get(12)?,
                created_at_ms: r.get(13)?,
            })
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut out = Vec::new();
    for item in rows {
        out.push(item.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?);
    }
    Ok(Json(out))
}

async fn get_delta_blob(
    State(state): State<AppState>,
    Extension(auth_peer): Extension<AuthPeer>,
    AxumPath(id): AxumPath<i64>,
    Query(query): Query<PeerQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    auth_peer.require_matches(&query.peer)?;
    let blob_name: String = {
        let db = state
            .db
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        db.query_row(
            "SELECT blob_name FROM pending_deltas WHERE id = ?1 AND target_peer = ?2 AND blob_name != ''",
            params![id, query.peer],
            |r| r.get(0),
        )
        .optional()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?
    };
    let blob_path = state.blobs_dir.join(blob_name);
    let data = tokio::fs::read(&blob_path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/zstd")],
        data,
    ))
}

async fn post_ack(
    State(state): State<AppState>,
    Extension(auth_peer): Extension<AuthPeer>,
    Json(req): Json<AckRequest>,
) -> Result<StatusCode, StatusCode> {
    auth_peer.require_matches(&req.target_peer)?;
    let (blob_to_purge, chunks_to_purge): (Option<String>, Vec<String>) = {
        let mut db = state
            .db
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let tx = db
            .transaction()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let row: Option<(String, String, String)> = tx
            .query_row(
                "SELECT op_type, blake3_hash, blob_name FROM pending_deltas WHERE id = ?1 AND target_peer = ?2",
                params![req.delta_id, req.target_peer],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let Some((op_type, expected_hash, blob_name)) = row else {
            return Err(StatusCode::NOT_FOUND);
        };

        if op_type == "upsert" && expected_hash != req.verified_blake3 {
            return Err(StatusCode::CONFLICT);
        }

        let unref_chunks = release_delta_chunks(&tx, req.delta_id)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        tx.execute(
            "DELETE FROM pending_deltas WHERE id = ?1 AND target_peer = ?2",
            params![req.delta_id, req.target_peer],
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        tx.commit().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let blob_purge =
            if blob_name.is_empty() || is_blob_referenced(&db, &blob_name).unwrap_or(true) {
                None
            } else {
                Some(blob_name)
            };
        (blob_purge, unref_chunks)
    };

    if let Some(name) = blob_to_purge {
        let path = state.blobs_dir.join(name);
        if let Err(e) = tokio::fs::remove_file(&path).await {
            if e.kind() != std::io::ErrorKind::NotFound {
                error!("Failed to purge ACKed blob {}: {e}", path.display());
            }
        }
    }
    for cid in chunks_to_purge {
        let _ = tokio::fs::remove_file(state.chunks_dir.join(format!("{cid}.chk"))).await;
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn post_chunks_has(
    State(state): State<AppState>,
    Json(req): Json<HasChunksRequest>,
) -> Result<Json<HasChunksResponse>, StatusCode> {
    let mut missing = Vec::new();
    let db = state
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    for cid in req.chunk_ids {
        if !is_valid_chunk_id(&cid) {
            return Err(StatusCode::BAD_REQUEST);
        }
        let exists_db: bool = db
            .query_row(
                "SELECT 1 FROM chunks WHERE chunk_id = ?1",
                params![cid],
                |_| Ok(true),
            )
            .optional()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .unwrap_or(false);
        if !exists_db || !state.chunks_dir.join(format!("{cid}.chk")).exists() {
            missing.push(cid);
        }
    }
    Ok(Json(HasChunksResponse { missing }))
}

async fn put_chunk(
    State(state): State<AppState>,
    AxumPath(chunk_id): AxumPath<String>,
    body: Bytes,
) -> Result<StatusCode, (StatusCode, String)> {
    if !is_valid_chunk_id(&chunk_id) {
        return Err((StatusCode::BAD_REQUEST, "Invalid chunk_id".into()));
    }
    let chunk_size = body.len() as u64;
    let chunk_path = state.chunks_dir.join(format!("{chunk_id}.chk"));
    let tmp_path = state
        .chunks_dir
        .join(format!("{chunk_id}.{}.tmp", Uuid::new_v4()));

    let _quota_guard = {
        let db = state
            .db
            .lock()
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB lock poisoned".into()))?;
        let exists_db: bool = db
            .query_row(
                "SELECT 1 FROM chunks WHERE chunk_id = ?1",
                params![chunk_id],
                |_| Ok(true),
            )
            .optional()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .unwrap_or(false);
        if exists_db && chunk_path.exists() {
            return Ok(StatusCode::NO_CONTENT);
        }
        let (_, used_bytes) =
            current_usage(&db).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let reserved = state.reserved_bytes.load(Ordering::SeqCst);
        let projected = used_bytes
            .saturating_add(reserved)
            .saturating_add(chunk_size);
        if projected > state.max_bytes {
            return Err((
                StatusCode::INSUFFICIENT_STORAGE,
                format!(
                    "Relay storage quota exceeded ({projected} > {})",
                    state.max_bytes
                ),
            ));
        }
        state.reserved_bytes.fetch_add(chunk_size, Ordering::SeqCst);
        QuotaGuard {
            counter: state.reserved_bytes.clone(),
            amount: chunk_size,
        }
    };

    if let Err(e) = tokio::fs::write(&tmp_path, &body).await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Write chunk failed: {e}"),
        ));
    }
    if let Err(e) = tokio::fs::rename(&tmp_path, &chunk_path).await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Rename chunk failed: {e}"),
        ));
    }

    let db = state
        .db
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB lock poisoned".into()))?;
    db.execute(
        "INSERT OR IGNORE INTO chunks (chunk_id, size_bytes, created_at_ms) VALUES (?1, ?2, ?3)",
        params![chunk_id, chunk_size as i64, now_ms()],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

async fn get_chunk(
    State(state): State<AppState>,
    AxumPath(chunk_id): AxumPath<String>,
) -> Result<impl IntoResponse, StatusCode> {
    if !is_valid_chunk_id(&chunk_id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let chunk_path = state.chunks_dir.join(format!("{chunk_id}.chk"));
    let data = tokio::fs::read(&chunk_path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        data,
    ))
}

async fn get_events(
    State(state): State<AppState>,
    Extension(auth_peer): Extension<AuthPeer>,
    Query(q): Query<EventsQuery>,
) -> Result<Json<EventsResponse>, StatusCode> {
    auth_peer.require_matches(&q.peer)?;
    let has_pending = || -> Result<bool, StatusCode> {
        let db = state
            .db
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let d_count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM pending_deltas WHERE target_peer = ?1",
                params![q.peer],
                |r| r.get(0),
            )
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if d_count > 0 {
            return Ok(true);
        }
        let p_count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM pull_requests WHERE target_peer = ?1",
                params![q.peer],
                |r| r.get(0),
            )
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok(p_count > 0)
    };

    if has_pending()? {
        return Ok(Json(EventsResponse { pending: true }));
    }

    let wait = Duration::from_secs(q.wait_secs.unwrap_or(25).clamp(1, 30));
    let mut rx = state.notify_tx.subscribe();
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Ok(Json(EventsResponse { pending: false }));
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Ok(target)) if target == q.peer => {
                return Ok(Json(EventsResponse { pending: true }));
            }
            Ok(Ok(_)) => continue,
            Ok(Err(broadcast::error::RecvError::Lagged(_))) => {
                if has_pending()? {
                    return Ok(Json(EventsResponse { pending: true }));
                }
            }
            Ok(Err(_)) | Err(_) => {
                return Ok(Json(EventsResponse { pending: false }));
            }
        }
    }
}

async fn put_folder_index(
    State(state): State<AppState>,
    Extension(auth_peer): Extension<AuthPeer>,
    Json(payload): Json<FolderIndexPayload>,
) -> Result<StatusCode, StatusCode> {
    auth_peer.require_matches(&payload.source_peer)?;
    let subdirs_json =
        serde_json::to_string(&payload.subdirs).map_err(|_| StatusCode::BAD_REQUEST)?;
    let db = state
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    db.execute(
        "INSERT INTO folder_indices (source_peer, folder_id, subdirs_json, updated_at_ms)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(source_peer, folder_id) DO UPDATE SET
            subdirs_json = excluded.subdirs_json,
            updated_at_ms = excluded.updated_at_ms",
        params![
            payload.source_peer,
            payload.folder_id,
            subdirs_json,
            payload.updated_at_ms
        ],
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_folder_index(
    State(state): State<AppState>,
    Extension(auth_peer): Extension<AuthPeer>,
    Query(q): Query<FolderIndexQuery>,
) -> Result<StatusCode, StatusCode> {
    auth_peer.require_matches(&q.source_peer)?;
    let db = state
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    db.execute(
        "DELETE FROM folder_indices WHERE source_peer = ?1 AND folder_id = ?2",
        params![q.source_peer, q.folder_id],
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn post_register_peer(
    State(state): State<AppState>,
    Extension(auth_peer): Extension<AuthPeer>,
    Json(req): Json<PeerRegistration>,
) -> Result<StatusCode, StatusCode> {
    auth_peer.require_matches(&req.peer_id)?;
    if req.peer_id.trim().is_empty() || req.workspace_id.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let db = state
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    db.execute(
        "INSERT INTO peers (peer_id, workspace_id, last_seen_ms)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(peer_id) DO UPDATE SET
            workspace_id = excluded.workspace_id,
            last_seen_ms = excluded.last_seen_ms",
        params![req.peer_id, req.workspace_id, now_ms()],
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_peers(
    State(state): State<AppState>,
    Query(q): Query<WorkspaceQuery>,
) -> Result<Json<Vec<PeerInfo>>, StatusCode> {
    let db = state
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut stmt = db
        .prepare(
            "SELECT peer_id, workspace_id, last_seen_ms FROM peers WHERE workspace_id = ?1 ORDER BY peer_id ASC",
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let rows = stmt
        .query_map(params![q.workspace_id], |r| {
            Ok(PeerInfo {
                peer_id: r.get(0)?,
                workspace_id: r.get(1)?,
                last_seen_ms: r.get(2)?,
            })
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut out = Vec::new();
    for item in rows {
        out.push(item.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?);
    }
    Ok(Json(out))
}

async fn get_folder_indices(
    State(state): State<AppState>,
    Query(q): Query<FolderIndicesQuery>,
) -> Result<Json<Vec<FolderIndexPayload>>, StatusCode> {
    let db = state
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut stmt = db
        .prepare(
            "SELECT folder_id, subdirs_json, updated_at_ms FROM folder_indices WHERE source_peer = ?1 ORDER BY folder_id ASC",
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let rows = stmt
        .query_map(params![q.source_peer], |r| {
            let folder_id: String = r.get(0)?;
            let subdirs_json: String = r.get(1)?;
            let updated_at_ms: i64 = r.get(2)?;
            let subdirs: Vec<String> = serde_json::from_str(&subdirs_json).unwrap_or_default();
            Ok(FolderIndexPayload {
                source_peer: q.source_peer.clone(),
                folder_id,
                subdirs,
                updated_at_ms,
            })
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut out = Vec::new();
    for item in rows {
        out.push(item.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?);
    }
    Ok(Json(out))
}

async fn post_pull_request(
    State(state): State<AppState>,
    Extension(auth_peer): Extension<AuthPeer>,
    Json(req): Json<PullRequest>,
) -> Result<StatusCode, StatusCode> {
    auth_peer.require_matches(&req.source_peer)?;
    let subdir = if req.subdir == "*" {
        "*".to_string()
    } else {
        normalize_rel_path(&req.subdir).ok_or(StatusCode::BAD_REQUEST)?
    };
    {
        let db = state
            .db
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        db.execute(
            "INSERT INTO pull_requests (source_peer, target_peer, folder_id, subdir, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(target_peer, folder_id, subdir) DO UPDATE SET
                source_peer = excluded.source_peer,
                created_at_ms = excluded.created_at_ms",
            params![
                req.source_peer,
                req.target_peer,
                req.folder_id,
                subdir,
                now_ms()
            ],
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    let _ = state.notify_tx.send(req.target_peer);
    Ok(StatusCode::ACCEPTED)
}

async fn get_pull_requests(
    State(state): State<AppState>,
    Extension(auth_peer): Extension<AuthPeer>,
    Query(q): Query<PeerQuery>,
) -> Result<Json<Vec<PendingPullRequest>>, StatusCode> {
    auth_peer.require_matches(&q.peer)?;
    let db = state
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut stmt = db
        .prepare(
            "SELECT id, source_peer, target_peer, folder_id, subdir, created_at_ms
             FROM pull_requests WHERE target_peer = ?1 ORDER BY id ASC",
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let rows = stmt
        .query_map(params![q.peer], |r| {
            Ok(PendingPullRequest {
                id: r.get(0)?,
                source_peer: r.get(1)?,
                target_peer: r.get(2)?,
                folder_id: r.get(3)?,
                subdir: r.get(4)?,
                created_at_ms: r.get(5)?,
            })
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut out = Vec::new();
    for item in rows {
        out.push(item.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?);
    }
    Ok(Json(out))
}

async fn post_pull_request_ack(
    State(state): State<AppState>,
    Extension(auth_peer): Extension<AuthPeer>,
    Json(req): Json<AckPullRequest>,
) -> Result<StatusCode, StatusCode> {
    auth_peer.require_matches(&req.target_peer)?;
    let db = state
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    db.execute(
        "DELETE FROM pull_requests WHERE id = ?1 AND target_peer = ?2",
        params![req.request_id, req.target_peer],
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn build_router(state: AppState) -> Router {
    let authed_routes = Router::new()
        .route("/v1/status", get(get_status))
        .route("/v1/events", get(get_events))
        .route(
            "/v1/deltas",
            put(put_delta).get(get_deltas).layer(DefaultBodyLimit::max(
                deltadrop_common::MAX_CHUNK_HTTP_BYTES,
            )),
        )
        .route("/v1/deltas/:id/blob", get(get_delta_blob))
        .route("/v1/chunks/has", post(post_chunks_has))
        .route(
            "/v1/chunks/:chunk_id",
            put(put_chunk).get(get_chunk).layer(DefaultBodyLimit::max(
                deltadrop_common::MAX_CHUNK_HTTP_BYTES,
            )),
        )
        .route("/v1/deletes", post(post_delete))
        .route("/v1/ack", post(post_ack))
        .route(
            "/v1/folder-index",
            put(put_folder_index).delete(delete_folder_index),
        )
        .route("/v1/folder-indices", get(get_folder_indices))
        .route("/v1/peers/register", post(post_register_peer))
        .route("/v1/peers", get(get_peers))
        .route(
            "/v1/pull-requests",
            post(post_pull_request).get(get_pull_requests),
        )
        .route("/v1/pull-requests/ack", post(post_pull_request_ack))
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    let gated_routes = authed_routes
        .merge(api_v1::build_api_v1_router(state.clone()))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            gate_middleware,
        ));

    Router::new()
        .route("/healthz", get(healthz))
        .merge(gated_routes)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            limit_and_timeout_middleware,
        ))
        .with_state(state)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("Shutdown signal received, draining connections...");
}

pub async fn serve_on(listener: tokio::net::TcpListener, state: AppState) -> anyhow::Result<()> {
    let app = build_router(state);
    axum::serve(listener, app).await?;
    Ok(())
}

pub async fn run_cli_or_server() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 3 && args[1] == "user" && args[2] == "create" {
        return handle_user_create_cli(&args[3..]);
    }
    run_server().await
}

fn handle_user_create_cli(args: &[String]) -> anyhow::Result<()> {
    let mut username = None;
    let mut password = None;
    let mut is_admin = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--username" | "-u" => {
                i += 1;
                username = args.get(i).cloned();
            }
            "--password" | "-p" => {
                i += 1;
                password = args.get(i).cloned();
            }
            "--admin" => {
                is_admin = true;
            }
            other => anyhow::bail!("Unknown flag: {other}"),
        }
        i += 1;
    }
    let username = username
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("--username is required"))?;
    let password = password
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("--password is required"))?;

    let data_dir = PathBuf::from(
        std::env::var("DELTADROP_DATA_DIR").unwrap_or_else(|_| "/var/lib/deltadrop".to_string()),
    );
    std::fs::create_dir_all(&data_dir)?;
    let conn = init_db(&data_dir.join("relay.db"))?;

    let salt_hex = generate_random_hex_32();
    let auth_key = derive_auth_key_for_cli(&password, &salt_hex)?;
    let auth_hash = hash_auth_key(&auth_key)?;
    let role = if is_admin { "admin" } else { "user" };
    let id = Uuid::new_v4().to_string();
    let now = now_ms();

    conn.execute(
        "INSERT INTO users (id, username, role, salt, auth_hash, disabled, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)",
        params![id, username, role, salt_hex, auth_hash, now],
    )?;
    println!("Created {role} user '{username}' (id={id})");
    Ok(())
}

pub async fn run_server() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "deltadrop_relay=info".into()),
        )
        .init();

    let bind_addr: SocketAddr = std::env::var("DELTADROP_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8787".to_string())
        .parse()?;
    let data_dir = PathBuf::from(
        std::env::var("DELTADROP_DATA_DIR").unwrap_or_else(|_| "/var/lib/deltadrop".to_string()),
    );
    let auth_token = std::env::var("DELTADROP_AUTH_TOKEN").unwrap_or_default();
    let network_secret = std::env::var("RELAY_NETWORK_SECRET")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let max_bytes: u64 = if let Ok(gb_str) = std::env::var("MAX_CACHE_GB") {
        let gb: u64 = gb_str.trim().parse().unwrap_or(50);
        gb.saturating_mul(1024 * 1024 * 1024)
    } else {
        std::env::var("DELTADROP_MAX_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(50 * 1024 * 1024 * 1024)
    };
    let max_peer_bytes: u64 = std::env::var("DELTADROP_MAX_PEER_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| max_bytes.saturating_mul(80) / 100);
    let blob_ttl_secs: u64 = if let Ok(hrs_str) = std::env::var("CHUNK_TTL_HOURS") {
        let hrs: u64 = hrs_str.trim().parse().unwrap_or(72);
        hrs.saturating_mul(3600)
    } else {
        std::env::var("DELTADROP_BLOB_TTL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(72 * 3600)
    };

    std::fs::create_dir_all(&data_dir)?;
    let blobs_dir = data_dir.join("blobs");
    std::fs::create_dir_all(&blobs_dir)?;
    let conn = init_db(&data_dir.join("relay.db"))?;

    let mut state = AppState::new(conn, blobs_dir, auth_token, max_bytes);
    state.max_peer_bytes = max_peer_bytes.max(1);
    state.blob_ttl_secs = blob_ttl_secs;
    state.network_secret = network_secret;

    gc_expired_deltas(&state.db, &state.blobs_dir, state.blob_ttl_secs);
    gc_orphan_blobs(&state.db, &state.blobs_dir, 0);
    gc_expired_user_chunks(&state.db, &state.chunks_dir, state.blob_ttl_secs);
    evict_lru_user_chunks(&state.db, &state.chunks_dir, state.max_bytes);

    let gc_db = state.db.clone();
    let gc_dir = state.blobs_dir.clone();
    let gc_chunks_dir = state.chunks_dir.clone();
    let gc_ttl = state.blob_ttl_secs;
    let gc_max = state.max_bytes;
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(300));
        tick.tick().await;
        loop {
            tick.tick().await;
            gc_expired_deltas(&gc_db, &gc_dir, gc_ttl);
            gc_orphan_blobs(&gc_db, &gc_dir, 60);
            gc_expired_user_chunks(&gc_db, &gc_chunks_dir, gc_ttl);
            evict_lru_user_chunks(&gc_db, &gc_chunks_dir, gc_max);
        }
    });

    let app = build_router(state);
    info!("deltadrop-relay listening on {bind_addr} (max_bytes={max_bytes}, ttl_secs={blob_ttl_secs})");
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Method;
    use deltadrop_common::{encode_meta_header, DeltaUploadMeta};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn test_state(max_bytes: u64) -> (tempfile::TempDir, AppState) {
        let dir = tempfile::tempdir().unwrap();
        let blobs_dir = dir.path().join("blobs");
        std::fs::create_dir_all(&blobs_dir).unwrap();
        let conn = init_db(&dir.path().join("relay.db")).unwrap();
        let state = AppState::new(conn, blobs_dir, "test-secret".to_string(), max_bytes);
        (dir, state)
    }

    #[tokio::test]
    async fn deduplicates_in_place_and_purges_on_ack() {
        let (_dir, state) = test_state(1024 * 1024);
        let app = build_router(state.clone());

        let meta1 = encode_meta_header(&DeltaUploadMeta {
            source_peer: "desktop".into(),
            target_peer: "laptop".into(),
            folder_id: "code".into(),
            rel_path: "src/main.rs".into(),
            blake3_hash: "hash1".into(),
            base_hash: None,
            op_type: OpType::Upsert,
            delta_version: 1,
            chunk_ids: vec![],
            raw_size: 10,
            mtime_ms: 100,
        })
        .unwrap();

        let resp1 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/v1/deltas")
                    .header("Authorization", "Bearer test-secret")
                    .header("X-Delta-Meta", meta1)
                    .body(Body::from(vec![1u8; 32]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp1.status(), StatusCode::OK);
        let d1: PendingDelta =
            serde_json::from_slice(&resp1.into_body().collect().await.unwrap().to_bytes()).unwrap();

        // Overwrite same (target_peer, folder_id, rel_path)
        let meta2 = encode_meta_header(&DeltaUploadMeta {
            source_peer: "desktop".into(),
            target_peer: "laptop".into(),
            folder_id: "code".into(),
            rel_path: "src/main.rs".into(),
            blake3_hash: "hash2".into(),
            base_hash: Some("hash1".into()),
            op_type: OpType::Upsert,
            delta_version: 2,
            chunk_ids: vec![],
            raw_size: 20,
            mtime_ms: 200,
        })
        .unwrap();

        let resp2 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/v1/deltas")
                    .header("Authorization", "Bearer test-secret")
                    .header("X-Delta-Meta", meta2)
                    .body(Body::from(vec![2u8; 48]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
        let body2 = resp2.into_body().collect().await.unwrap().to_bytes();
        let delta: PendingDelta = serde_json::from_slice(&body2).unwrap();
        assert!(
            delta.id > d1.id,
            "overwrite must allocate a fresh monotonic id"
        );

        // Only 1 blob file and 1 queued row should exist
        assert_eq!(std::fs::read_dir(&state.blobs_dir).unwrap().count(), 1);
        let status_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/status")
                    .header("Authorization", "Bearer test-secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status_bytes = status_resp.into_body().collect().await.unwrap().to_bytes();
        let status: RelayStatus = serde_json::from_slice(&status_bytes).unwrap();
        assert_eq!(status.queued_count, 1);
        assert_eq!(status.used_bytes, 48);

        // ACK immediately purges blob and SQLite row
        let ack_body = serde_json::to_string(&AckRequest {
            target_peer: "laptop".into(),
            delta_id: delta.id,
            verified_blake3: "hash2".into(),
        })
        .unwrap();
        let ack_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/ack")
                    .header("Authorization", "Bearer test-secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(ack_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ack_resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(std::fs::read_dir(&state.blobs_dir).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn stale_ack_does_not_purge_newer_delete() {
        let (_dir, state) = test_state(1024 * 1024);
        let app = build_router(state.clone());

        let meta = encode_meta_header(&DeltaUploadMeta {
            source_peer: "desktop".into(),
            target_peer: "laptop".into(),
            folder_id: "code".into(),
            rel_path: "notes.md".into(),
            blake3_hash: "h1".into(),
            base_hash: None,
            op_type: OpType::Upsert,
            delta_version: 1,
            chunk_ids: vec![],
            raw_size: 5,
            mtime_ms: 100,
        })
        .unwrap();
        let up = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/v1/deltas")
                    .header("Authorization", "Bearer test-secret")
                    .header("X-Delta-Meta", meta)
                    .body(Body::from(vec![1u8; 16]))
                    .unwrap(),
            )
            .await
            .unwrap();
        let v1: PendingDelta =
            serde_json::from_slice(&up.into_body().collect().await.unwrap().to_bytes()).unwrap();

        // Source deletes the file before target ACKs V1
        let del_body = serde_json::to_string(&DeleteRequest {
            source_peer: "desktop".into(),
            target_peer: "laptop".into(),
            folder_id: "code".into(),
            rel_path: "notes.md".into(),
            base_hash: Some("h1".into()),
            mtime_ms: 200,
        })
        .unwrap();
        let del = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/deletes")
                    .header("Authorization", "Bearer test-secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(del_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(del.status(), StatusCode::OK);
        let d_del: PendingDelta =
            serde_json::from_slice(&del.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert!(d_del.id > v1.id);

        // Stale ACK for V1 must fail with 404 and leave the pending Delete intact
        let stale_ack = serde_json::to_string(&AckRequest {
            target_peer: "laptop".into(),
            delta_id: v1.id,
            verified_blake3: "h1".into(),
        })
        .unwrap();
        let ack_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/ack")
                    .header("Authorization", "Bearer test-secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(stale_ack))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ack_resp.status(), StatusCode::NOT_FOUND);

        let list = app
            .oneshot(
                Request::builder()
                    .uri("/v1/deltas?peer=laptop")
                    .header("Authorization", "Bearer test-secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let deltas: Vec<PendingDelta> =
            serde_json::from_slice(&list.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].op_type, OpType::Delete);
        assert_eq!(deltas[0].id, d_del.id);
    }

    #[test]
    fn gc_removes_unreferenced_blobs() {
        let (_dir, state) = test_state(1024 * 1024);
        std::fs::write(state.blobs_dir.join("orphan.zst"), b"junk").unwrap();
        std::fs::write(state.blobs_dir.join("stale.tmp"), b"junk").unwrap();
        assert_eq!(gc_orphan_blobs(&state.db, &state.blobs_dir, 0), 2);
        assert_eq!(std::fs::read_dir(&state.blobs_dir).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn enforces_quota_and_auth() {
        let (_dir, state) = test_state(16);
        let app = build_router(state);

        let unauth = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

        let meta = encode_meta_header(&DeltaUploadMeta {
            source_peer: "desktop".into(),
            target_peer: "laptop".into(),
            folder_id: "code".into(),
            rel_path: "big.bin".into(),
            blake3_hash: "h".into(),
            base_hash: None,
            op_type: OpType::Upsert,
            delta_version: 1,
            chunk_ids: vec![],
            raw_size: 100,
            mtime_ms: 1,
        })
        .unwrap();
        let over = app
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/v1/deltas")
                    .header("Authorization", "Bearer test-secret")
                    .header("X-Delta-Meta", meta)
                    .body(Body::from(vec![0u8; 32]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(over.status(), StatusCode::INSUFFICIENT_STORAGE);
    }

    #[tokio::test]
    async fn scoped_peer_tokens_prevent_cross_peer_access_and_spoofing() {
        let (_dir, state) = test_state(1024 * 1024);
        let app = build_router(state);

        let health = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);

        let desktop_tok = deltadrop_common::derive_peer_token("test-secret", "desktop");
        let laptop_tok = deltadrop_common::derive_peer_token("test-secret", "laptop");

        // Desktop cannot read laptop's queue
        let cross_read = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/deltas?peer=laptop")
                    .header("Authorization", format!("Bearer {desktop_tok}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cross_read.status(), StatusCode::FORBIDDEN);

        // Desktop cannot spoof source_peer = "laptop"
        let spoof_meta = encode_meta_header(&DeltaUploadMeta {
            source_peer: "laptop".into(),
            target_peer: "desktop".into(),
            folder_id: "e2e".into(),
            rel_path: "slot/1".into(),
            op_type: OpType::Upsert,
            blake3_hash: "h".into(),
            base_hash: None,
            delta_version: 1,
            chunk_ids: vec![],
            raw_size: 0,
            mtime_ms: 1,
        })
        .unwrap();
        let spoof = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/v1/deltas")
                    .header("Authorization", format!("Bearer {desktop_tok}"))
                    .header("X-Delta-Meta", spoof_meta)
                    .body(Body::from(vec![1u8; 8]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(spoof.status(), StatusCode::FORBIDDEN);

        // Laptop can read its own queue
        let ok_read = app
            .oneshot(
                Request::builder()
                    .uri("/v1/deltas?peer=laptop")
                    .header("Authorization", format!("Bearer {laptop_tok}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok_read.status(), StatusCode::OK);
        assert_eq!(
            ok_read
                .headers()
                .get(PROTOCOL_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some(PROTOCOL_VERSION)
        );
    }

    #[tokio::test]
    async fn rejects_mismatched_protocol_version() {
        let (_dir, state) = test_state(1024 * 1024);
        let app = build_router(state);
        let bad = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .header(PROTOCOL_HEADER, "99")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad.status(), StatusCode::UPGRADE_REQUIRED);
    }

    fn client_derive(password: &str, salt_hex: &str) -> ([u8; 32], [u8; 32]) {
        let salt = deltadrop_common::decode_hex_32(salt_hex).unwrap();
        let mut master = [0u8; 32];
        argon2::Argon2::default()
            .hash_password_into(password.as_bytes(), &salt[..16], &mut master)
            .unwrap();
        deltadrop_common::derive_auth_and_vault_keys(&master)
    }

    fn seed_admin_user(state: &AppState, username: &str, password: &str) -> String {
        let salt_hex = generate_random_hex_32();
        let (auth_key, _) = client_derive(password, &salt_hex);
        let auth_hash = hash_auth_key(&auth_key).unwrap();
        let id = Uuid::new_v4().to_string();
        let db = state.db.lock().unwrap();
        db.execute(
            "INSERT INTO users (id, username, role, salt, auth_hash, disabled, created_at)
             VALUES (?1, ?2, 'admin', ?3, ?4, 0, ?5)",
            params![id, username, salt_hex, auth_hash, now_ms()],
        )
        .unwrap();
        id
    }

    #[tokio::test]
    async fn admin_subuser_isolation_and_gate_secret() {
        let (_dir, mut state) = test_state(1024 * 1024);
        state.network_secret = Some("gate-secret-123".to_string());
        seed_admin_user(&state, "pauli", "hunter2");
        let app = build_router(state.clone());

        // Missing X-DeltaDrop-Gate returns 401 before touching auth
        let blocked = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/auth/params?username=pauli")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(blocked.status(), StatusCode::UNAUTHORIZED);

        // Fetch params with gate header
        let params_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/auth/params?username=pauli")
                    .header(deltadrop_common::GATE_HEADER, "gate-secret-123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(params_resp.status(), StatusCode::OK);
        let ap: deltadrop_common::AuthParamsResponse =
            serde_json::from_slice(&params_resp.into_body().collect().await.unwrap().to_bytes())
                .unwrap();

        let (auth_key, _) = client_derive("hunter2", &ap.salt_hex);
        let login_body = serde_json::to_string(&deltadrop_common::LoginRequest {
            username: "pauli".into(),
            auth_key_hex: deltadrop_common::encode_hex(&auth_key),
            device_id: "dev-1".into(),
            encrypted_device_name: "enc-desktop".into(),
            os: "windows".into(),
        })
        .unwrap();
        let login_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/auth/login")
                    .header(deltadrop_common::GATE_HEADER, "gate-secret-123")
                    .header("Content-Type", "application/json")
                    .body(Body::from(login_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login_resp.status(), StatusCode::OK);
        let admin_login: deltadrop_common::LoginResponse =
            serde_json::from_slice(&login_resp.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(admin_login.role, deltadrop_common::UserRole::Admin);

        // Admin creates sub-user "alice"
        let sub_salt = generate_random_hex_32();
        let (sub_auth_key, _) = client_derive("alicepass", &sub_salt);
        let create_body = serde_json::to_string(&deltadrop_common::CreateUserRequest {
            username: "alice".into(),
            salt_hex: sub_salt,
            auth_key_hex: deltadrop_common::encode_hex(&sub_auth_key),
            role: deltadrop_common::UserRole::User,
        })
        .unwrap();
        let create_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/admin/users")
                    .header(deltadrop_common::GATE_HEADER, "gate-secret-123")
                    .header("Authorization", format!("Bearer {}", admin_login.token))
                    .header("Content-Type", "application/json")
                    .body(Body::from(create_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_resp.status(), StatusCode::CREATED);
        let alice_info: deltadrop_common::AdminUserInfo =
            serde_json::from_slice(&create_resp.into_body().collect().await.unwrap().to_bytes())
                .unwrap();

        // Alice logs in
        let alice_login_body = serde_json::to_string(&deltadrop_common::LoginRequest {
            username: "alice".into(),
            auth_key_hex: deltadrop_common::encode_hex(&sub_auth_key),
            device_id: "alice-laptop".into(),
            encrypted_device_name: "enc-laptop".into(),
            os: "linux".into(),
        })
        .unwrap();
        let alice_login_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/auth/login")
                    .header(deltadrop_common::GATE_HEADER, "gate-secret-123")
                    .header("Content-Type", "application/json")
                    .body(Body::from(alice_login_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let alice_login: deltadrop_common::LoginResponse = serde_json::from_slice(
            &alice_login_resp
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes(),
        )
        .unwrap();
        assert_eq!(alice_login.role, deltadrop_common::UserRole::User);

        // Sub-user cannot access admin endpoint
        let forbid = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/admin/users")
                    .header(deltadrop_common::GATE_HEADER, "gate-secret-123")
                    .header("Authorization", format!("Bearer {}", alice_login.token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(forbid.status(), StatusCode::FORBIDDEN);

        // Alice uploads a chunk; admin cannot read Alice's chunk (isolated workspace)
        let cid = "0123456789abcdef0123456789abcdef";
        let put_chunk = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(format!(
                        "/api/v1/chunks/{cid}?pending_peers=alice-laptop,alice-pc"
                    ))
                    .header(deltadrop_common::GATE_HEADER, "gate-secret-123")
                    .header("Authorization", format!("Bearer {}", alice_login.token))
                    .body(Body::from(vec![9u8; 64]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put_chunk.status(), StatusCode::NO_CONTENT);

        let cross_get = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/chunks/{cid}"))
                    .header(deltadrop_common::GATE_HEADER, "gate-secret-123")
                    .header("Authorization", format!("Bearer {}", admin_login.token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cross_get.status(), StatusCode::NOT_FOUND);

        // First ACK keeps chunk (alice-pc still pending); second ACK deletes chunk immediately
        let ack1 = serde_json::to_string(&deltadrop_common::ChunkAckRequest {
            device_id: "alice-laptop".into(),
            chunk_ids: vec![cid.into()],
        })
        .unwrap();
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/chunks/ack")
                    .header(deltadrop_common::GATE_HEADER, "gate-secret-123")
                    .header("Authorization", format!("Bearer {}", alice_login.token))
                    .header("Content-Type", "application/json")
                    .body(Body::from(ack1))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(state
            .chunks_dir
            .join(&alice_info.id)
            .join(format!("{cid}.chk"))
            .exists());

        let ack2 = serde_json::to_string(&deltadrop_common::ChunkAckRequest {
            device_id: "alice-pc".into(),
            chunk_ids: vec![cid.into()],
        })
        .unwrap();
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/chunks/ack")
                    .header(deltadrop_common::GATE_HEADER, "gate-secret-123")
                    .header("Authorization", format!("Bearer {}", alice_login.token))
                    .header("Content-Type", "application/json")
                    .body(Body::from(ack2))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(!state
            .chunks_dir
            .join(&alice_info.id)
            .join(format!("{cid}.chk"))
            .exists());
    }

    #[test]
    fn ttl_and_lru_evict_user_chunks() {
        let (_dir, state) = test_state(100);
        let u_dir = state.chunks_dir.join("u1");
        std::fs::create_dir_all(&u_dir).unwrap();
        std::fs::write(u_dir.join("c1.chk"), vec![0u8; 60]).unwrap();
        std::fs::write(u_dir.join("c2.chk"), vec![0u8; 60]).unwrap();
        {
            let db = state.db.lock().unwrap();
            let now = now_ms();
            db.execute(
                "INSERT INTO user_chunks (user_id, chunk_id, size_bytes, pending_peers_json, created_at_ms, last_accessed_ms)
                 VALUES ('u1', 'c1', 60, '[]', ?1, 100)",
                params![now],
            ).unwrap();
            db.execute(
                "INSERT INTO user_chunks (user_id, chunk_id, size_bytes, pending_peers_json, created_at_ms, last_accessed_ms)
                 VALUES ('u1', 'c2', 60, '[]', ?1, 200)",
                params![now],
            ).unwrap();
        }
        assert_eq!(evict_lru_user_chunks(&state.db, &state.chunks_dir, 100), 1);
        assert!(!u_dir.join("c1.chk").exists());
        assert!(u_dir.join("c2.chk").exists());
    }
}
