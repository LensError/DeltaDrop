use std::collections::HashSet;

use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::{delete, get, patch, post, put};
use axum::{Extension, Json, Router};
use deltadrop_common::{
    decode_hex_32, AdminUserInfo, AuthParamsResponse, ChunkAckRequest, CreateUserRequest,
    DeviceInfo, FolderManifestPayload, LoginRequest, LoginResponse, PendingSyncRequest,
    RegisterDeviceRequest, RelayCacheStatus, SyncRequestPayload, UpdateUserRequest, UserRole,
    WsSignal, MAX_CHUNK_HTTP_BYTES,
};
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::auth::{
    auth_rate_limit_middleware, generate_random_hex_32, hash_auth_key, hash_session_token,
    session_auth_middleware, verify_auth_key, AuthUser,
};
use crate::db::{is_valid_chunk_id, purge_user_db_rows, user_chunks_usage};
use crate::storage::{evict_lru_user_chunks, now_ms};
use crate::AppState;

const SESSION_TTL_MS: i64 = 30 * 24 * 3600 * 1000;

#[derive(Deserialize)]
pub struct AuthParamsQuery {
    pub username: String,
}

#[derive(Deserialize)]
pub struct ManifestsQuery {
    pub device_id: Option<String>,
}

#[derive(Deserialize)]
pub struct SyncRequestsQuery {
    pub source_device_id: String,
}

#[derive(Deserialize)]
pub struct ChunkPutQuery {
    pub pending_peers: Option<String>,
}

#[derive(Deserialize)]
pub struct WsQuery {
    pub device_id: String,
}

#[derive(Deserialize)]
pub struct ReplaceDeviceBody {
    pub new_device_id: String,
    pub encrypted_name: String,
    pub os: String,
}

pub fn build_api_v1_router(state: AppState) -> Router<AppState> {
    let auth_routes = Router::new()
        .route("/auth/params", get(get_auth_params))
        .route("/auth/login", post(post_login))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_rate_limit_middleware,
        ));

    let protected_routes = Router::new()
        .route(
            "/admin/users",
            get(admin_list_users).post(admin_create_user),
        )
        .route(
            "/admin/users/:id",
            patch(admin_update_user).delete(admin_delete_user),
        )
        .route("/devices/register", post(register_device))
        .route("/devices", get(list_devices))
        .route("/devices/:device_id", delete(delete_device))
        .route("/devices/:device_id/replace", post(replace_device))
        .route(
            "/manifests/:folder_id",
            put(put_manifest).delete(delete_manifest),
        )
        .route("/manifests", get(list_manifests))
        .route(
            "/sync-requests",
            post(create_sync_request).get(list_sync_requests),
        )
        .route("/sync-requests/:id/fulfill", post(fulfill_sync_request))
        .route(
            "/chunks/:chunk_id",
            put(put_user_chunk)
                .get(get_user_chunk)
                .layer(DefaultBodyLimit::max(MAX_CHUNK_HTTP_BYTES)),
        )
        .route("/chunks/ack", post(ack_user_chunks))
        .route("/cache/status", get(get_cache_status))
        .route("/ws", get(ws_handler))
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(middleware::from_fn_with_state(
            state,
            session_auth_middleware,
        ));

    Router::new().nest("/api/v1", auth_routes.merge(protected_routes))
}

async fn get_auth_params(
    State(state): State<AppState>,
    Query(q): Query<AuthParamsQuery>,
) -> Result<Json<AuthParamsResponse>, StatusCode> {
    let username = q.username.trim();
    if username.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let db = state
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let row: Option<(String, i64)> = db
        .query_row(
            "SELECT salt, disabled FROM users WHERE username = ?1",
            params![username],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let Some((salt_hex, disabled)) = row else {
        return Err(StatusCode::NOT_FOUND);
    };
    if disabled != 0 {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(Json(AuthParamsResponse {
        username: username.to_string(),
        salt_hex,
    }))
}

async fn post_login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    let username = req.username.trim();
    let auth_key = decode_hex_32(&req.auth_key_hex)
        .ok_or((StatusCode::BAD_REQUEST, "Invalid auth_key_hex".into()))?;
    if username.is_empty() || req.device_id.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Username and device_id required".into(),
        ));
    }

    let user_row: Option<(String, String, String, i64)> = {
        let db = state
            .db
            .lock()
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB lock".into()))?;
        db.query_row(
            "SELECT id, role, auth_hash, disabled FROM users WHERE username = ?1",
            params![username],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    };

    let Some((user_id, role_str, auth_hash, disabled)) = user_row else {
        return Err((StatusCode::UNAUTHORIZED, "Invalid credentials".into()));
    };
    if disabled != 0 {
        return Err((StatusCode::FORBIDDEN, "Account disabled".into()));
    }
    if !verify_auth_key(&auth_key, &auth_hash) {
        return Err((StatusCode::UNAUTHORIZED, "Invalid credentials".into()));
    }

    let token = format!(
        "dds_{}_{}",
        Uuid::new_v4().simple(),
        generate_random_hex_32()
    );
    let token_hash = hash_session_token(&token);
    let now = now_ms();
    let expires_at_ms = now + SESSION_TTL_MS;

    {
        let db = state
            .db
            .lock()
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB lock".into()))?;
        db.execute(
            "INSERT INTO sessions (token_hash, user_id, device_id, expires_at_ms, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                token_hash,
                user_id,
                req.device_id.trim(),
                expires_at_ms,
                now
            ],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        db.execute(
            "INSERT INTO devices (user_id, device_id, encrypted_name, os, last_seen_ms, online)
             VALUES (?1, ?2, ?3, ?4, ?5, 1)
             ON CONFLICT(user_id, device_id) DO UPDATE SET
                encrypted_name = CASE WHEN excluded.encrypted_name != '' THEN excluded.encrypted_name ELSE devices.encrypted_name END,
                os = CASE WHEN excluded.os != '' THEN excluded.os ELSE devices.os END,
                last_seen_ms = excluded.last_seen_ms",
            params![
                user_id,
                req.device_id.trim(),
                req.encrypted_device_name,
                req.os,
                now
            ],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    Ok(Json(LoginResponse {
        token,
        user_id,
        username: username.to_string(),
        role: UserRole::from_db(&role_str),
        expires_at_ms,
    }))
}

async fn admin_list_users(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Json<Vec<AdminUserInfo>>, StatusCode> {
    user.require_admin()?;
    let db = state
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut stmt = db
        .prepare(
            "SELECT id, username, role, disabled, created_at FROM users ORDER BY created_at ASC",
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let rows = stmt
        .query_map([], |r| {
            Ok(AdminUserInfo {
                id: r.get(0)?,
                username: r.get(1)?,
                role: UserRole::from_db(&r.get::<_, String>(2)?),
                disabled: r.get::<_, i64>(3)? != 0,
                created_at: r.get(4)?,
            })
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut out = Vec::new();
    for item in rows {
        out.push(item.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?);
    }
    Ok(Json(out))
}

async fn admin_create_user(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<AdminUserInfo>), (StatusCode, String)> {
    user.require_admin()
        .map_err(|s| (s, "Admin role required".into()))?;
    let username = req.username.trim();
    if username.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Username cannot be empty".into()));
    }
    if decode_hex_32(&req.salt_hex).is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "salt_hex must be 32-byte hex".into(),
        ));
    }
    let auth_key = decode_hex_32(&req.auth_key_hex).ok_or((
        StatusCode::BAD_REQUEST,
        "auth_key_hex must be 32-byte hex".into(),
    ))?;
    let auth_hash =
        hash_auth_key(&auth_key).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let id = Uuid::new_v4().to_string();
    let created_at = now_ms();
    let db = state
        .db
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB lock".into()))?;
    db.execute(
        "INSERT INTO users (id, username, role, salt, auth_hash, disabled, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)",
        params![
            id,
            username,
            req.role.as_str(),
            req.salt_hex,
            auth_hash,
            created_at
        ],
    )
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            (StatusCode::CONFLICT, "Username already exists".into())
        } else {
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        }
    })?;

    Ok((
        StatusCode::CREATED,
        Json(AdminUserInfo {
            id,
            username: username.to_string(),
            role: req.role,
            disabled: false,
            created_at,
        }),
    ))
}

async fn admin_update_user(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    AxumPath(target_id): AxumPath<String>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    user.require_admin()
        .map_err(|s| (s, "Admin role required".into()))?;

    let mut new_auth_hash = None;
    if let (Some(ref salt), Some(ref key_hex)) = (&req.salt_hex, &req.auth_key_hex) {
        if decode_hex_32(salt).is_none() {
            return Err((StatusCode::BAD_REQUEST, "Invalid salt_hex".into()));
        }
        let key = decode_hex_32(key_hex)
            .ok_or((StatusCode::BAD_REQUEST, "Invalid auth_key_hex".into()))?;
        new_auth_hash = Some(
            hash_auth_key(&key).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
        );
    }

    let db = state
        .db
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB lock".into()))?;
    let exists: Option<String> = db
        .query_row(
            "SELECT id FROM users WHERE id = ?1",
            params![target_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "User not found".into()));
    }

    if let Some(disabled) = req.disabled {
        db.execute(
            "UPDATE users SET disabled = ?1 WHERE id = ?2",
            params![if disabled { 1i64 } else { 0i64 }, target_id],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if disabled {
            let _ = db.execute(
                "DELETE FROM sessions WHERE user_id = ?1",
                params![target_id],
            );
        }
    }
    if let Some(role) = req.role {
        db.execute(
            "UPDATE users SET role = ?1 WHERE id = ?2",
            params![role.as_str(), target_id],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    if let (Some(salt), Some(auth_hash)) = (req.salt_hex, new_auth_hash) {
        db.execute(
            "UPDATE users SET salt = ?1, auth_hash = ?2 WHERE id = ?3",
            params![salt, auth_hash, target_id],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let _ = db.execute(
            "DELETE FROM sessions WHERE user_id = ?1",
            params![target_id],
        );
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn admin_delete_user(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    AxumPath(target_id): AxumPath<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    user.require_admin()
        .map_err(|s| (s, "Admin role required".into()))?;
    if target_id == user.user_id {
        return Err((StatusCode::BAD_REQUEST, "Cannot delete yourself".into()));
    }
    {
        let db = state
            .db
            .lock()
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB lock".into()))?;
        purge_user_db_rows(&db, &target_id)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    let user_chunk_dir = state.chunks_dir.join(&target_id);
    if user_chunk_dir.exists() {
        let _ = tokio::fs::remove_dir_all(&user_chunk_dir).await;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn register_device(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<RegisterDeviceRequest>,
) -> Result<StatusCode, StatusCode> {
    if req.device_id.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let db = state
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    db.execute(
        "INSERT INTO devices (user_id, device_id, encrypted_name, os, last_seen_ms, online)
         VALUES (?1, ?2, ?3, ?4, ?5, 1)
         ON CONFLICT(user_id, device_id) DO UPDATE SET
            encrypted_name = excluded.encrypted_name,
            os = excluded.os,
            last_seen_ms = excluded.last_seen_ms,
            online = 1",
        params![
            user.user_id,
            req.device_id.trim(),
            req.encrypted_name,
            req.os,
            now_ms()
        ],
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_devices(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Json<Vec<DeviceInfo>>, StatusCode> {
    let ws_online: HashSet<String> = {
        let map = state
            .ws_clients
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        map.keys()
            .filter(|(uid, _)| uid == &user.user_id)
            .map(|(_, did)| did.clone())
            .collect()
    };
    let db = state
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut stmt = db
        .prepare(
            "SELECT device_id, encrypted_name, os, last_seen_ms, online
             FROM devices WHERE user_id = ?1 ORDER BY last_seen_ms DESC",
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let rows = stmt
        .query_map(params![user.user_id], |r| {
            let device_id: String = r.get(0)?;
            let db_online: i64 = r.get(4)?;
            Ok(DeviceInfo {
                online: ws_online.contains(&device_id) || db_online != 0,
                device_id,
                encrypted_name: r.get(1)?,
                os: r.get(2)?,
                last_seen_ms: r.get(3)?,
            })
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut out = Vec::new();
    for item in rows {
        out.push(item.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?);
    }
    Ok(Json(out))
}

async fn delete_device(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    AxumPath(device_id): AxumPath<String>,
) -> Result<StatusCode, StatusCode> {
    let db = state
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    db.execute(
        "DELETE FROM sync_requests WHERE user_id = ?1 AND (source_device_id = ?2 OR target_device_id = ?2)",
        params![user.user_id, device_id],
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    db.execute(
        "DELETE FROM folder_manifests WHERE user_id = ?1 AND device_id = ?2",
        params![user.user_id, device_id],
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    db.execute(
        "DELETE FROM devices WHERE user_id = ?1 AND device_id = ?2",
        params![user.user_id, device_id],
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn replace_device(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    AxumPath(old_device_id): AxumPath<String>,
    Json(req): Json<ReplaceDeviceBody>,
) -> Result<StatusCode, StatusCode> {
    if req.new_device_id.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let db = state
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    db.execute(
        "UPDATE OR IGNORE folder_manifests SET device_id = ?1 WHERE user_id = ?2 AND device_id = ?3",
        params![req.new_device_id.trim(), user.user_id, old_device_id],
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    db.execute(
        "UPDATE sync_requests SET target_device_id = ?1 WHERE user_id = ?2 AND target_device_id = ?3",
        params![req.new_device_id.trim(), user.user_id, old_device_id],
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    db.execute(
        "DELETE FROM devices WHERE user_id = ?1 AND device_id = ?2",
        params![user.user_id, old_device_id],
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    db.execute(
        "INSERT INTO devices (user_id, device_id, encrypted_name, os, last_seen_ms, online)
         VALUES (?1, ?2, ?3, ?4, ?5, 1)
         ON CONFLICT(user_id, device_id) DO UPDATE SET
            encrypted_name = excluded.encrypted_name,
            os = excluded.os,
            last_seen_ms = excluded.last_seen_ms,
            online = 1",
        params![
            user.user_id,
            req.new_device_id.trim(),
            req.encrypted_name,
            req.os,
            now_ms()
        ],
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn put_manifest(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    AxumPath(folder_id): AxumPath<String>,
    Json(payload): Json<FolderManifestPayload>,
) -> Result<StatusCode, StatusCode> {
    if payload.device_id.trim().is_empty() || folder_id.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    {
        let db = state
            .db
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        db.execute(
            "INSERT INTO folder_manifests (user_id, device_id, folder_id, encrypted_meta_b64, version, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(user_id, device_id, folder_id) DO UPDATE SET
                encrypted_meta_b64 = excluded.encrypted_meta_b64,
                version = excluded.version,
                updated_at_ms = excluded.updated_at_ms",
            params![
                user.user_id,
                payload.device_id,
                folder_id,
                payload.encrypted_meta_b64,
                payload.version as i64,
                now_ms()
            ],
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    let dev_id = payload.device_id.clone();
    push_ws_to_user(
        &state,
        &user.user_id,
        Some(&dev_id),
        &WsSignal::ManifestUpdated {
            device_id: payload.device_id,
            folder_id,
            version: payload.version,
        },
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn list_manifests(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Query(q): Query<ManifestsQuery>,
) -> Result<Json<Vec<FolderManifestPayload>>, StatusCode> {
    let db = state
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut out = Vec::new();
    if let Some(ref did) = q.device_id {
        let mut stmt = db
            .prepare(
                "SELECT device_id, folder_id, encrypted_meta_b64, version, updated_at_ms
                 FROM folder_manifests WHERE user_id = ?1 AND device_id = ?2",
            )
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let rows = stmt
            .query_map(params![user.user_id, did], |r| {
                Ok(FolderManifestPayload {
                    device_id: r.get(0)?,
                    folder_id: r.get(1)?,
                    encrypted_meta_b64: r.get(2)?,
                    version: r.get::<_, i64>(3)? as u64,
                    updated_at_ms: r.get(4)?,
                })
            })
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        for item in rows {
            out.push(item.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?);
        }
    } else {
        let mut stmt = db
            .prepare(
                "SELECT device_id, folder_id, encrypted_meta_b64, version, updated_at_ms
                 FROM folder_manifests WHERE user_id = ?1",
            )
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let rows = stmt
            .query_map(params![user.user_id], |r| {
                Ok(FolderManifestPayload {
                    device_id: r.get(0)?,
                    folder_id: r.get(1)?,
                    encrypted_meta_b64: r.get(2)?,
                    version: r.get::<_, i64>(3)? as u64,
                    updated_at_ms: r.get(4)?,
                })
            })
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        for item in rows {
            out.push(item.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?);
        }
    }
    Ok(Json(out))
}

async fn delete_manifest(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    AxumPath(folder_id): AxumPath<String>,
    Query(q): Query<ManifestsQuery>,
) -> Result<StatusCode, StatusCode> {
    let Some(did) = q.device_id else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let db = state
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    db.execute(
        "DELETE FROM folder_manifests WHERE user_id = ?1 AND device_id = ?2 AND folder_id = ?3",
        params![user.user_id, did, folder_id],
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn create_sync_request(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<SyncRequestPayload>,
) -> Result<(StatusCode, Json<PendingSyncRequest>), StatusCode> {
    let hashes_json =
        serde_json::to_string(&req.chunk_hashes).map_err(|_| StatusCode::BAD_REQUEST)?;
    let now = now_ms();
    let id = {
        let db = state
            .db
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        db.execute(
            "INSERT INTO sync_requests (user_id, source_device_id, target_device_id, folder_id, chunk_hashes_json, status, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6)",
            params![
                user.user_id,
                req.source_device_id,
                req.target_device_id,
                req.folder_id,
                hashes_json,
                now
            ],
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        db.last_insert_rowid()
    };

    push_ws_to_device(
        &state,
        &user.user_id,
        &req.source_device_id,
        &WsSignal::SyncRequest {
            request_id: id,
            folder_id: req.folder_id.clone(),
            target_device_id: req.target_device_id.clone(),
            chunk_hashes: req.chunk_hashes.clone(),
        },
    );

    Ok((
        StatusCode::ACCEPTED,
        Json(PendingSyncRequest {
            id,
            source_device_id: req.source_device_id,
            target_device_id: req.target_device_id,
            folder_id: req.folder_id,
            chunk_hashes: req.chunk_hashes,
            status: "pending".to_string(),
            created_at_ms: now,
        }),
    ))
}

async fn list_sync_requests(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Query(q): Query<SyncRequestsQuery>,
) -> Result<Json<Vec<PendingSyncRequest>>, StatusCode> {
    let db = state
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut stmt = db
        .prepare(
            "SELECT id, source_device_id, target_device_id, folder_id, chunk_hashes_json, status, created_at_ms
             FROM sync_requests
             WHERE user_id = ?1 AND source_device_id = ?2 AND status = 'pending'
             ORDER BY id ASC",
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let rows = stmt
        .query_map(params![user.user_id, q.source_device_id], |r| {
            let hashes_json: String = r.get(4)?;
            let chunk_hashes: Vec<String> = serde_json::from_str(&hashes_json).unwrap_or_default();
            Ok(PendingSyncRequest {
                id: r.get(0)?,
                source_device_id: r.get(1)?,
                target_device_id: r.get(2)?,
                folder_id: r.get(3)?,
                chunk_hashes,
                status: r.get(5)?,
                created_at_ms: r.get(6)?,
            })
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut out = Vec::new();
    for item in rows {
        out.push(item.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?);
    }
    Ok(Json(out))
}

async fn fulfill_sync_request(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    AxumPath(req_id): AxumPath<i64>,
) -> Result<StatusCode, StatusCode> {
    let db = state
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    db.execute(
        "DELETE FROM sync_requests WHERE id = ?1 AND user_id = ?2",
        params![req_id, user.user_id],
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn put_user_chunk(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    AxumPath(chunk_id): AxumPath<String>,
    Query(q): Query<ChunkPutQuery>,
    body: Bytes,
) -> Result<StatusCode, (StatusCode, String)> {
    if !is_valid_chunk_id(&chunk_id) {
        return Err((StatusCode::BAD_REQUEST, "Invalid chunk_id".into()));
    }
    if body.len() > MAX_CHUNK_HTTP_BYTES {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "Chunk exceeds 16 MiB limit".into(),
        ));
    }

    let user_dir = state.chunks_dir.join(&user.user_id);
    if let Err(e) = tokio::fs::create_dir_all(&user_dir).await {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
    }
    let chunk_path = user_dir.join(format!("{chunk_id}.chk"));
    let tmp_path = user_dir.join(format!("{chunk_id}.{}.tmp", Uuid::new_v4()));
    if let Err(e) = tokio::fs::write(&tmp_path, &body).await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
    }
    if let Err(e) = tokio::fs::rename(&tmp_path, &chunk_path).await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
    }

    let pending: Vec<String> = q
        .pending_peers
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    let pending_json = serde_json::to_string(&pending).unwrap_or_else(|_| "[]".to_string());
    let now = now_ms();

    {
        let db = state
            .db
            .lock()
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB lock".into()))?;
        db.execute(
            "INSERT INTO user_chunks (user_id, chunk_id, size_bytes, pending_peers_json, created_at_ms, last_accessed_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)
             ON CONFLICT(user_id, chunk_id) DO UPDATE SET
                size_bytes = excluded.size_bytes,
                pending_peers_json = excluded.pending_peers_json,
                last_accessed_ms = excluded.last_accessed_ms",
            params![user.user_id, chunk_id, body.len() as i64, pending_json, now],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    evict_lru_user_chunks(&state.db, &state.chunks_dir, state.max_bytes);
    for peer_id in &pending {
        push_ws_to_device(
            &state,
            &user.user_id,
            peer_id,
            &WsSignal::ChunkAvailable {
                folder_id: String::new(),
                chunk_id: chunk_id.clone(),
            },
        );
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn get_user_chunk(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    AxumPath(chunk_id): AxumPath<String>,
) -> Result<impl IntoResponse, StatusCode> {
    if !is_valid_chunk_id(&chunk_id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let chunk_path = state
        .chunks_dir
        .join(&user.user_id)
        .join(format!("{chunk_id}.chk"));
    let data = tokio::fs::read(&chunk_path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    if let Ok(db) = state.db.lock() {
        let _ = db.execute(
            "UPDATE user_chunks SET last_accessed_ms = ?1 WHERE user_id = ?2 AND chunk_id = ?3",
            params![now_ms(), user.user_id, chunk_id],
        );
    }
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        data,
    ))
}

async fn ack_user_chunks(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<ChunkAckRequest>,
) -> Result<StatusCode, StatusCode> {
    let mut to_delete = Vec::new();
    {
        let db = state
            .db
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        for cid in &req.chunk_ids {
            let row: Option<String> = db
                .query_row(
                    "SELECT pending_peers_json FROM user_chunks WHERE user_id = ?1 AND chunk_id = ?2",
                    params![user.user_id, cid],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            let Some(pending_json) = row else {
                continue;
            };
            let mut peers: Vec<String> = serde_json::from_str(&pending_json).unwrap_or_default();
            peers.retain(|p| p != &req.device_id);
            if peers.is_empty() {
                db.execute(
                    "DELETE FROM user_chunks WHERE user_id = ?1 AND chunk_id = ?2",
                    params![user.user_id, cid],
                )
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                to_delete.push(cid.clone());
            } else {
                let updated = serde_json::to_string(&peers).unwrap_or_else(|_| "[]".to_string());
                db.execute(
                    "UPDATE user_chunks SET pending_peers_json = ?1 WHERE user_id = ?2 AND chunk_id = ?3",
                    params![updated, user.user_id, cid],
                )
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            }
        }
    }
    for cid in to_delete {
        let _ = tokio::fs::remove_file(
            state
                .chunks_dir
                .join(&user.user_id)
                .join(format!("{cid}.chk")),
        )
        .await;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn get_cache_status(
    State(state): State<AppState>,
    Extension(_user): Extension<AuthUser>,
) -> Result<Json<RelayCacheStatus>, StatusCode> {
    let db = state
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let (chunk_count, used_bytes) =
        user_chunks_usage(&db).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(RelayCacheStatus {
        used_bytes,
        max_bytes: state.max_bytes,
        chunk_count,
        ttl_hours: state.blob_ttl_secs / 3600,
    }))
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Query(q): Query<WsQuery>,
) -> impl IntoResponse {
    let device_id = q.device_id.trim().to_string();
    ws.on_upgrade(move |socket| handle_ws(socket, state, user.user_id, device_id))
}

async fn handle_ws(mut socket: WebSocket, state: AppState, user_id: String, device_id: String) {
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    {
        if let Ok(mut map) = state.ws_clients.lock() {
            map.insert((user_id.clone(), device_id.clone()), tx);
        }
        if let Ok(db) = state.db.lock() {
            let _ = db.execute(
                "UPDATE devices SET online = 1, last_seen_ms = ?1 WHERE user_id = ?2 AND device_id = ?3",
                params![now_ms(), user_id, device_id],
            );
        }
    }

    loop {
        tokio::select! {
            Some(msg) = rx.recv() => {
                if socket.send(Message::Text(msg)).await.is_err() {
                    break;
                }
            }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Ping(p))) => {
                        let _ = socket.send(Message::Pong(p)).await;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    _ => {}
                }
            }
        }
    }

    if let Ok(mut map) = state.ws_clients.lock() {
        map.remove(&(user_id.clone(), device_id.clone()));
    }
    if let Ok(db) = state.db.lock() {
        let _ = db.execute(
            "UPDATE devices SET online = 0, last_seen_ms = ?1 WHERE user_id = ?2 AND device_id = ?3",
            params![now_ms(), user_id, device_id],
        );
    }
}

fn push_ws_to_device(state: &AppState, user_id: &str, device_id: &str, signal: &WsSignal) {
    let Ok(json) = serde_json::to_string(signal) else {
        return;
    };
    if let Ok(map) = state.ws_clients.lock() {
        if let Some(tx) = map.get(&(user_id.to_string(), device_id.to_string())) {
            let _ = tx.send(json);
        }
    }
}

fn push_ws_to_user(
    state: &AppState,
    user_id: &str,
    exclude_device: Option<&str>,
    signal: &WsSignal,
) {
    let Ok(json) = serde_json::to_string(signal) else {
        return;
    };
    if let Ok(map) = state.ws_clients.lock() {
        for ((uid, did), tx) in map.iter() {
            if uid == user_id && exclude_device != Some(did.as_str()) {
                let _ = tx.send(json.clone());
            }
        }
    }
}
