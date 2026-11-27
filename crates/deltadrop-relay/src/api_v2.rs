use std::collections::{HashMap, HashSet};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post, put};
use axum::{Extension, Json, Router};
use deltadrop_common::{
    decode_hex_32, is_valid_chunk_id, is_valid_share_id, AdminUserInfo, AuthParamsResponse,
    CreateUserRequest, DeviceInfo, HasChunksRequest, HasChunksResponse, LoginRequest,
    LoginResponse, PendingReseed, PutShareRequest, PutShareResponse, RelayCacheStatus,
    ReplaceDeviceRequest, ReseedRequest, ShareRecord, UpdateUserRequest, UserRole, WsClientMsg,
    WsServerMsg, MAX_CHUNK_HTTP_BYTES, MAX_MANIFEST_HTTP_BYTES,
};
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::auth::{
    auth_rate_limit_middleware, check_network_gate, gate_middleware, generate_random_hex_32,
    hash_auth_key, hash_session_token, lookup_session_user, session_auth_middleware,
    verify_auth_key, AuthUser,
};
use crate::db::{purge_user_db_rows, user_chunks_usage};
use crate::storage::{evict_lru_user_chunks, now_ms};
use crate::AppState;

const SESSION_TTL_MS: i64 = 30 * 24 * 3600 * 1000;

#[derive(Deserialize)]
pub struct AuthParamsQuery {
    pub username: String,
}

pub fn build_api_v2_router(state: AppState) -> Router<AppState> {
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
        .route("/devices", get(list_devices))
        .route("/devices/:device_id", delete(delete_device))
        .route("/devices/:device_id/replace", post(replace_device))
        .route("/shares", get(list_shares))
        .route(
            "/shares/:share_id",
            get(get_share)
                .put(put_share)
                .delete(delete_share)
                .layer(DefaultBodyLimit::max(MAX_MANIFEST_HTTP_BYTES)),
        )
        .route("/shares/:share_id/reseed", post(post_reseed_request))
        .route("/reseed-requests", get(list_reseed_requests))
        .route("/chunks/has", post(post_chunks_has))
        .route(
            "/chunks/:chunk_id",
            put(put_user_chunk)
                .get(get_user_chunk)
                .layer(DefaultBodyLimit::max(MAX_CHUNK_HTTP_BYTES)),
        )
        .route("/cache/status", get(get_cache_status))
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            session_auth_middleware,
        ));

    let gated_http = auth_routes
        .merge(protected_routes)
        .layer(middleware::from_fn_with_state(state, gate_middleware));

    // WebSocket authenticates via its first JSON frame (token + optional gate) so secrets never appear in URLs.
    let ws_route = Router::new().route("/ws", get(ws_handler));

    Router::new().nest("/api/v2", gated_http.merge(ws_route))
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
                last_seen_ms = excluded.last_seen_ms,
                online = 1",
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
            "SELECT device_id, encrypted_name, os, last_seen_ms
             FROM devices WHERE user_id = ?1 ORDER BY last_seen_ms DESC",
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let rows = stmt
        .query_map(params![user.user_id], |r| {
            let device_id: String = r.get(0)?;
            Ok(DeviceInfo {
                online: ws_online.contains(&device_id),
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
        "DELETE FROM sessions WHERE user_id = ?1 AND device_id = ?2",
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
    Json(req): Json<ReplaceDeviceRequest>,
) -> Result<StatusCode, StatusCode> {
    let new_id = req.new_device_id.trim();
    if new_id.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let db = state
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    db.execute(
        "UPDATE shares SET owner_device_id = ?1 WHERE user_id = ?2 AND owner_device_id = ?3",
        params![new_id, user.user_id, old_device_id],
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
        params![user.user_id, new_id, req.encrypted_name, req.os, now_ms()],
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_shares(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Json<Vec<ShareRecord>>, StatusCode> {
    let db = state
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut stmt = db
        .prepare(
            "SELECT share_id, owner_device_id, last_writer_device_id, version, encrypted_manifest_b64, updated_at_ms
             FROM shares WHERE user_id = ?1 ORDER BY updated_at_ms DESC",
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let rows = stmt
        .query_map(params![user.user_id], |r| {
            Ok(ShareRecord {
                share_id: r.get(0)?,
                owner_device_id: r.get(1)?,
                last_writer_device_id: r.get(2)?,
                version: r.get::<_, i64>(3)? as u64,
                encrypted_manifest_b64: r.get(4)?,
                updated_at_ms: r.get(5)?,
            })
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut out = Vec::new();
    for item in rows {
        out.push(item.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?);
    }
    Ok(Json(out))
}

async fn get_share(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    AxumPath(share_id): AxumPath<String>,
) -> Result<Json<ShareRecord>, StatusCode> {
    if !is_valid_share_id(&share_id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let db = state
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let row: Option<ShareRecord> = db
        .query_row(
            "SELECT share_id, owner_device_id, last_writer_device_id, version, encrypted_manifest_b64, updated_at_ms
             FROM shares WHERE user_id = ?1 AND share_id = ?2",
            params![user.user_id, share_id],
            |r| {
                Ok(ShareRecord {
                    share_id: r.get(0)?,
                    owner_device_id: r.get(1)?,
                    last_writer_device_id: r.get(2)?,
                    version: r.get::<_, i64>(3)? as u64,
                    encrypted_manifest_b64: r.get(4)?,
                    updated_at_ms: r.get(5)?,
                })
            },
        )
        .optional()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let Some(record) = row else {
        return Err(StatusCode::NOT_FOUND);
    };
    Ok(Json(record))
}

async fn put_share(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    AxumPath(share_id): AxumPath<String>,
    Json(req): Json<PutShareRequest>,
) -> Response {
    if !is_valid_share_id(&share_id) || req.device_id.trim().is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let now = now_ms();
    let result: Result<PutShareResponse, Box<Response>> = (|| {
        let mut db = state
            .db
            .lock()
            .map_err(|_| Box::new(StatusCode::INTERNAL_SERVER_ERROR.into_response()))?;
        let tx = db
            .transaction()
            .map_err(|_| Box::new(StatusCode::INTERNAL_SERVER_ERROR.into_response()))?;

        let existing: Option<ShareRecord> = tx
            .query_row(
                "SELECT share_id, owner_device_id, last_writer_device_id, version, encrypted_manifest_b64, updated_at_ms
                 FROM shares WHERE user_id = ?1 AND share_id = ?2",
                params![user.user_id, share_id],
                |r| {
                    Ok(ShareRecord {
                        share_id: r.get(0)?,
                        owner_device_id: r.get(1)?,
                        last_writer_device_id: r.get(2)?,
                        version: r.get::<_, i64>(3)? as u64,
                        encrypted_manifest_b64: r.get(4)?,
                        updated_at_ms: r.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(|_| Box::new(StatusCode::INTERNAL_SERVER_ERROR.into_response()))?;

        let new_version = match existing {
            None => {
                if req.base_version != 0 {
                    return Err(Box::new(StatusCode::CONFLICT.into_response()));
                }
                let owner = if req.owner_device_id.trim().is_empty() {
                    req.device_id.trim()
                } else {
                    req.owner_device_id.trim()
                };
                tx.execute(
                    "INSERT INTO shares (user_id, share_id, owner_device_id, last_writer_device_id, version, encrypted_manifest_b64, updated_at_ms)
                     VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6)",
                    params![
                        user.user_id,
                        share_id,
                        owner,
                        req.device_id.trim(),
                        req.encrypted_manifest_b64,
                        now
                    ],
                )
                .map_err(|_| Box::new(StatusCode::INTERNAL_SERVER_ERROR.into_response()))?;
                1u64
            }
            Some(cur) => {
                if req.base_version != cur.version {
                    return Err(Box::new((StatusCode::CONFLICT, Json(cur)).into_response()));
                }
                let next_ver = cur.version + 1;
                tx.execute(
                    "UPDATE shares
                     SET last_writer_device_id = ?1, version = ?2, encrypted_manifest_b64 = ?3, updated_at_ms = ?4
                     WHERE user_id = ?5 AND share_id = ?6",
                    params![
                        req.device_id.trim(),
                        next_ver as i64,
                        req.encrypted_manifest_b64,
                        now,
                        user.user_id,
                        share_id
                    ],
                )
                .map_err(|_| Box::new(StatusCode::INTERNAL_SERVER_ERROR.into_response()))?;
                next_ver
            }
        };

        tx.commit()
            .map_err(|_| Box::new(StatusCode::INTERNAL_SERVER_ERROR.into_response()))?;
        Ok(PutShareResponse {
            version: new_version,
            updated_at_ms: now,
        })
    })();

    match result {
        Ok(resp) => {
            let writer_id = req.device_id.trim().to_string();
            push_ws_to_user(
                &state,
                &user.user_id,
                Some(&writer_id),
                &WsServerMsg::ShareUpdated {
                    share_id,
                    version: resp.version,
                    writer_device_id: writer_id.clone(),
                },
            );
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(err_resp) => *err_resp,
    }
}

async fn delete_share(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    AxumPath(share_id): AxumPath<String>,
) -> Result<StatusCode, StatusCode> {
    if !is_valid_share_id(&share_id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    {
        let db = state
            .db
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        db.execute(
            "DELETE FROM shares WHERE user_id = ?1 AND share_id = ?2",
            params![user.user_id, share_id],
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        db.execute(
            "DELETE FROM reseed_requests WHERE user_id = ?1 AND share_id = ?2",
            params![user.user_id, share_id],
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    push_ws_to_user(
        &state,
        &user.user_id,
        None,
        &WsServerMsg::ShareDeleted { share_id },
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn post_reseed_request(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    AxumPath(share_id): AxumPath<String>,
    Json(req): Json<ReseedRequest>,
) -> Result<StatusCode, StatusCode> {
    if !is_valid_share_id(&share_id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let valid_ids: Vec<String> = req
        .chunk_ids
        .into_iter()
        .filter(|cid| is_valid_chunk_id(cid))
        .collect();
    if valid_ids.is_empty() {
        return Ok(StatusCode::NO_CONTENT);
    }
    let now = now_ms();
    {
        let db = state
            .db
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        for cid in &valid_ids {
            let _ = db.execute(
                "INSERT OR REPLACE INTO reseed_requests (user_id, share_id, chunk_id, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4)",
                params![user.user_id, share_id, cid, now],
            );
        }
    }
    push_ws_to_user(
        &state,
        &user.user_id,
        Some(req.requester_device_id.trim()),
        &WsServerMsg::ReseedRequested {
            share_id,
            chunk_ids: valid_ids,
        },
    );
    Ok(StatusCode::ACCEPTED)
}

async fn list_reseed_requests(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Json<Vec<PendingReseed>>, StatusCode> {
    let db = state
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut stmt = db
        .prepare("SELECT share_id, chunk_id FROM reseed_requests WHERE user_id = ?1")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let rows = stmt
        .query_map(params![user.user_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut grouped: HashMap<String, Vec<String>> = HashMap::new();
    for item in rows {
        let (sid, cid) = item.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        grouped.entry(sid).or_default().push(cid);
    }
    let out = grouped
        .into_iter()
        .map(|(share_id, chunk_ids)| PendingReseed {
            share_id,
            chunk_ids,
        })
        .collect();
    Ok(Json(out))
}

async fn post_chunks_has(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<HasChunksRequest>,
) -> Result<Json<HasChunksResponse>, StatusCode> {
    let mut missing = Vec::new();
    let user_dir = state.chunks_dir.join(&user.user_id);
    let now = now_ms();
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
                "SELECT 1 FROM user_chunks WHERE user_id = ?1 AND chunk_id = ?2",
                params![user.user_id, cid],
                |_| Ok(true),
            )
            .optional()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .unwrap_or(false);
        if exists_db && user_dir.join(format!("{cid}.chk")).exists() {
            let _ = db.execute(
                "UPDATE user_chunks SET last_accessed_ms = ?1 WHERE user_id = ?2 AND chunk_id = ?3",
                params![now, user.user_id, cid],
            );
        } else {
            missing.push(cid);
        }
    }
    Ok(Json(HasChunksResponse { missing }))
}

async fn put_user_chunk(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    AxumPath(chunk_id): AxumPath<String>,
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

    let now = now_ms();
    {
        let db = state
            .db
            .lock()
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB lock".into()))?;
        db.execute(
            "INSERT INTO user_chunks (user_id, chunk_id, size_bytes, created_at_ms, last_accessed_ms)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(user_id, chunk_id) DO UPDATE SET
                size_bytes = excluded.size_bytes,
                last_accessed_ms = excluded.last_accessed_ms",
            params![user.user_id, chunk_id, body.len() as i64, now],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let _ = db.execute(
            "DELETE FROM reseed_requests WHERE user_id = ?1 AND chunk_id = ?2",
            params![user.user_id, chunk_id],
        );
    }

    evict_lru_user_chunks(&state.db, &state.chunks_dir, state.max_bytes);
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

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

async fn handle_ws(mut socket: WebSocket, state: AppState) {
    let auth_frame = tokio::time::timeout(Duration::from_secs(10), socket.recv()).await;
    let Ok(Some(Ok(Message::Text(text)))) = auth_frame else {
        return;
    };
    let Ok(WsClientMsg::Auth {
        token,
        device_id,
        gate,
    }) = serde_json::from_str::<WsClientMsg>(&text)
    else {
        let _ = send_ws(&mut socket, &WsServerMsg::AuthError {
            message: "Expected auth message".into(),
        })
        .await;
        return;
    };
    if !check_network_gate(state.network_secret.as_deref(), gate.as_deref()) {
        let _ = send_ws(&mut socket, &WsServerMsg::AuthError {
            message: "Invalid network gate".into(),
        })
        .await;
        return;
    }
    let device_id = device_id.trim().to_string();
    if device_id.is_empty() {
        let _ = send_ws(&mut socket, &WsServerMsg::AuthError {
            message: "Empty device_id".into(),
        })
        .await;
        return;
    }
    let Ok(Some(user)) = lookup_session_user(&state, &token) else {
        let _ = send_ws(&mut socket, &WsServerMsg::AuthError {
            message: "Unauthorized".into(),
        })
        .await;
        return;
    };
    if send_ws(&mut socket, &WsServerMsg::AuthOk).await.is_err() {
        return;
    }

    let user_id = user.user_id;
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
    push_ws_to_user(
        &state,
        &user_id,
        Some(&device_id),
        &WsServerMsg::DeviceStatus {
            device_id: device_id.clone(),
            online: true,
        },
    );

    loop {
        tokio::select! {
            Some(msg) = rx.recv() => {
                if socket.send(Message::Text(msg)).await.is_err() {
                    break;
                }
            }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Text(txt))) => {
                        if let Ok(WsClientMsg::Ping) = serde_json::from_str::<WsClientMsg>(&txt) {
                            let _ = send_ws(&mut socket, &WsServerMsg::Pong).await;
                        }
                    }
                    Some(Ok(Message::Ping(p))) => {
                        let _ = socket.send(Message::Pong(p)).await;
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
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
    push_ws_to_user(
        &state,
        &user_id,
        Some(&device_id),
        &WsServerMsg::DeviceStatus {
            device_id: device_id.clone(),
            online: false,
        },
    );
}

async fn send_ws(socket: &mut WebSocket, msg: &WsServerMsg) -> Result<(), axum::Error> {
    if let Ok(json) = serde_json::to_string(msg) {
        socket.send(Message::Text(json)).await?;
    }
    Ok(())
}

fn push_ws_to_user(
    state: &AppState,
    user_id: &str,
    exclude_device: Option<&str>,
    signal: &WsServerMsg,
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
