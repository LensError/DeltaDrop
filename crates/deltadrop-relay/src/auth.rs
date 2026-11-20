use std::net::IpAddr;
use std::time::{Duration, Instant};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use deltadrop_common::{
    constant_time_eq_blake3, decode_hex_32, derive_auth_and_vault_keys, encode_hex,
    verify_peer_token, UserRole, GATE_HEADER,
};
use rand::RngCore;
use rusqlite::{params, OptionalExtension};

use crate::storage::now_ms;
use crate::AppState;

#[derive(Clone, Debug)]
pub struct AuthPeer(pub Option<String>);

#[derive(Clone, Debug)]
pub struct AuthUser {
    pub user_id: String,
    #[allow(dead_code)]
    pub username: String,
    pub role: UserRole,
}

impl AuthUser {
    pub fn require_admin(&self) -> Result<(), StatusCode> {
        if self.role != UserRole::Admin {
            return Err(StatusCode::FORBIDDEN);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct RateLimitEntry {
    pub failures: u32,
    pub blocked_until: Option<Instant>,
    pub window_start: Instant,
    pub requests_in_window: u32,
}

impl AuthPeer {
    pub fn require_matches(&self, peer: &str) -> Result<(), StatusCode> {
        if let Some(ref scoped) = self.0 {
            if scoped != peer {
                return Err(StatusCode::FORBIDDEN);
            }
        }
        Ok(())
    }
}

pub fn hash_session_token(token: &str) -> String {
    blake3::hash(token.as_bytes()).to_hex().to_string()
}

pub fn hash_auth_key(auth_key_bytes: &[u8]) -> anyhow::Result<String> {
    let mut salt_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|e| anyhow::anyhow!("Salt encode failed: {e}"))?;
    let hash = Argon2::default()
        .hash_password(auth_key_bytes, &salt)
        .map_err(|e| anyhow::anyhow!("Argon2id hash failed: {e}"))?;
    Ok(hash.to_string())
}

pub fn verify_auth_key(auth_key_bytes: &[u8], phc_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(auth_key_bytes, &parsed)
        .is_ok()
}

/// Derives `auth_key` from plaintext `(password, salt_hex)` using the exact same
/// Argon2id + BLAKE3 domain separation as `deltadrop-client`, for CLI user creation.
pub fn derive_auth_key_for_cli(password: &str, salt_hex: &str) -> anyhow::Result<[u8; 32]> {
    let salt =
        decode_hex_32(salt_hex).ok_or_else(|| anyhow::anyhow!("Invalid 32-byte salt hex"))?;
    let mut master = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), &salt[..16], &mut master)
        .map_err(|e| anyhow::anyhow!("Argon2id derivation failed: {e}"))?;
    let (auth_key, _) = derive_auth_and_vault_keys(&master);
    Ok(auth_key)
}

pub fn generate_random_hex_32() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    encode_hex(&bytes)
}

pub async fn gate_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if let Some(ref expected) = state.network_secret {
        if !expected.is_empty() {
            let provided = req
                .headers()
                .get(GATE_HEADER)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !constant_time_eq_blake3(provided.as_bytes(), expected.as_bytes()) {
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
    }
    Ok(next.run(req).await)
}

fn extract_client_ip(headers: &HeaderMap, req_ext: &axum::http::Extensions) -> IpAddr {
    if let Some(fwd) = headers
        .get("cf-connecting-ip")
        .or_else(|| headers.get("x-forwarded-for"))
        .and_then(|v| v.to_str().ok())
    {
        if let Some(first) = fwd.split(',').next() {
            if let Ok(ip) = first.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }
    req_ext
        .get::<ConnectInfo<SocketAddrWrapper>>()
        .map(|c| c.0 .0)
        .unwrap_or(IpAddr::from([127, 0, 0, 1]))
}

#[derive(Clone, Copy, Debug)]
pub struct SocketAddrWrapper(pub IpAddr);

pub async fn auth_rate_limit_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let ip = extract_client_ip(req.headers(), req.extensions());
    let now = Instant::now();
    {
        let mut map = state
            .auth_rate_limits
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let entry = map.entry(ip).or_insert(RateLimitEntry {
            failures: 0,
            blocked_until: None,
            window_start: now,
            requests_in_window: 0,
        });
        if let Some(until) = entry.blocked_until {
            if now < until {
                let retry_secs = (until - now).as_secs().max(1);
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    [("Retry-After", retry_secs.to_string())],
                    "Too many auth attempts",
                )
                    .into_response();
            }
        }
        if now.duration_since(entry.window_start) >= Duration::from_secs(60) {
            entry.window_start = now;
            entry.requests_in_window = 0;
        }
        entry.requests_in_window += 1;
        if entry.requests_in_window > 30 {
            entry.blocked_until = Some(now + Duration::from_secs(60));
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [("Retry-After", "60".to_string())],
                "Rate limit exceeded",
            )
                .into_response();
        }
    }

    let resp = next.run(req).await;
    if resp.status() == StatusCode::UNAUTHORIZED || resp.status() == StatusCode::FORBIDDEN {
        let mut map = state
            .auth_rate_limits
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = map.get_mut(&ip) {
            entry.failures = entry.failures.saturating_add(1);
            if entry.failures >= 3 {
                let shift = (entry.failures - 3).min(8);
                let backoff_secs = (2u64 << shift).min(300);
                entry.blocked_until = Some(Instant::now() + Duration::from_secs(backoff_secs));
            }
        }
    } else if resp.status().is_success() {
        let mut map = state
            .auth_rate_limits
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        map.remove(&ip);
    }
    resp
}

pub async fn session_auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let token = header
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let token_hash = hash_session_token(token);
    let now = now_ms();

    let auth_user = {
        let db = state
            .db
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        db.query_row(
            "SELECT u.id, u.username, u.role, u.disabled, s.expires_at_ms
             FROM sessions s
             JOIN users u ON u.id = s.user_id
             WHERE s.token_hash = ?1",
            params![token_hash],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    };

    let Some((user_id, username, role_str, disabled, expires_at_ms)) = auth_user else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    if disabled != 0 || expires_at_ms <= now {
        return Err(StatusCode::UNAUTHORIZED);
    }

    req.extensions_mut().insert(AuthUser {
        user_id,
        username,
        role: UserRole::from_db(&role_str),
    });
    Ok(next.run(req).await)
}

pub async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let Some(header) = auth_header else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    let Some(token) = header.strip_prefix("Bearer ") else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    let auth_peer = if !state.auth_token.is_empty()
        && constant_time_eq_blake3(token.as_bytes(), state.auth_token.as_bytes())
    {
        AuthPeer(None)
    } else if !state.auth_token.is_empty() {
        if let Some(peer_id) = verify_peer_token(&state.auth_token, token) {
            AuthPeer(Some(peer_id))
        } else if validate_session_token(&state, token)? {
            AuthPeer(None)
        } else {
            return Err(StatusCode::UNAUTHORIZED);
        }
    } else if validate_session_token(&state, token)? {
        AuthPeer(None)
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    req.extensions_mut().insert(auth_peer);
    Ok(next.run(req).await)
}

fn validate_session_token(state: &AppState, token: &str) -> Result<bool, StatusCode> {
    let token_hash = hash_session_token(token);
    let now = now_ms();
    let db = state.db.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let row = db
        .query_row(
            "SELECT u.disabled, s.expires_at_ms
             FROM sessions s
             JOIN users u ON u.id = s.user_id
             WHERE s.token_hash = ?1",
            params![token_hash],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(matches!(row, Some((disabled, exp)) if disabled == 0 && exp > now))
}
