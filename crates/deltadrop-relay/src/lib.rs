mod api_v2;
mod auth;
mod db;
mod storage;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use deltadrop_common::{PROTOCOL_HEADER, PROTOCOL_VERSION};
use rusqlite::{params, Connection};
use tokio::sync::{mpsc, Semaphore};
use tracing::info;
use uuid::Uuid;

use auth::{derive_auth_key_for_cli, generate_random_hex_32, hash_auth_key, RateLimitEntry};
pub use db::init_db;
pub use storage::{evict_lru_user_chunks, gc_expired_user_chunks};
use storage::now_ms;

pub type WsClientMap = Arc<Mutex<HashMap<(String, String), mpsc::UnboundedSender<String>>>>;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Mutex<Connection>>,
    pub chunks_dir: PathBuf,
    pub network_secret: Option<String>,
    pub max_bytes: u64,
    pub blob_ttl_secs: u64,
    pub concurrency: Arc<Semaphore>,
    pub auth_rate_limits: Arc<Mutex<HashMap<IpAddr, RateLimitEntry>>>,
    pub ws_clients: WsClientMap,
}

impl AppState {
    pub fn new(db: Connection, data_dir: PathBuf, max_bytes: u64) -> Self {
        let chunks_dir = data_dir.join("chunks");
        let _ = std::fs::create_dir_all(&chunks_dir);
        Self {
            db: Arc::new(Mutex::new(db)),
            chunks_dir,
            network_secret: None,
            max_bytes,
            blob_ttl_secs: 72 * 3600,
            concurrency: Arc::new(Semaphore::new(64)),
            auth_rate_limits: Arc::new(Mutex::new(HashMap::new())),
            ws_clients: Arc::new(Mutex::new(HashMap::new())),
        }
    }
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
    let is_ws = req
        .headers()
        .get(axum::http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    if is_ws {
        return Ok(next.run(req).await);
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

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .merge(api_v2::build_api_v2_router(state.clone()))
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

pub fn seed_user_in_db(
    conn: &Connection,
    username: &str,
    password: &str,
    is_admin: bool,
) -> anyhow::Result<String> {
    let salt_hex = generate_random_hex_32();
    let auth_key = derive_auth_key_for_cli(password, &salt_hex)?;
    let auth_hash = hash_auth_key(&auth_key)?;
    let role = if is_admin { "admin" } else { "user" };
    let id = Uuid::new_v4().to_string();
    let now = now_ms();
    conn.execute(
        "INSERT INTO users (id, username, role, salt, auth_hash, disabled, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)",
        params![id, username, role, salt_hex, auth_hash, now],
    )?;
    Ok(id)
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
    let id = seed_user_in_db(&conn, &username, &password, is_admin)?;
    let role = if is_admin { "admin" } else { "user" };
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
    let conn = init_db(&data_dir.join("relay.db"))?;

    let mut state = AppState::new(conn, data_dir, max_bytes);
    state.blob_ttl_secs = blob_ttl_secs;
    state.network_secret = network_secret;

    gc_expired_user_chunks(&state.db, &state.chunks_dir, state.blob_ttl_secs);
    evict_lru_user_chunks(&state.db, &state.chunks_dir, state.max_bytes);

    let gc_db = state.db.clone();
    let gc_chunks_dir = state.chunks_dir.clone();
    let gc_ttl = state.blob_ttl_secs;
    let gc_max = state.max_bytes;
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(300));
        tick.tick().await;
        loop {
            tick.tick().await;
            gc_expired_user_chunks(&gc_db, &gc_chunks_dir, gc_ttl);
            evict_lru_user_chunks(&gc_db, &gc_chunks_dir, gc_max);
        }
    });

    let app = build_router(state);
    info!(
        "deltadrop-relay v{} listening on {bind_addr} (max_bytes={max_bytes}, ttl_secs={blob_ttl_secs})",
        env!("CARGO_PKG_VERSION")
    );
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
    use deltadrop_common::{
        AdminUserInfo, AuthParamsResponse, CreateUserRequest, HasChunksRequest, HasChunksResponse,
        LoginRequest, LoginResponse, PutShareRequest, PutShareResponse, ShareRecord, UserRole,
        GATE_HEADER,
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn test_state(max_bytes: u64) -> (tempfile::TempDir, AppState) {
        let dir = tempfile::tempdir().unwrap();
        let conn = init_db(&dir.path().join("relay.db")).unwrap();
        let state = AppState::new(conn, dir.path().to_path_buf(), max_bytes);
        (dir, state)
    }

    fn client_derive(password: &str, salt_hex: &str) -> ([u8; 32], [u8; 32]) {
        let salt = deltadrop_common::decode_hex_32(salt_hex).unwrap();
        let mut master = [0u8; 32];
        argon2::Argon2::default()
            .hash_password_into(password.as_bytes(), &salt[..16], &mut master)
            .unwrap();
        deltadrop_common::derive_auth_and_vault_keys(&master)
    }

    #[tokio::test]
    async fn auth_gate_isolation_and_share_optimistic_concurrency() {
        let (_dir, mut state) = test_state(1024 * 1024);
        state.network_secret = Some("gate-123".to_string());
        {
            let db = state.db.lock().unwrap();
            seed_user_in_db(&db, "pauli", "hunter2", true).unwrap();
        }
        let app = build_router(state.clone());

        // Missing gate header rejected
        let blocked = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v2/auth/params?username=pauli")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(blocked.status(), StatusCode::UNAUTHORIZED);

        // Fetch salt & login
        let params_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v2/auth/params?username=pauli")
                    .header(GATE_HEADER, "gate-123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(params_resp.status(), StatusCode::OK);
        let ap: AuthParamsResponse =
            serde_json::from_slice(&params_resp.into_body().collect().await.unwrap().to_bytes())
                .unwrap();

        let (auth_key, _) = client_derive("hunter2", &ap.salt_hex);
        let login_body = serde_json::to_string(&LoginRequest {
            username: "pauli".into(),
            auth_key_hex: deltadrop_common::encode_hex(&auth_key),
            device_id: "host-pc".into(),
            encrypted_device_name: "enc-host".into(),
            os: "windows".into(),
        })
        .unwrap();
        let login_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v2/auth/login")
                    .header(GATE_HEADER, "gate-123")
                    .header("Content-Type", "application/json")
                    .body(Body::from(login_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login_resp.status(), StatusCode::OK);
        let admin: LoginResponse =
            serde_json::from_slice(&login_resp.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(admin.role, UserRole::Admin);

        // Publish share v1
        let put1_body = serde_json::to_string(&PutShareRequest {
            device_id: "host-pc".into(),
            owner_device_id: "host-pc".into(),
            base_version: 0,
            encrypted_manifest_b64: "enc-v1".into(),
        })
        .unwrap();
        let put1 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/api/v2/shares/my-unity-proj")
                    .header(GATE_HEADER, "gate-123")
                    .header("Authorization", format!("Bearer {}", admin.token))
                    .header("Content-Type", "application/json")
                    .body(Body::from(put1_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put1.status(), StatusCode::OK);
        let r1: PutShareResponse =
            serde_json::from_slice(&put1.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(r1.version, 1);

        // Stale base_version returns 409 Conflict with latest ShareRecord
        let stale_body = serde_json::to_string(&PutShareRequest {
            device_id: "laptop".into(),
            owner_device_id: "host-pc".into(),
            base_version: 0,
            encrypted_manifest_b64: "enc-stale".into(),
        })
        .unwrap();
        let conflict = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/api/v2/shares/my-unity-proj")
                    .header(GATE_HEADER, "gate-123")
                    .header("Authorization", format!("Bearer {}", admin.token))
                    .header("Content-Type", "application/json")
                    .body(Body::from(stale_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        let latest: ShareRecord =
            serde_json::from_slice(&conflict.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(latest.version, 1);
        assert_eq!(latest.encrypted_manifest_b64, "enc-v1");

        // Create sub-user Alice and verify strict user isolation on shares & chunks
        let sub_salt = generate_random_hex_32();
        let (sub_auth_key, _) = client_derive("alicepass", &sub_salt);
        let create_body = serde_json::to_string(&CreateUserRequest {
            username: "alice".into(),
            salt_hex: sub_salt,
            auth_key_hex: deltadrop_common::encode_hex(&sub_auth_key),
            role: UserRole::User,
        })
        .unwrap();
        let create_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v2/admin/users")
                    .header(GATE_HEADER, "gate-123")
                    .header("Authorization", format!("Bearer {}", admin.token))
                    .header("Content-Type", "application/json")
                    .body(Body::from(create_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_resp.status(), StatusCode::CREATED);
        let _alice_info: AdminUserInfo =
            serde_json::from_slice(&create_resp.into_body().collect().await.unwrap().to_bytes())
                .unwrap();

        let alice_login_body = serde_json::to_string(&LoginRequest {
            username: "alice".into(),
            auth_key_hex: deltadrop_common::encode_hex(&sub_auth_key),
            device_id: "alice-pc".into(),
            encrypted_device_name: "enc-alice".into(),
            os: "linux".into(),
        })
        .unwrap();
        let alice_login_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v2/auth/login")
                    .header(GATE_HEADER, "gate-123")
                    .header("Content-Type", "application/json")
                    .body(Body::from(alice_login_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let alice: LoginResponse = serde_json::from_slice(
            &alice_login_resp
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes(),
        )
        .unwrap();

        // Admin uploads chunk; Alice cannot see it or admin's shares
        let cid = "0123456789abcdef0123456789abcdef";
        let put_chunk = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(format!("/api/v2/chunks/{cid}"))
                    .header(GATE_HEADER, "gate-123")
                    .header("Authorization", format!("Bearer {}", admin.token))
                    .body(Body::from(vec![7u8; 64]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put_chunk.status(), StatusCode::NO_CONTENT);

        let alice_shares = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v2/shares")
                    .header(GATE_HEADER, "gate-123")
                    .header("Authorization", format!("Bearer {}", alice.token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let list: Vec<ShareRecord> =
            serde_json::from_slice(&alice_shares.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert!(list.is_empty());

        let alice_has = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v2/chunks/has")
                    .header(GATE_HEADER, "gate-123")
                    .header("Authorization", format!("Bearer {}", alice.token))
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&HasChunksRequest {
                            chunk_ids: vec![cid.into()],
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let has_resp: HasChunksResponse =
            serde_json::from_slice(&alice_has.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(has_resp.missing, vec![cid.to_string()]);
    }

    #[test]
    fn lru_evicts_oldest_user_chunks() {
        let (_dir, state) = test_state(100);
        let u_dir = state.chunks_dir.join("u1");
        std::fs::create_dir_all(&u_dir).unwrap();
        std::fs::write(u_dir.join("c1.chk"), vec![0u8; 60]).unwrap();
        std::fs::write(u_dir.join("c2.chk"), vec![0u8; 60]).unwrap();
        {
            let db = state.db.lock().unwrap();
            let now = now_ms();
            db.execute(
                "INSERT INTO user_chunks (user_id, chunk_id, size_bytes, created_at_ms, last_accessed_ms)
                 VALUES ('u1', 'c1', 60, ?1, 100)",
                params![now],
            )
            .unwrap();
            db.execute(
                "INSERT INTO user_chunks (user_id, chunk_id, size_bytes, created_at_ms, last_accessed_ms)
                 VALUES ('u1', 'c2', 60, ?1, 200)",
                params![now],
            )
            .unwrap();
        }
        assert_eq!(evict_lru_user_chunks(&state.db, &state.chunks_dir, 100), 1);
        assert!(!u_dir.join("c1.chk").exists());
        assert!(u_dir.join("c2.chk").exists());
    }
}
