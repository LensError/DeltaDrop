use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use deltadrop_common::{
    decode_base64url, decode_hex_32, derive_auth_and_vault_keys, encode_base64url, encode_hex,
    AdminUserInfo, AuthParamsResponse, CreateUserRequest, DeviceInfo, LoginRequest, LoginResponse,
    RelayCacheStatus, UpdateUserRequest, UserRole, GATE_HEADER,
};
use rand::RngCore;
use reqwest::{Client, RequestBuilder};
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct AuthSession {
    pub token: String,
    pub user_id: String,
    pub username: String,
    pub role: UserRole,
    pub vault_key: [u8; 32],
}

fn with_gate(req: RequestBuilder, network_secret: Option<&str>) -> RequestBuilder {
    match network_secret.map(str::trim).filter(|s| !s.is_empty()) {
        Some(secret) => req.header(GATE_HEADER, secret),
        None => req,
    }
}

pub fn derive_keys_from_password(
    password: &str,
    salt_hex: &str,
) -> anyhow::Result<([u8; 32], [u8; 32])> {
    let salt = decode_hex_32(salt_hex)
        .ok_or_else(|| anyhow::anyhow!("Invalid 32-byte salt hex from relay"))?;
    let mut master_secret = [0u8; 32];
    argon2::Argon2::default()
        .hash_password_into(password.as_bytes(), &salt[..16], &mut master_secret)
        .map_err(|e| anyhow::anyhow!("Argon2id key derivation failed: {e}"))?;
    Ok(derive_auth_and_vault_keys(&master_secret))
}

pub fn encrypt_vault_b64(vault_key: &[u8; 32], plaintext: &[u8]) -> anyhow::Result<String> {
    let cipher = ChaCha20Poly1305::new(vault_key.into());
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("Vault encryption failed: {e}"))?;
    let mut combined = Vec::with_capacity(12 + ct.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ct);
    Ok(encode_base64url(&combined))
}

#[allow(dead_code)]
pub fn decrypt_vault_b64(vault_key: &[u8; 32], b64: &str) -> anyhow::Result<Vec<u8>> {
    let raw = decode_base64url(b64).ok_or_else(|| anyhow::anyhow!("Invalid base64url"))?;
    if raw.len() < 12 {
        anyhow::bail!("Ciphertext too short");
    }
    let (nonce_bytes, ct) = raw.split_at(12);
    let cipher = ChaCha20Poly1305::new(vault_key.into());
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ct)
        .map_err(|e| anyhow::anyhow!("Vault decryption failed: {e}"))
}

pub async fn login_zero_knowledge(
    client: &Client,
    relay_url: &str,
    username: &str,
    password: &str,
    device_id: &str,
    device_name: &str,
    network_secret: Option<&str>,
) -> anyhow::Result<AuthSession> {
    let base = relay_url.trim().trim_end_matches('/');
    let params_url = format!("{base}/api/v1/auth/params");
    let params_resp = with_gate(
        client
            .get(&params_url)
            .query(&[("username", username.trim())]),
        network_secret,
    )
    .send()
    .await?
    .error_for_status()?;
    let auth_params: AuthParamsResponse = params_resp.json().await?;

    let (auth_key, vault_key) = derive_keys_from_password(password, &auth_params.salt_hex)?;
    let encrypted_device_name = encrypt_vault_b64(&vault_key, device_name.as_bytes())?;

    let login_url = format!("{base}/api/v1/auth/login");
    let login_req = LoginRequest {
        username: username.trim().to_string(),
        auth_key_hex: encode_hex(&auth_key),
        device_id: device_id.trim().to_string(),
        encrypted_device_name,
        os: std::env::consts::OS.to_string(),
    };
    let login_resp: LoginResponse =
        with_gate(client.post(&login_url).json(&login_req), network_secret)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

    Ok(AuthSession {
        token: login_resp.token,
        user_id: login_resp.user_id,
        username: login_resp.username,
        role: login_resp.role,
        vault_key,
    })
}

pub async fn admin_list_users(
    client: &Client,
    relay_url: &str,
    token: &str,
    network_secret: Option<&str>,
) -> anyhow::Result<Vec<AdminUserInfo>> {
    let url = format!("{}/api/v1/admin/users", relay_url.trim_end_matches('/'));
    let resp = with_gate(client.get(url).bearer_auth(token), network_secret)
        .send()
        .await?
        .error_for_status()?;
    Ok(resp.json().await?)
}

pub async fn admin_create_user(
    client: &Client,
    relay_url: &str,
    token: &str,
    network_secret: Option<&str>,
    username: &str,
    password: &str,
    role: UserRole,
) -> anyhow::Result<AdminUserInfo> {
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    let salt_hex = encode_hex(&salt);
    let (auth_key, _) = derive_keys_from_password(password, &salt_hex)?;
    let req = CreateUserRequest {
        username: username.trim().to_string(),
        salt_hex,
        auth_key_hex: encode_hex(&auth_key),
        role,
    };
    let url = format!("{}/api/v1/admin/users", relay_url.trim_end_matches('/'));
    let resp = with_gate(
        client.post(url).bearer_auth(token).json(&req),
        network_secret,
    )
    .send()
    .await?
    .error_for_status()?;
    Ok(resp.json().await?)
}

pub async fn admin_update_user(
    client: &Client,
    relay_url: &str,
    token: &str,
    network_secret: Option<&str>,
    target_user_id: &str,
    disabled: Option<bool>,
    new_password: Option<&str>,
) -> anyhow::Result<()> {
    let (salt_hex, auth_key_hex) = if let Some(pw) = new_password {
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        let s_hex = encode_hex(&salt);
        let (auth_key, _) = derive_keys_from_password(pw, &s_hex)?;
        (Some(s_hex), Some(encode_hex(&auth_key)))
    } else {
        (None, None)
    };
    let req = UpdateUserRequest {
        disabled,
        role: None,
        salt_hex,
        auth_key_hex,
    };
    let url = format!(
        "{}/api/v1/admin/users/{}",
        relay_url.trim_end_matches('/'),
        target_user_id
    );
    with_gate(
        client.patch(url).bearer_auth(token).json(&req),
        network_secret,
    )
    .send()
    .await?
    .error_for_status()?;
    Ok(())
}

pub async fn admin_delete_user(
    client: &Client,
    relay_url: &str,
    token: &str,
    network_secret: Option<&str>,
    target_user_id: &str,
) -> anyhow::Result<()> {
    let url = format!(
        "{}/api/v1/admin/users/{}",
        relay_url.trim_end_matches('/'),
        target_user_id
    );
    with_gate(client.delete(url).bearer_auth(token), network_secret)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

pub async fn list_devices(
    client: &Client,
    relay_url: &str,
    token: &str,
    network_secret: Option<&str>,
) -> anyhow::Result<Vec<DeviceInfo>> {
    let url = format!("{}/api/v1/devices", relay_url.trim_end_matches('/'));
    let resp = with_gate(client.get(url).bearer_auth(token), network_secret)
        .send()
        .await?
        .error_for_status()?;
    Ok(resp.json().await?)
}

pub async fn delete_device(
    client: &Client,
    relay_url: &str,
    token: &str,
    network_secret: Option<&str>,
    device_id: &str,
) -> anyhow::Result<()> {
    let url = format!(
        "{}/api/v1/devices/{}",
        relay_url.trim_end_matches('/'),
        device_id
    );
    with_gate(client.delete(url).bearer_auth(token), network_secret)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

#[derive(Serialize)]
struct ReplaceDevicePayload<'a> {
    new_device_id: &'a str,
    encrypted_name: &'a str,
    os: &'a str,
}

#[allow(clippy::too_many_arguments)]
pub async fn replace_device(
    client: &Client,
    relay_url: &str,
    token: &str,
    network_secret: Option<&str>,
    old_device_id: &str,
    new_device_id: &str,
    device_name: &str,
    vault_key: &[u8; 32],
) -> anyhow::Result<()> {
    let enc_name = encrypt_vault_b64(vault_key, device_name.as_bytes())?;
    let url = format!(
        "{}/api/v1/devices/{}/replace",
        relay_url.trim_end_matches('/'),
        old_device_id
    );
    let body = ReplaceDevicePayload {
        new_device_id,
        encrypted_name: &enc_name,
        os: std::env::consts::OS,
    };
    with_gate(
        client.post(url).bearer_auth(token).json(&body),
        network_secret,
    )
    .send()
    .await?
    .error_for_status()?;
    Ok(())
}

pub async fn fetch_cache_status(
    client: &Client,
    relay_url: &str,
    token: &str,
    network_secret: Option<&str>,
) -> anyhow::Result<RelayCacheStatus> {
    let url = format!("{}/api/v1/cache/status", relay_url.trim_end_matches('/'));
    let resp = with_gate(client.get(url).bearer_auth(token), network_secret)
        .send()
        .await?
        .error_for_status()?;
    Ok(resp.json().await?)
}
