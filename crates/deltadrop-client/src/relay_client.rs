use std::time::Instant;

use deltadrop_common::{
    encode_hex, AdminUserInfo, AuthParamsResponse, CreateUserRequest, DeviceInfo, HasChunksRequest,
    HasChunksResponse, LoginRequest, LoginResponse, PendingReseed, PutShareRequest,
    PutShareResponse, RelayCacheStatus, ReplaceDeviceRequest, ReseedRequest, ShareRecord,
    UpdateUserRequest, UserRole, GATE_HEADER, MAX_CHUNK_HTTP_BYTES, PROTOCOL_HEADER,
    PROTOCOL_VERSION,
};
use lumenic::{HttpClient, HttpLimits, HttpRequest, HttpResponse};
use rand::RngCore;

use crate::crypto::{derive_keys_from_password, encrypt_vault_b64};

#[derive(Debug, Clone)]
pub struct AuthSession {
    pub token: String,
    pub user_id: String,
    pub username: String,
    pub role: UserRole,
    pub vault_key: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct RelayClient {
    pub base_url: String,
    pub token: String,
    pub network_secret: Option<String>,
}

pub enum PutShareResult {
    Ok(PutShareResponse),
    Conflict,
}

pub fn normalize_relay_url(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return trimmed.to_string();
    }

    let host_port = trimmed.split('/').next().unwrap_or("");
    let (host, has_port) = if let Some(rest) = host_port.strip_prefix('[') {
        if let Some((h, after)) = rest.split_once(']') {
            (h, after.starts_with(':'))
        } else {
            (host_port, false)
        }
    } else if let Some((h, port_str)) = host_port.rsplit_once(':') {
        if !port_str.is_empty() && port_str.bytes().all(|b| b.is_ascii_digit()) {
            (h, true)
        } else {
            (host_port, false)
        }
    } else {
        (host_port, false)
    };

    let use_http = if host.eq_ignore_ascii_case("localhost")
        || matches!(host, "127.0.0.1" | "::1")
        || host.to_ascii_lowercase().ends_with(".ts.net")
    {
        true
    } else if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        let octets = ip.octets();
        let is_tailscale = octets[0] == 100 && (64..=127).contains(&octets[1]);
        is_tailscale || (has_port && (ip.is_private() || ip.is_loopback() || ip.is_link_local()))
    } else {
        false
    };

    let scheme = if use_http { "http://" } else { "https://" };
    format!("{scheme}{trimmed}")
}

impl RelayClient {
    pub fn new(base_url: &str, token: &str, network_secret: Option<&str>) -> Self {
        Self {
            base_url: normalize_relay_url(base_url),
            token: token.trim().to_string(),
            network_secret: network_secret
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string),
        }
    }

    fn limits(timeout_ms: u64) -> HttpLimits {
        HttpLimits {
            max_header_bytes: 32 * 1024,
            max_response_bytes: MAX_CHUNK_HTTP_BYTES + 1024 * 1024,
            max_redirects: 4,
            timeout_ms,
        }
    }

    fn apply_headers(&self, mut req: HttpRequest, with_auth: bool) -> HttpRequest {
        req = req
            .header(PROTOCOL_HEADER, PROTOCOL_VERSION)
            .limits(Self::limits(60_000));
        if let Some(ref gate) = self.network_secret {
            req = req.header(GATE_HEADER, gate.clone());
        }
        if with_auth && !self.token.is_empty() {
            req = req.header("Authorization", format!("Bearer {}", self.token));
        }
        req
    }

    fn send(&self, req: HttpRequest, with_auth: bool) -> anyhow::Result<(HttpResponse, u64)> {
        let built = self.apply_headers(req, with_auth);
        let t0 = Instant::now();
        let resp = HttpClient::send_sync(&built).map_err(|e| anyhow::anyhow!("HTTP error: {e}"))?;
        let ms = t0.elapsed().as_millis() as u64;
        if resp.status == 426 {
            anyhow::bail!(
                "Protocol mismatch (client v{PROTOCOL_VERSION}) - update client or relay"
            );
        }
        Ok((resp, ms))
    }

    fn check_ok(resp: HttpResponse, context: &str) -> anyhow::Result<HttpResponse> {
        if resp.is_success() {
            return Ok(resp);
        }
        let body = String::from_utf8_lossy(&resp.body);
        anyhow::bail!("{context}: HTTP {} {}", resp.status, body.trim())
    }

    pub fn login_zero_knowledge(
        &self,
        username: &str,
        password: &str,
        device_id: &str,
        device_name: &str,
    ) -> anyhow::Result<(AuthSession, u64)> {
        let user_q = url_encode(username.trim());
        let (params_resp, _) = self.send(
            HttpRequest::get(format!("{}/api/v2/auth/params?username={user_q}", self.base_url)),
            false,
        )?;
        let params_resp = Self::check_ok(params_resp, "Auth params failed")?;
        let auth_params: AuthParamsResponse = serde_json::from_slice(&params_resp.body)?;

        let (auth_key, vault_key) = derive_keys_from_password(password, &auth_params.salt_hex)?;
        let encrypted_device_name = encrypt_vault_b64(&vault_key, device_name.as_bytes())?;

        let login_req = LoginRequest {
            username: username.trim().to_string(),
            auth_key_hex: encode_hex(&auth_key),
            device_id: device_id.trim().to_string(),
            encrypted_device_name,
            os: std::env::consts::OS.to_string(),
        };
        let (login_resp, ms) = self.send(
            HttpRequest::post(format!("{}/api/v2/auth/login", self.base_url))
                .json(serde_json::to_string(&login_req)?),
            false,
        )?;
        let login_resp = Self::check_ok(login_resp, "Sign-in failed")?;
        let parsed: LoginResponse = serde_json::from_slice(&login_resp.body)?;
        Ok((
            AuthSession {
                token: parsed.token,
                user_id: parsed.user_id,
                username: parsed.username,
                role: parsed.role,
                vault_key,
            },
            ms,
        ))
    }

    pub fn list_shares(&self) -> anyhow::Result<(Vec<ShareRecord>, u64)> {
        let (resp, ms) = self.send(
            HttpRequest::get(format!("{}/api/v2/shares", self.base_url)),
            true,
        )?;
        let resp = Self::check_ok(resp, "List shares failed")?;
        Ok((serde_json::from_slice(&resp.body)?, ms))
    }

    pub fn get_share(&self, share_id: &str) -> anyhow::Result<Option<ShareRecord>> {
        let (resp, _) = self.send(
            HttpRequest::get(format!("{}/api/v2/shares/{share_id}", self.base_url)),
            true,
        )?;
        if resp.status == 404 {
            return Ok(None);
        }
        let resp = Self::check_ok(resp, "Get share failed")?;
        Ok(Some(serde_json::from_slice(&resp.body)?))
    }

    pub fn put_share(
        &self,
        share_id: &str,
        req: &PutShareRequest,
    ) -> anyhow::Result<PutShareResult> {
        let (resp, _) = self.send(
            HttpRequest::put(format!("{}/api/v2/shares/{share_id}", self.base_url))
                .json(serde_json::to_string(req)?),
            true,
        )?;
        if resp.status == 409 {
            return Ok(PutShareResult::Conflict);
        }
        let resp = Self::check_ok(resp, "Put share failed")?;
        Ok(PutShareResult::Ok(serde_json::from_slice(&resp.body)?))
    }

    pub fn delete_share(&self, share_id: &str) -> anyhow::Result<()> {
        let (resp, _) = self.send(
            HttpRequest::delete(format!("{}/api/v2/shares/{share_id}", self.base_url)),
            true,
        )?;
        Self::check_ok(resp, "Delete share failed")?;
        Ok(())
    }

    pub fn has_chunks(&self, chunk_ids: Vec<String>) -> anyhow::Result<Vec<String>> {
        if chunk_ids.is_empty() {
            return Ok(Vec::new());
        }
        let (resp, _) = self.send(
            HttpRequest::post(format!("{}/api/v2/chunks/has", self.base_url))
                .json(serde_json::to_string(&HasChunksRequest { chunk_ids })?),
            true,
        )?;
        let resp = Self::check_ok(resp, "Chunk check failed")?;
        let parsed: HasChunksResponse = serde_json::from_slice(&resp.body)?;
        Ok(parsed.missing)
    }

    pub fn put_chunk(&self, chunk_id: &str, bytes: Vec<u8>) -> anyhow::Result<()> {
        let (resp, _) = self.send(
            HttpRequest::put(format!("{}/api/v2/chunks/{chunk_id}", self.base_url))
                .header("Content-Type", "application/octet-stream")
                .body(bytes),
            true,
        )?;
        Self::check_ok(resp, "Chunk upload failed")?;
        Ok(())
    }

    pub fn get_chunk(&self, chunk_id: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let (resp, _) = self.send(
            HttpRequest::get(format!("{}/api/v2/chunks/{chunk_id}", self.base_url)),
            true,
        )?;
        if resp.status == 404 {
            return Ok(None);
        }
        let resp = Self::check_ok(resp, "Chunk download failed")?;
        Ok(Some(resp.body))
    }

    pub fn request_reseed(
        &self,
        share_id: &str,
        requester_device_id: &str,
        chunk_ids: Vec<String>,
    ) -> anyhow::Result<()> {
        if chunk_ids.is_empty() {
            return Ok(());
        }
        let (resp, _) = self.send(
            HttpRequest::post(format!("{}/api/v2/shares/{share_id}/reseed", self.base_url)).json(
                serde_json::to_string(&ReseedRequest {
                    requester_device_id: requester_device_id.to_string(),
                    chunk_ids,
                })?,
            ),
            true,
        )?;
        Self::check_ok(resp, "Reseed request failed")?;
        Ok(())
    }

    pub fn list_reseed_requests(&self) -> anyhow::Result<Vec<PendingReseed>> {
        let (resp, _) = self.send(
            HttpRequest::get(format!("{}/api/v2/reseed-requests", self.base_url)),
            true,
        )?;
        let resp = Self::check_ok(resp, "List reseed requests failed")?;
        Ok(serde_json::from_slice(&resp.body)?)
    }

    pub fn list_devices(&self) -> anyhow::Result<Vec<DeviceInfo>> {
        let (resp, _) = self.send(
            HttpRequest::get(format!("{}/api/v2/devices", self.base_url)),
            true,
        )?;
        let resp = Self::check_ok(resp, "List devices failed")?;
        Ok(serde_json::from_slice(&resp.body)?)
    }

    pub fn delete_device(&self, device_id: &str) -> anyhow::Result<()> {
        let (resp, _) = self.send(
            HttpRequest::delete(format!("{}/api/v2/devices/{device_id}", self.base_url)),
            true,
        )?;
        Self::check_ok(resp, "Delete device failed")?;
        Ok(())
    }

    pub fn replace_device(
        &self,
        old_device_id: &str,
        new_device_id: &str,
        device_name: &str,
        vault_key: &[u8; 32],
    ) -> anyhow::Result<()> {
        let encrypted_name = encrypt_vault_b64(vault_key, device_name.as_bytes())?;
        let body = ReplaceDeviceRequest {
            new_device_id: new_device_id.to_string(),
            encrypted_name,
            os: std::env::consts::OS.to_string(),
        };
        let (resp, _) = self.send(
            HttpRequest::post(format!(
                "{}/api/v2/devices/{old_device_id}/replace",
                self.base_url
            ))
            .json(serde_json::to_string(&body)?),
            true,
        )?;
        Self::check_ok(resp, "Replace device failed")?;
        Ok(())
    }

    pub fn fetch_cache_status(&self) -> anyhow::Result<(RelayCacheStatus, u64)> {
        let (resp, ms) = self.send(
            HttpRequest::get(format!("{}/api/v2/cache/status", self.base_url)),
            true,
        )?;
        let resp = Self::check_ok(resp, "Cache status failed")?;
        Ok((serde_json::from_slice(&resp.body)?, ms))
    }

    pub fn admin_list_users(&self) -> anyhow::Result<Vec<AdminUserInfo>> {
        let (resp, _) = self.send(
            HttpRequest::get(format!("{}/api/v2/admin/users", self.base_url)),
            true,
        )?;
        let resp = Self::check_ok(resp, "List users failed")?;
        Ok(serde_json::from_slice(&resp.body)?)
    }

    pub fn admin_create_user(
        &self,
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
        let (resp, _) = self.send(
            HttpRequest::post(format!("{}/api/v2/admin/users", self.base_url))
                .json(serde_json::to_string(&req)?),
            true,
        )?;
        let resp = Self::check_ok(resp, "Create user failed")?;
        Ok(serde_json::from_slice(&resp.body)?)
    }

    pub fn admin_update_user(
        &self,
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
        let (resp, _) = self.send(
            HttpRequest::patch(format!(
                "{}/api/v2/admin/users/{target_user_id}",
                self.base_url
            ))
            .json(serde_json::to_string(&req)?),
            true,
        )?;
        Self::check_ok(resp, "Update user failed")?;
        Ok(())
    }

    pub fn admin_delete_user(&self, target_user_id: &str) -> anyhow::Result<()> {
        let (resp, _) = self.send(
            HttpRequest::delete(format!(
                "{}/api/v2/admin/users/{target_user_id}",
                self.base_url
            )),
            true,
        )?;
        Self::check_ok(resp, "Delete user failed")?;
        Ok(())
    }

    pub fn ws_url(&self) -> String {
        if let Some(rest) = self.base_url.strip_prefix("https://") {
            format!("wss://{rest}/api/v2/ws")
        } else if let Some(rest) = self.base_url.strip_prefix("http://") {
            format!("ws://{rest}/api/v2/ws")
        } else {
            format!("wss://{}/api/v2/ws", self.base_url)
        }
    }
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            use std::fmt::Write;
            let _ = write!(&mut out, "%{b:02X}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::normalize_relay_url;

    #[test]
    fn normalize_relay_url_schemes() {
        assert_eq!(normalize_relay_url("localhost:8080/"), "http://localhost:8080");
        assert_eq!(normalize_relay_url("127.0.0.1:9000"), "http://127.0.0.1:9000");
        assert_eq!(normalize_relay_url("100.101.102.103:8080"), "http://100.101.102.103:8080");
        assert_eq!(normalize_relay_url("my-pc.tailnet-abc.ts.net"), "http://my-pc.tailnet-abc.ts.net");
        assert_eq!(normalize_relay_url("192.168.1.42:8080"), "http://192.168.1.42:8080");
        assert_eq!(normalize_relay_url("sync.example.com"), "https://sync.example.com");
        assert_eq!(normalize_relay_url("https://sync.example.com/"), "https://sync.example.com");
        assert_eq!(normalize_relay_url("http://192.168.1.42:8080/"), "http://192.168.1.42:8080");
    }
}
