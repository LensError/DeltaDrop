use std::io::Read;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use deltadrop_common::{
    decode_base64url, decode_hex_32, derive_auth_and_vault_keys, encode_base64url, ShareManifest,
};
use rand::RngCore;

const HARD_DECOMPRESS_CEILING: u64 = 128 * 1024 * 1024;

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
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|_| anyhow::anyhow!("Vault encryption failed"))?;
    let mut combined = Vec::with_capacity(12 + ct.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ct);
    Ok(encode_base64url(&combined))
}

pub fn decrypt_vault_b64(vault_key: &[u8; 32], b64: &str) -> anyhow::Result<Vec<u8>> {
    let raw = decode_base64url(b64).ok_or_else(|| anyhow::anyhow!("Invalid base64url"))?;
    if raw.len() < 12 {
        anyhow::bail!("Ciphertext too short");
    }
    let (nonce_bytes, ct) = raw.split_at(12);
    let cipher = ChaCha20Poly1305::new(vault_key.into());
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ct)
        .map_err(|_| anyhow::anyhow!("Vault decryption failed"))
}

pub fn decrypt_device_name(vault_key: Option<&[u8; 32]>, encrypted: &str, fallback: &str) -> String {
    let Some(vk) = vault_key else {
        return fallback.to_string();
    };
    if encrypted.trim().is_empty() {
        return fallback.to_string();
    }
    decrypt_vault_b64(vk, encrypted)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

/// Derives a user-private content-addressed chunk ID so the relay cannot correlate chunks across users.
pub fn compute_chunk_id(vault_key: &[u8; 32], plaintext: &[u8]) -> String {
    let id_key = blake3::derive_key("deltadrop-v3-chunk-id", vault_key);
    blake3::keyed_hash(&id_key, plaintext).to_hex().to_string()
}

pub fn encrypt_manifest(
    vault_key: &[u8; 32],
    user_id: &str,
    manifest: &ShareManifest,
) -> anyhow::Result<String> {
    let key = blake3::derive_key("deltadrop-v3-manifest", vault_key);
    let cipher = ChaCha20Poly1305::new((&key).into());
    let json = serde_json::to_vec(manifest)?;
    let compressed = zstd::encode_all(json.as_slice(), 3)?;
    let aad = format!("dd-v3-manifest|{user_id}|{}", manifest.share_id);
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: compressed.as_slice(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("Manifest encryption failed"))?;
    let mut combined = Vec::with_capacity(12 + ct.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ct);
    Ok(encode_base64url(&combined))
}

pub fn decrypt_manifest(
    vault_key: &[u8; 32],
    user_id: &str,
    share_id: &str,
    b64: &str,
) -> anyhow::Result<ShareManifest> {
    let raw = decode_base64url(b64).ok_or_else(|| anyhow::anyhow!("Invalid manifest base64url"))?;
    if raw.len() < 12 {
        anyhow::bail!("Encrypted manifest too short");
    }
    let key = blake3::derive_key("deltadrop-v3-manifest", vault_key);
    let cipher = ChaCha20Poly1305::new((&key).into());
    let aad = format!("dd-v3-manifest|{user_id}|{share_id}");
    let compressed = cipher
        .decrypt(
            Nonce::from_slice(&raw[..12]),
            Payload {
                msg: &raw[12..],
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("Manifest decryption failed (wrong key or tampered)"))?;
    let decoder = zstd::stream::read::Decoder::new(compressed.as_slice())?;
    let mut limited = decoder.take(HARD_DECOMPRESS_CEILING);
    let mut json = Vec::new();
    limited.read_to_end(&mut json)?;
    let manifest: ShareManifest = serde_json::from_slice(&json)?;
    if manifest.share_id != share_id {
        anyhow::bail!("Manifest share_id mismatch");
    }
    Ok(manifest)
}

pub fn encrypt_chunk(
    vault_key: &[u8; 32],
    user_id: &str,
    chunk_id: &str,
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let compressed = zstd::encode_all(plaintext, 3)?;
    let key = blake3::derive_key("deltadrop-v3-chunk", vault_key);
    let cipher = ChaCha20Poly1305::new((&key).into());
    let aad = format!("dd-v3-chunk|{user_id}|{chunk_id}");
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: compressed.as_slice(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("Chunk encryption failed"))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt_chunk(
    vault_key: &[u8; 32],
    user_id: &str,
    chunk_id: &str,
    ciphertext: &[u8],
    expected_raw_size: u64,
) -> anyhow::Result<Vec<u8>> {
    if ciphertext.len() < 12 {
        anyhow::bail!("Encrypted chunk too short");
    }
    if expected_raw_size > HARD_DECOMPRESS_CEILING {
        anyhow::bail!("Declared chunk raw_size exceeds safety ceiling");
    }
    let key = blake3::derive_key("deltadrop-v3-chunk", vault_key);
    let cipher = ChaCha20Poly1305::new((&key).into());
    let aad = format!("dd-v3-chunk|{user_id}|{chunk_id}");
    let compressed = cipher
        .decrypt(
            Nonce::from_slice(&ciphertext[..12]),
            Payload {
                msg: &ciphertext[12..],
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("Chunk decryption failed (wrong key or tampered)"))?;
    let decoder = zstd::stream::read::Decoder::new(compressed.as_slice())?;
    let mut limited = decoder.take(expected_raw_size.saturating_add(1));
    let mut out = Vec::with_capacity(expected_raw_size.min(8 * 1024 * 1024) as usize);
    limited.read_to_end(&mut out)?;
    if out.len() as u64 != expected_raw_size {
        anyhow::bail!(
            "Decompressed chunk size {} != expected {}",
            out.len(),
            expected_raw_size
        );
    }
    Ok(out)
}
