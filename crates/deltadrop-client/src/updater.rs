use std::path::{Path, PathBuf};

use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const GITHUB_LATEST_URL: &str = "https://api.github.com/repos/LensError/DeltaDrop/releases/latest";

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum UpdateStatus {
    Idle,
    Checking,
    UpToDate(String),
    Available {
        version: String,
        asset_url: String,
        asset_name: String,
        sums_url: String,
    },
    Downloading(String),
    ReadyToRestart(String),
    Error(String),
}

#[derive(Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
    assets: Vec<GithubAsset>,
}

pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub fn parse_semver(raw: &str) -> Option<(u64, u64, u64)> {
    let clean = raw.trim().trim_start_matches('v');
    let clean = clean.split('-').next().unwrap_or(clean);
    let mut parts = clean.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    Some((major, minor, patch))
}

pub fn is_newer_version(current: &str, latest: &str) -> bool {
    match (parse_semver(current), parse_semver(latest)) {
        (Some(c), Some(l)) => l > c,
        _ => false,
    }
}

pub fn expected_platform_asset_name() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "deltadrop-client-windows-x86_64.zip"
    }
    #[cfg(target_os = "macos")]
    {
        "deltadrop-client-macos-universal.tar.gz"
    }
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        "deltadrop-client-linux-x86_64.tar.gz"
    }
}

pub fn parse_sha256_for_asset(sums_text: &str, asset_name: &str) -> Option<String> {
    for line in sums_text.lines() {
        let mut parts = line.split_whitespace();
        let hash = parts.next()?;
        let file = parts.next()?.trim_start_matches('*');
        if file == asset_name && hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Some(hash.to_ascii_lowercase());
        }
    }
    None
}

pub fn verify_sha256_bytes(bytes: &[u8], expected_hex: &str) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut actual = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(&mut actual, "{b:02x}");
    }
    actual == expected_hex.trim().to_ascii_lowercase()
}

pub fn cleanup_old_windows_exe() {
    if let Ok(exe) = std::env::current_exe() {
        let old = PathBuf::from(format!("{}.old", exe.display()));
        if old.exists() {
            let _ = std::fs::remove_file(old);
        }
    }
}

pub async fn check_for_updates(client: &Client) -> Result<UpdateStatus, String> {
    let resp = client
        .get(GITHUB_LATEST_URL)
        .header(
            "User-Agent",
            format!("deltadrop-client/{}", current_version()),
        )
        .send()
        .await
        .map_err(|e| format!("Update check failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("GitHub API returned {}", resp.status()));
    }
    let release: GithubRelease = resp
        .json()
        .await
        .map_err(|e| format!("Invalid release JSON: {e}"))?;

    if !is_newer_version(current_version(), &release.tag_name) {
        return Ok(UpdateStatus::UpToDate(current_version().to_string()));
    }

    let asset_name = expected_platform_asset_name().to_string();
    let asset = release
        .assets
        .iter()
        .find(|a| a.name == asset_name)
        .ok_or_else(|| format!("Release {} missing asset {}", release.tag_name, asset_name))?;
    let sums = release
        .assets
        .iter()
        .find(|a| a.name == "SHA256SUMS")
        .ok_or_else(|| format!("Release {} missing SHA256SUMS", release.tag_name))?;

    Ok(UpdateStatus::Available {
        version: release.tag_name,
        asset_url: asset.browser_download_url.clone(),
        asset_name,
        sums_url: sums.browser_download_url.clone(),
    })
}

pub async fn download_and_stage_update(
    client: &Client,
    version: &str,
    asset_url: &str,
    asset_name: &str,
    sums_url: &str,
) -> Result<UpdateStatus, String> {
    let sums_text = client
        .get(sums_url)
        .header(
            "User-Agent",
            format!("deltadrop-client/{}", current_version()),
        )
        .send()
        .await
        .map_err(|e| format!("Failed to fetch SHA256SUMS: {e}"))?
        .error_for_status()
        .map_err(|e| format!("SHA256SUMS HTTP error: {e}"))?
        .text()
        .await
        .map_err(|e| format!("Failed to read SHA256SUMS: {e}"))?;

    let expected_hash = parse_sha256_for_asset(&sums_text, asset_name)
        .ok_or_else(|| format!("SHA256SUMS missing entry for {asset_name}"))?;

    let archive_bytes = client
        .get(asset_url)
        .header(
            "User-Agent",
            format!("deltadrop-client/{}", current_version()),
        )
        .send()
        .await
        .map_err(|e| format!("Failed to download update: {e}"))?
        .error_for_status()
        .map_err(|e| format!("Update download HTTP error: {e}"))?
        .bytes()
        .await
        .map_err(|e| format!("Failed to read update bytes: {e}"))?;

    if !verify_sha256_bytes(&archive_bytes, &expected_hash) {
        return Err("SHA-256 verification failed for downloaded update".to_string());
    }

    let current_exe =
        std::env::current_exe().map_err(|e| format!("Cannot locate current exe: {e}"))?;
    let parent = current_exe
        .parent()
        .ok_or_else(|| "Current exe has no parent directory".to_string())?;
    let stage_archive = parent.join(format!(".deltadrop-update-{asset_name}"));
    std::fs::write(&stage_archive, &archive_bytes)
        .map_err(|e| format!("Failed to write staged archive: {e}"))?;

    let new_bin = extract_binary_from_archive(&stage_archive, parent)?;
    let _ = std::fs::remove_file(&stage_archive);

    atomic_replace_exe(&current_exe, &new_bin)?;
    Ok(UpdateStatus::ReadyToRestart(version.to_string()))
}

fn extract_binary_from_archive(archive_path: &Path, work_dir: &Path) -> Result<PathBuf, String> {
    let new_bin = work_dir.join(if cfg!(target_os = "windows") {
        ".deltadrop-client.new.exe"
    } else {
        ".deltadrop-client.new"
    });
    let _ = std::fs::remove_file(&new_bin);

    #[cfg(target_os = "windows")]
    {
        let status = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "Expand-Archive -Path '{}' -DestinationPath '{}' -Force",
                    archive_path.display(),
                    work_dir.join(".deltadrop-unpack").display()
                ),
            ])
            .status()
            .map_err(|e| format!("Failed to extract zip: {e}"))?;
        if !status.success() {
            return Err("Archive extraction failed".to_string());
        }
        let extracted = work_dir
            .join(".deltadrop-unpack")
            .join("deltadrop-client.exe");
        std::fs::rename(&extracted, &new_bin)
            .map_err(|e| format!("Failed to stage extracted exe: {e}"))?;
        let _ = std::fs::remove_dir_all(work_dir.join(".deltadrop-unpack"));
    }

    #[cfg(not(target_os = "windows"))]
    {
        let unpack = work_dir.join(".deltadrop-unpack");
        let _ = std::fs::create_dir_all(&unpack);
        let status = std::process::Command::new("tar")
            .args([
                "-xzf",
                &archive_path.display().to_string(),
                "-C",
                &unpack.display().to_string(),
            ])
            .status()
            .map_err(|e| format!("Failed to run tar: {e}"))?;
        if !status.success() {
            return Err("tar extraction failed".to_string());
        }
        let extracted = unpack.join("deltadrop-client");
        std::fs::rename(&extracted, &new_bin)
            .map_err(|e| format!("Failed to stage extracted binary: {e}"))?;
        let _ = std::fs::remove_dir_all(&unpack);
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&new_bin, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod failed: {e}"))?;
    }

    Ok(new_bin)
}

fn atomic_replace_exe(current_exe: &Path, new_bin: &Path) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let old_exe = PathBuf::from(format!("{}.old", current_exe.display()));
        let _ = std::fs::remove_file(&old_exe);
        std::fs::rename(current_exe, &old_exe)
            .map_err(|e| format!("Failed to move running exe to .old: {e}"))?;
        if let Err(e) = std::fs::rename(new_bin, current_exe) {
            let _ = std::fs::rename(&old_exe, current_exe);
            return Err(format!("Failed to move new exe into place: {e}"));
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::fs::rename(new_bin, current_exe)
            .map_err(|e| format!("Failed to replace binary: {e}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_semver_tags() {
        assert!(is_newer_version("0.1.0", "v0.2.0"));
        assert!(is_newer_version("0.1.0", "0.1.1"));
        assert!(!is_newer_version("0.2.0", "v0.2.0"));
        assert!(!is_newer_version("0.2.0", "v0.1.9"));
    }

    #[test]
    fn parses_and_verifies_sha256sums() {
        let payload = b"deltadrop-binary-bytes";
        let mut hasher = Sha256::new();
        hasher.update(payload);
        let hex = format!("{:x}", hasher.finalize());
        let sums = format!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  other.tar.gz\n{hex}  deltadrop-client-windows-x86_64.zip\n"
        );
        let parsed = parse_sha256_for_asset(&sums, "deltadrop-client-windows-x86_64.zip").unwrap();
        assert!(verify_sha256_bytes(payload, &parsed));
        assert!(!verify_sha256_bytes(b"tampered", &parsed));
    }
}
