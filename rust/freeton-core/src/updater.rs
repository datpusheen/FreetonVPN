use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::header::{ACCEPT, CACHE_CONTROL, EXPIRES, PRAGMA, USER_AGENT};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

use crate::APP_VERSION;

/// Default GitHub repository slug used for release page and GitHub Releases API fallback.
pub const DEFAULT_GITHUB_REPO: &str = "datpusheen/FreetonVPN";

/// Dedicated Rust desktop release manifest URL (isolated from legacy v2.4.3 `version.json`).
pub const DEFAULT_RUST_VERSION_JSON_URL: &str =
    "https://raw.githubusercontent.com/datpusheen/FreetonVPN/refs/heads/main/version-rust.json";

/// Default GitHub REST API origin.
pub const DEFAULT_GITHUB_API_BASE_URL: &str = "https://api.github.com";

const INSTALLER_ASSET_NAME: &str = "FreetonVPN-Setup-x64.exe";
const MAX_SHA256_ASSET_BYTES: usize = 64 * 1024;

/// Release update metadata parsed from `version-rust.json` or GitHub Releases API fallback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateInfo {
    pub version: String,
    pub release_date: String,
    pub title: String,
    pub changelog: Vec<String>,
    pub download_url: String,
    pub file_size_bytes: u64,
    pub sha256: String,
    pub mandatory: bool,
    pub min_supported_version: String,
}

impl UpdateInfo {
    /// Formats `changelog` entries as a bulleted display string matching `updater.py`.
    pub fn formatted_changelog(&self) -> String {
        if self.changelog.is_empty() {
            return "Không có thông tin thay đổi.".to_owned();
        }
        self.changelog
            .iter()
            .map(|item| {
                let trimmed = item.trim();
                if trimmed.starts_with('•') || trimmed.starts_with('-') || trimmed.starts_with('*')
                {
                    item.clone()
                } else {
                    format!("• {item}")
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Next step returned by `download_and_verify_update` under the fail-closed verification policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateAction {
    /// Installer passed SHA-256 verification and is ready for `ShellExecuteW runas`.
    LaunchVerifiedInstaller(PathBuf),
    /// No valid SHA-256 digest was provided; never download/run an unverified installer.
    OpenReleasePageInBrowser(String),
}

/// Errors returned while fetching update manifests or downloading/verifying installers.
#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("Lỗi kết nối máy chủ cập nhật: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Metadata cập nhật không hợp lệ: {0}")]
    InvalidManifest(String),
    #[error("URL tải cập nhật không hợp lệ: {0}")]
    InvalidUrl(String),
    #[error("Lỗi tệp cập nhật: {0}")]
    Io(#[from] std::io::Error),
    #[error("Tệp cài đặt tải về rỗng hoặc bị ngắt.")]
    EmptyDownload,
    #[error("Xác thực SHA-256 thất bại (kỳ vọng {expected}, thực tế {actual}).")]
    ChecksumMismatch { expected: String, actual: String },
}

fn encode_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Returns `true` when `s` is exactly 64 ASCII hexadecimal characters.
pub fn is_valid_sha256_hex(s: &str) -> bool {
    let trimmed = s.trim();
    trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Extracts numeric components from a version string (e.g. `"v2.4.1"` -> `[2, 4, 1]`,
/// `"3.0-beta"` -> `[3, 0]`, `""` -> `[0]`).
pub fn parse_version_tuple(version: &str) -> Vec<u64> {
    let mut nums = Vec::new();
    let mut current = String::new();

    for ch in version.chars() {
        if ch.is_ascii_digit() {
            current.push(ch);
        } else if !current.is_empty() {
            nums.push(current.parse::<u64>().unwrap_or(u64::MAX));
            current.clear();
        }
    }
    if !current.is_empty() {
        nums.push(current.parse::<u64>().unwrap_or(u64::MAX));
    }
    if nums.is_empty() {
        nums.push(0);
    }
    nums
}

/// Returns `true` if `remote` is strictly newer than `current` (zero-padding shorter tuples).
pub fn is_newer_version(current: &str, remote: &str) -> bool {
    let mut curr = parse_version_tuple(current);
    let mut rem = parse_version_tuple(remote);
    let max_len = curr.len().max(rem.len());
    curr.resize(max_len, 0);
    rem.resize(max_len, 0);
    rem > curr
}

/// Parses a `version-rust.json` / `version.json` object into `UpdateInfo`.
pub fn parse_json_update_info(data: &Value) -> Result<UpdateInfo, UpdateError> {
    let version = data
        .get("version")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| UpdateError::InvalidManifest("Missing `version` field".to_owned()))?
        .to_owned();

    let title = data
        .get("title")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("Freeton VPN v{version}"));

    let release_date = data
        .get("release_date")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_owned();

    let download_url = data
        .get("download_url")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_owned();

    let file_size_bytes = data
        .get("file_size_bytes")
        .and_then(Value::as_u64)
        .unwrap_or(0);

    let sha256 = data
        .get("sha256")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();

    let mandatory = data
        .get("mandatory")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let min_supported_version = data
        .get("min_supported_version")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_owned();

    let changelog = match data.get("changelog") {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect(),
        Some(Value::String(text)) => text
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    };

    Ok(UpdateInfo {
        version,
        release_date,
        title,
        changelog,
        download_url,
        file_size_bytes,
        sha256,
        mandatory,
        min_supported_version,
    })
}

/// Parses a GitHub Releases API JSON response into `(UpdateInfo, Option<companion_sha256_url>)`.
///
/// Prefers `FreetonVPN-Setup-x64.exe` (falling back to the first `.exe` asset) and locates a
/// companion `<installer_name>.sha256` (or first `*.sha256`) release asset URL when present.
pub fn parse_github_release_info(
    data: &Value,
) -> Result<(UpdateInfo, Option<String>), UpdateError> {
    let raw_tag = data
        .get("tag_name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| UpdateError::InvalidManifest("Missing `tag_name` in release".to_owned()))?;
    let version = raw_tag.trim_start_matches(['v', 'V']).to_owned();
    if version.is_empty() {
        return Err(UpdateError::InvalidManifest(
            "Empty version after trimming tag prefix".to_owned(),
        ));
    }

    let title = data
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("Freeton VPN v{version}"));

    let release_date = data
        .get("published_at")
        .and_then(Value::as_str)
        .map(|s| s.chars().take(10).collect::<String>())
        .unwrap_or_default();

    let changelog = data
        .get("body")
        .and_then(Value::as_str)
        .map(|body| {
            body.lines()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();

    let assets = data
        .get("assets")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);

    let chosen_exe = assets
        .iter()
        .find(|asset| {
            asset
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|n| n.trim().eq_ignore_ascii_case(INSTALLER_ASSET_NAME))
        })
        .or_else(|| {
            assets.iter().find(|asset| {
                asset
                    .get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|n| n.trim().to_ascii_lowercase().ends_with(".exe"))
            })
        });

    let (installer_name, download_url, file_size_bytes) = if let Some(asset) = chosen_exe {
        (
            asset
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or("")
                .to_owned(),
            asset
                .get("browser_download_url")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or("")
                .to_owned(),
            asset.get("size").and_then(Value::as_u64).unwrap_or(0),
        )
    } else {
        (String::new(), String::new(), 0)
    };

    let expected_sha_name =
        (!installer_name.is_empty()).then(|| format!("{installer_name}.sha256"));
    let chosen_sha_asset = expected_sha_name
        .as_deref()
        .and_then(|target_name| {
            assets.iter().find(|asset| {
                asset
                    .get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|n| n.trim().eq_ignore_ascii_case(target_name))
            })
        })
        .or_else(|| {
            assets.iter().find(|asset| {
                asset
                    .get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|n| n.trim().to_ascii_lowercase().ends_with(".sha256"))
            })
        });

    let sha_asset_url = chosen_sha_asset
        .and_then(|asset| asset.get("browser_download_url").and_then(Value::as_str))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);

    Ok((
        UpdateInfo {
            version,
            release_date,
            title,
            changelog,
            download_url,
            file_size_bytes,
            sha256: String::new(),
            mandatory: false,
            min_supported_version: String::new(),
        },
        sha_asset_url,
    ))
}

fn extract_hex64_from_line(line: &str) -> Option<String> {
    line.split(|c: char| c.is_whitespace() || c == '=' || c == '*')
        .map(str::trim)
        .find(|token| is_valid_sha256_hex(token))
        .map(|token| token.to_ascii_lowercase())
}

/// Safely extracts a 64-character lowercase SHA-256 hex digest from a `.sha256` file payload.
pub fn parse_sha256_text(text: &str, expected_filename: Option<&str>) -> Option<String> {
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if lines.is_empty() {
        return None;
    }

    if let Some(filename) = expected_filename.map(str::trim).filter(|f| !f.is_empty()) {
        let filename_lower = filename.to_ascii_lowercase();
        let matching_hashes: Vec<String> = lines
            .iter()
            .filter(|line| line.to_ascii_lowercase().contains(&filename_lower))
            .filter_map(|line| extract_hex64_from_line(line))
            .collect();
        if matching_hashes.len() == 1 {
            return matching_hashes.into_iter().next();
        }
        if matching_hashes.len() > 1 {
            return None;
        }
    }

    let all_hashes: Vec<String> = lines
        .iter()
        .filter_map(|line| extract_hex64_from_line(line))
        .collect();
    if all_hashes.len() == 1 {
        all_hashes.into_iter().next()
    } else {
        None
    }
}

/// Computes the lowercase SHA-256 hex digest of an existing file on disk.
pub fn compute_file_sha256(file_path: &Path) -> Result<String, UpdateError> {
    let file = File::open(file_path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65_536];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(encode_hex_lower(&hasher.finalize()))
}

fn build_updater_client() -> Result<Client, UpdateError> {
    Ok(Client::builder()
        .connect_timeout(Duration::from_secs(8))
        .timeout(Duration::from_secs(20))
        .user_agent(format!(
            "FreetonVPN-Desktop-Updater/{APP_VERSION} (Windows)"
        ))
        .build()?)
}

fn cache_busted_url(raw_url: &str) -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let sep = if raw_url.contains('?') { '&' } else { '?' };
    format!("{raw_url}{sep}_cb={ts}")
}

fn validate_download_url(raw_url: &str) -> Result<Url, UpdateError> {
    let parsed = Url::parse(raw_url.trim())
        .map_err(|err| UpdateError::InvalidUrl(format!("Invalid download URL: {err}")))?;
    match parsed.scheme() {
        "https" => Ok(parsed),
        "http" => {
            let is_loopback = matches!(
                parsed.host_str(),
                Some("127.0.0.1" | "localhost" | "::1" | "[::1]")
            );
            if is_loopback {
                Ok(parsed)
            } else {
                Err(UpdateError::InvalidUrl(
                    "Non-HTTPS update URLs are only permitted on loopback for tests".to_owned(),
                ))
            }
        }
        other => Err(UpdateError::InvalidUrl(format!(
            "Unsupported URL scheme: {other}"
        ))),
    }
}

fn release_page_url(info: &UpdateInfo) -> String {
    if let Ok(parsed) = Url::parse(info.download_url.trim()) {
        if let Some(host) = parsed.host_str() {
            if host.eq_ignore_ascii_case("github.com") {
                if let Some((prefix, rest)) = parsed.path().split_once("/releases/download/") {
                    if let Some((tag, _)) = rest.split_once('/') {
                        if !tag.is_empty() {
                            return format!("https://github.com{prefix}/releases/tag/{tag}");
                        }
                    }
                }
            }
        }
    }
    format!("https://github.com/{DEFAULT_GITHUB_REPO}/releases")
}

fn sanitize_installer_filename(url: &Url) -> String {
    let candidate = url
        .path_segments()
        .and_then(|mut segments| segments.rfind(|s| !s.is_empty()))
        .unwrap_or(INSTALLER_ASSET_NAME);
    if candidate.is_empty()
        || candidate == "."
        || candidate == ".."
        || candidate.contains('/')
        || candidate.contains('\\')
        || candidate.contains(':')
        || candidate.chars().any(char::is_control)
    {
        INSTALLER_ASSET_NAME.to_owned()
    } else {
        candidate.to_owned()
    }
}

/// Fetches update metadata from `version-rust.json` first, falling back to the GitHub Releases
/// API (and fetching any companion `.sha256` release asset) if the primary manifest fails.
pub async fn fetch_update_info(
    manifest_url: Option<&str>,
    repo: Option<&str>,
) -> Result<Option<UpdateInfo>, UpdateError> {
    fetch_update_info_with_base(manifest_url, repo, None).await
}

/// Testable variant of `fetch_update_info` allowing a custom GitHub API base URL.
pub async fn fetch_update_info_with_base(
    manifest_url: Option<&str>,
    repo: Option<&str>,
    github_api_base: Option<&str>,
) -> Result<Option<UpdateInfo>, UpdateError> {
    let client = build_updater_client()?;
    let target_url = manifest_url
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_RUST_VERSION_JSON_URL);
    let target_repo = repo
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_GITHUB_REPO);
    let api_base = github_api_base
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_GITHUB_API_BASE_URL)
        .trim_end_matches('/');

    // 1. Primary manifest (`version-rust.json` with CDN cache-buster).
    if let Ok(resp) = client
        .get(cache_busted_url(target_url))
        .timeout(Duration::from_secs(6))
        .header(
            USER_AGENT,
            format!("FreetonVPN-Desktop-Updater/{APP_VERSION}"),
        )
        .header(CACHE_CONTROL, "no-cache, no-store, must-revalidate")
        .header(PRAGMA, "no-cache")
        .header(EXPIRES, "0")
        .send()
        .await
    {
        if resp.status().is_success() {
            if let Ok(json_val) = resp.json::<Value>().await {
                if let Ok(info) = parse_json_update_info(&json_val) {
                    return Ok(Some(info));
                }
            }
        }
    }

    // 2. Fallback: GitHub Releases API + companion `.sha256` asset.
    let gh_url = format!("{api_base}/repos/{target_repo}/releases/latest");
    let gh_resp = client
        .get(&gh_url)
        .timeout(Duration::from_secs(8))
        .header(ACCEPT, "application/vnd.github.v3+json")
        .send()
        .await?;

    if gh_resp.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !gh_resp.status().is_success() {
        return Err(UpdateError::InvalidManifest(format!(
            "GitHub Releases API returned HTTP {}",
            gh_resp.status().as_u16()
        )));
    }

    let gh_json: Value = gh_resp.json().await?;
    let (mut info, sha_asset_url) = parse_github_release_info(&gh_json)?;

    if let Some(asset_url) = sha_asset_url {
        let expected_name = Url::parse(&info.download_url)
            .ok()
            .map(|u| sanitize_installer_filename(&u));
        if let Ok(sha_resp) = client
            .get(&asset_url)
            .timeout(Duration::from_secs(8))
            .send()
            .await
        {
            if sha_resp.status().is_success() {
                if let Ok(bytes) = sha_resp.bytes().await {
                    if bytes.len() <= MAX_SHA256_ASSET_BYTES {
                        let text = String::from_utf8_lossy(&bytes);
                        if let Some(digest) = parse_sha256_text(&text, expected_name.as_deref()) {
                            info.sha256 = digest;
                        }
                    }
                }
            }
        }
    }

    Ok(Some(info))
}

/// Downloads and verifies an installer update under a strict fail-closed policy:
///
/// - If `info.sha256` is missing, empty, or not a 64-character hex digest, returns
///   `Ok(UpdateAction::OpenReleasePageInBrowser(url))` without touching disk or downloading.
/// - Otherwise streams the installer to `<dest_dir>/<filename>.part`, hashes incrementally,
///   and verifies exact SHA-256 parity before renaming to `<dest_dir>/<filename>`.
/// - On checksum mismatch or download error, deletes any `.part` file and returns `Err(...)`.
pub async fn download_and_verify_update(
    info: &UpdateInfo,
    dest_dir: &Path,
    on_progress: impl Fn(u64, u64, f32),
) -> Result<UpdateAction, UpdateError> {
    let expected_sha = info.sha256.trim().to_ascii_lowercase();
    if !is_valid_sha256_hex(&expected_sha) {
        return Ok(UpdateAction::OpenReleasePageInBrowser(release_page_url(
            info,
        )));
    }

    let download_url = validate_download_url(&info.download_url)?;
    let filename = sanitize_installer_filename(&download_url);
    fs::create_dir_all(dest_dir)?;

    let dest_path = dest_dir.join(&filename);
    let part_path = dest_dir.join(format!("{filename}.part"));
    if part_path.exists() {
        let _ = fs::remove_file(&part_path);
    }

    let client = build_updater_client()?;
    let mut response = client.get(download_url).send().await?.error_for_status()?;
    let total_size = response.content_length().unwrap_or(info.file_size_bytes);

    let result: Result<(u64, String), UpdateError> = async {
        let file = File::create(&part_path)?;
        let mut writer = BufWriter::new(file);
        let mut hasher = Sha256::new();
        let mut downloaded: u64 = 0;

        while let Some(chunk) = response.chunk().await? {
            writer.write_all(&chunk)?;
            hasher.update(&chunk);
            downloaded += u64::try_from(chunk.len()).unwrap_or(0);

            let percent = if total_size > 0 {
                ((downloaded as f64 / total_size as f64) * 100.0).min(100.0) as f32
            } else {
                0.0
            };
            on_progress(downloaded, total_size, percent);
        }

        writer.flush()?;
        drop(writer);

        if downloaded == 0 {
            return Err(UpdateError::EmptyDownload);
        }

        Ok((downloaded, encode_hex_lower(&hasher.finalize())))
    }
    .await;

    let (_, actual_sha) = match result {
        Ok(ok) => ok,
        Err(err) => {
            let _ = fs::remove_file(&part_path);
            return Err(err);
        }
    };

    if actual_sha != expected_sha {
        let _ = fs::remove_file(&part_path);
        return Err(UpdateError::ChecksumMismatch {
            expected: expected_sha,
            actual: actual_sha,
        });
    }

    if dest_path.exists() {
        let _ = fs::remove_file(&dest_path);
    }
    if let Err(err) = fs::rename(&part_path, &dest_path) {
        let _ = fs::remove_file(&part_path);
        return Err(UpdateError::Io(err));
    }

    Ok(UpdateAction::LaunchVerifiedInstaller(dest_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn read_http_request(socket: &mut tokio::net::TcpStream) -> String {
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = socket.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
            if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        String::from_utf8_lossy(&raw).into_owned()
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "freeton_updater_test_{}_{}_{}",
            name,
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp test dir");
        dir
    }

    #[test]
    fn test_version_comparison_and_manifest_parsing() {
        assert_eq!(parse_version_tuple("2.4"), vec![2, 4]);
        assert_eq!(parse_version_tuple("v2.4.1"), vec![2, 4, 1]);
        assert_eq!(parse_version_tuple("3.0-beta"), vec![3, 0]);
        assert_eq!(parse_version_tuple(""), vec![0]);

        assert!(is_newer_version("2.4", "2.5"));
        assert!(is_newer_version("2.4", "2.4.1"));
        assert!(is_newer_version("v2.4.0", "v2.5.0"));
        assert!(is_newer_version("2.4", "3.0"));

        assert!(!is_newer_version("2.4", "2.4"));
        assert!(!is_newer_version("2.4.0", "2.4"));
        assert!(!is_newer_version("v2.4.0", "2.4"));
        assert!(!is_newer_version("2.5", "2.4"));
        assert!(!is_newer_version("3.0", "2.9.9"));

        let sample_json = serde_json::json!({
            "version": "2.5",
            "release_date": "2026-09-01",
            "title": "Bản cập nhật v2.5",
            "changelog": [
                "⚡ Tối ưu ping",
                "🐛 Sửa lỗi kết nối"
            ],
            "download_url": "https://github.com/datpusheen/FreetonVPN/releases/download/v2.5/FreetonVPN.exe",
            "file_size_bytes": 15_000_000,
            "sha256": "ABCDEF1234567890",
            "mandatory": true,
            "min_supported_version": "2.0"
        });
        let info = parse_json_update_info(&sample_json).expect("valid manifest json");
        assert_eq!(info.version, "2.5");
        assert_eq!(info.title, "Bản cập nhật v2.5");
        assert_eq!(info.changelog.len(), 2);
        assert_eq!(info.sha256, "abcdef1234567890");
        assert!(info.mandatory);
        assert_eq!(info.min_supported_version, "2.0");
        assert!(info.formatted_changelog().contains("Tối ưu ping"));

        let sample_gh = serde_json::json!({
            "tag_name": "v2.5",
            "name": "Freeton VPN 2.5 Release",
            "published_at": "2026-09-01T12:00:00Z",
            "body": "- Tối ưu kết nối\n- Nâng cấp UI",
            "assets": [
                {
                    "name": "FreetonVPN.exe",
                    "browser_download_url": "https://github.com/datpusheen/FreetonVPN/releases/download/v2.5/FreetonVPN.exe",
                    "size": 18_000_000
                }
            ]
        });
        let (gh_info, sha_asset_url) =
            parse_github_release_info(&sample_gh).expect("valid github json");
        assert_eq!(gh_info.version, "2.5");
        assert_eq!(gh_info.release_date, "2026-09-01");
        assert_eq!(
            gh_info.download_url,
            "https://github.com/datpusheen/FreetonVPN/releases/download/v2.5/FreetonVPN.exe"
        );
        assert_eq!(gh_info.file_size_bytes, 18_000_000);
        assert_eq!(gh_info.changelog.len(), 2);
        assert!(sha_asset_url.is_none());

        let dir = temp_dir("sha256_file");
        let file_path = dir.join("payload.bin");
        fs::write(&file_path, b"Hello Freeton VPN Updater Test").expect("write test payload");
        let expected = encode_hex_lower(&Sha256::digest(b"Hello Freeton VPN Updater Test"));
        let calculated = compute_file_sha256(&file_path).expect("compute file sha256");
        assert_eq!(calculated, expected);
        let _ = fs::remove_dir_all(&dir);

        let digest_a = "a".repeat(64);
        let digest_b = "b".repeat(64);
        assert_eq!(
            parse_sha256_text(
                &format!(
                    "SHA256 (FreetonVPN-Setup-x64.exe) = {}",
                    digest_a.to_ascii_uppercase()
                ),
                Some("FreetonVPN-Setup-x64.exe")
            ),
            Some(digest_a.clone())
        );
        assert_eq!(
            parse_sha256_text(
                &format!("{digest_b} *other.exe\n{digest_a}  FreetonVPN-Setup-x64.exe"),
                Some("FreetonVPN-Setup-x64.exe")
            ),
            Some(digest_a)
        );
        assert_eq!(
            parse_sha256_text(
                &format!("{digest_b}  other1.exe\n{digest_b}  other2.exe"),
                Some("FreetonVPN-Setup-x64.exe")
            ),
            None
        );
    }

    #[tokio::test]
    async fn test_github_fallback_parses_companion_sha256_or_fails_closed() {
        let installer_bytes = b"MZ-FAKE-NSIS-INSTALLER-PAYLOAD-V3.1.0";
        let valid_sha = encode_hex_lower(&Sha256::digest(installer_bytes));
        let valid_sha_clone = valid_sha.clone();

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let base_url = format!("http://{addr}");
        let base_for_server = base_url.clone();

        let server_task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let sha_hex = valid_sha_clone.clone();
                let base = base_for_server.clone();
                tokio::spawn(async move {
                    let req = read_http_request(&mut socket).await;
                    let path = req
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("");

                    if path.starts_with("/version-rust.json") {
                        let body = "Internal Server Error";
                        let resp = format!(
                            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(resp.as_bytes()).await;
                    } else if path == "/repos/datpusheen/FreetonVPN/releases/latest" {
                        let body = serde_json::json!({
                            "tag_name": "v3.1.0",
                            "name": "Freeton VPN v3.1.0",
                            "published_at": "2026-12-01T10:00:00Z",
                            "body": "- Native Rust update",
                            "assets": [
                                {
                                    "name": "FreetonVPN-Setup-x64.exe",
                                    "browser_download_url": format!("{base}/download/v3.1.0/FreetonVPN-Setup-x64.exe"),
                                    "size": installer_bytes.len()
                                },
                                {
                                    "name": "FreetonVPN-Setup-x64.exe.sha256",
                                    "browser_download_url": format!("{base}/download/v3.1.0/FreetonVPN-Setup-x64.exe.sha256"),
                                    "size": 96
                                }
                            ]
                        })
                        .to_string();
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(resp.as_bytes()).await;
                    } else if path == "/repos/datpusheen/NoHash/releases/latest" {
                        let body = serde_json::json!({
                            "tag_name": "v3.1.0",
                            "name": "Freeton VPN v3.1.0",
                            "published_at": "2026-12-01T10:00:00Z",
                            "body": "- Missing sha256 asset",
                            "assets": [
                                {
                                    "name": "FreetonVPN-Setup-x64.exe",
                                    "browser_download_url": "https://github.com/datpusheen/FreetonVPN/releases/download/v3.1.0/FreetonVPN-Setup-x64.exe",
                                    "size": 100
                                }
                            ]
                        })
                        .to_string();
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(resp.as_bytes()).await;
                    } else if path == "/download/v3.1.0/FreetonVPN-Setup-x64.exe.sha256" {
                        let body = format!(
                            "{}  FreetonVPN-Setup-x64.exe\n",
                            sha_hex.to_ascii_uppercase()
                        );
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(resp.as_bytes()).await;
                    } else if path == "/download/v3.1.0/FreetonVPN-Setup-x64.exe" {
                        let header = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            installer_bytes.len()
                        );
                        let _ = socket.write_all(header.as_bytes()).await;
                        let _ = socket.write_all(installer_bytes).await;
                    } else {
                        let _ = socket
                            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                            .await;
                    }
                });
            }
        });

        // 1. Companion .sha256 asset populates sha256 when version-rust.json fails.
        let manifest_url = format!("{base_url}/version-rust.json");
        let with_hash = fetch_update_info_with_base(
            Some(&manifest_url),
            Some("datpusheen/FreetonVPN"),
            Some(&base_url),
        )
        .await
        .expect("fallback request succeeds")
        .expect("update info returned");
        assert_eq!(with_hash.version, "3.1.0");
        assert_eq!(with_hash.sha256, valid_sha);

        // 2. Absent .sha256 asset -> sha256 empty -> fail-closed browser fallback without touching disk.
        let no_hash = fetch_update_info_with_base(
            Some(&manifest_url),
            Some("datpusheen/NoHash"),
            Some(&base_url),
        )
        .await
        .expect("no-hash fallback succeeds")
        .expect("update info returned");
        assert!(no_hash.sha256.is_empty());

        let missing_dir = temp_dir("missing_sha");
        let action = download_and_verify_update(&no_hash, &missing_dir, |_, _, _| {})
            .await
            .expect("missing sha256 fails closed via browser fallback");
        match action {
            UpdateAction::OpenReleasePageInBrowser(url) => {
                assert!(
                    url.contains("https://github.com/datpusheen/FreetonVPN/releases/tag/v3.1.0")
                );
            }
            other => panic!("expected OpenReleasePageInBrowser, got {other:?}"),
        }
        assert_eq!(fs::read_dir(&missing_dir).expect("read dir").count(), 0);
        let _ = fs::remove_dir_all(&missing_dir);

        // 3. Invalid non-64-hex sha256 also fails closed via browser fallback.
        let mut invalid_hash_info = with_hash.clone();
        invalid_hash_info.sha256 = "abcdef".to_owned();
        let invalid_dir = temp_dir("invalid_sha");
        let invalid_action =
            download_and_verify_update(&invalid_hash_info, &invalid_dir, |_, _, _| {})
                .await
                .expect("invalid sha256 fails closed via browser fallback");
        assert!(matches!(
            invalid_action,
            UpdateAction::OpenReleasePageInBrowser(_)
        ));
        assert_eq!(fs::read_dir(&invalid_dir).expect("read dir").count(), 0);
        let _ = fs::remove_dir_all(&invalid_dir);

        // 4. Mismatched SHA-256 -> Err(UpdateError::ChecksumMismatch) and deletes .part & final file.
        let mut bad_hash_info = with_hash.clone();
        bad_hash_info.sha256 = "0".repeat(64);
        let mismatch_dir = temp_dir("mismatch_sha");
        let err = download_and_verify_update(&bad_hash_info, &mismatch_dir, |_, _, _| {})
            .await
            .expect_err("checksum mismatch must error");
        assert!(matches!(err, UpdateError::ChecksumMismatch { .. }));
        assert_eq!(fs::read_dir(&mismatch_dir).expect("read dir").count(), 0);
        let _ = fs::remove_dir_all(&mismatch_dir);

        server_task.abort();
    }

    #[tokio::test]
    async fn test_manifest_priority_and_verified_streaming_download() {
        let payload = b"VERIFIED-RUST-INSTALLER-BYTES-1234567890";
        let expected_sha = encode_hex_lower(&Sha256::digest(payload));
        let expected_sha_clone = expected_sha.clone();

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let base_url = format!("http://{addr}");
        let base_for_server = base_url.clone();

        let server_task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let sha_hex = expected_sha_clone.clone();
                let base = base_for_server.clone();
                tokio::spawn(async move {
                    let req = read_http_request(&mut socket).await;
                    let path = req
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("");

                    if path.starts_with("/version-rust.json") {
                        let body = serde_json::json!({
                            "version": "3.2.0",
                            "release_date": "2026-12-15",
                            "title": "Freeton VPN v3.2.0",
                            "changelog": ["New Win32 pinger"],
                            "download_url": format!("{base}/files/FreetonVPN-Setup-x64.exe"),
                            "file_size_bytes": payload.len(),
                            "sha256": sha_hex,
                            "mandatory": false,
                            "min_supported_version": "3.0.0"
                        })
                        .to_string();
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(resp.as_bytes()).await;
                    } else if path == "/files/FreetonVPN-Setup-x64.exe" {
                        let header = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            payload.len()
                        );
                        let _ = socket.write_all(header.as_bytes()).await;
                        let _ = socket.write_all(payload).await;
                    } else {
                        let _ = socket
                            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                            .await;
                    }
                });
            }
        });

        let manifest_url = format!("{base_url}/version-rust.json");
        let info = fetch_update_info_with_base(
            Some(&manifest_url),
            Some("datpusheen/FreetonVPN"),
            Some(&base_url),
        )
        .await
        .expect("manifest succeeds")
        .expect("manifest parsed");
        assert_eq!(info.version, "3.2.0");
        assert_eq!(info.sha256, expected_sha);

        let dest_dir = temp_dir("verified_download");
        let progress_events: Arc<Mutex<Vec<(u64, u64, f32)>>> = Arc::new(Mutex::new(Vec::new()));
        let events_clone = Arc::clone(&progress_events);

        let action = download_and_verify_update(&info, &dest_dir, move |d, t, p| {
            events_clone.lock().expect("progress lock").push((d, t, p));
        })
        .await
        .expect("verified download succeeds");

        match action {
            UpdateAction::LaunchVerifiedInstaller(path) => {
                assert_eq!(path, dest_dir.join("FreetonVPN-Setup-x64.exe"));
                assert_eq!(fs::read(&path).expect("read downloaded"), payload);
                assert!(!dest_dir.join("FreetonVPN-Setup-x64.exe.part").exists());
            }
            other => panic!("expected LaunchVerifiedInstaller, got {other:?}"),
        }

        let recorded = progress_events.lock().expect("progress lock");
        let last = recorded.last().expect("at least one progress callback");
        assert_eq!(last.0, payload.len() as u64);
        assert_eq!(last.1, payload.len() as u64);
        assert!((last.2 - 100.0).abs() < 0.01);

        drop(recorded);
        let _ = fs::remove_dir_all(&dest_dir);
        server_task.abort();
    }
}
