use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use reqwest::{Client, Method, StatusCode};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use tokio::sync::Mutex;
use url::Url;

use crate::srp::{
    create_srp_proof, ed25519_pem_to_wireguard_privkey, verify_server_proof, SrpChallenge, SrpError,
};
use crate::storage::{ClientConfig, CredentialStore, StorageError, StoredAuthSession};
use crate::APP_VERSION;

/// Primary Proton SRP authentication API host.
pub const DEFAULT_AUTH_BASE_URL: &str = "https://api.protonmail.ch";

/// Ordered Proton VPN API hosts tried when switching away from unreachable or blocked hosts.
pub const DEFAULT_VPN_BASE_URLS: &[&str] = &[
    "https://account.protonvpn.com/api",
    "https://api.protonmail.ch",
    "https://account.proton.me/api",
];

/// Public IP lookup endpoint used to display the active exit IP address.
pub const DEFAULT_PUBLIC_IP_URL: &str = "https://api.ipify.org?format=json";

/// Proton API client identifier header (`x-pm-appversion`).
pub const PROTON_APP_VERSION: &str = "Other";

/// Proton API locale header (`x-pm-locale`).
pub const PROTON_LOCALE: &str = "en_US";

/// Proactive WireGuard certificate renewal threshold in seconds (2 hours).
pub const WG_KEY_REFRESH_WINDOW_SECS: i64 = 7_200;

const ALLOWED_HV_HOSTS: &[&str] = &[
    "verify.proton.me",
    "account.proton.me",
    "account.protonvpn.com",
];

const PROTON_CODE_SUCCESS: i64 = 1000;
const PROTON_CODE_SUCCESS_ALT: i64 = 1001;
const PROTON_CODE_HUMAN_VERIFICATION_REQUIRED: i64 = 9001;
const PROTON_CODE_HUMAN_VERIFICATION_INVALID: i64 = 12087;

/// Errors returned by Proton SRP login, 2FA, token refresh, logical server fetch, key registration,
/// and exit IP lookups.
#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Chưa có phiên đăng nhập Proton.")]
    NotAuthenticated,
    #[error("Lỗi SRP: {0}")]
    Srp(#[from] SrpError),
    #[error("Lỗi lưu trữ thông tin đăng nhập: {0}")]
    Storage(#[from] StorageError),
    #[error("Lỗi kết nối mạng: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Phản hồi Proton API không hợp lệ: {0}")]
    InvalidResponse(String),
    #[error("Dữ liệu đầu vào không hợp lệ: {0}")]
    InvalidInput(String),
    #[error("Không thể xác minh chữ ký máy chủ Proton (ServerProof).")]
    ServerProofRejected,
    #[error("URL xác minh người dùng (CAPTCHA) không hợp lệ: {0}")]
    InvalidHumanVerificationUrl(String),
    #[error(
        "Phiên Proton đã hết hạn hoặc bị từ chối (HTTP {http_status}, Code {api_code}): {message}"
    )]
    Unauthorized {
        http_status: u16,
        api_code: i64,
        message: String,
    },
    #[error(
        "Phiên đăng nhập Proton đã hết hạn hoặc bị thu hồi (HTTP {http_status}, Code {api_code}): {message}"
    )]
    SessionExpired {
        http_status: u16,
        api_code: i64,
        message: String,
    },
    #[error("Proton API trả về lỗi (HTTP {http_status}, Code {api_code}): {message}")]
    Proton {
        http_status: u16,
        api_code: i64,
        message: String,
    },
}

impl ApiError {
    /// Returns the HTTP status code associated with this error, if any.
    pub fn http_status(&self) -> Option<u16> {
        match self {
            Self::Unauthorized { http_status, .. }
            | Self::SessionExpired { http_status, .. }
            | Self::Proton { http_status, .. } => Some(*http_status),
            Self::Network(err) => err.status().map(|s| s.as_u16()),
            _ => None,
        }
    }

    /// Returns the Proton JSON `Code` field associated with this error, if any.
    pub fn api_code(&self) -> Option<i64> {
        match self {
            Self::Unauthorized { api_code, .. }
            | Self::SessionExpired { api_code, .. }
            | Self::Proton { api_code, .. } => Some(*api_code),
            _ => None,
        }
    }

    /// Returns true when the Proton refresh token itself was definitively rejected (400/401/422).
    pub fn is_session_expired(&self) -> bool {
        matches!(self, Self::SessionExpired { .. })
    }
}

fn deserialize_null_f64_opt<'de, D>(deserializer: D) -> Result<Option<f64>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<f64>::deserialize(deserializer)
}

fn deserialize_null_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?.unwrap_or_default())
}

fn deserialize_null_i64<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<i64>::deserialize(deserializer)?.unwrap_or_default())
}

fn deserialize_null_usize<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<usize>::deserialize(deserializer)?.unwrap_or_default())
}

/// Normalized Proton free WireGuard server node matching `servers_cache.json` layout.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServerNode {
    #[serde(default, deserialize_with = "deserialize_null_string")]
    pub name: String,
    #[serde(default, deserialize_with = "deserialize_null_string")]
    pub country: String,
    #[serde(
        rename = "entryCountry",
        default,
        deserialize_with = "deserialize_null_string"
    )]
    pub entry_country: String,
    #[serde(default, deserialize_with = "deserialize_null_string")]
    pub city: String,
    #[serde(default, deserialize_with = "deserialize_null_f64_opt")]
    pub load: Option<f64>,
    #[serde(default, deserialize_with = "deserialize_null_i64")]
    pub status: i64,
    #[serde(default, deserialize_with = "deserialize_null_string")]
    pub domain: String,
    #[serde(
        rename = "entryIP",
        default,
        deserialize_with = "deserialize_null_string"
    )]
    pub entry_ip: String,
    #[serde(
        rename = "exitIP",
        default,
        deserialize_with = "deserialize_null_string"
    )]
    pub exit_ip: String,
    #[serde(
        rename = "x25519PublicKey",
        default,
        deserialize_with = "deserialize_null_string"
    )]
    pub x25519_public_key: String,
    #[serde(
        rename = "activePhysicalServers",
        default,
        deserialize_with = "deserialize_null_usize"
    )]
    pub active_physical_servers: usize,
    #[serde(
        rename = "pingTarget",
        default,
        deserialize_with = "deserialize_null_string"
    )]
    pub ping_target: String,
    #[serde(
        rename = "pingMs",
        default,
        deserialize_with = "deserialize_null_f64_opt"
    )]
    pub ping_ms: Option<f64>,
    #[serde(default, deserialize_with = "deserialize_null_f64_opt")]
    pub latitude: Option<f64>,
    #[serde(default, deserialize_with = "deserialize_null_f64_opt")]
    pub longitude: Option<f64>,
}

/// User's physical/un-tunneled geographic coordinates resolved from Proton `/vpn/v1/location`
/// (or offline Windows region fallback).
#[derive(Debug, Clone, PartialEq)]
pub struct UserLocation {
    pub country: Option<String>,
    pub lat: f32,
    pub lon: f32,
}

/// Parses Proton's `/vpn/v1/location` payload into validated geographic coordinates.
pub fn parse_user_location_payload(payload: &Value) -> Result<UserLocation, ApiError> {
    let raw_lat = payload
        .get("Lat")
        .or_else(|| payload.get("Latitude"))
        .and_then(Value::as_f64);
    let raw_lon = payload
        .get("Long")
        .or_else(|| payload.get("Longitude"))
        .and_then(Value::as_f64);
    let (Some(lat), Some(lon)) = (raw_lat, raw_lon) else {
        return Err(ApiError::InvalidResponse(
            "Location payload missing finite Lat/Long coordinates".to_owned(),
        ));
    };
    if !lat.is_finite() || !lon.is_finite() || !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        return Err(ApiError::InvalidResponse(format!(
            "Location payload coordinates out of range: ({lat}, {lon})"
        )));
    }
    let country = payload
        .get("Country")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_uppercase());
    Ok(UserLocation {
        country,
        lat: lat as f32,
        lon: lon as f32,
    })
}

/// Solved CAPTCHA / human verification token passed when retrying `ProtonClient::login_srp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HumanVerificationToken {
    pub token: String,
    pub token_type: String,
}

impl HumanVerificationToken {
    pub fn new(token: impl Into<String>, methods: &[String]) -> Self {
        let token_type = if methods.is_empty() {
            "captcha".to_owned()
        } else {
            methods.join(",")
        };
        Self {
            token: token.into(),
            token_type,
        }
    }
}

/// Challenge details emitted when Proton asks for CAPTCHA / human verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanVerificationChallenge {
    pub url: String,
    pub methods: Vec<String>,
}

/// Result of `ProtonClient::login_srp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginOutcome {
    Authenticated(StoredAuthSession),
    NeedsTwoFactor(StoredAuthSession),
    NeedsHumanVerification { url: String, methods: Vec<String> },
}

/// Trims outer whitespace from a 2FA or recovery code without stripping non-digit characters.
pub fn normalize_2fa_code(code: &str) -> Result<String, ApiError> {
    let trimmed = code.trim();
    if trimmed.is_empty() {
        return Err(ApiError::InvalidInput(
            "Vui lòng nhập mã 2FA để tiếp tục.".to_owned(),
        ));
    }
    Ok(trimmed.to_owned())
}

/// Returns `true` when a Proton physical server entry is online and has `ServicesDown == 0`.
pub fn is_usable_physical_server(server: &Value) -> bool {
    let status = server.get("Status").and_then(Value::as_i64);
    let services_down = server.get("ServicesDown").and_then(Value::as_i64);
    status == Some(1) && services_down == Some(0)
}

fn first_non_empty(candidates: &[Option<&str>]) -> String {
    for value in candidates.iter().flatten() {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return trimmed.to_owned();
        }
    }
    String::new()
}

/// Filters Proton's `/vpn/v1/logicals` JSON payload for Tier 0 (Free) servers with usable WireGuard
/// physical nodes, matching `select_free_servers_with_wg` in `proton_warp_material_gui.py`.
pub fn select_free_servers_with_wg(
    payload: &Value,
    country: Option<&str>,
    include_down: bool,
) -> Result<Vec<ServerNode>, ApiError> {
    let logical_servers = payload
        .get("LogicalServers")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ApiError::InvalidResponse("Response không có mảng LogicalServers hợp lệ.".to_owned())
        })?;

    let country_filter = country.map(str::trim).filter(|c| !c.is_empty());
    let mut selected = Vec::new();

    for server in logical_servers {
        if server.get("Tier").and_then(Value::as_i64) != Some(0) {
            continue;
        }
        let exit_country = server
            .get("ExitCountry")
            .and_then(Value::as_str)
            .unwrap_or("");
        let entry_country = server
            .get("EntryCountry")
            .and_then(Value::as_str)
            .unwrap_or("");
        if let Some(code) = country_filter {
            if code != entry_country && code != exit_country {
                continue;
            }
        }

        let physicals = server
            .get("Servers")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let active_physicals: Vec<&Value> = physicals
            .iter()
            .filter(|phys| is_usable_physical_server(phys))
            .collect();

        let logical_status = server.get("Status").and_then(Value::as_i64).unwrap_or(0);
        if !include_down && (logical_status != 1 || active_physicals.is_empty()) {
            continue;
        }

        let first_phys = active_physicals.first().copied();
        let server_domain = server.get("Domain").and_then(Value::as_str);
        let phys_domain = first_phys.and_then(|p| p.get("Domain").and_then(Value::as_str));
        let phys_entry_ip = first_phys.and_then(|p| p.get("EntryIP").and_then(Value::as_str));
        let phys_exit_ip = first_phys.and_then(|p| p.get("ExitIP").and_then(Value::as_str));
        let phys_x25519 = first_phys.and_then(|p| p.get("X25519PublicKey").and_then(Value::as_str));
        let phys_pubkey = first_phys.and_then(|p| p.get("PublicKey").and_then(Value::as_str));

        let entry_ip = first_non_empty(&[phys_entry_ip, phys_domain, server_domain]);
        let exit_ip = first_non_empty(&[phys_exit_ip, Some(entry_ip.as_str())]);
        let domain = first_non_empty(&[phys_domain, server_domain]);
        let x25519_public_key = first_non_empty(&[phys_x25519, phys_pubkey]);

        let load_val = server.get("Load").and_then(Value::as_f64).unwrap_or(0.0);
        let location = server.get("Location");
        let raw_lat = location.and_then(|loc| loc.get("Lat")).and_then(Value::as_f64);
        let raw_lon = location
            .and_then(|loc| loc.get("Long"))
            .and_then(Value::as_f64);
        let (latitude, longitude) = match (raw_lat, raw_lon) {
            (Some(lat), Some(lon))
                if lat.is_finite()
                    && lon.is_finite()
                    && (-90.0..=90.0).contains(&lat)
                    && (-180.0..=180.0).contains(&lon) =>
            {
                (Some(lat), Some(lon))
            }
            _ => (None, None),
        };

        selected.push(ServerNode {
            name: server
                .get("Name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            country: exit_country.to_owned(),
            entry_country: entry_country.to_owned(),
            city: server
                .get("City")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            load: Some(load_val),
            status: logical_status,
            domain,
            entry_ip: entry_ip.clone(),
            exit_ip,
            x25519_public_key,
            active_physical_servers: active_physicals.len(),
            ping_target: entry_ip,
            ping_ms: None,
            latitude,
            longitude,
        });
    }

    selected.sort_by(|a, b| {
        a.load
            .unwrap_or(0.0)
            .total_cmp(&b.load.unwrap_or(0.0))
            .then_with(|| a.name.cmp(&b.name))
    });

    Ok(selected)
}

/// Builds and validates a Proton human verification URL with `ForceWebMessaging=1` appended.
pub fn extract_human_verification(details: &Value) -> Result<(String, Vec<String>), ApiError> {
    let parse_methods = |val: &Value| -> Vec<String> {
        val.as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .take(8)
                    .collect()
            })
            .unwrap_or_default()
    };
    let primary_methods = details
        .get("Methods")
        .map(parse_methods)
        .unwrap_or_default();
    let methods = if primary_methods.is_empty() {
        details
            .get("HumanVerificationMethods")
            .map(parse_methods)
            .unwrap_or_default()
    } else {
        primary_methods
    };

    let mut url = if let Some(web_url) = details
        .get("WebUrl")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Url::parse(web_url).map_err(|err| {
            ApiError::InvalidHumanVerificationUrl(format!("Invalid WebUrl: {err}"))
        })?
    } else {
        let token = details
            .get("HumanVerificationToken")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                ApiError::InvalidHumanVerificationUrl(
                    "Missing WebUrl and HumanVerificationToken".to_owned(),
                )
            })?;
        let mut built = Url::parse("https://verify.proton.me/")
            .map_err(|err| ApiError::InvalidHumanVerificationUrl(err.to_string()))?;
        let methods_param = if methods.is_empty() {
            "captcha".to_owned()
        } else {
            methods.join(",")
        };
        built
            .query_pairs_mut()
            .append_pair("methods", &methods_param)
            .append_pair("token", token);
        built
    };

    let host = url
        .host_str()
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if url.scheme() != "https" || !ALLOWED_HV_HOSTS.contains(&host.as_str()) {
        return Err(ApiError::InvalidHumanVerificationUrl(format!(
            "Disallowed verification URL host or scheme: {}",
            url
        )));
    }

    let preserved_pairs: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(key, _)| key != "ForceWebMessaging")
        .map(|(key, val)| (key.into_owned(), val.into_owned()))
        .collect();
    {
        let mut query = url.query_pairs_mut();
        query.clear();
        for (key, val) in preserved_pairs {
            query.append_pair(&key, &val);
        }
        query.append_pair("ForceWebMessaging", "1");
    }

    Ok((url.to_string(), methods))
}

struct ParsedProtonResponse {
    status: StatusCode,
    payload: Value,
    code: i64,
    error_message: String,
}

/// Async Proton API client handling SRP authentication, 2FA, CAPTCHA challenge extraction,
/// serialized `401` token refresh, WireGuard certificate key provisioning, and exit IP lookup.
pub struct ProtonClient {
    http: Client,
    store: Arc<dyn CredentialStore>,
    auth_base_url: String,
    vpn_base_urls: Vec<String>,
    public_ip_url: String,
    refresh_mutex: Mutex<()>,
    refresh_generation: AtomicU64,
    wg_key_mutex: Mutex<()>,
    pending_login_account: Mutex<Option<(String, String)>>,
}

impl ProtonClient {
    /// Creates a `ProtonClient` configured with Proton's production API endpoints.
    pub fn new(store: Arc<dyn CredentialStore>) -> Self {
        Self::with_endpoints(
            store,
            DEFAULT_AUTH_BASE_URL.to_owned(),
            DEFAULT_VPN_BASE_URLS
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            DEFAULT_PUBLIC_IP_URL.to_owned(),
        )
    }

    /// Creates a `ProtonClient` with explicit endpoint URLs (useful for mock HTTP server tests).
    pub fn with_endpoints(
        store: Arc<dyn CredentialStore>,
        auth_base_url: String,
        vpn_base_urls: Vec<String>,
        public_ip_url: String,
    ) -> Self {
        let http = Client::builder()
            .connect_timeout(Duration::from_secs(8))
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_default();

        Self {
            http,
            store,
            auth_base_url,
            vpn_base_urls,
            public_ip_url,
            refresh_mutex: Mutex::new(()),
            refresh_generation: AtomicU64::new(0),
            wg_key_mutex: Mutex::new(()),
            pending_login_account: Mutex::new(None),
        }
    }

    /// Returns a reference to the backing credential store.
    pub fn store(&self) -> &Arc<dyn CredentialStore> {
        &self.store
    }

    /// Performs Proton SRP v3/v4 authentication against `/auth/info` and `/auth`.
    pub async fn login_srp(
        &self,
        username: &str,
        password: &str,
        human_verification: Option<HumanVerificationToken>,
    ) -> Result<LoginOutcome, ApiError> {
        let user = username.trim().to_owned();
        if user.is_empty() || password.is_empty() {
            return Err(ApiError::Srp(SrpError::MissingCredentials));
        }

        let mut extra_headers = HeaderMap::new();
        if let Some(hv) = human_verification.as_ref() {
            let token_header = HeaderValue::from_str(hv.token.trim()).map_err(|_| {
                ApiError::InvalidInput("Invalid human verification token header".to_owned())
            })?;
            let token_type_str = if hv.token_type.trim().is_empty() {
                "captcha"
            } else {
                hv.token_type.trim()
            };
            let type_header = HeaderValue::from_str(token_type_str).map_err(|_| {
                ApiError::InvalidInput("Invalid human verification token type header".to_owned())
            })?;
            extra_headers.insert("x-pm-human-verification-token", token_header);
            extra_headers.insert("x-pm-human-verification-token-type", type_header);
        }

        let info_resp = self
            .send_proton_request(
                &self.auth_base_url,
                "auth/info",
                Method::POST,
                Some(&json!({ "Username": user })),
                None,
                Some(&extra_headers),
            )
            .await?;
        if let Some(hv) = Self::maybe_human_verification(&info_resp)? {
            return Ok(hv);
        }
        let info = Self::ensure_success(info_resp)?;

        let version = info
            .get("Version")
            .and_then(Value::as_u64)
            .and_then(|v| u8::try_from(v).ok())
            .ok_or_else(|| {
                ApiError::InvalidResponse("Missing SRP Version in /auth/info".to_owned())
            })?;
        let srp_session = Self::require_non_empty_str(&info, "SRPSession")?;
        let modulus_armored = Self::require_non_empty_str(&info, "Modulus")?;
        let server_ephemeral_b64 = Self::require_non_empty_str(&info, "ServerEphemeral")?;
        let salt_b64 = Self::require_non_empty_str(&info, "Salt")?;

        let challenge = SrpChallenge {
            version,
            modulus_armored,
            server_ephemeral_b64,
            salt_b64,
        };
        let user_for_srp = user.clone();
        let password_owned = password.to_owned();
        let proof = tokio::task::spawn_blocking(move || {
            create_srp_proof(&challenge, &user_for_srp, &password_owned)
        })
        .await
        .map_err(|err| ApiError::InvalidResponse(format!("SRP worker panicked: {err}")))??;

        let auth_resp = self
            .send_proton_request(
                &self.auth_base_url,
                "auth",
                Method::POST,
                Some(&json!({
                    "Username": user,
                    "ClientEphemeral": proof.client_ephemeral_b64,
                    "ClientProof": proof.client_proof_b64,
                    "SRPSession": srp_session,
                })),
                None,
                Some(&extra_headers),
            )
            .await?;
        if let Some(hv) = Self::maybe_human_verification(&auth_resp)? {
            return Ok(hv);
        }
        let auth_data = Self::ensure_success(auth_resp)?;

        let server_proof_b64 = Self::require_non_empty_str(&auth_data, "ServerProof")?;
        if !verify_server_proof(&proof.expected_server_proof, &server_proof_b64) {
            return Err(ApiError::ServerProofRejected);
        }

        let session = StoredAuthSession {
            uid: Self::require_non_empty_str(&auth_data, "UID")?,
            access_token: Self::require_non_empty_str(&auth_data, "AccessToken")?,
            refresh_token: Self::require_non_empty_str(&auth_data, "RefreshToken")?,
            scopes: Self::parse_scopes(&auth_data),
        };

        if session.scopes.iter().any(|scope| scope == "twofactor") {
            *self.pending_login_account.lock().await = Some((session.uid.clone(), user));
            return Ok(LoginOutcome::NeedsTwoFactor(session));
        }

        *self.pending_login_account.lock().await = None;
        self.store.save_auth_session(&user, &session)?;
        Ok(LoginOutcome::Authenticated(session))
    }

    /// Submits a 2FA or recovery code for a pending SRP session (`Scopes` containing `"twofactor"`),
    /// trimming outer whitespace without stripping non-digit recovery characters.
    pub async fn submit_2fa(
        &self,
        pending: &StoredAuthSession,
        code: &str,
    ) -> Result<StoredAuthSession, ApiError> {
        let normalized_code = normalize_2fa_code(code)?;
        let resp = self
            .send_proton_request(
                &self.auth_base_url,
                "auth/2fa",
                Method::POST,
                Some(&json!({ "TwoFactorCode": normalized_code })),
                Some(pending),
                None,
            )
            .await?;
        let data = Self::ensure_success(resp)?;
        let scopes = if data.get("Scopes").is_some() {
            Self::parse_scopes(&data)
        } else {
            pending.scopes.clone()
        };

        let completed = StoredAuthSession {
            uid: pending.uid.clone(),
            access_token: pending.access_token.clone(),
            refresh_token: pending.refresh_token.clone(),
            scopes,
        };

        let pending_account = self.pending_login_account.lock().await.take();
        if let Some((uid, account)) = pending_account {
            if uid == completed.uid {
                self.store.save_auth_session(&account, &completed)?;
            }
        }

        Ok(completed)
    }

    /// Executes an authenticated Proton VPN API request across configured fallback hosts,
    /// serializing `401` token refreshes via `tokio::sync::Mutex` and retrying once.
    pub async fn api_request(
        &self,
        path: &str,
        method: Method,
        json_body: Option<&Value>,
    ) -> Result<Value, ApiError> {
        let (_, mut session) = self
            .store
            .load_auth_session()?
            .ok_or(ApiError::NotAuthenticated)?;

        let mut last_error: Option<ApiError> = None;

        for attempt in 0..2 {
            let used_access_token = session.access_token.clone();
            let gen_at_start = self.refresh_generation.load(Ordering::Acquire);
            let mut need_refresh = false;

            for base in &self.vpn_base_urls {
                tracing::debug!(method = %method, path, base, attempt, "Proton API request");
                match self
                    .send_proton_request(
                        base,
                        path,
                        method.clone(),
                        json_body,
                        Some(&session),
                        None,
                    )
                    .await
                {
                    Ok(resp) if resp.status == StatusCode::UNAUTHORIZED => {
                        tracing::warn!(method = %method, path, base, attempt, "Proton API returned 401 Unauthorized");
                        last_error = Some(Self::response_to_error(&resp));
                        if attempt == 0 {
                            need_refresh = true;
                            break;
                        }
                    }
                    Ok(resp) if resp.status.is_success() && Self::is_success_code(resp.code) => {
                        tracing::debug!(method = %method, path, base, http_status = resp.status.as_u16(), "Proton API request succeeded");
                        return Ok(resp.payload);
                    }
                    Ok(resp) => {
                        let can_try_next = matches!(
                            resp.status,
                            StatusCode::FORBIDDEN
                                | StatusCode::NOT_FOUND
                                | StatusCode::METHOD_NOT_ALLOWED
                                | StatusCode::REQUEST_TIMEOUT
                                | StatusCode::BAD_GATEWAY
                                | StatusCode::SERVICE_UNAVAILABLE
                                | StatusCode::GATEWAY_TIMEOUT
                        );
                        let err = Self::response_to_error(&resp);
                        if can_try_next {
                            tracing::warn!(method = %method, path, base, http_status = resp.status.as_u16(), "Proton API host failed with retryable status; trying fallback");
                            last_error = Some(err);
                            continue;
                        }
                        tracing::warn!(method = %method, path, base, error = %err, "Proton API returned error");
                        return Err(err);
                    }
                    Err(err) => {
                        tracing::warn!(method = %method, path, base, error = %err, "Proton API transport error; trying fallback");
                        last_error = Some(err);
                    }
                }
            }

            if need_refresh && attempt == 0 {
                session = self
                    .refresh_token_serialized(&used_access_token, gen_at_start)
                    .await?;
                continue;
            }
            break;
        }

        Err(last_error.unwrap_or(ApiError::NotAuthenticated))
    }

    async fn refresh_token_serialized(
        &self,
        failed_access_token: &str,
        expected_generation: u64,
    ) -> Result<StoredAuthSession, ApiError> {
        let _guard = self.refresh_mutex.lock().await;

        let (_, current) = self
            .store
            .load_auth_session()?
            .ok_or(ApiError::NotAuthenticated)?;

        // Another concurrent task already refreshed and persisted a new token while we waited.
        if self.refresh_generation.load(Ordering::Acquire) != expected_generation
            || current.access_token != failed_access_token
        {
            return Ok(current);
        }

        if current.uid.trim().is_empty() || current.refresh_token.trim().is_empty() {
            return Err(ApiError::NotAuthenticated);
        }

        let refresh_auth = StoredAuthSession {
            uid: current.uid.clone(),
            access_token: String::new(),
            refresh_token: current.refresh_token.clone(),
            scopes: current.scopes.clone(),
        };
        let body = json!({
            "ResponseType": "token",
            "GrantType": "refresh_token",
            "RefreshToken": current.refresh_token,
        });

        let mut last_error: Option<ApiError> = None;
        let mut refresh_bases = vec![self.auth_base_url.as_str()];
        for base in &self.vpn_base_urls {
            if !refresh_bases.contains(&base.as_str()) {
                refresh_bases.push(base.as_str());
            }
        }

        tracing::info!("Refreshing Proton access token via auth/v4/refresh");
        for base in refresh_bases {
            match self
                .send_proton_request(
                    base,
                    "auth/v4/refresh",
                    Method::POST,
                    Some(&body),
                    Some(&refresh_auth),
                    None,
                )
                .await
            {
                Ok(resp) if resp.status.is_success() && Self::is_success_code(resp.code) => {
                    let new_access = Self::require_non_empty_str(&resp.payload, "AccessToken")?;
                    let new_refresh = resp
                        .payload
                        .get("RefreshToken")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned)
                        .unwrap_or_else(|| current.refresh_token.clone());
                    let new_scopes = if resp.payload.get("Scopes").is_some() {
                        Self::parse_scopes(&resp.payload)
                    } else {
                        current.scopes.clone()
                    };

                    let updated = StoredAuthSession {
                        uid: current.uid.clone(),
                        access_token: new_access,
                        refresh_token: new_refresh,
                        scopes: new_scopes,
                    };
                    self.store.update_auth_session(&updated)?;
                    self.refresh_generation.fetch_add(1, Ordering::Release);
                    tracing::info!(base, "Proton access token refreshed cleanly");
                    return Ok(updated);
                }
                Ok(resp) => {
                    let can_try_next = matches!(
                        resp.status,
                        StatusCode::NOT_FOUND
                            | StatusCode::METHOD_NOT_ALLOWED
                            | StatusCode::BAD_GATEWAY
                            | StatusCode::SERVICE_UNAVAILABLE
                            | StatusCode::GATEWAY_TIMEOUT
                    );
                    let err = Self::response_to_error(&resp);
                    if can_try_next {
                        last_error = Some(err);
                        continue;
                    }
                    if matches!(
                        resp.status,
                        StatusCode::BAD_REQUEST
                            | StatusCode::UNAUTHORIZED
                            | StatusCode::UNPROCESSABLE_ENTITY
                    ) {
                        let message = if resp.error_message.is_empty() {
                            format!("HTTP {}", resp.status.as_u16())
                        } else {
                            resp.error_message.clone()
                        };
                        tracing::warn!(
                            base,
                            http_status = resp.status.as_u16(),
                            api_code = resp.code,
                            %message,
                            "Proton rejected refresh token; marking session expired"
                        );
                        return Err(ApiError::SessionExpired {
                            http_status: resp.status.as_u16(),
                            api_code: resp.code,
                            message,
                        });
                    }
                    return Err(err);
                }
                Err(err) => {
                    last_error = Some(err);
                }
            }
        }

        // Preserve existing stored credentials on transient network failures.
        Err(last_error.unwrap_or_else(|| ApiError::Unauthorized {
            http_status: 401,
            api_code: 0,
            message: "Refresh failed".to_owned(),
        }))
    }

    /// Fetches `/vpn/v1/logicals?WithIpV6=1` and returns both the raw JSON payload and filtered
    /// free WireGuard server list.
    pub async fn fetch_logicals_raw(&self) -> Result<(Value, Vec<ServerNode>), ApiError> {
        let payload = self
            .api_request("vpn/v1/logicals?WithIpV6=1", Method::GET, None)
            .await?;
        let servers = select_free_servers_with_wg(&payload, None, false)?;
        Ok((payload, servers))
    }

    /// Fetches `/vpn/v1/logicals?WithIpV6=1` and returns the filtered free WireGuard server list.
    pub async fn fetch_logicals(&self) -> Result<Vec<ServerNode>, ApiError> {
        let (_, servers) = self.fetch_logicals_raw().await?;
        Ok(servers)
    }

    /// Queries Proton `/vpn/v1/location` for the client's current IP geolocation.
    pub async fn fetch_user_location(&self) -> Result<UserLocation, ApiError> {
        let payload = self
            .api_request("vpn/v1/location", Method::GET, None)
            .await?;
        parse_user_location_payload(&payload)
    }

    /// Ensures a valid WireGuard client key is registered and stored in `ClientConfig`,
    /// refreshing proactively within `7200` seconds of expiry while preserving static keys (`expiration == 0`).
    pub async fn ensure_wg_key(&self, force: bool) -> Result<ClientConfig, ApiError> {
        let _guard = self.wg_key_mutex.lock().await;
        let current = self.store.load_client_config()?;
        if !force && !current.needs_key_refresh(WG_KEY_REFRESH_WINDOW_SECS) {
            tracing::debug!(expiration = current.expiration, "Existing WireGuard key still usable");
            return Ok(current);
        }

        tracing::info!(force, "Requesting WireGuard keypair and certificate from Proton API");
        let ec_res = self
            .api_request("vpn/v1/certificate/key/EC", Method::GET, None)
            .await?;
        let priv_pem = Self::require_non_empty_str(&ec_res, "PrivateKey")?;
        let pub_pem = Self::require_non_empty_str(&ec_res, "PublicKey")?;

        let reg_body = json!({
            "ClientPublicKey": pub_pem,
            "Platform": "Windows",
            "Features": {},
        });
        let cert_res = self
            .api_request("vpn/v1/certificate", Method::POST, Some(&reg_body))
            .await?;
        let expiration = cert_res
            .get("ExpirationTime")
            .and_then(Value::as_i64)
            .unwrap_or(0);

        let wg_priv = ed25519_pem_to_wireguard_privkey(&priv_pem)?;
        let mut updated = self.store.load_client_config()?;
        updated.private_key = wg_priv;
        updated.public_key = pub_pem;
        updated.expiration = expiration;
        self.store.save_client_config(&updated)?;
        tracing::info!(expiration, "Saved updated WireGuard keypair and certificate");
        Ok(updated)
    }

    /// Queries the public exit IP address from `api.ipify.org?format=json`.
    pub async fn fetch_public_ip(&self) -> Result<String, ApiError> {
        let resp = self
            .http
            .get(&self.public_ip_url)
            .header(USER_AGENT, "curl/7.68.0")
            .timeout(Duration::from_secs(4))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(ApiError::InvalidResponse(format!(
                "Public IP lookup returned HTTP {}",
                resp.status().as_u16()
            )));
        }
        let body: Value = resp.json().await?;
        let ip = Self::require_non_empty_str(&body, "ip")?;
        tracing::info!(%ip, "Resolved public exit IP");
        Ok(ip)
    }

    async fn send_proton_request(
        &self,
        base_url: &str,
        path: &str,
        method: Method,
        json_body: Option<&Value>,
        auth: Option<&StoredAuthSession>,
        extra_headers: Option<&HeaderMap>,
    ) -> Result<ParsedProtonResponse, ApiError> {
        let url = format!(
            "{}/{}",
            base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        );

        let mut req = self
            .http
            .request(method, &url)
            .header(ACCEPT, "application/vnd.protonmail.v1+json")
            .header("x-pm-appversion", PROTON_APP_VERSION)
            .header("x-pm-locale", PROTON_LOCALE)
            .header(USER_AGENT, format!("freeton-vpn/{APP_VERSION} (Windows)"));

        if let Some(session) = auth {
            if !session.uid.trim().is_empty() {
                req = req.header("x-pm-uid", session.uid.trim());
            }
            if !session.access_token.trim().is_empty() {
                req = req.header(
                    AUTHORIZATION,
                    format!("Bearer {}", session.access_token.trim()),
                );
            }
        }
        if let Some(headers) = extra_headers {
            for (name, value) in headers {
                req = req.header(name, value);
            }
        }
        if let Some(body) = json_body {
            req = req.header(CONTENT_TYPE, "application/json").json(body);
        }

        let response = req.send().await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        let payload: Value = if bytes.is_empty() {
            Value::Object(Default::default())
        } else {
            serde_json::from_slice(&bytes).unwrap_or_else(|_| Value::Object(Default::default()))
        };
        let code = payload.get("Code").and_then(Value::as_i64).unwrap_or(0);
        let error_message = payload
            .get("Error")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();

        Ok(ParsedProtonResponse {
            status,
            payload,
            code,
            error_message,
        })
    }

    fn is_success_code(code: i64) -> bool {
        code == PROTON_CODE_SUCCESS || code == PROTON_CODE_SUCCESS_ALT
    }

    fn maybe_human_verification(
        resp: &ParsedProtonResponse,
    ) -> Result<Option<LoginOutcome>, ApiError> {
        if resp.code == PROTON_CODE_HUMAN_VERIFICATION_REQUIRED
            || resp.code == PROTON_CODE_HUMAN_VERIFICATION_INVALID
        {
            let details = resp.payload.get("Details").unwrap_or(&Value::Null);
            let (url, methods) = extract_human_verification(details)?;
            return Ok(Some(LoginOutcome::NeedsHumanVerification { url, methods }));
        }
        Ok(None)
    }

    fn ensure_success(resp: ParsedProtonResponse) -> Result<Value, ApiError> {
        if resp.status.is_success() && Self::is_success_code(resp.code) {
            return Ok(resp.payload);
        }
        Err(Self::response_to_error(&resp))
    }

    fn response_to_error(resp: &ParsedProtonResponse) -> ApiError {
        let message = if resp.error_message.is_empty() {
            format!("HTTP {}", resp.status.as_u16())
        } else {
            resp.error_message.clone()
        };
        if resp.status == StatusCode::UNAUTHORIZED {
            ApiError::Unauthorized {
                http_status: resp.status.as_u16(),
                api_code: resp.code,
                message,
            }
        } else {
            ApiError::Proton {
                http_status: resp.status.as_u16(),
                api_code: resp.code,
                message,
            }
        }
    }

    fn require_non_empty_str(obj: &Value, key: &str) -> Result<String, ApiError> {
        obj.get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| ApiError::InvalidResponse(format!("Missing field `{key}`")))
    }

    fn parse_scopes(obj: &Value) -> Vec<String> {
        obj.get("Scopes")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{
        current_unix_timestamp, ClientConfig, CredentialStore, StorageError, StoredAuthSession,
    };
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use reqwest::Method;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[derive(Default)]
    struct MockCredentialStore {
        entries: Mutex<HashMap<(String, String), String>>,
    }

    impl MockCredentialStore {
        fn with_session(account: &str, session: &StoredAuthSession) -> Self {
            let store = Self::default();
            store
                .save_auth_session(account, session)
                .expect("seed mock session");
            store
        }
    }

    impl CredentialStore for MockCredentialStore {
        fn get_password(
            &self,
            service: &str,
            username: &str,
        ) -> Result<Option<String>, StorageError> {
            Ok(self
                .entries
                .lock()
                .expect("mock lock")
                .get(&(service.to_owned(), username.to_owned()))
                .cloned())
        }

        fn set_password(
            &self,
            service: &str,
            username: &str,
            password: &str,
        ) -> Result<(), StorageError> {
            self.entries.lock().expect("mock lock").insert(
                (service.to_owned(), username.to_owned()),
                password.to_owned(),
            );
            Ok(())
        }

        fn delete_password(&self, service: &str, username: &str) -> Result<(), StorageError> {
            self.entries
                .lock()
                .expect("mock lock")
                .remove(&(service.to_owned(), username.to_owned()));
            Ok(())
        }
    }

    async fn read_http_request(socket: &mut tokio::net::TcpStream) -> String {
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = socket.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
            if let Some(hdr_end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&raw[..hdr_end]);
                let content_len = headers
                    .lines()
                    .find_map(|line| {
                        let (k, v) = line.split_once(':')?;
                        if k.eq_ignore_ascii_case("content-length") {
                            v.trim().parse::<usize>().ok()
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0);
                if raw.len() >= hdr_end + 4 + content_len {
                    break;
                }
            }
        }
        String::from_utf8_lossy(&raw).into_owned()
    }

    #[test]
    fn test_select_free_servers_filters_tier_zero_and_usable_physical() {
        let payload = serde_json::json!({
            "Code": 1000,
            "LogicalServers": [
                {
                    "Name": "US-PAID#1",
                    "Tier": 2,
                    "Status": 1,
                    "EntryCountry": "US",
                    "ExitCountry": "US",
                    "City": "New York",
                    "Load": 10,
                    "Domain": "paid.protonvpn.net",
                    "Servers": [{"EntryIP": "203.0.113.1", "Status": 1, "ServicesDown": 0, "X25519PublicKey": "paidkey"}]
                },
                {
                    "Name": "JP-FREE#2",
                    "Tier": 0,
                    "Status": 1,
                    "EntryCountry": "JP",
                    "ExitCountry": "JP",
                    "City": "Tokyo",
                    "Load": 30,
                    "Domain": "jp-free-2.protonvpn.net",
                    "Servers": [
                        {"EntryIP": "198.51.100.1", "Status": 0, "ServicesDown": 0, "X25519PublicKey": "down-phys"},
                        {"EntryIP": "198.51.100.2", "Status": 1, "ServicesDown": 1, "X25519PublicKey": "services-down"},
                        {"EntryIP": "198.51.100.3", "ExitIP": "198.51.100.4", "Status": 1, "ServicesDown": 0, "X25519PublicKey": "jp2-key"}
                    ]
                },
                {
                    "Name": "NL-FREE#1",
                    "Tier": 0,
                    "Status": 1,
                    "EntryCountry": "NL",
                    "ExitCountry": "NL",
                    "City": "Amsterdam",
                    "Load": 15,
                    "Domain": "nl-free-1.protonvpn.net",
                    "Servers": [
                        {"EntryIP": "192.0.2.5", "Status": 1, "ServicesDown": 0, "X25519PublicKey": "nl1-key"}
                    ]
                },
                {
                    "Name": "SG-DOWN#1",
                    "Tier": 0,
                    "Status": 1,
                    "EntryCountry": "SG",
                    "ExitCountry": "SG",
                    "City": "Singapore",
                    "Load": 5,
                    "Domain": "sg-down.protonvpn.net",
                    "Servers": [
                        {"EntryIP": "192.0.2.99", "Status": 1, "ServicesDown": 2, "X25519PublicKey": "bad-key"}
                    ]
                }
            ]
        });

        let nodes = select_free_servers_with_wg(&payload, None, false).expect("valid payload");
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "NL-FREE#1");
        assert_eq!(nodes[0].entry_ip, "192.0.2.5");
        assert_eq!(nodes[0].x25519_public_key, "nl1-key");
        assert_eq!(nodes[0].active_physical_servers, 1);

        assert_eq!(nodes[1].name, "JP-FREE#2");
        assert_eq!(nodes[1].entry_ip, "198.51.100.3");
        assert_eq!(nodes[1].exit_ip, "198.51.100.4");
        assert_eq!(nodes[1].x25519_public_key, "jp2-key");
        assert_eq!(nodes[1].active_physical_servers, 1);

        let jp_only = select_free_servers_with_wg(&payload, Some("JP"), false).expect("jp filter");
        assert_eq!(jp_only.len(), 1);
        assert_eq!(jp_only[0].name, "JP-FREE#2");

        let with_down = select_free_servers_with_wg(&payload, None, true).expect("include down");
        assert_eq!(with_down.len(), 3);
        assert_eq!(with_down[0].name, "SG-DOWN#1");
        assert_eq!(with_down[0].active_physical_servers, 0);
    }

    #[test]
    fn test_select_free_servers_parses_valid_location_and_rejects_invalid() {
        let payload = serde_json::json!({
            "LogicalServers": [
                {
                    "Name": "JP-FREE#1",
                    "Tier": 0,
                    "Status": 1,
                    "ExitCountry": "JP",
                    "EntryCountry": "JP",
                    "City": "Tokyo",
                    "Load": 20.0,
                    "Domain": "jp-1.protonvpn.net",
                    "Location": { "Lat": 35.6762, "Long": 139.6503 },
                    "Servers": [{ "Status": 1, "ServicesDown": 0, "EntryIP": "198.51.100.1", "X25519PublicKey": "k1" }]
                },
                {
                    "Name": "US-FREE#1",
                    "Tier": 0,
                    "Status": 1,
                    "ExitCountry": "US",
                    "EntryCountry": "US",
                    "City": "New York",
                    "Load": 30.0,
                    "Domain": "us-1.protonvpn.net",
                    "Location": { "Lat": 120.0, "Long": -74.0 },
                    "Servers": [{ "Status": 1, "ServicesDown": 0, "EntryIP": "198.51.100.2", "X25519PublicKey": "k2" }]
                },
                {
                    "Name": "SG-FREE#1",
                    "Tier": 0,
                    "Status": 1,
                    "ExitCountry": "SG",
                    "EntryCountry": "SG",
                    "City": "Singapore",
                    "Load": 40.0,
                    "Domain": "sg-1.protonvpn.net",
                    "Servers": [{ "Status": 1, "ServicesDown": 0, "EntryIP": "198.51.100.3", "X25519PublicKey": "k3" }]
                }
            ]
        });
        let nodes = select_free_servers_with_wg(&payload, None, false).expect("valid payload");
        let jp = nodes.iter().find(|n| n.name == "JP-FREE#1").unwrap();
        assert_eq!(jp.latitude, Some(35.6762));
        assert_eq!(jp.longitude, Some(139.6503));

        let us = nodes.iter().find(|n| n.name == "US-FREE#1").unwrap();
        assert_eq!(us.latitude, None);
        assert_eq!(us.longitude, None);

        let sg = nodes.iter().find(|n| n.name == "SG-FREE#1").unwrap();
        assert_eq!(sg.latitude, None);
        assert_eq!(sg.longitude, None);
    }

    #[test]
    fn test_server_node_deserializes_legacy_json_without_coordinates() {
        let legacy = r#"{"name":"SG-FREE#1","country":"SG","entryCountry":"SG","city":"Singapore","load":50.0,"status":1,"domain":"d","entryIP":"1.1.1.1","exitIP":"1.1.1.1","x25519PublicKey":"k","activePhysicalServers":1,"pingTarget":"1.1.1.1","pingMs":40.0}"#;
        let node: ServerNode = serde_json::from_str(legacy).expect("legacy json deserializes");
        assert_eq!(node.latitude, None);
        assert_eq!(node.longitude, None);
    }

    #[test]
    fn test_is_usable_physical_server_rejects_missing_or_null_services_down() {
        assert!(is_usable_physical_server(&serde_json::json!({
            "Status": 1,
            "ServicesDown": 0
        })));
        assert!(!is_usable_physical_server(&serde_json::json!({
            "Status": 1
        })));
        assert!(!is_usable_physical_server(&serde_json::json!({
            "Status": 1,
            "ServicesDown": null
        })));
        assert!(!is_usable_physical_server(&serde_json::json!({
            "Status": 1,
            "ServicesDown": "0"
        })));

        let payload = serde_json::json!({
            "Code": 1000,
            "LogicalServers": [
                {
                    "Name": "MISSING-SD#1",
                    "Tier": 0,
                    "Status": 1,
                    "EntryCountry": "US",
                    "ExitCountry": "US",
                    "City": "Dallas",
                    "Load": 10,
                    "Domain": "missing-sd.protonvpn.net",
                    "Servers": [
                        {"EntryIP": "198.51.100.10", "Status": 1, "X25519PublicKey": "k1"},
                        {"EntryIP": "198.51.100.11", "Status": 1, "ServicesDown": null, "X25519PublicKey": "k2"}
                    ]
                }
            ]
        });
        let usable = select_free_servers_with_wg(&payload, None, false).expect("valid payload");
        assert!(usable.is_empty());
    }

    #[tokio::test]
    async fn test_2fa_code_preserves_recovery_characters() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let captured_body = Arc::new(Mutex::new(String::new()));
        let captured_clone = Arc::clone(&captured_body);

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let req = read_http_request(&mut socket).await;
            if let Some((_, body)) = req.split_once("\r\n\r\n") {
                *captured_clone.lock().expect("body lock") = body.to_owned();
            }
            let resp_body = r#"{"Code":1000,"Scopes":["full"]}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                resp_body.len(),
                resp_body
            );
            socket.write_all(resp.as_bytes()).await.expect("write");
        });

        let store = Arc::new(MockCredentialStore::default());
        let base = format!("http://{addr}");
        let client = ProtonClient::with_endpoints(store, base.clone(), vec![base.clone()], base);
        let pending = StoredAuthSession {
            uid: "uid-2fa".to_owned(),
            access_token: "acc-2fa".to_owned(),
            refresh_token: "ref-2fa".to_owned(),
            scopes: vec!["twofactor".to_owned()],
        };

        let result = client
            .submit_2fa(&pending, " abcd-1234 ")
            .await
            .expect("2fa succeeds");
        assert_eq!(result.scopes, vec!["full"]);
        let sent_json: Value =
            serde_json::from_str(&captured_body.lock().expect("lock")).expect("valid json");
        assert_eq!(sent_json["TwoFactorCode"], "abcd-1234");
    }

    #[tokio::test]
    async fn test_concurrent_401_triggers_single_refresh_and_retries() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let refresh_count = Arc::new(AtomicUsize::new(0));
        let refresh_clone = Arc::clone(&refresh_count);

        let server_task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let refresh_counter = Arc::clone(&refresh_clone);
                tokio::spawn(async move {
                    let req = read_http_request(&mut socket).await;
                    let first_line = req.lines().next().unwrap_or("");
                    let (status, body) = if first_line.starts_with("POST /auth/v4/refresh") {
                        refresh_counter.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        (
                            "200 OK",
                            r#"{"Code":1000,"AccessToken":"new-acc","RefreshToken":"new-ref","Scopes":["full"]}"#,
                        )
                    } else if req.contains("Authorization: Bearer new-acc")
                        || req.contains("authorization: Bearer new-acc")
                    {
                        ("200 OK", r#"{"Code":1000,"Ok":true}"#)
                    } else {
                        (
                            "401 Unauthorized",
                            r#"{"Code":401,"Error":"Invalid access token"}"#,
                        )
                    };
                    let resp = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                });
            }
        });

        let initial_session = StoredAuthSession {
            uid: "uid-1".to_owned(),
            access_token: "old-acc".to_owned(),
            refresh_token: "old-ref".to_owned(),
            scopes: vec!["full".to_owned()],
        };
        let store = Arc::new(MockCredentialStore::with_session(
            "user@proton.me",
            &initial_session,
        ));
        let base = format!("http://{addr}");
        let client = Arc::new(ProtonClient::with_endpoints(
            Arc::clone(&store) as Arc<dyn CredentialStore>,
            base.clone(),
            vec![base.clone()],
            base,
        ));

        let c1 = Arc::clone(&client);
        let c2 = Arc::clone(&client);
        let (r1, r2) = tokio::join!(
            c1.api_request("vpn/v1/logicals?WithIpV6=1", Method::GET, None),
            c2.api_request("vpn/v1/certificate/key/EC", Method::GET, None),
        );
        assert_eq!(r1.expect("first retry succeeds")["Ok"], true);
        assert_eq!(r2.expect("second retry succeeds")["Ok"], true);
        assert_eq!(refresh_count.load(Ordering::SeqCst), 1);

        let (_, persisted) = store
            .load_auth_session()
            .expect("load session")
            .expect("session preserved");
        assert_eq!(persisted.access_token, "new-acc");
        assert_eq!(persisted.refresh_token, "new-ref");
        server_task.abort();

        // Network error on refresh must preserve existing stored credentials.
        let dead_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let dead_addr = dead_listener.local_addr().expect("dead addr");
        drop(dead_listener);

        let vpn_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let vpn_addr = vpn_listener.local_addr().expect("vpn addr");
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = vpn_listener.accept().await {
                let _ = read_http_request(&mut socket).await;
                let body = r#"{"Code":401,"Error":"Expired"}"#;
                let resp = format!(
                    "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            }
        });

        let preserved_store = Arc::new(MockCredentialStore::with_session(
            "keep@proton.me",
            &initial_session,
        ));
        let fail_client = ProtonClient::with_endpoints(
            Arc::clone(&preserved_store) as Arc<dyn CredentialStore>,
            format!("http://{dead_addr}"),
            vec![format!("http://{vpn_addr}")],
            format!("http://{dead_addr}"),
        );
        let err = fail_client
            .api_request("vpn/v1/logicals", Method::GET, None)
            .await
            .expect_err("refresh network failure must error");
        let _ = err;
        let (_, still_there) = preserved_store
            .load_auth_session()
            .expect("load session")
            .expect("credentials must remain intact on refresh network failure");
        assert_eq!(still_there, initial_session);
    }

    #[tokio::test]
    async fn test_human_verification_9001_extracts_force_web_messaging_url() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let _ = read_http_request(&mut socket).await;
            let body = r#"{
                "Code": 9001,
                "Error": "Human verification required",
                "Details": {
                    "HumanVerificationMethods": ["captcha"],
                    "Methods": ["captcha", "ownership-email"],
                    "HumanVerificationToken": "hv-token-xyz",
                    "WebUrl": "https://verify.proton.me/?methods=captcha&token=hv-token-xyz"
                }
            }"#;
            let resp = format!(
                "HTTP/1.1 422 Unprocessable Entity\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(resp.as_bytes()).await.expect("write");
        });

        let store = Arc::new(MockCredentialStore::default());
        let base = format!("http://{addr}");
        let client = ProtonClient::with_endpoints(store, base.clone(), vec![base.clone()], base);
        let outcome = client
            .login_srp("user@proton.me", "secret", None)
            .await
            .expect("9001 returns NeedsHumanVerification");
        match outcome {
            LoginOutcome::NeedsHumanVerification { url, methods } => {
                assert_eq!(methods, vec!["captcha", "ownership-email"]);
                let parsed = Url::parse(&url).expect("valid URL");
                assert_eq!(parsed.host_str(), Some("verify.proton.me"));
                let pairs: HashMap<String, String> = parsed.query_pairs().into_owned().collect();
                assert_eq!(
                    pairs.get("ForceWebMessaging").map(String::as_str),
                    Some("1")
                );
                assert_eq!(pairs.get("token").map(String::as_str), Some("hv-token-xyz"));
            }
            other => panic!("expected NeedsHumanVerification, got {other:?}"),
        }

        // Also reject disallowed verification hosts.
        let evil = serde_json::json!({
            "WebUrl": "https://evil.example.com/verify",
            "Methods": ["captcha"]
        });
        assert!(matches!(
            extract_human_verification(&evil),
            Err(ApiError::InvalidHumanVerificationUrl(_))
        ));

        // Fallback URL construction when WebUrl is absent.
        let fallback = serde_json::json!({
            "HumanVerificationToken": "tok-only",
            "Methods": ["captcha"]
        });
        let (fallback_url, fallback_methods) =
            extract_human_verification(&fallback).expect("fallback hv url");
        assert_eq!(fallback_methods, vec!["captcha"]);
        let parsed_fb = Url::parse(&fallback_url).expect("valid fallback url");
        assert_eq!(parsed_fb.host_str(), Some("verify.proton.me"));
        let fb_pairs: HashMap<String, String> = parsed_fb.query_pairs().into_owned().collect();
        assert_eq!(
            fb_pairs.get("ForceWebMessaging").map(String::as_str),
            Some("1")
        );
        assert_eq!(fb_pairs.get("token").map(String::as_str), Some("tok-only"));
    }

    #[test]
    fn test_human_verification_uses_human_verification_methods_when_methods_absent() {
        let details = serde_json::json!({
            "HumanVerificationMethods": ["captcha", "ownership-email"],
            "HumanVerificationToken": "hv-only-methods-token"
        });
        let (url, methods) = extract_human_verification(&details)
            .expect("extracts HumanVerificationMethods fallback");
        assert_eq!(methods, vec!["captcha", "ownership-email"]);
        let parsed = Url::parse(&url).expect("valid fallback url");
        assert_eq!(parsed.scheme(), "https");
        assert_eq!(parsed.host_str(), Some("verify.proton.me"));
        let pairs: HashMap<String, String> = parsed.query_pairs().into_owned().collect();
        assert_eq!(
            pairs.get("methods").map(String::as_str),
            Some("captcha,ownership-email")
        );
        assert_eq!(
            pairs.get("token").map(String::as_str),
            Some("hv-only-methods-token")
        );
        assert_eq!(
            pairs.get("ForceWebMessaging").map(String::as_str),
            Some("1")
        );
    }

    #[tokio::test]
    async fn test_ensure_wg_key_serializes_within_window_and_fetch_public_ip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let key_requests = Arc::new(AtomicUsize::new(0));
        let key_clone = Arc::clone(&key_requests);

        let der: [u8; 48] = [
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
            0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            STANDARD.encode(der)
        );
        let future_exp = current_unix_timestamp() + 86_400;

        let server_task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let kc = Arc::clone(&key_clone);
                let pem_clone = pem.clone();
                tokio::spawn(async move {
                    let req = read_http_request(&mut socket).await;
                    let first_line = req.lines().next().unwrap_or("");
                    let body = if first_line.starts_with("GET /vpn/v1/certificate/key/EC") {
                        kc.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(40)).await;
                        serde_json::json!({
                            "Code": 1000,
                            "PrivateKey": pem_clone,
                            "PublicKey": "PUB-PEM"
                        })
                        .to_string()
                    } else if first_line.starts_with("POST /vpn/v1/certificate") {
                        serde_json::json!({
                            "Code": 1000,
                            "ExpirationTime": future_exp
                        })
                        .to_string()
                    } else if first_line.starts_with("GET /ip") {
                        r#"{"ip":"198.51.100.77"}"#.to_owned()
                    } else {
                        r#"{"Code":1000}"#.to_owned()
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                });
            }
        });

        let session = StoredAuthSession {
            uid: "uid-wg".to_owned(),
            access_token: "acc-wg".to_owned(),
            refresh_token: "ref-wg".to_owned(),
            scopes: vec!["full".to_owned()],
        };
        let store = Arc::new(MockCredentialStore::with_session("wg@proton.me", &session));
        // Seed an expiring key (inside 7200s window) to confirm proactive refresh fires once across concurrent callers.
        store
            .save_client_config(&ClientConfig {
                private_key: "expiring-soon".to_owned(),
                expiration: current_unix_timestamp() + 300,
                ..ClientConfig::default()
            })
            .expect("seed expiring config");

        let base = format!("http://{addr}");
        let client = Arc::new(ProtonClient::with_endpoints(
            Arc::clone(&store) as Arc<dyn CredentialStore>,
            base.clone(),
            vec![base.clone()],
            format!("{base}/ip"),
        ));

        let c1 = Arc::clone(&client);
        let c2 = Arc::clone(&client);
        let (k1, k2) = tokio::join!(c1.ensure_wg_key(false), c2.ensure_wg_key(false));
        let k1 = k1.expect("first ensure_wg_key");
        let k2 = k2.expect("second ensure_wg_key");
        assert_eq!(key_requests.load(Ordering::SeqCst), 1);
        assert_eq!(k1, k2);
        assert_eq!(k1.public_key, "PUB-PEM");
        assert_eq!(k1.expiration, future_exp);
        assert!(!k1.private_key.is_empty());

        let ip = client.fetch_public_ip().await.expect("public ip");
        assert_eq!(ip, "198.51.100.77");
        server_task.abort();
    }

    #[tokio::test]
    async fn test_fetch_logicals_falls_back_across_vpn_hosts_and_12087_hv() {
        let dead_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let dead_addr = dead_listener.local_addr().expect("dead addr");
        drop(dead_listener);

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server_task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let req = read_http_request(&mut socket).await;
                    let first_line = req.lines().next().unwrap_or("");
                    let (status, body) = if first_line.starts_with("POST /auth/info") {
                        (
                            "422 Unprocessable Entity",
                            r#"{"Code":12087,"Error":"Invalid HV","Details":{"Methods":["captcha"],"HumanVerificationToken":"retry-hv"}}"#,
                        )
                    } else {
                        (
                            "200 OK",
                            r#"{"Code":1000,"LogicalServers":[{"Name":"SG-FREE#1","Tier":0,"Status":1,"EntryCountry":"SG","ExitCountry":"SG","City":"Singapore","Load":12,"Domain":"sg-1.protonvpn.net","Servers":[{"EntryIP":"198.51.100.88","Status":1,"ServicesDown":0,"X25519PublicKey":"sg-pub"}]}]}"#,
                        )
                    };
                    let resp = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                });
            }
        });

        let session = StoredAuthSession {
            uid: "uid-fb".to_owned(),
            access_token: "acc-fb".to_owned(),
            refresh_token: "ref-fb".to_owned(),
            scopes: vec!["full".to_owned()],
        };
        let store = Arc::new(MockCredentialStore::with_session("fb@proton.me", &session));
        let ok_base = format!("http://{addr}");
        let dead_base = format!("http://{dead_addr}");
        let client = ProtonClient::with_endpoints(
            store,
            ok_base.clone(),
            vec![dead_base, ok_base.clone()],
            ok_base,
        );

        let nodes = client.fetch_logicals().await.expect("fallback succeeds");
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "SG-FREE#1");
        assert_eq!(nodes[0].x25519_public_key, "sg-pub");

        let hv_12087 = client
            .login_srp("fb@proton.me", "pw", None)
            .await
            .expect("12087 yields NeedsHumanVerification");
        assert!(matches!(
            hv_12087,
            LoginOutcome::NeedsHumanVerification { .. }
        ));
        server_task.abort();
    }

    #[tokio::test]
    async fn test_static_key_preserved_when_force_false_and_input_validation() {
        let store = Arc::new(MockCredentialStore::default());
        store
            .save_client_config(&ClientConfig {
                private_key: "static-user-key".to_owned(),
                expiration: 0,
                ..ClientConfig::default()
            })
            .expect("save static config");

        let dead_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let dead_addr = dead_listener.local_addr().expect("addr");
        drop(dead_listener);
        let dead_base = format!("http://{dead_addr}");
        let client = ProtonClient::with_endpoints(
            Arc::clone(&store) as Arc<dyn CredentialStore>,
            dead_base.clone(),
            vec![dead_base.clone()],
            dead_base,
        );

        let cfg = client
            .ensure_wg_key(false)
            .await
            .expect("static key does not hit network when force=false");
        assert_eq!(cfg.private_key, "static-user-key");
        assert_eq!(cfg.expiration, 0);

        assert!(matches!(
            client.login_srp("   ", "pw", None).await,
            Err(ApiError::Srp(SrpError::MissingCredentials))
        ));

        let pending = StoredAuthSession {
            uid: "u".to_owned(),
            access_token: "a".to_owned(),
            refresh_token: "r".to_owned(),
            scopes: vec!["twofactor".to_owned()],
        };
        assert!(matches!(
            client.submit_2fa(&pending, "   ").await,
            Err(ApiError::InvalidInput(_))
        ));
    }

    #[tokio::test]
    async fn test_refresh_token_rejection_returns_session_expired_while_5xx_does_not() {
        let session = StoredAuthSession {
            uid: "uid-exp".to_owned(),
            access_token: "acc-old".to_owned(),
            refresh_token: "ref-bad".to_owned(),
            scopes: vec!["full".to_owned()],
        };

        let run_case = |refresh_status: &'static str, refresh_body: &'static str| {
            let sess = session.clone();
            async move {
                let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
                let addr = listener.local_addr().expect("addr");
                let task = tokio::spawn(async move {
                    loop {
                        let Ok((mut socket, _)) = listener.accept().await else {
                            break;
                        };
                        tokio::spawn(async move {
                            let req = read_http_request(&mut socket).await;
                            let first_line = req.lines().next().unwrap_or("");
                            let (status, body) = if first_line.starts_with("POST /auth/v4/refresh")
                            {
                                (refresh_status, refresh_body)
                            } else {
                                (
                                    "401 Unauthorized",
                                    r#"{"Code":401,"Error":"Invalid access token"}"#,
                                )
                            };
                            let resp = format!(
                                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            let _ = socket.write_all(resp.as_bytes()).await;
                        });
                    }
                });
                let store = Arc::new(MockCredentialStore::with_session("u@proton.me", &sess));
                let base = format!("http://{addr}");
                let client = ProtonClient::with_endpoints(
                    store,
                    base.clone(),
                    vec![base.clone()],
                    base,
                );
                let err = client
                    .fetch_logicals()
                    .await
                    .expect_err("refresh failure must return error");
                task.abort();
                err
            }
        };

        let expired = run_case(
            "400 Bad Request",
            r#"{"Code":10013,"Error":"Invalid refresh token"}"#,
        )
        .await;
        assert!(expired.is_session_expired());
        assert_eq!(expired.http_status(), Some(400));
        assert_eq!(expired.api_code(), Some(10013));

        let transient = run_case("503 Service Unavailable", r#"{"Code":503,"Error":"Busy"}"#).await;
        assert!(
            !transient.is_session_expired(),
            "5xx outage must NOT mark session expired: {transient:?}"
        );
    }

    #[test]
    fn test_parse_user_location_payload_valid_and_invalid() {
        let valid = serde_json::json!({
            "Code": 1000,
            "Lat": 10.8231,
            "Long": 106.6297,
            "Country": " vn "
        });
        let parsed = parse_user_location_payload(&valid).expect("valid location");
        assert_eq!(parsed.country.as_deref(), Some("VN"));
        assert!((parsed.lat - 10.8231).abs() < 1e-4);
        assert!((parsed.lon - 106.6297).abs() < 1e-4);

        let no_country = serde_json::json!({
            "Latitude": 21.0278,
            "Longitude": 105.8342,
            "Country": "   "
        });
        let parsed2 = parse_user_location_payload(&no_country).expect("fallback keys");
        assert_eq!(parsed2.country, None);
        assert!((parsed2.lat - 21.0278).abs() < 1e-4);

        for invalid in [
            serde_json::json!({"Lat": 95.0, "Long": 106.0}),
            serde_json::json!({"Lat": 10.0, "Long": 181.0}),
            serde_json::json!({"Lat": 10.0}),
            serde_json::json!({}),
        ] {
            assert!(
                parse_user_location_payload(&invalid).is_err(),
                "invalid location payload must fail: {invalid}"
            );
        }
    }

    #[tokio::test]
    async fn test_fetch_user_location_calls_vpn_v1_location() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let seen_location_req = Arc::new(AtomicUsize::new(0));
        let seen_clone = Arc::clone(&seen_location_req);
        let server_task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let sc = Arc::clone(&seen_clone);
                tokio::spawn(async move {
                    let req = read_http_request(&mut socket).await;
                    let first_line = req.lines().next().unwrap_or("");
                    let (status, body) = if first_line.starts_with("GET /vpn/v1/location") {
                        sc.fetch_add(1, Ordering::SeqCst);
                        (
                            "200 OK",
                            r#"{"Code":1000,"IP":"203.113.152.1","Lat":21.0278,"Long":105.8342,"Country":"VN"}"#,
                        )
                    } else {
                        ("404 Not Found", r#"{"Code":404}"#)
                    };
                    let resp = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                });
            }
        });

        let session = StoredAuthSession {
            uid: "uid-loc".to_owned(),
            access_token: "acc-loc".to_owned(),
            refresh_token: "ref-loc".to_owned(),
            scopes: vec!["full".to_owned()],
        };
        let store = Arc::new(MockCredentialStore::with_session("loc@proton.me", &session));
        let base = format!("http://{addr}");
        let client = ProtonClient::with_endpoints(store, base.clone(), vec![base.clone()], base);

        let loc = client.fetch_user_location().await.expect("fetch user location");
        assert_eq!(seen_location_req.load(Ordering::SeqCst), 1);
        assert_eq!(loc.country.as_deref(), Some("VN"));
        assert!((loc.lat - 21.0278).abs() < 1e-4);
        assert!((loc.lon - 105.8342).abs() < 1e-4);
        server_task.abort();
    }
}
