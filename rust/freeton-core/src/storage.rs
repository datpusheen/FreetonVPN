use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND, WIN32_ERROR};
use windows::Win32::Security::Credentials::{
    CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_FLAGS, CRED_PERSIST_ENTERPRISE,
    CRED_TYPE_GENERIC,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE, REG_SZ, REG_VALUE_TYPE,
};

use crate::api::ServerNode;

/// Windows Credential Manager target/service name for Proton SRP account state.
pub const KEYRING_SERVICE_SRP: &str = "proton-node-checker";

/// Windows Credential Manager username key storing the active Proton account identifier.
pub const KEYRING_ACCOUNT_SRP: &str = "active-account";

/// Windows Credential Manager target/service name for WireGuard client settings and keys.
pub const KEYRING_SERVICE_WG: &str = "proton-node-checker-wireguard";

/// Windows Credential Manager username key storing serialized `ClientConfig`.
pub const KEYRING_ACCOUNT_WG_CONFIG: &str = "client_config";

/// Legacy Windows Credential Manager browser cookie session service (cleaned on logout).
pub const KEYRING_SERVICE_BROWSER: &str = "proton-node-checker-browser";

/// Legacy Windows Credential Manager browser cookie session username key.
pub const KEYRING_ACCOUNT_BROWSER: &str = "session-state";

/// Default WireGuard tunnel interface CIDR address.
pub const DEFAULT_WG_ADDRESS: &str = "10.2.0.2/32";

/// Default WireGuard DNS resolvers.
pub const DEFAULT_WG_DNS: &str = "10.2.0.1, 1.1.1.1";

/// Default WireGuard UDP endpoint port.
pub const DEFAULT_WG_PORT: &str = "51820";

/// Registry subkey under `HKCU` controlling user logon startup apps.
pub const STARTUP_REG_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

/// Registry value name under `HKCU\...\Run` for Freeton VPN.
pub const STARTUP_REG_VALUE_NAME: &str = "FreetonVPN";

/// Errors returned by credential storage, cache persistence, and Windows startup registry helpers.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Windows Credential Manager error: {0}")]
    Credential(String),
    #[error("Windows Registry error: {0}")]
    Registry(String),
    #[error("Filesystem I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

fn default_address() -> String {
    DEFAULT_WG_ADDRESS.to_owned()
}

fn default_dns() -> String {
    DEFAULT_WG_DNS.to_owned()
}

fn default_port() -> String {
    DEFAULT_WG_PORT.to_owned()
}

fn default_true() -> bool {
    true
}

fn deserialize_null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    T: Default + Deserialize<'de>,
    D: Deserializer<'de>,
{
    let opt = Option::<T>::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

fn deserialize_string_or_default<'de, D>(
    deserializer: D,
    default_fn: fn() -> String,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(deserializer)?;
    Ok(opt.unwrap_or_else(default_fn))
}

fn deserialize_address<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_string_or_default(deserializer, default_address)
}

fn deserialize_dns<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_string_or_default(deserializer, default_dns)
}

fn deserialize_true_if_null<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    let opt = Option::<bool>::deserialize(deserializer)?;
    Ok(opt.unwrap_or(true))
}

fn deserialize_port_flexible<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    match value {
        None | Some(serde_json::Value::Null) => Ok(default_port()),
        Some(serde_json::Value::String(s)) => {
            if s.trim().is_empty() {
                Ok(default_port())
            } else {
                Ok(s)
            }
        }
        Some(serde_json::Value::Number(n)) => Ok(n.to_string()),
        Some(other) => Err(serde::de::Error::custom(format!(
            "unexpected port value: {other}"
        ))),
    }
}

fn deserialize_i64_flexible<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    match value {
        None | Some(serde_json::Value::Null) => Ok(0),
        Some(serde_json::Value::Number(n)) => {
            if let Some(i) = n.as_i64() {
                Ok(i)
            } else if let Some(f) = n.as_f64() {
                Ok(f as i64)
            } else {
                Err(serde::de::Error::custom(format!(
                    "invalid integer expiration: {n}"
                )))
            }
        }
        Some(serde_json::Value::String(s)) => s
            .trim()
            .parse::<f64>()
            .map(|f| f as i64)
            .map_err(|e| serde::de::Error::custom(format!("invalid expiration string: {e}"))),
        Some(other) => Err(serde::de::Error::custom(format!(
            "unexpected expiration value: {other}"
        ))),
    }
}

/// WireGuard client settings and UI preferences persisted in Windows Credential Manager
/// under target `proton-node-checker-wireguard` (`client_config`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientConfig {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub private_key: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub public_key: String,
    #[serde(default, deserialize_with = "deserialize_i64_flexible")]
    pub expiration: i64,
    #[serde(default = "default_address", deserialize_with = "deserialize_address")]
    pub address: String,
    #[serde(default = "default_dns", deserialize_with = "deserialize_dns")]
    pub dns: String,
    #[serde(
        default = "default_port",
        deserialize_with = "deserialize_port_flexible"
    )]
    pub port: String,
    #[serde(
        default = "default_true",
        deserialize_with = "deserialize_true_if_null"
    )]
    pub animations_enabled: bool,
    #[serde(
        default = "default_true",
        deserialize_with = "deserialize_true_if_null"
    )]
    pub auto_check_update: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub debug_mode: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            private_key: String::new(),
            public_key: String::new(),
            expiration: 0,
            address: default_address(),
            dns: default_dns(),
            port: default_port(),
            animations_enabled: true,
            auto_check_update: true,
            debug_mode: false,
        }
    }
}

impl ClientConfig {
    /// Returns `true` when a non-empty private key exists and is either static (`expiration == 0`)
    /// or remains valid for at least `minimum_valid_seconds` from now.
    pub fn has_usable_key(&self, minimum_valid_seconds: i64) -> bool {
        self.has_usable_key_at(current_unix_timestamp(), minimum_valid_seconds)
    }

    pub(crate) fn has_usable_key_at(&self, now_unix: i64, minimum_valid_seconds: i64) -> bool {
        if self.private_key.trim().is_empty() {
            return false;
        }
        self.expiration == 0 || self.expiration >= now_unix + minimum_valid_seconds
    }

    /// Returns `true` when no private key is configured or a dynamic Proton certificate key
    /// expires within `within_seconds` (`7200` by default). Static keys (`expiration == 0`) do not refresh.
    pub fn needs_key_refresh(&self, within_seconds: i64) -> bool {
        self.needs_key_refresh_at(current_unix_timestamp(), within_seconds)
    }

    pub(crate) fn needs_key_refresh_at(&self, now_unix: i64, within_seconds: i64) -> bool {
        if self.private_key.trim().is_empty() {
            return true;
        }
        self.expiration > 0 && self.expiration < now_unix + within_seconds
    }
}

/// Proton SRP session tokens persisted in Windows Credential Manager (`session:<account_lower>`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredAuthSession {
    #[serde(rename = "UID", alias = "uid")]
    pub uid: String,
    #[serde(rename = "AccessToken", alias = "access_token")]
    pub access_token: String,
    #[serde(rename = "RefreshToken", alias = "refresh_token")]
    pub refresh_token: String,
    #[serde(
        rename = "Scopes",
        alias = "scopes",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub scopes: Vec<String>,
}

/// Returns the canonical keyring username key for a Proton account's session payload.
pub fn session_username_key(account: &str) -> String {
    format!("session:{}", account.trim().to_lowercase())
}

/// Abstract credential store interface compatible with Python `keyring` service/username pairs.
pub trait CredentialStore: Send + Sync {
    fn get_password(&self, service: &str, username: &str) -> Result<Option<String>, StorageError>;
    fn set_password(
        &self,
        service: &str,
        username: &str,
        password: &str,
    ) -> Result<(), StorageError>;
    fn delete_password(&self, service: &str, username: &str) -> Result<(), StorageError>;

    /// Loads the currently active Proton account identifier from `proton-node-checker`/`active-account`.
    fn load_active_account(&self) -> Result<Option<String>, StorageError> {
        Ok(self
            .get_password(KEYRING_SERVICE_SRP, KEYRING_ACCOUNT_SRP)?
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty()))
    }

    /// Loads the active Proton account and its stored SRP session tokens, if present and valid.
    fn load_auth_session(&self) -> Result<Option<(String, StoredAuthSession)>, StorageError> {
        let Some(account) = self.load_active_account()? else {
            return Ok(None);
        };
        let key = session_username_key(&account);
        let Some(raw) = self.get_password(KEYRING_SERVICE_SRP, &key)? else {
            return Ok(None);
        };
        let Ok(session) = serde_json::from_str::<StoredAuthSession>(&raw) else {
            return Ok(None);
        };
        if session.uid.trim().is_empty() || session.access_token.trim().is_empty() {
            return Ok(None);
        }
        Ok(Some((account, session)))
    }

    /// Saves both the active account identifier and its serialized `StoredAuthSession`.
    fn save_auth_session(
        &self,
        account: &str,
        session: &StoredAuthSession,
    ) -> Result<(), StorageError> {
        let trimmed = account.trim();
        let json = serde_json::to_string(session)?;
        self.set_password(KEYRING_SERVICE_SRP, KEYRING_ACCOUNT_SRP, trimmed)?;
        self.set_password(KEYRING_SERVICE_SRP, &session_username_key(trimmed), &json)
    }

    /// Updates the serialized `StoredAuthSession` for the active Proton account without changing `active-account`.
    fn update_auth_session(&self, session: &StoredAuthSession) -> Result<(), StorageError> {
        let account = self.load_active_account()?.ok_or_else(|| {
            StorageError::Credential("No active Proton account stored".to_owned())
        })?;
        let json = serde_json::to_string(session)?;
        self.set_password(KEYRING_SERVICE_SRP, &session_username_key(&account), &json)
    }

    /// Loads `ClientConfig` from `proton-node-checker-wireguard`/`client_config`, returning defaults
    /// if missing or corrupted.
    fn load_client_config(&self) -> Result<ClientConfig, StorageError> {
        let Some(raw) = self.get_password(KEYRING_SERVICE_WG, KEYRING_ACCOUNT_WG_CONFIG)? else {
            return Ok(ClientConfig::default());
        };
        Ok(serde_json::from_str::<ClientConfig>(&raw).unwrap_or_default())
    }

    /// Persists `ClientConfig` JSON into `proton-node-checker-wireguard`/`client_config`.
    fn save_client_config(&self, config: &ClientConfig) -> Result<(), StorageError> {
        let json = serde_json::to_string(config)?;
        self.set_password(KEYRING_SERVICE_WG, KEYRING_ACCOUNT_WG_CONFIG, &json)
    }

    /// Deletes saved SRP session credentials, WireGuard config, and any legacy browser session entry.
    fn clear_all_sessions(&self) -> Result<(), StorageError> {
        let _ = self.delete_password(KEYRING_SERVICE_BROWSER, KEYRING_ACCOUNT_BROWSER);
        if let Some(account) = self.load_active_account()? {
            let _ = self.delete_password(KEYRING_SERVICE_SRP, &session_username_key(&account));
            let _ = self.delete_password(KEYRING_SERVICE_SRP, KEYRING_ACCOUNT_SRP);
        } else {
            let _ = self.delete_password(KEYRING_SERVICE_SRP, KEYRING_ACCOUNT_SRP);
        }
        let _ = self.delete_password(KEYRING_SERVICE_WG, KEYRING_ACCOUNT_WG_CONFIG);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawCredential {
    username: Option<String>,
    secret: String,
}

trait RawCredentialBackend: Send + Sync {
    fn read_target(&self, target: &str) -> Result<Option<RawCredential>, StorageError>;
    fn write_target(&self, target: &str, username: &str, secret: &str) -> Result<(), StorageError>;
    fn delete_target(&self, target: &str) -> Result<(), StorageError>;
}

/// Implements Python `keyring.backends.Windows.WinVaultKeyring` exact target naming & relocation:
/// primary writes go under `service`, and colliding distinct `username` entries relocate to `{username}@{service}`.
struct WinVaultAdapter<B: RawCredentialBackend> {
    backend: B,
}

impl<B: RawCredentialBackend> WinVaultAdapter<B> {
    fn compound_name(username: &str, service: &str) -> String {
        format!("{username}@{service}")
    }

    fn get_password(&self, service: &str, username: &str) -> Result<Option<String>, StorageError> {
        if let Some(cred) = self.backend.read_target(service)? {
            if cred.username.as_deref() == Some(username) {
                return Ok(Some(cred.secret));
            }
        }
        let compound = Self::compound_name(username, service);
        if let Some(cred) = self.backend.read_target(&compound)? {
            if cred.username.is_none() || cred.username.as_deref() == Some(username) {
                return Ok(Some(cred.secret));
            }
        }
        Ok(None)
    }

    fn set_password(
        &self,
        service: &str,
        username: &str,
        password: &str,
    ) -> Result<(), StorageError> {
        if let Some(existing) = self.backend.read_target(service)? {
            if let Some(existing_user) = existing.username.as_deref() {
                if existing_user != username {
                    let relocated_target = Self::compound_name(existing_user, service);
                    self.backend.write_target(
                        &relocated_target,
                        existing_user,
                        &existing.secret,
                    )?;
                }
            }
        }
        self.backend.write_target(service, username, password)?;
        let compound = Self::compound_name(username, service);
        if let Some(stale) = self.backend.read_target(&compound)? {
            if stale.username.as_deref() == Some(username) {
                let _ = self.backend.delete_target(&compound);
            }
        }
        Ok(())
    }

    fn delete_password(&self, service: &str, username: &str) -> Result<(), StorageError> {
        let compound = Self::compound_name(username, service);
        for target in [service, compound.as_str()] {
            if let Some(existing) = self.backend.read_target(target)? {
                if existing.username.as_deref() == Some(username) {
                    self.backend.delete_target(target)?;
                }
            }
        }
        Ok(())
    }
}

struct Win32CredBackend;

impl RawCredentialBackend for Win32CredBackend {
    fn read_target(&self, target: &str) -> Result<Option<RawCredential>, StorageError> {
        let target_w = to_wide_nul(target);
        let mut cred_ptr: *mut CREDENTIALW = std::ptr::null_mut();

        // SAFETY: `target_w` is null-terminated UTF-16 and `cred_ptr` receives a CredFree-managed buffer on success.
        let result = unsafe {
            CredReadW(
                PCWSTR(target_w.as_ptr()),
                CRED_TYPE_GENERIC,
                Some(0),
                &mut cred_ptr,
            )
        };
        if let Err(err) = result {
            if err.code() == ERROR_NOT_FOUND.to_hresult() {
                return Ok(None);
            }
            return Err(StorageError::Credential(format!(
                "CredReadW({target}) failed: {err}"
            )));
        }

        struct CredGuard(*mut CREDENTIALW);
        impl Drop for CredGuard {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    // SAFETY: pointer was returned by CredReadW.
                    unsafe { CredFree(self.0.cast()) };
                }
            }
        }
        let _guard = CredGuard(cred_ptr);

        // SAFETY: `cred_ptr` is non-null after successful CredReadW and valid until `_guard` drops.
        let cred = unsafe { &*cred_ptr };
        let username = unsafe { pwstr_to_string(cred.UserName) };
        let blob_slice = if cred.CredentialBlob.is_null() || cred.CredentialBlobSize == 0 {
            &[]
        } else {
            // SAFETY: `CredentialBlob` points to `CredentialBlobSize` bytes owned by CredReadW allocation.
            unsafe {
                std::slice::from_raw_parts(cred.CredentialBlob, cred.CredentialBlobSize as usize)
            }
        };
        let secret = decode_credential_blob(blob_slice)?;
        Ok(Some(RawCredential { username, secret }))
    }

    fn write_target(&self, target: &str, username: &str, secret: &str) -> Result<(), StorageError> {
        let mut target_w = to_wide_nul(target);
        let mut username_w = to_wide_nul(username);
        let mut comment_w = to_wide_nul("Stored using python-keyring");
        let mut blob_bytes = encode_credential_blob_utf16(secret);

        let blob_size = u32::try_from(blob_bytes.len())
            .map_err(|_| StorageError::Credential("Credential blob exceeds u32::MAX".to_owned()))?;
        let blob_ptr = if blob_bytes.is_empty() {
            std::ptr::null_mut()
        } else {
            blob_bytes.as_mut_ptr()
        };

        let credential = CREDENTIALW {
            Flags: CRED_FLAGS(0),
            Type: CRED_TYPE_GENERIC,
            TargetName: PWSTR(target_w.as_mut_ptr()),
            Comment: PWSTR(comment_w.as_mut_ptr()),
            LastWritten: Default::default(),
            CredentialBlobSize: blob_size,
            CredentialBlob: blob_ptr,
            Persist: CRED_PERSIST_ENTERPRISE,
            AttributeCount: 0,
            Attributes: std::ptr::null_mut(),
            TargetAlias: PWSTR::null(),
            UserName: PWSTR(username_w.as_mut_ptr()),
        };

        // SAFETY: All pointers in `credential` stay alive and valid for the duration of `CredWriteW`.
        unsafe { CredWriteW(&credential, 0) }
            .map_err(|err| StorageError::Credential(format!("CredWriteW({target}) failed: {err}")))
    }

    fn delete_target(&self, target: &str) -> Result<(), StorageError> {
        let target_w = to_wide_nul(target);
        // SAFETY: `target_w` is null-terminated UTF-16.
        let result = unsafe { CredDeleteW(PCWSTR(target_w.as_ptr()), CRED_TYPE_GENERIC, Some(0)) };
        if let Err(err) = result {
            if err.code() == ERROR_NOT_FOUND.to_hresult() {
                return Ok(());
            }
            return Err(StorageError::Credential(format!(
                "CredDeleteW({target}) failed: {err}"
            )));
        }
        Ok(())
    }
}

/// Windows Credential Manager backed store compatible with Python `keyring.backends.Windows.WinVaultKeyring`.
pub struct WindowsCredentialStore {
    inner: WinVaultAdapter<Win32CredBackend>,
    /// Guards multi-step read-relocate-write cycles across concurrent callers in this process.
    write_lock: Mutex<()>,
}

impl Default for WindowsCredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsCredentialStore {
    pub fn new() -> Self {
        Self {
            inner: WinVaultAdapter {
                backend: Win32CredBackend,
            },
            write_lock: Mutex::new(()),
        }
    }
}

impl CredentialStore for WindowsCredentialStore {
    fn get_password(&self, service: &str, username: &str) -> Result<Option<String>, StorageError> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| StorageError::Credential("Credential lock poisoned".to_owned()))?;
        self.inner.get_password(service, username)
    }

    fn set_password(
        &self,
        service: &str,
        username: &str,
        password: &str,
    ) -> Result<(), StorageError> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| StorageError::Credential("Credential lock poisoned".to_owned()))?;
        self.inner.set_password(service, username, password)
    }

    fn delete_password(&self, service: &str, username: &str) -> Result<(), StorageError> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| StorageError::Credential("Credential lock poisoned".to_owned()))?;
        self.inner.delete_password(service, username)
    }
}

/// Disk cache for Proton logical server payloads and measured latencies under `%LOCALAPPDATA%\FreetonVPN\servers_cache.json`.
pub struct ServerCacheManager;

#[derive(Debug, Serialize, Deserialize)]
struct ServerCacheDiskPayload {
    timestamp: i64,
    raw_payload: Option<serde_json::Value>,
    servers: Vec<ServerNode>,
}

impl ServerCacheManager {
    /// Returns `%LOCALAPPDATA%\FreetonVPN\servers_cache.json` (falling back to `%TEMP%`).
    pub fn default_cache_path() -> PathBuf {
        let base = env::var_os("LOCALAPPDATA")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir);
        base.join("FreetonVPN").join("servers_cache.json")
    }

    /// Loads cached raw payload and server list. Returns `(None, vec![])` if missing, empty, or corrupted.
    pub fn load(path: &Path) -> (Option<serde_json::Value>, Vec<ServerNode>) {
        let Ok(content) = fs::read_to_string(path) else {
            return (None, Vec::new());
        };
        let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) else {
            return (None, Vec::new());
        };
        let Some(servers_val) = parsed.get("servers") else {
            return (None, Vec::new());
        };
        let Ok(servers) = serde_json::from_value::<Vec<ServerNode>>(servers_val.clone()) else {
            return (None, Vec::new());
        };
        if servers.is_empty() {
            return (None, Vec::new());
        }
        let raw_payload = parsed.get("raw_payload").filter(|v| !v.is_null()).cloned();
        (raw_payload, servers)
    }

    /// Saves raw Proton logicals payload and processed servers to disk, creating parent directories as needed.
    pub fn save(
        path: &Path,
        raw_payload: Option<&serde_json::Value>,
        servers: &[ServerNode],
    ) -> Result<(), StorageError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let disk = ServerCacheDiskPayload {
            timestamp: current_unix_timestamp(),
            raw_payload: raw_payload.cloned(),
            servers: servers.to_vec(),
        };
        let json = serde_json::to_string(&disk)?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Removes the cache file if it exists.
    pub fn clear(path: &Path) -> Result<(), StorageError> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(StorageError::Io(err)),
        }
    }
}

/// Manages Windows user logon auto-start via `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
pub struct StartupManager;

impl StartupManager {
    /// Returns `true` when `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\FreetonVPN` has a non-empty value.
    pub fn is_enabled() -> bool {
        Self::is_enabled_in(STARTUP_REG_KEY, STARTUP_REG_VALUE_NAME)
    }

    /// Enables or disables `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\FreetonVPN` pointing to `exe_path`.
    pub fn set_enabled(exe_path: &Path, enable: bool) -> Result<(), StorageError> {
        Self::set_enabled_in(STARTUP_REG_KEY, STARTUP_REG_VALUE_NAME, exe_path, enable)
    }

    pub(crate) fn format_run_command(exe_path: &Path) -> String {
        format!("\"{}\"", exe_path.display())
    }

    fn is_enabled_in(subkey: &str, value_name: &str) -> bool {
        let subkey_w = to_wide_nul(subkey);
        let value_w = to_wide_nul(value_name);
        let mut hkey = HKEY::default();

        // SAFETY: `subkey_w` is null-terminated UTF-16 and `hkey` receives an open registry handle on ERROR_SUCCESS.
        let open_err = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(subkey_w.as_ptr()),
                Some(0),
                KEY_READ,
                &mut hkey,
            )
        };
        if open_err != WIN32_ERROR(0) {
            return false;
        }
        let _guard = RegKeyGuard(hkey);

        let mut value_type = REG_VALUE_TYPE(0);
        let mut byte_len: u32 = 0;
        // SAFETY: Querying required buffer size first with null output pointer.
        let query_len_err = unsafe {
            RegQueryValueExW(
                hkey,
                PCWSTR(value_w.as_ptr()),
                None,
                Some(&mut value_type),
                None,
                Some(&mut byte_len),
            )
        };
        if query_len_err != WIN32_ERROR(0) || byte_len == 0 {
            return false;
        }

        let mut buf = vec![0u8; byte_len as usize];
        // SAFETY: `buf` has size `byte_len` as reported by `RegQueryValueExW`.
        let query_err = unsafe {
            RegQueryValueExW(
                hkey,
                PCWSTR(value_w.as_ptr()),
                None,
                Some(&mut value_type),
                Some(buf.as_mut_ptr()),
                Some(&mut byte_len),
            )
        };
        if query_err != WIN32_ERROR(0) || value_type != REG_SZ {
            return false;
        }

        decode_reg_sz(&buf[..byte_len as usize])
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
    }

    fn set_enabled_in(
        subkey: &str,
        value_name: &str,
        exe_path: &Path,
        enable: bool,
    ) -> Result<(), StorageError> {
        let subkey_w = to_wide_nul(subkey);
        let value_w = to_wide_nul(value_name);
        let mut hkey = HKEY::default();

        // SAFETY: `subkey_w` is null-terminated UTF-16 and `hkey` receives an open registry handle.
        let open_err = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(subkey_w.as_ptr()),
                Some(0),
                KEY_SET_VALUE,
                &mut hkey,
            )
        };
        if open_err != WIN32_ERROR(0) {
            return Err(StorageError::Registry(format!(
                "RegOpenKeyExW({subkey}) failed with Win32 error {}",
                open_err.0
            )));
        }
        let _guard = RegKeyGuard(hkey);

        if enable {
            let cmd = Self::format_run_command(exe_path);
            let cmd_w = to_wide_nul(&cmd);
            let bytes: Vec<u8> = cmd_w.iter().flat_map(|c| c.to_le_bytes()).collect();
            // SAFETY: `value_w` is null-terminated UTF-16 and `bytes` holds null-terminated UTF-16 `REG_SZ`.
            let set_err = unsafe {
                RegSetValueExW(
                    hkey,
                    PCWSTR(value_w.as_ptr()),
                    Some(0),
                    REG_SZ,
                    Some(&bytes),
                )
            };
            if set_err != WIN32_ERROR(0) {
                return Err(StorageError::Registry(format!(
                    "RegSetValueExW({value_name}) failed with Win32 error {}",
                    set_err.0
                )));
            }
        } else {
            // SAFETY: `value_w` is null-terminated UTF-16.
            let del_err = unsafe { RegDeleteValueW(hkey, PCWSTR(value_w.as_ptr())) };
            if del_err != WIN32_ERROR(0) && del_err != ERROR_FILE_NOT_FOUND {
                return Err(StorageError::Registry(format!(
                    "RegDeleteValueW({value_name}) failed with Win32 error {}",
                    del_err.0
                )));
            }
        }

        Ok(())
    }
}

struct RegKeyGuard(HKEY);

impl Drop for RegKeyGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: `self.0` was opened by `RegOpenKeyExW`.
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }
}

fn to_wide_nul(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

unsafe fn pwstr_to_string(ptr: PWSTR) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    while *ptr.0.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(ptr.0, len);
    Some(String::from_utf16_lossy(slice))
}

fn encode_credential_blob_utf16(value: &str) -> Vec<u8> {
    value.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn le_bytes_to_u16_words(bytes: &[u8]) -> impl Iterator<Item = u16> + '_ {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .copied()
        .map(u16::from_le_bytes)
}

fn decode_credential_blob(bytes: &[u8]) -> Result<String, StorageError> {
    if bytes.is_empty() {
        return Ok(String::new());
    }
    if bytes.len().is_multiple_of(2) {
        let words: Vec<u16> = le_bytes_to_u16_words(bytes).collect();
        if let Ok(decoded) = String::from_utf16(&words) {
            return Ok(decoded
                .strip_prefix('\u{FEFF}')
                .unwrap_or(&decoded)
                .to_owned());
        }
    }
    String::from_utf8(bytes.to_vec())
        .map_err(|err| StorageError::Credential(format!("Invalid credential blob encoding: {err}")))
}

fn decode_reg_sz(bytes: &[u8]) -> Option<String> {
    let words: Vec<u16> = le_bytes_to_u16_words(bytes)
        .take_while(|&w| w != 0)
        .collect();
    String::from_utf16(&words).ok()
}

pub(crate) fn current_unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
use std::collections::HashMap;

#[cfg(test)]
#[derive(Default)]
struct InMemoryRawBackend {
    targets: Mutex<HashMap<String, (String, String)>>,
}

#[cfg(test)]
impl RawCredentialBackend for InMemoryRawBackend {
    fn read_target(&self, target: &str) -> Result<Option<RawCredential>, StorageError> {
        Ok(self
            .targets
            .lock()
            .expect("vault lock")
            .get(target)
            .map(|(username, secret)| RawCredential {
                username: Some(username.clone()),
                secret: secret.clone(),
            }))
    }

    fn write_target(&self, target: &str, username: &str, secret: &str) -> Result<(), StorageError> {
        self.targets
            .lock()
            .expect("vault lock")
            .insert(target.to_owned(), (username.to_owned(), secret.to_owned()));
        Ok(())
    }

    fn delete_target(&self, target: &str) -> Result<(), StorageError> {
        self.targets.lock().expect("vault lock").remove(target);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ServerNode;

    #[test]
    fn test_client_config_defaults_when_legacy_json_omits_fields() {
        let cfg: ClientConfig =
            serde_json::from_str(r#"{"private_key":"abc","expiration":0}"#).expect("legacy json");
        assert_eq!(cfg.private_key, "abc");
        assert_eq!(cfg.public_key, "");
        assert_eq!(cfg.expiration, 0);
        assert_eq!(cfg.address, "10.2.0.2/32");
        assert_eq!(cfg.dns, "10.2.0.1, 1.1.1.1");
        assert_eq!(cfg.port, "51820");
        assert!(cfg.animations_enabled);
        assert!(cfg.auto_check_update);
        assert!(!cfg.debug_mode);

        let numeric_port: ClientConfig = serde_json::from_str(
            r#"{"private_key":"xyz","port":51820,"animations_enabled":false}"#,
        )
        .expect("numeric port legacy json");
        assert_eq!(numeric_port.port, "51820");
        assert!(!numeric_port.animations_enabled);
    }

    #[test]
    fn test_server_cache_handles_corrupt_json_gracefully() {
        let dir =
            std::env::temp_dir().join(format!("freeton-cache-corrupt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("servers_cache.json");
        std::fs::write(&path, "{not valid json!!!").expect("write corrupt cache");

        let (payload, servers) = ServerCacheManager::load(&path);
        assert!(payload.is_none());
        assert!(servers.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_server_cache_roundtrip_and_missing_file() {
        let dir =
            std::env::temp_dir().join(format!("freeton-cache-roundtrip-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("nested").join("servers_cache.json");

        let (missing_payload, missing_servers) = ServerCacheManager::load(&path);
        assert!(missing_payload.is_none());
        assert!(missing_servers.is_empty());

        let raw_payload = serde_json::json!({"Code": 1000, "LogicalServers": []});
        let node = ServerNode {
            name: "JP-FREE#1".to_owned(),
            country: "JP".to_owned(),
            entry_country: "JP".to_owned(),
            city: "Tokyo".to_owned(),
            load: Some(25.0),
            status: 1,
            domain: "node-jp-01.protonvpn.net".to_owned(),
            entry_ip: "198.51.100.10".to_owned(),
            exit_ip: "198.51.100.10".to_owned(),
            x25519_public_key: "pubkey123".to_owned(),
            active_physical_servers: 1,
            ping_target: "198.51.100.10".to_owned(),
            ping_ms: Some(42.5),
        };
        ServerCacheManager::save(&path, Some(&raw_payload), std::slice::from_ref(&node))
            .expect("save cache");

        let (loaded_payload, loaded_servers) = ServerCacheManager::load(&path);
        assert_eq!(loaded_payload, Some(raw_payload));
        assert_eq!(loaded_servers, vec![node]);

        ServerCacheManager::clear(&path).expect("clear cache");
        assert!(!path.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_stored_auth_session_roundtrips_legacy_python_json() {
        let legacy = r#"{
            "UID": "uid-123",
            "AccessToken": "acc-456",
            "RefreshToken": "ref-789",
            "Scopes": ["full", "nondelinquent"],
            "Environment": "prod",
            "AccountName": "user@proton.me",
            "LastUseData": {"2FA": null, "appversion": "Other", "refresh_revision": 0}
        }"#;
        let session: StoredAuthSession = serde_json::from_str(legacy).expect("legacy session");
        assert_eq!(session.uid, "uid-123");
        assert_eq!(session.access_token, "acc-456");
        assert_eq!(session.refresh_token, "ref-789");
        assert_eq!(session.scopes, vec!["full", "nondelinquent"]);
    }

    #[test]
    fn test_winvault_target_resolution_and_utf16_blob_compatibility() {
        let adapter = WinVaultAdapter {
            backend: InMemoryRawBackend::default(),
        };

        // Simulates Python `keyring.set_password("proton-node-checker", "active-account", "User@Proton.me")`
        // followed by `keyring.set_password("proton-node-checker", "session:user@proton.me", "...")`.
        adapter
            .set_password(KEYRING_SERVICE_SRP, KEYRING_ACCOUNT_SRP, "User@Proton.me")
            .expect("write active-account");
        adapter
            .set_password(
                KEYRING_SERVICE_SRP,
                &session_username_key("User@Proton.me"),
                "{\"UID\":\"u1\"}",
            )
            .expect("write session");

        // active-account relocated to `active-account@proton-node-checker`, session stays at `proton-node-checker`.
        assert_eq!(
            adapter
                .get_password(KEYRING_SERVICE_SRP, KEYRING_ACCOUNT_SRP)
                .expect("read active-account"),
            Some("User@Proton.me".to_owned())
        );
        assert_eq!(
            adapter
                .get_password(KEYRING_SERVICE_SRP, "session:user@proton.me")
                .expect("read session"),
            Some("{\"UID\":\"u1\"}".to_owned())
        );

        // Updating active-account relocates session back to `session:user@proton.me@proton-node-checker` without losing it.
        adapter
            .set_password(KEYRING_SERVICE_SRP, KEYRING_ACCOUNT_SRP, "Other@Proton.me")
            .expect("update active-account");
        assert_eq!(
            adapter
                .get_password(KEYRING_SERVICE_SRP, "session:user@proton.me")
                .expect("read relocated session"),
            Some("{\"UID\":\"u1\"}".to_owned())
        );

        adapter
            .delete_password(KEYRING_SERVICE_SRP, "session:user@proton.me")
            .expect("delete relocated session");
        assert_eq!(
            adapter
                .get_password(KEYRING_SERVICE_SRP, "session:user@proton.me")
                .expect("verify deleted"),
            None
        );

        // Verify UTF-16LE encoding without BOM or trailing NUL matches win32ctypes.
        let encoded = encode_credential_blob_utf16("Freeton-🔑");
        assert_eq!(
            decode_credential_blob(&encoded).expect("decode utf16"),
            "Freeton-🔑"
        );
        assert_eq!(
            decode_credential_blob(b"legacy-utf8-odd").expect("decode utf8 fallback"),
            "legacy-utf8-odd"
        );
    }

    #[test]
    fn test_client_config_key_lifetime_and_startup_command_quoting() {
        let mut cfg = ClientConfig::default();
        assert!(!cfg.has_usable_key_at(1_000, 60));
        assert!(cfg.needs_key_refresh_at(1_000, 7_200));

        // Static imported key (expiration == 0) is usable and never triggers background refresh.
        cfg.private_key = "static-key".to_owned();
        cfg.expiration = 0;
        assert!(cfg.has_usable_key_at(1_000, 60));
        assert!(!cfg.needs_key_refresh_at(1_000, 7_200));

        // Dynamic key expiring in 3600s is still usable for connecting, but within 7200s refresh window.
        cfg.expiration = 4_600;
        assert!(cfg.has_usable_key_at(1_000, 60));
        assert!(cfg.needs_key_refresh_at(1_000, 7_200));

        // Dynamic key expiring in 10800s needs no refresh yet.
        cfg.expiration = 11_800;
        assert!(cfg.has_usable_key_at(1_000, 60));
        assert!(!cfg.needs_key_refresh_at(1_000, 7_200));

        assert_eq!(
            StartupManager::format_run_command(Path::new(
                r"C:\Program Files\FreetonVPN\FreetonVPN.exe"
            )),
            r#""C:\Program Files\FreetonVPN\FreetonVPN.exe""#
        );
    }
}
