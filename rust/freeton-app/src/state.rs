use std::future::Future;
use std::io;
use std::os::windows::io::{FromRawHandle, IntoRawHandle, OwnedHandle, RawHandle};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use freeton_core::api::{
    ApiError, HumanVerificationChallenge, HumanVerificationToken, LoginOutcome, ProtonClient,
    ServerNode,
};
use freeton_core::logging::{
    app_log_dir, build_realtime_log_viewer_script, clean_display_path,
    encode_powershell_encoded_command, service_log_dir, APP_LOG_FILE_NAME, SERVICE_LOG_FILE_NAME,
    TUNNEL_LOG_FILE_NAME,
};
use freeton_core::ping::{ping_servers, score_server, sort_and_filter_servers, SortMode};
use freeton_core::storage::{
    ClientConfig, CredentialStore, ServerCacheManager, StartupManager, StorageError,
    StoredAuthSession, WindowsCredentialStore, DEFAULT_WG_ADDRESS, DEFAULT_WG_DNS, DEFAULT_WG_PORT,
    KEYRING_ACCOUNT_WG_CONFIG, KEYRING_SERVICE_WG,
};
use freeton_core::updater::{
    download_and_verify_update, expected_part_filename, fetch_custom_update_info,
    fetch_update_info, is_newer_version, validate_manifest_url, UpdateAction, UpdateError,
    UpdateInfo,
};
use freeton_core::wg::{
    validate_address_list, validate_and_build_conf, validate_dns_list, validate_port_str,
    validate_wg_key, ActiveTunnelInfo, ServiceRequest, ServiceResponse, TunnelHealthState,
    DEFAULT_TUNNEL_NAME, SERVICE_PIPE_NAME,
};
use freeton_core::{APP_NAME, APP_VERSION};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::NamedPipeClient;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};
use windows::core::{w, PCWSTR};
use windows::Win32::System::Com::{
    CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

use crate::captcha::{solve_challenge_blocking, CaptchaError};
use crate::ui::dialogs::{
    parse_wireguard_conf, sibling_service_exe_path, validate_https_browser_url, DevModeTapTracker,
    ParsedWireGuardConf,
};

pub const CAPTCHA_TIMEOUT_SECS: u64 = 300;
pub const STATUS_POLL_INTERVAL: Duration = Duration::from_millis(3500);
pub const STARTUP_UPDATE_DELAY: Duration = Duration::from_secs(3);
pub const LOADING_HIDE_DELAY: Duration = Duration::from_millis(1400);
pub const DEFAULT_PING_TIMEOUT_MS: u32 = 800;
pub const DEFAULT_PING_WORKERS: usize = 16;
pub const MAX_IPC_RESPONSE_BYTES: usize = 256 * 1024;
const PIPE_CONNECT_TIMEOUT: Duration = Duration::from_secs(45);
const PIPE_CONTROL_TIMEOUT: Duration = Duration::from_secs(20);
const PIPE_STATUS_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppView {
    Login,
    Srp,
    Home,
    Drawer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewDirection {
    Forward,
    Backward,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveDialog {
    None,
    Settings,
    About,
    Update,
    ServiceRepair,
    ErrorDetail,
    LogoutConfirm,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceHealthStatus {
    Unknown,
    Healthy,
    Unavailable(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeLevel {
    Info,
    Warning,
    Success,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusNotice {
    pub text: String,
    pub level: NoticeLevel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppErrorInfo {
    pub title: String,
    pub friendly_msg: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LoadingState {
    pub visible: bool,
    pub text: String,
    pub progress: f32,
    pub hide_at: Option<Instant>,
}

impl Default for LoadingState {
    fn default() -> Self {
        Self {
            visible: false,
            text: "● Sẵn sàng".to_owned(),
            progress: 0.0,
            hide_at: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipeClientError {
    Unavailable(String),
    Io(String),
    Protocol(String),
    ServiceError { code: String, message: String },
}

impl std::fmt::Display for PipeClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(msg) => write!(f, "FreetonVPNService chưa sẵn sàng: {msg}"),
            Self::Io(msg) => write!(f, "Lỗi giao tiếp dịch vụ VPN: {msg}"),
            Self::Protocol(msg) => write!(f, "Phản hồi IPC không hợp lệ: {msg}"),
            Self::ServiceError { code, message } => write!(f, "[{code}] {message}"),
        }
    }
}

pub type PipeFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait PipeTransport: Send + Sync {
    fn send_request<'a>(
        &'a self,
        req: &'a ServiceRequest,
        timeout: Duration,
    ) -> PipeFuture<'a, Result<ServiceResponse, PipeClientError>>;
}

/// Frames a single `ServiceRequest` -> newline-delimited JSON -> `ServiceResponse` exchange
/// over any bidirectional `AsyncRead + AsyncWrite` stream.
pub async fn frame_ipc_exchange<S>(
    stream: S,
    req: &ServiceRequest,
) -> Result<ServiceResponse, PipeClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut json =
        serde_json::to_string(req).map_err(|e| PipeClientError::Protocol(e.to_string()))?;
    json.push('\n');

    let (read_half, mut write_half) = tokio::io::split(stream);
    write_half
        .write_all(json.as_bytes())
        .await
        .map_err(|e| PipeClientError::Io(e.to_string()))?;
    write_half
        .flush()
        .await
        .map_err(|e| PipeClientError::Io(e.to_string()))?;

    let mut reader = BufReader::new(read_half);
    let mut buf = Vec::with_capacity(256);
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|e| PipeClientError::Io(e.to_string()))?;
        if available.is_empty() {
            if buf.is_empty() {
                return Err(PipeClientError::Io(
                    "Named pipe closed before response arrived".to_owned(),
                ));
            }
            break;
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            let take = pos + 1;
            if buf.len() + take > MAX_IPC_RESPONSE_BYTES {
                return Err(PipeClientError::Protocol(
                    "IPC response exceeds maximum allowed size".to_owned(),
                ));
            }
            buf.extend_from_slice(&available[..take]);
            reader.consume(take);
            break;
        }
        if buf.len() + available.len() > MAX_IPC_RESPONSE_BYTES {
            return Err(PipeClientError::Protocol(
                "IPC response exceeds maximum allowed size".to_owned(),
            ));
        }
        buf.extend_from_slice(available);
        let len = available.len();
        reader.consume(len);
    }

    let text = String::from_utf8(buf).map_err(|e| PipeClientError::Protocol(e.to_string()))?;
    serde_json::from_str::<ServiceResponse>(text.trim())
        .map_err(|e| PipeClientError::Protocol(e.to_string()))
}

pub struct WindowsPipeTransport {
    pipe_name: String,
}

impl WindowsPipeTransport {
    pub fn new(pipe_name: impl Into<String>) -> Self {
        Self {
            pipe_name: pipe_name.into(),
        }
    }

    fn try_open_pipe_once(
        wide_name: &[u16],
        past_deadline: bool,
    ) -> Result<Option<NamedPipeClient>, PipeClientError> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::ERROR_PIPE_BUSY;
        use windows::Win32::Storage::FileSystem::{
            CreateFileW, FILE_FLAG_OVERLAPPED, FILE_READ_DATA, FILE_SHARE_MODE, FILE_WRITE_DATA,
            OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
        };

        let access = FILE_READ_DATA.0 | FILE_WRITE_DATA.0;
        let flags = FILE_FLAG_OVERLAPPED | SECURITY_IDENTIFICATION | SECURITY_SQOS_PRESENT;
        let res = unsafe {
            CreateFileW(
                PCWSTR(wide_name.as_ptr()),
                access,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                flags,
                None,
            )
        };
        match res {
            Ok(handle) => {
                if handle.is_invalid() {
                    return Err(PipeClientError::Io(
                        "CreateFileW returned an invalid pipe handle".to_owned(),
                    ));
                }
                // SAFETY: `CreateFileW` just created an exclusive valid Win32 handle.
                let owned = unsafe { OwnedHandle::from_raw_handle(handle.0 as RawHandle) };
                // SAFETY: Runs on an I/O-enabled Tokio runtime with `FILE_FLAG_OVERLAPPED`,
                // transferring sole ownership of the handle into `NamedPipeClient`.
                let client = unsafe { NamedPipeClient::from_raw_handle(owned.into_raw_handle()) }
                    .map_err(|e| PipeClientError::Io(e.to_string()))?;
                Ok(Some(client))
            }
            Err(err) => {
                let hresult = err.code().0 as u32;
                let os_err = if (hresult & 0xFFFF_0000) == 0x8007_0000 {
                    io::Error::from_raw_os_error((hresult & 0xFFFF) as i32)
                } else {
                    io::Error::other(err.to_string())
                };
                if os_err.raw_os_error() == Some(ERROR_PIPE_BUSY.0 as i32) {
                    if !past_deadline {
                        return Ok(None);
                    }
                    return Err(PipeClientError::Unavailable(os_err.to_string()));
                }
                if matches!(
                    os_err.kind(),
                    io::ErrorKind::NotFound
                        | io::ErrorKind::PermissionDenied
                        | io::ErrorKind::ConnectionRefused
                ) {
                    return Err(PipeClientError::Unavailable(os_err.to_string()));
                }
                Err(PipeClientError::Io(os_err.to_string()))
            }
        }
    }

    async fn open_named_pipe_client(
        pipe_name: &str,
        timeout: Duration,
    ) -> Result<NamedPipeClient, PipeClientError> {
        let wide_name: Vec<u16> = pipe_name.encode_utf16().chain(Some(0)).collect();
        let open_deadline = Instant::now() + timeout.min(Duration::from_secs(2));

        loop {
            let past_deadline = Instant::now() >= open_deadline;
            if let Some(client) = Self::try_open_pipe_once(&wide_name, past_deadline)? {
                return Ok(client);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

impl Default for WindowsPipeTransport {
    fn default() -> Self {
        Self::new(SERVICE_PIPE_NAME)
    }
}

impl PipeTransport for WindowsPipeTransport {
    fn send_request<'a>(
        &'a self,
        req: &'a ServiceRequest,
        timeout: Duration,
    ) -> PipeFuture<'a, Result<ServiceResponse, PipeClientError>> {
        let pipe_name = self.pipe_name.clone();
        let req_owned = req.clone();
        Box::pin(async move {
            let started = Instant::now();
            let client = Self::open_named_pipe_client(&pipe_name, timeout).await?;
            let remaining = timeout
                .saturating_sub(started.elapsed())
                .max(Duration::from_millis(50));
            match tokio::time::timeout(remaining, frame_ipc_exchange(client, &req_owned)).await {
                Ok(res) => res,
                Err(_) => Err(PipeClientError::Io(
                    "Hết thời gian chờ phản hồi từ FreetonVPNService.".to_owned(),
                )),
            }
        })
    }
}

pub trait ShellLauncher: Send + Sync {
    fn launch_elevated(
        &self,
        target: &Path,
        args: &str,
        working_dir: Option<&Path>,
    ) -> Result<(), String>;
    fn open_https_url(&self, url: &str) -> Result<(), String>;
    fn open_directory(&self, dir: &Path) -> Result<(), String>;
    fn open_realtime_log_cli(
        &self,
        app_log: &Path,
        service_log: &Path,
        tunnel_log: &Path,
    ) -> Result<(), String>;
}

struct ComStaGuard(bool);

impl ComStaGuard {
    fn enter() -> Self {
        let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) };
        Self(hr.is_ok())
    }
}

impl Drop for ComStaGuard {
    fn drop(&mut self) {
        if self.0 {
            unsafe { CoUninitialize() };
        }
    }
}

pub struct WindowsShellLauncher;

impl WindowsShellLauncher {
    pub fn open_https_url_direct(url: &str) -> Result<(), String> {
        let safe_url = validate_https_browser_url(url)?;
        let _com = ComStaGuard::enter();
        let url_w: Vec<u16> = safe_url.encode_utf16().chain(Some(0)).collect();
        let hinst = unsafe {
            ShellExecuteW(
                None,
                w!("open"),
                PCWSTR(url_w.as_ptr()),
                PCWSTR::null(),
                PCWSTR::null(),
                SW_SHOWNORMAL,
            )
        };
        let code = hinst.0 as isize;
        if code > 32 {
            Ok(())
        } else {
            let err = io::Error::last_os_error();
            Err(format!(
                "Không thể mở trình duyệt (mã ShellExecuteW={code}: {err})."
            ))
        }
    }
}

impl ShellLauncher for WindowsShellLauncher {
    fn launch_elevated(
        &self,
        target: &Path,
        args: &str,
        working_dir: Option<&Path>,
    ) -> Result<(), String> {
        let _com = ComStaGuard::enter();
        let target_str = target.to_string_lossy();
        let target_w: Vec<u16> = target_str.encode_utf16().chain(Some(0)).collect();
        let args_w: Vec<u16> = args.encode_utf16().chain(Some(0)).collect();
        let args_ptr = if args.trim().is_empty() {
            PCWSTR::null()
        } else {
            PCWSTR(args_w.as_ptr())
        };
        let dir_w: Option<Vec<u16>> =
            working_dir.map(|d| d.to_string_lossy().encode_utf16().chain(Some(0)).collect());
        let dir_ptr = dir_w
            .as_ref()
            .map_or(PCWSTR::null(), |v| PCWSTR(v.as_ptr()));

        let hinst = unsafe {
            ShellExecuteW(
                None,
                w!("runas"),
                PCWSTR(target_w.as_ptr()),
                args_ptr,
                dir_ptr,
                SW_SHOWNORMAL,
            )
        };
        let code = hinst.0 as isize;
        if code > 32 {
            Ok(())
        } else {
            let last_err = io::Error::last_os_error();
            if code == 5 || last_err.raw_os_error() == Some(1223) {
                Err(
                    "Người dùng đã từ chối cấp quyền quản trị (UAC) hoặc không có quyền thực thi."
                        .to_owned(),
                )
            } else {
                Err(format!(
                    "Không thể khởi chạy tiến trình với quyền quản trị (mã ShellExecuteW={code}: {last_err})."
                ))
            }
        }
    }

    fn open_https_url(&self, url: &str) -> Result<(), String> {
        Self::open_https_url_direct(url)
    }

    fn open_directory(&self, dir: &Path) -> Result<(), String> {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("Không thể tạo thư mục {}: {e}", dir.display()))?;
        let _com = ComStaGuard::enter();
        let display = clean_display_path(dir);
        let dir_w: Vec<u16> = display.encode_utf16().chain(Some(0)).collect();
        let hinst = unsafe {
            ShellExecuteW(
                None,
                w!("open"),
                PCWSTR(dir_w.as_ptr()),
                PCWSTR::null(),
                PCWSTR::null(),
                SW_SHOWNORMAL,
            )
        };
        let code = hinst.0 as isize;
        if code > 32 {
            Ok(())
        } else {
            let err = io::Error::last_os_error();
            Err(format!("Không thể mở thư mục log (mã {code}: {err})."))
        }
    }

    fn open_realtime_log_cli(
        &self,
        app_log: &Path,
        service_log: &Path,
        tunnel_log: &Path,
    ) -> Result<(), String> {
        const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
        if let Some(parent) = app_log.parent().filter(|p| !p.as_os_str().is_empty()) {
            let _ = std::fs::create_dir_all(parent);
        }
        let sys_root = std::env::var_os("SystemRoot")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        let ps_exe = sys_root
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");

        let script = build_realtime_log_viewer_script(app_log, service_log, tunnel_log);
        let encoded = encode_powershell_encoded_command(&script);
        std::process::Command::new(&ps_exe)
            .creation_flags(CREATE_NEW_CONSOLE)
            .args(["-NoLogo", "-NoExit", "-EncodedCommand", &encoded])
            .spawn()
            .map(|_| ())
            .map_err(|e| format!("Không thể mở cửa sổ CLI realtime log: {e}"))
    }
}

pub trait StartupController: Send + Sync {
    fn is_enabled(&self) -> bool;
    fn set_enabled(&self, enable: bool) -> Result<(), StorageError>;
}

pub struct WindowsStartupController;

impl StartupController for WindowsStartupController {
    fn is_enabled(&self) -> bool {
        StartupManager::is_enabled()
    }

    fn set_enabled(&self, enable: bool) -> Result<(), StorageError> {
        let exe_path = std::env::current_exe()?;
        StartupManager::set_enabled(&exe_path, enable)
    }
}

#[derive(Default)]
pub struct UpdateCancelCoordinator {
    active: Option<(u64, watch::Sender<bool>)>,
    cancelled_gens: Vec<u64>,
}

impl UpdateCancelCoordinator {
    pub fn register(&mut self, generation: u64) -> Option<watch::Receiver<bool>> {
        if self.cancelled_gens.contains(&generation) {
            return None;
        }
        if let Some((_, prev_tx)) = self.active.take() {
            let _ = prev_tx.send(true);
        }
        let (tx, rx) = watch::channel(false);
        self.active = Some((generation, tx));
        Some(rx)
    }

    pub fn cancel(&mut self, generation: u64) {
        if !self.cancelled_gens.contains(&generation) {
            if self.cancelled_gens.len() >= 16 {
                self.cancelled_gens.remove(0);
            }
            self.cancelled_gens.push(generation);
        }
        if let Some((active_gen, tx)) = self.active.as_ref() {
            if *active_gen == generation {
                let _ = tx.send(true);
            }
        }
    }

    pub fn clear(&mut self, generation: u64) {
        if self.active.as_ref().is_some_and(|(g, _)| *g == generation) {
            self.active = None;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsDraft {
    pub startup_enabled: bool,
    pub startup_dirty: bool,
    pub animations_enabled: bool,
    pub auto_check_update: bool,
    pub private_key: String,
    pub public_key: String,
    pub expiration: i64,
    pub address: String,
    pub dns: String,
    pub port: String,
    pub custom_update_url: String,
    pub original_private_key: String,
    pub imported_from_conf: bool,
}

impl SettingsDraft {
    pub fn from_config(cfg: &ClientConfig, startup_enabled: bool) -> Self {
        Self {
            startup_enabled,
            startup_dirty: false,
            animations_enabled: cfg.animations_enabled,
            auto_check_update: cfg.auto_check_update,
            private_key: cfg.private_key.clone(),
            public_key: cfg.public_key.clone(),
            expiration: cfg.expiration,
            address: cfg.address.clone(),
            dns: cfg.dns.clone(),
            port: cfg.port.clone(),
            custom_update_url: cfg.custom_update_url.clone(),
            original_private_key: cfg.private_key.clone(),
            imported_from_conf: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub enum UpdateDialogPhase {
    #[default]
    Idle,
    Downloading {
        downloaded_bytes: u64,
        total_bytes: u64,
        percent: f32,
        confirm_cancel: bool,
    },
    Verifying,
    LaunchingInstaller,
    BrowserOpened(String),
    Cancelled,
    Failed(String),
}

impl UpdateDialogPhase {
    pub fn is_busy(&self) -> bool {
        matches!(
            self,
            Self::Downloading { .. } | Self::Verifying | Self::LaunchingInstaller
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ServiceRepairPhase {
    #[default]
    Idle,
    LaunchingAndWaiting,
    Succeeded,
    Failed(String),
}

#[derive(Debug, Clone)]
pub enum UiCommand {
    SrpLogin {
        username: String,
        password: String,
        two_factor: String,
        pending_session: Option<(String, StoredAuthSession)>,
    },
    StartScan {
        auth_generation: u64,
    },
    EnsureWgKey {
        auth_generation: u64,
        force: bool,
    },
    FetchWgKeyManual {
        auth_generation: u64,
    },
    PickAndImportConf,
    RefreshStartupStatus,
    SetStartupEnabled {
        enabled: bool,
    },
    Connect {
        generation: u64,
        auth_generation: u64,
        server: ServerNode,
    },
    Disconnect {
        generation: u64,
    },
    RefreshTunnelStatus {
        generation: u64,
    },
    ResolvePublicIp {
        generation: u64,
    },
    CheckForUpdates {
        manual: bool,
        manifest_url_override: Option<String>,
    },
    StartUpdateDownload {
        generation: u64,
        info: UpdateInfo,
    },
    CancelUpdateDownload {
        generation: u64,
    },
    LaunchUpdateInstaller {
        path: PathBuf,
    },
    OpenExternalUrl {
        url: String,
    },
    OpenLogFolder,
    OpenRealtimeLogCli,
    RepairService,
    ExportConf {
        auth_generation: u64,
        server: ServerNode,
    },
    SaveClientConfig {
        config: ClientConfig,
    },
    ShutdownOnExit,
}

#[derive(Debug, Clone)]
pub enum WorkerEvent {
    LoginStatus(StatusNotice),
    LoginSuccess {
        account: String,
    },
    LoginNeedsTwoFactor {
        account: String,
        session: StoredAuthSession,
    },
    LoginError {
        title: String,
        friendly_msg: String,
        detail: String,
        inline_msg: String,
    },
    LoadingProgress {
        auth_generation: u64,
        text: String,
        progress: f32,
    },
    ScanStatus {
        auth_generation: u64,
        text: String,
    },
    ScanComplete {
        auth_generation: u64,
        raw_payload: Option<serde_json::Value>,
        servers: Vec<ServerNode>,
    },
    ScanError {
        auth_generation: u64,
        friendly_msg: String,
        detail: String,
    },
    ScanNeedsLogin {
        auth_generation: u64,
    },
    SessionExpired {
        auth_generation: u64,
        detail: String,
    },
    WgKeyRefreshed {
        auth_generation: u64,
        key: WgKeySnapshot,
    },
    WgKeyManualSucceeded {
        auth_generation: u64,
        key: WgKeySnapshot,
    },
    WgKeyManualFailed {
        auth_generation: u64,
        friendly_msg: String,
        detail: String,
    },
    ConfImportCancelled,
    ConfImported {
        filename: String,
        parsed: ParsedWireGuardConf,
    },
    ConfImportError {
        title: String,
        friendly_msg: String,
        detail: String,
    },
    StartupStatusLoaded {
        enabled: bool,
    },
    StartupSaveResult {
        enabled: bool,
        error: Option<String>,
    },
    ConnectProgress {
        generation: u64,
        text: String,
        progress: f32,
    },
    ConnectSucceeded {
        generation: u64,
        payload: Box<ConnectSuccessPayload>,
    },
    ConnectFailed {
        generation: u64,
        message: String,
        detail: String,
        service_unavailable: bool,
    },
    DisconnectSucceeded {
        generation: u64,
    },
    DisconnectFailed {
        generation: u64,
        message: String,
        detail: String,
    },
    TunnelStatus {
        generation: u64,
        status: Result<TunnelHealthState, PipeClientError>,
    },
    PublicIpResolved {
        generation: u64,
        ip: String,
    },
    UpdateAvailable {
        info: UpdateInfo,
    },
    UpdateUpToDate {
        manual: bool,
        current_version: String,
    },
    UpdateCheckFailed {
        manual: bool,
        message: String,
    },
    UpdateDownloadProgress {
        generation: u64,
        downloaded_bytes: u64,
        total_bytes: u64,
        percent: f32,
    },
    UpdateDownloadCancelled {
        generation: u64,
    },
    UpdateDownloadFinished {
        generation: u64,
        action: Result<UpdateAction, String>,
    },
    UpdateInstallerLaunched {
        result: Result<(), String>,
    },
    ExternalUrlError {
        message: String,
    },
    ServiceRepairSucceeded,
    ServiceRepairFailed {
        message: String,
        detail: String,
    },
    ConfExported {
        message: String,
    },
    ConfExportError {
        title: String,
        friendly_msg: String,
        detail: String,
    },
    ExitReady {
        error: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgKeySnapshot {
    pub private_key: String,
    pub public_key: String,
    pub expiration: i64,
}

impl WgKeySnapshot {
    pub fn from_config(cfg: &ClientConfig) -> Self {
        Self {
            private_key: cfg.private_key.clone(),
            public_key: cfg.public_key.clone(),
            expiration: cfg.expiration,
        }
    }

    pub fn apply_to(&self, target: &mut ClientConfig) {
        target.private_key = self.private_key.clone();
        target.public_key = self.public_key.clone();
        target.expiration = self.expiration;
    }
}

#[derive(Debug, Clone)]
pub struct ConnectSuccessPayload {
    pub server: ServerNode,
    pub info: ActiveTunnelInfo,
    pub wg_key: Option<WgKeySnapshot>,
}

#[derive(Debug, Clone)]
pub struct SrpLoginParams<'a> {
    pub username: &'a str,
    pub password: &'a str,
    pub two_factor: &'a str,
    pub pending_session: Option<(String, StoredAuthSession)>,
}

pub struct AppState {
    pub current_view: AppView,
    pub previous_view: Option<AppView>,
    pub view_transition_dir: ViewDirection,
    pub view_transition_started: Option<Instant>,
    pub active_dialog: ActiveDialog,
    pub is_logged_in: bool,
    pub active_account: Option<String>,
    pub srp_username: String,
    pub srp_password: String,
    pub srp_2fa: String,
    pub srp_show_password: bool,
    pub is_srp_logging_in: bool,
    pub srp_status: Option<StatusNotice>,
    pub pending_srp_account: Option<String>,
    pub pending_srp_session: Option<StoredAuthSession>,
    pub raw_payload: Option<serde_json::Value>,
    pub all_free_servers: Vec<ServerNode>,
    pub selected_server: Option<ServerNode>,
    pub connected_server: Option<ServerNode>,
    pub server_selection_manual: bool,
    pub is_scanning: bool,
    pub is_connecting_vpn: bool,
    pub is_disconnecting_vpn: bool,
    pub tunnel_running: bool,
    pub tunnel_verified: bool,
    pub tunnel_unverified_reason: Option<String>,
    pub status_check_pending: bool,
    pub connection_generation: u64,
    pub auth_generation: u64,
    pub closing: bool,
    pub exit_ready: bool,
    pub logout_after_disconnect: bool,
    pub client_config: ClientConfig,
    pub live_public_ip: Option<String>,
    pub vpn_connect_time_unix: Option<i64>,
    pub selected_country_code: Option<String>,
    pub search_query: String,
    pub sort_mode: SortMode,
    pub loading: LoadingState,
    pub available_update: Option<UpdateInfo>,
    pub update_check_message: Option<String>,
    pub update_check_pending: bool,
    pub update_generation: u64,
    pub update_phase: UpdateDialogPhase,
    pub service_health: ServiceHealthStatus,
    pub service_repair_phase: ServiceRepairPhase,
    pub service_repair_detail: Option<String>,
    pub error_modal: Option<AppErrorInfo>,
    pub return_dialog: Option<ActiveDialog>,
    pub info_toast: Option<StatusNotice>,
    pub startup_enabled: bool,
    startup_before_save: Option<bool>,
    pub settings_draft: SettingsDraft,
    pub settings_key_fetching: bool,
    pub settings_conf_importing: bool,
    pub settings_status_msg: Option<StatusNotice>,
    pub settings_dev_taps: DevModeTapTracker,
    pub window_visible: bool,
    pub window_drag_active: bool,
    pub user_has_custom_dragged: bool,
    pub drawer_scroll_to_top: bool,
    auth_generation_shared: Arc<AtomicU64>,
    last_status_poll: Instant,
    startup_update_checked: bool,
    started_at: Instant,
    pending_commands: Vec<UiCommand>,
}

impl AppState {
    pub fn from_local_storage(store: &dyn CredentialStore) -> Self {
        let client_config = store.load_client_config().unwrap_or_default();
        let active_account = store.load_auth_session().ok().flatten().map(|(acc, _)| acc);
        let is_logged_in = active_account.is_some();
        let cache_path = ServerCacheManager::default_cache_path();
        let (raw_payload, cached_servers) = ServerCacheManager::load(&cache_path);
        let mut state = Self::new(
            is_logged_in,
            active_account,
            client_config,
            raw_payload,
            cached_servers,
        );
        let startup_enabled = StartupManager::is_enabled();
        state.startup_enabled = startup_enabled;
        state.settings_draft.startup_enabled = startup_enabled;
        state
    }

    pub fn new(
        is_logged_in: bool,
        active_account: Option<String>,
        client_config: ClientConfig,
        raw_payload: Option<serde_json::Value>,
        cached_servers: Vec<ServerNode>,
    ) -> Self {
        let now = Instant::now();
        let initial_auth_generation = u64::from(is_logged_in);
        let auth_generation_shared = Arc::new(AtomicU64::new(initial_auth_generation));
        let settings_draft = SettingsDraft::from_config(&client_config, false);
        let mut state = Self {
            current_view: if is_logged_in {
                AppView::Home
            } else {
                AppView::Login
            },
            previous_view: None,
            view_transition_dir: ViewDirection::Forward,
            view_transition_started: None,
            active_dialog: ActiveDialog::None,
            is_logged_in,
            active_account,
            srp_username: String::new(),
            srp_password: String::new(),
            srp_2fa: String::new(),
            srp_show_password: false,
            is_srp_logging_in: false,
            srp_status: None,
            pending_srp_account: None,
            pending_srp_session: None,
            raw_payload,
            all_free_servers: cached_servers,
            selected_server: None,
            connected_server: None,
            server_selection_manual: false,
            is_scanning: false,
            is_connecting_vpn: false,
            is_disconnecting_vpn: false,
            tunnel_running: false,
            tunnel_verified: false,
            tunnel_unverified_reason: None,
            status_check_pending: false,
            connection_generation: 0,
            auth_generation: initial_auth_generation,
            closing: false,
            exit_ready: false,
            logout_after_disconnect: false,
            client_config,
            live_public_ip: None,
            vpn_connect_time_unix: None,
            selected_country_code: None,
            search_query: String::new(),
            sort_mode: SortMode::Best,
            loading: LoadingState::default(),
            available_update: None,
            update_check_message: None,
            update_check_pending: false,
            update_generation: 0,
            update_phase: UpdateDialogPhase::Idle,
            service_health: ServiceHealthStatus::Unknown,
            service_repair_phase: ServiceRepairPhase::Idle,
            service_repair_detail: None,
            error_modal: None,
            return_dialog: None,
            info_toast: None,
            startup_enabled: false,
            startup_before_save: None,
            settings_draft,
            settings_key_fetching: false,
            settings_conf_importing: false,
            settings_status_msg: None,
            settings_dev_taps: DevModeTapTracker::default(),
            window_visible: true,
            window_drag_active: false,
            user_has_custom_dragged: false,
            drawer_scroll_to_top: false,
            auth_generation_shared,
            last_status_poll: now,
            startup_update_checked: false,
            started_at: now,
            pending_commands: Vec::new(),
        };

        if !state.all_free_servers.is_empty() {
            state.pick_best_server_as_selected();
        }

        state.request_status_refresh();
        if state.is_logged_in {
            if !state.all_free_servers.is_empty() {
                state.show_loading_status("● Đang kiểm tra & cập nhật danh sách máy chủ...", 0.1);
            }
            state.start_scan();
            if state
                .client_config
                .needs_key_refresh(freeton_core::api::WG_KEY_REFRESH_WINDOW_SECS)
            {
                state.pending_commands.push(UiCommand::EnsureWgKey {
                    auth_generation: state.auth_generation,
                    force: false,
                });
            }
        } else {
            state.hide_loading_with_delay("● Vui lòng đăng nhập để bắt đầu.");
        }

        state
    }

    pub fn auth_generation_handle(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.auth_generation_shared)
    }

    fn bump_auth_generation(&mut self) -> u64 {
        self.auth_generation = self.auth_generation.saturating_add(1);
        self.auth_generation_shared
            .store(self.auth_generation, Ordering::Release);
        self.auth_generation
    }

    pub fn drain_commands(&mut self) -> Vec<UiCommand> {
        std::mem::take(&mut self.pending_commands)
    }

    pub fn account_chip_text(&self) -> String {
        if !self.is_logged_in {
            return "○ Chưa đăng nhập".to_owned();
        }
        match self.active_account.as_deref() {
            Some(acc) if !acc.trim().is_empty() => {
                let trimmed = acc.trim();
                let chars: Vec<char> = trimmed.chars().collect();
                if chars.len() <= 14 {
                    format!("● {trimmed}")
                } else {
                    let prefix: String = chars.into_iter().take(11).collect();
                    format!("● {prefix}...")
                }
            }
            _ => "● Đã đăng nhập".to_owned(),
        }
    }

    pub fn transition_progress(&self, now: Instant) -> f32 {
        if !self.client_config.animations_enabled {
            return 1.0;
        }
        let Some(started) = self.view_transition_started else {
            return 1.0;
        };
        let elapsed = now.saturating_duration_since(started).as_secs_f32();
        let t = (elapsed / 0.22).clamp(0.0, 1.0);
        1.0 - (1.0 - t).powi(4)
    }

    fn switch_view(&mut self, target: AppView, dir: ViewDirection) {
        if self.current_view != target {
            self.previous_view = Some(self.current_view);
            self.current_view = target;
            self.view_transition_dir = dir;
            self.view_transition_started = if self.client_config.animations_enabled {
                Some(Instant::now())
            } else {
                None
            };
        }
    }

    pub fn show_login_view(&mut self) {
        self.switch_view(AppView::Login, ViewDirection::Backward);
    }

    pub fn show_srp_view(&mut self) {
        self.srp_status = None;
        self.switch_view(AppView::Srp, ViewDirection::Forward);
    }

    pub fn show_home_view(&mut self) {
        if !self.is_logged_in {
            self.show_login_view();
            return;
        }
        self.switch_view(AppView::Home, ViewDirection::Backward);
    }

    pub fn show_drawer_view(&mut self) {
        if !self.is_logged_in {
            self.show_login_view();
            return;
        }
        debug!(server_count = self.all_free_servers.len(), "Opened server list drawer");
        self.drawer_scroll_to_top = true;
        self.switch_view(AppView::Drawer, ViewDirection::Forward);
    }

    pub fn open_settings_dialog(&mut self) {
        info!("Opened Settings dialog");
        self.settings_draft = SettingsDraft::from_config(&self.client_config, self.startup_enabled);
        self.settings_status_msg = None;
        self.settings_dev_taps.reset();
        if self.service_repair_phase != ServiceRepairPhase::LaunchingAndWaiting {
            self.service_repair_phase = ServiceRepairPhase::Idle;
            self.service_repair_detail = None;
        }
        self.return_dialog = None;
        self.active_dialog = ActiveDialog::Settings;
        self.window_visible = true;
        self.pending_commands.push(UiCommand::RefreshStartupStatus);
        self.request_status_refresh();
    }

    pub fn open_about_dialog(&mut self) {
        info!("Opened About dialog");
        self.settings_dev_taps.reset();
        self.return_dialog = None;
        self.active_dialog = ActiveDialog::About;
        self.window_visible = true;
    }

    pub fn open_service_repair_dialog(&mut self) {
        info!("Opened Service Repair dialog");
        if self.service_repair_phase != ServiceRepairPhase::LaunchingAndWaiting {
            self.service_repair_phase = ServiceRepairPhase::Idle;
            self.service_repair_detail = None;
        }
        self.return_dialog = None;
        self.active_dialog = ActiveDialog::ServiceRepair;
        self.window_visible = true;
    }

    pub fn close_dialog(&mut self) {
        if self.active_dialog == ActiveDialog::Update {
            let is_mandatory = self.available_update.as_ref().is_some_and(|u| u.mandatory);
            if is_mandatory || self.update_phase.is_busy() {
                return;
            }
        }
        if self.active_dialog == ActiveDialog::ErrorDetail {
            if let Some(prev) = self.return_dialog.take() {
                self.active_dialog = prev;
                return;
            }
        }
        if self.active_dialog == ActiveDialog::ServiceRepair {
            if self.service_repair_phase == ServiceRepairPhase::LaunchingAndWaiting {
                return;
            }
            self.service_repair_phase = ServiceRepairPhase::Idle;
            self.service_repair_detail = None;
        }
        if matches!(self.active_dialog, ActiveDialog::Settings | ActiveDialog::About) {
            self.settings_dev_taps.reset();
        }
        self.return_dialog = None;
        self.active_dialog = ActiveDialog::None;
    }

    pub fn save_settings_dialog(&mut self) {
        let mut cfg = self.client_config.clone();
        let custom_priv = self.settings_draft.private_key.trim().to_owned();
        if custom_priv.is_empty() {
            cfg.private_key.clear();
            cfg.public_key.clear();
            cfg.expiration = 0;
        } else {
            let validated_priv = match validate_wg_key("Private Key", &custom_priv) {
                Ok(key) => key,
                Err(err) => {
                    let msg = format!(
                        "❌ Private Key WireGuard không hợp lệ (cần khóa Base64 32 byte hoặc để trống để xóa): {err}"
                    );
                    self.settings_status_msg = Some(StatusNotice {
                        text: msg.clone(),
                        level: NoticeLevel::Error,
                    });
                    self.info_toast = Some(StatusNotice {
                        text: msg,
                        level: NoticeLevel::Error,
                    });
                    return;
                }
            };
            cfg.private_key = validated_priv.clone();
            if self.settings_draft.imported_from_conf
                || validated_priv != self.settings_draft.original_private_key
            {
                cfg.public_key.clear();
                cfg.expiration = 0;
            } else {
                cfg.public_key = self.settings_draft.public_key.clone();
                cfg.expiration = self.settings_draft.expiration;
            }
        }

        let addr_raw = self.settings_draft.address.trim();
        cfg.address = if addr_raw.is_empty() {
            DEFAULT_WG_ADDRESS.to_owned()
        } else {
            match validate_address_list(addr_raw) {
                Ok(addr) => addr,
                Err(err) => {
                    let msg = format!("❌ Địa chỉ Interface WireGuard không hợp lệ: {err}");
                    self.settings_status_msg = Some(StatusNotice {
                        text: msg.clone(),
                        level: NoticeLevel::Error,
                    });
                    self.info_toast = Some(StatusNotice {
                        text: msg,
                        level: NoticeLevel::Error,
                    });
                    return;
                }
            }
        };

        cfg.dns = match validate_dns_list(self.settings_draft.dns.trim()) {
            Ok(dns) => dns,
            Err(err) => {
                let msg = format!(
                    "❌ DNS Server không hợp lệ (nhập các IP cách nhau bởi dấu phẩy, vd 10.2.0.1, 1.1.1.1): {err}"
                );
                self.settings_status_msg = Some(StatusNotice {
                    text: msg.clone(),
                    level: NoticeLevel::Error,
                });
                self.info_toast = Some(StatusNotice {
                    text: msg,
                    level: NoticeLevel::Error,
                });
                return;
            }
        };

        cfg.port = match validate_port_str(self.settings_draft.port.trim()) {
            Ok(port) => port.to_string(),
            Err(err) => {
                let msg = format!("❌ Port WireGuard không hợp lệ (cần số từ 1 đến 65535): {err}");
                self.settings_status_msg = Some(StatusNotice {
                    text: msg.clone(),
                    level: NoticeLevel::Error,
                });
                self.info_toast = Some(StatusNotice {
                    text: msg,
                    level: NoticeLevel::Error,
                });
                return;
            }
        };

        let custom_update_raw = self.settings_draft.custom_update_url.trim();
        cfg.custom_update_url = if custom_update_raw.is_empty() {
            String::new()
        } else {
            match validate_manifest_url(custom_update_raw) {
                Ok(url) => url,
                Err(err) => {
                    let msg = format!(
                        "❌ Update Manifest URL không hợp lệ (cần https:// hoặc http://127.0.0.1 / localhost): {err}"
                    );
                    self.settings_status_msg = Some(StatusNotice {
                        text: msg.clone(),
                        level: NoticeLevel::Error,
                    });
                    self.info_toast = Some(StatusNotice {
                        text: msg,
                        level: NoticeLevel::Error,
                    });
                    return;
                }
            }
        };

        cfg.animations_enabled = self.settings_draft.animations_enabled;
        cfg.auto_check_update = self.settings_draft.auto_check_update;
        cfg.debug_mode = self.client_config.debug_mode;

        self.startup_before_save = Some(self.startup_enabled);
        self.startup_enabled = self.settings_draft.startup_enabled;
        self.save_client_config(cfg);
        self.pending_commands.push(UiCommand::SetStartupEnabled {
            enabled: self.settings_draft.startup_enabled,
        });
        self.settings_dev_taps.reset();
        self.settings_status_msg = None;
        self.return_dialog = None;
        self.active_dialog = ActiveDialog::None;
        self.info_toast = Some(StatusNotice {
            text: "Đã lưu và áp dụng cài đặt thành công!".to_owned(),
            level: NoticeLevel::Success,
        });
        info!(
            startup = self.settings_draft.startup_enabled,
            animations = self.client_config.animations_enabled,
            auto_check_update = self.client_config.auto_check_update,
            port = %self.client_config.port,
            dns = %self.client_config.dns,
            dev_mode = self.client_config.debug_mode,
            "Settings saved"
        );
    }

    pub fn toggle_dev_mode(&mut self) {
        let mut cfg = self.client_config.clone();
        cfg.debug_mode = !cfg.debug_mode;
        self.save_client_config(cfg);

        let notice = if self.client_config.debug_mode {
            StatusNotice {
                text: "🛠️ ĐÃ KÍCH HOẠT CHẾ ĐỘ DEBUG! Mở khóa '💾 Xuất .conf' và chi tiết lỗi kỹ thuật.".to_owned(),
                level: NoticeLevel::Success,
            }
        } else {
            StatusNotice {
                text: "🔒 ĐÃ TẮT CHẾ ĐỘ DEBUG! Đã chuyển về Chế độ Người dùng Tiêu chuẩn."
                    .to_owned(),
                level: NoticeLevel::Info,
            }
        };
        self.settings_status_msg = Some(notice.clone());
        self.info_toast = Some(notice);
    }

    pub fn fetch_wg_key_from_settings(&mut self) {
        if self.settings_key_fetching || self.closing {
            return;
        }
        if !self.is_logged_in {
            self.settings_status_msg = Some(StatusNotice {
                text: "Vui lòng đăng nhập Proton để cấp Key mới từ API.".to_owned(),
                level: NoticeLevel::Warning,
            });
            return;
        }
        self.settings_key_fetching = true;
        self.settings_status_msg = Some(StatusNotice {
            text: "● Đang cấp WireGuard Key mới từ Proton API...".to_owned(),
            level: NoticeLevel::Warning,
        });
        self.pending_commands.push(UiCommand::FetchWgKeyManual {
            auth_generation: self.auth_generation,
        });
    }

    pub fn pick_and_import_conf(&mut self) {
        if self.settings_conf_importing || self.closing {
            return;
        }
        self.settings_conf_importing = true;
        self.pending_commands.push(UiCommand::PickAndImportConf);
    }

    pub fn start_update_download(&mut self) {
        if self.update_phase.is_busy() || self.closing {
            return;
        }
        let Some(info) = self.available_update.clone() else {
            return;
        };
        self.update_generation = self.update_generation.saturating_add(1);
        let generation = self.update_generation;
        self.update_phase = UpdateDialogPhase::Downloading {
            downloaded_bytes: 0,
            total_bytes: info.file_size_bytes,
            percent: 0.0,
            confirm_cancel: false,
        };
        self.pending_commands
            .push(UiCommand::StartUpdateDownload { generation, info });
    }

    pub fn cancel_update_download(&mut self) {
        if !matches!(
            self.update_phase,
            UpdateDialogPhase::Downloading { .. } | UpdateDialogPhase::Verifying
        ) {
            return;
        }
        let cancelled_gen = self.update_generation;
        self.update_generation = self.update_generation.saturating_add(1);
        self.pending_commands.push(UiCommand::CancelUpdateDownload {
            generation: cancelled_gen,
        });
        let is_mandatory = self.available_update.as_ref().is_some_and(|u| u.mandatory);
        self.update_phase = UpdateDialogPhase::Cancelled;
        if !is_mandatory && self.active_dialog == ActiveDialog::Update {
            self.active_dialog = ActiveDialog::None;
            self.info_toast = Some(StatusNotice {
                text: "Đã hủy quá trình tải bản cập nhật.".to_owned(),
                level: NoticeLevel::Info,
            });
        }
    }

    pub fn start_service_repair(&mut self) {
        if self.service_repair_phase == ServiceRepairPhase::LaunchingAndWaiting || self.closing {
            return;
        }
        self.service_repair_phase = ServiceRepairPhase::LaunchingAndWaiting;
        self.service_repair_detail = None;
        self.pending_commands.push(UiCommand::RepairService);
    }

    pub fn open_log_folder(&mut self) {
        if self.closing {
            return;
        }
        info!("Opening log directory");
        self.pending_commands.push(UiCommand::OpenLogFolder);
    }

    pub fn open_realtime_log_cli(&mut self) {
        if self.closing {
            return;
        }
        info!(
            app_log = %app_log_dir().join(APP_LOG_FILE_NAME).display(),
            service_log = %service_log_dir().join(SERVICE_LOG_FILE_NAME).display(),
            "Opening Dev Mode realtime CLI log viewer"
        );
        self.pending_commands.push(UiCommand::OpenRealtimeLogCli);
    }

    pub fn tick(&mut self, now: Instant) {
        if self.loading.visible {
            if let Some(hide_at) = self.loading.hide_at {
                if now >= hide_at {
                    self.loading.visible = false;
                    self.loading.hide_at = None;
                }
            }
        }

        if !self.closing
            && now.saturating_duration_since(self.last_status_poll) >= STATUS_POLL_INTERVAL
        {
            self.last_status_poll = now;
            self.request_status_refresh();
        }

        if !self.closing
            && !self.startup_update_checked
            && self.client_config.auto_check_update
            && now.saturating_duration_since(self.started_at) >= STARTUP_UPDATE_DELAY
        {
            self.startup_update_checked = true;
            self.check_for_updates(false);
        }
    }

    pub fn submit_srp_login(&mut self) {
        if self.is_srp_logging_in || self.closing {
            return;
        }
        let user = self.srp_username.trim().to_owned();
        let pwd = self.srp_password.clone();
        let twofa = self.srp_2fa.trim().to_owned();
        if user.is_empty() || pwd.is_empty() {
            self.srp_status = Some(StatusNotice {
                text: "Vui lòng nhập đầy đủ Email và Mật khẩu.".to_owned(),
                level: NoticeLevel::Warning,
            });
            return;
        }

        self.is_srp_logging_in = true;
        self.srp_status = Some(StatusNotice {
            text: "● Đang xác thực với Proton SRP API...".to_owned(),
            level: NoticeLevel::Warning,
        });

        let pending_session = if !twofa.is_empty()
            && self.pending_srp_account.as_deref() == Some(user.to_lowercase().as_str())
        {
            self.pending_srp_session
                .clone()
                .map(|sess| (user.clone(), sess))
        } else {
            None
        };

        self.pending_commands.push(UiCommand::SrpLogin {
            username: user,
            password: pwd,
            two_factor: twofa,
            pending_session,
        });
    }

    pub fn start_scan(&mut self) {
        if !self.is_logged_in {
            self.show_login_view();
            return;
        }
        if self.is_scanning || self.is_connecting_vpn || self.closing {
            return;
        }
        self.is_scanning = true;
        info!(auth_generation = self.auth_generation, "Starting server scan");
        self.show_loading_status("● Đang kết nối Proton API & lấy danh sách máy chủ...", 0.1);
        self.pending_commands.push(UiCommand::StartScan {
            auth_generation: self.auth_generation,
        });
    }

    pub fn select_and_connect_server(&mut self, server: ServerNode) {
        if self.is_connecting_vpn || self.closing {
            return;
        }
        self.selected_server = Some(server.clone());
        self.server_selection_manual = true;
        self.show_home_view();
        self.connect_to_server(server);
    }

    pub fn toggle_vpn(&mut self) {
        if self.is_connecting_vpn || self.closing {
            return;
        }
        if self.tunnel_running {
            self.disconnect_vpn();
            return;
        }
        if !self.is_logged_in {
            self.show_login_view();
            return;
        }
        if self.selected_server.is_none() && !self.all_free_servers.is_empty() {
            self.pick_best_server_as_selected();
        }
        if let Some(server) = self.selected_server.clone() {
            self.connect_to_server(server);
        } else {
            self.start_scan();
        }
    }

    pub fn connect_to_server(&mut self, server: ServerNode) {
        if self.is_connecting_vpn || self.closing {
            return;
        }
        if self.tunnel_verified
            && self
                .connected_server
                .as_ref()
                .is_some_and(|s| s.name == server.name)
        {
            return;
        }

        self.is_connecting_vpn = true;
        self.is_disconnecting_vpn = false;
        self.connection_generation = self.connection_generation.saturating_add(1);
        let generation = self.connection_generation;
        self.live_public_ip = None;
        self.tunnel_verified = false;
        self.tunnel_unverified_reason = None;
        self.selected_server = Some(server.clone());
        info!(
            generation,
            auth_generation = self.auth_generation,
            server = %server.name,
            country = %server.country,
            entry_ip = %server.entry_ip,
            "Initiating WireGuard VPN connection"
        );

        self.show_loading_status("● [1/4] 🔑 Kiểm tra WireGuard Key & Chứng chỉ...", 0.25);
        self.pending_commands.push(UiCommand::Connect {
            generation,
            auth_generation: self.auth_generation,
            server,
        });
    }

    pub fn disconnect_vpn(&mut self) {
        if self.is_connecting_vpn || self.closing {
            return;
        }
        self.is_connecting_vpn = true;
        self.is_disconnecting_vpn = true;
        self.connection_generation = self.connection_generation.saturating_add(1);
        let generation = self.connection_generation;
        info!(generation, "Initiating WireGuard VPN disconnect");
        self.show_loading_status(
            "● Đang ngắt WireGuard Tunnel & hoàn trả cấu hình mạng...",
            0.4,
        );
        self.pending_commands
            .push(UiCommand::Disconnect { generation });
    }

    pub fn request_status_refresh(&mut self) {
        if self.is_connecting_vpn || self.status_check_pending || self.closing {
            return;
        }
        self.status_check_pending = true;
        let generation = self.connection_generation;
        self.pending_commands
            .push(UiCommand::RefreshTunnelStatus { generation });
    }

    fn reset_to_logged_out_view(
        &mut self,
        client_config: Option<ClientConfig>,
        srp_notice: Option<StatusNotice>,
        toast: StatusNotice,
    ) {
        self.bump_auth_generation();
        self.connection_generation = self.connection_generation.saturating_add(1);
        self.is_scanning = false;
        self.settings_key_fetching = false;
        self.settings_conf_importing = false;
        self.settings_status_msg = None;
        if let Some(cfg) = client_config {
            self.client_config = cfg;
        }
        self.all_free_servers.clear();
        self.raw_payload = None;
        self.selected_server = None;
        self.connected_server = None;
        self.server_selection_manual = false;
        self.pending_srp_account = None;
        self.pending_srp_session = None;
        self.srp_password.clear();
        self.srp_2fa.clear();
        self.srp_status = srp_notice;
        self.is_logged_in = false;
        self.active_account = None;
        self.live_public_ip = None;
        self.vpn_connect_time_unix = None;
        self.active_dialog = ActiveDialog::None;
        self.info_toast = Some(toast);
        self.show_login_view();
    }

    pub fn request_logout(&mut self, store: &dyn CredentialStore) {
        if self.active_dialog == ActiveDialog::LogoutConfirm {
            self.active_dialog = ActiveDialog::None;
        }
        if self.closing {
            return;
        }
        if self.is_disconnecting_vpn {
            self.logout_after_disconnect = true;
            return;
        }
        if self.is_connecting_vpn {
            self.info_toast = Some(StatusNotice {
                text: "Đang thiết lập kết nối VPN, vui lòng chờ hoàn tất rồi thử đăng xuất lại."
                    .to_owned(),
                level: NoticeLevel::Warning,
            });
            return;
        }
        if self.tunnel_running {
            self.logout_after_disconnect = true;
            self.disconnect_vpn();
            return;
        }
        let _ = store.clear_all_sessions();
        let _ = ServerCacheManager::clear(&ServerCacheManager::default_cache_path());
        self.reset_to_logged_out_view(
            Some(store.load_client_config().unwrap_or_default()),
            None,
            StatusNotice {
                text: "Đã xóa phiên đăng nhập trên máy.".to_owned(),
                level: NoticeLevel::Info,
            },
        );
    }

    pub fn request_quit(&mut self) {
        if self.closing {
            return;
        }
        if matches!(
            self.update_phase,
            UpdateDialogPhase::Downloading { .. } | UpdateDialogPhase::Verifying
        ) {
            let cancelled_gen = self.update_generation;
            self.update_generation = self.update_generation.saturating_add(1);
            self.pending_commands.push(UiCommand::CancelUpdateDownload {
                generation: cancelled_gen,
            });
        }
        self.closing = true;
        self.connection_generation = self.connection_generation.saturating_add(1);
        self.pending_commands.push(UiCommand::ShutdownOnExit);
    }

    pub fn export_selected_conf(&mut self) {
        if let Some(server) = self.selected_server.clone() {
            self.export_server_conf(server);
        }
    }

    pub fn export_server_conf(&mut self, server: ServerNode) {
        self.pending_commands.push(UiCommand::ExportConf {
            auth_generation: self.auth_generation,
            server,
        });
    }

    fn dispatch_check_for_updates(&mut self, manual: bool, manifest_url_override: Option<String>) {
        if manual {
            self.update_check_pending = true;
            self.update_check_message = None;
        }
        self.pending_commands.push(UiCommand::CheckForUpdates {
            manual,
            manifest_url_override,
        });
    }

    pub fn check_for_updates(&mut self, manual: bool) {
        let override_url = self.client_config.custom_update_url.trim().to_owned();
        let opt = (!override_url.is_empty()).then_some(override_url);
        self.dispatch_check_for_updates(manual, opt);
    }

    pub fn check_for_updates_with_override(&mut self, manual: bool, raw_url: &str) {
        let trimmed = raw_url.trim();
        if trimmed.is_empty() {
            self.dispatch_check_for_updates(manual, None);
            return;
        }
        match validate_manifest_url(trimmed) {
            Ok(url) => self.dispatch_check_for_updates(manual, Some(url)),
            Err(err) => {
                let msg = format!(
                    "❌ Update Manifest URL không hợp lệ (cần https:// hoặc http://127.0.0.1 / localhost): {err}"
                );
                self.settings_status_msg = Some(StatusNotice {
                    text: msg.clone(),
                    level: NoticeLevel::Error,
                });
                self.info_toast = Some(StatusNotice {
                    text: msg,
                    level: NoticeLevel::Error,
                });
            }
        }
    }

    pub fn save_client_config(&mut self, config: ClientConfig) {
        self.client_config = config.clone();
        self.pending_commands
            .push(UiCommand::SaveClientConfig { config });
    }

    pub fn pick_best_server_as_selected(&mut self) {
        if self.all_free_servers.is_empty() {
            return;
        }
        let best_reachable = self
            .all_free_servers
            .iter()
            .filter(|s| s.ping_ms.is_some())
            .min_by(|a, b| {
                score_server(a)
                    .total_cmp(&score_server(b))
                    .then_with(|| a.name.cmp(&b.name))
            })
            .cloned();

        let best = best_reachable.or_else(|| {
            self.all_free_servers
                .iter()
                .min_by(|a, b| {
                    a.load
                        .unwrap_or(0.0)
                        .total_cmp(&b.load.unwrap_or(0.0))
                        .then_with(|| a.name.cmp(&b.name))
                })
                .cloned()
        });
        self.selected_server = best;
    }

    pub fn drawer_servers(&self) -> (Option<ServerNode>, Vec<ServerNode>) {
        sort_and_filter_servers(
            &self.all_free_servers,
            self.selected_country_code.as_deref(),
            &self.search_query,
            self.sort_mode,
        )
    }

    pub fn country_counts(&self) -> Vec<(String, usize)> {
        let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for srv in &self.all_free_servers {
            let code = srv.country.trim();
            if !code.is_empty() {
                *counts.entry(code.to_owned()).or_insert(0) += 1;
            }
        }
        let mut items: Vec<(String, usize)> = counts.into_iter().collect();
        items.sort_by(|a, b| {
            b.1.cmp(&a.1).then_with(|| {
                freeton_core::ping::get_country_display(&a.0)
                    .cmp(&freeton_core::ping::get_country_display(&b.0))
            })
        });
        items
    }

    pub fn show_loading_status(&mut self, text: impl Into<String>, progress: f32) {
        self.loading.visible = true;
        self.loading.text = text.into();
        self.loading.progress = progress.clamp(0.0, 1.0);
        self.loading.hide_at = None;
    }

    pub fn hide_loading_with_delay(&mut self, final_text: impl Into<String>) {
        self.loading.visible = true;
        self.loading.text = final_text.into();
        self.loading.progress = 1.0;
        self.loading.hide_at = Some(Instant::now() + LOADING_HIDE_DELAY);
    }

    pub fn formatted_session_timer(&self, now_unix: i64) -> (&'static str, String) {
        if self.is_connecting_vpn && !self.is_disconnecting_vpn {
            ("warning", "Đang thiết lập kết nối…".to_owned())
        } else if self.is_disconnecting_vpn {
            ("warning", "Đang ngắt kết nối…".to_owned())
        } else if self.tunnel_verified {
            if let Some(started) = self.vpn_connect_time_unix {
                let elapsed = (now_unix - started).max(0);
                let hours = elapsed / 3600;
                let minutes = (elapsed % 3600) / 60;
                let seconds = elapsed % 60;
                (
                    "success",
                    format!("Thời gian kết nối  {hours:02}:{minutes:02}:{seconds:02}"),
                )
            } else {
                ("success", "Thời gian kết nối  00:00:00".to_owned())
            }
        } else if self.tunnel_running {
            ("warning", "Đang kiểm tra đường truyền…".to_owned())
        } else {
            ("dim", "Sẵn sàng khi bạn cần".to_owned())
        }
    }

    pub fn effective_endpoint_and_interface(&self) -> (String, String, String, u16) {
        if let Some(srv) = &self.connected_server {
            let port = self
                .client_config
                .port
                .trim()
                .parse::<u16>()
                .unwrap_or(51820);
            let addr = if self.client_config.address.trim().is_empty() {
                DEFAULT_WG_ADDRESS.to_owned()
            } else {
                self.client_config.address.clone()
            };
            return (srv.country.clone(), srv.entry_ip.clone(), addr, port);
        }
        (
            String::new(),
            String::new(),
            self.client_config.address.clone(),
            self.client_config
                .port
                .trim()
                .parse::<u16>()
                .unwrap_or(51820),
        )
    }

    pub fn apply_event(&mut self, event: WorkerEvent) {
        match event {
            WorkerEvent::LoginStatus(notice) => {
                self.srp_status = Some(notice);
            }
            WorkerEvent::LoginNeedsTwoFactor { account, session } => {
                self.is_srp_logging_in = false;
                self.pending_srp_account = Some(account.trim().to_lowercase());
                self.pending_srp_session = Some(session);
                self.srp_status = Some(StatusNotice {
                    text: "Tài khoản yêu cầu mã 2FA. Vui lòng nhập mã 2FA vào ô trên rồi bấm Đăng nhập ngay.".to_owned(),
                    level: NoticeLevel::Warning,
                });
            }
            WorkerEvent::LoginSuccess { account } => {
                self.is_srp_logging_in = false;
                self.is_logged_in = true;
                self.active_account = Some(account);
                self.srp_password.clear();
                self.srp_2fa.clear();
                self.srp_status = None;
                self.pending_srp_account = None;
                self.pending_srp_session = None;
                self.is_scanning = false;
                let auth_gen = self.bump_auth_generation();
                self.show_home_view();
                self.pending_commands.push(UiCommand::EnsureWgKey {
                    auth_generation: auth_gen,
                    force: false,
                });
                self.start_scan();
            }
            WorkerEvent::LoginError {
                title,
                friendly_msg,
                detail,
                inline_msg,
            } => {
                self.is_srp_logging_in = false;
                self.srp_status = Some(StatusNotice {
                    text: inline_msg,
                    level: NoticeLevel::Error,
                });
                self.error_modal = Some(AppErrorInfo {
                    title,
                    friendly_msg,
                    detail,
                });
                self.active_dialog = ActiveDialog::ErrorDetail;
            }
            WorkerEvent::LoadingProgress {
                auth_generation,
                text,
                progress,
            } => {
                if auth_generation == self.auth_generation
                    && self.is_logged_in
                    && !self.is_connecting_vpn
                    && !self.closing
                {
                    self.show_loading_status(text, progress);
                }
            }
            WorkerEvent::ScanStatus {
                auth_generation,
                text,
            } => {
                if auth_generation == self.auth_generation
                    && self.is_logged_in
                    && !self.is_connecting_vpn
                    && !self.closing
                {
                    self.show_loading_status(text, self.loading.progress);
                }
            }
            WorkerEvent::ScanComplete {
                auth_generation,
                raw_payload,
                servers,
            } => {
                if auth_generation != self.auth_generation || !self.is_logged_in || self.closing {
                    return;
                }
                self.raw_payload = raw_payload;
                self.all_free_servers = servers;
                self.is_scanning = false;

                let preserve_selection = self.selected_server.is_some()
                    && (self.is_connecting_vpn
                        || self.tunnel_running
                        || self.server_selection_manual);
                if preserve_selection {
                    if let Some(current_name) = self.selected_server.as_ref().map(|s| &s.name) {
                        if let Some(updated) = self
                            .all_free_servers
                            .iter()
                            .find(|s| &s.name == current_name)
                            .cloned()
                        {
                            self.selected_server = Some(updated);
                        }
                    }
                } else {
                    self.pick_best_server_as_selected();
                }

                if !self.is_connecting_vpn {
                    self.hide_loading_with_delay(format!(
                        "● Hoàn tất! Đã quét {} máy chủ Free.",
                        self.all_free_servers.len()
                    ));
                }
            }
            WorkerEvent::ScanError {
                auth_generation,
                friendly_msg,
                detail,
            } => {
                if auth_generation != self.auth_generation || !self.is_logged_in || self.closing {
                    return;
                }
                self.is_scanning = false;
                if !self.is_connecting_vpn {
                    self.hide_loading_with_delay("● Lỗi quét danh sách.");
                }
                self.error_modal = Some(AppErrorInfo {
                    title: "Lỗi Quét Máy Chủ".to_owned(),
                    friendly_msg,
                    detail,
                });
                self.active_dialog = ActiveDialog::ErrorDetail;
            }
            WorkerEvent::ScanNeedsLogin { auth_generation } => {
                if auth_generation != self.auth_generation || self.closing {
                    return;
                }
                self.is_scanning = false;
                if self.is_logged_in {
                    self.hide_loading_with_delay("● Không thể nạp server. Bấm ↻ để thử lại.");
                    self.show_home_view();
                } else {
                    self.hide_loading_with_delay("● Cần đăng nhập Proton.");
                    self.show_login_view();
                }
            }
            WorkerEvent::SessionExpired {
                auth_generation,
                detail,
            } => {
                if auth_generation != self.auth_generation || !self.is_logged_in || self.closing {
                    return;
                }
                debug!(%detail, "Proton refresh token expired/revoked; auto-logging out");
                self.is_connecting_vpn = false;
                self.is_scanning = false;
                self.settings_key_fetching = false;
                self.settings_conf_importing = false;
                self.loading.visible = false;
                self.loading.hide_at = None;
                self.window_visible = true;

                if self.tunnel_running || self.is_disconnecting_vpn {
                    self.logout_after_disconnect = true;
                    if !self.is_disconnecting_vpn {
                        self.disconnect_vpn();
                    }
                    self.info_toast = Some(StatusNotice {
                        text: "Phiên đăng nhập đã hết hạn, đang ngắt VPN để đăng nhập lại."
                            .to_owned(),
                        level: NoticeLevel::Warning,
                    });
                    return;
                }

                let expired_msg =
                    "⚠ Phiên đăng nhập đã hết hạn hoặc bị thu hồi. Vui lòng đăng nhập lại."
                        .to_owned();
                self.reset_to_logged_out_view(
                    None,
                    Some(StatusNotice {
                        text: expired_msg,
                        level: NoticeLevel::Warning,
                    }),
                    StatusNotice {
                        text: "Phiên đăng nhập đã hết hạn — vui lòng đăng nhập lại.".to_owned(),
                        level: NoticeLevel::Warning,
                    },
                );
            }
            WorkerEvent::WgKeyRefreshed {
                auth_generation,
                key,
            } => {
                if auth_generation == self.auth_generation && self.is_logged_in && !self.closing {
                    key.apply_to(&mut self.client_config);
                    if self.active_dialog == ActiveDialog::Settings
                        && !self.settings_draft.imported_from_conf
                        && self.settings_draft.private_key
                            == self.settings_draft.original_private_key
                    {
                        self.settings_draft.private_key = key.private_key.clone();
                        self.settings_draft.original_private_key = key.private_key;
                        self.settings_draft.public_key = key.public_key;
                        self.settings_draft.expiration = key.expiration;
                    }
                }
            }
            WorkerEvent::WgKeyManualSucceeded {
                auth_generation,
                key,
            } => {
                self.settings_key_fetching = false;
                if auth_generation == self.auth_generation && self.is_logged_in && !self.closing {
                    key.apply_to(&mut self.client_config);
                    self.settings_draft.private_key = key.private_key.clone();
                    self.settings_draft.original_private_key = key.private_key;
                    self.settings_draft.public_key = key.public_key;
                    self.settings_draft.expiration = key.expiration;
                    self.settings_draft.imported_from_conf = false;
                    let msg = "Đã cấp và kích hoạt WireGuard Key mới thành công!".to_owned();
                    self.settings_status_msg = Some(StatusNotice {
                        text: format!("✓ {msg}"),
                        level: NoticeLevel::Success,
                    });
                    self.info_toast = Some(StatusNotice {
                        text: msg,
                        level: NoticeLevel::Success,
                    });
                }
            }
            WorkerEvent::WgKeyManualFailed {
                auth_generation,
                friendly_msg,
                detail,
            } => {
                self.settings_key_fetching = false;
                if auth_generation == self.auth_generation && !self.closing {
                    self.settings_status_msg = Some(StatusNotice {
                        text: format!("❌ {friendly_msg}"),
                        level: NoticeLevel::Error,
                    });
                    if self.active_dialog == ActiveDialog::Settings {
                        self.return_dialog = Some(ActiveDialog::Settings);
                    }
                    self.error_modal = Some(AppErrorInfo {
                        title: "Lỗi Cấp Key".to_owned(),
                        friendly_msg,
                        detail,
                    });
                    self.active_dialog = ActiveDialog::ErrorDetail;
                }
            }
            WorkerEvent::ConfImportCancelled => {
                self.settings_conf_importing = false;
            }
            WorkerEvent::ConfImported { filename, parsed } => {
                self.settings_conf_importing = false;
                self.settings_draft.private_key = parsed.private_key;
                self.settings_draft.public_key.clear();
                if let Some(addr) = parsed.address {
                    self.settings_draft.address = addr;
                }
                if let Some(dns) = parsed.dns {
                    self.settings_draft.dns = dns;
                }
                self.settings_draft.expiration = 0;
                self.settings_draft.imported_from_conf = true;
                self.settings_status_msg = Some(StatusNotice {
                    text: format!(
                        "✓ Đã nạp cấu hình từ file: {filename} (bấm Lưu & Áp dụng để ghi nhận)"
                    ),
                    level: NoticeLevel::Success,
                });
            }
            WorkerEvent::ConfImportError {
                title,
                friendly_msg,
                detail,
            } => {
                self.settings_conf_importing = false;
                if self.active_dialog == ActiveDialog::Settings {
                    self.return_dialog = Some(ActiveDialog::Settings);
                }
                self.error_modal = Some(AppErrorInfo {
                    title,
                    friendly_msg,
                    detail,
                });
                self.active_dialog = ActiveDialog::ErrorDetail;
            }
            WorkerEvent::StartupStatusLoaded { enabled } => {
                if self.startup_before_save.is_none() {
                    self.startup_enabled = enabled;
                    if !self.settings_draft.startup_dirty {
                        self.settings_draft.startup_enabled = enabled;
                    }
                }
            }
            WorkerEvent::StartupSaveResult { enabled, error } => {
                if let Some(err) = error {
                    let reverted = self.startup_before_save.take().unwrap_or(!enabled);
                    self.startup_enabled = reverted;
                    self.settings_draft.startup_enabled = reverted;
                    self.settings_draft.startup_dirty = false;
                    self.pending_commands.push(UiCommand::RefreshStartupStatus);
                    self.info_toast = Some(StatusNotice {
                        text: format!("Không thể cập nhật khởi động cùng Windows: {err}"),
                        level: NoticeLevel::Warning,
                    });
                } else {
                    self.startup_before_save = None;
                    self.startup_enabled = enabled;
                }
            }
            WorkerEvent::ConnectProgress {
                generation,
                text,
                progress,
            } => {
                if generation == self.connection_generation && !self.closing {
                    self.show_loading_status(text, progress);
                }
            }
            WorkerEvent::ConnectSucceeded {
                generation,
                payload,
            } => {
                if generation != self.connection_generation || self.closing || !self.is_logged_in {
                    return;
                }
                let ConnectSuccessPayload {
                    server,
                    info,
                    wg_key,
                } = *payload;
                self.is_connecting_vpn = false;
                self.is_disconnecting_vpn = false;
                self.tunnel_running = true;
                self.tunnel_verified = true;
                self.tunnel_unverified_reason = None;
                self.service_health = ServiceHealthStatus::Healthy;
                if let Some(key) = wg_key {
                    key.apply_to(&mut self.client_config);
                }
                self.connected_server = Some(server.clone());
                self.vpn_connect_time_unix = Some(info.connected_at_unix);
                self.hide_loading_with_delay(format!(
                    "● [4/4] 🛡 Kết nối {} thành công!",
                    server.name
                ));
                self.pending_commands
                    .push(UiCommand::ResolvePublicIp { generation });
            }
            WorkerEvent::ConnectFailed {
                generation,
                message,
                detail,
                service_unavailable,
            } => {
                if generation != self.connection_generation || self.closing {
                    return;
                }
                self.is_connecting_vpn = false;
                self.is_disconnecting_vpn = false;
                self.tunnel_verified = false;
                self.connected_server = None;
                self.vpn_connect_time_unix = None;
                if service_unavailable {
                    self.service_health = ServiceHealthStatus::Unavailable(detail.clone());
                }
                self.hide_loading_with_delay(format!("Lỗi: {message}"));
                self.request_status_refresh();
                if service_unavailable {
                    self.error_modal = Some(AppErrorInfo {
                        title: "Dịch vụ FreetonVPNService chưa sẵn sàng".to_owned(),
                        friendly_msg: format!(
                            "Không thể kết nối tới dịch vụ hệ thống FreetonVPNService.\n\n{message}"
                        ),
                        detail,
                    });
                    self.active_dialog = ActiveDialog::ServiceRepair;
                } else {
                    self.error_modal = Some(AppErrorInfo {
                        title: "Lỗi Kết Nối WireGuard".to_owned(),
                        friendly_msg: format!("Chưa xác minh được đường truyền VPN.\n\n{message}"),
                        detail,
                    });
                    self.active_dialog = ActiveDialog::ErrorDetail;
                }
            }
            WorkerEvent::DisconnectSucceeded { generation } => {
                if generation != self.connection_generation || self.closing {
                    return;
                }
                self.is_connecting_vpn = false;
                self.is_disconnecting_vpn = false;
                self.tunnel_running = false;
                self.tunnel_verified = false;
                self.tunnel_unverified_reason = None;
                self.connected_server = None;
                self.vpn_connect_time_unix = None;
                self.live_public_ip = None;
                self.service_health = ServiceHealthStatus::Healthy;
                self.hide_loading_with_delay("● Đã ngắt kết nối an toàn.");
            }
            WorkerEvent::DisconnectFailed {
                generation,
                message,
                detail,
            } => {
                if generation != self.connection_generation || self.closing {
                    return;
                }
                self.is_connecting_vpn = false;
                self.is_disconnecting_vpn = false;
                self.logout_after_disconnect = false;
                self.hide_loading_with_delay("● Chưa ngắt được VPN.");
                self.request_status_refresh();
                self.error_modal = Some(AppErrorInfo {
                    title: "Lỗi ngắt VPN".to_owned(),
                    friendly_msg: format!(
                        "Tunnel có thể vẫn đang bật. Vui lòng thử ngắt lại.\n\n{message}"
                    ),
                    detail,
                });
                self.active_dialog = ActiveDialog::ErrorDetail;
            }
            WorkerEvent::TunnelStatus { generation, status } => {
                self.status_check_pending = false;
                if generation != self.connection_generation
                    || self.is_connecting_vpn
                    || self.closing
                {
                    return;
                }
                match status {
                    Ok(TunnelHealthState::Disconnected) => {
                        self.service_health = ServiceHealthStatus::Healthy;
                        if self.active_dialog == ActiveDialog::ServiceRepair {
                            self.service_repair_phase = ServiceRepairPhase::Succeeded;
                        }
                        self.tunnel_running = false;
                        self.tunnel_verified = false;
                        self.tunnel_unverified_reason = None;
                        self.connected_server = None;
                        self.vpn_connect_time_unix = None;
                        self.live_public_ip = None;
                    }
                    Ok(TunnelHealthState::Connecting) => {
                        self.service_health = ServiceHealthStatus::Healthy;
                        if self.active_dialog == ActiveDialog::ServiceRepair {
                            self.service_repair_phase = ServiceRepairPhase::Succeeded;
                        }
                        self.tunnel_running = true;
                        self.tunnel_verified = false;
                        self.tunnel_unverified_reason =
                            Some("Đang thiết lập kết nối WireGuard...".to_owned());
                    }
                    Ok(TunnelHealthState::Verifying(info)) => {
                        self.service_health = ServiceHealthStatus::Healthy;
                        if self.active_dialog == ActiveDialog::ServiceRepair {
                            self.service_repair_phase = ServiceRepairPhase::Succeeded;
                        }
                        self.tunnel_running = true;
                        self.tunnel_verified = false;
                        self.tunnel_unverified_reason =
                            Some("Tunnel đang khởi động và chờ xác minh handshake/DNS.".to_owned());
                        self.hydrate_from_tunnel_info(&info);
                    }
                    Ok(TunnelHealthState::Connected(info)) => {
                        let was_verified = self.tunnel_verified;
                        self.service_health = ServiceHealthStatus::Healthy;
                        if self.active_dialog == ActiveDialog::ServiceRepair {
                            self.service_repair_phase = ServiceRepairPhase::Succeeded;
                        }
                        self.tunnel_running = true;
                        self.tunnel_verified = true;
                        self.tunnel_unverified_reason = None;
                        self.hydrate_from_tunnel_info(&info);
                        if !was_verified && self.live_public_ip.is_none() {
                            self.pending_commands
                                .push(UiCommand::ResolvePublicIp { generation });
                        }
                    }
                    Ok(TunnelHealthState::Unverified { info, reason }) => {
                        self.service_health = ServiceHealthStatus::Healthy;
                        if self.active_dialog == ActiveDialog::ServiceRepair {
                            self.service_repair_phase = ServiceRepairPhase::Succeeded;
                        }
                        self.tunnel_running = true;
                        self.tunnel_verified = false;
                        self.tunnel_unverified_reason = Some(reason);
                        self.hydrate_from_tunnel_info(&info);
                    }
                    Err(PipeClientError::Unavailable(msg)) => {
                        self.service_health = ServiceHealthStatus::Unavailable(msg);
                        self.tunnel_running = false;
                        self.tunnel_verified = false;
                        self.tunnel_unverified_reason = None;
                        self.connected_server = None;
                        self.vpn_connect_time_unix = None;
                        self.live_public_ip = None;
                    }
                    Err(err) => {
                        debug!(error = %err, "non-fatal tunnel status query error");
                    }
                }
            }
            WorkerEvent::PublicIpResolved { generation, ip } => {
                if generation == self.connection_generation && self.tunnel_verified && !self.closing
                {
                    self.live_public_ip = Some(ip);
                }
            }
            WorkerEvent::UpdateAvailable { info } => {
                self.update_check_pending = false;
                if self.active_dialog == ActiveDialog::Update && self.update_phase.is_busy() {
                    return;
                }
                self.available_update = Some(info);
                self.update_check_message = None;
                self.update_phase = UpdateDialogPhase::Idle;
                self.return_dialog = None;
                self.active_dialog = ActiveDialog::Update;
                self.window_visible = true;
            }
            WorkerEvent::UpdateUpToDate {
                manual,
                current_version,
            } => {
                self.update_check_pending = false;
                if manual {
                    self.update_check_message = Some(format!(
                        "🎉 Bạn đang sử dụng phiên bản mới nhất ({APP_NAME} v{current_version})!\nKhông có bản cập nhật nào."
                    ));
                    self.info_toast = Some(StatusNotice {
                        text: format!("Đang dùng bản mới nhất v{current_version}"),
                        level: NoticeLevel::Success,
                    });
                }
            }
            WorkerEvent::UpdateCheckFailed { manual, message } => {
                self.update_check_pending = false;
                if manual {
                    self.update_check_message = Some(message.clone());
                    self.info_toast = Some(StatusNotice {
                        text: message,
                        level: NoticeLevel::Warning,
                    });
                }
            }
            WorkerEvent::UpdateDownloadProgress {
                generation,
                downloaded_bytes,
                total_bytes,
                percent,
            } => {
                if generation != self.update_generation || self.closing {
                    return;
                }
                if let UpdateDialogPhase::Downloading { confirm_cancel, .. } = &self.update_phase {
                    self.update_phase = UpdateDialogPhase::Downloading {
                        downloaded_bytes,
                        total_bytes,
                        percent,
                        confirm_cancel: *confirm_cancel,
                    };
                }
            }
            WorkerEvent::UpdateDownloadCancelled { generation } => {
                if generation == self.update_generation && !self.closing {
                    self.update_phase = UpdateDialogPhase::Cancelled;
                }
            }
            WorkerEvent::UpdateDownloadFinished { generation, action } => {
                if generation != self.update_generation || self.closing {
                    return;
                }
                match action {
                    Ok(UpdateAction::LaunchVerifiedInstaller(path)) => {
                        self.update_phase = UpdateDialogPhase::LaunchingInstaller;
                        self.pending_commands
                            .push(UiCommand::LaunchUpdateInstaller { path });
                    }
                    Ok(UpdateAction::OpenReleasePageInBrowser(url)) => {
                        match validate_https_browser_url(&url) {
                            Ok(safe_url) => {
                                self.update_phase =
                                    UpdateDialogPhase::BrowserOpened(safe_url.clone());
                                self.pending_commands
                                    .push(UiCommand::OpenExternalUrl { url: safe_url });
                            }
                            Err(err) => {
                                self.update_phase = UpdateDialogPhase::Failed(err);
                            }
                        }
                    }
                    Err(err) => {
                        self.update_phase = UpdateDialogPhase::Failed(err);
                    }
                }
            }
            WorkerEvent::UpdateInstallerLaunched { result } => match result {
                Ok(()) => {
                    self.request_quit();
                }
                Err(err) => {
                    self.update_phase = UpdateDialogPhase::Failed(err);
                }
            },
            WorkerEvent::ExternalUrlError { message } => {
                self.info_toast = Some(StatusNotice {
                    text: message,
                    level: NoticeLevel::Warning,
                });
            }
            WorkerEvent::ServiceRepairSucceeded => {
                self.service_health = ServiceHealthStatus::Healthy;
                self.service_repair_phase = ServiceRepairPhase::Succeeded;
                self.service_repair_detail = None;
                self.info_toast = Some(StatusNotice {
                    text: "FreetonVPNService đã được sửa và đang hoạt động!".to_owned(),
                    level: NoticeLevel::Success,
                });
                self.request_status_refresh();
            }
            WorkerEvent::ServiceRepairFailed { message, detail } => {
                self.service_repair_phase = ServiceRepairPhase::Failed(message);
                self.service_repair_detail = Some(detail);
            }
            WorkerEvent::ConfExported { message } => {
                self.info_toast = Some(StatusNotice {
                    text: message,
                    level: NoticeLevel::Success,
                });
            }
            WorkerEvent::ConfExportError {
                title,
                friendly_msg,
                detail,
            } => {
                self.error_modal = Some(AppErrorInfo {
                    title,
                    friendly_msg,
                    detail,
                });
                self.active_dialog = ActiveDialog::ErrorDetail;
            }
            WorkerEvent::ExitReady { error } => {
                if let Some(err) = error {
                    self.closing = false;
                    self.is_connecting_vpn = false;
                    self.is_disconnecting_vpn = false;
                    self.window_visible = true;
                    self.request_status_refresh();
                    self.error_modal = Some(AppErrorInfo {
                        title: "Không thể ngắt VPN để thoát".to_owned(),
                        friendly_msg: "Hãy thử ngắt VPN rồi thoát lại.".to_owned(),
                        detail: err,
                    });
                    self.active_dialog = ActiveDialog::ErrorDetail;
                } else {
                    self.exit_ready = true;
                }
            }
        }
    }

    fn hydrate_from_tunnel_info(&mut self, info: &ActiveTunnelInfo) {
        let matched = self
            .all_free_servers
            .iter()
            .find(|s| s.name == info.server_name)
            .cloned();

        let node = matched.unwrap_or_else(|| ServerNode {
            name: info.server_name.clone(),
            country: info.country.clone(),
            entry_country: info.country.clone(),
            city: String::new(),
            load: None,
            status: 1,
            domain: String::new(),
            entry_ip: info.entry_ip.clone(),
            exit_ip: info.entry_ip.clone(),
            x25519_public_key: info.x25519_pubkey.clone(),
            active_physical_servers: 1,
            ping_target: info.entry_ip.clone(),
            ping_ms: None,
        });

        self.connected_server = Some(node.clone());
        if !self.server_selection_manual {
            self.selected_server = Some(node);
        }
        self.vpn_connect_time_unix = Some(info.connected_at_unix);
    }
}

tokio::task_local! {
    static TASK_AUTH_GENERATION: u64;
}

/// Wraps a `CredentialStore` for `ProtonClient` so background WireGuard key writes
/// (`KEYRING_SERVICE_WG` / `KEYRING_ACCOUNT_WG_CONFIG`) fail closed after logout or
/// superseded `auth_generation`.
pub struct AuthGuardedStore {
    inner: Arc<dyn CredentialStore>,
    auth_generation: Arc<AtomicU64>,
}

impl AuthGuardedStore {
    pub fn new(inner: Arc<dyn CredentialStore>, auth_generation: Arc<AtomicU64>) -> Self {
        Self {
            inner,
            auth_generation,
        }
    }
}

impl CredentialStore for AuthGuardedStore {
    fn get_password(&self, service: &str, username: &str) -> Result<Option<String>, StorageError> {
        self.inner.get_password(service, username)
    }

    fn set_password(
        &self,
        service: &str,
        username: &str,
        password: &str,
    ) -> Result<(), StorageError> {
        if service == KEYRING_SERVICE_WG && username == KEYRING_ACCOUNT_WG_CONFIG {
            let has_session = self.inner.load_auth_session().ok().flatten().is_some();
            if !has_session {
                return Err(StorageError::Credential(
                    "Phiên đăng nhập đã kết thúc; bỏ qua lưu ClientConfig.".to_owned(),
                ));
            }
            if let Ok(expected_gen) = TASK_AUTH_GENERATION.try_with(|&g| g) {
                if self.auth_generation.load(Ordering::Acquire) != expected_gen {
                    return Err(StorageError::Credential(
                        "Phiên đăng nhập đã thay đổi; bỏ qua lưu ClientConfig cũ.".to_owned(),
                    ));
                }
            }
        }
        self.inner.set_password(service, username, password)
    }

    fn delete_password(&self, service: &str, username: &str) -> Result<(), StorageError> {
        self.inner.delete_password(service, username)
    }
}

pub struct WorkerDeps {
    pub store: Arc<dyn CredentialStore>,
    pub proton: Arc<ProtonClient>,
    pub pipe: Arc<dyn PipeTransport>,
    pub shell: Arc<dyn ShellLauncher>,
    pub startup: Arc<dyn StartupController>,
    pub cache_path: PathBuf,
    pub update_manifest_url: Option<String>,
    pub update_repo: Option<String>,
    pub update_download_dir: Option<PathBuf>,
    pub service_exe_path: Option<PathBuf>,
    pub service_repair_poll_attempts: u32,
    pub service_repair_poll_interval: Duration,
    pub auth_generation: Arc<AtomicU64>,
    pub update_cancel: Arc<StdMutex<UpdateCancelCoordinator>>,
}

impl WorkerDeps {
    pub fn production() -> Self {
        Self::production_with_auth(Arc::new(AtomicU64::new(0)))
    }

    pub fn production_with_auth(auth_generation: Arc<AtomicU64>) -> Self {
        let store: Arc<dyn CredentialStore> = Arc::new(WindowsCredentialStore::new());
        let guarded: Arc<dyn CredentialStore> = Arc::new(AuthGuardedStore::new(
            Arc::clone(&store),
            Arc::clone(&auth_generation),
        ));
        let proton = Arc::new(ProtonClient::new(guarded));
        let pipe: Arc<dyn PipeTransport> = Arc::new(WindowsPipeTransport::default());
        Self {
            store,
            proton,
            pipe,
            shell: Arc::new(WindowsShellLauncher),
            startup: Arc::new(WindowsStartupController),
            cache_path: ServerCacheManager::default_cache_path(),
            update_manifest_url: None,
            update_repo: None,
            update_download_dir: None,
            service_exe_path: None,
            service_repair_poll_attempts: 24,
            service_repair_poll_interval: Duration::from_millis(500),
            auth_generation,
            update_cancel: Arc::new(StdMutex::new(UpdateCancelCoordinator::default())),
        }
    }

    pub fn is_auth_current(&self, expected_gen: u64) -> bool {
        self.auth_generation.load(Ordering::Acquire) == expected_gen
            && self.store.load_auth_session().ok().flatten().is_some()
    }
}

pub fn spawn_worker_runtime(
    deps: WorkerDeps,
    on_wake: Arc<dyn Fn() + Send + Sync>,
) -> (
    tokio::runtime::Runtime,
    mpsc::UnboundedSender<UiCommand>,
    mpsc::UnboundedReceiver<WorkerEvent>,
) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .max_blocking_threads(24)
        .thread_keep_alive(Duration::from_secs(5))
        .build()
        .expect("failed creating Tokio runtime for freeton-app");

    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (evt_tx, evt_rx) = mpsc::unbounded_channel();

    runtime.spawn(run_worker_loop(Arc::new(deps), cmd_rx, evt_tx, on_wake));
    (runtime, cmd_tx, evt_rx)
}

pub async fn run_worker_loop(
    deps: Arc<WorkerDeps>,
    mut cmd_rx: mpsc::UnboundedReceiver<UiCommand>,
    evt_tx: mpsc::UnboundedSender<WorkerEvent>,
    on_wake: Arc<dyn Fn() + Send + Sync>,
) {
    while let Some(cmd) = cmd_rx.recv().await {
        let deps = Arc::clone(&deps);
        let tx = evt_tx.clone();
        let wake = Arc::clone(&on_wake);
        tokio::spawn(async move {
            handle_ui_command(deps, cmd, &tx, wake.as_ref()).await;
        });
    }
}

fn emit(tx: &mpsc::UnboundedSender<WorkerEvent>, wake: &(dyn Fn() + Send + Sync), ev: WorkerEvent) {
    if tx.send(ev).is_ok() {
        wake();
    }
}

pub async fn handle_ui_command(
    deps: Arc<WorkerDeps>,
    cmd: UiCommand,
    tx: &mpsc::UnboundedSender<WorkerEvent>,
    wake: &(dyn Fn() + Send + Sync),
) {
    match cmd {
        UiCommand::SrpLogin {
            username,
            password,
            two_factor,
            pending_session,
        } => {
            handle_srp_login(
                &deps,
                &username,
                &password,
                &two_factor,
                pending_session,
                tx,
                wake,
            )
            .await;
        }
        UiCommand::StartScan { auth_generation } => {
            handle_scan(&deps, auth_generation, tx, wake).await;
        }
        UiCommand::EnsureWgKey {
            auth_generation,
            force,
        } => {
            if !deps.is_auth_current(auth_generation) {
                return;
            }
            let res = TASK_AUTH_GENERATION
                .scope(auth_generation, deps.proton.ensure_wg_key(force))
                .await;
            if !deps.is_auth_current(auth_generation) {
                return;
            }
            match res {
                Ok(cfg) => emit(
                    tx,
                    wake,
                    WorkerEvent::WgKeyRefreshed {
                        auth_generation,
                        key: WgKeySnapshot::from_config(&cfg),
                    },
                ),
                Err(err) if err.is_session_expired() => {
                    handle_session_expired(&deps, auth_generation, err.to_string(), tx, wake);
                }
                Err(err) => debug!(error = %err, "background WireGuard key check failed"),
            }
        }
        UiCommand::FetchWgKeyManual { auth_generation } => {
            handle_fetch_wg_key_manual(&deps, auth_generation, tx, wake).await;
        }
        UiCommand::PickAndImportConf => {
            handle_pick_and_import_conf(tx, wake).await;
        }
        UiCommand::RefreshStartupStatus => {
            let startup = Arc::clone(&deps.startup);
            let enabled = tokio::task::spawn_blocking(move || startup.is_enabled())
                .await
                .unwrap_or(false);
            emit(tx, wake, WorkerEvent::StartupStatusLoaded { enabled });
        }
        UiCommand::SetStartupEnabled { enabled } => {
            let startup = Arc::clone(&deps.startup);
            let res = tokio::task::spawn_blocking(move || startup.set_enabled(enabled)).await;
            let error = match res {
                Ok(Ok(())) => None,
                Ok(Err(err)) => Some(err.to_string()),
                Err(err) => Some(err.to_string()),
            };
            emit(tx, wake, WorkerEvent::StartupSaveResult { enabled, error });
        }
        UiCommand::Connect {
            generation,
            auth_generation,
            server,
        } => {
            handle_connect(&deps, generation, auth_generation, server, tx, wake).await;
        }
        UiCommand::Disconnect { generation } => {
            handle_disconnect(&deps, generation, tx, wake).await;
        }
        UiCommand::RefreshTunnelStatus { generation } => {
            let status = match deps
                .pipe
                .send_request(&ServiceRequest::Status, PIPE_STATUS_TIMEOUT)
                .await
            {
                Ok(ServiceResponse::Status(s)) => Ok(s),
                Ok(ServiceResponse::Ok) => Err(PipeClientError::Protocol(
                    "Unexpected ServiceResponse::Ok for Status".to_owned(),
                )),
                Ok(ServiceResponse::Error { code, message }) => {
                    Err(PipeClientError::ServiceError { code, message })
                }
                Err(e) => Err(e),
            };
            emit(tx, wake, WorkerEvent::TunnelStatus { generation, status });
        }
        UiCommand::ResolvePublicIp { generation } => {
            if let Ok(ip) = deps.proton.fetch_public_ip().await {
                emit(tx, wake, WorkerEvent::PublicIpResolved { generation, ip });
            }
        }
        UiCommand::CheckForUpdates {
            manual,
            manifest_url_override,
        } => {
            handle_check_updates(&deps, manual, manifest_url_override, tx, wake).await;
        }
        UiCommand::StartUpdateDownload { generation, info } => {
            handle_start_update_download(&deps, generation, info, tx, wake).await;
        }
        UiCommand::CancelUpdateDownload { generation } => {
            if let Ok(mut guard) = deps.update_cancel.lock() {
                guard.cancel(generation);
            }
        }
        UiCommand::LaunchUpdateInstaller { path } => {
            let shell = Arc::clone(&deps.shell);
            let res = tokio::task::spawn_blocking(move || {
                let dir = path.parent().map(Path::to_path_buf);
                shell.launch_elevated(&path, "/S", dir.as_deref())
            })
            .await;
            let result = match res {
                Ok(inner) => inner,
                Err(err) => Err(format!("Không thể khởi chạy trình cài đặt: {err}")),
            };
            emit(tx, wake, WorkerEvent::UpdateInstallerLaunched { result });
        }
        UiCommand::OpenExternalUrl { url } => {
            let shell = Arc::clone(&deps.shell);
            let res = tokio::task::spawn_blocking(move || shell.open_https_url(&url)).await;
            match res {
                Ok(Ok(())) => {}
                Ok(Err(message)) => emit(tx, wake, WorkerEvent::ExternalUrlError { message }),
                Err(err) => emit(
                    tx,
                    wake,
                    WorkerEvent::ExternalUrlError {
                        message: err.to_string(),
                    },
                ),
            }
        }
        UiCommand::OpenLogFolder => {
            let shell = Arc::clone(&deps.shell);
            let dir = app_log_dir();
            let res = tokio::task::spawn_blocking(move || shell.open_directory(&dir)).await;
            match res {
                Ok(Ok(())) => {}
                Ok(Err(message)) => emit(tx, wake, WorkerEvent::ExternalUrlError { message }),
                Err(err) => emit(
                    tx,
                    wake,
                    WorkerEvent::ExternalUrlError {
                        message: err.to_string(),
                    },
                ),
            }
        }
        UiCommand::OpenRealtimeLogCli => {
            let shell = Arc::clone(&deps.shell);
            let app_log = app_log_dir().join(APP_LOG_FILE_NAME);
            let svc_dir = service_log_dir();
            let svc_log = svc_dir.join(SERVICE_LOG_FILE_NAME);
            let tun_log = svc_dir.join(TUNNEL_LOG_FILE_NAME);
            let res = tokio::task::spawn_blocking(move || {
                shell.open_realtime_log_cli(&app_log, &svc_log, &tun_log)
            })
            .await;
            match res {
                Ok(Ok(())) => {}
                Ok(Err(message)) => emit(tx, wake, WorkerEvent::ExternalUrlError { message }),
                Err(err) => emit(
                    tx,
                    wake,
                    WorkerEvent::ExternalUrlError {
                        message: err.to_string(),
                    },
                ),
            }
        }
        UiCommand::RepairService => {
            handle_repair_service(&deps, tx, wake).await;
        }
        UiCommand::ExportConf {
            auth_generation,
            server,
        } => {
            handle_export_conf(&deps, auth_generation, server, tx, wake).await;
        }
        UiCommand::SaveClientConfig { config } => {
            if let Err(err) = deps.store.save_client_config(&config) {
                warn!(error = %err, "failed saving ClientConfig");
            }
        }
        UiCommand::ShutdownOnExit => {
            let res = deps
                .pipe
                .send_request(&ServiceRequest::ShutdownTunnelOnExit, PIPE_CONTROL_TIMEOUT)
                .await;
            let error = match res {
                Ok(ServiceResponse::Ok) | Ok(ServiceResponse::Status(_)) => None,
                Ok(ServiceResponse::Error { message, .. }) => Some(message),
                Err(PipeClientError::Unavailable(_)) => None,
                Err(err) => Some(err.to_string()),
            };
            emit(tx, wake, WorkerEvent::ExitReady { error });
        }
    }
}

async fn handle_srp_login(
    deps: &WorkerDeps,
    username: &str,
    password: &str,
    two_factor: &str,
    pending_session: Option<(String, StoredAuthSession)>,
    tx: &mpsc::UnboundedSender<WorkerEvent>,
    wake: &(dyn Fn() + Send + Sync),
) {
    handle_srp_login_with_captcha(
        deps,
        SrpLoginParams {
            username,
            password,
            two_factor,
            pending_session,
        },
        |challenge| async move {
            tokio::task::spawn_blocking(move || {
                solve_challenge_blocking(&challenge, Duration::from_secs(CAPTCHA_TIMEOUT_SECS))
            })
            .await
            .map_err(|err| CaptchaError::WebView(format!("CAPTCHA task panicked: {err}")))?
        },
        tx,
        wake,
    )
    .await;
}

pub async fn handle_srp_login_with_captcha<F, Fut>(
    deps: &WorkerDeps,
    params: SrpLoginParams<'_>,
    solve_captcha: F,
    tx: &mpsc::UnboundedSender<WorkerEvent>,
    wake: &(dyn Fn() + Send + Sync),
) where
    F: FnOnce(HumanVerificationChallenge) -> Fut,
    Fut: Future<Output = Result<String, CaptchaError>>,
{
    let user = params.username.trim().to_owned();
    let twofa = params.two_factor.trim().to_owned();
    let password = params.password;

    if let Some((pending_user, pending)) = params.pending_session {
        if pending_user.eq_ignore_ascii_case(&user) && !twofa.is_empty() {
            match deps.proton.submit_2fa(&pending, &twofa).await {
                Ok(completed) => {
                    if let Err(err) = deps.store.save_auth_session(&user, &completed) {
                        emit_login_error(tx, wake, &err.to_string());
                        return;
                    }
                    emit(tx, wake, WorkerEvent::LoginSuccess { account: user });
                }
                Err(err) => {
                    emit_login_error(tx, wake, &err.to_string());
                }
            }
            return;
        }
    }

    let first_outcome = match deps.proton.login_srp(&user, password, None).await {
        Ok(outcome) => outcome,
        Err(err) => {
            emit_login_error(tx, wake, &err.to_string());
            return;
        }
    };

    let outcome = match first_outcome {
        LoginOutcome::NeedsHumanVerification { url, methods } => {
            emit(
                tx,
                wake,
                WorkerEvent::LoginStatus(StatusNotice {
                    text: "● Yêu cầu xác minh bảo mật (CAPTCHA)...".to_owned(),
                    level: NoticeLevel::Warning,
                }),
            );
            let challenge = HumanVerificationChallenge {
                url,
                methods: methods.clone(),
            };
            let token = match solve_captcha(challenge).await {
                Ok(tok) => tok,
                Err(err) => {
                    emit_login_error(tx, wake, &format!("Lỗi CAPTCHA: {err}"));
                    return;
                }
            };
            emit(
                tx,
                wake,
                WorkerEvent::LoginStatus(StatusNotice {
                    text: "● Đang hoàn tất đăng nhập sau xác minh CAPTCHA...".to_owned(),
                    level: NoticeLevel::Warning,
                }),
            );
            let hv_token = HumanVerificationToken::new(token, &methods);
            match deps.proton.login_srp(&user, password, Some(hv_token)).await {
                Ok(retried) => retried,
                Err(err) => {
                    emit_login_error(tx, wake, &err.to_string());
                    return;
                }
            }
        }
        other => other,
    };

    match outcome {
        LoginOutcome::Authenticated(_) => {
            emit(tx, wake, WorkerEvent::LoginSuccess { account: user });
        }
        LoginOutcome::NeedsTwoFactor(session) => {
            if twofa.is_empty() {
                emit(
                    tx,
                    wake,
                    WorkerEvent::LoginNeedsTwoFactor {
                        account: user,
                        session,
                    },
                );
                return;
            }
            match deps.proton.submit_2fa(&session, &twofa).await {
                Ok(completed) => {
                    if let Err(err) = deps.store.save_auth_session(&user, &completed) {
                        emit_login_error(tx, wake, &err.to_string());
                        return;
                    }
                    emit(tx, wake, WorkerEvent::LoginSuccess { account: user });
                }
                Err(err) => {
                    emit(
                        tx,
                        wake,
                        WorkerEvent::LoginNeedsTwoFactor {
                            account: user,
                            session,
                        },
                    );
                    emit_login_error(tx, wake, &format!("Mã 2FA không hợp lệ: {err}"));
                }
            }
        }
        LoginOutcome::NeedsHumanVerification { .. } => {
            emit_login_error(
                tx,
                wake,
                "Xác minh CAPTCHA không thành công hoặc Proton yêu cầu thử lại.",
            );
        }
    }
}

fn emit_login_error(
    tx: &mpsc::UnboundedSender<WorkerEvent>,
    wake: &(dyn Fn() + Send + Sync),
    err: &str,
) {
    let err_lower = err.to_lowercase();
    let mut friendly_title = "Lỗi Xác Thực SRP".to_owned();
    let mut friendly_msg = "Xác thực mật mã Proton SRP thất bại.".to_owned();

    if err.contains("429") || err.contains("2028") || err_lower.contains("too many requests") {
        friendly_title = "Giới Hạn Yêu Cầu (Rate Limit 429)".to_owned();
        friendly_msg = concat!(
            "Máy chủ Proton đang tạm thời giới hạn lượt yêu cầu do có quá nhiều lần thử từ mạng/IP này trong thời gian ngắn.\n\n",
            "💡 Cách xử lý nhanh nhất:\n",
            "1. Phát 4G/5G từ điện thoại cho máy tính kết nối (đổi IP mạng mới) rồi đăng nhập lại ngay lập tức.\n",
            "2. Hoặc chờ khoảng 5 - 15 phút để máy chủ Proton tự động mở khóa giới hạn.\n",
            "3. Tránh bấm nút Đăng nhập hoặc Enter liên tục nhiều lần."
        )
        .to_owned();
    } else if err_lower.contains("captcha") {
        friendly_msg =
            "Xác minh Captcha không thành công hoặc đã hết hạn. Vui lòng thử lại.".to_owned();
    } else if err.contains("2FA") || err_lower.contains("2fa") {
        friendly_msg = err.to_owned();
    }

    let short: String = err.chars().take(72).collect();
    let inline_msg = if err.chars().count() > 72 {
        format!("Lỗi: {short}...")
    } else {
        format!("Lỗi: {short}")
    };

    warn!(error = %err, title = %friendly_title, "SRP login failed");
    emit(
        tx,
        wake,
        WorkerEvent::LoginError {
            title: friendly_title,
            friendly_msg,
            detail: err.to_owned(),
            inline_msg,
        },
    );
}

fn handle_session_expired(
    deps: &WorkerDeps,
    auth_generation: u64,
    detail: String,
    tx: &mpsc::UnboundedSender<WorkerEvent>,
    wake: &(dyn Fn() + Send + Sync),
) {
    if !deps.is_auth_current(auth_generation) {
        return;
    }
    let _ = deps.store.clear_all_sessions();
    let _ = ServerCacheManager::clear(&deps.cache_path);
    emit(
        tx,
        wake,
        WorkerEvent::SessionExpired {
            auth_generation,
            detail,
        },
    );
}

async fn handle_scan(
    deps: &WorkerDeps,
    auth_generation: u64,
    tx: &mpsc::UnboundedSender<WorkerEvent>,
    wake: &(dyn Fn() + Send + Sync),
) {
    if !deps.is_auth_current(auth_generation) {
        return;
    }

    emit(
        tx,
        wake,
        WorkerEvent::ScanStatus {
            auth_generation,
            text: "● Đang đọc phiên đăng nhập SRP...".to_owned(),
        },
    );

    let (raw_payload, mut servers) = match deps.proton.fetch_logicals_raw().await {
        Ok(res) => res,
        Err(ApiError::NotAuthenticated) => {
            if deps.auth_generation.load(Ordering::Acquire) == auth_generation {
                emit(tx, wake, WorkerEvent::ScanNeedsLogin { auth_generation });
            }
            return;
        }
        Err(err) if err.is_session_expired() => {
            handle_session_expired(deps, auth_generation, err.to_string(), tx, wake);
            return;
        }
        Err(err) => {
            warn!(error = %err, "fetch_logicals_raw failed");
            if deps.is_auth_current(auth_generation) {
                emit(
                    tx,
                    wake,
                    WorkerEvent::ScanError {
                        auth_generation,
                        friendly_msg: "Không thể lấy danh sách máy chủ Proton VPN. Vui lòng kiểm tra kết nối mạng và thử lại.".to_owned(),
                        detail: err.to_string(),
                    },
                );
            }
            return;
        }
    };
    info!(server_count = servers.len(), "Fetched logical server list");

    if !deps.is_auth_current(auth_generation) {
        return;
    }

    let last_emit = std::sync::Mutex::new(Instant::now() - Duration::from_secs(1));
    ping_servers(
        &mut servers,
        DEFAULT_PING_TIMEOUT_MS,
        DEFAULT_PING_WORKERS,
        |cur, total| {
            if !deps.is_auth_current(auth_generation) {
                return;
            }
            let mut guard = last_emit.lock().expect("progress mutex");
            if cur == 0 || cur == total || guard.elapsed() >= Duration::from_millis(100) {
                *guard = Instant::now();
                let pct = if total > 0 {
                    cur as f32 / total as f32
                } else {
                    0.0
                };
                let pct_int = (pct * 100.0).round() as usize;
                emit(
                    tx,
                    wake,
                    WorkerEvent::LoadingProgress {
                        auth_generation,
                        text: format!("● Đang đo ping: {cur}/{total} máy chủ ({pct_int}%)..."),
                        progress: pct,
                    },
                );
            }
        },
    )
    .await;

    if !deps.is_auth_current(auth_generation) {
        return;
    }

    if let Err(err) = ServerCacheManager::save(&deps.cache_path, Some(&raw_payload), &servers) {
        debug!(error = %err, "failed saving servers cache");
    }

    if !deps.is_auth_current(auth_generation) {
        return;
    }

    emit(
        tx,
        wake,
        WorkerEvent::ScanComplete {
            auth_generation,
            raw_payload: Some(raw_payload),
            servers,
        },
    );
}

async fn handle_connect(
    deps: &WorkerDeps,
    generation: u64,
    auth_generation: u64,
    server: ServerNode,
    tx: &mpsc::UnboundedSender<WorkerEvent>,
    wake: &(dyn Fn() + Send + Sync),
) {
    let mut config = match deps.store.load_client_config() {
        Ok(cfg) => cfg,
        Err(err) => {
            emit(
                tx,
                wake,
                WorkerEvent::ConnectFailed {
                    generation,
                    message: err.to_string(),
                    detail: err.to_string(),
                    service_unavailable: false,
                },
            );
            return;
        }
    };

    let mut refreshed_key: Option<WgKeySnapshot> = None;
    if !config.has_usable_key(60) {
        emit(
            tx,
            wake,
            WorkerEvent::ConnectProgress {
                generation,
                text: "● [1/4] 🔑 Đang cấp & kích hoạt WireGuard Key mới từ Proton API..."
                    .to_owned(),
                progress: 0.25,
            },
        );
        match TASK_AUTH_GENERATION
            .scope(auth_generation, deps.proton.ensure_wg_key(false))
            .await
        {
            Ok(updated) => {
                refreshed_key = Some(WgKeySnapshot::from_config(&updated));
                config = updated;
            }
            Err(err) if err.is_session_expired() => {
                handle_session_expired(deps, auth_generation, err.to_string(), tx, wake);
                return;
            }
            Err(err) => {
                emit(
                    tx,
                    wake,
                    WorkerEvent::ConnectFailed {
                        generation,
                        message: format!("Không thể cấp WireGuard Key: {err}"),
                        detail: err.to_string(),
                        service_unavailable: false,
                    },
                );
                return;
            }
        }
    }

    emit(
        tx,
        wake,
        WorkerEvent::ConnectProgress {
            generation,
            text: "● [2/4] 📝 Đang xác thực cấu hình WireGuard...".to_owned(),
            progress: 0.45,
        },
    );

    let (spec, _) = match validate_and_build_conf(&server, &config) {
        Ok(ok) => ok,
        Err(err) => {
            emit(
                tx,
                wake,
                WorkerEvent::ConnectFailed {
                    generation,
                    message: err.to_string(),
                    detail: err.to_string(),
                    service_unavailable: false,
                },
            );
            return;
        }
    };

    let pubkey_short = if spec.server_pubkey.len() > 16 {
        format!(
            "{}...{}",
            &spec.server_pubkey[..10],
            &spec.server_pubkey[spec.server_pubkey.len() - 6..]
        )
    } else {
        spec.server_pubkey.clone()
    };

    emit(
        tx,
        wake,
        WorkerEvent::ConnectProgress {
            generation,
            text: format!(
                "● [2/4] 📝 Cấu hình Tunnel: {}:{} • Peer: {pubkey_short}",
                spec.entry_ip, spec.port
            ),
            progress: 0.65,
        },
    );

    emit(
        tx,
        wake,
        WorkerEvent::ConnectProgress {
            generation,
            text: format!(
                "● [3/4] ⚡ Đang xác minh handshake & DNS qua {}...",
                spec.entry_ip
            ),
            progress: 0.85,
        },
    );

    info!(
        generation,
        server = %spec.server_name,
        entry_ip = %spec.entry_ip,
        port = spec.port,
        dns = %spec.dns,
        refreshed_key = refreshed_key.is_some(),
        "Sending Connect request to FreetonVPNService"
    );
    let req = ServiceRequest::Connect(spec.clone());
    match deps.pipe.send_request(&req, PIPE_CONNECT_TIMEOUT).await {
        Ok(ServiceResponse::Ok) => {
            let now_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
                .unwrap_or(0);
            let info = match deps
                .pipe
                .send_request(&ServiceRequest::Status, PIPE_STATUS_TIMEOUT)
                .await
            {
                Ok(ServiceResponse::Status(TunnelHealthState::Connected(info))) => info,
                _ => ActiveTunnelInfo {
                    server_name: spec.server_name,
                    country: spec.country,
                    entry_ip: spec.entry_ip,
                    x25519_pubkey: spec.server_pubkey,
                    address: if spec.address.is_empty() {
                        DEFAULT_WG_ADDRESS.to_owned()
                    } else {
                        spec.address
                    },
                    dns: if spec.dns.is_empty() {
                        DEFAULT_WG_DNS.to_owned()
                    } else {
                        spec.dns
                    },
                    port: if spec.port == 0 {
                        DEFAULT_WG_PORT.parse().unwrap_or(51820)
                    } else {
                        spec.port
                    },
                    connected_at_unix: now_unix,
                },
            };
            info!(server = %server.name, tunnel = DEFAULT_TUNNEL_NAME, "WireGuard tunnel connected");
            emit(
                tx,
                wake,
                WorkerEvent::ConnectSucceeded {
                    generation,
                    payload: Box::new(ConnectSuccessPayload {
                        server,
                        info,
                        wg_key: refreshed_key,
                    }),
                },
            );
        }
        Ok(ServiceResponse::Status(_)) => {
            emit(
                tx,
                wake,
                WorkerEvent::ConnectFailed {
                    generation,
                    message: "Phản hồi bất thường từ FreetonVPNService.".to_owned(),
                    detail: "Unexpected Status response to Connect".to_owned(),
                    service_unavailable: false,
                },
            );
        }
        Ok(ServiceResponse::Error { code, message }) => {
            emit(
                tx,
                wake,
                WorkerEvent::ConnectFailed {
                    generation,
                    message: message.clone(),
                    detail: format!("[{code}] {message}"),
                    service_unavailable: false,
                },
            );
        }
        Err(PipeClientError::Unavailable(detail)) => {
            emit(
                tx,
                wake,
                WorkerEvent::ConnectFailed {
                    generation,
                    message: "Dịch vụ nền FreetonVPNService chưa chạy hoặc chưa được cài đặt."
                        .to_owned(),
                    detail,
                    service_unavailable: true,
                },
            );
        }
        Err(err) => {
            emit(
                tx,
                wake,
                WorkerEvent::ConnectFailed {
                    generation,
                    message: err.to_string(),
                    detail: err.to_string(),
                    service_unavailable: false,
                },
            );
        }
    }
}

async fn handle_disconnect(
    deps: &WorkerDeps,
    generation: u64,
    tx: &mpsc::UnboundedSender<WorkerEvent>,
    wake: &(dyn Fn() + Send + Sync),
) {
    match deps
        .pipe
        .send_request(&ServiceRequest::Disconnect, PIPE_CONTROL_TIMEOUT)
        .await
    {
        Ok(ServiceResponse::Ok) => {
            emit(tx, wake, WorkerEvent::DisconnectSucceeded { generation });
        }
        Ok(ServiceResponse::Error { code, message }) => {
            emit(
                tx,
                wake,
                WorkerEvent::DisconnectFailed {
                    generation,
                    message: message.clone(),
                    detail: format!("[{code}] {message}"),
                },
            );
        }
        Ok(ServiceResponse::Status(_)) => {
            emit(
                tx,
                wake,
                WorkerEvent::DisconnectFailed {
                    generation,
                    message: "Phản hồi bất thường từ FreetonVPNService.".to_owned(),
                    detail: "Unexpected Status response to Disconnect".to_owned(),
                },
            );
        }
        Err(err) => {
            emit(
                tx,
                wake,
                WorkerEvent::DisconnectFailed {
                    generation,
                    message: err.to_string(),
                    detail: err.to_string(),
                },
            );
        }
    }
}

async fn handle_check_updates(
    deps: &WorkerDeps,
    manual: bool,
    manifest_url_override: Option<String>,
    tx: &mpsc::UnboundedSender<WorkerEvent>,
    wake: &(dyn Fn() + Send + Sync),
) {
    let result = if let Some(custom_url) = manifest_url_override
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        fetch_custom_update_info(custom_url).await
    } else {
        fetch_update_info(
            deps.update_manifest_url.as_deref(),
            deps.update_repo.as_deref(),
        )
        .await
    };

    match result {
        Ok(Some(info)) if is_newer_version(APP_VERSION, &info.version) => {
            emit(tx, wake, WorkerEvent::UpdateAvailable { info });
        }
        Ok(Some(_)) => {
            emit(
                tx,
                wake,
                WorkerEvent::UpdateUpToDate {
                    manual,
                    current_version: APP_VERSION.to_owned(),
                },
            );
        }
        Ok(None) => {
            emit(
                tx,
                wake,
                WorkerEvent::UpdateCheckFailed {
                    manual,
                    message: "Không thể kiểm tra phiên bản mới lúc này. Vui lòng kiểm tra lại kết nối mạng hoặc thử lại sau.".to_owned(),
                },
            );
        }
        Err(err) => {
            emit(
                tx,
                wake,
                WorkerEvent::UpdateCheckFailed {
                    manual,
                    message: format!("Đã xảy ra lỗi khi kiểm tra phiên bản mới:\n{err}"),
                },
            );
        }
    }
}

async fn handle_export_conf(
    deps: &WorkerDeps,
    auth_generation: u64,
    server: ServerNode,
    tx: &mpsc::UnboundedSender<WorkerEvent>,
    wake: &(dyn Fn() + Send + Sync),
) {
    let mut config = match deps.store.load_client_config() {
        Ok(cfg) => cfg,
        Err(err) => {
            emit(
                tx,
                wake,
                WorkerEvent::ConfExportError {
                    title: "Lỗi Key WireGuard".to_owned(),
                    friendly_msg: "Không thể đọc cấu hình WireGuard.".to_owned(),
                    detail: err.to_string(),
                },
            );
            return;
        }
    };

    if !config.has_usable_key(60) {
        if !deps.is_auth_current(auth_generation) {
            return;
        }
        match TASK_AUTH_GENERATION
            .scope(auth_generation, deps.proton.ensure_wg_key(false))
            .await
        {
            Ok(updated) => {
                if !deps.is_auth_current(auth_generation) {
                    return;
                }
                let key = WgKeySnapshot::from_config(&updated);
                config = updated;
                emit(
                    tx,
                    wake,
                    WorkerEvent::WgKeyRefreshed {
                        auth_generation,
                        key,
                    },
                );
            }
            Err(err) if err.is_session_expired() => {
                handle_session_expired(deps, auth_generation, err.to_string(), tx, wake);
                return;
            }
            Err(err) => {
                emit(
                    tx,
                    wake,
                    WorkerEvent::ConfExportError {
                        title: "Lỗi Key WireGuard".to_owned(),
                        friendly_msg: "Không thể lấy hoặc đăng ký WireGuard Key cho tài khoản."
                            .to_owned(),
                        detail: err.to_string(),
                    },
                );
                return;
            }
        }
    }

    let (_, conf_content) = match validate_and_build_conf(&server, &config) {
        Ok(ok) => ok,
        Err(err) => {
            emit(
                tx,
                wake,
                WorkerEvent::ConfExportError {
                    title: "Lỗi Cấu Hình WireGuard".to_owned(),
                    friendly_msg: "Thông số máy chủ hoặc WireGuard không hợp lệ.".to_owned(),
                    detail: err.to_string(),
                },
            );
            return;
        }
    };

    let safe_name = if server.name.trim().is_empty() {
        "FreetonVPN".to_owned()
    } else {
        server
            .name
            .chars()
            .map(|c| {
                if matches!(c, '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
                    '_'
                } else {
                    c
                }
            })
            .collect()
    };
    let default_filename = format!("{safe_name}.conf");
    let dialog_title = format!("Xuất cấu hình cho {}", server.name);

    let picked = tokio::task::spawn_blocking(move || {
        rfd::FileDialog::new()
            .set_file_name(&default_filename)
            .add_filter("WireGuard Config", &["conf"])
            .set_title(&dialog_title)
            .save_file()
    })
    .await;

    let Some(path) = picked.ok().flatten() else {
        return;
    };

    match std::fs::write(&path, conf_content) {
        Ok(()) => emit(
            tx,
            wake,
            WorkerEvent::ConfExported {
                message: format!("Đã lưu file WireGuard tại:\n{}", path.display()),
            },
        ),
        Err(err) => emit(
            tx,
            wake,
            WorkerEvent::ConfExportError {
                title: "Lỗi Xuất File".to_owned(),
                friendly_msg: "Không thể lưu file cấu hình WireGuard.".to_owned(),
                detail: err.to_string(),
            },
        ),
    }
}

async fn handle_fetch_wg_key_manual(
    deps: &WorkerDeps,
    auth_generation: u64,
    tx: &mpsc::UnboundedSender<WorkerEvent>,
    wake: &(dyn Fn() + Send + Sync),
) {
    if !deps.is_auth_current(auth_generation) {
        return;
    }
    let res = TASK_AUTH_GENERATION
        .scope(auth_generation, deps.proton.ensure_wg_key(true))
        .await;
    if !deps.is_auth_current(auth_generation) {
        return;
    }
    match res {
        Ok(cfg) => emit(
            tx,
            wake,
            WorkerEvent::WgKeyManualSucceeded {
                auth_generation,
                key: WgKeySnapshot::from_config(&cfg),
            },
        ),
        Err(err) if err.is_session_expired() => {
            handle_session_expired(deps, auth_generation, err.to_string(), tx, wake);
        }
        Err(err) => emit(
            tx,
            wake,
            WorkerEvent::WgKeyManualFailed {
                auth_generation,
                friendly_msg: "Không thể tự động cấp WireGuard Key từ tài khoản.".to_owned(),
                detail: err.to_string(),
            },
        ),
    }
}

async fn handle_pick_and_import_conf(
    tx: &mpsc::UnboundedSender<WorkerEvent>,
    wake: &(dyn Fn() + Send + Sync),
) {
    let picked = tokio::task::spawn_blocking(|| {
        rfd::FileDialog::new()
            .add_filter("WireGuard Config", &["conf"])
            .set_title("Chọn file cấu hình WireGuard (.conf)")
            .pick_file()
    })
    .await;

    let Some(path) = picked.ok().flatten() else {
        emit(tx, wake, WorkerEvent::ConfImportCancelled);
        return;
    };

    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("config.conf")
        .to_owned();

    match tokio::task::spawn_blocking(move || std::fs::read_to_string(&path)).await {
        Ok(Ok(content)) => match parse_wireguard_conf(&content) {
            Ok(parsed) => emit(tx, wake, WorkerEvent::ConfImported { filename, parsed }),
            Err(err) => emit(
                tx,
                wake,
                WorkerEvent::ConfImportError {
                    title: "Lỗi Nạp File .conf".to_owned(),
                    friendly_msg: "File cấu hình WireGuard không hợp lệ.".to_owned(),
                    detail: err,
                },
            ),
        },
        Ok(Err(err)) => emit(
            tx,
            wake,
            WorkerEvent::ConfImportError {
                title: "Lỗi Nạp File .conf".to_owned(),
                friendly_msg: "Không thể đọc file cấu hình WireGuard.".to_owned(),
                detail: err.to_string(),
            },
        ),
        Err(err) => emit(
            tx,
            wake,
            WorkerEvent::ConfImportError {
                title: "Lỗi Nạp File .conf".to_owned(),
                friendly_msg: "Không thể đọc file cấu hình WireGuard.".to_owned(),
                detail: err.to_string(),
            },
        ),
    }
}

fn default_update_download_dir() -> PathBuf {
    std::env::temp_dir().join("FreetonVPN_Update")
}

fn cleanup_targeted_partial_file(run_dir: &Path, download_url: &str) {
    let part_path = run_dir.join(expected_part_filename(download_url));
    if part_path.exists() {
        let _ = std::fs::remove_file(&part_path);
    }
    let _ = std::fs::remove_dir(run_dir);
}

enum UpdateSelectOutcome {
    Cancelled,
    Finished(Result<UpdateAction, UpdateError>),
}

async fn handle_start_update_download(
    deps: &WorkerDeps,
    generation: u64,
    info: UpdateInfo,
    tx: &mpsc::UnboundedSender<WorkerEvent>,
    wake: &(dyn Fn() + Send + Sync),
) {
    let cancel_rx_opt = {
        let mut guard = deps
            .update_cancel
            .lock()
            .expect("update cancel mutex poisoned");
        guard.register(generation)
    };
    let Some(mut cancel_rx) = cancel_rx_opt else {
        emit(
            tx,
            wake,
            WorkerEvent::UpdateDownloadCancelled { generation },
        );
        return;
    };

    let base_dir = deps
        .update_download_dir
        .clone()
        .unwrap_or_else(default_update_download_dir);
    let run_dir = base_dir.join(format!("gen-{generation}"));
    let last_emit = StdMutex::new(Instant::now() - Duration::from_secs(1));

    let outcome = {
        let download_fut = download_and_verify_update(
            &info,
            &run_dir,
            |downloaded_bytes, total_bytes, percent| {
                let mut guard = last_emit.lock().expect("progress mutex");
                if percent >= 99.9 || guard.elapsed() >= Duration::from_millis(50) {
                    *guard = Instant::now();
                    emit(
                        tx,
                        wake,
                        WorkerEvent::UpdateDownloadProgress {
                            generation,
                            downloaded_bytes,
                            total_bytes,
                            percent,
                        },
                    );
                }
            },
        );

        tokio::select! {
            biased;
            _ = cancel_rx.wait_for(|&cancelled| cancelled) => UpdateSelectOutcome::Cancelled,
            res = download_fut => UpdateSelectOutcome::Finished(res),
        }
    };

    if let Ok(mut guard) = deps.update_cancel.lock() {
        guard.clear(generation);
    }

    match outcome {
        UpdateSelectOutcome::Cancelled => {
            cleanup_targeted_partial_file(&run_dir, &info.download_url);
            emit(
                tx,
                wake,
                WorkerEvent::UpdateDownloadCancelled { generation },
            );
        }
        UpdateSelectOutcome::Finished(res) => {
            emit(
                tx,
                wake,
                WorkerEvent::UpdateDownloadFinished {
                    generation,
                    action: res.map_err(|e| e.to_string()),
                },
            );
        }
    }
}

async fn handle_repair_service(
    deps: &WorkerDeps,
    tx: &mpsc::UnboundedSender<WorkerEvent>,
    wake: &(dyn Fn() + Send + Sync),
) {
    let exe_opt = deps.service_exe_path.clone().or_else(|| {
        std::env::current_exe()
            .ok()
            .and_then(|exe| sibling_service_exe_path(&exe))
    });
    let Some(service_exe) = exe_opt else {
        emit(
            tx,
            wake,
            WorkerEvent::ServiceRepairFailed {
                message: "Không thể xác định đường dẫn FreetonVPNService.exe.".to_owned(),
                detail: "std::env::current_exe() failed".to_owned(),
            },
        );
        return;
    };
    if !service_exe.is_file() {
        emit(
            tx,
            wake,
            WorkerEvent::ServiceRepairFailed {
                message: "Không tìm thấy FreetonVPNService.exe cạnh ứng dụng. Vui lòng cài đặt lại Freeton VPN.".to_owned(),
                detail: format!("Missing sibling executable: {}", service_exe.display()),
            },
        );
        return;
    }

    let shell = Arc::clone(&deps.shell);
    let exe_clone = service_exe.clone();
    let launch_res = tokio::task::spawn_blocking(move || {
        let dir = exe_clone.parent().map(Path::to_path_buf);
        shell.launch_elevated(&exe_clone, "--install", dir.as_deref())
    })
    .await;

    match launch_res {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            emit(
                tx,
                wake,
                WorkerEvent::ServiceRepairFailed {
                    message: err.clone(),
                    detail: err,
                },
            );
            return;
        }
        Err(err) => {
            emit(
                tx,
                wake,
                WorkerEvent::ServiceRepairFailed {
                    message: "Không thể khởi chạy trình cài đặt dịch vụ (UAC).".to_owned(),
                    detail: err.to_string(),
                },
            );
            return;
        }
    }

    let attempts = deps.service_repair_poll_attempts.max(1);
    let mut last_err = "FreetonVPNService chưa phản hồi".to_owned();
    for attempt in 0..attempts {
        match deps
            .pipe
            .send_request(&ServiceRequest::Status, PIPE_STATUS_TIMEOUT)
            .await
        {
            Ok(ServiceResponse::Status(_)) => {
                emit(tx, wake, WorkerEvent::ServiceRepairSucceeded);
                return;
            }
            Ok(other) => {
                last_err = format!("Phản hồi không mong đợi từ FreetonVPNService: {other:?}");
            }
            Err(err) => {
                last_err = err.to_string();
            }
        }
        if attempt + 1 < attempts && !deps.service_repair_poll_interval.is_zero() {
            tokio::time::sleep(deps.service_repair_poll_interval).await;
        }
    }

    emit(
        tx,
        wake,
        WorkerEvent::ServiceRepairFailed {
            message: "Đã chạy cài đặt nhưng FreetonVPNService chưa phản hồi. Hãy bấm 'Kiểm tra lại' sau vài giây.".to_owned(),
            detail: last_err,
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use freeton_core::storage::StorageError;
    use freeton_core::wg::TunnelHealthState;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn make_server(
        name: &str,
        country: &str,
        city: &str,
        ping_ms: Option<f64>,
        load: Option<f64>,
    ) -> ServerNode {
        ServerNode {
            name: name.to_owned(),
            country: country.to_owned(),
            entry_country: country.to_owned(),
            city: city.to_owned(),
            load,
            status: 1,
            domain: format!("{}.protonvpn.net", name.to_ascii_lowercase()),
            entry_ip: "198.51.100.10".to_owned(),
            exit_ip: "198.51.100.11".to_owned(),
            x25519_public_key: "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=".to_owned(),
            active_physical_servers: 1,
            ping_target: "198.51.100.10".to_owned(),
            ping_ms,
        }
    }

    #[derive(Default)]
    struct MockCredentialStore {
        entries: Mutex<HashMap<(String, String), String>>,
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
                .expect("mock cred lock")
                .get(&(service.to_owned(), username.to_owned()))
                .cloned())
        }

        fn set_password(
            &self,
            service: &str,
            username: &str,
            password: &str,
        ) -> Result<(), StorageError> {
            self.entries.lock().expect("mock cred lock").insert(
                (service.to_owned(), username.to_owned()),
                password.to_owned(),
            );
            Ok(())
        }

        fn delete_password(&self, service: &str, username: &str) -> Result<(), StorageError> {
            self.entries
                .lock()
                .expect("mock cred lock")
                .remove(&(service.to_owned(), username.to_owned()));
            Ok(())
        }
    }

    struct MockPipeTransport {
        sent: Mutex<Vec<ServiceRequest>>,
        response: Mutex<Result<ServiceResponse, PipeClientError>>,
    }

    impl MockPipeTransport {
        fn ok(resp: ServiceResponse) -> Self {
            Self {
                sent: Mutex::new(Vec::new()),
                response: Mutex::new(Ok(resp)),
            }
        }

        fn err(err: PipeClientError) -> Self {
            Self {
                sent: Mutex::new(Vec::new()),
                response: Mutex::new(Err(err)),
            }
        }
    }

    impl PipeTransport for MockPipeTransport {
        fn send_request<'a>(
            &'a self,
            req: &'a ServiceRequest,
            _timeout: Duration,
        ) -> PipeFuture<'a, Result<ServiceResponse, PipeClientError>> {
            self.sent.lock().expect("mock pipe lock").push(req.clone());
            let res = self.response.lock().expect("mock pipe lock").clone();
            Box::pin(async move { res })
        }
    }

    #[derive(Default)]
    struct MockShellLauncher {
        elevated_calls: Mutex<Vec<(PathBuf, String)>>,
        opened_urls: Mutex<Vec<String>>,
        opened_dirs: Mutex<Vec<PathBuf>>,
        realtime_log_calls: Mutex<Vec<(PathBuf, PathBuf, PathBuf)>>,
        elevated_result: Mutex<Option<Result<(), String>>>,
    }

    impl MockShellLauncher {
        fn ok() -> Self {
            Self {
                elevated_result: Mutex::new(Some(Ok(()))),
                ..Default::default()
            }
        }

        fn elevated_err(msg: &str) -> Self {
            Self {
                elevated_result: Mutex::new(Some(Err(msg.to_owned()))),
                ..Default::default()
            }
        }
    }

    impl ShellLauncher for MockShellLauncher {
        fn launch_elevated(
            &self,
            target: &Path,
            args: &str,
            _working_dir: Option<&Path>,
        ) -> Result<(), String> {
            self.elevated_calls
                .lock()
                .expect("elevated lock")
                .push((target.to_path_buf(), args.to_owned()));
            self.elevated_result
                .lock()
                .expect("res lock")
                .clone()
                .unwrap_or(Ok(()))
        }

        fn open_https_url(&self, url: &str) -> Result<(), String> {
            let safe = validate_https_browser_url(url)?;
            self.opened_urls.lock().expect("url lock").push(safe);
            Ok(())
        }

        fn open_directory(&self, dir: &Path) -> Result<(), String> {
            self.opened_dirs
                .lock()
                .expect("dir lock")
                .push(dir.to_path_buf());
            Ok(())
        }

        fn open_realtime_log_cli(
            &self,
            app_log: &Path,
            service_log: &Path,
            tunnel_log: &Path,
        ) -> Result<(), String> {
            self.realtime_log_calls
                .lock()
                .expect("realtime log lock")
                .push((
                    app_log.to_path_buf(),
                    service_log.to_path_buf(),
                    tunnel_log.to_path_buf(),
                ));
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockStartupController {
        enabled: Mutex<bool>,
    }

    impl StartupController for MockStartupController {
        fn is_enabled(&self) -> bool {
            *self.enabled.lock().expect("startup lock")
        }

        fn set_enabled(&self, enable: bool) -> Result<(), StorageError> {
            *self.enabled.lock().expect("startup lock") = enable;
            Ok(())
        }
    }

    fn make_test_deps(
        store: Arc<dyn CredentialStore>,
        proton: Arc<ProtonClient>,
        pipe: Arc<dyn PipeTransport>,
    ) -> WorkerDeps {
        WorkerDeps {
            store,
            proton,
            pipe,
            shell: Arc::new(MockShellLauncher::ok()),
            startup: Arc::new(MockStartupController::default()),
            cache_path: std::env::temp_dir().join("freeton_unused_cache.json"),
            update_manifest_url: None,
            update_repo: None,
            update_download_dir: None,
            service_exe_path: None,
            service_repair_poll_attempts: 3,
            service_repair_poll_interval: Duration::from_millis(5),
            auth_generation: Arc::new(AtomicU64::new(0)),
            update_cancel: Arc::new(StdMutex::new(UpdateCancelCoordinator::default())),
        }
    }

    #[test]
    fn test_repeated_connect_ignored_while_connecting_or_disconnecting() {
        let s1 = make_server("JP-FREE#1", "JP", "Tokyo", Some(25.0), Some(15.0));
        let s2 = make_server("SG-FREE#1", "SG", "Singapore", Some(20.0), Some(10.0));
        let mut state = AppState::new(
            true,
            Some("user@proton.me".to_owned()),
            ClientConfig::default(),
            None,
            vec![s1.clone(), s2.clone()],
        );
        let _ = state.drain_commands();

        // Start first connection.
        state.select_and_connect_server(s1);
        assert!(state.is_connecting_vpn);
        let gen_after_first = state.connection_generation;
        assert_eq!(state.drain_commands().len(), 1);

        // Repeated connect or drawer server click while connecting must be ignored.
        state.connect_to_server(s2.clone());
        state.select_and_connect_server(s2.clone());
        state.toggle_vpn();
        assert_eq!(state.connection_generation, gen_after_first);
        assert_eq!(
            state.selected_server.as_ref().map(|s| s.name.as_str()),
            Some("JP-FREE#1")
        );
        assert!(state.drain_commands().is_empty());

        // Simulate disconnect flow: repeated disconnect must also be ignored while disconnecting.
        state.is_connecting_vpn = false;
        state.is_disconnecting_vpn = false;
        state.tunnel_running = true;
        state.tunnel_verified = true;
        state.disconnect_vpn();
        assert!(state.is_connecting_vpn);
        assert!(state.is_disconnecting_vpn);
        let gen_after_disconnect = state.connection_generation;
        assert_eq!(state.drain_commands().len(), 1);

        state.disconnect_vpn();
        state.connect_to_server(s2);
        assert_eq!(state.connection_generation, gen_after_disconnect);
        assert!(state.drain_commands().is_empty());
    }

    #[test]
    fn test_stale_scan_does_not_overwrite_manual_selection_while_connecting() {
        let manual = make_server("manual", "JP", "Tokyo", Some(50.0), Some(30.0));
        let fastest = make_server("fastest", "SG", "Singapore", Some(12.0), Some(5.0));
        let mut state = AppState::new(
            true,
            Some("user@proton.me".to_owned()),
            ClientConfig::default(),
            None,
            vec![manual.clone()],
        );
        state.selected_server = Some(manual);
        state.is_connecting_vpn = true;
        state.loading.visible = true;
        state.loading.text = "● [3/4] Đang xác minh...".to_owned();

        state.apply_event(WorkerEvent::ScanComplete {
            auth_generation: state.auth_generation,
            raw_payload: None,
            servers: vec![
                fastest,
                make_server("manual", "JP", "Tokyo", Some(42.0), Some(20.0)),
            ],
        });

        assert_eq!(
            state.selected_server.as_ref().map(|s| s.name.as_str()),
            Some("manual")
        );
        assert_eq!(
            state.selected_server.as_ref().and_then(|s| s.ping_ms),
            Some(42.0)
        );
        assert!(state.loading.hide_at.is_none());
    }

    #[test]
    fn test_stale_status_event_from_old_generation_is_discarded() {
        let active = make_server("JP-FREE#1", "JP", "Tokyo", Some(25.0), Some(15.0));
        let mut state = AppState::new(
            true,
            Some("user@proton.me".to_owned()),
            ClientConfig::default(),
            None,
            vec![active.clone()],
        );
        state.tunnel_running = true;
        state.tunnel_verified = true;
        state.connected_server = Some(active);
        state.vpn_connect_time_unix = Some(1_700_000_000);
        state.connection_generation = 1;
        state.request_status_refresh();
        assert!(state.status_check_pending);
        let _ = state.drain_commands();

        // Generation advances before old status arrives.
        state.connection_generation = 2;
        state.apply_event(WorkerEvent::TunnelStatus {
            generation: 1,
            status: Ok(TunnelHealthState::Disconnected),
        });

        assert!(!state.status_check_pending);
        assert!(state.tunnel_running);
        assert!(state.tunnel_verified);
        assert!(state.connected_server.is_some());
    }

    #[test]
    fn test_hydrates_connected_state_from_running_service_on_startup() {
        let sg = make_server("SG-FREE#1", "SG", "Singapore", Some(20.0), Some(10.0));
        let jp = make_server("JP-FREE#2", "JP", "Tokyo", Some(35.0), Some(20.0));
        let mut state = AppState::new(
            true,
            Some("user@proton.me".to_owned()),
            ClientConfig::default(),
            None,
            vec![sg, jp.clone()],
        );
        let _ = state.drain_commands();

        let info = ActiveTunnelInfo {
            server_name: jp.name.clone(),
            country: jp.country.clone(),
            entry_ip: jp.entry_ip.clone(),
            x25519_pubkey: jp.x25519_public_key.clone(),
            address: "10.2.0.2/32".to_owned(),
            dns: "10.2.0.1, 1.1.1.1".to_owned(),
            port: 51820,
            connected_at_unix: 1_700_000_123,
        };
        state.connection_generation = 1;
        state.status_check_pending = true;
        state.apply_event(WorkerEvent::TunnelStatus {
            generation: 1,
            status: Ok(TunnelHealthState::Connected(info)),
        });

        assert!(state.tunnel_running);
        assert!(state.tunnel_verified);
        assert_eq!(
            state.connected_server.as_ref().map(|s| s.name.as_str()),
            Some("JP-FREE#2")
        );
        assert_eq!(
            state.selected_server.as_ref().map(|s| s.name.as_str()),
            Some("JP-FREE#2")
        );
        assert_eq!(state.vpn_connect_time_unix, Some(1_700_000_123));
        assert!(matches!(state.service_health, ServiceHealthStatus::Healthy));
    }

    #[test]
    fn test_drawer_filtering_sorting_and_empty_search_state() {
        let servers = vec![
            make_server("US-FREE#2", "US", "New York", Some(120.0), Some(10.0)),
            make_server("JP-FREE#1", "JP", "Tokyo", Some(35.0), Some(60.0)),
            make_server("JP-FREE#2", "JP", "Osaka", None, Some(5.0)),
            make_server("SG-FREE#1", "SG", "Singapore", Some(25.0), Some(20.0)),
        ];
        let mut state = AppState::new(
            true,
            Some("user@proton.me".to_owned()),
            ClientConfig::default(),
            None,
            servers,
        );

        state.selected_country_code = Some("JP".to_owned());
        state.search_query = "nhật bản".to_owned();
        state.sort_mode = SortMode::Ping;
        let (best_jp, jp_list) = state.drawer_servers();
        assert_eq!(best_jp.as_ref().map(|s| s.name.as_str()), Some("JP-FREE#1"));
        assert_eq!(
            jp_list.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
            vec!["JP-FREE#1", "JP-FREE#2"]
        );

        state.selected_country_code = None;
        state.search_query.clear();
        state.sort_mode = SortMode::Load;
        let (_, load_list) = state.drawer_servers();
        assert_eq!(
            load_list
                .iter()
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>(),
            vec!["JP-FREE#2", "US-FREE#2", "SG-FREE#1", "JP-FREE#1"]
        );

        state.search_query = "not-a-real-server".to_owned();
        let (empty_best, empty_list) = state.drawer_servers();
        assert!(empty_best.is_none());
        assert!(empty_list.is_empty());
    }

    #[tokio::test]
    async fn test_ipc_framing_roundtrips_request_and_response_over_duplex() {
        let (client_stream, mut server_stream) = tokio::io::duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut raw = Vec::new();
            let mut buf = [0u8; 512];
            loop {
                let n = server_stream.read(&mut buf).await.expect("read");
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&buf[..n]);
                if raw.contains(&b'\n') {
                    break;
                }
            }
            let req: ServiceRequest =
                serde_json::from_str(String::from_utf8_lossy(&raw).trim()).expect("parse req");
            assert_eq!(req, ServiceRequest::Status);

            let resp = ServiceResponse::Status(TunnelHealthState::Disconnected);
            let mut line = serde_json::to_string(&resp).expect("serialize resp");
            line.push('\n');
            server_stream
                .write_all(line.as_bytes())
                .await
                .expect("write resp");
            server_stream.flush().await.expect("flush resp");
        });

        let response = frame_ipc_exchange(client_stream, &ServiceRequest::Status)
            .await
            .expect("ipc exchange succeeds");
        assert_eq!(
            response,
            ServiceResponse::Status(TunnelHealthState::Disconnected)
        );
        server_task.await.expect("server task");
    }

    #[tokio::test]
    async fn test_quit_sends_shutdown_tunnel_on_exit_and_ignores_unavailable_pipe() {
        let pipe = Arc::new(MockPipeTransport::ok(ServiceResponse::Ok));
        let store = Arc::new(MockCredentialStore::default());
        let deps = Arc::new(make_test_deps(
            Arc::clone(&store) as Arc<dyn CredentialStore>,
            Arc::new(ProtonClient::new(store)),
            Arc::clone(&pipe) as Arc<dyn PipeTransport>,
        ));

        let mut app = AppState::new(false, None, ClientConfig::default(), None, Vec::new());
        let _ = app.drain_commands();
        app.request_quit();
        assert!(app.closing);
        let cmds = app.drain_commands();
        assert!(matches!(cmds.as_slice(), [UiCommand::ShutdownOnExit]));

        let (tx, mut rx) = mpsc::unbounded_channel();
        handle_ui_command(deps, UiCommand::ShutdownOnExit, &tx, &|| {}).await;
        assert_eq!(
            *pipe.sent.lock().expect("sent lock"),
            vec![ServiceRequest::ShutdownTunnelOnExit]
        );
        let ev = rx.recv().await.expect("exit event");
        app.apply_event(ev);
        assert!(app.exit_ready);

        // Unavailable pipe still exits cleanly without trapping the user.
        let unavail_store = Arc::new(MockCredentialStore::default());
        let unavail_deps = Arc::new(make_test_deps(
            Arc::clone(&unavail_store) as Arc<dyn CredentialStore>,
            Arc::new(ProtonClient::new(unavail_store)),
            Arc::new(MockPipeTransport::err(PipeClientError::Unavailable(
                "not installed".to_owned(),
            ))),
        ));
        let (tx2, mut rx2) = mpsc::unbounded_channel();
        handle_ui_command(unavail_deps, UiCommand::ShutdownOnExit, &tx2, &|| {}).await;
        let ev2 = rx2.recv().await.expect("exit event 2");
        assert!(matches!(ev2, WorkerEvent::ExitReady { error: None }));
    }

    #[tokio::test]
    async fn test_srp_login_captcha_challenge_retries_once_with_token() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let captured_requests = Arc::new(Mutex::new(Vec::<String>::new()));
        let captured_clone = Arc::clone(&captured_requests);

        tokio::spawn(async move {
            for idx in 0..2 {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
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
                let req_str = String::from_utf8_lossy(&raw).into_owned();
                captured_clone
                    .lock()
                    .expect("cap lock")
                    .push(req_str.clone());

                let (status, body) = if idx == 0 {
                    (
                        "422 Unprocessable Entity",
                        r#"{"Code":9001,"Error":"Human verification required","Details":{"Methods":["captcha"],"HumanVerificationToken":"tok-chal","WebUrl":"https://verify.proton.me/?methods=captcha&token=tok-chal"}}"#,
                    )
                } else {
                    (
                        "400 Bad Request",
                        r#"{"Code":8002,"Error":"Incorrect login credentials"}"#,
                    )
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            }
        });

        let store = Arc::new(MockCredentialStore::default());
        let base = format!("http://{addr}");
        let proton = Arc::new(ProtonClient::with_endpoints(
            Arc::clone(&store) as Arc<dyn CredentialStore>,
            base.clone(),
            vec![base.clone()],
            base,
        ));
        let deps = make_test_deps(
            store,
            proton,
            Arc::new(MockPipeTransport::ok(ServiceResponse::Ok)),
        );

        let (tx, mut rx) = mpsc::unbounded_channel();
        let captured_url = Arc::new(Mutex::new(None::<String>));
        let captured_url_clone = Arc::clone(&captured_url);

        handle_srp_login_with_captcha(
            &deps,
            SrpLoginParams {
                username: "user@proton.me",
                password: "pass123",
                two_factor: "",
                pending_session: None,
            },
            move |challenge| {
                *captured_url_clone.lock().expect("url lock") = Some(challenge.url);
                async move { Ok("solved_hv_token_0123456789abcdef".to_owned()) }
            },
            &tx,
            &|| {},
        )
        .await;

        let reqs = captured_requests.lock().expect("cap lock");
        assert_eq!(reqs.len(), 2);
        assert!(reqs[1]
            .to_ascii_lowercase()
            .contains("x-pm-human-verification-token: solved_hv_token_0123456789abcdef"));
        assert!(reqs[1]
            .to_ascii_lowercase()
            .contains("x-pm-human-verification-token-type: captcha"));
        assert!(captured_url
            .lock()
            .expect("url lock")
            .as_deref()
            .is_some_and(|u| u.contains("ForceWebMessaging=1")));

        let mut events = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            events.push(ev);
        }
        assert!(events
            .iter()
            .any(|e| matches!(e, WorkerEvent::LoginStatus(_))));
        assert!(events
            .iter()
            .any(|e| matches!(e, WorkerEvent::LoginError { .. })));
    }

    #[test]
    fn test_logout_closes_confirm_dialog_and_discards_stale_scan_and_key_events() {
        let store = MockCredentialStore::default();
        let active = make_server("JP-FREE#1", "JP", "Tokyo", Some(25.0), Some(15.0));
        let mut state = AppState::new(
            true,
            Some("user@proton.me".to_owned()),
            ClientConfig::default(),
            None,
            vec![active.clone()],
        );
        let initial_gen = state.auth_generation;
        assert_eq!(initial_gen, 1);
        let _ = state.drain_commands();

        // 1. Logout while connected closes LogoutConfirm immediately and sets logout_after_disconnect.
        state.tunnel_running = true;
        state.tunnel_verified = true;
        state.active_dialog = ActiveDialog::LogoutConfirm;
        state.request_logout(&store);
        assert_eq!(state.active_dialog, ActiveDialog::None);
        assert!(state.logout_after_disconnect);
        assert!(state.is_disconnecting_vpn);
        let _ = state.drain_commands();

        // 2. Logout clicked while connecting also closes LogoutConfirm cleanly with warning toast.
        state.logout_after_disconnect = false;
        state.is_disconnecting_vpn = false;
        state.is_connecting_vpn = true;
        state.active_dialog = ActiveDialog::LogoutConfirm;
        state.request_logout(&store);
        assert_eq!(state.active_dialog, ActiveDialog::None);
        assert!(state.info_toast.is_some());

        // 3. Complete idle logout: increments auth_generation and discards stale scan/key events.
        state.is_connecting_vpn = false;
        state.tunnel_running = false;
        state.tunnel_verified = false;
        state.request_logout(&store);
        assert!(!state.is_logged_in);
        assert_eq!(state.auth_generation, 2);
        assert!(state.all_free_servers.is_empty());

        let stale_server = make_server("SG-FREE#9", "SG", "Singapore", Some(12.0), Some(5.0));
        state.apply_event(WorkerEvent::ScanStatus {
            auth_generation: initial_gen,
            text: "stale".to_owned(),
        });
        state.apply_event(WorkerEvent::LoadingProgress {
            auth_generation: initial_gen,
            text: "stale".to_owned(),
            progress: 0.5,
        });
        state.apply_event(WorkerEvent::ScanComplete {
            auth_generation: initial_gen,
            raw_payload: Some(serde_json::json!({"LogicalServers": []})),
            servers: vec![stale_server.clone()],
        });
        state.apply_event(WorkerEvent::ScanError {
            auth_generation: initial_gen,
            friendly_msg: "stale err".to_owned(),
            detail: "stale detail".to_owned(),
        });
        state.apply_event(WorkerEvent::ScanNeedsLogin {
            auth_generation: initial_gen,
        });
        state.apply_event(WorkerEvent::WgKeyRefreshed {
            auth_generation: initial_gen,
            key: WgKeySnapshot {
                private_key: "stale-priv".to_owned(),
                public_key: "stale-pub".to_owned(),
                expiration: 1_999_999_999,
            },
        });
        assert!(state.all_free_servers.is_empty());
        assert_eq!(state.active_dialog, ActiveDialog::None);
        assert!(state.client_config.private_key.is_empty());

        // 4. Re-login bumps auth_generation again so events from session 1 stay rejected.
        state.apply_event(WorkerEvent::LoginSuccess {
            account: "new@proton.me".to_owned(),
        });
        assert!(state.is_logged_in);
        assert_eq!(state.auth_generation, 3);
        let _ = state.drain_commands();

        state.apply_event(WorkerEvent::ScanComplete {
            auth_generation: initial_gen,
            raw_payload: None,
            servers: vec![stale_server],
        });
        assert!(state.all_free_servers.is_empty());

        let fresh_server = make_server("JP-FREE#2", "JP", "Tokyo", Some(18.0), Some(8.0));
        state.apply_event(WorkerEvent::ScanComplete {
            auth_generation: 3,
            raw_payload: None,
            servers: vec![fresh_server],
        });
        assert_eq!(state.all_free_servers.len(), 1);
        assert_eq!(state.all_free_servers[0].name, "JP-FREE#2");
    }

    #[tokio::test]
    async fn test_post_logout_scan_and_key_workers_do_not_write_cache_or_client_config() {
        let store = Arc::new(MockCredentialStore::default());
        let session = StoredAuthSession {
            uid: "uid-test".to_owned(),
            access_token: "acc-test".to_owned(),
            refresh_token: "ref-test".to_owned(),
            scopes: vec!["full".to_owned()],
        };
        store
            .save_auth_session("user@proton.me", &session)
            .expect("seed auth session");

        let auth_gen = Arc::new(AtomicU64::new(1));
        let guarded_store: Arc<dyn CredentialStore> = Arc::new(AuthGuardedStore::new(
            Arc::clone(&store) as Arc<dyn CredentialStore>,
            Arc::clone(&auth_gen),
        ));

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let logicals_entered = Arc::new(tokio::sync::Notify::new());
        let logicals_release = Arc::new(tokio::sync::Notify::new());
        let cert_entered = Arc::new(tokio::sync::Notify::new());
        let cert_release = Arc::new(tokio::sync::Notify::new());

        let l_ent = Arc::clone(&logicals_entered);
        let l_rel = Arc::clone(&logicals_release);
        let c_ent = Arc::clone(&cert_entered);
        let c_rel = Arc::clone(&cert_release);

        tokio::spawn(async move {
            let pem = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f\n-----END PRIVATE KEY-----\n";
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let l_ent = Arc::clone(&l_ent);
                let l_rel = Arc::clone(&l_rel);
                let c_ent = Arc::clone(&c_ent);
                let c_rel = Arc::clone(&c_rel);
                tokio::spawn(async move {
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
                    let req = String::from_utf8_lossy(&raw);
                    let first_line = req.lines().next().unwrap_or("");
                    let body = if first_line.starts_with("GET /vpn/v1/logicals") {
                        l_ent.notify_one();
                        l_rel.notified().await;
                        r#"{"Code":1000,"LogicalServers":[]}"#.to_owned()
                    } else if first_line.starts_with("GET /vpn/v1/certificate/key/EC") {
                        serde_json::json!({
                            "Code": 1000,
                            "PrivateKey": pem,
                            "PublicKey": "PUB-PEM"
                        })
                        .to_string()
                    } else if first_line.starts_with("POST /vpn/v1/certificate") {
                        c_ent.notify_one();
                        c_rel.notified().await;
                        r#"{"Code":1000,"ExpirationTime":2000000000}"#.to_owned()
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

        let base = format!("http://{addr}");
        let proton = Arc::new(ProtonClient::with_endpoints(
            guarded_store,
            base.clone(),
            vec![base.clone()],
            base,
        ));
        let cache_path = std::env::temp_dir().join(format!(
            "freeton_post_logout_scan_{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&cache_path);

        let mut deps_inner = make_test_deps(
            Arc::clone(&store) as Arc<dyn CredentialStore>,
            proton,
            Arc::new(MockPipeTransport::ok(ServiceResponse::Ok)),
        );
        deps_inner.cache_path = cache_path.clone();
        deps_inner.auth_generation = Arc::clone(&auth_gen);
        let deps = Arc::new(deps_inner);

        let (tx, mut rx) = mpsc::unbounded_channel();

        // 1. Start scan in-flight at auth_generation 1, then log out before HTTP responds.
        let deps_scan = Arc::clone(&deps);
        let tx_scan = tx.clone();
        let scan_task = tokio::spawn(async move {
            handle_ui_command(
                deps_scan,
                UiCommand::StartScan { auth_generation: 1 },
                &tx_scan,
                &|| {},
            )
            .await;
        });
        tokio::time::timeout(Duration::from_secs(3), logicals_entered.notified())
            .await
            .expect("scan worker should reach local HTTP endpoint");
        store.clear_all_sessions().expect("clear sessions");
        let _ = std::fs::remove_file(&cache_path);
        auth_gen.store(2, Ordering::Release);
        logicals_release.notify_one();
        scan_task.await.expect("scan task");

        assert!(
            !cache_path.exists(),
            "servers_cache.json must not be created after logout"
        );
        while let Ok(ev) = rx.try_recv() {
            assert!(
                !matches!(
                    ev,
                    WorkerEvent::ScanComplete { .. } | WorkerEvent::ScanError { .. }
                ),
                "stale scan event leaked after logout: {ev:?}"
            );
        }

        // 2. Re-login with session 2, start EnsureWgKey at auth_generation 2, then log out mid-flight.
        store
            .save_auth_session("user@proton.me", &session)
            .expect("re-seed auth session");
        let deps_key = Arc::clone(&deps);
        let tx_key = tx.clone();
        let key_task = tokio::spawn(async move {
            handle_ui_command(
                deps_key,
                UiCommand::EnsureWgKey {
                    auth_generation: 2,
                    force: true,
                },
                &tx_key,
                &|| {},
            )
            .await;
        });
        tokio::time::timeout(Duration::from_secs(3), cert_entered.notified())
            .await
            .expect("ensure_wg_key worker should reach local HTTP endpoint");
        store.clear_all_sessions().expect("clear sessions 2");
        auth_gen.store(3, Ordering::Release);
        cert_release.notify_one();
        key_task.await.expect("key task");

        let saved_cfg = store
            .get_password(KEYRING_SERVICE_WG, KEYRING_ACCOUNT_WG_CONFIG)
            .expect("read mock cred");
        assert!(
            saved_cfg.is_none(),
            "ClientConfig must not be persisted to CredentialStore after logout"
        );
        assert!(
            rx.try_recv().is_err(),
            "no WgKeyRefreshed event expected after logout"
        );
    }

    #[test]
    fn test_exit_ready_error_reveals_hidden_window() {
        let mut state = AppState::new(false, None, ClientConfig::default(), None, Vec::new());
        let _ = state.drain_commands();
        state.window_visible = false;
        state.closing = true;

        state.apply_event(WorkerEvent::ExitReady {
            error: Some("pipe teardown failed".to_owned()),
        });

        assert!(state.window_visible);
        assert!(!state.closing);
        assert_eq!(state.active_dialog, ActiveDialog::ErrorDetail);
        assert!(state.error_modal.is_some());
    }

    #[test]
    fn test_connect_succeeded_preserves_post_start_client_config_settings() {
        let srv = make_server("JP-FREE#1", "JP", "Tokyo", Some(25.0), Some(15.0));
        let initial_cfg = ClientConfig {
            private_key: "old-priv".to_owned(),
            public_key: "old-pub".to_owned(),
            expiration: 100,
            animations_enabled: true,
            auto_check_update: true,
            debug_mode: false,
            ..ClientConfig::default()
        };
        let mut state = AppState::new(
            true,
            Some("user@proton.me".to_owned()),
            initial_cfg,
            None,
            vec![srv.clone()],
        );
        let _ = state.drain_commands();

        state.connect_to_server(srv.clone());
        let gen = state.connection_generation;

        // Simulate user modifying preferences while WireGuard connection is being established.
        let mut updated_prefs = state.client_config.clone();
        updated_prefs.animations_enabled = false;
        updated_prefs.auto_check_update = false;
        updated_prefs.debug_mode = true;
        updated_prefs.dns = "1.1.1.1".to_owned();
        state.save_client_config(updated_prefs);

        state.apply_event(WorkerEvent::ConnectSucceeded {
            generation: gen,
            payload: Box::new(ConnectSuccessPayload {
                server: srv,
                info: ActiveTunnelInfo {
                    server_name: "JP-FREE#1".to_owned(),
                    country: "JP".to_owned(),
                    entry_ip: "198.51.100.10".to_owned(),
                    x25519_pubkey: "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=".to_owned(),
                    address: DEFAULT_WG_ADDRESS.to_owned(),
                    dns: DEFAULT_WG_DNS.to_owned(),
                    port: 51820,
                    connected_at_unix: 1_700_000_500,
                },
                wg_key: Some(WgKeySnapshot {
                    private_key: "new-priv".to_owned(),
                    public_key: "new-pub".to_owned(),
                    expiration: 1_900_000_000,
                }),
            }),
        });

        assert_eq!(state.client_config.private_key, "new-priv");
        assert_eq!(state.client_config.public_key, "new-pub");
        assert_eq!(state.client_config.expiration, 1_900_000_000);
        assert!(!state.client_config.animations_enabled);
        assert!(!state.client_config.auto_check_update);
        assert!(state.client_config.debug_mode);
        assert_eq!(state.client_config.dns, "1.1.1.1");
    }

    #[tokio::test]
    async fn test_windows_pipe_transport_reuses_frame_ipc_exchange_bounds_and_maps_pipe_busy() {
        use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};

        let pid = std::process::id();

        // 1. Successful roundtrip over a real Windows named pipe via CreateFileW + frame_ipc_exchange.
        let ok_pipe = format!(r"\\.\pipe\freeton_app_ok_{pid}");
        let mut ok_server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&ok_pipe)
            .expect("create ok server");
        let ok_task = tokio::spawn(async move {
            ok_server.connect().await.expect("accept ok");
            let mut raw = Vec::new();
            let mut buf = [0u8; 256];
            loop {
                let n = ok_server.read(&mut buf).await.expect("read ok");
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&buf[..n]);
                if raw.contains(&b'\n') {
                    break;
                }
            }
            let resp = ServiceResponse::Status(TunnelHealthState::Disconnected);
            let mut line = serde_json::to_string(&resp).expect("ser");
            line.push('\n');
            ok_server
                .write_all(line.as_bytes())
                .await
                .expect("write ok");
            ok_server.flush().await.expect("flush ok");
        });
        let transport_ok = WindowsPipeTransport::new(&ok_pipe);
        let res = transport_ok
            .send_request(&ServiceRequest::Status, Duration::from_secs(2))
            .await
            .expect("pipe roundtrip succeeds");
        assert_eq!(
            res,
            ServiceResponse::Status(TunnelHealthState::Disconnected)
        );
        ok_task.await.expect("ok server task");

        // 2. Oversized response (> MAX_IPC_RESPONSE_BYTES) fails with Protocol bound error.
        let big_pipe = format!(r"\\.\pipe\freeton_app_big_{pid}");
        let mut big_server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&big_pipe)
            .expect("create big server");
        let big_task = tokio::spawn(async move {
            big_server.connect().await.expect("accept big");
            let mut buf = [0u8; 256];
            let _ = big_server.read(&mut buf).await;
            let oversized = vec![b'x'; MAX_IPC_RESPONSE_BYTES + 128];
            let _ = big_server.write_all(&oversized).await;
            let _ = big_server.write_all(b"\n").await;
        });
        let transport_big = WindowsPipeTransport::new(&big_pipe);
        let err_big = transport_big
            .send_request(&ServiceRequest::Status, Duration::from_secs(2))
            .await
            .expect_err("oversized response must be rejected");
        assert!(matches!(err_big, PipeClientError::Protocol(_)));
        let _ = big_task.await;

        // 3. Persistent ERROR_PIPE_BUSY past deadline maps to PipeClientError::Unavailable.
        let busy_pipe = format!(r"\\.\pipe\freeton_app_busy_{pid}");
        let _busy_server = ServerOptions::new()
            .first_pipe_instance(true)
            .max_instances(1)
            .create(&busy_pipe)
            .expect("create busy server");
        let _held_client = ClientOptions::new()
            .open(&busy_pipe)
            .expect("occupy single pipe instance");
        let transport_busy = WindowsPipeTransport::new(&busy_pipe);
        let err_busy = transport_busy
            .send_request(&ServiceRequest::Status, Duration::from_millis(120))
            .await
            .expect_err("persistent busy must error");
        assert!(
            matches!(err_busy, PipeClientError::Unavailable(_)),
            "expected Unavailable for persistent ERROR_PIPE_BUSY, got {err_busy:?}"
        );

        // 4. Stalled server response cancels cleanly under async tokio::time::timeout.
        let stall_pipe = format!(r"\\.\pipe\freeton_app_stall_{pid}");
        let stall_server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&stall_pipe)
            .expect("create stall server");
        let _stall_task = tokio::spawn(async move {
            if stall_server.connect().await.is_ok() {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
        let transport_stall = WindowsPipeTransport::new(&stall_pipe);
        let err_stall = transport_stall
            .send_request(&ServiceRequest::Status, Duration::from_millis(120))
            .await
            .expect_err("stalled pipe must timeout cleanly");
        assert!(matches!(err_stall, PipeClientError::Io(_)));
    }

    #[tokio::test]
    async fn test_worker_update_verified_launches_runas_and_missing_sha_opens_browser() {
        let payload = b"FAKE-INSTALLER-PAYLOAD-FOR-TASK9";
        let temp_dir =
            std::env::temp_dir().join(format!("freeton_task9_upd_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).expect("create temp dir");
        let seed_file = temp_dir.join("seed.bin");
        std::fs::write(&seed_file, payload).expect("write seed");
        let expected_sha =
            freeton_core::updater::compute_file_sha256(&seed_file).expect("compute sha256");
        let _ = std::fs::remove_file(&seed_file);

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = socket.read(&mut buf).await;
                    let hdr = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        payload.len()
                    );
                    let _ = socket.write_all(hdr.as_bytes()).await;
                    let _ = socket.write_all(payload).await;
                });
            }
        });

        let shell = Arc::new(MockShellLauncher::ok());
        let store = Arc::new(MockCredentialStore::default());
        let mut deps = make_test_deps(
            Arc::clone(&store) as Arc<dyn CredentialStore>,
            Arc::new(ProtonClient::new(store)),
            Arc::new(MockPipeTransport::ok(ServiceResponse::Ok)),
        );
        deps.shell = Arc::clone(&shell) as Arc<dyn ShellLauncher>;
        deps.update_download_dir = Some(temp_dir.clone());
        let deps = Arc::new(deps);

        let info_verified = UpdateInfo {
            version: "3.1.0".to_owned(),
            release_date: "2026-12-01".to_owned(),
            title: "v3.1.0".to_owned(),
            changelog: vec!["Fix".to_owned()],
            download_url: format!("http://{addr}/FreetonVPN-Setup-x64.exe"),
            file_size_bytes: payload.len() as u64,
            sha256: expected_sha,
            mandatory: false,
            min_supported_version: "3.0.0".to_owned(),
        };

        let (tx, mut rx) = mpsc::unbounded_channel();
        handle_ui_command(
            Arc::clone(&deps),
            UiCommand::StartUpdateDownload {
                generation: 1,
                info: info_verified,
            },
            &tx,
            &|| {},
        )
        .await;

        let mut finished_path = None;
        while let Ok(ev) = rx.try_recv() {
            if let WorkerEvent::UpdateDownloadFinished {
                generation: 1,
                action: Ok(UpdateAction::LaunchVerifiedInstaller(path)),
            } = ev
            {
                finished_path = Some(path);
            }
        }
        let installer_path = finished_path.expect("verified installer path");
        assert!(installer_path.exists());

        handle_ui_command(
            Arc::clone(&deps),
            UiCommand::LaunchUpdateInstaller {
                path: installer_path.clone(),
            },
            &tx,
            &|| {},
        )
        .await;
        let launched_ev = rx.try_recv().expect("launch event");
        assert!(matches!(
            launched_ev,
            WorkerEvent::UpdateInstallerLaunched { result: Ok(()) }
        ));
        assert_eq!(
            *shell.elevated_calls.lock().expect("elevated lock"),
            vec![(installer_path, "/S".to_owned())]
        );

        // Missing SHA-256 -> browser fallback without touching runas.
        let info_no_sha = UpdateInfo {
            version: "3.1.0".to_owned(),
            release_date: "2026-12-01".to_owned(),
            title: "v3.1.0".to_owned(),
            changelog: vec![],
            download_url: "https://github.com/datpusheen/FreetonVPN/releases/download/v3.1.0/FreetonVPN-Setup-x64.exe".to_owned(),
            file_size_bytes: 0,
            sha256: String::new(),
            mandatory: false,
            min_supported_version: "3.0.0".to_owned(),
        };
        handle_ui_command(
            Arc::clone(&deps),
            UiCommand::StartUpdateDownload {
                generation: 2,
                info: info_no_sha,
            },
            &tx,
            &|| {},
        )
        .await;
        let fallback_ev = rx.try_recv().expect("fallback event");
        match fallback_ev {
            WorkerEvent::UpdateDownloadFinished {
                generation: 2,
                action: Ok(UpdateAction::OpenReleasePageInBrowser(url)),
            } => {
                handle_ui_command(
                    Arc::clone(&deps),
                    UiCommand::OpenExternalUrl { url: url.clone() },
                    &tx,
                    &|| {},
                )
                .await;
                assert_eq!(*shell.opened_urls.lock().expect("url lock"), vec![url]);
            }
            other => panic!("expected OpenReleasePageInBrowser, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_worker_service_repair_runs_install_elevated_and_rechecks_status() {
        let temp_dir =
            std::env::temp_dir().join(format!("freeton_task9_svc_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let dummy_svc = temp_dir.join("FreetonVPNService.exe");
        std::fs::write(&dummy_svc, b"stub").expect("write dummy service exe");

        // 1. Success path: launches elevated `--install` and sees pipe Status -> ServiceRepairSucceeded.
        let shell_ok = Arc::new(MockShellLauncher::ok());
        let pipe_ok = Arc::new(MockPipeTransport::ok(ServiceResponse::Status(
            TunnelHealthState::Disconnected,
        )));
        let store = Arc::new(MockCredentialStore::default());
        let mut deps = make_test_deps(
            Arc::clone(&store) as Arc<dyn CredentialStore>,
            Arc::new(ProtonClient::new(store)),
            Arc::clone(&pipe_ok) as Arc<dyn PipeTransport>,
        );
        deps.shell = Arc::clone(&shell_ok) as Arc<dyn ShellLauncher>;
        deps.service_exe_path = Some(dummy_svc.clone());
        let deps = Arc::new(deps);

        let (tx, mut rx) = mpsc::unbounded_channel();
        handle_ui_command(deps, UiCommand::RepairService, &tx, &|| {}).await;
        assert!(matches!(
            rx.try_recv().expect("repair ok event"),
            WorkerEvent::ServiceRepairSucceeded
        ));
        assert_eq!(
            *shell_ok.elevated_calls.lock().expect("elevated lock"),
            vec![(dummy_svc.clone(), "--install".to_owned())]
        );
        assert!(pipe_ok
            .sent
            .lock()
            .expect("pipe sent")
            .contains(&ServiceRequest::Status));

        // 2. UAC declined -> ServiceRepairFailed without polling pipe.
        let shell_deny = Arc::new(MockShellLauncher::elevated_err("UAC declined"));
        let pipe_unused = Arc::new(MockPipeTransport::err(PipeClientError::Unavailable(
            "down".to_owned(),
        )));
        let store2 = Arc::new(MockCredentialStore::default());
        let mut deps_deny = make_test_deps(
            Arc::clone(&store2) as Arc<dyn CredentialStore>,
            Arc::new(ProtonClient::new(store2)),
            Arc::clone(&pipe_unused) as Arc<dyn PipeTransport>,
        );
        deps_deny.shell = Arc::clone(&shell_deny) as Arc<dyn ShellLauncher>;
        deps_deny.service_exe_path = Some(dummy_svc);
        handle_ui_command(Arc::new(deps_deny), UiCommand::RepairService, &tx, &|| {}).await;
        assert!(matches!(
            rx.try_recv().expect("repair fail event"),
            WorkerEvent::ServiceRepairFailed { .. }
        ));
        assert!(pipe_unused.sent.lock().expect("pipe sent").is_empty());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_worker_update_download_cancel_cleans_partial_file() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let entered = Arc::new(tokio::sync::Notify::new());
        let entered_srv = Arc::clone(&entered);

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let hdr = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 1000000\r\nConnection: close\r\n\r\n";
                let _ = socket.write_all(hdr.as_bytes()).await;
                let _ = socket.write_all(b"PARTIAL-DATA-").await;
                let _ = socket.flush().await;
                entered_srv.notify_one();
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });

        let temp_dir =
            std::env::temp_dir().join(format!("freeton_task9_cancel_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);

        let store = Arc::new(MockCredentialStore::default());
        let mut deps = make_test_deps(
            Arc::clone(&store) as Arc<dyn CredentialStore>,
            Arc::new(ProtonClient::new(store)),
            Arc::new(MockPipeTransport::ok(ServiceResponse::Ok)),
        );
        deps.update_download_dir = Some(temp_dir.clone());
        let deps = Arc::new(deps);

        let info = UpdateInfo {
            version: "3.1.0".to_owned(),
            release_date: "2026-12-01".to_owned(),
            title: "v3.1.0".to_owned(),
            changelog: vec![],
            download_url: format!("http://{addr}/FreetonVPN-Setup-x64.exe"),
            file_size_bytes: 1_000_000,
            sha256: "a".repeat(64),
            mandatory: false,
            min_supported_version: "3.0.0".to_owned(),
        };

        let (tx, mut rx) = mpsc::unbounded_channel();
        let deps_dl = Arc::clone(&deps);
        let tx_dl = tx.clone();
        let dl_task = tokio::spawn(async move {
            handle_ui_command(
                deps_dl,
                UiCommand::StartUpdateDownload {
                    generation: 9,
                    info,
                },
                &tx_dl,
                &|| {},
            )
            .await;
        });

        tokio::time::timeout(Duration::from_secs(3), entered.notified())
            .await
            .expect("download should reach server");
        tokio::time::sleep(Duration::from_millis(40)).await;

        handle_ui_command(
            Arc::clone(&deps),
            UiCommand::CancelUpdateDownload { generation: 9 },
            &tx,
            &|| {},
        )
        .await;
        dl_task.await.expect("download task finishes cleanly");

        let mut saw_cancel = false;
        while let Ok(ev) = rx.try_recv() {
            if matches!(ev, WorkerEvent::UpdateDownloadCancelled { generation: 9 }) {
                saw_cancel = true;
            }
            assert!(
                !matches!(ev, WorkerEvent::UpdateDownloadFinished { .. }),
                "cancelled download must not emit UpdateDownloadFinished"
            );
        }
        assert!(saw_cancel);
        assert!(
            !temp_dir
                .join("gen-9")
                .join("FreetonVPN-Setup-x64.exe.part")
                .exists(),
            "targeted .part file must be removed cleanly after download_fut drops"
        );

        // Immediate retry (gen-10) uses isolated generation dir and is untouched by gen-9 cancel.
        let retry_dir = temp_dir.join("gen-10");
        std::fs::create_dir_all(&retry_dir).expect("create retry dir");
        let retry_part = retry_dir.join("FreetonVPN-Setup-x64.exe.part");
        std::fs::write(&retry_part, b"IN-PROGRESS-RETRY").expect("write retry part");
        cleanup_targeted_partial_file(
            &temp_dir.join("gen-9"),
            "https://example.com/FreetonVPN-Setup-x64.exe",
        );
        assert!(
            retry_part.exists(),
            "cancelling gen-9 must never delete retry gen-10 .part file"
        );
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_startup_save_failure_reverts_startup_enabled_and_re_queries() {
        struct FailingStartupController {
            actual_enabled: bool,
        }
        impl StartupController for FailingStartupController {
            fn is_enabled(&self) -> bool {
                self.actual_enabled
            }
            fn set_enabled(&self, _enable: bool) -> Result<(), StorageError> {
                Err(StorageError::Registry("HKCU write denied".to_owned()))
            }
        }

        let mut state = AppState::new(
            true,
            Some("user@proton.me".to_owned()),
            ClientConfig::default(),
            None,
            Vec::new(),
        );
        assert!(!state.startup_enabled);
        let _ = state.drain_commands();

        state.open_settings_dialog();
        let _ = state.drain_commands();
        state.settings_draft.startup_enabled = true;
        state.settings_draft.startup_dirty = true;
        state.save_settings_dialog();
        let cmds = state.drain_commands();
        assert!(cmds
            .iter()
            .any(|c| matches!(c, UiCommand::SetStartupEnabled { enabled: true })));

        let store = Arc::new(MockCredentialStore::default());
        let mut deps = make_test_deps(
            Arc::clone(&store) as Arc<dyn CredentialStore>,
            Arc::new(ProtonClient::new(store)),
            Arc::new(MockPipeTransport::ok(ServiceResponse::Ok)),
        );
        deps.startup = Arc::new(FailingStartupController {
            actual_enabled: false,
        });
        let deps = Arc::new(deps);

        let (tx, mut rx) = mpsc::unbounded_channel();
        handle_ui_command(
            Arc::clone(&deps),
            UiCommand::SetStartupEnabled { enabled: true },
            &tx,
            &|| {},
        )
        .await;
        let save_ev = rx.recv().await.expect("StartupSaveResult");
        state.apply_event(save_ev);

        assert!(
            !state.startup_enabled,
            "state.startup_enabled must revert to pre-save value on registry error"
        );
        assert!(
            !state.settings_draft.startup_enabled,
            "settings_draft.startup_enabled must revert on registry error"
        );
        assert!(state.info_toast.is_some());
        let follow_up_cmds = state.drain_commands();
        assert!(follow_up_cmds
            .iter()
            .any(|c| matches!(c, UiCommand::RefreshStartupStatus)));
    }

    #[test]
    fn test_custom_update_url_validation_persistence_and_check_dispatch() {
        let mut state = AppState::new(
            true,
            Some("user@proton.me".to_owned()),
            ClientConfig::default(),
            None,
            Vec::new(),
        );
        let _ = state.drain_commands();

        state.open_settings_dialog();
        state.settings_draft.custom_update_url = "http://insecure.example.com/v.json".to_owned();
        state.save_settings_dialog();
        assert_eq!(
            state.active_dialog,
            ActiveDialog::Settings,
            "invalid non-loopback http custom_update_url must keep Settings open with error"
        );
        assert!(state.client_config.custom_update_url.is_empty());

        state.settings_draft.custom_update_url = "  http://127.0.0.1:8080/version-rust.json  ".to_owned();
        state.save_settings_dialog();
        assert_eq!(state.active_dialog, ActiveDialog::None);
        assert_eq!(
            state.client_config.custom_update_url,
            "http://127.0.0.1:8080/version-rust.json"
        );

        let _ = state.drain_commands();
        state.check_for_updates(true);
        let cmds = state.drain_commands();
        assert!(cmds.iter().any(|c| matches!(
            c,
            UiCommand::CheckForUpdates {
                manual: true,
                manifest_url_override: Some(url),
            } if url == "http://127.0.0.1:8080/version-rust.json"
        )));
    }

    #[test]
    fn test_worker_runtime_supports_full_ping_blocking_concurrency() {
        let (runtime, _cmd_tx, _evt_rx) = spawn_worker_runtime(
            WorkerDeps::production_with_auth(Arc::new(AtomicU64::new(0))),
            Arc::new(|| {}),
        );

        let started = Instant::now();
        runtime.block_on(async {
            let mut join_set = tokio::task::JoinSet::new();
            for _ in 0..DEFAULT_PING_WORKERS {
                join_set.spawn_blocking(|| {
                    std::thread::sleep(Duration::from_millis(120));
                });
            }
            while join_set.join_next().await.is_some() {}
        });
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_millis(350),
            "ping runtime blocking pool serialized DEFAULT_PING_WORKERS ({DEFAULT_PING_WORKERS}) probes: elapsed {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn test_invalid_refresh_token_during_scan_auto_logs_out_and_clears_session() {
        let store = Arc::new(MockCredentialStore::default());
        let session = StoredAuthSession {
            uid: "uid-expired".to_owned(),
            access_token: "acc-expired".to_owned(),
            refresh_token: "revoked-ref".to_owned(),
            scopes: vec!["full".to_owned()],
        };
        store
            .save_auth_session("user@proton.me", &session)
            .expect("seed auth session");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server_task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
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
                    let req = String::from_utf8_lossy(&raw);
                    let first_line = req.lines().next().unwrap_or("");
                    let (status, body) = if first_line.starts_with("POST /auth/v4/refresh") {
                        (
                            "400 Bad Request",
                            r#"{"Code":10013,"Error":"Invalid refresh token"}"#,
                        )
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

        let base = format!("http://{addr}");
        let proton = Arc::new(ProtonClient::with_endpoints(
            Arc::clone(&store) as Arc<dyn CredentialStore>,
            base.clone(),
            vec![base.clone()],
            base,
        ));
        let deps = Arc::new(make_test_deps(
            Arc::clone(&store) as Arc<dyn CredentialStore>,
            proton,
            Arc::new(MockPipeTransport::ok(ServiceResponse::Ok)),
        ));
        let auth_gen = deps.auth_generation.load(Ordering::Acquire);
        let (tx, mut rx) = mpsc::unbounded_channel();

        handle_scan(&deps, auth_gen, &tx, &|| {}).await;
        server_task.abort();

        let mut events = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            events.push(ev);
        }

        let mut app = AppState::new(
            true,
            Some("user@proton.me".to_owned()),
            ClientConfig::default(),
            None,
            Vec::new(),
        );
        app.auth_generation = auth_gen;

        for ev in events {
            assert!(
                !matches!(ev, WorkerEvent::ScanError { .. }),
                "invalid refresh token must auto-logout instead of showing generic ScanError: {ev:?}"
            );
            app.apply_event(ev);
        }

        assert!(
            store.load_auth_session().expect("load").is_none(),
            "revoked refresh token must clear stored session from keyring"
        );
        assert!(
            !app.is_logged_in,
            "app must auto-logout to Login screen after invalid refresh token"
        );
        assert_eq!(app.current_view, AppView::Login);
        assert!(app.srp_status.is_some());
    }

    #[tokio::test]
    async fn test_dev_mode_realtime_log_cli_and_folder_commands() {
        let store = Arc::new(MockCredentialStore::default());
        let shell = Arc::new(MockShellLauncher::ok());
        let mut state = AppState::new(false, None, ClientConfig::default(), None, Vec::new());
        let _ = state.drain_commands();

        state.open_realtime_log_cli();
        state.open_log_folder();
        let cmds = state.drain_commands();
        assert_eq!(cmds.len(), 2);
        assert!(matches!(cmds[0], UiCommand::OpenRealtimeLogCli));
        assert!(matches!(cmds[1], UiCommand::OpenLogFolder));

        let dead_base = "http://127.0.0.1:1".to_owned();
        let proton = Arc::new(ProtonClient::with_endpoints(
            Arc::clone(&store) as Arc<dyn CredentialStore>,
            dead_base.clone(),
            vec![dead_base.clone()],
            dead_base,
        ));
        let mut deps = make_test_deps(
            store,
            proton,
            Arc::new(MockPipeTransport::ok(ServiceResponse::Ok)),
        );
        deps.shell = Arc::clone(&shell) as Arc<dyn ShellLauncher>;
        let deps = Arc::new(deps);
        let (tx, _rx) = mpsc::unbounded_channel();

        for cmd in cmds {
            handle_ui_command(deps.clone(), cmd, &tx, &|| {}).await;
        }

        let cli_calls = shell.realtime_log_calls.lock().expect("cli calls");
        assert_eq!(cli_calls.len(), 1);
        assert!(cli_calls[0].0.ends_with(APP_LOG_FILE_NAME));
        assert!(cli_calls[0].1.ends_with(SERVICE_LOG_FILE_NAME));
        assert!(cli_calls[0].2.ends_with(TUNNEL_LOG_FILE_NAME));

        let dir_calls = shell.opened_dirs.lock().expect("dir calls");
        assert_eq!(dir_calls.len(), 1);
        assert_eq!(dir_calls[0], app_log_dir());
    }
}
