use std::ffi::OsString;
use std::future::Future;
use std::io;
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use freeton_core::wg::{
    dns_responds_through_tunnel, parse_uapi_latest_handshake, validate_tunnel_spec,
    ActiveTunnelInfo, ServiceRequest, ServiceResponse, TunnelHealthState, ValidatedTunnelSpec,
    DEFAULT_TUNNEL_NAME, SERVICE_PIPE_NAME,
};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use tokio::sync::{watch, Mutex as AsyncMutex};
use tracing::{error, info, warn};
use windows::core::PCWSTR;
use windows::Win32::Foundation::FALSE;
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
    ServiceType, SessionChangeReason,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use crate::tunnel_runner::{
    default_tunnels_dir, install_and_start_tunnel_service, query_service_state, query_uapi_state,
    remove_tunnel_conf, stop_and_delete_service, to_wide_null, tunnel_service_name,
    write_restricted_tunnel_conf, LocalFreeGuard,
};

pub const BROKER_SERVICE_NAME: &str = "FreetonVPNService";
pub const BROKER_SERVICE_DISPLAY_NAME: &str = "Freeton VPN Service";
pub const BROKER_SERVICE_DESCRIPTION: &str = "Privileged WireGuard tunnel broker for Freeton VPN";
/// SDDL DACL for `\\.\pipe\FreetonVPNService`:
/// - `SY` (LocalSystem) & `BA` (Administrators): `GA` (Generic All)
/// - `IU` (Interactive Users): `0x0012019b` (`FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES`,
///   deliberately omitting `FILE_CREATE_PIPE_INSTANCE` (`0x0004`) to prevent unprivileged pipe-squatting).
///
/// Interactive User clients open the pipe using `FILE_READ_DATA | FILE_WRITE_DATA` (or
/// `tokio::net::windows::named_pipe::ClientOptions::new().read(true).write(true)`).
pub const PIPE_SDDL_DACL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x0012019b;;;IU)";
pub const HANDSHAKE_MAX_AGE_SECS: i64 = 180;
pub const MAX_IPC_LINE_BYTES: usize = 64 * 1024;
pub const MAX_CONSECUTIVE_PIPE_FAILURES: u32 = 8;

const SERVICE_RUNNING_STATE: u32 = 4;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone)]
pub struct BrokerConfig {
    pub tunnel_name: String,
    pub service_wait_timeout: Duration,
    pub service_poll_interval: Duration,
    pub connect_timeout: Duration,
    pub handshake_poll_interval: Duration,
    pub dns_probe_timeout: Duration,
    pub dns_recheck_interval: Duration,
}

impl Default for BrokerConfig {
    fn default() -> Self {
        Self {
            tunnel_name: DEFAULT_TUNNEL_NAME.to_owned(),
            service_wait_timeout: Duration::from_secs(10),
            service_poll_interval: Duration::from_millis(100),
            connect_timeout: Duration::from_secs(20),
            handshake_poll_interval: Duration::from_millis(250),
            dns_probe_timeout: Duration::from_secs(2),
            dns_recheck_interval: Duration::from_secs(30),
        }
    }
}

pub trait TunnelRuntime: Send + Sync + 'static {
    fn now_unix(&self) -> i64;
    fn service_state<'a>(&'a self, tunnel_name: &'a str) -> BoxFuture<'a, Result<u32, String>>;
    fn write_conf<'a>(
        &'a self,
        tunnel_name: &'a str,
        conf_content: &'a str,
    ) -> BoxFuture<'a, Result<PathBuf, String>>;
    fn remove_conf<'a>(&'a self, tunnel_name: &'a str) -> BoxFuture<'a, Result<(), String>>;
    fn install_and_start_tunnel<'a>(
        &'a self,
        tunnel_name: &'a str,
        conf_path: &'a Path,
    ) -> BoxFuture<'a, Result<(), String>>;
    fn uninstall_tunnel<'a>(&'a self, tunnel_name: &'a str) -> BoxFuture<'a, Result<(), String>>;
    fn read_uapi_state<'a>(&'a self, tunnel_name: &'a str)
        -> BoxFuture<'a, Result<String, String>>;
    fn check_dns_through_tunnel<'a>(
        &'a self,
        address: &'a str,
        dns: &'a str,
        timeout: Duration,
    ) -> BoxFuture<'a, bool>;
}

pub struct WindowsTunnelRuntime {
    tunnels_dir: PathBuf,
    service_exe: PathBuf,
}

impl WindowsTunnelRuntime {
    pub fn new(tunnels_dir: PathBuf, service_exe: PathBuf) -> Self {
        Self {
            tunnels_dir,
            service_exe,
        }
    }
}

impl TunnelRuntime for WindowsTunnelRuntime {
    fn now_unix(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
            .unwrap_or(0)
    }

    fn service_state<'a>(&'a self, tunnel_name: &'a str) -> BoxFuture<'a, Result<u32, String>> {
        let svc_name = tunnel_service_name(tunnel_name);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || query_service_state(&svc_name))
                .await
                .map_err(|e| format!("service_state task panicked: {e}"))?
                .map_err(|e| e.to_string())
        })
    }

    fn write_conf<'a>(
        &'a self,
        tunnel_name: &'a str,
        conf_content: &'a str,
    ) -> BoxFuture<'a, Result<PathBuf, String>> {
        let dir = self.tunnels_dir.clone();
        let name = tunnel_name.to_owned();
        let content = conf_content.to_owned();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                write_restricted_tunnel_conf(&dir, &name, &content, true)
            })
            .await
            .map_err(|e| format!("write_conf task panicked: {e}"))?
            .map_err(|e| e.to_string())
        })
    }

    fn remove_conf<'a>(&'a self, tunnel_name: &'a str) -> BoxFuture<'a, Result<(), String>> {
        let dir = self.tunnels_dir.clone();
        let name = tunnel_name.to_owned();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || remove_tunnel_conf(&dir, &name))
                .await
                .map_err(|e| format!("remove_conf task panicked: {e}"))?
                .map_err(|e| e.to_string())
        })
    }

    fn install_and_start_tunnel<'a>(
        &'a self,
        tunnel_name: &'a str,
        conf_path: &'a Path,
    ) -> BoxFuture<'a, Result<(), String>> {
        let name = tunnel_name.to_owned();
        let conf = conf_path.to_path_buf();
        let exe = self.service_exe.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                install_and_start_tunnel_service(&name, &conf, &exe)
            })
            .await
            .map_err(|e| format!("install_and_start_tunnel task panicked: {e}"))?
            .map_err(|e| e.to_string())
        })
    }

    fn uninstall_tunnel<'a>(&'a self, tunnel_name: &'a str) -> BoxFuture<'a, Result<(), String>> {
        let svc_name = tunnel_service_name(tunnel_name);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || stop_and_delete_service(&svc_name))
                .await
                .map_err(|e| format!("uninstall_tunnel task panicked: {e}"))?
                .map_err(|e| e.to_string())
        })
    }

    fn read_uapi_state<'a>(
        &'a self,
        tunnel_name: &'a str,
    ) -> BoxFuture<'a, Result<String, String>> {
        Box::pin(async move {
            query_uapi_state(tunnel_name)
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn check_dns_through_tunnel<'a>(
        &'a self,
        address: &'a str,
        dns: &'a str,
        timeout: Duration,
    ) -> BoxFuture<'a, bool> {
        let address = address.to_owned();
        let dns = dns.to_owned();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                dns_responds_through_tunnel(&address, &dns, timeout)
            })
            .await
            .unwrap_or(false)
        })
    }
}

#[derive(Debug, Clone)]
enum BrokerPhase {
    Idle,
    Connecting,
    Verifying(ActiveTunnelInfo),
    Active(ActiveTunnelInfo),
}

#[derive(Debug, Clone)]
struct BrokerState {
    phase: BrokerPhase,
    last_dns_verified_unix: Option<i64>,
    generation: u64,
}

impl Default for BrokerState {
    fn default() -> Self {
        Self {
            phase: BrokerPhase::Idle,
            last_dns_verified_unix: None,
            generation: 0,
        }
    }
}

impl BrokerState {
    fn set_phase(&mut self, phase: BrokerPhase, last_dns_verified_unix: Option<i64>) {
        self.phase = phase;
        self.last_dns_verified_unix = last_dns_verified_unix;
        self.generation = self.generation.wrapping_add(1);
    }
}

enum ServiceWaitError {
    Cancelled,
    Other(String),
}

struct ConnectCancelToken {
    cancel_rx: watch::Receiver<bool>,
    shutdown_rx: watch::Receiver<bool>,
    external_shutdown_rx: Option<watch::Receiver<bool>>,
}

impl ConnectCancelToken {
    fn is_cancelled(&self) -> bool {
        *self.cancel_rx.borrow()
            || *self.shutdown_rx.borrow()
            || self
                .external_shutdown_rx
                .as_ref()
                .is_some_and(|rx| *rx.borrow())
    }

    async fn cancelled(&mut self) {
        if self.is_cancelled() {
            return;
        }
        let cancel_rx = &mut self.cancel_rx;
        let shutdown_rx = &mut self.shutdown_rx;
        let external_rx = &mut self.external_shutdown_rx;

        tokio::select! {
            biased;
            _ = wait_for_shutdown(cancel_rx) => {}
            _ = wait_for_shutdown(shutdown_rx) => {}
            _ = async {
                if let Some(rx) = external_rx.as_mut() {
                    wait_for_shutdown(rx).await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {}
        }
    }
}

struct ActiveConnectGuard<'a> {
    slot: &'a Mutex<Option<watch::Sender<bool>>>,
}

impl Drop for ActiveConnectGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.slot.lock() {
            *guard = None;
        }
    }
}

pub struct TunnelBroker<R: TunnelRuntime> {
    runtime: Arc<R>,
    config: BrokerConfig,
    mutation_lock: AsyncMutex<()>,
    state: Mutex<BrokerState>,
    active_connect_cancel: Mutex<Option<watch::Sender<bool>>>,
    shutdown_tx: watch::Sender<bool>,
    external_shutdown: Option<watch::Receiver<bool>>,
}

fn is_fresh_handshake(stamp: i64, now_unix: i64) -> bool {
    stamp > 0 && (0..=HANDSHAKE_MAX_AGE_SECS).contains(&(now_unix - stamp))
}

fn normalize_entry_ip(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        let inner = &trimmed[1..trimmed.len() - 1];
        if inner.parse::<Ipv6Addr>().is_ok() {
            return inner.to_owned();
        }
    }
    trimmed.to_owned()
}

fn build_active_info(spec: &ValidatedTunnelSpec, connected_at_unix: i64) -> ActiveTunnelInfo {
    let server_name = spec.server_name.trim();
    ActiveTunnelInfo {
        server_name: if server_name.is_empty() {
            "Proton Server".to_owned()
        } else {
            server_name.to_owned()
        },
        country: spec.country.trim().to_owned(),
        entry_ip: normalize_entry_ip(&spec.entry_ip),
        x25519_pubkey: spec.server_pubkey.trim().to_owned(),
        address: spec.address.trim().to_owned(),
        dns: spec.dns.trim().to_owned(),
        port: spec.port,
        connected_at_unix,
    }
}

impl<R: TunnelRuntime> TunnelBroker<R> {
    pub fn new(runtime: Arc<R>, config: BrokerConfig) -> Self {
        let (shutdown_tx, _) = watch::channel(false);
        Self {
            runtime,
            config,
            mutation_lock: AsyncMutex::new(()),
            state: Mutex::new(BrokerState::default()),
            active_connect_cancel: Mutex::new(None),
            shutdown_tx,
            external_shutdown: None,
        }
    }

    pub fn with_shutdown(mut self, external_shutdown: watch::Receiver<bool>) -> Self {
        self.external_shutdown = Some(external_shutdown);
        self
    }

    fn cancel_in_flight_connect(&self) {
        if let Ok(guard) = self.active_connect_cancel.lock() {
            if let Some(tx) = guard.as_ref() {
                let _ = tx.send(true);
            }
        }
    }

    pub fn cancel_for_service_stop(&self) {
        let _ = self.shutdown_tx.send(true);
        self.cancel_in_flight_connect();
    }

    fn is_stopping(&self) -> bool {
        *self.shutdown_tx.borrow()
            || self
                .external_shutdown
                .as_ref()
                .is_some_and(|rx| *rx.borrow())
    }

    fn register_connect_cancel(&self) -> (ConnectCancelToken, ActiveConnectGuard<'_>) {
        let (tx, rx) = watch::channel(false);
        {
            let mut slot = self
                .active_connect_cancel
                .lock()
                .expect("active connect cancel lock poisoned");
            *slot = Some(tx);
        }
        let token = ConnectCancelToken {
            cancel_rx: rx,
            shutdown_rx: self.shutdown_tx.subscribe(),
            external_shutdown_rx: self.external_shutdown.clone(),
        };
        (
            token,
            ActiveConnectGuard {
                slot: &self.active_connect_cancel,
            },
        )
    }

    pub async fn handle_request(&self, req: ServiceRequest) -> ServiceResponse {
        match req {
            ServiceRequest::Connect(spec) => self.handle_connect(spec).await,
            ServiceRequest::Disconnect | ServiceRequest::ShutdownTunnelOnExit => {
                self.cancel_in_flight_connect();
                match self.teardown_locked().await {
                    Ok(()) => ServiceResponse::Ok,
                    Err(message) => ServiceResponse::Error {
                        code: "DISCONNECT_FAILED".to_owned(),
                        message,
                    },
                }
            }
            ServiceRequest::Status => ServiceResponse::Status(self.handle_status().await),
        }
    }

    pub async fn handle_session_change(&self, reason: SessionChangeReason) -> Result<(), String> {
        if should_teardown_on_session_change(reason) {
            info!("Windows session change ({reason:?}) detected; tearing down active tunnel");
            self.cancel_in_flight_connect();
            self.teardown_locked().await?;
        }
        Ok(())
    }

    pub async fn shutdown_for_service_stop(&self) {
        self.cancel_for_service_stop();
        if let Err(err) = self.teardown_locked().await {
            warn!("failed tearing down tunnel during service stop: {err}");
        }
    }

    async fn wait_for_service_state(
        &self,
        expected_state: u32,
        mut cancel: Option<&mut ConnectCancelToken>,
    ) -> Result<(), ServiceWaitError> {
        let deadline = Instant::now() + self.config.service_wait_timeout;
        loop {
            if cancel.as_ref().is_some_and(|c| c.is_cancelled()) {
                return Err(ServiceWaitError::Cancelled);
            }

            let state = match cancel.as_deref_mut() {
                Some(token) => {
                    tokio::select! {
                        biased;
                        _ = token.cancelled() => return Err(ServiceWaitError::Cancelled),
                        res = self.runtime.service_state(&self.config.tunnel_name) => {
                            res.map_err(ServiceWaitError::Other)?
                        }
                    }
                }
                None => self
                    .runtime
                    .service_state(&self.config.tunnel_name)
                    .await
                    .map_err(ServiceWaitError::Other)?,
            };

            if state == expected_state {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(ServiceWaitError::Other(
                    "WireGuard Service chưa hoàn tất thay đổi trạng thái. Vui lòng thử lại."
                        .to_owned(),
                ));
            }

            let sleep_dur = self
                .config
                .service_poll_interval
                .min(deadline.saturating_duration_since(Instant::now()));
            match cancel.as_deref_mut() {
                Some(token) => {
                    tokio::select! {
                        biased;
                        _ = token.cancelled() => return Err(ServiceWaitError::Cancelled),
                        _ = tokio::time::sleep(sleep_dur) => {}
                    }
                }
                None => {
                    tokio::time::sleep(sleep_dur).await;
                }
            }
        }
    }

    /// Stops and deletes `WireGuardTunnel$FreetonVPN` if it exists, waits for state `0`, and removes
    /// the `.conf` file only after uninstall succeeds.
    async fn disconnect_while_locked(&self) -> Result<(), String> {
        let state = self.runtime.service_state(&self.config.tunnel_name).await?;
        if state != 0 {
            self.runtime
                .uninstall_tunnel(&self.config.tunnel_name)
                .await?;
            self.wait_for_service_state(0, None)
                .await
                .map_err(|err| match err {
                    ServiceWaitError::Cancelled => "cancelled".to_owned(),
                    ServiceWaitError::Other(msg) => msg,
                })?;
        }
        // Keep the .conf file if service uninstall failed above; only remove after absent.
        self.runtime.remove_conf(&self.config.tunnel_name).await?;
        Ok(())
    }

    async fn disconnect_while_locked_cancellable(
        &self,
        cancel: &mut ConnectCancelToken,
    ) -> Result<(), ServiceWaitError> {
        if cancel.is_cancelled() {
            return Err(ServiceWaitError::Cancelled);
        }
        let state = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(ServiceWaitError::Cancelled),
            res = self.runtime.service_state(&self.config.tunnel_name) => {
                res.map_err(ServiceWaitError::Other)?
            }
        };
        if state != 0 {
            self.runtime
                .uninstall_tunnel(&self.config.tunnel_name)
                .await
                .map_err(ServiceWaitError::Other)?;
            self.wait_for_service_state(0, Some(cancel)).await?;
        }
        self.runtime
            .remove_conf(&self.config.tunnel_name)
            .await
            .map_err(ServiceWaitError::Other)?;
        Ok(())
    }

    async fn teardown_locked(&self) -> Result<(), String> {
        let _guard = self.mutation_lock.lock().await;
        self.disconnect_while_locked().await?;
        let mut st = self.state.lock().expect("broker state lock poisoned");
        st.set_phase(BrokerPhase::Idle, None);
        Ok(())
    }

    async fn handle_connect(&self, spec: ValidatedTunnelSpec) -> ServiceResponse {
        // Always re-validate incoming Named Pipe specs before stopping a working tunnel or writing disk.
        let conf_content = match validate_tunnel_spec(&spec) {
            Ok(conf) => conf,
            Err(err) => {
                return ServiceResponse::Error {
                    code: "INVALID_SPEC".to_owned(),
                    message: err.to_string(),
                };
            }
        };

        let _guard = self.mutation_lock.lock().await;
        if self.is_stopping() {
            return ServiceResponse::Error {
                code: "CONNECT_CANCELLED".to_owned(),
                message: "Dịch vụ đang dừng; đã hủy yêu cầu kết nối.".to_owned(),
            };
        }

        let (mut cancel_token, _cancel_guard) = self.register_connect_cancel();

        let prev_state = self
            .state
            .lock()
            .expect("broker state lock poisoned")
            .clone();
        {
            let mut st = self.state.lock().expect("broker state lock poisoned");
            st.set_phase(BrokerPhase::Connecting, None);
        }

        if let Err(err) = self
            .disconnect_while_locked_cancellable(&mut cancel_token)
            .await
        {
            return match err {
                ServiceWaitError::Cancelled => {
                    let cleanup_res = self.disconnect_while_locked().await;
                    let mut st = self.state.lock().expect("broker state lock poisoned");
                    st.set_phase(BrokerPhase::Idle, None);
                    let msg = match cleanup_res {
                        Ok(()) => "Kết nối WireGuard đã bị hủy.".to_owned(),
                        Err(cleanup_err) => {
                            format!(
                                "Kết nối WireGuard đã bị hủy.\nKhông thể dọn tunnel: {cleanup_err}"
                            )
                        }
                    };
                    ServiceResponse::Error {
                        code: "CONNECT_CANCELLED".to_owned(),
                        message: msg,
                    }
                }
                ServiceWaitError::Other(msg) => {
                    let mut st = self.state.lock().expect("broker state lock poisoned");
                    st.set_phase(prev_state.phase, prev_state.last_dns_verified_unix);
                    ServiceResponse::Error {
                        code: "DISCONNECT_FAILED".to_owned(),
                        message: msg,
                    }
                }
            };
        }

        let info = build_active_info(&spec, self.runtime.now_unix());
        {
            let mut st = self.state.lock().expect("broker state lock poisoned");
            st.set_phase(BrokerPhase::Verifying(info.clone()), None);
        }

        match self
            .install_and_verify(&conf_content, &info, &mut cancel_token)
            .await
        {
            Ok(()) => {
                let mut st = self.state.lock().expect("broker state lock poisoned");
                st.set_phase(BrokerPhase::Active(info), Some(self.runtime.now_unix()));
                ServiceResponse::Ok
            }
            Err((code, message)) => {
                let cleanup_res = self.disconnect_while_locked().await;
                let mut st = self.state.lock().expect("broker state lock poisoned");
                st.set_phase(BrokerPhase::Idle, None);

                let full_message = match cleanup_res {
                    Ok(()) => message,
                    Err(cleanup_err) => {
                        format!("{message}\nKhông thể dọn tunnel lỗi: {cleanup_err}")
                    }
                };
                ServiceResponse::Error {
                    code: code.to_owned(),
                    message: full_message,
                }
            }
        }
    }

    async fn install_and_verify(
        &self,
        conf_content: &str,
        info: &ActiveTunnelInfo,
        cancel: &mut ConnectCancelToken,
    ) -> Result<(), (&'static str, String)> {
        if cancel.is_cancelled() {
            return Err((
                "CONNECT_CANCELLED",
                "Kết nối WireGuard đã bị hủy.".to_owned(),
            ));
        }

        let conf_path = self
            .runtime
            .write_conf(&self.config.tunnel_name, conf_content)
            .await
            .map_err(|e| ("CONF_WRITE_FAILED", e))?;

        if cancel.is_cancelled() {
            return Err((
                "CONNECT_CANCELLED",
                "Kết nối WireGuard đã bị hủy.".to_owned(),
            ));
        }

        self.runtime
            .install_and_start_tunnel(&self.config.tunnel_name, &conf_path)
            .await
            .map_err(|e| ("INSTALL_FAILED", e))?;

        self.wait_for_service_state(SERVICE_RUNNING_STATE, Some(cancel))
            .await
            .map_err(|err| match err {
                ServiceWaitError::Cancelled => (
                    "CONNECT_CANCELLED",
                    "Kết nối WireGuard đã bị hủy.".to_owned(),
                ),
                ServiceWaitError::Other(e) => ("SERVICE_START_TIMEOUT", e),
            })?;

        self.wait_for_connection(info, cancel).await
    }

    async fn wait_for_connection(
        &self,
        info: &ActiveTunnelInfo,
        cancel: &mut ConnectCancelToken,
    ) -> Result<(), (&'static str, String)> {
        let deadline = Instant::now() + self.config.connect_timeout;
        let mut handshaken = false;
        let mut saw_driver_state = false;
        let mut last_uapi_err: Option<String> = None;

        while Instant::now() < deadline {
            if cancel.is_cancelled() {
                return Err((
                    "CONNECT_CANCELLED",
                    "Kết nối WireGuard đã bị hủy.".to_owned(),
                ));
            }

            let state = tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    return Err((
                        "CONNECT_CANCELLED",
                        "Kết nối WireGuard đã bị hủy.".to_owned(),
                    ));
                }
                res = self.runtime.service_state(&self.config.tunnel_name) => {
                    res.map_err(|e| ("SCM_ERROR", e))?
                }
            };
            if state != SERVICE_RUNNING_STATE {
                return Err((
                    "SERVICE_STOPPED",
                    "WireGuard Service đã dừng trước khi kết nối hoàn tất.".to_owned(),
                ));
            }

            handshaken = tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    return Err((
                        "CONNECT_CANCELLED",
                        "Kết nối WireGuard đã bị hủy.".to_owned(),
                    ));
                }
                uapi_res = self.runtime.read_uapi_state(&self.config.tunnel_name) => {
                    match uapi_res {
                        Ok(uapi) => {
                            saw_driver_state = true;
                            last_uapi_err = None;
                            let stamp = parse_uapi_latest_handshake(&uapi, &info.x25519_pubkey);
                            is_fresh_handshake(stamp, self.runtime.now_unix())
                        }
                        Err(err) => {
                            last_uapi_err = Some(err);
                            false
                        }
                    }
                }
            };

            if handshaken {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let dns_budget = self
                    .config
                    .dns_probe_timeout
                    .min(remaining.max(Duration::from_millis(1)));
                let dns_ok = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => {
                        return Err((
                            "CONNECT_CANCELLED",
                            "Kết nối WireGuard đã bị hủy.".to_owned(),
                        ));
                    }
                    ok = self.runtime.check_dns_through_tunnel(&info.address, &info.dns, dns_budget) => ok,
                };
                if dns_ok {
                    return Ok(());
                }
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    return Err((
                        "CONNECT_CANCELLED",
                        "Kết nối WireGuard đã bị hủy.".to_owned(),
                    ));
                }
                _ = tokio::time::sleep(self.config.handshake_poll_interval.min(remaining)) => {}
            }
        }

        if handshaken {
            Err((
                "DNS_FAILED",
                "WireGuard đã bắt tay nhưng DNS qua VPN chưa phản hồi. Hãy kiểm tra DNS trong Cài đặt hoặc chọn máy chủ khác.".to_owned(),
            ))
        } else {
            let detail = match last_uapi_err {
                Some(err) if !saw_driver_state => {
                    warn!(error = %err, "WireGuard driver/UAPI state unreadable during connect timeout");
                    format!("\nChi tiết driver WireGuard: {err}")
                }
                _ => String::new(),
            };
            Err((
                "HANDSHAKE_TIMEOUT",
                format!(
                    "Máy chủ chưa phản hồi handshake WireGuard. Hãy thử máy chủ khác, kiểm tra cổng UDP hoặc cấp lại WireGuard Key trong Cài đặt.{detail}"
                ),
            ))
        }
    }

    async fn handle_status(&self) -> TunnelHealthState {
        let snapshot = self
            .state
            .lock()
            .expect("broker state lock poisoned")
            .clone();
        let snapshot_generation = snapshot.generation;
        let (info, last_dns_verified_unix) = match snapshot.phase {
            BrokerPhase::Idle => return TunnelHealthState::Disconnected,
            BrokerPhase::Connecting => return TunnelHealthState::Connecting,
            BrokerPhase::Verifying(info) => return TunnelHealthState::Verifying(info),
            BrokerPhase::Active(info) => (info, snapshot.last_dns_verified_unix),
        };

        match self.runtime.service_state(&self.config.tunnel_name).await {
            Ok(state) if state == SERVICE_RUNNING_STATE => {}
            Ok(_) => {
                self.clear_stale_active(snapshot_generation);
                return TunnelHealthState::Disconnected;
            }
            Err(err) => {
                return TunnelHealthState::Unverified {
                    info,
                    reason: format!("Không kiểm tra được trạng thái dịch vụ WireGuard: {err}"),
                };
            }
        }

        let uapi = match self.runtime.read_uapi_state(&self.config.tunnel_name).await {
            Ok(data) => data,
            Err(err) => {
                self.invalidate_dns_cache(snapshot_generation);
                return TunnelHealthState::Unverified {
                    info,
                    reason: format!("Không đọc được handshake WireGuard: {err}"),
                };
            }
        };

        let now = self.runtime.now_unix();
        let stamp = parse_uapi_latest_handshake(&uapi, &info.x25519_pubkey);
        if !is_fresh_handshake(stamp, now) {
            self.invalidate_dns_cache(snapshot_generation);
            return TunnelHealthState::Unverified {
                info,
                reason: "Chưa có handshake WireGuard hợp lệ (hết hạn hoặc chưa bắt tay)."
                    .to_owned(),
            };
        }

        let recheck_secs = i64::try_from(self.config.dns_recheck_interval.as_secs()).unwrap_or(30);
        let dns_fresh = last_dns_verified_unix
            .is_some_and(|verified_at| now >= verified_at && (now - verified_at) < recheck_secs);
        if !dns_fresh {
            if !self
                .runtime
                .check_dns_through_tunnel(&info.address, &info.dns, self.config.dns_probe_timeout)
                .await
            {
                self.invalidate_dns_cache(snapshot_generation);
                return TunnelHealthState::Unverified {
                    info,
                    reason: "DNS qua VPN chưa phản hồi.".to_owned(),
                };
            }
            self.mark_dns_verified(snapshot_generation, self.runtime.now_unix());
        }

        TunnelHealthState::Connected(info)
    }

    fn clear_stale_active(&self, expected_generation: u64) {
        let mut st = self.state.lock().expect("broker state lock poisoned");
        if st.generation == expected_generation && matches!(st.phase, BrokerPhase::Active(_)) {
            st.set_phase(BrokerPhase::Idle, None);
        }
    }

    fn invalidate_dns_cache(&self, expected_generation: u64) {
        let mut st = self.state.lock().expect("broker state lock poisoned");
        if st.generation == expected_generation && matches!(st.phase, BrokerPhase::Active(_)) {
            st.last_dns_verified_unix = None;
        }
    }

    fn mark_dns_verified(&self, expected_generation: u64, verified_at: i64) {
        let mut st = self.state.lock().expect("broker state lock poisoned");
        if st.generation == expected_generation && matches!(st.phase, BrokerPhase::Active(_)) {
            st.last_dns_verified_unix = Some(verified_at);
        }
    }
}

pub fn create_secured_pipe_server(
    pipe_name: &str,
    sddl: &str,
    first_instance: bool,
) -> io::Result<NamedPipeServer> {
    let wide_sddl =
        to_wide_null(sddl).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(wide_sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
        .map_err(|e| io::Error::other(format!("SDDL parse failed: {e}")))?;
    }
    let _sd_guard = LocalFreeGuard(sd.0);

    let mut sa = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(core::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
        lpSecurityDescriptor: sd.0,
        bInheritHandle: FALSE,
    };

    let mut opts = ServerOptions::new();
    opts.access_inbound(true)
        .access_outbound(true)
        .pipe_mode(PipeMode::Byte)
        .reject_remote_clients(true)
        .first_pipe_instance(first_instance);

    unsafe {
        opts.create_with_security_attributes_raw(
            pipe_name,
            (&mut sa as *mut SECURITY_ATTRIBUTES).cast(),
        )
    }
}

async fn write_response_line<W: AsyncWrite + Unpin>(
    writer: &mut W,
    resp: &ServiceResponse,
) -> io::Result<()> {
    let mut json = serde_json::to_string(resp).map_err(io::Error::other)?;
    json.push('\n');
    writer.write_all(json.as_bytes()).await?;
    writer.flush().await
}

enum ReadLineOutcome {
    Eof,
    TooLong,
    Line(String),
}

async fn read_bounded_line<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    max_bytes: usize,
) -> io::Result<ReadLineOutcome> {
    let mut buf = Vec::with_capacity(256);
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if buf.is_empty() {
                return Ok(ReadLineOutcome::Eof);
            }
            let text = String::from_utf8(buf)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            return Ok(ReadLineOutcome::Line(text));
        }

        if let Some(newline_pos) = available.iter().position(|&b| b == b'\n') {
            let take_len = newline_pos + 1;
            if buf.len() + take_len > max_bytes {
                reader.consume(take_len);
                return Ok(ReadLineOutcome::TooLong);
            }
            buf.extend_from_slice(&available[..take_len]);
            reader.consume(take_len);
            let text = String::from_utf8(buf)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            return Ok(ReadLineOutcome::Line(text));
        }

        if buf.len() + available.len() > max_bytes {
            let len = available.len();
            reader.consume(len);
            return Ok(ReadLineOutcome::TooLong);
        }
        buf.extend_from_slice(available);
        let len = available.len();
        reader.consume(len);
    }
}

pub async fn serve_pipe_stream<S, R>(stream: S, broker: Arc<TunnelBroker<R>>)
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: TunnelRuntime,
{
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    loop {
        match read_bounded_line(&mut reader, MAX_IPC_LINE_BYTES).await {
            Ok(ReadLineOutcome::Eof) => break,
            Ok(ReadLineOutcome::TooLong) => {
                let err_resp = ServiceResponse::Error {
                    code: "INVALID_REQUEST".to_owned(),
                    message: "IPC request exceeds maximum line length".to_owned(),
                };
                let _ = write_response_line(&mut write_half, &err_resp).await;
                break;
            }
            Ok(ReadLineOutcome::Line(line)) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let response = match serde_json::from_str::<ServiceRequest>(trimmed) {
                    Ok(req) => broker.handle_request(req).await,
                    Err(err) => ServiceResponse::Error {
                        code: "INVALID_REQUEST".to_owned(),
                        message: format!("Malformed ServiceRequest JSON: {err}"),
                    },
                };
                if write_response_line(&mut write_half, &response)
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(_) => {
                let err_resp = ServiceResponse::Error {
                    code: "INVALID_REQUEST".to_owned(),
                    message: "Invalid UTF-8 in IPC request".to_owned(),
                };
                let _ = write_response_line(&mut write_half, &err_resp).await;
                break;
            }
        }
    }
}

pub(crate) fn should_teardown_on_session_change(reason: SessionChangeReason) -> bool {
    matches!(
        reason,
        SessionChangeReason::SessionLogoff | SessionChangeReason::ConsoleDisconnect
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipeServerBackoff {
    pub initial: Duration,
    pub max: Duration,
    pub max_consecutive_failures: u32,
}

impl Default for PipeServerBackoff {
    fn default() -> Self {
        Self {
            initial: Duration::from_millis(50),
            max: Duration::from_secs(2),
            max_consecutive_failures: MAX_CONSECUTIVE_PIPE_FAILURES,
        }
    }
}

impl PipeServerBackoff {
    fn delay_for_attempt(&self, failure_count: u32) -> Duration {
        let shift = failure_count.saturating_sub(1).min(10);
        let factor = 1u32.checked_shl(shift).unwrap_or(u32::MAX);
        self.initial.saturating_mul(factor).min(self.max)
    }
}

pub trait PipeInstance: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    fn accept_client<'a>(&'a mut self) -> BoxFuture<'a, io::Result<()>>;
}

impl PipeInstance for NamedPipeServer {
    fn accept_client<'a>(&'a mut self) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move { self.connect().await })
    }
}

pub trait PipeServerFactory: Send + Sync + 'static {
    type Pipe: PipeInstance;
    fn create_pipe(&self, first_instance: bool) -> io::Result<Self::Pipe>;
}

struct WindowsPipeFactory {
    pipe_name: String,
    sddl: String,
}

impl PipeServerFactory for WindowsPipeFactory {
    type Pipe = NamedPipeServer;

    fn create_pipe(&self, first_instance: bool) -> io::Result<Self::Pipe> {
        create_secured_pipe_server(&self.pipe_name, &self.sddl, first_instance)
    }
}

async fn wait_for_shutdown(rx: &mut watch::Receiver<bool>) {
    if *rx.borrow() {
        return;
    }
    while rx.changed().await.is_ok() {
        if *rx.borrow() {
            return;
        }
    }
}

async fn create_next_pipe_with_retry<F: PipeServerFactory>(
    factory: &F,
    shutdown: &mut watch::Receiver<bool>,
    backoff: PipeServerBackoff,
    consecutive_failures: &mut u32,
) -> io::Result<Option<F::Pipe>> {
    loop {
        if *shutdown.borrow() {
            return Ok(None);
        }
        match factory.create_pipe(false) {
            Ok(next) => return Ok(Some(next)),
            Err(err) => {
                *consecutive_failures = consecutive_failures.saturating_add(1);
                if *consecutive_failures >= backoff.max_consecutive_failures {
                    error!(
                        "pipe instance creation failed {} consecutive times: {err}",
                        *consecutive_failures
                    );
                    return Err(err);
                }
                let delay = backoff.delay_for_attempt(*consecutive_failures);
                warn!(
                    "transient named pipe creation error (attempt {}/{}): {err}; retrying in {:?}",
                    *consecutive_failures, backoff.max_consecutive_failures, delay
                );
                tokio::select! {
                    biased;
                    _ = wait_for_shutdown(shutdown) => return Ok(None),
                    _ = tokio::time::sleep(delay) => {}
                }
            }
        }
    }
}

pub async fn run_pipe_accept_loop<F, R>(
    initial_server: F::Pipe,
    factory: Arc<F>,
    broker: Arc<TunnelBroker<R>>,
    mut shutdown: watch::Receiver<bool>,
    backoff: PipeServerBackoff,
) -> io::Result<()>
where
    F: PipeServerFactory,
    R: TunnelRuntime,
{
    let mut server = initial_server;
    let mut consecutive_failures = 0u32;

    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            biased;
            _ = wait_for_shutdown(&mut shutdown) => {
                break;
            }
            conn = server.accept_client() => {
                match conn {
                    Ok(()) => {
                        let connected_stream = server;
                        let broker_clone = Arc::clone(&broker);
                        tokio::spawn(async move {
                            serve_pipe_stream(connected_stream, broker_clone).await;
                        });
                        match create_next_pipe_with_retry(
                            factory.as_ref(),
                            &mut shutdown,
                            backoff,
                            &mut consecutive_failures,
                        )
                        .await?
                        {
                            Some(next_server) => {
                                consecutive_failures = 0;
                                server = next_server;
                            }
                            None => break,
                        }
                    }
                    Err(err) => {
                        consecutive_failures = consecutive_failures.saturating_add(1);
                        if consecutive_failures >= backoff.max_consecutive_failures {
                            error!(
                                "named pipe accept failed {} consecutive times: {err}",
                                consecutive_failures
                            );
                            return Err(err);
                        }
                        let delay = backoff.delay_for_attempt(consecutive_failures);
                        warn!(
                            "transient named pipe accept error (attempt {}/{}): {err}; retrying in {:?}",
                            consecutive_failures, backoff.max_consecutive_failures, delay
                        );
                        tokio::select! {
                            biased;
                            _ = wait_for_shutdown(&mut shutdown) => break,
                            _ = tokio::time::sleep(delay) => {}
                        }
                        match create_next_pipe_with_retry(
                            factory.as_ref(),
                            &mut shutdown,
                            backoff,
                            &mut consecutive_failures,
                        )
                        .await?
                        {
                            Some(next_server) => {
                                server = next_server;
                            }
                            None => break,
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

trait ServiceStatusReporter: Send + Sync {
    fn set_status(
        &self,
        state: ServiceState,
        controls_accepted: ServiceControlAccept,
        wait_hint: Duration,
        exit_code: ServiceExitCode,
    ) -> Result<(), String>;
}

struct ScmStatusReporter(service_control_handler::ServiceStatusHandle);

impl ServiceStatusReporter for ScmStatusReporter {
    fn set_status(
        &self,
        state: ServiceState,
        controls_accepted: ServiceControlAccept,
        wait_hint: Duration,
        exit_code: ServiceExitCode,
    ) -> Result<(), String> {
        self.0
            .set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: state,
                controls_accepted,
                exit_code,
                checkpoint: 0,
                wait_hint,
                process_id: None,
            })
            .map_err(|e| format!("SetServiceStatus({state:?}) failed: {e}"))
    }
}

async fn run_broker_lifecycle<F, S, R>(
    status_reporter: &S,
    pipe_factory: Arc<F>,
    broker: Arc<TunnelBroker<R>>,
    mut shutdown_rx: watch::Receiver<bool>,
    mut session_rx: tokio::sync::mpsc::UnboundedReceiver<SessionChangeReason>,
    backoff: PipeServerBackoff,
) -> Result<(), String>
where
    F: PipeServerFactory,
    S: ServiceStatusReporter,
    R: TunnelRuntime,
{
    status_reporter.set_status(
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        Duration::from_secs(5),
        ServiceExitCode::Win32(0),
    )?;

    // Bind initial pipe instance BEFORE transitioning SCM to Running; fail startup if bind fails.
    let initial_pipe = match pipe_factory.create_pipe(true) {
        Ok(pipe) => pipe,
        Err(err) => {
            let msg = format!("failed creating initial IPC pipe instance: {err}");
            let _ = status_reporter.set_status(
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                Duration::ZERO,
                ServiceExitCode::Win32(1),
            );
            return Err(msg);
        }
    };

    let (internal_stop_tx, internal_stop_rx) = watch::channel(false);

    let session_broker = Arc::clone(&broker);
    let mut session_shutdown = shutdown_rx.clone();
    let mut session_internal_stop = internal_stop_rx.clone();
    let session_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = wait_for_shutdown(&mut session_shutdown) => break,
                _ = wait_for_shutdown(&mut session_internal_stop) => break,
                maybe_reason = session_rx.recv() => {
                    match maybe_reason {
                        Some(reason) => {
                            if let Err(err) = session_broker.handle_session_change(reason).await {
                                warn!("session change ({reason:?}) teardown error: {err}");
                            }
                        }
                        None => break,
                    }
                }
            }
        }
    });

    let pipe_broker = Arc::clone(&broker);
    let pipe_shutdown = shutdown_rx.clone();
    let mut pipe_task = tokio::spawn(async move {
        run_pipe_accept_loop(
            initial_pipe,
            pipe_factory,
            pipe_broker,
            pipe_shutdown,
            backoff,
        )
        .await
    });

    if let Err(err) = status_reporter.set_status(
        ServiceState::Running,
        ServiceControlAccept::STOP
            | ServiceControlAccept::SHUTDOWN
            | ServiceControlAccept::SESSION_CHANGE,
        Duration::ZERO,
        ServiceExitCode::Win32(0),
    ) {
        let _ = internal_stop_tx.send(true);
        pipe_task.abort();
        let _ = session_task.await;
        let _ = pipe_task.await;
        broker.shutdown_for_service_stop().await;
        let _ = status_reporter.set_status(
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            Duration::ZERO,
            ServiceExitCode::Win32(1),
        );
        return Err(err);
    }

    let mut lifecycle_result: Result<(), String> = Ok(());
    let mut pipe_finished = false;
    tokio::select! {
        biased;
        _ = wait_for_shutdown(&mut shutdown_rx) => {}
        pipe_res = &mut pipe_task => {
            pipe_finished = true;
            match pipe_res {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    lifecycle_result = Err(format!("pipe server failed unrecoverably: {err}"));
                }
                Err(err) => {
                    lifecycle_result = Err(format!("pipe server task panicked: {err}"));
                }
            }
        }
    }

    let _ = internal_stop_tx.send(true);
    broker.cancel_for_service_stop();
    let _ = status_reporter.set_status(
        ServiceState::StopPending,
        ServiceControlAccept::empty(),
        Duration::from_secs(15),
        ServiceExitCode::Win32(0),
    );

    let _ = session_task.await;
    if !pipe_finished {
        if let Ok(Err(err)) = pipe_task.await {
            warn!("pipe server stopped with error: {err}");
        }
    }
    broker.shutdown_for_service_stop().await;

    let exit_code = if lifecycle_result.is_ok() {
        ServiceExitCode::Win32(0)
    } else {
        ServiceExitCode::Win32(1)
    };
    let _ = status_reporter.set_status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        Duration::ZERO,
        exit_code,
    );

    lifecycle_result
}

define_windows_service!(ffi_broker_service_main, broker_service_main);

fn broker_service_main(_arguments: Vec<OsString>) {
    if let Err(err) = run_broker_service_inner() {
        error!("FreetonVPNService exited with error: {err}");
    }
}

fn run_broker_service_inner() -> Result<(), String> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (session_tx, session_rx) = tokio::sync::mpsc::unbounded_channel();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(true);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::SessionChange(param) => {
                if should_teardown_on_session_change(param.reason) {
                    let _ = session_tx.send(param.reason);
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(BROKER_SERVICE_NAME, event_handler)
        .map_err(|e| format!("register control handler failed: {e}"))?;
    let reporter = ScmStatusReporter(status_handle);

    let service_exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let runtime = Arc::new(WindowsTunnelRuntime::new(
        default_tunnels_dir(),
        service_exe,
    ));
    let broker = Arc::new(
        TunnelBroker::new(runtime, BrokerConfig::default()).with_shutdown(shutdown_rx.clone()),
    );
    let pipe_factory = Arc::new(WindowsPipeFactory {
        pipe_name: SERVICE_PIPE_NAME.to_owned(),
        sddl: PIPE_SDDL_DACL.to_owned(),
    });

    let tokio_rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("failed to create Tokio runtime: {e}"))?;

    tokio_rt.block_on(run_broker_lifecycle(
        &reporter,
        pipe_factory,
        broker,
        shutdown_rx,
        session_rx,
        PipeServerBackoff::default(),
    ))
}

pub fn run_windows_service() -> Result<(), String> {
    service_dispatcher::start(BROKER_SERVICE_NAME, ffi_broker_service_main)
        .map_err(|e| format!("service_dispatcher::start failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use freeton_core::wg::{ActiveTunnelInfo, TunnelHealthState, ValidatedTunnelSpec};
    use std::collections::VecDeque;
    use std::fs;
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    const TEST_PRIVKEY_B64: &str = "ERERERERERERERERERERERERERERERERERERERERERE=";
    const TEST_PUBKEY_B64: &str = "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=";

    fn sample_key_hex(fill: u8) -> String {
        format!("{fill:02x}").repeat(32)
    }

    fn sample_spec() -> ValidatedTunnelSpec {
        ValidatedTunnelSpec {
            server_name: "JP-FREE#1".to_owned(),
            country: "JP".to_owned(),
            domain: "node-jp-01.protonvpn.net".to_owned(),
            entry_ip: "192.0.2.1".to_owned(),
            server_pubkey: TEST_PUBKEY_B64.to_owned(),
            private_key: TEST_PRIVKEY_B64.to_owned(),
            address: "10.2.0.2/32".to_owned(),
            dns: "10.2.0.1, 1.1.1.1".to_owned(),
            port: 51820,
        }
    }

    fn test_config() -> BrokerConfig {
        BrokerConfig {
            tunnel_name: DEFAULT_TUNNEL_NAME.to_owned(),
            service_wait_timeout: Duration::from_millis(200),
            service_poll_interval: Duration::from_millis(1),
            connect_timeout: Duration::from_millis(80),
            handshake_poll_interval: Duration::from_millis(1),
            dns_probe_timeout: Duration::from_millis(20),
            dns_recheck_interval: Duration::from_secs(30),
        }
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "freeton_broker_test_{label}_{}_{}",
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    struct MockState {
        events: Vec<String>,
        service_states: VecDeque<Result<u32, String>>,
        current_service_state: u32,
        uninstall_result: Result<(), String>,
        install_result: Result<(), String>,
        uapi_responses: VecDeque<Result<String, String>>,
        default_uapi: Result<String, String>,
        dns_results: VecDeque<bool>,
        default_dns: bool,
        dns_calls: usize,
    }

    struct MockRuntime {
        now: AtomicI64,
        tunnels_dir: PathBuf,
        inner: Mutex<MockState>,
    }

    impl MockRuntime {
        fn new(tunnels_dir: PathBuf, now_unix: i64) -> Self {
            Self {
                now: AtomicI64::new(now_unix),
                tunnels_dir,
                inner: Mutex::new(MockState {
                    events: Vec::new(),
                    service_states: VecDeque::new(),
                    current_service_state: 0,
                    uninstall_result: Ok(()),
                    install_result: Ok(()),
                    uapi_responses: VecDeque::new(),
                    default_uapi: Ok("errno=0\n".to_owned()),
                    dns_results: VecDeque::new(),
                    default_dns: true,
                    dns_calls: 0,
                }),
            }
        }

        fn conf_path(&self, tunnel_name: &str) -> PathBuf {
            self.tunnels_dir.join(format!("{tunnel_name}.conf"))
        }

        fn events(&self) -> Vec<String> {
            self.inner.lock().expect("lock").events.clone()
        }
    }

    impl TunnelRuntime for MockRuntime {
        fn now_unix(&self) -> i64 {
            self.now.load(Ordering::SeqCst)
        }

        fn service_state<'a>(&'a self, tunnel_name: &'a str) -> BoxFuture<'a, Result<u32, String>> {
            Box::pin(async move {
                let mut state = self.inner.lock().expect("lock");
                let res = match state.service_states.pop_front() {
                    Some(v) => {
                        if let Ok(code) = v {
                            state.current_service_state = code;
                        }
                        v
                    }
                    None => Ok(state.current_service_state),
                };
                if let Ok(code) = res {
                    state.events.push(format!("state:{tunnel_name}:{code}"));
                }
                res
            })
        }

        fn write_conf<'a>(
            &'a self,
            tunnel_name: &'a str,
            conf_content: &'a str,
        ) -> BoxFuture<'a, Result<PathBuf, String>> {
            Box::pin(async move {
                fs::create_dir_all(&self.tunnels_dir).map_err(|e| e.to_string())?;
                let path = self.conf_path(tunnel_name);
                fs::write(&path, conf_content).map_err(|e| e.to_string())?;
                self.inner
                    .lock()
                    .expect("lock")
                    .events
                    .push(format!("write_conf:{tunnel_name}"));
                Ok(path)
            })
        }

        fn remove_conf<'a>(&'a self, tunnel_name: &'a str) -> BoxFuture<'a, Result<(), String>> {
            Box::pin(async move {
                let path = self.conf_path(tunnel_name);
                match fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                    Err(err) => return Err(err.to_string()),
                }
                self.inner
                    .lock()
                    .expect("lock")
                    .events
                    .push(format!("remove_conf:{tunnel_name}"));
                Ok(())
            })
        }

        fn install_and_start_tunnel<'a>(
            &'a self,
            tunnel_name: &'a str,
            _conf_path: &'a Path,
        ) -> BoxFuture<'a, Result<(), String>> {
            Box::pin(async move {
                let mut state = self.inner.lock().expect("lock");
                state.events.push(format!("install:{tunnel_name}"));
                let res = state.install_result.clone();
                if res.is_ok() {
                    state.current_service_state = 4;
                }
                res
            })
        }

        fn uninstall_tunnel<'a>(
            &'a self,
            tunnel_name: &'a str,
        ) -> BoxFuture<'a, Result<(), String>> {
            Box::pin(async move {
                let mut state = self.inner.lock().expect("lock");
                state.events.push(format!("uninstall:{tunnel_name}"));
                let res = state.uninstall_result.clone();
                if res.is_ok() {
                    state.current_service_state = 0;
                }
                res
            })
        }

        fn read_uapi_state<'a>(
            &'a self,
            tunnel_name: &'a str,
        ) -> BoxFuture<'a, Result<String, String>> {
            Box::pin(async move {
                let mut state = self.inner.lock().expect("lock");
                state.events.push(format!("uapi:{tunnel_name}"));
                state
                    .uapi_responses
                    .pop_front()
                    .unwrap_or_else(|| state.default_uapi.clone())
            })
        }

        fn check_dns_through_tunnel<'a>(
            &'a self,
            _address: &'a str,
            _dns: &'a str,
            _timeout: Duration,
        ) -> BoxFuture<'a, bool> {
            Box::pin(async move {
                let mut state = self.inner.lock().expect("lock");
                state.dns_calls += 1;
                let ok = state.dns_results.pop_front().unwrap_or(state.default_dns);
                state.events.push(format!("dns:{ok}"));
                ok
            })
        }
    }

    fn uapi_with_handshake(pubkey_hex: &str, stamp: i64) -> String {
        format!("public_key={pubkey_hex}\nlast_handshake_time_sec={stamp}\nerrno=0\n")
    }

    #[tokio::test]
    async fn test_switch_waits_for_old_tunnel_service_absence_before_install() {
        let dir = unique_temp_dir("switch");
        let now = 1_700_000_500;
        let runtime = Arc::new(MockRuntime::new(dir.clone(), now));
        {
            let mut st = runtime.inner.lock().expect("lock");
            st.current_service_state = 4;
            st.service_states = VecDeque::from([
                Ok(4), // initial check -> existing service
                Ok(3), // STOP_PENDING during wait for 0
                Ok(0), // absent -> safe to write conf & install
                Ok(2), // START_PENDING during wait for SERVICE_RUNNING
                Ok(4), // SERVICE_RUNNING
                Ok(4), // verify loop service check
            ]);
            st.uapi_responses = VecDeque::from([
                Err("pipe starting".to_owned()),
                Ok(uapi_with_handshake(&sample_key_hex(0xAB), now - 5)),
            ]);
            st.default_dns = true;
        }

        let broker = TunnelBroker::new(runtime.clone(), test_config());

        // Invalid spec must be rejected before stopping or touching existing tunnel.
        let mut bad_spec = sample_spec();
        bad_spec.dns = "10.2.0.1\nPostUp = calc.exe".to_owned();
        let bad_resp = broker
            .handle_request(ServiceRequest::Connect(bad_spec))
            .await;
        assert!(
            matches!(bad_resp, ServiceResponse::Error { ref code, .. } if code == "INVALID_SPEC")
        );
        assert!(runtime.events().is_empty());

        let resp = broker
            .handle_request(ServiceRequest::Connect(sample_spec()))
            .await;
        assert_eq!(resp, ServiceResponse::Ok);
        assert!(runtime.conf_path(DEFAULT_TUNNEL_NAME).exists());

        let events = runtime.events();
        let pos_uninstall = events
            .iter()
            .position(|e| e == "uninstall:FreetonVPN")
            .expect("uninstall event");
        let pos_zero = events
            .iter()
            .position(|e| e == "state:FreetonVPN:0")
            .expect("state 0 event");
        let pos_write = events
            .iter()
            .position(|e| e == "write_conf:FreetonVPN")
            .expect("write_conf event");
        let pos_install = events
            .iter()
            .position(|e| e == "install:FreetonVPN")
            .expect("install event");
        let pos_running = events
            .iter()
            .rposition(|e| e == "state:FreetonVPN:4")
            .expect("SERVICE_RUNNING event");
        let pos_uapi = events
            .iter()
            .position(|e| e == "uapi:FreetonVPN")
            .expect("uapi event");
        let pos_dns = events
            .iter()
            .position(|e| e == "dns:true")
            .expect("dns event");

        assert!(pos_uninstall < pos_zero);
        assert!(pos_zero < pos_write);
        assert!(pos_write < pos_install);
        assert!(pos_install < pos_running);
        assert!(pos_uapi < pos_dns);

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_handshake_timeout_and_dns_failure_cleanup_conf_and_service() {
        // Case A: Handshake timeout -> cleans up tunnel & .conf, never probes DNS
        let dir_a = unique_temp_dir("hs_timeout");
        let now = 1_700_000_500;
        let runtime_a = Arc::new(MockRuntime::new(dir_a.clone(), now));
        {
            let mut st = runtime_a.inner.lock().expect("lock");
            st.service_states = VecDeque::from([
                Ok(0), // no pre-existing tunnel
                Ok(4), // SERVICE_RUNNING after install
            ]);
            st.current_service_state = 4;
            st.default_uapi = Ok(uapi_with_handshake(&sample_key_hex(0xAB), 0));
        }

        let broker_a = TunnelBroker::new(runtime_a.clone(), test_config());
        let resp_a = broker_a
            .handle_request(ServiceRequest::Connect(sample_spec()))
            .await;
        match resp_a {
            ServiceResponse::Error { code, message } => {
                assert_eq!(code, "HANDSHAKE_TIMEOUT");
                assert!(message.to_lowercase().contains("handshake"));
            }
            other => panic!("expected handshake error, got {other:?}"),
        }
        assert_eq!(runtime_a.inner.lock().expect("lock").dns_calls, 0);
        assert!(!runtime_a.conf_path(DEFAULT_TUNNEL_NAME).exists());
        assert!(runtime_a
            .events()
            .iter()
            .any(|e| e == "uninstall:FreetonVPN"));

        // Case B: Handshake succeeds, DNS fails -> cleans up tunnel & .conf with distinct DNS error
        let dir_b = unique_temp_dir("dns_fail");
        let runtime_b = Arc::new(MockRuntime::new(dir_b.clone(), now));
        {
            let mut st = runtime_b.inner.lock().expect("lock");
            st.service_states = VecDeque::from([Ok(0), Ok(4)]);
            st.current_service_state = 4;
            st.default_uapi = Ok(uapi_with_handshake(&sample_key_hex(0xAB), now - 2));
            st.default_dns = false;
        }

        let broker_b = TunnelBroker::new(runtime_b.clone(), test_config());
        let resp_b = broker_b
            .handle_request(ServiceRequest::Connect(sample_spec()))
            .await;
        match resp_b {
            ServiceResponse::Error { code, message } => {
                assert_eq!(code, "DNS_FAILED");
                assert!(message.contains("DNS"));
            }
            other => panic!("expected DNS error, got {other:?}"),
        }
        assert!(!runtime_b.conf_path(DEFAULT_TUNNEL_NAME).exists());
        assert!(runtime_b
            .events()
            .iter()
            .any(|e| e == "uninstall:FreetonVPN"));

        let _ = fs::remove_dir_all(&dir_a);
        let _ = fs::remove_dir_all(&dir_b);
    }

    #[tokio::test]
    async fn test_uninstall_failure_retains_conf_and_propagates_error() {
        let dir = unique_temp_dir("uninstall_fail");
        let runtime = Arc::new(MockRuntime::new(dir.clone(), 1_700_000_500));
        let conf_path = runtime.conf_path(DEFAULT_TUNNEL_NAME);
        fs::write(&conf_path, "keep this configuration").expect("write conf");

        {
            let mut st = runtime.inner.lock().expect("lock");
            st.current_service_state = 4;
            st.uninstall_result = Err("access denied".to_owned());
        }

        let broker = TunnelBroker::new(runtime.clone(), test_config());
        let resp = broker.handle_request(ServiceRequest::Disconnect).await;
        match resp {
            ServiceResponse::Error { message, .. } => {
                assert!(message.contains("access denied"));
            }
            other => panic!("expected error, got {other:?}"),
        }
        assert!(
            conf_path.exists(),
            "conf must be retained when uninstall fails"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_status_hydrates_active_tunnel_info_and_logoff_triggers_teardown() {
        let dir = unique_temp_dir("status_logoff");
        let now = 1_700_000_500;
        let runtime = Arc::new(MockRuntime::new(dir.clone(), now));
        {
            let mut st = runtime.inner.lock().expect("lock");
            st.service_states = VecDeque::from([Ok(0), Ok(4)]);
            st.current_service_state = 4;
            st.default_uapi = Ok(uapi_with_handshake(&sample_key_hex(0xAB), now - 3));
            st.default_dns = true;
        }

        let broker = TunnelBroker::new(runtime.clone(), test_config());
        let spec = sample_spec();
        assert_eq!(
            broker
                .handle_request(ServiceRequest::Connect(spec.clone()))
                .await,
            ServiceResponse::Ok
        );

        // Simulated UI reconnect querying Status hydrates full ActiveTunnelInfo.
        let status_1 = broker.handle_request(ServiceRequest::Status).await;
        match status_1 {
            ServiceResponse::Status(TunnelHealthState::Connected(ActiveTunnelInfo {
                server_name,
                country,
                entry_ip,
                x25519_pubkey,
                address,
                dns,
                port,
                connected_at_unix,
            })) => {
                assert_eq!(server_name, spec.server_name);
                assert_eq!(country, spec.country);
                assert_eq!(entry_ip, spec.entry_ip);
                assert_eq!(x25519_pubkey, spec.server_pubkey);
                assert_eq!(address, spec.address);
                assert_eq!(dns, spec.dns);
                assert_eq!(port, spec.port);
                assert_eq!(connected_at_unix, now);
            }
            other => panic!("expected Connected status, got {other:?}"),
        }

        // Stale handshake (> 180s) returns Unverified while service is still running.
        runtime.now.store(now + 200, Ordering::SeqCst);
        let stale_status = broker.handle_request(ServiceRequest::Status).await;
        assert!(matches!(
            stale_status,
            ServiceResponse::Status(TunnelHealthState::Unverified { .. })
        ));

        // Fresh handshake again + stale DNS cache re-verifies DNS cleanly.
        runtime.now.store(now + 40, Ordering::SeqCst);
        {
            let mut st = runtime.inner.lock().expect("lock");
            st.default_uapi = Ok(uapi_with_handshake(&sample_key_hex(0xAB), now + 35));
            st.default_dns = false;
        }
        let dns_broken_status = broker.handle_request(ServiceRequest::Status).await;
        assert!(matches!(
            dns_broken_status,
            ServiceResponse::Status(TunnelHealthState::Unverified { .. })
        ));

        {
            let mut st = runtime.inner.lock().expect("lock");
            st.default_dns = true;
        }
        let recovered_status = broker.handle_request(ServiceRequest::Status).await;
        assert!(matches!(
            recovered_status,
            ServiceResponse::Status(TunnelHealthState::Connected(_))
        ));

        // ShutdownTunnelOnExit tears down tunnel and removes .conf.
        assert_eq!(
            broker
                .handle_request(ServiceRequest::ShutdownTunnelOnExit)
                .await,
            ServiceResponse::Ok
        );
        assert!(!runtime.conf_path(DEFAULT_TUNNEL_NAME).exists());
        assert_eq!(
            broker.handle_request(ServiceRequest::Status).await,
            ServiceResponse::Status(TunnelHealthState::Disconnected)
        );

        // Reconnect and verify SessionLogoff tears down tunnel too.
        {
            let mut st = runtime.inner.lock().expect("lock");
            st.service_states = VecDeque::from([Ok(0), Ok(4)]);
            st.current_service_state = 4;
            st.default_uapi = Ok(uapi_with_handshake(&sample_key_hex(0xAB), now + 38));
        }
        assert_eq!(
            broker.handle_request(ServiceRequest::Connect(spec)).await,
            ServiceResponse::Ok
        );
        assert!(runtime.conf_path(DEFAULT_TUNNEL_NAME).exists());
        broker
            .handle_session_change(SessionChangeReason::SessionLogoff)
            .await
            .expect("session logoff teardown");
        assert!(!runtime.conf_path(DEFAULT_TUNNEL_NAME).exists());
        assert_eq!(
            broker.handle_request(ServiceRequest::Status).await,
            ServiceResponse::Status(TunnelHealthState::Disconnected)
        );

        // External service stop clears stale active metadata and reports Disconnected.
        {
            let mut st = runtime.inner.lock().expect("lock");
            st.service_states = VecDeque::from([Ok(0), Ok(4)]);
            st.current_service_state = 4;
        }
        assert_eq!(
            broker
                .handle_request(ServiceRequest::Connect(sample_spec()))
                .await,
            ServiceResponse::Ok
        );
        {
            let mut st = runtime.inner.lock().expect("lock");
            st.current_service_state = 0;
        }
        assert_eq!(
            broker.handle_request(ServiceRequest::Status).await,
            ServiceResponse::Status(TunnelHealthState::Disconnected)
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_pipe_newline_json_framing_and_error_handling() {
        let dir = unique_temp_dir("pipe_framing");
        let runtime = Arc::new(MockRuntime::new(dir.clone(), 1_700_000_500));
        let broker = Arc::new(TunnelBroker::new(runtime, test_config()));

        let (client_stream, server_stream) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(serve_pipe_stream(server_stream, broker));

        let (read_half, mut write_half) = tokio::io::split(client_stream);
        let mut reader = BufReader::new(read_half);

        let status_req = serde_json::to_string(&ServiceRequest::Status).expect("serialize");
        write_half
            .write_all(format!("{status_req}\n").as_bytes())
            .await
            .expect("write status req");
        write_half.flush().await.expect("flush");

        let mut resp_line = String::new();
        reader.read_line(&mut resp_line).await.expect("read resp");
        let decoded: ServiceResponse =
            serde_json::from_str(resp_line.trim()).expect("parse response");
        assert_eq!(
            decoded,
            ServiceResponse::Status(TunnelHealthState::Disconnected)
        );

        // Invalid JSON produces structured ServiceResponse::Error without closing stream.
        write_half
            .write_all(b"{invalid_json}\n")
            .await
            .expect("write bad json");
        write_half.flush().await.expect("flush");
        resp_line.clear();
        reader
            .read_line(&mut resp_line)
            .await
            .expect("read err resp");
        let err_decoded: ServiceResponse =
            serde_json::from_str(resp_line.trim()).expect("parse err response");
        assert!(matches!(
            err_decoded,
            ServiceResponse::Error { ref code, .. } if code == "INVALID_REQUEST"
        ));

        drop(write_half);
        drop(reader);
        server_task.await.expect("server task finishes cleanly");
        let _ = fs::remove_dir_all(&dir);
    }

    struct MockPipeInstance {
        stream: tokio::io::DuplexStream,
        accept_result: Option<io::Result<()>>,
        pend_accept: bool,
    }

    impl MockPipeInstance {
        fn ready(stream: tokio::io::DuplexStream, accept_result: io::Result<()>) -> Self {
            Self {
                stream,
                accept_result: Some(accept_result),
                pend_accept: false,
            }
        }

        fn pending(stream: tokio::io::DuplexStream) -> Self {
            Self {
                stream,
                accept_result: None,
                pend_accept: true,
            }
        }
    }

    impl PipeInstance for MockPipeInstance {
        fn accept_client<'a>(&'a mut self) -> BoxFuture<'a, io::Result<()>> {
            let pend = self.pend_accept;
            let res = self.accept_result.take();
            Box::pin(async move {
                if pend {
                    std::future::pending::<io::Result<()>>().await
                } else {
                    res.unwrap_or(Ok(()))
                }
            })
        }
    }

    impl AsyncRead for MockPipeInstance {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for MockPipeInstance {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            Pin::new(&mut self.stream).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_shutdown(cx)
        }
    }

    struct MockPipeFactory {
        create_results: Mutex<VecDeque<io::Result<MockPipeInstance>>>,
        calls: Mutex<Vec<bool>>,
    }

    impl MockPipeFactory {
        fn new(results: Vec<io::Result<MockPipeInstance>>) -> Self {
            Self {
                create_results: Mutex::new(VecDeque::from(results)),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl PipeServerFactory for MockPipeFactory {
        type Pipe = MockPipeInstance;

        fn create_pipe(&self, first_instance: bool) -> io::Result<Self::Pipe> {
            self.calls.lock().expect("lock").push(first_instance);
            self.create_results
                .lock()
                .expect("lock")
                .pop_front()
                .unwrap_or_else(|| {
                    Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "exhausted mock pipes",
                    ))
                })
        }
    }

    struct MockStatusReporter {
        states: Mutex<Vec<(ServiceState, u32)>>,
    }

    impl MockStatusReporter {
        fn new() -> Self {
            Self {
                states: Mutex::new(Vec::new()),
            }
        }

        fn states(&self) -> Vec<(ServiceState, u32)> {
            self.states.lock().expect("lock").clone()
        }
    }

    impl ServiceStatusReporter for MockStatusReporter {
        fn set_status(
            &self,
            state: ServiceState,
            _controls_accepted: ServiceControlAccept,
            _wait_hint: Duration,
            exit_code: ServiceExitCode,
        ) -> Result<(), String> {
            let code = match exit_code {
                ServiceExitCode::Win32(c) => c,
                ServiceExitCode::ServiceSpecific(c) => c,
            };
            self.states.lock().expect("lock").push((state, code));
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_pipe_startup_failure_prevents_running_and_transient_errors_retry() {
        let dir = unique_temp_dir("pipe_startup_retry");
        let runtime = Arc::new(MockRuntime::new(dir.clone(), 1_700_000_500));
        let broker = Arc::new(TunnelBroker::new(runtime.clone(), test_config()));

        // Part A: Initial pipe bind failure prevents ServiceState::Running.
        let failing_factory = Arc::new(MockPipeFactory::new(vec![Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "pipe squatted",
        ))]));
        let reporter = MockStatusReporter::new();
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let (_session_tx, session_rx) = tokio::sync::mpsc::unbounded_channel();
        let res = run_broker_lifecycle(
            &reporter,
            failing_factory.clone(),
            Arc::clone(&broker),
            shutdown_rx,
            session_rx,
            PipeServerBackoff {
                initial: Duration::from_millis(1),
                max: Duration::from_millis(4),
                max_consecutive_failures: 3,
            },
        )
        .await;
        assert!(res.is_err());
        assert_eq!(*failing_factory.calls.lock().expect("lock"), vec![true]);
        let recorded = reporter.states();
        assert!(!recorded.iter().any(|(st, _)| *st == ServiceState::Running));
        assert_eq!(
            recorded,
            vec![(ServiceState::StartPending, 0), (ServiceState::Stopped, 1)]
        );

        // Part B: Transient accept & rebind errors retry with bounded backoff, serve a client,
        // and only fail after max_consecutive_failures consecutive errors.
        let (_unused_client, unused_server) = tokio::io::duplex(1024);
        let (client_stream, ok_server) = tokio::io::duplex(4096);
        let (_tail_client, tail_server) = tokio::io::duplex(1024);

        let retry_factory = Arc::new(MockPipeFactory::new(vec![
            Ok(MockPipeInstance::ready(
                unused_server,
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "transient accept error",
                )),
            )),
            Err(io::Error::other("transient rebind 1")),
            Err(io::Error::other("transient rebind 2")),
            Ok(MockPipeInstance::ready(ok_server, Ok(()))),
            Ok(MockPipeInstance::ready(
                tail_server,
                Err(io::Error::other("terminal accept failure")),
            )),
            Err(io::Error::other("terminal rebind 1")),
            Err(io::Error::other("terminal rebind 2")),
        ]));

        let retry_reporter = MockStatusReporter::new();
        let (_shutdown_tx2, shutdown_rx2) = watch::channel(false);
        let (_session_tx2, session_rx2) = tokio::sync::mpsc::unbounded_channel();
        let backoff = PipeServerBackoff {
            initial: Duration::from_millis(1),
            max: Duration::from_millis(4),
            max_consecutive_failures: 4,
        };

        let client_task = tokio::spawn(async move {
            let (read_half, mut write_half) = tokio::io::split(client_stream);
            let mut reader = BufReader::new(read_half);
            let req = serde_json::to_string(&ServiceRequest::Status).expect("serialize");
            write_half
                .write_all(format!("{req}\n").as_bytes())
                .await
                .expect("write");
            write_half.flush().await.expect("flush");
            let mut line = String::new();
            reader.read_line(&mut line).await.expect("read");
            let decoded: ServiceResponse = serde_json::from_str(line.trim()).expect("parse");
            assert_eq!(
                decoded,
                ServiceResponse::Status(TunnelHealthState::Disconnected)
            );
        });

        let lifecycle_res = run_broker_lifecycle(
            &retry_reporter,
            retry_factory.clone(),
            broker,
            shutdown_rx2,
            session_rx2,
            backoff,
        )
        .await;
        client_task.await.expect("client succeeded across retries");
        assert!(lifecycle_res.is_err());
        assert_eq!(
            *retry_factory.calls.lock().expect("lock"),
            vec![true, false, false, false, false, false, false, false]
        );
        let retry_states = retry_reporter.states();
        assert!(retry_states
            .iter()
            .any(|(st, _)| *st == ServiceState::Running));
        assert_eq!(
            retry_states.last().copied(),
            Some((ServiceState::Stopped, 1))
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_pipe_sddl_omits_create_pipe_instance_and_allows_rw_data_client() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows::Win32::Security::{
            AclSizeInformation, CreateWellKnownSid, EqualSid, GetAce, GetAclInformation,
            GetSecurityDescriptorDacl, WinInteractiveSid, ACCESS_ALLOWED_ACE, ACL,
            ACL_SIZE_INFORMATION, PSID,
        };
        use windows::Win32::Storage::FileSystem::{
            FILE_CREATE_PIPE_INSTANCE, FILE_READ_DATA, FILE_WRITE_DATA,
        };

        assert_eq!(
            PIPE_SDDL_DACL,
            "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x0012019b;;;IU)"
        );

        // 1. Inspect the parsed DACL ACE for Interactive Users (IU) directly.
        let wide_sddl = to_wide_null(PIPE_SDDL_DACL).expect("wide sddl");
        let mut sd = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide_sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut sd,
                None,
            )
            .expect("parse PIPE_SDDL_DACL");
        }
        let _sd_guard = LocalFreeGuard(sd.0);

        let mut present = windows::core::BOOL(0);
        let mut pacl: *mut ACL = core::ptr::null_mut();
        let mut defaulted = windows::core::BOOL(0);
        unsafe {
            GetSecurityDescriptorDacl(sd, &mut present, &mut pacl, &mut defaulted)
                .expect("GetSecurityDescriptorDacl");
        }
        assert!(present.as_bool() && !pacl.is_null());

        let mut acl_info = ACL_SIZE_INFORMATION::default();
        unsafe {
            GetAclInformation(
                pacl.cast_const(),
                (&mut acl_info as *mut ACL_SIZE_INFORMATION).cast(),
                u32::try_from(core::mem::size_of::<ACL_SIZE_INFORMATION>()).unwrap(),
                AclSizeInformation,
            )
            .expect("GetAclInformation");
        }

        let mut iu_sid = vec![0u8; 68];
        let mut iu_sid_len = u32::try_from(iu_sid.len()).unwrap();
        let iu_psid = PSID(iu_sid.as_mut_ptr().cast());
        unsafe {
            CreateWellKnownSid(WinInteractiveSid, None, Some(iu_psid), &mut iu_sid_len)
                .expect("WinInteractiveSid");
        }

        let mut found_iu_mask = None;
        for idx in 0..acl_info.AceCount {
            let mut pace: *mut core::ffi::c_void = core::ptr::null_mut();
            unsafe {
                GetAce(pacl.cast_const(), idx, &mut pace).expect("GetAce");
            }
            let ace = unsafe { &*(pace as *const ACCESS_ALLOWED_ACE) };
            let sid_ptr = PSID(
                ((&ace.SidStart as *const u32).cast::<u8>())
                    .cast_mut()
                    .cast(),
            );
            if unsafe { EqualSid(sid_ptr, iu_psid) }.is_ok() {
                found_iu_mask = Some(ace.Mask);
            }
        }
        let iu_mask = found_iu_mask.expect("IU ACE present in PIPE_SDDL_DACL");
        assert_eq!(iu_mask, 0x0012_019b);
        assert_eq!(
            iu_mask & FILE_CREATE_PIPE_INSTANCE.0,
            0,
            "IU ACE must not grant FILE_CREATE_PIPE_INSTANCE"
        );

        // 2. Verify a local Named Pipe created with the IU-only 0x0012019b SDDL can be opened by a
        //    client requesting FILE_READ_DATA | FILE_WRITE_DATA and rejects extra pipe instances.
        let dir = unique_temp_dir("pipe_sddl_client");
        let runtime = Arc::new(MockRuntime::new(dir.clone(), 1_700_000_500));
        let broker = Arc::new(TunnelBroker::new(runtime, test_config()));
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let pipe_name = format!(
            r"\\.\pipe\FreetonVPNServiceTest_{}_{}",
            std::process::id(),
            nanos
        );
        let test_sddl = "D:(A;;GA;;;SY)(A;;0x0012019b;;;IU)";
        let server = create_secured_pipe_server(&pipe_name, test_sddl, true)
            .expect("create secured test pipe");

        // Second pipe instance creation without SY/BA must fail with PermissionDenied when IU
        // lacks FILE_CREATE_PIPE_INSTANCE.
        let squatter = create_secured_pipe_server(&pipe_name, test_sddl, false);
        assert!(
            matches!(squatter, Err(ref e) if e.kind() == io::ErrorKind::PermissionDenied),
            "expected PermissionDenied for unprivileged pipe instance, got {squatter:?}"
        );

        let server_task = tokio::spawn(async move {
            server.connect().await.expect("accept local test client");
            serve_pipe_stream(server, broker).await;
        });

        let pipe_name_for_client = pipe_name.clone();
        let client_handle = tokio::task::spawn_blocking(move || -> ServiceResponse {
            use std::io::{BufRead, BufReader as StdBufReader, Write};
            let mut file = std::fs::OpenOptions::new()
                .access_mode(FILE_READ_DATA.0 | FILE_WRITE_DATA.0)
                .open(&pipe_name_for_client)
                .expect("client opens pipe with FILE_READ_DATA | FILE_WRITE_DATA");
            let req = serde_json::to_string(&ServiceRequest::Status).expect("serialize");
            writeln!(file, "{req}").expect("write status");
            file.flush().expect("flush");
            let mut reader = StdBufReader::new(file);
            let mut line = String::new();
            reader.read_line(&mut line).expect("read response");
            serde_json::from_str(line.trim()).expect("deserialize response")
        });

        let resp = tokio::time::timeout(Duration::from_secs(5), client_handle)
            .await
            .expect("client pipe roundtrip timed out")
            .expect("client task");
        assert_eq!(
            resp,
            ServiceResponse::Status(TunnelHealthState::Disconnected)
        );
        tokio::time::timeout(Duration::from_secs(5), server_task)
            .await
            .expect("server pipe shutdown timed out")
            .expect("server task");

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_console_disconnect_tears_down_while_session_lock_keeps_tunnel() {
        assert!(should_teardown_on_session_change(
            SessionChangeReason::SessionLogoff
        ));
        assert!(should_teardown_on_session_change(
            SessionChangeReason::ConsoleDisconnect
        ));
        assert!(!should_teardown_on_session_change(
            SessionChangeReason::SessionLock
        ));
        assert!(!should_teardown_on_session_change(
            SessionChangeReason::SessionUnlock
        ));
        assert!(!should_teardown_on_session_change(
            SessionChangeReason::ConsoleConnect
        ));

        let dir = unique_temp_dir("console_disconnect");
        let now = 1_700_000_500;
        let runtime = Arc::new(MockRuntime::new(dir.clone(), now));
        {
            let mut st = runtime.inner.lock().expect("lock");
            st.service_states = VecDeque::from([Ok(0), Ok(4)]);
            st.current_service_state = 4;
            st.default_uapi = Ok(uapi_with_handshake(&sample_key_hex(0xAB), now - 2));
            st.default_dns = true;
        }

        let broker = Arc::new(TunnelBroker::new(runtime.clone(), test_config()));
        assert_eq!(
            broker
                .handle_request(ServiceRequest::Connect(sample_spec()))
                .await,
            ServiceResponse::Ok
        );
        assert!(runtime.conf_path(DEFAULT_TUNNEL_NAME).exists());

        // Drive events through run_broker_lifecycle's session channel as SCM would.
        let (_client_unused, server_unused) = tokio::io::duplex(1024);
        let factory = Arc::new(MockPipeFactory::new(vec![Ok(MockPipeInstance::pending(
            server_unused,
        ))]));
        let reporter = MockStatusReporter::new();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (session_tx, session_rx) = tokio::sync::mpsc::unbounded_channel();

        let broker_for_lifecycle = Arc::clone(&broker);
        let lifecycle_task = tokio::spawn(async move {
            run_broker_lifecycle(
                &reporter,
                factory,
                broker_for_lifecycle,
                shutdown_rx,
                session_rx,
                PipeServerBackoff::default(),
            )
            .await
        });

        // Wait briefly until Running is reached.
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Win+L (SessionLock) must leave the active tunnel connected and .conf intact.
        session_tx
            .send(SessionChangeReason::SessionLock)
            .expect("send SessionLock");
        tokio::time::sleep(Duration::from_millis(15)).await;
        assert!(runtime.conf_path(DEFAULT_TUNNEL_NAME).exists());
        assert!(matches!(
            broker.handle_request(ServiceRequest::Status).await,
            ServiceResponse::Status(TunnelHealthState::Connected(_))
        ));

        // Fast User Switching (ConsoleDisconnect) must tear down the tunnel and delete .conf.
        session_tx
            .send(SessionChangeReason::ConsoleDisconnect)
            .expect("send ConsoleDisconnect");
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!runtime.conf_path(DEFAULT_TUNNEL_NAME).exists());
        assert_eq!(
            broker.handle_request(ServiceRequest::Status).await,
            ServiceResponse::Status(TunnelHealthState::Disconnected)
        );

        let _ = shutdown_tx.send(true);
        lifecycle_task
            .await
            .expect("lifecycle join")
            .expect("clean service stop");
        let _ = fs::remove_dir_all(&dir);
    }

    struct BlockingRuntime {
        now: AtomicI64,
        tunnels_dir: PathBuf,
        uapi_entered: Arc<tokio::sync::Notify>,
        dns_entered: Arc<tokio::sync::Notify>,
        dns_release: Arc<tokio::sync::Notify>,
        block_uapi: std::sync::atomic::AtomicBool,
        block_dns: std::sync::atomic::AtomicBool,
        inner: Mutex<MockState>,
    }

    impl BlockingRuntime {
        fn new(tunnels_dir: PathBuf, now_unix: i64) -> Self {
            Self {
                now: AtomicI64::new(now_unix),
                tunnels_dir,
                uapi_entered: Arc::new(tokio::sync::Notify::new()),
                dns_entered: Arc::new(tokio::sync::Notify::new()),
                dns_release: Arc::new(tokio::sync::Notify::new()),
                block_uapi: std::sync::atomic::AtomicBool::new(false),
                block_dns: std::sync::atomic::AtomicBool::new(false),
                inner: Mutex::new(MockState {
                    events: Vec::new(),
                    service_states: VecDeque::new(),
                    current_service_state: 0,
                    uninstall_result: Ok(()),
                    install_result: Ok(()),
                    uapi_responses: VecDeque::new(),
                    default_uapi: Ok("errno=0\n".to_owned()),
                    dns_results: VecDeque::new(),
                    default_dns: true,
                    dns_calls: 0,
                }),
            }
        }

        fn conf_path(&self, tunnel_name: &str) -> PathBuf {
            self.tunnels_dir.join(format!("{tunnel_name}.conf"))
        }
    }

    impl TunnelRuntime for BlockingRuntime {
        fn now_unix(&self) -> i64 {
            self.now.load(Ordering::SeqCst)
        }

        fn service_state<'a>(&'a self, tunnel_name: &'a str) -> BoxFuture<'a, Result<u32, String>> {
            Box::pin(async move {
                let mut st = self.inner.lock().expect("lock");
                let res = match st.service_states.pop_front() {
                    Some(v) => {
                        if let Ok(code) = v {
                            st.current_service_state = code;
                        }
                        v
                    }
                    None => Ok(st.current_service_state),
                };
                if let Ok(code) = res {
                    st.events.push(format!("state:{tunnel_name}:{code}"));
                }
                res
            })
        }

        fn write_conf<'a>(
            &'a self,
            tunnel_name: &'a str,
            conf_content: &'a str,
        ) -> BoxFuture<'a, Result<PathBuf, String>> {
            Box::pin(async move {
                fs::create_dir_all(&self.tunnels_dir).map_err(|e| e.to_string())?;
                let path = self.conf_path(tunnel_name);
                fs::write(&path, conf_content).map_err(|e| e.to_string())?;
                self.inner
                    .lock()
                    .expect("lock")
                    .events
                    .push(format!("write_conf:{tunnel_name}"));
                Ok(path)
            })
        }

        fn remove_conf<'a>(&'a self, tunnel_name: &'a str) -> BoxFuture<'a, Result<(), String>> {
            Box::pin(async move {
                let path = self.conf_path(tunnel_name);
                match fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                    Err(err) => return Err(err.to_string()),
                }
                self.inner
                    .lock()
                    .expect("lock")
                    .events
                    .push(format!("remove_conf:{tunnel_name}"));
                Ok(())
            })
        }

        fn install_and_start_tunnel<'a>(
            &'a self,
            tunnel_name: &'a str,
            _conf_path: &'a Path,
        ) -> BoxFuture<'a, Result<(), String>> {
            Box::pin(async move {
                let mut st = self.inner.lock().expect("lock");
                st.events.push(format!("install:{tunnel_name}"));
                st.current_service_state = 4;
                Ok(())
            })
        }

        fn uninstall_tunnel<'a>(
            &'a self,
            tunnel_name: &'a str,
        ) -> BoxFuture<'a, Result<(), String>> {
            Box::pin(async move {
                let mut st = self.inner.lock().expect("lock");
                st.events.push(format!("uninstall:{tunnel_name}"));
                st.current_service_state = 0;
                Ok(())
            })
        }

        fn read_uapi_state<'a>(
            &'a self,
            tunnel_name: &'a str,
        ) -> BoxFuture<'a, Result<String, String>> {
            Box::pin(async move {
                if self.block_uapi.load(Ordering::SeqCst) {
                    self.uapi_entered.notify_one();
                    std::future::pending::<()>().await;
                }
                let mut st = self.inner.lock().expect("lock");
                st.events.push(format!("uapi:{tunnel_name}"));
                Ok(st.default_uapi.clone().unwrap_or_default())
            })
        }

        fn check_dns_through_tunnel<'a>(
            &'a self,
            _address: &'a str,
            _dns: &'a str,
            _timeout: Duration,
        ) -> BoxFuture<'a, bool> {
            Box::pin(async move {
                if self.block_dns.load(Ordering::SeqCst) {
                    let res = {
                        let mut st = self.inner.lock().expect("lock");
                        st.dns_calls += 1;
                        st.dns_results.pop_front().unwrap_or(st.default_dns)
                    };
                    self.dns_entered.notify_one();
                    self.dns_release.notified().await;
                    return res;
                }
                let mut st = self.inner.lock().expect("lock");
                st.dns_calls += 1;
                st.dns_results.pop_front().unwrap_or(st.default_dns)
            })
        }
    }

    #[tokio::test]
    async fn test_disconnect_shutdown_and_scm_cancel_abort_in_flight_connect_immediately() {
        let dir = unique_temp_dir("cancel_connect");
        let now = 1_700_000_500;
        let runtime = Arc::new(BlockingRuntime::new(dir.clone(), now));
        runtime.block_uapi.store(true, Ordering::SeqCst);

        let long_cfg = BrokerConfig {
            tunnel_name: DEFAULT_TUNNEL_NAME.to_owned(),
            service_wait_timeout: Duration::from_secs(20),
            service_poll_interval: Duration::from_millis(5),
            connect_timeout: Duration::from_secs(30),
            handshake_poll_interval: Duration::from_secs(5),
            dns_probe_timeout: Duration::from_secs(5),
            dns_recheck_interval: Duration::from_secs(30),
        };
        let broker = Arc::new(TunnelBroker::new(Arc::clone(&runtime), long_cfg));

        // Case 1: Disconnect cancels in-flight Connect immediately and cleans up partial tunnel.
        let b_conn = Arc::clone(&broker);
        let connect_task = tokio::spawn(async move {
            b_conn
                .handle_request(ServiceRequest::Connect(sample_spec()))
                .await
        });

        tokio::time::timeout(Duration::from_secs(2), runtime.uapi_entered.notified())
            .await
            .expect("connect entered wait_for_connection");

        let disc_resp = tokio::time::timeout(
            Duration::from_secs(1),
            broker.handle_request(ServiceRequest::Disconnect),
        )
        .await
        .expect("Disconnect must not wait 30s for in-flight Connect");
        assert_eq!(disc_resp, ServiceResponse::Ok);

        let conn_resp = tokio::time::timeout(Duration::from_secs(1), connect_task)
            .await
            .expect("Connect task finishes promptly")
            .expect("join");
        assert!(matches!(
            conn_resp,
            ServiceResponse::Error { ref code, .. } if code == "CONNECT_CANCELLED"
        ));
        assert!(!runtime.conf_path(DEFAULT_TUNNEL_NAME).exists());
        assert_eq!(
            broker.handle_request(ServiceRequest::Status).await,
            ServiceResponse::Status(TunnelHealthState::Disconnected)
        );

        // Case 2: Subsequent normal Connect works cleanly (cancellation was per-connect).
        runtime.block_uapi.store(false, Ordering::SeqCst);
        {
            let mut st = runtime.inner.lock().expect("lock");
            st.default_uapi = Ok(uapi_with_handshake(&sample_key_hex(0xAB), now - 1));
            st.default_dns = true;
        }
        assert_eq!(
            broker
                .handle_request(ServiceRequest::Connect(sample_spec()))
                .await,
            ServiceResponse::Ok
        );
        assert_eq!(
            broker
                .handle_request(ServiceRequest::ShutdownTunnelOnExit)
                .await,
            ServiceResponse::Ok
        );

        // Case 3: ShutdownTunnelOnExit cancels an in-flight Connect immediately.
        runtime.block_uapi.store(true, Ordering::SeqCst);
        let b_conn2 = Arc::clone(&broker);
        let connect_task2 = tokio::spawn(async move {
            b_conn2
                .handle_request(ServiceRequest::Connect(sample_spec()))
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), runtime.uapi_entered.notified())
            .await
            .expect("second connect entered wait_for_connection");
        let exit_resp = tokio::time::timeout(
            Duration::from_secs(1),
            broker.handle_request(ServiceRequest::ShutdownTunnelOnExit),
        )
        .await
        .expect("ShutdownTunnelOnExit must abort Connect immediately");
        assert_eq!(exit_resp, ServiceResponse::Ok);
        let conn_resp2 = tokio::time::timeout(Duration::from_secs(1), connect_task2)
            .await
            .expect("second Connect finishes")
            .expect("join");
        assert!(matches!(
            conn_resp2,
            ServiceResponse::Error { ref code, .. } if code == "CONNECT_CANCELLED"
        ));

        // Case 4: SCM Stop (via run_broker_lifecycle shutdown_tx) cancels in-flight Connect immediately.
        let (_client_unused, server_unused) = tokio::io::duplex(1024);
        let factory = Arc::new(MockPipeFactory::new(vec![Ok(MockPipeInstance::pending(
            server_unused,
        ))]));
        let reporter = MockStatusReporter::new();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (_session_tx, session_rx) = tokio::sync::mpsc::unbounded_channel();

        let b_life = Arc::clone(&broker);
        let life_task = tokio::spawn(async move {
            run_broker_lifecycle(
                &reporter,
                factory,
                b_life,
                shutdown_rx,
                session_rx,
                PipeServerBackoff::default(),
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(10)).await;

        let b_conn3 = Arc::clone(&broker);
        let connect_task3 = tokio::spawn(async move {
            b_conn3
                .handle_request(ServiceRequest::Connect(sample_spec()))
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), runtime.uapi_entered.notified())
            .await
            .expect("third connect entered wait_for_connection");

        let _ = shutdown_tx.send(true);
        tokio::time::timeout(Duration::from_secs(1), life_task)
            .await
            .expect("SCM Stop lifecycle must complete immediately")
            .expect("join")
            .expect("clean stop");
        let conn_resp3 = tokio::time::timeout(Duration::from_secs(1), connect_task3)
            .await
            .expect("third Connect finishes")
            .expect("join");
        assert!(matches!(
            conn_resp3,
            ServiceResponse::Error { ref code, .. } if code == "CONNECT_CANCELLED"
        ));
        assert!(!runtime.conf_path(DEFAULT_TUNNEL_NAME).exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_generation_prevents_same_second_stale_status_clobber() {
        let dir = unique_temp_dir("generation_guard");
        let same_second = 1_700_000_500;
        let runtime = Arc::new(BlockingRuntime::new(dir.clone(), same_second));
        {
            let mut st = runtime.inner.lock().expect("lock");
            st.default_uapi = Ok(uapi_with_handshake(&sample_key_hex(0xAB), same_second - 1));
            st.default_dns = true;
        }

        let broker = Arc::new(TunnelBroker::new(
            Arc::clone(&runtime),
            BrokerConfig {
                dns_recheck_interval: Duration::from_secs(30),
                ..test_config()
            },
        ));

        // 1. Connect session 1 at `same_second`.
        assert_eq!(
            broker
                .handle_request(ServiceRequest::Connect(sample_spec()))
                .await,
            ServiceResponse::Ok
        );
        let gen1 = broker.state.lock().expect("lock").generation;

        // Trigger a DNS recheck in handle_status for session 1 and pause inside check_dns_through_tunnel.
        runtime.now.store(same_second + 40, Ordering::SeqCst);
        {
            let mut st = runtime.inner.lock().expect("lock");
            st.default_uapi = Ok(uapi_with_handshake(&sample_key_hex(0xAB), same_second + 35));
            st.dns_results = VecDeque::from([false]); // stale check will fail
        }
        runtime.block_dns.store(true, Ordering::SeqCst);
        let b_status = Arc::clone(&broker);
        let stale_status_task =
            tokio::spawn(async move { b_status.handle_request(ServiceRequest::Status).await });
        tokio::time::timeout(Duration::from_secs(2), runtime.dns_entered.notified())
            .await
            .expect("stale handle_status paused inside check_dns_through_tunnel");

        // 2. While stale status check is paused, disconnect & reconnect session 2 at `same_second`!
        runtime.block_dns.store(false, Ordering::SeqCst);
        runtime.now.store(same_second, Ordering::SeqCst);
        {
            let mut st = runtime.inner.lock().expect("lock");
            st.default_uapi = Ok(uapi_with_handshake(&sample_key_hex(0xAB), same_second - 1));
            st.default_dns = true;
        }
        assert_eq!(
            broker.handle_request(ServiceRequest::Disconnect).await,
            ServiceResponse::Ok
        );
        assert_eq!(
            broker
                .handle_request(ServiceRequest::Connect(sample_spec()))
                .await,
            ServiceResponse::Ok
        );
        let gen2 = broker.state.lock().expect("lock").generation;
        assert!(gen2 > gen1);

        // 3. Release paused stale status from session 1 (returns DNS=false and calls invalidate_dns_cache(gen1)).
        runtime.dns_release.notify_one();
        let stale_resp = stale_status_task.await.expect("join stale status");
        assert!(matches!(
            stale_resp,
            ServiceResponse::Status(TunnelHealthState::Unverified { .. })
        ));

        // 4. Direct calls with stale `gen1` must NOT clear or alter session 2's Active phase or DNS cache!
        broker.clear_stale_active(gen1);
        broker.invalidate_dns_cache(gen1);
        broker.mark_dns_verified(gen1, same_second + 999);
        {
            let st = broker.state.lock().expect("lock");
            assert_eq!(st.generation, gen2);
            assert!(matches!(st.phase, BrokerPhase::Active(_)));
            assert_eq!(st.last_dns_verified_unix, Some(same_second));
        }

        let _ = fs::remove_dir_all(&dir);
    }
}
