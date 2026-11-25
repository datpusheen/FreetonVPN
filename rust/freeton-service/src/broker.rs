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
use tokio::sync::{watch, Mutex as AsyncMutex, Notify};
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
pub const PIPE_SDDL_DACL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";
pub const HANDSHAKE_MAX_AGE_SECS: i64 = 180;
pub const MAX_IPC_LINE_BYTES: usize = 64 * 1024;

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
}

impl Default for BrokerState {
    fn default() -> Self {
        Self {
            phase: BrokerPhase::Idle,
            last_dns_verified_unix: None,
        }
    }
}

pub struct TunnelBroker<R: TunnelRuntime> {
    runtime: Arc<R>,
    config: BrokerConfig,
    mutation_lock: AsyncMutex<()>,
    state: Mutex<BrokerState>,
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
        Self {
            runtime,
            config,
            mutation_lock: AsyncMutex::new(()),
            state: Mutex::new(BrokerState::default()),
        }
    }

    pub async fn handle_request(&self, req: ServiceRequest) -> ServiceResponse {
        match req {
            ServiceRequest::Connect(spec) => self.handle_connect(spec).await,
            ServiceRequest::Disconnect | ServiceRequest::ShutdownTunnelOnExit => {
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

    pub async fn handle_session_logoff(&self) -> Result<(), String> {
        info!("Windows session logoff detected; tearing down active tunnel");
        self.teardown_locked().await
    }

    pub async fn shutdown_for_service_stop(&self) {
        if let Err(err) = self.teardown_locked().await {
            warn!("failed tearing down tunnel during service stop: {err}");
        }
    }

    async fn wait_for_service_state(&self, expected_state: u32) -> Result<(), String> {
        let deadline = Instant::now() + self.config.service_wait_timeout;
        loop {
            let state = self.runtime.service_state(&self.config.tunnel_name).await?;
            if state == expected_state {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(
                    "WireGuard Service chưa hoàn tất thay đổi trạng thái. Vui lòng thử lại."
                        .to_owned(),
                );
            }
            tokio::time::sleep(self.config.service_poll_interval).await;
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
            self.wait_for_service_state(0).await?;
        }
        // Keep the .conf file if service uninstall failed above; only remove after absent.
        self.runtime.remove_conf(&self.config.tunnel_name).await?;
        Ok(())
    }

    async fn teardown_locked(&self) -> Result<(), String> {
        let _guard = self.mutation_lock.lock().await;
        self.disconnect_while_locked().await?;
        let mut st = self.state.lock().expect("broker state lock poisoned");
        st.phase = BrokerPhase::Idle;
        st.last_dns_verified_unix = None;
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
        let prev_state = self
            .state
            .lock()
            .expect("broker state lock poisoned")
            .clone();
        {
            let mut st = self.state.lock().expect("broker state lock poisoned");
            st.phase = BrokerPhase::Connecting;
            st.last_dns_verified_unix = None;
        }

        if let Err(err) = self.disconnect_while_locked().await {
            *self.state.lock().expect("broker state lock poisoned") = prev_state;
            return ServiceResponse::Error {
                code: "DISCONNECT_FAILED".to_owned(),
                message: err,
            };
        }

        let info = build_active_info(&spec, self.runtime.now_unix());
        {
            let mut st = self.state.lock().expect("broker state lock poisoned");
            st.phase = BrokerPhase::Verifying(info.clone());
        }

        match self.install_and_verify(&conf_content, &info).await {
            Ok(()) => {
                let mut st = self.state.lock().expect("broker state lock poisoned");
                st.phase = BrokerPhase::Active(info);
                st.last_dns_verified_unix = Some(self.runtime.now_unix());
                ServiceResponse::Ok
            }
            Err((code, message)) => {
                let cleanup_res = self.disconnect_while_locked().await;
                let mut st = self.state.lock().expect("broker state lock poisoned");
                st.phase = BrokerPhase::Idle;
                st.last_dns_verified_unix = None;

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
    ) -> Result<(), (&'static str, String)> {
        let conf_path = self
            .runtime
            .write_conf(&self.config.tunnel_name, conf_content)
            .await
            .map_err(|e| ("CONF_WRITE_FAILED", e))?;

        self.runtime
            .install_and_start_tunnel(&self.config.tunnel_name, &conf_path)
            .await
            .map_err(|e| ("INSTALL_FAILED", e))?;

        self.wait_for_service_state(SERVICE_RUNNING_STATE)
            .await
            .map_err(|e| ("SERVICE_START_TIMEOUT", e))?;

        self.wait_for_connection(info).await
    }

    async fn wait_for_connection(
        &self,
        info: &ActiveTunnelInfo,
    ) -> Result<(), (&'static str, String)> {
        let deadline = Instant::now() + self.config.connect_timeout;
        let mut handshaken = false;

        while Instant::now() < deadline {
            let state = self
                .runtime
                .service_state(&self.config.tunnel_name)
                .await
                .map_err(|e| ("SCM_ERROR", e))?;
            if state != SERVICE_RUNNING_STATE {
                return Err((
                    "SERVICE_STOPPED",
                    "WireGuard Service đã dừng trước khi kết nối hoàn tất.".to_owned(),
                ));
            }

            handshaken = match self.runtime.read_uapi_state(&self.config.tunnel_name).await {
                Ok(uapi) => {
                    let stamp = parse_uapi_latest_handshake(&uapi, &info.x25519_pubkey);
                    is_fresh_handshake(stamp, self.runtime.now_unix())
                }
                Err(_) => false,
            };

            if handshaken {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let dns_budget = self
                    .config
                    .dns_probe_timeout
                    .min(remaining.max(Duration::from_millis(1)));
                if self
                    .runtime
                    .check_dns_through_tunnel(&info.address, &info.dns, dns_budget)
                    .await
                {
                    return Ok(());
                }
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            tokio::time::sleep(self.config.handshake_poll_interval.min(remaining)).await;
        }

        if handshaken {
            Err((
                "DNS_FAILED",
                "WireGuard đã bắt tay nhưng DNS qua VPN chưa phản hồi. Hãy kiểm tra DNS trong Cài đặt hoặc chọn máy chủ khác.".to_owned(),
            ))
        } else {
            Err((
                "HANDSHAKE_TIMEOUT",
                "Máy chủ chưa phản hồi handshake WireGuard. Hãy thử máy chủ khác, kiểm tra cổng UDP hoặc cấp lại WireGuard Key trong Cài đặt.".to_owned(),
            ))
        }
    }

    async fn handle_status(&self) -> TunnelHealthState {
        let snapshot = self
            .state
            .lock()
            .expect("broker state lock poisoned")
            .clone();
        let (info, last_dns_verified_unix) = match snapshot.phase {
            BrokerPhase::Idle => return TunnelHealthState::Disconnected,
            BrokerPhase::Connecting => return TunnelHealthState::Connecting,
            BrokerPhase::Verifying(info) => return TunnelHealthState::Verifying(info),
            BrokerPhase::Active(info) => (info, snapshot.last_dns_verified_unix),
        };

        match self.runtime.service_state(&self.config.tunnel_name).await {
            Ok(state) if state == SERVICE_RUNNING_STATE => {}
            Ok(_) => {
                self.clear_stale_active(info.connected_at_unix);
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
                self.invalidate_dns_cache(info.connected_at_unix);
                return TunnelHealthState::Unverified {
                    info,
                    reason: format!("Không đọc được handshake WireGuard: {err}"),
                };
            }
        };

        let now = self.runtime.now_unix();
        let stamp = parse_uapi_latest_handshake(&uapi, &info.x25519_pubkey);
        if !is_fresh_handshake(stamp, now) {
            self.invalidate_dns_cache(info.connected_at_unix);
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
                self.invalidate_dns_cache(info.connected_at_unix);
                return TunnelHealthState::Unverified {
                    info,
                    reason: "DNS qua VPN chưa phản hồi.".to_owned(),
                };
            }
            self.mark_dns_verified(info.connected_at_unix, self.runtime.now_unix());
        }

        TunnelHealthState::Connected(info)
    }

    fn clear_stale_active(&self, expected_connected_at: i64) {
        let mut st = self.state.lock().expect("broker state lock poisoned");
        if matches!(&st.phase, BrokerPhase::Active(cur) if cur.connected_at_unix == expected_connected_at)
        {
            st.phase = BrokerPhase::Idle;
            st.last_dns_verified_unix = None;
        }
    }

    fn invalidate_dns_cache(&self, expected_connected_at: i64) {
        let mut st = self.state.lock().expect("broker state lock poisoned");
        if matches!(&st.phase, BrokerPhase::Active(cur) if cur.connected_at_unix == expected_connected_at)
        {
            st.last_dns_verified_unix = None;
        }
    }

    fn mark_dns_verified(&self, expected_connected_at: i64, verified_at: i64) {
        let mut st = self.state.lock().expect("broker state lock poisoned");
        if matches!(&st.phase, BrokerPhase::Active(cur) if cur.connected_at_unix == expected_connected_at)
        {
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

pub async fn run_pipe_server<R: TunnelRuntime>(
    pipe_name: String,
    broker: Arc<TunnelBroker<R>>,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    let mut server = create_secured_pipe_server(&pipe_name, PIPE_SDDL_DACL, true)?;
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            biased;
            _ = wait_for_shutdown(&mut shutdown) => {
                break;
            }
            conn = server.connect() => {
                match conn {
                    Ok(()) => {
                        let connected_stream = server;
                        server = create_secured_pipe_server(&pipe_name, PIPE_SDDL_DACL, false)?;
                        let broker_clone = Arc::clone(&broker);
                        tokio::spawn(async move {
                            serve_pipe_stream(connected_stream, broker_clone).await;
                        });
                    }
                    Err(err) => {
                        warn!("named pipe accept error: {err}");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        server = create_secured_pipe_server(&pipe_name, PIPE_SDDL_DACL, false)?;
                    }
                }
            }
        }
    }
    Ok(())
}

define_windows_service!(ffi_broker_service_main, broker_service_main);

fn broker_service_main(_arguments: Vec<OsString>) {
    if let Err(err) = run_broker_service_inner() {
        error!("FreetonVPNService exited with error: {err}");
    }
}

fn set_service_status_checked(
    handle: &service_control_handler::ServiceStatusHandle,
    state: ServiceState,
    controls_accepted: ServiceControlAccept,
    wait_hint: Duration,
    exit_code: ServiceExitCode,
) -> Result<(), String> {
    handle
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

fn run_broker_service_inner() -> Result<(), String> {
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let logoff_notify = Arc::new(Notify::new());

    let logoff_for_handler = Arc::clone(&logoff_notify);

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(true);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::SessionChange(param) => {
                if param.reason == SessionChangeReason::SessionLogoff {
                    logoff_for_handler.notify_one();
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(BROKER_SERVICE_NAME, event_handler)
        .map_err(|e| format!("register control handler failed: {e}"))?;

    set_service_status_checked(
        &status_handle,
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        Duration::from_secs(5),
        ServiceExitCode::Win32(0),
    )?;

    let service_exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let runtime = Arc::new(WindowsTunnelRuntime::new(
        default_tunnels_dir(),
        service_exe,
    ));
    let broker = Arc::new(TunnelBroker::new(runtime, BrokerConfig::default()));

    let tokio_rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("failed to create Tokio runtime: {e}"))?;

    let exit_result: Result<(), String> = tokio_rt.block_on(async {
        let logoff_broker = Arc::clone(&broker);
        let mut logoff_shutdown = shutdown_rx.clone();
        let logoff_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = wait_for_shutdown(&mut logoff_shutdown) => break,
                    _ = logoff_notify.notified() => {
                        if let Err(err) = logoff_broker.handle_session_logoff().await {
                            warn!("logoff tunnel teardown error: {err}");
                        }
                    }
                }
            }
        });

        let pipe_broker = Arc::clone(&broker);
        let pipe_shutdown = shutdown_rx.clone();
        let pipe_task = tokio::spawn(async move {
            run_pipe_server(SERVICE_PIPE_NAME.to_owned(), pipe_broker, pipe_shutdown).await
        });

        set_service_status_checked(
            &status_handle,
            ServiceState::Running,
            ServiceControlAccept::STOP
                | ServiceControlAccept::SHUTDOWN
                | ServiceControlAccept::SESSION_CHANGE,
            Duration::ZERO,
            ServiceExitCode::Win32(0),
        )?;

        wait_for_shutdown(&mut shutdown_rx).await;

        let _ = set_service_status_checked(
            &status_handle,
            ServiceState::StopPending,
            ServiceControlAccept::empty(),
            Duration::from_secs(15),
            ServiceExitCode::Win32(0),
        );

        let _ = logoff_task.await;
        if let Ok(Err(err)) = pipe_task.await {
            warn!("pipe server stopped with error: {err}");
        }
        broker.shutdown_for_service_stop().await;
        Ok(())
    });

    let exit_code = if exit_result.is_ok() {
        ServiceExitCode::Win32(0)
    } else {
        ServiceExitCode::Win32(1)
    };
    let _ = set_service_status_checked(
        &status_handle,
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        Duration::ZERO,
        exit_code,
    );

    exit_result
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
            .handle_session_logoff()
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
}
