use std::fmt::Write as _;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::api::ServerNode;
use crate::ping::get_country_display;
use crate::storage::{ClientConfig, DEFAULT_WG_ADDRESS, DEFAULT_WG_DNS, DEFAULT_WG_PORT};

/// Windows Named Pipe exposed by `FreetonVPNService` for IPC with `FreetonVPN.exe`.
pub const SERVICE_PIPE_NAME: &str = r"\\.\pipe\FreetonVPNService";

/// Default WireGuard tunnel interface and Windows service suffix (`WireGuardTunnel$FreetonVPN`).
pub const DEFAULT_TUNNEL_NAME: &str = "FreetonVPN";

/// WireGuard tunnel interface MTU matching `proton_warp_material_gui.py`.
pub const DEFAULT_WG_MTU: u16 = 1380;

/// WireGuard `AllowedIPs` value routing IPv4 traffic through the tunnel.
pub const DEFAULT_WG_ALLOWED_IPS: &str = "0.0.0.0/0";

/// WireGuard `PersistentKeepalive` interval in seconds.
pub const DEFAULT_WG_PERSISTENT_KEEPALIVE: u16 = 25;

const DNS_PORT: u16 = 53;
const DNS_FLAG_RESPONSE: u16 = 0x8000;
const DNS_FLAG_ERROR_OR_TRUNCATED_MASK: u16 = 0x020F;
const DNS_QUERY_QUESTION_ACCOUNT_PROTONVPN_COM: &[u8] =
    b"\x07account\x09protonvpn\x03com\x00\x00\x01\x00\x01";

/// Errors returned during WireGuard configuration validation and generation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WgError {
    #[error("Cấu hình WireGuard không hợp lệ: {0}")]
    InvalidInput(String),
}

/// Strictly validated WireGuard tunnel parameters transferred between `freeton-app` and `freeton-service`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatedTunnelSpec {
    pub server_name: String,
    pub country: String,
    pub domain: String,
    pub entry_ip: String,
    pub server_pubkey: String,
    pub private_key: String,
    pub address: String,
    pub dns: String,
    pub port: u16,
}

/// Commands sent from `freeton-app` to `FreetonVPNService` over `SERVICE_PIPE_NAME`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceRequest {
    Connect(ValidatedTunnelSpec),
    Disconnect,
    Status,
    ShutdownTunnelOnExit,
}

/// Metadata describing the currently active or verifying WireGuard tunnel held by `FreetonVPNService`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveTunnelInfo {
    pub server_name: String,
    pub country: String,
    pub entry_ip: String,
    pub x25519_pubkey: String,
    pub address: String,
    pub dns: String,
    pub port: u16,
    pub connected_at_unix: i64,
}

/// Reported WireGuard tunnel lifecycle and verification state returned by `FreetonVPNService`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TunnelHealthState {
    Disconnected,
    Connecting,
    Verifying(ActiveTunnelInfo),
    Connected(ActiveTunnelInfo),
    Unverified {
        info: ActiveTunnelInfo,
        reason: String,
    },
}

/// Structured IPC response returned by `FreetonVPNService` over `SERVICE_PIPE_NAME`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceResponse {
    Ok,
    Status(TunnelHealthState),
    Error { code: String, message: String },
}

fn reject_control_chars(field: &str, value: &str) -> Result<(), WgError> {
    if value.chars().any(char::is_control) {
        return Err(WgError::InvalidInput(format!(
            "{field} contains disallowed control or newline characters"
        )));
    }
    Ok(())
}

fn validate_metadata_text(field: &str, value: &str) -> Result<String, WgError> {
    reject_control_chars(field, value)?;
    Ok(value.trim().to_owned())
}

pub fn validate_wg_key(field: &str, raw: &str) -> Result<String, WgError> {
    reject_control_chars(field, raw)?;
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_whitespace) {
        return Err(WgError::InvalidInput(format!(
            "{field} must be a non-empty 32-byte base64 WireGuard key"
        )));
    }
    let decoded = STANDARD
        .decode(trimmed)
        .map_err(|_| WgError::InvalidInput(format!("{field} is not valid base64")))?;
    if decoded.len() != 32 {
        return Err(WgError::InvalidInput(format!(
            "{field} must decode to 32 bytes, got {} bytes",
            decoded.len()
        )));
    }
    Ok(trimmed.to_owned())
}

fn parse_cidr_ip(token: &str) -> Option<(IpAddr, Option<u8>)> {
    if token.is_empty() || token.chars().any(char::is_whitespace) {
        return None;
    }
    if let Some((ip_part, prefix_part)) = token.split_once('/') {
        let ip = ip_part.parse::<IpAddr>().ok()?;
        if prefix_part.is_empty() || !prefix_part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let prefix = prefix_part.parse::<u8>().ok()?;
        let max_prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max_prefix {
            return None;
        }
        Some((ip, Some(prefix)))
    } else {
        let ip = token.parse::<IpAddr>().ok()?;
        Some((ip, None))
    }
}

pub fn validate_address_list(raw: &str) -> Result<String, WgError> {
    reject_control_chars("address", raw)?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(WgError::InvalidInput(
            "address must contain at least one IP or CIDR".to_owned(),
        ));
    }

    let mut normalized = Vec::new();
    for item in trimmed.split(',') {
        let token = item.trim();
        let (ip, prefix) = parse_cidr_ip(token).ok_or_else(|| {
            WgError::InvalidInput(format!("invalid WireGuard interface address: {token:?}"))
        })?;
        match prefix {
            Some(len) => normalized.push(format!("{ip}/{len}")),
            None => normalized.push(ip.to_string()),
        }
    }

    Ok(normalized.join(", "))
}

pub fn validate_dns_list(raw: &str) -> Result<String, WgError> {
    reject_control_chars("dns", raw)?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(WgError::InvalidInput(
            "dns must contain at least one IP address".to_owned(),
        ));
    }

    let mut normalized = Vec::new();
    for item in trimmed.split(',') {
        let token = item.trim();
        if token.is_empty() || token.chars().any(char::is_whitespace) {
            return Err(WgError::InvalidInput(format!(
                "invalid WireGuard DNS server entry: {token:?}"
            )));
        }
        let ip = token.parse::<IpAddr>().map_err(|_| {
            WgError::InvalidInput(format!("invalid WireGuard DNS IP address: {token:?}"))
        })?;
        normalized.push(ip.to_string());
    }

    Ok(normalized.join(", "))
}

pub fn validate_port_str(raw: &str) -> Result<u16, WgError> {
    reject_control_chars("port", raw)?;
    let trimmed = raw.trim();
    if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return Err(WgError::InvalidInput(format!(
            "port must be an integer between 1 and 65535, got {trimmed:?}"
        )));
    }
    let port = trimmed.parse::<u16>().map_err(|_| {
        WgError::InvalidInput(format!("port {trimmed:?} is out of range (1..=65535)"))
    })?;
    if port == 0 {
        return Err(WgError::InvalidInput(
            "port must be between 1 and 65535 (got 0)".to_owned(),
        ));
    }
    Ok(port)
}

fn validate_entry_ip(raw: &str) -> Result<String, WgError> {
    reject_control_chars("entry_ip", raw)?;
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_whitespace) {
        return Err(WgError::InvalidInput(
            "entry_ip must be a non-empty IPv4, IPv6, or strict hostname".to_owned(),
        ));
    }

    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }

    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        let inner = &trimmed[1..trimmed.len() - 1];
        if let Ok(v6) = inner.parse::<Ipv6Addr>() {
            return Ok(v6.to_string());
        }
        return Err(WgError::InvalidInput(format!(
            "invalid bracketed IPv6 endpoint: {trimmed:?}"
        )));
    }

    if trimmed.len() > 253 {
        return Err(WgError::InvalidInput(
            "hostname exceeds maximum length of 253 bytes".to_owned(),
        ));
    }

    let labels: Vec<&str> = trimmed.split('.').collect();
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return Err(WgError::InvalidInput(format!(
                "invalid endpoint hostname label in {trimmed:?}"
            )));
        }
        let bytes = label.as_bytes();
        if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
            return Err(WgError::InvalidInput(format!(
                "hostname label cannot start or end with '-': {trimmed:?}"
            )));
        }
        if !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            return Err(WgError::InvalidInput(format!(
                "invalid endpoint address or hostname: {trimmed:?}"
            )));
        }
    }

    // Reject all-numeric final labels (e.g. malformed IPv4 like "192.0.2.999") per RFC 3696 §2.
    let last_label = labels.last().copied().unwrap_or("");
    if !last_label.bytes().any(|b| b.is_ascii_alphabetic()) {
        return Err(WgError::InvalidInput(format!(
            "invalid endpoint IP address: {trimmed:?}"
        )));
    }

    Ok(trimmed.to_owned())
}

fn format_endpoint(entry_ip: &str, port: u16) -> String {
    if entry_ip.parse::<Ipv6Addr>().is_ok() {
        format!("[{entry_ip}]:{port}")
    } else {
        format!("{entry_ip}:{port}")
    }
}

fn normalize_and_validate_spec(
    spec: &ValidatedTunnelSpec,
) -> Result<(ValidatedTunnelSpec, String), WgError> {
    if spec.port == 0 {
        return Err(WgError::InvalidInput(
            "port must be between 1 and 65535 (got 0)".to_owned(),
        ));
    }

    let server_name = validate_metadata_text("server_name", &spec.server_name)?;
    let country = validate_metadata_text("country", &spec.country)?;
    let domain = validate_metadata_text("domain", &spec.domain)?;
    let entry_ip = validate_entry_ip(&spec.entry_ip)?;
    let server_pubkey = validate_wg_key("server_pubkey", &spec.server_pubkey)?;
    let private_key = validate_wg_key("private_key", &spec.private_key)?;
    let address = validate_address_list(&spec.address)?;
    let dns = validate_dns_list(&spec.dns)?;

    let normalized = ValidatedTunnelSpec {
        server_name,
        country,
        domain,
        entry_ip,
        server_pubkey,
        private_key,
        address,
        dns,
        port: spec.port,
    };

    let display_server_name = if normalized.server_name.is_empty() {
        "Proton Server"
    } else {
        normalized.server_name.as_str()
    };
    let country_display = get_country_display(&normalized.country);
    let endpoint = format_endpoint(&normalized.entry_ip, normalized.port);

    let conf = format!(
        "# ==========================================\n\
         # Freeton VPN WireGuard Configuration\n\
         # Bản VPN Proton không chính thức phát triển bởi pishun\n\
         # Server: {display_server_name}\n\
         # Quốc gia: {country_display}\n\
         # Domain Server: {}\n\
         # IP Cổng vào: {}\n\
         # ==========================================\n\
         \n\
         [Interface]\n\
         PrivateKey = {}\n\
         Address = {}\n\
         DNS = {}\n\
         MTU = {DEFAULT_WG_MTU}\n\
         \n\
         [Peer]\n\
         PublicKey = {}\n\
         AllowedIPs = {DEFAULT_WG_ALLOWED_IPS}\n\
         Endpoint = {endpoint}\n\
         PersistentKeepalive = {DEFAULT_WG_PERSISTENT_KEEPALIVE}\n",
        normalized.domain,
        normalized.entry_ip,
        normalized.private_key,
        normalized.address,
        normalized.dns,
        normalized.server_pubkey,
    );

    Ok((normalized, conf))
}

/// Validates every field of an existing `ValidatedTunnelSpec` (for example after deserializing a
/// Named Pipe `ServiceRequest::Connect`) and renders the hardened WireGuard `.conf` contents.
pub fn validate_tunnel_spec(spec: &ValidatedTunnelSpec) -> Result<String, WgError> {
    let (_, conf) = normalize_and_validate_spec(spec)?;
    Ok(conf)
}

/// Validates Proton server metadata and WireGuard client configuration against directive/control-char
/// injection and malformed fields, returning `(ValidatedTunnelSpec, conf_content)`.
pub fn validate_and_build_conf(
    server: &ServerNode,
    config: &ClientConfig,
) -> Result<(ValidatedTunnelSpec, String), WgError> {
    // Reject control chars across all raw fields before trimming or applying fallbacks so trailing
    // newlines or hidden lines cannot be masked.
    reject_control_chars("server.name", &server.name)?;
    reject_control_chars("server.country", &server.country)?;
    reject_control_chars("server.domain", &server.domain)?;
    reject_control_chars("server.entry_ip", &server.entry_ip)?;
    reject_control_chars("server.ping_target", &server.ping_target)?;
    reject_control_chars("server.x25519_public_key", &server.x25519_public_key)?;
    reject_control_chars("config.private_key", &config.private_key)?;
    reject_control_chars("config.address", &config.address)?;
    reject_control_chars("config.dns", &config.dns)?;
    reject_control_chars("config.port", &config.port)?;

    let endpoint_raw = if !server.entry_ip.trim().is_empty() {
        server.entry_ip.trim()
    } else if !server.ping_target.trim().is_empty() {
        server.ping_target.trim()
    } else {
        server.domain.trim()
    };

    let address_raw = if config.address.trim().is_empty() {
        DEFAULT_WG_ADDRESS
    } else {
        config.address.trim()
    };

    let dns_raw = if config.dns.trim().is_empty() {
        DEFAULT_WG_DNS
    } else {
        config.dns.trim()
    };

    let port_raw = if config.port.trim().is_empty() {
        DEFAULT_WG_PORT
    } else {
        config.port.trim()
    };
    let port = validate_port_str(port_raw)?;

    let candidate = ValidatedTunnelSpec {
        server_name: server.name.clone(),
        country: server.country.clone(),
        domain: server.domain.clone(),
        entry_ip: endpoint_raw.to_owned(),
        server_pubkey: server.x25519_public_key.clone(),
        private_key: config.private_key.clone(),
        address: address_raw.to_owned(),
        dns: dns_raw.to_owned(),
        port,
    };

    normalize_and_validate_spec(&candidate)
}

fn normalize_wg_key_to_hex(key: &str) -> Option<String> {
    let trimmed = key.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_whitespace) {
        return None;
    }
    if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Some(trimmed.to_ascii_lowercase());
    }
    let decoded = STANDARD.decode(trimmed).ok()?;
    if decoded.len() != 32 {
        return None;
    }
    let mut hex = String::with_capacity(64);
    for byte in decoded {
        let _ = write!(hex, "{byte:02x}");
    }
    Some(hex)
}

/// Parses WireGuard Windows UAPI `get=1` output and returns the maximum positive
/// `last_handshake_time_sec` timestamp matching `expected_pubkey_hex_or_b64` (accepting either
/// 64-character hex or 32-byte base64), or `0` if absent, zero, or invalid.
pub fn parse_uapi_latest_handshake(uapi_output: &str, expected_pubkey_hex_or_b64: &str) -> i64 {
    let Some(expected_hex) = normalize_wg_key_to_hex(expected_pubkey_hex_or_b64) else {
        return 0;
    };

    let mut current_peer_matches = false;
    let mut latest_ts: i64 = 0;

    for raw_line in uapi_output.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "private_key" | "listen_port" | "fwmark" => {
                current_peer_matches = false;
            }
            "public_key" => {
                current_peer_matches =
                    normalize_wg_key_to_hex(value).as_deref() == Some(expected_hex.as_str());
            }
            "last_handshake_time_sec" if current_peer_matches => {
                if let Ok(ts) = value.trim().parse::<i64>() {
                    if ts > 0 {
                        latest_ts = latest_ts.max(ts);
                    }
                }
            }
            "errno" if value.trim() != "0" => {
                return 0;
            }
            _ => {}
        }
    }

    latest_ts
}

/// Builds a standard UDP DNS `A` query packet for `account.protonvpn.com` with `query_id`.
pub fn build_dns_query(query_id: u16) -> Vec<u8> {
    let mut query = Vec::with_capacity(12 + DNS_QUERY_QUESTION_ACCOUNT_PROTONVPN_COM.len());
    query.extend_from_slice(&query_id.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes()); // standard recursive query
    query.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    query.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    query.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    query.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0
    query.extend_from_slice(DNS_QUERY_QUESTION_ACCOUNT_PROTONVPN_COM);
    query
}

/// Validates a raw DNS UDP response header against `expected_query_id` and `windows_vpn.py` checks:
/// `QR == 1` (`flags & 0x8000 != 0`), `TC == 0 && RCODE == 0` (`flags & 0x020F == 0`),
/// `QDCOUNT == 1`, and `ANCOUNT > 0`.
pub fn is_valid_dns_response(response: &[u8], expected_query_id: u16) -> bool {
    if response.len() < 12 {
        return false;
    }
    let ident = u16::from_be_bytes([response[0], response[1]]);
    let flags = u16::from_be_bytes([response[2], response[3]]);
    let questions = u16::from_be_bytes([response[4], response[5]]);
    let answers = u16::from_be_bytes([response[6], response[7]]);

    ident == expected_query_id
        && (flags & DNS_FLAG_RESPONSE) != 0
        && (flags & DNS_FLAG_ERROR_OR_TRUNCATED_MASK) == 0
        && questions == 1
        && answers > 0
}

fn parse_tunnel_source_ips(address: &str) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for item in address.split(',') {
        let Some((ip, _)) = parse_cidr_ip(item.trim()) else {
            return Vec::new();
        };
        ips.push(ip);
    }
    ips
}

fn parse_dns_targets(dns: &str) -> Vec<IpAddr> {
    dns.split(',')
        .filter_map(|item| item.trim().parse::<IpAddr>().ok())
        .collect()
}

trait ProbeSocket {
    fn set_timeout(&self, timeout: Duration) -> io::Result<()>;
    fn connect_remote(&self, remote: SocketAddr) -> io::Result<()>;
    fn send_query(&self, buf: &[u8]) -> io::Result<usize>;
    fn recv_reply(&self, buf: &mut [u8]) -> io::Result<usize>;
}

trait ProbeSocketFactory {
    type Sock: ProbeSocket;
    fn bind_and_open(&self, local: SocketAddr) -> io::Result<Self::Sock>;
}

struct RealUdpFactory;

impl ProbeSocketFactory for RealUdpFactory {
    type Sock = UdpSocket;

    fn bind_and_open(&self, local: SocketAddr) -> io::Result<Self::Sock> {
        UdpSocket::bind(local)
    }
}

impl ProbeSocket for UdpSocket {
    fn set_timeout(&self, timeout: Duration) -> io::Result<()> {
        self.set_read_timeout(Some(timeout))?;
        self.set_write_timeout(Some(timeout))
    }

    fn connect_remote(&self, remote: SocketAddr) -> io::Result<()> {
        self.connect(remote)
    }

    fn send_query(&self, buf: &[u8]) -> io::Result<usize> {
        self.send(buf)
    }

    fn recv_reply(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv(buf)
    }
}

fn random_query_id() -> u16 {
    let mut bytes = [0u8; 2];
    rand::rng().fill_bytes(&mut bytes);
    u16::from_be_bytes(bytes)
}

fn probe_dns_with<F, G>(
    address: &str,
    dns: &str,
    port: u16,
    timeout: Duration,
    factory: &F,
    mut next_query_id: G,
) -> bool
where
    F: ProbeSocketFactory,
    G: FnMut() -> u16,
{
    let sources = parse_tunnel_source_ips(address);
    let targets = parse_dns_targets(dns);
    if sources.is_empty() || targets.is_empty() || timeout.is_zero() {
        return false;
    }

    let candidates: Vec<(IpAddr, IpAddr)> = targets
        .into_iter()
        .filter_map(|target| {
            sources
                .iter()
                .find(|ip| ip.is_ipv4() == target.is_ipv4())
                .copied()
                .map(|source| (source, target))
        })
        .collect();
    if candidates.is_empty() {
        return false;
    }

    let deadline = Instant::now() + timeout;
    let total_targets = candidates.len();
    let mut recv_buf = [0u8; 4096];

    for (index, (source, target)) in candidates.into_iter().enumerate() {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        if remaining.is_zero() {
            break;
        }

        let divisor = u32::try_from(total_targets - index).unwrap_or(1).max(1);
        let per_target_timeout = (remaining / divisor).max(Duration::from_millis(1));
        let query_id = next_query_id();
        let query = build_dns_query(query_id);

        // Bind strictly to the tunnel's local IP before connecting or sending; if bind fails,
        // return to the next candidate without ever sending an unbound packet over the physical NIC.
        let Ok(sock) = factory.bind_and_open(SocketAddr::new(source, 0)) else {
            continue;
        };
        if sock.set_timeout(per_target_timeout).is_err() {
            continue;
        }
        if sock.connect_remote(SocketAddr::new(target, port)).is_err() {
            continue;
        }
        if sock.send_query(&query).is_err() {
            continue;
        }
        let Ok(n) = sock.recv_reply(&mut recv_buf) else {
            continue;
        };
        if is_valid_dns_response(&recv_buf[..n], query_id) {
            return true;
        }
    }

    false
}

/// Sends a UDP DNS query for `account.protonvpn.com` strictly bound to the configured WireGuard
/// tunnel interface IP (`address`), trying each configured `dns` server on port `53` within
/// `timeout`. Never sends an unbound packet if local binding fails.
pub fn dns_responds_through_tunnel(address: &str, dns: &str, timeout: Duration) -> bool {
    dns_responds_through_tunnel_with_port(address, dns, DNS_PORT, timeout)
}

pub(crate) fn dns_responds_through_tunnel_with_port(
    address: &str,
    dns: &str,
    port: u16,
    timeout: Duration,
) -> bool {
    probe_dns_with(
        address,
        dns,
        port,
        timeout,
        &RealUdpFactory,
        random_query_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ServerNode;
    use crate::storage::ClientConfig;
    use base64::engine::general_purpose::STANDARD;
    use std::cell::RefCell;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
    use std::time::Duration;

    fn sample_b64_key(fill: u8) -> String {
        STANDARD.encode([fill; 32])
    }

    fn sample_hex_key(fill: u8) -> String {
        format!("{fill:02x}").repeat(32)
    }

    fn sample_server() -> ServerNode {
        ServerNode {
            name: "JP-FREE#1".to_owned(),
            country: "JP".to_owned(),
            entry_country: "JP".to_owned(),
            city: "Tokyo".to_owned(),
            load: Some(20.0),
            status: 1,
            domain: "node-jp-01.protonvpn.net".to_owned(),
            entry_ip: "192.0.2.1".to_owned(),
            exit_ip: "192.0.2.2".to_owned(),
            x25519_public_key: sample_b64_key(0xAB),
            active_physical_servers: 1,
            ping_target: "192.0.2.1".to_owned(),
            ping_ms: Some(25.0),
        }
    }

    fn sample_config() -> ClientConfig {
        ClientConfig {
            private_key: sample_b64_key(0x11),
            public_key: "PUB-PEM".to_owned(),
            expiration: 0,
            address: "10.2.0.2/32".to_owned(),
            dns: "10.2.0.1, 1.1.1.1".to_owned(),
            port: "51820".to_owned(),
            animations_enabled: true,
            auto_check_update: true,
            debug_mode: false,
        }
    }

    #[test]
    fn test_rejects_conf_injection_and_invalid_fields() {
        let base_server = sample_server();
        let base_cfg = sample_config();

        for bad_address in [
            "10.2.0.2/32\nPostUp = calc.exe",
            "10.2.0.2/32\r\n[Peer]",
            "[Peer]",
            "10.2.0.2/33",
            "10.2.0.2/+32",
            "not-an-ip",
            "10.2.0.2/32, ",
            "\n",
        ] {
            let mut cfg = base_cfg.clone();
            cfg.address = bad_address.to_owned();
            assert!(
                matches!(
                    validate_and_build_conf(&base_server, &cfg),
                    Err(WgError::InvalidInput(_))
                ),
                "address {bad_address:?} must be rejected"
            );
        }

        for bad_dns in [
            "10.2.0.1\nPostUp = calc.exe",
            "10.2.0.1\r",
            "[Peer]",
            "1.1.1.1, bad-dns",
            "10.2.0.1/24",
            "10.2.0.1,",
            "\t10.2.0.1",
        ] {
            let mut cfg = base_cfg.clone();
            cfg.dns = bad_dns.to_owned();
            assert!(
                matches!(
                    validate_and_build_conf(&base_server, &cfg),
                    Err(WgError::InvalidInput(_))
                ),
                "dns {bad_dns:?} must be rejected"
            );
        }

        for bad_entry in [
            "",
            "192.0.2.1\nPostUp = calc.exe",
            "192.0.2.1\r\n[Interface]",
            "[Peer]",
            "192.0.2.1:51820",
            "192.0.2.999",
            "bad host",
            "foo..bar",
            "-bad.protonvpn.net",
            "bad-.protonvpn.net",
        ] {
            let mut srv = base_server.clone();
            srv.entry_ip = bad_entry.to_owned();
            srv.ping_target = String::new();
            srv.domain = if bad_entry.is_empty() {
                String::new()
            } else {
                base_server.domain.clone()
            };
            assert!(
                matches!(
                    validate_and_build_conf(&srv, &base_cfg),
                    Err(WgError::InvalidInput(_))
                ),
                "entry_ip {bad_entry:?} must be rejected"
            );
        }

        for bad_key in [
            "",
            "not-base64!!!",
            &STANDARD.encode([0x11; 16]),
            &STANDARD.encode([0x11; 33]),
            &format!("{}\nPostUp = calc.exe", sample_b64_key(0x11)),
        ] {
            let mut cfg = base_cfg.clone();
            cfg.private_key = bad_key.to_owned();
            assert!(
                matches!(
                    validate_and_build_conf(&base_server, &cfg),
                    Err(WgError::InvalidInput(_))
                ),
                "private_key {bad_key:?} must be rejected"
            );

            let mut srv = base_server.clone();
            srv.x25519_public_key = bad_key.to_owned();
            assert!(
                matches!(
                    validate_and_build_conf(&srv, &base_cfg),
                    Err(WgError::InvalidInput(_))
                ),
                "x25519PublicKey {bad_key:?} must be rejected"
            );
        }

        for bad_port in ["0", "70000", "-1", "+51820", "abc", "51820\nPostUp = evil"] {
            let mut cfg = base_cfg.clone();
            cfg.port = bad_port.to_owned();
            assert!(
                matches!(
                    validate_and_build_conf(&base_server, &cfg),
                    Err(WgError::InvalidInput(_))
                ),
                "port {bad_port:?} must be rejected"
            );
        }

        // Comment injection via metadata fields must also be rejected.
        for mutate_meta in [
            |s: &mut ServerNode| s.name = "JP-FREE#1\n[Peer]\nPublicKey = evil".to_owned(),
            |s: &mut ServerNode| s.country = "JP\rPostUp = calc".to_owned(),
            |s: &mut ServerNode| s.domain = "node.proton.me\nPostDown = calc".to_owned(),
        ] {
            let mut srv = base_server.clone();
            mutate_meta(&mut srv);
            assert!(matches!(
                validate_and_build_conf(&srv, &base_cfg),
                Err(WgError::InvalidInput(_))
            ));
        }

        // Direct Named Pipe spec re-validation catches malformed specs too.
        let (valid_spec, _) =
            validate_and_build_conf(&base_server, &base_cfg).expect("valid baseline");
        let mut bad_spec = valid_spec.clone();
        bad_spec.port = 0;
        assert!(matches!(
            validate_tunnel_spec(&bad_spec),
            Err(WgError::InvalidInput(_))
        ));

        let mut bad_spec2 = valid_spec.clone();
        bad_spec2.address = String::new();
        assert!(matches!(
            validate_tunnel_spec(&bad_spec2),
            Err(WgError::InvalidInput(_))
        ));

        let mut bad_spec3 = valid_spec;
        bad_spec3.dns = "10.2.0.1\nPostUp = evil".to_owned();
        assert!(matches!(
            validate_tunnel_spec(&bad_spec3),
            Err(WgError::InvalidInput(_))
        ));

        // Strict hostname entry_ip is allowed and rendered cleanly.
        let mut hostname_srv = base_server;
        hostname_srv.entry_ip = "node-jp-01.protonvpn.net".to_owned();
        let (host_spec, host_conf) =
            validate_and_build_conf(&hostname_srv, &base_cfg).expect("valid hostname");
        assert_eq!(host_spec.entry_ip, "node-jp-01.protonvpn.net");
        assert!(host_conf.contains("Endpoint = node-jp-01.protonvpn.net:51820"));
    }

    #[test]
    fn test_ipv6_endpoint_is_bracketed_in_conf() {
        let cfg = sample_config();

        let mut v6_server = sample_server();
        v6_server.entry_ip = "2001:db8::1".to_owned();
        let (v6_spec, v6_conf) = validate_and_build_conf(&v6_server, &cfg).expect("valid IPv6");
        assert_eq!(v6_spec.entry_ip, "2001:db8::1");
        assert!(v6_conf.contains("Endpoint = [2001:db8::1]:51820\n"));
        assert!(v6_conf.contains("MTU = 1380\n"));
        assert!(v6_conf.contains("AllowedIPs = 0.0.0.0/0\n"));
        assert!(v6_conf.contains("PersistentKeepalive = 25\n"));

        // Already-bracketed IPv6 literal should normalize cleanly without double brackets.
        let mut bracketed_v6 = sample_server();
        bracketed_v6.entry_ip = "[2001:db8::1]".to_owned();
        let (bracketed_spec, bracketed_conf) =
            validate_and_build_conf(&bracketed_v6, &cfg).expect("bracketed IPv6");
        assert_eq!(bracketed_spec.entry_ip, "2001:db8::1");
        assert!(bracketed_conf.contains("Endpoint = [2001:db8::1]:51820\n"));

        let v4_server = sample_server();
        let (_, v4_conf) = validate_and_build_conf(&v4_server, &cfg).expect("valid IPv4");
        assert!(v4_conf.contains("Endpoint = 192.0.2.1:51820\n"));

        // Empty address/dns/port in ClientConfig fall back to DEFAULT_WG_* constants.
        let mut empty_defaults_cfg = sample_config();
        empty_defaults_cfg.address = String::new();
        empty_defaults_cfg.dns = "   ".to_owned();
        empty_defaults_cfg.port = String::new();
        let (fallback_spec, fallback_conf) =
            validate_and_build_conf(&v4_server, &empty_defaults_cfg).expect("default fallbacks");
        assert_eq!(fallback_spec.address, DEFAULT_WG_ADDRESS);
        assert_eq!(fallback_spec.dns, DEFAULT_WG_DNS);
        assert_eq!(fallback_spec.port, 51820);
        assert!(fallback_conf.contains(&format!("Address = {DEFAULT_WG_ADDRESS}\n")));
        assert!(fallback_conf.contains(&format!("DNS = {DEFAULT_WG_DNS}\n")));
    }

    #[test]
    fn test_parse_uapi_handshake_matches_expected_peer_only() {
        let other_hex = sample_hex_key(0x11);
        let expected_hex = sample_hex_key(0xAB);
        let expected_b64 = sample_b64_key(0xAB);
        let third_hex = sample_hex_key(0xCD);

        let uapi = format!(
            "private_key={}\n\
             listen_port=51820\n\
             public_key={other_hex}\n\
             last_handshake_time_sec=9999999999\n\
             tx_bytes=100\n\
             public_key={expected_hex}\n\
             endpoint=192.0.2.1:51820\n\
             last_handshake_time_sec=1700000123\n\
             last_handshake_time_nsec=500000\n\
             public_key={third_hex}\n\
             last_handshake_time_sec=1800000000\n\
             errno=0\n",
            sample_hex_key(0x22)
        );

        assert_eq!(
            parse_uapi_latest_handshake(&uapi, &expected_b64),
            1_700_000_123
        );
        assert_eq!(
            parse_uapi_latest_handshake(&uapi, &expected_hex),
            1_700_000_123
        );
        assert_eq!(
            parse_uapi_latest_handshake(&uapi, &expected_hex.to_ascii_uppercase()),
            1_700_000_123
        );

        let zero_uapi = format!(
            "public_key={other_hex}\n\
             last_handshake_time_sec=9999999999\n\
             public_key={expected_hex}\n\
             last_handshake_time_sec=0\n\
             errno=0\n"
        );
        assert_eq!(parse_uapi_latest_handshake(&zero_uapi, &expected_b64), 0);

        let missing_uapi = format!(
            "public_key={other_hex}\n\
             last_handshake_time_sec=9999999999\n\
             errno=0\n"
        );
        assert_eq!(parse_uapi_latest_handshake(&missing_uapi, &expected_b64), 0);
        assert_eq!(parse_uapi_latest_handshake(&uapi, ""), 0);
        assert_eq!(parse_uapi_latest_handshake(&uapi, "invalid-key"), 0);
    }

    struct MockSocketScript {
        bind_fail: bool,
        responses: RefCell<Vec<io::Result<Vec<u8>>>>,
        binds: RefCell<Vec<SocketAddr>>,
        connects: RefCell<Vec<SocketAddr>>,
        sends: RefCell<Vec<Vec<u8>>>,
        timeouts: RefCell<Vec<Duration>>,
    }

    impl MockSocketScript {
        fn new(bind_fail: bool, responses: Vec<io::Result<Vec<u8>>>) -> Self {
            Self {
                bind_fail,
                responses: RefCell::new(responses),
                binds: RefCell::new(Vec::new()),
                connects: RefCell::new(Vec::new()),
                sends: RefCell::new(Vec::new()),
                timeouts: RefCell::new(Vec::new()),
            }
        }
    }

    struct MockBoundSocket<'a> {
        script: &'a MockSocketScript,
    }

    struct MockFactory<'a>(&'a MockSocketScript);

    impl<'a> ProbeSocketFactory for MockFactory<'a> {
        type Sock = MockBoundSocket<'a>;

        fn bind_and_open(&self, local: SocketAddr) -> io::Result<Self::Sock> {
            self.0.binds.borrow_mut().push(local);
            if self.0.bind_fail {
                return Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "missing tunnel adapter",
                ));
            }
            Ok(MockBoundSocket { script: self.0 })
        }
    }

    impl ProbeSocket for MockBoundSocket<'_> {
        fn set_timeout(&self, timeout: Duration) -> io::Result<()> {
            self.script.timeouts.borrow_mut().push(timeout);
            Ok(())
        }

        fn connect_remote(&self, remote: SocketAddr) -> io::Result<()> {
            self.script.connects.borrow_mut().push(remote);
            Ok(())
        }

        fn send_query(&self, buf: &[u8]) -> io::Result<usize> {
            self.script.sends.borrow_mut().push(buf.to_vec());
            Ok(buf.len())
        }

        fn recv_reply(&self, buf: &mut [u8]) -> io::Result<usize> {
            let mut responses = self.script.responses.borrow_mut();
            if responses.is_empty() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "no more responses"));
            }
            let next = responses.remove(0)?;
            let len = next.len().min(buf.len());
            buf[..len].copy_from_slice(&next[..len]);
            Ok(len)
        }
    }

    #[test]
    fn test_dns_query_packet_and_response_validation() {
        let query = build_dns_query(42);
        assert_eq!(
            &query[..12],
            &[0x00, 42, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            &query[12..],
            b"\x07account\x09protonvpn\x03com\x00\x00\x01\x00\x01"
        );

        let make_resp = |id: u16, flags: u16, qd: u16, an: u16| -> Vec<u8> {
            let mut pkt = Vec::with_capacity(12);
            pkt.extend_from_slice(&id.to_be_bytes());
            pkt.extend_from_slice(&flags.to_be_bytes());
            pkt.extend_from_slice(&qd.to_be_bytes());
            pkt.extend_from_slice(&an.to_be_bytes());
            pkt.extend_from_slice(&0u16.to_be_bytes());
            pkt.extend_from_slice(&0u16.to_be_bytes());
            pkt
        };

        assert!(is_valid_dns_response(&make_resp(42, 0x8180, 1, 1), 42));
        for (id, flags, qd, an) in [
            (43, 0x8180, 1, 1), // mismatched query ID
            (42, 0x0100, 1, 1), // query flag (QR=0)
            (42, 0x8182, 1, 0), // SERVFAIL (RCODE=2)
            (42, 0x8183, 1, 1), // NXDOMAIN (RCODE=3)
            (42, 0x8380, 1, 1), // TC bit set (0x0200)
            (42, 0x8180, 1, 0), // zero answers
            (42, 0x8180, 0, 1), // wrong question count
        ] {
            assert!(
                !is_valid_dns_response(&make_resp(id, flags, qd, an), 42),
                "packet ({id}, {flags:#06x}, {qd}, {an}) must be rejected"
            );
        }
        assert!(!is_valid_dns_response(&[0u8; 11], 42));

        // Bind failure must never connect or send an unbound packet.
        let bind_fail_mock = MockSocketScript::new(true, vec![Ok(make_resp(42, 0x8180, 1, 1))]);
        assert!(!probe_dns_with(
            "10.2.0.2/32",
            "10.2.0.1",
            53,
            Duration::from_secs(2),
            &MockFactory(&bind_fail_mock),
            || 42,
        ));
        assert_eq!(
            *bind_fail_mock.binds.borrow(),
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 2, 0, 2)), 0)]
        );
        assert!(bind_fail_mock.connects.borrow().is_empty());
        assert!(bind_fail_mock.sends.borrow().is_empty());

        // Secondary resolver fallback succeeds when primary times out.
        let fallback_mock = MockSocketScript::new(
            false,
            vec![
                Err(io::Error::new(io::ErrorKind::TimedOut, "timeout")),
                Ok(make_resp(42, 0x8180, 1, 1)),
            ],
        );
        assert!(probe_dns_with(
            "10.2.0.2/32",
            "10.2.0.1, 1.1.1.1",
            53,
            Duration::from_secs(2),
            &MockFactory(&fallback_mock),
            || 42,
        ));
        assert_eq!(
            *fallback_mock.connects.borrow(),
            vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1)), 53),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
            ]
        );

        // Family mismatch (IPv4 source vs IPv6 DNS target) never binds or sends.
        let family_mismatch_mock =
            MockSocketScript::new(false, vec![Ok(make_resp(42, 0x8180, 1, 1))]);
        assert!(!probe_dns_with(
            "10.2.0.2/32",
            "2606:4700:4700::1111",
            53,
            Duration::from_secs(2),
            &MockFactory(&family_mismatch_mock),
            || 42,
        ));
        assert!(family_mismatch_mock.binds.borrow().is_empty());

        // Real loopback UDP socket test (bound strictly to 127.0.0.1).
        let server_sock = UdpSocket::bind("127.0.0.1:0").expect("bind mock DNS UDP server");
        let server_port = server_sock.local_addr().expect("server addr").port();
        server_sock
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set timeout");

        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            if let Ok((n, peer)) = server_sock.recv_from(&mut buf) {
                if n >= 12 {
                    let mut reply = make_resp(u16::from_be_bytes([buf[0], buf[1]]), 0x8180, 1, 1);
                    reply.extend_from_slice(&buf[12..n]);
                    let _ = server_sock.send_to(&reply, peer);
                }
            }
        });

        assert!(dns_responds_through_tunnel_with_port(
            "127.0.0.1/32",
            "127.0.0.1",
            server_port,
            Duration::from_secs(2),
        ));
        handle.join().expect("mock DNS server thread");

        // Unbindable tunnel IP must fail bind and never reach localhost server.
        assert!(!dns_responds_through_tunnel_with_port(
            "203.0.113.1/32",
            "127.0.0.1",
            server_port,
            Duration::from_millis(200),
        ));
    }

    #[test]
    fn test_ipv6_dns_target_does_not_halve_ipv4_timeout_budget() {
        let mut resp = Vec::with_capacity(12);
        resp.extend_from_slice(&42u16.to_be_bytes());
        resp.extend_from_slice(&0x8180u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());

        for dns_list in [
            "10.2.0.1, 2606:4700:4700::1111",
            "2606:4700:4700::1111, 10.2.0.1",
        ] {
            let mock = MockSocketScript::new(false, vec![Ok(resp.clone())]);
            assert!(probe_dns_with(
                "10.2.0.2/32",
                dns_list,
                53,
                Duration::from_secs(2),
                &MockFactory(&mock),
                || 42,
            ));
            let timeouts = mock.timeouts.borrow();
            assert_eq!(timeouts.len(), 1);
            assert!(
                timeouts[0] > Duration::from_millis(1500),
                "IPv6 target must be filtered before timeout slicing ({dns_list}): got {:?}",
                timeouts[0]
            );
        }
    }

    #[test]
    fn test_service_ipc_roundtrip_serialization() {
        assert_eq!(SERVICE_PIPE_NAME, r"\\.\pipe\FreetonVPNService");
        assert_eq!(DEFAULT_TUNNEL_NAME, "FreetonVPN");

        let (spec, _) =
            validate_and_build_conf(&sample_server(), &sample_config()).expect("valid spec");
        let info = ActiveTunnelInfo {
            server_name: spec.server_name.clone(),
            country: spec.country.clone(),
            entry_ip: spec.entry_ip.clone(),
            x25519_pubkey: spec.server_pubkey.clone(),
            address: spec.address.clone(),
            dns: spec.dns.clone(),
            port: spec.port,
            connected_at_unix: 1_700_000_500,
        };

        for req in [
            ServiceRequest::Connect(spec),
            ServiceRequest::Disconnect,
            ServiceRequest::Status,
            ServiceRequest::ShutdownTunnelOnExit,
        ] {
            let json = serde_json::to_string(&req).expect("serialize request");
            assert!(!json.contains('\n'));
            let decoded: ServiceRequest = serde_json::from_str(&json).expect("deserialize request");
            assert_eq!(decoded, req);
        }

        for state in [
            TunnelHealthState::Disconnected,
            TunnelHealthState::Connecting,
            TunnelHealthState::Verifying(info.clone()),
            TunnelHealthState::Connected(info.clone()),
            TunnelHealthState::Unverified {
                info: info.clone(),
                reason: "DNS probe failed".to_owned(),
            },
        ] {
            let json = serde_json::to_string(&state).expect("serialize health state");
            assert!(!json.contains('\n'));
            let decoded: TunnelHealthState =
                serde_json::from_str(&json).expect("deserialize health state");
            assert_eq!(decoded, state);
        }

        for resp in [
            ServiceResponse::Ok,
            ServiceResponse::Status(TunnelHealthState::Connected(info)),
            ServiceResponse::Error {
                code: "DNS_FAILED".to_owned(),
                message: "DNS qua VPN chưa phản hồi".to_owned(),
            },
        ] {
            let json = serde_json::to_string(&resp).expect("serialize response");
            assert!(!json.contains('\n'));
            let decoded: ServiceResponse =
                serde_json::from_str(&json).expect("deserialize response");
            assert_eq!(decoded, resp);
        }
    }
}
