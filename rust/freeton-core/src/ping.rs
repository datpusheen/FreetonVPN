use std::borrow::Cow;
use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::IpHelper::{
    IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, ICMP_ECHO_REPLY, IP_SUCCESS,
};

use crate::api::ServerNode;

/// Default per-target Win32 ICMP echo timeout in milliseconds.
pub const DEFAULT_PING_TIMEOUT_MS: u32 = 800;

/// Default maximum concurrent ICMP ping workers.
pub const DEFAULT_PING_WORKERS: usize = 16;

/// Penalty latency (ms) applied when a server is unreachable or unpinged.
pub const MISSING_PING_PENALTY: f64 = 9_999.0;

/// Fallback server load (%) applied when a server omits load metadata.
pub const MISSING_LOAD_PENALTY: f64 = 50.0;

const COUNTRY_NAMES: &[(&str, &str)] = &[
    ("SG", "Singapore (SG)"),
    ("JP", "Nhật Bản (JP)"),
    ("US", "Hoa Kỳ (US)"),
    ("NL", "Hà Lan (NL)"),
    ("RO", "Romania (RO)"),
    ("PL", "Ba Lan (PL)"),
    ("CH", "Thụy Sĩ (CH)"),
    ("DE", "Đức (DE)"),
    ("FR", "Pháp (FR)"),
    ("GB", "Vương quốc Anh (GB)"),
    ("CA", "Canada (CA)"),
    ("NO", "Na Uy (NO)"),
    ("MX", "Mexico (MX)"),
    ("IS", "Iceland (IS)"),
    ("SE", "Thụy Điển (SE)"),
    ("ES", "Tây Ban Nha (ES)"),
    ("IT", "Ý (IT)"),
    ("AU", "Úc (AU)"),
    ("BR", "Brazil (BR)"),
    ("IN", "Ấn Độ (IN)"),
];

/// Sort orders supported in the Server Picker Drawer, matching `proton_warp_material_gui.py`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortMode {
    #[default]
    Best,
    Ping,
    Load,
    Name,
}

/// Returns the localized display label for an ISO country code (e.g., `"JP"` -> `"Nhật Bản (JP)"`).
pub fn get_country_display(code: &str) -> Cow<'static, str> {
    let trimmed = code.trim();
    for &(iso, label) in COUNTRY_NAMES {
        if iso.eq_ignore_ascii_case(trimmed) {
            return Cow::Borrowed(label);
        }
    }
    Cow::Owned(trimmed.to_owned())
}

fn effective_ping(node: &ServerNode) -> f64 {
    node.ping_ms
        .filter(|v| v.is_finite() && *v >= 0.0)
        .unwrap_or(MISSING_PING_PENALTY)
}

fn effective_load_for_score(node: &ServerNode) -> f64 {
    node.load
        .filter(|v| v.is_finite())
        .unwrap_or(MISSING_LOAD_PENALTY)
}

fn load_or_zero(node: &ServerNode) -> f64 {
    node.load.filter(|v| v.is_finite()).unwrap_or(0.0)
}

/// Computes the composite server score `(ping_ms * 0.7) + (load * 0.8)`.
///
/// Missing/non-finite ping defaults to `9999.0` and missing/non-finite load defaults to `50.0`.
/// Lower scores represent better servers.
pub fn score_server(node: &ServerNode) -> f64 {
    (effective_ping(node) * 0.7) + (effective_load_for_score(node) * 0.8)
}

/// Filters `servers` by optional ISO `country` code and search `query` (matching `name`, `city`,
/// `domain`, `country`, and localized `get_country_display`), sorts according to `sort`, and
/// returns `(best_matching_server, sorted_servers)`.
pub fn sort_and_filter_servers(
    servers: &[ServerNode],
    country: Option<&str>,
    query: &str,
    sort: SortMode,
) -> (Option<ServerNode>, Vec<ServerNode>) {
    let country_filter = country.map(str::trim).filter(|c| !c.is_empty());
    let query_lower = query.trim().to_lowercase();

    let mut filtered: Vec<ServerNode> = servers
        .iter()
        .filter(|server| {
            let country_ok =
                country_filter.is_none_or(|code| server.country.trim().eq_ignore_ascii_case(code));
            if !country_ok {
                return false;
            }
            if query_lower.is_empty() {
                return true;
            }
            let display = get_country_display(&server.country);
            [
                server.name.as_str(),
                server.city.as_str(),
                server.domain.as_str(),
                server.country.as_str(),
                display.as_ref(),
            ]
            .iter()
            .any(|field| field.to_lowercase().contains(&query_lower))
        })
        .cloned()
        .collect();

    let best = filtered
        .iter()
        .min_by(|a, b| {
            score_server(a)
                .total_cmp(&score_server(b))
                .then_with(|| a.name.cmp(&b.name))
        })
        .cloned();

    match sort {
        SortMode::Best => {
            filtered.sort_by(|a, b| {
                score_server(a)
                    .total_cmp(&score_server(b))
                    .then_with(|| a.name.cmp(&b.name))
            });
        }
        SortMode::Ping => {
            filtered.sort_by(|a, b| {
                effective_ping(a)
                    .total_cmp(&effective_ping(b))
                    .then_with(|| load_or_zero(a).total_cmp(&load_or_zero(b)))
                    .then_with(|| a.name.cmp(&b.name))
            });
        }
        SortMode::Load => {
            filtered.sort_by(|a, b| {
                load_or_zero(a)
                    .total_cmp(&load_or_zero(b))
                    .then_with(|| effective_ping(a).total_cmp(&effective_ping(b)))
                    .then_with(|| a.name.cmp(&b.name))
            });
        }
        SortMode::Name => {
            filtered.sort_by(|a, b| a.name.cmp(&b.name));
        }
    }

    (best, filtered)
}

struct IcmpHandle(HANDLE);

impl Drop for IcmpHandle {
    fn drop(&mut self) {
        let _ = unsafe { IcmpCloseHandle(self.0) };
    }
}

fn icmp_echo_ipv4(addr: Ipv4Addr, timeout_ms: u32) -> Option<f64> {
    let handle = IcmpHandle(unsafe { IcmpCreateFile() }.ok()?);
    let dest_addr = u32::from_ne_bytes(addr.octets());
    const REQUEST_DATA: &[u8] = b"FreetonPing0123456789abcdef01234";

    let min_reply_bytes = std::mem::size_of::<ICMP_ECHO_REPLY>() + REQUEST_DATA.len() + 8;
    let word_count = min_reply_bytes.div_ceil(std::mem::size_of::<u64>());
    let mut reply_buf = vec![0u64; word_count];
    let reply_buf_bytes =
        u32::try_from(reply_buf.len() * std::mem::size_of::<u64>()).unwrap_or(u32::MAX);

    let reply_count = unsafe {
        IcmpSendEcho(
            handle.0,
            dest_addr,
            REQUEST_DATA.as_ptr().cast(),
            REQUEST_DATA.len() as u16,
            None,
            reply_buf.as_mut_ptr().cast(),
            reply_buf_bytes,
            timeout_ms.max(1),
        )
    };
    if reply_count == 0 {
        return None;
    }

    let reply = unsafe { &*(reply_buf.as_ptr().cast::<ICMP_ECHO_REPLY>()) };
    if reply.Status == IP_SUCCESS {
        Some(f64::from(reply.RoundTripTime))
    } else {
        None
    }
}

/// Resolves `target` (IPv4 literal or DNS hostname via `tokio::net::lookup_host`) and sends a
/// single native Win32 ICMP echo request with `timeout_ms`, returning RTT in milliseconds.
pub async fn ping_host(target: String, timeout_ms: u32) -> Option<f64> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return None;
    }

    let ipv4 = match trimmed.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => ip,
        Ok(IpAddr::V6(_)) => return None,
        Err(_) => {
            let dns_timeout = Duration::from_millis(u64::from(timeout_ms).max(1_500));
            let lookup = tokio::time::timeout(dns_timeout, tokio::net::lookup_host((trimmed, 0)))
                .await
                .ok()?
                .ok()?;
            lookup.into_iter().find_map(|addr| match addr {
                SocketAddr::V4(v4) => Some(*v4.ip()),
                SocketAddr::V6(_) => None,
            })?
        }
    };

    tokio::task::spawn_blocking(move || icmp_echo_ipv4(ipv4, timeout_ms))
        .await
        .ok()
        .flatten()
}

/// Probes all `servers` concurrently with target deduplication by `ping_target`, bounded by
/// `max_workers` semaphore permits, using the native Win32 ICMP pinger (`ping_host`).
pub async fn ping_servers<F>(
    servers: &mut [ServerNode],
    timeout_ms: u32,
    max_workers: usize,
    on_progress: F,
) where
    F: FnMut(usize, usize),
{
    ping_servers_with(servers, timeout_ms, max_workers, ping_host, on_progress).await;
}

/// Same as `ping_servers`, accepting an injected async target probe closure for deterministic tests.
pub async fn ping_servers_with<P, Fut, F>(
    servers: &mut [ServerNode],
    timeout_ms: u32,
    max_workers: usize,
    probe: P,
    mut on_progress: F,
) where
    P: Fn(String, u32) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Option<f64>> + Send,
    F: FnMut(usize, usize),
{
    let total = servers.len();
    on_progress(0, total);
    if total == 0 {
        return;
    }

    let mut groups: Vec<(String, Vec<usize>)> = Vec::new();
    let mut index_by_target: HashMap<String, usize> = HashMap::new();
    let mut empty_indices: Vec<usize> = Vec::new();

    for (idx, server) in servers.iter().enumerate() {
        let target = server.ping_target.trim();
        if target.is_empty() {
            empty_indices.push(idx);
            continue;
        }
        if let Some(&group_idx) = index_by_target.get(target) {
            groups[group_idx].1.push(idx);
        } else {
            let group_idx = groups.len();
            index_by_target.insert(target.to_owned(), group_idx);
            groups.push((target.to_owned(), vec![idx]));
        }
    }

    let mut completed = 0usize;
    for idx in empty_indices {
        servers[idx].ping_ms = None;
        completed += 1;
    }
    if groups.is_empty() {
        on_progress(completed, total);
        return;
    }
    if completed > 0 {
        on_progress(completed, total);
    }

    let semaphore = Arc::new(Semaphore::new(max_workers.max(1)));
    let probe_fn = Arc::new(probe);
    let mut join_set: JoinSet<(usize, Option<f64>)> = JoinSet::new();

    for (group_idx, (target, _)) in groups.iter().enumerate() {
        let sem = Arc::clone(&semaphore);
        let probe_ref = Arc::clone(&probe_fn);
        let target_owned = target.clone();
        join_set.spawn(async move {
            let Ok(_permit) = sem.acquire_owned().await else {
                return (group_idx, None);
            };
            let latency = probe_ref(target_owned, timeout_ms).await;
            (group_idx, latency)
        });
    }

    let mut applied = vec![false; groups.len()];
    while let Some(res) = join_set.join_next().await {
        if let Ok((group_idx, latency)) = res {
            applied[group_idx] = true;
            let indices = &groups[group_idx].1;
            for &idx in indices {
                servers[idx].ping_ms = latency;
            }
            completed += indices.len();
            on_progress(completed, total);
        }
    }

    for (group_idx, was_applied) in applied.into_iter().enumerate() {
        if !was_applied {
            let indices = &groups[group_idx].1;
            for &idx in indices {
                servers[idx].ping_ms = None;
            }
            completed += indices.len();
            on_progress(completed, total);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ServerNode;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    fn make_node(
        name: &str,
        country: &str,
        city: &str,
        ping_target: &str,
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
            entry_ip: ping_target.to_owned(),
            exit_ip: ping_target.to_owned(),
            x25519_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            active_physical_servers: 1,
            ping_target: ping_target.to_owned(),
            ping_ms,
        }
    }

    #[test]
    fn test_zero_load_is_better_than_fifty_percent() {
        let loaded = make_node(
            "loaded",
            "JP",
            "Tokyo",
            "198.51.100.1",
            Some(20.0),
            Some(50.0),
        );
        let empty = make_node(
            "empty",
            "JP",
            "Tokyo",
            "198.51.100.2",
            Some(20.0),
            Some(0.0),
        );

        assert!(score_server(&empty) < score_server(&loaded));

        let (best, sorted) =
            sort_and_filter_servers(&[loaded.clone(), empty.clone()], None, "", SortMode::Best);
        assert_eq!(best.expect("best server").name, "empty");
        assert_eq!(sorted[0].name, "empty");
        assert_eq!(sorted[1].name, "loaded");
    }

    #[test]
    fn test_sort_and_filter_servers_modes_country_and_vietnamese_search() {
        let servers = vec![
            make_node(
                "US-FREE#2",
                "US",
                "New York",
                "192.0.2.1",
                Some(120.0),
                Some(10.0),
            ),
            make_node(
                "JP-FREE#1",
                "JP",
                "Tokyo",
                "192.0.2.2",
                Some(35.0),
                Some(60.0),
            ),
            make_node("JP-FREE#2", "JP", "Osaka", "192.0.2.3", None, Some(5.0)),
            make_node(
                "SG-FREE#1",
                "SG",
                "Singapore",
                "192.0.2.4",
                Some(25.0),
                Some(20.0),
            ),
        ];

        // Country filter + Vietnamese country display query ("nhật bản").
        let (best_jp, jp_list) =
            sort_and_filter_servers(&servers, Some("JP"), "nhật bản", SortMode::Ping);
        assert_eq!(jp_list.len(), 2);
        assert_eq!(jp_list[0].name, "JP-FREE#1");
        assert_eq!(jp_list[1].name, "JP-FREE#2");
        assert_eq!(best_jp.expect("best jp").name, "JP-FREE#1");

        // SortMode::Load orders lowest load first (5% < 10% < 20% < 60%).
        let (_, by_load) = sort_and_filter_servers(&servers, None, "", SortMode::Load);
        let load_names: Vec<&str> = by_load.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            load_names,
            vec!["JP-FREE#2", "US-FREE#2", "SG-FREE#1", "JP-FREE#1"]
        );

        // SortMode::Name orders alphabetically.
        let (_, by_name) = sort_and_filter_servers(&servers, None, "", SortMode::Name);
        let alpha_names: Vec<&str> = by_name.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            alpha_names,
            vec!["JP-FREE#1", "JP-FREE#2", "SG-FREE#1", "US-FREE#2"]
        );

        // Empty search result returns None + empty vec.
        let (none_best, empty_list) =
            sort_and_filter_servers(&servers, None, "nonexistent-city", SortMode::Best);
        assert!(none_best.is_none());
        assert!(empty_list.is_empty());
    }

    #[tokio::test]
    async fn test_deduplicated_ping_updates_all_matching_targets() {
        let mut servers = vec![
            make_node(
                "JP-FREE#1",
                "JP",
                "Tokyo",
                "198.51.100.10",
                None,
                Some(20.0),
            ),
            make_node(
                "JP-FREE#2",
                "JP",
                "Tokyo",
                "198.51.100.10",
                None,
                Some(40.0),
            ),
            make_node(
                "SG-FREE#1",
                "SG",
                "Singapore",
                "198.51.100.20",
                None,
                Some(10.0),
            ),
            make_node("EMPTY-TARGET", "US", "NYC", "", Some(99.0), Some(15.0)),
        ];

        let probe_counts: Arc<Mutex<HashMap<String, usize>>> = Arc::new(Mutex::new(HashMap::new()));
        let probe_counts_clone = Arc::clone(&probe_counts);
        let mut progress_steps = Vec::new();

        ping_servers_with(
            &mut servers,
            800,
            16,
            move |target: String, _timeout_ms: u32| {
                let counts = Arc::clone(&probe_counts_clone);
                async move {
                    *counts
                        .lock()
                        .expect("counts lock")
                        .entry(target.clone())
                        .or_insert(0) += 1;
                    match target.as_str() {
                        "198.51.100.10" => Some(42.5),
                        "198.51.100.20" => Some(18.0),
                        _ => None,
                    }
                }
            },
            |completed, total| {
                progress_steps.push((completed, total));
            },
        )
        .await;

        assert_eq!(servers[0].ping_ms, Some(42.5));
        assert_eq!(servers[1].ping_ms, Some(42.5));
        assert_eq!(servers[2].ping_ms, Some(18.0));
        assert_eq!(servers[3].ping_ms, None);

        let counts = probe_counts.lock().expect("counts lock");
        assert_eq!(counts.get("198.51.100.10"), Some(&1));
        assert_eq!(counts.get("198.51.100.20"), Some(&1));
        assert_eq!(counts.len(), 2);

        assert_eq!(progress_steps.first(), Some(&(0, 4)));
        assert_eq!(progress_steps.last(), Some(&(4, 4)));
    }

    #[tokio::test]
    async fn test_win32_icmp_ping_localhost_smoke_and_unreachable_fallback() {
        let mut servers = vec![
            make_node("LOCALHOST-IP", "US", "Local", "127.0.0.1", None, Some(0.0)),
            make_node(
                "LOCALHOST-DNS",
                "US",
                "LocalDns",
                "localhost",
                None,
                Some(0.0),
            ),
            make_node("EMPTY", "US", "None", "   ", Some(12.0), Some(0.0)),
            make_node(
                "BAD-HOST",
                "US",
                "Invalid",
                "does-not-exist.invalid",
                Some(12.0),
                Some(0.0),
            ),
        ];

        ping_servers(&mut servers, 800, 4, |_, _| {}).await;

        let local_ip_ping = servers[0]
            .ping_ms
            .expect("127.0.0.1 Win32 IcmpSendEcho smoke test should succeed");
        assert!((0.0..800.0).contains(&local_ip_ping));
        let local_dns_ping = servers[1]
            .ping_ms
            .expect("localhost DNS lookup + Win32 IcmpSendEcho should succeed");
        assert!((0.0..800.0).contains(&local_dns_ping));
        assert_eq!(servers[2].ping_ms, None);
        assert_eq!(servers[3].ping_ms, None);
    }
}
