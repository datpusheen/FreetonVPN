# LAN Bypass & Excluded IPs (Split Tunneling) Design

**Date:** 2026-11-28  
**Branch:** `master`  
**Status:** Approved

## Intent & Why
Allow Freeton VPN users to access local home/office devices (routers, NAS, printers, LAN servers on `192.168.x.x`, `10.x.x.x`, `172.16.x.x`, etc.) directly over the physical network while connected to Proton VPN, without manually computing inverse CIDR ranges for WireGuard `AllowedIPs`.

## Approaches Considered
- **Approach A (Selected — LAN Toggle + Custom Excluded IP/CIDR Input):** Add an `allow_lan_access` switch (`false` by default to keep full `0.0.0.0/0` kill-switch behavior unless opted in) plus a custom `excluded_ips` text field in Settings (`🛡️ CÀI ĐẶT WIREGUARD & MẠNG`). `freeton-core` validates excluded IPv4/CIDR entries, subtracts them from `0.0.0.0/0`, automatically re-includes configured IPv4 DNS `/32` addresses (`10.2.0.1/32`) so Proton internal DNS inside `10.0.0.0/8` continues working, and emits normalized `AllowedIPs` for both `.conf` export and `FreetonVPNService` (`ValidatedTunnelSpec`).
- **Approach B (Rejected — Raw Manual `AllowedIPs` Input):** Forces users to invert private IP ranges manually into ~18 CIDR blocks and risks breaking `10.2.0.1` Proton DNS.

## Key Constraints & Backward Compatibility
- Zero new Cargo crates.
- `ClientConfig.allow_lan_access` (`false`), `ClientConfig.excluded_ips` (`""`), and `ValidatedTunnelSpec.allowed_ips` (`"0.0.0.0/0"`) all use `#[serde(default)]` for seamless backward compatibility with stored credentials/configs.
- Reject control/newline characters and full `0.0.0.0/0` exclusions; preserve strict single-token IPv4/CIDR parsing.
- `FreetonVPNService` validates incoming `ValidatedTunnelSpec.allowed_ips` via `validate_tunnel_spec`.
