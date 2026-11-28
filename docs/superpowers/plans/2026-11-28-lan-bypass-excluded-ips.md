# LAN Bypass & Excluded IPs Implementation Plan

**Goal:** Add an `allow_lan_access` toggle and custom `excluded_ips` setting so local/private subnets bypass the WireGuard tunnel while keeping Proton's internal DNS (`10.2.0.1/32`) routed inside the tunnel.

**Spec:** [2026-11-28-lan-bypass-excluded-ips-design.md](../specs/2026-11-28-lan-bypass-excluded-ips-design.md)

## Tasks
1. **Core (`freeton-core::storage` & `freeton-core::wg`):**
   - Persist `allow_lan_access: bool` (`false`) and `excluded_ips: String` (`""`) on `ClientConfig`.
   - Add `LAN_BYPASS_CIDRS`, `validate_excluded_ips_list`, `validate_allowed_ips_list`, and `compute_allowed_ips` (IPv4 interval subtraction + DNS `/32` re-inclusion + minimal CIDR decomposition).
   - Add `allowed_ips: String` (`#[serde(default = "default_wg_allowed_ips")]`) to `ValidatedTunnelSpec`, validate it in `normalize_and_validate_spec`, and use it in `AllowedIPs = ...` output.
2. **Service Compatibility (`freeton-service::broker`):**
   - Update `sample_spec()` in `broker.rs` tests and verify `validate_tunnel_spec` accepts computed multi-CIDR `AllowedIPs` while rejecting newline injection.
3. **App State & Settings UI (`freeton-app`):**
   - Add `allow_lan_access` and `excluded_ips` to `SettingsDraft`, validate/save in `save_settings_dialog` (with reconnect reminder toast when active tunnel settings change), and render toggle + input in Settings Section 3 (`ui/dialogs.rs`).
4. **Verification & Build:**
   - Full `cargo test --manifest-path rust/Cargo.toml` (`0` failed) and build updated binaries (`freeton-app`, `freeton-service`).
