# Globe Polish, User Location & Smooth Dismiss Animations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (inline execution) or superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a sky-blue user-location marker (fetched from Proton `/vpn/v1/location` when disconnected with Windows Region/Vietnam fallback), persistent Blue-to-node arc + greyed-out inactive markers when connected, `"servers"` tooltip copy, balanced vertical alignment in the top status card & toast bar, and smooth close animations for dialogs and notifications.

**Architecture:** `freeton-core` adds `UserLocation`, `parse_user_location_payload`, `ProtonClient::fetch_user_location`, and Windows registry Geo lookup. `AppState` caches `user_location` and refreshes it during scans only while the VPN tunnel is inactive (`!tunnel_running`). `ui/globe.rs` draws the persistent blue origin marker, persistent Blue → active node elevated arc, and greyed-out inactive markers; `ui/home.rs`, `ui/mod.rs`, and `ui/dialogs.rs` fix `0.0`-height layout skew, directional close easing, height collapse, and exit `ui.disable()` dim flashes.

**Tech Stack:** Rust workspace (`freeton-core`, `freeton-app`), `eframe`/`egui` 0.37 painter, `reqwest`/`serde_json`, `windows` Win32 Registry API.

**Spec:** [2026-11-28-globe-polish-location-animations-design.md](../specs/2026-11-28-globe-polish-location-animations-design.md)

## Global Constraints
- Zero third-party GeoIP APIs; never overwrite `user_location` while `tunnel_running` (or connecting/disconnecting).
- Zero new Cargo dependencies.
- Preserve `390×610` fixed window bounds across all banner/toast/dialog states.
- Never trigger short repaint loops when `!window_visible` or `!animations_enabled`.
- Local commits on `exp/globe-home-ui` only — never run `git push`.

## Review Focus
1. **VPN Active Guard on User Location:** Scanning or receiving `WorkerEvent::UserLocationDetected` while `tunnel_running` or `is_connecting_vpn` must NOT replace the user's home Blue pin with the VPN exit country.
2. **Offline / Unauthenticated Fallback:** Missing `HKCU\Control Panel\International\Geo\Name`, unknown ISO codes, or failed `/vpn/v1/location` calls fall back cleanly to Vietnam (`14.0583, 108.2772`) without breaking login or server scan.
3. **Interactive Greyed Nodes & Non-Connectable Blue Pin:** When connected, unconnected greyed markers can still be hovered and clicked to switch countries; clicking the Blue user pin never triggers a VPN connection.
4. **Hidden Window & Reduced Motion Safety:** Toast/dialog/loading exit animations and click-dismiss repaints must not schedule continuous repaints when `!window_visible` or `!animations_enabled`, and mid-exit test assertions (`t=0.62` in `ui/mod.rs`) remain satisfied.
5. **Re-opening Mid-Exit & Measured Height Cache:** Dismissing a toast smoothly collapses the flow slot height toward 0 without clipping inner text violently on frame 1 or leaving layout displaced after completion.

---

### Task 1: Proton `fetch_user_location()` + Windows Geo Registry Fallback (`freeton-core`)

**Files:**
- Modify: `rust/freeton-core/src/api.rs`
- Modify: `rust/freeton-core/src/storage.rs`

**Interfaces:**
- Produces in `freeton_core::api`:
  - `pub struct UserLocation { pub country: Option<String>, pub lat: f32, pub lon: f32 }`
  - `pub fn parse_user_location_payload(payload: &Value) -> Result<UserLocation, ApiError>`
  - `pub async fn ProtonClient::fetch_user_location(&self) -> Result<UserLocation, ApiError>`
- Produces in `freeton_core::storage`:
  - `pub const WINDOWS_GEO_REG_KEY: &str = r"Control Panel\International\Geo";`
  - `pub const WINDOWS_GEO_NAME_VALUE: &str = "Name";`
  - `pub fn normalize_iso_country_code(raw: &str) -> Option<String>`
  - `pub fn read_windows_geo_country_code() -> Option<String>`

- [ ] **Step 1: Write failing tests** for `parse_user_location_payload`, `fetch_user_location` (`GET /vpn/v1/location` mock), and `normalize_iso_country_code` / `read_windows_geo_country_code`.
- [ ] **Step 2: Run targeted tests** to verify failure.
- [ ] **Step 3: Implement** `UserLocation`, `parse_user_location_payload`, `ProtonClient::fetch_user_location` in `api.rs`, and `read_reg_sz_in`, `normalize_iso_country_code`, `read_windows_geo_country_code` in `storage.rs`.
- [ ] **Step 4: Run targeted tests** (`cargo test --manifest-path rust/Cargo.toml -p freeton-core user_location` and `windows_geo`) and verify PASS.
- [ ] **Step 5: Commit locally** (`feat(core): add Proton user location parser/endpoint and Windows geo fallback`).

---

### Task 2: Wire `user_location` into `AppState` & Scan Worker (`freeton-app`)

**Files:**
- Modify: `rust/freeton-app/src/state.rs`

**Interfaces:**
- Consumes: `freeton_core::api::{ProtonClient::fetch_user_location, UserLocation}`, `freeton_core::storage::read_windows_geo_country_code`, `crate::ui::globe_data::{fallback_country_coords, DEFAULT_ORIGIN_COORDS}`
- Produces in `crate::state`:
  - `pub fn resolve_offline_user_location(geo_country: Option<&str>) -> UserLocation`
  - `AppState::user_location: UserLocation`
  - `UiCommand::StartScan { auth_generation: u64, fetch_location: bool }`
  - `WorkerEvent::UserLocationDetected { auth_generation: u64, location: UserLocation }`

- [ ] **Step 1: Write failing tests** (`test_resolve_offline_user_location_maps_known_country_and_falls_back_to_vietnam`, `test_user_location_event_ignored_when_tunnel_running_or_connecting_or_stale_auth`, `test_start_scan_sets_fetch_location_false_while_tunnel_running`).
- [ ] **Step 2: Run targeted tests** to verify failure.
- [ ] **Step 3: Implement** `resolve_offline_user_location`, `user_location` field + logout reset, `fetch_location` on `StartScan`, `handle_scan` location call (swallowing errors silently), and guarded `WorkerEvent::UserLocationDetected` handler.
- [ ] **Step 4: Run targeted tests** (`BypassSandbox: true` if localhost socket tests run) and verify PASS.
- [ ] **Step 5: Commit locally** (`feat(app): fetch Proton user location when disconnected with Windows geo fallback`).

---

### Task 3: Blue Origin Pin, Persistent Blue→Node Arc, Greyed Nodes & `"servers"` Tooltip (`globe.rs` & `home.rs`)

**Files:**
- Modify: `rust/freeton-app/src/ui/globe.rs`
- Modify: `rust/freeton-app/src/ui/home.rs`

**Interfaces:**
- Consumes: `AppState::user_location` in `home.rs`
- Produces in `crate::ui::globe`:
  - `pub const C_USER_ORIGIN_BLUE: Color32 = Color32::from_rgb(0x38, 0xbd, 0xf8);`
  - `pub const C_NODE_GREYED: Color32 = Color32::from_rgb(0x64, 0x74, 0x8b);`
  - `pub fn format_server_count_label(count: usize) -> String`
  - `GlobeRenderInputs<'a>` fields `user_origin: (f32, f32)` and `user_country: Option<&'a str>`

- [ ] **Step 1: Write failing tests** (`test_format_server_count_label_singular_and_plural`, `test_blue_user_origin_dot_always_renders_and_hover_does_not_connect`, `test_connected_globe_greys_out_unconnected_nodes_and_keeps_blue_to_target_arc`, `test_marker_hover_tooltip_uses_servers_wording`) and update existing test inputs/flight-origin expectations.
- [ ] **Step 2: Run `globe` tests** to verify failure.
- [ ] **Step 3: Implement** sky-blue user dot rendering + hover hit-test/tooltip + non-connect click guard, persistent `user_origin` flight arc, greyed-out unconnected nodes while active/connecting, `"1 server"` / `"{n} servers"` tooltip format, and wire `user_origin`/`user_country` from `home.rs`.
- [ ] **Step 4: Run `globe` & `home` tests** and verify PASS.
- [ ] **Step 5: Commit locally** (`feat(app): add blue user-location pin, greyed inactive nodes & servers tooltip`).

---

### Task 4: Symmetric Top Status Card & Toast Alignment + Smooth Dismiss Animations (`home.rs`, `ui/mod.rs`, `ui/dialogs.rs`)

**Files:**
- Modify: `rust/freeton-app/src/ui/home.rs`
- Modify: `rust/freeton-app/src/ui/mod.rs`
- Modify: `rust/freeton-app/src/ui/dialogs.rs`

**Interfaces:**
- Produces in `crate::ui`:
  - `pub(crate) fn modal_ease(t: f32, entering: bool) -> f32`

- [ ] **Step 1: Write failing tests** in `ui/mod.rs` (`test_modal_ease_is_monotonic_and_does_not_stall_on_exit`, `test_toast_dismiss_collapses_height_smoothly_and_requests_repaint_immediately`, `test_dialog_close_click_requests_immediate_repaint_without_disabled_dim_snap`) and `ui/home.rs` (`test_top_status_card_has_symmetric_vertical_padding_and_centered_toggle`).
- [ ] **Step 2: Run `ui::` tests** to verify failure.
- [ ] **Step 3: Implement**:
  - `modal_ease` directional easing, non-`ui.disable()` exit fade + `.interactable(is_open)` in `dialogs.rs`, smooth height collapse + non-disabled exit in `ui/mod.rs` for toast and loading bar, immediate `ctx.request_repaint()` on click close (only when `state.window_visible && anim_on`), and symmetric `Align::Min` row alignment in `home.rs` & `ui/mod.rs`.
- [ ] **Step 4: Run full workspace tests** (`cargo test --manifest-path rust/Cargo.toml`) and verify ALL PASS.
- [ ] **Step 5: Commit locally** (`fix(app): balance top card/toast alignment and smooth dialog/toast dismiss`).
