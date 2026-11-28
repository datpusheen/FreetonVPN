# Globe Home UI Polish, User Location & Smooth Dismiss Animations

**Date:** 2026-11-28  
**Branch:** `exp/globe-home-ui`  
**Status:** Draft (awaiting user approval)

## Intent & Why

Refine the experimental 3D dot-matrix globe Home UI in Freeton VPN (`390×610` fixed window) so the globe gives clear spatial feedback of where the user's real origin sits and where the encrypted tunnel lands, clean up top-area vertical alignment issues observed in testing, and eliminate mid-transition stutters when closing dialogs or dismissing top notifications.

## Goals, Non-Goals, Anti-Goals & Constraints

### Goals
1. **Blue Current-Location Anchor:** Render the user's current real-world location as a distinct sky-blue (`#38BDF8`) dot on the 3D globe, fetched from Proton's own `GET vpn/v1/location` when authenticated & VPN is off, with offline fallback via Windows Region (`HKCU\Control Panel\International\Geo\Name`) and default Vietnam coordinates (`14.0583, 108.2772`).
2. **Origin-to-Node Tunnel Arc & Greyed-Out Nodes:** Keep a visible 3D elevated arc connecting the user's Blue dot to the active/connecting node; while connecting or connected, render all unconnected country dots greyed out (`#64748B`, reduced glow/alpha) while preserving hover brighten + click-to-switch.
3. **Clearer Tooltip Copy:** Display `"1 server"` / `"{n} servers"` instead of `"{n} sv"` on country marker hover tooltips.
4. **Balanced Top Alignment:** Remove the `~9px` phantom top shift on text blocks inside the `KẾT NỐI CỦA BẠN` status card and the dismissible info toast bar so padding and vertical centering match symmetrically.
5. **Stutter-Free Close Animations:** Fix directional easing, eliminate the sudden `ui.disable()` dim flash on frame 1 of exit, collapse toast/loading height smoothly during exit, and trigger `request_repaint()` immediately on dismiss.

### Non-Goals
- No third-party GeoIP services (no external IP lookup APIs beyond Proton API + Windows local registry).
- No changes to WireGuard tunnel connection/daemon lifecycle, drawer list layout, or core credentials storage format.

### Anti-Goals
- Never overwrite the cached user origin while `tunnel_running` (or connecting/disconnecting), which would show the VPN exit country as the user's own home location.
- Never let toast overlays cover top bar controls or status text on the `390×610` window.
- Never trigger short repaint loops when `!window_visible` or `!animations_enabled`.

### Constraints
- Zero new Cargo dependencies (`egui`/`eframe` 0.37 painter + existing `freeton-core` Proton client & `windows` registry bindings).
- Preserve `390×610` window geometry across all banner/toast/dialog states.
- Local commits on `exp/globe-home-ui` only (do not push until requested).

---

## Approaches Considered

### Approach A (Selected): Integrated Scan Location + Smooth Flow Collapse
- Call `ProtonClient::fetch_user_location()` (`GET vpn/v1/location`) alongside server fetching in `handle_scan` only when `!tunnel_running` (avoiding exit-IP contamination), caching the resolved `UserLocation` in `AppState` and falling back to Windows Region registry → `DEFAULT_ORIGIN_COORDS`.
- Keep the info toast and loading bar in the `CentralPanel` flow and smoothly animate their vertical height/spacing (`cached_h * eased_h`) + opacity while replacing `allocate_ui_with_layout(Vec2::new(w, 0.0), ...)` phantom padding and `ui.disable()` dimming on exit.
- **Why chosen:** Keeps UI uncluttered and unoccluded within `390×610`, adds minimal plumbing, and directly resolves both alignment and dismiss-stutter root causes.

### Approach B (Rejected): Floating Overlay Toast + Separate Worker Command
- Move toast to an `egui::Area` overlay so dismiss doesn't resize flow, and add dedicated `FetchUserLocation` worker command/event plumbing.
- **Why rejected:** Persistent notices (such as `"Đang dùng bản mới nhất v3.0.3"`) would cover the top bar or `KẾT NỐI CỦA BẠN` card on a `390×610` window, and separate worker messaging duplicates work already performed cleanly during scan.

---

## Detailed Design

### 1. Blue Current-Location Marker (`UserLocation`)
- **Data Model (`freeton-core` & `AppState`):**
  - Add `UserLocation { pub country: Option<String>, pub lat: f32, pub lon: f32 }` in `freeton-core::api` with `fetch_user_location(&self) -> Result<UserLocation, ApiError>` calling `GET vpn/v1/location` (`Lat`, `Long`, optional `Country` / ISO code) and validating finite `[-90, 90]` / `[-180, 180]`.
  - Add offline helper reading `HKCU\Control Panel\International\Geo\Name` -> `fallback_country_coords(iso)` -> `DEFAULT_ORIGIN_COORDS`. Note: only update `AppState.user_location` from Proton when `!self.tunnel_running && !self.is_connecting_vpn`.
  - Store `user_location: Option<UserLocation>` on `AppState` (initialized with Windows/VN offline fallback; updated via `WorkerEvent::ScanFinished` or scan location payload if tunnel was off when fetched).
- **Globe Rendering:**
  - Always project `(user_lat, user_lon)` on the front hemisphere (`z > -0.06`) as the **Your Location** dot in sky blue (`Color32::from_rgb(0x38, 0xbd, 0xf8)` — visually distinct from ping red/yellow/green and teal accent), with a subtle halo (`alpha ~ 55..80`) and crisp bright core (`alpha ~ 245`).
  - Hover hit-testing recognizes the user dot (unless dragging or blocked by modal): shows clamped dark-glass tooltip `"Vị trí hiện tại của bạn"` (or `"Vị trí của bạn • <Country>"` when known) and status caption `"VỊ TRÍ CỦA BẠN  •  Điểm xuất phát đường hầm"`. Clicking the blue user dot does not initiate a VPN server connection.
  - Auto-recenter / initial origin: use `user_location` coordinates instead of hardcoded `DEFAULT_ORIGIN_COORDS` where appropriate (e.g., tunnel flight origin).

### 2. Persistent Blue → Connected Node Arc & Greyed-Out Nodes
- **Tunnel Arc Origin:** When connecting or connected, elevated 3D `slerp_arc_points` always originates from the resolved Blue user-location coordinates `(user_lat, user_lon)` to the target/connected node (even when switching countries, keep `origin = user_location` so the visual tunnel clearly links Blue → active node; builder may animate smooth target-to-target transition or direct origin-to-target arc—direct Blue → node matches the user's explicit request).
- **Unconnected Node Dimming:** While `is_active_or_connecting` (`(tunnel_running || is_connecting) && !is_disconnecting`):
  - Active/connecting target country dot stays bright (`accent_tone`, ring + radar pulse).
  - All other country dots render greyed out (`Color32::from_rgb(0x64, 0x74, 0x8b)`, reduced halo/alpha, ~`0.45..0.60` multiplier) instead of ping red/yellow/green.
  - Hovering a greyed-out node brightens it subtly with white ring + tooltip and still allows clicking to switch directly to that country.
  - When disconnected/idle, all server nodes return to their normal ping colors (green/yellow/red/teal).

### 3. Hover Tooltip Wording
- Format marker server count as:
  - `if marker.server_count == 1 { "1 server".to_owned() } else { format!("{} servers", marker.server_count) }`
  - E.g. `"Japan (JP) • 64 ms • 4 servers"` instead of `"4 sv"`.

### 4. Top Status Card & Info Toast Alignment
- **Root Cause:** In `home.rs` (`KẾT NỐI CỦA BẠN` card) and `mod.rs` (info toast bar), calling `ui.allocate_ui_with_layout(Vec2::new(w, 0.0), Layout::top_down(Align::Min), ...)` inside `ui.horizontal(...)` defaults `Align::Center` cross-axis allocation against `Vec2::new(..., 0.0)`, causing `egui` to offset the left vertical column downward (`~9px` extra space above `KẾT NỐI CỦA BẠN`, cramped bottom, vertically misaligned vs toggle / `✕`).
- **Fix:** Measure or allocate the horizontal row with symmetric vertical padding inside `rounded_card`, align the left column cleanly from `ui.min_rect().top()` (or `Layout::left_to_right(Align::Center)` with explicit equal-top container height / `ui.vertical(...)` whose width is constrained without zero-height center offset), and vertically center the right-hand iOS toggle switch (`home.rs`) and `✕` close button (`mod.rs`) against the full content height of the card. Verify alignment in UI layout tests (`top_gap == bottom_gap` within 1-2px tolerance).

### 5. Smooth Dialog & Toast Close Animations
- **Directional Easing:**
  - Enter (`is_open == true` / `toast.is_some()`): fast-out ease `1.0 - (1.0 - t).powi(3)`.
  - Exit (`is_open == false` / `toast.is_none()`): ease-out in reverse so exit starts immediately and finishes smoothly (`eased = t * t` or `t.powi(3)` / `t * t * (3.0 - 2.0 * t)` — specifically `t.powi(2)` or `t.powi(3)` from `1 -> 0` moves briskly off frame 1 instead of stalling at `1.0`!). Track direction (`entering` bool vs `anim_t`) cleanly so partial open/close reversals never jump.
- **No Exit Dim Flash:** Remove `ui.disable()` during exit fade in `dialogs.rs` (`render_dialog_overlay`) and `mod.rs` (`info_toast`, `loading`). Block pointer clicks safely via `Sense::hover()` / opaque backdrop click catcher or `!interactive` interaction guard without applying egui's ~50% disabled-widget gray multiplier before `set_opacity(eased)` fades cleanly to `0`.
- **Smooth Flow Collapse for Toast & Loading:** Cache the rendered height of the info toast (and loading bar), scale reserved vertical layout height by `eased_h` (e.g., `clip_rect` shrinking cleanly + `allocate_space`), so dismissing the green update banner slides the status card and globe upward smoothly instead of snapping `~38px`.
- **Immediate Repaint on Dismiss:** Call `ctx.request_repaint()` directly when clicking the toast `✕` button, `Escape`, backdrop/Hủy dialog close so no idle frame delay stalls the start of the fade-out.

---

## Left to Builder
- Tune exact rgba values for sky-blue marker, greyed-out inactive nodes, and subtle hover highlight.
- Choose clean measured-height height-collapse helper for toast/loading so layout tests remain deterministic at `t = 0.0`, mid-exit, and `t = 1.0`.
- Add thorough unit/UI tests for:
  1. `ProtonClient::fetch_user_location` valid/invalid payloads + Windows `HKCU\...\Geo\Name` fallback + active-tunnel guard (`!tunnel_running`).
  2. Blue marker projection, tooltip (`"1 server"` / `"4 servers"`), greyed-out unconnected markers while connected, and persistent Blue → node arc.
  3. Symmetric top/bottom padding & vertical centering inside `KẾT NỐI CỦA BẠN` card and info toast.
  4. Monotonic exit easing (no halfway stall), no `ui.disable()` flash during exit, and continuous frame repaint requests until close finishes.
