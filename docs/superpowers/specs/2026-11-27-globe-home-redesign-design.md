# Experimental Home UI Redesign: Interactive 3D Dot-Matrix Globe

**Branch:** `exp/globe-home-ui` (branched from local `master` commit `952a736`)  
**Status:** Design draft for approval (experimental)  
**Target Crate(s):** `freeton-core` (optional lat/lon fields on `ServerNode`), `freeton-app` (`ui/home.rs`, new `ui/globe.rs`, new `ui/globe_data.rs`, `ui/mod.rs`)

---

## 1. Intent & Why

The current `Home` view in `rust/freeton-app/src/ui/home.rs` places a plain iOS toggle switch in the center of a large empty dark space between the top status card and the bottom server card. The user wants an experimental, bolder, more engaging main screen inspired by **TunnelBear**:

- Move the VPN toggle switch up into the top connection card.
- Fill the central hero area with an interactive **3D globe** showing markers for countries with available free Proton servers.
- Let users spin the globe, inspect countries, and click a country marker to watch a **3D flight/tunnel arc animation** shoot to that destination while connecting.

All work stays on the experimental branch `exp/globe-home-ui` so the user can test and evaluate it without affecting `master`.

---

## 2. Goals, Non-Goals, and Anti-Goals

### Goals
- **Merged Top Status & Toggle Card:** Place the VPN toggle switch inside the top `KẾT NỐI CỦA BẠN` card alongside the connection heading, status details, and session timer badge.
- **Interactive 3D Dot-Matrix Globe (User Decision — Style 1):** Render a dark-glass 3D globe with glowing cyber dot-matrix landmasses in the center of `Home`.
- **Clickable Country Markers (User Decision — Interaction Mode 1):**
  - Plot a glowing marker for every country present in `state.all_free_servers`.
  - Support free pointer drag rotation with damped inertia.
  - Hovering a marker highlights it and displays a compact floating tooltip (localized country name, best ping, server count).
  - Clicking a country marker picks that country's best-scored server (`sort_and_filter_servers(..., Some(code), "", SortMode::Best)`) and immediately triggers `state.select_and_connect_server(best)` (connecting even if VPN is currently off, or switching servers if already connected).
- **TunnelBear-Style Flight Animation:**
  - On connect / server switch, smoothly rotate the globe camera toward the target country, apply subtle zoom (`1.0 → 1.16`), launch an elevated 3D great-circle glowing arc with a bright comet tip from origin to destination, and burst an expanding radar pulse upon landing.
  - Origin rule (User approved): default to **Vietnam** (`14.0583° N, 108.2772° E`) when connecting from an idle/disconnected state (zero external GeoIP leaks); when switching from an active/previous server in country A to country B, launch from **A → B**.
- **Preserve Existing Home Capabilities:** Keep the bottom `VỊ TRÍ MÁY CHỦ` card (`Đổi vị trí ›` → `AppView::Drawer`) for per-node selection, and keep the bottom action strip (`Cài đặt`, `Giới thiệu`, `Đăng xuất` / `🔑 Đăng nhập`, plus `💾 Xuất .conf` when `debug_mode` is enabled).
- **Strict Window Fit:** Fit cleanly inside the fixed `390×610` window across all banner states (clean home, toast notice, loading progress bar, UAC service repair banner, unverified tunnel warning), continuing to pass `test_home_layout_fits_cleanly_inside_390x610_across_banner_states`.

### Non-Goals
- Changing the fixed `390×610` window dimensions, borderless top window bar, `Login`, `Srp`, `Drawer`, or modal `dialogs`.
- Calling external GeoIP services or downloading map tiles/assets over the network.
- Adding heavy 3D rendering crates (e.g., `three-d`, `bevy`) or WebView2 map views.
- Modifying `freeton-service`, WireGuard configuration generation, or named-pipe IPC.

### Anti-Goals
- **Idle CPU/GPU drain:** Requesting continuous repaints when hidden to tray (`!state.window_visible`) or when `client_config.animations_enabled == false`.
- **Renderer breakage:** Failing on `Renderer::Glow` (OpenGL fallback), VM WARP software rendering, or headless `egui::Context::run_ui` unit tests.
- **Cache breakage:** Failing to deserialize existing `servers_cache.json` files that lack latitude/longitude fields.
- **Footer clipping:** Allowing the globe area to push bottom cards or action chips below `WINDOW_HEIGHT - 12.0` when top banners stack.

---

## 3. Constraints

- **Window & Panel Budget:** Fixed `390.0 × 610.0` logical pixels (`WINDOW_WIDTH`, `WINDOW_HEIGHT` in `ui/mod.rs`). `CentralPanel` uses `Margin::symmetric(14, 12)` (`362 × 586` inner area); top bar consumes `42px` plus spacing/loading/toast/repair banners when active.
- **Multi-Backend Rendering (`main.rs`):** Must render identically on `wgpu` DX12, VM WARP software DX12, `glow` OpenGL fallback, and headless `egui::Context::run_ui` tests.
- **Low Memory Footprint:** Must align with `trim_working_set()` and keep binary/memory overhead minimal (only static baked point data, no dynamic large textures or WebView instances).
- **State Guards (`state.rs`):** Globe marker clicks must respect `state.is_connecting_vpn`, `state.closing`, and `!state.is_logged_in` (redirecting to Login if unauthenticated, matching `toggle_vpn` / `show_drawer_view`).

---

## 4. Approaches Considered

### Approach A (Chosen by User): Pure `egui::Painter` 3D Projection + Baked Static Land Dots
- **How it works:** Build `ui/globe.rs` + `ui/globe_data.rs` using pure Rust 3D vector math and `egui::Painter` primitives (`circle_filled`, `circle_stroke`, `line_segment` / polyline). Bake ~1,400–1,800 Fibonacci-sphere land dots as a static `const` slice of quantized `i16` unit vectors (`[i16; 3]`, ~8–12 KB) derived from real-world landmass boundaries.
- **Pros:** Zero new Cargo dependencies; 100% deterministic across `wgpu`, `glow`, WARP, and headless tests; 0% CPU when hidden to tray; tiny binary & RAM footprint; fast iteration for an experimental branch.
- **Cons:** No GPU pixel-shader volumetric bloom; spends ~1–2% CPU while actively animating ~1,500 circles per frame.

### Approach B (Rejected): Custom `wgpu` WGSL Shader (`egui_wgpu::Callback`) + Painter Overlay
- **How it works:** Render the sphere, atmosphere glow, and arc inside a custom WGSL fragment/vertex pass via `egui_wgpu::Callback`, with `Painter` markers/tooltips overlaid.
- **Why rejected:** Cannot run under `Renderer::Glow` fallback (requires maintaining a duplicate OpenGL path) or headless `egui::Context::run_ui` layout tests; unnecessary complexity for an experimental UI exploration.

### Approach C (Ruled Out): Embedded `WebView2` WebGL Widget
- **How it works:** Host a local HTML/WebGL globe inside `webview2-com`.
- **Why ruled out:** Adds ~60–120 MB RAM per WebView2 process (contradicting Freeton's low-RAM work), complicates borderless dragging/clipping/DPI, and introduces async JS/Rust state sync overhead.

---

## 5. Detailed Design

### 5.1 Home Screen Layout (`ui/home.rs`)

Vertical stack inside `CentralPanel` (below top bar, loading bar, and optional info toast):

1. **Top Status + Toggle Card (Merged):**
   - Rendered via `rounded_card` with existing semantic border colors (`C_BORDER` idle, `C_WARNING` connecting/disconnecting/unverified/closing, `C_SUCCESS` verified connected).
   - **Horizontal split inside card:**
     - **Left column** (`avail_w - toggle_w - gap`):
       - Top row: `KẾT NỐI CỦA BẠN` (`10.0–10.5px`, `C_TEXT_DIM`) + inline compact status/timer pill (`HH:MM:SS` when verified, `"Đang kết nối…"` / `"Sẵn sàng"` otherwise, styled using `state.formatted_session_timer(now_unix)`).
       - Main heading: existing status title (`CHƯA BẬT VPN`, `ĐÃ KẾT NỐI`, `ĐANG THIẾT LẬP KẾT NỐI...`, `VPN CHƯA XÁC MINH`, etc.) sized cleanly (`17.0–18.0px` bold) so it fits beside the toggle without overflowing.
       - Subtitle: concise 1–2 line status/endpoint/public-IP text (`10.5–11.0px`, wrapped to left column width).
     - **Right column** (vertically centered):
       - Compact `ios_toggle_switch` (`Vec2::new(72.0, 38.0)` normal, `Vec2::new(64.0, 34.0)` in compact mode), retaining the existing connecting amber pulse halo and smooth knob slide. Clicking toggles VPN via `state.toggle_vpn()`.
   - *Design call (Assistant proposal):* Compacting the header card and placing the timer inline inside it frees ~80px of vertical height compared to the old stacked timer + giant 136×70 toggle + caption, giving the globe plenty of breathing room.

2. **Optional UAC Service Repair Banner (Unchanged):**
   - Shown below the top card when `matches!(state.service_health, ServiceHealthStatus::Unavailable(_)) && !state.closing`.

3. **Central Interactive Globe Arena:**
   - Dynamically claims remaining vertical space between the top card/repair banner and the bottom reserved footer (`server_card_est_h + between_gap + footer_chips_h + bottom_pad`):
     - Typical clean state: `~230–260px` tall.
     - Worst-case stacked-banner state (loading bar + toast + UAC banner + unverified 2-line card): gracefully shrinks to `~110–140px` without clipping the footer.
   - Sphere radius: `radius = (avail_w.min(arena_h - caption_h) * 0.45).clamp(48.0, 108.0)`.
   - Bottom of arena displays a subtle 1-line caption (`10.0px`, `C_TEXT_DIM`) — e.g. `"WIREGUARD  •  Kéo để xoay, bấm nước để kết nối"` when idle, or active tunnel indicator (`"WIREGUARD  •  Đang mã hóa qua Singapore"`) when connected.

4. **Bottom Server Card & Action Chips (Preserved):**
   - `VỊ TRÍ MÁY CHỦ` card (`Đổi vị trí ›`, ping badge, load badge; clicking opens `AppView::Drawer`).
   - `34px` bottom action row (`[💾 Xuất .conf in debug]`, `Cài đặt`, `Giới thiệu`, `Đăng xuất` / `🔑 Đăng nhập`).

### 5.2 Server Coordinates & Country Marker Aggregation

1. **`ServerNode` Coordinate Extension (`rust/freeton-core/src/api.rs`):**
   - Add two optional fields to `ServerNode`:
     ```rust
     #[serde(default, deserialize_with = "deserialize_null_f64_opt")]
     pub latitude: Option<f64>,
     #[serde(default, deserialize_with = "deserialize_null_f64_opt")]
     pub longitude: Option<f64>,
     ```
   - In `select_free_servers_with_wg`, read `server.get("Location")` → `"Lat"` and `"Long"` (`as_f64()`), storing finite values as `Some(...)`.
   - Backward compatibility: `#[serde(default)]` ensures existing `servers_cache.json` snapshots deserialize cleanly with `None`.

2. **ISO Country Fallback Coordinate Table (`ui/globe.rs`):**
   - Include a `const` lookup table mapping ISO 3166-1 alpha-2 codes to representative `(lat_deg, lon_deg)` coordinates covering all 20 countries in `freeton_core::ping::COUNTRY_NAMES` plus common Proton countries (e.g., `AT`, `BE`, `BG`, `CZ`, `DK`, `EE`, `FI`, `GR`, `HK`, `HU`, `IE`, `KR`, `LT`, `LV`, `MD`, `PT`, `RS`, `SK`, `TW`, `UA`, `VN`, `ZA`, etc.).
   - When computing a country marker's position from `state.all_free_servers`:
     - Prefer the centroid (average lat/lon) of servers in that country that have `Some(lat)` & `Some(lon)` (filtering non-finite values).
     - Fall back to the static ISO table if coordinates are missing (e.g., from an older cache).
     - Skip countries that have neither server coordinates nor a fallback entry (no crash, gracefully ignored).

3. **Country Grouping & Best Node Selection:**
   - Group `state.all_free_servers` by normalized uppercase country code.
   - For each country present:
     - `server_count`: number of free servers in that country.
     - `best_server`: first result / `best` tuple from `sort_and_filter_servers(&state.all_free_servers, Some(code), "", SortMode::Best)` so clicking a country on the globe uses the exact same scoring formula `(ping * 0.7) + (load * 0.8)` as the Drawer.
     - `best_ping_ms`: `best_server.ping_ms`.

### 5.3 3D Math, Projection, and Visual Style (`ui/globe.rs`)

- **Coordinate System & Projection:**
  - Spherical to 3D unit vector `(x, y, z)` with `lat` in radians, `lon` in radians:
    - Apply camera rotation `yaw` (around Y) and `pitch` (around X, clamped to `[-65°, +65°]`).
    - Orthographic projection onto screen:
      - `screen_x = center.x + x_rot * radius * zoom`
      - `screen_y = center.y - y_rot * radius * zoom`
      - Depth `z_rot` in `[-1.0, +1.0]` (`z_rot > 0` faces viewer).
- **Sphere Backdrop & Atmosphere:**
  - Outer subtle atmospheric halo (`circle_stroke` layers with low alpha, shifting from `C_ACCENT` tint when idle/connected to `C_WARNING` tint while connecting/unverified).
  - Filled dark sphere base (`#121922`) + faint inner rim highlight stroke (`C_BORDER` / `C_ACCENT` tinted).
  - Faint latitude/longitude reference rings (equator + 2–3 meridians, very low alpha `14–22`) to reinforce 3D curvature.
- **Cyber Dot-Matrix Landmasses (`ui/globe_data.rs`):**
  - ~1,400–1,800 Fibonacci-sphere points inside world landmass polygons, stored as quantized `[(i16, i16, i16); N]` (`val / 32767.0` -> unit vector) for zero runtime generation cost and compact binary size.
  - Back-limb dots (`-0.25 < z_rot <= 0.0`): drawn first at tiny size (`0.9px`) and very faint alpha (`12–18`) to give a translucent glass-hologram feel.
  - Front dots (`z_rot > 0.0`): radius `1.0..1.75px` scaled by `z_rot`; color interpolates from muted slate (`#2c3d4f`) at horizon to bright teal-slate (`#4d7882`) near center, warming toward mint (`C_ACCENT`) when VPN is verified connected.
- **Country Markers (Sorted back-to-front by `z_rot`):**
  - Only markers with `z_rot > -0.10` are drawn; only `z_rot > 0.08` are interactive hit targets (preventing accidental clicks on markers behind the globe edge).
  - **Normal country:** `3.0px` core dot + `6.5px` soft halo (`alpha 45`), colored by `ping_status_color(best_ping_ms)` (or `C_ACCENT` if ping unknown).
  - **Hovered country:** `4.6px` core + crisp `8.5px` outer ring (`C_TEXT`), plus a floating Dark Glass tooltip card (`C_SURFACE` fill, `C_ACCENT` border) showing `"{CountryDisplay} • {PingText} • {N} sv"`, clamped strictly within the globe arena bounds.
  - **Selected / Connected / Connecting target country:** Bright `C_SUCCESS` (or `C_WARNING` while connecting/unverified) beacon + animated expanding radar ripple ring.
  - **Origin marker (when active tunnel/flight exists):** Subtle secondary dot at origin (Vietnam or previous server country) so both ends of the arc are anchored visually.

### 5.4 Pointer Interaction & TunnelBear Flight Animation

- **Pointer Controls:**
  - Dragging anywhere inside the globe circle rotates `yaw` and `pitch` proportionally (`dx / radius`, `dy / radius`).
  - Releasing a drag imparts short damped angular velocity (`inertia_yaw`, `inertia_pitch`, decaying with `exp(-dt * 5.0)` until below epsilon).
  - Drag vs. Click threshold: a pointer press/release is treated as a **click** only if total pointer travel `< 5.0px`; otherwise it is a drag.
  - **Hit-Testing:** Find the closest front-hemisphere (`z_rot > 0.08`) country marker within `14.0px` of the pointer position (tie-breaking by larger `z_rot` / smaller screen distance). Hovering updates immediately so the user sees the tooltip confirming which dense-region country (e.g., NL vs DE vs CH) is targeted before clicking.
  - **Click Action (User Decision):**
    - If `!state.is_logged_in`, redirect to `state.show_login_view()`.
    - If `state.is_connecting_vpn || state.closing`, ignore click (matching `select_and_connect_server` guard).
    - Otherwise, launch the flight animation toward that country and invoke `state.select_and_connect_server(best_server)`.
  - **Drawer / Toggle Sync:** If the user selects a server via `AppView::Drawer` or toggles VPN on via the top switch, `Home` detects the change in active target (`selected_server` / `connected_server` / connecting transition) and automatically triggers the same camera rotation + flight arc animation!

- **Flight Animation Timeline (`GlobeViewState`):**
  - Stored persistently across frames (e.g., on `egui::Context` temp data keyed by a stable ID or inside a dedicated `GlobeState` struct; *Builder call: keep `GlobeState` testable independent of `egui::Context` if desired, or pass `&mut GlobeState` in unit tests*).
  - **On new connection / target change** (when `animations_enabled == true`):
    - Determine `origin_coord`: previous active/connected country coordinate if switching while connected/connecting, else Vietnam (`14.0583, 108.2772`).
    - Determine `target_coord`: destination server's `(lat, lon)` (or country fallback).
    - Start flight (`progress: 0.0 -> 1.0` over `0.95s` with cubic ease-out):
      - Camera interpolates `(yaw, pitch)` via shortest angular path to face `target_coord` (slightly tilted so both arc and destination sit attractively in view) and eases zoom `1.0 -> 1.16`.
      - Draw great-circle 3D arc (`slerp(origin, target, u)` lifted radially by `1.0 + sin(π * u) * arc_lift`, where `arc_lift` scales gently with angular distance up to `0.28`).
      - During flight (`progress < 1.0`): draw illuminated arc segment from `0..progress` plus a bright comet tip; upon reaching `1.0`, trigger a landing radar shockwave ring at `target_coord`.
    - **While connected & settled:** Keep subtle zoom (`1.16` or user-adjusted), pause idle auto-spin (user can still drag anytime), and animate a soft traveling pulse along the established great-circle tunnel arc.
    - **On disconnect:** Ease arc alpha out (`0.30s`), ease zoom back to `1.0`, and resume slow idle rotation (`~6°/s`) when not hovered/dragged.
  - **When `animations_enabled == false`:** Snap camera & arc immediately (`progress = 1.0`), no idle spin, no shockwave/comet loop.
  - **Repaint Policy (Battery / Tray Friendly):**
    - When `!state.window_visible`: request **no** globe repaints.
    - When `animations_enabled` and actively flying, dragging inertia, connecting, or pulsing: `request_repaint_after(16ms)` (or `33ms` for gentle idle spin / subtle connected pulse).

### 5.5 What's Left to the Builder

- **Land Dot Generation:** Choose the exact build-time or one-off script (e.g., Python script reading Natural Earth 110m land polygons or equivalent accurate world landmass mask) to generate the baked `const` array in `rust/freeton-app/src/ui/globe_data.rs`, ensuring continents (Americas, Europe, Africa, Asia, Australia) are clearly recognizable at ~1,500–1,800 dots.
- **Exact Palette & Alpha Tuning:** Fine-tune dot alphas, rim stroke thickness, arc segment count (`~32–48` segments), and tooltip layout margins within the Dark Glass palette (`C_SURFACE`, `C_ACCENT`, `C_SUCCESS`, `C_WARNING`).
- **State Placement:** Decide whether `GlobeState` lives inside `AppState` (e.g., `pub globe: GlobeState` with `#[cfg(test)]` helpers) or in `egui::Context` temp storage, ensuring unit tests can exercise marker aggregation, flight transitions, and 390×610 layout bounds cleanly.
