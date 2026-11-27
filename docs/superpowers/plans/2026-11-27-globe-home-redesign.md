# Experimental 3D Dot-Matrix Globe Home UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Redesign Freeton VPN's `Home` view on branch `exp/globe-home-ui` by merging the VPN toggle into the top status card, placing an interactive 3D Cyber Dot-Matrix Globe with clickable country markers in the center, and adding a TunnelBear-style 3D great-circle flight animation on connect/switch.

**Architecture:** Pure `egui::Painter` 3D orthographic projection (`ui/globe.rs`) backed by embedded static continent polygons sampled onto a deterministic Fibonacci sphere (`ui/globe_data.rs`, cached via `OnceLock`), paired with optional `latitude`/`longitude` parsing on `ServerNode` (`freeton-core/src/api.rs`) and an ISO fallback table. `GlobeState` lives on `AppState` and drives camera rotation, inertia, hit-testing, and flight/pulse timelines while respecting `window_visible` and `animations_enabled`.

**Tech Stack:** Rust 2021, `eframe`/`egui` 0.37 (`epaint`), `serde`/`serde_json`, `freeton-core`, `freeton-app` (zero new Cargo dependencies).

**Spec:** [docs/superpowers/specs/2026-11-27-globe-home-redesign-design.md](../specs/2026-11-27-globe-home-redesign-design.md)

## Global Constraints

- Fixed window `390.0 × 610.0` (`WINDOW_WIDTH`, `WINDOW_HEIGHT`), `CentralPanel` inner margin `Margin::symmetric(14, 12)` (`362 × 586` inner area); all widgets and text must remain inside `x <= 376.0` and `y <= 598.0` even under worst-case stacked banners.
- Zero new external Cargo dependencies; must work identically across `wgpu` DX12, VM WARP software rendering, `glow` OpenGL fallback, and headless `egui::Context::run_ui` tests.
- Zero external network calls for GeoIP or map assets; default idle flight origin is Vietnam `(14.0583, 108.2772)`.
- Backward-compatible `ServerNode` serde deserialization (`#[serde(default, deserialize_with = "deserialize_null_f64_opt")]`) so legacy `servers_cache.json` files load without error.
- Battery/tray discipline: zero continuous animation repaint requests when `!state.window_visible` or `!state.client_config.animations_enabled`; instant snap when animations are disabled.
- Preserve existing state guards (`is_connecting_vpn`, `closing`, `!is_logged_in` redirect to Login) and keep bottom server card (`Đổi vị trí ›` → `Drawer`) and `34px` footer action chips intact.
- Never run `git push`; all commits stay local on `exp/globe-home-ui`.

## Review Focus

1. **NaN / out-of-range coordinates (`|lat| > 90`, `|lon| > 180`) or empty `all_free_servers`:** Never poison centroid averaging or emit NaN painter coordinates; invalid coordinates become `None` and fall back to ISO table (or render empty globe cleanly). *(Pinned in Task 1 & Task 3)*
2. **Antimeridian & antipodal flight arcs (`JP ↔ US`, `(0,0) ↔ (0,180)`) and zero-length arcs (`origin == target`):** Camera yaw takes shortest wrap across `±π`, and `slerp_arc_points` never divides by zero or produces NaN points. *(Pinned in Task 3)*
3. **Back-hemisphere & dense European cluster hit-testing (`NL`, `DE`, `CH`):** Markers with `z <= 0.08` never intercept clicks, and competing front-side markers within `14.0px` deterministically select the closest/frontmost one matching the hover tooltip. *(Pinned in Task 3)*
4. **State guard bypass on globe click:** Clicking a country dot when `!is_logged_in` redirects to `AppView::Login`; clicking when `is_connecting_vpn || closing` is a no-op; dragging `>= 5.0px` never triggers a click. *(Pinned in Task 3 & Task 4)*
5. **Hidden-to-tray / disabled-animations repaint drain & worst-case `390×610` stacked-banner overflow:** `!window_visible` or `!animations_enabled` schedules no short animation repaint, and stacked toast + loading + UAC repair + unverified banner + clamped hover tooltip still fit within `390×610`. *(Pinned in Task 4)*

---

### Task 1: Extend `ServerNode` with Optional Coordinates & Parse Proton `Location`

**Files:**
- Modify: `rust/freeton-core/src/api.rs:154-209` (`ServerNode`), `rust/freeton-core/src/api.rs:340-363` (`select_free_servers_with_wg`), `rust/freeton-core/src/api.rs` (unit tests)
- Modify: `rust/freeton-core/src/ping.rs:391`
- Modify: `rust/freeton-core/src/storage.rs:1015`
- Modify: `rust/freeton-core/src/wg.rs:712`
- Modify: `rust/freeton-app/src/state.rs:2649`, `rust/freeton-app/src/state.rs:4177`

**Interfaces:**
- Consumes: `deserialize_null_f64_opt` in `rust/freeton-core/src/api.rs:124-129`
- Produces:
  - `ServerNode.latitude: Option<f64>` (`#[serde(default, deserialize_with = "deserialize_null_f64_opt")]`)
  - `ServerNode.longitude: Option<f64>` (`#[serde(default, deserialize_with = "deserialize_null_f64_opt")]`)
  - Validated `Location.Lat` (`-90.0..=90.0`, finite) and `Location.Long` (`-180.0..=180.0`, finite) parsing inside `select_free_servers_with_wg`

- [ ] **Step 1: Write the failing tests in `rust/freeton-core/src/api.rs`**

```rust
#[test]
fn test_select_free_servers_parses_valid_location_and_rejects_invalid() {
    let payload = json!({
        "LogicalServers": [
            {
                "Name": "JP-FREE#1",
                "Tier": 0,
                "Status": 1,
                "ExitCountry": "JP",
                "EntryCountry": "JP",
                "City": "Tokyo",
                "Load": 20.0,
                "Domain": "jp-1.protonvpn.net",
                "Location": { "Lat": 35.6762, "Long": 139.6503 },
                "Servers": [{ "Status": 1, "ServicesDown": 0, "EntryIP": "198.51.100.1", "X25519PublicKey": "k1" }]
            },
            {
                "Name": "US-FREE#1",
                "Tier": 0,
                "Status": 1,
                "ExitCountry": "US",
                "EntryCountry": "US",
                "City": "New York",
                "Load": 30.0,
                "Domain": "us-1.protonvpn.net",
                "Location": { "Lat": 120.0, "Long": -74.0 },
                "Servers": [{ "Status": 1, "ServicesDown": 0, "EntryIP": "198.51.100.2", "X25519PublicKey": "k2" }]
            },
            {
                "Name": "SG-FREE#1",
                "Tier": 0,
                "Status": 1,
                "ExitCountry": "SG",
                "EntryCountry": "SG",
                "City": "Singapore",
                "Load": 40.0,
                "Domain": "sg-1.protonvpn.net",
                "Servers": [{ "Status": 1, "ServicesDown": 0, "EntryIP": "198.51.100.3", "X25519PublicKey": "k3" }]
            }
        ]
    });
    let nodes = select_free_servers_with_wg(&payload, None, false).expect("valid payload");
    let jp = nodes.iter().find(|n| n.name == "JP-FREE#1").unwrap();
    assert_eq!(jp.latitude, Some(35.6762));
    assert_eq!(jp.longitude, Some(139.6503));

    let us = nodes.iter().find(|n| n.name == "US-FREE#1").unwrap();
    assert_eq!(us.latitude, None);
    assert_eq!(us.longitude, None);

    let sg = nodes.iter().find(|n| n.name == "SG-FREE#1").unwrap();
    assert_eq!(sg.latitude, None);
    assert_eq!(sg.longitude, None);
}

#[test]
fn test_server_node_deserializes_legacy_json_without_coordinates() {
    let legacy = r#"{"name":"SG-FREE#1","country":"SG","entryCountry":"SG","city":"Singapore","load":50.0,"status":1,"domain":"d","entryIP":"1.1.1.1","exitIP":"1.1.1.1","x25519PublicKey":"k","activePhysicalServers":1,"pingTarget":"1.1.1.1","pingMs":40.0}"#;
    let node: ServerNode = serde_json::from_str(legacy).expect("legacy json deserializes");
    assert_eq!(node.latitude, None);
    assert_eq!(node.longitude, None);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --manifest-path rust/Cargo.toml -p freeton-core test_select_free_servers_parses_valid_location_and_rejects_invalid`  
Expected: FAIL with compile error (`no field latitude on type ServerNode`).

- [ ] **Step 3: Implement coordinate fields, parser validation, and update existing literals**

Add `latitude: Option<f64>` and `longitude: Option<f64>` (both `#[serde(default, deserialize_with = "deserialize_null_f64_opt")]`) to `ServerNode` in `rust/freeton-core/src/api.rs`. In `select_free_servers_with_wg`, extract `Location.Lat` and `Location.Long` via `as_f64()`; keep `(Some(lat), Some(lon))` only when both are present, finite, `(-90.0..=90.0).contains(&lat)`, and `(-180.0..=180.0).contains(&lon)`, otherwise `(None, None)`. Set `latitude: None, longitude: None` on the 5 existing `ServerNode` struct literals in `ping.rs`, `storage.rs`, `wg.rs`, and `state.rs` (2 sites).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --manifest-path rust/Cargo.toml -p freeton-core; cargo check --manifest-path rust/Cargo.toml --tests`  
Expected: PASS across `freeton-core` and clean test compilation across the workspace.

- [ ] **Step 5: Commit**

```powershell
git add rust/freeton-core/src/api.rs rust/freeton-core/src/ping.rs rust/freeton-core/src/storage.rs rust/freeton-core/src/wg.rs rust/freeton-app/src/state.rs
git commit -m "feat(core): parse optional latitude/longitude on ServerNode"
```

---

### Task 2: Create `ui/globe_data.rs` — Static World Landmass Polygons, Fibonacci-Sphere Land Dots & ISO Fallback Coordinates

**Files:**
- Create: `rust/freeton-app/src/ui/globe_data.rs`
- Modify: `rust/freeton-app/src/ui/mod.rs:1-4` (expose `pub mod globe_data;`)

**Interfaces:**
- Consumes: `std::sync::OnceLock`
- Produces:
  - `pub const DEFAULT_ORIGIN_COORDS: (f32, f32) = (14.0583, 108.2772);`
  - `pub fn fallback_country_coords(code: &str) -> Option<(f32, f32)>`
  - `pub fn is_land(lat_deg: f32, lon_deg: f32) -> bool`
  - `pub fn land_dots() -> &'static [[f32; 3]]`

- [ ] **Step 1: Create `rust/freeton-app/src/ui/globe_data.rs` with stub signatures and failing tests, and export `pub mod globe_data;` in `ui/mod.rs`**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_land_recognizes_major_landmasses_and_oceans() {
        let land_cities = [
            ("Tokyo", 35.68, 139.65),
            ("Singapore", 1.35, 103.82),
            ("Hanoi", 21.03, 105.85),
            ("Amsterdam", 52.37, 4.90),
            ("London", 51.50, -0.12),
            ("New York", 40.71, -74.00),
            ("Sao Paulo", -23.55, -46.63),
            ("Cairo", 30.04, 31.24),
            ("Sydney", -33.87, 151.21),
        ];
        for (name, lat, lon) in land_cities {
            assert!(is_land(lat, lon), "{name} ({lat}, {lon}) should be on land");
        }

        let oceans = [
            ("Pacific", 0.0, -140.0),
            ("Atlantic", 30.0, -40.0),
            ("Indian", -20.0, 80.0),
        ];
        for (name, lat, lon) in oceans {
            assert!(!is_land(lat, lon), "{name} ({lat}, {lon}) should be ocean");
        }
    }

    #[test]
    fn test_land_dots_count_and_unit_length() {
        let dots = land_dots();
        assert!(
            (1350..=1950).contains(&dots.len()),
            "expected ~1400-1900 land dots, got {}",
            dots.len()
        );
        for d in dots {
            assert!(d.iter().all(|v| v.is_finite()));
            let len = (d[0] * d[0] + d[1] * d[1] + d[2] * d[2]).sqrt();
            assert!((len - 1.0).abs() < 1e-4, "non-unit dot length: {len}");
        }
    }

    #[test]
    fn test_fallback_country_coords_covers_core_countries() {
        let required = [
            "SG", "JP", "US", "NL", "RO", "PL", "CH", "DE", "FR", "GB",
            "CA", "NO", "MX", "IS", "SE", "ES", "IT", "AU", "BR", "IN",
            "vn", "AT", "UA",
        ];
        for code in required {
            let (lat, lon) = fallback_country_coords(code)
                .unwrap_or_else(|| panic!("missing fallback for {code}"));
            assert!((-90.0..=90.0).contains(&lat));
            assert!((-180.0..=180.0).contains(&lon));
        }
        assert_eq!(fallback_country_coords("ZZ"), None);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --manifest-path rust/Cargo.toml -p freeton-app globe_data`  
Expected: FAIL (`is_land` / `land_dots` / `fallback_country_coords` return stub values).

- [ ] **Step 3: Implement `fallback_country_coords`, landmass polygons + `is_land`, and `land_dots` in `rust/freeton-app/src/ui/globe_data.rs`**

- `fallback_country_coords(code: &str) -> Option<(f32, f32)>`: trims `code` and matches `to_ascii_uppercase().as_str()` across all 20 `COUNTRY_NAMES` plus `AT, BE, BG, CZ, DK, EE, FI, GR, HK, HU, IE, IL, KR, LT, LU, LV, MD, NZ, PT, RS, SK, TW, UA, VN, ZA`.
- Landmass polygons: simplified closed `(lat, lon)` rings for North/Central America, Greenland, Cuba, South America, Europe/Iberia/Italy/Balkans, UK/Ireland, Scandinavia, Iceland, Africa, Madagascar, Asia/Middle East/India/Indochina/Malay Peninsula, Sumatra/Java/Borneo/Sulawesi, Philippines, Taiwan, Japan, Australia, New Zealand; `is_land` uses standard ray-casting point-in-polygon over each ring.
- `land_dots()`: uses `OnceLock<Vec<[f32; 3]>>` to sample `N = 5200` golden-angle Fibonacci sphere points (`y = 1 - 2*(i+0.5)/N`), convert `(x, y, z)` to `(lat_deg, lon_deg)`, filter via `is_land`, and convert kept points using the globe's unit-vector convention (`x = cos(lat)*sin(lon)`, `y = sin(lat)`, `z = cos(lat)*cos(lon)`). Tune `N` if needed so `dots.len()` lands squarely inside `1400..=1850`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --manifest-path rust/Cargo.toml -p freeton-app globe_data`  
Expected: PASS (all 3 tests green).

- [ ] **Step 5: Commit**

```powershell
git add rust/freeton-app/src/ui/globe_data.rs rust/freeton-app/src/ui/mod.rs
git commit -m "feat(app): add world land polygons, Fibonacci land dots, and ISO coords"
```

---

### Task 3: Create `ui/globe.rs` — 3D Math, Country Marker Aggregation, Flight State Machine & `egui::Painter` Renderer

**Files:**
- Create: `rust/freeton-app/src/ui/globe.rs`
- Modify: `rust/freeton-app/src/ui/mod.rs:1-4` (expose `pub mod globe;`)

**Interfaces:**
- Consumes: `ServerNode`, `sort_and_filter_servers`, `SortMode`, `get_country_display`, `globe_data::{DEFAULT_ORIGIN_COORDS, fallback_country_coords, land_dots}`, `ui::{C_ACCENT, C_BORDER, C_CARD, C_SURFACE, C_SUCCESS, C_TEXT, C_TEXT_DIM, C_TEXT_MUTED, C_WARNING, lerp_color, ping_status_color}`
- Produces:
  - `pub struct GlobeCountryMarker { pub country_code: String, pub display_name: String, pub lat: f32, pub lon: f32, pub server_count: usize, pub best_server: ServerNode, pub best_ping_ms: Option<f64> }`
  - `pub struct ProjectedMarker { pub idx: usize, pub pos: Pos2, pub z: f32 }`
  - `pub enum GlobeAction { None, ConnectCountry(ServerNode) }`
  - `pub struct GlobeRenderInputs<'a> { pub servers: &'a [ServerNode], pub selected_server: Option<&'a ServerNode>, pub connected_server: Option<&'a ServerNode>, pub is_connecting: bool, pub is_disconnecting: bool, pub tunnel_running: bool, pub tunnel_verified: bool, pub animations_enabled: bool, pub window_visible: bool }`
  - `pub struct GlobeState` (derives `Debug`, implements `Default` oriented toward Asia/Europe with `zoom = 1.0`, storing camera yaw/pitch/zoom, drag inertia, active flight `{ origin: (f32, f32), target: (f32, f32), target_country: String, progress: f32, landing_pulse: f32 }`, `arc_alpha: f32`, `last_synced_target: Option<String>`, `was_active_tunnel: bool`, `drag_distance: f32`, `is_dragging: bool`)
  - `pub fn lat_lon_to_unit(lat_deg: f32, lon_deg: f32) -> [f32; 3]`
  - `pub fn rotate_point(p: [f32; 3], yaw: f32, pitch: f32) -> [f32; 3]`
  - `pub fn shortest_angle_delta(from: f32, to: f32) -> f32`
  - `pub fn camera_angles_for_lat_lon(lat_deg: f32, lon_deg: f32) -> (f32, f32)`
  - `pub fn slerp_arc_points(origin: (f32, f32), target: (f32, f32), segments: usize, max_lift: f32) -> Vec<[f32; 3]>`
  - `pub fn build_country_markers(servers: &[ServerNode]) -> Vec<GlobeCountryMarker>`
  - `pub fn hit_test_marker(markers: &[ProjectedMarker], pointer: Pos2, hit_radius: f32) -> Option<usize>`
  - `pub fn sync_and_advance_globe(globe: &mut GlobeState, target_country: Option<(&str, (f32, f32))>, is_active_or_connecting: bool, animations_enabled: bool, hovering_marker: bool, dt: f32)`
  - `pub fn render_globe_widget(ui: &mut Ui, inputs: &GlobeRenderInputs<'_>, globe: &mut GlobeState, area_size: Vec2) -> GlobeAction`

- [ ] **Step 1: Create `rust/freeton-app/src/ui/globe.rs` with stub types/functions and failing unit tests, and export `pub mod globe;` in `ui/mod.rs`**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use freeton_core::api::ServerNode;

    fn mk_srv(name: &str, cc: &str, ping: Option<f64>, load: Option<f64>, lat: Option<f64>, lon: Option<f64>) -> ServerNode {
        ServerNode {
            name: name.to_owned(),
            country: cc.to_owned(),
            ping_ms: ping,
            load,
            latitude: lat,
            longitude: lon,
            ..ServerNode::default()
        }
    }

    #[test]
    fn test_build_country_markers_groups_averages_coords_and_picks_best() {
        let servers = vec![
            mk_srv("JP-FREE#2", "jp", Some(120.0), Some(80.0), Some(34.0), Some(135.0)),
            mk_srv("JP-FREE#1", "JP", Some(45.0), Some(20.0), Some(36.0), Some(139.0)),
            mk_srv("SG-FREE#1", "SG", Some(35.0), Some(40.0), None, None),
            mk_srv("NL-BAD", "NL", Some(90.0), Some(10.0), Some(f64::NAN), Some(400.0)),
            mk_srv("ZZ-UNK", "ZZ", Some(50.0), Some(10.0), None, None),
        ];
        let markers = build_country_markers(&servers);
        assert_eq!(markers.len(), 3, "ZZ without coords must be skipped");

        let jp = markers.iter().find(|m| m.country_code == "JP").unwrap();
        assert_eq!(jp.server_count, 2);
        assert_eq!(jp.best_server.name, "JP-FREE#1");
        assert!((jp.lat - 35.0).abs() < 1e-3);
        assert!((jp.lon - 137.0).abs() < 1e-3);

        let sg = markers.iter().find(|m| m.country_code == "SG").unwrap();
        let sg_fb = fallback_country_coords("SG").unwrap();
        assert!((sg.lat - sg_fb.0).abs() < 1e-3);

        let nl = markers.iter().find(|m| m.country_code == "NL").unwrap();
        let nl_fb = fallback_country_coords("NL").unwrap();
        assert!(nl.lat.is_finite() && (nl.lat - nl_fb.0).abs() < 1e-3);
    }

    #[test]
    fn test_slerp_arc_and_shortest_angle_handle_antimeridian_antipodal_and_identical() {
        let delta = shortest_angle_delta(3.0, -3.0);
        assert!(delta.abs() < 0.35, "expected short wrap across PI, got {delta}");

        for (o, t) in [
            ((35.67, 139.65), (37.77, -122.41)),
            ((0.0, 0.0), (0.0, 180.0)),
            ((14.0583, 108.2772), (14.0583, 108.2772)),
        ] {
            let pts = slerp_arc_points(o, t, 32, 0.25);
            assert_eq!(pts.len(), 33);
            assert!(pts.iter().all(|p| p.iter().all(|v| v.is_finite())));
        }
    }

    #[test]
    fn test_hit_test_ignores_back_hemisphere_and_prefers_closest_front_marker() {
        let markers = vec![
            ProjectedMarker { idx: 0, pos: Pos2::new(100.0, 100.0), z: 0.05 }, // back/edge -> ignored
            ProjectedMarker { idx: 1, pos: Pos2::new(103.0, 100.0), z: 0.70 }, // 3px away
            ProjectedMarker { idx: 2, pos: Pos2::new(108.0, 100.0), z: 0.90 }, // 8px away
            ProjectedMarker { idx: 3, pos: Pos2::new(125.0, 100.0), z: 0.99 }, // >14px -> ignored
        ];
        assert_eq!(hit_test_marker(&markers, Pos2::new(100.0, 100.0), 14.0), Some(1));
        assert_eq!(hit_test_marker(&markers, Pos2::new(150.0, 150.0), 14.0), None);
    }

    #[test]
    fn test_flight_origin_transitions_and_disabled_animations() {
        let mut globe = GlobeState::default();
        let sg = fallback_country_coords("SG").unwrap();
        let jp = fallback_country_coords("JP").unwrap();

        // Idle -> Connect starts from Vietnam
        sync_and_advance_globe(&mut globe, Some(("SG", sg)), true, true, false, 0.016);
        let flight = globe.flight.as_ref().expect("flight started");
        assert_eq!(flight.origin, DEFAULT_ORIGIN_COORDS);
        assert_eq!(flight.target_country, "SG");
        assert!(flight.progress < 1.0);

        // Switching SG -> JP starts from SG
        sync_and_advance_globe(&mut globe, Some(("JP", jp)), true, true, false, 0.016);
        let flight2 = globe.flight.as_ref().expect("switch flight started");
        assert_eq!(flight2.origin, sg);
        assert_eq!(flight2.target_country, "JP");

        // Disabled animations snap immediately
        let mut instant = GlobeState::default();
        sync_and_advance_globe(&mut instant, Some(("SG", sg)), true, false, false, 0.016);
        assert_eq!(instant.flight.as_ref().unwrap().progress, 1.0);
        assert!((instant.zoom - 1.16).abs() < 1e-4);

        // Disconnect fades arc and eases zoom back toward 1.0
        sync_and_advance_globe(&mut instant, Some(("SG", sg)), false, true, false, 0.40);
        assert!(instant.arc_alpha < 0.05);
        assert!(instant.zoom < 1.10);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --manifest-path rust/Cargo.toml -p freeton-app globe::tests`  
Expected: FAIL.

- [ ] **Step 3: Implement `rust/freeton-app/src/ui/globe.rs`**

Key design values from spec:
- Camera math: `lat_lon_to_unit`, `rotate_point` (yaw around Y, pitch around X clamped to `[-65°, +65°]`), `shortest_angle_delta`, `camera_angles_for_lat_lon` (rotates target `(lat, lon)` to front `+Z` with a slight downward tilt offset so the arc sits nicely in frame).
- `slerp_arc_points`: uses normalized chord/dot slerp with fallback linear blend when `dot > 0.9995` or `dot < -0.9995` (orthogonal mid-vector for antipodal), applying radial lift `1.0 + (PI * u).sin() * max_lift` (where `max_lift` scales smoothly with great-circle angle up to `0.28`).
- `build_country_markers`: groups by uppercase trimmed `country`, computes centroid of finite in-range `(lat, lon)` servers or falls back to `fallback_country_coords`, calls `sort_and_filter_servers(servers, Some(&code), "", SortMode::Best)` to get `best_server`, sorts deterministically by country code.
- `hit_test_marker`: filters `m.z > 0.08`, finds markers with `(m.pos - pointer).length() <= hit_radius`, returns index minimizing `(dist, -z)`.
- `sync_and_advance_globe`:
  - Flight duration `0.95s` cubic ease-out (`1.0 - (1.0 - p).powi(3)`), target zoom `1.16`, disconnect arc fade `0.30s`, drag inertia decay `(-dt * 5.0).exp()`, idle auto-spin `~6°/s` (`0.1047 rad/s`) only when `!is_active_or_connecting && !globe.is_dragging && !hovering_marker && animations_enabled`.
  - Records `origin` as previous active target coords when `was_active_tunnel` is true, else `DEFAULT_ORIGIN_COORDS`.
  - When `!animations_enabled`, snaps `progress = 1.0`, `zoom = 1.16` (if active) or `1.0` (if idle), clears inertia, and triggers zero repaint loops.
- `render_globe_widget`:
  - Allocates `area_size`, computes `radius = (area_size.x.min(area_size.y - 20.0) * 0.45).clamp(48.0, 108.0)` and `center = Pos2::new(rect.center().x, rect.top() + (area_size.y - 20.0) * 0.5)`.
  - Handles drag (`Sense::click_and_drag()` inside the globe rect), accumulating pointer delta into `drag_distance` and rotating `(yaw, pitch)`, applying release velocity when drag ends, and only emitting `GlobeAction::ConnectCountry(best_server)` when clicked (`released` with `drag_distance < 5.0`) on a hit marker.
  - Draws dark glass disk (`#121922`), layered atmospheric rim, faint equator/meridians, back-limb (`-0.25 < z <= 0.0`) & front (`z > 0.0`) land dots, elevated glowing 3D arc + comet head / flowing pulse, origin anchor dot, sorted country markers (`ping_status_color`, hovered ring, active `C_SUCCESS`/`C_WARNING` radar ripple), floating tooltip clamped inside `rect`, and bottom 1-line caption.
  - Requests repaint (`16ms` during flight/drag/inertia/connecting, `33ms` during idle spin or connected pulse) **only** when `inputs.window_visible && inputs.animations_enabled`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --manifest-path rust/Cargo.toml -p freeton-app globe`  
Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add rust/freeton-app/src/ui/globe.rs rust/freeton-app/src/ui/mod.rs
git commit -m "feat(app): implement 3D dot-matrix globe widget with flight animation"
```

---

### Task 4: Wire `GlobeState` into `AppState` & Redesign `ui/home.rs` (`390×610`)

**Files:**
- Modify: `rust/freeton-app/src/state.rs:973-979`, `rust/freeton-app/src/state.rs:1074-1083`
- Modify: `rust/freeton-app/src/ui/home.rs:17-449`, `rust/freeton-app/src/ui/home.rs:520-714`

**Interfaces:**
- Consumes: `crate::ui::globe::{GlobeAction, GlobeRenderInputs, GlobeState, render_globe_widget}`, `AppState::{toggle_vpn, select_and_connect_server, show_login_view, show_drawer_view, formatted_session_timer}`
- Produces: `pub globe: GlobeState` on `AppState`, `pub(crate) fn handle_globe_action(state: &mut AppState, action: GlobeAction)`, redesigned `render_home_view`

- [ ] **Step 1: Add/update tests in `rust/freeton-app/src/ui/home.rs`**

1. Update `test_home_layout_fits_cleanly_inside_390x610_across_banner_states` to check clean, connected, and busy stacked-banner states, asserting both `max_widget_bottom <= panel_inner_bottom + 0.5` and `max_right <= WINDOW_WIDTH - 14.0 + 0.5`.
2. Add `test_home_globe_click_respects_auth_and_connecting_guards`:
   - `!is_logged_in` + `ConnectCountry` → `current_view == AppView::Login`, `pending_commands` has no connect.
   - `is_logged_in`, `is_connecting_vpn = true` → `ConnectCountry` is ignored (`selected_server` unchanged).
   - `is_logged_in`, `closing = true` → `ConnectCountry` is ignored.
   - `is_logged_in`, idle → `ConnectCountry(srv)` updates `selected_server`, sets `is_connecting_vpn = true`.
3. Add `test_home_globe_requests_no_short_repaint_when_hidden_or_animations_disabled`:
   - Run `ctx.run_ui` on `render_root` with `window_visible = false` (`animations_enabled = true`, `tunnel_running = false`) and verify `out.viewport_output.values().all(|v| v.repaint_delay >= Duration::from_millis(100))`.
   - Run `ctx.run_ui` with `window_visible = true` and `animations_enabled = false` (`tunnel_running = false`) and verify `out.viewport_output.values().all(|v| v.repaint_delay >= Duration::from_millis(100))`.

- [ ] **Step 2: Run tests to verify new tests fail**

Run: `cargo test --manifest-path rust/Cargo.toml -p freeton-app ui::home::tests`  
Expected: FAIL (`handle_globe_action` not found / `AppState.globe` missing).

- [ ] **Step 3: Wire `GlobeState` into `AppState` and redesign `render_home_view` in `rust/freeton-app/src/ui/home.rs`**

- In `rust/freeton-app/src/state.rs`, add `pub globe: crate::ui::globe::GlobeState` to `AppState` and initialize `globe: crate::ui::globe::GlobeState::default()` in `AppState::new`.
- In `rust/freeton-app/src/ui/home.rs`:
  - Implement `pub(crate) fn handle_globe_action(state: &mut AppState, action: GlobeAction)`:
    - On `GlobeAction::ConnectCountry(server)`: if `!state.is_logged_in` -> `state.show_login_view()`; else if `!state.is_connecting_vpn && !state.closing` -> `state.select_and_connect_server(server)`.
  - Update `render_home_view`:
    - **Top Status + Toggle Card:** Split horizontally via `ui.horizontal`: left column (`(avail_w - toggle_w - 10.0).max(160.0)`) renders `KẾT NỐI CỦA BẠN` + compact inline timer pill (`formatted_session_timer`), status heading (`17.0px` bold), and wrapped subtitle (`10.5px`); right column vertically centers `ios_toggle_switch` (`72×38` normal, `64×34` compact) and calls `state.toggle_vpn()` on click.
    - **Optional UAC Banner:** Preserved verbatim below top card.
    - **Central Globe Arena:** Compute `reserved_bottom = server_card_est_h + between_card_and_chips + footer_chips_h + footer_bottom_pad`; claim `globe_h = (ui.available_height() - reserved_bottom).max(108.0)`; build `GlobeRenderInputs` from `state` fields and call `render_globe_widget(ui, &inputs, &mut state.globe, Vec2::new(ui.available_width(), globe_h))`; pass action to `handle_globe_action(state, action)`. (Suppress short timer `request_repaint_after(1s)` in `home.rs` when `!state.window_visible` so hidden-window repaint test stays strict.)
    - **Bottom Server Card & Footer Chips:** Preserved cleanly inside `reserved_bottom`, with `server_card` click opening `state.show_drawer_view()`.

- [ ] **Step 4: Run full workspace verification**

Run: `cargo test --manifest-path rust/Cargo.toml; cargo check --manifest-path rust/Cargo.toml --all-targets`  
Expected: ALL tests PASS and `cargo check --all-targets` exits 0 with zero warnings.

- [ ] **Step 5: Commit**

```powershell
git add rust/freeton-app/src/state.rs rust/freeton-app/src/ui/home.rs
git commit -m "feat(app): integrate 3D globe and merged status toggle into Home view"
```
