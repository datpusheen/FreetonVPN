use std::collections::HashMap;
use std::f32::consts::PI;

use egui::{
    Align2, Color32, CornerRadius, CursorIcon, FontId, Pos2, Rect, Sense, Shape, Stroke, Ui, Vec2,
};
use freeton_core::api::ServerNode;
use freeton_core::ping::{get_country_display, sort_and_filter_servers, SortMode};

use crate::ui::globe_data::{fallback_country_coords, land_dots, DEFAULT_ORIGIN_COORDS};
use crate::ui::{
    lerp_color, ping_status_color, C_ACCENT, C_BORDER, C_SUCCESS, C_SURFACE, C_TEXT, C_TEXT_DIM,
    C_WARNING,
};

const MAX_PITCH_RAD: f32 = 1.134_464; // 65 degrees
const TARGET_ZOOM_ACTIVE: f32 = 1.16;
const FLIGHT_DURATION_SECS: f32 = 0.95;
const ARC_FADE_OUT_SECS: f32 = 0.30;
const LANDING_PULSE_SECS: f32 = 0.80;
const DRAG_CLICK_THRESHOLD_PX: f32 = 5.0;
const MARKER_HIT_RADIUS_PX: f32 = 14.0;
const IDLE_SPIN_RAD_PER_SEC: f32 = 0.104_72; // ~6 deg/sec

#[derive(Debug, Clone)]
pub struct GlobeCountryMarker {
    pub country_code: String,
    pub display_name: String,
    pub lat: f32,
    pub lon: f32,
    pub server_count: usize,
    pub best_server: ServerNode,
    pub best_ping_ms: Option<f64>,
}

#[derive(Debug, Clone, Copy)]
pub struct ProjectedMarker {
    pub idx: usize,
    pub pos: Pos2,
    pub z: f32,
}

#[derive(Debug, Clone)]
pub enum GlobeAction {
    None,
    ConnectCountry(ServerNode),
}

pub struct GlobeRenderInputs<'a> {
    pub servers: &'a [ServerNode],
    pub selected_server: Option<&'a ServerNode>,
    pub connected_server: Option<&'a ServerNode>,
    pub is_connecting: bool,
    pub is_disconnecting: bool,
    pub tunnel_running: bool,
    pub tunnel_verified: bool,
    pub animations_enabled: bool,
    pub window_visible: bool,
}

#[derive(Debug, Clone)]
pub struct GlobeFlight {
    pub origin: (f32, f32),
    pub target: (f32, f32),
    pub target_country: String,
    pub progress: f32,
    pub landing_pulse: f32,
    pub start_yaw: f32,
    pub start_pitch: f32,
    pub start_zoom: f32,
    pub camera_locked: bool,
}

#[derive(Debug, Clone)]
pub struct GlobeState {
    pub yaw: f32,
    pub pitch: f32,
    pub zoom: f32,
    pub vel_yaw: f32,
    pub vel_pitch: f32,
    pub flight: Option<GlobeFlight>,
    pub arc_alpha: f32,
    pub last_synced_target: Option<String>,
    pub was_active_tunnel: bool,
    pub drag_distance: f32,
    pub is_dragging: bool,
    pub last_frame_time: Option<f64>,
}

impl Default for GlobeState {
    fn default() -> Self {
        let (yaw, pitch) = camera_angles_for_lat_lon(16.0, 102.0);
        Self {
            yaw,
            pitch,
            zoom: 1.0,
            vel_yaw: 0.0,
            vel_pitch: 0.0,
            flight: None,
            arc_alpha: 0.0,
            last_synced_target: None,
            was_active_tunnel: false,
            drag_distance: 0.0,
            is_dragging: false,
            last_frame_time: None,
        }
    }
}

pub fn lat_lon_to_unit(lat_deg: f32, lon_deg: f32) -> [f32; 3] {
    let lat = lat_deg.to_radians();
    let lon = lon_deg.to_radians();
    let cos_lat = lat.cos();
    [cos_lat * lon.sin(), lat.sin(), cos_lat * lon.cos()]
}

pub fn rotate_point(p: [f32; 3], yaw: f32, pitch: f32) -> [f32; 3] {
    let (sy, cy) = yaw.sin_cos();
    let (sp, cp) = pitch.sin_cos();

    let x1 = p[0] * cy + p[2] * sy;
    let z1 = -p[0] * sy + p[2] * cy;

    let y2 = p[1] * cp - z1 * sp;
    let z2 = p[1] * sp + z1 * cp;

    [x1, y2, z2]
}

fn normalize_angle(mut angle: f32) -> f32 {
    while angle > PI {
        angle -= 2.0 * PI;
    }
    while angle < -PI {
        angle += 2.0 * PI;
    }
    angle
}

pub fn shortest_angle_delta(from: f32, to: f32) -> f32 {
    normalize_angle(to - from)
}

pub fn camera_angles_for_lat_lon(lat_deg: f32, lon_deg: f32) -> (f32, f32) {
    let yaw = normalize_angle(-lon_deg.to_radians());
    let pitch = lat_deg.to_radians().clamp(-MAX_PITCH_RAD, MAX_PITCH_RAD);
    (yaw, pitch)
}

fn normalize_vec3(v: [f32; 3]) -> [f32; 3] {
    let len_sq = v[0] * v[0] + v[1] * v[1] + v[2] * v[2];
    if !len_sq.is_finite() || len_sq <= 1e-12 {
        return [0.0, 0.0, 1.0];
    }
    let inv = len_sq.sqrt().recip();
    [v[0] * inv, v[1] * inv, v[2] * inv]
}

pub fn slerp_arc_points(
    origin: (f32, f32),
    target: (f32, f32),
    segments: usize,
    max_lift: f32,
) -> Vec<[f32; 3]> {
    let steps = segments.max(1);
    let a = normalize_vec3(lat_lon_to_unit(origin.0, origin.1));
    let b = normalize_vec3(lat_lon_to_unit(target.0, target.1));
    let dot = (a[0] * b[0] + a[1] * b[1] + a[2] * b[2]).clamp(-1.0, 1.0);
    let omega = dot.acos();
    let lift = if omega < 1e-4 {
        0.0
    } else {
        max_lift.max(0.0) * (omega / PI).clamp(0.22, 1.0)
    };

    let ortho = if dot < -0.9995 {
        let up = if a[1].abs() > 0.9 {
            [1.0_f32, 0.0, 0.0]
        } else {
            [0.0_f32, 1.0, 0.0]
        };
        normalize_vec3([
            a[1] * up[2] - a[2] * up[1],
            a[2] * up[0] - a[0] * up[2],
            a[0] * up[1] - a[1] * up[0],
        ])
    } else {
        [0.0, 1.0, 0.0]
    };

    let mut out = Vec::with_capacity(steps + 1);
    for i in 0..=steps {
        let u = i as f32 / steps as f32;
        let base = if dot > 0.9995 {
            normalize_vec3([
                a[0] + (b[0] - a[0]) * u,
                a[1] + (b[1] - a[1]) * u,
                a[2] + (b[2] - a[2]) * u,
            ])
        } else if dot < -0.9995 {
            let ang = PI * u;
            let (s, c) = ang.sin_cos();
            normalize_vec3([
                a[0] * c + ortho[0] * s,
                a[1] * c + ortho[1] * s,
                a[2] * c + ortho[2] * s,
            ])
        } else {
            let sin_omega = omega.sin().max(1e-6);
            let wa = ((1.0 - u) * omega).sin() / sin_omega;
            let wb = (u * omega).sin() / sin_omega;
            normalize_vec3([
                a[0] * wa + b[0] * wb,
                a[1] * wa + b[1] * wb,
                a[2] * wa + b[2] * wb,
            ])
        };

        let radial = 1.0 + (PI * u).sin() * lift;
        out.push([base[0] * radial, base[1] * radial, base[2] * radial]);
    }
    out
}

fn valid_server_coords(srv: &ServerNode) -> Option<(f32, f32)> {
    let lat = srv.latitude?;
    let lon = srv.longitude?;
    if lat.is_finite()
        && lon.is_finite()
        && (-90.0..=90.0).contains(&lat)
        && (-180.0..=180.0).contains(&lon)
    {
        Some((lat as f32, lon as f32))
    } else {
        None
    }
}

pub fn build_country_markers(servers: &[ServerNode]) -> Vec<GlobeCountryMarker> {
    let mut grouped: HashMap<String, Vec<&ServerNode>> = HashMap::new();
    for srv in servers {
        let code = srv.country.trim().to_ascii_uppercase();
        if !code.is_empty() {
            grouped.entry(code).or_default().push(srv);
        }
    }

    let mut markers = Vec::with_capacity(grouped.len());
    for (code, list) in grouped {
        let mut lat_sum = 0.0_f64;
        let mut lon_sum = 0.0_f64;
        let mut coord_count = 0usize;
        for srv in &list {
            if let Some((lat, lon)) = valid_server_coords(srv) {
                lat_sum += f64::from(lat);
                lon_sum += f64::from(lon);
                coord_count += 1;
            }
        }
        let coords = if coord_count > 0 {
            Some((
                (lat_sum / coord_count as f64) as f32,
                (lon_sum / coord_count as f64) as f32,
            ))
        } else {
            fallback_country_coords(&code)
        };
        let Some((lat, lon)) = coords else {
            continue;
        };

        let owned_list: Vec<ServerNode> = list.iter().map(|s| (*s).clone()).collect();
        let (best_opt, sorted) = sort_and_filter_servers(&owned_list, Some(&code), "", SortMode::Best);
        let Some(best_server) = best_opt.or_else(|| sorted.into_iter().next()) else {
            continue;
        };
        let best_ping_ms = list
            .iter()
            .filter_map(|s| s.ping_ms.filter(|v| v.is_finite() && *v >= 0.0))
            .min_by(f64::total_cmp)
            .or(best_server.ping_ms);

        markers.push(GlobeCountryMarker {
            display_name: get_country_display(&code).into_owned(),
            country_code: code,
            lat,
            lon,
            server_count: list.len(),
            best_server,
            best_ping_ms,
        });
    }

    markers.sort_by(|a, b| a.country_code.cmp(&b.country_code));
    markers
}

pub fn hit_test_marker(
    markers: &[ProjectedMarker],
    pointer: Pos2,
    hit_radius: f32,
) -> Option<usize> {
    let mut best: Option<(usize, f32, f32)> = None;
    for m in markers {
        if m.z <= 0.08 {
            continue;
        }
        let dist = (m.pos - pointer).length();
        if dist > hit_radius {
            continue;
        }
        let replace = match best {
            None => true,
            Some((_, best_dist, best_z)) => {
                dist < best_dist - 0.5 || ((dist - best_dist).abs() <= 0.5 && m.z > best_z)
            }
        };
        if replace {
            best = Some((m.idx, dist, m.z));
        }
    }
    best.map(|(idx, _, _)| idx)
}

pub fn sync_and_advance_globe(
    globe: &mut GlobeState,
    target_country: Option<(&str, (f32, f32))>,
    is_active_or_connecting: bool,
    animations_enabled: bool,
    hovering_marker: bool,
    dt: f32,
) {
    let dt = dt.max(0.0);

    if is_active_or_connecting {
        if let Some((cc, target_coords)) = target_country {
            let target_changed = globe.last_synced_target.as_deref() != Some(cc);
            if !globe.was_active_tunnel || target_changed {
                let origin = if globe.was_active_tunnel {
                    globe
                        .flight
                        .as_ref()
                        .map(|f| f.target)
                        .unwrap_or(DEFAULT_ORIGIN_COORDS)
                } else {
                    DEFAULT_ORIGIN_COORDS
                };
                globe.flight = Some(GlobeFlight {
                    origin,
                    target: target_coords,
                    target_country: cc.to_owned(),
                    progress: if animations_enabled { 0.0 } else { 1.0 },
                    landing_pulse: 0.0,
                    start_yaw: globe.yaw,
                    start_pitch: globe.pitch,
                    start_zoom: globe.zoom,
                    camera_locked: true,
                });
                globe.last_synced_target = Some(cc.to_owned());
                globe.vel_yaw = 0.0;
                globe.vel_pitch = 0.0;
            }
        }
        globe.was_active_tunnel = true;

        if !animations_enabled {
            globe.arc_alpha = 1.0;
            globe.zoom = TARGET_ZOOM_ACTIVE;
            globe.vel_yaw = 0.0;
            globe.vel_pitch = 0.0;
            if let Some(flight) = &mut globe.flight {
                flight.progress = 1.0;
                flight.landing_pulse = 0.0;
                let (ty, tp) = camera_angles_for_lat_lon(flight.target.0, flight.target.1);
                globe.yaw = ty;
                globe.pitch = tp;
            }
        } else {
            globe.arc_alpha = (globe.arc_alpha + dt / 0.22).min(1.0);
            if let Some(flight) = &mut globe.flight {
                let prev_progress = flight.progress;
                if flight.progress < 1.0 {
                    flight.progress = (flight.progress + dt / FLIGHT_DURATION_SECS).min(1.0);
                    let e = 1.0 - (1.0 - flight.progress).powi(3);
                    if flight.camera_locked && !globe.is_dragging {
                        let (ty, tp) = camera_angles_for_lat_lon(flight.target.0, flight.target.1);
                        let dy = shortest_angle_delta(flight.start_yaw, ty);
                        globe.yaw = normalize_angle(flight.start_yaw + dy * e);
                        globe.pitch = (flight.start_pitch + (tp - flight.start_pitch) * e)
                            .clamp(-MAX_PITCH_RAD, MAX_PITCH_RAD);
                        globe.zoom = flight.start_zoom + (TARGET_ZOOM_ACTIVE - flight.start_zoom) * e;
                    }
                    if prev_progress < 1.0 && flight.progress >= 1.0 {
                        flight.landing_pulse = 1.0;
                    }
                } else if flight.landing_pulse > 0.0 {
                    flight.landing_pulse = (flight.landing_pulse - dt / LANDING_PULSE_SECS).max(0.0);
                }
            }
        }
    } else {
        globe.was_active_tunnel = false;
        globe.last_synced_target = None;

        if !animations_enabled {
            globe.arc_alpha = 0.0;
            globe.zoom = 1.0;
            globe.vel_yaw = 0.0;
            globe.vel_pitch = 0.0;
            globe.flight = None;
        } else {
            globe.arc_alpha = (globe.arc_alpha - dt / ARC_FADE_OUT_SECS).max(0.0);
            if globe.arc_alpha <= 0.0 {
                globe.flight = None;
            }
            let zoom_t = (dt * 6.0).min(1.0);
            globe.zoom += (1.0 - globe.zoom) * zoom_t;
        }
    }

    if !globe.is_dragging && animations_enabled {
        if globe.vel_yaw.abs() > 0.002 || globe.vel_pitch.abs() > 0.002 {
            globe.yaw = normalize_angle(globe.yaw + globe.vel_yaw * dt);
            globe.pitch = (globe.pitch + globe.vel_pitch * dt).clamp(-MAX_PITCH_RAD, MAX_PITCH_RAD);
            let damp = (-dt * 5.0).exp();
            globe.vel_yaw *= damp;
            globe.vel_pitch *= damp;
        } else {
            globe.vel_yaw = 0.0;
            globe.vel_pitch = 0.0;
            if !is_active_or_connecting && !hovering_marker {
                globe.yaw = normalize_angle(globe.yaw + IDLE_SPIN_RAD_PER_SEC * dt);
            }
        }
    }
}

fn project_unit(p: [f32; 3], center: Pos2, scale: f32) -> (Pos2, f32) {
    (
        Pos2::new(center.x + p[0] * scale, center.y - p[1] * scale),
        p[2],
    )
}

fn target_coords_for_inputs(
    inputs: &GlobeRenderInputs<'_>,
    markers: &[GlobeCountryMarker],
) -> Option<(String, (f32, f32))> {
    let srv = inputs.connected_server.or(inputs.selected_server)?;
    let cc = srv.country.trim().to_ascii_uppercase();
    if cc.is_empty() {
        return None;
    }
    if let Some(coords) = valid_server_coords(srv) {
        return Some((cc, coords));
    }
    if let Some(m) = markers.iter().find(|m| m.country_code == cc) {
        return Some((cc, (m.lat, m.lon)));
    }
    fallback_country_coords(&cc).map(|coords| (cc, coords))
}

pub fn render_globe_widget(
    ui: &mut Ui,
    inputs: &GlobeRenderInputs<'_>,
    globe: &mut GlobeState,
    area_size: Vec2,
) -> GlobeAction {
    let alloc_w = area_size.x.max(120.0);
    let alloc_h = area_size.y.max(96.0);
    let (rect, response) = ui.allocate_exact_size(Vec2::new(alloc_w, alloc_h), Sense::click_and_drag());

    let caption_h = 18.0;
    let globe_h = (rect.height() - caption_h).max(76.0);
    let base_radius = (rect.width().min(globe_h) * 0.445).clamp(36.0, 106.0);
    let center = Pos2::new(rect.center().x, rect.top() + globe_h * 0.5);

    let now_time = ui.ctx().input(|i| i.time);
    let dt = match globe.last_frame_time {
        Some(prev) if now_time >= prev => ((now_time - prev) as f32).clamp(0.0, 0.1),
        _ => 0.016,
    };
    globe.last_frame_time = Some(now_time);

    let markers = build_country_markers(inputs.servers);
    let is_active_or_connecting =
        (inputs.tunnel_running || inputs.is_connecting) && !inputs.is_disconnecting;

    // Handle pointer drag first so user drag immediately overrides flight camera lock.
    let pointer_pos = response.hover_pos().or_else(|| ui.ctx().pointer_latest_pos());
    if response.drag_started() {
        globe.is_dragging = true;
        globe.drag_distance = 0.0;
        globe.vel_yaw = 0.0;
        globe.vel_pitch = 0.0;
        if let Some(flight) = &mut globe.flight {
            flight.camera_locked = false;
        }
    }
    if response.dragged() {
        let delta = response.drag_delta();
        globe.drag_distance += delta.length();
        let sens = (1.6 / base_radius.max(32.0)).clamp(0.008, 0.032);
        let dyaw = delta.x * sens;
        let dpitch = delta.y * sens;
        globe.yaw = normalize_angle(globe.yaw + dyaw);
        globe.pitch = (globe.pitch + dpitch).clamp(-MAX_PITCH_RAD, MAX_PITCH_RAD);
        if dt > 0.001 && inputs.animations_enabled {
            globe.vel_yaw = (dyaw / dt).clamp(-3.5, 3.5);
            globe.vel_pitch = (dpitch / dt).clamp(-2.5, 2.5);
        }
    }
    if response.drag_stopped() {
        globe.is_dragging = false;
    }

    let scale_pre = base_radius * globe.zoom;
    let projected_pre: Vec<ProjectedMarker> = markers
        .iter()
        .enumerate()
        .map(|(idx, m)| {
            let rot = rotate_point(lat_lon_to_unit(m.lat, m.lon), globe.yaw, globe.pitch);
            let (pos, z) = project_unit(rot, center, scale_pre);
            ProjectedMarker { idx, pos, z }
        })
        .collect();

    let hovered_pre = pointer_pos
        .filter(|pos| rect.contains(*pos))
        .and_then(|pos| hit_test_marker(&projected_pre, pos, MARKER_HIT_RADIUS_PX));

    let target_info = target_coords_for_inputs(inputs, &markers);
    let target_ref = target_info
        .as_ref()
        .map(|(cc, coords)| (cc.as_str(), *coords));

    sync_and_advance_globe(
        globe,
        target_ref,
        is_active_or_connecting,
        inputs.animations_enabled,
        hovered_pre.is_some(),
        dt,
    );

    let scale = base_radius * globe.zoom;
    let projected: Vec<ProjectedMarker> = markers
        .iter()
        .enumerate()
        .map(|(idx, m)| {
            let rot = rotate_point(lat_lon_to_unit(m.lat, m.lon), globe.yaw, globe.pitch);
            let (pos, z) = project_unit(rot, center, scale);
            ProjectedMarker { idx, pos, z }
        })
        .collect();

    let hovered_idx = if globe.is_dragging {
        None
    } else {
        pointer_pos
            .filter(|pos| rect.contains(*pos))
            .and_then(|pos| hit_test_marker(&projected, pos, MARKER_HIT_RADIUS_PX))
    };

    if hovered_idx.is_some() {
        let _ = response.clone().on_hover_cursor(CursorIcon::PointingHand);
    } else if globe.is_dragging {
        let _ = response.clone().on_hover_cursor(CursorIcon::Grabbing);
    } else if response.hovered() {
        let _ = response.clone().on_hover_cursor(CursorIcon::Grab);
    }

    let mut action = GlobeAction::None;
    let is_clean_click = response.clicked() && globe.drag_distance < DRAG_CLICK_THRESHOLD_PX;
    if is_clean_click {
        if let Some(idx) = hovered_idx {
            action = GlobeAction::ConnectCountry(markers[idx].best_server.clone());
        }
    }

    if ui.is_rect_visible(rect) {
        let p = ui.painter().with_clip_rect(rect);
        let accent_tone = if inputs.is_connecting
            || inputs.is_disconnecting
            || (inputs.tunnel_running && !inputs.tunnel_verified)
        {
            C_WARNING
        } else if inputs.tunnel_verified {
            C_SUCCESS
        } else {
            C_ACCENT
        };

        // 1. Atmospheric outer halo + Dark Glass sphere disk
        p.circle_stroke(
            center,
            scale + 5.0,
            Stroke::new(
                4.0,
                Color32::from_rgba_unmultiplied(
                    accent_tone.r(),
                    accent_tone.g(),
                    accent_tone.b(),
                    16,
                ),
            ),
        );
        p.circle_stroke(
            center,
            scale + 1.5,
            Stroke::new(
                1.5,
                Color32::from_rgba_unmultiplied(
                    accent_tone.r(),
                    accent_tone.g(),
                    accent_tone.b(),
                    38,
                ),
            ),
        );
        p.circle_filled(center, scale, Color32::from_rgb(0x11, 0x18, 0x22));
        // Subtle off-center ambient spherical shading
        p.circle_filled(
            Pos2::new(center.x - scale * 0.22, center.y - scale * 0.22),
            scale * 0.62,
            Color32::from_rgba_unmultiplied(0x28, 0x3a, 0x4b, 26),
        );
        p.circle_stroke(
            center,
            scale,
            Stroke::new(
                1.1,
                lerp_color(
                    C_BORDER,
                    accent_tone,
                    if inputs.tunnel_verified { 0.55 } else { 0.25 },
                ),
            ),
        );

        // 2. Faint spherical latitude/longitude graticule (front hemisphere only)
        let grat_stroke = Stroke::new(0.7, Color32::from_rgba_unmultiplied(0x5a, 0x76, 0x8a, 24));
        for lat_deg in [-30.0_f32, 0.0, 30.0] {
            let mut seg = Vec::new();
            for step in 0..=48 {
                let lon_deg = -180.0 + (step as f32 / 48.0) * 360.0;
                let rot = rotate_point(lat_lon_to_unit(lat_deg, lon_deg), globe.yaw, globe.pitch);
                if rot[2] > 0.0 {
                    seg.push(project_unit(rot, center, scale).0);
                } else if seg.len() >= 2 {
                    p.add(Shape::line(std::mem::take(&mut seg), grat_stroke));
                } else {
                    seg.clear();
                }
            }
            if seg.len() >= 2 {
                p.add(Shape::line(seg, grat_stroke));
            }
        }
        for lon_deg in [0.0_f32, 45.0, 90.0, 135.0] {
            let mut seg = Vec::new();
            for step in 0..=48 {
                let ang = (step as f32 / 48.0) * 2.0 * PI;
                let u = [
                    ang.cos() * lon_deg.to_radians().sin(),
                    ang.sin(),
                    ang.cos() * lon_deg.to_radians().cos(),
                ];
                let rot = rotate_point(u, globe.yaw, globe.pitch);
                if rot[2] > 0.0 {
                    seg.push(project_unit(rot, center, scale).0);
                } else if seg.len() >= 2 {
                    p.add(Shape::line(std::mem::take(&mut seg), grat_stroke));
                } else {
                    seg.clear();
                }
            }
            if seg.len() >= 2 {
                p.add(Shape::line(seg, grat_stroke));
            }
        }

        // 3. Cyber Dot-Matrix Continents (back-limb translucent + front depth-shaded)
        let horizon_col = Color32::from_rgb(0x23, 0x33, 0x42);
        let front_col = if inputs.tunnel_verified {
            Color32::from_rgb(0x63, 0xac, 0xa2)
        } else {
            Color32::from_rgb(0x47, 0x73, 0x7e)
        };
        let back_col = Color32::from_rgba_unmultiplied(0x3a, 0x56, 0x66, 18);

        for &dot in land_dots() {
            let rot = rotate_point(dot, globe.yaw, globe.pitch);
            if rot[2] > 0.0 {
                let (pos, z) = project_unit(rot, center, scale);
                let dot_r = 0.9 + z * 0.72;
                let col = lerp_color(horizon_col, front_col, z.powf(0.75));
                p.circle_filled(pos, dot_r, col);
            } else if rot[2] > -0.26 {
                let (pos, _) = project_unit(rot, center, scale);
                p.circle_filled(pos, 0.85, back_col);
            }
        }

        // 4. Elevated 3D Great-Circle Flight Arc & Origin Anchor
        if let Some(flight) = &globe.flight {
            if globe.arc_alpha > 0.01 {
                let arc_3d = slerp_arc_points(flight.origin, flight.target, 36, 0.28);
                let visible_count = ((flight.progress * (arc_3d.len() - 1) as f32).ceil() as usize + 1)
                    .min(arc_3d.len());
                let mut arc_screen: Vec<Pos2> = Vec::with_capacity(visible_count);
                for &pt in &arc_3d[..visible_count] {
                    let rot = rotate_point(pt, globe.yaw, globe.pitch);
                    if rot[2] > -0.14 {
                        arc_screen.push(project_unit(rot, center, scale).0);
                    } else if arc_screen.len() >= 2 {
                        let a_u8 = (globe.arc_alpha * 72.0).round() as u8;
                        let core_u8 = (globe.arc_alpha * 235.0).round() as u8;
                        p.add(Shape::line(
                            arc_screen.clone(),
                            Stroke::new(
                                4.5,
                                Color32::from_rgba_unmultiplied(
                                    accent_tone.r(),
                                    accent_tone.g(),
                                    accent_tone.b(),
                                    a_u8,
                                ),
                            ),
                        ));
                        p.add(Shape::line(
                            std::mem::take(&mut arc_screen),
                            Stroke::new(
                                1.8,
                                Color32::from_rgba_unmultiplied(
                                    accent_tone.r(),
                                    accent_tone.g(),
                                    accent_tone.b(),
                                    core_u8,
                                ),
                            ),
                        ));
                    } else {
                        arc_screen.clear();
                    }
                }
                if arc_screen.len() >= 2 {
                    let a_u8 = (globe.arc_alpha * 72.0).round() as u8;
                    let core_u8 = (globe.arc_alpha * 235.0).round() as u8;
                    p.add(Shape::line(
                        arc_screen.clone(),
                        Stroke::new(
                            4.5,
                            Color32::from_rgba_unmultiplied(
                                accent_tone.r(),
                                accent_tone.g(),
                                accent_tone.b(),
                                a_u8,
                            ),
                        ),
                    ));
                    p.add(Shape::line(
                        arc_screen,
                        Stroke::new(
                            1.8,
                            Color32::from_rgba_unmultiplied(
                                accent_tone.r(),
                                accent_tone.g(),
                                accent_tone.b(),
                                core_u8,
                            ),
                        ),
                    ));
                }

                // Origin anchor dot
                let orig_rot = rotate_point(
                    lat_lon_to_unit(flight.origin.0, flight.origin.1),
                    globe.yaw,
                    globe.pitch,
                );
                if orig_rot[2] > -0.05 {
                    let (orig_pos, _) = project_unit(orig_rot, center, scale);
                    let oa = (globe.arc_alpha * 190.0).round() as u8;
                    p.circle_filled(
                        orig_pos,
                        5.2,
                        Color32::from_rgba_unmultiplied(
                            C_ACCENT.r(),
                            C_ACCENT.g(),
                            C_ACCENT.b(),
                            (globe.arc_alpha * 55.0).round() as u8,
                        ),
                    );
                    p.circle_filled(
                        orig_pos,
                        2.4,
                        Color32::from_rgba_unmultiplied(C_TEXT.r(), C_TEXT.g(), C_TEXT.b(), oa),
                    );
                }

                // Comet tip during flight OR traveling packet pulse after landing
                let tip_idx = if flight.progress < 1.0 {
                    (flight.progress * (arc_3d.len() - 1) as f32)
                        .round()
                        .clamp(0.0, (arc_3d.len() - 1) as f32) as usize
                } else if inputs.animations_enabled {
                    let phase = (now_time as f32 * 0.65).fract();
                    (phase * (arc_3d.len() - 1) as f32)
                        .round()
                        .clamp(0.0, (arc_3d.len() - 1) as f32) as usize
                } else {
                    arc_3d.len() - 1
                };
                let tip_rot = rotate_point(arc_3d[tip_idx], globe.yaw, globe.pitch);
                if tip_rot[2] > -0.10 {
                    let (tip_pos, _) = project_unit(tip_rot, center, scale);
                    p.circle_filled(
                        tip_pos,
                        6.5,
                        Color32::from_rgba_unmultiplied(
                            accent_tone.r(),
                            accent_tone.g(),
                            accent_tone.b(),
                            (globe.arc_alpha * 90.0).round() as u8,
                        ),
                    );
                    p.circle_filled(
                        tip_pos,
                        2.8,
                        Color32::from_rgba_unmultiplied(
                            255,
                            255,
                            255,
                            (globe.arc_alpha * 240.0).round() as u8,
                        ),
                    );
                }
            }
        }

        // 5. Country Markers (sorted back-to-front by depth z)
        let mut draw_order: Vec<ProjectedMarker> =
            projected.iter().copied().filter(|m| m.z > -0.06).collect();
        draw_order.sort_by(|a, b| a.z.total_cmp(&b.z));

        let active_country_code = target_info.as_ref().map(|(cc, _)| cc.as_str());
        for pm in draw_order {
            let marker = &markers[pm.idx];
            let is_hovered = hovered_idx == Some(pm.idx);
            let is_target = active_country_code == Some(marker.country_code.as_str());
            let depth_fade: f32 = if pm.z > 0.08 { 1.0 } else { 0.45 };

            let base_col = if is_target && is_active_or_connecting {
                accent_tone
            } else {
                marker
                    .best_ping_ms
                    .map(|ms| ping_status_color(Some(ms)))
                    .unwrap_or(C_ACCENT)
            };

            let halo_r = if is_hovered {
                9.5
            } else if is_target {
                8.0
            } else {
                6.0
            };
            let core_r = if is_hovered {
                4.4
            } else if is_target {
                3.8
            } else {
                2.8
            };
            let halo_alpha = ((if is_hovered || is_target { 72.0 } else { 42.0 }) * depth_fade)
                .round() as u8;
            let core_alpha = (245.0 * depth_fade).round() as u8;

            p.circle_filled(
                pm.pos,
                halo_r,
                Color32::from_rgba_unmultiplied(
                    base_col.r(),
                    base_col.g(),
                    base_col.b(),
                    halo_alpha,
                ),
            );
            p.circle_filled(
                pm.pos,
                core_r,
                Color32::from_rgba_unmultiplied(
                    base_col.r(),
                    base_col.g(),
                    base_col.b(),
                    core_alpha,
                ),
            );

            if is_hovered {
                p.circle_stroke(pm.pos, 7.5, Stroke::new(1.3, C_TEXT));
            } else if is_target {
                p.circle_stroke(pm.pos, 6.4, Stroke::new(1.2, accent_tone));
            }

            // Radar shockwave / steady pulse on active target
            if is_target && is_active_or_connecting && inputs.animations_enabled {
                let landing = globe
                    .flight
                    .as_ref()
                    .map(|f| f.landing_pulse)
                    .unwrap_or(0.0);
                if landing > 0.0 {
                    let expand = 1.0 - landing;
                    let r = 6.0 + expand * 18.0;
                    let a = (landing * 190.0).round() as u8;
                    p.circle_stroke(
                        pm.pos,
                        r,
                        Stroke::new(
                            1.8,
                            Color32::from_rgba_unmultiplied(
                                accent_tone.r(),
                                accent_tone.g(),
                                accent_tone.b(),
                                a,
                            ),
                        ),
                    );
                } else {
                    let phase = (now_time as f32 * 1.35).fract();
                    let r = 6.0 + phase * 11.0;
                    let a = ((1.0 - phase) * 125.0).round() as u8;
                    p.circle_stroke(
                        pm.pos,
                        r,
                        Stroke::new(
                            1.4,
                            Color32::from_rgba_unmultiplied(
                                accent_tone.r(),
                                accent_tone.g(),
                                accent_tone.b(),
                                a,
                            ),
                        ),
                    );
                }
            }
        }

        // 6. Clamped Floating Hover Tooltip
        if let Some(idx) = hovered_idx {
            let marker = &markers[idx];
            let pm = projected[idx];
            let ping_txt = match marker.best_ping_ms {
                Some(ms) => format!("{ms:.0} ms"),
                None => "-- ms".to_owned(),
            };
            let tip_text = format!(
                "{} • {} • {} sv",
                marker.display_name, ping_txt, marker.server_count
            );
            let font = FontId::proportional(11.0);
            let galley = p.layout_no_wrap(tip_text, font, C_TEXT);
            let pad = Vec2::new(8.0, 5.0);
            let tip_size = galley.size() + pad * 2.0;

            let raw_x = pm.pos.x - tip_size.x * 0.5;
            let raw_y = if pm.pos.y - tip_size.y - 12.0 >= rect.top() + 2.0 {
                pm.pos.y - tip_size.y - 12.0
            } else {
                pm.pos.y + 12.0
            };
            let max_x = (rect.right() - tip_size.x - 2.0).max(rect.left() + 2.0);
            let max_y = (rect.bottom() - caption_h - tip_size.y - 2.0).max(rect.top() + 2.0);
            let tip_pos = Pos2::new(
                raw_x.clamp(rect.left() + 2.0, max_x),
                raw_y.clamp(rect.top() + 2.0, max_y),
            );
            let tip_rect = Rect::from_min_size(tip_pos, tip_size);
            p.rect_filled(tip_rect, CornerRadius::same(7), C_SURFACE);
            p.rect_stroke(
                tip_rect,
                CornerRadius::same(7),
                Stroke::new(1.0, C_ACCENT),
                egui::StrokeKind::Inside,
            );
            p.galley(tip_pos + pad, galley, C_TEXT);
        }

        // 7. Bottom 1-line instruction / status caption inside arena
        let caption = if let Some(idx) = hovered_idx {
            format!(
                "Bấm để kết nối tới {} ({})",
                markers[idx].display_name, markers[idx].best_server.name
            )
        } else if inputs.tunnel_verified {
            if let Some(srv) = inputs.connected_server {
                format!("WIREGUARD  •  Đang mã hóa qua {}", get_country_display(&srv.country))
            } else {
                "WIREGUARD  •  KẾT NỐI MÃ HÓA".to_owned()
            }
        } else if inputs.is_connecting {
            "WIREGUARD  •  Đang thiết lập đường hầm 3D...".to_owned()
        } else {
            "WIREGUARD  •  Kéo để xoay, bấm nước để kết nối".to_owned()
        };
        p.text(
            Pos2::new(rect.center().x, rect.bottom() - 3.0),
            Align2::CENTER_BOTTOM,
            caption,
            FontId::proportional(10.0),
            if hovered_idx.is_some() { C_ACCENT } else { C_TEXT_DIM },
        );
    }

    // 8. Battery & tray-friendly repaint policy
    if inputs.window_visible && inputs.animations_enabled {
        let fast_anim = globe.is_dragging
            || globe.vel_yaw.abs() > 0.002
            || globe.vel_pitch.abs() > 0.002
            || inputs.is_connecting
            || inputs.is_disconnecting
            || globe
                .flight
                .as_ref()
                .is_some_and(|f| f.progress < 1.0 || f.landing_pulse > 0.0)
            || (!is_active_or_connecting && globe.arc_alpha > 0.01)
            || (globe.zoom - 1.0).abs() > 0.005 && !is_active_or_connecting;

        if fast_anim {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(16));
        } else {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(33));
        }
    }

    action
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::globe_data::{fallback_country_coords, DEFAULT_ORIGIN_COORDS};
    use freeton_core::api::ServerNode;

    fn mk_srv(
        name: &str,
        cc: &str,
        ping: Option<f64>,
        load: Option<f64>,
        lat: Option<f64>,
        lon: Option<f64>,
    ) -> ServerNode {
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
    fn test_camera_angles_center_target_on_front_hemisphere() {
        for (lat, lon) in [
            (1.35, 103.82),
            (35.68, 139.65),
            (39.83, -98.58),
            (52.37, 4.90),
            (-33.87, 151.21),
        ] {
            let (yaw, pitch) = camera_angles_for_lat_lon(lat, lon);
            let rotated = rotate_point(lat_lon_to_unit(lat, lon), yaw, pitch);
            assert!(
                rotated[2] > 0.9,
                "expected ({lat}, {lon}) to face front (+Z), got {:?}",
                rotated
            );
        }
    }

    #[test]
    fn test_hit_test_ignores_back_hemisphere_and_prefers_closest_front_marker() {
        let markers = vec![
            ProjectedMarker {
                idx: 0,
                pos: Pos2::new(100.0, 100.0),
                z: 0.05,
            },
            ProjectedMarker {
                idx: 1,
                pos: Pos2::new(103.0, 100.0),
                z: 0.70,
            },
            ProjectedMarker {
                idx: 2,
                pos: Pos2::new(108.0, 100.0),
                z: 0.90,
            },
            ProjectedMarker {
                idx: 3,
                pos: Pos2::new(125.0, 100.0),
                z: 0.99,
            },
        ];
        assert_eq!(hit_test_marker(&markers, Pos2::new(100.0, 100.0), 14.0), Some(1));
        assert_eq!(hit_test_marker(&markers, Pos2::new(150.0, 150.0), 14.0), None);
    }

    #[test]
    fn test_flight_origin_transitions_and_disabled_animations() {
        let mut globe = GlobeState::default();
        let sg = fallback_country_coords("SG").unwrap();
        let jp = fallback_country_coords("JP").unwrap();

        sync_and_advance_globe(&mut globe, Some(("SG", sg)), true, true, false, 0.016);
        let flight = globe.flight.as_ref().expect("flight started");
        assert_eq!(flight.origin, DEFAULT_ORIGIN_COORDS);
        assert_eq!(flight.target_country, "SG");
        assert!(flight.progress < 1.0);

        sync_and_advance_globe(&mut globe, Some(("JP", jp)), true, true, false, 0.016);
        let flight2 = globe.flight.as_ref().expect("switch flight started");
        assert_eq!(flight2.origin, sg);
        assert_eq!(flight2.target_country, "JP");

        let mut instant = GlobeState::default();
        sync_and_advance_globe(&mut instant, Some(("SG", sg)), true, false, false, 0.016);
        assert_eq!(instant.flight.as_ref().unwrap().progress, 1.0);
        assert!((instant.zoom - 1.16).abs() < 1e-4);

        sync_and_advance_globe(&mut instant, Some(("SG", sg)), false, true, false, 0.40);
        assert!(instant.arc_alpha < 0.05);
        assert!(instant.zoom < 1.10);
    }
}
