use std::time::{SystemTime, UNIX_EPOCH};

use egui::{
    Align, Color32, CornerRadius, CursorIcon, Layout, Margin, Pos2, Response, RichText, Sense,
    Stroke, StrokeKind, Ui, Vec2,
};
use freeton_core::ping::get_country_display;
use freeton_core::storage::CredentialStore;

use crate::state::{AppState, ServiceHealthStatus};
use crate::ui::globe::{render_globe_widget, GlobeAction, GlobeRenderInputs};
use crate::ui::{
    lerp_color, load_status_color, pill_button, ping_status_color, rounded_card, PillStyle,
    C_ACCENT, C_BG, C_BORDER, C_CARD, C_CARD_HIGH, C_DANGER, C_SUCCESS, C_TEXT, C_TEXT_DIM,
    C_TEXT_MUTED, C_TOGGLE_CONNECTING, C_TOGGLE_OFF, C_TOGGLE_ON, C_WARNING,
};

pub(crate) fn handle_globe_action(state: &mut AppState, action: GlobeAction) {
    if let GlobeAction::ConnectCountry(server) = action {
        if !state.is_logged_in {
            state.show_login_view();
        } else if !state.is_connecting_vpn && !state.closing {
            state.select_and_connect_server(server);
        }
    }
}

pub fn render_home_view(ui: &mut Ui, state: &mut AppState, store: &dyn CredentialStore) {
    ui.add_space(4.0);

    let initial_avail_h = ui.available_height().max(0.0);
    let compact = initial_avail_h < 460.0
        || matches!(state.service_health, ServiceHealthStatus::Unavailable(_));

    // 1. Merged Top Protection Status + Toggle Card
    let (status_border, status_title, status_title_color, status_sub, status_sub_color) = if state
        .closing
    {
        (
            C_WARNING,
            "ĐANG THOÁT...",
            C_WARNING,
            "Đang ngắt WireGuard Tunnel và dọn dẹp kết nối...".to_owned(),
            C_TEXT_MUTED,
        )
    } else if state.is_connecting_vpn && !state.is_disconnecting_vpn {
        let (country, entry_ip, addr, port) = if let Some(srv) = &state.selected_server {
            (
                srv.country.clone(),
                if !srv.entry_ip.is_empty() {
                    srv.entry_ip.clone()
                } else if !srv.ping_target.is_empty() {
                    srv.ping_target.clone()
                } else {
                    srv.domain.clone()
                },
                state.client_config.address.clone(),
                state
                    .client_config
                    .port
                    .trim()
                    .parse::<u16>()
                    .unwrap_or(51820),
            )
        } else {
            state.effective_endpoint_and_interface()
        };
        let _ = country;
        let srv_name = state
            .selected_server
            .as_ref()
            .map(|s| s.name.as_str())
            .unwrap_or("Proton Server");
        (
            C_WARNING,
            "ĐANG KẾT NỐI...",
            C_WARNING,
            format!("{srv_name} • {entry_ip}:{port} • {addr}"),
            C_TEXT,
        )
    } else if state.is_disconnecting_vpn {
        (
            C_WARNING,
            "ĐANG NGẮT KẾT NỐI...",
            C_WARNING,
            "Đang ngắt WireGuard Tunnel & hoàn trả mạng...".to_owned(),
            C_TEXT_MUTED,
        )
    } else if state.tunnel_running && state.tunnel_verified {
        let (country_code, entry_ip, addr, port) = state.effective_endpoint_and_interface();
        let country_disp = get_country_display(&country_code);
        let sub = if let Some(pub_ip) = &state.live_public_ip {
            format!("Exit IP: {pub_ip} ({country_disp})\n{entry_ip}:{port} • {addr}")
        } else {
            format!("Mã hóa qua {country_disp} • {entry_ip}:{port}\nIP Nội bộ: {addr}")
        };
        (C_SUCCESS, "ĐÃ KẾT NỐI", C_SUCCESS, sub, C_TEXT)
    } else if state.tunnel_running {
        let reason = state
            .tunnel_unverified_reason
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("Tunnel đang bật nhưng chưa xác minh handshake/DNS.");
        (
            C_WARNING,
            "VPN CHƯA XÁC MINH",
            C_WARNING,
            format!("{reason}\nBấm công tắc để ngắt hoặc chọn nước khác."),
            C_WARNING,
        )
    } else {
        (
            C_BORDER,
            "CHƯA BẬT VPN",
            C_TEXT,
            "Gạt công tắc hoặc chạm quốc gia trên địa cầu".to_owned(),
            C_TEXT_MUTED,
        )
    };

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(0))
        .unwrap_or(0);
    let (tone, timer_full_text) = state.formatted_session_timer(now_unix);
    if state.tunnel_verified && state.window_visible {
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_secs(1));
    }
    let timer_color = match tone {
        "success" => C_SUCCESS,
        "warning" => C_WARNING,
        _ => C_TEXT_DIM,
    };
    let badge_text = if state.tunnel_verified {
        let hhmmss = timer_full_text
            .split_whitespace()
            .last()
            .unwrap_or("00:00:00");
        format!("● {hhmmss}")
    } else if state.is_connecting_vpn && !state.is_disconnecting_vpn {
        "● Đang kết nối".to_owned()
    } else if state.is_disconnecting_vpn {
        "● Đang ngắt".to_owned()
    } else if state.tunnel_running {
        "● Chưa xác minh".to_owned()
    } else {
        "● Sẵn sàng".to_owned()
    };

    let top_toggle_w = if compact { 64.0 } else { 72.0 };
    let top_toggle_h = if compact { 34.0 } else { 38.0 };
    let top_pad_y = if compact { 8 } else { 10 };
    let mut toggle_clicked = false;
    let toggle_on =
        (state.tunnel_running || state.is_connecting_vpn) && !state.is_disconnecting_vpn;

    rounded_card(
        ui,
        C_CARD,
        status_border,
        14,
        Margin::symmetric(12, top_pad_y),
        |ui| {
            let row_w = ui.available_width();
            ui.set_width(row_w);
            let gap_x = 10.0;
            let left_w = (row_w - top_toggle_w - gap_x).max(140.0);
            ui.with_layout(Layout::left_to_right(Align::Min), |ui| {
                ui.spacing_mut().item_spacing.x = gap_x;
                let left_resp = ui.allocate_ui_with_layout(
                    Vec2::new(left_w, 0.0),
                    Layout::top_down(Align::Min),
                    |ui| {
                        ui.set_width(left_w);
                        ui.spacing_mut().item_spacing.y = 3.0;
                        ui.allocate_ui_with_layout(
                            Vec2::new(left_w, 18.0),
                            Layout::left_to_right(Align::Center),
                            |ui| {
                                ui.spacing_mut().item_spacing.x = 6.0;
                                ui.label(
                                    RichText::new("KẾT NỐI CỦA BẠN")
                                        .size(10.0)
                                        .strong()
                                        .color(C_TEXT_DIM),
                                );
                                let badge_style = PillStyle {
                                    bg: C_CARD_HIGH,
                                    fg: timer_color,
                                    border: timer_color,
                                    hover_bg: C_CARD_HIGH,
                                    hover_fg: timer_color,
                                    hover_border: timer_color,
                                    radius: 6,
                                    height: 18.0,
                                    font_size: 9.5,
                                    bold: true,
                                    pad_x: 6.0,
                                };
                                let _ = pill_button(ui, &badge_text, None, badge_style);
                            },
                        );
                        ui.add(
                            egui::Label::new(
                                RichText::new(status_title)
                                    .size(if compact { 16.5 } else { 17.5 })
                                    .strong()
                                    .color(status_title_color),
                            )
                            .wrap(),
                        );
                        ui.add(
                            egui::Label::new(
                                RichText::new(status_sub)
                                    .size(10.5)
                                    .color(status_sub_color),
                            )
                            .wrap(),
                        );
                    },
                );

                let left_h = left_resp.response.rect.height();
                ui.allocate_ui_with_layout(
                    Vec2::new(ui.available_width().max(top_toggle_w), left_h.max(top_toggle_h)),
                    Layout::right_to_left(Align::Center),
                    |ui| {
                        if ios_toggle_switch(
                            ui,
                            "home_vpn_toggle",
                            toggle_on,
                            state.is_connecting_vpn,
                            state.client_config.animations_enabled,
                            Vec2::new(top_toggle_w, top_toggle_h),
                        )
                        .clicked()
                        {
                            toggle_clicked = true;
                        }
                    },
                );
            });
        },
    );
    if toggle_clicked {
        state.toggle_vpn();
    }

    if matches!(state.service_health, ServiceHealthStatus::Unavailable(_)) && !state.closing {
        ui.add_space(4.0);
        let repair_pill = PillStyle {
            bg: Color32::from_rgb(0x2b, 0x22, 0x16),
            fg: C_WARNING,
            border: C_WARNING,
            hover_bg: Color32::from_rgb(0x3a, 0x2d, 0x1c),
            hover_fg: C_TEXT,
            hover_border: C_WARNING,
            radius: 9,
            height: 26.0,
            font_size: 11.0,
            bold: true,
            pad_x: 10.0,
        };
        if pill_button(
            ui,
            "⚠ Dịch vụ VPN chưa sẵn sàng • Bấm để sửa (UAC)",
            Some(ui.available_width()),
            repair_pill,
        )
        .clicked()
        {
            state.open_service_repair_dialog();
        }
    }

    // 2. Central Interactive 3D Globe Area + 3. Location Card + 4. Bottom Action Chips
    let available_after_status = ui.available_height().max(0.0);
    let spacing_y = ui.spacing().item_spacing.y;
    let footer_chips_h = 34.0;
    let footer_bottom_pad = 2.0;
    let server_card_est_h = if compact { 90.0 } else { 98.0 };
    let between_card_and_chips = if compact { 6.0 } else { 8.0 };
    let reserved_bottom =
        server_card_est_h + between_card_and_chips + footer_chips_h + footer_bottom_pad;
    let globe_h = (available_after_status - reserved_bottom - spacing_y * 2.0).max(96.0);

    let globe_action = {
        let inputs = GlobeRenderInputs {
            servers: &state.all_free_servers,
            selected_server: state.selected_server.as_ref(),
            connected_server: state.connected_server.as_ref(),
            user_origin: (state.user_location.lat, state.user_location.lon),
            user_country: state.user_location.country.as_deref(),
            is_connecting: state.is_connecting_vpn,
            is_disconnecting: state.is_disconnecting_vpn,
            tunnel_running: state.tunnel_running,
            tunnel_verified: state.tunnel_verified,
            animations_enabled: state.client_config.animations_enabled,
            window_visible: state.window_visible,
        };
        render_globe_widget(
            ui,
            &inputs,
            &mut state.globe,
            Vec2::new(ui.available_width(), globe_h),
        )
    };
    handle_globe_action(state, globe_action);

    // 3. Selected Server / Location Card (smooth hover-in / hover-out border & fill highlight)
    let anim_dur = if state.client_config.animations_enabled {
        0.14
    } else {
        0.0
    };
    let card_hover_id = ui.scope_id().with("home_server_card_hover");
    let prev_hovered = ui
        .ctx()
        .data(|d| d.get_temp::<bool>(card_hover_id).unwrap_or(false));
    let card_hover_t = ui
        .ctx()
        .animate_bool_with_time(card_hover_id, prev_hovered, anim_dur);
    let card_fill = lerp_color(C_CARD, C_CARD_HIGH, card_hover_t * 0.35);
    let card_border = lerp_color(C_BORDER, C_ACCENT, card_hover_t * 0.85);
    let card_pad_y = if compact { 8 } else { 10 };
    let server_card_resp = rounded_card(
        ui,
        card_fill,
        card_border,
        14,
        Margin::symmetric(12, card_pad_y),
        |ui| {
            let card_inner_w = ui.available_width();
            ui.set_width(card_inner_w);
            ui.spacing_mut().item_spacing.y = 3.0;
            ui.horizontal(|ui| {
                let lbl_resp = ui.label(
                    RichText::new("VỊ TRÍ MÁY CHỦ")
                        .size(10.0)
                        .strong()
                        .color(C_TEXT_DIM),
                );
                let rem_w =
                    (card_inner_w - lbl_resp.rect.width() - ui.spacing().item_spacing.x).max(40.0);
                ui.allocate_ui_with_layout(
                    Vec2::new(rem_w, 16.0),
                    Layout::right_to_left(Align::Center),
                    |ui| {
                        ui.label(
                            RichText::new("Đổi vị trí ❯")
                                .size(11.0)
                                .strong()
                                .color(C_ACCENT),
                        );
                    },
                );
            });

            let (title, ping_text, ping_color, load_text, load_color) =
                if let Some(srv) = &state.selected_server {
                    let c_disp = get_country_display(&srv.country);
                    let title = format!("{c_disp} ({})", srv.name);
                    let pt = match srv.ping_ms {
                        Some(ms) => format!("Ping: {ms:.0} ms"),
                        None => "Ping: -- ms".to_owned(),
                    };
                    let pc = ping_status_color(srv.ping_ms);
                    let lt = match srv.load {
                        Some(pct) => format!("Tải: {pct:.0}%"),
                        None => "Tải: --%".to_owned(),
                    };
                    let lc = load_status_color(srv.load);
                    (title, pt, pc, lt, lc)
                } else {
                    (
                        "Đang tìm node tốt nhất...".to_owned(),
                        "Ping: -- ms".to_owned(),
                        C_TEXT_MUTED,
                        "Tải: --%".to_owned(),
                        C_TEXT_MUTED,
                    )
                };

            ui.label(RichText::new(title).size(14.0).strong().color(C_TEXT));
            ui.add_space(2.0);

            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                let ping_pill = PillStyle {
                    bg: C_CARD_HIGH,
                    fg: ping_color,
                    border: C_BORDER,
                    hover_bg: C_CARD_HIGH,
                    hover_fg: ping_color,
                    hover_border: C_ACCENT,
                    radius: 7,
                    height: 25.0,
                    font_size: 11.0,
                    bold: true,
                    pad_x: 10.0,
                };
                if pill_button(ui, &ping_text, None, ping_pill).clicked() {
                    state.show_drawer_view();
                }

                let load_pill = PillStyle {
                    bg: C_CARD_HIGH,
                    fg: load_color,
                    border: C_BORDER,
                    hover_bg: C_CARD_HIGH,
                    hover_fg: load_color,
                    hover_border: C_ACCENT,
                    radius: 7,
                    height: 25.0,
                    font_size: 11.0,
                    bold: true,
                    pad_x: 10.0,
                };
                if pill_button(ui, &load_text, None, load_pill).clicked() {
                    state.show_drawer_view();
                }
            });
        },
    )
    .response
    .interact(Sense::click())
    .on_hover_cursor(CursorIcon::PointingHand);

    ui.ctx()
        .data_mut(|d| d.insert_temp(card_hover_id, server_card_resp.hovered()));
    if server_card_resp.clicked() {
        state.show_drawer_view();
    }

    // 4. Bottom Action Chips — allocate an explicit 34px strip above bottom margin so Layout::bottom_up
    // never mis-measures horizontal row height and clips buttons past CentralPanel bounds.
    ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
        let row_w = ui.available_width();
        ui.allocate_ui_with_layout(
            Vec2::new(row_w, footer_chips_h),
            Layout::left_to_right(Align::Center),
            |ui| {
                let show_export = state.client_config.debug_mode;
                let count = if show_export { 4 } else { 3 };
                let gap = 6.0;
                ui.spacing_mut().item_spacing.x = gap;
                let total_w = ui.available_width();
                let btn_w = ((total_w - gap * (count - 1) as f32) / count as f32).max(58.0);
                let chip_style = PillStyle {
                    font_size: if show_export { 11.0 } else { 12.0 },
                    pad_x: if show_export { 6.0 } else { 10.0 },
                    ..PillStyle::secondary(34.0)
                };

                if show_export
                    && pill_button(ui, "💾 Xuất .conf", Some(btn_w), chip_style).clicked()
                {
                    state.export_selected_conf();
                }

                if pill_button(ui, "Cài đặt", Some(btn_w), chip_style).clicked() {
                    state.open_settings_dialog();
                }

                if pill_button(ui, "Giới thiệu", Some(btn_w), chip_style).clicked() {
                    state.open_about_dialog();
                }

                let logout_style = PillStyle {
                    fg: if state.is_logged_in {
                        C_TEXT_MUTED
                    } else {
                        C_ACCENT
                    },
                    hover_fg: if state.is_logged_in {
                        C_DANGER
                    } else {
                        C_ACCENT
                    },
                    hover_border: if state.is_logged_in {
                        C_DANGER
                    } else {
                        C_ACCENT
                    },
                    ..chip_style
                };
                let auth_lbl = if state.is_logged_in {
                    "Đăng xuất"
                } else {
                    "🔑 Đăng nhập"
                };
                if pill_button(ui, auth_lbl, Some(btn_w), logout_style).clicked() {
                    if state.is_logged_in {
                        state.request_logout(store);
                    } else {
                        state.show_login_view();
                    }
                }
            },
        );
    });

    let _ = C_BG;
}

pub fn ios_toggle_switch(
    ui: &mut Ui,
    id_salt: impl std::hash::Hash + std::fmt::Debug,
    on: bool,
    connecting: bool,
    animations_enabled: bool,
    size: Vec2,
) -> Response {
    let (rect, response) = ui.allocate_exact_size(size, Sense::click());
    let response = response.on_hover_cursor(CursorIcon::PointingHand);

    let anim_time = if animations_enabled { 0.16 } else { 0.0 };
    let target = on;
    let anim_id = egui::Id::unique("freeton_ios_toggle").with(id_salt);
    let t = ui.ctx().animate_bool_with_time(anim_id, target, anim_time);

    if ui.is_rect_visible(rect) {
        let p = ui.painter();
        let radius = rect.height() * 0.5;
        let track_color = if connecting {
            C_TOGGLE_CONNECTING
        } else {
            lerp_color(C_TOGGLE_OFF, C_TOGGLE_ON, t)
        };
        if connecting && animations_enabled {
            let phase = (ui.ctx().input(|i| i.time) as f32 * 2.4).fract();
            let expand = phase * 6.0;
            let halo_alpha = ((1.0 - phase) * 95.0).round().clamp(0.0, 255.0) as u8;
            let halo_rect = rect.expand(expand);
            p.rect_stroke(
                halo_rect,
                CornerRadius::same((radius + expand).round().min(255.0) as u8),
                Stroke::new(
                    2.0,
                    Color32::from_rgba_unmultiplied(0xf5, 0x9e, 0x0b, halo_alpha),
                ),
                StrokeKind::Outside,
            );
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(33));
        }
        p.rect_filled(rect, CornerRadius::same(radius.round() as u8), track_color);

        let knob_r = radius - (rect.height() * 0.045).max(2.5);
        let min_x = rect.left() + radius;
        let max_x = rect.right() - radius;
        let knob_x = min_x + (max_x - min_x) * t;
        let knob_y = rect.center().y;

        p.circle_filled(
            Pos2::new(knob_x, knob_y + 2.0),
            knob_r,
            Color32::from_rgb(0x11, 0x11, 0x16),
        );
        p.circle_filled(Pos2::new(knob_x, knob_y), knob_r, Color32::WHITE);

        if response.hovered() {
            p.rect_stroke(
                rect,
                CornerRadius::same(radius.round() as u8),
                Stroke::new(1.0, Color32::from_white_alpha(38)),
                StrokeKind::Inside,
            );
        }
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui::Rect;
    use freeton_core::storage::{ClientConfig, StorageError};

    struct NoopStore;
    impl CredentialStore for NoopStore {
        fn get_password(&self, _: &str, _: &str) -> Result<Option<String>, StorageError> {
            Ok(None)
        }
        fn set_password(&self, _: &str, _: &str, _: &str) -> Result<(), StorageError> {
            Ok(())
        }
        fn delete_password(&self, _: &str, _: &str) -> Result<(), StorageError> {
            Ok(())
        }
    }

    fn collect_text(shapes: &[egui::epaint::ClippedShape]) -> String {
        let mut out = String::new();
        fn visit(shape: &egui::epaint::Shape, out: &mut String) {
            match shape {
                egui::epaint::Shape::Text(t) => {
                    out.push_str(t.galley.text());
                    out.push('\n');
                }
                egui::epaint::Shape::Vec(items) => {
                    for s in items {
                        visit(s, out);
                    }
                }
                _ => {}
            }
        }
        for clipped in shapes {
            visit(&clipped.shape, &mut out);
        }
        out
    }

    #[test]
    fn test_home_renders_tunnel_unverified_reason() {
        let ctx = egui::Context::default();
        let store = NoopStore;
        let mut state = AppState::new(
            true,
            Some("user@proton.me".to_owned()),
            ClientConfig::default(),
            None,
            Vec::new(),
        );
        state.tunnel_running = true;
        state.tunnel_verified = false;
        state.tunnel_unverified_reason = Some("DNS qua VPN chưa phản hồi.".to_owned());

        let raw_input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(
                Pos2::ZERO,
                Vec2::new(crate::ui::WINDOW_WIDTH, crate::ui::WINDOW_HEIGHT),
            )),
            ..Default::default()
        };
        let mut out = ctx.run_ui(raw_input, |ui| {
            render_home_view(ui, &mut state, &store);
        });
        out.textures_delta.clear();
        let rendered = collect_text(&out.shapes);
        assert!(
            rendered.contains("VPN CHƯA XÁC MINH"),
            "expected unverified heading in rendered home text: {rendered}"
        );
        assert!(
            rendered.contains("DNS qua VPN chưa phản hồi."),
            "expected tunnel_unverified_reason in rendered home text: {rendered}"
        );
    }

    #[test]
    fn test_home_layout_fits_cleanly_inside_390x610_across_banner_states() {
        use crate::state::{LoadingState, NoticeLevel, StatusNotice};
        use freeton_core::api::ServerNode;

        fn assert_fits_without_clipping(mut state: AppState, label: &str) {
            let ctx = egui::Context::default();
            let store = NoopStore;
            let raw_input = egui::RawInput {
                screen_rect: Some(Rect::from_min_size(
                    Pos2::ZERO,
                    Vec2::new(crate::ui::WINDOW_WIDTH, crate::ui::WINDOW_HEIGHT),
                )),
                ..Default::default()
            };
            let mut out = ctx.run_ui(raw_input, |ui| {
                crate::ui::render_root(ui, &mut state, &store);
            });
            out.textures_delta.clear();

            let mut max_widget_bottom = 0.0f32;
            let mut max_text_bottom = 0.0f32;
            let mut max_right = 0.0f32;
            let mut offenders = Vec::new();
            let panel_inner_bottom = crate::ui::WINDOW_HEIGHT - 12.0;
            let panel_inner_right = crate::ui::WINDOW_WIDTH - 14.0;
            fn visit_bounds(
                shape: &egui::epaint::Shape,
                max_widget_bottom: &mut f32,
                max_text_bottom: &mut f32,
                max_right: &mut f32,
                offenders: &mut Vec<String>,
                panel_inner_right: f32,
                panel_inner_bottom: f32,
            ) {
                match shape {
                    egui::epaint::Shape::Text(t) => {
                        let rect = t.galley.rect.translate(t.pos.to_vec2());
                        let bottom = rect.max.y;
                        let right = rect.max.x;
                        *max_text_bottom = max_text_bottom.max(bottom);
                        *max_widget_bottom = max_widget_bottom.max(bottom);
                        *max_right = max_right.max(right);
                        if right > panel_inner_right + 0.5 || bottom > panel_inner_bottom + 0.5 {
                            offenders.push(format!(
                                "Text({:?}, x={:.1}..{:.1}, y={:.1}..{:.1})",
                                t.galley.text(),
                                rect.min.x,
                                right,
                                rect.min.y,
                                bottom
                            ));
                        }
                    }
                    egui::epaint::Shape::Rect(r) => {
                        if r.rect.width() < crate::ui::WINDOW_WIDTH - 2.0 {
                            *max_right = max_right.max(r.rect.max.x);
                            if r.rect.max.x > panel_inner_right + 0.5 {
                                offenders.push(format!("RectX({:?})", r.rect));
                            }
                        }
                        // Exclude the full-window CentralPanel background/border rect itself (height == 610).
                        if r.rect.height() < crate::ui::WINDOW_HEIGHT - 2.0 {
                            *max_widget_bottom = max_widget_bottom.max(r.rect.max.y);
                            if r.rect.max.y > panel_inner_bottom + 0.5 {
                                offenders.push(format!("RectY({:?})", r.rect));
                            }
                        }
                    }
                    egui::epaint::Shape::Circle(c) => {
                        *max_widget_bottom = max_widget_bottom.max(c.center.y + c.radius);
                        *max_right = max_right.max(c.center.x + c.radius);
                        if c.center.x + c.radius > panel_inner_right + 0.5
                            || c.center.y + c.radius > panel_inner_bottom + 0.5
                        {
                            offenders.push(format!("Circle({:?}, r={:.1})", c.center, c.radius));
                        }
                    }
                    egui::epaint::Shape::Vec(items) => {
                        for item in items {
                            visit_bounds(
                                item,
                                max_widget_bottom,
                                max_text_bottom,
                                max_right,
                                offenders,
                                panel_inner_right,
                                panel_inner_bottom,
                            );
                        }
                    }
                    _ => {}
                }
            }
            for clipped in &out.shapes {
                visit_bounds(
                    &clipped.shape,
                    &mut max_widget_bottom,
                    &mut max_text_bottom,
                    &mut max_right,
                    &mut offenders,
                    panel_inner_right,
                    panel_inner_bottom,
                );
            }

            assert!(
                max_right <= panel_inner_right + 0.5,
                "{label}: right widget edge {max_right:.1} exceeds panel right {panel_inner_right:.1}; offenders={offenders:?}"
            );
            assert!(
                max_widget_bottom <= panel_inner_bottom + 0.5,
                "{label}: bottom widget edge {max_widget_bottom:.1} exceeds panel bottom {panel_inner_bottom:.1}; offenders={offenders:?}"
            );
            assert!(
                max_text_bottom <= panel_inner_bottom,
                "{label}: bottom text edge {max_text_bottom:.1} exceeds panel bottom {panel_inner_bottom:.1}; offenders={offenders:?}"
            );
        }

        let sample_server = ServerNode {
            name: "SG-FREE#17".to_owned(),
            country: "SG".to_owned(),
            city: "Singapore".to_owned(),
            domain: "node-sg-17.protonvpn.net".to_owned(),
            entry_ip: "149.40.50.10".to_owned(),
            ping_target: "149.40.50.10".to_owned(),
            x25519_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            load: Some(77.0),
            ping_ms: Some(57.0),
            ..ServerNode::default()
        };

        let clean_cfg = ClientConfig {
            debug_mode: true,
            ..Default::default()
        };
        let mut clean_state = AppState::new(
            true,
            Some("pishun@duck.com".to_owned()),
            clean_cfg.clone(),
            None,
            vec![sample_server.clone()],
        );
        clean_state.selected_server = Some(sample_server.clone());
        clean_state.window_visible = true;
        assert_fits_without_clipping(clean_state, "clean home");

        let mut connected_state = AppState::new(
            true,
            Some("pishun@duck.com".to_owned()),
            clean_cfg.clone(),
            None,
            vec![sample_server.clone()],
        );
        connected_state.selected_server = Some(sample_server.clone());
        connected_state.connected_server = Some(sample_server.clone());
        connected_state.tunnel_running = true;
        connected_state.tunnel_verified = true;
        connected_state.live_public_ip = Some("149.40.50.10".to_owned());
        connected_state.vpn_connect_time_unix = Some(1_700_000_000);
        connected_state.window_visible = true;
        assert_fits_without_clipping(connected_state, "connected home");

        let mut busy_state = AppState::new(
            true,
            Some("pishun@duck.com".to_owned()),
            clean_cfg,
            None,
            vec![sample_server.clone()],
        );
        busy_state.selected_server = Some(sample_server);
        busy_state.window_visible = true;
        busy_state.tunnel_running = true;
        busy_state.tunnel_verified = false;
        busy_state.tunnel_unverified_reason =
            Some("Chưa có handshake WireGuard hợp lệ (hết hạn hoặc chưa bắt tay).".to_owned());
        busy_state.service_health = ServiceHealthStatus::Unavailable("Pipe unavailable".to_owned());
        busy_state.loading = LoadingState {
            visible: true,
            text: "Đang thiết lập WireGuard tunnel...".to_owned(),
            progress: 0.6,
            hide_at: None,
        };
        busy_state.info_toast = Some(StatusNotice {
            text: "🛠 ĐÃ KÍCH HOẠT CHẾ ĐỘ DEBUG! Mở khóa Xuất .conf và chi tiết lỗi.".to_owned(),
            level: NoticeLevel::Warning,
        });
        assert_fits_without_clipping(busy_state, "busy stacked-banner home");
    }

    #[test]
    fn test_home_globe_click_respects_auth_and_connecting_guards() {
        use crate::state::AppView;
        use crate::ui::globe::GlobeAction;
        use freeton_core::api::ServerNode;

        let srv_jp = ServerNode {
            name: "JP-FREE#1".to_owned(),
            country: "JP".to_owned(),
            ..ServerNode::default()
        };
        let srv_sg = ServerNode {
            name: "SG-FREE#1".to_owned(),
            country: "SG".to_owned(),
            ..ServerNode::default()
        };

        let mut logged_out = AppState::new(
            false,
            None,
            ClientConfig::default(),
            None,
            vec![srv_jp.clone()],
        );
        logged_out.current_view = AppView::Home;
        handle_globe_action(&mut logged_out, GlobeAction::ConnectCountry(srv_sg.clone()));
        assert_eq!(logged_out.current_view, AppView::Login);
        assert!(!logged_out.is_connecting_vpn);

        let mut connecting = AppState::new(
            true,
            Some("u@proton.me".to_owned()),
            ClientConfig::default(),
            None,
            vec![srv_jp.clone()],
        );
        let _ = connecting.drain_commands();
        connecting.is_connecting_vpn = true;
        handle_globe_action(&mut connecting, GlobeAction::ConnectCountry(srv_sg.clone()));
        assert_eq!(
            connecting.selected_server.as_ref().map(|s| s.name.as_str()),
            Some("JP-FREE#1")
        );
        assert!(connecting.drain_commands().is_empty());

        let mut closing = AppState::new(
            true,
            Some("u@proton.me".to_owned()),
            ClientConfig::default(),
            None,
            vec![srv_jp.clone()],
        );
        let _ = closing.drain_commands();
        closing.closing = true;
        handle_globe_action(&mut closing, GlobeAction::ConnectCountry(srv_sg.clone()));
        assert_eq!(
            closing.selected_server.as_ref().map(|s| s.name.as_str()),
            Some("JP-FREE#1")
        );
        assert!(closing.drain_commands().is_empty());

        let mut ready = AppState::new(
            true,
            Some("u@proton.me".to_owned()),
            ClientConfig::default(),
            None,
            vec![srv_jp.clone()],
        );
        let _ = ready.drain_commands();
        handle_globe_action(&mut ready, GlobeAction::ConnectCountry(srv_sg));
        assert_eq!(
            ready.selected_server.as_ref().map(|s| s.name.as_str()),
            Some("SG-FREE#1")
        );
        assert!(ready.is_connecting_vpn);
    }

    #[test]
    fn test_home_globe_requests_no_short_repaint_when_hidden_or_animations_disabled() {
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        let store = NoopStore;
        let raw_input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(
                Pos2::ZERO,
                Vec2::new(crate::ui::WINDOW_WIDTH, crate::ui::WINDOW_HEIGHT),
            )),
            ..Default::default()
        };

        // Case 1: Hidden window (loading bar hidden so we isolate Home/Globe repaint policy)
        let ctx_hidden = egui::Context::default();
        let mut hidden_state = AppState::new(
            true,
            Some("u@proton.me".to_owned()),
            ClientConfig {
                animations_enabled: true,
                ..Default::default()
            },
            None,
            Vec::new(),
        );
        hidden_state.loading.visible = false;
        hidden_state.window_visible = false;
        let mut warm = ctx_hidden.run_ui(
            egui::RawInput {
                time: Some(0.0),
                ..raw_input.clone()
            },
            |ui| {
                crate::ui::render_root(ui, &mut hidden_state, &store);
            },
        );
        warm.textures_delta.clear();

        let hidden_delays = Arc::new(Mutex::new(Vec::new()));
        ctx_hidden.set_repaint_observer({
            let hidden_delays = Arc::clone(&hidden_delays);
            move |info| hidden_delays.lock().unwrap().push(info.delay)
        });

        let mut out_hidden = ctx_hidden.run_ui(
            egui::RawInput {
                time: Some(0.25),
                ..raw_input.clone()
            },
            |ui| {
                hidden_delays.lock().unwrap().clear();
                crate::ui::render_root(ui, &mut hidden_state, &store);
            },
        );
        out_hidden.textures_delta.clear();
        for delay in hidden_delays.lock().unwrap().iter() {
            assert!(
                *delay >= Duration::from_millis(100),
                "hidden window must not request short animation repaint, got {delay:?}"
            );
        }

        // Case 2: Animations disabled
        let ctx_static = egui::Context::default();
        let mut static_state = AppState::new(
            true,
            Some("u@proton.me".to_owned()),
            ClientConfig {
                animations_enabled: false,
                ..Default::default()
            },
            None,
            Vec::new(),
        );
        static_state.loading.visible = false;
        static_state.window_visible = true;
        let mut warm2 = ctx_static.run_ui(
            egui::RawInput {
                time: Some(0.0),
                ..raw_input.clone()
            },
            |ui| {
                crate::ui::render_root(ui, &mut static_state, &store);
            },
        );
        warm2.textures_delta.clear();

        let static_delays = Arc::new(Mutex::new(Vec::new()));
        ctx_static.set_repaint_observer({
            let static_delays = Arc::clone(&static_delays);
            move |info| static_delays.lock().unwrap().push(info.delay)
        });

        let mut out_static = ctx_static.run_ui(
            egui::RawInput {
                time: Some(0.25),
                ..raw_input.clone()
            },
            |ui| {
                static_delays.lock().unwrap().clear();
                crate::ui::render_root(ui, &mut static_state, &store);
            },
        );
        out_static.textures_delta.clear();
        for delay in static_delays.lock().unwrap().iter() {
            assert!(
                *delay >= Duration::from_millis(100),
                "disabled animations must not request short animation repaint, got {delay:?}"
            );
        }

        // Case 3 (positive control): visible + animations enabled DOES schedule globe repaint
        let ctx_live = egui::Context::default();
        let mut live_state = AppState::new(
            true,
            Some("u@proton.me".to_owned()),
            ClientConfig {
                animations_enabled: true,
                ..Default::default()
            },
            None,
            Vec::new(),
        );
        live_state.loading.visible = false;
        live_state.window_visible = true;
        let live_delays = Arc::new(Mutex::new(Vec::new()));
        ctx_live.set_repaint_observer({
            let live_delays = Arc::clone(&live_delays);
            move |info| live_delays.lock().unwrap().push(info.delay)
        });
        let mut out_live = ctx_live.run_ui(
            egui::RawInput {
                time: Some(0.25),
                ..raw_input
            },
            |ui| {
                live_delays.lock().unwrap().clear();
                crate::ui::render_root(ui, &mut live_state, &store);
            },
        );
        out_live.textures_delta.clear();
        assert!(
            live_delays
                .lock()
                .unwrap()
                .iter()
                .any(|d| *d == Duration::from_millis(33)),
            "visible animated globe should schedule a 33ms smooth repaint, got {:?}",
            *live_delays.lock().unwrap()
        );
    }

    #[test]
    fn test_top_status_card_has_symmetric_vertical_padding_and_centered_toggle() {
        let store = NoopStore;
        let ctx = egui::Context::default();
        let mut state = AppState::new(
            true,
            Some("pishun@duck.com".to_owned()),
            ClientConfig::default(),
            None,
            Vec::new(),
        );
        state.loading.visible = false;
        state.window_visible = true;

        let raw_input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(
                Pos2::ZERO,
                Vec2::new(crate::ui::WINDOW_WIDTH, crate::ui::WINDOW_HEIGHT),
            )),
            ..Default::default()
        };
        let mut out = ctx.run_ui(raw_input, |ui| {
            crate::ui::render_root(ui, &mut state, &store);
        });
        out.textures_delta.clear();

        let mut status_card_rect: Option<Rect> = None;
        let mut heading_rect: Option<Rect> = None;
        let mut sub_rect: Option<Rect> = None;
        let mut toggle_knob_center_y: Option<f32> = None;

        fn scan(
            s: &egui::epaint::Shape,
            status_card_rect: &mut Option<Rect>,
            heading_rect: &mut Option<Rect>,
            sub_rect: &mut Option<Rect>,
            toggle_knob_center_y: &mut Option<f32>,
        ) {
            match s {
                egui::epaint::Shape::Rect(r) => {
                    if r.fill == crate::ui::C_CARD
                        && r.rect.width() > 330.0
                        && r.rect.min.y > 40.0
                        && r.rect.min.y < 120.0
                    {
                        *status_card_rect = Some(r.rect);
                    }
                }
                egui::epaint::Shape::Text(t) => {
                    let tr = t.galley.rect.translate(t.pos.to_vec2());
                    if t.galley.text() == "KẾT NỐI CỦA BẠN" {
                        *heading_rect = Some(tr);
                    } else if t.galley.text().contains("Gạt công tắc") {
                        *sub_rect = Some(tr);
                    }
                }
                egui::epaint::Shape::Circle(c) => {
                    if c.fill == Color32::WHITE && c.radius > 12.0 && c.center.y < 170.0 {
                        *toggle_knob_center_y = Some(c.center.y);
                    }
                }
                egui::epaint::Shape::Vec(v) => {
                    for item in v {
                        scan(
                            item,
                            status_card_rect,
                            heading_rect,
                            sub_rect,
                            toggle_knob_center_y,
                        );
                    }
                }
                _ => {}
            }
        }
        for c in &out.shapes {
            scan(
                &c.shape,
                &mut status_card_rect,
                &mut heading_rect,
                &mut sub_rect,
                &mut toggle_knob_center_y,
            );
        }

        let card = status_card_rect.expect("status card rect");
        let top_lbl = heading_rect.expect("heading rect");
        let sub_lbl = sub_rect.expect("sub rect");
        let knob_y = toggle_knob_center_y.expect("toggle knob circle");

        let top_pad = top_lbl.min.y - card.min.y;
        let bottom_pad = card.max.y - sub_lbl.max.y;
        assert!(
            (top_pad - bottom_pad).abs() <= 4.0,
            "top status card vertical padding should be balanced (top={top_pad:.1}, bottom={bottom_pad:.1})"
        );
        assert!(
            (knob_y - card.center().y).abs() <= 3.0,
            "toggle switch should be vertically centered inside status card (knob_y={knob_y:.1}, card_cy={:.1})",
            card.center().y
        );
    }

    #[test]
    fn test_vpn_toggle_keeps_off_state_when_toast_and_loading_collapse() {
        use crate::state::{NoticeLevel, StatusNotice};

        fn find_toggle_knob_x(shapes: &[egui::epaint::ClippedShape]) -> f32 {
            fn collect(shape: &egui::epaint::Shape, out: &mut Vec<f32>) {
                match shape {
                    egui::epaint::Shape::Circle(c) => {
                        if c.fill == Color32::WHITE && c.radius >= 12.0 {
                            out.push(c.center.x);
                        }
                    }
                    egui::epaint::Shape::Vec(items) => {
                        for item in items {
                            collect(item, out);
                        }
                    }
                    _ => {}
                }
            }
            let mut xs = Vec::new();
            for clipped in shapes {
                collect(&clipped.shape, &mut xs);
            }
            assert_eq!(
                xs.len(),
                1,
                "expected exactly 1 VPN toggle knob circle, found {}",
                xs.len()
            );
            xs[0]
        }

        let ctx = egui::Context::default();
        let store = NoopStore;
        let mut config = ClientConfig::default();
        config.animations_enabled = true;
        let mut state = AppState::new(
            true,
            Some("pishun@duck.com".to_owned()),
            config,
            None,
            Vec::new(),
        );
        state.window_visible = true;
        state.loading.visible = false;
        state.tunnel_running = true;

        let make_input = |time: f64| egui::RawInput {
            screen_rect: Some(Rect::from_min_size(
                Pos2::ZERO,
                Vec2::new(crate::ui::WINDOW_WIDTH, crate::ui::WINDOW_HEIGHT),
            )),
            time: Some(time),
            ..Default::default()
        };

        // 1. Connected & idle -> settle at ON position.
        let mut out = ctx.run_ui(make_input(0.0), |ui| {
            crate::ui::render_root(ui, &mut state, &store);
        });
        out.textures_delta.clear();
        let mut out = ctx.run_ui(make_input(0.40), |ui| {
            crate::ui::render_root(ui, &mut state, &store);
        });
        out.textures_delta.clear();
        let x_on = find_toggle_knob_x(&out.shapes);

        // 2. While disconnecting (both connecting & disconnecting flags set), knob must slide
        // left toward OFF immediately rather than staying pinned ON.
        state.is_connecting_vpn = true;
        state.is_disconnecting_vpn = true;
        state.loading.visible = true;
        state.loading.text = "Đang ngắt kết nối...".to_owned();
        let mut disc_start = ctx.run_ui(make_input(0.41), |ui| {
            crate::ui::render_root(ui, &mut state, &store);
        });
        disc_start.textures_delta.clear();
        let mut disc_mid = ctx.run_ui(make_input(0.48), |ui| {
            crate::ui::render_root(ui, &mut state, &store);
        });
        disc_mid.textures_delta.clear();
        let x_disconnecting = find_toggle_knob_x(&disc_mid.shapes);
        assert!(
            x_disconnecting < x_on - 2.0,
            "toggle knob must slide toward OFF while disconnecting (x_on={x_on:.1}, x_disconnecting={x_disconnecting:.1})"
        );

        // 3. Disconnected with toast + loading banner visible -> settle at OFF position.
        state.tunnel_running = false;
        state.is_connecting_vpn = false;
        state.is_disconnecting_vpn = false;
        state.info_toast = Some(StatusNotice {
            text: "Đã ngắt kết nối VPN".to_owned(),
            level: NoticeLevel::Info,
        });
        let mut off_start = ctx.run_ui(make_input(0.60), |ui| {
            crate::ui::render_root(ui, &mut state, &store);
        });
        off_start.textures_delta.clear();
        let mut off_settled = ctx.run_ui(make_input(1.10), |ui| {
            crate::ui::render_root(ui, &mut state, &store);
        });
        off_settled.textures_delta.clear();
        let x_off = find_toggle_knob_x(&off_settled.shapes);
        assert!(
            x_off < x_on - 15.0,
            "OFF knob position must be clearly left of ON position (x_off={x_off:.1}, x_on={x_on:.1})"
        );

        // 4. Dismiss both banners -> across every collapse and post-unmount frame, the knob
        // must stay pinned at x_off and NEVER snap back toward x_on.
        state.info_toast = None;
        state.loading.visible = false;
        for t in [1.15_f64, 1.22, 1.30, 1.45, 1.80] {
            let mut frame = ctx.run_ui(make_input(t), |ui| {
                crate::ui::render_root(ui, &mut state, &store);
            });
            frame.textures_delta.clear();
            let knob_x = find_toggle_knob_x(&frame.shapes);
            assert!(
                (knob_x - x_off).abs() < 1.0,
                "toggle knob bounced during banner collapse at t={t:.2}: knob_x={knob_x:.2}, expected x_off={x_off:.2} (x_on={x_on:.2})"
            );
        }
    }
}
