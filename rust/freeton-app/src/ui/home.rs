use std::time::{SystemTime, UNIX_EPOCH};

use egui::{
    Align, Color32, CornerRadius, CursorIcon, Layout, Margin, Pos2, Response, RichText, Sense,
    Stroke, StrokeKind, Ui, Vec2,
};
use freeton_core::ping::get_country_display;
use freeton_core::storage::CredentialStore;

use crate::state::{AppState, ServiceHealthStatus};
use crate::ui::{
    lerp_color, pill_button, rounded_card, PillStyle, C_ACCENT, C_BG, C_BORDER, C_CARD,
    C_CARD_HIGH, C_DANGER, C_SUCCESS, C_TEXT, C_TEXT_DIM, C_TEXT_MUTED, C_TOGGLE_CONNECTING,
    C_TOGGLE_OFF, C_TOGGLE_ON, C_WARNING,
};

pub fn render_home_view(ui: &mut Ui, state: &mut AppState, store: &dyn CredentialStore) {
    ui.add_space(4.0);

    // 1. Top Protection Status Card
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
            "ĐANG THIẾT LẬP KẾT NỐI...",
            C_WARNING,
            format!(
                "Server: {srv_name} • Endpoint: {entry_ip}:{port}\nInterface: {addr} • DNS: {}",
                state.client_config.dns
            ),
            C_TEXT,
        )
    } else if state.is_disconnecting_vpn {
        (
            C_WARNING,
            "ĐANG NGẮT KẾT NỐI...",
            C_WARNING,
            "Đang ngắt WireGuard Tunnel & hoàn trả cấu hình mạng...".to_owned(),
            C_TEXT_MUTED,
        )
    } else if state.tunnel_running && state.tunnel_verified {
        let (country_code, entry_ip, addr, port) = state.effective_endpoint_and_interface();
        let country_disp = get_country_display(&country_code);
        let sub = if let Some(pub_ip) = &state.live_public_ip {
            format!(
                    "IP Public (Exit): {pub_ip} ({country_disp})\nEndpoint: {entry_ip}:{port} • IP Nội bộ: {addr}"
                )
        } else {
            format!(
                    "Đang mã hóa qua {country_disp} • Endpoint: {entry_ip}:{port}\nIP Nội bộ WireGuard: {addr}"
                )
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
            format!("{reason}\nBấm công tắc để ngắt hoặc thử máy chủ khác."),
            C_WARNING,
        )
    } else {
        (
            C_BORDER,
            "CHƯA BẬT VPN",
            C_TEXT,
            "Bấm công tắc để kích hoạt kết nối an toàn WireGuard".to_owned(),
            C_TEXT_MUTED,
        )
    };

    rounded_card(
        ui,
        C_CARD,
        status_border,
        14,
        Margin::symmetric(12, 11),
        |ui| {
            ui.set_width(ui.available_width());
            ui.set_min_height(86.0);
            ui.label(
                RichText::new("KẾT NỐI CỦA BẠN")
                    .size(10.5)
                    .strong()
                    .color(C_TEXT_DIM),
            );
            ui.add_space(2.0);
            ui.label(
                RichText::new(status_title)
                    .size(19.0)
                    .strong()
                    .color(status_title_color),
            );
            ui.add_space(2.0);
            ui.label(RichText::new(status_sub).size(11.0).color(status_sub_color));
        },
    );

    if matches!(state.service_health, ServiceHealthStatus::Unavailable(_)) && !state.closing {
        ui.add_space(6.0);
        let repair_pill = PillStyle {
            bg: Color32::from_rgb(0x2b, 0x22, 0x16),
            fg: C_WARNING,
            border: C_WARNING,
            hover_bg: Color32::from_rgb(0x3a, 0x2d, 0x1c),
            hover_fg: C_TEXT,
            hover_border: C_WARNING,
            radius: 9,
            height: 28.0,
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

    // 2. Central Giant iOS Pill Switch Area + 3. Location Card + 4. Bottom Action Chips
    // Measure/reserve footer cleanly so bottom buttons never clip below CentralPanel bounds, even
    // when top banners (toast, loading bar, or UAC service repair) reduce available height.
    let available_after_status = ui.available_height().max(0.0);
    let compact = available_after_status < 330.0;
    let footer_chips_h = 34.0;
    let footer_bottom_pad = 4.0;
    let server_card_est_h = if compact { 88.0 } else { 96.0 };
    let between_card_and_chips = if compact { 6.0 } else { 8.0 };
    let reserved_bottom =
        server_card_est_h + between_card_and_chips + footer_chips_h + footer_bottom_pad;

    let toggle_h = if compact { 62.0 } else { 70.0 };
    let toggle_w = if compact { 122.0 } else { 136.0 };
    let inner_gap_1 = if compact { 8.0 } else { 14.0 };
    let inner_gap_2 = if compact { 8.0 } else { 12.0 };
    let toggle_group_h = 30.0 + inner_gap_1 + toggle_h + inner_gap_2 + 16.0;

    let center_room = (available_after_status - reserved_bottom).max(toggle_group_h);
    let extra_center = (center_room - toggle_group_h).max(0.0);
    let top_center_pad = (extra_center * 0.45).round();
    let bottom_center_pad = (extra_center - top_center_pad).round();

    ui.allocate_ui_with_layout(
        Vec2::new(
            ui.available_width(),
            top_center_pad + toggle_group_h + bottom_center_pad,
        ),
        Layout::top_down(Align::Center),
        |ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            if top_center_pad > 0.0 {
                ui.add_space(top_center_pad);
            }

            let now_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| i64::try_from(d.as_secs()).unwrap_or(0))
                .unwrap_or(0);
            let (tone, timer_text) = state.formatted_session_timer(now_unix);
            if state.tunnel_verified {
                // Request 1s repaint so HH:MM:SS ticks smoothly.
                ui.ctx()
                    .request_repaint_after(std::time::Duration::from_secs(1));
            }
            let timer_color = match tone {
                "success" => C_SUCCESS,
                "warning" => C_WARNING,
                _ => C_TEXT_DIM,
            };

            let timer_style = PillStyle {
                bg: C_CARD,
                fg: timer_color,
                border: timer_color,
                hover_bg: C_CARD,
                hover_fg: timer_color,
                hover_border: timer_color,
                radius: 10,
                height: 30.0,
                font_size: 11.5,
                bold: true,
                pad_x: 14.0,
            };
            let _ = pill_button(ui, &timer_text, None, timer_style);

            ui.add_space(inner_gap_1);

            let toggle_on =
                state.tunnel_running || (state.is_connecting_vpn && !state.is_disconnecting_vpn);
            if ios_toggle_switch(
                ui,
                toggle_on,
                state.is_connecting_vpn,
                state.client_config.animations_enabled,
                Vec2::new(toggle_w, toggle_h),
            )
            .clicked()
            {
                state.toggle_vpn();
            }

            ui.add_space(inner_gap_2);
            ui.label(
                RichText::new("WIREGUARD  /  KẾT NỐI MÃ HÓA")
                    .size(10.5)
                    .color(C_TEXT_DIM),
            );
            if bottom_center_pad > 0.0 {
                ui.add_space(bottom_center_pad);
            }
        },
    );

    // 3. Selected Server / Location Card
    let card_pad_y = if compact { 8 } else { 10 };
    let server_card_resp = rounded_card(
        ui,
        C_CARD,
        C_BORDER,
        14,
        Margin::symmetric(12, card_pad_y),
        |ui| {
            ui.set_width(ui.available_width());
            ui.spacing_mut().item_spacing.y = 3.0;
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("VỊ TRÍ MÁY CHỦ")
                        .size(10.0)
                        .strong()
                        .color(C_TEXT_DIM),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        RichText::new("Đổi vị trí ❯")
                            .size(11.0)
                            .strong()
                            .color(C_ACCENT),
                    );
                });
            });

            let (title, ping_text, ping_color, load_text) =
                if let Some(srv) = &state.selected_server {
                    let c_disp = get_country_display(&srv.country);
                    let title = format!("{c_disp} ({})", srv.name);
                    let (pt, pc) = match srv.ping_ms {
                        Some(ms) => (format!("Ping: {ms:.0} ms"), C_SUCCESS),
                        None => ("Ping: -- ms".to_owned(), C_TEXT_MUTED),
                    };
                    let lt = format!("Tải: {:.0}%", srv.load.unwrap_or(0.0));
                    (title, pt, pc, lt)
                } else {
                    (
                        "Đang tìm node tốt nhất...".to_owned(),
                        "Ping: -- ms".to_owned(),
                        C_TEXT_MUTED,
                        "Tải: --%".to_owned(),
                    )
                };

            ui.label(RichText::new(title).size(14.0).strong().color(C_TEXT));
            ui.add_space(2.0);

            ui.horizontal(|ui| {
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

                ui.add_space(6.0);

                let load_pill = PillStyle {
                    bg: C_CARD_HIGH,
                    fg: C_TEXT_MUTED,
                    border: C_BORDER,
                    hover_bg: C_CARD_HIGH,
                    hover_fg: C_TEXT_MUTED,
                    hover_border: C_ACCENT,
                    radius: 7,
                    height: 25.0,
                    font_size: 11.0,
                    bold: false,
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

    if server_card_resp.clicked() {
        state.show_drawer_view();
    }

    // 4. Bottom Action Chips — allocate an explicit 34px strip above bottom margin so Layout::bottom_up
    // never mis-measures horizontal row height and clips buttons past CentralPanel bounds.
    ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
        ui.add_space(2.0);
        let row_w = ui.available_width();
        ui.allocate_ui_with_layout(
            Vec2::new(row_w, footer_chips_h),
            Layout::left_to_right(Align::Center),
            |ui| {
                let show_export = state.client_config.debug_mode;
                let count = if show_export { 4 } else { 3 };
                let gap = 5.0;
                ui.spacing_mut().item_spacing.x = gap;
                let total_w = ui.available_width();
                let btn_w = ((total_w - gap * (count - 1) as f32) / count as f32).max(58.0);

                if show_export
                    && pill_button(ui, "💾 Xuất .conf", Some(btn_w), PillStyle::secondary(34.0))
                        .clicked()
                {
                    state.export_selected_conf();
                }

                if pill_button(ui, "Cài đặt", Some(btn_w), PillStyle::secondary(34.0)).clicked()
                {
                    state.open_settings_dialog();
                }

                if pill_button(ui, "Giới thiệu", Some(btn_w), PillStyle::secondary(34.0)).clicked()
                {
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
                    ..PillStyle::secondary(34.0)
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
    on: bool,
    connecting: bool,
    animations_enabled: bool,
    size: Vec2,
) -> Response {
    let (rect, response) = ui.allocate_exact_size(size, Sense::click());
    let response = response.on_hover_cursor(CursorIcon::PointingHand);

    let anim_time = if animations_enabled { 0.16 } else { 0.0 };
    let target = on || connecting;
    let t = ui
        .ctx()
        .animate_bool_with_time(response.id.with("ios_toggle"), target, anim_time);

    if ui.is_rect_visible(rect) {
        let p = ui.painter();
        let radius = rect.height() * 0.5;
        let track_color = if connecting {
            C_TOGGLE_CONNECTING
        } else {
            lerp_color(C_TOGGLE_OFF, C_TOGGLE_ON, t)
        };
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
            fn visit_bounds(
                shape: &egui::epaint::Shape,
                max_widget_bottom: &mut f32,
                max_text_bottom: &mut f32,
            ) {
                match shape {
                    egui::epaint::Shape::Text(t) => {
                        let bottom = t.pos.y + t.galley.size().y;
                        *max_text_bottom = max_text_bottom.max(bottom);
                        *max_widget_bottom = max_widget_bottom.max(bottom);
                    }
                    egui::epaint::Shape::Rect(r) => {
                        // Exclude the full-window CentralPanel background/border rect itself (height == 610).
                        if r.rect.height() < crate::ui::WINDOW_HEIGHT - 2.0 {
                            *max_widget_bottom = max_widget_bottom.max(r.rect.max.y);
                        }
                    }
                    egui::epaint::Shape::Vec(items) => {
                        for item in items {
                            visit_bounds(item, max_widget_bottom, max_text_bottom);
                        }
                    }
                    _ => {}
                }
            }
            for clipped in &out.shapes {
                visit_bounds(&clipped.shape, &mut max_widget_bottom, &mut max_text_bottom);
            }

            let panel_inner_bottom = crate::ui::WINDOW_HEIGHT - 12.0;
            assert!(
                max_widget_bottom <= panel_inner_bottom + 0.5,
                "{label}: bottom widget edge {max_widget_bottom:.1} exceeds panel bottom {panel_inner_bottom:.1}"
            );
            assert!(
                max_text_bottom <= panel_inner_bottom,
                "{label}: bottom text edge {max_text_bottom:.1} exceeds panel bottom {panel_inner_bottom:.1}"
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
}
