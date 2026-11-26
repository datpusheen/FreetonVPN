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
        (
                C_WARNING,
                "VPN CHƯA XÁC MINH",
                C_WARNING,
                "Tunnel đang bật nhưng chưa xác minh handshake/DNS.\nBấm công tắc để ngắt hoặc thử máy chủ khác.".to_owned(),
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

    // 2. Central Giant iOS Pill Switch Area
    let bottom_reserved = 166.0;
    let center_h = (ui.available_height() - bottom_reserved).max(150.0);
    ui.allocate_ui(Vec2::new(ui.available_width(), center_h), |ui| {
        ui.vertical_centered(|ui| {
            ui.add_space(10.0);

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

            ui.add_space(16.0);

            let toggle_on =
                state.tunnel_running || (state.is_connecting_vpn && !state.is_disconnecting_vpn);
            if ios_toggle_switch(
                ui,
                toggle_on,
                state.is_connecting_vpn,
                state.client_config.animations_enabled,
                Vec2::new(136.0, 70.0),
            )
            .clicked()
            {
                state.toggle_vpn();
            }

            ui.add_space(14.0);
            ui.label(
                RichText::new("WIREGUARD  /  KẾT NỐI MÃ HÓA")
                    .size(10.5)
                    .color(C_TEXT_DIM),
            );
        });
    });

    // 3. Selected Server / Location Card
    let server_card_resp =
        rounded_card(ui, C_CARD, C_BORDER, 14, Margin::symmetric(12, 10), |ui| {
            ui.set_width(ui.available_width());
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

            ui.add_space(3.0);

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
            ui.add_space(5.0);

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
        })
        .response
        .interact(Sense::click())
        .on_hover_cursor(CursorIcon::PointingHand);

    if server_card_resp.clicked() {
        state.show_drawer_view();
    }

    // 4. Bottom Action Chips
    ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
        ui.add_space(2.0);
        ui.horizontal(|ui| {
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

            if pill_button(ui, "Cài đặt", Some(btn_w), PillStyle::secondary(34.0)).clicked() {
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
        });
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
