use egui::{
    Align, Color32, ComboBox, CornerRadius, CursorIcon, Layout, Margin, RichText, ScrollArea,
    Sense, Stroke, StrokeKind, TextEdit, Ui, Vec2,
};
use freeton_core::api::ServerNode;
use freeton_core::ping::{get_country_display, SortMode};

use crate::state::AppState;
use crate::ui::{
    lerp_color, load_status_color, pill_button, ping_status_color, rounded_card, PillStyle,
    C_ACCENT, C_ACCENT_HOVER, C_BORDER, C_CARD, C_CARD_HIGH, C_SUCCESS_BG, C_TEXT, C_TEXT_DIM,
    C_TEXT_MUTED,
};

const QUICK_PILLS: &[(&str, Option<&str>)] = &[
    ("Tất cả", None),
    ("Singapore", Some("SG")),
    ("Nhật Bản", Some("JP")),
    ("Hoa Kỳ", Some("US")),
    ("Hà Lan", Some("NL")),
];

const SORT_OPTIONS: &[(&str, SortMode)] = &[
    ("🚀 Tối ưu", SortMode::Best),
    ("⚡ Ping", SortMode::Ping),
    ("📊 Tải", SortMode::Load),
    ("🔤 A-Z", SortMode::Name),
];

pub const SERVER_ROW_HEIGHT: f32 = 54.0;
pub const SERVER_ROW_SPACING: f32 = 4.0;
pub const SERVER_ROW_STRIDE: f32 = SERVER_ROW_HEIGHT + SERVER_ROW_SPACING;

pub fn render_drawer_view(ui: &mut Ui, state: &mut AppState) {
    // Header with Back & Title
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        let back_style = PillStyle {
            fg: C_ACCENT,
            hover_fg: C_ACCENT_HOVER,
            radius: 7,
            font_size: 11.5,
            pad_x: 10.0,
            ..PillStyle::secondary(26.0)
        };
        if pill_button(ui, "‹ Quay lại", Some(78.0), back_style).clicked() {
            state.show_home_view();
        }
        let rem_w = ui.available_width().max(60.0);
        ui.allocate_ui_with_layout(
            Vec2::new(rem_w, 26.0),
            Layout::right_to_left(Align::Center),
            |ui| {
                ui.label(
                    RichText::new("Danh Sách Máy Chủ")
                        .size(14.0)
                        .strong()
                        .color(C_TEXT),
                );
            },
        );
    });

    ui.add_space(6.0);

    // 1. Search Bar
    rounded_card(ui, C_CARD, C_BORDER, 12, Margin::symmetric(8, 5), |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new("🔍").size(12.0).color(C_TEXT_DIM));
            let clear_w = if state.search_query.is_empty() {
                0.0
            } else {
                22.0
            };
            let input_w = (ui.available_width() - clear_w - 4.0).max(80.0);
            let resp = ui.add_sized(
                Vec2::new(input_w, 22.0),
                TextEdit::singleline(&mut state.search_query)
                    .frame(egui::Frame::NONE)
                    .hint_text("Tìm server, thành phố, quốc gia...")
                    .text_color(C_TEXT),
            );
            if resp.changed() {
                state.drawer_scroll_to_top = true;
            }
            if !state.search_query.is_empty() {
                let clr = ui
                    .label(RichText::new("✕").size(11.0).color(C_TEXT_DIM))
                    .interact(Sense::click())
                    .on_hover_cursor(CursorIcon::PointingHand);
                if clr.clicked() {
                    state.search_query.clear();
                    state.drawer_scroll_to_top = true;
                }
            }
        });
    });

    ui.add_space(6.0);

    // 2. Country Dropdown Menu Row
    let counts = state.country_counts();
    let total_count = state.all_free_servers.len();
    let current_label = match &state.selected_country_code {
        None => format!("Tất cả quốc gia ({total_count} máy chủ)"),
        Some(code) => {
            let c_cnt = counts
                .iter()
                .find(|(c, _)| c == code)
                .map(|(_, n)| *n)
                .unwrap_or(0);
            format!("{} ({c_cnt} máy chủ)", get_country_display(code))
        }
    };

    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        ui.label(
            RichText::new("Quốc gia:")
                .size(11.5)
                .strong()
                .color(C_TEXT_MUTED),
        );
        ComboBox::from_id_salt("drawer_country_dropdown")
            .width(ui.available_width().max(120.0))
            .selected_text(RichText::new(&current_label).size(11.5).color(C_TEXT))
            .show_ui(ui, |ui| {
                let all_lbl = format!("Tất cả quốc gia ({total_count} máy chủ)");
                if ui
                    .selectable_label(state.selected_country_code.is_none(), all_lbl)
                    .clicked()
                {
                    state.selected_country_code = None;
                    state.drawer_scroll_to_top = true;
                }
                for (code, cnt) in &counts {
                    let lbl = format!("{} ({cnt} máy chủ)", get_country_display(code));
                    let selected = state.selected_country_code.as_deref() == Some(code.as_str());
                    if ui.selectable_label(selected, lbl).clicked() {
                        state.selected_country_code = Some(code.clone());
                        state.drawer_scroll_to_top = true;
                    }
                }
            });
    });

    ui.add_space(6.0);

    // 3. Quick Popular Country Filter Pills
    ui.horizontal(|ui| {
        let gap = 4.0;
        ui.spacing_mut().item_spacing.x = gap;
        let total_w = ui.available_width();
        let pill_w =
            ((total_w - gap * (QUICK_PILLS.len() - 1) as f32) / QUICK_PILLS.len() as f32).max(40.0);
        for &(label, code) in QUICK_PILLS {
            let is_active = state.selected_country_code.as_deref() == code;
            let style = if is_active {
                PillStyle {
                    bg: C_ACCENT,
                    fg: Color32::BLACK,
                    border: C_ACCENT,
                    hover_bg: C_ACCENT_HOVER,
                    hover_fg: Color32::BLACK,
                    hover_border: C_ACCENT_HOVER,
                    radius: 8,
                    height: 24.0,
                    font_size: 10.5,
                    bold: true,
                    pad_x: 4.0,
                }
            } else {
                PillStyle {
                    bg: C_CARD,
                    fg: C_TEXT_MUTED,
                    border: C_BORDER,
                    hover_bg: C_CARD_HIGH,
                    hover_fg: C_ACCENT,
                    hover_border: C_ACCENT,
                    radius: 8,
                    height: 24.0,
                    font_size: 10.5,
                    bold: true,
                    pad_x: 4.0,
                }
            };
            if pill_button(ui, label, Some(pill_w), style).clicked() {
                state.selected_country_code = code.map(str::to_owned);
                state.drawer_scroll_to_top = true;
            }
        }
    });

    ui.add_space(5.0);

    // 4. Sort Bar
    ui.horizontal(|ui| {
        let gap = 4.0;
        ui.spacing_mut().item_spacing.x = gap;
        ui.label(
            RichText::new("Sắp xếp:")
                .size(10.5)
                .strong()
                .color(C_TEXT_DIM),
        );
        let avail_w = ui.available_width();
        let chip_w = ((avail_w - gap * (SORT_OPTIONS.len() - 1) as f32)
            / SORT_OPTIONS.len() as f32)
            .max(40.0);
        for &(label, mode) in SORT_OPTIONS {
            let is_active = state.sort_mode == mode;
            let style = if is_active {
                PillStyle {
                    bg: C_ACCENT,
                    fg: Color32::BLACK,
                    border: C_ACCENT,
                    hover_bg: C_ACCENT_HOVER,
                    hover_fg: Color32::BLACK,
                    hover_border: C_ACCENT_HOVER,
                    radius: 6,
                    height: 22.0,
                    font_size: 10.5,
                    bold: true,
                    pad_x: 4.0,
                }
            } else {
                PillStyle {
                    bg: C_CARD,
                    fg: C_TEXT_MUTED,
                    border: C_BORDER,
                    hover_bg: C_CARD_HIGH,
                    hover_fg: C_TEXT,
                    hover_border: C_ACCENT,
                    radius: 6,
                    height: 22.0,
                    font_size: 10.5,
                    bold: true,
                    pad_x: 4.0,
                }
            };
            if pill_button(ui, label, Some(chip_w), style).clicked() {
                state.sort_mode = mode;
                state.drawer_scroll_to_top = true;
            }
        }
    });

    ui.add_space(6.0);

    let (best_opt, filtered) = state.drawer_servers();
    if filtered.is_empty() {
        ui.add_space(24.0);
        ui.vertical_centered(|ui| {
            let msg = if state.all_free_servers.is_empty() {
                "Chưa có dữ liệu máy chủ."
            } else {
                "Không tìm thấy máy chủ phù hợp."
            };
            ui.label(RichText::new(msg).size(12.5).color(C_TEXT_DIM));
        });
        return;
    }

    let mut action_connect: Option<ServerNode> = None;
    let mut action_export: Option<ServerNode> = None;
    let debug_mode = state.client_config.debug_mode;
    let selected_name = state.selected_server.as_ref().map(|s| s.name.clone());
    let connected_name = state.connected_server.as_ref().map(|s| s.name.clone());

    if let Some(best) = best_opt {
        let (connect, export) = render_server_row(
            ui,
            &best,
            true,
            selected_name.as_deref() == Some(best.name.as_str()),
            connected_name.as_deref() == Some(best.name.as_str()),
            debug_mode,
        );
        if connect {
            action_connect = Some(best.clone());
        }
        if export {
            action_export = Some(best);
        }
        ui.add_space(5.0);
    }

    ui.label(
        RichText::new(format!("TẤT CẢ MÁY CHỦ  ·  {}", filtered.len()))
            .size(10.0)
            .strong()
            .color(C_TEXT_DIM),
    );
    ui.add_space(4.0);

    ui.scope(|ui| {
        ui.spacing_mut().item_spacing.y = SERVER_ROW_SPACING;
        let mut scroll = ScrollArea::vertical()
            .id_salt("drawer_server_scroll")
            .auto_shrink([false, false]);
        if state.drawer_scroll_to_top {
            scroll = scroll.vertical_scroll_offset(0.0);
            state.drawer_scroll_to_top = false;
        }

        scroll.show_rows(ui, SERVER_ROW_HEIGHT, filtered.len(), |ui, row_range| {
            for idx in row_range {
                let srv = &filtered[idx];
                let is_selected = selected_name.as_deref() == Some(srv.name.as_str());
                let is_connected = connected_name.as_deref() == Some(srv.name.as_str());
                let (connect, export) =
                    render_server_row(ui, srv, false, is_selected, is_connected, debug_mode);
                if connect {
                    action_connect = Some(srv.clone());
                }
                if export {
                    action_export = Some(srv.clone());
                }
            }
        });
    });

    if let Some(server) = action_export {
        state.export_server_conf(server);
    } else if let Some(server) = action_connect {
        state.select_and_connect_server(server);
    }
}

fn render_server_row(
    ui: &mut Ui,
    server: &ServerNode,
    is_best: bool,
    is_selected: bool,
    is_connected: bool,
    debug_mode: bool,
) -> (bool, bool) {
    let row_h = if is_best { 72.0 } else { SERVER_ROW_HEIGHT };
    // Inside ScrollArea, leave a small gap for the floating scrollbar when not the top best card.
    let width = if is_best {
        ui.available_width().max(60.0)
    } else {
        (ui.available_width() - 6.0).max(60.0)
    };
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, row_h), Sense::click());
    let response = response.on_hover_cursor(CursorIcon::PointingHand);

    let hover_dur = ui.style().animation_time;
    let hover_t = ui.ctx().animate_bool_with_time(
        response.id.with("row_hover"),
        response.hovered(),
        hover_dur,
    );
    let base_bg = if is_connected {
        C_SUCCESS_BG
    } else if is_selected {
        C_CARD_HIGH
    } else {
        C_CARD
    };
    let bg = if is_connected || is_selected {
        base_bg
    } else {
        lerp_color(base_bg, C_CARD_HIGH, hover_t * 0.55)
    };
    let border = if is_selected || is_connected || is_best {
        C_ACCENT
    } else {
        lerp_color(C_BORDER, C_ACCENT, hover_t)
    };

    let mut export_clicked = false;
    if ui.is_rect_visible(rect) {
        let p = ui.painter();
        let cr = CornerRadius::same(10);
        p.rect_filled(rect, cr, bg);
        p.rect_stroke(rect, cr, Stroke::new(1.0, border), StrokeKind::Inside);

        let mut text_y = rect.top() + 10.0;
        if is_best {
            p.text(
                egui::Pos2::new(rect.left() + 12.0, text_y),
                egui::Align2::LEFT_TOP,
                "GỢI Ý TỐI ƯU NHẤT",
                egui::FontId::proportional(10.0),
                C_ACCENT,
            );
            p.text(
                egui::Pos2::new(rect.right() - 12.0, text_y),
                egui::Align2::RIGHT_TOP,
                "Kết nối ngay ›",
                egui::FontId::proportional(11.0),
                C_ACCENT,
            );
            text_y += 18.0;
        }

        let title = format!("{} — {}", server.name, get_country_display(&server.country));
        let max_title_w = (rect.width() - 24.0).max(40.0);
        let title_font = egui::FontId::proportional(12.5);
        let title_galley = p.layout(title, title_font, C_TEXT, max_title_w);
        p.galley(
            egui::Pos2::new(rect.left() + 12.0, text_y),
            title_galley,
            C_TEXT,
        );

        let meta_y = text_y + 20.0;
        let ping_txt = match server.ping_ms {
            Some(ms) => format!("Ping  {ms:.0} ms"),
            None => "Ping  —".to_owned(),
        };
        let ping_col = ping_status_color(server.ping_ms);
        p.text(
            egui::Pos2::new(rect.left() + 12.0, meta_y),
            egui::Align2::LEFT_TOP,
            ping_txt,
            egui::FontId::proportional(11.0),
            ping_col,
        );
        let load_txt = match server.load {
            Some(pct) => format!("Tải  {pct:.0}%"),
            None => "Tải  —".to_owned(),
        };
        let load_col = load_status_color(server.load);
        p.text(
            egui::Pos2::new(rect.left() + 122.0, meta_y),
            egui::Align2::LEFT_TOP,
            load_txt,
            egui::FontId::proportional(11.0),
            load_col,
        );

        if debug_mode {
            let export_rect = egui::Rect::from_min_max(
                egui::Pos2::new(rect.right() - 82.0, meta_y - 2.0),
                egui::Pos2::new(rect.right() - 6.0, rect.bottom() - 4.0),
            );
            let export_resp =
                ui.interact(export_rect, response.id.with("export_conf"), Sense::click());
            let export_col = if export_resp.hovered() {
                C_ACCENT_HOVER
            } else {
                C_ACCENT
            };
            p.text(
                egui::Pos2::new(rect.right() - 12.0, meta_y),
                egui::Align2::RIGHT_TOP,
                "Xuất .conf",
                egui::FontId::proportional(11.0),
                export_col,
            );
            if export_resp.clicked() {
                export_clicked = true;
            }
        }
    }

    let row_clicked = response.clicked() && !export_clicked;
    (row_clicked, export_clicked)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drawer_row_height_matches_show_rows_stride() {
        assert_eq!(SERVER_ROW_STRIDE, SERVER_ROW_HEIGHT + SERVER_ROW_SPACING);

        let total_rows = 24usize;
        let ctx = egui::Context::default();
        let mut raw_input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                Vec2::new(360.0, 260.0),
            )),
            ..Default::default()
        };
        let mut observed_tops = Vec::new();
        let mut observed_heights = Vec::new();
        let mut content_height = 0.0_f32;

        // Run a couple frames so ScrollArea computes steady-state viewport and content height.
        for _ in 0..2 {
            observed_tops.clear();
            observed_heights.clear();
            let mut full_output = ctx.run_ui(raw_input.take(), |ui| {
                egui::CentralPanel::default().show(ui, |ui| {
                    ui.scope(|ui| {
                        ui.spacing_mut().item_spacing.y = SERVER_ROW_SPACING;
                        let out = ScrollArea::vertical()
                            .id_salt("drawer_stride_test_scroll")
                            .auto_shrink([false, false])
                            .show_rows(ui, SERVER_ROW_HEIGHT, total_rows, |ui, range| {
                                for _ in range {
                                    let (rect, _) = ui.allocate_exact_size(
                                        Vec2::new(ui.available_width(), SERVER_ROW_HEIGHT),
                                        Sense::hover(),
                                    );
                                    observed_tops.push(rect.top());
                                    observed_heights.push(rect.height());
                                }
                            });
                        content_height = out.content_size.y;
                    });
                });
            });
            full_output.textures_delta.clear();
        }

        let expected_total_h = SERVER_ROW_STRIDE * total_rows as f32 - SERVER_ROW_SPACING;
        assert!(
            (content_height - expected_total_h).abs() < 0.01,
            "content height {content_height} drifted from {expected_total_h}"
        );
        assert!(observed_heights.len() >= 2);
        for h in &observed_heights {
            assert!((*h - SERVER_ROW_HEIGHT).abs() < 0.01);
        }
        for pair in observed_tops.windows(2) {
            let stride = pair[1] - pair[0];
            assert!(
                (stride - SERVER_ROW_STRIDE).abs() < 0.01,
                "row stride {stride} drifted from {SERVER_ROW_STRIDE}"
            );
        }
    }

    #[test]
    fn test_drawer_login_srp_fit_within_390x610_horizontal_and_vertical_bounds() {
        use crate::state::AppView;
        use freeton_core::storage::{ClientConfig, CredentialStore, StorageError};

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

        fn measure_view(mut state: AppState, label: &str) {
            let ctx = egui::Context::default();
            let store = NoopStore;
            let raw_input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    Vec2::new(crate::ui::WINDOW_WIDTH, crate::ui::WINDOW_HEIGHT),
                )),
                ..Default::default()
            };
            // Two frames allow ScrollArea to settle viewport and scrollbar geometry.
            let mut out = ctx.run_ui(raw_input.clone(), |ui| {
                crate::ui::render_root(ui, &mut state, &store);
            });
            out.textures_delta.clear();
            let mut out = ctx.run_ui(raw_input, |ui| {
                crate::ui::render_root(ui, &mut state, &store);
            });
            out.textures_delta.clear();

            let mut max_right = 0.0f32;
            let mut max_bottom = 0.0f32;
            let mut text = String::new();
            let mut offenders = Vec::new();
            let panel_inner_right = crate::ui::WINDOW_WIDTH - 14.0;
            let panel_inner_bottom = crate::ui::WINDOW_HEIGHT - 12.0;
            fn visit(
                shape: &egui::epaint::Shape,
                max_right: &mut f32,
                max_bottom: &mut f32,
                text: &mut String,
                offenders: &mut Vec<String>,
                panel_inner_right: f32,
                panel_inner_bottom: f32,
            ) {
                match shape {
                    egui::epaint::Shape::Text(t) => {
                        let rect = t.galley.rect.translate(t.pos.to_vec2());
                        *max_right = max_right.max(rect.max.x);
                        *max_bottom = max_bottom.max(rect.max.y);
                        if rect.max.x > panel_inner_right + 0.5
                            || rect.max.y > panel_inner_bottom + 0.5
                        {
                            offenders.push(format!(
                                "Text({:?}, x={:.1}..{:.1}, y={:.1}..{:.1})",
                                t.galley.text(),
                                rect.min.x,
                                rect.max.x,
                                rect.min.y,
                                rect.max.y
                            ));
                        }
                        text.push_str(t.galley.text());
                        text.push('\n');
                    }
                    egui::epaint::Shape::Rect(r) => {
                        if r.rect.width() < crate::ui::WINDOW_WIDTH - 2.0 {
                            *max_right = max_right.max(r.rect.max.x);
                            if r.rect.max.x > panel_inner_right + 0.5 {
                                offenders.push(format!("Rect({:?})", r.rect));
                            }
                        }
                        if r.rect.height() < crate::ui::WINDOW_HEIGHT - 2.0 {
                            *max_bottom = max_bottom.max(r.rect.max.y);
                            if r.rect.max.y > panel_inner_bottom + 0.5 {
                                offenders.push(format!("RectY({:?})", r.rect));
                            }
                        }
                    }
                    egui::epaint::Shape::Vec(items) => {
                        for item in items {
                            visit(
                                item,
                                max_right,
                                max_bottom,
                                text,
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
                let is_scroll_row = clipped.clip_rect.max.y < panel_inner_bottom
                    && clipped.clip_rect.min.y > 200.0
                    && matches!(
                        &clipped.shape,
                        egui::epaint::Shape::Rect(_)
                            | egui::epaint::Shape::Text(_)
                            | egui::epaint::Shape::Vec(_)
                    );
                if is_scroll_row {
                    // Only enforce horizontal bounds for scrolled rows inside the ScrollArea viewport.
                    let mut dummy_bottom = 0.0f32;
                    visit(
                        &clipped.shape,
                        &mut max_right,
                        &mut dummy_bottom,
                        &mut text,
                        &mut offenders,
                        panel_inner_right,
                        f32::INFINITY,
                    );
                } else {
                    visit(
                        &clipped.shape,
                        &mut max_right,
                        &mut max_bottom,
                        &mut text,
                        &mut offenders,
                        panel_inner_right,
                        panel_inner_bottom,
                    );
                }
            }

            assert!(
                max_right <= panel_inner_right + 0.5,
                "{label}: right edge {max_right:.1} overflows inner right {panel_inner_right:.1}; offenders: {offenders:?}"
            );
            assert!(
                max_bottom <= panel_inner_bottom + 0.5,
                "{label}: bottom edge {max_bottom:.1} overflows inner bottom {panel_inner_bottom:.1}; offenders: {offenders:?}"
            );
            if matches!(state.current_view, AppView::Drawer) {
                assert!(
                    text.contains("Hà Lan"),
                    "Drawer missing 'Hà Lan' pill: {text}"
                );
                assert!(
                    text.contains("A-Z"),
                    "Drawer missing 'A-Z' sort chip: {text}"
                );
                assert!(
                    text.contains("Kết nối ngay"),
                    "Drawer missing 'Kết nối ngay' label: {text}"
                );
            }
        }

        let servers: Vec<ServerNode> = (1..=30)
            .map(|i| ServerNode {
                name: format!("SG-FREE#{i}"),
                country: "SG".to_owned(),
                city: "Singapore".to_owned(),
                domain: format!("node-{i}.protonvpn.net"),
                entry_ip: format!("149.40.50.{i}"),
                ping_target: format!("149.40.50.{i}"),
                x25519_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
                load: Some(65.0),
                ping_ms: Some(50.0 + i as f64),
                ..ServerNode::default()
            })
            .collect();

        let cfg = ClientConfig {
            debug_mode: true,
            ..Default::default()
        };

        let mut drawer_state = AppState::new(
            true,
            Some("pishun@duck.com".to_owned()),
            cfg.clone(),
            None,
            servers.clone(),
        );
        drawer_state.current_view = AppView::Drawer;
        drawer_state.window_visible = true;
        measure_view(drawer_state, "drawer view");

        let mut login_state = AppState::new(false, None, cfg.clone(), None, Vec::new());
        login_state.current_view = AppView::Login;
        login_state.window_visible = true;
        measure_view(login_state, "login view");

        let mut srp_state = AppState::new(false, None, cfg, None, Vec::new());
        srp_state.current_view = AppView::Srp;
        srp_state.window_visible = true;
        measure_view(srp_state, "srp view");
    }
}
