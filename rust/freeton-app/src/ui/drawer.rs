use egui::{
    Align, Color32, ComboBox, CornerRadius, CursorIcon, Layout, Margin, RichText, ScrollArea,
    Sense, Stroke, StrokeKind, TextEdit, Ui, Vec2,
};
use freeton_core::api::ServerNode;
use freeton_core::ping::{get_country_display, SortMode};

use crate::state::AppState;
use crate::ui::{
    pill_button, rounded_card, PillStyle, C_ACCENT, C_ACCENT_HOVER, C_BORDER, C_CARD, C_CARD_HIGH,
    C_SUCCESS, C_SUCCESS_BG, C_TEXT, C_TEXT_DIM, C_TEXT_MUTED,
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

const SERVER_ROW_HEIGHT: f32 = 58.0;

pub fn render_drawer_view(ui: &mut Ui, state: &mut AppState) {
    // Header with Back & Title
    ui.horizontal(|ui| {
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
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(
                RichText::new("Danh Sách Máy Chủ")
                    .size(14.0)
                    .strong()
                    .color(C_TEXT),
            );
        });
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
        ui.label(
            RichText::new("Quốc gia:")
                .size(11.5)
                .strong()
                .color(C_TEXT_MUTED),
        );
        ui.add_space(4.0);
        ComboBox::from_id_salt("drawer_country_dropdown")
            .width(ui.available_width())
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
        let total_w = ui.available_width();
        let pill_w =
            ((total_w - gap * (QUICK_PILLS.len() - 1) as f32) / QUICK_PILLS.len() as f32).max(52.0);
        for (idx, &(label, code)) in QUICK_PILLS.iter().enumerate() {
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
            if idx + 1 < QUICK_PILLS.len() {
                ui.add_space(gap);
            }
        }
    });

    ui.add_space(5.0);

    // 4. Sort Bar
    ui.horizontal(|ui| {
        ui.label(
            RichText::new("Sắp xếp:")
                .size(10.5)
                .strong()
                .color(C_TEXT_DIM),
        );
        ui.add_space(4.0);
        let gap = 3.0;
        let avail_w = ui.available_width();
        let chip_w = ((avail_w - gap * (SORT_OPTIONS.len() - 1) as f32)
            / SORT_OPTIONS.len() as f32)
            .max(54.0);
        for (idx, &(label, mode)) in SORT_OPTIONS.iter().enumerate() {
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
            if idx + 1 < SORT_OPTIONS.len() {
                ui.add_space(gap);
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
    let row_h = if is_best {
        74.0
    } else {
        SERVER_ROW_HEIGHT - 4.0
    };
    let width = ui.available_width().max(60.0);
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, row_h), Sense::click());
    let response = response.on_hover_cursor(CursorIcon::PointingHand);

    let bg = if is_connected {
        C_SUCCESS_BG
    } else if is_selected {
        C_CARD_HIGH
    } else {
        C_CARD
    };
    let border = if response.hovered() || is_selected || is_connected || is_best {
        C_ACCENT
    } else {
        C_BORDER
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
        let (ping_txt, ping_col) = match server.ping_ms {
            Some(ms) if ms < 80.0 => (format!("Ping  {ms:.0} ms"), C_SUCCESS),
            Some(ms) => (format!("Ping  {ms:.0} ms"), C_TEXT_MUTED),
            None => ("Ping  —".to_owned(), C_TEXT_MUTED),
        };
        p.text(
            egui::Pos2::new(rect.left() + 12.0, meta_y),
            egui::Align2::LEFT_TOP,
            ping_txt,
            egui::FontId::proportional(11.0),
            ping_col,
        );
        p.text(
            egui::Pos2::new(rect.left() + 122.0, meta_y),
            egui::Align2::LEFT_TOP,
            format!("Tải  {:.0}%", server.load.unwrap_or(0.0)),
            egui::FontId::proportional(11.0),
            C_TEXT_MUTED,
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
