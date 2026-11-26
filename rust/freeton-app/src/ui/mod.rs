pub mod dialogs;
pub mod drawer;
pub mod home;
pub mod login;

use std::sync::Arc;

use egui::epaint::text::{FontData, FontDefinitions, FontFamily};
use egui::{
    Align, Color32, CornerRadius, CursorIcon, Frame, Layout, Margin, Pos2, Rect, Response,
    RichText, Sense, Stroke, StrokeKind, Ui, Vec2, ViewportCommand,
};
use freeton_core::storage::CredentialStore;
use freeton_core::APP_NAME;
use tracing::warn;

use crate::state::{
    ActiveDialog, AppState, AppView, NoticeLevel, ViewDirection, WindowsShellLauncher,
};

// Design Tokens (Dark Glass Theme matching proton_warp_material_gui.py)
pub const C_BG: Color32 = Color32::from_rgb(0x10, 0x14, 0x19);
pub const C_SURFACE: Color32 = Color32::from_rgb(0x15, 0x1b, 0x22);
pub const C_CARD: Color32 = Color32::from_rgb(0x1b, 0x22, 0x2b);
pub const C_CARD_HIGH: Color32 = Color32::from_rgb(0x25, 0x2f, 0x3a);
pub const C_ACCENT: Color32 = Color32::from_rgb(0x8b, 0xd5, 0xc5);
pub const C_ACCENT_HOVER: Color32 = Color32::from_rgb(0xab, 0xe4, 0xd8);
pub const C_SUCCESS: Color32 = Color32::from_rgb(0x8b, 0xd5, 0xc5);
pub const C_SUCCESS_BG: Color32 = Color32::from_rgb(0x1b, 0x33, 0x2f);
pub const C_WARNING: Color32 = Color32::from_rgb(0xd9, 0xb7, 0x7a);
pub const C_DANGER: Color32 = Color32::from_rgb(0xe6, 0x9a, 0x9a);
pub const C_CLOSE_HOVER: Color32 = Color32::from_rgb(0xef, 0x44, 0x44);
pub const C_TEXT: Color32 = Color32::from_rgb(0xf8, 0xfa, 0xfc);
pub const C_TEXT_MUTED: Color32 = Color32::from_rgb(0x94, 0xa3, 0xb8);
pub const C_TEXT_DIM: Color32 = Color32::from_rgb(0x89, 0x97, 0xa8);
pub const C_BORDER: Color32 = Color32::from_rgb(0x30, 0x3b, 0x48);
pub const C_TOGGLE_OFF: Color32 = Color32::from_rgb(0x30, 0x3a, 0x46);
pub const C_TOGGLE_CONNECTING: Color32 = Color32::from_rgb(0xf5, 0x9e, 0x0b);
pub const C_TOGGLE_ON: Color32 = Color32::from_rgb(0x79, 0xcb, 0xbb);

// Semantic traffic-light colors for server ping and load badges.
pub const C_METRIC_GREEN: Color32 = Color32::from_rgb(0x4a, 0xde, 0x80);
pub const C_METRIC_YELLOW: Color32 = Color32::from_rgb(0xfb, 0xbf, 0x24);
pub const C_METRIC_RED: Color32 = Color32::from_rgb(0xf8, 0x71, 0x71);

pub fn ping_status_color(ping_ms: Option<f64>) -> Color32 {
    match ping_ms {
        Some(ms) if ms.is_finite() && ms >= 0.0 => {
            if ms < 80.0 {
                C_METRIC_GREEN
            } else if ms < 180.0 {
                C_METRIC_YELLOW
            } else {
                C_METRIC_RED
            }
        }
        _ => C_TEXT_MUTED,
    }
}

pub fn load_status_color(load_pct: Option<f64>) -> Color32 {
    match load_pct {
        Some(pct) if pct.is_finite() && pct >= 0.0 => {
            if pct < 50.0 {
                C_METRIC_GREEN
            } else if pct < 80.0 {
                C_METRIC_YELLOW
            } else {
                C_METRIC_RED
            }
        }
        _ => C_TEXT_MUTED,
    }
}

pub const WINDOW_WIDTH: f32 = 390.0;
pub const WINDOW_HEIGHT: f32 = 610.0;

fn resolve_windows_fonts_dir(
    windir: Option<std::ffi::OsString>,
    system_root: Option<std::ffi::OsString>,
) -> std::path::PathBuf {
    windir
        .filter(|v| !v.is_empty())
        .or_else(|| system_root.filter(|v| !v.is_empty()))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"))
        .join("Fonts")
}

pub fn configure_fonts_and_style(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();

    let mut prop_prefix = Vec::new();
    let mut mono_suffix = Vec::new();

    let fonts_dir =
        resolve_windows_fonts_dir(std::env::var_os("WINDIR"), std::env::var_os("SystemRoot"));

    if let Ok(segoe_bytes) = std::fs::read(fonts_dir.join("segoeui.ttf")) {
        fonts.font_data.insert(
            "segoe_ui".to_owned(),
            Arc::new(FontData::from_owned(segoe_bytes)),
        );
        prop_prefix.push("segoe_ui".to_owned());
    }

    if let Ok(emoji_bytes) = std::fs::read(fonts_dir.join("seguiemj.ttf")) {
        fonts.font_data.insert(
            "segoe_ui_emoji".to_owned(),
            Arc::new(FontData::from_owned(emoji_bytes)),
        );
        prop_prefix.push("segoe_ui_emoji".to_owned());
        mono_suffix.push("segoe_ui_emoji".to_owned());
    }

    if let Ok(sym_bytes) = std::fs::read(fonts_dir.join("seguisym.ttf")) {
        fonts.font_data.insert(
            "segoe_ui_symbol".to_owned(),
            Arc::new(FontData::from_owned(sym_bytes)),
        );
        prop_prefix.push("segoe_ui_symbol".to_owned());
        mono_suffix.push("segoe_ui_symbol".to_owned());
    }

    if !prop_prefix.is_empty() {
        if let Some(prop_list) = fonts.families.get_mut(&FontFamily::Proportional) {
            let mut merged = prop_prefix;
            merged.append(prop_list);
            *prop_list = merged;
        }
    }

    if !mono_suffix.is_empty() {
        if let Some(mono_list) = fonts.families.get_mut(&FontFamily::Monospace) {
            mono_list.extend(mono_suffix);
        }
    }

    ctx.set_fonts(fonts);

    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = C_BG;
    visuals.window_fill = C_CARD;
    visuals.extreme_bg_color = C_BG;
    visuals.faint_bg_color = C_SURFACE;
    visuals.window_stroke = Stroke::new(1.0, C_BORDER);
    visuals.window_corner_radius = CornerRadius::same(12);
    visuals.selection.bg_fill = C_SUCCESS_BG;
    visuals.selection.stroke = Stroke::new(1.0, C_ACCENT);

    visuals.widgets.noninteractive.bg_fill = C_CARD;
    visuals.widgets.noninteractive.weak_bg_fill = C_CARD;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, C_BORDER);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, C_TEXT);
    visuals.widgets.noninteractive.corner_radius = CornerRadius::same(8);

    visuals.widgets.inactive.bg_fill = C_CARD;
    visuals.widgets.inactive.weak_bg_fill = C_CARD;
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, C_BORDER);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, C_TEXT);
    visuals.widgets.inactive.corner_radius = CornerRadius::same(8);

    visuals.widgets.hovered.bg_fill = C_CARD_HIGH;
    visuals.widgets.hovered.weak_bg_fill = C_CARD_HIGH;
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, C_ACCENT);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, C_TEXT);
    visuals.widgets.hovered.corner_radius = CornerRadius::same(8);

    visuals.widgets.active.bg_fill = C_CARD_HIGH;
    visuals.widgets.active.weak_bg_fill = C_CARD_HIGH;
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, C_ACCENT);
    visuals.widgets.active.fg_stroke = Stroke::new(1.0, C_TEXT);
    visuals.widgets.active.corner_radius = CornerRadius::same(8);

    ctx.set_visuals(visuals);
}

#[derive(Clone, Copy)]
pub struct PillStyle {
    pub bg: Color32,
    pub fg: Color32,
    pub border: Color32,
    pub hover_bg: Color32,
    pub hover_fg: Color32,
    pub hover_border: Color32,
    pub radius: u8,
    pub height: f32,
    pub font_size: f32,
    pub bold: bool,
    pub pad_x: f32,
}

impl PillStyle {
    pub fn secondary(height: f32) -> Self {
        Self {
            bg: C_CARD,
            fg: C_TEXT,
            border: C_BORDER,
            hover_bg: C_CARD_HIGH,
            hover_fg: C_ACCENT,
            hover_border: C_ACCENT,
            radius: 8,
            height,
            font_size: 12.0,
            bold: true,
            pad_x: 10.0,
        }
    }

    pub fn accent(height: f32) -> Self {
        Self {
            bg: C_ACCENT,
            fg: Color32::BLACK,
            border: C_ACCENT,
            hover_bg: C_ACCENT_HOVER,
            hover_fg: Color32::BLACK,
            hover_border: C_ACCENT_HOVER,
            radius: 10,
            height,
            font_size: 13.0,
            bold: true,
            pad_x: 14.0,
        }
    }
}

pub fn pill_button(ui: &mut Ui, text: &str, width: Option<f32>, style: PillStyle) -> Response {
    let mut rt = RichText::new(text).size(style.font_size);
    if style.bold {
        rt = rt.strong();
    }
    let galley = ui.painter().layout_no_wrap(
        text.to_owned(),
        egui::FontId::proportional(style.font_size),
        style.fg,
    );
    let desired_w = width.unwrap_or_else(|| (galley.size().x + style.pad_x * 2.0).max(28.0));
    let desired_size = Vec2::new(desired_w, style.height);
    let (rect, response) = ui.allocate_exact_size(desired_size, Sense::click());
    let response = response.on_hover_cursor(CursorIcon::PointingHand);

    let hover_t = if ui.style().animation_time > 0.0 {
        ui.ctx()
            .animate_bool_with_time(response.id.with("hover"), response.hovered(), 0.12)
    } else if response.hovered() {
        1.0
    } else {
        0.0
    };

    let bg = if response.is_pointer_button_down_on() {
        style.border
    } else {
        lerp_color(style.bg, style.hover_bg, hover_t)
    };
    let fg = lerp_color(style.fg, style.hover_fg, hover_t);
    let border = lerp_color(style.border, style.hover_border, hover_t);

    if ui.is_rect_visible(rect) {
        let p = ui.painter();
        let cr = CornerRadius::same(style.radius);
        p.rect_filled(rect, cr, bg);
        p.rect_stroke(rect, cr, Stroke::new(1.0, border), StrokeKind::Inside);

        let mut text_rt = RichText::new(text).size(style.font_size).color(fg);
        if style.bold {
            text_rt = text_rt.strong();
        }
        let text_galley = ui.painter().layout_no_wrap(
            text_rt.text().to_owned(),
            egui::FontId::proportional(style.font_size),
            fg,
        );
        let offset_y = if response.is_pointer_button_down_on() {
            1.0
        } else {
            0.0
        };
        let pos = Pos2::new(
            rect.center().x - text_galley.size().x * 0.5,
            rect.center().y - text_galley.size().y * 0.5 + offset_y,
        );
        p.galley(pos, text_galley, fg);
    }

    let _ = rt;
    response
}

pub fn rounded_card<R>(
    ui: &mut Ui,
    fill: Color32,
    border: Color32,
    radius: u8,
    margin: Margin,
    add_contents: impl FnOnce(&mut Ui) -> R,
) -> egui::InnerResponse<R> {
    Frame::NONE
        .fill(fill)
        .stroke(Stroke::new(1.0, border))
        .corner_radius(CornerRadius::same(radius))
        .inner_margin(margin)
        .show(ui, add_contents)
}

pub fn lerp_color(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let inv = 1.0 - t;
    Color32::from_rgba_premultiplied(
        (a.r() as f32 * inv + b.r() as f32 * t).round() as u8,
        (a.g() as f32 * inv + b.g() as f32 * t).round() as u8,
        (a.b() as f32 * inv + b.b() as f32 * t).round() as u8,
        (a.a() as f32 * inv + b.a() as f32 * t).round() as u8,
    )
}

pub fn open_external_url(url: &str) {
    if let Err(err) = WindowsShellLauncher::open_https_url_direct(url) {
        warn!(url = %url, error = %err, "rejected or failed opening external URL");
    }
}

fn render_view_contents(
    view: AppView,
    ui: &mut Ui,
    state: &mut AppState,
    store: &dyn CredentialStore,
) {
    match view {
        AppView::Login => login::render_login_view(ui, state),
        AppView::Srp => login::render_srp_view(ui, state),
        AppView::Home => home::render_home_view(ui, state, store),
        AppView::Drawer => drawer::render_drawer_view(ui, state),
    }
}

pub fn render_root(ui: &mut Ui, state: &mut AppState, store: &dyn CredentialStore) {
    let ctx = ui.ctx().clone();
    let anim_on = state.client_config.animations_enabled;
    let anim_time = if anim_on { 0.14 } else { 0.0 };
    ctx.style_mut_of(egui::Theme::Dark, |s| {
        s.animation_time = anim_time;
    });
    ui.style_mut().animation_time = anim_time;

    egui::CentralPanel::default()
        .frame(
            Frame::NONE
                .fill(C_BG)
                .stroke(Stroke::new(1.0, C_BORDER))
                .inner_margin(Margin::symmetric(14, 12)),
        )
        .show(ui, |ui| {
            render_top_bar(&ctx, ui, state);

            // Loading bar with symmetric enter/exit animation.
            let loading_t = ctx.animate_bool_with_time(
                egui::Id::unique("freeton_loading_visible_t"),
                state.loading.visible,
                if anim_on { 0.16 } else { 0.0 },
            );
            let loading_text_id = egui::Id::unique("freeton_loading_cached_text");
            if state.loading.visible {
                ctx.data_mut(|d| d.insert_temp(loading_text_id, state.loading.text.clone()));
            }
            let loading_text = if state.loading.visible {
                Some(state.loading.text.clone())
            } else if loading_t > 0.0 {
                ctx.data(|d| d.get_temp::<String>(loading_text_id))
            } else {
                ctx.data_mut(|d| d.remove::<String>(loading_text_id));
                None
            };
            if (state.loading.visible && loading_t < 1.0)
                || (!state.loading.visible && loading_t > 0.0)
            {
                ctx.request_repaint();
            }
            if let Some(text) = loading_text {
                ui.add_space(4.0 * loading_t);
                ui.scope(|ui| {
                    if !state.loading.visible {
                        ui.disable();
                    }
                    ui.set_opacity(loading_t);
                    render_loading_bar(ui, &ctx, state, &text, anim_on);
                });
                ui.add_space(6.0 * loading_t);
            } else {
                ui.add_space(4.0);
            }

            // Info toast with symmetric slide + fade enter/exit animation.
            let toast_t = ctx.animate_bool_with_time(
                egui::Id::unique("freeton_info_toast_t"),
                state.info_toast.is_some(),
                if anim_on { 0.18 } else { 0.0 },
            );
            let toast_cache_id = egui::Id::unique("freeton_info_toast_cache");
            if let Some(toast) = &state.info_toast {
                ctx.data_mut(|d| d.insert_temp(toast_cache_id, toast.clone()));
            }
            let rendered_toast = if let Some(toast) = state.info_toast.clone() {
                Some((toast, true))
            } else if toast_t > 0.0 {
                ctx.data(|d| d.get_temp::<crate::state::StatusNotice>(toast_cache_id))
                    .map(|t| (t, false))
            } else {
                ctx.data_mut(|d| d.remove::<crate::state::StatusNotice>(toast_cache_id));
                None
            };
            if (state.info_toast.is_some() && toast_t < 1.0)
                || (state.info_toast.is_none() && toast_t > 0.0)
            {
                ctx.request_repaint();
            }
            if let Some((toast, interactive)) = rendered_toast {
                let eased_toast = 1.0 - (1.0 - toast_t).powi(3);
                let color = match toast.level {
                    NoticeLevel::Success => C_SUCCESS,
                    NoticeLevel::Warning => C_WARNING,
                    NoticeLevel::Error => C_DANGER,
                    NoticeLevel::Info => C_ACCENT,
                };
                let toast_slide_y = -6.0 * (1.0 - eased_toast);
                let row_rect = ui.available_rect_before_wrap();
                let shifted_rect = row_rect.translate(Vec2::new(0.0, toast_slide_y));
                let resp = ui.scope_builder(egui::UiBuilder::new().max_rect(shifted_rect), |ui| {
                    ui.set_clip_rect(row_rect);
                    if !interactive {
                        ui.disable();
                    }
                    ui.set_opacity(eased_toast);
                    rounded_card(ui, C_SURFACE, color, 8, Margin::symmetric(8, 5), |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 6.0;
                            let close_w = 18.0;
                            let text_w = (ui.available_width() - close_w - 6.0).max(80.0);
                            ui.allocate_ui_with_layout(
                                Vec2::new(text_w, 0.0),
                                Layout::top_down(Align::Min),
                                |ui| {
                                    ui.set_width(text_w);
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(&toast.text).size(11.0).color(color),
                                        )
                                        .wrap(),
                                    );
                                },
                            );
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui
                                    .add(
                                        egui::Button::new(
                                            RichText::new("✕").size(10.0).color(C_TEXT_DIM),
                                        )
                                        .frame(false),
                                    )
                                    .clicked()
                                {
                                    state.info_toast = None;
                                }
                            });
                        });
                    });
                });
                let _ = resp;
                ui.add_space(4.0 * eased_toast);
            }

            let now = std::time::Instant::now();
            let progress = state.transition_progress(now);
            if progress < 1.0 {
                ctx.request_repaint();
            }

            let dir_sign = match state.view_transition_dir {
                ViewDirection::Forward => 1.0,
                ViewDirection::Backward => -1.0,
            };
            let avail = ui.available_rect_before_wrap();

            // Render exiting view underneath (symmetric slide-out + fade-out) during active view transitions.
            if progress < 1.0 {
                if let Some(prev_view) = state.previous_view.filter(|&p| p != state.current_view) {
                    let exit_px = -34.0 * dir_sign * progress;
                    let exit_rect = avail.translate(Vec2::new(exit_px, 0.0));
                    ui.scope_builder(egui::UiBuilder::new().max_rect(exit_rect), |ui| {
                        ui.set_clip_rect(avail);
                        ui.disable();
                        ui.set_opacity((1.0 - progress).powf(1.2));
                        render_view_contents(prev_view, ui, state, store);
                    });
                }
            }

            let enter_px = if progress < 1.0 {
                34.0 * dir_sign * (1.0 - progress)
            } else {
                0.0
            };
            let shifted = avail.translate(Vec2::new(enter_px, 0.0));
            ui.scope_builder(egui::UiBuilder::new().max_rect(shifted), |ui| {
                ui.set_clip_rect(avail);
                if progress < 1.0 {
                    ui.set_opacity(progress.clamp(0.0, 1.0));
                }
                render_view_contents(state.current_view, ui, state, store);
            });
        });

    dialogs::render_dialog_overlay(&ctx, state, store);
}

fn render_top_bar(ctx: &egui::Context, ui: &mut Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        // Left: draggable brand header
        let brand_resp = ui
            .allocate_ui_with_layout(
                Vec2::new(150.0, 42.0),
                Layout::left_to_right(Align::Center),
                |ui| {
                    ui.label(RichText::new("⚡").size(20.0).color(C_ACCENT));
                    ui.add_space(4.0);
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 0.0;
                        ui.label(RichText::new(APP_NAME).size(15.0).strong().color(C_TEXT));
                        ui.label(
                            RichText::new("by pishun")
                                .size(10.0)
                                .italics()
                                .color(C_TEXT_DIM),
                        );
                    });
                },
            )
            .response
            .interact(Sense::drag());

        if brand_resp.drag_started() {
            state.user_has_custom_dragged = true;
            ctx.send_viewport_cmd(ViewportCommand::StartDrag);
        }

        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let close_style = PillStyle {
                bg: C_CARD,
                fg: C_TEXT_MUTED,
                border: C_BORDER,
                hover_bg: C_CLOSE_HOVER,
                hover_fg: Color32::WHITE,
                hover_border: C_CLOSE_HOVER,
                radius: 8,
                height: 28.0,
                font_size: 14.0,
                bold: true,
                pad_x: 0.0,
            };
            if pill_button(ui, "✕", Some(30.0), close_style)
                .on_hover_text("Thu gọn xuống khay hệ thống")
                .clicked()
            {
                state.window_visible = false;
                ctx.send_viewport_cmd(ViewportCommand::Visible(false));
            }

            ui.add_space(4.0);

            let refresh_style = PillStyle {
                fg: if state.is_scanning { C_ACCENT } else { C_TEXT },
                font_size: 14.0,
                pad_x: 0.0,
                ..PillStyle::secondary(28.0)
            };
            if pill_button(ui, "↻", Some(30.0), refresh_style)
                .on_hover_text("Quét lại danh sách máy chủ")
                .clicked()
            {
                if state.is_logged_in {
                    state.start_scan();
                } else {
                    state.show_login_view();
                }
            }

            ui.add_space(4.0);

            let chip_text = state.account_chip_text();
            let chip_fg = if state.is_logged_in {
                C_SUCCESS
            } else {
                C_TEXT_DIM
            };
            let chip_style = PillStyle {
                fg: chip_fg,
                hover_fg: C_TEXT,
                font_size: 11.0,
                pad_x: 10.0,
                ..PillStyle::secondary(28.0)
            };
            if pill_button(ui, &chip_text, None, chip_style).clicked() {
                if state.is_logged_in {
                    state.active_dialog = ActiveDialog::LogoutConfirm;
                } else {
                    state.show_login_view();
                }
            }
        });
    });
}

fn render_loading_bar(
    ui: &mut Ui,
    ctx: &egui::Context,
    state: &AppState,
    label_text: &str,
    animations_enabled: bool,
) {
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 3.0;
        ui.label(
            RichText::new(label_text)
                .size(10.5)
                .strong()
                .color(C_ACCENT),
        );
        let width = ui.available_width().max(40.0);
        let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 4.0), Sense::hover());
        let p = ui.painter();
        let cr = CornerRadius::same(2);
        p.rect_filled(rect, cr, C_CARD);
        let target_frac = state.loading.progress.clamp(0.0, 1.0);
        let anim_frac = ctx.animate_value_with_time(
            egui::Id::unique("freeton_loading_frac"),
            target_frac,
            if animations_enabled { 0.22 } else { 0.0 },
        );
        if (anim_frac - target_frac).abs() > 0.005 {
            ctx.request_repaint();
        }
        if anim_frac > 0.0 {
            let fill_w = (rect.width() * anim_frac).max(4.0);
            let fill_rect = Rect::from_min_size(rect.min, Vec2::new(fill_w, rect.height()));
            p.rect_filled(fill_rect, cr, C_ACCENT);

            // Subtle traveling shimmer highlight while visible.
            if animations_enabled && state.loading.visible && fill_w > 18.0 {
                let time = ctx.input(|i| i.time) as f32;
                let cycle = (time * 1.15).fract();
                let shimmer_w = (fill_w * 0.28).clamp(12.0, 48.0);
                let x = fill_rect.left() - shimmer_w + (fill_w + shimmer_w) * cycle;
                let clipped_min_x = x.max(fill_rect.left());
                let clipped_max_x = (x + shimmer_w).min(fill_rect.right());
                if clipped_max_x > clipped_min_x {
                    let shimmer_rect = Rect::from_min_max(
                        Pos2::new(clipped_min_x, fill_rect.top()),
                        Pos2::new(clipped_max_x, fill_rect.bottom()),
                    );
                    p.rect_filled(shimmer_rect, cr, Color32::from_white_alpha(64));
                }
                ctx.request_repaint_after(std::time::Duration::from_millis(33));
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::resolve_windows_fonts_dir;
    use std::ffi::OsString;
    use std::path::PathBuf;

    #[test]
    fn test_resolve_windows_fonts_dir_precedence() {
        assert_eq!(
            resolve_windows_fonts_dir(
                Some(OsString::from(r"D:\WinOS")),
                Some(OsString::from(r"E:\Fallback"))
            ),
            PathBuf::from(r"D:\WinOS\Fonts")
        );
        assert_eq!(
            resolve_windows_fonts_dir(Some(OsString::new()), Some(OsString::from(r"E:\SysRoot"))),
            PathBuf::from(r"E:\SysRoot\Fonts")
        );
        assert_eq!(
            resolve_windows_fonts_dir(None, None),
            PathBuf::from(r"C:\Windows\Fonts")
        );
    }

    #[test]
    fn test_symmetric_enter_and_exit_animations_for_views_dialogs_and_toast() {
        use crate::state::{ActiveDialog, AppState, NoticeLevel, StatusNotice};
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

        fn collect_all_text(shapes: &[egui::epaint::ClippedShape]) -> String {
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
            for c in shapes {
                visit(&c.shape, &mut out);
            }
            out
        }

        let ctx = egui::Context::default();
        let store = NoopStore;
        let mut state = AppState::new(
            true,
            Some("user@proton.me".to_owned()),
            ClientConfig::default(),
            None,
            Vec::new(),
        );
        state.window_visible = true;

        let make_input = |time: f64| egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::Vec2::new(super::WINDOW_WIDTH, super::WINDOW_HEIGHT),
            )),
            time: Some(time),
            ..Default::default()
        };

        // 1. Seed closed dialog/toast state at t=0.0, then open About + Toast, then close and verify
        // exit animation keeps rendering smoothly during fade-out and unmounts after completion.
        let mut out = ctx.run_ui(make_input(0.0), |ui| {
            super::render_root(ui, &mut state, &store);
        });
        out.textures_delta.clear();

        state.open_about_dialog();
        state.info_toast = Some(StatusNotice {
            text: "Thông báo thử nghiệm animation".to_owned(),
            level: NoticeLevel::Info,
        });
        state.show_drawer_view();

        let mut start_enter = ctx.run_ui(make_input(0.05), |ui| {
            super::render_root(ui, &mut state, &store);
        });
        start_enter.textures_delta.clear();
        let mut mid = ctx.run_ui(make_input(0.12), |ui| {
            super::render_root(ui, &mut state, &store);
        });
        mid.textures_delta.clear();
        let mid_text = collect_all_text(&mid.shapes);
        assert!(
            mid_text.contains("KẾT NỐI CỦA BẠN") && mid_text.contains("Danh Sách Máy Chủ"),
            "view transition must render both exiting Home and entering Drawer: {mid_text}"
        );
        assert!(mid_text.contains("TUYÊN BỐ PHÁP LÝ"));
        assert!(mid_text.contains("Thông báo thử nghiệm animation"));

        // Ensure enter animation reaches 1.0 by t=0.50.
        let mut settled = ctx.run_ui(make_input(0.50), |ui| {
            super::render_root(ui, &mut state, &store);
        });
        settled.textures_delta.clear();

        // Close dialog & toast: during exit window (t=0.55 -> t=0.62) both fade/slide out smoothly; by t=1.00 both are gone.
        state.close_dialog();
        state.info_toast = None;
        assert_eq!(state.active_dialog, ActiveDialog::None);

        let mut start_exit = ctx.run_ui(make_input(0.55), |ui| {
            super::render_root(ui, &mut state, &store);
        });
        start_exit.textures_delta.clear();
        let mut exiting = ctx.run_ui(make_input(0.62), |ui| {
            super::render_root(ui, &mut state, &store);
        });
        exiting.textures_delta.clear();
        let exiting_text = collect_all_text(&exiting.shapes);
        assert!(
            exiting_text.contains("TUYÊN BỐ PHÁP LÝ"),
            "dialog exit animation must fade out About dialog instead of vanishing at 0ms: {exiting_text}"
        );
        assert!(
            exiting_text.contains("Thông báo thử nghiệm animation"),
            "toast exit animation must fade out toast instead of vanishing at 0ms: {exiting_text}"
        );

        let mut finished = ctx.run_ui(make_input(1.00), |ui| {
            super::render_root(ui, &mut state, &store);
        });
        finished.textures_delta.clear();
        let finished_text = collect_all_text(&finished.shapes);
        assert!(!finished_text.contains("TUYÊN BỐ PHÁP LÝ"));
        assert!(!finished_text.contains("Thông báo thử nghiệm animation"));
    }

    #[test]
    fn test_ping_and_load_status_colors_thresholds() {
        assert_eq!(super::ping_status_color(None), super::C_TEXT_MUTED);
        assert_eq!(super::ping_status_color(Some(-5.0)), super::C_TEXT_MUTED);
        assert_eq!(
            super::ping_status_color(Some(f64::NAN)),
            super::C_TEXT_MUTED
        );
        assert_eq!(super::ping_status_color(Some(54.0)), super::C_METRIC_GREEN);
        assert_eq!(super::ping_status_color(Some(79.9)), super::C_METRIC_GREEN);
        assert_eq!(super::ping_status_color(Some(80.0)), super::C_METRIC_YELLOW);
        assert_eq!(
            super::ping_status_color(Some(179.9)),
            super::C_METRIC_YELLOW
        );
        assert_eq!(super::ping_status_color(Some(180.0)), super::C_METRIC_RED);

        assert_eq!(super::load_status_color(None), super::C_TEXT_MUTED);
        assert_eq!(super::load_status_color(Some(-1.0)), super::C_TEXT_MUTED);
        assert_eq!(super::load_status_color(Some(25.0)), super::C_METRIC_GREEN);
        assert_eq!(super::load_status_color(Some(49.9)), super::C_METRIC_GREEN);
        assert_eq!(super::load_status_color(Some(50.0)), super::C_METRIC_YELLOW);
        assert_eq!(super::load_status_color(Some(79.9)), super::C_METRIC_YELLOW);
        assert_eq!(super::load_status_color(Some(80.0)), super::C_METRIC_RED);
        assert_eq!(super::load_status_color(Some(98.0)), super::C_METRIC_RED);
    }
}
