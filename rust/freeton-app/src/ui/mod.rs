pub mod dialogs;
pub mod drawer;
pub mod globe;
pub mod globe_data;
pub mod home;
pub mod login;

use std::sync::Arc;

use egui::epaint::text::{
    FontData, FontDefinitions, FontFamily, FontTweak, HintingTarget, SmoothHinting,
};
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

const BRAND_LOGO_PNG: &[u8] = include_bytes!("../../../../website/assets/images/logo.png");

/// Loads and caches the embedded purple Freeton VPN logo texture on the `egui::Context`.
pub fn brand_logo_texture(ctx: &egui::Context) -> egui::TextureHandle {
    let tex_id = egui::Id::unique("freeton_brand_logo_texture");
    if let Some(handle) = ctx.data(|d| d.get_temp::<egui::TextureHandle>(tex_id)) {
        return handle;
    }

    let color_image = match image::load_from_memory_with_format(BRAND_LOGO_PNG, image::ImageFormat::Png)
    {
        Ok(img) => {
            let rgba = img.to_rgba8();
            let (w, h) = rgba.dimensions();
            egui::ColorImage::from_rgba_unmultiplied([w as usize, h as usize], rgba.as_raw())
        }
        Err(err) => {
            warn!(error = %err, "failed to decode embedded brand logo PNG");
            egui::ColorImage::filled([1, 1], Color32::from_rgb(0xc0, 0x84, 0xfc))
        }
    };

    let handle = ctx.load_texture(
        "freeton_brand_logo",
        color_image,
        egui::TextureOptions::LINEAR,
    );
    ctx.data_mut(|d| d.insert_temp(tex_id, handle.clone()));
    handle
}

/// Renders the embedded purple Freeton VPN brand logo at the requested square logical size.
pub fn render_brand_logo(ui: &mut Ui, size: f32) -> Response {
    let tex = brand_logo_texture(ui.ctx());
    ui.add(egui::Image::new(egui::load::SizedTexture::new(
        tex.id(),
        Vec2::splat(size),
    )))
}

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

fn crisp_font_tweak() -> FontTweak {
    FontTweak {
        hinting: Some(true),
        subpixel_binning: Some(false),
        hinting_target: HintingTarget::Smooth(SmoothHinting {
            light: false,
            symmetric_rendering: false,
            preserve_linear_metrics: false,
        }),
        ..Default::default()
    }
}

fn apply_windows_fonts_to_definitions(fonts: &mut FontDefinitions, fonts_dir: &std::path::Path) {
    let mut prop_prefix = Vec::new();
    let mut mono_suffix = Vec::new();
    let crisp_tweak = crisp_font_tweak();

    if let Ok(segoe_bytes) = std::fs::read(fonts_dir.join("segoeui.ttf")) {
        fonts.font_data.insert(
            "segoe_ui".to_owned(),
            Arc::new(FontData::from_owned(segoe_bytes).tweak(crisp_tweak.clone())),
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
            Arc::new(FontData::from_owned(sym_bytes).tweak(crisp_tweak)),
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
}

pub fn configure_fonts_and_style(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    let fonts_dir =
        resolve_windows_fonts_dir(std::env::var_os("WINDIR"), std::env::var_os("SystemRoot"));
    apply_windows_fonts_to_definitions(&mut fonts, &fonts_dir);

    ctx.set_fonts(fonts);

    let mut visuals = egui::Visuals::dark();
    visuals.text_options.font_hinting = true;
    visuals.text_options.subpixel_binning = false;
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

pub(crate) fn modal_ease(t: f32, entering: bool) -> f32 {
    let t = t.clamp(0.0, 1.0);
    if entering {
        1.0 - (1.0 - t).powi(3)
    } else {
        t * t
    }
}

/// Renders a flow banner slot whose occupied height and opacity collapse smoothly during enter/exit.
fn render_collapsible_slot(
    ui: &mut Ui,
    height_id: egui::Id,
    default_h: f32,
    t: f32,
    height_frac: f32,
    opacity_frac: f32,
    add_contents: impl FnOnce(&mut Ui) -> f32,
) {
    let measured_h = if t >= 0.999 {
        add_contents(ui)
    } else {
        let cached_h = ui
            .ctx()
            .data(|d| d.get_temp::<f32>(height_id))
            .unwrap_or(default_h)
            .max(1.0);
        let vis_h = (cached_h * height_frac).max(0.0);
        let row_w = ui.available_width();
        let (slot, _) = ui.allocate_exact_size(Vec2::new(row_w, vis_h), Sense::hover());
        let inner_rect = Rect::from_min_size(slot.min, Vec2::new(slot.width(), cached_h));
        ui.scope_builder(egui::UiBuilder::new().max_rect(inner_rect), |ui| {
            ui.set_clip_rect(slot);
            ui.set_opacity(opacity_frac);
            add_contents(ui)
        })
        .inner
    };
    if measured_h > 1.0 {
        ui.ctx()
            .data_mut(|d| d.insert_temp(height_id, measured_h));
    }
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

            // Loading bar with smooth height collapse & symmetric enter/exit animation.
            let loading_entering = state.loading.visible;
            let loading_t = ctx.animate_bool_with_time(
                egui::Id::unique("freeton_loading_visible_t"),
                loading_entering,
                if anim_on { 0.16 } else { 0.0 },
            );
            let loading_text_id = egui::Id::unique("freeton_loading_cached_text");
            let loading_height_id = egui::Id::unique("freeton_loading_cached_height");
            if loading_entering {
                ctx.data_mut(|d| d.insert_temp(loading_text_id, state.loading.text.clone()));
            }
            let loading_text = if loading_entering {
                Some(state.loading.text.clone())
            } else if loading_t > 0.0 {
                ctx.data(|d| d.get_temp::<String>(loading_text_id))
            } else {
                ctx.data_mut(|d| {
                    d.remove::<String>(loading_text_id);
                    d.remove::<f32>(loading_height_id);
                });
                None
            };
            if anim_on
                && state.window_visible
                && ((loading_entering && loading_t < 1.0) || (!loading_entering && loading_t > 0.0))
            {
                ctx.request_repaint();
            }
            if let Some(text) = loading_text {
                let eased_loading = modal_ease(loading_t, loading_entering);
                let loading_h_frac = if loading_entering { eased_loading } else { loading_t };
                ui.add_space(4.0 * loading_h_frac);
                render_collapsible_slot(
                    ui,
                    loading_height_id,
                    24.0,
                    loading_t,
                    loading_h_frac,
                    eased_loading,
                    |ui| {
                        ui.vertical(|ui| render_loading_bar(ui, &ctx, state, &text, anim_on))
                            .response
                            .rect
                            .height()
                    },
                );
                ui.add_space(6.0 * loading_h_frac);
            } else {
                ui.add_space(4.0);
            }

            // Info toast with symmetric padding, directional ease, and smooth height collapse.
            let toast_entering = state.info_toast.is_some();
            let toast_t = ctx.animate_bool_with_time(
                egui::Id::unique("freeton_info_toast_t"),
                toast_entering,
                if anim_on { 0.18 } else { 0.0 },
            );
            let toast_cache_id = egui::Id::unique("freeton_info_toast_cache");
            let toast_height_id = egui::Id::unique("freeton_info_toast_height");
            if let Some(toast) = &state.info_toast {
                ctx.data_mut(|d| d.insert_temp(toast_cache_id, toast.clone()));
            }
            let rendered_toast = if let Some(toast) = state.info_toast.clone() {
                Some((toast, true))
            } else if toast_t > 0.0 {
                ctx.data(|d| d.get_temp::<crate::state::StatusNotice>(toast_cache_id))
                    .map(|t| (t, false))
            } else {
                ctx.data_mut(|d| {
                    d.remove::<crate::state::StatusNotice>(toast_cache_id);
                    d.remove::<f32>(toast_height_id);
                });
                None
            };
            if anim_on
                && state.window_visible
                && ((toast_entering && toast_t < 1.0) || (!toast_entering && toast_t > 0.0))
            {
                ctx.request_repaint();
            }
            if let Some((toast, interactive)) = rendered_toast {
                let eased_toast = modal_ease(toast_t, toast_entering);
                let toast_h_frac = if toast_entering { eased_toast } else { toast_t };
                let color = match toast.level {
                    NoticeLevel::Success => C_SUCCESS,
                    NoticeLevel::Warning => C_WARNING,
                    NoticeLevel::Error => C_DANGER,
                    NoticeLevel::Info => C_ACCENT,
                };
                render_collapsible_slot(
                    ui,
                    toast_height_id,
                    32.0,
                    toast_t,
                    toast_h_frac,
                    eased_toast,
                    |ui| {
                        rounded_card(ui, C_SURFACE, color, 8, Margin::symmetric(10, 7), |ui| {
                            let inner_w = ui.available_width();
                            ui.set_width(inner_w);
                            ui.with_layout(Layout::left_to_right(Align::Min), |ui| {
                                let gap = 8.0;
                                ui.spacing_mut().item_spacing.x = gap;
                                let close_w = 18.0;
                                let text_w = (inner_w - close_w - gap).max(80.0);
                                let left_resp = ui.allocate_ui_with_layout(
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
                                let row_h = left_resp.response.rect.height().max(16.0);
                                ui.allocate_ui_with_layout(
                                    Vec2::new(close_w, row_h),
                                    Layout::right_to_left(Align::Center),
                                    |ui| {
                                        if interactive {
                                            if ui
                                                .add(
                                                    egui::Button::new(
                                                        RichText::new("✕")
                                                            .size(10.0)
                                                            .color(C_TEXT_DIM),
                                                    )
                                                    .frame(false),
                                                )
                                                .on_hover_cursor(CursorIcon::PointingHand)
                                                .clicked()
                                            {
                                                state.info_toast = None;
                                                if anim_on && state.window_visible {
                                                    ctx.request_repaint();
                                                }
                                            }
                                        } else {
                                            ui.add(
                                                egui::Label::new(
                                                    RichText::new("✕")
                                                        .size(10.0)
                                                        .color(C_TEXT_DIM),
                                                )
                                                .selectable(false),
                                            );
                                        }
                                    },
                                );
                            });
                        })
                        .response
                        .rect
                        .height()
                    },
                );
                ui.add_space(4.0 * toast_h_frac);
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
    let mut controls_rect: Option<Rect> = None;

    let bar_resp = ui.allocate_ui_with_layout(
        Vec2::new(ui.available_width(), 42.0),
        Layout::left_to_right(Align::Center),
        |ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            render_brand_logo(ui, 26.0);
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                ui.add(
                    egui::Label::new(RichText::new(APP_NAME).size(15.0).strong().color(C_TEXT))
                        .selectable(false),
                );
                ui.add(
                    egui::Label::new(
                        RichText::new("by pishun")
                            .size(10.0)
                            .italics()
                            .color(C_TEXT_DIM),
                    )
                    .selectable(false),
                );
            });

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.spacing_mut().item_spacing.x = 5.0;
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
                let close_resp = pill_button(ui, "✕", Some(30.0), close_style)
                    .on_hover_text("Thu gọn xuống khay hệ thống");
                let mut bounds = close_resp.rect;
                if close_resp.clicked() {
                    state.window_visible = false;
                    ctx.send_viewport_cmd(ViewportCommand::Visible(false));
                }

                let refresh_style = PillStyle {
                    fg: if state.is_scanning { C_ACCENT } else { C_TEXT },
                    font_size: 14.0,
                    pad_x: 0.0,
                    ..PillStyle::secondary(28.0)
                };
                let refresh_resp = pill_button(ui, "↻", Some(30.0), refresh_style)
                    .on_hover_text("Quét lại danh sách máy chủ");
                bounds = bounds.union(refresh_resp.rect);
                if refresh_resp.clicked() {
                    if state.is_logged_in {
                        state.start_scan();
                    } else {
                        state.show_login_view();
                    }
                }

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
                let chip_resp = pill_button(ui, &chip_text, None, chip_style);
                bounds = bounds.union(chip_resp.rect);
                if chip_resp.clicked() {
                    if state.is_logged_in {
                        state.active_dialog = ActiveDialog::LogoutConfirm;
                    } else {
                        state.show_login_view();
                    }
                }

                controls_rect = Some(bounds);
            });
        },
    );

    let screen = ctx.content_rect();
    let bar_rect = bar_resp.response.rect;
    let header_bounds = Rect::from_min_max(
        screen.min,
        Pos2::new(screen.max.x.max(bar_rect.max.x), bar_rect.max.y),
    );

    let drag_zones: Vec<Rect> = if let Some(ctrl) = controls_rect {
        let ctrl = ctrl.intersect(header_bounds);
        vec![
            Rect::from_min_max(header_bounds.min, Pos2::new(ctrl.min.x, header_bounds.max.y)),
            Rect::from_min_max(
                Pos2::new(ctrl.min.x, header_bounds.min.y),
                Pos2::new(ctrl.max.x, ctrl.min.y),
            ),
            Rect::from_min_max(
                Pos2::new(ctrl.min.x, ctrl.max.y),
                Pos2::new(ctrl.max.x, header_bounds.max.y),
            ),
            Rect::from_min_max(Pos2::new(ctrl.max.x, header_bounds.min.y), header_bounds.max),
        ]
    } else {
        vec![header_bounds]
    };

    let primary_down = ctx.input(|i| i.pointer.primary_down());
    if state.active_dialog != ActiveDialog::None || !primary_down {
        state.window_drag_active = false;
    }

    let mut start_drag_now = false;
    for (idx, zone) in drag_zones.into_iter().enumerate() {
        if zone.width() <= 0.0 || zone.height() <= 0.0 {
            continue;
        }
        let resp = ui.interact(
            zone,
            ui.scope_id().with(("top_bar_drag_zone", idx)),
            Sense::drag(),
        );
        if resp.is_pointer_button_down_on() && primary_down && state.active_dialog == ActiveDialog::None
        {
            start_drag_now = true;
        }
    }

    if start_drag_now {
        state.window_drag_active = true;
        state.user_has_custom_dragged = true;
    }
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

    #[test]
    fn test_brand_logo_renders_in_topbar_login_and_about_without_lightning_emoji() {
        use crate::state::{AppState, AppView};
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

        fn count_brand_images(
            shapes: &[egui::epaint::ClippedShape],
            brand_tex_id: egui::TextureId,
        ) -> usize {
            fn visit(shape: &egui::epaint::Shape, brand_tex_id: egui::TextureId) -> usize {
                match shape {
                    egui::epaint::Shape::Rect(r) if r.fill_texture_id() == brand_tex_id => 1,
                    egui::epaint::Shape::Mesh(m) if m.texture_id == brand_tex_id => 1,
                    egui::epaint::Shape::Vec(items) => {
                        items.iter().map(|s| visit(s, brand_tex_id)).sum()
                    }
                    _ => 0,
                }
            }
            shapes.iter().map(|c| visit(&c.shape, brand_tex_id)).sum()
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
        let tex_handle = super::brand_logo_texture(&ctx);
        assert_eq!(tex_handle.size(), [256, 256]);
        let brand_tex_id = tex_handle.id();

        let store = NoopStore;
        let mut state = AppState::new(false, None, ClientConfig::default(), None, Vec::new());
        state.current_view = AppView::Login;
        state.window_visible = true;
        state.open_about_dialog();

        let mut out = egui::FullOutput::default();
        for frame_idx in 0..2 {
            let raw_input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::Vec2::new(super::WINDOW_WIDTH, super::WINDOW_HEIGHT),
                )),
                time: Some(frame_idx as f64 * 0.1),
                ..Default::default()
            };
            out = ctx.run_ui(raw_input, |ui| {
                super::render_root(ui, &mut state, &store);
            });
            out.textures_delta.clear();
        }

        // Top bar + Login hero card + About dialog = 3 rendered brand logo images.
        assert_eq!(count_brand_images(&out.shapes, brand_tex_id), 3);
        let text = collect_all_text(&out.shapes);
        assert!(
            !text.contains('⚡'),
            "Top bar, Login hero, and About dialog must not render ⚡ emoji: {text}"
        );
    }

    #[test]
    fn test_top_bar_drag_works_on_entire_empty_header_but_not_on_buttons() {
        use crate::state::AppState;
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

        fn simulate_drag_at(
            start_pos: egui::Pos2,
            drag_delta: egui::Vec2,
        ) -> (bool, bool) {
            let ctx = egui::Context::default();
            let store = NoopStore;
            let mut state = AppState::new(false, None, ClientConfig::default(), None, Vec::new());
            state.window_visible = true;

            let base_input = |events: Vec<egui::Event>, time: f64| egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::Vec2::new(super::WINDOW_WIDTH, super::WINDOW_HEIGHT),
                )),
                time: Some(time),
                events,
                ..Default::default()
            };

            let mut out = ctx.run_ui(base_input(vec![], 0.0), |ui| {
                super::render_root(ui, &mut state, &store);
            });
            out.textures_delta.clear();

            let mut out2 = ctx.run_ui(
                base_input(
                    vec![
                        egui::Event::PointerMoved(start_pos),
                        egui::Event::PointerButton {
                            pos: start_pos,
                            button: egui::PointerButton::Primary,
                            pressed: true,
                            modifiers: egui::Modifiers::NONE,
                        },
                    ],
                    0.02,
                ),
                |ui| {
                    super::render_root(ui, &mut state, &store);
                },
            );
            out2.textures_delta.clear();

            let mut out3 = ctx.run_ui(
                base_input(
                    vec![egui::Event::PointerMoved(start_pos + drag_delta)],
                    0.04,
                ),
                |ui| {
                    super::render_root(ui, &mut state, &store);
                },
            );
            out3.textures_delta.clear();

            let active_during_drag = state.window_drag_active;

            let mut out4 = ctx.run_ui(
                base_input(
                    vec![egui::Event::PointerButton {
                        pos: start_pos + drag_delta,
                        button: egui::PointerButton::Primary,
                        pressed: false,
                        modifiers: egui::Modifiers::NONE,
                    }],
                    0.06,
                ),
                |ui| {
                    super::render_root(ui, &mut state, &store);
                },
            );
            out4.textures_delta.clear();

            let no_modal_start_drag = !out2
                .viewport_output
                .get(&egui::ViewportId::ROOT)
                .is_some_and(|v| v.commands.contains(&egui::ViewportCommand::StartDrag))
                && !out3
                    .viewport_output
                    .get(&egui::ViewportId::ROOT)
                    .is_some_and(|v| v.commands.contains(&egui::ViewportCommand::StartDrag));

            assert!(
                !state.window_drag_active,
                "window_drag_active must clear when primary button releases"
            );
            assert!(
                no_modal_start_drag,
                "direct Win32 drag must not emit modal ViewportCommand::StartDrag"
            );

            (state.user_has_custom_dragged, active_during_drag)
        }

        // Empty middle space between brand header and account chip
        assert_eq!(
            simulate_drag_at(egui::Pos2::new(165.0, 32.0), egui::Vec2::new(8.0, 4.0)),
            (true, true)
        );
        // Top margin strip above buttons (y = 4 inside 12px top margin)
        assert_eq!(
            simulate_drag_at(egui::Pos2::new(310.0, 4.0), egui::Vec2::new(6.0, 2.0)),
            (true, true)
        );
        // Brand logo/text area on the left
        assert_eq!(
            simulate_drag_at(egui::Pos2::new(60.0, 32.0), egui::Vec2::new(6.0, 4.0)),
            (true, true)
        );
        // Over the close button (right edge: 390 - 14 margin - 15 center = 361, y = 33) -> must NOT drag
        assert_eq!(
            simulate_drag_at(egui::Pos2::new(361.0, 33.0), egui::Vec2::new(6.0, 2.0)),
            (false, false)
        );
    }

    #[test]
    fn test_configured_fonts_apply_crisp_hinting_and_keep_color_emojis() {
        let fonts_dir =
            super::resolve_windows_fonts_dir(std::env::var_os("WINDIR"), std::env::var_os("SystemRoot"));
        let mut fonts = egui::FontDefinitions::default();
        super::apply_windows_fonts_to_definitions(&mut fonts, &fonts_dir);

        if fonts_dir.join("segoeui.ttf").exists() {
            let segoe = fonts.font_data.get("segoe_ui").expect("segoe_ui font loaded");
            assert_eq!(segoe.tweak.hinting, Some(true));
            assert_eq!(segoe.tweak.subpixel_binning, Some(false));
            assert_eq!(
                segoe.tweak.hinting_target,
                super::HintingTarget::Smooth(super::SmoothHinting {
                    light: false,
                    symmetric_rendering: false,
                    preserve_linear_metrics: false,
                })
            );
        }
        if fonts_dir.join("seguiemj.ttf").exists() {
            assert!(
                fonts.font_data.contains_key("segoe_ui_emoji"),
                "seguiemj.ttf must remain enabled when present so UI emojis stay in full color"
            );
        }

        let ctx = egui::Context::default();
        super::configure_fonts_and_style(&ctx);
        let mut missing = Vec::new();
        let mut out = ctx.run_ui(egui::RawInput::default(), |ui| {
            let font_id = egui::FontId::proportional(13.0);
            missing = ui.fonts_mut(|f| {
                ['●', '▸', '✓', '✕', '↻', '⚙', '⚠', '⚡', 'Đ', 'ệ', 'ư', '🚀', '🛡', '🛠', '🔄', '❌', '📊', '🔤']
                    .into_iter()
                    .filter(|&ch| !f.has_glyph(&font_id, ch))
                    .collect()
            });
        });
        out.textures_delta.clear();
        assert!(
            missing.is_empty(),
            "missing UI glyphs in configured font stack: {missing:?}"
        );
        let text_opts = ctx.global_style().visuals.text_options;
        assert!(text_opts.font_hinting, "font hinting must stay enabled for crisp text");
        assert!(
            !text_opts.subpixel_binning,
            "subpixel_binning must be disabled to prevent blurry text"
        );
    }

    #[test]
    fn test_color_emoji_renders_chromatic_pixels_in_font_atlas() {
        let fonts_dir = super::resolve_windows_fonts_dir(
            std::env::var_os("WINDIR"),
            std::env::var_os("SystemRoot"),
        );
        if !fonts_dir.join("seguiemj.ttf").exists() {
            return;
        }

        let ctx = egui::Context::default();
        super::configure_fonts_and_style(&ctx);

        // Warm up the atlas with plain monochrome ASCII first so any newly uploaded
        // delta on the next frame comes from laying out the emoji glyphs.
        let mut warmup = ctx.run_ui(egui::RawInput::default(), |ui| {
            ui.label("ASCII warmup");
        });
        warmup.textures_delta.clear();

        let mut emoji_out = ctx.run_ui(egui::RawInput::default(), |ui| {
            ui.label("🚀 ⚡ 📊");
        });

        let mut chromatic_pixel_count = 0usize;
        for (id, deltas) in &emoji_out.textures_delta.set {
            if *id != egui::TextureId::Managed(0) {
                continue;
            }
            for delta in deltas {
                let egui::ImageData::Color(image) = &delta.image;
                chromatic_pixel_count += image
                    .pixels
                    .iter()
                    .filter(|px| px.a() > 0 && (px.r() != px.g() || px.g() != px.b()))
                    .count();
            }
        }
        emoji_out.textures_delta.clear();

        assert!(
            chromatic_pixel_count > 10,
            "expected color emoji rasterization in font atlas (epaint color_fonts), found only {chromatic_pixel_count} chromatic pixels"
        );
    }

    #[test]
    fn test_modal_ease_is_monotonic_and_does_not_stall_on_exit() {
        let samples = [0.0_f32, 0.2, 0.5, 0.8, 1.0];
        for entering in [true, false] {
            let vals: Vec<f32> = samples.iter().map(|&t| super::modal_ease(t, entering)).collect();
            assert!((vals[0] - 0.0).abs() < 1e-6);
            assert!((vals[4] - 1.0).abs() < 1e-6);
            for w in vals.windows(2) {
                assert!(w[1] > w[0], "modal_ease(entering={entering}) must be monotonic: {vals:?}");
            }
        }
        assert!(super::modal_ease(0.5, true) > 0.8);
        assert!(
            super::modal_ease(0.5, false) < 0.35,
            "exit easing at t=0.5 must drop decisively instead of stalling near 1.0"
        );
    }

    #[test]
    fn test_toast_dismiss_collapses_height_smoothly_and_requests_repaint_immediately() {
        use crate::state::{AppState, NoticeLevel, StatusNotice};
        use freeton_core::storage::{ClientConfig, CredentialStore, StorageError};
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

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

        fn find_text_rect_below(
            shapes: &[egui::epaint::ClippedShape],
            needle: &str,
            min_y: f32,
        ) -> Option<egui::Rect> {
            fn visit(s: &egui::epaint::Shape, needle: &str, min_y: f32) -> Option<egui::Rect> {
                match s {
                    egui::epaint::Shape::Text(t) if t.galley.text().contains(needle) => {
                        let r = t.galley.rect.translate(t.pos.to_vec2());
                        (r.min.y >= min_y).then_some(r)
                    }
                    egui::epaint::Shape::Vec(v) => {
                        v.iter().find_map(|item| visit(item, needle, min_y))
                    }
                    _ => None,
                }
            }
            shapes.iter().find_map(|c| visit(&c.shape, needle, min_y))
        }

        let ctx = egui::Context::default();
        let delays = Arc::new(Mutex::new(Vec::new()));
        ctx.set_repaint_observer({
            let delays = Arc::clone(&delays);
            move |info| delays.lock().unwrap().push(info.delay)
        });

        let store = NoopStore;
        let mut state = AppState::new(
            true,
            Some("user@proton.me".to_owned()),
            ClientConfig::default(),
            None,
            Vec::new(),
        );
        state.loading.visible = false;
        state.window_visible = true;
        state.info_toast = Some(StatusNotice {
            text: "Đang dùng bản mới nhất v3.0.3".to_owned(),
            level: NoticeLevel::Info,
        });

        let make_input = |time: f64, events: Vec<egui::Event>| egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::Vec2::new(super::WINDOW_WIDTH, super::WINDOW_HEIGHT),
            )),
            time: Some(time),
            events,
            ..Default::default()
        };

        for t in [0.0_f64, 0.5_f64] {
            let mut out = ctx.run_ui(make_input(t, vec![]), |ui| {
                super::render_root(ui, &mut state, &store);
            });
            out.textures_delta.clear();
        }

        let mut open_out = ctx.run_ui(make_input(0.55, vec![]), |ui| {
            super::render_root(ui, &mut state, &store);
        });
        open_out.textures_delta.clear();
        let full_status_y = find_text_rect_below(&open_out.shapes, "KẾT NỐI CỦA BẠN", 0.0)
            .expect("status heading open")
            .min
            .y;
        let close_pos = find_text_rect_below(&open_out.shapes, "✕", 50.0)
            .expect("toast close X button")
            .center();

        // Click toast close '✕': state becomes None immediately AND repaint(0) is requested on same frame
        let _ = ctx.run_ui(
            make_input(
                0.60,
                vec![
                    egui::Event::PointerMoved(close_pos),
                    egui::Event::PointerButton {
                        pos: close_pos,
                        button: egui::PointerButton::Primary,
                        pressed: true,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
            ),
            |ui| {
                super::render_root(ui, &mut state, &store);
            },
        );
        let _ = ctx.run_ui(
            make_input(
                0.62,
                vec![egui::Event::PointerButton {
                    pos: close_pos,
                    button: egui::PointerButton::Primary,
                    pressed: false,
                    modifiers: egui::Modifiers::NONE,
                }],
            ),
            |ui| {
                delays.lock().unwrap().clear();
                super::render_root(ui, &mut state, &store);
            },
        );
        assert!(state.info_toast.is_none(), "toast should dismiss on click");
        assert!(
            delays.lock().unwrap().contains(&Duration::ZERO),
            "clicking toast close must request immediate repaint on click frame: {:?}",
            *delays.lock().unwrap()
        );

        let mut mid_out = ctx.run_ui(make_input(0.69, vec![]), |ui| {
            super::render_root(ui, &mut state, &store);
        });
        mid_out.textures_delta.clear();
        let mid_status_y = find_text_rect_below(&mid_out.shapes, "KẾT NỐI CỦA BẠN", 0.0)
            .expect("status heading mid exit")
            .min
            .y;

        let mut done_out = ctx.run_ui(make_input(1.10, vec![]), |ui| {
            super::render_root(ui, &mut state, &store);
        });
        done_out.textures_delta.clear();
        let done_status_y = find_text_rect_below(&done_out.shapes, "KẾT NỐI CỦA BẠN", 0.0)
            .expect("status heading post exit")
            .min
            .y;

        assert!(
            done_status_y < mid_status_y - 2.0 && mid_status_y < full_status_y - 2.0,
            "toast height must collapse smoothly during exit: full={full_status_y}, mid={mid_status_y}, done={done_status_y}"
        );
    }

    #[test]
    fn test_dialog_close_click_requests_immediate_repaint_without_disabled_dim_snap() {
        use crate::state::{ActiveDialog, AppState};
        use freeton_core::storage::{ClientConfig, CredentialStore, StorageError};
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

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

        fn find_close_btn(shapes: &[egui::epaint::ClippedShape]) -> Option<egui::Pos2> {
            fn visit(s: &egui::epaint::Shape) -> Option<egui::Pos2> {
                match s {
                    egui::epaint::Shape::Text(t) if t.galley.text() == "Đóng" => {
                        Some(t.galley.rect.translate(t.pos.to_vec2()).center())
                    }
                    egui::epaint::Shape::Vec(v) => v.iter().find_map(visit),
                    _ => None,
                }
            }
            shapes.iter().find_map(|c| visit(&c.shape))
        }

        let ctx = egui::Context::default();
        let delays = Arc::new(Mutex::new(Vec::new()));
        ctx.set_repaint_observer({
            let delays = Arc::clone(&delays);
            move |info| delays.lock().unwrap().push(info.delay)
        });

        let store = NoopStore;
        let mut state = AppState::new(
            true,
            Some("user@proton.me".to_owned()),
            ClientConfig::default(),
            None,
            Vec::new(),
        );
        state.window_visible = true;
        state.open_about_dialog();

        let make_input = |time: f64, events: Vec<egui::Event>| egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::Vec2::new(super::WINDOW_WIDTH, super::WINDOW_HEIGHT),
            )),
            time: Some(time),
            events,
            ..Default::default()
        };

        for t in [0.0_f64, 0.5_f64] {
            let mut out = ctx.run_ui(make_input(t, vec![]), |ui| {
                super::render_root(ui, &mut state, &store);
            });
            out.textures_delta.clear();
        }
        let open_out = ctx.run_ui(make_input(0.55, vec![]), |ui| {
            super::render_root(ui, &mut state, &store);
        });
        let close_btn = find_close_btn(&open_out.shapes).expect("About Đóng button");

        let _ = ctx.run_ui(
            make_input(
                0.60,
                vec![
                    egui::Event::PointerMoved(close_btn),
                    egui::Event::PointerButton {
                        pos: close_btn,
                        button: egui::PointerButton::Primary,
                        pressed: true,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
            ),
            |ui| {
                super::render_root(ui, &mut state, &store);
            },
        );
        let _ = ctx.run_ui(
            make_input(
                0.62,
                vec![egui::Event::PointerButton {
                    pos: close_btn,
                    button: egui::PointerButton::Primary,
                    pressed: false,
                    modifiers: egui::Modifiers::NONE,
                }],
            ),
            |ui| {
                delays.lock().unwrap().clear();
                super::render_root(ui, &mut state, &store);
            },
        );
        assert_eq!(state.active_dialog, ActiveDialog::None);
        assert!(
            delays.lock().unwrap().contains(&Duration::ZERO),
            "closing dialog must request immediate repaint on click frame: {:?}",
            *delays.lock().unwrap()
        );
    }
}
