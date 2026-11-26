use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use egui::{
    Align, Color32, CornerRadius, CursorIcon, Key, Layout, Margin, PointerButton, Rect, RichText,
    ScrollArea, Sense, TextEdit, TextStyle, Ui, Vec2,
};
use freeton_core::storage::{ClientConfig, CredentialStore, DEFAULT_WG_ADDRESS};
use freeton_core::wg::{validate_address_list, validate_dns_list, validate_wg_key};
use freeton_core::{APP_NAME, APP_VERSION};
use windows::Win32::Foundation::{FILETIME, SYSTEMTIME};
use windows::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};

use crate::state::{
    ActiveDialog, AppState, NoticeLevel, ServiceHealthStatus, ServiceRepairPhase, SettingsDraft,
    StatusNotice, UpdateDialogPhase,
};
use crate::ui::home::ios_toggle_switch;
use crate::ui::{
    pill_button, rounded_card, PillStyle, C_ACCENT, C_BG, C_BORDER, C_CARD, C_CARD_HIGH, C_DANGER,
    C_SUCCESS, C_SURFACE, C_TEXT, C_TEXT_DIM, C_TEXT_MUTED, C_WARNING,
};

pub const DEV_MODE_HOLD_DURATION: Duration = Duration::from_millis(750);

const UNIX_EPOCH_IN_WINDOWS_TICKS: u64 = 116_444_736_000_000_000;
const WINDOWS_TICKS_PER_SECOND: u64 = 10_000_000;

#[derive(Debug, Clone, Default)]
pub struct MiddleHoldTracker {
    pressed_at: Option<Instant>,
    triggered: bool,
}

impl MiddleHoldTracker {
    pub fn on_press(&mut self, now: Instant) {
        self.pressed_at = Some(now);
        self.triggered = false;
    }

    pub fn on_release(&mut self) {
        self.pressed_at = None;
        self.triggered = false;
    }

    pub fn poll(&mut self, now: Instant) -> bool {
        let Some(started) = self.pressed_at else {
            return false;
        };
        if self.triggered {
            return false;
        }
        if now.saturating_duration_since(started) >= DEV_MODE_HOLD_DURATION {
            self.triggered = true;
            return true;
        }
        false
    }

    pub fn is_holding(&self) -> bool {
        self.pressed_at.is_some() && !self.triggered
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedWireGuardConf {
    pub private_key: String,
    pub address: Option<String>,
    pub dns: Option<String>,
}

/// Parses `[Interface]` `PrivateKey`, `Address`, and `DNS` fields from a WireGuard `.conf` file.
pub fn parse_wireguard_conf(content: &str) -> Result<ParsedWireGuardConf, String> {
    if content.contains('\0') {
        return Err("File cấu hình chứa ký tự null không hợp lệ.".to_owned());
    }

    let stripped = content.strip_prefix('\u{FEFF}').unwrap_or(content);
    let mut seen_interface = false;
    let mut in_interface = false;
    let mut private_key: Option<String> = None;
    let mut address: Option<String> = None;
    let mut dns: Option<String> = None;

    for raw_line in stripped.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let section = line[1..line.len() - 1].trim();
            in_interface = section.eq_ignore_ascii_case("Interface");
            if in_interface {
                seen_interface = true;
            }
            continue;
        }
        if !in_interface {
            continue;
        }
        let Some((key_raw, val_raw)) = line.split_once('=') else {
            continue;
        };
        let key = key_raw.trim();
        let val = val_raw.trim();
        if val.chars().any(char::is_control) {
            return Err(format!(
                "Trường '{key}' trong file .conf chứa ký tự điều khiển không hợp lệ."
            ));
        }

        if key.eq_ignore_ascii_case("PrivateKey") {
            let validated = validate_wg_key("PrivateKey", val).map_err(|e| e.to_string())?;
            private_key = Some(validated);
        } else if key.eq_ignore_ascii_case("Address") {
            let validated = validate_address_list(val).map_err(|e| e.to_string())?;
            address = Some(validated);
        } else if key.eq_ignore_ascii_case("DNS") {
            let validated = validate_dns_list(val).map_err(|e| e.to_string())?;
            dns = Some(validated);
        }
    }

    if !seen_interface {
        return Err("File .conf thiếu mục [Interface] hợp lệ.".to_owned());
    }

    let Some(private_key) = private_key else {
        return Err("Không tìm thấy trường PrivateKey hợp lệ trong mục [Interface].".to_owned());
    };

    Ok(ParsedWireGuardConf {
        private_key,
        address,
        dns,
    })
}

/// Applies imported `.conf` parameters onto `ClientConfig` and marks the key as static (`expiration = 0`).
pub fn apply_imported_conf(config: &mut ClientConfig, parsed: &ParsedWireGuardConf) {
    config.private_key = parsed.private_key.clone();
    config.public_key.clear();
    if let Some(addr) = &parsed.address {
        config.address = addr.clone();
    }
    if let Some(dns) = &parsed.dns {
        config.dns = dns.clone();
    }
    config.expiration = 0;
}

/// Validates that an external browser URL uses strict `https://` with a non-empty host.
pub fn validate_https_browser_url(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
        return Err("URL trình duyệt không hợp lệ.".to_owned());
    }
    let parsed = url::Url::parse(trimmed).map_err(|err| format!("URL không hợp lệ: {err}"))?;
    if !parsed.scheme().eq_ignore_ascii_case("https") {
        return Err(format!(
            "Chỉ cho phép mở URL HTTPS an toàn trong trình duyệt (từ chối giao thức '{}').",
            parsed.scheme()
        ));
    }
    if parsed.host_str().is_none_or(|h| h.trim().is_empty()) {
        return Err("URL HTTPS thiếu tên miền hợp lệ.".to_owned());
    }
    Ok(parsed.to_string())
}

/// Resolves `FreetonVPNService.exe` in the same directory as `FreetonVPN.exe`.
pub fn sibling_service_exe_path(app_exe: &Path) -> Option<PathBuf> {
    let parent = app_exe.parent()?;
    if parent.as_os_str().is_empty() {
        return None;
    }
    Some(parent.join("FreetonVPNService.exe"))
}

pub fn format_unix_timestamp_local(unix_secs: i64) -> String {
    if unix_secs <= 0 {
        return "Vĩnh viễn / Tĩnh".to_owned();
    }
    let Some(ticks) = u64::try_from(unix_secs)
        .ok()
        .and_then(|s| s.checked_mul(WINDOWS_TICKS_PER_SECOND))
        .and_then(|t| t.checked_add(UNIX_EPOCH_IN_WINDOWS_TICKS))
    else {
        return "Không xác định".to_owned();
    };
    let ft = FILETIME {
        dwLowDateTime: (ticks & 0xFFFF_FFFF) as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    };
    let mut utc_st = SYSTEMTIME::default();
    let mut local_st = SYSTEMTIME::default();
    unsafe {
        if FileTimeToSystemTime(&ft, &mut utc_st).is_err() {
            return format!("{unix_secs}");
        }
        if SystemTimeToTzSpecificLocalTime(None, &utc_st, &mut local_st).is_err() {
            local_st = utc_st;
        }
    }
    format!(
        "{:02}/{:02}/{:04} {:02}:{:02}",
        local_st.wDay, local_st.wMonth, local_st.wYear, local_st.wHour, local_st.wMinute
    )
}

pub fn format_byte_size(bytes: u64) -> String {
    if bytes == 0 {
        return String::new();
    }
    if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.0} KB", (bytes as f64 / 1024.0).max(1.0))
    }
}

fn format_key_status_line(draft: &SettingsDraft) -> (String, Color32) {
    if draft.expiration > 0 {
        let formatted = format_unix_timestamp_local(draft.expiration);
        (
            format!("● Trạng thái Key: {formatted} (Tự làm mới)"),
            C_SUCCESS,
        )
    } else if draft.imported_from_conf {
        (
            "● Trạng thái Key: Đã nạp từ .conf (Key tĩnh)".to_owned(),
            C_SUCCESS,
        )
    } else if !draft.private_key.trim().is_empty() {
        (
            "● Trạng thái Key: Vĩnh viễn / Tĩnh (Key tĩnh)".to_owned(),
            C_SUCCESS,
        )
    } else {
        (
            "● Trạng thái Key: Chưa có Key (tự cấp khi kết nối)".to_owned(),
            C_WARNING,
        )
    }
}

pub fn render_dialog_overlay(
    ctx: &egui::Context,
    state: &mut AppState,
    store: &dyn CredentialStore,
) {
    if ctx.input(|i| i.key_pressed(Key::Escape)) {
        state.close_dialog();
        if state.active_dialog == ActiveDialog::None {
            return;
        }
    }

    let screen_rect = ctx.content_rect();
    egui::Area::new(egui::Id::unique("dialog_backdrop"))
        .order(egui::Order::Middle)
        .fixed_pos(screen_rect.min)
        .show(ctx, |ui| {
            let _ = ui.allocate_response(screen_rect.size(), Sense::click());
            ui.painter()
                .rect_filled(screen_rect, 0.0, Color32::from_black_alpha(185));
        });

    let card_resp = egui::Area::new(egui::Id::unique("dialog_card"))
        .order(egui::Order::Foreground)
        .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
        .show(ctx, |ui| {
            ui.set_max_width(356.0);
            ui.set_max_height(574.0);
            rounded_card(ui, C_CARD, C_BORDER, 14, Margin::same(14), |ui| {
                ui.set_width(326.0);
                match state.active_dialog {
                    ActiveDialog::None => {}
                    ActiveDialog::LogoutConfirm => render_logout_confirm_dialog(ui, state, store),
                    ActiveDialog::About => render_about_dialog(ui, state),
                    ActiveDialog::Settings => render_settings_dialog(ctx, ui, state),
                    ActiveDialog::Update => render_update_dialog(ctx, ui, state),
                    ActiveDialog::ServiceRepair => render_service_repair_dialog(ctx, ui, state),
                    ActiveDialog::ErrorDetail => render_error_detail_dialog(ui, state),
                }
            })
        });

    if state.active_dialog == ActiveDialog::Settings {
        handle_settings_middle_mouse_hold(ctx, state, card_resp.response.rect);
    }
}

fn handle_settings_middle_mouse_hold(ctx: &egui::Context, state: &mut AppState, card_rect: Rect) {
    let (pressed, down, released, pos) = ctx.input(|i| {
        (
            i.pointer.button_pressed(PointerButton::Middle),
            i.pointer.button_down(PointerButton::Middle),
            i.pointer.button_released(PointerButton::Middle),
            i.pointer.interact_pos(),
        )
    });
    let now = Instant::now();
    if pressed && pos.is_some_and(|p| card_rect.contains(p)) {
        state.settings_middle_hold.on_press(now);
    }
    if released || !down {
        state.settings_middle_hold.on_release();
    } else if state.settings_middle_hold.poll(now) {
        state.toggle_dev_mode();
    }
    if state.settings_middle_hold.is_holding() {
        ctx.request_repaint_after(Duration::from_millis(40));
    }
}

fn render_logout_confirm_dialog(ui: &mut Ui, state: &mut AppState, store: &dyn CredentialStore) {
    ui.label(RichText::new("Tài khoản").size(15.0).strong().color(C_TEXT));
    ui.add_space(8.0);
    ui.label(
        RichText::new("Đang lưu phiên đăng nhập.\n\nBạn có muốn đăng xuất để đổi tài khoản không?")
            .size(12.0)
            .color(C_TEXT_MUTED),
    );
    ui.add_space(14.0);
    ui.horizontal(|ui| {
        if pill_button(ui, "Hủy", Some(110.0), PillStyle::secondary(32.0)).clicked() {
            state.close_dialog();
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let danger_style = PillStyle {
                bg: C_DANGER,
                fg: Color32::BLACK,
                border: C_DANGER,
                hover_bg: Color32::from_rgb(0xf4, 0xb8, 0xb8),
                hover_fg: Color32::BLACK,
                hover_border: C_DANGER,
                ..PillStyle::accent(32.0)
            };
            if pill_button(ui, "Đăng xuất", Some(120.0), danger_style).clicked() {
                state.request_logout(store);
            }
        });
    });
}

fn render_about_dialog(ui: &mut Ui, state: &mut AppState) {
    ui.vertical_centered(|ui| {
        ui.label(RichText::new("⚡").size(28.0).color(C_ACCENT));
        ui.label(RichText::new(APP_NAME).size(17.0).strong().color(C_TEXT));
        ui.label(
            RichText::new(format!("by pishun • v{APP_VERSION}"))
                .size(11.5)
                .italics()
                .color(C_ACCENT),
        );
    });
    ui.add_space(8.0);
    ui.label(
        RichText::new(
            "Phần mềm kết nối WireGuard tốc độ cao, siêu nhẹ cho các cụm máy chủ Proton VPN Free với thuật toán tự động chọn node tối ưu.",
        )
        .size(11.5)
        .color(C_TEXT_MUTED),
    );
    ui.add_space(10.0);
    rounded_card(ui, C_CARD_HIGH, C_BORDER, 10, Margin::same(10), |ui| {
        ui.set_width(ui.available_width());
        ui.label(
            RichText::new("TUYÊN BỐ PHÁP LÝ (LEGAL DISCLAIMER)")
                .size(10.0)
                .strong()
                .color(C_TEXT_DIM),
        );
        ui.add_space(4.0);
        ui.label(
            RichText::new(
                "Freeton VPN là một dự án mã nguồn mở độc lập và KHÔNG thuộc sở hữu, KHÔNG liên kết, cũng như KHÔNG được ủy quyền hay tài trợ bởi Proton AG hoặc Proton VPN. Tất cả tên nhãn hiệu, logo và thương hiệu đều thuộc bản quyền của chủ sở hữu tương ứng.",
            )
            .size(10.5)
            .color(C_TEXT_MUTED),
        );
    });

    if state.update_check_pending {
        ui.add_space(8.0);
        ui.label(
            RichText::new("● Đang kiểm tra phiên bản mới...")
                .size(11.0)
                .color(C_ACCENT),
        );
    } else if let Some(msg) = &state.update_check_message {
        ui.add_space(8.0);
        rounded_card(ui, C_SURFACE, C_BORDER, 8, Margin::same(8), |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(msg).size(11.0).color(C_TEXT_MUTED));
        });
    }

    ui.add_space(12.0);
    ui.horizontal(|ui| {
        let chk_label = if state.update_check_pending {
            "Đang kiểm tra..."
        } else {
            "🔄 Kiểm tra bản mới"
        };
        if pill_button(ui, chk_label, Some(152.0), PillStyle::secondary(32.0)).clicked()
            && !state.update_check_pending
        {
            state.check_for_updates(true);
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if pill_button(ui, "Đóng", Some(104.0), PillStyle::accent(32.0)).clicked() {
                state.close_dialog();
            }
        });
    });
}

fn render_settings_dialog(ctx: &egui::Context, ui: &mut Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.label(
            RichText::new("⚙️ Cài Đặt Hệ Thống")
                .size(15.0)
                .strong()
                .color(C_TEXT),
        );
        if state.client_config.debug_mode {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let badge_style = PillStyle {
                    radius: 6,
                    font_size: 10.0,
                    pad_x: 8.0,
                    ..PillStyle::accent(22.0)
                };
                if pill_button(ui, "🛠️ DEV MODE", Some(88.0), badge_style)
                    .on_hover_text("Nhấn hoặc giữ chuột giữa 750ms để tắt Dev Mode")
                    .clicked()
                {
                    state.toggle_dev_mode();
                }
            });
        }
    });

    if let Some(notice) = state.settings_status_msg.clone() {
        ui.add_space(6.0);
        let color = match notice.level {
            NoticeLevel::Success => C_SUCCESS,
            NoticeLevel::Warning => C_WARNING,
            NoticeLevel::Error => C_DANGER,
            NoticeLevel::Info => C_ACCENT,
        };
        rounded_card(ui, C_SURFACE, color, 8, Margin::symmetric(8, 6), |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(&notice.text).size(10.5).color(color));
        });
    }

    ui.add_space(8.0);
    let anim = state.client_config.animations_enabled;

    ScrollArea::vertical()
        .id_salt("settings_dialog_scroll")
        .max_height(390.0)
        .auto_shrink([false, true])
        .show(ui, |ui| {
            // Section 1: App Settings
            rounded_card(ui, C_SURFACE, C_BORDER, 10, Margin::same(10), |ui| {
                ui.set_width(ui.available_width());
                ui.label(
                    RichText::new("⚙️ CÀI ĐẶT ỨNG DỤNG")
                        .size(10.0)
                        .strong()
                        .color(C_ACCENT),
                );
                ui.add_space(6.0);

                ui.horizontal(|ui| {
                    let lbl = ui
                        .label(
                            RichText::new("Khởi động cùng Windows (Startup)")
                                .size(11.5)
                                .color(C_TEXT),
                        )
                        .interact(Sense::click())
                        .on_hover_cursor(CursorIcon::PointingHand);
                    let mut toggled = lbl.clicked();
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ios_toggle_switch(
                            ui,
                            state.settings_draft.startup_enabled,
                            false,
                            anim,
                            Vec2::new(40.0, 22.0),
                        )
                        .clicked()
                        {
                            toggled = true;
                        }
                    });
                    if toggled {
                        state.settings_draft.startup_enabled =
                            !state.settings_draft.startup_enabled;
                        state.settings_draft.startup_dirty = true;
                    }
                });
                ui.add_space(4.0);

                ui.horizontal(|ui| {
                    let lbl = ui
                        .label(
                            RichText::new("Hiệu ứng chuyển động (Animations)")
                                .size(11.5)
                                .color(C_TEXT),
                        )
                        .interact(Sense::click())
                        .on_hover_cursor(CursorIcon::PointingHand);
                    let mut toggled = lbl.clicked();
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ios_toggle_switch(
                            ui,
                            state.settings_draft.animations_enabled,
                            false,
                            anim,
                            Vec2::new(40.0, 22.0),
                        )
                        .clicked()
                        {
                            toggled = true;
                        }
                    });
                    if toggled {
                        state.settings_draft.animations_enabled =
                            !state.settings_draft.animations_enabled;
                    }
                });
                ui.add_space(4.0);

                ui.horizontal(|ui| {
                    let lbl = ui
                        .label(
                            RichText::new("Tự động kiểm tra bản cập nhật")
                                .size(11.5)
                                .color(C_TEXT),
                        )
                        .interact(Sense::click())
                        .on_hover_cursor(CursorIcon::PointingHand);
                    let mut toggled = lbl.clicked();
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ios_toggle_switch(
                            ui,
                            state.settings_draft.auto_check_update,
                            false,
                            anim,
                            Vec2::new(40.0, 22.0),
                        )
                        .clicked()
                        {
                            toggled = true;
                        }
                    });
                    if toggled {
                        state.settings_draft.auto_check_update =
                            !state.settings_draft.auto_check_update;
                    }
                });
                ui.add_space(8.0);

                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;
                    let half_w = ((ui.available_width() - 6.0) * 0.5).max(100.0);
                    let upd_lbl = if state.update_check_pending {
                        "Đang kiểm tra..."
                    } else {
                        "🔄 Kiểm tra bản mới"
                    };
                    let btn_style = PillStyle {
                        font_size: 11.0,
                        pad_x: 6.0,
                        ..PillStyle::secondary(28.0)
                    };
                    if pill_button(ui, upd_lbl, Some(half_w), btn_style).clicked()
                        && !state.update_check_pending
                    {
                        state.check_for_updates(true);
                    }
                    let svc_btn_style = PillStyle {
                        fg: C_ACCENT,
                        font_size: 11.0,
                        pad_x: 6.0,
                        ..PillStyle::secondary(28.0)
                    };
                    if pill_button(ui, "🛠️ Sửa dịch vụ VPN", Some(half_w), svc_btn_style).clicked()
                    {
                        state.open_service_repair_dialog();
                    }
                });

                if let Some(msg) = &state.update_check_message {
                    ui.add_space(6.0);
                    ui.label(RichText::new(msg).size(10.5).color(C_TEXT_MUTED));
                }
            });

            ui.add_space(8.0);

            // Section 2: Service Health & Repair
            rounded_card(ui, C_SURFACE, C_BORDER, 10, Margin::same(10), |ui| {
                ui.set_width(ui.available_width());
                ui.label(
                    RichText::new("🔧 DỊCH VỤ NỀN WIREGUARD")
                        .size(10.0)
                        .strong()
                        .color(C_ACCENT),
                );
                ui.add_space(4.0);

                let (svc_label, svc_color) = match &state.service_health {
                    ServiceHealthStatus::Healthy => {
                        ("● FreetonVPNService: Đang hoạt động", C_SUCCESS)
                    }
                    ServiceHealthStatus::Unavailable(_) => {
                        ("⚠ FreetonVPNService: Chưa sẵn sàng", C_WARNING)
                    }
                    ServiceHealthStatus::Unknown => {
                        ("○ FreetonVPNService: Đang kiểm tra...", C_TEXT_MUTED)
                    }
                };
                ui.label(
                    RichText::new(svc_label)
                        .size(11.5)
                        .strong()
                        .color(svc_color),
                );

                if state.service_repair_phase == ServiceRepairPhase::LaunchingAndWaiting {
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("⏳ Đang chạy FreetonVPNService.exe --install (UAC)...")
                            .size(10.5)
                            .color(C_ACCENT),
                    );
                    ctx.request_repaint_after(Duration::from_millis(200));
                } else if let ServiceRepairPhase::Failed(err) = &state.service_repair_phase {
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(format!("❌ {err}"))
                            .size(10.5)
                            .color(C_DANGER),
                    );
                }

                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    let is_unavailable =
                        matches!(state.service_health, ServiceHealthStatus::Unavailable(_));
                    let repairing =
                        state.service_repair_phase == ServiceRepairPhase::LaunchingAndWaiting;
                    let repair_w = if is_unavailable { 172.0 } else { 150.0 };
                    let repair_style = if is_unavailable {
                        PillStyle {
                            font_size: 11.0,
                            radius: 8,
                            pad_x: 8.0,
                            ..PillStyle::accent(28.0)
                        }
                    } else {
                        PillStyle {
                            font_size: 11.0,
                            pad_x: 8.0,
                            ..PillStyle::secondary(28.0)
                        }
                    };
                    let repair_lbl = if repairing {
                        "Đang cài đặt..."
                    } else {
                        "🔧 Sửa dịch vụ (UAC)"
                    };
                    if pill_button(ui, repair_lbl, Some(repair_w), repair_style).clicked()
                        && !repairing
                    {
                        state.start_service_repair();
                    }

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let recheck_style = PillStyle {
                            font_size: 11.0,
                            pad_x: 8.0,
                            ..PillStyle::secondary(28.0)
                        };
                        if pill_button(ui, "↻ Kiểm tra", Some(96.0), recheck_style).clicked() {
                            state.request_status_refresh();
                        }
                    });
                });
            });

            ui.add_space(8.0);

            // Section 3: WireGuard & Network
            rounded_card(ui, C_SURFACE, C_BORDER, 10, Margin::same(10), |ui| {
                ui.set_width(ui.available_width());
                ui.label(
                    RichText::new("🛡️ CÀI ĐẶT WIREGUARD & MẠNG")
                        .size(10.0)
                        .strong()
                        .color(C_ACCENT),
                );
                ui.add_space(4.0);

                let (exp_text, exp_color) = format_key_status_line(&state.settings_draft);
                ui.label(RichText::new(exp_text).size(11.0).strong().color(exp_color));

                if state.settings_draft.address.trim() != DEFAULT_WG_ADDRESS
                    && !state.settings_draft.address.trim().is_empty()
                {
                    ui.label(
                        RichText::new(format!("Interface IP: {}", state.settings_draft.address))
                            .size(10.0)
                            .color(C_TEXT_DIM),
                    );
                }

                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;
                    let half_w = ((ui.available_width() - 6.0) * 0.5).max(100.0);
                    let key_lbl = if state.settings_key_fetching {
                        "Đang cấp Key..."
                    } else {
                        "⚡ Cấp Key mới (API)"
                    };
                    let key_style = PillStyle {
                        fg: C_ACCENT,
                        font_size: 11.0,
                        pad_x: 6.0,
                        ..PillStyle::secondary(28.0)
                    };
                    if pill_button(ui, key_lbl, Some(half_w), key_style).clicked() {
                        state.fetch_wg_key_from_settings();
                    }

                    let import_lbl = if state.settings_conf_importing {
                        "Đang mở file..."
                    } else {
                        "📂 Nhập file .conf"
                    };
                    let import_style = PillStyle {
                        font_size: 11.0,
                        pad_x: 6.0,
                        ..PillStyle::secondary(28.0)
                    };
                    if pill_button(ui, import_lbl, Some(half_w), import_style).clicked() {
                        state.pick_and_import_conf();
                    }
                });

                ui.add_space(8.0);
                ui.label(
                    RichText::new("WIREGUARD PRIVATE KEY")
                        .size(9.5)
                        .strong()
                        .color(C_TEXT_MUTED),
                );
                ui.add_space(2.0);
                rounded_card(ui, C_BG, C_BORDER, 8, Margin::symmetric(8, 5), |ui| {
                    let priv_w = ui.available_width().max(80.0);
                    ui.add_sized(
                        Vec2::new(priv_w, 20.0),
                        TextEdit::singleline(&mut state.settings_draft.private_key)
                            .frame(egui::Frame::NONE)
                            .font(TextStyle::Monospace)
                            .desired_width(priv_w)
                            .hint_text("Base64 PrivateKey")
                            .text_color(C_TEXT),
                    );
                });

                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 8.0;
                    let col_w = ((ui.available_width() - 8.0) * 0.5).max(100.0);
                    ui.vertical(|ui| {
                        ui.set_width(col_w);
                        ui.label(
                            RichText::new("DNS SERVER")
                                .size(9.5)
                                .strong()
                                .color(C_TEXT_MUTED),
                        );
                        ui.add_space(2.0);
                        rounded_card(ui, C_BG, C_BORDER, 8, Margin::symmetric(8, 5), |ui| {
                            let dns_w = (col_w - 18.0).max(60.0);
                            ui.add_sized(
                                Vec2::new(dns_w, 20.0),
                                TextEdit::singleline(&mut state.settings_draft.dns)
                                    .frame(egui::Frame::NONE)
                                    .desired_width(dns_w)
                                    .text_color(C_TEXT),
                            );
                        });
                    });
                    ui.vertical(|ui| {
                        ui.set_width(col_w);
                        ui.label(
                            RichText::new("PORT WIREGUARD")
                                .size(9.5)
                                .strong()
                                .color(C_TEXT_MUTED),
                        );
                        ui.add_space(2.0);
                        rounded_card(ui, C_BG, C_BORDER, 8, Margin::symmetric(8, 5), |ui| {
                            let port_w = (col_w - 18.0).max(60.0);
                            ui.add_sized(
                                Vec2::new(port_w, 20.0),
                                TextEdit::singleline(&mut state.settings_draft.port)
                                    .frame(egui::Frame::NONE)
                                    .desired_width(port_w)
                                    .text_color(C_TEXT),
                            );
                        });
                    });
                });
            });
        });

    ui.add_space(10.0);
    ui.horizontal(|ui| {
        if pill_button(ui, "Đóng", Some(104.0), PillStyle::secondary(32.0)).clicked() {
            state.close_dialog();
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if pill_button(ui, "💾 Lưu & Áp dụng", Some(156.0), PillStyle::accent(32.0)).clicked()
            {
                state.save_settings_dialog();
            }
        });
    });
}

fn render_update_dialog(ctx: &egui::Context, ui: &mut Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("🚀").size(18.0).color(C_ACCENT));
        ui.label(
            RichText::new("Có Bản Cập Nhật Mới!")
                .size(15.0)
                .strong()
                .color(C_TEXT),
        );
    });
    ui.add_space(6.0);

    let Some(info) = state.available_update.clone() else {
        ui.label(
            RichText::new("Không có thông tin bản cập nhật.")
                .size(12.0)
                .color(C_TEXT_MUTED),
        );
        ui.add_space(10.0);
        if pill_button(ui, "Đóng", Some(100.0), PillStyle::secondary(32.0)).clicked() {
            state.close_dialog();
        }
        return;
    };

    ui.label(
        RichText::new(format!(
            "Phiên bản hiện tại: v{APP_VERSION}  ➔  Mới nhất: v{}",
            info.version
        ))
        .size(11.5)
        .strong()
        .color(C_ACCENT),
    );
    if !info.title.trim().is_empty() {
        ui.label(RichText::new(&info.title).size(12.0).strong().color(C_TEXT));
    }
    if !info.release_date.trim().is_empty() {
        ui.label(
            RichText::new(format!("Ngày phát hành: {}", info.release_date))
                .size(10.5)
                .color(C_TEXT_MUTED),
        );
    }
    if info.mandatory {
        ui.add_space(4.0);
        ui.label(
            RichText::new("⚠️ Bản cập nhật bắt buộc — Vui lòng cập nhật để tiếp tục sử dụng.")
                .size(10.5)
                .strong()
                .color(C_WARNING),
        );
    }

    ui.add_space(8.0);
    ui.label(
        RichText::new("NHỮNG ĐIỂM MỚI (CHANGELOG)")
            .size(10.0)
            .strong()
            .color(C_TEXT_DIM),
    );
    ui.add_space(3.0);
    rounded_card(ui, C_BG, C_BORDER, 8, Margin::same(8), |ui| {
        ui.set_width(ui.available_width());
        ScrollArea::vertical()
            .id_salt("update_changelog_scroll")
            .max_height(155.0)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                ui.label(
                    RichText::new(info.formatted_changelog())
                        .size(11.0)
                        .color(C_TEXT),
                );
            });
    });

    ui.add_space(10.0);

    let (status_text, status_color, progress_frac) = match &state.update_phase {
        UpdateDialogPhase::Idle => {
            let size_txt = format_byte_size(info.file_size_bytes);
            let txt = if size_txt.is_empty() {
                "Sẵn sàng tải về".to_owned()
            } else {
                format!("Sẵn sàng tải về ({size_txt})")
            };
            (txt, C_TEXT_MUTED, 0.0_f32)
        }
        UpdateDialogPhase::Downloading {
            downloaded_bytes,
            total_bytes,
            percent,
            ..
        } => {
            ctx.request_repaint_after(Duration::from_millis(80));
            let d_mb = *downloaded_bytes as f64 / (1024.0 * 1024.0);
            let txt = if *total_bytes > 0 {
                let t_mb = *total_bytes as f64 / (1024.0 * 1024.0);
                format!("Đang tải: {d_mb:.1} MB / {t_mb:.1} MB ({percent:.0}%)")
            } else {
                format!("Đang tải: {d_mb:.1} MB")
            };
            (txt, C_ACCENT, (*percent / 100.0).clamp(0.0, 1.0))
        }
        UpdateDialogPhase::Verifying => {
            ctx.request_repaint_after(Duration::from_millis(80));
            (
                "Đang xác thực tính toàn vẹn (SHA-256)...".to_owned(),
                C_ACCENT,
                1.0,
            )
        }
        UpdateDialogPhase::LaunchingInstaller => {
            ctx.request_repaint_after(Duration::from_millis(80));
            (
                "✓ Tải & xác thực hoàn tất! Đang khởi chạy trình cài đặt...".to_owned(),
                C_SUCCESS,
                1.0,
            )
        }
        UpdateDialogPhase::BrowserOpened(url) => (
            format!("🌐 Đã mở trang phát hành trên trình duyệt (chưa có mã SHA-256):\n{url}"),
            C_ACCENT,
            0.0,
        ),
        UpdateDialogPhase::Cancelled => ("Đã hủy quá trình tải.".to_owned(), C_WARNING, 0.0),
        UpdateDialogPhase::Failed(err) => (format!("❌ {err}"), C_DANGER, 0.0),
    };

    ui.label(RichText::new(status_text).size(11.0).color(status_color));
    ui.add_space(4.0);
    render_progress_bar(ui, progress_frac);
    ui.add_space(10.0);

    match state.update_phase.clone() {
        UpdateDialogPhase::Downloading {
            confirm_cancel: true,
            ..
        } => {
            rounded_card(ui, C_SURFACE, C_WARNING, 8, Margin::same(8), |ui| {
                ui.set_width(ui.available_width());
                ui.label(
                    RichText::new("Bạn có chắc muốn hủy quá trình tải bản cập nhật?")
                        .size(11.0)
                        .color(C_WARNING),
                );
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if pill_button(ui, "Tiếp tục tải", Some(120.0), PillStyle::secondary(28.0))
                        .clicked()
                    {
                        if let UpdateDialogPhase::Downloading { confirm_cancel, .. } =
                            &mut state.update_phase
                        {
                            *confirm_cancel = false;
                        }
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let danger_style = PillStyle {
                            bg: C_DANGER,
                            fg: Color32::BLACK,
                            border: C_DANGER,
                            hover_bg: Color32::from_rgb(0xf4, 0xb8, 0xb8),
                            hover_fg: Color32::BLACK,
                            hover_border: C_DANGER,
                            font_size: 11.5,
                            ..PillStyle::accent(28.0)
                        };
                        if pill_button(ui, "Xác nhận hủy", Some(120.0), danger_style).clicked()
                        {
                            state.cancel_update_download();
                        }
                    });
                });
            });
        }
        UpdateDialogPhase::Downloading {
            confirm_cancel: false,
            ..
        } => {
            ui.horizontal(|ui| {
                if pill_button(ui, "Hủy tải", Some(104.0), PillStyle::secondary(32.0)).clicked()
                {
                    if let UpdateDialogPhase::Downloading { confirm_cancel, .. } =
                        &mut state.update_phase
                    {
                        *confirm_cancel = true;
                    }
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let disabled_style = PillStyle {
                        bg: C_CARD_HIGH,
                        fg: C_TEXT_DIM,
                        border: C_BORDER,
                        hover_bg: C_CARD_HIGH,
                        hover_fg: C_TEXT_DIM,
                        hover_border: C_BORDER,
                        ..PillStyle::accent(32.0)
                    };
                    let _ = pill_button(ui, "Đang tải...", Some(196.0), disabled_style);
                });
            });
        }
        UpdateDialogPhase::Verifying | UpdateDialogPhase::LaunchingInstaller => {
            let disabled_style = PillStyle {
                bg: C_CARD_HIGH,
                fg: C_TEXT_DIM,
                border: C_BORDER,
                hover_bg: C_CARD_HIGH,
                hover_fg: C_TEXT_DIM,
                hover_border: C_BORDER,
                ..PillStyle::accent(32.0)
            };
            let _ = pill_button(
                ui,
                "Đang xử lý...",
                Some(ui.available_width()),
                disabled_style,
            );
        }
        UpdateDialogPhase::Idle
        | UpdateDialogPhase::BrowserOpened(_)
        | UpdateDialogPhase::Cancelled
        | UpdateDialogPhase::Failed(_) => {
            ui.horizontal(|ui| {
                if !info.mandatory
                    && pill_button(ui, "Để sau", Some(96.0), PillStyle::secondary(32.0)).clicked()
                {
                    state.close_dialog();
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let action_w = if info.mandatory {
                        ui.available_width()
                    } else {
                        214.0
                    };
                    if pill_button(
                        ui,
                        "⚡ Cập nhật & Khởi động lại",
                        Some(action_w),
                        PillStyle::accent(32.0),
                    )
                    .clicked()
                    {
                        state.start_update_download();
                    }
                });
            });
        }
    }
}

fn render_service_repair_dialog(ctx: &egui::Context, ui: &mut Ui, state: &mut AppState) {
    let is_healthy = state.service_health == ServiceHealthStatus::Healthy
        || state.service_repair_phase == ServiceRepairPhase::Succeeded;
    let title_color = if is_healthy { C_SUCCESS } else { C_WARNING };

    ui.label(
        RichText::new("🔧 Sửa Dịch Vụ FreetonVPNService")
            .size(14.5)
            .strong()
            .color(title_color),
    );
    ui.add_space(8.0);

    if is_healthy {
        ui.label(
            RichText::new(
                "✓ Dịch vụ nền FreetonVPNService đã sẵn sàng hoạt động.\n\nBạn có thể bật/tắt kết nối WireGuard mà không cần hộp thoại UAC.",
            )
            .size(12.0)
            .color(C_TEXT),
        );
    } else {
        ui.label(
            RichText::new(
                "Freeton VPN sử dụng dịch vụ hệ thống FreetonVPNService để quản lý WireGuard an toàn mà không hỏi quyền quản trị mỗi lần kết nối.\n\nDịch vụ hiện chưa chạy hoặc chưa được cài đặt. Bấm nút bên dưới để cấp quyền UAC một lần và tự động cài đặt/khởi động lại dịch vụ.",
            )
            .size(11.5)
            .color(C_TEXT_MUTED),
        );
    }

    match &state.service_repair_phase {
        ServiceRepairPhase::Idle => {}
        ServiceRepairPhase::LaunchingAndWaiting => {
            ctx.request_repaint_after(Duration::from_millis(200));
            ui.add_space(8.0);
            rounded_card(ui, C_SURFACE, C_ACCENT, 8, Margin::same(8), |ui| {
                ui.set_width(ui.available_width());
                ui.label(
                    RichText::new(
                        "⏳ Đang khởi chạy FreetonVPNService.exe --install và chờ dịch vụ phản hồi...",
                    )
                    .size(11.0)
                    .color(C_ACCENT),
                );
            });
        }
        ServiceRepairPhase::Succeeded => {}
        ServiceRepairPhase::Failed(err) => {
            ui.add_space(8.0);
            rounded_card(ui, C_SURFACE, C_DANGER, 8, Margin::same(8), |ui| {
                ui.set_width(ui.available_width());
                ui.label(
                    RichText::new(format!("❌ {err}"))
                        .size(11.0)
                        .color(C_DANGER),
                );
            });
        }
    }

    if state.client_config.debug_mode {
        let diag = state
            .service_repair_detail
            .as_deref()
            .or(match &state.service_health {
                ServiceHealthStatus::Unavailable(detail) => Some(detail.as_str()),
                _ => None,
            })
            .or_else(|| state.error_modal.as_ref().map(|e| e.detail.as_str()))
            .unwrap_or("");
        if !diag.is_empty() {
            ui.add_space(8.0);
            rounded_card(ui, C_BG, C_BORDER, 8, Margin::same(8), |ui| {
                ui.set_width(ui.available_width());
                ui.label(
                    RichText::new(format!("[DEBUG]\n{diag}"))
                        .size(10.0)
                        .monospace()
                        .color(C_TEXT_MUTED),
                );
            });
        }
    }

    ui.add_space(12.0);
    let busy = state.service_repair_phase == ServiceRepairPhase::LaunchingAndWaiting;
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        if !busy && pill_button(ui, "Đóng", Some(74.0), PillStyle::secondary(32.0)).clicked() {
            state.close_dialog();
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if is_healthy {
                if pill_button(ui, "Xong", Some(120.0), PillStyle::accent(32.0)).clicked() {
                    state.close_dialog();
                }
            } else if busy {
                let disabled_style = PillStyle {
                    bg: C_CARD_HIGH,
                    fg: C_TEXT_DIM,
                    border: C_BORDER,
                    hover_bg: C_CARD_HIGH,
                    hover_fg: C_TEXT_DIM,
                    hover_border: C_BORDER,
                    ..PillStyle::accent(32.0)
                };
                let _ = pill_button(
                    ui,
                    "Đang sửa dịch vụ...",
                    Some(ui.available_width()),
                    disabled_style,
                );
            } else {
                let repair_style = PillStyle {
                    font_size: 11.0,
                    pad_x: 6.0,
                    ..PillStyle::accent(32.0)
                };
                if pill_button(ui, "🔧 Sửa dịch vụ (UAC)", Some(142.0), repair_style).clicked()
                {
                    state.start_service_repair();
                }
                let recheck_style = PillStyle {
                    font_size: 11.0,
                    pad_x: 6.0,
                    ..PillStyle::secondary(32.0)
                };
                if pill_button(ui, "↻ Kiểm tra", Some(82.0), recheck_style).clicked() {
                    state.request_status_refresh();
                }
            }
        });
    });
}

fn render_error_detail_dialog(ui: &mut Ui, state: &mut AppState) {
    let (title, friendly, detail) = if let Some(err) = &state.error_modal {
        (
            err.title.clone(),
            err.friendly_msg.clone(),
            err.detail.clone(),
        )
    } else {
        (
            "Thông báo".to_owned(),
            "Đã xảy ra sự cố.".to_owned(),
            String::new(),
        )
    };

    let display_title = if state.client_config.debug_mode {
        format!("{title} [Debug Mode ✦]")
    } else {
        title
    };

    ui.label(
        RichText::new(display_title)
            .size(14.5)
            .strong()
            .color(C_DANGER),
    );
    ui.add_space(8.0);
    ui.label(RichText::new(&friendly).size(12.0).color(C_TEXT));

    if state.client_config.debug_mode && !detail.is_empty() && detail != friendly {
        ui.add_space(8.0);
        ui.label(
            RichText::new("── [DEBUG: CHI TIẾT KỸ THUẬT] ──")
                .size(10.0)
                .strong()
                .color(C_WARNING),
        );
        ui.add_space(4.0);
        rounded_card(ui, C_BG, C_BORDER, 8, Margin::same(8), |ui| {
            ui.set_width(ui.available_width());
            ScrollArea::vertical()
                .id_salt("error_detail_scroll")
                .max_height(150.0)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    ui.label(
                        RichText::new(&detail)
                            .size(10.5)
                            .monospace()
                            .color(C_TEXT_MUTED),
                    );
                });
        });
    }

    ui.add_space(12.0);
    ui.horizontal(|ui| {
        if state.client_config.debug_mode
            && !detail.is_empty()
            && pill_button(
                ui,
                "📋 Sao chép lỗi",
                Some(124.0),
                PillStyle::secondary(32.0),
            )
            .clicked()
        {
            ui.ctx().copy_text(detail.clone());
            state.info_toast = Some(StatusNotice {
                text: "Đã sao chép chi tiết lỗi.".to_owned(),
                level: NoticeLevel::Info,
            });
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if pill_button(ui, "Đóng", Some(104.0), PillStyle::accent(32.0)).clicked() {
                state.close_dialog();
            }
        });
    });
}

fn render_progress_bar(ui: &mut Ui, frac: f32) {
    let width = ui.available_width().max(40.0);
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 6.0), Sense::hover());
    let p = ui.painter();
    let cr = CornerRadius::same(3);
    p.rect_filled(rect, cr, C_BG);
    let clamped = frac.clamp(0.0, 1.0);
    if clamped > 0.0 {
        let fill_w = (rect.width() * clamped).max(6.0);
        let fill_rect = Rect::from_min_size(rect.min, Vec2::new(fill_w, rect.height()));
        p.rect_filled(fill_rect, cr, C_ACCENT);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{
        ActiveDialog, AppState, ServiceHealthStatus, ServiceRepairPhase, UiCommand,
        UpdateDialogPhase, WorkerEvent,
    };
    use freeton_core::storage::ClientConfig;
    use freeton_core::updater::{UpdateAction, UpdateInfo};

    #[test]
    fn test_middle_mouse_hold_750ms_toggles_dev_mode_and_persists() {
        let mut tracker = MiddleHoldTracker::default();
        let t0 = Instant::now();

        tracker.on_press(t0);
        assert!(!tracker.poll(t0 + Duration::from_millis(500)));
        assert!(!tracker.poll(t0 + Duration::from_millis(749)));
        tracker.on_release();

        // Re-press and hold past 750ms: fires exactly once per press.
        let t1 = t0 + Duration::from_secs(1);
        tracker.on_press(t1);
        assert!(!tracker.poll(t1 + Duration::from_millis(749)));
        assert!(tracker.poll(t1 + Duration::from_millis(750)));
        assert!(!tracker.poll(t1 + Duration::from_millis(1500)));
        tracker.on_release();

        let mut state = AppState::new(false, None, ClientConfig::default(), None, Vec::new());
        let _ = state.drain_commands();
        assert!(!state.client_config.debug_mode);

        state.toggle_dev_mode();
        assert!(state.client_config.debug_mode);
        let cmds = state.drain_commands();
        assert!(cmds.iter().any(|c| matches!(
            c,
            UiCommand::SaveClientConfig { config } if config.debug_mode
        )));

        state.toggle_dev_mode();
        assert!(!state.client_config.debug_mode);
        let cmds2 = state.drain_commands();
        assert!(cmds2.iter().any(|c| matches!(
            c,
            UiCommand::SaveClientConfig { config } if !config.debug_mode
        )));
    }

    #[test]
    fn test_import_conf_parses_private_key_address_dns_and_sets_static_expiration() {
        let sample_conf = "\u{FEFF}# Proton WireGuard config\r\n\
            [Interface]\r\n\
            PrivateKey = c2FtcGxlLXByaXZhdGUta2V5LTAxMjM0NTY3ODkwMTI=\r\n\
            Address = 10.2.0.9/32\r\n\
            DNS = 10.2.0.1, 9.9.9.9\r\n\
            MTU = 1380\r\n\
            \r\n\
            [Peer]\r\n\
            PublicKey = c2FtcGxlLXB1YmxpYy1rZXktMDEyMzQ1Njc4OTAxMjM=\r\n\
            AllowedIPs = 0.0.0.0/0\r\n\
            Endpoint = 198.51.100.10:51820\r\n";

        let parsed = parse_wireguard_conf(sample_conf).expect("valid wireguard conf");
        assert_eq!(
            parsed.private_key,
            "c2FtcGxlLXByaXZhdGUta2V5LTAxMjM0NTY3ODkwMTI="
        );
        assert_eq!(parsed.address.as_deref(), Some("10.2.0.9/32"));
        assert_eq!(parsed.dns.as_deref(), Some("10.2.0.1, 9.9.9.9"));

        let mut cfg = ClientConfig {
            private_key: "old-key".to_owned(),
            public_key: "old-api-cert-pub".to_owned(),
            expiration: 1_900_000_000,
            ..ClientConfig::default()
        };
        apply_imported_conf(&mut cfg, &parsed);
        assert_eq!(
            cfg.private_key,
            "c2FtcGxlLXByaXZhdGUta2V5LTAxMjM0NTY3ODkwMTI="
        );
        assert!(cfg.public_key.is_empty());
        assert_eq!(cfg.address, "10.2.0.9/32");
        assert_eq!(cfg.dns, "10.2.0.1, 9.9.9.9");
        assert_eq!(cfg.expiration, 0);

        // Missing [Interface], missing PrivateKey, invalid key/CIDR/DNS, or control characters are rejected.
        assert!(parse_wireguard_conf(
            "PrivateKey = c2FtcGxlLXByaXZhdGUta2V5LTAxMjM0NTY3ODkwMTI=\n"
        )
        .is_err());
        assert!(parse_wireguard_conf("[Interface]\nAddress = 10.2.0.2/32\n").is_err());
        assert!(parse_wireguard_conf("[Interface]\nPrivateKey = not-base64-32-bytes\n").is_err());
        assert!(parse_wireguard_conf(
            "[Interface]\nPrivateKey = c2FtcGxlLXByaXZhdGUta2V5LTAxMjM0NTY3ODkwMTI=\nAddress = 10.2.0.2/99\n"
        )
        .is_err());
        assert!(parse_wireguard_conf(
            "[Interface]\nPrivateKey = c2FtcGxlLXByaXZhdGUta2V5LTAxMjM0NTY3ODkwMTI=\nDNS = bad-dns\n"
        )
        .is_err());
        assert!(parse_wireguard_conf("[Interface]\nPrivateKey = abc\nDNS = 1.1.1.1\n\0").is_err());
    }

    #[test]
    fn test_validate_https_browser_url_rejects_non_https_schemes() {
        assert!(
            validate_https_browser_url("https://github.com/datpusheen/FreetonVPN/releases").is_ok()
        );
        assert!(validate_https_browser_url("HTTPS://account.protonvpn.com/signup").is_ok());
        assert!(validate_https_browser_url("http://github.com/datpusheen/FreetonVPN").is_err());
        assert!(validate_https_browser_url("file:///C:/Windows/System32/calc.exe").is_err());
        assert!(validate_https_browser_url("javascript:alert(1)").is_err());
        assert!(validate_https_browser_url("").is_err());
        assert!(validate_https_browser_url("https://github.com/\nfoo").is_err());
    }

    #[test]
    fn test_settings_save_persists_config_and_startup_and_cancel_discards_draft() {
        let valid_priv = "c2FtcGxlLXByaXZhdGUta2V5LTAxMjM0NTY3ODkwMTI=".to_owned();
        let initial = ClientConfig {
            private_key: valid_priv.clone(),
            public_key: "initial-pub".to_owned(),
            expiration: 1_900_000_000,
            ..ClientConfig::default()
        };
        let mut state = AppState::new(
            true,
            Some("u@proton.me".to_owned()),
            initial,
            None,
            Vec::new(),
        );
        let _ = state.drain_commands();

        state.open_settings_dialog();
        assert_eq!(state.active_dialog, ActiveDialog::Settings);
        state.settings_draft.animations_enabled = false;
        state.settings_draft.auto_check_update = false;
        state.settings_draft.startup_enabled = true;
        state.settings_draft.dns = "1.1.1.1".to_owned();
        state.settings_draft.port = "51821".to_owned();

        // Closing discards draft without emitting SaveClientConfig.
        state.close_dialog();
        assert_eq!(state.active_dialog, ActiveDialog::None);
        assert!(state.client_config.animations_enabled);
        assert!(!state
            .drain_commands()
            .iter()
            .any(|c| matches!(c, UiCommand::SaveClientConfig { .. })));

        // Re-open, edit, and save -> persists and closes.
        state.open_settings_dialog();
        state.settings_draft.animations_enabled = false;
        state.settings_draft.auto_check_update = false;
        state.settings_draft.startup_enabled = true;
        state.settings_draft.dns = "9.9.9.9".to_owned();
        state.settings_draft.port = "443".to_owned();
        state.save_settings_dialog();

        assert_eq!(state.active_dialog, ActiveDialog::None);
        assert!(!state.client_config.animations_enabled);
        assert!(!state.client_config.auto_check_update);
        assert!(state.startup_enabled);
        assert_eq!(state.client_config.private_key, valid_priv);
        assert_eq!(state.client_config.dns, "9.9.9.9");
        assert_eq!(state.client_config.port, "443");
        assert_eq!(state.client_config.expiration, 1_900_000_000);

        let cmds = state.drain_commands();
        assert!(cmds.iter().any(
            |c| matches!(c, UiCommand::SaveClientConfig { config } if config.dns == "9.9.9.9")
        ));
        assert!(cmds
            .iter()
            .any(|c| matches!(c, UiCommand::SetStartupEnabled { enabled: true })));
    }

    #[test]
    fn test_settings_save_validates_inputs_and_clears_empty_private_key() {
        let valid_priv = "c2FtcGxlLXByaXZhdGUta2V5LTAxMjM0NTY3ODkwMTI=".to_owned();
        let initial = ClientConfig {
            private_key: valid_priv.clone(),
            public_key: "existing-pub".to_owned(),
            expiration: 1_900_000_000,
            ..ClientConfig::default()
        };
        let mut state = AppState::new(
            true,
            Some("u@proton.me".to_owned()),
            initial,
            None,
            Vec::new(),
        );
        let _ = state.drain_commands();

        // 1. Invalid Private Key keeps Settings open without persisting.
        state.open_settings_dialog();
        let _ = state.drain_commands();
        state.settings_draft.private_key = "not-a-32-byte-wireguard-key".to_owned();
        state.save_settings_dialog();
        assert_eq!(state.active_dialog, ActiveDialog::Settings);
        assert_eq!(state.client_config.private_key, valid_priv);
        assert!(state.settings_status_msg.is_some());
        assert!(state.drain_commands().is_empty());

        // 2. Invalid DNS keeps Settings open without persisting.
        state.settings_draft.private_key = valid_priv.clone();
        state.settings_draft.dns = "bad-dns-host".to_owned();
        state.save_settings_dialog();
        assert_eq!(state.active_dialog, ActiveDialog::Settings);
        assert_eq!(state.client_config.dns, "10.2.0.1, 1.1.1.1");
        assert!(state.drain_commands().is_empty());

        // 3. Invalid Port (0 or > 65535 or non-numeric) keeps Settings open without persisting.
        for bad_port in ["0", "65536", "abc", ""] {
            state.settings_draft.dns = "1.1.1.1".to_owned();
            state.settings_draft.port = bad_port.to_owned();
            state.save_settings_dialog();
            assert_eq!(
                state.active_dialog,
                ActiveDialog::Settings,
                "port {bad_port:?} must be rejected"
            );
            assert_eq!(state.client_config.port, "51820");
            assert!(state.drain_commands().is_empty());
        }

        // 4. Clearing private_key (empty) clears private_key, public_key, and sets expiration = 0.
        state.settings_draft.private_key = "   ".to_owned();
        state.settings_draft.dns = "1.1.1.1, 9.9.9.9".to_owned();
        state.settings_draft.port = "51820".to_owned();
        state.save_settings_dialog();
        assert_eq!(state.active_dialog, ActiveDialog::None);
        assert!(state.client_config.private_key.is_empty());
        assert!(state.client_config.public_key.is_empty());
        assert_eq!(state.client_config.expiration, 0);
        assert_eq!(state.client_config.dns, "1.1.1.1, 9.9.9.9");
        assert!(state.drain_commands().iter().any(
            |c| matches!(c, UiCommand::SaveClientConfig { config } if config.private_key.is_empty() && config.expiration == 0)
        ));
    }

    #[test]
    fn test_update_download_launch_vs_browser_fallback_and_mandatory_guards() {
        let mut info = UpdateInfo {
            version: "3.1.0".to_owned(),
            release_date: "2026-12-01".to_owned(),
            title: "Freeton VPN v3.1.0".to_owned(),
            changelog: vec!["Fix bug".to_owned()],
            download_url: "https://github.com/datpusheen/FreetonVPN/releases/download/v3.1.0/FreetonVPN-Setup-x64.exe".to_owned(),
            file_size_bytes: 12_345_678,
            sha256: "a".repeat(64),
            mandatory: true,
            min_supported_version: "3.0.0".to_owned(),
        };

        let mut state = AppState::new(false, None, ClientConfig::default(), None, Vec::new());
        let _ = state.drain_commands();

        state.apply_event(WorkerEvent::UpdateAvailable { info: info.clone() });
        assert_eq!(state.active_dialog, ActiveDialog::Update);

        // Mandatory update cannot be dismissed directly.
        state.close_dialog();
        assert_eq!(state.active_dialog, ActiveDialog::Update);

        // Start download -> LaunchingVerifiedInstaller launches elevated, exits ONLY on Ok(()).
        state.start_update_download();
        let gen = state.update_generation;
        assert!(matches!(
            state.update_phase,
            UpdateDialogPhase::Downloading { .. }
        ));
        assert!(state.drain_commands().iter().any(
            |c| matches!(c, UiCommand::StartUpdateDownload { generation, .. } if *generation == gen)
        ));

        // Mid-download close is blocked even if non-mandatory; explicit cancel must be used.
        state.available_update.as_mut().unwrap().mandatory = false;
        state.close_dialog();
        assert_eq!(state.active_dialog, ActiveDialog::Update);

        let installer_path = PathBuf::from(r"C:\Temp\FreetonVPN-Setup-x64.exe");
        state.apply_event(WorkerEvent::UpdateDownloadFinished {
            generation: gen,
            action: Ok(UpdateAction::LaunchVerifiedInstaller(
                installer_path.clone(),
            )),
        });
        assert_eq!(state.update_phase, UpdateDialogPhase::LaunchingInstaller);
        assert!(!state.closing);
        assert!(state.drain_commands().iter().any(
            |c| matches!(c, UiCommand::LaunchUpdateInstaller { path } if path == &installer_path)
        ));

        // Failed / UAC-cancelled launch must NOT shut down tunnel or exit app.
        state.apply_event(WorkerEvent::UpdateInstallerLaunched {
            result: Err("UAC cancelled".to_owned()),
        });
        assert!(!state.closing);
        assert!(matches!(state.update_phase, UpdateDialogPhase::Failed(_)));
        assert!(state.drain_commands().is_empty());

        // Successful launch triggers clean tunnel shutdown & exit.
        state.apply_event(WorkerEvent::UpdateInstallerLaunched { result: Ok(()) });
        assert!(state.closing);
        assert!(state
            .drain_commands()
            .iter()
            .any(|c| matches!(c, UiCommand::ShutdownOnExit)));

        // Browser fallback: valid HTTPS opens; non-HTTPS rejected.
        info.mandatory = false;
        info.sha256.clear();
        let mut state2 = AppState::new(false, None, ClientConfig::default(), None, Vec::new());
        let _ = state2.drain_commands();
        state2.apply_event(WorkerEvent::UpdateAvailable { info });
        state2.start_update_download();
        let gen2 = state2.update_generation;
        let _ = state2.drain_commands();

        state2.apply_event(WorkerEvent::UpdateDownloadFinished {
            generation: gen2,
            action: Ok(UpdateAction::OpenReleasePageInBrowser(
                "http://insecure.example.com/release".to_owned(),
            )),
        });
        assert!(matches!(state2.update_phase, UpdateDialogPhase::Failed(_)));
        assert!(state2.drain_commands().is_empty());

        state2.start_update_download();
        let gen3 = state2.update_generation;
        let _ = state2.drain_commands();
        state2.apply_event(WorkerEvent::UpdateDownloadFinished {
            generation: gen3,
            action: Ok(UpdateAction::OpenReleasePageInBrowser(
                "https://github.com/datpusheen/FreetonVPN/releases/tag/v3.1.0".to_owned(),
            )),
        });
        assert!(matches!(
            state2.update_phase,
            UpdateDialogPhase::BrowserOpened(_)
        ));
        assert!(state2.drain_commands().iter().any(
            |c| matches!(c, UiCommand::OpenExternalUrl { url } if url.starts_with("https://"))
        ));

        // Explicit cancel mid-download sends CancelUpdateDownload and bumps generation.
        state2.start_update_download();
        let gen4 = state2.update_generation;
        let _ = state2.drain_commands();
        state2.cancel_update_download();
        assert_ne!(state2.update_generation, gen4);
        assert_eq!(state2.active_dialog, ActiveDialog::None);
        assert!(state2.drain_commands().iter().any(
            |c| matches!(c, UiCommand::CancelUpdateDownload { generation } if *generation == gen4)
        ));
    }

    #[test]
    fn test_service_repair_state_transitions_and_sibling_path() {
        let exe =
            sibling_service_exe_path(Path::new(r"C:\Program Files\FreetonVPN\FreetonVPN.exe"))
                .expect("sibling exe path");
        assert_eq!(
            exe,
            PathBuf::from(r"C:\Program Files\FreetonVPN\FreetonVPNService.exe")
        );
        assert!(sibling_service_exe_path(Path::new("FreetonVPN.exe")).is_none());

        let mut state = AppState::new(
            true,
            Some("u@proton.me".to_owned()),
            ClientConfig::default(),
            None,
            Vec::new(),
        );
        let _ = state.drain_commands();

        state.connection_generation = 1;
        state.apply_event(WorkerEvent::ConnectFailed {
            generation: 1,
            message: "Service unavailable".to_owned(),
            detail: "ERROR_FILE_NOT_FOUND".to_owned(),
            service_unavailable: true,
        });
        assert_eq!(state.active_dialog, ActiveDialog::ServiceRepair);
        assert!(matches!(
            state.service_health,
            ServiceHealthStatus::Unavailable(_)
        ));
        assert_eq!(state.service_repair_phase, ServiceRepairPhase::Idle);
        let _ = state.drain_commands();

        state.start_service_repair();
        assert_eq!(
            state.service_repair_phase,
            ServiceRepairPhase::LaunchingAndWaiting
        );
        assert!(state
            .drain_commands()
            .iter()
            .any(|c| matches!(c, UiCommand::RepairService)));

        // Duplicate clicks while repair is running are ignored.
        state.start_service_repair();
        assert!(state.drain_commands().is_empty());

        // Closing via Escape/close_dialog or reopening while LaunchingAndWaiting cannot cancel/reset state.
        state.close_dialog();
        assert_eq!(state.active_dialog, ActiveDialog::ServiceRepair);
        assert_eq!(
            state.service_repair_phase,
            ServiceRepairPhase::LaunchingAndWaiting
        );
        state.open_service_repair_dialog();
        assert_eq!(state.active_dialog, ActiveDialog::ServiceRepair);
        assert_eq!(
            state.service_repair_phase,
            ServiceRepairPhase::LaunchingAndWaiting
        );

        let escape_ctx = egui::Context::default();
        let escape_input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(
                egui::Pos2::ZERO,
                Vec2::new(crate::ui::WINDOW_WIDTH, crate::ui::WINDOW_HEIGHT),
            )),
            events: vec![egui::Event::Key {
                key: Key::Escape,
                physical_key: Some(Key::Escape),
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            }],
            ..Default::default()
        };
        struct DummyStore;
        impl CredentialStore for DummyStore {
            fn get_password(
                &self,
                _: &str,
                _: &str,
            ) -> Result<Option<String>, freeton_core::storage::StorageError> {
                Ok(None)
            }
            fn set_password(
                &self,
                _: &str,
                _: &str,
                _: &str,
            ) -> Result<(), freeton_core::storage::StorageError> {
                Ok(())
            }
            fn delete_password(
                &self,
                _: &str,
                _: &str,
            ) -> Result<(), freeton_core::storage::StorageError> {
                Ok(())
            }
        }
        let mut out = escape_ctx.run_ui(escape_input, |ui| {
            crate::ui::render_root(ui, &mut state, &DummyStore);
        });
        out.textures_delta.clear();
        assert_eq!(state.active_dialog, ActiveDialog::ServiceRepair);
        assert_eq!(
            state.service_repair_phase,
            ServiceRepairPhase::LaunchingAndWaiting
        );

        state.apply_event(WorkerEvent::ServiceRepairFailed {
            message: "UAC denied".to_owned(),
            detail: "code 5".to_owned(),
        });
        assert!(matches!(
            state.service_repair_phase,
            ServiceRepairPhase::Failed(_)
        ));

        state.start_service_repair();
        let _ = state.drain_commands();
        state.apply_event(WorkerEvent::ServiceRepairSucceeded);
        assert_eq!(state.service_repair_phase, ServiceRepairPhase::Succeeded);
        assert_eq!(state.service_health, ServiceHealthStatus::Healthy);
    }

    #[test]
    fn test_formatting_helpers_and_error_detail_returns_to_settings() {
        assert_eq!(format_byte_size(0), "");
        assert_eq!(format_byte_size(512), "1 KB");
        assert_eq!(format_byte_size(2 * 1024 * 1024), "2.0 MB");

        assert_eq!(format_unix_timestamp_local(0), "Vĩnh viễn / Tĩnh");
        let ts = format_unix_timestamp_local(1_700_000_000);
        assert_eq!(ts.len(), 16);
        assert!(ts.contains('/'));
        assert!(ts.contains(':'));

        let mut state = AppState::new(
            true,
            Some("u@proton.me".to_owned()),
            ClientConfig::default(),
            None,
            Vec::new(),
        );
        state.open_settings_dialog();
        state.apply_event(WorkerEvent::ConfImportError {
            title: "Lỗi Nạp File .conf".to_owned(),
            friendly_msg: "File không hợp lệ".to_owned(),
            detail: "Missing PrivateKey".to_owned(),
        });
        assert_eq!(state.active_dialog, ActiveDialog::ErrorDetail);
        state.close_dialog();
        assert_eq!(state.active_dialog, ActiveDialog::Settings);
    }

    #[test]
    fn test_all_dialogs_render_cleanly_inside_flyout_bounds() {
        use freeton_core::storage::StorageError;

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

        let ctx = egui::Context::default();
        let store = NoopStore;
        let mut state = AppState::new(
            true,
            Some("user@proton.me".to_owned()),
            ClientConfig {
                debug_mode: true,
                ..ClientConfig::default()
            },
            None,
            Vec::new(),
        );
        state.available_update = Some(UpdateInfo {
            version: "3.1.0".to_owned(),
            release_date: "2026-12-01".to_owned(),
            title: "Freeton VPN v3.1.0".to_owned(),
            changelog: vec!["Tối ưu hiệu năng".to_owned(), "Sửa lỗi".to_owned()],
            download_url: "https://github.com/datpusheen/FreetonVPN/releases/download/v3.1.0/FreetonVPN-Setup-x64.exe".to_owned(),
            file_size_bytes: 10_485_760,
            sha256: "a".repeat(64),
            mandatory: false,
            min_supported_version: "3.0.0".to_owned(),
        });
        state.error_modal = Some(crate::state::AppErrorInfo {
            title: "Lỗi thử nghiệm".to_owned(),
            friendly_msg: "Thông báo thân thiện".to_owned(),
            detail: "Stack trace detail line".to_owned(),
        });

        for dialog in [
            ActiveDialog::Settings,
            ActiveDialog::About,
            ActiveDialog::Update,
            ActiveDialog::ServiceRepair,
            ActiveDialog::ErrorDetail,
            ActiveDialog::LogoutConfirm,
        ] {
            if dialog == ActiveDialog::Settings {
                state.open_settings_dialog();
            } else {
                state.active_dialog = dialog;
            }
            for _ in 0..2 {
                let raw_input = egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(
                        egui::Pos2::ZERO,
                        Vec2::new(crate::ui::WINDOW_WIDTH, crate::ui::WINDOW_HEIGHT),
                    )),
                    ..Default::default()
                };
                let mut out = ctx.run_ui(raw_input, |ui| {
                    crate::ui::render_root(ui, &mut state, &store);
                });
                out.textures_delta.clear();
            }
            let card_rect = ctx
                .memory(|m| m.area_rect(egui::Id::unique("dialog_card")))
                .expect("dialog_card rect");
            assert!(
                card_rect.min.x >= 0.0
                    && card_rect.min.y >= 0.0
                    && card_rect.max.x <= crate::ui::WINDOW_WIDTH
                    && card_rect.max.y <= crate::ui::WINDOW_HEIGHT,
                "dialog {dialog:?} overflowed flyout bounds: {card_rect:?}"
            );
        }

        // Also cover non-healthy ServiceRepair 3-button bottom row inside a fresh context.
        state.service_health = ServiceHealthStatus::Unavailable("pipe missing".to_owned());
        state.service_repair_phase = ServiceRepairPhase::Idle;
        state.active_dialog = ActiveDialog::ServiceRepair;
        for _ in 0..2 {
            let raw_input = egui::RawInput {
                screen_rect: Some(Rect::from_min_size(
                    egui::Pos2::ZERO,
                    Vec2::new(crate::ui::WINDOW_WIDTH, crate::ui::WINDOW_HEIGHT),
                )),
                ..Default::default()
            };
            let mut out = ctx.run_ui(raw_input, |ui| {
                crate::ui::render_root(ui, &mut state, &store);
            });
            out.textures_delta.clear();
        }
        let repair_rect = ctx
            .memory(|m| m.area_rect(egui::Id::unique("dialog_card")))
            .expect("non-healthy ServiceRepair card rect");
        assert!(
            repair_rect.min.x >= 0.0
                && repair_rect.min.y >= 0.0
                && repair_rect.max.x <= crate::ui::WINDOW_WIDTH
                && repair_rect.max.y <= crate::ui::WINDOW_HEIGHT
                && repair_rect.width() <= 356.0,
            "non-healthy ServiceRepair overflowed card bounds: {repair_rect:?}"
        );
    }
}
