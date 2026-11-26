use egui::{Align, Color32, CursorIcon, Key, Layout, Margin, RichText, Sense, TextEdit, Ui, Vec2};
use freeton_core::APP_NAME;

use crate::state::{AppState, NoticeLevel};
use crate::ui::{
    open_external_url, pill_button, rounded_card, PillStyle, C_ACCENT, C_BG, C_BORDER, C_CARD,
    C_CARD_HIGH, C_DANGER, C_SUCCESS, C_TEXT, C_TEXT_DIM, C_TEXT_MUTED, C_WARNING,
};

const SIGNUP_URL: &str = "https://account.protonvpn.com/signup";

pub fn render_login_view(ui: &mut Ui, state: &mut AppState) {
    ui.add_space(4.0);

    // 1. Hero Brand Card
    rounded_card(ui, C_CARD, C_BORDER, 16, Margin::same(16), |ui| {
        ui.set_width(ui.available_width());
        ui.vertical_centered(|ui| {
            crate::ui::render_brand_logo(ui, 42.0);
            ui.add_space(4.0);
            ui.label(RichText::new(APP_NAME).size(20.0).strong().color(C_TEXT));
            ui.label(
                RichText::new("by pishun • WireGuard Client")
                    .size(11.0)
                    .italics()
                    .color(C_ACCENT),
            );
            ui.add_space(6.0);
            ui.label(
                RichText::new("Kết nối mạng riêng ảo Proton VPN tốc độ cao, không giới hạn dung lượng với công nghệ WireGuard hiện đại.")
                    .size(11.5)
                    .color(C_TEXT_MUTED),
            );
        });
    });

    ui.add_space(10.0);

    // 2. Login Prompt Card
    rounded_card(ui, C_CARD_HIGH, C_BORDER, 12, Margin::same(12), |ui| {
        ui.set_width(ui.available_width());
        ui.label(
            RichText::new("🔒 YÊU CẦU ĐĂNG NHẬP")
                .size(11.0)
                .strong()
                .color(C_WARNING),
        );
        ui.add_space(4.0);
        ui.label(
            RichText::new("Để tải danh sách máy chủ Free độc quyền và tự động cấp chứng chỉ WireGuard bảo mật từ Proton API, vui lòng đăng nhập tài khoản Proton của bạn.")
                .size(11.5)
                .color(C_TEXT_MUTED),
        );
        ui.add_space(4.0);
        ui.label(
            RichText::new("🛡️ Phiên đăng nhập được mã hóa & lưu trong Windows Credential Manager an toàn tuyệt đối.")
                .size(10.5)
                .italics()
                .color(C_SUCCESS),
        );
    });

    ui.add_space(14.0);

    // 3. Primary SRP Login CTA (Browser login permanently removed)
    let w = ui.available_width();
    if pill_button(
        ui,
        "🔐 Đăng nhập Proton VPN (Email/Mật khẩu)",
        Some(w),
        PillStyle::accent(40.0),
    )
    .clicked()
    {
        state.show_srp_view();
    }

    // 4. Bottom Links
    ui.with_layout(Layout::bottom_up(Align::Center), |ui| {
        ui.add_space(4.0);
        let about_resp = ui
            .label(
                RichText::new("ℹ️ Giới thiệu Freeton VPN")
                    .size(11.0)
                    .color(C_TEXT_DIM),
            )
            .interact(Sense::click())
            .on_hover_cursor(CursorIcon::PointingHand);
        if about_resp.clicked() {
            state.open_about_dialog();
        }

        ui.add_space(4.0);

        let signup_resp = ui
            .label(
                RichText::new("Chưa có tài khoản? Đăng ký Proton miễn phí ↗")
                    .size(11.5)
                    .underline()
                    .color(C_ACCENT),
            )
            .interact(Sense::click())
            .on_hover_cursor(CursorIcon::PointingHand);
        if signup_resp.clicked() {
            open_external_url(SIGNUP_URL);
        }
    });
}

pub fn render_srp_view(ui: &mut Ui, state: &mut AppState) {
    // Header with Back button & Title
    ui.horizontal(|ui| {
        let back_style = PillStyle {
            fg: C_ACCENT,
            hover_fg: crate::ui::C_ACCENT_HOVER,
            radius: 7,
            font_size: 11.5,
            pad_x: 10.0,
            ..PillStyle::secondary(26.0)
        };
        if pill_button(ui, "‹ Quay lại", Some(78.0), back_style).clicked() {
            state.show_login_view();
        }

        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(
                RichText::new("Đăng Nhập Proton SRP")
                    .size(14.0)
                    .strong()
                    .color(C_TEXT),
            );
        });
    });

    ui.add_space(8.0);

    // Hero Card
    rounded_card(ui, C_CARD, C_BORDER, 14, Margin::same(10), |ui| {
        ui.set_width(ui.available_width());
        ui.vertical_centered(|ui| {
            ui.label(
                RichText::new("⚡ Mật mã Client-Side SRP")
                    .size(12.5)
                    .strong()
                    .color(C_ACCENT),
            );
            ui.add_space(2.0);
            ui.label(
                RichText::new("Đăng nhập trực tiếp qua thư viện mật mã Proton API\nKhông mở trình duyệt • Không lưu mật khẩu trên máy")
                    .size(11.0)
                    .color(C_TEXT_MUTED),
            );
        });
    });

    ui.add_space(10.0);

    let mut enter_pressed = false;

    // Email / Username
    ui.label(
        RichText::new("EMAIL HOẶC USERNAME PROTON")
            .size(10.5)
            .strong()
            .color(C_TEXT_MUTED),
    );
    ui.add_space(2.0);
    rounded_card(ui, C_CARD, C_BORDER, 10, Margin::symmetric(8, 6), |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new("✉").size(12.5).color(C_TEXT_DIM));
            let resp = ui.add_sized(
                Vec2::new(ui.available_width(), 20.0),
                TextEdit::singleline(&mut state.srp_username)
                    .frame(egui::Frame::NONE)
                    .hint_text("name@proton.me")
                    .text_color(C_TEXT),
            );
            if resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                enter_pressed = true;
            }
        });
    });

    ui.add_space(8.0);

    // Password with Show/Hide toggle
    ui.label(
        RichText::new("MẬT KHẨU PROTON")
            .size(10.5)
            .strong()
            .color(C_TEXT_MUTED),
    );
    ui.add_space(2.0);
    rounded_card(ui, C_CARD, C_BORDER, 10, Margin::symmetric(8, 6), |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new("🔒").size(12.5).color(C_TEXT_DIM));
            let eye_w = 24.0;
            let input_w = (ui.available_width() - eye_w - 6.0).max(80.0);
            let resp = ui.add_sized(
                Vec2::new(input_w, 20.0),
                TextEdit::singleline(&mut state.srp_password)
                    .frame(egui::Frame::NONE)
                    .password(!state.srp_show_password)
                    .hint_text("••••••••")
                    .text_color(C_TEXT),
            );
            if resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                enter_pressed = true;
            }

            let eye_color = if state.srp_show_password {
                C_ACCENT
            } else {
                C_TEXT_DIM
            };
            let eye_resp = ui
                .label(RichText::new("👁").size(13.0).color(eye_color))
                .interact(Sense::click())
                .on_hover_cursor(CursorIcon::PointingHand);
            if eye_resp.clicked() {
                state.srp_show_password = !state.srp_show_password;
            }
        });
    });

    ui.add_space(8.0);

    // 2FA / Recovery Code (never strip valid recovery chars)
    ui.label(
        RichText::new("MÃ 2FA / RECOVERY CODE (NẾU CÓ)")
            .size(10.5)
            .strong()
            .color(C_TEXT_MUTED),
    );
    ui.add_space(2.0);
    rounded_card(ui, C_CARD, C_BORDER, 10, Margin::symmetric(8, 6), |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new("🛡").size(12.0).color(C_TEXT_DIM));
            let resp = ui.add_sized(
                Vec2::new(ui.available_width(), 20.0),
                TextEdit::singleline(&mut state.srp_2fa)
                    .frame(egui::Frame::NONE)
                    .hint_text("6 chữ số hoặc recovery code")
                    .text_color(C_TEXT),
            );
            if resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                enter_pressed = true;
            }
        });
    });

    ui.add_space(8.0);

    // Status banner
    if let Some(status) = &state.srp_status {
        let color = match status.level {
            NoticeLevel::Warning => C_WARNING,
            NoticeLevel::Error => C_DANGER,
            NoticeLevel::Success => C_SUCCESS,
            NoticeLevel::Info => C_ACCENT,
        };
        ui.vertical_centered(|ui| {
            ui.label(RichText::new(&status.text).size(11.5).color(color));
        });
        ui.add_space(6.0);
    } else {
        ui.add_space(10.0);
    }

    // Submit Button
    let w = ui.available_width();
    let submit_style = if state.is_srp_logging_in {
        PillStyle {
            bg: C_CARD_HIGH,
            fg: C_TEXT_DIM,
            border: C_BORDER,
            hover_bg: C_CARD_HIGH,
            hover_fg: C_TEXT_DIM,
            hover_border: C_BORDER,
            ..PillStyle::accent(38.0)
        }
    } else {
        PillStyle::accent(38.0)
    };
    let submit_label = if state.is_srp_logging_in {
        "Đang xử lý..."
    } else {
        "Đăng nhập ngay ➔"
    };
    if pill_button(ui, submit_label, Some(w), submit_style).clicked() || enter_pressed {
        state.submit_srp_login();
    }

    // Footer Link
    ui.with_layout(Layout::bottom_up(Align::Center), |ui| {
        ui.add_space(4.0);
        let foot = ui
            .label(
                RichText::new("‹ Trở về trang Đăng nhập chính")
                    .size(11.5)
                    .color(C_TEXT_MUTED),
            )
            .interact(Sense::click())
            .on_hover_cursor(CursorIcon::PointingHand);
        if foot.clicked() {
            state.show_login_view();
        }
    });

    let _ = (Color32::BLACK, C_BG);
}
