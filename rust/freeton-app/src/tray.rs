use std::path::Path;
use std::sync::Arc;

use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayVisualState {
    Idle,
    Connecting,
    Connected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayAction {
    OpenWindow,
    ToggleVpn,
    OpenSettings,
    OpenAbout,
    Exit,
}

const MENU_ID_OPEN: &str = "open";
const MENU_ID_TOGGLE: &str = "toggle";
const MENU_ID_SETTINGS: &str = "settings";
const MENU_ID_ABOUT: &str = "about";
const MENU_ID_EXIT: &str = "exit";

pub fn tray_guid_for_exe_path(path: &Path) -> u128 {
    const FNV_OFFSET_BASIS_128: u128 = 0x6c62_272e_07bb_0142_62b8_2175_6295_c58d;
    const FNV_PRIME_128: u128 = 0x0000_0000_0100_0000_0000_0000_0000_013b;

    let raw = path.to_string_lossy();
    let stripped = raw.strip_prefix(r"\\?\").unwrap_or(&raw);
    let normalized = stripped.replace('/', "\\").to_ascii_lowercase();

    let mut hash = FNV_OFFSET_BASIS_128;
    for &b in b"FreetonVPN-Tray:"
        .iter()
        .chain(normalized.as_bytes().iter())
    {
        hash ^= u128::from(b);
        hash = hash.wrapping_mul(FNV_PRIME_128);
    }
    (hash & 0xffff_ffff_ffff_0fff_3fff_ffff_ffff_ffff) | 0x0000_0000_0000_4000_8000_0000_0000_0000
}

pub struct TrayController {
    tray_icon: TrayIcon,
    current_visual: TrayVisualState,
    action_rx: std::sync::mpsc::Receiver<TrayAction>,
}

impl TrayController {
    pub fn new(on_wake: Arc<dyn Fn() + Send + Sync>) -> Result<Self, String> {
        let (action_tx, action_rx) = std::sync::mpsc::channel::<TrayAction>();

        let open_item = MenuItem::with_id(MenuId::new(MENU_ID_OPEN), "Mở Freeton VPN", true, None);
        let toggle_item =
            MenuItem::with_id(MenuId::new(MENU_ID_TOGGLE), "⚡ Bật/Tắt VPN", true, None);
        let settings_item =
            MenuItem::with_id(MenuId::new(MENU_ID_SETTINGS), "⚙️ Cài đặt", true, None);
        let about_item = MenuItem::with_id(MenuId::new(MENU_ID_ABOUT), "ℹ️ Giới thiệu", true, None);
        let separator = PredefinedMenuItem::separator();
        let exit_item = MenuItem::with_id(MenuId::new(MENU_ID_EXIT), "❌ Thoát", true, None);

        let menu = Menu::with_items(&[
            &open_item,
            &toggle_item,
            &settings_item,
            &about_item,
            &separator,
            &exit_item,
        ])
        .map_err(|e| format!("Menu build failed: {e}"))?;

        let tx_menu = action_tx.clone();
        let wake_menu = Arc::clone(&on_wake);
        MenuEvent::set_event_handler(Some(Arc::new(move |event: MenuEvent| {
            let action = match event.id().as_ref() {
                MENU_ID_OPEN => Some(TrayAction::OpenWindow),
                MENU_ID_TOGGLE => Some(TrayAction::ToggleVpn),
                MENU_ID_SETTINGS => Some(TrayAction::OpenSettings),
                MENU_ID_ABOUT => Some(TrayAction::OpenAbout),
                MENU_ID_EXIT => Some(TrayAction::Exit),
                _ => None,
            };
            if let Some(act) = action {
                let _ = tx_menu.send(act);
                wake_menu();
            }
        })));

        let tx_tray = action_tx;
        let wake_tray = on_wake;
        TrayIconEvent::set_event_handler(Some(move |event: TrayIconEvent| {
            let should_open = matches!(
                event,
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } | TrayIconEvent::DoubleClick {
                    button: MouseButton::Left,
                    ..
                }
            );
            if should_open {
                let _ = tx_tray.send(TrayAction::OpenWindow);
                wake_tray();
            }
        }));

        let tray_guid = std::env::current_exe()
            .map(|p| tray_guid_for_exe_path(&p))
            .unwrap_or_else(|_| tray_guid_for_exe_path(Path::new("FreetonVPN.exe")));
        let icon = build_tray_icon(TrayVisualState::Idle)?;
        let tray_icon = TrayIconBuilder::new()
            .with_id("FreetonVPN")
            .with_guid(tray_guid)
            .with_menu(Box::new(menu))
            .with_menu_on_left_click(false)
            .with_tooltip("Freeton VPN - by pishun")
            .with_icon(icon)
            .build()
            .map_err(|e| format!("TrayIcon build failed: {e}"))?;

        Ok(Self {
            tray_icon,
            current_visual: TrayVisualState::Idle,
            action_rx,
        })
    }

    pub fn set_status(&mut self, state: TrayVisualState) {
        if self.current_visual == state {
            return;
        }
        if let Ok(icon) = build_tray_icon(state) {
            if self.tray_icon.set_icon(Some(icon)).is_ok() {
                self.current_visual = state;
            }
        }
    }

    pub fn drain_actions(&self) -> Vec<TrayAction> {
        let mut actions = Vec::new();
        while let Ok(act) = self.action_rx.try_recv() {
            actions.push(act);
        }
        actions
    }
}

pub fn build_tray_icon(state: TrayVisualState) -> Result<Icon, String> {
    let rgba = render_tray_rgba(state);
    Icon::from_rgba(rgba, 64, 64).map_err(|e| format!("Icon::from_rgba failed: {e}"))
}

/// Generates a 64x64 RGBA rounded-square status icon matching `create_tray_image` in
/// `proton_warp_material_gui.py`:
/// - `Idle`: Violet (`#c084fc` / `(192, 132, 252)`) on dark violet (`(48, 24, 78)`)
/// - `Connecting`: Amber (`#fbbf24` / `(251, 191, 36)`) on dark amber (`(70, 50, 15)`)
/// - `Connected`: Emerald (`#4ade80` / `(74, 222, 128)`) on dark green (`(20, 60, 35)`)
pub fn render_tray_rgba(state: TrayVisualState) -> Vec<u8> {
    const SIZE: usize = 64;
    let (fill, inner) = match state {
        TrayVisualState::Connected => ([74u8, 222, 128, 255], [20u8, 60, 35, 255]),
        TrayVisualState::Connecting => ([251u8, 191, 36, 255], [70u8, 50, 15, 255]),
        TrayVisualState::Idle => ([192u8, 132, 252, 255], [48u8, 24, 78, 255]),
    };

    let mut rgba = vec![0u8; SIZE * SIZE * 4];
    let center = 32.0_f32;
    let half_outer = 28.0_f32; // [4..60]
    let corner_r = 18.0_f32;
    let border_w = 4.0_f32;
    let inner_dot_r = 10.0_f32; // [22..42]

    for y in 0..SIZE {
        for x in 0..SIZE {
            let px = x as f32 + 0.5;
            let py = y as f32 + 0.5;

            // Signed distance to outer rounded rectangle [4, 4, 60, 60]
            let dx = (px - center).abs() - (half_outer - corner_r);
            let dy = (py - center).abs() - (half_outer - corner_r);
            let sd_outer = (dx.max(0.0).hypot(dy.max(0.0))) + dx.max(dy).min(0.0) - corner_r;

            let outer_cov = (0.5 - sd_outer).clamp(0.0, 1.0);
            if outer_cov <= 0.0 {
                continue;
            }

            // Inner background vs 4px outline ring
            let sd_inner = sd_outer + border_w;
            let inner_cov = (0.5 - sd_inner).clamp(0.0, 1.0);

            // Center circle (radius 10)
            let dist_dot = (px - center).hypot(py - center);
            let dot_cov = (inner_dot_r + 0.5 - dist_dot).clamp(0.0, 1.0);

            // Blend: fill (outline ring) -> inner -> fill (center dot)
            let mut r = fill[0] as f32 * (1.0 - inner_cov) + inner[0] as f32 * inner_cov;
            let mut g = fill[1] as f32 * (1.0 - inner_cov) + inner[1] as f32 * inner_cov;
            let mut b = fill[2] as f32 * (1.0 - inner_cov) + inner[2] as f32 * inner_cov;

            r = r * (1.0 - dot_cov) + fill[0] as f32 * dot_cov;
            g = g * (1.0 - dot_cov) + fill[1] as f32 * dot_cov;
            b = b * (1.0 - dot_cov) + fill[2] as f32 * dot_cov;

            let idx = (y * SIZE + x) * 4;
            rgba[idx] = r.round() as u8;
            rgba[idx + 1] = g.round() as u8;
            rgba[idx + 2] = b.round() as u8;
            rgba[idx + 3] = (outer_cov * 255.0).round() as u8;
        }
    }

    rgba
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pixel_at(rgba: &[u8], x: usize, y: usize) -> [u8; 4] {
        let i = (y * 64 + x) * 4;
        [rgba[i], rgba[i + 1], rgba[i + 2], rgba[i + 3]]
    }

    #[test]
    fn test_render_tray_rgba_colors_and_geometry() {
        for (state, expected_fill, expected_inner) in [
            (
                TrayVisualState::Idle,
                [192, 132, 252, 255],
                [48, 24, 78, 255],
            ),
            (
                TrayVisualState::Connecting,
                [251, 191, 36, 255],
                [70, 50, 15, 255],
            ),
            (
                TrayVisualState::Connected,
                [74, 222, 128, 255],
                [20, 60, 35, 255],
            ),
        ] {
            let rgba = render_tray_rgba(state);
            assert_eq!(rgba.len(), 64 * 64 * 4);
            // Outer corner is transparent
            assert_eq!(pixel_at(&rgba, 0, 0), [0, 0, 0, 0]);
            // Center dot uses fill color
            assert_eq!(pixel_at(&rgba, 32, 32), expected_fill);
            // Interior ring between dot and outline uses inner color
            assert_eq!(pixel_at(&rgba, 14, 32), expected_inner);
            // Outline border uses fill color
            assert_eq!(pixel_at(&rgba, 6, 32), expected_fill);
        }
    }

    #[test]
    fn test_tray_guid_for_exe_path_case_insensitive_and_distinct_per_install_dir() {
        let installed_upper = Path::new(r"C:\Program Files\FreetonVPN\FreetonVPN.exe");
        let installed_lower = Path::new(r"c:\program files\freetonvpn\freetonvpn.exe");
        let installed_slashes = Path::new(r"\\?\C:/Program Files/FreetonVPN/FreetonVPN.exe");
        let dev_build = Path::new(
            r"C:\Users\dev\Documents\ChatGPT\proton-node-checker\rust\target\release\FreetonVPN.exe",
        );

        let guid_upper = tray_guid_for_exe_path(installed_upper);
        let guid_lower = tray_guid_for_exe_path(installed_lower);
        let guid_slashes = tray_guid_for_exe_path(installed_slashes);
        let guid_dev = tray_guid_for_exe_path(dev_build);

        assert_ne!(guid_upper, 0);
        assert_eq!(guid_upper, guid_lower);
        assert_eq!(guid_upper, guid_slashes);
        assert_ne!(guid_upper, guid_dev);
    }
}
