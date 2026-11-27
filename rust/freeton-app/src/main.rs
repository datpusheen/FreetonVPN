#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

pub mod captcha;
pub mod state;
pub mod tray;
pub mod ui;

use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui::{self, ViewportBuilder, ViewportCommand};
use eframe::{egui_wgpu, wgpu, Renderer};
use freeton_core::storage::{CredentialStore, WindowsCredentialStore};
use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use windows::core::{w, BOOL, PCWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE, HWND, POINT, RECT, TRUE,
};
use windows::Win32::Graphics::Dwm::{
    DwmSetWindowAttribute, DWMWA_USE_IMMERSIVE_DARK_MODE, DWMWINDOWATTRIBUTE,
};
use windows::Win32::Graphics::Gdi::{EnumDisplayDevicesW, DISPLAY_DEVICEW};
use windows::Win32::System::Threading::{
    CreateMutexW, GetCurrentProcess, SetProcessWorkingSetSize,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetAsyncKeyState, ReleaseCapture, SetCapture, VK_LBUTTON,
};
use windows::Win32::UI::WindowsAndMessaging::{
    FindWindowW, GetCursorPos, GetSystemMetrics, GetWindowRect, IsIconic, MessageBoxW,
    SetForegroundWindow, SetWindowPos, ShowWindow, SystemParametersInfoW, MB_ICONERROR, MB_OK,
    SM_REMOTESESSION, SPI_GETWORKAREA, SWP_NOACTIVATE, SWP_NOSIZE, SWP_NOZORDER, SW_RESTORE,
    SW_SHOW, SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS,
};

use state::{spawn_worker_runtime, AppState, UiCommand, WorkerDeps, WorkerEvent};
use tray::{TrayAction, TrayController, TrayVisualState};
use ui::{configure_fonts_and_style, render_root, WINDOW_HEIGHT, WINDOW_WIDTH};

const WINDOW_TITLE: &str = "Freeton VPN by pishun";
const SINGLE_INSTANCE_MUTEX: windows::core::PCWSTR = w!("Local\\FreetonVPN_SingleInstance");
const DWMWA_WINDOW_CORNER_PREFERENCE: DWMWINDOWATTRIBUTE = DWMWINDOWATTRIBUTE(33);
const DWMWCP_ROUND: i32 = 2;

struct SingleInstanceGuard(HANDLE);

impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

fn acquire_single_instance() -> Option<SingleInstanceGuard> {
    let handle = unsafe { CreateMutexW(None, false, SINGLE_INSTANCE_MUTEX) }.ok()?;
    let last_err = unsafe { GetLastError() };
    if last_err == ERROR_ALREADY_EXISTS {
        unsafe {
            let _ = CloseHandle(handle);
        }
        bring_existing_window_to_front();
        return None;
    }
    Some(SingleInstanceGuard(handle))
}

fn bring_existing_window_to_front() {
    let title_wide: Vec<u16> = WINDOW_TITLE.encode_utf16().chain(Some(0)).collect();
    if let Ok(hwnd) = unsafe { FindWindowW(PCWSTR::null(), PCWSTR(title_wide.as_ptr())) } {
        if !hwnd.0.is_null() {
            unsafe {
                if IsIconic(hwnd).as_bool() {
                    let _ = ShowWindow(hwnd, SW_RESTORE);
                } else {
                    let _ = ShowWindow(hwnd, SW_SHOW);
                }
                let _ = SetForegroundWindow(hwnd);
            }
        }
    }
}

fn load_embedded_icon() -> Option<egui::IconData> {
    let raw = include_bytes!("../../../freeton_icon.ico");
    let img = image::load_from_memory_with_format(raw, image::ImageFormat::Ico).ok()?;
    let rgba = img.to_rgba8();
    let (width, height) = rgba.dimensions();
    Some(egui::IconData {
        rgba: rgba.into_raw(),
        width,
        height,
    })
}

fn extract_hwnd(frame: &eframe::Frame) -> Option<HWND> {
    let handle = frame.window_handle().ok()?;
    match handle.as_raw() {
        RawWindowHandle::Win32(win32) => Some(HWND(win32.hwnd.get() as *mut core::ffi::c_void)),
        _ => None,
    }
}

fn apply_win11_rounded_corners_and_position(hwnd: HWND, reposition: bool) {
    let corner_pref: i32 = DWMWCP_ROUND;
    let _ = unsafe {
        DwmSetWindowAttribute(
            hwnd,
            DWMWA_WINDOW_CORNER_PREFERENCE,
            (&raw const corner_pref).cast(),
            std::mem::size_of::<i32>() as u32,
        )
    };
    let dark: BOOL = TRUE;
    let _ = unsafe {
        DwmSetWindowAttribute(
            hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE,
            (&raw const dark).cast(),
            std::mem::size_of::<BOOL>() as u32,
        )
    };

    if reposition {
        let mut work_area = RECT::default();
        let mut win_rect = RECT::default();
        let ok_work = unsafe {
            SystemParametersInfoW(
                SPI_GETWORKAREA,
                0,
                Some((&raw mut work_area).cast()),
                SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
            )
        }
        .is_ok();
        let ok_win = unsafe { GetWindowRect(hwnd, &mut win_rect) }.is_ok();
        if ok_work && ok_win {
            let win_w = win_rect.right - win_rect.left;
            let win_h = win_rect.bottom - win_rect.top;
            let x = (work_area.right - win_w - 14).max(work_area.left);
            let y = (work_area.bottom - win_h - 12).max(work_area.top);
            let _ = unsafe {
                SetWindowPos(
                    hwnd,
                    None,
                    x,
                    y,
                    0,
                    0,
                    SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE,
                )
            };
        }
    }
}

fn should_reveal_window(was_visible: bool, is_visible: bool, force_reveal: bool) -> bool {
    is_visible && (!was_visible || force_reveal)
}

pub(crate) fn compute_window_drag_position(
    start_win_x: i32,
    start_win_y: i32,
    start_cursor_x: i32,
    start_cursor_y: i32,
    cur_cursor_x: i32,
    cur_cursor_y: i32,
) -> (i32, i32) {
    (
        start_win_x + (cur_cursor_x - start_cursor_x),
        start_win_y + (cur_cursor_y - start_cursor_y),
    )
}

#[derive(Debug, Clone, Copy)]
struct ActiveWindowDrag {
    start_win_x: i32,
    start_win_y: i32,
    start_cursor_x: i32,
    start_cursor_y: i32,
    last_x: i32,
    last_y: i32,
}

struct FreetonDesktopApp {
    state: AppState,
    store: Arc<dyn CredentialStore>,
    _runtime: tokio::runtime::Runtime,
    cmd_tx: mpsc::UnboundedSender<UiCommand>,
    evt_rx: mpsc::UnboundedReceiver<WorkerEvent>,
    tray: Option<TrayController>,
    dwm_initialized: bool,
    startup_trimmed: bool,
    started_at: Instant,
    last_window_visible: bool,
    active_drag: Option<ActiveWindowDrag>,
}

impl FreetonDesktopApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        configure_fonts_and_style(&cc.egui_ctx);

        let store: Arc<dyn CredentialStore> = Arc::new(WindowsCredentialStore::new());
        let mut state = AppState::from_local_storage(store.as_ref());
        let last_window_visible = state.window_visible;

        let wake_ctx = cc.egui_ctx.clone();
        let on_wake: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            wake_ctx.request_repaint();
        });

        let (runtime, cmd_tx, evt_rx) = spawn_worker_runtime(
            WorkerDeps::production_with_auth(state.auth_generation_handle()),
            Arc::clone(&on_wake),
        );

        for cmd in state.drain_commands() {
            let _ = cmd_tx.send(cmd);
        }

        let tray = match TrayController::new(on_wake) {
            Ok(t) => Some(t),
            Err(err) => {
                warn!(error = %err, "system tray initialization failed");
                None
            }
        };

        Self {
            state,
            store,
            _runtime: runtime,
            cmd_tx,
            evt_rx,
            tray,
            dwm_initialized: false,
            startup_trimmed: false,
            started_at: Instant::now(),
            last_window_visible,
            active_drag: None,
        }
    }

    fn sync_direct_window_drag(&mut self, ctx: &egui::Context, frame: &eframe::Frame) {
        let lbutton_down = unsafe { (GetAsyncKeyState(VK_LBUTTON.0 as i32) as u16 & 0x8000) != 0 };
        if !self.state.window_drag_active || !lbutton_down {
            if self.active_drag.take().is_some() {
                self.state.window_drag_active = false;
                unsafe {
                    let _ = ReleaseCapture();
                }
            }
            return;
        }

        let Some(hwnd) = extract_hwnd(frame) else {
            return;
        };

        let mut cursor = POINT::default();
        if unsafe { GetCursorPos(&mut cursor) }.is_err() {
            return;
        }

        if self.active_drag.is_none() {
            let mut win_rect = RECT::default();
            if unsafe { GetWindowRect(hwnd, &mut win_rect) }.is_err() {
                return;
            }
            unsafe {
                SetCapture(hwnd);
            }
            self.active_drag = Some(ActiveWindowDrag {
                start_win_x: win_rect.left,
                start_win_y: win_rect.top,
                start_cursor_x: cursor.x,
                start_cursor_y: cursor.y,
                last_x: win_rect.left,
                last_y: win_rect.top,
            });
        }

        if let Some(drag) = &mut self.active_drag {
            let (new_x, new_y) = compute_window_drag_position(
                drag.start_win_x,
                drag.start_win_y,
                drag.start_cursor_x,
                drag.start_cursor_y,
                cursor.x,
                cursor.y,
            );
            if new_x != drag.last_x || new_y != drag.last_y {
                drag.last_x = new_x;
                drag.last_y = new_y;
                let _ = unsafe {
                    SetWindowPos(
                        hwnd,
                        None,
                        new_x,
                        new_y,
                        0,
                        0,
                        SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE,
                    )
                };
            }
            ctx.request_repaint_after(std::time::Duration::from_millis(8));
        }
    }

    fn reveal_window(&self, ctx: &egui::Context, frame: &eframe::Frame) {
        ctx.send_viewport_cmd(ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(ViewportCommand::Focus);
        if let Some(hwnd) = extract_hwnd(frame) {
            unsafe {
                if IsIconic(hwnd).as_bool() {
                    let _ = ShowWindow(hwnd, SW_RESTORE);
                } else {
                    let _ = ShowWindow(hwnd, SW_SHOW);
                }
                let _ = SetForegroundWindow(hwnd);
            }
            if !self.state.user_has_custom_dragged {
                apply_win11_rounded_corners_and_position(hwnd, true);
            }
        }
    }

    fn pump_events_and_commands(&mut self, ctx: &egui::Context, frame: &eframe::Frame) {
        if !self.dwm_initialized {
            if let Some(hwnd) = extract_hwnd(frame) {
                apply_win11_rounded_corners_and_position(hwnd, !self.state.user_has_custom_dragged);
                self.dwm_initialized = true;
            }
        }
        if !self.startup_trimmed && self.started_at.elapsed() >= Duration::from_secs(2) {
            self.startup_trimmed = true;
            trim_working_set();
        }

        let mut force_reveal = false;
        if let Some(tray) = &self.tray {
            for action in tray.drain_actions() {
                match action {
                    TrayAction::OpenWindow => {
                        self.state.window_visible = true;
                        force_reveal = true;
                    }
                    TrayAction::ToggleVpn => {
                        self.state.toggle_vpn();
                    }
                    TrayAction::OpenSettings => {
                        self.state.open_settings_dialog();
                        force_reveal = true;
                    }
                    TrayAction::OpenAbout => {
                        self.state.open_about_dialog();
                        force_reveal = true;
                    }
                    TrayAction::Exit => {
                        self.state.request_quit();
                    }
                }
            }
        }

        while let Ok(ev) = self.evt_rx.try_recv() {
            self.state.apply_event(ev);
        }

        if self.state.logout_after_disconnect
            && !self.state.tunnel_running
            && !self.state.is_connecting_vpn
        {
            self.state.logout_after_disconnect = false;
            self.state.request_logout(self.store.as_ref());
        }

        self.state.tick(Instant::now());

        if should_reveal_window(
            self.last_window_visible,
            self.state.window_visible,
            force_reveal,
        ) {
            self.reveal_window(ctx, frame);
        }
        if self.last_window_visible && !self.state.window_visible {
            trim_working_set();
        }
        self.last_window_visible = self.state.window_visible;

        for cmd in self.state.drain_commands() {
            let _ = self.cmd_tx.send(cmd);
        }

        if let Some(tray) = &mut self.tray {
            let visual = if self.state.is_connecting_vpn
                || (self.state.tunnel_running && !self.state.tunnel_verified)
            {
                TrayVisualState::Connecting
            } else if self.state.tunnel_running && self.state.tunnel_verified {
                TrayVisualState::Connected
            } else {
                TrayVisualState::Idle
            };
            tray.set_status(visual);
        }

        if ctx.input(|i| i.viewport().close_requested()) && !self.state.exit_ready {
            ctx.send_viewport_cmd(ViewportCommand::CancelClose);
            self.state.window_visible = false;
            self.last_window_visible = false;
            ctx.send_viewport_cmd(ViewportCommand::Visible(false));
            trim_working_set();
        }

        if self.state.exit_ready {
            ctx.send_viewport_cmd(ViewportCommand::Close);
        }
    }
}

impl eframe::App for FreetonDesktopApp {
    fn logic(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        self.pump_events_and_commands(ctx, frame);
        self.sync_direct_window_drag(ctx, frame);
        ctx.request_repaint_after(idle_repaint_interval(
            self.state.window_visible,
            self.state.tunnel_running,
        ));
    }

    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        render_root(ui, &mut self.state, self.store.as_ref());
        let ctx = ui.ctx().clone();
        self.sync_direct_window_drag(&ctx, frame);
    }

    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        ui::C_BG.to_normalized_gamma_f32()
    }
}

pub(crate) fn idle_repaint_interval(window_visible: bool, tunnel_running: bool) -> Duration {
    if !window_visible {
        Duration::from_secs(30)
    } else if tunnel_running {
        Duration::from_secs(1)
    } else {
        Duration::from_secs(5)
    }
}

pub(crate) fn is_virtual_gpu_adapter(
    name: &str,
    vendor: u32,
    device_type: wgpu::DeviceType,
) -> bool {
    if matches!(device_type, wgpu::DeviceType::VirtualGpu) {
        return true;
    }
    if matches!(vendor, 0x15ad | 0x80ee | 0x1af4 | 0x1234 | 0x1ab8) {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    [
        "vmware",
        "virtualbox",
        "vbox",
        "hyper-v",
        "basic display",
        "remote display",
        "parallels",
        "qemu",
        "virtio",
        "qxl",
        "citrix",
        "red hat",
    ]
    .iter()
    .any(|kw| lower.contains(kw))
}

pub(crate) fn adapter_selection_rank(
    name: &str,
    vendor: u32,
    device_type: wgpu::DeviceType,
    force_software: bool,
) -> u8 {
    let is_virtual = is_virtual_gpu_adapter(name, vendor, device_type);
    if force_software {
        return match device_type {
            wgpu::DeviceType::Cpu => 0,
            wgpu::DeviceType::IntegratedGpu if !is_virtual => 1,
            wgpu::DeviceType::DiscreteGpu if !is_virtual => 2,
            _ => 3,
        };
    }

    if is_virtual {
        return 3;
    }

    match device_type {
        wgpu::DeviceType::IntegratedGpu => 0,
        wgpu::DeviceType::DiscreteGpu => 1,
        wgpu::DeviceType::Cpu => 2,
        wgpu::DeviceType::Other | wgpu::DeviceType::VirtualGpu => 3,
    }
}

fn is_vm_or_remote_graphics_session() -> bool {
    if std::env::var_os("FREETON_SW_RENDER").is_some() {
        return true;
    }
    if unsafe { GetSystemMetrics(SM_REMOTESESSION) } != 0 {
        return true;
    }
    for dev_idx in 0..4 {
        let mut dev = DISPLAY_DEVICEW {
            cb: std::mem::size_of::<DISPLAY_DEVICEW>() as u32,
            ..Default::default()
        };
        if !unsafe { EnumDisplayDevicesW(None, dev_idx, &mut dev, 0) }.as_bool() {
            break;
        }
        let end = dev
            .DeviceString
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(dev.DeviceString.len());
        let name = String::from_utf16_lossy(&dev.DeviceString[..end]);
        if is_virtual_gpu_adapter(&name, 0, wgpu::DeviceType::Other) {
            return true;
        }
    }
    false
}

fn trim_working_set() {
    unsafe {
        let _ = SetProcessWorkingSetSize(GetCurrentProcess(), usize::MAX, usize::MAX);
    }
}

fn show_fatal_launch_error(message: &str) {
    let title: Vec<u16> = "Freeton VPN - Lỗi khởi động"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let body: Vec<u16> = message.encode_utf16().chain(Some(0)).collect();
    unsafe {
        let _ = MessageBoxW(
            None,
            PCWSTR(body.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_OK | MB_ICONERROR,
        );
    }
}

fn build_wgpu_configuration(force_software: bool) -> egui_wgpu::WgpuConfiguration {
    let mut setup = egui_wgpu::WgpuSetupCreateNew::without_display_handle();
    setup.instance_descriptor.backends = wgpu::Backends::DX12;
    setup.power_preference = wgpu::PowerPreference::LowPower;
    setup.device_descriptor = Arc::new(|adapter| {
        let _ = adapter;
        wgpu::DeviceDescriptor {
            label: Some("freeton_wgpu_device"),
            required_limits: wgpu::Limits {
                max_texture_dimension_2d: 2048,
                ..wgpu::Limits::downlevel_defaults()
            },
            ..Default::default()
        }
    });
    setup.native_adapter_selector = Some(Arc::new(move |adapters, surface| {
        let mut ranked: Vec<(&wgpu::Adapter, u8)> = adapters
            .iter()
            .filter(|a| surface.is_none_or(|s| a.is_surface_supported(s)))
            .map(|a| {
                let info = a.get_info();
                (
                    a,
                    adapter_selection_rank(&info.name, info.vendor, info.device_type, force_software),
                )
            })
            .collect();
        ranked.sort_by_key(|(_, rank)| *rank);
        ranked
            .into_iter()
            .next()
            .map(|(a, _)| a.clone())
            .ok_or_else(|| "No compatible DX12 graphics adapter found".to_owned())
    }));

    egui_wgpu::WgpuConfiguration {
        wgpu_setup: egui_wgpu::WgpuSetup::CreateNew(setup),
        ..Default::default()
    }
}

fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .try_init();
}

fn main() {
    init_logging();

    let Some(_single_instance) = acquire_single_instance() else {
        info!("Freeton VPN already running; activated existing window");
        return;
    };

    let mut viewport = ViewportBuilder::default()
        .with_title(WINDOW_TITLE)
        .with_app_id("pishun.FreetonVPN")
        .with_inner_size([WINDOW_WIDTH, WINDOW_HEIGHT])
        .with_min_inner_size([WINDOW_WIDTH, WINDOW_HEIGHT])
        .with_max_inner_size([WINDOW_WIDTH, WINDOW_HEIGHT])
        .with_decorations(false)
        .with_resizable(false)
        .with_taskbar(true);

    if let Some(icon) = load_embedded_icon() {
        viewport = viewport.with_icon(icon);
    }

    let prefer_software = is_vm_or_remote_graphics_session();
    let base_options = eframe::NativeOptions {
        viewport,
        persist_window: false,
        ..Default::default()
    };

    if prefer_software {
        let vm_wgpu_options = eframe::NativeOptions {
            renderer: Renderer::Wgpu,
            wgpu_options: build_wgpu_configuration(true),
            ..base_options.clone()
        };
        if let Err(wgpu_err) = eframe::run_native(
            WINDOW_TITLE,
            vm_wgpu_options,
            Box::new(|cc| Ok(Box::new(FreetonDesktopApp::new(cc)))),
        ) {
            warn!(error = %wgpu_err, "VM WARP wgpu renderer failed; falling back to glow OpenGL");
            let glow_options = eframe::NativeOptions {
                renderer: Renderer::Glow,
                ..base_options
            };
            if let Err(glow_err) = eframe::run_native(
                WINDOW_TITLE,
                glow_options,
                Box::new(|cc| Ok(Box::new(FreetonDesktopApp::new(cc)))),
            ) {
                error!(wgpu = %wgpu_err, glow = %glow_err, "all graphics backends failed");
                show_fatal_launch_error(&format!(
                    "Không thể khởi tạo giao diện đồ họa.\n\nDX12 WARP (wgpu): {wgpu_err}\nOpenGL (glow): {glow_err}"
                ));
            }
        }
        return;
    }

    let glow_options = eframe::NativeOptions {
        renderer: Renderer::Glow,
        ..base_options.clone()
    };
    if let Err(glow_err) = eframe::run_native(
        WINDOW_TITLE,
        glow_options,
        Box::new(|cc| Ok(Box::new(FreetonDesktopApp::new(cc)))),
    ) {
        warn!(error = %glow_err, "glow OpenGL renderer failed; falling back to wgpu DX12");
        let wgpu_options = eframe::NativeOptions {
            renderer: Renderer::Wgpu,
            wgpu_options: build_wgpu_configuration(false),
            ..base_options.clone()
        };
        if let Err(wgpu_err) = eframe::run_native(
            WINDOW_TITLE,
            wgpu_options,
            Box::new(|cc| Ok(Box::new(FreetonDesktopApp::new(cc)))),
        ) {
            warn!(error = %wgpu_err, "wgpu DX12 hardware failed; falling back to DX12 WARP");
            let warp_options = eframe::NativeOptions {
                renderer: Renderer::Wgpu,
                wgpu_options: build_wgpu_configuration(true),
                ..base_options
            };
            if let Err(warp_err) = eframe::run_native(
                WINDOW_TITLE,
                warp_options,
                Box::new(|cc| Ok(Box::new(FreetonDesktopApp::new(cc)))),
            ) {
                error!(glow = %glow_err, wgpu = %wgpu_err, warp = %warp_err, "all graphics backends failed");
                show_fatal_launch_error(&format!(
                    "Không thể khởi tạo giao diện đồ họa.\n\nOpenGL (glow): {glow_err}\nDX12 (wgpu): {wgpu_err}\nDX12 WARP: {warp_err}"
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        adapter_selection_rank, compute_window_drag_position, idle_repaint_interval,
        is_virtual_gpu_adapter, should_reveal_window,
    };
    use eframe::wgpu;

    #[test]
    fn test_window_reveal_transition_handles_tray_and_background_events() {
        assert!(should_reveal_window(false, true, false));
        assert!(should_reveal_window(true, true, true));
        assert!(!should_reveal_window(true, true, false));
        assert!(!should_reveal_window(false, false, true));
    }

    #[test]
    fn test_compute_window_drag_position_tracks_cursor_delta_1_to_1() {
        assert_eq!(
            compute_window_drag_position(1200, 300, 1300, 320, 1250, 365),
            (1150, 345)
        );
    }

    #[test]
    fn test_virtual_gpu_detection_and_adapter_priority_prefers_cpu_over_virtual() {
        assert!(is_virtual_gpu_adapter("VMware SVGA 3D", 0x15ad, wgpu::DeviceType::VirtualGpu));
        assert!(is_virtual_gpu_adapter("VirtualBox Graphics Adapter", 0x80ee, wgpu::DeviceType::Other));
        assert!(is_virtual_gpu_adapter("Microsoft Basic Display Adapter", 0x1414, wgpu::DeviceType::Other));
        assert!(is_virtual_gpu_adapter("Microsoft Hyper-V Video", 0x1414, wgpu::DeviceType::VirtualGpu));
        assert!(is_virtual_gpu_adapter("Red Hat VirtIO GPU", 0x1af4, wgpu::DeviceType::VirtualGpu));
        assert!(!is_virtual_gpu_adapter("Intel(R) UHD Graphics 770", 0x8086, wgpu::DeviceType::IntegratedGpu));
        assert!(!is_virtual_gpu_adapter("NVIDIA GeForce RTX 3060", 0x10de, wgpu::DeviceType::DiscreteGpu));

        let integrated_rank = adapter_selection_rank("Intel UHD", 0x8086, wgpu::DeviceType::IntegratedGpu, false);
        let discrete_rank = adapter_selection_rank("NVIDIA RTX", 0x10de, wgpu::DeviceType::DiscreteGpu, false);
        let cpu_rank = adapter_selection_rank("Microsoft Basic Render Driver", 0x1414, wgpu::DeviceType::Cpu, false);
        let virtual_rank = adapter_selection_rank("VMware SVGA 3D", 0x15ad, wgpu::DeviceType::VirtualGpu, false);
        assert!(integrated_rank < discrete_rank);
        assert!(discrete_rank < cpu_rank);
        assert!(cpu_rank < virtual_rank);

        let sw_cpu_rank = adapter_selection_rank("Microsoft Basic Render Driver", 0x1414, wgpu::DeviceType::Cpu, true);
        let sw_gpu_rank = adapter_selection_rank("Intel UHD", 0x8086, wgpu::DeviceType::IntegratedGpu, true);
        assert!(sw_cpu_rank < sw_gpu_rank);
    }

    #[test]
    fn test_idle_repaint_interval_scales_by_visibility_and_tunnel() {
        use std::time::Duration;
        assert!(idle_repaint_interval(false, false) >= Duration::from_secs(15));
        assert!(idle_repaint_interval(false, true) >= Duration::from_secs(15));
        assert!(idle_repaint_interval(true, false) >= Duration::from_secs(3));
        assert_eq!(idle_repaint_interval(true, true), Duration::from_secs(1));
    }
}
