#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

pub mod captcha;
pub mod state;
pub mod tray;
pub mod ui;

use std::sync::Arc;
use std::time::Instant;

use eframe::egui::{self, ViewportBuilder, ViewportCommand};
use freeton_core::storage::{CredentialStore, WindowsCredentialStore};
use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use windows::core::{w, BOOL, PCWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE, HWND, RECT, TRUE,
};
use windows::Win32::Graphics::Dwm::{
    DwmSetWindowAttribute, DWMWA_USE_IMMERSIVE_DARK_MODE, DWMWINDOWATTRIBUTE,
};
use windows::Win32::System::Threading::CreateMutexW;
use windows::Win32::UI::WindowsAndMessaging::{
    FindWindowW, GetWindowRect, IsIconic, SetForegroundWindow, SetWindowPos, ShowWindow,
    SystemParametersInfoW, SPI_GETWORKAREA, SWP_NOACTIVATE, SWP_NOSIZE, SWP_NOZORDER, SW_RESTORE,
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

struct FreetonDesktopApp {
    state: AppState,
    store: Arc<dyn CredentialStore>,
    _runtime: tokio::runtime::Runtime,
    cmd_tx: mpsc::UnboundedSender<UiCommand>,
    evt_rx: mpsc::UnboundedReceiver<WorkerEvent>,
    tray: Option<TrayController>,
    dwm_initialized: bool,
}

impl FreetonDesktopApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        configure_fonts_and_style(&cc.egui_ctx);

        let store: Arc<dyn CredentialStore> = Arc::new(WindowsCredentialStore::new());
        let mut state = AppState::from_local_storage(store.as_ref());

        let wake_ctx = cc.egui_ctx.clone();
        let on_wake: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            wake_ctx.request_repaint();
        });

        let (runtime, cmd_tx, evt_rx) =
            spawn_worker_runtime(WorkerDeps::production(), Arc::clone(&on_wake));

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
        }
    }

    fn pump_events_and_commands(&mut self, ctx: &egui::Context, frame: &eframe::Frame) {
        if !self.dwm_initialized {
            if let Some(hwnd) = extract_hwnd(frame) {
                apply_win11_rounded_corners_and_position(hwnd, !self.state.user_has_custom_dragged);
                self.dwm_initialized = true;
            }
        }

        if let Some(tray) = &self.tray {
            for action in tray.drain_actions() {
                match action {
                    TrayAction::OpenWindow => {
                        self.state.window_visible = true;
                        ctx.send_viewport_cmd(ViewportCommand::Visible(true));
                        ctx.send_viewport_cmd(ViewportCommand::Focus);
                        if let Some(hwnd) = extract_hwnd(frame) {
                            unsafe {
                                let _ = ShowWindow(hwnd, SW_SHOW);
                                let _ = SetForegroundWindow(hwnd);
                            }
                            if !self.state.user_has_custom_dragged {
                                apply_win11_rounded_corners_and_position(hwnd, true);
                            }
                        }
                    }
                    TrayAction::ToggleVpn => {
                        self.state.toggle_vpn();
                    }
                    TrayAction::OpenSettings => {
                        self.state.open_settings_dialog();
                        ctx.send_viewport_cmd(ViewportCommand::Visible(true));
                        ctx.send_viewport_cmd(ViewportCommand::Focus);
                    }
                    TrayAction::OpenAbout => {
                        self.state.open_about_dialog();
                        ctx.send_viewport_cmd(ViewportCommand::Visible(true));
                        ctx.send_viewport_cmd(ViewportCommand::Focus);
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
            ctx.send_viewport_cmd(ViewportCommand::Visible(false));
        }

        if self.state.exit_ready {
            ctx.send_viewport_cmd(ViewportCommand::Close);
        }
    }
}

impl eframe::App for FreetonDesktopApp {
    fn logic(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        self.pump_events_and_commands(ctx, frame);
        ctx.request_repaint_after(std::time::Duration::from_millis(500));
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        render_root(ui, &mut self.state, self.store.as_ref());
    }

    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        ui::C_BG.to_normalized_gamma_f32()
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

    let options = eframe::NativeOptions {
        viewport,
        persist_window: false,
        ..Default::default()
    };

    if let Err(err) = eframe::run_native(
        WINDOW_TITLE,
        options,
        Box::new(|cc| Ok(Box::new(FreetonDesktopApp::new(cc)))),
    ) {
        error!(error = %err, "eframe run_native failed");
    }
}
