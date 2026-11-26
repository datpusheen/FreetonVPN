use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use freeton_core::api::HumanVerificationChallenge;
use serde_json::Value;
use thiserror::Error;
use tracing::{debug, warn};
use url::Url;
use webview2_com::Microsoft::Web::WebView2::Win32::{
    CreateCoreWebView2EnvironmentWithOptions, ICoreWebView2, ICoreWebView2Controller,
    ICoreWebView2Controller2, ICoreWebView2Environment, ICoreWebView2EnvironmentOptions,
    COREWEBVIEW2_COLOR,
};
use webview2_com::{
    AddScriptToExecuteOnDocumentCreatedCompletedHandler, CoTaskMemPWSTR,
    CoreWebView2EnvironmentOptions, CreateCoreWebView2ControllerCompletedHandler,
    CreateCoreWebView2EnvironmentCompletedHandler, NavigationStartingEventHandler,
    NewWindowRequestedEventHandler, WebMessageReceivedEventHandler,
};
use windows::core::{w, Interface, BOOL, HRESULT, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    COLORREF, ERROR_CLASS_ALREADY_EXISTS, HINSTANCE, HWND, LPARAM, LRESULT, RECT, TRUE, WPARAM,
};
use windows::Win32::Graphics::Dwm::{
    DwmSetWindowAttribute, DWMWA_USE_IMMERSIVE_DARK_MODE, DWMWINDOWATTRIBUTE,
};
use windows::Win32::Graphics::Gdi::{CreateSolidBrush, DeleteObject, FillRect, HBRUSH, HDC};
use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::HiDpi::{AdjustWindowRectExForDpi, GetDpiForSystem};
use windows::Win32::UI::Input::KeyboardAndMouse::SetFocus;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetClientRect, GetMessageW,
    GetSystemMetrics, GetWindowLongPtrW, IsWindow, KillTimer, LoadCursorW, PostMessageW,
    PostQuitMessage, RegisterClassExW, SetForegroundWindow, SetTimer, SetWindowLongPtrW,
    ShowWindow, SystemParametersInfoW, TranslateMessage, GWLP_USERDATA, IDC_ARROW, MSG,
    SM_CXSCREEN, SM_CYSCREEN, SPI_GETWORKAREA, SW_SHOW, SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS,
    WINDOW_EX_STYLE, WM_APP, WM_CLOSE, WM_DESTROY, WM_ERASEBKGND, WM_SIZE, WM_TIMER, WNDCLASSEXW,
    WS_CAPTION, WS_CLIPCHILDREN, WS_MINIMIZEBOX, WS_OVERLAPPED, WS_SYSMENU, WS_THICKFRAME,
};

const ALLOWED_CAPTCHA_HOSTS: &[&str] = &[
    "verify.proton.me",
    "account.proton.me",
    "account.protonvpn.com",
];

const TOKEN_KEYS: &[&str] = &[
    "Token",
    "token",
    "verificationToken",
    "HumanVerificationToken",
    "humanVerificationToken",
];

const TOKEN_MIN_LEN: usize = 20;
const TOKEN_MAX_LEN: usize = 8192;
const MAX_JSON_NESTING_DEPTH: u8 = 2;

const MODAL_LOGICAL_WIDTH: i32 = 520;
const MODAL_LOGICAL_HEIGHT: i32 = 720;
const MODAL_BG_COLORREF: u32 = 0x0019_1410; // #101419 in Win32 BGR
const CAPTCHA_TIMER_ID: usize = 1;
const CAPTCHA_TIMER_INTERVAL_MS: u32 = 250;
const WM_APP_COMPLETE: u32 = WM_APP + 1;
const DWMWA_USE_IMMERSIVE_DARK_MODE_LEGACY: DWMWINDOWATTRIBUTE = DWMWINDOWATTRIBUTE(19);
const HRESULT_ERROR_FILE_NOT_FOUND: i32 = 0x8007_0002_u32 as i32;

const CAPTCHA_CAPTURE_SCRIPT: &str = r#"(() => {
  if (window !== window.top) return;
  if (window.__freetonCaptchaCaptureInstalled) return;
  window.__freetonCaptchaCaptureInstalled = true;
  const ALLOWED_ORIGIN_RE = /^https:\/\/([a-z0-9-]+\.)*(proton\.me|protonvpn\.com)$/i;
  const isAllowedOrigin = (origin) =>
    typeof origin === "string" &&
    ((origin === window.location.origin && /^https:\/\//i.test(origin)) ||
      ALLOWED_ORIGIN_RE.test(origin));
  const TOKEN_KEYS = [
    "Token",
    "token",
    "verificationToken",
    "HumanVerificationToken",
    "humanVerificationToken"
  ];
  let lastSent = "";
  const forward = (value) => {
    if (typeof value !== "string") return;
    const trimmed = value.trim();
    if (
      value.length < 20 ||
      value.length > 8192 ||
      trimmed.length < 20 ||
      /^https?:\/\//i.test(trimmed)
    ) {
      return;
    }
    if (value === lastSent) return;
    lastSent = value;
    try {
      window.chrome?.webview?.postMessage(value);
    } catch (_) {}
  };
  window.addEventListener("message", (event) => {
    if (!isAllowedOrigin(event.origin)) return;
    const data = event.data;
    if (typeof data === "string") {
      const trimmed = data.trim();
      if (trimmed.startsWith("{")) {
        try {
          const parsed = JSON.parse(trimmed);
          if (parsed && typeof parsed === "object") {
            for (const key of TOKEN_KEYS) {
              forward(parsed[key]);
            }
          }
        } catch (_) {}
      } else {
        forward(data);
      }
      return;
    }
    if (data && typeof data === "object") {
      for (const key of TOKEN_KEYS) {
        forward(data[key]);
      }
    }
  }, false);
})();"#;

static RUN_SEQUENCE: AtomicU64 = AtomicU64::new(1);
static WINDOW_CLASS_REGISTERED: OnceLock<Result<(), String>> = OnceLock::new();

/// Errors returned while validating or running the transient WebView2 CAPTCHA modal.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CaptchaError {
    #[error("URL xác minh người dùng (CAPTCHA) không hợp lệ: {0}")]
    InvalidUrl(String),
    #[error("Người dùng đã đóng cửa sổ xác minh CAPTCHA.")]
    Cancelled,
    #[error("Hết thời gian chờ xác minh CAPTCHA.")]
    Timeout,
    #[error("Không thể khởi tạo cửa sổ xác minh WebView2: {0}")]
    WebView(String),
}

fn parse_allowed_captcha_url(raw_url: &str) -> Result<Url, CaptchaError> {
    let trimmed = raw_url.trim();
    let url = Url::parse(trimmed)
        .map_err(|err| CaptchaError::InvalidUrl(format!("URL không hợp lệ: {err}")))?;

    if url.scheme() != "https" {
        return Err(CaptchaError::InvalidUrl(format!(
            "Chỉ chấp nhận giao thức HTTPS: {trimmed}"
        )));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(CaptchaError::InvalidUrl(
            "URL xác minh không được chứa thông tin xác thực nhúng.".to_owned(),
        ));
    }
    if url.port().is_some() {
        return Err(CaptchaError::InvalidUrl(
            "URL xác minh không được dùng cổng tùy chỉnh.".to_owned(),
        ));
    }

    let host = url
        .host_str()
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if !ALLOWED_CAPTCHA_HOSTS.contains(&host.as_str()) {
        return Err(CaptchaError::InvalidUrl(format!(
            "Miền xác minh không được phép: {host}"
        )));
    }

    Ok(url)
}

/// Returns `true` when `raw_url` uses HTTPS on an allowlisted Proton verification host.
pub fn is_allowed_captcha_url(raw_url: &str) -> bool {
    parse_allowed_captcha_url(raw_url).is_ok()
}

/// Validates a Proton CAPTCHA URL and normalizes `ForceWebMessaging=1` while preserving existing
/// query parameters and fragments.
pub fn validate_captcha_url(raw_url: &str) -> Result<String, CaptchaError> {
    let mut url = parse_allowed_captcha_url(raw_url)?;
    let preserved_pairs: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(key, _)| key != "ForceWebMessaging")
        .map(|(key, val)| (key.into_owned(), val.into_owned()))
        .collect();
    {
        let mut query = url.query_pairs_mut();
        query.clear();
        for (key, val) in preserved_pairs {
            query.append_pair(&key, &val);
        }
        query.append_pair("ForceWebMessaging", "1");
    }
    Ok(url.to_string())
}

fn is_valid_token(value: &str) -> bool {
    let trimmed = value.trim();
    if value.len() < TOKEN_MIN_LEN
        || value.len() > TOKEN_MAX_LEN
        || trimmed.len() < TOKEN_MIN_LEN
        || value.chars().any(char::is_control)
    {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    !lower.starts_with("http://") && !lower.starts_with("https://")
}

fn extract_token_inner(raw: &str, depth: u8) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    if trimmed.starts_with('{') {
        let parsed: Value = serde_json::from_str(trimmed).ok()?;
        let Value::Object(map) = parsed else {
            return None;
        };
        for key in TOKEN_KEYS {
            if let Some(Value::String(candidate)) = map.get(*key) {
                if is_valid_token(candidate) {
                    return Some(candidate.clone());
                }
            }
        }
        return None;
    }

    if trimmed.starts_with('"') {
        if depth >= MAX_JSON_NESTING_DEPTH {
            return None;
        }
        let parsed: Value = serde_json::from_str(trimmed).ok()?;
        return match parsed {
            Value::String(inner) => extract_token_inner(&inner, depth + 1),
            _ => None,
        };
    }

    if trimmed.starts_with('[') || matches!(trimmed, "null" | "true" | "false") {
        return None;
    }

    is_valid_token(raw).then(|| raw.to_owned())
}

/// Extracts a Proton human verification token from either a raw string or JSON `postMessage`
/// payload (`Token`, `token`, `verificationToken`, `HumanVerificationToken`,
/// `humanVerificationToken`), ignoring short strings, control characters, and `http(s)://` URLs.
pub fn extract_token_from_post_message(raw: &str) -> Option<String> {
    extract_token_inner(raw, 0)
}

fn default_captcha_user_data_base() -> PathBuf {
    let root = std::env::var_os("LOCALAPPDATA")
        .filter(|val| !val.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    root.join("FreetonVPN").join("webview2-captcha")
}

/// Builds a unique per-run WebView2 user data directory path under `base_dir`.
pub fn build_per_run_user_data_dir(base_dir: &Path) -> PathBuf {
    let pid = std::process::id();
    let seq = RUN_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    base_dir.join(format!("run-{pid}-{nanos}-{seq}"))
}

fn cleanup_stale_user_data_dirs(base_dir: &Path) {
    let Ok(entries) = fs::read_dir(base_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_run_dir = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|name| name.starts_with("run-"));
        if is_run_dir && path.is_dir() {
            let _ = fs::remove_dir_all(path);
        }
    }
}

fn cleanup_run_user_data_dir(run_dir: &Path) {
    if !run_dir.exists() {
        return;
    }
    for attempt in 0..5 {
        match fs::remove_dir_all(run_dir) {
            Ok(()) => return,
            Err(_) if attempt < 4 => thread::sleep(Duration::from_millis(30)),
            Err(err) => {
                debug!(
                    path = %run_dir.display(),
                    error = %err,
                    "deferring locked WebView2 captcha profile cleanup"
                );
                return;
            }
        }
    }
}

/// Opens a transient, isolated Edge WebView2 modal window for Proton human verification and
/// blocks until a verification token is captured, the window is closed (`Cancelled`), or
/// `timeout` expires (`Timeout`).
pub fn solve_captcha_blocking(url: &str, timeout: Duration) -> Result<String, CaptchaError> {
    let validated_url = validate_captcha_url(url)?;
    if timeout.is_zero() {
        return Err(CaptchaError::Timeout);
    }

    let handle = thread::Builder::new()
        .name("freeton-captcha-webview".to_owned())
        .spawn(move || run_captcha_sta_thread(&validated_url, timeout))
        .map_err(|err| CaptchaError::WebView(format!("Không thể tạo luồng WebView2 STA: {err}")))?;

    handle.join().map_err(|_| {
        CaptchaError::WebView("Luồng cửa sổ xác minh WebView2 bị dừng đột ngột.".to_owned())
    })?
}

/// Convenience wrapper for [`solve_captcha_blocking`] consuming [`HumanVerificationChallenge`].
pub fn solve_challenge_blocking(
    challenge: &HumanVerificationChallenge,
    timeout: Duration,
) -> Result<String, CaptchaError> {
    solve_captcha_blocking(&challenge.url, timeout)
}

struct ComApartmentGuard;

impl ComApartmentGuard {
    fn enter() -> Result<Self, CaptchaError> {
        let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
        hr.ok().map_err(|err| {
            CaptchaError::WebView(format!("Không thể khởi tạo COM STA cho WebView2: {err}"))
        })?;
        Ok(Self)
    }
}

impl Drop for ComApartmentGuard {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

struct ModalState {
    deadline: Option<Instant>,
    bg_brush: HBRUSH,
    closing: bool,
    outcome: Option<Result<String, CaptchaError>>,
    environment: Option<ICoreWebView2Environment>,
    controller: Option<ICoreWebView2Controller>,
    webview: Option<ICoreWebView2>,
}

impl Drop for ModalState {
    fn drop(&mut self) {
        if !self.bg_brush.0.is_null() {
            unsafe {
                let _ = DeleteObject(self.bg_brush.into());
            }
            self.bg_brush = HBRUSH::default();
        }
    }
}

fn run_captcha_sta_thread(url: &str, timeout: Duration) -> Result<String, CaptchaError> {
    let _com = ComApartmentGuard::enter()?;

    let base_dir = default_captcha_user_data_base();
    fs::create_dir_all(&base_dir).map_err(|err| {
        CaptchaError::WebView(format!(
            "Không thể tạo thư mục dữ liệu WebView2 ({}): {err}",
            base_dir.display()
        ))
    })?;
    cleanup_stale_user_data_dirs(&base_dir);

    let user_data_dir = build_per_run_user_data_dir(&base_dir);
    fs::create_dir_all(&user_data_dir).map_err(|err| {
        CaptchaError::WebView(format!(
            "Không thể tạo hồ sơ tạm WebView2 ({}): {err}",
            user_data_dir.display()
        ))
    })?;

    let result = run_modal_on_sta(url, &user_data_dir, timeout);
    cleanup_run_user_data_dir(&user_data_dir);
    result
}

fn register_captcha_window_class(hinstance: HINSTANCE) -> Result<(), CaptchaError> {
    let res = WINDOW_CLASS_REGISTERED.get_or_init(|| {
        let cursor = unsafe { LoadCursorW(None, IDC_ARROW) }.unwrap_or_default();
        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(captcha_wndproc),
            hInstance: hinstance,
            hCursor: cursor,
            lpszClassName: w!("FreetonVpnCaptchaModal"),
            ..Default::default()
        };
        let atom = unsafe { RegisterClassExW(&wc) };
        if atom == 0 {
            let err = windows::core::Error::from_thread();
            if err.code() != HRESULT::from(ERROR_CLASS_ALREADY_EXISTS) {
                return Err(format!("RegisterClassExW thất bại: {err}"));
            }
        }
        Ok(())
    });

    res.clone().map_err(CaptchaError::WebView)
}

fn apply_dark_titlebar(hwnd: HWND) {
    let use_dark: BOOL = TRUE;
    let size = std::mem::size_of::<BOOL>() as u32;
    let first = unsafe {
        DwmSetWindowAttribute(
            hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE,
            (&raw const use_dark).cast(),
            size,
        )
    };
    if first.is_err() {
        let _ = unsafe {
            DwmSetWindowAttribute(
                hwnd,
                DWMWA_USE_IMMERSIVE_DARK_MODE_LEGACY,
                (&raw const use_dark).cast(),
                size,
            )
        };
    }
}

fn compute_centered_window_rect(
    style: windows::Win32::UI::WindowsAndMessaging::WINDOW_STYLE,
    ex_style: WINDOW_EX_STYLE,
) -> RECT {
    let dpi = unsafe { GetDpiForSystem() }.max(96);
    let client_w = (MODAL_LOGICAL_WIDTH * dpi as i32) / 96;
    let client_h = (MODAL_LOGICAL_HEIGHT * dpi as i32) / 96;

    let mut adjusted = RECT {
        left: 0,
        top: 0,
        right: client_w,
        bottom: client_h,
    };
    let _ = unsafe { AdjustWindowRectExForDpi(&mut adjusted, style, false, ex_style, dpi) };
    let mut win_w = adjusted.right - adjusted.left;
    let mut win_h = adjusted.bottom - adjusted.top;

    let mut work_area = RECT::default();
    let got_work_area = unsafe {
        SystemParametersInfoW(
            SPI_GETWORKAREA,
            0,
            Some((&raw mut work_area).cast()),
            SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
        )
    }
    .is_ok();

    if !got_work_area {
        work_area = RECT {
            left: 0,
            top: 0,
            right: unsafe { GetSystemMetrics(SM_CXSCREEN) }.max(win_w),
            bottom: unsafe { GetSystemMetrics(SM_CYSCREEN) }.max(win_h),
        };
    }

    let avail_w = (work_area.right - work_area.left).max(320);
    let avail_h = (work_area.bottom - work_area.top).max(320);
    win_w = win_w.min(avail_w);
    win_h = win_h.min(avail_h);

    let x = work_area.left + (avail_w - win_w) / 2;
    let y = work_area.top + (avail_h - win_h) / 2;

    RECT {
        left: x,
        top: y,
        right: x + win_w,
        bottom: y + win_h,
    }
}

fn run_modal_on_sta(
    url: &str,
    user_data_dir: &Path,
    timeout: Duration,
) -> Result<String, CaptchaError> {
    let module = unsafe { GetModuleHandleW(None) }
        .map_err(|err| CaptchaError::WebView(format!("GetModuleHandleW thất bại: {err}")))?;
    let hinstance = HINSTANCE(module.0);

    register_captcha_window_class(hinstance)?;

    let style =
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_THICKFRAME | WS_CLIPCHILDREN;
    let ex_style = WINDOW_EX_STYLE::default();
    let window_rect = compute_centered_window_rect(style, ex_style);

    let bg_brush = unsafe { CreateSolidBrush(COLORREF(MODAL_BG_COLORREF)) };
    let state = Rc::new(RefCell::new(ModalState {
        deadline: Instant::now().checked_add(timeout),
        bg_brush,
        closing: false,
        outcome: None,
        environment: None,
        controller: None,
        webview: None,
    }));

    let hwnd = unsafe {
        CreateWindowExW(
            ex_style,
            w!("FreetonVpnCaptchaModal"),
            w!("Xác minh bảo mật - Freeton VPN"),
            style,
            window_rect.left,
            window_rect.top,
            window_rect.right - window_rect.left,
            window_rect.bottom - window_rect.top,
            None,
            None,
            Some(hinstance),
            None,
        )
    }
    .map_err(|err| CaptchaError::WebView(format!("Không thể tạo cửa sổ modal: {err}")))?;

    let state_raw = Rc::into_raw(state.clone());
    unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, state_raw as isize) };

    apply_dark_titlebar(hwnd);
    unsafe {
        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = SetForegroundWindow(hwnd);
        let _ = SetFocus(Some(hwnd));
        let _ = SetTimer(
            Some(hwnd),
            CAPTCHA_TIMER_ID,
            CAPTCHA_TIMER_INTERVAL_MS,
            None,
        );
    }

    if let Err(err) = start_webview2_session(hwnd, &state, url, user_data_dir) {
        finish_modal_with_result(&state, hwnd, Err(err));
    }

    let mut msg = MSG::default();
    loop {
        let status = unsafe { GetMessageW(&mut msg, None, 0, 0).0 };
        if status == -1 {
            let err = windows::core::Error::from_thread();
            let mut guard = state.borrow_mut();
            if guard.outcome.is_none() {
                guard.outcome = Some(Err(CaptchaError::WebView(format!(
                    "Lỗi vòng lặp thông điệp Win32: {err}"
                ))));
            }
            break;
        }
        if status == 0 {
            break;
        }
        unsafe {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    if unsafe { IsWindow(Some(hwnd)).as_bool() } {
        unsafe {
            let _ = DestroyWindow(hwnd);
        }
    }

    let outcome = state
        .borrow_mut()
        .outcome
        .take()
        .unwrap_or(Err(CaptchaError::Cancelled));
    outcome
}

fn map_webview_init_error(err: &windows::core::Error) -> CaptchaError {
    if err.code().0 == HRESULT_ERROR_FILE_NOT_FOUND {
        CaptchaError::WebView(
            "Không tìm thấy Microsoft Edge WebView2 Runtime trên máy. Vui lòng cài Edge WebView2 Runtime để hoàn tất xác minh CAPTCHA."
                .to_owned(),
        )
    } else {
        CaptchaError::WebView(format!("WebView2 lỗi ({}): {err}", err.code()))
    }
}

fn finish_modal_with_result(
    state: &Rc<RefCell<ModalState>>,
    hwnd: HWND,
    result: Result<String, CaptchaError>,
) {
    let should_post = {
        let mut guard = state.borrow_mut();
        if guard.outcome.is_none() {
            guard.outcome = Some(result);
        }
        if guard.closing {
            false
        } else {
            guard.closing = true;
            true
        }
    };

    if should_post {
        unsafe {
            let _ = PostMessageW(Some(hwnd), WM_APP_COMPLETE, WPARAM(0), LPARAM(0));
        }
    }
}

fn start_webview2_session(
    hwnd: HWND,
    state: &Rc<RefCell<ModalState>>,
    url: &str,
    user_data_dir: &Path,
) -> Result<(), CaptchaError> {
    let options: ICoreWebView2EnvironmentOptions = CoreWebView2EnvironmentOptions::default().into();
    let user_data_pwstr = CoTaskMemPWSTR::from(user_data_dir.to_string_lossy().as_ref());
    let target_url = url.to_owned();
    let weak_state = Rc::downgrade(state);

    let env_handler = CreateCoreWebView2EnvironmentCompletedHandler::create(Box::new(
        move |error_code, environment| {
            let Some(state) = weak_state.upgrade() else {
                return Ok(());
            };
            if let Err(err) = error_code {
                finish_modal_with_result(&state, hwnd, Err(map_webview_init_error(&err)));
                return Ok(());
            }
            let Some(environment) = environment else {
                finish_modal_with_result(
                    &state,
                    hwnd,
                    Err(CaptchaError::WebView(
                        "WebView2 không trả về ICoreWebView2Environment.".to_owned(),
                    )),
                );
                return Ok(());
            };

            let should_abort = {
                let mut guard = state.borrow_mut();
                if guard.closing || guard.outcome.is_some() {
                    true
                } else {
                    guard.environment = Some(environment.clone());
                    false
                }
            };
            if should_abort {
                return Ok(());
            }

            let weak_for_controller = Rc::downgrade(&state);
            let url_for_controller = target_url.clone();
            let controller_handler = CreateCoreWebView2ControllerCompletedHandler::create(
                Box::new(move |ctrl_err, controller| {
                    let Some(state) = weak_for_controller.upgrade() else {
                        if let Some(ctrl) = controller {
                            unsafe {
                                let _ = ctrl.Close();
                            }
                        }
                        return Ok(());
                    };
                    if let Err(err) = ctrl_err {
                        finish_modal_with_result(
                            &state,
                            hwnd,
                            Err(CaptchaError::WebView(format!(
                                "Không thể tạo WebView2 controller: {err}"
                            ))),
                        );
                        return Ok(());
                    }
                    let Some(controller) = controller else {
                        finish_modal_with_result(
                            &state,
                            hwnd,
                            Err(CaptchaError::WebView(
                                "WebView2 không trả về ICoreWebView2Controller.".to_owned(),
                            )),
                        );
                        return Ok(());
                    };

                    let already_closing = {
                        let guard = state.borrow();
                        guard.closing || guard.outcome.is_some()
                    };
                    if already_closing {
                        unsafe {
                            let _ = controller.Close();
                        }
                        return Ok(());
                    }

                    if let Err(err) = configure_and_navigate_webview(
                        hwnd,
                        &state,
                        controller,
                        &url_for_controller,
                    ) {
                        finish_modal_with_result(&state, hwnd, Err(err));
                    }
                    Ok(())
                }),
            );

            if let Err(err) =
                unsafe { environment.CreateCoreWebView2Controller(hwnd, &controller_handler) }
            {
                finish_modal_with_result(
                    &state,
                    hwnd,
                    Err(CaptchaError::WebView(format!(
                        "CreateCoreWebView2Controller thất bại: {err}"
                    ))),
                );
            }
            Ok(())
        },
    ));

    unsafe {
        CreateCoreWebView2EnvironmentWithOptions(
            PCWSTR::null(),
            *user_data_pwstr.as_ref().as_pcwstr(),
            &options,
            &env_handler,
        )
    }
    .map_err(|err| map_webview_init_error(&err))
}

fn configure_and_navigate_webview(
    hwnd: HWND,
    state: &Rc<RefCell<ModalState>>,
    controller: ICoreWebView2Controller,
    target_url: &str,
) -> Result<(), CaptchaError> {
    let mut client_rect = RECT::default();
    unsafe {
        let _ = GetClientRect(hwnd, &mut client_rect);
        controller.SetBounds(client_rect).map_err(|err| {
            CaptchaError::WebView(format!("Không thể đặt kích thước WebView2: {err}"))
        })?;
        if let Ok(controller2) = controller.cast::<ICoreWebView2Controller2>() {
            let _ = controller2.SetDefaultBackgroundColor(COREWEBVIEW2_COLOR {
                A: 255,
                R: 0x10,
                G: 0x14,
                B: 0x19,
            });
        }
        let _ = controller.SetIsVisible(true);
    }

    let webview = unsafe { controller.CoreWebView2() }
        .map_err(|err| CaptchaError::WebView(format!("Không thể truy cập CoreWebView2: {err}")))?;

    if let Ok(settings) = unsafe { webview.Settings() } {
        unsafe {
            let _ = settings.SetAreDevToolsEnabled(false);
            let _ = settings.SetAreDefaultContextMenusEnabled(false);
            let _ = settings.SetIsStatusBarEnabled(false);
        }
    }

    let nav_handler = NavigationStartingEventHandler::create(Box::new(move |_sender, args| {
        let Some(args) = args else {
            return Ok(());
        };
        let mut raw_uri = PWSTR::null();
        if unsafe { args.Uri(&mut raw_uri) }.is_ok() {
            let uri = CoTaskMemPWSTR::from(raw_uri).to_string();
            if !is_allowed_captcha_url(&uri) {
                warn!(
                    uri = %uri,
                    "blocked disallowed top-level navigation inside CAPTCHA modal"
                );
                let _ = unsafe { args.SetCancel(true) };
            }
        } else {
            let _ = unsafe { args.SetCancel(true) };
        }
        Ok(())
    }));
    let mut nav_token = 0;
    unsafe { webview.add_NavigationStarting(&nav_handler, &mut nav_token) }.map_err(|err| {
        CaptchaError::WebView(format!("Đăng ký NavigationStarting thất bại: {err}"))
    })?;

    let new_window_handler =
        NewWindowRequestedEventHandler::create(Box::new(move |_sender, args| {
            if let Some(args) = args {
                let _ = unsafe { args.SetHandled(true) };
            }
            Ok(())
        }));
    let mut new_win_token = 0;
    unsafe { webview.add_NewWindowRequested(&new_window_handler, &mut new_win_token) }.map_err(
        |err| CaptchaError::WebView(format!("Đăng ký NewWindowRequested thất bại: {err}")),
    )?;

    let weak_for_msg = Rc::downgrade(state);
    let msg_handler = WebMessageReceivedEventHandler::create(Box::new(move |_sender, args| {
        let Some(state) = weak_for_msg.upgrade() else {
            return Ok(());
        };
        let Some(args) = args else {
            return Ok(());
        };

        let mut raw_source = PWSTR::null();
        if unsafe { args.Source(&mut raw_source) }.is_err() {
            return Ok(());
        }
        let source_url = CoTaskMemPWSTR::from(raw_source).to_string();
        if !is_allowed_captcha_url(&source_url) {
            warn!(
                source = %source_url,
                "ignored WebMessage from disallowed origin in CAPTCHA modal"
            );
            return Ok(());
        }

        let mut raw_msg = PWSTR::null();
        if unsafe { args.WebMessageAsJson(&mut raw_msg) }.is_ok() {
            let json_msg = CoTaskMemPWSTR::from(raw_msg).to_string();
            if let Some(token) = extract_token_from_post_message(&json_msg) {
                finish_modal_with_result(&state, hwnd, Ok(token));
            }
        }
        Ok(())
    }));
    let mut msg_token = 0;
    unsafe { webview.add_WebMessageReceived(&msg_handler, &mut msg_token) }.map_err(|err| {
        CaptchaError::WebView(format!("Đăng ký WebMessageReceived thất bại: {err}"))
    })?;

    {
        let mut guard = state.borrow_mut();
        guard.controller = Some(controller);
        guard.webview = Some(webview.clone());
    }

    let weak_for_script = Rc::downgrade(state);
    let nav_url = target_url.to_owned();
    let script_handler = AddScriptToExecuteOnDocumentCreatedCompletedHandler::create(Box::new(
        move |script_err, _id| {
            let Some(state) = weak_for_script.upgrade() else {
                return Ok(());
            };
            if let Err(err) = script_err {
                finish_modal_with_result(
                    &state,
                    hwnd,
                    Err(CaptchaError::WebView(format!(
                        "Không thể cài script bắt token CAPTCHA: {err}"
                    ))),
                );
                return Ok(());
            }

            let maybe_webview = {
                let guard = state.borrow();
                if guard.closing || guard.outcome.is_some() {
                    None
                } else {
                    guard.webview.clone()
                }
            };

            if let Some(webview) = maybe_webview {
                let nav_pwstr = CoTaskMemPWSTR::from(nav_url.as_str());
                if let Err(err) = unsafe { webview.Navigate(*nav_pwstr.as_ref().as_pcwstr()) } {
                    finish_modal_with_result(
                        &state,
                        hwnd,
                        Err(CaptchaError::WebView(format!(
                            "Không thể điều hướng tới trang CAPTCHA: {err}"
                        ))),
                    );
                }
            }
            Ok(())
        },
    ));

    let script_pwstr = CoTaskMemPWSTR::from(CAPTCHA_CAPTURE_SCRIPT);
    unsafe {
        webview.AddScriptToExecuteOnDocumentCreated(
            *script_pwstr.as_ref().as_pcwstr(),
            &script_handler,
        )
    }
    .map_err(|err| {
        CaptchaError::WebView(format!(
            "AddScriptToExecuteOnDocumentCreated thất bại: {err}"
        ))
    })?;

    Ok(())
}

fn clone_state_from_hwnd(hwnd: HWND) -> Option<Rc<RefCell<ModalState>>> {
    let raw = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) };
    if raw == 0 {
        return None;
    }
    let ptr = raw as *const RefCell<ModalState>;
    unsafe { Rc::increment_strong_count(ptr) };
    Some(unsafe { Rc::from_raw(ptr) })
}

extern "system" fn captcha_wndproc(
    hwnd: HWND,
    msg: u32,
    w_param: WPARAM,
    l_param: LPARAM,
) -> LRESULT {
    match msg {
        WM_ERASEBKGND => {
            if let Some(state) = clone_state_from_hwnd(hwnd) {
                let brush = state.borrow().bg_brush;
                if !brush.0.is_null() {
                    let mut client_rect = RECT::default();
                    let _ = unsafe { GetClientRect(hwnd, &mut client_rect) };
                    let hdc = HDC(w_param.0 as _);
                    unsafe {
                        let _ = FillRect(hdc, &client_rect, brush);
                    }
                    return LRESULT(1);
                }
            }
            unsafe { DefWindowProcW(hwnd, msg, w_param, l_param) }
        }
        WM_SIZE => {
            if let Some(state) = clone_state_from_hwnd(hwnd) {
                let controller = state.borrow().controller.clone();
                if let Some(controller) = controller {
                    let mut client_rect = RECT::default();
                    unsafe {
                        let _ = GetClientRect(hwnd, &mut client_rect);
                        let _ = controller.SetBounds(client_rect);
                    }
                }
            }
            LRESULT(0)
        }
        WM_TIMER => {
            if w_param.0 == CAPTCHA_TIMER_ID {
                if let Some(state) = clone_state_from_hwnd(hwnd) {
                    let timed_out = {
                        let mut guard = state.borrow_mut();
                        let expired = guard.deadline.is_some_and(|d| Instant::now() >= d);
                        if expired && !guard.closing {
                            if guard.outcome.is_none() {
                                guard.outcome = Some(Err(CaptchaError::Timeout));
                            }
                            guard.closing = true;
                            true
                        } else {
                            false
                        }
                    };
                    if timed_out {
                        unsafe {
                            let _ = KillTimer(Some(hwnd), CAPTCHA_TIMER_ID);
                            let _ = DestroyWindow(hwnd);
                        }
                    }
                }
            }
            LRESULT(0)
        }
        WM_APP_COMPLETE => {
            unsafe {
                let _ = KillTimer(Some(hwnd), CAPTCHA_TIMER_ID);
                let _ = DestroyWindow(hwnd);
            }
            LRESULT(0)
        }
        WM_CLOSE => {
            if let Some(state) = clone_state_from_hwnd(hwnd) {
                let mut guard = state.borrow_mut();
                if guard.outcome.is_none() {
                    guard.outcome = Some(Err(CaptchaError::Cancelled));
                }
                guard.closing = true;
            }
            unsafe {
                let _ = KillTimer(Some(hwnd), CAPTCHA_TIMER_ID);
                let _ = DestroyWindow(hwnd);
            }
            LRESULT(0)
        }
        WM_DESTROY => {
            unsafe {
                let _ = KillTimer(Some(hwnd), CAPTCHA_TIMER_ID);
            }
            let raw = unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0) };
            if raw != 0 {
                let state = unsafe { Rc::from_raw(raw as *const RefCell<ModalState>) };
                let (controller, _webview, _env) = {
                    let mut guard = state.borrow_mut();
                    guard.closing = true;
                    if guard.outcome.is_none() {
                        guard.outcome = Some(Err(CaptchaError::Cancelled));
                    }
                    (
                        guard.controller.take(),
                        guard.webview.take(),
                        guard.environment.take(),
                    )
                };
                if let Some(controller) = controller {
                    unsafe {
                        let _ = controller.Close();
                    }
                }
                drop(state);
            }
            unsafe { PostQuitMessage(0) };
            LRESULT(0)
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, w_param, l_param) },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use url::Url;

    #[test]
    fn test_validate_captcha_url_enforces_proton_https_and_force_web_messaging() {
        for bad in [
            "",
            "http://verify.proton.me/?methods=captcha&token=abc",
            "https://evil.example.com/?methods=captcha&token=abc",
            "https://verify.proton.me.evil.com/?methods=captcha&token=abc",
            "https://sub.verify.proton.me/?methods=captcha&token=abc",
            "javascript:alert(1)",
            "file:///C:/Windows/System32/calc.exe",
            "https://user:pass@verify.proton.me/?token=abc",
            "https://verify.proton.me:8443/?token=abc",
        ] {
            let err = validate_captcha_url(bad).expect_err(&format!(
                "expected invalid CAPTCHA URL to be rejected: {bad}"
            ));
            assert!(
                matches!(err, CaptchaError::InvalidUrl(_)),
                "expected InvalidUrl for {bad}, got {err:?}"
            );
        }

        let verified = validate_captcha_url(
            "https://verify.proton.me/?methods=captcha&token=challenge123#frag",
        )
        .expect("valid verify.proton.me URL");
        let parsed = Url::parse(&verified).expect("valid normalized URL");
        assert_eq!(parsed.scheme(), "https");
        assert_eq!(parsed.host_str(), Some("verify.proton.me"));
        assert_eq!(parsed.fragment(), Some("frag"));
        let pairs: HashMap<String, String> = parsed.query_pairs().into_owned().collect();
        assert_eq!(pairs.get("methods").map(String::as_str), Some("captcha"));
        assert_eq!(pairs.get("token").map(String::as_str), Some("challenge123"));
        assert_eq!(
            pairs.get("ForceWebMessaging").map(String::as_str),
            Some("1")
        );

        let overwritten =
            validate_captcha_url("https://ACCOUNT.PROTON.ME/authorize?foo=bar&ForceWebMessaging=0")
                .expect("valid account.proton.me URL");
        let parsed_overwritten = Url::parse(&overwritten).expect("valid overwritten URL");
        let count_fwm = parsed_overwritten
            .query_pairs()
            .filter(|(k, _)| k == "ForceWebMessaging")
            .count();
        assert_eq!(count_fwm, 1);
        let pairs_overwritten: HashMap<String, String> =
            parsed_overwritten.query_pairs().into_owned().collect();
        assert_eq!(
            pairs_overwritten.get("foo").map(String::as_str),
            Some("bar")
        );
        assert_eq!(
            pairs_overwritten
                .get("ForceWebMessaging")
                .map(String::as_str),
            Some("1")
        );

        let vpn_host = validate_captcha_url("https://account.protonvpn.com/captcha")
            .expect("valid account.protonvpn.com URL");
        let parsed_vpn = Url::parse(&vpn_host).expect("valid protonvpn URL");
        assert_eq!(parsed_vpn.host_str(), Some("account.protonvpn.com"));
        let pairs_vpn: HashMap<String, String> = parsed_vpn.query_pairs().into_owned().collect();
        assert_eq!(
            pairs_vpn.get("ForceWebMessaging").map(String::as_str),
            Some("1")
        );
    }

    #[test]
    fn test_extract_token_from_post_message_variants() {
        let valid = "hv_token_0123456789abcdef";
        assert!(valid.len() >= 20);

        assert_eq!(
            extract_token_from_post_message(valid),
            Some(valid.to_owned())
        );

        let json_string_wrapped = format!("\"{valid}\"");
        assert_eq!(
            extract_token_from_post_message(&json_string_wrapped),
            Some(valid.to_owned())
        );

        for key in [
            "Token",
            "token",
            "verificationToken",
            "HumanVerificationToken",
            "humanVerificationToken",
        ] {
            let payload = serde_json::json!({ "type": "pm_captcha", key: valid }).to_string();
            assert_eq!(
                extract_token_from_post_message(&payload),
                Some(valid.to_owned()),
                "failed to extract key {key}"
            );

            let double_encoded = serde_json::Value::String(payload).to_string();
            assert_eq!(
                extract_token_from_post_message(&double_encoded),
                Some(valid.to_owned()),
                "failed to extract double-encoded key {key}"
            );
        }

        let too_short = "short_19_characters";
        assert_eq!(too_short.len(), 19);
        assert_eq!(extract_token_from_post_message(too_short), None);
        assert_eq!(
            extract_token_from_post_message(&serde_json::json!({ "token": too_short }).to_string()),
            None
        );

        for url_like in [
            "http://verify.proton.me/token/12345678901234567890",
            "https://verify.proton.me/token/12345678901234567890",
            "HTTPS://account.proton.me/token/12345678901234567890",
        ] {
            assert_eq!(extract_token_from_post_message(url_like), None);
            assert_eq!(
                extract_token_from_post_message(
                    &serde_json::json!({ "token": url_like }).to_string()
                ),
                None
            );
        }

        // Unrelated JSON messages whose raw JSON length >= 20 must NEVER be treated as a token.
        assert_eq!(
            extract_token_from_post_message(r#"{"type":"height","height":500}"#),
            None
        );
        assert_eq!(
            extract_token_from_post_message("                    "),
            None
        );
        assert_eq!(
            extract_token_from_post_message("tok_0123456789\r\ninjected"),
            None
        );
        let exact_min = "a".repeat(20);
        assert_eq!(extract_token_from_post_message(&exact_min), Some(exact_min));
        let exact_max = "a".repeat(8192);
        assert_eq!(extract_token_from_post_message(&exact_max), Some(exact_max));
        let oversized = "a".repeat(8193);
        assert_eq!(extract_token_from_post_message(&oversized), None);
    }

    #[test]
    fn test_is_allowed_captcha_url_validates_sender_and_navigation_origins() {
        assert!(is_allowed_captcha_url(
            "https://verify.proton.me/?methods=captcha"
        ));
        assert!(is_allowed_captcha_url("https://ACCOUNT.PROTON.ME/path"));
        assert!(is_allowed_captcha_url("https://account.protonvpn.com/hv"));

        assert!(!is_allowed_captcha_url("http://verify.proton.me/"));
        assert!(!is_allowed_captcha_url("about:blank"));
        assert!(!is_allowed_captcha_url("https://newassets.hcaptcha.com/"));
        assert!(!is_allowed_captcha_url(
            "https://verify.proton.me.evil.com/"
        ));
    }

    #[test]
    fn test_solve_captcha_and_challenge_reject_invalid_url_and_zero_timeout_before_window() {
        let err =
            solve_captcha_blocking("http://verify.proton.me/?token=abc", Duration::from_secs(5))
                .expect_err("http URL must fail immediately");
        assert!(matches!(err, CaptchaError::InvalidUrl(_)));

        let challenge = HumanVerificationChallenge {
            url: "https://evil.example.com/hv".to_owned(),
            methods: vec!["captcha".to_owned()],
        };
        let err = solve_challenge_blocking(&challenge, Duration::from_secs(5))
            .expect_err("disallowed host must fail immediately");
        assert!(matches!(err, CaptchaError::InvalidUrl(_)));

        let timeout_err =
            solve_captcha_blocking("https://verify.proton.me/?token=abc", Duration::ZERO)
                .expect_err("zero timeout must fail before creating WebView2 window");
        assert_eq!(timeout_err, CaptchaError::Timeout);
    }

    #[test]
    fn test_capture_script_contains_top_frame_guard_and_token_keys() {
        assert!(CAPTCHA_CAPTURE_SCRIPT.contains("window !== window.top"));
        assert!(CAPTCHA_CAPTURE_SCRIPT.contains("window.chrome?.webview?.postMessage"));
        for key in TOKEN_KEYS {
            assert!(
                CAPTCHA_CAPTURE_SCRIPT.contains(key),
                "missing token key {key} in CAPTCHA_CAPTURE_SCRIPT"
            );
        }
    }

    #[test]
    fn test_capture_script_enforces_proton_event_origin_filter() {
        assert!(CAPTCHA_CAPTURE_SCRIPT.contains(
            r"const ALLOWED_ORIGIN_RE = /^https:\/\/([a-z0-9-]+\.)*(proton\.me|protonvpn\.com)$/i;"
        ));
        assert!(CAPTCHA_CAPTURE_SCRIPT.contains(
            r#"const isAllowedOrigin = (origin) =>
    typeof origin === "string" &&
    ((origin === window.location.origin && /^https:\/\//i.test(origin)) ||
      ALLOWED_ORIGIN_RE.test(origin));"#
        ));
        assert!(CAPTCHA_CAPTURE_SCRIPT.contains("if (!isAllowedOrigin(event.origin)) return;"));

        let js_harness = r#"
const script = process.env.FREETON_CAPTCHA_SCRIPT;
if (!script) throw new Error("missing FREETON_CAPTCHA_SCRIPT");

let subHandler = null;
global.window = {
  location: { origin: "https://verify.proton.me" },
  chrome: { webview: { postMessage: () => { throw new Error("subframe should not post"); } } },
  addEventListener: (ev, fn) => { if (ev === "message") subHandler = fn; },
  top: {},
};
new Function(script)();
if (subHandler !== null) {
  throw new Error("expected non-top frame not to register message listener");
}

let handler = null;
const posted = [];
global.window = {
  location: { origin: "https://verify.proton.me" },
  chrome: { webview: { postMessage: (v) => posted.push(v) } },
  addEventListener: (ev, fn) => { if (ev === "message") handler = fn; },
};
global.window.top = global.window;
new Function(script)();
if (typeof handler !== "function") {
  throw new Error("expected top-level frame to register message listener");
}

const tok1 = "hv_token_0123456789abcdef_1";
const tok2 = "hv_token_0123456789abcdef_2";
const tok3 = "hv_token_0123456789abcdef_3";

for (const badOrigin of [
  "https://newassets.hcaptcha.com",
  "https://hcaptcha.com",
  "http://verify.proton.me",
  "https://verify.proton.me.evil.com",
  "https://evilproton.me",
  "https://verify.proton.me:8443",
  "null",
  "",
]) {
  handler({ origin: badOrigin, data: tok1 });
  handler({ origin: badOrigin, data: { token: tok1 } });
  handler({ origin: badOrigin, data: JSON.stringify({ Token: tok1 }) });
}
handler({ origin: "https://verify.proton.me", data: "https://verify.proton.me/path_over_20_chars" });
handler({ origin: "https://verify.proton.me", data: "short" });
handler({ origin: "https://verify.proton.me", data: JSON.stringify({ type: "height", height: 500 }) });
if (posted.length !== 0) {
  throw new Error("unexpected forward from untrusted origin/payload: " + JSON.stringify(posted));
}

handler({ origin: "https://verify-api.proton.me", data: { token: tok1 } });
handler({ origin: "https://verify.proton.me", data: tok2 });
handler({ origin: "https://account.protonvpn.com", data: JSON.stringify({ HumanVerificationToken: tok3 }) });

const expected = JSON.stringify([tok1, tok2, tok3]);
if (JSON.stringify(posted) !== expected) {
  throw new Error("expected " + expected + ", got " + JSON.stringify(posted));
}
"#;

        let mut child = match std::process::Command::new("node")
            .arg("-")
            .env("FREETON_CAPTCHA_SCRIPT", CAPTCHA_CAPTURE_SCRIPT)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return,
            Err(err) => panic!("failed to launch node to verify CAPTCHA_CAPTURE_SCRIPT: {err}"),
        };

        {
            use std::io::Write;
            let stdin = child.stdin.as_mut().expect("piped stdin");
            stdin
                .write_all(js_harness.as_bytes())
                .expect("write JS harness to node stdin");
        }
        let output = child.wait_with_output().expect("wait for node process");
        assert!(
            output.status.success(),
            "node verification failed (status: {:?})\nstdout: {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn test_per_run_user_data_dir_is_unique() {
        let base = PathBuf::from(r"C:\Temp\FreetonVPN\webview2-captcha");
        let first = build_per_run_user_data_dir(&base);
        let second = build_per_run_user_data_dir(&base);
        assert_ne!(first, second);
        assert_eq!(first.parent(), Some(base.as_path()));
        assert_eq!(second.parent(), Some(base.as_path()));
    }
}
