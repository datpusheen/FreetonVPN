use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::ClientOptions;
use windows::core::{s, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, FreeLibrary, LocalFree, ERROR_FILE_NOT_FOUND, ERROR_SERVICE_CANNOT_ACCEPT_CTRL,
    ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_MARKED_FOR_DELETE, ERROR_SERVICE_NOT_ACTIVE,
    HLOCAL, HMODULE, WIN32_ERROR,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryW, SetDefaultDllDirectories, LOAD_LIBRARY_SEARCH_APPLICATION_DIR,
    LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows::Win32::System::Services::{
    ChangeServiceConfig2W, CloseServiceHandle, ControlService, CreateServiceW, DeleteService,
    OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, StartServiceW, SC_HANDLE,
    SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE, SC_STATUS_PROCESS_INFO, SERVICE_ALL_ACCESS,
    SERVICE_CONFIG_SERVICE_SID_INFO, SERVICE_CONTROL_STOP, SERVICE_DEMAND_START,
    SERVICE_ERROR_NORMAL, SERVICE_QUERY_STATUS, SERVICE_SID_INFO, SERVICE_SID_TYPE_UNRESTRICTED,
    SERVICE_STATUS, SERVICE_STATUS_PROCESS, SERVICE_STOP, SERVICE_WIN32_OWN_PROCESS,
};

pub const TUNNEL_SERVICE_PREFIX: &str = "WireGuardTunnel$";
pub const TUNNEL_SERVICE_DISPLAY_PREFIX: &str = "WireGuard Tunnel: ";
pub const WIREGUARD_UAPI_PIPE_PREFIX: &str = r"\\.\pipe\ProtectedPrefix\Administrators\WireGuard\";
pub const RESTRICTED_TUNNEL_DIR_SDDL: &str = "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)";

const UAPI_PIPE_TIMEOUT: Duration = Duration::from_secs(2);
const DELETE_ACCESS: u32 = 0x0001_0000;

type WireGuardTunnelServiceFn = unsafe extern "system" fn(*const u16) -> i32;

#[derive(Debug, Error)]
pub enum TunnelError {
    #[error("Invalid tunnel name: {0}")]
    InvalidTunnelName(String),
    #[error("Invalid tunnel configuration path: {0}")]
    InvalidConfPath(String),
    #[error("Missing required WireGuard dependency: {0}")]
    MissingDependency(String),
    #[error("Failed to load tunnel.dll: {0}")]
    DllLoad(String),
    #[error("WireGuardTunnelService returned failure")]
    TunnelEntryFailed,
    #[error("Windows SCM error: {0}")]
    Scm(String),
    #[error("WireGuard UAPI pipe error: {0}")]
    Pipe(String),
    #[error("Security descriptor error: {0}")]
    Security(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub(crate) struct ScHandleGuard(pub(crate) SC_HANDLE);

impl Drop for ScHandleGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseServiceHandle(self.0);
            }
        }
    }
}

pub(crate) struct LocalFreeGuard(pub(crate) *mut core::ffi::c_void);

impl Drop for LocalFreeGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0)));
            }
        }
    }
}

struct LibraryGuard(HMODULE);

impl Drop for LibraryGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = FreeLibrary(self.0);
            }
        }
    }
}

/// Ensures Windows `CloseHandle` usage stays clean if needed across modules.
#[allow(dead_code)]
pub(crate) struct WinHandleGuard(pub(crate) windows::Win32::Foundation::HANDLE);

impl Drop for WinHandleGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

pub(crate) fn to_wide_null(value: impl AsRef<OsStr>) -> Result<Vec<u16>, TunnelError> {
    let wide: Vec<u16> = value.as_ref().encode_wide().collect();
    if wide.contains(&0) {
        return Err(TunnelError::InvalidConfPath(
            "string contains embedded NUL byte".to_owned(),
        ));
    }
    let mut out = wide;
    out.push(0);
    Ok(out)
}

pub(crate) fn to_wide_multi_sz(values: &[&str]) -> Vec<u16> {
    let mut out = Vec::new();
    for val in values {
        out.extend(OsStr::new(val).encode_wide());
        out.push(0);
    }
    out.push(0);
    out
}

pub(crate) fn win32_err_code(err: &windows::core::Error) -> Option<WIN32_ERROR> {
    WIN32_ERROR::from_error(err)
}

pub fn tunnel_service_name(tunnel_name: &str) -> String {
    format!("{TUNNEL_SERVICE_PREFIX}{tunnel_name}")
}

pub fn tunnel_uapi_pipe_name(tunnel_name: &str) -> String {
    format!("{WIREGUARD_UAPI_PIPE_PREFIX}{tunnel_name}")
}

pub fn validate_tunnel_name(tunnel_name: &str) -> Result<(), TunnelError> {
    if tunnel_name.is_empty()
        || tunnel_name.len() > 32
        || !tunnel_name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(TunnelError::InvalidTunnelName(format!(
            "unsupported tunnel name {tunnel_name:?}"
        )));
    }
    Ok(())
}

pub fn default_tunnels_dir() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("FreetonVPN").join("tunnels")
}

/// Strips the `\\?\` extended-length prefix for standard drive-letter paths (`\\?\C:\...` -> `C:\...`)
/// after canonicalization so `tunnel.dll` and SCM receive standard Win32 paths.
pub fn to_win32_path_arg(canonical_path: &Path) -> PathBuf {
    if let Some(raw) = canonical_path.to_str() {
        if let Some(stripped) = raw.strip_prefix(r"\\?\") {
            if !stripped.starts_with(r"UNC\") {
                return PathBuf::from(stripped);
            }
        }
    }
    canonical_path.to_path_buf()
}

/// Verifies that `conf_path` is an existing regular `.conf` file (never a symlink) whose canonical
/// path resolves directly inside `allowed_dir`.
pub fn validate_tunnel_conf_path(
    conf_path: &Path,
    allowed_dir: &Path,
) -> Result<PathBuf, TunnelError> {
    if !conf_path.is_absolute() {
        return Err(TunnelError::InvalidConfPath(format!(
            "configuration path must be absolute: {}",
            conf_path.display()
        )));
    }

    let is_conf = conf_path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("conf"));
    if !is_conf || conf_path.file_name().is_none() {
        return Err(TunnelError::InvalidConfPath(format!(
            "configuration path must have a .conf filename: {}",
            conf_path.display()
        )));
    }

    let meta = fs::symlink_metadata(conf_path).map_err(|err| {
        TunnelError::InvalidConfPath(format!(
            "cannot access configuration file {}: {err}",
            conf_path.display()
        ))
    })?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(TunnelError::InvalidConfPath(format!(
            "configuration path must be a regular non-symlink file: {}",
            conf_path.display()
        )));
    }

    let canonical_dir = fs::canonicalize(allowed_dir).map_err(|err| {
        TunnelError::InvalidConfPath(format!(
            "allowed tunnels directory {} is unavailable: {err}",
            allowed_dir.display()
        ))
    })?;
    let canonical_conf = fs::canonicalize(conf_path).map_err(|err| {
        TunnelError::InvalidConfPath(format!(
            "failed to canonicalize {}: {err}",
            conf_path.display()
        ))
    })?;

    if !canonical_conf.is_file()
        || canonical_conf == canonical_dir
        || canonical_conf.parent() != Some(canonical_dir.as_path())
    {
        return Err(TunnelError::InvalidConfPath(format!(
            "configuration path {} escapes allowed directory {}",
            canonical_conf.display(),
            canonical_dir.display()
        )));
    }

    Ok(canonical_conf)
}

pub fn apply_restricted_dacl(path: &Path, sddl: &str) -> Result<(), TunnelError> {
    let wide_sddl = to_wide_null(sddl)?;
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(wide_sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
        .map_err(|e| TunnelError::Security(format!("failed to parse SDDL {sddl:?}: {e}")))?;
    }
    let _sd_guard = LocalFreeGuard(sd.0);

    let mut dacl_present = windows::core::BOOL(0);
    let mut p_dacl: *mut ACL = core::ptr::null_mut();
    let mut dacl_defaulted = windows::core::BOOL(0);
    unsafe {
        GetSecurityDescriptorDacl(sd, &mut dacl_present, &mut p_dacl, &mut dacl_defaulted)
            .map_err(|e| TunnelError::Security(format!("GetSecurityDescriptorDacl failed: {e}")))?;
    }
    if !dacl_present.as_bool() || p_dacl.is_null() {
        return Err(TunnelError::Security(
            "SDDL descriptor did not contain a valid DACL".to_owned(),
        ));
    }

    let wide_path = to_wide_null(path.as_os_str())?;
    let status = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(wide_path.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(p_dacl.cast_const()),
            None,
        )
    };
    if status != WIN32_ERROR(0) {
        return Err(TunnelError::Security(format!(
            "SetNamedSecurityInfoW failed on {}: win32 error {}",
            path.display(),
            status.0
        )));
    }

    Ok(())
}

pub fn ensure_restricted_tunnels_dir(
    tunnels_dir: &Path,
    enforce_acl: bool,
) -> Result<(), TunnelError> {
    fs::create_dir_all(tunnels_dir)?;
    let meta = fs::symlink_metadata(tunnels_dir)?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(TunnelError::InvalidConfPath(format!(
            "tunnels directory {} must be a real directory",
            tunnels_dir.display()
        )));
    }
    if enforce_acl {
        apply_restricted_dacl(tunnels_dir, RESTRICTED_TUNNEL_DIR_SDDL)?;
    }
    Ok(())
}

pub fn write_restricted_tunnel_conf(
    tunnels_dir: &Path,
    tunnel_name: &str,
    conf_content: &str,
    enforce_acl: bool,
) -> Result<PathBuf, TunnelError> {
    validate_tunnel_name(tunnel_name)?;
    ensure_restricted_tunnels_dir(tunnels_dir, enforce_acl)?;

    let conf_path = tunnels_dir.join(format!("{tunnel_name}.conf"));
    if let Ok(meta) = fs::symlink_metadata(&conf_path) {
        if meta.file_type().is_symlink() {
            return Err(TunnelError::InvalidConfPath(format!(
                "refusing to overwrite symlink {}",
                conf_path.display()
            )));
        }
    }

    fs::write(&conf_path, conf_content.as_bytes())?;
    if enforce_acl {
        apply_restricted_dacl(&conf_path, RESTRICTED_TUNNEL_DIR_SDDL)?;
    }
    validate_tunnel_conf_path(&conf_path, tunnels_dir)
}

pub fn remove_tunnel_conf(tunnels_dir: &Path, tunnel_name: &str) -> Result<(), TunnelError> {
    validate_tunnel_name(tunnel_name)?;
    let conf_path = tunnels_dir.join(format!("{tunnel_name}.conf"));
    match fs::remove_file(&conf_path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(TunnelError::Io(err)),
    }
}

/// Executes `WireGuardTunnelService` exported from sibling `tunnel.dll` after validating that
/// `conf_path` resolves strictly inside `%ProgramData%\FreetonVPN\tunnels\` and `wireguard.dll`
/// sits alongside `tunnel.dll`.
pub fn run_tunnel_service_from_cli(conf_path: &Path) -> Result<(), TunnelError> {
    let tunnels_dir = default_tunnels_dir();
    let canonical_conf = validate_tunnel_conf_path(conf_path, &tunnels_dir)?;
    let win32_conf = to_win32_path_arg(&canonical_conf);

    let exe_path = std::env::current_exe()?;
    let exe_dir = exe_path.parent().ok_or_else(|| {
        TunnelError::MissingDependency("cannot resolve FreetonVPNService.exe directory".to_owned())
    })?;

    let wireguard_dll = exe_dir.join("wireguard.dll");
    if !wireguard_dll.is_file() {
        return Err(TunnelError::MissingDependency(format!(
            "missing required sibling DLL {}",
            wireguard_dll.display()
        )));
    }
    let tunnel_dll = exe_dir.join("tunnel.dll");
    if !tunnel_dll.is_file() {
        return Err(TunnelError::MissingDependency(format!(
            "missing required sibling DLL {}",
            tunnel_dll.display()
        )));
    }

    unsafe {
        let _ = SetDefaultDllDirectories(
            LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
        );
    }

    let wide_tunnel_dll = to_wide_null(tunnel_dll.as_os_str())?;
    let module = unsafe { LoadLibraryW(PCWSTR(wide_tunnel_dll.as_ptr())) }.map_err(|err| {
        TunnelError::DllLoad(format!("failed loading {}: {err}", tunnel_dll.display()))
    })?;
    let _module_guard = LibraryGuard(module);

    let proc_ptr =
        unsafe { GetProcAddress(module, s!("WireGuardTunnelService")) }.ok_or_else(|| {
            TunnelError::DllLoad(format!(
                "symbol WireGuardTunnelService not found in {}",
                tunnel_dll.display()
            ))
        })?;
    let tunnel_service_fn: WireGuardTunnelServiceFn = unsafe { core::mem::transmute(proc_ptr) };

    let wide_conf = to_wide_null(win32_conf.as_os_str())?;
    let ok = unsafe { tunnel_service_fn(wide_conf.as_ptr()) };
    if ok == 0 {
        return Err(TunnelError::TunnelEntryFailed);
    }
    Ok(())
}

pub(crate) fn open_sc_manager(access: u32) -> Result<ScHandleGuard, TunnelError> {
    let scm = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), access) }
        .map_err(|e| TunnelError::Scm(format!("OpenSCManagerW failed: {e}")))?;
    Ok(ScHandleGuard(scm))
}

pub fn query_service_state(service_name: &str) -> Result<u32, TunnelError> {
    let scm = open_sc_manager(SC_MANAGER_CONNECT)?;
    let wide_name = to_wide_null(service_name)?;
    let service =
        match unsafe { OpenServiceW(scm.0, PCWSTR(wide_name.as_ptr()), SERVICE_QUERY_STATUS) } {
            Ok(h) => ScHandleGuard(h),
            Err(err) => {
                if win32_err_code(&err) == Some(ERROR_SERVICE_DOES_NOT_EXIST) {
                    return Ok(0);
                }
                return Err(TunnelError::Scm(format!(
                    "OpenServiceW({service_name}) failed: {err}"
                )));
            }
        };

    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0u32;
    let buf = unsafe {
        core::slice::from_raw_parts_mut(
            (&mut status as *mut SERVICE_STATUS_PROCESS).cast::<u8>(),
            core::mem::size_of::<SERVICE_STATUS_PROCESS>(),
        )
    };
    unsafe {
        QueryServiceStatusEx(service.0, SC_STATUS_PROCESS_INFO, Some(buf), &mut needed).map_err(
            |e| TunnelError::Scm(format!("QueryServiceStatusEx({service_name}) failed: {e}")),
        )?;
    }
    Ok(status.dwCurrentState.0)
}

pub fn install_and_start_tunnel_service(
    tunnel_name: &str,
    conf_path: &Path,
    service_exe: &Path,
) -> Result<(), TunnelError> {
    validate_tunnel_name(tunnel_name)?;
    let svc_name = tunnel_service_name(tunnel_name);
    let display_name = format!("{TUNNEL_SERVICE_DISPLAY_PREFIX}{tunnel_name}");
    let clean_conf = to_win32_path_arg(conf_path);
    let cmd_line = format!(
        "\"{}\" --tunnel \"{}\"",
        service_exe.display(),
        clean_conf.display()
    );

    let wide_name = to_wide_null(&svc_name)?;
    let wide_display = to_wide_null(&display_name)?;
    let wide_cmd = to_wide_null(&cmd_line)?;
    let wide_deps = to_wide_multi_sz(&["Nsi", "TcpIp"]);

    let scm = open_sc_manager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
    let service = unsafe {
        CreateServiceW(
            scm.0,
            PCWSTR(wide_name.as_ptr()),
            PCWSTR(wide_display.as_ptr()),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            PCWSTR(wide_cmd.as_ptr()),
            PCWSTR::null(),
            None,
            PCWSTR(wide_deps.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
        )
    }
    .map_err(|e| TunnelError::Scm(format!("CreateServiceW({svc_name}) failed: {e}")))?;
    let service_guard = ScHandleGuard(service);

    let sid_info = SERVICE_SID_INFO {
        dwServiceSidType: SERVICE_SID_TYPE_UNRESTRICTED,
    };
    unsafe {
        ChangeServiceConfig2W(
            service_guard.0,
            SERVICE_CONFIG_SERVICE_SID_INFO,
            Some((&sid_info as *const SERVICE_SID_INFO).cast()),
        )
        .map_err(|e| {
            TunnelError::Scm(format!(
                "ChangeServiceConfig2W(SERVICE_SID_TYPE_UNRESTRICTED) failed for {svc_name}: {e}"
            ))
        })?;
    }

    unsafe {
        StartServiceW(service_guard.0, None)
            .map_err(|e| TunnelError::Scm(format!("StartServiceW({svc_name}) failed: {e}")))?;
    }

    Ok(())
}

pub fn stop_and_delete_service(service_name: &str) -> Result<(), TunnelError> {
    let scm = open_sc_manager(SC_MANAGER_CONNECT)?;
    let wide_name = to_wide_null(service_name)?;
    let service = match unsafe {
        OpenServiceW(
            scm.0,
            PCWSTR(wide_name.as_ptr()),
            SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE_ACCESS,
        )
    } {
        Ok(h) => ScHandleGuard(h),
        Err(err) => {
            if win32_err_code(&err) == Some(ERROR_SERVICE_DOES_NOT_EXIST) {
                return Ok(());
            }
            return Err(TunnelError::Scm(format!(
                "OpenServiceW({service_name}) failed: {err}"
            )));
        }
    };

    let mut svc_status = SERVICE_STATUS::default();
    if let Err(err) = unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut svc_status) } {
        let code = win32_err_code(&err);
        if code != Some(ERROR_SERVICE_NOT_ACTIVE) && code != Some(ERROR_SERVICE_CANNOT_ACCEPT_CTRL)
        {
            return Err(TunnelError::Scm(format!(
                "ControlService(STOP, {service_name}) failed: {err}"
            )));
        }
    }

    if let Err(err) = unsafe { DeleteService(service.0) } {
        if win32_err_code(&err) != Some(ERROR_SERVICE_MARKED_FOR_DELETE) {
            return Err(TunnelError::Scm(format!(
                "DeleteService({service_name}) failed: {err}"
            )));
        }
    }

    Ok(())
}

/// Queries WireGuard's Windows UAPI named pipe (`get=1\n\n`) and reads lines until the blank-line
/// terminator (`\n\n`) or EOF.
pub async fn query_uapi_state(tunnel_name: &str) -> Result<String, TunnelError> {
    validate_tunnel_name(tunnel_name)?;
    let pipe_path = tunnel_uapi_pipe_name(tunnel_name);
    let client = ClientOptions::new()
        .read(true)
        .write(true)
        .open(&pipe_path)
        .map_err(|err| {
            let tag = if err.raw_os_error() == Some(ERROR_FILE_NOT_FOUND.0 as i32) {
                "WireGuard UAPI pipe not ready"
            } else {
                "failed opening WireGuard UAPI pipe"
            };
            TunnelError::Pipe(format!("{tag} ({pipe_path}): {err}"))
        })?;

    tokio::time::timeout(UAPI_PIPE_TIMEOUT, async move {
        let (reader_half, mut writer_half) = tokio::io::split(client);
        writer_half
            .write_all(b"get=1\n\n")
            .await
            .map_err(|e| TunnelError::Pipe(format!("UAPI write failed: {e}")))?;
        writer_half
            .flush()
            .await
            .map_err(|e| TunnelError::Pipe(format!("UAPI flush failed: {e}")))?;

        let mut reader = BufReader::new(reader_half);
        let mut out = String::new();
        let mut line = String::new();
        loop {
            line.clear();
            let n = reader
                .read_line(&mut line)
                .await
                .map_err(|e| TunnelError::Pipe(format!("UAPI read failed: {e}")))?;
            if n == 0 {
                break;
            }
            if line.trim().is_empty() {
                if !out.is_empty() {
                    break;
                }
                continue;
            }
            out.push_str(&line);
        }
        Ok(out)
    })
    .await
    .map_err(|_| TunnelError::Pipe("timed out reading WireGuard UAPI state".to_owned()))?
}

/// Utility helper for converting a UTF-16 `PWSTR` if needed in diagnostics.
#[allow(dead_code)]
pub(crate) fn _check_pwstr_unused(_: PWSTR) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "freeton_tunnel_test_{label}_{}_{}",
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn test_rejects_conf_path_outside_programdata_tunnels() {
        let root = unique_temp_dir("path_validation");
        let tunnels_dir = root.join("FreetonVPN").join("tunnels");
        let sibling_dir = root.join("FreetonVPN").join("tunnels-evil");
        let outside_dir = root.join("Public");
        let nested_dir = tunnels_dir.join("subdir");
        fs::create_dir_all(&tunnels_dir).expect("create tunnels dir");
        fs::create_dir_all(&sibling_dir).expect("create sibling dir");
        fs::create_dir_all(&outside_dir).expect("create outside dir");
        fs::create_dir_all(&nested_dir).expect("create nested dir");

        let valid_conf = tunnels_dir.join("FreetonVPN.conf");
        let txt_file = tunnels_dir.join("FreetonVPN.txt");
        let sibling_conf = sibling_dir.join("FreetonVPN.conf");
        let outside_conf = outside_dir.join("evil.conf");
        let nested_conf = nested_dir.join("FreetonVPN.conf");

        fs::write(&valid_conf, "[Interface]\n").expect("write valid conf");
        fs::write(&txt_file, "[Interface]\n").expect("write txt");
        fs::write(&sibling_conf, "[Interface]\n").expect("write sibling");
        fs::write(&outside_conf, "[Interface]\n").expect("write outside");
        fs::write(&nested_conf, "[Interface]\n").expect("write nested");

        let validated =
            validate_tunnel_conf_path(&valid_conf, &tunnels_dir).expect("valid canonical conf");
        assert_eq!(
            validated,
            fs::canonicalize(&valid_conf).expect("canonical valid")
        );

        let traversal_inside = tunnels_dir
            .join("..")
            .join("tunnels")
            .join("FreetonVPN.conf");
        assert!(
            validate_tunnel_conf_path(&traversal_inside, &tunnels_dir).is_ok(),
            "canonical path resolving inside tunnels dir is valid"
        );

        let traversal_outside = tunnels_dir
            .join("..")
            .join("..")
            .join("Public")
            .join("evil.conf");
        for bad_path in [
            Path::new("FreetonVPN.conf"),
            Path::new(r"..\tunnels\FreetonVPN.conf"),
            outside_conf.as_path(),
            sibling_conf.as_path(),
            traversal_outside.as_path(),
            txt_file.as_path(),
            nested_conf.as_path(),
            tunnels_dir.as_path(),
            tunnels_dir.join("does_not_exist.conf").as_path(),
        ] {
            let res = validate_tunnel_conf_path(bad_path, &tunnels_dir);
            assert!(
                matches!(res, Err(TunnelError::InvalidConfPath(_))),
                "path {:?} must be rejected, got {res:?}",
                bad_path
            );
        }

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_sddl_strings_and_win32_path_helpers() {
        assert_eq!(
            to_win32_path_arg(Path::new(
                r"\\?\C:\ProgramData\FreetonVPN\tunnels\FreetonVPN.conf"
            )),
            PathBuf::from(r"C:\ProgramData\FreetonVPN\tunnels\FreetonVPN.conf")
        );
        assert_eq!(
            to_win32_path_arg(Path::new(r"\\?\UNC\server\share\FreetonVPN.conf")),
            PathBuf::from(r"\\?\UNC\server\share\FreetonVPN.conf")
        );

        assert!(validate_tunnel_name("FreetonVPN").is_ok());
        assert!(validate_tunnel_name("../evil").is_err());
        assert!(validate_tunnel_name("bad\\name").is_err());
        assert!(validate_tunnel_name("").is_err());

        for sddl in [RESTRICTED_TUNNEL_DIR_SDDL, crate::broker::PIPE_SDDL_DACL] {
            let wide = to_wide_null(sddl).expect("wide sddl");
            let mut sd = PSECURITY_DESCRIPTOR::default();
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    PCWSTR(wide.as_ptr()),
                    SDDL_REVISION_1,
                    &mut sd,
                    None,
                )
                .expect("SDDL should parse via advapi32");
            }
            let _guard = LocalFreeGuard(sd.0);
        }
    }
}
