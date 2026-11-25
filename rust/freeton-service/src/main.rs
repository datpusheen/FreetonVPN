use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use freeton_core::wg::DEFAULT_TUNNEL_NAME;
use tracing::{error, info};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_DOES_NOT_EXIST,
    ERROR_SERVICE_EXISTS, WIN32_ERROR,
};
use windows::Win32::Security::Authorization::{
    SetEntriesInAclW, EXPLICIT_ACCESS_W, GRANT_ACCESS, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP,
    TRUSTEE_W,
};
use windows::Win32::Security::{
    CreateWellKnownSid, GetSecurityDescriptorDacl, InitializeSecurityDescriptor,
    SetSecurityDescriptorDacl, WinInteractiveSid, ACE_FLAGS, ACL, DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR,
};
use windows::Win32::System::Services::{
    ChangeServiceConfig2W, ChangeServiceConfigW, ControlService, CreateServiceW, OpenServiceW,
    QueryServiceObjectSecurity, SetServiceObjectSecurity, StartServiceW, SC_MANAGER_ALL_ACCESS,
    SERVICE_ALL_ACCESS, SERVICE_AUTO_START, SERVICE_CONFIG_DESCRIPTION, SERVICE_CONTROL_STOP,
    SERVICE_DESCRIPTIONW, SERVICE_ERROR_NORMAL, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
    SERVICE_START, SERVICE_STATUS, SERVICE_STOPPED, SERVICE_WIN32_OWN_PROCESS,
};

mod broker;
mod tunnel_runner;

use broker::{
    run_windows_service, BROKER_SERVICE_DESCRIPTION, BROKER_SERVICE_DISPLAY_NAME,
    BROKER_SERVICE_NAME,
};
use tunnel_runner::{
    default_tunnels_dir, ensure_restricted_tunnels_dir, open_sc_manager, query_service_state,
    run_tunnel_service_from_cli, stop_and_delete_service, to_wide_null, tunnel_service_name,
    win32_err_code, LocalFreeGuard, ScHandleGuard,
};

const READ_CONTROL_ACCESS: u32 = 0x0002_0000;
const WRITE_DAC_ACCESS: u32 = 0x0004_0000;
const SECURITY_DESCRIPTOR_REVISION_1: u32 = 1;
const STANDARD_SID_MAX_BYTES: usize = 68;

#[derive(Debug, PartialEq, Eq)]
enum CliMode {
    Service,
    Tunnel(PathBuf),
    Install,
    Uninstall,
}

fn parse_cli_args(args: &[OsString]) -> Result<CliMode, String> {
    match args {
        [_, flag] if flag == "--service" => Ok(CliMode::Service),
        [_, flag] if flag == "--install" => Ok(CliMode::Install),
        [_, flag] if flag == "--uninstall" => Ok(CliMode::Uninstall),
        [_, flag, conf_path] if flag == "--tunnel" && !conf_path.is_empty() => {
            Ok(CliMode::Tunnel(PathBuf::from(conf_path)))
        }
        _ => Err(
            "Usage: FreetonVPNService.exe [--service | --tunnel <abs_conf_path> | --install | --uninstall]"
                .to_owned(),
        ),
    }
}

fn wait_for_scm_state(service_name: &str, expected: u32, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        let state = query_service_state(service_name).map_err(|e| e.to_string())?;
        if state == expected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for service {service_name} to reach state {expected} (last state {state})"
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn grant_interactive_user_service_rights(service_handle: &ScHandleGuard) -> Result<(), String> {
    let mut bytes_needed = 0u32;
    let first_err = unsafe {
        QueryServiceObjectSecurity(
            service_handle.0,
            DACL_SECURITY_INFORMATION.0,
            None,
            0,
            &mut bytes_needed,
        )
    };
    if let Err(err) = first_err {
        if win32_err_code(&err) != Some(ERROR_INSUFFICIENT_BUFFER) {
            return Err(format!("QueryServiceObjectSecurity(size) failed: {err}"));
        }
    }

    let mut sd_buf = vec![0u8; bytes_needed.max(64) as usize];
    let existing_sd = PSECURITY_DESCRIPTOR(sd_buf.as_mut_ptr().cast());
    unsafe {
        QueryServiceObjectSecurity(
            service_handle.0,
            DACL_SECURITY_INFORMATION.0,
            Some(existing_sd),
            u32::try_from(sd_buf.len()).unwrap_or(u32::MAX),
            &mut bytes_needed,
        )
        .map_err(|e| format!("QueryServiceObjectSecurity failed: {e}"))?;
    }

    let mut dacl_present = windows::core::BOOL(0);
    let mut old_dacl: *mut ACL = core::ptr::null_mut();
    let mut dacl_defaulted = windows::core::BOOL(0);
    unsafe {
        GetSecurityDescriptorDacl(
            existing_sd,
            &mut dacl_present,
            &mut old_dacl,
            &mut dacl_defaulted,
        )
        .map_err(|e| format!("GetSecurityDescriptorDacl failed: {e}"))?;
    }

    let mut iu_sid = vec![0u8; STANDARD_SID_MAX_BYTES];
    let mut iu_sid_len = u32::try_from(iu_sid.len()).unwrap_or(68);
    let sid_ptr = windows::Win32::Security::PSID(iu_sid.as_mut_ptr().cast());
    unsafe {
        CreateWellKnownSid(WinInteractiveSid, None, Some(sid_ptr), &mut iu_sid_len)
            .map_err(|e| format!("CreateWellKnownSid(WinInteractiveSid) failed: {e}"))?;
    }

    let explicit_access = [EXPLICIT_ACCESS_W {
        grfAccessPermissions: SERVICE_START | SERVICE_QUERY_STATUS | READ_CONTROL_ACCESS,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: ACE_FLAGS(0),
        Trustee: TRUSTEE_W {
            pMultipleTrustee: core::ptr::null_mut(),
            MultipleTrusteeOperation: Default::default(),
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
            ptstrName: windows::core::PWSTR(sid_ptr.0.cast()),
        },
    }];

    let mut new_dacl: *mut ACL = core::ptr::null_mut();
    let old_acl_opt = if dacl_present.as_bool() && !old_dacl.is_null() {
        Some(old_dacl.cast_const())
    } else {
        None
    };
    let acl_err = unsafe { SetEntriesInAclW(Some(&explicit_access), old_acl_opt, &mut new_dacl) };
    if acl_err != WIN32_ERROR(0) {
        return Err(format!(
            "SetEntriesInAclW failed: win32 error {}",
            acl_err.0
        ));
    }
    let _acl_guard = LocalFreeGuard(new_dacl.cast());

    let mut new_sd = SECURITY_DESCRIPTOR::default();
    let new_sd_ptr = PSECURITY_DESCRIPTOR((&mut new_sd as *mut SECURITY_DESCRIPTOR).cast());
    unsafe {
        InitializeSecurityDescriptor(new_sd_ptr, SECURITY_DESCRIPTOR_REVISION_1)
            .map_err(|e| format!("InitializeSecurityDescriptor failed: {e}"))?;
        SetSecurityDescriptorDacl(new_sd_ptr, true, Some(new_dacl.cast_const()), false)
            .map_err(|e| format!("SetSecurityDescriptorDacl failed: {e}"))?;
        SetServiceObjectSecurity(service_handle.0, DACL_SECURITY_INFORMATION, new_sd_ptr)
            .map_err(|e| format!("SetServiceObjectSecurity failed: {e}"))?;
    }

    Ok(())
}

fn install_broker_service() -> Result<(), String> {
    let tunnels_dir = default_tunnels_dir();
    ensure_restricted_tunnels_dir(&tunnels_dir, true).map_err(|e| e.to_string())?;

    let exe_path = std::env::current_exe().map_err(|e| e.to_string())?;
    let launch_cmd = format!("\"{}\" --service", exe_path.display());

    let wide_name = to_wide_null(BROKER_SERVICE_NAME).map_err(|e| e.to_string())?;
    let wide_display = to_wide_null(BROKER_SERVICE_DISPLAY_NAME).map_err(|e| e.to_string())?;
    let wide_cmd = to_wide_null(&launch_cmd).map_err(|e| e.to_string())?;
    let mut wide_desc = to_wide_null(BROKER_SERVICE_DESCRIPTION).map_err(|e| e.to_string())?;

    let scm = open_sc_manager(SC_MANAGER_ALL_ACCESS).map_err(|e| e.to_string())?;

    let service_guard = match unsafe {
        CreateServiceW(
            scm.0,
            PCWSTR(wide_name.as_ptr()),
            PCWSTR(wide_display.as_ptr()),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            PCWSTR(wide_cmd.as_ptr()),
            PCWSTR::null(),
            None,
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
        )
    } {
        Ok(h) => ScHandleGuard(h),
        Err(err) if win32_err_code(&err) == Some(ERROR_SERVICE_EXISTS) => {
            let handle = unsafe {
                OpenServiceW(
                    scm.0,
                    PCWSTR(wide_name.as_ptr()),
                    SERVICE_ALL_ACCESS | READ_CONTROL_ACCESS | WRITE_DAC_ACCESS,
                )
            }
            .map_err(|e| format!("OpenServiceW({BROKER_SERVICE_NAME}) failed: {e}"))?;
            let guard = ScHandleGuard(handle);

            let current_state =
                query_service_state(BROKER_SERVICE_NAME).map_err(|e| e.to_string())?;
            if current_state != 0 && current_state != SERVICE_STOPPED.0 {
                let mut status = SERVICE_STATUS::default();
                let _ = unsafe { ControlService(guard.0, SERVICE_CONTROL_STOP, &mut status) };
                wait_for_scm_state(
                    BROKER_SERVICE_NAME,
                    SERVICE_STOPPED.0,
                    Duration::from_secs(15),
                )?;
            }

            unsafe {
                ChangeServiceConfigW(
                    guard.0,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL,
                    PCWSTR(wide_cmd.as_ptr()),
                    PCWSTR::null(),
                    None,
                    PCWSTR::null(),
                    PCWSTR::null(),
                    PCWSTR::null(),
                    PCWSTR(wide_display.as_ptr()),
                )
                .map_err(|e| format!("ChangeServiceConfigW({BROKER_SERVICE_NAME}) failed: {e}"))?;
            }
            guard
        }
        Err(err) => {
            return Err(format!(
                "CreateServiceW({BROKER_SERVICE_NAME}) failed: {err}"
            ));
        }
    };

    let desc = SERVICE_DESCRIPTIONW {
        lpDescription: windows::core::PWSTR(wide_desc.as_mut_ptr()),
    };
    unsafe {
        ChangeServiceConfig2W(
            service_guard.0,
            SERVICE_CONFIG_DESCRIPTION,
            Some((&desc as *const SERVICE_DESCRIPTIONW).cast()),
        )
        .map_err(|e| format!("ChangeServiceConfig2W(DESCRIPTION) failed: {e}"))?;
    }

    grant_interactive_user_service_rights(&service_guard)?;

    if let Err(err) = unsafe { StartServiceW(service_guard.0, None) } {
        if win32_err_code(&err) != Some(ERROR_SERVICE_ALREADY_RUNNING) {
            return Err(format!(
                "StartServiceW({BROKER_SERVICE_NAME}) failed: {err}"
            ));
        }
    }
    wait_for_scm_state(
        BROKER_SERVICE_NAME,
        SERVICE_RUNNING.0,
        Duration::from_secs(15),
    )?;
    info!("Installed and started {BROKER_SERVICE_NAME}");
    Ok(())
}

fn uninstall_broker_service() -> Result<(), String> {
    let tunnel_svc = tunnel_service_name(DEFAULT_TUNNEL_NAME);
    stop_and_delete_service(&tunnel_svc).map_err(|e| e.to_string())?;
    wait_for_scm_state(&tunnel_svc, 0, Duration::from_secs(15))?;

    let tunnels_dir = default_tunnels_dir();
    match fs::remove_dir_all(&tunnels_dir) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(format!("failed removing {}: {err}", tunnels_dir.display()));
        }
    }

    stop_and_delete_service(BROKER_SERVICE_NAME).map_err(|e| e.to_string())?;
    match wait_for_scm_state(BROKER_SERVICE_NAME, 0, Duration::from_secs(15)) {
        Ok(()) => {}
        Err(err) => {
            // Confirm it wasn't just absent already.
            if query_service_state(BROKER_SERVICE_NAME).unwrap_or(0) != 0 {
                return Err(err);
            }
        }
    }
    let _ = ERROR_SERVICE_DOES_NOT_EXIST;
    info!("Uninstalled {BROKER_SERVICE_NAME} and cleaned up {tunnel_svc}");
    Ok(())
}

fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .try_init();
}

fn main() -> ExitCode {
    init_logging();
    let args: Vec<OsString> = std::env::args_os().collect();
    let mode = match parse_cli_args(&args) {
        Ok(m) => m,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::from(2);
        }
    };

    let result = match mode {
        CliMode::Service => run_windows_service(),
        CliMode::Tunnel(conf_path) => {
            run_tunnel_service_from_cli(&conf_path).map_err(|e| e.to_string())
        }
        CliMode::Install => install_broker_service(),
        CliMode::Uninstall => uninstall_broker_service(),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            error!("{err}");
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cli_args() {
        let exe = OsString::from("FreetonVPNService.exe");
        assert_eq!(
            parse_cli_args(&[exe.clone(), OsString::from("--service")]),
            Ok(CliMode::Service)
        );
        assert_eq!(
            parse_cli_args(&[exe.clone(), OsString::from("--install")]),
            Ok(CliMode::Install)
        );
        assert_eq!(
            parse_cli_args(&[exe.clone(), OsString::from("--uninstall")]),
            Ok(CliMode::Uninstall)
        );
        assert_eq!(
            parse_cli_args(&[
                exe.clone(),
                OsString::from("--tunnel"),
                OsString::from(r"C:\ProgramData\FreetonVPN\tunnels\FreetonVPN.conf")
            ]),
            Ok(CliMode::Tunnel(PathBuf::from(
                r"C:\ProgramData\FreetonVPN\tunnels\FreetonVPN.conf"
            )))
        );
        assert!(parse_cli_args(std::slice::from_ref(&exe)).is_err());
        assert!(parse_cli_args(&[exe.clone(), OsString::from("--tunnel")]).is_err());
        assert!(parse_cli_args(&[exe, OsString::from("--unknown")]).is_err());
    }
}
