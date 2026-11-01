//! Host, OS, session, service, autostart and privilege-elevation context.
//! Everything that describes *the machine* rather than the target process.

use std::ffi::{c_void, OsString};
use std::os::windows::ffi::OsStringExt;
use std::path::Path;

use super::ffi;
use crate::model::*;
use crate::util::{self, WResult, WinError};

// ---------------------------------------------------------------------------
// Elevation of the inspecting engine
// ---------------------------------------------------------------------------

pub fn is_elevated() -> bool {
    unsafe {
        let mut tok: ffi::HANDLE = std::ptr::null_mut();
        if ffi::OpenProcessToken(ffi::GetCurrentProcess(), ffi::TOKEN_QUERY, &mut tok) == ffi::FALSE
        {
            return ffi::IsUserAnAdmin() != ffi::FALSE;
        }
        let mut elevation: u32 = 0;
        let mut ret: u32 = 0;
        let ok = ffi::GetTokenInformation(
            tok,
            ffi::TOKEN_ELEVATION_CLASS,
            &mut elevation as *mut u32 as *mut c_void,
            std::mem::size_of::<u32>() as u32,
            &mut ret,
        );
        ffi::CloseHandle(tok);
        ok != ffi::FALSE && elevation != 0
    }
}

pub fn current_exe() -> String {
    let mut buf = vec![0u16; 32_768];
    unsafe {
        let n = ffi::GetModuleFileNameW(0, buf.as_mut_ptr(), buf.len() as u32);
        util::from_wide(&buf[..n as usize])
    }
}

/// Re-launches the engine elevated via the UAC broker ("runas" verb).
/// Returns `Ok(true)` when the child was started, `Ok(false)` when the operator
/// declined the prompt (ERROR_CANCELLED) - never a hard failure.
pub fn relaunch_elevated(args: &[String]) -> WResult<bool> {
    let exe = util::wide(current_exe());
    let params = util::wide(
        args.iter()
            .map(|a| quote_arg(a))
            .collect::<Vec<_>>()
            .join(" "),
    );
    let verb = util::wide("runas");
    unsafe {
        let mut sei = ffi::SHELLEXECUTEINFOW::default();
        sei.cbSize = std::mem::size_of::<ffi::SHELLEXECUTEINFOW>() as u32;
        sei.fMask = ffi::SEE_MASK_NOCLOSEPROCESS;
        sei.lpVerb = verb.as_ptr();
        sei.lpFile = exe.as_ptr();
        sei.lpParameters = params.as_ptr();
        sei.nShow = ffi::SW_SHOWNORMAL;
        if ffi::ShellExecuteExW(&mut sei) != ffi::FALSE {
            if !sei.hProcess.is_null() {
                ffi::CloseHandle(sei.hProcess);
            }
            return Ok(true);
        }
        let e = WinError::last();
        if e.code == ffi::ERROR_CANCELLED {
            return Ok(false);
        }
        Err(e)
    }
}

/// Opens a URL in the default browser (used to surface the dashboard).
/// Returns whether the shell accepted the request, so the caller can print a
/// copyable URL instead of silently doing nothing on a locked-down box.
pub fn open_url(url: &str) -> bool {
    let verb = util::wide("open");
    let file = util::wide(url);
    unsafe {
        let mut sei = ffi::SHELLEXECUTEINFOW::default();
        sei.cbSize = std::mem::size_of::<ffi::SHELLEXECUTEINFOW>() as u32;
        sei.lpVerb = verb.as_ptr();
        sei.lpFile = file.as_ptr();
        sei.nShow = ffi::SW_SHOWNORMAL;
        let ok = ffi::ShellExecuteExW(&mut sei) != ffi::FALSE;
        if !sei.hProcess.is_null() {
            ffi::CloseHandle(sei.hProcess);
        }
        ok
    }
}

fn quote_arg(a: &str) -> String {
    if a.contains(' ') && !a.starts_with('"') {
        format!("\"{a}\"")
    } else {
        a.to_string()
    }
}

// ---------------------------------------------------------------------------
// Host / OS fingerprint
// ---------------------------------------------------------------------------

pub fn computer_name(kind: u32) -> String {
    let mut buf = vec![0u16; 512];
    let mut size = buf.len() as u32;
    unsafe {
        if ffi::GetComputerNameExW(kind, buf.as_mut_ptr(), &mut size) == ffi::FALSE {
            return String::new();
        }
    }
    util::from_wide(&buf[..size as usize])
}

pub fn os_info() -> OsInfo {
    unsafe {
        let mut vi = ffi::RTL_OSVERSIONINFOW::default();
        vi.dwOSVersionInfoSize = std::mem::size_of::<ffi::RTL_OSVERSIONINFOW>() as u32;
        let st = ffi::RtlGetVersion(&mut vi);
        if st < 0 {
            return OsInfo::default();
        }
        let product = match (vi.dwMajorVersion, vi.dwMinorVersion) {
            (10, _) if vi.dwBuildNumber >= 22000 => "Windows 11",
            (10, _) => "Windows 10",
            (6, 3) => "Windows 8.1",
            (6, 2) => "Windows 8",
            (6, 1) => "Windows 7",
            (6, 0) => "Windows Vista",
            _ => "Windows",
        };
        OsInfo {
            product_name: product.to_string(),
            version: format!(
                "{}.{}.{}",
                vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber
            ),
            build: vi.dwBuildNumber,
            native_arch: native_arch(),
        }
    }
}

pub fn native_arch() -> String {
    let m = if cfg!(target_arch = "aarch64") {
        ffi::IMAGE_FILE_MACHINE_ARM64
    } else {
        ffi::IMAGE_FILE_MACHINE_AMD64
    };
    // Confirm via the API rather than trusting our own build target.
    unsafe {
        let mut proc_m: u16 = 0;
        let mut native_m: u16 = 0;
        if ffi::IsWow64Process2(ffi::GetCurrentProcess(), &mut proc_m, &mut native_m) != ffi::FALSE
            && native_m != 0
        {
            return match native_m {
                ffi::IMAGE_FILE_MACHINE_AMD64 => "x64",
                ffi::IMAGE_FILE_MACHINE_ARM64 => "arm64",
                ffi::IMAGE_FILE_MACHINE_I386 => "x86",
                _ => "unknown",
            }
            .to_string();
        }
        match m {
            ffi::IMAGE_FILE_MACHINE_ARM64 => "arm64".to_string(),
            _ => "x64".to_string(),
        }
    }
}

pub fn host_info() -> HostInfo {
    let uptime_ms = unsafe { ffi::GetTickCount64() };
    let uptime_seconds = uptime_ms / 1000;
    let now_ms = util::UnixTime::now().unix_ms;
    let boot_ms = now_ms - uptime_ms as i64;
    let bias = unsafe {
        let mut tz = ffi::TIME_ZONE_INFORMATION::default();
        let r = ffi::GetTimeZoneInformation(&mut tz);
        if r == 0xFFFF_FFFF {
            0
        } else {
            tz.Bias
        }
    };
    HostInfo {
        computer_name: computer_name(ffi::COMPUTER_NAME_NETBIOS),
        dns_hostname: computer_name(ffi::COMPUTER_NAME_DNS_HOSTNAME),
        dns_domain: computer_name(ffi::COMPUTER_NAME_DNS_DOMAIN),
        uptime_seconds,
        boot_time_utc: Some(util::rfc3339(boot_ms, 0)),
        timezone_bias_minutes: bias,
    }
}

// ---------------------------------------------------------------------------
// Session context (WTS)
// ---------------------------------------------------------------------------

/// Copies a WTS buffer into owned memory and frees the WTS allocation at once.
fn wts_raw(session_id: u32, class: u32) -> Option<Vec<u8>> {
    let api = ffi::wtsapi()?;
    unsafe {
        let mut buf: *mut u16 = std::ptr::null_mut();
        let mut bytes: u32 = 0;
        if (api.QuerySessionInformationW)(
            ffi::WTS_CURRENT_SERVER_HANDLE,
            session_id,
            class,
            &mut buf,
            &mut bytes,
        ) == ffi::FALSE
            || buf.is_null()
            || bytes == 0
        {
            return None;
        }
        let out = std::slice::from_raw_parts(buf as *const u8, bytes as usize).to_vec();
        (api.FreeMemory)(buf as *mut c_void);
        Some(out)
    }
}

fn wts_string(session_id: u32, class: u32) -> String {
    match wts_raw(session_id, class) {
        Some(raw) => {
            let wide: Vec<u16> = raw
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&c| c != 0)
                .collect();
            String::from_utf16_lossy(&wide)
        }
        None => String::new(),
    }
}

pub fn session_info(session_id: u32, pid: u32) -> SessionInfo {
    // A process can only run in session 0 if it is a service; PID 0/4 are the
    // kernel itself. Distinguish that from a real interactive/RDP session.
    let is_remote = wts_raw(session_id, ffi::WTSIsRemoteSession)
        .map(|b| b.len() >= 4 && u32::from_le_bytes([b[0], b[1], b[2], b[3]]) != 0)
        .unwrap_or(false);

    let protocol = wts_raw(session_id, ffi::WTSClientProtocolType)
        .map(|b| {
            if b.len() >= 2 {
                u16::from_le_bytes([b[0], b[1]])
            } else {
                0xFFFF
            }
        })
        .unwrap_or(0xFFFF);

    let kind = if pid > 0 && pid <= 4 {
        "kernel"
    } else if session_id == 0 {
        "service"
    } else if protocol == 0 {
        "console"
    } else if protocol == 2 || is_remote {
        "rdp"
    } else {
        "other"
    };

    let client_address = wts_raw(session_id, ffi::WTSClientAddress)
        .map(|raw| {
            // WTS_CLIENT_ADDRESS { u32 AddressFamily; u8 Address[20] }
            if raw.len() < 24 {
                return String::new();
            }
            let family = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
            if family == ffi::AF_INET && raw[4..8] != [0, 0, 0, 0] {
                format!("{}.{}.{}.{}", raw[4], raw[5], raw[6], raw[7])
            } else if family == ffi::AF_INET6 && raw[4..20].iter().any(|&b| b != 0) {
                (0..8)
                    .map(|i| format!("{:x}", u16::from_be_bytes([raw[4 + i * 2], raw[5 + i * 2]])))
                    .collect::<Vec<_>>()
                    .join(":")
            } else {
                String::new()
            }
        })
        .unwrap_or_default();

    SessionInfo {
        id: session_id,
        kind: kind.to_string(),
        username: wts_string(session_id, ffi::WTSUserName),
        domain: wts_string(session_id, ffi::WTSDomainName),
        client_name: wts_string(session_id, ffi::WTSClientName),
        client_address,
    }
}

// ---------------------------------------------------------------------------
// Services (SCM)
// ---------------------------------------------------------------------------

fn start_type_name(t: u32) -> &'static str {
    match t {
        0 => "boot",
        1 => "system",
        2 => "auto",
        3 => "manual",
        4 => "disabled",
        _ => "unknown",
    }
}

fn svc_type_name(t: u32) -> String {
    let mut parts = Vec::new();
    if t & 0x0000_0001 != 0 {
        parts.push("kernel_driver");
    }
    if t & 0x0000_0002 != 0 {
        parts.push("file_system_driver");
    }
    if t & 0x0000_0004 != 0 {
        parts.push("adapter");
    }
    if t & 0x0000_0008 != 0 {
        parts.push("recognizer_driver");
    }
    if t & 0x0000_0010 != 0 {
        parts.push("win32_own_process");
    }
    if t & 0x0000_0020 != 0 {
        parts.push("win32_share_process");
    }
    if t & 0x0000_0100 != 0 {
        parts.push("interactive_process");
    }
    if parts.is_empty() {
        "unknown".to_string()
    } else {
        parts.join("|")
    }
}

fn svc_state_name(s: u32) -> &'static str {
    match s {
        1 => "stopped",
        2 => "start_pending",
        3 => "stop_pending",
        4 => "running",
        5 => "continue_pending",
        6 => "pause_pending",
        7 => "paused",
        _ => "unknown",
    }
}

/// Services whose hosted process is the target, or whose configured binary is
/// the target image. Catches both "process is a service host" and "image is
/// registered as a service but currently dormant".
pub fn services_for_target(pid: u32, target_exe: &str) -> SectionMeta2<Vec<ServiceInfo>> {
    let target_name = Path::new(target_exe)
        .file_name()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let target_path_norm = normalize_path(target_exe);

    unsafe {
        let scm = ffi::OpenSCManagerW(
            std::ptr::null(),
            std::ptr::null(),
            ffi::SC_MANAGER_ENUMERATE_SERVICE | ffi::SC_MANAGER_CONNECT,
        );
        if scm.is_null() {
            let e = WinError::last();
            return SectionMeta2 {
                meta: SectionMeta::denied(format!("OpenSCManager failed: {e}")),
                data: Vec::new(),
            };
        }

        let mut out = Vec::new();
        let mut resume: u32 = 0;
        let mut warnings = Vec::new();
        let mut buf_len: u32 = 256 * 1024;
        let mut iterations = 0;

        loop {
            iterations += 1;
            if iterations > 64 {
                warnings.push("service enumeration truncated at 64 pages".into());
                break;
            }
            let mut buf = vec![0u8; buf_len as usize];
            let mut needed: u32 = 0;
            let mut returned: u32 = 0;
            let ok = ffi::EnumServicesStatusExW(
                scm,
                ffi::SC_ENUM_PROCESS_INFO,
                ffi::SERVICE_WIN32,
                ffi::SERVICE_STATE_ALL,
                buf.as_mut_ptr(),
                buf_len,
                &mut needed,
                &mut returned,
                &mut resume,
                std::ptr::null(),
            );
            if ok == ffi::FALSE {
                let e = WinError::last();
                if e.code == ffi::ERROR_MORE_DATA {
                    if needed > buf_len {
                        buf_len = needed + 8192;
                        continue;
                    }
                } else {
                    warnings.push(format!("EnumServicesStatusEx: {e}"));
                    break;
                }
            }

            let entry_size = std::mem::size_of::<ffi::ENUM_SERVICE_STATUS_PROCESSW>();
            for i in 0..returned as usize {
                let off = i * entry_size;
                if off + entry_size > buf.len() {
                    break;
                }
                let esp: ffi::ENUM_SERVICE_STATUS_PROCESSW =
                    std::ptr::read_unaligned(buf.as_ptr().add(off) as *const _);
                let svc_name = util::from_wide_ptr(esp.lpServiceName);
                let disp_name = util::from_wide_ptr(esp.lpDisplayName);
                let spid = esp.ServiceStatusProcess.dwProcessId;

                if spid != pid {
                    continue;
                }

                let mut info = ServiceInfo {
                    name: svc_name.clone(),
                    display_name: disp_name,
                    pid: spid,
                    state: svc_state_name(esp.ServiceStatusProcess.dwCurrentState).into(),
                    service_type: svc_type_name(esp.ServiceStatusProcess.dwServiceType),
                    ..Default::default()
                };

                if let Some(cfg) = query_service_config(&svc_name) {
                    info.binary_path = cfg.0;
                    info.start_type = cfg.1;
                    info.account = cfg.2;
                    let bin_norm = normalize_path(&strip_svc_args(&info.binary_path));
                    info.binary_matches_target = !target_name.is_empty()
                        && (bin_norm == target_path_norm
                            || bin_norm.ends_with(&format!("\\{target_name}")));
                }
                out.push(info);
            }

            if resume == 0 {
                break;
            }
            buf_len = 256 * 1024;
        }

        ffi::CloseServiceHandle(scm);
        let mut meta = SectionMeta::ok();
        for w in warnings {
            meta.warn(w);
        }
        SectionMeta2 { meta, data: out }
    }
}

pub struct SectionMeta2<T> {
    pub meta: SectionMeta,
    pub data: T,
}

/// Services that are registered (but not necessarily running) with a binary
/// path pointing at the target image - a classic persistence indicator.
pub fn services_with_binary_matching(target_exe: &str, pid: u32) -> Vec<ServiceInfo> {
    let target_norm = normalize_path(target_exe);
    if target_norm.is_empty() {
        return Vec::new();
    }
    unsafe {
        let scm = ffi::OpenSCManagerW(
            std::ptr::null(),
            std::ptr::null(),
            ffi::SC_MANAGER_ENUMERATE_SERVICE | ffi::SC_MANAGER_CONNECT,
        );
        if scm.is_null() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut resume: u32 = 0;
        let mut buf_len: u32 = 256 * 1024;
        let mut pages = 0;
        loop {
            pages += 1;
            if pages > 32 {
                break;
            }
            let mut buf = vec![0u8; buf_len as usize];
            let mut needed = 0u32;
            let mut returned = 0u32;
            let ok = ffi::EnumServicesStatusExW(
                scm,
                ffi::SC_ENUM_PROCESS_INFO,
                ffi::SERVICE_WIN32,
                ffi::SERVICE_STATE_ALL,
                buf.as_mut_ptr(),
                buf_len,
                &mut needed,
                &mut returned,
                &mut resume,
                std::ptr::null(),
            );
            if ok == ffi::FALSE {
                if WinError::last().code == ffi::ERROR_MORE_DATA && needed > buf_len {
                    buf_len = needed + 8192;
                    continue;
                }
                break;
            }
            let entry_size = std::mem::size_of::<ffi::ENUM_SERVICE_STATUS_PROCESSW>();
            for i in 0..returned as usize {
                let off = i * entry_size;
                if off + entry_size > buf.len() {
                    break;
                }
                let esp: ffi::ENUM_SERVICE_STATUS_PROCESSW =
                    std::ptr::read_unaligned(buf.as_ptr().add(off) as *const _);
                if esp.ServiceStatusProcess.dwProcessId == pid && pid != 0 {
                    continue; // already covered by the PID query
                }
                let name = util::from_wide_ptr(esp.lpServiceName);
                if let Some(cfg) = query_service_config(&name) {
                    let bin_norm = normalize_path(&strip_svc_args(&cfg.0));
                    if bin_norm == target_norm {
                        out.push(ServiceInfo {
                            name,
                            display_name: util::from_wide_ptr(esp.lpDisplayName),
                            binary_path: cfg.0,
                            start_type: cfg.1,
                            account: cfg.2,
                            service_type: svc_type_name(esp.ServiceStatusProcess.dwServiceType),
                            state: svc_state_name(esp.ServiceStatusProcess.dwCurrentState).into(),
                            pid: esp.ServiceStatusProcess.dwProcessId,
                            binary_matches_target: true,
                        });
                    }
                }
            }
            if resume == 0 {
                break;
            }
        }
        ffi::CloseServiceHandle(scm);
        out
    }
}

fn query_service_config(name: &str) -> Option<(String, String, String)> {
    unsafe {
        let scm = ffi::OpenSCManagerW(std::ptr::null(), std::ptr::null(), ffi::SC_MANAGER_CONNECT);
        if scm.is_null() {
            return None;
        }
        let wname = util::wide(name);
        let svc = ffi::OpenServiceW(scm, wname.as_ptr(), ffi::SERVICE_QUERY_CONFIG);
        if svc.is_null() {
            ffi::CloseServiceHandle(scm);
            return None;
        }
        let mut needed = 0u32;
        ffi::QueryServiceConfigW(svc, std::ptr::null_mut(), 0, &mut needed);
        if needed == 0 {
            ffi::CloseServiceHandle(svc);
            ffi::CloseServiceHandle(scm);
            return None;
        }
        let mut buf = vec![0u8; needed as usize + 512];
        let ok = ffi::QueryServiceConfigW(
            svc,
            buf.as_mut_ptr() as *mut ffi::QUERY_SERVICE_CONFIGW,
            buf.len() as u32,
            &mut needed,
        );
        let res = if ok == ffi::FALSE {
            None
        } else {
            let cfg: ffi::QUERY_SERVICE_CONFIGW =
                std::ptr::read_unaligned(buf.as_ptr() as *const ffi::QUERY_SERVICE_CONFIGW);
            Some((
                util::from_wide_ptr(cfg.lpBinaryPathName),
                start_type_name(cfg.dwStartType).to_string(),
                util::from_wide_ptr(cfg.lpServiceStartName),
            ))
        };
        ffi::CloseServiceHandle(svc);
        ffi::CloseServiceHandle(scm);
        res
    }
}

/// `"C:\Windows\system32\svchost.exe -k netsvcs -p"` -> `"C:\Windows\system32\svchost.exe"`
fn strip_svc_args(bin: &str) -> String {
    let b = bin.trim();
    if let Some(rest) = b.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            return rest[..end].to_string();
        }
    }
    if let Some(rest) = b.strip_prefix("\\??\\") {
        return strip_svc_args(rest);
    }
    if b.to_ascii_lowercase().starts_with("\\systemroot\\") {
        return format!(
            "{}\\{}",
            std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into()),
            &b[12..]
        );
    }
    // Unquoted path: stop at " -" / " /" argument boundary after the .exe
    let lower = b.to_ascii_lowercase();
    if let Some(idx) = lower.find(".exe") {
        return b[..idx + 4].to_string();
    }
    b.split_whitespace().next().unwrap_or(b).to_string()
}

pub fn normalize_path(p: &str) -> String {
    let mut s = p.trim().to_string();
    if let Some(rest) = s.strip_prefix("\\??\\") {
        s = rest.to_string();
    }
    if let Some(rest) = s.strip_prefix("\\\\?\\") {
        s = rest.to_string();
    }
    let lower = s.to_ascii_lowercase();
    if lower.starts_with("\\systemroot\\") {
        s = format!(
            "{}\\{}",
            std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into()),
            &s[12..]
        );
    } else if lower.starts_with("system32\\") {
        s = format!(
            "{}\\{}",
            std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into()),
            s
        );
    }
    // Expand %SystemRoot% style references found in service ImagePath values.
    s = expand_env(&s);
    s.replace('/', "\\").trim_end_matches('\\').to_lowercase()
}

pub fn expand_env(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let src = util::wide(s);
    let mut out = vec![0u16; 4096];
    unsafe {
        let n = ffi::ExpandEnvironmentStringsW(src.as_ptr(), out.as_mut_ptr(), out.len() as u32);
        if n > 0 && (n as usize) <= out.len() {
            return util::from_wide(&out[..n as usize]);
        }
    }
    s.to_string()
}

// ---------------------------------------------------------------------------
// Registry autostart (persistence) correlation
// ---------------------------------------------------------------------------

pub struct AutorunScan {
    pub entries: Vec<AutorunEntry>,
    pub notes: Vec<String>,
}

const AUTORUN_KEYS: &[(&str, &str)] = &[
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    (
        "HKLM",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
    ),
    (
        "HKLM",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    ),
    (
        "HKLM",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    ),
    (
        "HKLM",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    ),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    (
        "HKCU",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    ),
    (
        "HKLM",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    ),
];

/// Scans the classic autostart locations and flags entries whose command line
/// references the target image. Read-only; safely degrades on access denial.
pub fn scan_autoruns(target_exe: &str) -> AutorunScan {
    let target_name = Path::new(target_exe)
        .file_name()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let target_norm = normalize_path(target_exe);
    let mut entries = Vec::new();
    let mut notes = Vec::new();

    for (hive, key) in AUTORUN_KEYS {
        let root = match *hive {
            "HKLM" => ffi::HKEY_LOCAL_MACHINE,
            "HKCU" => ffi::HKEY_CURRENT_USER,
            _ => continue,
        };
        let wkey = util::wide(*key);
        unsafe {
            let mut hk: ffi::HKEY = 0;
            let rc = ffi::RegOpenKeyExW(root, wkey.as_ptr(), 0, ffi::KEY_READ, &mut hk);
            if rc != 0 {
                if rc as u32 != ffi::ERROR_FILE_NOT_FOUND {
                    notes.push(format!(
                        "{hive}\\{key}: {}",
                        util::format_message(rc as u32)
                    ));
                }
                continue;
            }
            let mut index = 0u32;
            loop {
                let mut name = vec![0u16; 512];
                let mut name_len = name.len() as u32;
                let mut data = vec![0u8; 8192];
                let mut data_len = data.len() as u32;
                let mut ty: u32 = 0;
                let rc = ffi::RegEnumValueW(
                    hk,
                    index,
                    name.as_mut_ptr(),
                    &mut name_len,
                    std::ptr::null_mut(),
                    &mut ty,
                    data.as_mut_ptr(),
                    &mut data_len,
                );
                if rc as u32 == ffi::ERROR_NO_MORE_ITEMS {
                    break;
                }
                if rc != 0 {
                    if rc as u32 != ffi::ERROR_NO_MORE_ITEMS {
                        notes.push(format!(
                            "{hive}\\{key} enum: {}",
                            util::format_message(rc as u32)
                        ));
                    }
                    break;
                }
                index += 1;

                // Winlogon is a mixed bag - only keep the execution values.
                let value_name = util::from_wide(&name);
                if key.ends_with("Winlogon")
                    && !matches!(
                        value_name.to_ascii_lowercase().as_str(),
                        "shell" | "userinit" | "taskman" | "appsetup" | "vmapplet"
                    )
                {
                    continue;
                }

                let command = match ty {
                    ffi::REG_SZ => decode_utf16(&data[..data_len as usize]),
                    ffi::REG_EXPAND_SZ => expand_env(&decode_utf16(&data[..data_len as usize])),
                    ffi::REG_MULTI_SZ => {
                        decode_utf16(&data[..data_len as usize]).replace('\0', "; ")
                    }
                    _ => continue,
                };
                if command.trim().is_empty() {
                    continue;
                }
                let cmd_lower = command.to_ascii_lowercase();
                let cmd_norm = normalize_path(&strip_svc_args(&command));
                let matches = (!target_name.is_empty() && cmd_lower.contains(&target_name))
                    || (!target_norm.is_empty() && cmd_norm == target_norm);
                entries.push(AutorunEntry {
                    hive: (*hive).to_string(),
                    key: (*key).to_string(),
                    value_name,
                    command,
                    matches_target: matches,
                });
            }
            ffi::RegCloseKey(hk);
        }
    }
    AutorunScan { entries, notes }
}

fn decode_utf16(bytes: &[u8]) -> String {
    let wide: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&c| c != 0)
        .collect();
    OsString::from_wide(&wide).to_string_lossy().into_owned()
}
