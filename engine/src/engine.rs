//! Collection orchestrator.
//!
//! Every module is isolated behind `catch_unwind`, so a defect in one collector
//! (or an unexpected FFI panic) degrades that single section to `error` instead
//! of taking down the acquisition - the same defensive posture commercial DFIR
//! tooling takes when touching hostile processes.

use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Instant;

use crate::model::*;
use crate::util::{self, rfc3339_of, UnixTime};
use crate::win::{
    binary, ffi, handles, kernel, memory, modules, net, paths, process, sys, token, tree, window,
};

#[derive(Debug, Clone)]
pub struct Options {
    pub handle_cap: u32,
    pub include_handles: bool,
    pub resolve_dns: bool,
    pub case: CaseInfo,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            handle_cap: handles::DEFAULT_HANDLE_CAP,
            include_handles: true,
            resolve_dns: false,
            case: CaseInfo::default(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Target {
    /// `interactive_pick` | `hotkey_pick` | `explicit_pid` | `explicit_hwnd`
    pub mode: String,
    pub hwnd: isize,
    pub pid: u32,
    pub screen_x: i32,
    pub screen_y: i32,
    pub picked_at_utc: String,
}

impl Target {
    pub fn from_pid(pid: u32) -> Self {
        Target {
            mode: "explicit_pid".into(),
            pid,
            picked_at_utc: rfc3339_of(UnixTime::now()).unwrap_or_default(),
            ..Default::default()
        }
    }

    pub fn from_pick(p: &window::PickResult) -> Self {
        Target {
            mode: if p.via.is_empty() {
                "interactive_pick".into()
            } else {
                p.via.clone()
            },
            hwnd: p.hwnd,
            pid: p.pid,
            screen_x: p.screen_x,
            screen_y: p.screen_y,
            picked_at_utc: p.picked_at_utc.clone(),
        }
    }
}

pub struct Custody {
    events: Vec<CustodyEvent>,
    seq: u32,
}

impl Custody {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            seq: 0,
        }
    }
    pub fn log(&mut self, action: &str, detail: impl Into<String>) {
        self.seq += 1;
        self.events.push(CustodyEvent {
            seq: self.seq,
            at_utc: rfc3339_of(UnixTime::now()).unwrap_or_default(),
            action: action.to_string(),
            detail: detail.into(),
        });
    }
    pub fn into_events(self) -> Vec<CustodyEvent> {
        self.events
    }
}

impl Default for Custody {
    fn default() -> Self {
        Self::new()
    }
}

/// Runs a collector, converting a panic into an `Err(String)`.
fn guard<T>(name: &str, f: impl FnOnce() -> T) -> Result<T, String> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(v) => Ok(v),
        Err(p) => {
            let msg = if let Some(s) = p.downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = p.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            Err(format!("collector '{name}' panicked: {msg}"))
        }
    }
}

/// Performs a complete acquisition for one target.
pub fn inspect(target: &Target, opts: &Options) -> Report {
    let started = Instant::now();
    let started_at = rfc3339_of(UnixTime::now()).unwrap_or_default();
    let mut custody = Custody::new();
    custody.log(
        "acquisition_start",
        format!(
            "{} v{} | schema {} | mode={} pid={}",
            TOOL_NAME, TOOL_VERSION, SCHEMA_VERSION, target.mode, target.pid
        ),
    );

    // Elevation handling: try to obtain SeDebugPrivilege; never fatal.
    let already_elevated = sys::is_elevated();
    let debug_priv = token::enable_debug_privilege();
    custody.log(
        "privilege_state",
        format!("elevated={already_elevated} SeDebugPrivilege_enabled={debug_priv}"),
    );

    let pid = target.pid;
    let entries = guard("process_snapshot", tree::snapshot).unwrap_or_else(|e| {
        custody.log("module_failed", format!("process_snapshot: {e}"));
        Vec::new()
    });

    // ---------------------------------------------------------------- module A
    let outcome = process::open_for_forensics(pid);
    let mut process_info = ProcessInfo {
        pid,
        thread_count: tree::thread_count_of(&entries, pid),
        ..Default::default()
    };

    if let Some(p) = outcome.process.as_ref() {
        process_info.accessible = true;
        match p.image_path() {
            Ok(path) => {
                process_info.image_path_source = "live process (QueryFullProcessImageNameW)".into();
                process_info.image_path = path.clone();
                process_info.image_name = std::path::Path::new(&path)
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default();
                process_info.image_dir = std::path::Path::new(&path)
                    .parent()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default();
            }
            Err(e) => {
                process_info.meta = SectionMeta::partial(format!("image path unavailable: {e}"));
            }
        }
        let (arch, wow) = p.architecture();
        process_info.arch = arch;
        process_info.is_wow64 = wow;
        process_info.handle_count = p.handle_count();
        process_info.priority_class = p.priority_class();
        match p.times() {
            Ok(t) => process_info.times = t,
            Err(e) => process_info.meta.warn(format!("GetProcessTimes: {e}")),
        }
        if let Some(m) = p.memory() {
            process_info.memory = m;
        }
        process_info.parent_pid = p.parent_pid().unwrap_or_else(|| {
            entries
                .iter()
                .find(|e| e.pid == pid)
                .map(|e| e.ppid)
                .unwrap_or(0)
        });
        let (level, signer) = p.protection();
        process_info.protection_level = level;
        process_info.protection_signer = signer;

        let peb = p.peb_snapshot();
        if peb.readable {
            process_info.command_line = peb.command_line;
            process_info.current_directory = peb.current_directory;
            process_info.dll_path = peb.dll_path;
            process_info.environment = peb.environment;
            process_info.command_line_source = "live PEB (RTL_USER_PROCESS_PARAMETERS)".into();
            process_info.environment_source = "live PEB environment block".into();
        } else {
            // Fall back to a CIM query through PowerShell, clearly labelled so the
            // examiner knows the provenance is weaker than live memory.
            process_info.command_line_source = "unavailable (PEB unreadable)".into();
            process_info.environment_source = "unavailable".into();
            process_info
                .meta
                .warn(peb.error.unwrap_or_else(|| "PEB read failed".into()));
            if let Some(cl) = cim_command_line(pid) {
                process_info.command_line = Some(cl);
                process_info.command_line_source =
                    "Win32_Process.CommandLine (CIM fallback)".into();
                process_info
                    .meta
                    .warn("command line came from CIM, not live memory");
            }
        }
    } else {
        process_info.accessible = false;
        let err = outcome
            .error
            .map(|e| e.to_string())
            .unwrap_or_else(|| "OpenProcess failed".into());
        process_info.access_error = Some(err.clone());
        process_info.meta = SectionMeta::with(
            if outcome.full_access {
                Status::Error
            } else {
                Status::Denied
            },
            format!("process handle not obtainable: {err}"),
        );
        process_info
            .meta
            .warnings
            .push("re-run the engine elevated (Run as administrator) to inspect protected/SYSTEM processes".into());
        // Still recover what we can without a handle: the kernel's process table
        // is queryable by a standard user and carries the image name, start time
        // and parent - enough to hash and signature-check the image offline.
        if let Some(e) = entries.iter().find(|e| e.pid == pid) {
            process_info.image_name = e.name.clone();
            process_info.thread_count = e.threads;
        }
        if let Some(ki) = kernel::kernel_process_info(pid) {
            process_info.parent_pid = ki.ppid;
            process_info.session_id = ki.session_id;
            process_info.thread_count = ki.threads;
            process_info.handle_count = ki.handles;
            process_info.meta.note(format!(
                "kernel process table: {} thread(s), parent pid {}, session {}",
                ki.threads, ki.ppid, ki.session_id
            ));
            if let Some(created) = util::rfc3339_of(ki.created) {
                process_info.times.created_utc = Some(created);
                process_info.times.created_unix_ms = ki.created.unix_ms;
                process_info.times.created_filetime_raw = ki.created.raw_filetime;
                let age = util::UnixTime::now().unix_ms - ki.created.unix_ms;
                process_info.times.elapsed_ms = age.max(0) as u64;
            }
            if let Some(native) = ki.image_name {
                let direct = paths::resolve_kernel_image_path(&native);
                let (resolved, search_note) = match direct {
                    Some(p) => (Some(p), ""),
                    None => match paths::resolve_bare_image_name(&native) {
                        Some(p) => (
                            Some(p),
                            " - located by unambiguous name search in the system directories (NOT an authoritative path)",
                        ),
                        None => (None, ""),
                    },
                };
                process_info.image_path_source = format!(
                    "kernel process table image name ({native}){}{}",
                    if resolved.is_some() {
                        " - resolved to an existing DOS path"
                    } else {
                        " - NOT resolvable on disk"
                    },
                    search_note
                );
                if process_info.image_name.is_empty() {
                    process_info.image_name =
                        paths::file_name_of(&resolved.clone().unwrap_or_else(|| native.clone()));
                }
                if let Some(path) = resolved {
                    process_info.image_dir = std::path::Path::new(&path)
                        .parent()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    process_info.image_path = path;
                }
                process_info.meta.note(
                    "no process handle was obtainable; identity came from the kernel process table, so live memory (PEB), token, modules and handles are unavailable",
                );
            }
        }
        if let Some(cl) = cim_command_line(pid) {
            process_info.command_line = Some(cl);
            process_info.command_line_source = "Win32_Process.CommandLine (CIM fallback)".into();
        }
    }

    // Session id from the OS (authoritative); the kernel-table value is only a
    // fallback when the API is refused.
    let mut sid = 0u32;
    if unsafe { ffi::ProcessIdToSessionId(pid, &mut sid) } != ffi::FALSE {
        process_info.session_id = sid;
    }
    custody.log(
        "module_collect",
        format!(
            "process_identity pid={pid} status={}",
            process_info.meta.status.as_str()
        ),
    );

    // ---------------------------------------------------------------- module B
    let user_context = match outcome.process.as_ref() {
        Some(p) => guard("user_context", || {
            token::collect(p.handle, pid, process_info.session_id)
        })
        .unwrap_or_else(|e| {
            custody.log("module_failed", format!("user_context: {e}"));
            UserContext {
                meta: SectionMeta::error(e),
                ..Default::default()
            }
        }),
        None => UserContext {
            meta: SectionMeta::denied("no process handle - token not readable"),
            session: sys::session_info(process_info.session_id, pid),
            ..Default::default()
        },
    };
    process_info.is_elevated_process = user_context.elevation.is_elevated;
    custody.log(
        "module_collect",
        format!(
            "user_context account={}\\{} integrity={} elevated={}",
            user_context.account_domain,
            user_context.account_name,
            user_context.integrity.name,
            user_context.elevation.is_elevated
        ),
    );

    // ---------------------------------------------------------------- window A
    let window_info = if target.hwnd != 0 {
        window::window_info(target.hwnd)
    } else {
        match window::first_window_of_pid(pid) {
            Some(h) => window::window_info(h),
            None => WindowInfo {
                process_id: pid,
                ..Default::default()
            },
        }
    };

    // ---------------------------------------------------------------- module C
    let genealogy = guard("genealogy", || {
        tree::collect(
            pid,
            Some(process_info.parent_pid),
            process_info.times.created_unix_ms,
        )
    })
    .unwrap_or_else(|e| {
        custody.log("module_failed", format!("genealogy: {e}"));
        Genealogy {
            meta: SectionMeta::error(e),
            ..Default::default()
        }
    });
    custody.log(
        "module_collect",
        format!(
            "genealogy parent={:?} children={} descendants={}",
            genealogy.parent.as_ref().map(|p| p.pid),
            genealogy.children.len(),
            genealogy.descendants.len()
        ),
    );

    // ---------------------------------------------------------------- module D
    let network = guard("network", || net::collect(pid, opts.resolve_dns)).unwrap_or_else(|e| {
        custody.log("module_failed", format!("network: {e}"));
        NetworkInfo {
            meta: SectionMeta::error(e),
            ..Default::default()
        }
    });
    custody.log(
        "module_collect",
        format!(
            "network tcp={} udp={} established={} listening={}",
            network.tcp_count,
            network.udp_count,
            network.established_count,
            network.listening_count
        ),
    );

    // ---------------------------------------------------------------- module E
    let module_list = match outcome.process.as_ref() {
        Some(p) => guard("modules", || modules::collect(p, &process_info.image_path))
            .unwrap_or_else(|e| {
                custody.log("module_failed", format!("modules: {e}"));
                ModuleList {
                    meta: SectionMeta::error(e),
                    ..Default::default()
                }
            }),
        None => ModuleList {
            meta: SectionMeta::denied("no process handle - module list unreadable"),
            ..Default::default()
        },
    };
    custody.log(
        "module_collect",
        format!(
            "modules count={} status={}",
            module_list.count,
            module_list.meta.status.as_str()
        ),
    );

    let handle_list = if opts.include_handles {
        match outcome.process.as_ref() {
            Some(p) => guard("handles", || handles::collect(p, pid, opts.handle_cap))
                .unwrap_or_else(|e| {
                    custody.log("module_failed", format!("handles: {e}"));
                    HandleList {
                        meta: SectionMeta::error(e),
                        ..Default::default()
                    }
                }),
            None => HandleList {
                meta: SectionMeta::denied(
                    "no process handle (PROCESS_DUP_HANDLE) - handle table unreadable",
                ),
                ..Default::default()
            },
        }
    } else {
        HandleList {
            meta: SectionMeta::with(Status::Skipped, "disabled by --no-handles"),
            ..Default::default()
        }
    };
    custody.log(
        "module_collect",
        format!(
            "handles inspected={} resolved={} truncated={} status={}",
            handle_list.inspected,
            handle_list.items.len(),
            handle_list.truncated,
            handle_list.meta.status.as_str()
        ),
    );

    let mut registry = handles::registry_from_handles(pid, &handle_list);
    let autorun_scan = guard("autoruns", || sys::scan_autoruns(&process_info.image_path))
        .unwrap_or_else(|e| {
            custody.log("module_failed", format!("autoruns: {e}"));
            sys::AutorunScan {
                entries: Vec::new(),
                notes: vec![format!("autorun scan failed: {e}")],
            }
        });
    let matched_autoruns: Vec<AutorunEntry> = autorun_scan
        .entries
        .iter()
        .filter(|e| e.matches_target)
        .cloned()
        .collect();
    custody.log(
        "module_collect",
        format!(
            "autoruns scanned={} matching={}",
            autorun_scan.entries.len(),
            matched_autoruns.len()
        ),
    );
    registry.autoruns = matched_autoruns;
    registry.autorun_scan_notes = autorun_scan.notes;

    // ---------------------------------------------------------------- services
    let svc = guard("services", || {
        sys::services_for_target(pid, &process_info.image_path)
    })
    .unwrap_or_else(|e| sys::SectionMeta2 {
        meta: SectionMeta::error(e),
        data: Vec::new(),
    });
    let extra_svcs = guard("services_path_match", || {
        sys::services_with_binary_matching(&process_info.image_path, pid)
    })
    .unwrap_or_default();
    let mut services = ServiceList {
        meta: svc.meta,
        services: svc.data,
        ..Default::default()
    };
    for s in extra_svcs {
        if !services
            .services
            .iter()
            .any(|x| x.name.eq_ignore_ascii_case(&s.name))
        {
            services.services.push(s);
        }
    }
    custody.log(
        "module_collect",
        format!("services matched={}", services.services.len()),
    );

    // ---------------------------------------------------------------- module G
    let memory_report = match outcome.process.as_ref() {
        Some(p) => guard("memory_anomalies", || memory::collect(p, pid)).unwrap_or_else(|e| {
            custody.log("module_failed", format!("memory_anomalies: {e}"));
            MemoryReport {
                meta: SectionMeta::error(e),
                ..Default::default()
            }
        }),
        None => MemoryReport {
            meta: SectionMeta::denied("no process handle - address space not walkable"),
            ..Default::default()
        },
    };
    custody.log(
        "module_collect",
        format!(
            "memory regions={} exec={} rwx={} exec_private={} status={}",
            memory_report.regions_scanned,
            memory_report.executable_regions,
            memory_report.writable_executable_regions,
            memory_report.private_executable_regions,
            memory_report.meta.status.as_str()
        ),
    );

    // ---------------------------------------------------------------- module F
    let binary_info = guard("binary_integrity", || {
        binary::collect(&process_info.image_path, &process_info.image_path_source)
    })
    .unwrap_or_else(|e| {
        custody.log("module_failed", format!("binary_integrity: {e}"));
        BinaryInfo {
            meta: SectionMeta::error(e),
            ..Default::default()
        }
    });
    if !binary_info.sha256.is_empty() {
        custody.log(
            "hash_computed",
            format!(
                "SHA-256({}) = {} ({} bytes in {} ms at {})",
                binary_info.path,
                binary_info.sha256,
                binary_info.bytes_read,
                binary_info.hash_duration_ms,
                binary_info.hashed_at_utc
            ),
        );
    }

    // ------------------------------------------------------------- assemble
    let mut report = Report {
        schema: SCHEMA_VERSION.to_string(),
        tool: ToolInfo {
            name: TOOL_NAME.to_string(),
            version: TOOL_VERSION.to_string(),
            schema: SCHEMA_VERSION.to_string(),
            build_profile: if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            }
            .to_string(),
            arch: sys::native_arch(),
            os: sys::os_info(),
            host: sys::host_info(),
            running_elevated: already_elevated,
            debug_privilege_held: debug_priv,
            dpi_awareness: if crate::win::dpi::is_per_monitor_aware() {
                "per_monitor".to_string()
            } else {
                "system_or_unaware".to_string()
            },
            started_at_utc: started_at,
            completed_at_utc: String::new(),
            duration_ms: 0,
        },
        case: opts.case.clone(),
        selection: Selection {
            mode: target.mode.clone(),
            picked_at_utc: target.picked_at_utc.clone(),
            screen_x: target.screen_x,
            screen_y: target.screen_y,
            hwnd: if target.hwnd != 0 {
                format!("0x{:X}", target.hwnd)
            } else {
                String::new()
            },
            window: window_info,
        },
        process: process_info,
        user_context,
        genealogy,
        network,
        modules: module_list,
        handles: handle_list,
        registry,
        services,
        memory: memory_report,
        binary: binary_info,
        integrity: ReportIntegrity::default(),
    };

    // Aggregate section health so the UI can show one glanceable verdict.
    let mut warnings: Vec<String> = Vec::new();
    let mut degraded = 0u32;
    let sections: [(&str, &SectionMeta); 10] = [
        ("process", &report.process.meta),
        ("user_context", &report.user_context.meta),
        ("genealogy", &report.genealogy.meta),
        ("network", &report.network.meta),
        ("modules", &report.modules.meta),
        ("handles", &report.handles.meta),
        ("registry", &report.registry.meta),
        ("services", &report.services.meta),
        ("memory", &report.memory.meta),
        ("binary", &report.binary.meta),
    ];
    for (name, meta) in sections.iter() {
        if !meta.status.is_ok() {
            degraded += 1;
            warnings.push(format!(
                "{name}: {} - {}",
                meta.status.as_str(),
                meta.error.clone().unwrap_or_else(|| "see section".into())
            ));
        }
        for w in &meta.warnings {
            warnings.push(format!("{name}: {w}"));
        }
    }

    report.tool.completed_at_utc = rfc3339_of(UnixTime::now()).unwrap_or_default();
    report.tool.duration_ms = started.elapsed().as_millis() as u64;

    custody.log(
        "acquisition_complete",
        format!(
            "duration_ms={} sections_degraded={}",
            report.tool.duration_ms, degraded
        ),
    );

    report.integrity = ReportIntegrity {
        report_sha256: String::new(),
        hash_algorithm: "SHA-256".into(),
        seal_scope: "canonical JSON of this report with integrity.report_sha256 set to \"\"".into(),
        sealed_at_utc: String::new(),
        artifact_sections: sections.len() as u32,
        sections_degraded: degraded,
        warnings,
        custody_log: custody.into_events(),
    };
    report
}

/// Last-resort command line recovery through CIM. Explicitly labelled as a
/// weaker source in the report.
fn cim_command_line(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    let script = format!(
        "(Get-CimInstance Win32_Process -Filter \"ProcessId={pid}\" -ErrorAction SilentlyContinue).CommandLine"
    );
    let out = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

/// Convenience: pid -> process name map for the dashboard's process list.
pub fn live_process_map(limit: usize) -> Vec<serde_json::Value> {
    let mut entries = tree::snapshot();
    entries.sort_by_key(|a| a.name.to_lowercase());
    let rows: HashMap<u32, String> = HashMap::new();
    let _ = rows;
    entries
        .into_iter()
        .take(limit)
        .map(|e| {
            serde_json::json!({
                "pid": e.pid,
                "ppid": e.ppid,
                "name": e.name,
                "threads": e.threads,
                "session": tree::session_id_of(e.pid),
            })
        })
        .collect()
}

/// Used by `lai self-check`.
pub fn diagnostics() -> serde_json::Value {
    let os = sys::os_info();
    let host = sys::host_info();
    let (user, domain, elevated) = token::self_account();
    serde_json::json!({
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "schema": SCHEMA_VERSION,
        "engine_arch": sys::native_arch(),
        "engine_path": sys::current_exe(),
        "elevated": elevated,
        "debug_privilege_enabled": token::self_has_enabled_privilege("SeDebugPrivilege"),
        "account": format!("{domain}\\{user}"),
        "os": os.product_name,
        "os_version": os.version,
        "os_build": os.build,
        "computer": host.computer_name,
        "uptime_seconds": host.uptime_seconds,
        "hotkey_listener": window::peek_hotkey_active(),
        "dpi_awareness": if crate::win::dpi::is_per_monitor_aware() { "per_monitor" } else { "system_or_unaware" },
        "os_time_utc": util::rfc3339_of(UnixTime::now()),
    })
}
