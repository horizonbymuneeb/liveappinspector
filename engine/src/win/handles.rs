//! Module E (part 2): open handle enumeration and object-name resolution.
//!
//! Strategy
//! --------
//! 1. One `NtQuerySystemInformation(SystemExtendedHandleInformation)` call gives
//!    the system-wide handle table; we filter to the target PID.
//! 2. Each handle is duplicated into our process (needs `PROCESS_DUP_HANDLE`).
//! 3. The object type name is resolved once per type index and cached - type
//!    indices are stable for the lifetime of the boot.
//! 4. Object *names* are resolved only for interesting classes (files, registry
//!    keys, sections, ALPC ports). Named-pipe handles are deliberately skipped
//!    because `NtQueryObject` blocks on them, and every resolution runs on a
//!    watchdog thread with a hard timeout, so a hung driver cannot freeze us.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use super::ffi;
use super::process::Process;
use super::tree;
use crate::model::*;
use crate::util::{self, WinError};

pub const DEFAULT_HANDLE_CAP: u32 = 5000;
const NAME_TIMEOUT_MS: u64 = 150;
const NT_SUCCESS: i32 = 0;

type TypeCache = Mutex<HashMap<u16, String>>;

fn type_cache() -> &'static TypeCache {
    static CACHE: OnceLock<TypeCache> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

// ---------------------------------------------------------------------------
// Watchdog-backed object name resolver
// ---------------------------------------------------------------------------
struct ResolveReq {
    id: u64,
    /// Raw handle value as usize so the request is `Send` across the watchdog
    /// thread boundary (HANDLE is a raw pointer and is not Send).
    handle: usize,
    class: u32,
}

type ResolveResp = (u64, Result<String, i32>);

struct NameResolver {
    req_tx: Sender<ResolveReq>,
    resp_rx: Arc<Mutex<Receiver<ResolveResp>>>,
    next_id: u64,
}

impl NameResolver {
    fn new() -> Self {
        let (req_tx, req_rx) = mpsc::channel::<ResolveReq>();
        let (resp_tx, resp_rx) = mpsc::channel::<ResolveResp>();
        let resp_rx = Arc::new(Mutex::new(resp_rx));
        let req_rx = Arc::new(Mutex::new(req_rx));
        spawn_worker(req_rx, resp_tx);
        Self {
            req_tx,
            resp_rx,
            next_id: 1,
        }
    }

    /// Returns Ok(name) / Err(ntstatus) / Err(-1) meaning "timed out".
    fn resolve(&mut self, handle: ffi::HANDLE, class: u32) -> Result<String, i32> {
        let id = self.next_id;
        self.next_id += 1;
        if self
            .req_tx
            .send(ResolveReq {
                id,
                handle: handle as usize,
                class,
            })
            .is_err()
        {
            return Err(-2);
        }
        match self
            .resp_rx
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_millis(NAME_TIMEOUT_MS))
        {
            Ok((got_id, res)) if got_id == id => res,
            Ok(_) => Err(-3), // stale response from an abandoned worker
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // The worker is wedged inside NtQueryObject. Abandon it, start a
                // fresh one, and mark this handle's name as unresolved.
                Err(-1)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(-2),
        }
    }
}

fn spawn_worker(req_rx: Arc<Mutex<Receiver<ResolveReq>>>, resp_tx: Sender<ResolveResp>) {
    std::thread::spawn(move || loop {
        let req = {
            let rx = req_rx.lock().unwrap();
            rx.recv()
        };
        let req = match req {
            Ok(r) => r,
            Err(_) => return,
        };
        let mut buf = vec![0u8; 8192];
        let mut ret: u32 = 0;
        let st = unsafe {
            ffi::NtQueryObject(
                req.handle as ffi::HANDLE,
                req.class,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                &mut ret,
            )
        };
        let result = if st == NT_SUCCESS || (st as u32) == ffi::STATUS_BUFFER_OVERFLOW as u32 {
            // OBJECT_NAME_INFORMATION / OBJECT_TYPE_INFORMATION both begin with a
            // UNICODE_STRING.
            let us: ffi::UNICODE_STRING =
                unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const _) };
            if us.Buffer.is_null() || us.Length == 0 {
                Ok(String::new())
            } else {
                let chars = (us.Length / 2) as usize;
                let ptr = us.Buffer as *const u16;
                // Bounds check against the buffer we actually own.
                let base = buf.as_ptr() as usize;
                let end = base + buf.len();
                if (ptr as usize) >= base && (ptr as usize) + chars * 2 <= end {
                    Ok(util::from_wide(unsafe {
                        std::slice::from_raw_parts(ptr, chars)
                    }))
                } else {
                    Err(-4)
                }
            }
        } else {
            Err(st)
        };
        if resp_tx.send((req.id, result)).is_err() {
            return;
        }
    });
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

struct DeviceMap {
    pairs: Vec<(String, String)>, // ("\Device\HarddiskVolume3", "C:")
}

impl DeviceMap {
    fn new() -> Self {
        let mut pairs = Vec::new();
        unsafe {
            let mut drives = vec![0u16; 512];
            let n = ffi::GetLogicalDriveStringsW(drives.len() as u32, drives.as_mut_ptr());
            if n > 0 {
                let mut idx = 0usize;
                while idx < n as usize {
                    let start = idx;
                    while idx < n as usize && drives[idx] != 0 {
                        idx += 1;
                    }
                    if idx > start {
                        let letter = util::from_wide(&drives[start..idx]);
                        let letter = letter.trim_end_matches('\\').to_string();
                        let target = util::wide(format!("{letter}:"));
                        let mut dev = vec![0u16; 1024];
                        let len = ffi::QueryDosDeviceW(
                            target.as_ptr(),
                            dev.as_mut_ptr(),
                            dev.len() as u32,
                        );
                        if len > 0 {
                            pairs.push((util::from_wide(&dev[..len as usize]), letter));
                        }
                    }
                    idx += 1;
                }
            }
        }
        // Longest device path first so "\Device\HarddiskVolume10" wins over 1.
        pairs.sort_by_key(|p| std::cmp::Reverse(p.0.len()));
        Self { pairs }
    }

    fn to_dos(&self, native: &str) -> Option<String> {
        for (dev, letter) in &self.pairs {
            if native.len() >= dev.len() && native[..dev.len()].eq_ignore_ascii_case(dev) {
                return Some(format!("{letter}{}", &native[dev.len()..]));
            }
        }
        None
    }
}

fn registry_to_hive(native: &str) -> String {
    let up = native.to_ascii_uppercase();
    let tail = |prefix: &str| -> String { native[prefix.len()..].to_string() };
    if up.starts_with(r"\REGISTRY\MACHINE\") {
        format!(r"HKLM\{}", tail(r"\REGISTRY\MACHINE\"))
    } else if up.starts_with(r"\REGISTRY\USER\") {
        format!(r"HKU\{}", tail(r"\REGISTRY\USER\"))
    } else if up.starts_with(r"\REGISTRY\A\") {
        format!(r"HKCR\{}", tail(r"\REGISTRY\A\"))
    } else {
        native.to_string()
    }
}

fn classify(type_name: &str) -> &'static str {
    match type_name {
        "File" => "file",
        "Directory" => "directory",
        "Key" => "registry",
        "Process" => "process",
        "Thread" => "thread",
        "Section" => "section",
        "Token" => "token",
        "Event" | "Mutant" | "Semaphore" | "Timer" | "EventPair" => "sync",
        "Port" | "IoCompletion" | "WaitCompletionPacket" | "TpWorkerFactory" | "WmiGuid" => "ipc",
        "ALPC Port" => "ipc",
        "SymbolicLink" => "link",
        "Controller" | "Device" | "Adapter" | "Driver" => "driver",
        _ => "other",
    }
}

fn should_resolve_name(type_name: &str) -> bool {
    matches!(
        type_name,
        "File" | "Key" | "Section" | "SymbolicLink" | "ALPC Port" | "Directory" | "Device"
    )
}

// ---------------------------------------------------------------------------
// Collection
// ---------------------------------------------------------------------------

pub fn collect(proc: &Process, pid: u32, cap: u32) -> HandleList {
    let mut out = HandleList {
        limit: cap,
        ..Default::default()
    };

    let table = match query_system_handles() {
        Ok(t) => t,
        Err(e) => {
            out.meta = SectionMeta::with(
                if e.is_access_denied() {
                    Status::Denied
                } else {
                    Status::Error
                },
                format!("SystemExtendedHandleInformation failed: {e}"),
            );
            out.meta.win32_error = Some(e.code);
            out.meta.warnings.push(
                "handle enumeration requires an elevated engine and a process that is not protected"
                    .into(),
            );
            return out;
        }
    };

    let entries = parse_handle_table(&table);
    let mine: Vec<&ffi::SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> = entries
        .iter()
        .filter(|e| e.UniqueProcessId as u32 == pid)
        .collect();
    out.inspected = mine.len() as u32;

    let device_map = DeviceMap::new();
    let proc_names = {
        let snap = tree::snapshot();
        snap.into_iter()
            .map(|e| (e.pid, e.name))
            .collect::<HashMap<u32, String>>()
    };
    let mut resolver = NameResolver::new();
    let current = unsafe { ffi::GetCurrentProcess() };
    let mut timeouts = 0u32;
    let mut unresolved = 0u32;

    for entry in mine.iter().take(cap as usize) {
        let src_handle = entry.HandleValue as ffi::HANDLE;
        let type_name = resolve_type_name(&mut resolver, &entries, proc, pid, entry, src_handle);
        let classifier = classify(&type_name).to_string();

        let mut info = HandleInfo {
            handle: format!("0x{:X}", entry.HandleValue),
            type_name: type_name.clone(),
            classifier,
            granted_access: format!("0x{:08X}", entry.GrantedAccess),
            object_address: if entry.Object.is_null() {
                // Windows 11 redacts kernel object addresses from unprivileged
                // callers; an empty string is honest, "0x0" would be misleading.
                String::new()
            } else {
                format!("0x{:X}", entry.Object as usize)
            },
            ..Default::default()
        };

        // Duplicate into our process so names can be read safely.
        let mut dup: ffi::HANDLE = std::ptr::null_mut();
        let dup_ok = unsafe {
            ffi::DuplicateHandle(
                proc.handle,
                src_handle,
                current,
                &mut dup,
                0,
                ffi::FALSE,
                ffi::DUPLICATE_SAME_ACCESS,
            )
        } != ffi::FALSE;

        if !dup_ok {
            let e = WinError::last();
            info.note = Some(match e.code {
                ffi::ERROR_NOT_SUPPORTED => {
                    "this object type cannot be duplicated out of its process; handle name unavailable".to_string()
                }
                _ => format!("DuplicateHandle failed: {}", e.message),
            });
            out.items.push(info);
            continue;
        }

        // Named pipes / char devices will block NtQueryObject: identify them first.
        let mut is_pipe = false;
        if type_name == "File" {
            let ft = unsafe { ffi::GetFileType(dup) };
            is_pipe = ft == ffi::FILE_TYPE_PIPE;
        }

        if type_name == "Process" {
            let target = unsafe { ffi::GetProcessId(dup) };
            if target != 0 {
                info.target_pid = Some(target);
                if let Some(n) = proc_names.get(&target) {
                    info.object_name = Some(n.clone());
                }
            }
        } else if should_resolve_name(&type_name) && !is_pipe {
            match resolver.resolve(dup, ffi::OBJECT_NAME_INFORMATION_CLASS) {
                Ok(name) if !name.is_empty() => {
                    let mapped = match type_name.as_str() {
                        "Key" => registry_to_hive(&name),
                        "File" | "Directory" => {
                            device_map.to_dos(&name).unwrap_or_else(|| name.clone())
                        }
                        _ => name.clone(),
                    };
                    info.object_name = Some(mapped);
                }
                Ok(_) => info.object_name = None,
                Err(-1) => {
                    timeouts += 1;
                    info.note = Some("name query timed out (object may be remote/blocking)".into());
                }
                Err(st) => {
                    unresolved += 1;
                    if st > 0 {
                        let dos = unsafe { ffi::RtlNtStatusToDosError(st) };
                        info.note =
                            Some(format!("name unavailable: {}", util::format_message(dos)));
                    }
                }
            }
        } else if is_pipe {
            info.note =
                Some("named-pipe handle: name withheld (NtQueryObject blocks on pipes)".into());
        }

        unsafe {
            ffi::CloseHandle(dup);
        }
        out.items.push(info);
    }

    out.truncated = mine.len() > cap as usize;
    if out.truncated {
        out.meta.warn(format!(
            "handle list truncated: {} handles present, cap is {cap}",
            mine.len()
        ));
    }
    if timeouts > 0 {
        out.meta.warn(format!(
            "{timeouts} object-name queries exceeded the {NAME_TIMEOUT_MS} ms budget"
        ));
    }
    if unresolved > 0 {
        out.meta
            .warn(format!("{unresolved} object names were not resolvable"));
    }

    // An opaque `type_N` means neither this process's handle nor any other
    // process we can open allowed a duplicate - the usual cause is an unelevated
    // engine looking at a SYSTEM/service process.
    let opaque = out
        .items
        .iter()
        .filter(|i| i.type_name.starts_with("type_"))
        .count();
    if opaque > 0 {
        let share = if out.items.is_empty() {
            100
        } else {
            opaque * 100 / out.items.len()
        };
        if share >= 25 {
            out.meta.warn(format!(
                "{opaque} of {} handles ({share}%) have an unresolved object type: the engine could not duplicate them out of their owner process - run elevated for full handle semantics",
                out.items.len()
            ));
        } else {
            out.meta
                .note(format!("{opaque} handle(s) had an unresolved object type"));
        }
    }

    // Aggregate counts by object type, most frequent first.
    let mut counts: HashMap<String, u32> = HashMap::new();
    for i in &out.items {
        *counts.entry(i.type_name.clone()).or_insert(0) += 1;
    }
    let mut counts: Vec<TypeCount> = counts
        .into_iter()
        .map(|(k, v)| TypeCount {
            type_name: k,
            count: v,
        })
        .collect();
    counts.sort_by(|a, b| b.count.cmp(&a.count).then(a.type_name.cmp(&b.type_name)));
    out.counts_by_type = counts;

    // Stable ordering: registry/files first (most forensic signal), then the rest.
    out.items.sort_by(|a, b| {
        rank(&a.classifier)
            .cmp(&rank(&b.classifier))
            .then(a.type_name.cmp(&b.type_name))
            .then(a.object_name.cmp(&b.object_name))
    });

    out
}

fn rank(c: &str) -> u8 {
    match c {
        "registry" => 0,
        "file" => 1,
        "process" => 2,
        "section" => 3,
        "ipc" => 4,
        "driver" => 5,
        "token" => 6,
        "thread" => 7,
        "directory" => 8,
        "link" => 9,
        "sync" => 10,
        _ => 11,
    }
}

/// Resolves the object type name for a type index.
///
/// Type indices are per-boot stable, so a successful resolution is cached for the
/// whole process lifetime. Some object types cannot be duplicated out of their
/// owning process (`DuplicateHandle` -> ERROR_NOT_SUPPORTED); for those we fall
/// back to looking for the same type index in a process we *can* duplicate from.
/// Failures are never cached, so a later handle of the same type gets retried.
fn resolve_type_name(
    resolver: &mut NameResolver,
    entries: &[ffi::SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX],
    proc: &Process,
    pid: u32,
    entry: &ffi::SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX,
    src_handle: ffi::HANDLE,
) -> String {
    let idx = entry.ObjectTypeIndex;
    if let Some(name) = type_cache().lock().unwrap().get(&idx) {
        return name.clone();
    }

    let from_target = dup_and_query_type(resolver, proc.handle, src_handle);
    let name = match from_target {
        Some(n) if !n.is_empty() => n,
        _ => resolve_type_from_any_holder(resolver, entries, idx, pid)
            .unwrap_or_else(|| format!("type_{idx}")),
    };

    if !name.starts_with("type_") {
        type_cache().lock().unwrap().insert(idx, name.clone());
    }
    name
}

fn dup_and_query_type(
    resolver: &mut NameResolver,
    source_process: ffi::HANDLE,
    src_handle: ffi::HANDLE,
) -> Option<String> {
    unsafe {
        let current = ffi::GetCurrentProcess();
        let mut dup: ffi::HANDLE = std::ptr::null_mut();
        if ffi::DuplicateHandle(
            source_process,
            src_handle,
            current,
            &mut dup,
            0,
            ffi::FALSE,
            ffi::DUPLICATE_SAME_ACCESS,
        ) == ffi::FALSE
        {
            return None;
        }
        let r = resolver.resolve(dup, ffi::OBJECT_TYPE_INFORMATION_CLASS);
        ffi::CloseHandle(dup);
        r.ok()
    }
}

/// Looks for another process holding a handle of `idx` that we are allowed to
/// duplicate from, and asks that handle for its type name.
fn resolve_type_from_any_holder(
    resolver: &mut NameResolver,
    entries: &[ffi::SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX],
    idx: u16,
    skip_pid: u32,
) -> Option<String> {
    let mut attempts = 0;
    for e in entries.iter().filter(|e| e.ObjectTypeIndex == idx) {
        let other = e.UniqueProcessId as u32;
        if other == 0 || other == skip_pid {
            continue;
        }
        attempts += 1;
        if attempts > 8 {
            break;
        }
        unsafe {
            let h = ffi::OpenProcess(ffi::PROCESS_DUP_HANDLE, ffi::FALSE, other);
            if h.is_null() {
                continue;
            }
            let name = dup_and_query_type(resolver, h, e.HandleValue as ffi::HANDLE);
            ffi::CloseHandle(h);
            if let Some(n) = name {
                if !n.is_empty() {
                    return Some(n);
                }
            }
        }
    }
    None
}

fn query_system_handles() -> Result<Vec<u8>, WinError> {
    unsafe {
        let mut size: usize = 2 * 1024 * 1024;
        for _ in 0..8 {
            let mut buf = vec![0u8; size];
            let mut ret: u32 = 0;
            let st = ffi::NtQuerySystemInformation(
                ffi::SYSTEM_EXTENDED_HANDLE_INFORMATION_CLASS,
                buf.as_mut_ptr() as *mut c_void,
                size as u32,
                &mut ret,
            );
            if st == NT_SUCCESS {
                buf.truncate(ret as usize);
                return Ok(buf);
            }
            if st == ffi::STATUS_INFO_LENGTH_MISMATCH {
                size = (ret as usize + 1024 * 1024).min(256 * 1024 * 1024);
                continue;
            }
            return Err(WinError::from_code(ffi::RtlNtStatusToDosError(st)));
        }
        Err(WinError::from_code(ffi::ERROR_NOT_ENOUGH_MEMORY))
    }
}

fn parse_handle_table(buf: &[u8]) -> Vec<ffi::SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> {
    if buf.len() < 16 {
        return Vec::new();
    }
    let count = usize::from_le_bytes(buf[0..8].try_into().unwrap());
    let entry_size = std::mem::size_of::<ffi::SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>();
    let avail = (buf.len() - 16) / entry_size;
    let n = count.min(avail).min(2_000_000);
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let off = 16 + i * entry_size;
        out.push(unsafe {
            std::ptr::read_unaligned(
                buf.as_ptr().add(off) as *const ffi::SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
            )
        });
    }
    out
}

/// Derives the registry-handle view of Module E (part 3).
pub fn registry_from_handles(pid: u32, handles: &HandleList) -> RegistryInfo {
    let mut reg = RegistryInfo::default();
    for h in handles.items.iter().filter(|h| h.classifier == "registry") {
        if let Some(name) = &h.object_name {
            reg.keys.push(RegistryKeyRef {
                path: name.clone(),
                native_path: name.replacen("HKLM\\", r"\REGISTRY\MACHINE\", 1).replacen(
                    "HKU\\",
                    r"\REGISTRY\USER\",
                    1,
                ),
                handle: h.handle.clone(),
                granted_access: h.granted_access.clone(),
            });
        }
    }
    reg.keys.sort_by(|a, b| a.path.cmp(&b.path));
    reg.keys.dedup_by(|a, b| a.path == b.path);
    if reg.keys.is_empty() {
        reg.meta = SectionMeta::with(
            Status::Skipped,
            format!("no Key handles were observable for PID {pid}"),
        );
    }
    reg
}
