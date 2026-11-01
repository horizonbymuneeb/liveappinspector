//! Module A + C plumbing: process handle acquisition, identity, architecture,
//! timing, memory, mitigation/protection state, and PEB-derived launch context
//! (command line, working directory, environment) read straight from the live
//! process - not from a stale WMI row.

use std::ffi::c_void;

use super::ffi;
use crate::model::{MemoryInfo, ProcessTimes};
use crate::util::{self, rfc3339_of, WResult, WinError};

pub const OPEN_FULL: u32 = ffi::PROCESS_QUERY_INFORMATION
    | ffi::PROCESS_VM_READ
    | ffi::PROCESS_DUP_HANDLE
    | ffi::PROCESS_SYNCHRONIZE;
pub const OPEN_LIMITED: u32 = ffi::PROCESS_QUERY_LIMITED_INFORMATION | ffi::PROCESS_SYNCHRONIZE;

/// RAII owner for a process handle: the handle is always closed, on every error
/// path and on panic unwind.
#[allow(dead_code)] // `pid`/`full_access` document the handle's provenance
pub struct Process {
    pub handle: ffi::HANDLE,
    pub pid: u32,
    pub full_access: bool,
}

impl Drop for Process {
    fn drop(&mut self) {
        unsafe {
            if !self.handle.is_null() {
                ffi::CloseHandle(self.handle);
            }
        }
    }
}

pub struct OpenOutcome {
    pub process: Option<Process>,
    pub full_access: bool,
    /// Populated when even limited access failed (protected / zombie process).
    pub error: Option<WinError>,
}

/// Opens a target process, degrading gracefully from full forensic access
/// (query + VM read + handle duplication) to limited query access, and finally
/// to a hard failure with the Win32 reason preserved for the report.
pub fn open_for_forensics(pid: u32) -> OpenOutcome {
    if pid == 0 {
        return OpenOutcome {
            process: None,
            full_access: false,
            error: Some(WinError::from_code(ffi::ERROR_INVALID_HANDLE)),
        };
    }
    unsafe {
        let h = ffi::OpenProcess(OPEN_FULL, ffi::FALSE, pid);
        if !h.is_null() {
            return OpenOutcome {
                process: Some(Process {
                    handle: h,
                    pid,
                    full_access: true,
                }),
                full_access: true,
                error: None,
            };
        }
        let first_err = WinError::last();
        let h = ffi::OpenProcess(OPEN_LIMITED, ffi::FALSE, pid);
        if !h.is_null() {
            return OpenOutcome {
                process: Some(Process {
                    handle: h,
                    pid,
                    full_access: false,
                }),
                full_access: false,
                error: Some(first_err),
            };
        }
        OpenOutcome {
            process: None,
            full_access: false,
            error: Some(WinError::last()),
        }
    }
}

impl Process {
    /// Full DOS image path via QueryFullProcessImageNameW (works for WOW64 too).
    pub fn image_path(&self) -> WResult<String> {
        let mut buf = vec![0u16; 32_768];
        let mut len = buf.len() as u32;
        let ok =
            unsafe { ffi::QueryFullProcessImageNameW(self.handle, 0, buf.as_mut_ptr(), &mut len) };
        if ok == ffi::FALSE {
            return Err(WinError::last());
        }
        Ok(util::from_wide(&buf[..len as usize]))
    }

    /// `(arch_string, is_wow64)` - distinguishes a 32-bit process running under
    /// WOW64 from a genuine 64-bit image on ARM64/x64 hosts.
    pub fn architecture(&self) -> (String, bool) {
        unsafe {
            let mut proc_machine: u16 = 0;
            let mut native_machine: u16 = 0;
            let ok = ffi::IsWow64Process2(self.handle, &mut proc_machine, &mut native_machine);
            if ok != ffi::FALSE {
                let is_wow64 = proc_machine != 0 && proc_machine != ffi::IMAGE_FILE_MACHINE_UNKNOWN;
                let effective = if proc_machine == 0 {
                    native_machine
                } else {
                    proc_machine
                };
                return (machine_name(effective), is_wow64);
            }
            // Pre-1709 fallback: IsWow64Process2 is unavailable.
            let mut wow: ffi::BOOL = 0;
            if ffi::IsWow64Process(self.handle, &mut wow) != ffi::FALSE && wow != 0 {
                return ("x86".into(), true);
            }
            (
                if cfg!(target_arch = "x86_64") {
                    "x64".into()
                } else {
                    "unknown".into()
                },
                false,
            )
        }
    }

    pub fn times(&self) -> WResult<ProcessTimes> {
        unsafe {
            let (mut c, mut e, mut k, mut u) = (
                ffi::FILETIME::default(),
                ffi::FILETIME::default(),
                ffi::FILETIME::default(),
                ffi::FILETIME::default(),
            );
            if ffi::GetProcessTimes(self.handle, &mut c, &mut e, &mut k, &mut u) == ffi::FALSE {
                return Err(WinError::last());
            }
            let created = util::filetime_from_parts(c.dwLowDateTime, c.dwHighDateTime);
            let exited = util::filetime_from_parts(e.dwLowDateTime, e.dwHighDateTime);
            let kernel = util::filetime_from_parts(k.dwLowDateTime, k.dwHighDateTime);
            let user = util::filetime_from_parts(u.dwLowDateTime, u.dwHighDateTime);
            let now_ms = util::UnixTime::now().unix_ms;
            Ok(ProcessTimes {
                created_utc: rfc3339_of(created),
                created_unix_ms: created.unix_ms,
                created_filetime_raw: created.raw_filetime,
                exited_utc: rfc3339_of(exited),
                elapsed_ms: if created.unix_ms > 0 {
                    (now_ms - created.unix_ms).max(0) as u64
                } else {
                    0
                },
                kernel_time_ms: (kernel.raw_filetime / 10_000),
                user_time_ms: (user.raw_filetime / 10_000),
            })
        }
    }

    pub fn memory(&self) -> Option<MemoryInfo> {
        unsafe {
            let mut c = ffi::PROCESS_MEMORY_COUNTERS::default();
            c.cb = std::mem::size_of::<ffi::PROCESS_MEMORY_COUNTERS>() as u32;
            if ffi::K32GetProcessMemoryInfo(self.handle, &mut c, c.cb) == ffi::FALSE {
                return None;
            }
            Some(MemoryInfo {
                working_set_bytes: c.WorkingSetSize as u64,
                peak_working_set_bytes: c.PeakWorkingSetSize as u64,
                pagefile_usage_bytes: c.PagefileUsage as u64,
                private_bytes: 0, // filled from VirtualQuery-style counters when available
                page_faults: c.PageFaultCount,
            })
        }
    }

    pub fn handle_count(&self) -> u32 {
        unsafe {
            let mut n = 0u32;
            if ffi::GetProcessHandleCount(self.handle, &mut n) != ffi::FALSE {
                n
            } else {
                0
            }
        }
    }

    pub fn priority_class(&self) -> String {
        unsafe {
            match ffi::GetPriorityClass(self.handle) {
                0x0000_0040 => "idle".into(),
                0x0000_4000 => "below_normal".into(),
                0x0000_0020 => "normal".into(),
                0x0000_8000 => "above_normal".into(),
                0x0000_0080 => "high".into(),
                0x0000_0100 => "realtime".into(),
                _ => "unknown".into(),
            }
        }
    }

    /// Root parent PID from the kernel (not Toolhelp, which rewrites reparented
    /// processes to 0/explorer.exe).
    pub fn parent_pid(&self) -> Option<u32> {
        unsafe {
            let mut pbi = ffi::PROCESS_BASIC_INFORMATION::default();
            let st = ffi::NtQueryInformationProcess(
                self.handle,
                ffi::PROCESS_BASIC_INFORMATION_CLASS,
                &mut pbi as *mut _ as *mut c_void,
                std::mem::size_of::<ffi::PROCESS_BASIC_INFORMATION>() as u32,
                std::ptr::null_mut(),
            );
            if st >= 0 {
                Some(pbi.InheritedFromUniqueProcessId as u32)
            } else {
                None
            }
        }
    }

    /// PS_PROTECTION (PPL) state - critical for spotting AV/EDR processes that
    /// will refuse handle access even to an Administrator.
    pub fn protection(&self) -> (String, String) {
        unsafe {
            let mut p = ffi::PS_PROTECTION::default();
            let st = ffi::NtQueryInformationProcess(
                self.handle,
                ffi::PROCESS_PROTECTION_INFORMATION_CLASS,
                &mut p as *mut _ as *mut c_void,
                std::mem::size_of::<ffi::PS_PROTECTION>() as u32,
                std::ptr::null_mut(),
            );
            if st < 0 {
                return ("unknown".into(), String::new());
            }
            let level = match p.Level {
                0 => "none",
                1 => "light",
                2 => "full",
                _ => "unknown",
            };
            let signer = match p.Type {
                0 => "none",
                1 => "authenticode",
                2 => "codegen",
                3 => "antimalware",
                4 => "lsa",
                5 => "windows",
                6 => "win_tcb",
                7 => "win_system",
                8 => "app",
                _ => "unknown",
            };
            (
                level.to_string(),
                if p.Type == 0 {
                    String::new()
                } else {
                    signer.to_string()
                },
            )
        }
    }

    /// Reads the PEB to recover live launch context. Works for both native and
    /// WOW64 targets by choosing the correct pointer width and PEB layout.
    pub fn peb_snapshot(&self) -> PebSnapshot {
        let mut snap = PebSnapshot::default();
        unsafe {
            // Determine pointer width / layout of the target.
            let (_, is_wow64) = self.arch_quick();
            let mut ptr_size = std::mem::size_of::<usize>();
            let mut peb;

            let mut pbi = ffi::PROCESS_BASIC_INFORMATION::default();
            let st = ffi::NtQueryInformationProcess(
                self.handle,
                ffi::PROCESS_BASIC_INFORMATION_CLASS,
                &mut pbi as *mut _ as *mut c_void,
                std::mem::size_of::<ffi::PROCESS_BASIC_INFORMATION>() as u32,
                std::ptr::null_mut(),
            );
            if st < 0 {
                snap.error = Some(util::format_message(ffi::RtlNtStatusToDosError(st)));
                return snap;
            }
            peb = pbi.PebBaseAddress as usize;

            if is_wow64 {
                // Ask for the 32-bit PEB explicitly.
                let mut wow_peb = 0u64;
                let st = ffi::NtQueryInformationProcess(
                    self.handle,
                    ffi::PROCESS_WOW64_INFORMATION_CLASS,
                    &mut wow_peb as *mut _ as *mut c_void,
                    8,
                    std::ptr::null_mut(),
                );
                if st < 0 || wow_peb == 0 {
                    snap.error = Some("WOW64 PEB unavailable".into());
                    return snap;
                }
                peb = wow_peb as usize;
                ptr_size = 4;
            }

            // RTL_USER_PROCESS_PARAMETERS offset inside the PEB.
            let params_off = if ptr_size == 4 { 0x10 } else { 0x20 };
            let params = match read_ptr(self.handle, peb + params_off, ptr_size) {
                Some(p) if p != 0 => p,
                _ => {
                    snap.error = Some("RTL_USER_PROCESS_PARAMETERS unreadable".into());
                    return snap;
                }
            };

            let (cwd_off, dll_off, image_off, cmd_off, env_off) = if ptr_size == 4 {
                (0x24usize, 0x38usize, 0x40usize, 0x48usize, 0x50usize)
            } else {
                (0x38usize, 0x50usize, 0x60usize, 0x70usize, 0x80usize)
            };

            snap.current_directory = read_unicode_string(self.handle, params + cwd_off, ptr_size);
            snap.dll_path = read_unicode_string(self.handle, params + dll_off, ptr_size);
            snap.image_path = read_unicode_string(self.handle, params + image_off, ptr_size);
            snap.command_line = read_unicode_string(self.handle, params + cmd_off, ptr_size);

            if let Some(env_ptr) = read_ptr(self.handle, params + env_off, ptr_size) {
                snap.environment = read_environment_block(self.handle, env_ptr);
            }
            snap.readable = true;
        }
        snap
    }

    fn arch_quick(&self) -> (String, bool) {
        unsafe {
            let mut proc_machine: u16 = 0;
            let mut native: u16 = 0;
            if ffi::IsWow64Process2(self.handle, &mut proc_machine, &mut native) != ffi::FALSE {
                let is_wow64 = proc_machine != 0 && proc_machine != ffi::IMAGE_FILE_MACHINE_UNKNOWN;
                return (
                    machine_name(if proc_machine == 0 {
                        native
                    } else {
                        proc_machine
                    }),
                    is_wow64,
                );
            }
            let mut wow: ffi::BOOL = 0;
            let is_wow64 = ffi::IsWow64Process(self.handle, &mut wow) != ffi::FALSE && wow != 0;
            ("unknown".into(), is_wow64)
        }
    }
}

#[derive(Debug, Default)]
pub struct PebSnapshot {
    pub readable: bool,
    pub command_line: Option<String>,
    pub image_path: Option<String>,
    pub current_directory: Option<String>,
    pub dll_path: Option<String>,
    pub environment: Vec<String>,
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Raw memory helpers (all bounds-checked against a caller-supplied cap)
// ---------------------------------------------------------------------------
fn read_bytes(h: ffi::HANDLE, addr: usize, len: usize) -> Option<Vec<u8>> {
    if addr == 0 || len == 0 || len > 1 << 20 {
        return None;
    }
    let mut buf = vec![0u8; len];
    unsafe {
        let mut read = 0usize;
        let ok = ffi::ReadProcessMemory(
            h,
            addr as *const c_void,
            buf.as_mut_ptr() as *mut c_void,
            len,
            &mut read,
        );
        if ok == ffi::FALSE {
            return None;
        }
        buf.truncate(read.max(1).min(len));
    }
    Some(buf)
}

fn read_ptr(h: ffi::HANDLE, addr: usize, ptr_size: usize) -> Option<usize> {
    let b = read_bytes(h, addr, ptr_size)?;
    Some(match ptr_size {
        8 => u64::from_le_bytes(b.get(0..8)?.try_into().ok()?) as usize,
        _ => u32::from_le_bytes(b.get(0..4)?.try_into().ok()?) as usize,
    })
}

/// Reads a UNICODE_STRING (Length/MaximumLength + pointer) from target memory.
fn read_unicode_string(h: ffi::HANDLE, header_addr: usize, ptr_size: usize) -> Option<String> {
    let hdr = read_bytes(h, header_addr, if ptr_size == 4 { 8 } else { 16 })?;
    let len = u16::from_le_bytes(hdr.get(0..2)?.try_into().ok()?) as usize;
    let buf_ptr = if ptr_size == 4 {
        u32::from_le_bytes(hdr.get(4..8)?.try_into().ok()?) as usize
    } else {
        u64::from_le_bytes(hdr.get(8..16)?.try_into().ok()?) as usize
    };
    if len == 0 || buf_ptr == 0 || len > 65_536 {
        return None;
    }
    let raw = read_bytes(h, buf_ptr, len)?;
    let wide: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&c| c != 0)
        .collect();
    Some(String::from_utf16_lossy(&wide))
}

/// Environment block: sequence of NUL-terminated UTF-16 strings ending with an
/// extra NUL. Capped to avoid pathological reads.
fn read_environment_block(h: ffi::HANDLE, addr: usize) -> Vec<String> {
    const MAX: usize = 64 * 1024;
    let mut raw: Vec<u8> = Vec::with_capacity(8192);
    let mut offset = 0usize;
    while let Some(chunk) = read_bytes(h, addr + offset, 4096) {
        raw.extend_from_slice(&chunk);
        let got = chunk.len();
        // Detect the double-NUL terminator on a 2-byte boundary.
        if raw.len() >= 4 && raw[raw.len() - 2] == 0 && raw[raw.len() - 4] == 0 {
            break;
        }
        if got < 4096 || raw.len() >= MAX {
            break;
        }
        offset += got;
    }
    let wide: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let mut out = Vec::new();
    let mut cur = String::new();
    for w in wide {
        if w == 0 {
            if cur.is_empty() {
                break;
            }
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(char::from_u32(w as u32).unwrap_or('\u{FFFD}'));
        }
        if out.len() > 4096 {
            break;
        }
    }
    out
}

fn machine_name(m: u16) -> String {
    match m {
        0x8664 => "x64".into(),
        0x014c => "x86".into(),
        0xAA64 => "arm64".into(),
        0x01c4 => "arm".into(),
        0x0200 => "ia64".into(),
        0 => "unknown".into(),
        _ => format!("machine_0x{m:04x}"),
    }
}
