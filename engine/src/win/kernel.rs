//! Kernel process-table fallback.
//!
//! When `OpenProcess` is refused (protected/PPL process, higher integrity, or an
//! unelevated engine), the kernel still exposes a process's image name, creation
//! time, thread/handle counts and parent through
//! `NtQuerySystemInformation(SystemProcessInformation)`. That keeps a "denied"
//! acquisition useful: the on-disk image can still be hashed, PE-parsed and
//! signature-checked, and the process start time can still be placed on a
//! timeline.

use std::ffi::c_void;

use super::ffi;
use crate::util::{FileTime, UnixTime};

#[derive(Debug, Clone, Default)]
#[allow(dead_code)] // `pid` is carried for call-site clarity
pub struct KernelProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    /// Kernel-native image name, e.g. `\SystemRoot\System32\winlogon.exe`.
    pub image_name: Option<String>,
    pub created: UnixTime,
    pub threads: u32,
    pub handles: u32,
    pub session_id: u32,
}

/// Looks up one PID in the kernel process list. Standard users can call this;
/// it is the same data Task Manager uses for the "Details" tab.
pub fn kernel_process_info(pid: u32) -> Option<KernelProcessInfo> {
    unsafe {
        let mut size: usize = 512 * 1024;
        for _ in 0..6 {
            let mut buf = vec![0u8; size];
            let mut ret: u32 = 0;
            let st = ffi::NtQuerySystemInformation(
                ffi::SYSTEM_PROCESS_INFORMATION_CLASS,
                buf.as_mut_ptr() as *mut c_void,
                size as u32,
                &mut ret,
            );
            if st == ffi::STATUS_INFO_LENGTH_MISMATCH {
                size = (ret as usize + 256 * 1024).min(512 * 1024 * 1024);
                continue;
            }
            if st < 0 {
                return None;
            }
            return scan(&buf[..ret as usize], pid);
        }
        None
    }
}

fn scan(buf: &[u8], pid: u32) -> Option<KernelProcessInfo> {
    let entry_size = std::mem::size_of::<ffi::SYSTEM_PROCESS_INFORMATION>();
    let mut off = 0usize;
    let mut guard = 0usize;
    while off + entry_size <= buf.len() && guard < 500_000 {
        guard += 1;
        let e: ffi::SYSTEM_PROCESS_INFORMATION =
            unsafe { std::ptr::read_unaligned(buf.as_ptr().add(off) as *const _) };

        if e.UniqueProcessId as u32 == pid {
            // The image-name buffer points into the returned blob; only read it
            // after proving it lies inside that blob.
            let image_name = if e.ImageName.Buffer.is_null() || e.ImageName.Length == 0 {
                None
            } else {
                let len = (e.ImageName.Length / 2) as usize;
                let base = buf.as_ptr() as usize;
                let ptr = e.ImageName.Buffer as usize;
                if ptr >= base && ptr + len * 2 <= base + buf.len() {
                    let wide = unsafe { std::slice::from_raw_parts(ptr as *const u16, len) };
                    Some(String::from_utf16_lossy(wide))
                } else {
                    None
                }
            };
            return Some(KernelProcessInfo {
                pid,
                ppid: e.InheritedFromUniqueProcessId as u32,
                image_name,
                created: FileTime(e.CreateTime as u64).to_unix(),
                threads: e.NumberOfThreads,
                handles: e.HandleCount,
                session_id: e.SessionId,
            });
        }

        if e.NextEntryOffset == 0 {
            break;
        }
        off += e.NextEntryOffset as usize;
    }
    None
}
