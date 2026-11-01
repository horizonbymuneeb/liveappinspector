//! Kernel-native path translation.
//!
//! Handle- and PEB-derived paths arrive in NT namespace form
//! (`\Device\HarddiskVolume3\Windows\System32\x.exe`, `\SystemRoot\System32\x.exe`,
//! `\??\C:\x.exe`). Reports need DOS paths an examiner can open, so each form is
//! translated and then **verified to exist** before it is trusted - a path that
//! does not resolve is never silently promoted to evidence.

use std::path::Path;

use super::ffi;
use crate::util;

const SYSTEM_ROOT_PREFIX: &str = "\\systemroot\\";
const NT_PREFIX: &str = "\\??\\";
const DEVICE_PREFIX: &str = "\\device\\";

/// Translates a kernel-native path into an existing DOS path, if one is found.
/// Returns `None` when nothing on disk matches - which is itself a signal
/// (unlinked/deleted image, or a device-backed mapping such as `\Device\CNG`).
pub fn resolve_kernel_image_path(raw: &str) -> Option<String> {
    if raw.trim().is_empty() {
        return None;
    }
    let mut candidates: Vec<String> = Vec::new();
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let lower = raw.to_ascii_lowercase();

    // Already a DOS path or a UNC share?
    if raw.len() > 2 && raw.as_bytes()[1] == b':' {
        candidates.push(raw.to_string());
    }
    if raw.starts_with("\\\\") && !raw.starts_with("\\\\?") && !raw.starts_with("\\\\.\\") {
        candidates.push(raw.to_string());
    }

    // \SystemRoot\...  ->  %SystemRoot%\...
    if lower.starts_with(SYSTEM_ROOT_PREFIX) {
        // Keep the leading backslash that belongs to the remainder.
        candidates.push(format!(
            "{system_root}{}",
            &raw[SYSTEM_ROOT_PREFIX.len() - 1..]
        ));
    }

    // \??\C:\...  ->  C:\...
    if let Some(rest) = raw.strip_prefix(NT_PREFIX) {
        candidates.push(rest.to_string());
    }

    // \Device\HarddiskVolumeN\...  ->  <drive>:\...
    if lower.starts_with(DEVICE_PREFIX) {
        for (device, letter) in dos_devices() {
            if lower.starts_with(&device.to_ascii_lowercase()) {
                candidates.push(format!("{letter}{}", &raw[device.len()..]));
                break;
            }
        }
    }

    candidates.push(raw.to_string());
    candidates.into_iter().find(|c| Path::new(c).is_file())
}

/// Resolves a *bare* image name (no directory component) against the handful of
/// locations where an unprivileged kernel query can plausibly point.
///
/// Deliberately conservative:
///   * only four well-known directories are searched,
///   * the name must resolve to **exactly one** file, otherwise nothing is
///     returned - guessing between candidates is how a report ends up
///     attributing the wrong binary to a process.
pub fn resolve_bare_image_name(name: &str) -> Option<String> {
    if name.is_empty() || name.contains(['\\', '/']) {
        return None;
    }
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let dirs = [
        format!("{system_root}\\System32"),
        format!("{system_root}\\SysWOW64"),
        format!("{system_root}\\System32\\drivers"),
        system_root.clone(),
    ];
    let mut found: Vec<String> = Vec::new();
    for dir in dirs {
        let candidate = format!("{dir}\\{name}");
        if Path::new(&candidate).is_file() {
            found.push(candidate);
        }
    }
    if found.len() == 1 {
        found.pop()
    } else {
        None
    }
}

/// Enumerates the DOS device map (`C:` -> `\Device\HarddiskVolume3`).
pub fn dos_devices() -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    unsafe {
        let mut drives = vec![0u16; 512];
        let n = ffi::GetLogicalDriveStringsW(drives.len() as u32, drives.as_mut_ptr());
        if n == 0 {
            return pairs;
        }
        let mut idx = 0usize;
        while idx < n as usize {
            let start = idx;
            while idx < n as usize && drives[idx] != 0 {
                idx += 1;
            }
            if idx > start {
                let letter = util::from_wide(&drives[start..idx])
                    .trim_end_matches('\\')
                    .to_string();
                let target = util::wide(format!("{letter}:"));
                let mut dev = vec![0u16; 1024];
                let len = ffi::QueryDosDeviceW(target.as_ptr(), dev.as_mut_ptr(), dev.len() as u32);
                if len > 0 {
                    pairs.push((util::from_wide(&dev[..len as usize]), letter));
                }
            }
            idx += 1;
        }
    }
    // Longest device path first so \Device\HarddiskVolume10 beats ...Volume1.
    pairs.sort_by_key(|p| std::cmp::Reverse(p.0.len()));
    pairs
}

/// Convenience for handle-derived names: DOS form when resolvable, else as-is.
#[allow(dead_code)]
pub fn to_dos_or_raw(native: &str) -> String {
    resolve_kernel_image_path(native).unwrap_or_else(|| native.to_string())
}

/// Best-effort basename extraction that works for both separators.
pub fn file_name_of(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}
