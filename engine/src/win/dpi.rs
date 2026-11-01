//! DPI awareness bootstrap.
//!
//! Why this matters for a forensic tool
//! ------------------------------------
//! A DPI-*unaware* process does not receive true screen coordinates: Windows
//! virtualises the coordinate space (`GetCursorPos`, `WindowFromPoint`,
//! `GetWindowRect`, `GetSystemMetrics`). On a multi-monitor or scaled desktop the
//! virtualised space can be offset and scaled differently per display, so a
//! picker built on those APIs can resolve **a different window than the one the
//! examiner clicked** - i.e. the report would describe the wrong process.
//!
//! The fix is to declare per-monitor-v2 awareness before any window exists, in
//! this order (newest API first, each degrading gracefully):
//!
//! ```text
//! SetProcessDpiAwarenessContext(PER_MONITOR_AWARE_V2)   Windows 10 1703+
//!   -> SetProcessDpiAwareness(PER_MONITOR_DPI_AWARE)    Windows 8.1+ (shcore)
//!     -> SetProcessDPIAware()                           Windows Vista+
//! ```

use super::ffi;

const DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2: isize = -4;
const PROCESS_PER_MONITOR_DPI_AWARE: u32 = 2;

/// Returns a short description of the resulting awareness level, useful in
/// `self-check` output and in support tickets.
pub fn enable() -> String {
    unsafe {
        // 1) Per-monitor v2 (best: correct coordinates on every display, and
        //    non-client area scaling behaves).
        if let Some(f) = proc_addr_user32("SetProcessDpiAwarenessContext") {
            let set: unsafe extern "system" fn(isize) -> ffi::BOOL = std::mem::transmute(f);
            if set(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) != ffi::FALSE {
                return "per_monitor_v2".to_string();
            }
        }

        // 2) Per-monitor (Windows 8.1+), exported by shcore.dll.
        if let Some(f) = proc_addr_shcore("SetProcessDpiAwareness") {
            let set: unsafe extern "system" fn(u32) -> ffi::HRESULT = std::mem::transmute(f);
            if set(PROCESS_PER_MONITOR_DPI_AWARE) == 0 {
                return "per_monitor".to_string();
            }
        }

        // 3) System DPI aware (still better than virtualised coordinates).
        if let Some(f) = proc_addr_user32("SetProcessDPIAware") {
            let set: unsafe extern "system" fn() -> ffi::BOOL = std::mem::transmute(f);
            if set() != ffi::FALSE {
                return "system".to_string();
            }
        }
    }
    "unaware".to_string()
}

/// True when the process reports per-monitor awareness (used by self-check).
pub fn is_per_monitor_aware() -> bool {
    unsafe {
        if let Some(f) = proc_addr_user32("GetAwarenessFromDpiAwarenessContext") {
            let get_ctx = proc_addr_user32("GetThreadDpiAwarenessContext");
            if let Some(gc) = get_ctx {
                let get_context: unsafe extern "system" fn() -> isize = std::mem::transmute(gc);
                let from_ctx: unsafe extern "system" fn(isize) -> i32 = std::mem::transmute(f);
                return from_ctx(get_context()) >= PROCESS_PER_MONITOR_DPI_AWARE as i32;
            }
        }
        false
    }
}

unsafe fn proc_addr_user32(name: &str) -> Option<*const std::ffi::c_void> {
    let module = ffi::GetModuleHandleW(wide("user32.dll").as_ptr());
    if module == 0 {
        return None;
    }
    let p = ffi::GetProcAddress(module, to_ansi(name).as_ptr());
    if p.is_null() {
        None
    } else {
        Some(p as *const std::ffi::c_void)
    }
}

unsafe fn proc_addr_shcore(name: &str) -> Option<*const std::ffi::c_void> {
    let module = ffi::LoadLibraryW(wide("shcore.dll").as_ptr());
    if module == 0 {
        return None;
    }
    let p = ffi::GetProcAddress(module, to_ansi(name).as_ptr());
    if p.is_null() {
        None
    } else {
        Some(p as *const std::ffi::c_void)
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn to_ansi(s: &str) -> Vec<i8> {
    let mut v: Vec<i8> = s.bytes().map(|b| b as i8).collect();
    v.push(0);
    v
}
