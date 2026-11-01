//! Module A (selection): the "point-and-shoot" window picker.
//!
//! Two entry points:
//!  * `pick_blocking()` - called directly by the dashboard button / CLI.
//!  * `start_hotkey_listener()` - registers the global hotkey `Ctrl+Alt+F` on a
//!    persistent message-only window so an operator can re-target without
//!    touching the dashboard. The result lands in `take_hotkey_pick()`.
//!
//! Implementation notes
//! --------------------
//! * A full-virtual-screen layered overlay is shown and given mouse capture, so
//!   the click is delivered to us instead of to the target window.
//! * The overlay is hidden *before* `WindowFromPoint`, guaranteeing we can never
//!   resolve our own crosshair window as the target.
//! * `GetAncestor(GA_ROOT)` normalises child windows (edit boxes, Chromium render
//!   widgets, ...) up to the top-level application window.
//! * Every loop is bounded by a deadline and is cancellable with Esc, a right
//!   click or a timeout, so a stalled operator can never wedge the engine.

use std::ffi::c_void;
use std::sync::mpsc;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use super::ffi;
use crate::model::{RectInfo, WindowInfo};
use crate::util;

#[derive(Debug, Clone, Default)]
pub struct PickResult {
    pub hwnd: isize,
    pub pid: u32,
    pub thread_id: u32,
    pub screen_x: i32,
    pub screen_y: i32,
    pub via: String,
    pub picked_at_utc: String,
}

#[derive(Default)]
struct PickState {
    hwnd: isize,
    done: bool,
    cancelled: bool,
    result: Option<PickResult>,
    via: String,
}

static STATE: Mutex<PickState> = Mutex::new(PickState {
    hwnd: 0,
    done: false,
    cancelled: false,
    result: None,
    via: String::new(),
});

/// Serialises concurrent pick requests (hotkey + dashboard button).
static PICK_LOCK: Mutex<()> = Mutex::new(());

static CLASS_NAME: OnceLock<Vec<u16>> = OnceLock::new();
static HOTKEY_PICK: Mutex<Option<PickResult>> = Mutex::new(None);
static HOTKEY_STARTED: OnceLock<()> = OnceLock::new();

const HOTKEY_ID: i32 = 0xB0B0;

/// Set `LAI_DEBUG=1` to trace the picker state machine to stderr.
pub fn trace(msg: &str) {
    if std::env::var("LAI_DEBUG")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        eprintln!("[picker] {msg}");
    }
}

fn class_name() -> &'static Vec<u16> {
    CLASS_NAME.get_or_init(|| util::wide("LiveAppInspector.PickerOverlay"))
}

// ---------------------------------------------------------------------------
// Overlay window procedure
// ---------------------------------------------------------------------------

unsafe extern "system" fn overlay_proc(
    hwnd: ffi::HWND,
    msg: u32,
    wparam: usize,
    lparam: isize,
) -> isize {
    match msg {
        ffi::WM_MOUSEMOVE => {
            let cross = ffi::LoadCursorW(0, ffi::IDC_CROSS as usize as *const u16);
            ffi::SetCursor(cross);
            0
        }
        ffi::WM_SETCURSOR => {
            let cross = ffi::LoadCursorW(0, ffi::IDC_CROSS as usize as *const u16);
            ffi::SetCursor(cross);
            1
        }
        ffi::WM_LBUTTONUP => {
            let mut pt = ffi::POINT::default();
            ffi::GetCursorPos(&mut pt);
            trace(&format!("WM_LBUTTONUP at {},{}", pt.x, pt.y));
            // Hide first: WindowFromPoint must never see our own overlay.
            ffi::ShowWindow(hwnd, ffi::SW_HIDE);
            ffi::ReleaseCapture();

            let mut target = ffi::WindowFromPoint(pt);
            if target != 0 {
                let root = ffi::GetAncestor(target, ffi::GA_ROOT);
                if root != 0 {
                    target = root;
                }
            }

            let mut pid: u32 = 0;
            let mut tid: u32 = 0;
            if target != 0 {
                tid = ffi::GetWindowThreadProcessId(target, &mut pid);
            }

            trace(&format!("resolved hwnd=0x{target:X} pid={pid}"));
            let mut st = STATE.lock().unwrap();
            st.done = true;
            if target == 0 || pid == 0 {
                st.cancelled = true;
            } else {
                st.result = Some(PickResult {
                    hwnd: target,
                    pid,
                    thread_id: tid,
                    screen_x: pt.x,
                    screen_y: pt.y,
                    via: st.via.clone(),
                    picked_at_utc: util::rfc3339_of(util::UnixTime::now()).unwrap_or_default(),
                });
            }
            0
        }
        ffi::WM_RBUTTONUP => {
            let mut st = STATE.lock().unwrap();
            st.done = true;
            st.cancelled = true;
            ffi::ShowWindow(hwnd, ffi::SW_HIDE);
            ffi::ReleaseCapture();
            0
        }
        ffi::WM_KEYDOWN => {
            if wparam as u32 == ffi::VK_ESCAPE {
                let mut st = STATE.lock().unwrap();
                st.done = true;
                st.cancelled = true;
                ffi::ShowWindow(hwnd, ffi::SW_HIDE);
                ffi::ReleaseCapture();
            }
            0
        }
        ffi::WM_PAINT => {
            paint_overlay(hwnd);
            0
        }
        _ => ffi::DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

/// Draws the crosshair instructions straight onto the layered overlay with GDI.
unsafe fn paint_overlay(hwnd: ffi::HWND) {
    let mut ps = ffi::PAINTSTRUCT::default();
    let hdc = ffi::BeginPaint(hwnd, &mut ps);
    if hdc == 0 {
        return;
    }
    let mut rc = ffi::RECT::default();
    ffi::GetClientRect(hwnd, &mut rc);

    // Dim the whole desktop so the operator knows capture is armed.
    let dim = ffi::CreateSolidBrush(0x0010_1010);
    ffi::FillRect(hdc, &rc, dim);
    ffi::DeleteObject(dim);

    // Centre panel.
    let panel_w = 620i32.min(rc.width() - 40);
    let panel_h = 120i32;
    let panel = ffi::RECT {
        left: (rc.width() - panel_w) / 2,
        top: (rc.height() - panel_h) / 2,
        right: (rc.width() + panel_w) / 2,
        bottom: (rc.height() + panel_h) / 2,
    };
    let panel_brush = ffi::CreateSolidBrush(0x001C_1C22);
    ffi::FillRect(hdc, &panel, panel_brush);
    ffi::DeleteObject(panel_brush);

    let face = util::wide("Segoe UI");
    let font = ffi::CreateFontW(
        -22,
        0,
        0,
        0,
        ffi::FW_SEMIBOLD,
        0,
        0,
        0,
        ffi::DEFAULT_CHARSET,
        0,
        0,
        ffi::FONT_CLEARTYPE,
        0,
        face.as_ptr(),
    );
    let small = ffi::CreateFontW(
        -16,
        0,
        0,
        0,
        400,
        0,
        0,
        0,
        ffi::DEFAULT_CHARSET,
        0,
        0,
        ffi::FONT_CLEARTYPE,
        0,
        face.as_ptr(),
    );
    let old = ffi::SelectObject(hdc, font);
    ffi::SetBkMode(hdc, ffi::TRANSPARENT);
    ffi::SetTextColor(hdc, 0x00F0_F4FF);

    let line1 = util::wide("LiveAppInspector  -  click the window to inspect");
    let mut r1 = ffi::RECT {
        top: panel.top + 26,
        ..panel
    };
    ffi::DrawTextW(
        hdc,
        line1.as_ptr(),
        -1,
        &mut r1,
        ffi::DT_CENTER | ffi::DT_SINGLELINE | ffi::DT_VCENTER,
    );

    ffi::SelectObject(hdc, small);
    ffi::SetTextColor(hdc, 0x008A_94A6);
    let line2 =
        util::wide("The report is captured from the live process  |  Esc or right-click cancels");
    let mut r2 = ffi::RECT {
        top: panel.top + 66,
        ..panel
    };
    ffi::DrawTextW(
        hdc,
        line2.as_ptr(),
        -1,
        &mut r2,
        ffi::DT_CENTER | ffi::DT_SINGLELINE | ffi::DT_VCENTER | ffi::DT_NOPREFIX,
    );

    if !old.is_null() {
        ffi::SelectObject(hdc, old);
    }
    ffi::DeleteObject(font);
    ffi::DeleteObject(small);
    ffi::EndPaint(hwnd, &ps);
}

fn ensure_class_registered() {
    static REGISTERED: OnceLock<()> = OnceLock::new();
    REGISTERED.get_or_init(|| unsafe {
        let mut wc = ffi::WNDCLASSW::default();
        wc.style = 0;
        wc.lpfnWndProc = Some(overlay_proc);
        wc.hInstance = ffi::GetModuleHandleW(std::ptr::null());
        wc.hCursor = ffi::LoadCursorW(0, ffi::IDC_CROSS as usize as *const u16);
        wc.hbrBackground = std::ptr::null_mut();
        wc.lpszClassName = class_name().as_ptr();
        ffi::RegisterClassW(&wc);
    });
}

// ---------------------------------------------------------------------------
// Public picker API
// ---------------------------------------------------------------------------

/// Shows the crosshair overlay and blocks until the operator picks a window.
/// `timeout` guards against an abandoned pick (default 60 s from the UI).
pub fn pick_blocking(via: &str, timeout: Duration) -> Result<Option<PickResult>, String> {
    let _guard = match PICK_LOCK.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    ensure_class_registered();

    {
        let mut st = STATE.lock().unwrap();
        st.done = false;
        st.cancelled = false;
        st.result = None;
        st.via = via.to_string();
    }

    let (tx, rx) = mpsc::channel::<Option<PickResult>>();
    let via_owned = via.to_string();

    std::thread::spawn(move || {
        let result = run_overlay_loop(&via_owned, timeout);
        let _ = tx.send(result);
    });

    match rx.recv_timeout(timeout + Duration::from_secs(2)) {
        Ok(r) => Ok(r),
        Err(_) => Ok(None),
    }
}

fn run_overlay_loop(via: &str, timeout: Duration) -> Option<PickResult> {
    unsafe {
        let hinst = ffi::GetModuleHandleW(std::ptr::null());
        let x = ffi::GetSystemMetrics(ffi::SM_XVIRTUALSCREEN);
        let y = ffi::GetSystemMetrics(ffi::SM_YVIRTUALSCREEN);
        let w = ffi::GetSystemMetrics(ffi::SM_CXVIRTUALSCREEN).max(800);
        let h = ffi::GetSystemMetrics(ffi::SM_CYVIRTUALSCREEN).max(600);

        let hwnd = ffi::CreateWindowExW(
            ffi::WS_EX_TOPMOST | ffi::WS_EX_TOOLWINDOW | ffi::WS_EX_LAYERED,
            class_name().as_ptr(),
            util::wide("LiveAppInspector picker").as_ptr(),
            ffi::WS_POPUP | ffi::WS_VISIBLE,
            x,
            y,
            w,
            h,
            0,
            std::ptr::null_mut(),
            hinst,
            std::ptr::null_mut(),
        );
        if hwnd == 0 {
            trace("CreateWindowExW failed");
            return None;
        }
        trace(&format!("overlay hwnd=0x{hwnd:X} {w}x{h} at {x},{y}"));

        // 0x02 = LWA_ALPHA: a dimmed desktop is the "capture is armed" cue.
        ffi::SetLayeredWindowAttributes(hwnd, 0, 90, 0x02);

        // The *first* ShowWindow in a process ignores its argument and honours
        // STARTUPINFO, so a console-launched engine can end up with an invisible
        // overlay. SetWindowPos with SWP_SHOWWINDOW is not subject to that rule.
        let style = ffi::GetWindowLongPtrW(hwnd, ffi::GWL_STYLE);
        ffi::SetWindowLongPtrW(hwnd, ffi::GWL_STYLE, style | ffi::WS_VISIBLE as isize);
        ffi::SetWindowPos(
            hwnd,
            ffi::HWND_TOPMOST,
            x,
            y,
            w,
            h,
            ffi::SWP_SHOWWINDOW | ffi::SWP_NOACTIVATE,
        );
        ffi::ShowWindow(hwnd, ffi::SW_SHOW);
        ffi::SetForegroundWindow(hwnd);
        ffi::SetCapture(hwnd);
        ffi::SetCursor(ffi::LoadCursorW(0, ffi::IDC_CROSS as usize as *const u16));
        ffi::InvalidateRect(hwnd, std::ptr::null(), ffi::TRUE);
        ffi::UpdateWindow(hwnd);
        trace(&format!(
            "overlay visible={}",
            ffi::IsWindowVisible(hwnd) != ffi::FALSE
        ));

        // The hotkey also works while the overlay is up.
        ffi::RegisterHotKey(
            hwnd,
            HOTKEY_ID,
            ffi::MOD_CONTROL | ffi::MOD_ALT,
            0x46, /* F */
        );

        let deadline = Instant::now() + timeout;
        let mut msg = ffi::MSG::default();
        let mut timed_out = false;
        // Edge-detector for the physical button state. Mouse capture can be
        // refused (UIPI, focus stealing prevention, elevated engine vs.
        // unelevated shell), so the picker also watches the hardware button.
        let mut was_down = false;
        loop {
            let done = {
                let st = STATE.lock().unwrap();
                st.done
            };
            if done {
                break;
            }

            let left_down = ffi::GetAsyncKeyState(ffi::VK_LBUTTON) as u16 & 0x8000 != 0;
            let right_down = ffi::GetAsyncKeyState(ffi::VK_RBUTTON) as u16 & 0x8000 != 0;
            let esc_down = ffi::GetAsyncKeyState(ffi::VK_ESCAPE as i32) as u16 & 0x8000 != 0;

            if esc_down || right_down {
                trace("cancel via keyboard/right button");
                let mut st = STATE.lock().unwrap();
                st.done = true;
                st.cancelled = true;
                ffi::ShowWindow(hwnd, ffi::SW_HIDE);
                ffi::ReleaseCapture();
                break;
            }
            if left_down && !was_down {
                // Let the click physically land, then resolve the window under it.
                ffi::ShowWindow(hwnd, ffi::SW_HIDE);
                ffi::ReleaseCapture();
                std::thread::sleep(Duration::from_millis(60));
                let mut pt = ffi::POINT::default();
                ffi::GetCursorPos(&mut pt);
                let mut target = ffi::WindowFromPoint(pt);
                if target != 0 {
                    let root = ffi::GetAncestor(target, ffi::GA_ROOT);
                    if root != 0 {
                        target = root;
                    }
                }
                let mut pid = 0u32;
                let mut tid = 0u32;
                if target != 0 {
                    tid = ffi::GetWindowThreadProcessId(target, &mut pid);
                }
                trace(&format!(
                    "poll-resolved hwnd=0x{target:X} pid={pid} at {},{}",
                    pt.x, pt.y
                ));
                let mut st = STATE.lock().unwrap();
                st.done = true;
                if target == 0 || pid == 0 {
                    st.cancelled = true;
                } else {
                    st.result = Some(PickResult {
                        hwnd: target,
                        pid,
                        thread_id: tid,
                        screen_x: pt.x,
                        screen_y: pt.y,
                        via: st.via.clone(),
                        picked_at_utc: util::rfc3339_of(util::UnixTime::now()).unwrap_or_default(),
                    });
                }
                break;
            }
            was_down = left_down;
            if Instant::now() >= deadline {
                timed_out = true;
                break;
            }
            // 0x0001 = PM_REMOVE
            while ffi::PeekMessageW(&mut msg, 0, 0, 0, 0x0001) != ffi::FALSE {
                if msg.message == ffi::WM_LBUTTONUP || msg.message == ffi::WM_LBUTTONDOWN {
                    trace(&format!(
                        "dispatch msg=0x{:X} hwnd=0x{:X}",
                        msg.message, msg.hwnd
                    ));
                }
                if msg.message == ffi::WM_QUIT {
                    break;
                }
                ffi::TranslateMessage(&msg);
                ffi::DispatchMessageW(&msg);
            }
            std::thread::sleep(Duration::from_millis(8));
        }

        trace("overlay loop finished");
        ffi::UnregisterHotKey(hwnd, HOTKEY_ID);
        ffi::ReleaseCapture();
        ffi::ShowWindow(hwnd, ffi::SW_HIDE);
        ffi::DestroyWindow(hwnd);

        let mut st = STATE.lock().unwrap();
        st.hwnd = 0;
        if timed_out {
            st.cancelled = true;
        }
        let mut result = st.result.take();
        if let Some(r) = result.as_mut() {
            r.via = via.to_string();
        }
        result
    }
}

/// Registers the global hotkey `Ctrl+Alt+F` once; subsequent calls are no-ops.
/// Failures (hotkey already owned by another app) are silent - the dashboard
/// button remains the primary path.
pub fn start_hotkey_listener() {
    HOTKEY_STARTED.get_or_init(|| {
        std::thread::spawn(|| unsafe {
            ensure_class_registered();
            let hinst = ffi::GetModuleHandleW(std::ptr::null());
            // HWND_MESSAGE == (HWND)-3: a message-only window, never rendered.
            let hwnd = ffi::CreateWindowExW(
                0,
                class_name().as_ptr(),
                util::wide("LiveAppInspector hotkey").as_ptr(),
                0,
                0,
                0,
                0,
                0,
                -3,
                std::ptr::null_mut(),
                hinst,
                std::ptr::null_mut(),
            );
            if hwnd == 0 {
                return;
            }
            ffi::RegisterHotKey(hwnd, HOTKEY_ID, ffi::MOD_CONTROL | ffi::MOD_ALT, 0x46);

            let mut msg = ffi::MSG::default();
            loop {
                let r = ffi::GetMessageW(&mut msg, 0, 0, 0);
                if r == 0 || r == -1 {
                    break;
                }
                if msg.message == ffi::WM_HOTKEY && msg.wParam as i32 == HOTKEY_ID {
                    let st = pick_blocking("hotkey_pick", Duration::from_secs(120));
                    if let Ok(Some(p)) = st {
                        if let Ok(mut slot) = HOTKEY_PICK.lock() {
                            *slot = Some(p);
                        }
                    }
                } else {
                    ffi::TranslateMessage(&msg);
                    ffi::DispatchMessageW(&msg);
                }
            }
        });
    });
}

/// Non-blocking take of the most recent hotkey-initiated pick.
pub fn take_hotkey_pick() -> Option<PickResult> {
    HOTKEY_PICK.lock().ok().and_then(|mut s| s.take())
}

pub fn peek_hotkey_active() -> bool {
    HOTKEY_STARTED.get().is_some()
}

// ---------------------------------------------------------------------------
// Window introspection
// ---------------------------------------------------------------------------

pub fn window_info(hwnd: ffi::HWND) -> WindowInfo {
    let mut info = WindowInfo::default();
    unsafe {
        if hwnd == 0 || ffi::IsWindow(hwnd) == ffi::FALSE {
            return info;
        }
        let mut pid = 0u32;
        info.thread_id = ffi::GetWindowThreadProcessId(hwnd, &mut pid);
        info.process_id = pid;

        let mut title = vec![0u16; 1024];
        let n = ffi::GetWindowTextW(hwnd, title.as_mut_ptr(), title.len() as i32);
        info.title = if n > 0 {
            util::from_wide(&title[..n as usize])
        } else {
            String::new()
        };

        let mut class = vec![0u16; 512];
        let n = ffi::GetClassNameW(hwnd, class.as_mut_ptr(), class.len() as i32);
        info.class_name = if n > 0 {
            util::from_wide(&class[..n as usize])
        } else {
            String::new()
        };

        let mut rc = ffi::RECT::default();
        if ffi::GetWindowRect(hwnd, &mut rc) != ffi::FALSE {
            info.rect = RectInfo {
                left: rc.left,
                top: rc.top,
                right: rc.right,
                bottom: rc.bottom,
                width: rc.width(),
                height: rc.height(),
            };
        }
        let mut crc = ffi::RECT::default();
        if ffi::GetClientRect(hwnd, &mut crc) != ffi::FALSE {
            info.client_rect = RectInfo {
                left: crc.left,
                top: crc.top,
                right: crc.right,
                bottom: crc.bottom,
                width: crc.width(),
                height: crc.height(),
            };
        }

        info.is_visible = ffi::IsWindowVisible(hwnd) != ffi::FALSE;
        info.dpi = ffi::GetDpiForWindow(hwnd);
        info.style_hex = format!(
            "0x{:08X}",
            ffi::GetWindowLongPtrW(hwnd, ffi::GWL_STYLE) as u32
        );
        info.ex_style_hex = format!(
            "0x{:08X}",
            ffi::GetWindowLongPtrW(hwnd, ffi::GWL_EXSTYLE) as u32
        );

        let root = ffi::GetAncestor(hwnd, ffi::GA_ROOT);
        info.root_hwnd = format!("0x{:X}", if root != 0 { root } else { hwnd });
        let owner = ffi::GetWindow(hwnd, ffi::GW_OWNER);
        info.owner_hwnd = if owner != 0 {
            format!("0x{owner:X}")
        } else {
            String::new()
        };

        // UWP/cloaked windows are "visible" but not actually on screen.
        let mut cloaked: u32 = 0;
        if let Some(api) = ffi::dwmapi() {
            let hr = (api.GetWindowAttribute)(
                hwnd,
                ffi::DWMWA_CLOAKED,
                &mut cloaked as *mut u32 as *mut c_void,
                std::mem::size_of::<u32>() as u32,
            );
            info.is_cloaked = hr == 0 && cloaked != 0;
        }
    }
    info
}

/// Resolves a PID directly to its top-level foreground-ish window (used when the
/// operator supplies `--pid` instead of picking interactively).
pub fn first_window_of_pid(pid: u32) -> Option<isize> {
    unsafe {
        let fg = ffi::GetForegroundWindow();
        let mut fg_pid = 0u32;
        if fg != 0 {
            ffi::GetWindowThreadProcessId(fg, &mut fg_pid);
            if fg_pid == pid {
                return Some(fg);
            }
        }
        // Fall back to enumerating top-level windows via GetWindow(GW_HWNDNEXT).
        let mut hwnd = ffi::GetForegroundWindow();
        let mut guard = 0;
        while hwnd != 0 && guard < 10_000 {
            let mut p = 0u32;
            ffi::GetWindowThreadProcessId(hwnd, &mut p);
            if p == pid && ffi::IsWindowVisible(hwnd) != ffi::FALSE {
                return Some(hwnd);
            }
            hwnd = ffi::GetWindow(hwnd, ffi::GW_HWNDNEXT);
            guard += 1;
        }
        // Last resort: walk children of the desktop.
        let desktop = ffi::GetDesktopWindow();
        let mut child = ffi::GetWindow(desktop, 5 /* GW_CHILD */);
        let mut guard = 0;
        while child != 0 && guard < 10_000 {
            let mut p = 0u32;
            ffi::GetWindowThreadProcessId(child, &mut p);
            if p == pid && ffi::IsWindowVisible(child) != ffi::FALSE {
                return Some(child);
            }
            child = ffi::GetWindow(child, ffi::GW_HWNDNEXT);
            guard += 1;
        }
        None
    }
}
