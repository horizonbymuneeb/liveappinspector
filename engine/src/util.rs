//! Small, dependency-free helpers: UTF-16 marshalling, Win32 error rendering,
//! 100ns FILETIME -> RFC3339 UTC conversion, and misc formatting.

use std::ffi::OsStr;
use std::fmt;
use std::os::windows::ffi::OsStrExt;

use super::win::ffi;

// ---------------------------------------------------------------------------
// String marshalling
// ---------------------------------------------------------------------------

/// NUL-terminated UTF-16 buffer for Win32 "W" APIs.
pub fn wide<S: AsRef<OsStr>>(s: S) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

pub fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// # Safety
/// `p` must be either null or a valid NUL-terminated UTF-16 string.
pub unsafe fn from_wide_ptr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while *p.add(len) != 0 {
        len += 1;
        if len > 65_536 {
            break;
        }
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct WinError {
    pub code: u32,
    pub message: String,
}

impl WinError {
    pub fn last() -> Self {
        Self::from_code(unsafe { ffi::GetLastError() })
    }

    pub fn from_code(code: u32) -> Self {
        Self {
            code,
            message: format_message(code),
        }
    }

    pub fn is_access_denied(&self) -> bool {
        self.code == ffi::ERROR_ACCESS_DENIED
    }
}

impl fmt::Display for WinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (0x{:08X})", self.message, self.code)
    }
}

impl std::error::Error for WinError {}

pub type WResult<T> = Result<T, WinError>;

/// Human readable text for a Win32/NTSTATUS code via FormatMessageW, with a
/// static fallback table for the codes we deliberately special-case.
pub fn format_message(code: u32) -> String {
    if let Some(msg) = ffi::known_status_text(code) {
        return msg;
    }
    unsafe {
        let mut buf: *mut u16 = std::ptr::null_mut();
        let len = ffi::FormatMessageW(
            ffi::FORMAT_MESSAGE_FROM_SYSTEM
                | ffi::FORMAT_MESSAGE_IGNORE_INSERTS
                | ffi::FORMAT_MESSAGE_ALLOCATE_BUFFER,
            std::ptr::null(),
            code,
            0,
            &mut buf as *mut *mut u16 as *mut u16,
            0,
            std::ptr::null_mut(),
        );
        if len == 0 || buf.is_null() {
            return format!("Unknown error 0x{code:08X}");
        }
        let s = from_wide(std::slice::from_raw_parts(buf, len as usize));
        ffi::LocalFree(buf as ffi::HLOCAL);
        s.trim().trim_end_matches('.').trim_end().to_string()
    }
}

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

/// Windows FILETIME: 100 ns ticks since 1601-01-01 UTC.
pub const FILETIME_UNIX_EPOCH_OFFSET_MS: i64 = 11_644_473_600_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileTime(pub u64);

impl FileTime {
    /// Milliseconds since the Unix epoch (negative for pre-1970 timestamps).
    pub fn unix_ms(&self) -> i64 {
        (self.0 / 10_000) as i64 - FILETIME_UNIX_EPOCH_OFFSET_MS
    }

    /// Sub-millisecond remainder in 100 ns ticks (0..10_000).
    pub fn sub_ms_ticks(&self) -> u32 {
        (self.0 % 10_000) as u32
    }

    pub fn to_unix(self) -> UnixTime {
        UnixTime {
            unix_ms: self.unix_ms(),
            sub_ms_ticks: self.sub_ms_ticks(),
            raw_filetime: self.0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UnixTime {
    pub unix_ms: i64,
    pub sub_ms_ticks: u32,
    pub raw_filetime: u64,
}

impl UnixTime {
    pub fn now() -> Self {
        FileTime(ffi::now_filetime()).to_unix()
    }

    pub fn is_zero(&self) -> bool {
        self.raw_filetime == 0
    }
}

/// RFC3339 / ISO-8601 UTC rendering with microsecond precision.
pub fn rfc3339(unix_ms: i64, sub_ms_ticks: u32) -> String {
    let secs = unix_ms.div_euclid(1000);
    let millis = unix_ms.rem_euclid(1000);
    let micros = sub_ms_ticks / 10; // 100ns ticks -> µs
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{millis:03}{micros:03}Z")
}

/// Howard Hinnant's `civil_from_days` (proleptic Gregorian, days since 1970-01-01).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn rfc3339_of(t: UnixTime) -> Option<String> {
    if t.is_zero() {
        None
    } else {
        Some(rfc3339(t.unix_ms, t.sub_ms_ticks))
    }
}

/// Parse a FILETIME-pair (low, high) into our timestamp type.
pub fn filetime_from_parts(lo: u32, hi: u32) -> UnixTime {
    FileTime(((hi as u64) << 32) | lo as u64).to_unix()
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

pub fn hex_lower(bytes: &[u8]) -> String {
    const T: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(T[(b >> 4) as usize] as char);
        out.push(T[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

pub fn human_bytes(n: u64) -> String {
    const U: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.2} {}", U[i])
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_epoch_is_1970() {
        let ft = FileTime(FILETIME_UNIX_EPOCH_OFFSET_MS as u64 * 10_000);
        assert_eq!(ft.unix_ms(), 0);
        assert_eq!(rfc3339(0, 0), "1970-01-01T00:00:00.000000Z");
    }

    #[test]
    fn known_timestamp_round_trips() {
        // 2026-11-01T14:50:34.369826Z
        let ms = 1_793_544_634_369i64;
        assert_eq!(rfc3339(ms, 8_260), "2026-11-01T14:50:34.369826Z");
    }

    #[test]
    fn leap_day_and_pre_epoch() {
        // 2024-02-29 is a real date; the civil conversion must not drift.
        let days = 19_782i64; // 2024-02-29
        let (y, m, d) = civil_from_days(days);
        assert_eq!((y, m, d), (2024, 2, 29));
        // 1969-12-31 (one day before the epoch)
        let (y, m, d) = civil_from_days(-1);
        assert_eq!((y, m, d), (1969, 12, 31));
    }

    #[test]
    fn html_escape_blocks_injection() {
        let hostile = r#"<script>alert("x")</script>&'\n"#;
        let out = html_escape(hostile);
        assert!(!out.contains('<'));
        assert!(!out.contains('>'));
        assert!(out.contains("&lt;script&gt;"));
        assert!(out.contains("&#39;"));
        assert!(out.contains("&amp;"));
    }

    #[test]
    fn byte_formatting() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(999), "999 B");
        assert_eq!(human_bytes(2048), "2.00 KB");
    }
}
