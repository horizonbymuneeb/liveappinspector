//! Module B: token, account, integrity level, elevation and session context.
//!
//! Everything here is derived from the *live process token*, which is
//! authoritative for "who is this process really running as" - file ACLs and
//! WMI Owner fields are advisory and trivially spoofable by comparison.

use std::ffi::c_void;

use super::ffi;
use super::sys;
use crate::model::*;
use crate::util::{self, WResult, WinError};

pub struct Token {
    pub handle: ffi::HANDLE,
}

impl Drop for Token {
    fn drop(&mut self) {
        unsafe {
            if !self.handle.is_null() {
                ffi::CloseHandle(self.handle);
            }
        }
    }
}

pub fn open_for_process(proc: ffi::HANDLE) -> WResult<Token> {
    unsafe {
        let mut h: ffi::HANDLE = std::ptr::null_mut();
        let ok = ffi::OpenProcessToken(
            proc,
            ffi::TOKEN_QUERY | ffi::TOKEN_QUERY_SOURCE | ffi::TOKEN_DUPLICATE,
            &mut h,
        );
        if ok == ffi::FALSE {
            return Err(WinError::last());
        }
        Ok(Token { handle: h })
    }
}

/// Reads a variable-length TOKEN_* information block into an owned buffer.
fn query(tok: &Token, class: u32) -> WResult<Vec<u8>> {
    unsafe {
        let mut size: u32 = 0;
        ffi::GetTokenInformation(tok.handle, class, std::ptr::null_mut(), 0, &mut size);
        if size == 0 {
            let e = WinError::last();
            // Some classes legitimately fail the sizing call; probe with a page.
            size = 4096;
            if e.code != ffi::ERROR_INSUFFICIENT_BUFFER {
                // fall through with the default probe size
            }
        }
        for _ in 0..4 {
            let mut buf = vec![0u8; size as usize];
            let mut ret: u32 = 0;
            let ok = ffi::GetTokenInformation(
                tok.handle,
                class,
                buf.as_mut_ptr() as *mut c_void,
                size,
                &mut ret,
            );
            if ok != ffi::FALSE {
                buf.truncate(ret as usize);
                return Ok(buf);
            }
            let err = WinError::last();
            if err.code == ffi::ERROR_INSUFFICIENT_BUFFER {
                size = ret.max(size * 2);
                continue;
            }
            return Err(err);
        }
        Err(WinError::from_code(ffi::ERROR_INSUFFICIENT_BUFFER))
    }
}

// ---------------------------------------------------------------------------
// SID helpers
// ---------------------------------------------------------------------------

pub fn sid_to_string(sid: ffi::PSID) -> Option<String> {
    if sid.is_null() || unsafe { ffi::IsValidSid(sid) } == ffi::FALSE {
        return None;
    }
    unsafe {
        let mut out: ffi::LPWSTR = std::ptr::null_mut();
        if ffi::ConvertSidToStringSidW(sid, &mut out) == ffi::FALSE {
            return None;
        }
        let s = util::from_wide_ptr(out);
        ffi::LocalFree(out as ffi::HLOCAL);
        Some(s)
    }
}

fn sid_type_name(t: u32) -> &'static str {
    match t {
        1 => "user",
        2 => "group",
        3 => "domain",
        4 => "alias",
        5 => "well_known_group",
        6 => "deleted_account",
        7 => "invalid",
        8 => "unknown",
        9 => "computer",
        10 => "label",
        _ => "unknown",
    }
}

fn sid_last_sub_authority(sid: ffi::PSID) -> Option<u32> {
    unsafe {
        if sid.is_null() || ffi::IsValidSid(sid) == ffi::FALSE {
            return None;
        }
        let count_ptr = ffi::GetSidSubAuthorityCount(sid);
        if count_ptr.is_null() {
            return None;
        }
        let count = *count_ptr as u32;
        if count == 0 {
            return None;
        }
        let sub = ffi::GetSidSubAuthority(sid, count - 1);
        if sub.is_null() {
            None
        } else {
            Some(*sub)
        }
    }
}

/// LookupAccountSidW resolution of a SID into `(account, domain, type)`.
pub fn lookup_account(sid: ffi::PSID) -> (String, String, String) {
    unsafe {
        if sid.is_null() {
            return (String::new(), String::new(), String::new());
        }
        let mut name = vec![0u16; 256];
        let mut domain = vec![0u16; 256];
        let mut name_len = name.len() as u32;
        let mut domain_len = domain.len() as u32;
        let mut sid_use: u32 = 0;
        let ok = ffi::LookupAccountSidW(
            std::ptr::null(),
            sid,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut sid_use,
        );
        if ok == ffi::FALSE {
            return (String::new(), String::new(), sid_type_name(0).to_string());
        }
        (
            util::from_wide(&name),
            util::from_wide(&domain),
            sid_type_name(sid_use).to_string(),
        )
    }
}

fn integrity_name(rid: u32) -> String {
    match rid {
        0x0000 => "untrusted".into(),
        0x1000 => "low".into(),
        0x2000 => "medium".into(),
        0x2100 => "medium_plus".into(),
        0x3000 => "high".into(),
        0x4000 => "system".into(),
        0x5000 => "protected_process".into(),
        other => format!("integrity_0x{other:04x}"),
    }
}

// ---------------------------------------------------------------------------
// Public collection entry point
// ---------------------------------------------------------------------------

/// Collects Module B. Never fails hard: on error the returned `UserContext`
/// carries a `denied`/`error` status plus the Win32 reason, and the rest of the
/// report remains usable.
pub fn collect(process_handle: ffi::HANDLE, pid: u32, session_id_hint: u32) -> UserContext {
    let mut uc = UserContext::default();

    let token = match open_for_process(process_handle) {
        Ok(t) => t,
        Err(e) => {
            uc.meta = SectionMeta::denied(format!("OpenProcessToken failed: {e}"));
            uc.meta.win32_error = Some(e.code);
            // Still try to describe the session, which does not need a token.
            uc.session = sys::session_info(session_id_hint, pid);
            uc.elevation.verdict = "unknown (token access denied)".into();
            return uc;
        }
    };

    // ---- user SID + account -------------------------------------------------
    match query(&token, ffi::TOKEN_USER_CLASS) {
        Ok(buf) => {
            if buf.len() >= std::mem::size_of::<ffi::SID_AND_ATTRIBUTES>() {
                let sa: ffi::SID_AND_ATTRIBUTES =
                    unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const _) };
                uc.sid = sid_to_string(sa.Sid).unwrap_or_default();
                let (name, domain, kind) = lookup_account(sa.Sid);
                uc.account_name = name;
                uc.account_domain = domain;
                uc.account_type = kind;
            }
        }
        Err(e) => uc.meta = SectionMeta::denied(format!("TokenUser: {e}")),
    }

    // ---- integrity level ----------------------------------------------------
    if let Ok(buf) = query(&token, ffi::TOKEN_INTEGRITY_LEVEL_CLASS) {
        if buf.len() >= std::mem::size_of::<ffi::SID_AND_ATTRIBUTES>() {
            let sa: ffi::SID_AND_ATTRIBUTES =
                unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const _) };
            if let Some(rid) = sid_last_sub_authority(sa.Sid) {
                uc.integrity = IntegrityInfo {
                    rid,
                    name: integrity_name(rid),
                };
            }
        }
    }

    // ---- elevation ----------------------------------------------------------
    let is_elevated = query(&token, ffi::TOKEN_ELEVATION_CLASS)
        .ok()
        .and_then(|b| {
            b.get(0..4)
                .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        })
        .map(|v| v != 0)
        .unwrap_or(false);
    let elevation_type = query(&token, ffi::TOKEN_ELEVATION_TYPE_CLASS)
        .ok()
        .and_then(|b| {
            b.get(0..4)
                .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        })
        .map(|v| match v {
            1 => "default".to_string(),
            2 => "full".to_string(),
            3 => "limited".to_string(),
            _ => "unknown".to_string(),
        })
        .unwrap_or_else(|| "unknown".into());

    uc.elevation = ElevationInfo {
        is_elevated,
        elevation_type: elevation_type.clone(),
        verdict: verdict_for(
            &uc.account_name,
            &uc.integrity.name,
            is_elevated,
            &elevation_type,
        ),
    };

    // ---- owner --------------------------------------------------------------
    if let Ok(buf) = query(&token, ffi::TOKEN_OWNER_CLASS) {
        if buf.len() >= std::mem::size_of::<ffi::PSID>() {
            let sid: ffi::PSID = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const _) };
            uc.token.owner_sid = sid_to_string(sid).unwrap_or_default();
        }
    }

    // ---- statistics (logon session / token identity) ------------------------
    if let Ok(buf) = query(&token, ffi::TOKEN_STATISTICS_CLASS) {
        if buf.len() >= std::mem::size_of::<ffi::TOKEN_STATISTICS>() {
            let st: ffi::TOKEN_STATISTICS =
                unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const _) };
            uc.token.authentication_id = format_luid(st.AuthenticationId);
            uc.token.token_id = format_luid(st.TokenId);
            uc.token.privilege_count = st.PrivilegeCount;
            uc.token.group_count = st.GroupCount;
            uc.token.token_type = match st.TokenType {
                1 => "primary".into(),
                2 => "impersonation".into(),
                _ => "unknown".into(),
            };
            uc.token.impersonation_level = match st.ImpersonationLevel {
                0 => "anonymous".into(),
                1 => "identification".into(),
                2 => "impersonation".into(),
                3 => "delegation".into(),
                _ => "unknown".into(),
            };
        }
    }

    if let Ok(buf) = query(&token, ffi::TOKEN_SESSION_ID_CLASS) {
        if buf.len() >= 4 {
            uc.token.logon_session = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        }
    }
    uc.token.is_app_container = query(&token, ffi::TOKEN_IS_APP_CONTAINER_CLASS)
        .ok()
        .and_then(|b| {
            b.get(0..4)
                .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        })
        .map(|v| v != 0)
        .unwrap_or(false);
    uc.token.virtualization_enabled = query(&token, ffi::TOKEN_VIRTUALIZATION_ENABLED_CLASS)
        .ok()
        .and_then(|b| {
            b.get(0..4)
                .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        })
        .map(|v| v != 0)
        .unwrap_or(false);

    // ---- privileges ---------------------------------------------------------
    if let Ok(buf) = query(&token, ffi::TOKEN_PRIVILEGES_CLASS) {
        if buf.len() >= 4 {
            let count = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            let entry = std::mem::size_of::<ffi::LUID_AND_ATTRIBUTES>();
            for i in 0..count {
                let off = 4 + i * entry;
                if off + entry > buf.len() {
                    break;
                }
                let la: ffi::LUID_AND_ATTRIBUTES =
                    unsafe { std::ptr::read_unaligned(buf.as_ptr().add(off) as *const _) };
                let name = privilege_name(&la.Luid).unwrap_or_else(|| "unknown_privilege".into());
                uc.privileges.push(PrivilegeInfo {
                    name,
                    enabled: la.Attributes & ffi::SE_PRIVILEGE_ENABLED != 0,
                    enabled_by_default: la.Attributes & ffi::SE_PRIVILEGE_ENABLED_BY_DEFAULT != 0,
                    removed: la.Attributes & ffi::SE_PRIVILEGE_REMOVED != 0,
                    used_for_access: la.Attributes & ffi::SE_PRIVILEGE_USED_FOR_ACCESS != 0,
                });
            }
            uc.privileges.sort_by(|a, b| a.name.cmp(&b.name));
        }
    }

    // ---- groups -------------------------------------------------------------
    if let Ok(buf) = query(&token, ffi::TOKEN_GROUPS_CLASS) {
        if buf.len() >= 8 {
            let count = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            // SID_AND_ATTRIBUTES is 16 bytes and 8-byte aligned on x64; the array
            // therefore starts at offset 8.
            let start = std::mem::align_of::<ffi::SID_AND_ATTRIBUTES>();
            let entry = std::mem::size_of::<ffi::SID_AND_ATTRIBUTES>();
            for i in 0..count {
                let off = start + i * entry;
                if off + entry > buf.len() {
                    break;
                }
                let sa: ffi::SID_AND_ATTRIBUTES =
                    unsafe { std::ptr::read_unaligned(buf.as_ptr().add(off) as *const _) };
                let (name, domain, _) = lookup_account(sa.Sid);
                uc.groups.push(GroupInfo {
                    sid: sid_to_string(sa.Sid).unwrap_or_default(),
                    name,
                    domain,
                    enabled: sa.Attributes & ffi::SE_GROUP_ENABLED != 0,
                    mandatory: sa.Attributes & ffi::SE_GROUP_MANDATORY != 0,
                    deny_only: sa.Attributes & 0x0000_0010 != 0,
                    integrity: sa.Attributes & ffi::SE_GROUP_INTEGRITY != 0,
                    logon_id: sa.Attributes & ffi::SE_GROUP_LOGON_ID != 0,
                    resource: sa.Attributes & ffi::SE_GROUP_RESOURCE != 0,
                });
            }
            uc.groups.sort_by(|a, b| a.name.cmp(&b.name));
        }
    }

    // ---- session ------------------------------------------------------------
    uc.session = sys::session_info(
        if uc.token.logon_session != 0 {
            uc.token.logon_session
        } else {
            session_id_hint
        },
        pid,
    );

    if uc.meta.status.is_ok() && uc.privileges.is_empty() && uc.groups.is_empty() {
        uc.meta
            .warn("token opened but privilege/group lists were empty");
    }
    uc
}

fn verdict_for(account: &str, integrity: &str, elevated: bool, elevation_type: &str) -> String {
    let acct = account.to_ascii_lowercase();
    if acct.ends_with("$") && acct != "system" {
        return "machine account / service context".into();
    }
    match (acct.as_str(), integrity) {
        ("system", "system") => "NT AUTHORITY\\SYSTEM - LocalSystem service context".into(),
        ("local service", _) => "NT AUTHORITY\\LOCAL SERVICE - restricted service account".into(),
        ("network service", _) => {
            "NT AUTHORITY\\NETWORK SERVICE - restricted service account".into()
        }
        (_, "high") if elevated => "Elevated administrator (full token)".into(),
        (_, "high") => "High integrity (elevated)".into(),
        (_, "medium_plus") => "Medium-plus integrity (UIAccess)".into(),
        (_, "medium") if elevation_type == "limited" => {
            "Standard user - UAC split token (limited)".into()
        }
        (_, "medium") => "Standard user (medium integrity)".into(),
        (_, "low") => "Low integrity - sandboxed / AppContainer context".into(),
        (_, "untrusted") => "Untrusted integrity".into(),
        (_, "protected_process") => "Protected process (PPL)".into(),
        _ => format!("Integrity {integrity}"),
    }
}

fn format_luid(l: ffi::LUID) -> String {
    format!("{:08x}-{:08x}", l.HighPart as u32, l.LowPart)
}

fn privilege_name(luid: &ffi::LUID) -> Option<String> {
    unsafe {
        let mut buf = vec![0u16; 256];
        let mut len = buf.len() as u32;
        if ffi::LookupPrivilegeNameW(std::ptr::null(), luid, buf.as_mut_ptr(), &mut len)
            == ffi::FALSE
        {
            return None;
        }
        Some(util::from_wide(&buf))
    }
}

/// Enables SeDebugPrivilege on the *inspecting* process so an elevated operator
/// can reach SYSTEM-level targets. Returns whether the privilege is now held.
pub fn enable_debug_privilege() -> bool {
    unsafe {
        let mut tok: ffi::HANDLE = std::ptr::null_mut();
        if ffi::OpenProcessToken(
            ffi::GetCurrentProcess(),
            ffi::TOKEN_ADJUST_PRIVILEGES | ffi::TOKEN_QUERY,
            &mut tok,
        ) == ffi::FALSE
        {
            return false;
        }
        let mut luid = ffi::LUID::default();
        let name = util::wide("SeDebugPrivilege");
        if ffi::LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) == ffi::FALSE {
            ffi::CloseHandle(tok);
            return false;
        }
        // TOKEN_PRIVILEGES: u32 count + LUID_AND_ATTRIBUTES[1]
        let mut tp = [0u8; 4 + 12];
        tp[0..4].copy_from_slice(&1u32.to_le_bytes());
        tp[4..8].copy_from_slice(&luid.LowPart.to_le_bytes());
        tp[8..12].copy_from_slice(&luid.HighPart.to_le_bytes());
        tp[12..16].copy_from_slice(&ffi::SE_PRIVILEGE_ENABLED.to_le_bytes());
        let ok = ffi::AdjustTokenPrivileges(
            tok,
            ffi::FALSE,
            tp.as_ptr() as *const c_void,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        let err = ffi::GetLastError();
        ffi::CloseHandle(tok);
        ok != ffi::FALSE && err == ffi::ERROR_SUCCESS
    }
}

/// Whether the *current* process token already holds an enabled privilege.
pub fn self_has_enabled_privilege(name: &str) -> bool {
    unsafe {
        let mut tok: ffi::HANDLE = std::ptr::null_mut();
        if ffi::OpenProcessToken(ffi::GetCurrentProcess(), ffi::TOKEN_QUERY, &mut tok) == ffi::FALSE
        {
            return false;
        }
        let t = Token { handle: tok };
        let mut found = false;
        if let Ok(buf) = query(&t, ffi::TOKEN_PRIVILEGES_CLASS) {
            if buf.len() >= 4 {
                let count = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                let entry = std::mem::size_of::<ffi::LUID_AND_ATTRIBUTES>();
                for i in 0..count {
                    let off = 4 + i * entry;
                    if off + entry > buf.len() {
                        break;
                    }
                    let la: ffi::LUID_AND_ATTRIBUTES =
                        std::ptr::read_unaligned(buf.as_ptr().add(off) as *const _);
                    if let Some(n) = privilege_name(&la.Luid) {
                        if n.eq_ignore_ascii_case(name)
                            && la.Attributes & ffi::SE_PRIVILEGE_ENABLED != 0
                        {
                            found = true;
                            break;
                        }
                    }
                }
            }
        }
        found
    }
}

/// Convenience wrapper used by the UI for the "who am I" banner.
pub fn self_account() -> (String, String, bool) {
    unsafe {
        let mut tok: ffi::HANDLE = std::ptr::null_mut();
        if ffi::OpenProcessToken(ffi::GetCurrentProcess(), ffi::TOKEN_QUERY, &mut tok) == ffi::FALSE
        {
            return (String::new(), String::new(), false);
        }
        let t = Token { handle: tok };
        let mut user = String::new();
        let mut domain = String::new();
        if let Ok(buf) = query(&t, ffi::TOKEN_USER_CLASS) {
            if buf.len() >= std::mem::size_of::<ffi::SID_AND_ATTRIBUTES>() {
                let sa: ffi::SID_AND_ATTRIBUTES =
                    std::ptr::read_unaligned(buf.as_ptr() as *const _);
                let (n, d, _) = lookup_account(sa.Sid);
                user = n;
                domain = d;
            }
        }
        let elevated = query(&t, ffi::TOKEN_ELEVATION_CLASS)
            .ok()
            .and_then(|b| {
                b.get(0..4)
                    .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
            })
            .map(|v| v != 0)
            .unwrap_or(false);
        (user, domain, elevated)
    }
}
