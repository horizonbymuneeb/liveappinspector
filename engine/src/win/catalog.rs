//! Authenticode **and** security-catalog trust verification.
//!
//! Most of `System32` (winlogon.exe, services.exe, ntoskrnl.exe, ...) carries no
//! embedded signature: it is signed by a *catalog* (`.cat`) file, and the catalog
//! is what the kernel and AppLocker trust. A DFIR tool that only calls
//! `WinVerifyTrust` on the file would report those images as "unsigned", which is
//! both wrong and misleading in a report. This module performs the full
//! catalog-member flow:
//!
//! ```text
//! CryptCATAdminAcquireContext2
//!   -> CryptCATAdminCalcHashFromFileHandle2   (file hash)
//!   -> CryptCATAdminEnumCatalogFromHash       (find the .cat claiming the member)
//!   -> CryptCATCatalogInfoFromContext         (catalog path)
//!   -> WinVerifyTrust(WTD_CHOICE_CATALOG)     (verify member + chain)
//! ```

use std::ffi::c_void;

use super::ffi;
use crate::util;

pub struct CatalogTrust {
    pub hr: ffi::HRESULT,
    pub catalog_path: String,
    /// Hex file hash used as the catalog member tag (SIP indirect data value).
    pub member_tag: String,
}

/// Verifies `path` against the security catalogs registered on this host.
/// Returns `None` when the file is simply not catalogued (the normal case for
/// third-party binaries), and `Some` when a catalog claimed it.
pub fn verify_catalog_member(path: &str) -> Option<CatalogTrust> {
    let api = ffi::wintrust()?;
    let wpath = util::wide(path);
    let sha256 = util::wide("SHA256");

    unsafe {
        let mut h_admin: isize = 0;
        if (api.CryptCATAdminAcquireContext2)(
            &mut h_admin,
            std::ptr::null(),
            sha256.as_ptr(),
            std::ptr::null(),
            0,
        ) == ffi::FALSE
            || h_admin == 0
        {
            return None;
        }

        let file = ffi::CreateFileW(
            wpath.as_ptr(),
            ffi::GENERIC_READ,
            ffi::FILE_SHARE_READ | ffi::FILE_SHARE_WRITE | ffi::FILE_SHARE_DELETE,
            std::ptr::null(),
            ffi::OPEN_EXISTING,
            ffi::FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        );
        if file == ffi::INVALID_HANDLE_VALUE {
            (api.CryptCATAdminReleaseContext)(h_admin, 0);
            return None;
        }

        // Size the hash, then calculate it.
        let mut cb: u32 = 0;
        (api.CryptCATAdminCalcHashFromFileHandle2)(h_admin, file, &mut cb, std::ptr::null_mut(), 0);
        if cb == 0 || cb > 128 {
            ffi::CloseHandle(file);
            (api.CryptCATAdminReleaseContext)(h_admin, 0);
            return None;
        }
        let mut hash = vec![0u8; cb as usize];
        if (api.CryptCATAdminCalcHashFromFileHandle2)(h_admin, file, &mut cb, hash.as_mut_ptr(), 0)
            == ffi::FALSE
        {
            ffi::CloseHandle(file);
            (api.CryptCATAdminReleaseContext)(h_admin, 0);
            return None;
        }

        let cat_info = (api.CryptCATAdminEnumCatalogFromHash)(
            h_admin,
            hash.as_ptr(),
            cb,
            0,
            std::ptr::null_mut(),
        );
        if cat_info.is_null() || cat_info == -1isize as *mut c_void {
            ffi::CloseHandle(file);
            (api.CryptCATAdminReleaseContext)(h_admin, 0);
            return None;
        }

        let mut ci = ffi::CATALOG_INFO::default();
        ci.cbStruct = std::mem::size_of::<ffi::CATALOG_INFO>() as u32;
        let have_path = (api.CryptCATCatalogInfoFromContext)(cat_info, &mut ci, 0) != ffi::FALSE;
        let catalog_path = if have_path {
            util::from_wide(&ci.wszCatalogFile)
        } else {
            String::new()
        };

        // The member tag is the upper-case hex of the calculated file hash.
        let member_tag: String = hash.iter().map(|b| format!("{b:02X}")).collect();
        let tag_wide = util::wide(&member_tag);
        let catalog_wide = util::wide(&catalog_path);

        let mut cat = ffi::WINTRUST_CATALOG_INFO::default();
        cat.cbStruct = std::mem::size_of::<ffi::WINTRUST_CATALOG_INFO>() as u32;
        cat.dwCatalogVersion = 0;
        cat.pcwszCatalogFilePath = catalog_wide.as_ptr();
        cat.pcwszMemberTag = tag_wide.as_ptr();
        cat.pcwszMemberFilePath = wpath.as_ptr();
        cat.hMemberFile = file;
        cat.pbCalculatedFileHash = hash.as_mut_ptr();
        cat.cbCalculatedFileHash = cb;
        cat.pcCatalogContext = std::ptr::null_mut();
        cat.hCatAdmin = h_admin;

        let mut data = ffi::WINTRUST_DATA::default();
        data.cbStruct = std::mem::size_of::<ffi::WINTRUST_DATA>() as u32;
        data.dwUIChoice = ffi::WTD_UI_NONE;
        data.fdwRevocationChecks = ffi::WTD_REVOKE_NONE;
        data.dwUnionChoice = ffi::WTD_CHOICE_CATALOG;
        data.pFile = &mut cat as *mut ffi::WINTRUST_CATALOG_INFO as *mut ffi::WINTRUST_FILE_INFO;
        data.dwStateAction = ffi::WTD_STATEACTION_VERIFY;
        data.dwProvFlags =
            ffi::WTD_SAFER_FLAG | ffi::WTD_CACHE_ONLY_URL_RETRIEVAL | ffi::WTD_DISABLE_MD2_MD4;

        let mut action = ffi::WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let hr = (api.WinVerifyTrust)(
            0,
            &mut action,
            &mut data as *mut ffi::WINTRUST_DATA as *mut c_void,
        );
        data.dwStateAction = ffi::WTD_STATEACTION_CLOSE;
        (api.WinVerifyTrust)(
            0,
            &mut action,
            &mut data as *mut ffi::WINTRUST_DATA as *mut c_void,
        );

        (api.CryptCATAdminReleaseCatalogContext)(h_admin, cat_info, 0);
        ffi::CloseHandle(file);
        (api.CryptCATAdminReleaseContext)(h_admin, 0);

        Some(CatalogTrust {
            hr,
            catalog_path,
            member_tag,
        })
    }
}
