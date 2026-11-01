//! Module E (part 1): loaded modules with version resources.

use std::ffi::c_void;

use super::binary;
use super::ffi;
use super::process::Process;
use crate::model::*;
use crate::util::{self, WinError};

const MAX_MODULES: usize = 1024;

pub fn collect(proc: &Process, target_path: &str) -> ModuleList {
    let mut list = ModuleList::default();

    unsafe {
        let mut needed: u32 = 0;
        let mut cap = 512usize;
        let mut modules: Vec<ffi::HMODULE> = Vec::new();
        let mut ok = false;
        for _ in 0..4 {
            modules = vec![0isize; cap];
            let bytes = (modules.len() * std::mem::size_of::<ffi::HMODULE>()) as u32;
            if ffi::K32EnumProcessModulesEx(
                proc.handle,
                modules.as_mut_ptr(),
                bytes,
                &mut needed,
                ffi::LIST_MODULES_ALL,
            ) != ffi::FALSE
            {
                ok = true;
                break;
            }
            let e = WinError::last();
            if e.code == ffi::ERROR_INSUFFICIENT_BUFFER {
                cap =
                    ((needed as usize / std::mem::size_of::<ffi::HMODULE>()) + 64).min(MAX_MODULES);
                continue;
            }
            list.meta = SectionMeta::with(
                if e.is_access_denied() {
                    Status::Denied
                } else {
                    Status::Error
                },
                format!("EnumProcessModulesEx failed: {e}"),
            );
            list.meta.win32_error = Some(e.code);
            return list;
        }
        if !ok {
            list.meta = SectionMeta::error("EnumProcessModulesEx did not converge");
            return list;
        }
        let count = (needed as usize / std::mem::size_of::<ffi::HMODULE>()).min(modules.len());
        modules.truncate(count);

        let target_norm = util::wide(target_path.to_ascii_lowercase());
        let target_lower = util::from_wide(&target_norm);

        for (idx, &hm) in modules.iter().enumerate() {
            if hm == 0 {
                continue;
            }
            let mut path_buf = vec![0u16; 4096];
            let n = ffi::K32GetModuleFileNameExW(
                proc.handle,
                hm,
                path_buf.as_mut_ptr(),
                path_buf.len() as u32,
            );
            let path = if n > 0 {
                util::from_wide(&path_buf[..n as usize])
            } else {
                String::new()
            };

            let mut mi = ffi::MODULEINFO::default();
            let have_info = ffi::K32GetModuleInformation(
                proc.handle,
                hm,
                &mut mi,
                std::mem::size_of::<ffi::MODULEINFO>() as u32,
            ) != ffi::FALSE;

            let mut name = path.rsplit('\\').next().unwrap_or("").to_string();
            if name.is_empty() {
                let mut base = vec![0u16; 512];
                let bn = ffi::K32GetModuleBaseNameW(
                    proc.handle,
                    hm,
                    base.as_mut_ptr(),
                    base.len() as u32,
                );
                if bn > 0 {
                    name = util::from_wide(&base[..bn as usize]);
                }
            }

            let mut info = ModuleInfo {
                name: name.clone(),
                is_target_image: !target_lower.is_empty()
                    && path.to_ascii_lowercase() == target_lower,
                base_address: format!("0x{:016X}", hm as usize),
                size_bytes: if have_info { mi.SizeOfImage as u64 } else { 0 },
                entry_point: format!("0x{:016X}", mi.EntryPoint as usize),
                path: path.clone(),
                ..Default::default()
            };

            if info.is_target_image && list.target_image_index.is_none() {
                list.target_image_index = Some(idx as u32);
            }

            if !path.is_empty() {
                if let Some((company, product, file_version, description)) = version_strings(&path)
                {
                    info.company = company;
                    info.product = product;
                    info.file_version = file_version;
                    info.description = description;
                }
                match binary::file_identity(&path) {
                    Some(id) => info.on_disk_modified_utc = util::rfc3339_of(id.modified),
                    None => {
                        // Image is mapped but the backing file is gone: unlinked
                        // module (process hollowing / manual mapping / deleted DLL).
                        info.missing_on_disk = true;
                        list.meta
                            .warn(format!("module {name} is mapped but missing on disk"));
                    }
                }
            }
            list.items.push(info);
        }

        ffi::CloseHandle(std::ptr::null_mut()); // no-op guard for clarity
        list.count = list.items.len() as u32;
        if list.items.is_empty() {
            list.meta = SectionMeta::partial("module list came back empty");
        }
    }

    list
}

/// Extracts VS_VERSIONINFO string resources for a module on disk.
fn version_strings(path: &str) -> Option<(String, String, String, String)> {
    let api = ffi::version_api()?;
    let wpath = util::wide(path);
    unsafe {
        let mut handle: u32 = 0;
        let size = (api.GetFileVersionInfoSizeW)(wpath.as_ptr(), &mut handle);
        if size == 0 {
            return None;
        }
        let mut block = vec![0u8; size as usize];
        if (api.GetFileVersionInfoW)(wpath.as_ptr(), 0, size, block.as_mut_ptr() as *mut c_void)
            == ffi::FALSE
        {
            return None;
        }

        // File version from the fixed info block.
        let mut file_version = String::new();
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let mut len: u32 = 0;
        let root = util::wide("\\");
        if (api.VerQueryValueW)(
            block.as_ptr() as *const c_void,
            root.as_ptr(),
            &mut ptr,
            &mut len,
        ) != ffi::FALSE
            && !ptr.is_null()
            && (len as usize) >= std::mem::size_of::<ffi::VS_FIXEDFILEINFO>()
        {
            let fi: ffi::VS_FIXEDFILEINFO = std::ptr::read_unaligned(ptr as *const _);
            if fi.dwSignature == 0xFEEF_04BD {
                file_version = format!(
                    "{}.{}.{}.{}",
                    (fi.dwFileVersionMS >> 16) & 0xFFFF,
                    fi.dwFileVersionMS & 0xFFFF,
                    (fi.dwFileVersionLS >> 16) & 0xFFFF,
                    fi.dwFileVersionLS & 0xFFFF
                );
            }
        }

        // Translation table -> StringFileInfo block.
        let mut company = String::new();
        let mut product = String::new();
        let mut description = String::new();
        let trans_key = util::wide("\\VarFileInfo\\Translation");
        let mut trans_ptr: *mut c_void = std::ptr::null_mut();
        let mut trans_len: u32 = 0;
        if (api.VerQueryValueW)(
            block.as_ptr() as *const c_void,
            trans_key.as_ptr(),
            &mut trans_ptr,
            &mut trans_len,
        ) != ffi::FALSE
            && !trans_ptr.is_null()
            && trans_len >= 4
        {
            let pairs =
                std::slice::from_raw_parts(trans_ptr as *const u16, (trans_len / 2) as usize);
            for chunk in pairs.chunks_exact(2).take(4) {
                let sub = |field: &str| -> String {
                    let key = util::wide(format!(
                        "\\StringFileInfo\\{:04x}{:04x}\\{}",
                        chunk[0], chunk[1], field
                    ));
                    let mut p: *mut c_void = std::ptr::null_mut();
                    let mut l: u32 = 0;
                    if (api.VerQueryValueW)(
                        block.as_ptr() as *const c_void,
                        key.as_ptr(),
                        &mut p,
                        &mut l,
                    ) != ffi::FALSE
                        && !p.is_null()
                    {
                        util::from_wide_ptr(p as *const u16)
                    } else {
                        String::new()
                    }
                };
                if company.is_empty() {
                    company = sub("CompanyName");
                }
                if product.is_empty() {
                    product = sub("ProductName");
                }
                if description.is_empty() {
                    description = sub("FileDescription");
                }
                if !company.is_empty() && !product.is_empty() && !description.is_empty() {
                    break;
                }
            }
        }

        if company.is_empty()
            && product.is_empty()
            && description.is_empty()
            && file_version.is_empty()
        {
            None
        } else {
            Some((company, product, file_version, description))
        }
    }
}
