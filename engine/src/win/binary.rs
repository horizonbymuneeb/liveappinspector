//! Module F: on-disk binary integrity - SHA-256 of the image as it exists at
//! inspection time, NTFS file identity, PE header facts and Authenticode trust.
//!
//! The hash is streamed over a share-read/write/delete handle so that a running
//! (even locked) executable can still be hashed without perturbing the target.

use std::ffi::c_void;
use std::io::Read;

use sha2::{Digest, Sha256};

use super::ffi;
use crate::model::*;
use crate::util::{self, rfc3339_of, WResult, WinError};

const HASH_CHUNK: usize = 1024 * 1024;
const MAX_HASH_BYTES: u64 = 8 * 1024 * 1024 * 1024; // 8 GiB safety valve

pub struct HashOutcome {
    pub sha256: String,
    pub bytes: u64,
    pub duration_ms: u64,
    /// True when the safety valve stopped hashing early (hash is then partial).
    pub truncated: bool,
}

/// Streams the file through SHA-256 using a minimally invasive file handle.
pub fn hash_file(path: &str) -> WResult<HashOutcome> {
    let wpath = util::wide(path);
    unsafe {
        let h = ffi::CreateFileW(
            wpath.as_ptr(),
            ffi::GENERIC_READ,
            ffi::FILE_SHARE_READ | ffi::FILE_SHARE_WRITE | ffi::FILE_SHARE_DELETE,
            std::ptr::null(),
            ffi::OPEN_EXISTING,
            ffi::FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        );
        if h == ffi::INVALID_HANDLE_VALUE {
            return Err(WinError::last());
        }

        let started = std::time::Instant::now();
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; HASH_CHUNK];
        let mut total: u64 = 0;
        let mut truncated = false;

        loop {
            let mut read: u32 = 0;
            let ok = ffi::ReadFile(
                h,
                buf.as_mut_ptr() as *mut c_void,
                HASH_CHUNK as u32,
                &mut read,
                std::ptr::null_mut(),
            );
            if ok == ffi::FALSE {
                let e = WinError::last();
                ffi::CloseHandle(h);
                return Err(e);
            }
            if read == 0 {
                break;
            }
            hasher.update(&buf[..read as usize]);
            total += read as u64;
            if total >= MAX_HASH_BYTES {
                truncated = true;
                break;
            }
        }
        ffi::CloseHandle(h);
        let digest = hasher.finalize();
        Ok(HashOutcome {
            sha256: util::hex_lower(&digest),
            bytes: total,
            duration_ms: started.elapsed().as_millis() as u64,
            truncated,
        })
    }
}

/// Cheap second opinion on hashing integrity: read via the Rust std file API.
pub fn hash_file_reference(path: &str) -> Option<String> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_CHUNK];
    let mut total: u64 = 0;
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
        if total >= MAX_HASH_BYTES {
            break;
        }
    }
    Some(util::hex_lower(&hasher.finalize()))
}

#[derive(Debug, Clone, Default)]
pub struct FileIdentity {
    pub size: u64,
    pub volume_serial: String,
    pub file_index: String,
    pub attributes: String,
    pub hard_links: u32,
    pub created: util::UnixTime,
    pub modified: util::UnixTime,
    pub accessed: util::UnixTime,
}

pub fn file_identity(path: &str) -> Option<FileIdentity> {
    let wpath = util::wide(path);
    unsafe {
        let h = ffi::CreateFileW(
            wpath.as_ptr(),
            ffi::GENERIC_READ,
            ffi::FILE_SHARE_READ | ffi::FILE_SHARE_WRITE | ffi::FILE_SHARE_DELETE,
            std::ptr::null(),
            ffi::OPEN_EXISTING,
            ffi::FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        );
        if h == ffi::INVALID_HANDLE_VALUE {
            return None;
        }
        let mut info = ffi::BY_HANDLE_FILE_INFORMATION::default();
        let ok = ffi::GetFileInformationByHandle(h, &mut info);
        ffi::CloseHandle(h);
        if ok == ffi::FALSE {
            return None;
        }
        let mut attrs = Vec::new();
        let a = info.dwFileAttributes;
        if a & 0x0000_0001 != 0 {
            attrs.push("readonly");
        }
        if a & 0x0000_0002 != 0 {
            attrs.push("hidden");
        }
        if a & 0x0000_0004 != 0 {
            attrs.push("system");
        }
        if a & 0x0000_0020 != 0 {
            attrs.push("archive");
        }
        if a & 0x0000_0400 != 0 {
            attrs.push("reparse_point");
        }
        if a & 0x0000_0800 != 0 {
            attrs.push("compressed");
        }
        if a & 0x0000_4000 != 0 {
            attrs.push("encrypted");
        }
        if a & 0x0000_0200 != 0 {
            attrs.push("sparse");
        }
        Some(FileIdentity {
            size: ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64,
            volume_serial: format!("{:08X}", info.dwVolumeSerialNumber),
            file_index: format!("{:08X}{:08X}", info.nFileIndexHigh, info.nFileIndexLow),
            attributes: if attrs.is_empty() {
                "normal".into()
            } else {
                attrs.join("|")
            },
            hard_links: info.nNumberOfLinks,
            created: util::filetime_from_parts(
                info.ftCreationTime.dwLowDateTime,
                info.ftCreationTime.dwHighDateTime,
            ),
            modified: util::filetime_from_parts(
                info.ftLastWriteTime.dwLowDateTime,
                info.ftLastWriteTime.dwHighDateTime,
            ),
            accessed: util::filetime_from_parts(
                info.ftLastAccessTime.dwLowDateTime,
                info.ftLastAccessTime.dwHighDateTime,
            ),
        })
    }
}

// ---------------------------------------------------------------------------
// PE header parsing (no external crate)
// ---------------------------------------------------------------------------

pub fn pe_info(path: &str) -> PeInfo {
    let mut out = PeInfo::default();
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            out.note = format!("unreadable: {e}");
            return out;
        }
    };
    if data.len() < 0x40 {
        out.note = "file too small to contain a DOS header".into();
        return out;
    }
    if &data[0..2] != b"MZ" {
        out.note = "no MZ signature (not a PE image)".into();
        return out;
    }
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if e_lfanew + 0x18 + 0x60 > data.len() {
        out.note = "e_lfanew out of bounds".into();
        return out;
    }
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        out.note = "missing PE signature".into();
        return out;
    }
    let coff = e_lfanew + 4;
    let machine = u16::from_le_bytes([data[coff], data[coff + 1]]);
    let timestamp = u32::from_le_bytes([
        data[coff + 4],
        data[coff + 5],
        data[coff + 6],
        data[coff + 7],
    ]);
    let size_opt = u16::from_le_bytes([data[coff + 16], data[coff + 17]]) as usize;
    let characteristics = u16::from_le_bytes([data[coff + 18], data[coff + 19]]);
    let opt = coff + 20;

    out.machine = match machine {
        0x014c => "x86".into(),
        0x8664 => "x64".into(),
        0xAA64 => "arm64".into(),
        0x01c4 => "arm".into(),
        0x0200 => "ia64".into(),
        other => format!("0x{other:04x}"),
    };
    if timestamp > 0 {
        out.compile_timestamp_utc = Some(util::rfc3339(timestamp as i64 * 1000, 0));
    }
    if opt + 2 <= data.len() {
        let magic = u16::from_le_bytes([data[opt], data[opt + 1]]);
        let pe32plus = magic == 0x20b;
        out.linker_version = format!("{}.{}", data[opt + 2], data[opt + 3]);
        let subsystem_off = if pe32plus { 0x44 } else { 0x40 };
        if opt + subsystem_off + 2 <= data.len() {
            let subs =
                u16::from_le_bytes([data[opt + subsystem_off], data[opt + subsystem_off + 1]]);
            out.subsystem = match subs {
                1 => "native".into(),
                2 => "gui".into(),
                3 => "console".into(),
                5 => "os2_cui".into(),
                7 => "posix_cui".into(),
                9 => "windows_ce".into(),
                10 => "efi_application".into(),
                o => format!("subsystem_{o}"),
            };
        }
        let dllchar_off = if pe32plus { 0x46 } else { 0x42 };
        if opt + dllchar_off + 2 <= data.len() {
            let dc = u16::from_le_bytes([data[opt + dllchar_off], data[opt + dllchar_off + 1]]);
            let mut flags = Vec::new();
            if dc & 0x0020 != 0 {
                flags.push("high_entropy_va");
            }
            if dc & 0x0040 != 0 {
                flags.push("aslr");
            }
            if dc & 0x0080 != 0 {
                flags.push("force_integrity");
            }
            if dc & 0x0100 != 0 {
                flags.push("nx_compat");
            }
            if dc & 0x0400 != 0 {
                flags.push("no_seh");
            }
            if dc & 0x4000 != 0 {
                flags.push("control_flow_guard");
            }
            if dc & 0x8000 != 0 {
                flags.push("terminal_server_aware");
            }
            out.characteristics = flags.join("|");
        }
        // Data directory 14 == CLR runtime header -> managed assembly
        let dd_off = opt + if pe32plus { 0x70 } else { 0x60 };
        let clr = dd_off + 14 * 8;
        if clr + 4 <= data.len() && opt + size_opt <= data.len() {
            let rva = u32::from_le_bytes([data[clr], data[clr + 1], data[clr + 2], data[clr + 3]]);
            out.is_dotnet = rva != 0;
        }
    }
    if characteristics & 0x2000 != 0 {
        out.note = "DLL image (not an EXE)".into();
    }
    out
}

// ---------------------------------------------------------------------------
// Authenticode
// ---------------------------------------------------------------------------

fn trust_status_text(hr: ffi::HRESULT) -> (&'static str, String) {
    match hr {
        0 => ("valid", "Signature verified and trusted".to_string()),
        ffi::TRUST_E_NOSIGNATURE => ("unsigned", "No Authenticode signature present".to_string()),
        ffi::TRUST_E_SUBJECT_FORM_UNKNOWN => (
            "unsigned",
            "No signature subject of a known form".to_string(),
        ),
        ffi::TRUST_E_PROVIDER_UNKNOWN => {
            ("unsigned", "No trust provider for this file".to_string())
        }
        ffi::TRUST_E_EXPLICIT_DISTRUST => (
            "untrusted_root",
            "Signature explicitly distrusted by the local policy".to_string(),
        ),
        ffi::CERT_E_UNTRUSTEDROOT => (
            "untrusted_root",
            "Certificate chain terminates in an untrusted root".to_string(),
        ),
        ffi::CERT_E_EXPIRED => ("expired", "Signing certificate has expired".to_string()),
        ffi::CERT_E_CHAINING => (
            "invalid",
            "A certificate chain could not be built".to_string(),
        ),
        ffi::CERT_E_REVOKED => (
            "revoked",
            "Signing certificate has been revoked".to_string(),
        ),
        ffi::CERT_E_REVOCATION_FAILURE => (
            "valid",
            "Signature valid; revocation status could not be checked".to_string(),
        ),
        ffi::CRYPT_E_SECURITY_SETTINGS => (
            "invalid",
            "Cryptographic security settings blocked verification".to_string(),
        ),
        other => (
            "invalid",
            format!("Trust verification returned 0x{:08X}", other as u32),
        ),
    }
}

/// Verifies Authenticode trust on-disk and, when signed, extracts the leaf
/// signer's subject and issuer CN for attribution.
pub fn verify_signature(path: &str) -> SignatureInfo {
    let wpath = util::wide(path);
    let mut info = SignatureInfo::default();

    let api = match ffi::wintrust() {
        Some(a) => a,
        None => {
            info.status = "error".into();
            info.message = "wintrust.dll unavailable; trust could not be evaluated".into();
            return info;
        }
    };

    unsafe {
        let mut file_info = ffi::WINTRUST_FILE_INFO::default();
        file_info.cbStruct = std::mem::size_of::<ffi::WINTRUST_FILE_INFO>() as u32;
        file_info.pcwszFilePath = wpath.as_ptr();

        let mut data = ffi::WINTRUST_DATA::default();
        data.cbStruct = std::mem::size_of::<ffi::WINTRUST_DATA>() as u32;
        data.dwUIChoice = ffi::WTD_UI_NONE;
        data.fdwRevocationChecks = ffi::WTD_REVOKE_NONE;
        data.dwUnionChoice = ffi::WTD_CHOICE_FILE;
        data.pFile = &mut file_info;
        data.dwStateAction = ffi::WTD_STATEACTION_VERIFY;
        data.dwProvFlags =
            ffi::WTD_SAFER_FLAG | ffi::WTD_CACHE_ONLY_URL_RETRIEVAL | ffi::WTD_DISABLE_MD2_MD4;

        let mut action = ffi::WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let hr = (api.WinVerifyTrust)(
            0,
            &mut action,
            &mut data as *mut ffi::WINTRUST_DATA as *mut c_void,
        );
        info.trust_status_hex = format!("0x{:08X}", hr as u32);
        let (status, message) = trust_status_text(hr);
        info.status = status.to_string();
        info.message = message;

        // Always release the trust state to avoid a handle leak per inspection.
        data.dwStateAction = ffi::WTD_STATEACTION_CLOSE;
        (api.WinVerifyTrust)(
            0,
            &mut action,
            &mut data as *mut ffi::WINTRUST_DATA as *mut c_void,
        );

        if matches!(status, "valid" | "expired" | "revoked") {
            info.signature_source = "embedded".into();
            if let Some((subject, issuer, count)) = extract_signer(&wpath) {
                info.signer_subject = subject;
                info.signer_issuer = issuer;
                info.certificates_in_store = count;
            }
            return info;
        }
    }

    // No embedded signature: most of System32 is *catalog*-signed, so check the
    // security catalogs before declaring the image unsigned.
    if info.status == "unsigned" {
        if let Some(cat) = super::catalog::verify_catalog_member(path) {
            info.catalog_path = cat.catalog_path.clone();
            info.catalog_member_tag = cat.member_tag.clone();
            info.trust_status_hex = format!("0x{:08X}", cat.hr as u32);
            if cat.hr == 0 {
                info.status = "valid".into();
                info.signature_source = "catalog".into();
                info.message = format!(
                    "No embedded signature; catalog-signed and trusted ({} catalog)",
                    if cat.catalog_path.is_empty() {
                        "unknown"
                    } else {
                        &cat.catalog_path
                    }
                );
                if let Some((subject, issuer, count)) = {
                    let wide_cat = util::wide(&cat.catalog_path);
                    unsafe { extract_signer(&wide_cat) }
                } {
                    info.signer_subject = subject;
                    info.signer_issuer = issuer;
                    info.certificates_in_store = count;
                }
            } else {
                let (status, message) = trust_status_text(cat.hr);
                info.status = status.to_string();
                info.message = format!("Catalog member verification failed: {message}");
                info.signature_source = "catalog".into();
            }
        } else {
            info.message =
                "No embedded Authenticode signature and no security catalog claims this file"
                    .into();
        }
    }

    info
}

/// Opens the embedded PKCS#7 store and finds the leaf signing certificate
/// (the certificate that is not an issuer of any other certificate present).
unsafe fn extract_signer(wpath: &[u16]) -> Option<(String, String, u32)> {
    let mut h_store: ffi::HANDLE = std::ptr::null_mut();
    let mut h_msg: ffi::HANDLE = std::ptr::null_mut();
    let mut enc = 0u32;
    let mut content = 0u32;
    let mut format = 0u32;
    let mut ctx: *mut c_void = std::ptr::null_mut();

    let ok = ffi::CryptQueryObject(
        ffi::CERT_QUERY_OBJECT_FILE,
        wpath.as_ptr() as *const c_void,
        ffi::CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        ffi::CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        &mut enc,
        &mut content,
        &mut format,
        &mut h_store,
        &mut h_msg,
        &mut ctx,
    );
    if ok == ffi::FALSE || h_store.is_null() {
        return None;
    }

    #[derive(Clone)]
    struct Node {
        ctx: *mut ffi::CERT_CONTEXT,
        subject: String,
        issuer: String,
    }

    let mut nodes: Vec<Node> = Vec::new();
    let mut cur: *mut ffi::CERT_CONTEXT = std::ptr::null_mut();
    loop {
        cur = ffi::CertEnumCertificatesInStore(h_store, cur);
        if cur.is_null() {
            break;
        }
        let subject = cert_name(cur, false).unwrap_or_default();
        let issuer = cert_name(cur, true).unwrap_or_default();
        nodes.push(Node {
            ctx: cur,
            subject,
            issuer,
        });
        if nodes.len() > 64 {
            break;
        }
    }

    let mut result = None;
    if !nodes.is_empty() {
        // Leaf = subject that never appears as an issuer in this store.
        let leaf = nodes
            .iter()
            .find(|n| {
                !nodes.iter().any(|m| {
                    m.issuer.eq_ignore_ascii_case(&n.subject) && !std::ptr::eq(m.ctx, n.ctx)
                })
            })
            .unwrap_or(&nodes[0]);
        result = Some((
            leaf.subject.clone(),
            leaf.issuer.clone(),
            nodes.len() as u32,
        ));
    }

    // Free contexts (CertEnumCertificatesInStore frees the previous one).
    if let Some(last) = nodes.last() {
        ffi::CertFreeCertificateContext(last.ctx);
    }
    if !h_msg.is_null() {
        ffi::CryptMsgClose(h_msg);
    }
    if !h_store.is_null() {
        ffi::CertCloseStore(h_store, 0);
    }
    result
}

unsafe fn cert_name(ctx: *mut ffi::CERT_CONTEXT, issuer: bool) -> Option<String> {
    if ctx.is_null() {
        return None;
    }
    const CERT_NAME_ISSUER_FLAG: u32 = 1;
    let flags = if issuer { CERT_NAME_ISSUER_FLAG } else { 0 };
    let mut buf = vec![0u16; 512];
    let n = ffi::CertGetNameStringW(
        ctx,
        ffi::CERT_NAME_SIMPLE_DISPLAY_TYPE,
        flags,
        std::ptr::null_mut(),
        buf.as_mut_ptr(),
        buf.len() as u32,
    );
    if n <= 1 {
        return None;
    }
    Some(util::from_wide(&buf[..(n as usize).min(buf.len())]))
}

// ---------------------------------------------------------------------------
// Aggregate
// ---------------------------------------------------------------------------

/// Collects the whole binary-integrity section, recording partial failures
/// (e.g. a locked file) without aborting the inspection.
pub fn collect(path: &str, path_provenance: &str) -> BinaryInfo {
    let mut b = BinaryInfo {
        path: path.to_string(),
        file_name: std::path::Path::new(path)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default(),
        hash_algorithm: "SHA-256".into(),
        ..Default::default()
    };

    if path.is_empty() {
        b.meta = SectionMeta::error("target image path unavailable (access denied to process)");
        return b;
    }
    if !path_provenance.starts_with("live process") {
        b.meta.note(format!(
            "image path provenance: {path_provenance} - the hash below covers the file currently at that path, which was not verified against the process's mapped image"
        ));
    }

    match hash_file(path) {
        Ok(h) => {
            b.sha256 = h.sha256;
            b.bytes_read = h.bytes;
            b.hash_duration_ms = h.duration_ms;
            b.hashed_at_utc = rfc3339_of(util::UnixTime::now()).unwrap_or_default();
            b.size_bytes = h.bytes;
            if h.truncated {
                b.meta
                    .warn("hashing stopped at the 8 GiB safety limit; hash is partial");
            }
            // Cross-check with an independent read path to detect tampering with
            // the file between collection passes.
            if let Some(reference) = hash_file_reference(path) {
                if reference != b.sha256 && !h.truncated {
                    b.meta.warn(format!(
                        "SHA-256 mismatch between native and std::fs read passes ({reference}) - file changed during collection"
                    ));
                }
            }
        }
        Err(e) => {
            b.meta = SectionMeta::with(
                if e.is_access_denied() {
                    Status::Denied
                } else {
                    Status::Error
                },
                format!("SHA-256 of image failed: {e}"),
            );
            b.meta.win32_error = Some(e.code);
        }
    }

    if let Some(id) = file_identity(path) {
        b.size_bytes = id.size;
        b.volume_serial = id.volume_serial;
        b.file_index = id.file_index;
        b.file_attributes = id.attributes;
        b.hard_link_count = id.hard_links;
        b.created_utc = rfc3339_of(id.created);
        b.modified_utc = rfc3339_of(id.modified);
        b.accessed_utc = rfc3339_of(id.accessed);
    } else {
        b.meta
            .warn("NTFS file identity unavailable (GetFileInformationByHandle failed)");
    }

    b.pe = pe_info(path);
    if let Some(compiled) = b.pe.compile_timestamp_utc.clone() {
        let now = crate::util::rfc3339_of(crate::util::UnixTime::now()).unwrap_or_default();
        if compiled.as_str() > now.as_str() {
            // MSVC's /Brepro (deterministic builds) writes a debug-directory hash
            // into TimeDateStamp instead of real time; Microsoft-signed binaries
            // are routinely "compiled in the future".
            b.meta.note(format!(
                "PE TimeDateStamp ({compiled}) is in the future: this is the deterministic-build marker (/Brepro), not a real compile time - do not use it as a timestomp indicator"
            ));
        } else if let Some(modified) = b.modified_utc.clone() {
            if compiled.as_str() > modified.as_str() {
                b.meta.warn(format!(
                    "PE compile timestamp ({compiled}) is newer than the on-disk last-write time ({modified}) - possible timestomping"
                ));
            }
        }
    }

    b.signature = verify_signature(path);
    if b.signature.status == "unsigned"
        && !b
            .path
            .to_ascii_lowercase()
            .contains("\\windows\\system32\\")
    {
        b.meta
            .warn("image is not Authenticode signed (common for portable/unsigned binaries)");
    }
    b
}
