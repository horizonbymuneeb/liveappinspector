//! Module G: virtual-memory anomaly triage.
//!
//! Why this exists
//! ---------------
//! Handles, modules and tokens describe what a process *is*; they do not show
//! what it has *mapped*. Executable private memory that is not backed by an image
//! (and W+X regions in general) is the single strongest cheap indicator of code
//! injection, reflective loading, a JIT-heavy runtime, or a manually mapped
//! payload. Walking the region list with `VirtualQueryEx` is read-only, bounded,
//! and needs no more privilege than the process handle already grants.
//!
//! What this module deliberately does **not** do
//! ---------------------------------------------
//! It does not claim to detect injection. It records facts an examiner can verify:
//! which regions are executable, whether they are image-backed, and whether they
//! are writable. A verdict ("hollowed", "injected") requires comparing mapped
//! bytes against the on-disk image, which is a different, riskier operation.
//!
//! Legitimate sources of private-executable memory are common: CLR/JIT
//! (`.NET`, JavaScript engines), Go and Java runtimes, `VirtualAlloc`-based
//! buffers, GPU driver thunks and Control-Flow-Guard dispatch tables. That is why
//! the section reports counts and addresses rather than a score.

use std::ffi::c_void;

use super::ffi;
use super::process::Process;
use crate::model::{MemoryAnomaly, MemoryReport, SectionMeta};

/// Hard bounds so a pathological address space cannot stall an acquisition.
const MAX_REGIONS: usize = 200_000;
const MAX_ANOMALIES: usize = 250;

pub fn protection_name(protect: u32) -> String {
    if protect == 0 {
        return "none".into();
    }
    let base = protect & !(ffi::PAGE_GUARD | ffi::PAGE_NOCACHE | ffi::PAGE_WRITECOMBINE);
    let mut name = match base {
        ffi::PAGE_NOACCESS => "noaccess",
        ffi::PAGE_READONLY => "r",
        ffi::PAGE_READWRITE => "rw",
        ffi::PAGE_WRITECOPY => "wc",
        ffi::PAGE_EXECUTE => "x",
        ffi::PAGE_EXECUTE_READ => "rx",
        ffi::PAGE_EXECUTE_READWRITE => "rwx",
        ffi::PAGE_EXECUTE_WRITECOPY => "xwc",
        _ => "unknown",
    }
    .to_string();
    if protect & ffi::PAGE_GUARD != 0 {
        name.push_str("|guard");
    }
    if protect & ffi::PAGE_NOCACHE != 0 {
        name.push_str("|nocache");
    }
    name
}

fn type_name(t: u32) -> &'static str {
    match t {
        0 => "none",
        ffi::MEM_PRIVATE => "private",
        ffi::MEM_MAPPED => "mapped",
        ffi::MEM_IMAGE => "image",
        _ => "unknown",
    }
}

fn is_executable(protect: u32) -> bool {
    protect
        & (ffi::PAGE_EXECUTE
            | ffi::PAGE_EXECUTE_READ
            | ffi::PAGE_EXECUTE_READWRITE
            | ffi::PAGE_EXECUTE_WRITECOPY)
        != 0
}

fn is_writable(protect: u32) -> bool {
    protect
        & (ffi::PAGE_READWRITE
            | ffi::PAGE_WRITECOPY
            | ffi::PAGE_EXECUTE_READWRITE
            | ffi::PAGE_EXECUTE_WRITECOPY)
        != 0
}

/// Walks the target's address space and classifies committed regions.
pub fn collect(proc: &Process, pid: u32) -> MemoryReport {
    let mut report = MemoryReport::default();

    if !proc.full_access {
        report.meta = SectionMeta::with(
            crate::model::Status::Denied,
            "VirtualQueryEx needs PROCESS_QUERY_INFORMATION + PROCESS_VM_READ; the handle is limited",
        );
        report.meta.warnings.push(
            "run the engine elevated (or uninjected with SeDebugPrivilege) to map the address space".into(),
        );
        return report;
    }

    let mut address: usize = 0;
    let mut scanned = 0usize;
    let mut anomalies: Vec<MemoryAnomaly> = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut image_bytes: u64 = 0;
    let mut mapped_bytes: u64 = 0;
    let mut private_bytes: u64 = 0;
    let mut committed = 0u32;

    unsafe {
        loop {
            let mut mbi = ffi::MEMORY_BASIC_INFORMATION::default();
            let written = ffi::VirtualQueryEx(
                proc.handle,
                address as *const c_void,
                &mut mbi,
                std::mem::size_of::<ffi::MEMORY_BASIC_INFORMATION>(),
            );
            if written == 0 || mbi.RegionSize == 0 {
                break;
            }
            scanned += 1;

            let region_start = mbi.BaseAddress as usize;
            let size = mbi.RegionSize as u64;

            if mbi.State == ffi::MEM_COMMIT {
                committed += 1;
                total_bytes += size;
                match mbi.Type {
                    ffi::MEM_IMAGE => image_bytes += size,
                    ffi::MEM_MAPPED => mapped_bytes += size,
                    ffi::MEM_PRIVATE => private_bytes += size,
                    _ => {}
                }

                if mbi.Protect & ffi::PAGE_GUARD == 0 && mbi.Protect != ffi::PAGE_NOACCESS {
                    let exec = is_executable(mbi.Protect);
                    let write = is_writable(mbi.Protect);
                    if exec {
                        report.executable_regions += 1;
                        report.executable_bytes += size;
                        if mbi.Type == ffi::MEM_PRIVATE {
                            report.private_executable_regions += 1;
                            report.private_executable_bytes += size;
                        }
                        if write {
                            report.writable_executable_regions += 1;
                            report.writable_executable_bytes += size;
                        }
                    }

                    // An anomaly is: executable **and** (private or writable). Private
                    // executable memory is not backed by any image on disk; writable
                    // executable memory needs no write-then-execute sequence.
                    if exec && (write || mbi.Type == ffi::MEM_PRIVATE) {
                        let mut note = String::new();
                        if write {
                            note.push_str("W+X region");
                        }
                        if mbi.Type == ffi::MEM_PRIVATE {
                            if !note.is_empty() {
                                note.push_str("; ");
                            }
                            note.push_str("executable private memory (no image backing)");
                        }
                        anomalies.push(MemoryAnomaly {
                            base_address: format!("0x{region_start:016X}"),
                            size_bytes: size,
                            protection: protection_name(mbi.Protect),
                            region_type: type_name(mbi.Type).to_string(),
                            note,
                        });
                    }
                }
            }

            let next = region_start.saturating_add(mbi.RegionSize);
            if next <= address || scanned >= MAX_REGIONS {
                break;
            }
            address = next;
        }
    }

    if scanned == 0 {
        let err = crate::util::WinError::last();
        report.meta = SectionMeta::with(
            if err.is_access_denied() {
                crate::model::Status::Denied
            } else {
                crate::model::Status::Error
            },
            format!("VirtualQueryEx could not walk the address space: {err}"),
        );
        report.meta.win32_error = Some(err.code);
        return report;
    }

    // Largest first: a payload is usually bigger than a JIT thunk, and the list is
    // truncated for display only (counts above stay complete).
    anomalies.sort_by_key(|a| std::cmp::Reverse(a.size_bytes));
    let total_anomalies = anomalies.len();
    anomalies.truncate(MAX_ANOMALIES);
    let shown = anomalies.len();

    report.pid = pid;
    report.regions_scanned = scanned as u32;
    report.committed_regions = committed;
    report.committed_bytes = total_bytes;
    report.image_bytes = image_bytes;
    report.mapped_bytes = mapped_bytes;
    report.private_bytes = private_bytes;
    report.anomalies = anomalies;
    report.anomalies_shown = shown as u32;

    if report.writable_executable_regions > 0 {
        report.meta.note(format!(
            "{} writable+executable region(s), {} executable private region(s) - legitimate for CLR/JIT, browser and Go runtimes, but worth correlating with unsigned modules and network activity",
            report.writable_executable_regions, report.private_executable_regions
        ));
    } else {
        report
            .meta
            .note("no writable+executable regions observed at collection time; note that JIT runtimes only create them on demand");
    }
    if total_anomalies > shown {
        report.meta.note(format!(
            "anomaly list truncated to the {} largest of {total_anomalies}; counters are complete",
            shown
        ));
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protection_decoding_covers_the_common_flags() {
        assert_eq!(protection_name(ffi::PAGE_EXECUTE_READ), "rx");
        assert_eq!(protection_name(ffi::PAGE_EXECUTE_READWRITE), "rwx");
        assert_eq!(
            protection_name(ffi::PAGE_READWRITE | ffi::PAGE_GUARD),
            "rw|guard"
        );
        assert_eq!(protection_name(0), "none");
    }

    #[test]
    fn exec_and_write_predicates() {
        assert!(is_executable(ffi::PAGE_EXECUTE_READWRITE));
        assert!(!is_executable(ffi::PAGE_READWRITE));
        assert!(is_writable(ffi::PAGE_EXECUTE_WRITECOPY));
        assert!(!is_writable(ffi::PAGE_EXECUTE_READ));
    }
}
