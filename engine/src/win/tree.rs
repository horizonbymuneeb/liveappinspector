//! Module C: process tree and genealogy.
//!
//! Parent linkage comes from the kernel (`NtQueryInformationProcess`), not from
//! Toolhelp, because Toolhelp happily reports a *recycled* parent PID as if it
//! were still the real parent. The creation-time ordering check below surfaces
//! exactly that spoofing primitive.

use std::collections::{HashMap, VecDeque};

use super::ffi;
use super::process;
use crate::model::*;
use crate::util;

#[derive(Debug, Clone)]
pub struct ProcEntry {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub threads: u32,
}

/// One Toolhelp pass over the live process list.
pub fn snapshot() -> Vec<ProcEntry> {
    let mut out = Vec::new();
    unsafe {
        let snap = ffi::CreateToolhelp32Snapshot(ffi::TH32CS_SNAPPROCESS, 0);
        if snap == ffi::INVALID_HANDLE_VALUE {
            return out;
        }
        let mut pe = ffi::PROCESSENTRY32W::default();
        pe.dwSize = std::mem::size_of::<ffi::PROCESSENTRY32W>() as u32;
        if ffi::Process32FirstW(snap, &mut pe) != ffi::FALSE {
            loop {
                out.push(ProcEntry {
                    pid: pe.th32ProcessID,
                    ppid: pe.th32ParentProcessID,
                    name: util::from_wide(&pe.szExeFile),
                    threads: pe.cntThreads,
                });
                if ffi::Process32NextW(snap, &mut pe) == ffi::FALSE {
                    break;
                }
                if out.len() > 100_000 {
                    break;
                }
            }
        }
        ffi::CloseHandle(snap);
    }
    out
}

pub fn thread_count_of(entries: &[ProcEntry], pid: u32) -> u32 {
    entries
        .iter()
        .find(|e| e.pid == pid)
        .map(|e| e.threads)
        .unwrap_or(0)
}

pub fn session_id_of(pid: u32) -> u32 {
    unsafe {
        let mut sid = 0u32;
        if ffi::ProcessIdToSessionId(pid, &mut sid) != ffi::FALSE {
            sid
        } else {
            0
        }
    }
}

/// Cheap, rights-limited probe of another process for name/path/creation time.
fn probe(pid: u32, fallback_name: &str, is_live: bool) -> ProcessRef {
    let mut r = ProcessRef {
        pid,
        name: fallback_name.to_string(),
        is_alive: is_live,
        session_id: session_id_of(pid),
        ..Default::default()
    };
    let outcome = process::open_for_forensics(pid);
    if let Some(p) = outcome.process {
        if let Ok(path) = p.image_path() {
            if r.name.is_empty() {
                r.name = std::path::Path::new(&path)
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default();
            }
            r.image_path = Some(path);
        }
        if let Ok(t) = p.times() {
            r.created_utc = t.created_utc;
        }
    }
    r
}

/// Builds the genealogy section for `pid`.
pub fn collect(pid: u32, kernel_parent: Option<u32>, target_created_ms: i64) -> Genealogy {
    let mut g = Genealogy::default();
    let entries = snapshot();
    g.living_processes_total = entries.len() as u32;

    let by_pid: HashMap<u32, &ProcEntry> = entries.iter().map(|e| (e.pid, e)).collect();
    let name_of = |p: u32| -> String { by_pid.get(&p).map(|e| e.name.clone()).unwrap_or_default() };

    // ---- parent -------------------------------------------------------------
    let parent_pid = kernel_parent.filter(|&p| p != 0).or_else(|| {
        // Fall back to Toolhelp only when the kernel query was denied.
        by_pid.get(&pid).map(|e| e.ppid).filter(|&p| p != 0)
    });

    if let Some(ppid) = parent_pid {
        let pr = probe(ppid, &name_of(ppid), by_pid.contains_key(&ppid));
        // Parent-PID recycling detector: a parent that started *after* its child
        // cannot be the real launcher.
        if let (Some(parent_created), true) = (&pr.created_utc, target_created_ms > 0) {
            if let Ok(pt) = parse_rfc3339_ms(parent_created) {
                if pt > target_created_ms {
                    g.meta.warn(format!(
                        "parent PID {ppid} was created after the target - parent PID was likely recycled (classic PPID-spoof indicator)"
                    ));
                }
            }
        }
        if !pr.is_alive {
            g.meta.note(format!(
                "parent PID {ppid} is no longer running: the launcher has exited or the PID was recycled (image name is unrecoverable)"
            ));
        }
        g.parent = Some(pr);
    } else {
        g.meta
            .warn("no parent PID resolved (kernel query denied and Toolhelp lookup empty)");
    }

    // ---- ancestors ----------------------------------------------------------
    let mut cursor = parent_pid;
    let mut seen = std::collections::HashSet::new();
    let mut depth = 1u32;
    while let Some(p) = cursor {
        if p == 0 || p == pid || !seen.insert(p) || depth > 32 {
            break;
        }
        let mut pr = probe(p, &name_of(p), by_pid.contains_key(&p));
        pr.depth = depth;
        let next = by_pid.get(&p).map(|e| e.ppid).unwrap_or(0);
        g.ancestors.push(pr);
        cursor = if next != 0 { Some(next) } else { None };
        depth += 1;
    }

    // ---- children and descendants -------------------------------------------
    let mut children_of: HashMap<u32, Vec<u32>> = HashMap::new();
    for e in &entries {
        children_of.entry(e.ppid).or_default().push(e.pid);
    }
    if let Some(kids) = children_of.get(&pid) {
        for &c in kids {
            let mut pr = probe(c, &name_of(c), true);
            pr.depth = 1;
            g.children.push(pr);
        }
    }
    g.children.sort_by_key(|c| c.pid);

    // BFS for the full descendant set (bounded, breadth-first for usefulness).
    let mut queue: VecDeque<(u32, u32)> = g.children.iter().map(|c| (c.pid, 1u32)).collect();
    let mut visited: std::collections::HashSet<u32> = g.children.iter().map(|c| c.pid).collect();
    while let Some((p, d)) = queue.pop_front() {
        if d > 8 || g.descendants.len() >= 512 {
            if g.descendants.len() >= 512 {
                g.meta
                    .warn("descendant enumeration truncated at 512 processes");
            }
            break;
        }
        for &c in children_of.get(&p).map(|v| v.as_slice()).unwrap_or(&[]) {
            if !visited.insert(c) {
                continue;
            }
            let mut pr = probe(c, &name_of(c), true);
            pr.depth = d + 1;
            g.descendants.push(pr);
            queue.push_back((c, d + 1));
        }
    }
    g.descendants.sort_by_key(|c| (c.depth, c.pid));

    g
}

fn parse_rfc3339_ms(s: &str) -> Result<i64, ()> {
    // Minimal parser for our own emitted format: YYYY-MM-DDTHH:MM:SS.ffffffZ
    let bytes = s.as_bytes();
    if bytes.len() < 20 {
        return Err(());
    }
    let num = |a: usize, b: usize| -> i64 {
        s.get(a..b).and_then(|x| x.parse::<i64>().ok()).unwrap_or(0)
    };
    let (y, mo, d) = (num(0, 4), num(5, 7), num(8, 10));
    let (h, mi, sec) = (num(11, 13), num(14, 16), num(17, 19));
    let millis = if bytes.len() > 20 && bytes[19] == b'.' {
        let frac = &s[20..s.len() - 1];
        let digits: String = frac.chars().take(3).collect();
        digits.parse::<i64>().unwrap_or(0) * 10i64.pow(3 - digits.len() as u32)
    } else {
        0
    };
    // days since epoch
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Ok(((days * 86_400 + h * 3600 + mi * 60 + sec) * 1000) + millis)
}
