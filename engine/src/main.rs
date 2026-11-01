//! LiveAppInspector - point-and-shoot live application forensics for Windows.
//!
//! Subcommands
//! -----------
//!   inspect  collect a full forensic report for a target window or PID
//!   pick     show the crosshair picker and print the resolved target
//!   serve    run the local dashboard engine (default when no args)
//!   hash     SHA-256 an on-disk file with NTFS identity metadata
//!   verify   re-verify the seal of an exported JSON report
//!   procs    list live processes (pid/parent/name)
//!   self-check  engine/diagnostic summary
//!
//! Exit codes: 0 success, 1 usage error, 2 collection failure, 3 access denied.

// Win32 structures are initialised field-by-field on a zeroed default so the
// security-relevant fields stay visible at the call site; a `..Default::default()`
// literal would bury them in noise. Everything else is clippy-clean.
#![allow(clippy::field_reassign_with_default)]

mod engine;
mod model;
mod report;
mod server;
mod util;
mod win;

use std::process::ExitCode;

use model::{CaseInfo, Report};
use util::WinError;

const HELP: &str = r#"LiveAppInspector - live application forensics (DFIR)

USAGE
  lai [serve] [--port N] [--open] [--no-handles] [--resolve-dns]
  lai inspect (--pid N | --window | --hwnd 0xNN) [options]
  lai pick [--json]
  lai render <report.json> [--html <path>] [--json <path>] [--reseal]
  lai hash <path>
  lai verify <report.json>
  lai procs [--limit N]
  lai self-check

TARGET SELECTION
  --pid N            inspect an explicit process id
  --window           show the crosshair picker, then inspect the picked window
  --hwnd 0xNN        inspect the process that owns an explicit window handle

COLLECTION OPTIONS
  --no-handles       skip handle-table enumeration (much faster, less evidence)
  --handle-cap N     maximum handles to resolve (default 8000)
  --resolve-dns      reverse-resolve remote endpoints (adds latency, off by default)

REPORTING
  --json <path>      write the sealed JSON report (inspect) / re-write a report (render)
  --html <path>      write the self-contained dark HTML exhibit
  --case <id>        case identifier recorded in the chain of custody
  --examiner <name>  examiner recorded in the chain of custody
  --org <name>       organisation recorded in the chain of custody
  --notes <text>     free-text case notes

  --elevate          re-launch the command elevated through UAC
  -h, --help         this help

EXAMPLES
  lai inspect --window --json case42.json --html case42.html --examiner "A. Examiner"
  lai inspect --pid 1234 --no-handles
  lai serve --open
  lai verify case42.json
  lai render case42.json --html redacted.html          re-render an exhibit
  lai render case42.json --reseal --json redacted.json seal an edited report
"#;

fn main() -> ExitCode {
    // Must happen before any window is created: a DPI-unaware process sees
    // virtualised screen coordinates, which would let the picker resolve a
    // different window than the one the examiner clicked.
    win::dpi::enable();

    let args: Vec<String> = std::env::args().skip(1).collect();

    // Nothing to do? Start the dashboard *and* open it: double-clicking the exe
    // is the primary product path for a responder on a live box.
    if args.is_empty() {
        let mut with_open = vec!["--open".to_string()];
        with_open.extend_from_slice(&[]);
        return run_serve(&with_open);
    }
    if args
        .iter()
        .any(|a| a == "-h" || a == "--help" || a == "help")
    {
        println!("{HELP}");
        return ExitCode::SUCCESS;
    }
    if args.iter().any(|a| a == "-V" || a == "--version") {
        println!("{} {}", model::TOOL_NAME, model::TOOL_VERSION);
        return ExitCode::SUCCESS;
    }

    match args[0].as_str() {
        "serve" => run_serve(&args[1..]),
        "inspect" => run_inspect(&args[1..]),
        "pick" => run_pick(&args[1..]),
        "render" => run_render(&args[1..]),
        "hash" => run_hash(&args[1..]),
        "verify" => run_verify(&args[1..]),
        "procs" => run_procs(&args[1..]),
        "self-check" | "selfcheck" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&engine::diagnostics()).unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("unknown command: {other}\n");
            println!("{HELP}");
            ExitCode::from(1)
        }
    }
}

// ---------------------------------------------------------------------------
// Argument helpers
// ---------------------------------------------------------------------------

fn flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn number(args: &[String], name: &str) -> Option<u32> {
    value(args, name).and_then(|v| v.trim().parse().ok())
}

fn build_options(args: &[String]) -> engine::Options {
    engine::Options {
        handle_cap: number(args, "--handle-cap").unwrap_or(win::handles::DEFAULT_HANDLE_CAP),
        include_handles: !flag(args, "--no-handles"),
        resolve_dns: flag(args, "--resolve-dns"),
        case: CaseInfo {
            case_id: value(args, "--case").unwrap_or_default(),
            examiner: value(args, "--examiner").unwrap_or_default(),
            organization: value(args, "--org").unwrap_or_default(),
            notes: value(args, "--notes").unwrap_or_default(),
        },
    }
}

fn maybe_elevate(args: &[String]) -> bool {
    if !flag(args, "--elevate") {
        return false;
    }
    let mut forward: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| a != "--elevate")
        .collect();
    forward.retain(|a| a != "--elevate");
    match win::sys::relaunch_elevated(&forward) {
        Ok(true) => true,
        Ok(false) => {
            eprintln!("elevation declined by the operator");
            false
        }
        Err(e) => {
            eprintln!("elevation failed: {e}");
            false
        }
    }
}

// ---------------------------------------------------------------------------
// serve
// ---------------------------------------------------------------------------

fn run_serve(args: &[String]) -> ExitCode {
    maybe_elevate(args);
    let cfg = server::Config {
        port: number(args, "--port").unwrap_or(0) as u16,
        port_final: 0,
        open_browser: flag(args, "--open"),
        options: build_options(args),
    };
    match server::serve(cfg) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("fatal: {e}");
            ExitCode::from(2)
        }
    }
}

// ---------------------------------------------------------------------------
// inspect
// ---------------------------------------------------------------------------

fn run_inspect(args: &[String]) -> ExitCode {
    maybe_elevate(args);
    let target = if let Some(pid) = number(args, "--pid") {
        engine::Target::from_pid(pid)
    } else if flag(args, "--window") {
        match win::window::pick_blocking("interactive_pick", std::time::Duration::from_secs(120)) {
            Ok(Some(p)) => engine::Target::from_pick(&p),
            Ok(None) => {
                eprintln!("pick cancelled or timed out");
                return ExitCode::from(2);
            }
            Err(e) => {
                eprintln!("picker error: {e}");
                return ExitCode::from(2);
            }
        }
    } else if let Some(h) = value(args, "--hwnd") {
        let hwnd = usize::from_str_radix(h.trim_start_matches("0x"), 16).unwrap_or(0) as isize;
        let mut pid = 0u32;
        unsafe { win::ffi::GetWindowThreadProcessId(hwnd, &mut pid) };
        let mut t = engine::Target::from_pid(pid);
        t.mode = "explicit_hwnd".into();
        t.hwnd = hwnd;
        t
    } else {
        // Default: the currently focused window - the fastest triage path.
        let fg = unsafe { win::ffi::GetForegroundWindow() };
        if fg == 0 {
            eprintln!("no foreground window and no --pid/--window/--hwnd given");
            return ExitCode::from(1);
        }
        let mut pid = 0u32;
        unsafe { win::ffi::GetWindowThreadProcessId(fg, &mut pid) };
        let mut t = engine::Target::from_pid(pid);
        t.mode = "foreground_window".into();
        t.hwnd = fg;
        t
    };

    let opts = build_options(args);
    let mut rep = engine::inspect(&target, &opts);
    let seal = report::json::seal(&mut rep);

    // CLI summary - the full artifact set goes to the files.
    print_summary(&rep, &seal);

    let mut wrote_file = false;
    if let Some(path) = value(args, "--json") {
        match report::json::write_atomic(&path, &report::json::to_pretty(&rep)) {
            Ok(()) => {
                println!("JSON report : {path}");
                wrote_file = true;
            }
            Err(e) => eprintln!("could not write {path}: {e}"),
        }
    }
    if let Some(path) = value(args, "--html") {
        match report::json::write_atomic(&path, &report::html::render(&rep)) {
            Ok(()) => {
                println!("HTML exhibit: {path}");
                wrote_file = true;
            }
            Err(e) => eprintln!("could not write {path}: {e}"),
        }
    }
    if !wrote_file {
        // No destination given: emit the sealed JSON on stdout so the command
        // composes with jq / pipelines.
        println!("{}", report::json::to_pretty(&rep));
    }

    if rep.process.accessible {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(3)
    }
}

fn print_summary(r: &Report, seal: &str) {
    let p = &r.process;
    let u = &r.user_context;
    println!(
        "LiveAppInspector {} - acquisition summary",
        model::TOOL_VERSION
    );
    println!(
        "  target      : {} (pid {})",
        if p.image_name.is_empty() {
            "<unknown>"
        } else {
            &p.image_name
        },
        p.pid
    );
    println!(
        "  image path  : {}",
        if p.image_path.is_empty() {
            "<denied>"
        } else {
            &p.image_path
        }
    );
    println!(
        "  arch / wow  : {} {}",
        p.arch,
        if p.is_wow64 { "(WOW64)" } else { "" }
    );
    println!(
        "  account     : {}\\{} [{} integrity, elevated={}]",
        u.account_domain, u.account_name, u.integrity.name, u.elevation.is_elevated
    );
    println!("  session     : {} ({})", u.session.id, u.session.kind);
    println!(
        "  created     : {}",
        p.times.created_utc.clone().unwrap_or_else(|| "-".into())
    );
    println!(
        "  command line: {}",
        p.command_line.clone().unwrap_or_else(|| "-".into())
    );
    println!(
        "  parent      : {:?}",
        r.genealogy.parent.as_ref().map(|x| (x.pid, x.name.clone()))
    );
    println!(
        "  children    : {} direct / {} descendants",
        r.genealogy.children.len(),
        r.genealogy.descendants.len()
    );
    println!(
        "  network     : {} tcp / {} udp ({} established, {} listening)",
        r.network.tcp_count,
        r.network.udp_count,
        r.network.established_count,
        r.network.listening_count
    );
    println!("  modules     : {}", r.modules.count);
    println!(
        "  handles     : {} inspected ({} resolved)",
        r.handles.inspected,
        r.handles.items.len()
    );
    println!(
        "  registry    : {} keys held, {} autostart matches",
        r.registry.keys.len(),
        r.registry.autoruns.len()
    );
    println!(
        "  services    : {} registration(s)",
        r.services.services.len()
    );
    println!(
        "  SHA-256     : {}",
        if r.binary.sha256.is_empty() {
            "<unavailable>"
        } else {
            &r.binary.sha256
        }
    );
    println!(
        "  signature   : {} ({})",
        r.binary.signature.status, r.binary.signature.signer_subject
    );
    println!("  took        : {} ms", r.tool.duration_ms);
    println!(
        "  degraded    : {} section(s)",
        r.integrity.sections_degraded
    );
    for w in r.integrity.warnings.iter().take(8) {
        println!("    - {w}");
    }
    println!("  report seal : {seal}");
}

// ---------------------------------------------------------------------------
// pick / hash / verify / procs
// ---------------------------------------------------------------------------

fn run_pick(args: &[String]) -> ExitCode {
    match win::window::pick_blocking("interactive_pick", std::time::Duration::from_secs(120)) {
        Ok(Some(p)) => {
            let info = win::window::window_info(p.hwnd);
            if flag(args, "--json") {
                let v = serde_json::json!({
                    "hwnd": format!("0x{:X}", p.hwnd),
                    "pid": p.pid,
                    "thread_id": p.thread_id,
                    "screen_x": p.screen_x,
                    "screen_y": p.screen_y,
                    "title": info.title,
                    "class_name": info.class_name,
                    "picked_at_utc": p.picked_at_utc,
                });
                println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            } else {
                println!(
                    "hwnd=0x{:X} pid={} title=\"{}\" class={}",
                    p.hwnd, p.pid, info.title, info.class_name
                );
            }
            ExitCode::SUCCESS
        }
        Ok(None) => {
            eprintln!("cancelled");
            ExitCode::from(2)
        }
        Err(e) => {
            eprintln!("picker error: {e}");
            ExitCode::from(2)
        }
    }
}

/// Re-renders an existing report (HTML exhibit and/or JSON).
///
/// Two real workflows depend on this: producing an exhibit after *redacting*
/// a report, and regenerating the HTML when the renderer improves without
/// re-acquiring the machine. `--reseal` recomputes the seal after edits, which
/// is why it is explicit - silently resealing would defeat the point of a seal.
fn run_render(args: &[String]) -> ExitCode {
    let Some(path) = args.first().filter(|a| !a.starts_with("--")) else {
        eprintln!("usage: lai render <report.json> [--html <path>] [--json <path>] [--reseal]");
        return ExitCode::from(1);
    };
    let text = match std::fs::read(path) {
        Ok(bytes) => {
            let bytes = if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
                bytes[3..].to_vec()
            } else {
                bytes
            };
            String::from_utf8_lossy(&bytes).into_owned()
        }
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let mut report: Report = match serde_json::from_str(&text) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("not a LiveAppInspector report: {e}");
            return ExitCode::from(2);
        }
    };
    let sealed_before = report.integrity.report_sha256.clone();

    if flag(args, "--reseal") {
        let seal = report::json::seal(&mut report);
        println!("resealed: {seal}");
        if !sealed_before.is_empty() && sealed_before != seal {
            println!("  previous seal: {sealed_before}");
            println!(
                "  NOTE: the report body changed after sealing; keep the original exhibit too"
            );
        }
    }

    let mut wrote = false;
    if let Some(out) = value(args, "--html") {
        match report::json::write_atomic(&out, &report::html::render(&report)) {
            Ok(()) => {
                println!("HTML exhibit: {out}");
                wrote = true;
            }
            Err(e) => eprintln!("could not write {out}: {e}"),
        }
    }
    if let Some(out) = value(args, "--json") {
        match report::json::write_atomic(&out, &report::json::to_pretty(&report)) {
            Ok(()) => {
                println!("JSON report : {out}");
                wrote = true;
            }
            Err(e) => eprintln!("could not write {out}: {e}"),
        }
    }
    if !wrote {
        eprintln!("nothing to do: pass --html <path> and/or --json <path>");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn run_hash(args: &[String]) -> ExitCode {
    let Some(path) = args.first().filter(|a| !a.starts_with("--")) else {
        eprintln!("usage: lai hash <path>");
        return ExitCode::from(1);
    };
    let started = std::time::Instant::now();
    let outcome = win::binary::hash_file(path);
    let identity = win::binary::file_identity(path);
    match outcome {
        Ok(h) => {
            let v = serde_json::json!({
                "path": path,
                "sha256": h.sha256,
                "bytes": h.bytes,
                "duration_ms": h.duration_ms,
                "hashed_at_utc": util::rfc3339_of(util::UnixTime::now()),
                "volume_serial": identity.as_ref().map(|i| i.volume_serial.clone()),
                "file_index": identity.as_ref().map(|i| i.file_index.clone()),
                "modified_utc": identity.as_ref().and_then(|i| util::rfc3339_of(i.modified)),
                "signature": win::binary::verify_signature(path),
            });
            if flag(args, "--json") {
                println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            } else {
                println!("SHA-256 {}", v["sha256"].as_str().unwrap_or(""));
                println!("  path     : {path}");
                println!("  bytes    : {}", h.bytes);
                println!("  took     : {:?}", started.elapsed());
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("hashing failed: {e}");
            ExitCode::from(if e.is_access_denied() { 3 } else { 2 })
        }
    }
}

fn run_verify(args: &[String]) -> ExitCode {
    let Some(path) = args.first().filter(|a| !a.starts_with("--")) else {
        eprintln!("usage: lai verify <report.json>");
        return ExitCode::from(1);
    };
    match report::json::verify_file(path) {
        Ok(v) => {
            println!("LiveAppInspector seal verification");
            println!("  report        : {path}");
            println!("  target        : {}", v.target);
            println!("  sealed at     : {}", v.sealed_at);
            println!("  embedded seal : {}", v.embedded);
            println!("  recomputed    : {}", v.computed);
            println!(
                "  VERDICT       : {}",
                if v.matches {
                    "MATCH - report is intact"
                } else {
                    "MISMATCH - report was modified after sealing"
                }
            );
            println!("  binary sha256 : {}", v.sha256_of_binary);
            println!(
                "  degraded      : {} section(s), {} custody events",
                v.sections_degraded, v.custody_events
            );
            if v.matches {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(2)
        }
    }
}

fn run_procs(args: &[String]) -> ExitCode {
    let limit = number(args, "--limit").unwrap_or(80) as usize;
    let rows = engine::live_process_map(limit);
    if flag(args, "--json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&rows).unwrap_or_default()
        );
        return ExitCode::SUCCESS;
    }
    println!(
        "{:>7}  {:>7}  {:>4}  {:>7}  NAME",
        "PID", "PPID", "THR", "SESSION"
    );
    for r in rows {
        println!(
            "{:>7}  {:>7}  {:>4}  {:>7}  {}",
            r["pid"],
            r["ppid"],
            r["threads"],
            r["session"],
            r["name"].as_str().unwrap_or("")
        );
    }
    ExitCode::SUCCESS
}

// Keep the WinError import meaningful for future structured exit codes.
#[allow(dead_code)]
fn exit_code_for(err: &WinError) -> u8 {
    if err.is_access_denied() {
        3
    } else {
        2
    }
}
