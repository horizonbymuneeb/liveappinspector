//! Loopback HTTP bridge + embedded dashboard.
//!
//! Security posture
//! ----------------
//! * Binds explicitly to `127.0.0.1` (never `0.0.0.0`), so the dashboard is not
//!   reachable from the network.
//! * Every `/api/*` call must carry the per-run session token, which is injected
//!   into the served HTML only. A token also expires with the process because it
//!   is generated from runtime entropy at startup.
//! * Request bodies are size-capped, paths are matched exactly (no filesystem
//!   access, no path traversal surface), and the served documents are embedded
//!   at compile time.
//! * The dashboard itself contains no remote resources: no CDN, no telemetry.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use sha2::{Digest, Sha256};

use crate::engine::{self, Options, Target};
use crate::model::Report;
use crate::report::{html, json as rjson};
use crate::util;
use crate::win::{sys, window};

const INDEX_HTML: &str = include_str!("../../ui/index.html");
const APP_JS: &str = include_str!("../../ui/app.js");
const STYLE_CSS: &str = include_str!("../../ui/style.css");

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

pub struct Config {
    pub port: u16,
    /// Filled by `serve()` once the socket is bound (a port of 0 binds an
    /// ephemeral port, which then has to be known for the elevate re-launch).
    pub port_final: u16,
    pub open_browser: bool,
    pub options: Options,
}

struct State {
    token: String,
    /// Bound port, recorded so the elevate re-launch can be reported to the UI.
    #[allow(dead_code)]
    port: u16,
    options: Mutex<Options>,
    last_report: Mutex<Option<Report>>,
    started: Instant,
}

pub fn serve(mut cfg: Config) -> Result<(), String> {
    let token = gen_token();
    let state = Arc::new(State {
        token: token.clone(),
        port: cfg.port_final,
        options: Mutex::new(cfg.options),
        last_report: Mutex::new(None),
        started: Instant::now(),
    });

    let listener = TcpListener::bind(("127.0.0.1", cfg.port))
        .map_err(|e| format!("cannot bind 127.0.0.1:{}: {e}", cfg.port))?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    cfg.port_final = addr.port();
    let url = format!("http://127.0.0.1:{}/", addr.port());

    // The hotkey listener is what makes "point-and-shoot" work while the
    // dashboard is in the background.
    window::start_hotkey_listener();

    println!(
        "LiveAppInspector engine {} listening on {url}",
        crate::model::TOOL_VERSION
    );
    println!("  session token: {token}");
    println!(
        "  elevation    : {}",
        if sys::is_elevated() {
            "elevated"
        } else {
            "standard user (protected processes will be denied)"
        }
    );
    println!("  hotkey       : Ctrl+Alt+F  (pick window, then Esc to cancel)");
    println!("  press Ctrl+C to stop");

    if cfg.open_browser {
        if sys::open_url(&url) {
            println!("  browser      : dashboard opened in your default browser");
        } else {
            println!("  browser      : could not launch a browser - open {url} manually");
        }
    }

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let st = Arc::clone(&state);
                std::thread::spawn(move || {
                    // A panicking handler must not take down the engine.
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        handle_connection(s, st)
                    }));
                });
            }
            Err(e) => eprintln!("accept failed: {e}"),
        }
    }
    Ok(())
}

fn gen_token() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id() as u128;
    let stack = &nanos as *const u128 as usize as u128;
    let mut hasher = Sha256::new();
    hasher.update(nanos.to_le_bytes());
    hasher.update(pid.to_le_bytes());
    hasher.update(stack.to_le_bytes());
    hasher.update(sys::current_exe());
    util::hex_lower(&hasher.finalize())[..32].to_string()
}

// ---------------------------------------------------------------------------
// Tiny HTTP plumbing
// ---------------------------------------------------------------------------

struct Request {
    method: String,
    path: String,
    query: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    fn param(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
    fn json(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(&self.body).ok()
    }
}

fn read_request(stream: &mut TcpStream) -> Option<Request> {
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(15)))
        .ok()?;
    let mut reader = BufReader::new(stream.try_clone().ok()?);

    let mut line = String::new();
    if reader.read_line(&mut line).ok()? == 0 {
        return None;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let raw_target = parts.next()?.to_string();
    let (path, query) = match raw_target.split_once('?') {
        Some((p, q)) => (p.to_string(), parse_query(q)),
        None => (raw_target, Vec::new()),
    };

    let mut headers = Vec::new();
    let mut consumed = line.len();
    loop {
        let mut h = String::new();
        let n = reader.read_line(&mut h).ok()?;
        if n == 0 {
            break;
        }
        consumed += n;
        if consumed > MAX_HEADER_BYTES {
            return None;
        }
        let trimmed = h.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    let len: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0)
        .min(MAX_BODY_BYTES);
    let mut body = vec![0u8; len];
    if len > 0 && reader.read_exact(&mut body).is_err() {
        return None;
    }

    Some(Request {
        method,
        path,
        query,
        headers,
        body,
    })
}

fn parse_query(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|s| !s.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (url_decode(k), url_decode(v)),
            None => (url_decode(pair), String::new()),
        })
        .collect()
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn respond(stream: &mut TcpStream, status: u16, ctype: &str, body: &[u8], extra: &[(&str, &str)]) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n",
        body.len()
    );
    for (k, v) in extra {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

fn json_response(stream: &mut TcpStream, value: &serde_json::Value) {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    respond(stream, 200, "application/json; charset=utf-8", &body, &[]);
}

fn err_response(stream: &mut TcpStream, _status: u16, msg: &str) {
    let body = serde_json::json!({ "ok": false, "error": msg });
    respond(
        stream,
        200,
        "application/json; charset=utf-8",
        serde_json::to_string(&body).unwrap_or_default().as_bytes(),
        &[],
    );
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

fn handle_connection(mut stream: TcpStream, state: Arc<State>) {
    let req = match read_request(&mut stream) {
        Some(r) => r,
        None => return,
    };

    // --- static assets (no token: they contain no data, and the token is
    // injected into the HTML document itself) ---
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") | ("GET", "/index.html") => {
            let html = INDEX_HTML.replace("__LAI_TOKEN__", &state.token);
            respond(&mut stream, 200, "text/html; charset=utf-8", html.as_bytes(), &[
                // Strict CSP: scripts only from this origin (the token arrives as
                // inert JSON), styles may be inline because the dashboard sets
                // per-element style attributes, and nothing may frame or post out.
                (
                    "Content-Security-Policy",
                    "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
                ),
            ]);
            return;
        }
        ("GET", "/app.js") => {
            respond(
                &mut stream,
                200,
                "application/javascript; charset=utf-8",
                APP_JS.as_bytes(),
                &[],
            );
            return;
        }
        ("GET", "/style.css") => {
            respond(
                &mut stream,
                200,
                "text/css; charset=utf-8",
                STYLE_CSS.as_bytes(),
                &[],
            );
            return;
        }
        ("GET", "/favicon.ico") => {
            respond(&mut stream, 200, "image/svg+xml", FAVICON.as_bytes(), &[]);
            return;
        }
        _ => {}
    }

    if !req.path.starts_with("/api/") {
        respond(
            &mut stream,
            404,
            "text/plain; charset=utf-8",
            b"not found",
            &[],
        );
        return;
    }

    // --- token gate ---
    let supplied = req
        .header("x-lai-token")
        .map(|s| s.to_string())
        .or_else(|| req.param("t").map(|s| s.to_string()))
        .unwrap_or_default();
    if supplied != state.token {
        respond(
            &mut stream,
            401,
            "application/json; charset=utf-8",
            br#"{"ok":false,"error":"invalid session token"}"#,
            &[],
        );
        return;
    }

    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/api/status") => {
            let (user, domain, elevated) = crate::win::token::self_account();
            let (inner, outer, _) = (sys::os_info(), sys::host_info(), 0);
            json_response(
                &mut stream,
                &serde_json::json!({
                    "ok": true,
                    "tool": crate::model::TOOL_NAME,
                    "version": crate::model::TOOL_VERSION,
                    "schema": crate::model::SCHEMA_VERSION,
                    "engine_elevated": elevated,
                    "debug_privilege": crate::win::token::self_has_enabled_privilege("SeDebugPrivilege"),
                    "account": format!("{domain}\\{user}"),
                    "host": outer.computer_name,
                    "os": format!("{} {}", inner.product_name, inner.version),
                    "arch": sys::native_arch(),
                    "uptime_seconds": state.started.elapsed().as_secs(),
                    "hotkey": "Ctrl+Alt+F",
                    "hotkey_listener": window::peek_hotkey_active(),
                }),
            );
        }
        ("POST", "/api/pick") => {
            let timeout = req
                .json()
                .and_then(|v| v.get("timeout_secs").and_then(|t| t.as_u64()))
                .unwrap_or(90)
                .clamp(5, 300);
            match window::pick_blocking("interactive_pick", std::time::Duration::from_secs(timeout))
            {
                Ok(Some(pick)) => {
                    let target = Target::from_pick(&pick);
                    let report = run_inspection(&state, &target);
                    json_response(
                        &mut stream,
                        &serde_json::json!({
                            "ok": true,
                            "target": {
                                "pid": pick.pid,
                                "hwnd": format!("0x{:X}", pick.hwnd),
                                "screen_x": pick.screen_x,
                                "screen_y": pick.screen_y,
                                "via": pick.via,
                            },
                            "report": report,
                        }),
                    );
                }
                Ok(None) => err_response(&mut stream, 200, "pick cancelled or timed out"),
                Err(e) => err_response(&mut stream, 200, &format!("picker error: {e}")),
            }
        }
        ("GET", "/api/hotkey_pick") => match window::take_hotkey_pick() {
            Some(pick) => {
                let target = Target::from_pick(&pick);
                let report = run_inspection(&state, &target);
                json_response(
                    &mut stream,
                    &serde_json::json!({
                        "ok": true,
                        "pending": false,
                        "target": {
                            "pid": pick.pid,
                            "hwnd": format!("0x{:X}", pick.hwnd),
                            "via": pick.via,
                        },
                        "report": report,
                    }),
                );
            }
            None => json_response(
                &mut stream,
                &serde_json::json!({ "ok": true, "pending": true }),
            ),
        },
        ("POST", "/api/inspect") => {
            let body = req.json().unwrap_or_default();
            if let Some(pid) = body.get("pid").and_then(|v| v.as_u64()) {
                let pid = pid as u32;
                if body
                    .get("resolve_dns")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                {
                    if let Ok(mut o) = state.options.lock() {
                        o.resolve_dns = true;
                    }
                }
                let report = run_inspection(&state, &Target::from_pid(pid));
                json_response(
                    &mut stream,
                    &serde_json::json!({ "ok": true, "report": report }),
                );
            } else if let Some(hwnd) = body.get("hwnd").and_then(|v| v.as_str()) {
                let h =
                    usize::from_str_radix(hwnd.trim_start_matches("0x"), 16).unwrap_or(0) as isize;
                if h == 0 {
                    err_response(&mut stream, 200, "invalid hwnd");
                    return;
                }
                let mut pid = 0u32;
                unsafe { crate::win::ffi::GetWindowThreadProcessId(h, &mut pid) };
                let mut t = Target::from_pid(pid);
                t.mode = "explicit_hwnd".into();
                t.hwnd = h;
                let report = run_inspection(&state, &t);
                json_response(
                    &mut stream,
                    &serde_json::json!({ "ok": true, "report": report }),
                );
            } else {
                err_response(&mut stream, 200, "body must contain pid or hwnd");
            }
        }
        ("GET", "/api/processes") => {
            let limit = req
                .param("limit")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(600);
            json_response(
                &mut stream,
                &serde_json::json!({ "ok": true, "processes": engine::live_process_map(limit) }),
            );
        }
        ("GET", "/api/export/json") => {
            match state.last_report.lock().ok().and_then(|g| g.clone()) {
                Some(report) => {
                    let body = rjson::to_pretty(&report);
                    respond(
                        &mut stream,
                        200,
                        "application/json; charset=utf-8",
                        body.as_bytes(),
                        &[(
                            "Content-Disposition",
                            &format!("attachment; filename=\"{}\"", export_name(&report, "json")),
                        )],
                    );
                }
                None => err_response(&mut stream, 200, "no report captured yet"),
            }
        }
        ("GET", "/api/export/html") => {
            match state.last_report.lock().ok().and_then(|g| g.clone()) {
                Some(report) => {
                    let body = html::render(&report);
                    respond(
                        &mut stream,
                        200,
                        "text/html; charset=utf-8",
                        body.as_bytes(),
                        &[(
                            "Content-Disposition",
                            &format!("attachment; filename=\"{}\"", export_name(&report, "html")),
                        )],
                    );
                }
                None => err_response(&mut stream, 200, "no report captured yet"),
            }
        }
        ("POST", "/api/elevate") => {
            // Re-launch the engine elevated on a fresh ephemeral port; the UI is
            // told the new URL so the operator lands on an admin-privileged
            // dashboard instead of a dead tab.
            let args = vec!["serve".to_string(), "--open".to_string()];
            match sys::relaunch_elevated(&args) {
                Ok(true) => json_response(
                    &mut stream,
                    &serde_json::json!({
                        "ok": true,
                        "message": "elevated engine launched - a UAC prompt was shown and a new dashboard tab will open",
                    }),
                ),
                Ok(false) => {
                    err_response(&mut stream, 200, "elevation was declined by the operator")
                }
                Err(e) => err_response(&mut stream, 200, &format!("elevation failed: {e}")),
            }
        }
        ("POST", "/api/shutdown") => {
            json_response(
                &mut stream,
                &serde_json::json!({ "ok": true, "message": "shutting down" }),
            );
            std::thread::spawn(|| {
                std::thread::sleep(std::time::Duration::from_millis(120));
                std::process::exit(0);
            });
        }
        _ => respond(
            &mut stream,
            404,
            "application/json; charset=utf-8",
            br#"{"ok":false,"error":"unknown endpoint"}"#,
            &[],
        ),
    }
}

fn export_name(report: &Report, ext: &str) -> String {
    let stamp = report
        .integrity
        .sealed_at_utc
        .replace([':', '-'], "")
        .replace('T', "-")
        .split('.')
        .next()
        .unwrap_or("report")
        .to_string();
    let img = if report.process.image_name.is_empty() {
        "unknown".to_string()
    } else {
        report
            .process
            .image_name
            .replace(|c: char| !c.is_alphanumeric() && c != '.', "_")
    };
    format!("LAI-{stamp}-{img}-pid{}.{ext}", report.process.pid)
}

fn run_inspection(state: &Arc<State>, target: &Target) -> serde_json::Value {
    let opts = state.options.lock().map(|o| o.clone()).unwrap_or_default();
    let mut report = engine::inspect(target, &opts);
    rjson::seal(&mut report);
    if let Ok(mut slot) = state.last_report.lock() {
        *slot = Some(report.clone());
    }
    serde_json::to_value(&report).unwrap_or_else(|_| serde_json::json!({}))
}

const FAVICON: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="8" fill="#12203a"/><circle cx="16" cy="16" r="7" fill="none" stroke="#4da3ff" stroke-width="2"/><path d="M16 3v6M16 23v6M3 16h6M23 16h6" stroke="#33d69f" stroke-width="2"/></svg>"##;
