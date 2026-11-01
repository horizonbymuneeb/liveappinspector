//! Self-contained dark-theme HTML exhibit renderer.
//!
//! Constraints that shaped this renderer:
//!  * **Single file.** No external CSS/JS/fonts, so the exhibit survives being
//!    copied to a USB stick or attached to a court filing and still renders.
//!  * **No active content.** No <script>, no remote references: the HTML is a
//!    static document, so it is safe to open on a forensic workstation.
//!  * **Escaped.** Every collected value passes through `html_escape`, because
//!    process/window/file names are attacker-controlled strings.

use crate::model::*;
use crate::util::{html_escape as esc, human_bytes};

const MAX_ROWS: usize = 1500;

pub fn render(report: &Report) -> String {
    let mut h = String::with_capacity(64 * 1024);
    head(&mut h, report);
    summary(&mut h, report);
    process_section(&mut h, report);
    user_section(&mut h, report);
    genealogy_section(&mut h, report);
    network_section(&mut h, report);
    modules_section(&mut h, report);
    handles_section(&mut h, report);
    registry_section(&mut h, report);
    services_section(&mut h, report);
    memory_section(&mut h, report);
    binary_section(&mut h, report);
    integrity_section(&mut h, report);
    tail(&mut h, report);
    h
}

// ---------------------------------------------------------------------------
// Building blocks
// ---------------------------------------------------------------------------

fn head(h: &mut String, r: &Report) {
    let target = if r.process.image_name.is_empty() {
        "<em>unknown target</em>".to_string()
    } else {
        esc(&r.process.image_name)
    };
    h.push_str(&format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LiveAppInspector report - {target} (pid {pid})</title>
<style>{css}</style>
</head><body>
<header>
  <div class="brand">
    <div class="logo">LAI</div>
    <div>
      <h1>Live Application Forensic Report</h1>
      <p class="sub">{tool} v{ver} &middot; schema {schema}</p>
    </div>
  </div>
  <div class="headmeta">
    <div><span>Target</span><strong>{target}</strong></div>
    <div><span>PID</span><strong>{pid}</strong></div>
    <div><span>Host</span><strong>{host}</strong></div>
    <div><span>Sealed (UTC)</span><strong>{sealed}</strong></div>
  </div>
</header>
<main>
"#,
        target = target,
        pid = r.process.pid,
        tool = esc(&r.tool.name),
        ver = esc(&r.tool.version),
        schema = esc(&r.schema),
        host = esc(&r.tool.host.computer_name),
        sealed = esc(if r.integrity.sealed_at_utc.is_empty() {
            &r.tool.completed_at_utc
        } else {
            &r.integrity.sealed_at_utc
        }),
        css = CSS,
    ));
}

fn tail(h: &mut String, r: &Report) {
    h.push_str(&format!(
        r#"</main>
<footer>
  <span>{tool} v{ver}</span>
  <span>report SHA-256: <code>{seal}</code></span>
  <span>generated {ts}</span>
</footer>
</body></html>"#,
        tool = esc(&r.tool.name),
        ver = esc(&r.tool.version),
        seal = esc(&r.integrity.report_sha256),
        ts = esc(&r.tool.completed_at_utc),
    ));
}

fn badge(status: Status) -> String {
    format!(
        r#"<span class="badge b-{cls}">{label}</span>"#,
        cls = status.as_str(),
        label = status.as_str().to_uppercase()
    )
}

fn section(h: &mut String, id: &str, title: &str, meta: &SectionMeta) -> bool {
    h.push_str(&format!(
        r#"<section id="{id}"><h2>{title} {badge}</h2>"#,
        id = id,
        title = esc(title),
        badge = badge(meta.status)
    ));
    if let Some(err) = &meta.error {
        h.push_str(&format!(r#"<p class="alert">{}</p>"#, esc(err)));
    }
    for w in &meta.warnings {
        h.push_str(&format!(r#"<p class="note">{}</p>"#, esc(w)));
    }
    true
}

fn end_section(h: &mut String) {
    h.push_str("</section>\n");
}

fn kv(h: &mut String, rows: &[(&str, String)]) {
    h.push_str(r#"<div class="kv">"#);
    for (k, v) in rows {
        let value = if v.is_empty() {
            r#"<span class="muted">-</span>"#.to_string()
        } else {
            esc(v)
        };
        h.push_str(&format!(
            r#"<div class="kvrow"><div class="k">{}</div><div class="v">{}</div></div>"#,
            esc(k),
            value
        ));
    }
    h.push_str("</div>");
}

fn table(h: &mut String, headers: &[&str], rows: Vec<Vec<String>>, truncated: usize) {
    h.push_str("<div class=\"tablewrap\"><table><thead><tr>");
    for th in headers {
        h.push_str(&format!("<th>{}</th>", esc(th)));
    }
    h.push_str("</tr></thead><tbody>");
    let mut shown = 0usize;
    for row in &rows {
        if shown >= MAX_ROWS {
            break;
        }
        h.push_str("<tr>");
        for (i, cell) in row.iter().enumerate() {
            let cls = if i == 0 { " class=\"mono\"" } else { "" };
            if cell.is_empty() {
                h.push_str(&format!("<td{cls}><span class=\"muted\">-</span></td>"));
            } else {
                h.push_str(&format!("<td{cls}>{}</td>", esc(cell)));
            }
        }
        h.push_str("</tr>");
        shown += 1;
    }
    h.push_str("</tbody></table></div>");
    if rows.len() > shown || truncated > 0 {
        h.push_str(&format!(
            r#"<p class="note">Showing {shown} of {total} rows{extra}. The complete set is in the JSON exhibit.</p>"#,
            shown = shown,
            total = rows.len(),
            extra = if truncated > 0 {
                format!(" ({truncated} additional rows were truncated at collection time)")
            } else {
                String::new()
            }
        ));
    }
}

fn opt(v: &Option<String>) -> String {
    v.clone().unwrap_or_default()
}

fn yesno(b: bool) -> String {
    if b {
        "yes".into()
    } else {
        "no".into()
    }
}

// ---------------------------------------------------------------------------
// Sections
// ---------------------------------------------------------------------------

fn summary(h: &mut String, r: &Report) {
    let degraded = r.integrity.sections_degraded;
    let verdict = if degraded == 0 {
        r#"<span class="pill ok">Complete acquisition</span>"#.to_string()
    } else {
        format!(r#"<span class="pill warn">{degraded} section(s) degraded</span>"#)
    };
    h.push_str(&format!(
        r#"<section class="hero">
  <div class="cards">
    <div class="card"><div class="cardlabel">Image</div><div class="cardvalue">{img}</div>
      <div class="cardsub mono">{path}</div></div>
    <div class="card"><div class="cardlabel">SHA-256</div><div class="cardvalue mono small">{sha}</div>
      <div class="cardsub">{size} &middot; signed: {sig}</div></div>
    <div class="card"><div class="cardlabel">Context</div><div class="cardvalue">{acct}</div>
      <div class="cardsub">{integrity} integrity &middot; session {session} ({kind})</div></div>
    <div class="card"><div class="cardlabel">Runtime</div><div class="cardvalue">{started}</div>
      <div class="cardsub">{elapsed} &middot; {threads} threads &middot; {handles} handles</div></div>
  </div>
  <div class="verdict">{verdict} <span class="muted">acquisition took {dur} ms</span></div>
</section>
"#,
        img = esc(if r.process.image_name.is_empty() {
            "<unknown>"
        } else {
            &r.process.image_name
        }),
        path = esc(&r.binary.path),
        sha = esc(&r.binary.sha256),
        size = esc(&human_bytes(r.binary.size_bytes)),
        sig = esc(&r.binary.signature.status),
        acct = esc(&format!(
            "{}\\{}",
            r.user_context.account_domain, r.user_context.account_name
        )),
        integrity = esc(&r.user_context.integrity.name),
        session = r.process.session_id,
        kind = esc(&r.user_context.session.kind),
        started = esc(&opt(&r.process.times.created_utc)),
        elapsed = esc(&human_duration(r.process.times.elapsed_ms)),
        threads = r.process.thread_count,
        handles = r.process.handle_count,
        verdict = verdict,
        dur = r.tool.duration_ms,
    ));
}

fn human_duration(ms: u64) -> String {
    let s = ms / 1000;
    if s < 90 {
        format!("{s}s uptime")
    } else if s < 5400 {
        format!("{}m {}s uptime", s / 60, s % 60)
    } else if s < 172_800 {
        format!("{}h {}m uptime", s / 3600, (s % 3600) / 60)
    } else {
        format!("{}d {}h uptime", s / 86_400, (s % 86_400) / 3600)
    }
}

fn process_section(h: &mut String, r: &Report) {
    let p = &r.process;
    section(h, "process", "Process identity & window", &p.meta);
    kv(
        h,
        &[
            ("PID", p.pid.to_string()),
            ("Parent PID", p.parent_pid.to_string()),
            ("Image", p.image_name.clone()),
            ("Image path", p.image_path.clone()),
            (
                "Architecture",
                format!("{}{}", p.arch, if p.is_wow64 { " (WOW64)" } else { "" }),
            ),
            (
                "Session id",
                format!("{} ({})", p.session_id, r.user_context.session.kind),
            ),
            (
                "Protection",
                format!(
                    "{}{}",
                    p.protection_level,
                    if p.protection_signer.is_empty() {
                        String::new()
                    } else {
                        format!(" / signer: {}", p.protection_signer)
                    }
                ),
            ),
            ("Command line", opt(&p.command_line)),
            ("Command line source", p.command_line_source.clone()),
            ("Working directory", opt(&p.current_directory)),
            ("DLL path", opt(&p.dll_path)),
            ("Created (UTC)", opt(&p.times.created_utc)),
            ("Elapsed", human_duration(p.times.elapsed_ms)),
            (
                "Kernel / user time",
                format!(
                    "{} ms / {} ms",
                    p.times.kernel_time_ms, p.times.user_time_ms
                ),
            ),
            (
                "Threads / handles",
                format!("{} / {}", p.thread_count, p.handle_count),
            ),
            ("Working set", human_bytes(p.memory.working_set_bytes)),
            ("Pagefile usage", human_bytes(p.memory.pagefile_usage_bytes)),
            ("Priority class", p.priority_class.clone()),
        ],
    );

    let w = &r.selection.window;
    if !w.class_name.is_empty() || !w.title.is_empty() {
        h.push_str("<h3>Selected window</h3>");
        kv(
            h,
            &[
                ("Selection mode", r.selection.mode.clone()),
                ("Picked (UTC)", r.selection.picked_at_utc.clone()),
                ("HWND", r.selection.hwnd.clone()),
                ("Title", w.title.clone()),
                ("Class", w.class_name.clone()),
                ("Thread id", w.thread_id.to_string()),
                (
                    "Rect",
                    format!(
                        "{},{} {}x{}",
                        w.rect.left, w.rect.top, w.rect.width, w.rect.height
                    ),
                ),
                ("DPI", w.dpi.to_string()),
                ("Visible", yesno(w.is_visible)),
                ("Cloaked (UWP)", yesno(w.is_cloaked)),
                (
                    "Style / exstyle",
                    format!("{} / {}", w.style_hex, w.ex_style_hex),
                ),
            ],
        );
    }

    if !p.environment.is_empty() {
        h.push_str(&format!(
            "<h3>Process environment ({} entries, source: {})</h3><pre class=\"raw\">{}</pre>",
            p.environment.len(),
            esc(&p.environment_source),
            esc(&p.environment.join("\n"))
        ));
    }
    end_section(h);
}

fn user_section(h: &mut String, r: &Report) {
    let u = &r.user_context;
    section(h, "identity", "User, token & session context", &u.meta);
    kv(
        h,
        &[
            (
                "Account",
                format!("{}\\{}", u.account_domain, u.account_name),
            ),
            ("SID", u.sid.clone()),
            ("Account type", u.account_type.clone()),
            ("Verdict", u.elevation.verdict.clone()),
            ("Elevated", yesno(u.elevation.is_elevated)),
            ("Elevation type", u.elevation.elevation_type.clone()),
            (
                "Integrity level",
                format!("{} (0x{:x})", u.integrity.name, u.integrity.rid),
            ),
            (
                "Session",
                format!(
                    "{} / {} / client {} {}",
                    u.session.id, u.session.kind, u.session.client_name, u.session.client_address
                ),
            ),
            (
                "Session user",
                format!("{}\\{}", u.session.domain, u.session.username),
            ),
            ("Token id", u.token.token_id.clone()),
            (
                "Authentication id (logon session)",
                u.token.authentication_id.clone(),
            ),
            (
                "Token type / impersonation",
                format!("{} / {}", u.token.token_type, u.token.impersonation_level),
            ),
            ("Owner SID", u.token.owner_sid.clone()),
            ("AppContainer", yesno(u.token.is_app_container)),
            (
                "Virtualization enabled",
                yesno(u.token.virtualization_enabled),
            ),
        ],
    );

    if !u.privileges.is_empty() {
        h.push_str("<h3>Token privileges</h3>");
        table(
            h,
            &["Privilege", "Enabled", "Default", "Removed", "Used"],
            u.privileges
                .iter()
                .map(|p| {
                    vec![
                        p.name.clone(),
                        yesno(p.enabled),
                        yesno(p.enabled_by_default),
                        yesno(p.removed),
                        yesno(p.used_for_access),
                    ]
                })
                .collect(),
            0,
        );
    }
    if !u.groups.is_empty() {
        h.push_str("<h3>Token groups</h3>");
        table(
            h,
            &["SID", "Name", "Domain", "Enabled", "Integrity", "Logon SID"],
            u.groups
                .iter()
                .map(|g| {
                    vec![
                        g.sid.clone(),
                        g.name.clone(),
                        g.domain.clone(),
                        yesno(g.enabled),
                        yesno(g.integrity),
                        yesno(g.logon_id),
                    ]
                })
                .collect(),
            0,
        );
    }
    end_section(h);
}

fn genealogy_section(h: &mut String, r: &Report) {
    let g = &r.genealogy;
    section(h, "genealogy", "Process tree & genealogy", &g.meta);
    h.push_str("<h3>Ancestry</h3><pre class=\"tree\">");
    for a in g.ancestors.iter().rev() {
        h.push_str(&format!(
            "{}{} <span class=\"muted\">(pid {}{})</span>\n",
            "  ".repeat(a.depth as usize),
            esc(if a.name.is_empty() {
                "<exited / unknown>"
            } else {
                &a.name
            }),
            a.pid,
            if a.is_alive { "" } else { ", exited" }
        ));
    }
    h.push_str(&format!(
        "{}<strong>{} (pid {})</strong>  &lt;- target\n",
        "  ".repeat((g.ancestors.len() + 1).min(12)),
        esc(if r.process.image_name.is_empty() {
            "<unknown>"
        } else {
            &r.process.image_name
        }),
        r.process.pid
    ));
    h.push_str("</pre>");

    if let Some(p) = &g.parent {
        h.push_str("<h3>Parent</h3>");
        kv(
            h,
            &[
                ("PID", p.pid.to_string()),
                ("Name", p.name.clone()),
                ("Image path", opt(&p.image_path)),
                ("Created (UTC)", opt(&p.created_utc)),
                ("Alive at collection", yesno(p.is_alive)),
            ],
        );
    }
    if !g.children.is_empty() {
        h.push_str("<h3>Children</h3>");
        table(
            h,
            &["PID", "Name", "Path", "Created (UTC)"],
            g.children
                .iter()
                .map(|c| {
                    vec![
                        c.pid.to_string(),
                        c.name.clone(),
                        opt(&c.image_path),
                        opt(&c.created_utc),
                    ]
                })
                .collect(),
            0,
        );
    }
    if !g.descendants.is_empty() {
        h.push_str("<h3>Descendants</h3>");
        table(
            h,
            &["PID", "Depth", "Name", "Path"],
            g.descendants
                .iter()
                .map(|c| {
                    vec![
                        c.pid.to_string(),
                        c.depth.to_string(),
                        c.name.clone(),
                        opt(&c.image_path),
                    ]
                })
                .collect(),
            0,
        );
    }
    end_section(h);
}

fn network_section(h: &mut String, r: &Report) {
    let n = &r.network;
    section(h, "network", "Network connections", &n.meta);
    kv(
        h,
        &[
            ("TCP endpoints", n.tcp_count.to_string()),
            ("UDP endpoints", n.udp_count.to_string()),
            ("Established", n.established_count.to_string()),
            ("Listening", n.listening_count.to_string()),
            (
                "Unique remote endpoints",
                n.unique_remote_endpoints.to_string(),
            ),
            ("Reverse DNS", yesno(n.resolve_dns)),
        ],
    );
    if !n.connections.is_empty() {
        table(
            h,
            &[
                "Proto",
                "Local",
                "Local port",
                "Remote",
                "Remote port",
                "State",
                "Remote host",
            ],
            n.connections
                .iter()
                .map(|c| {
                    vec![
                        c.protocol.clone(),
                        c.local_address.clone(),
                        c.local_port.to_string(),
                        c.remote_address.clone(),
                        if c.remote_port == 0 {
                            String::new()
                        } else {
                            c.remote_port.to_string()
                        },
                        c.state.clone(),
                        opt(&c.remote_hostname),
                    ]
                })
                .collect(),
            0,
        );
    }
    end_section(h);
}

fn modules_section(h: &mut String, r: &Report) {
    let m = &r.modules;
    section(h, "modules", "Loaded modules / DLLs", &m.meta);
    kv(
        h,
        &[
            ("Module count", m.count.to_string()),
            (
                "Unsigned / unversioned",
                m.items
                    .iter()
                    .filter(|i| i.company.is_empty())
                    .count()
                    .to_string(),
            ),
            (
                "Missing on disk",
                m.items
                    .iter()
                    .filter(|i| i.missing_on_disk)
                    .count()
                    .to_string(),
            ),
        ],
    );
    table(
        h,
        &[
            "Module",
            "Base address",
            "Size",
            "Version",
            "Company",
            "Path",
            "On disk modified (UTC)",
        ],
        m.items
            .iter()
            .map(|i| {
                vec![
                    i.name.clone(),
                    i.base_address.clone(),
                    human_bytes(i.size_bytes),
                    i.file_version.clone(),
                    i.company.clone(),
                    i.path.clone(),
                    opt(&i.on_disk_modified_utc),
                ]
            })
            .collect(),
        0,
    );
    end_section(h);
}

fn handles_section(h: &mut String, r: &Report) {
    let hl = &r.handles;
    section(h, "handles", "Open handles & loaded objects", &hl.meta);
    kv(
        h,
        &[
            ("Handles in process", hl.inspected.to_string()),
            ("Handles inspected", hl.items.len().to_string()),
            ("Truncated", yesno(hl.truncated)),
            ("Cap", hl.limit.to_string()),
            (
                "Object types",
                hl.counts_by_type
                    .iter()
                    .map(|t| format!("{}: {}", t.type_name, t.count))
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
        ],
    );
    let rows: Vec<Vec<String>> = hl
        .items
        .iter()
        .map(|i| {
            vec![
                i.handle.clone(),
                i.type_name.clone(),
                i.classifier.clone(),
                i.object_name.clone().unwrap_or_default(),
                i.granted_access.clone(),
                i.note.clone().unwrap_or_default(),
            ]
        })
        .collect();
    table(
        h,
        &["Handle", "Type", "Class", "Object name", "Access", "Note"],
        rows,
        if hl.truncated {
            hl.inspected.saturating_sub(hl.items.len() as u32) as usize
        } else {
            0
        },
    );
    end_section(h);
}

fn registry_section(h: &mut String, r: &Report) {
    let g = &r.registry;
    section(h, "registry", "Registry artifacts & persistence", &g.meta);
    if g.autoruns.is_empty() {
        h.push_str(r#"<p class="note">No autostart entry references this image (Run/RunOnce/RunServices/Winlogon checked).</p>"#);
    } else {
        h.push_str("<h3>Autostart entries referencing this image</h3>");
        table(
            h,
            &["Hive", "Key", "Value", "Command"],
            g.autoruns
                .iter()
                .map(|a| {
                    vec![
                        a.hive.clone(),
                        a.key.clone(),
                        a.value_name.clone(),
                        a.command.clone(),
                    ]
                })
                .collect(),
            0,
        );
    }
    for n in &g.autorun_scan_notes {
        h.push_str(&format!(r#"<p class="note">{}</p>"#, esc(n)));
    }
    if !g.keys.is_empty() {
        h.push_str(&format!(
            "<h3>Registry keys held open by the process ({})</h3>",
            g.keys.len()
        ));
        table(
            h,
            &["Key path", "Handle", "Access"],
            g.keys
                .iter()
                .map(|k| vec![k.path.clone(), k.handle.clone(), k.granted_access.clone()])
                .collect(),
            0,
        );
    }
    end_section(h);
}

fn services_section(h: &mut String, r: &Report) {
    let s = &r.services;
    section(h, "services", "Service registrations", &s.meta);
    if s.services.is_empty() {
        h.push_str(
            r#"<p class="note">This image is not registered with the Service Control Manager.</p>"#,
        );
    } else {
        table(
            h,
            &[
                "Service",
                "Display name",
                "State",
                "Start",
                "Account",
                "Binary path",
            ],
            s.services
                .iter()
                .map(|x| {
                    vec![
                        x.name.clone(),
                        x.display_name.clone(),
                        x.state.clone(),
                        x.start_type.clone(),
                        x.account.clone(),
                        x.binary_path.clone(),
                    ]
                })
                .collect(),
            0,
        );
    }
    end_section(h);
}

fn memory_section(h: &mut String, r: &Report) {
    let m = &r.memory;
    section(h, "memory", "Address space & memory anomalies", &m.meta);
    kv(
        h,
        &[
            ("Regions scanned", m.regions_scanned.to_string()),
            ("Committed regions", m.committed_regions.to_string()),
            ("Committed bytes", human_bytes(m.committed_bytes)),
            ("Image-backed", human_bytes(m.image_bytes)),
            ("File-mapped", human_bytes(m.mapped_bytes)),
            ("Private", human_bytes(m.private_bytes)),
            (
                "Executable regions",
                format!(
                    "{} ({})",
                    m.executable_regions,
                    human_bytes(m.executable_bytes)
                ),
            ),
            (
                "Executable private",
                format!(
                    "{} ({})",
                    m.private_executable_regions,
                    human_bytes(m.private_executable_bytes)
                ),
            ),
            (
                "Writable + executable",
                format!(
                    "{} ({})",
                    m.writable_executable_regions,
                    human_bytes(m.writable_executable_bytes)
                ),
            ),
        ],
    );
    h.push_str(r#"<p class="note">Private executable memory is not backed by any image on disk. It is legitimate for CLR/JIT, browser, Go and Java runtimes, and an indicator worth correlating elsewhere (unsigned modules, network activity, thread start addresses). This table records facts, not a verdict.</p>"#);
    if !m.anomalies.is_empty() {
        h.push_str(&format!(
            "<h3>Anomalous regions ({} largest of {})</h3>",
            m.anomalies_shown,
            m.anomalies.len().max(m.anomalies_shown as usize)
        ));
        table(
            h,
            &["Base address", "Size", "Protection", "Type", "Note"],
            m.anomalies
                .iter()
                .map(|a| {
                    vec![
                        a.base_address.clone(),
                        human_bytes(a.size_bytes),
                        a.protection.clone(),
                        a.region_type.clone(),
                        a.note.clone(),
                    ]
                })
                .collect(),
            0,
        );
    }
    end_section(h);
}

fn binary_section(h: &mut String, r: &Report) {
    let b = &r.binary;
    section(h, "binary", "Binary integrity & chain of custody", &b.meta);
    kv(
        h,
        &[
            ("Path", b.path.clone()),
            ("SHA-256", b.sha256.clone()),
            ("Algorithm", b.hash_algorithm.clone()),
            ("Hashed at (UTC)", b.hashed_at_utc.clone()),
            (
                "Bytes streamed",
                format!("{} ({} ms)", b.bytes_read, b.hash_duration_ms),
            ),
            ("Size", human_bytes(b.size_bytes)),
            ("NTFS volume serial", b.volume_serial.clone()),
            ("NTFS file index", b.file_index.clone()),
            ("Attributes", b.file_attributes.clone()),
            ("Hard links", b.hard_link_count.to_string()),
            ("Created (UTC)", opt(&b.created_utc)),
            ("Modified (UTC)", opt(&b.modified_utc)),
            ("Accessed (UTC)", opt(&b.accessed_utc)),
        ],
    );

    h.push_str("<h3>PE header</h3>");
    kv(
        h,
        &[
            ("Machine", b.pe.machine.clone()),
            ("Subsystem", b.pe.subsystem.clone()),
            ("Linker", b.pe.linker_version.clone()),
            ("Compile timestamp (UTC)", opt(&b.pe.compile_timestamp_utc)),
            ("Mitigations", b.pe.characteristics.clone()),
            (".NET assembly", yesno(b.pe.is_dotnet)),
            ("PE note", b.pe.note.clone()),
        ],
    );

    h.push_str("<h3>Authenticode</h3>");
    kv(
        h,
        &[
            ("Status", b.signature.status.clone()),
            ("Signature source", b.signature.signature_source.clone()),
            ("Trust result", b.signature.trust_status_hex.clone()),
            ("Detail", b.signature.message.clone()),
            ("Signer", b.signature.signer_subject.clone()),
            ("Issuer", b.signature.signer_issuer.clone()),
            (
                "Certificates in store",
                b.signature.certificates_in_store.to_string(),
            ),
            ("Security catalog", b.signature.catalog_path.clone()),
            ("Catalog member tag", b.signature.catalog_member_tag.clone()),
        ],
    );
    end_section(h);
}

fn integrity_section(h: &mut String, r: &Report) {
    let i = &r.integrity;
    h.push_str(&format!(
        r#"<section id="custody"><h2>Chain of custody</h2>
<div class="seal">
  <div class="seallabel">Report seal (SHA-256)</div>
  <code class="sealhash">{seal}</code>
  <p class="muted">Scope: {scope}. Re-verify with <code>lai verify &lt;report.json&gt;</code>.</p>
</div>
<div class="kv">
  <div class="kvrow"><div class="k">Sealed at (UTC)</div><div class="v">{sealed}</div></div>
  <div class="kvrow"><div class="k">Sections collected</div><div class="v">{sections}</div></div>
  <div class="kvrow"><div class="k">Sections degraded</div><div class="v">{degraded}</div></div>
  <div class="kvrow"><div class="k">Engine</div><div class="v">{tool} v{ver} ({arch}, {profile})</div></div>
  <div class="kvrow"><div class="k">Engine elevated</div><div class="v">{elev}</div></div>
  <div class="kvrow"><div class="k">SeDebugPrivilege</div><div class="v">{dbg}</div></div>
  <div class="kvrow"><div class="k">Operating system</div><div class="v">{osname} {osver} (build {build}, {native})</div></div>
  <div class="kvrow"><div class="k">Host</div><div class="v">{host} / {dns}</div></div>
  <div class="kvrow"><div class="k">Host uptime</div><div class="v">{uptime} s</div></div>
  <div class="kvrow"><div class="k">Case id</div><div class="v">{case}</div></div>
  <div class="kvrow"><div class="k">Examiner</div><div class="v">{examiner}</div></div>
  <div class="kvrow"><div class="k">Organization</div><div class="v">{org}</div></div>
  <div class="kvrow"><div class="k">Notes</div><div class="v">{notes}</div></div>
</div>
"#,
        seal = esc(&i.report_sha256),
        scope = esc(&i.seal_scope),
        sealed = esc(&i.sealed_at_utc),
        sections = i.artifact_sections,
        degraded = i.sections_degraded,
        tool = esc(&r.tool.name),
        ver = esc(&r.tool.version),
        arch = esc(&r.tool.arch),
        profile = esc(&r.tool.build_profile),
        elev = yesno(r.tool.running_elevated),
        dbg = yesno(r.tool.debug_privilege_held),
        osname = esc(&r.tool.os.product_name),
        osver = esc(&r.tool.os.version),
        build = r.tool.os.build,
        native = esc(&r.tool.os.native_arch),
        host = esc(&r.tool.host.computer_name),
        dns = esc(&r.tool.host.dns_hostname),
        uptime = r.tool.host.uptime_seconds,
        case = esc(&r.case.case_id),
        examiner = esc(&r.case.examiner),
        org = esc(&r.case.organization),
        notes = esc(&r.case.notes),
    ));

    if !i.warnings.is_empty() {
        h.push_str("<h3>Collection warnings</h3><ul class=\"warns\">");
        for w in &i.warnings {
            h.push_str(&format!("<li>{}</li>", esc(w)));
        }
        h.push_str("</ul>");
    }

    h.push_str("<h3>Custody log</h3>");
    table(
        h,
        &["#", "Timestamp (UTC)", "Action", "Detail"],
        i.custody_log
            .iter()
            .map(|e| {
                vec![
                    e.seq.to_string(),
                    e.at_utc.clone(),
                    e.action.clone(),
                    e.detail.clone(),
                ]
            })
            .collect(),
        0,
    );
    end_section(h);
}

// ---------------------------------------------------------------------------
// Styling
// ---------------------------------------------------------------------------

const CSS: &str = r#"
:root{
  --bg:#0b0d12; --panel:#12151d; --panel2:#171b25; --line:#232936;
  --txt:#e7ecf5; --muted:#8b95a7; --accent:#4da3ff; --ok:#33d69f;
  --warn:#ffb020; --err:#ff6b6b; --mono:ui-monospace,SFMono-Regular,"Cascadia Mono",Consolas,monospace;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);
  font:14px/1.55 "Segoe UI",system-ui,-apple-system,sans-serif}
code,.mono,.raw,.tree{font-family:var(--mono);font-size:12.5px}
header{display:flex;flex-wrap:wrap;gap:24px;justify-content:space-between;align-items:center;
  padding:22px 32px;background:linear-gradient(180deg,#121722,#0e111a);border-bottom:1px solid var(--line)}
.brand{display:flex;gap:16px;align-items:center}
.logo{width:46px;height:46px;border-radius:12px;display:grid;place-items:center;font-weight:700;
  letter-spacing:.5px;color:#06121f;background:linear-gradient(135deg,#63b3ff,#2f7fe0)}
h1{margin:0;font-size:19px;font-weight:600;letter-spacing:.2px}
.sub{margin:2px 0 0;color:var(--muted);font-size:12.5px}
.headmeta{display:flex;gap:28px;flex-wrap:wrap}
.headmeta div{display:flex;flex-direction:column}
.headmeta span{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.6px}
.headmeta strong{font-weight:600;font-size:13.5px;max-width:340px;overflow-wrap:anywhere}
main{padding:26px 32px 60px;max-width:1500px;margin:0 auto}
section{margin:0 0 26px;padding:20px 22px;background:var(--panel);border:1px solid var(--line);
  border-radius:14px}
section h2{margin:0 0 14px;font-size:15px;font-weight:600;display:flex;align-items:center;gap:10px;
  text-transform:uppercase;letter-spacing:.8px;color:#cdd7e6}
section h3{margin:20px 0 10px;font-size:12.5px;text-transform:uppercase;letter-spacing:.7px;color:var(--muted)}
.hero{background:linear-gradient(160deg,#141a26,#0f131c);padding:22px}
.cards{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(270px,1fr))}
.card{background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.cardlabel{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.7px}
.cardvalue{font-size:17px;font-weight:600;margin-top:4px;overflow-wrap:anywhere}
.cardvalue.small{font-size:12.5px;font-family:var(--mono);font-weight:500}
.cardsub{color:var(--muted);font-size:12px;margin-top:6px;overflow-wrap:anywhere}
.verdict{margin-top:16px;display:flex;gap:12px;align-items:center}
.pill{padding:4px 12px;border-radius:999px;font-size:12px;font-weight:600}
.pill.ok{background:rgba(51,214,159,.14);color:var(--ok);border:1px solid rgba(51,214,159,.35)}
.pill.warn{background:rgba(255,176,32,.14);color:var(--warn);border:1px solid rgba(255,176,32,.35)}
.badge{font-size:10.5px;padding:2px 8px;border-radius:999px;letter-spacing:.6px;font-weight:700}
.b-ok{background:rgba(51,214,159,.14);color:var(--ok)}
.b-partial{background:rgba(255,176,32,.14);color:var(--warn)}
.b-denied,.b-error{background:rgba(255,107,107,.14);color:var(--err)}
.b-skipped,.b-timeout{background:rgba(139,149,167,.16);color:var(--muted)}
.kv{display:grid;grid-template-columns:repeat(auto-fit,minmax(430px,1fr));gap:2px 26px}
.kvrow{display:grid;grid-template-columns:210px 1fr;gap:14px;padding:6px 0;border-bottom:1px dashed #1c2230}
.k{color:var(--muted);font-size:12.5px}
.v{overflow-wrap:anywhere}
.tablewrap{overflow-x:auto;border:1px solid var(--line);border-radius:10px;margin-top:10px}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th{position:sticky;top:0;background:#151a24;text-align:left;padding:9px 12px;color:#9fb0c9;
  font-size:11px;text-transform:uppercase;letter-spacing:.6px;border-bottom:1px solid var(--line)}
td{padding:7px 12px;border-bottom:1px solid #171c26;vertical-align:top;overflow-wrap:anywhere}
tbody tr:hover{background:#151b26}
td.mono{font-family:var(--mono);font-size:12px;color:#b8c6da;white-space:nowrap}
.muted{color:var(--muted)}
.alert{margin:6px 0;padding:10px 12px;border-radius:9px;background:rgba(255,107,107,.1);
  border:1px solid rgba(255,107,107,.3);color:#ffc9c9;font-size:13px}
.note{margin:8px 0;padding:8px 12px;border-radius:9px;background:rgba(255,176,32,.08);
  border:1px solid rgba(255,176,32,.22);color:#ffd89a;font-size:12.5px}
.warns li{color:#ffd89a;font-size:12.5px;margin:4px 0}
pre.raw{max-height:320px;overflow:auto;background:#0a0c11;border:1px solid var(--line);
  border-radius:10px;padding:12px;color:#a9b8cc;white-space:pre-wrap}
pre.tree{background:#0a0c11;border:1px solid var(--line);border-radius:10px;padding:12px;
  color:#c3d0e2;overflow:auto}
.seal{margin:6px 0 16px;padding:14px 16px;border-radius:12px;
  background:linear-gradient(135deg,rgba(77,163,255,.12),rgba(51,214,159,.08));
  border:1px solid rgba(77,163,255,.3)}
.seallabel{font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:#9fc4ee}
.sealhash{display:block;margin-top:6px;font-size:13px;color:#d7e9ff;overflow-wrap:anywhere}
footer{display:flex;flex-wrap:wrap;gap:18px;justify-content:space-between;padding:18px 32px;
  border-top:1px solid var(--line);color:var(--muted);font-size:12px}
footer code{color:#9fb0c9}
@media print{body{background:#fff;color:#111}section{break-inside:avoid}}
"#;
