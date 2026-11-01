/* LiveAppInspector dashboard logic - no framework, no CDN, no telemetry. */
'use strict';

const BOOT = (() => {
  try {
    return JSON.parse(document.getElementById('laiBoot').textContent);
  } catch {
    return { token: '' };
  }
})();
const TOKEN = BOOT.token || '';
const $ = (id) => document.getElementById(id);

const state = {
  report: null,
  status: null,
  tab: 'overview',
  busy: false,
  procsLoaded: false,
};

/* ------------------------------------------------------------------ utils */

const esc = (v) => String(v === null || v === undefined ? '' : v)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

const dash = (v) => (v === null || v === undefined || v === '' || v === 0
  ? '<span class="muted">—</span>' : esc(v));

const mono = (v) => (v ? `<span class="mono-cell">${esc(v)}</span>` : '<span class="muted">—</span>');

function bytes(n) {
  if (!n) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0, v = Number(n);
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return i === 0 ? `${v} B` : `${v.toFixed(2)} ${u[i]}`;
}

function uptime(ms) {
  const s = Math.floor((ms || 0) / 1000);
  if (s < 90) return `${s}s`;
  if (s < 5400) return `${Math.floor(s / 60)}m`;
  if (s < 172800) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
  return `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h`;
}

function when(iso) {
  if (!iso) return '<span class="muted">—</span>';
  return esc(iso.replace('T', ' ').replace('Z', ' UTC'));
}

function toast(msg, kind = '', ms = 4200) {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.innerHTML = msg;
  $('toasts').appendChild(el);
  setTimeout(() => el.remove(), ms);
}

function busy(on, text = 'Working…') {
  state.busy = on;
  $('overlay').hidden = !on;
  $('overlayText').textContent = text;
  $('btnPick').disabled = on;
  $('btnInspectPid').disabled = on;
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    method: opts.method || 'GET',
    headers: { 'X-LAI-Token': TOKEN, 'Content-Type': 'application/json' },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (res.status === 401) throw new Error('session token rejected - reload the dashboard from the engine URL');
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { throw new Error(text.slice(0, 300) || 'invalid response'); }
  if (data.ok === false) throw new Error(data.error || 'engine error');
  return data;
}

/* ------------------------------------------------------- engine status pill */

async function refreshStatus() {
  try {
    const s = await api('/api/status');
    state.status = s;
    $('engineDot').className = 'dot on';
    $('engineHost').textContent = s.host || 'localhost';
    $('engineIdentity').textContent = `${s.account} · ${s.os}`;
    const priv = $('enginePriv');
    priv.textContent = s.engine_elevated ? 'Administrator' : 'Standard user';
    priv.className = 'chip priv' + (s.engine_elevated ? ' admin' : '');
    priv.title = s.engine_elevated
      ? 'Engine is elevated - SYSTEM/protected processes are reachable'
      : 'Engine is not elevated - protected processes will return "denied"';
    const hint = $('welcomeHint');
    if (hint) {
      hint.innerHTML = s.engine_elevated
        ? `Engine ${esc(s.version)} running elevated. SeDebugPrivilege: ${s.debug_privilege ? 'held' : 'not held'}. Hotkey listener: ${s.hotkey_listener ? 'active' : 'unavailable'}.`
        : `Engine ${esc(s.version)} is running as a <strong>standard user</strong>. SYSTEM-level and protected processes (EDR, AV, services) will report <em>denied</em>; use <strong>Elevate engine</strong> for full coverage.`;
    }
  } catch (e) {
    $('engineDot').className = 'dot off';
    $('engineHost').textContent = 'engine unreachable';
    console.error(e);
  }
}

/* ------------------------------------------------------------- acquisition */

async function pickWindow() {
  if (state.busy) return;
  busy(true, 'Click the target application on your desktop… (Esc cancels)');
  $('overlayCancel').hidden = true;
  try {
    const data = await api('/api/pick', { method: 'POST', body: { timeout_secs: 120 } });
    applyReport(data.report, 'Window picked');
  } catch (e) {
    toast(esc(e.message), 'warn');
  } finally {
    busy(false);
    $('overlayCancel').hidden = true;
  }
}

async function inspectPid(pid) {
  const n = Number(pid);
  if (!Number.isFinite(n) || n <= 0) { toast('Enter a valid PID', 'warn'); return; }
  busy(true, `Acquiring PID ${n}…`);
  try {
    const data = await api('/api/inspect', {
      method: 'POST',
      body: { pid: n, resolve_dns: $('optDns').checked },
    });
    applyReport(data.report, `PID ${n} captured`);
  } catch (e) {
    toast(esc(e.message), 'err');
  } finally {
    busy(false);
  }
}

async function pollHotkey() {
  if (state.busy) return;
  try {
    const data = await api('/api/hotkey_pick');
    if (data && data.pending === false && data.report) {
      applyReport(data.report, 'Hotkey capture');
    }
  } catch { /* engine restarting: ignore */ }
}

function applyReport(report, label) {
  if (!report || typeof report !== 'object') { toast('Engine returned no report', 'err'); return; }
  state.report = report;
  $('tabs').hidden = false;
  $('exportBox').hidden = false;
  $('metaBox').hidden = false;
  renderSidebar();
  switchTab(state.tab);
  const name = report.process.image_name || 'target';
  toast(`<strong>${esc(name)}</strong> (pid ${report.process.pid}) captured in ${report.tool.duration_ms} ms · ${label || ''}`, 'ok');
}

/* ----------------------------------------------------------------- sidebar */

function renderSidebar() {
  const r = state.report;
  if (!r) return;
  const p = r.process;
  const u = r.user_context;
  const sig = r.binary.signature || {};
  const sigClass = sig.status === 'valid' ? 'b-ok'
    : sig.status === 'unsigned' ? 'b-skipped' : 'b-error';

  $('targetCard').innerHTML = `
    <h2>${esc(p.image_name || 'unknown image')}</h2>
    <div class="sub mono">${esc(p.image_path || 'path unavailable')}</div>
    <div class="sub">pid <strong>${p.pid}</strong> · ${esc(p.arch)}${p.is_wow64 ? ' (WOW64)' : ''} · session ${p.session_id}</div>
    <div class="sub">${esc(u.account_domain)}\\${esc(u.account_name)} · ${esc(u.integrity.name)} integrity</div>
    <div class="hash">${esc(r.binary.sha256 || 'hash unavailable')}</div>
    <div class="sub" style="margin-top:8px">
      <span class="badge ${sigClass}">${esc(sig.status || 'unknown')}</span>
      <span class="muted">${esc(sig.signer_subject || 'no signer')}${sig.signature_source === 'catalog' ? ' · catalog' : ''}</span>
    </div>`;

  $('acqList').innerHTML = `
    <dt>Collected</dt><dd>${when(r.tool.completed_at_utc)}</dd>
    <dt>Duration</dt><dd>${r.tool.duration_ms} ms</dd>
    <dt>Process age</dt><dd>${uptime(p.times.elapsed_ms)}</dd>
    <dt>Created</dt><dd>${when(p.times.created_utc)}</dd>
    <dt>Sections degraded</dt><dd>${r.integrity.sections_degraded === 0
      ? '<span class="pill ok">none</span>'
      : `<span class="pill warn">${r.integrity.sections_degraded}</span>`}</dd>
    <dt>Report seal</dt><dd class="mono">${esc((r.integrity.report_sha256 || '').slice(0, 32))}…</dd>
    <dt>Case</dt><dd>${dash(r.case.case_id)}</dd>
    <dt>Examiner</dt><dd>${dash(r.case.examiner)}</dd>`;

  $('cIdentity').textContent = (r.user_context.privileges || []).length;
  $('cTree').textContent = (r.genealogy.children || []).length;
  $('cNetwork').textContent = (r.network.connections || []).length;
  $('cModules').textContent = r.modules.count || 0;
  $('cHandles').textContent = r.handles.inspected || 0;
  $('cRegistry').textContent = (r.registry.keys || []).length;
}

/* ------------------------------------------------------------------- tabs */

function switchTab(tab) {
  state.tab = tab;
  document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === tab));
  renderPanel();
}

function renderPanel() {
  const r = state.report;
  if (!r) return;
  const renderers = {
    overview: renderOverview,
    identity: renderIdentity,
    tree: renderTree,
    network: renderNetwork,
    modules: renderModules,
    handles: renderHandles,
    registry: renderRegistry,
    integrity: renderIntegrity,
    raw: renderRaw,
  };
  const fn = renderers[state.tab] || renderOverview;
  $('panel').innerHTML = fn(r);
  wireFilters();
}

function statusBadge(meta) {
  const s = (meta && meta.status) || 'ok';
  return `<span class="badge b-${esc(s)}">${esc(s)}</span>`;
}

function metaBlock(meta) {
  if (!meta) return '';
  let out = '';
  if (meta.error) out += `<div class="alert">${esc(meta.error)}${meta.win32_error ? ` (Win32 ${meta.win32_error})` : ''}</div>`;
  (meta.warnings || []).forEach((w) => { out += `<div class="note">${esc(w)}</div>`; });
  return out;
}

function sectionHead(title, meta) {
  return `<div class="sectionhead"><h2>${esc(title)}</h2>${statusBadge(meta)}</div>${metaBlock(meta)}`;
}

function kv(rows) {
  return `<div class="kv">${rows
    .map(([k, v, isMono]) => `<div class="kvrow"><div class="k">${esc(k)}</div><div class="v${isMono ? ' mono' : ''}">${v}</div></div>`)
    .join('')}</div>`;
}

function table(headers, rows, opts = {}) {
  const body = rows.map((row) => `<tr>${row
    .map((cell, i) => `<td${i === 0 && opts.monoFirst !== false ? ' class="mono-cell"' : ''}>${cell === '' || cell === null || cell === undefined ? '<span class="muted">—</span>' : cell}</td>`)
    .join('')}</tr>`).join('');
  return `<div class="tablewrap"><table><thead><tr>${headers.map((h) => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${body}</tbody></table></div>`;
}

const yesno = (b) => (b ? '<span style="color:var(--ok)">yes</span>' : '<span class="muted">no</span>');

/* --------------------------------------------------------------- overview */

function renderOverview(r) {
  const p = r.process, u = r.user_context, n = r.network, g = r.genealogy;
  const degraded = r.integrity.sections_degraded;
  const health = [
    ['Process identity', p.meta], ['User & token', u.meta], ['Genealogy', g.meta],
    ['Network', n.meta], ['Modules', r.modules.meta], ['Handles', r.handles.meta],
    ['Registry', r.registry.meta], ['Services', r.services.meta], ['Binary integrity', r.binary.meta],
  ];

  return `
  <div class="grid">
    <div class="card">
      <h3>Target image</h3>
      <div class="big">${esc(p.image_name || 'unknown')}</div>
      <div class="small mono">${esc(p.image_path || 'path unavailable')}</div>
      <div class="statline">
        <div class="stat"><span class="n">${esc(p.arch)}${p.is_wow64 ? '·32' : ''}</span><span class="l">architecture</span></div>
        <div class="stat"><span class="n">${p.thread_count}</span><span class="l">threads</span></div>
        <div class="stat"><span class="n">${p.handle_count}</span><span class="l">handles</span></div>
        <div class="stat"><span class="n">${bytes(p.memory.working_set_bytes)}</span><span class="l">working set</span></div>
      </div>
    </div>

    <div class="card">
      <h3>Identity verdict</h3>
      <div class="big">${esc(u.account_domain)}\\${esc(u.account_name)}</div>
      <div class="small">${esc(u.elevation.verdict || 'unknown')}</div>
      <div class="statline">
        <div class="stat"><span class="n">${esc(u.integrity.name || '?')}</span><span class="l">integrity</span></div>
        <div class="stat"><span class="n">${esc(u.session.kind || '?')}</span><span class="l">session ${u.session.id}</span></div>
        <div class="stat"><span class="n">${(u.privileges || []).length}</span><span class="l">privileges</span></div>
        <div class="stat"><span class="n">${p.protection_level || 'none'}</span><span class="l">protection</span></div>
      </div>
    </div>

    <div class="card">
      <h3>Binary integrity</h3>
      <div class="small mono" style="color:#9fc4ee;word-break:break-all">${esc(r.binary.sha256 || 'hash unavailable')}</div>
      <div class="statline">
        <div class="stat"><span class="n">${esc(r.binary.signature.status || '?')}</span><span class="l">signature</span></div>
        <div class="stat"><span class="n">${bytes(r.binary.size_bytes)}</span><span class="l">on disk</span></div>
        <div class="stat"><span class="n">${esc(r.binary.pe.machine || '?')}</span><span class="l">PE machine</span></div>
        <div class="stat"><span class="n">${r.binary.hash_duration_ms} ms</span><span class="l">hash time</span></div>
      </div>
      <div class="small" style="margin-top:8px">${esc(r.binary.signature.signer_subject || 'unsigned')}</div>
    </div>

    <div class="card">
      <h3>Runtime context</h3>
      <div class="big">${when(p.times.created_utc)}</div>
      <div class="small">process creation time · age ${uptime(p.times.elapsed_ms)}</div>
      <div class="small mono" style="margin-top:8px">cmd: ${esc(p.command_line || 'unavailable')}</div>
      <div class="small">${esc(p.command_line_source || '')}</div>
      <div class="small" style="margin-top:6px">cwd: ${esc(p.current_directory || '—')}</div>
    </div>

    <div class="card">
      <h3>Genealogy</h3>
      <div class="big">${esc((g.parent && (g.parent.name || 'parent exited')) || 'no parent')}</div>
      <div class="small">parent pid ${g.parent ? g.parent.pid : '—'}</div>
      <div class="statline">
        <div class="stat"><span class="n">${g.children.length}</span><span class="l">children</span></div>
        <div class="stat"><span class="n">${g.descendants.length}</span><span class="l">descendants</span></div>
        <div class="stat"><span class="n">${g.ancestors.length}</span><span class="l">ancestors</span></div>
      </div>
    </div>

    <div class="card">
      <h3>Network &amp; persistence</h3>
      <div class="big">${n.tcp_count + n.udp_count} endpoints</div>
      <div class="small">${n.established_count} established · ${n.listening_count} listening · ${n.unique_remote_endpoints} remote</div>
      <div class="statline">
        <div class="stat"><span class="n">${(r.registry.autoruns || []).length}</span><span class="l">autostart</span></div>
        <div class="stat"><span class="n">${(r.services.services || []).length}</span><span class="l">services</span></div>
        <div class="stat"><span class="n">${(r.registry.keys || []).length}</span><span class="l">reg keys</span></div>
      </div>
    </div>

    <div class="card wide">
      <h3>Collection health ${degraded === 0 ? '<span class="pill ok">complete</span>' : `<span class="pill warn">${degraded} degraded</span>`}</h3>
      ${table(['Section', 'Status', 'Detail'], health.map(([name, meta]) => [
        esc(name),
        statusBadge(meta),
        esc((meta && (meta.error || (meta.warnings && meta.warnings[0]))) || ''),
      ]))}
      ${(r.integrity.warnings || []).length
        ? `<div class="note" style="margin-top:10px"><strong>${r.integrity.warnings.length} warning(s)</strong><br>${r.integrity.warnings.slice(0, 10).map(esc).join('<br>')}</div>`
        : ''}
    </div>
  </div>`;
}

/* --------------------------------------------------------------- identity */

function renderIdentity(r) {
  const u = r.user_context;
  return `
  ${sectionHead('Token & account', u.meta)}
  ${kv([
    ['Account', `${esc(u.account_domain)}\\${esc(u.account_name)}`],
    ['SID', mono(u.sid)],
    ['Account type', dash(u.account_type)],
    ['Verdict', esc(u.elevation.verdict)],
    ['Elevated', yesno(u.elevation.is_elevated)],
    ['Elevation type', dash(u.elevation.elevation_type)],
    ['Integrity level', `${esc(u.integrity.name)} (0x${(u.integrity.rid || 0).toString(16)})`],
    ['Session', `id ${u.session.id} · ${esc(u.session.kind)}`],
    ['Session user', `${esc(u.session.domain)}\\${esc(u.session.username)}`],
    ['Client', esc([u.session.client_name, u.session.client_address].filter(Boolean).join(' / '))],
    ['Token id', mono(u.token.token_id)],
    ['Logon session (auth id)', mono(u.token.authentication_id)],
    ['Token type', `${esc(u.token.token_type)} · ${esc(u.token.impersonation_level)}`],
    ['Owner SID', mono(u.token.owner_sid)],
    ['AppContainer', yesno(u.token.is_app_container)],
    ['Virtualization', yesno(u.token.virtualization_enabled)],
  ])}

  <div class="sectionhead"><h2>Privileges (${(u.privileges || []).length})</h2></div>
  ${table(['Privilege', 'Enabled', 'Default', 'Removed', 'Used'], (u.privileges || []).map((p) => [
    esc(p.name), yesno(p.enabled), yesno(p.enabled_by_default), yesno(p.removed), yesno(p.used_for_access),
  ]))}

  <div class="sectionhead"><h2>Groups (${(u.groups || []).length})</h2></div>
  ${table(['SID', 'Name', 'Domain', 'Enabled', 'Integrity', 'Logon SID'], (u.groups || []).map((g) => [
    esc(g.sid), esc(g.name), esc(g.domain), yesno(g.enabled), yesno(g.integrity), yesno(g.logon_id),
  ]))}`;
}

/* ------------------------------------------------------------------ tree */

function renderTree(r) {
  const g = r.genealogy, p = r.process;
  let tree = '';
  [...g.ancestors].reverse().forEach((a) => {
    tree += `${'  '.repeat(a.depth)}${esc(a.name || '<exited / unknown>')}  (pid ${a.pid}${a.is_alive ? '' : ', exited'})\n`;
  });
  tree += `${'  '.repeat(Math.min(g.ancestors.length + 1, 10))}<span class="target">${esc(p.image_name || '?')}  (pid ${p.pid})  &lt;- target</span>\n`;
  g.descendants.forEach((c) => {
    tree += `${'  '.repeat(Math.min(c.depth + g.ancestors.length + 1, 20))}${esc(c.name)}  (pid ${c.pid})\n`;
  });

  return `
  ${sectionHead('Genealogy', g.meta)}
  <pre class="tree">${tree}</pre>
  <div class="sectionhead"><h2>Children (${g.children.length})</h2></div>
  ${table(['PID', 'Name', 'Path', 'Created (UTC)'], g.children.map((c) => [
    esc(c.pid), esc(c.name), esc(c.image_path || ''), when(c.created_utc),
  ]), { monoFirst: false })}
  <div class="sectionhead"><h2>Descendants (${g.descendants.length})</h2></div>
  ${table(['PID', 'Depth', 'Name', 'Path'], g.descendants.map((c) => [
    esc(c.pid), esc(c.depth), esc(c.name), esc(c.image_path || ''),
  ]), { monoFirst: false })}
  <div class="sectionhead"><h2>Ancestry</h2></div>
  ${table(['PID', 'Name', 'Alive', 'Path', 'Created (UTC)'], g.ancestors.map((a) => [
    esc(a.pid), esc(a.name || ''), yesno(a.is_alive), esc(a.image_path || ''), when(a.created_utc),
  ]), { monoFirst: false })}`;
}

/* --------------------------------------------------------------- network */

function renderNetwork(r) {
  const n = r.network;
  return `
  ${sectionHead('Network endpoints', n.meta)}
  ${kv([
    ['TCP endpoints', esc(n.tcp_count)],
    ['UDP endpoints', esc(n.udp_count)],
    ['Established', esc(n.established_count)],
    ['Listening', esc(n.listening_count)],
    ['Unique remotes', esc(n.unique_remote_endpoints)],
    ['Reverse DNS', yesno(n.resolve_dns)],
  ])}
  <div class="sectionhead"><h2>Connections (${n.connections.length})</h2></div>
  ${table(['Proto', 'Local address', 'L-port', 'Remote address', 'R-port', 'State', 'Remote host'], n.connections.map((c) => [
    esc(c.protocol), esc(c.local_address), esc(c.local_port), esc(c.remote_address),
    esc(c.remote_port || ''), esc(c.state), esc(c.remote_hostname || ''),
  ]))}`;
}

/* --------------------------------------------------------------- modules */

function renderModules(r) {
  const m = r.modules;
  return `
  ${sectionHead('Loaded modules', m.meta)}
  ${kv([
    ['Module count', esc(m.count)],
    ['Target image at index', esc(m.target_image_index === null || m.target_image_index === undefined ? '' : m.target_image_index)],
    ['Missing on disk', esc((m.items || []).filter((i) => i.missing_on_disk).length)],
    ['Unversioned', esc((m.items || []).filter((i) => !i.company).length)],
  ])}
  <div class="toolbar-inline" style="margin-top:12px">
    <input id="filterInput" placeholder="filter modules by name, company or path…" autocomplete="off">
  </div>
  ${table(['Module', 'Base', 'Size', 'Version', 'Company', 'Path'], m.items.map((i) => [
    esc(i.name) + (i.is_target_image ? ' <span class="badge b-ok">target</span>' : '') + (i.missing_on_disk ? ' <span class="badge b-error">missing</span>' : ''),
    esc(i.base_address), bytes(i.size_bytes), esc(i.file_version), esc(i.company), esc(i.path),
  ]))}`;
}

/* --------------------------------------------------------------- handles */

function renderHandles(r) {
  const h = r.handles;
  const types = (h.items || []).reduce((acc, i) => {
    acc[i.type_name] = (acc[i.type_name] || 0) + 1;
    return acc;
  }, {});
  return `
  ${sectionHead('Handle table', h.meta)}
  ${kv([
    ['Handles in process', esc(h.inspected)],
    ['Resolved', esc((h.items || []).length)],
    ['Truncated', yesno(h.truncated)],
    ['Cap', esc(h.limit)],
    ['Types', Object.entries(types).sort((a, b) => b[1] - a[1]).map(([t, c]) => `${esc(t)}: ${c}`).join(' · ')],
  ])}
  <div class="toolbar-inline" style="margin-top:12px">
    <input id="filterInput" placeholder="filter by object name, type or handle…" autocomplete="off">
    <span class="muted" style="font-size:12px">registry keys and files first</span>
  </div>
  ${table(['Handle', 'Type', 'Class', 'Object name', 'Access', 'Note'], h.items.map((i) => [
    esc(i.handle), esc(i.type_name), esc(i.classifier),
    esc(i.object_name || (i.target_pid ? `pid ${i.target_pid}` : '')),
    esc(i.granted_access), esc(i.note || ''),
  ]))}`;
}

/* -------------------------------------------------------------- registry */

function renderRegistry(r) {
  const g = r.registry, s = r.services;
  return `
  ${sectionHead('Registry keys held open', g.meta)}
  ${(g.autoruns || []).length
    ? `<div class="sectionhead"><h2>Autostart entries referencing this image</h2></div>
       ${table(['Hive', 'Key', 'Value', 'Command'], g.autoruns.map((a) => [
         esc(a.hive), esc(a.key), esc(a.value_name), esc(a.command),
       ]))}`
    : `<div class="note">No Run/RunOnce/RunServices/Winlogon entry references this image.</div>`}
  ${(g.autorun_scan_notes || []).map((n) => `<div class="note">${esc(n)}</div>`).join('')}
  ${table(['Key path', 'Handle', 'Access'], g.keys.map((k) => [
    esc(k.path), esc(k.handle), esc(k.granted_access),
  ]))}

  ${sectionHead('Service registrations', s.meta)}
  ${(s.services || []).length
    ? table(['Service', 'Display name', 'State', 'Start', 'Account', 'Binary path'], s.services.map((x) => [
        esc(x.name), esc(x.display_name), esc(x.state), esc(x.start_type), esc(x.account), esc(x.binary_path),
      ]))
    : '<div class="note">This image is not registered with the Service Control Manager.</div>'}`;
}

/* ------------------------------------------------------------- integrity */

function renderIntegrity(r) {
  const b = r.binary, i = r.integrity, t = r.tool;
  return `
  ${sectionHead('Binary integrity', b.meta)}
  <div class="seal">
    <div class="label">SHA-256 of on-disk image</div>
    <code>${esc(b.sha256 || 'unavailable')}</code>
    <div class="small muted" style="margin-top:8px">hashed ${when(b.hashed_at_utc)} · ${bytes(b.bytes_read)} in ${b.hash_duration_ms} ms · ${esc(b.hash_algorithm)}</div>
  </div>
  ${kv([
    ['Path', esc(b.path)],
    ['Size', bytes(b.size_bytes)],
    ['NTFS volume serial', mono(b.volume_serial)],
    ['NTFS file index', mono(b.file_index)],
    ['Attributes', dash(b.file_attributes)],
    ['Hard links', esc(b.hard_link_count)],
    ['Created', when(b.created_utc)],
    ['Modified', when(b.modified_utc)],
    ['Accessed', when(b.accessed_utc)],
    ['PE machine', dash(b.pe.machine)],
    ['PE subsystem', dash(b.pe.subsystem)],
    ['PE linker', dash(b.pe.linker_version)],
    ['PE timestamp', when(b.pe.compile_timestamp_utc)],
    ['Mitigations', dash(b.pe.characteristics)],
    ['.NET', yesno(b.pe.is_dotnet)],
    ['Signature', `${esc(b.signature.status)} <span class="muted">(${esc(b.signature.trust_status_hex)})</span>`],
    ['Signature source', dash(b.signature.signature_source)],
    ['Signer', dash(b.signature.signer_subject)],
    ['Issuer', dash(b.signature.signer_issuer)],
    ['Security catalog', dash(b.signature.catalog_path)],
    ['Catalog member tag', b.signature.catalog_member_tag ? mono(b.signature.catalog_member_tag) : '<span class="muted">—</span>'],
  ])}

  <div class="sectionhead"><h2>Report seal</h2></div>
  <div class="seal">
    <div class="label">SHA-256 of the canonical report body</div>
    <code>${esc(i.report_sha256 || '(not sealed)')}</code>
    <div class="small muted" style="margin-top:8px">${esc(i.seal_scope)}</div>
  </div>
  ${kv([
    ['Sealed at', when(i.sealed_at_utc)],
    ['Sections', esc(i.artifact_sections)],
    ['Degraded sections', esc(i.sections_degraded)],
    ['Engine', `${esc(t.name)} ${esc(t.version)} (${esc(t.build_profile)}, ${esc(t.arch)})`],
    ['Engine elevated', yesno(t.running_elevated)],
    ['SeDebugPrivilege', yesno(t.debug_privilege_held)],
    ['OS', `${esc(t.os.product_name)} ${esc(t.os.version)} build ${t.os.build}`],
    ['Host', `${esc(t.host.computer_name)} / ${esc(t.host.dns_hostname)}`],
    ['Boot time', when(t.host.boot_time_utc)],
    ['Host uptime', `${t.host.uptime_seconds} s`],
    ['Duration', `${t.duration_ms} ms`],
  ])}
  <div class="sectionhead"><h2>Custody log (${i.custody_log.length})</h2></div>
  ${table(['#', 'Timestamp (UTC)', 'Action', 'Detail'], i.custody_log.map((e) => [
    esc(e.seq), when(e.at_utc), esc(e.action), esc(e.detail),
  ]), { monoFirst: false })}`;
}

/* ------------------------------------------------------------------- raw */

function renderRaw(r) {
  return `<pre class="raw">${esc(JSON.stringify(r, null, 2))}</pre>`;
}

/* --------------------------------------------------------------- filters */

function wireFilters() {
  const input = $('filterInput');
  if (!input) return;
  input.addEventListener('input', () => {
    const q = input.value.trim().toLowerCase();
    document.querySelectorAll('#panel tbody tr').forEach((tr) => {
      tr.style.display = !q || tr.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
  });
}

/* ------------------------------------------------------------ process list */

async function loadProcesses() {
  try {
    const data = await api('/api/processes?limit=800');
    state.procs = data.processes || [];
    renderProcessList('');
    state.procsLoaded = true;
  } catch (e) {
    toast(esc(e.message), 'err');
  }
}

function renderProcessList(filter) {
  const q = filter.toLowerCase();
  const rows = state.procs
    .filter((p) => !q || p.name.toLowerCase().includes(q) || String(p.pid).includes(q))
    .slice(0, 200)
    .map((p) => `<div class="prow" data-pid="${p.pid}">
        <span class="pid">${p.pid}</span>
        <span>${esc(p.name)}</span>
        <span class="thr">${p.threads}t · s${p.session}</span>
      </div>`)
    .join('');
  $('procListBody').innerHTML = rows || '<div class="muted" style="padding:10px">no match</div>';
  $('procListBody').querySelectorAll('.prow').forEach((el) => {
    el.addEventListener('click', () => {
      $('procDropdown').hidden = true;
      inspectPid(el.dataset.pid);
    });
  });
}

/* ------------------------------------------------------------------- init */

function init() {
  $('btnPick').addEventListener('click', pickWindow);
  $('btnInspectPid').addEventListener('click', () => inspectPid($('pidInput').value));
  $('pidInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') inspectPid($('pidInput').value); });

  $('tabs').addEventListener('click', (e) => {
    const tab = e.target.closest('.tab');
    if (tab) switchTab(tab.dataset.tab);
  });

  $('btnProcs').addEventListener('click', (e) => {
    e.stopPropagation();
    const dd = $('procDropdown');
    dd.hidden = !dd.hidden;
    if (!dd.hidden && !state.procsLoaded) loadProcesses();
    if (!dd.hidden) $('procFilter').focus();
  });
  $('procFilter').addEventListener('input', (e) => renderProcessList(e.target.value));
  document.addEventListener('click', (e) => {
    if (!$('procDropdown').hidden && !e.target.closest('.proclist')) $('procDropdown').hidden = true;
  });

  $('btnExportJson').addEventListener('click', () => {
    window.location.href = `/api/export/json?t=${encodeURIComponent(TOKEN)}`;
  });
  $('btnExportHtml').addEventListener('click', () => {
    window.location.href = `/api/export/html?t=${encodeURIComponent(TOKEN)}`;
  });
  $('btnCopyHash').addEventListener('click', async () => {
    const hash = state.report && state.report.binary && state.report.binary.sha256;
    if (!hash) { toast('No hash available', 'warn'); return; }
    try {
      await navigator.clipboard.writeText(hash);
      toast('SHA-256 copied to clipboard', 'ok', 2200);
    } catch {
      toast(`<span class="mono">${esc(hash)}</span>`, '', 9000);
    }
  });

  $('btnElevate').addEventListener('click', async () => {
    try {
      const d = await api('/api/elevate', { method: 'POST', body: {} });
      toast(esc(d.message || 'elevated engine launched'), 'ok', 8000);
    } catch (e) {
      toast(esc(e.message), 'warn');
    }
  });

  $('btnShutdown').addEventListener('click', async () => {
    if (!confirm('Stop the LiveAppInspector engine? The dashboard will disconnect.')) return;
    try { await api('/api/shutdown', { method: 'POST', body: {} }); } catch { /* expected */ }
    document.body.innerHTML = '<div style="display:grid;place-items:center;height:100vh;font:14px Segoe UI;color:#8a95a8">Engine stopped. You can close this tab.</div>';
  });

  document.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.altKey && (e.key === 'f' || e.key === 'F')) {
      e.preventDefault();
      pickWindow();
    }
  });

  refreshStatus();
  setInterval(refreshStatus, 15000);
  setInterval(pollHotkey, 2500);
}

init();
