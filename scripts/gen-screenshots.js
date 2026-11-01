/*
 * Regenerates docs/screenshots/*.png from a REDACTED report.
 *
 * Never point this at a real case: the dashboard renders whatever report you feed
 * it, so the screenshots would contain the examined host's identity. Produce the
 * input with scripts/sanitize-report.py first.
 *
 * Usage
 *   .\dist\lai.exe serve --port 8787
 *   (start Edge against the dashboard)
 *     msedge --app=http://127.0.0.1:8787/ --remote-debugging-port=9222 ^
 *            --user-data-dir=%TEMP%\lai-shots --no-first-run --headless=new
 *   node scripts/gen-screenshots.js docs/screenshots <redacted-report.json>
 */
const fs = require('fs');
const path = require('path');

const OUT = process.argv[2] || 'docs/screenshots';
const REPORT = process.argv[3] || 'redacted.json';
const CDP = 'http://127.0.0.1:9222/json/list';
const DASHBOARD = 'http://127.0.0.1:8787/';

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

async function attach(urlFilter) {
  const list = await (await fetch(CDP)).json();
  const target = list.find((t) => t.type === 'page' && t.url.includes(urlFilter));
  if (!target) throw new Error('target not found: ' + urlFilter);
  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
  let id = 0;
  const pending = new Map();
  ws.onmessage = (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && pending.has(m.id)) {
      const { res, rej } = pending.get(m.id);
      pending.delete(m.id);
      m.error ? rej(new Error(JSON.stringify(m.error))) : res(m.result);
    }
  };
  const send = (method, params = {}) =>
    new Promise((res, rej) => { const i = ++id; pending.set(i, { res, rej }); ws.send(JSON.stringify({ id: i, method, params })); });
  return { send };
}

const evaluate = async (c, expression) => {
  const r = await c.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.text);
  return r.result.value;
};

const shoot = async (c, file) => {
  const r = await c.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
  fs.writeFileSync(file, Buffer.from(r.data, 'base64'));
  console.log('  ' + path.basename(file) + '  ' + Math.round(fs.statSync(file).size / 1024) + ' KB');
};

(async () => {
  const report = JSON.parse(fs.readFileSync(REPORT, 'utf8'));

  // --- dashboard ----------------------------------------------------------
  const dashboard = await attach(DASHBOARD);
  await dashboard.send('Page.enable');
  await dashboard.send('Runtime.enable');
  await dashboard.send('Emulation.setDeviceMetricsOverride', { width: 1600, height: 1000, deviceScaleFactor: 1, mobile: false });
  await wait(600);
  await evaluate(dashboard, `applyReport(${JSON.stringify(report)}, 'reference capture')`);
  await wait(900);

  // The header chips are filled from the live /api/status call, not from the
  // report, so override them with the (already redacted) report identity.
  await evaluate(dashboard, `(() => {
    const host = document.getElementById('engineHost');
    const ident = document.getElementById('engineIdentity');
    if (host) host.textContent = state.report.tool.host.computer_name;
    if (ident) ident.textContent = state.report.case.organization + ' - ' + state.report.tool.os.product_name;
  })()`);

  const state = await evaluate(dashboard, 'state.report && state.report.process.pid');
  if (state !== report.process.pid) throw new Error('dashboard did not accept the report');

  const tabs = [
    ['overview', 'dashboard-overview.png'],
    ['identity', 'dashboard-identity.png'],
    ['network', 'dashboard-network.png'],
    ['handles', 'dashboard-handles.png'],
    ['integrity', 'dashboard-integrity.png'],
  ];
  for (const [tab, file] of tabs) {
    await evaluate(dashboard, `switchTab('${tab}')`);
    await wait(700);
    await shoot(dashboard, path.join(OUT, file));
  }

  // --- court exhibit ------------------------------------------------------
  const exhibit = path.resolve(OUT, 'exhibit.html').split(path.sep).join('/');
  const created = await dashboard.send('Target.createTarget', { url: 'file:///' + exhibit });
  await wait(1500);
  const list = await (await fetch(CDP)).json();
  const t = list.find((x) => x.id === created.targetId);
  const ws = new WebSocket(t.webSocketDebuggerUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
  let id = 0;
  const send = (method, params = {}) => new Promise((res) => { const i = ++id; ws.send(JSON.stringify({ id: i, method, params })); setTimeout(() => res(), 50); });
  await send('Emulation.setDeviceMetricsOverride', { width: 1600, height: 1000, deviceScaleFactor: 1, mobile: false });
  await wait(1200);
  const result = await new Promise((res) => {
    ws.onmessage = (ev) => { const m = JSON.parse(ev.data); if (m.id === id) res(m.result); };
    ws.send(JSON.stringify({ id: id, method: 'Page.captureScreenshot', params: { format: 'png' } }));
  });
  fs.writeFileSync(path.join(OUT, 'exhibit-report.png'), Buffer.from(result.data, 'base64'));
  console.log('  exhibit-report.png  ' + Math.round(fs.statSync(path.join(OUT, 'exhibit-report.png')).size / 1024) + ' KB');
  process.exit(0);
})().catch((e) => { console.error('FAILED: ' + e.message); process.exit(1); });
