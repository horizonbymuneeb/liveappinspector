/*
 * LiveAppInspector - browser-level UI smoke test.
 *
 * WHY THIS EXISTS
 * ---------------
 * An HTTP test that only fetches bytes cannot tell you whether the dashboard
 * actually *boots*. A Content-Security-Policy mistake (script-src without
 * 'self') shipped a dashboard that downloaded /app.js and then refused to run
 * it: every API check passed while the real UI was dead. This script drives a
 * real Chromium (Edge) through the DevTools protocol, executes an acquisition
 * from the page's own code path, asserts the DOM rendered, and saves reference
 * screenshots.
 *
 * USAGE
 *   dist\lai.exe serve --port 8787
 *   start msedge --app=http://127.0.0.1:8787/ --remote-debugging-port=9222 ^
 *                --user-data-dir=%TEMP%\lai-ui --no-first-run
 *   node tests/ui-smoke.js <output-dir> <target-pid> <session-token>
 *
 * The session token is printed by the engine on startup.
 */
const fs = require('fs');
const OUT = process.argv[2];
const PID = Number(process.argv[3]);
const TOKEN = process.argv[4];

const wait = (ms) => new Promise(r => setTimeout(r, ms));

async function connect(url) {
  const list = await (await fetch(url)).json();
  const page = list.find(t => t.type === 'page' && t.url.includes('127.0.0.1:8787'));
  if (!page) throw new Error('dashboard target not found');
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
  let id = 0;
  const pending = new Map();
  ws.onmessage = (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && pending.has(m.id)) { const { res, rej } = pending.get(m.id); pending.delete(m.id); m.error ? rej(new Error(JSON.stringify(m.error))) : res(m.result); }
  };
  const send = (method, params = {}) => new Promise((res, rej) => { const i = ++id; pending.set(i, { res, rej }); ws.send(JSON.stringify({ id: i, method, params })); });
  return { ws, send };
}

const evalJs = async (c, expr) => {
  const r = await c.send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.text + ' ' + (r.exceptionDetails.exception?.description || ''));
  return r.result.value;
};

const shot = async (c, file) => {
  const r = await c.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
  fs.writeFileSync(file, Buffer.from(r.data, 'base64'));
  console.log('saved', file, Math.round(fs.statSync(file).size / 1024) + ' KB');
};

(async () => {
  const c = await connect('http://127.0.0.1:9222/json/list');
  await c.send('Page.enable');
  await c.send('Runtime.enable');
  await c.send('Emulation.setDeviceMetricsOverride', { width: 1600, height: 1000, deviceScaleFactor: 1, mobile: false });
  await wait(800);
  console.log('engine status:', await evalJs(c, 'api("/api/status").then(d => d.host + " / " + d.os)'));

  // trigger a real acquisition through the dashboard's own UI code path
  await evalJs(c, `inspectPid(${PID})`);
  await wait(2500);
  const info = await evalJs(c, 'state.report ? state.report.process.image_name + " pid " + state.report.process.pid : "NO REPORT"');
  console.log('report in dashboard:', info);
  if (!info || info === 'NO REPORT') throw new Error('dashboard did not render a report');

  // The UI must be *live*: tabs visible, hash shown, no JS errors blocking render.
  const checks = await evalJs(c, `JSON.stringify({
    tabsVisible: !document.getElementById('tabs').hidden,
    dropdownHidden: document.getElementById('procDropdown').hidden,
    cards: document.querySelectorAll('#panel .card').length,
    hashShown: document.body.innerText.includes(state.report.binary.sha256),
    tabCounts: document.querySelectorAll('.tab .count').length,
    title: document.title
  })`);
  const c2 = JSON.parse(checks);
  console.log('dom checks:', checks);
  if (!c2.tabsVisible) throw new Error('tab bar is hidden after acquisition');
  if (!c2.dropdownHidden) throw new Error('process dropdown leaked open');
  if (c2.cards < 4) throw new Error('overview cards missing');
  if (!c2.hashShown) throw new Error('binary hash not rendered');

  await evalJs(c, "switchTab('overview')"); await wait(700); await shot(c, OUT + '/dashboard-overview.png');
  await evalJs(c, "switchTab('identity')"); await wait(700); await shot(c, OUT + '/dashboard-identity.png');
  await evalJs(c, "switchTab('network')");  await wait(700); await shot(c, OUT + '/dashboard-network.png');
  await evalJs(c, "switchTab('handles')");  await wait(900); await shot(c, OUT + '/dashboard-handles.png');
  await evalJs(c, "switchTab('integrity')"); await wait(800); await shot(c, OUT + '/dashboard-integrity.png');

  // court-facing HTML exhibit, rendered from the same report
  const html = await (await fetch(`http://127.0.0.1:8787/api/export/html?t=${TOKEN}`)).text();
  const file = OUT + '/exhibit.html';
  fs.writeFileSync(file, html);
  const fileUrl = 'file:///' + file.split(String.fromCharCode(92)).join('/');
  const t = await c.send('Target.createTarget', { url: fileUrl });
  const list = await (await fetch('http://127.0.0.1:9222/json/list')).json();
  const ex = list.find(x => x.id === t.targetId);
  const ws2 = new WebSocket(ex.webSocketDebuggerUrl);
  await new Promise((res, rej) => { ws2.onopen = res; ws2.onerror = rej; });
  let id2 = 0; const pend2 = new Map();
  ws2.onmessage = (ev) => { const m = JSON.parse(ev.data); if (m.id && pend2.has(m.id)) { const { res } = pend2.get(m.id); pend2.delete(m.id); res(m.result); } };
  const send2 = (method, params = {}) => new Promise((res) => { const i = ++id2; pend2.set(i, { res }); ws2.send(JSON.stringify({ id: i, method, params })); });
  await send2('Emulation.setDeviceMetricsOverride', { width: 1600, height: 1000, deviceScaleFactor: 1, mobile: false });
  await wait(1200);
  const r = await send2('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
  fs.writeFileSync(OUT + '/exhibit-report.png', Buffer.from(r.data, 'base64'));
  console.log('saved', OUT + '/exhibit-report.png', Math.round(fs.statSync(OUT + '/exhibit-report.png').size / 1024) + ' KB');
  process.exit(0);
})().catch(e => { console.error('FAILED:', e.message); process.exit(1); });
