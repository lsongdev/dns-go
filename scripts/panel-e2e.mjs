// Drives the web panel in headless Chrome over the DevTools protocol and
// checks the main flows end to end. It changes the server's configuration
// (creates zone test.lan, client "phone", custom rules), so point it at a
// throwaway instance with an unauthenticated API:
//
//   node scripts/panel-e2e.mjs http://127.0.0.1:8080 /tmp/panel-e2e
//
// Needs Node 22+ (built-in WebSocket) and Chrome; set CHROME to its path.
import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';

const [base, out = 'panel-e2e-out'] = process.argv.slice(2);
mkdirSync(out, { recursive: true });
const chromePath = process.env.CHROME || {
  darwin: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  win32: 'C:/Program Files/Google/Chrome/Application/chrome.exe',
}[process.platform] || 'google-chrome';
const chrome = spawn(chromePath, [
  '--headless=new', '--disable-gpu', '--remote-debugging-port=9333', '--window-size=1280,900',
  `--user-data-dir=${out}/profile`, 'about:blank',
], { stdio: 'ignore' });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let ws, id = 0;
const pending = new Map();
const errors = [];
function send(method, params = {}) {
  return new Promise((resolve, reject) => {
    const msgId = ++id;
    pending.set(msgId, { resolve, reject });
    ws.send(JSON.stringify({ id: msgId, method, params }));
  });
}
async function evaluate(expr) {
  const r = await send('Runtime.evaluate', { expression: `(async () => { ${expr} })()`, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) throw new Error(`${expr}\n→ ${r.exceptionDetails.exception?.description || r.exceptionDetails.text}`);
  return r.result.value;
}
async function shot(name) {
  const r = await send('Page.captureScreenshot', { format: 'png' });
  writeFileSync(`${out}/${name}.png`, Buffer.from(r.data, 'base64'));
}
const helpers = `
  const $ = (s) => document.querySelector(s);
  const $$ = (s) => [...document.querySelectorAll(s)];
  const wait = async (fn, ms = 4000) => { const t = Date.now(); while (Date.now() - t < ms) { const v = fn(); if (v) return v; await new Promise(r => setTimeout(r, 50)); } throw new Error('timeout waiting for ' + fn); };
  const button = (text, root = document) => [...root.querySelectorAll('button')].find(b => b.textContent.trim() === text);
  const click = (text, root) => { const b = button(text, root); if (!b) throw new Error('no button ' + text); b.click(); };
  const type = (el, v) => { el.value = v; el.dispatchEvent(new Event('input', { bubbles: true })); };
  const tick = () => new Promise(r => setTimeout(r, 30));
  const choose = (el, v) => { el.value = v; el.dispatchEvent(new Event('change', { bubbles: true })); };
`;
const step = async (name, body) => {
  try {
    const v = await evaluate(helpers + body);
    console.log(`✓ ${name}${v !== undefined ? ': ' + JSON.stringify(v) : ''}`);
  } catch (e) {
    console.log(`✘ ${name}: ${e.message.split('→').pop()}`);
    const page = await evaluate(`return document.querySelector('main')?.innerText.replace(/\\s+/g, ' ').slice(0, 400)`).catch(() => '');
    console.log(`  page: ${page}`);
    process.exitCode = 1;
  }
};

try {
  let target;
  for (let i = 0; i < 50 && !target; i++) {
    await sleep(100);
    target = await fetch('http://127.0.0.1:9333/json/new?about:blank', { method: 'PUT' }).then((r) => r.json()).catch(() => null);
  }
  ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((r) => ws.addEventListener('open', r));
  ws.addEventListener('message', (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id && pending.has(msg.id)) {
      const p = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? p.reject(new Error(msg.error.message)) : p.resolve(msg.result);
    } else if (msg.method === 'Runtime.exceptionThrown') {
      errors.push(msg.params.exceptionDetails.exception?.description || msg.params.exceptionDetails.text);
    } else if (msg.method === 'Runtime.consoleAPICalled' && msg.params.type === 'error') {
      errors.push(msg.params.args.map((a) => a.value ?? a.description).join(' '));
    }
  });
  await send('Runtime.enable');
  await send('Page.enable');
  await send('Page.navigate', { url: `${base}/#/zones` });
  await sleep(1500);

  await step('create zone', `
    click('New zone');
    const modal = await wait(() => $('.modal'));
    type(modal.querySelector('input'), 'test.lan');
    await tick(); modal.querySelector('form').requestSubmit();
    await wait(() => location.hash === '#/zones/test.lan');
    await wait(() => $('h2')?.textContent === 'test.lan');
    return location.hash;`);
  await step('add record', `
    click('Add record');
    const modal = await wait(() => $('.modal'));
    const inputs = modal.querySelectorAll('input');
    type(inputs[0], 'www');
    type(modal.querySelector('input.mono'), '10.1.2.3');
    await tick(); modal.querySelector('form').requestSubmit();
    await wait(() => !$('.modal'));
    return $$('table.records tbody tr').map(r => r.textContent.replace(/\\s+/g, ' ').trim());`);
  await step('invalid record shows error in modal', `
    click('Add record');
    const modal = await wait(() => $('.modal'));
    type(modal.querySelector('input'), 'bad');
    type(modal.querySelector('input.mono'), 'not-an-ip');
    await tick(); modal.querySelector('form').requestSubmit();
    const err = await wait(() => modal.querySelector('.alert.error'));
    return err.textContent;`);
  await shot('ui-record-error');
  await step('close modal with escape', `
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    await wait(() => !$('.modal'));`);
  await step('switch kind to transparent', `
    choose($('.btn-row select'), 'transparent');
    await wait(() => $('.page-head p')?.textContent.includes('Overrides'));`);
  await step('delete record', `
    const row = $$('table.records tbody tr').find(r => r.textContent.includes('www'));
    click('Delete', row);
    await wait(() => !$$('table.records tbody tr').some(r => r.textContent.includes('www')));`);

  await send('Page.navigate', { url: `${base}/#/filters` });
  await sleep(1200);
  await step('invalid custom rules list line errors', `
    const ta = await wait(() => $('textarea.rules'));
    type(ta, '||ok.example^\\n||bad domain^\\nexample.com$third-party');
    await tick(); click('Save rules');
    const errs = await wait(() => $('.line-errors'));
    return $$('.line-errors li').map(li => li.textContent);`);
  await shot('ui-rule-errors');
  await step('valid custom rules save', `
    type($('textarea.rules'), '||ok.example^\\n||tracker.example^');
    await tick(); click('Save rules');
    await wait(() => !$('.line-errors') && document.body.textContent.includes('Saved'));`);
  await step('check domain', `
    type($('.inline-form input'), 'a.tracker.example');
    await tick(); $('.inline-form').requestSubmit();
    return (await wait(() => $('.result'))).textContent;`);
  await step('change block mode', `
    $$('.segmented input')[1].click();
    await wait(() => $$('.segmented label')[1].classList.contains('active'));`);
  await step('add list modal', `
    click('Add list');
    const modal = await wait(() => $('.modal'));
    return [...modal.querySelectorAll('.chip')].map(c => c.textContent);`);
  await shot('ui-add-list');
  await evaluate(helpers + `window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));`);

  await send('Page.navigate', { url: `${base}/#/access` });
  await sleep(1200);
  await step('add client', `
    click('Add client');
    const modal = await wait(() => $('.modal'));
    type(modal.querySelector('input'), 'phone');
    await wait(() => modal.querySelector('.setup code'));
    return modal.querySelector('.setup code').textContent;`);
  await shot('ui-add-client');
  await step('save client', `
    await tick(); $('.modal form').requestSubmit();
    await wait(() => !$('.modal'));
    return $$('table tbody tr').map(r => r.querySelector('strong').textContent);`);

  await send('Page.navigate', { url: `${base}/#/tools` });
  await sleep(1000);
  await step('resolve', `
    type($('.inline-form input'), 'nas.home.lan');
    await tick(); $('form.panel').requestSubmit();
    await wait(() => $('.resolve'));
    return $('.resolve-head').textContent.replace(/\\s+/g, ' ');`);
  await shot('ui-resolve');

  await send('Page.navigate', { url: `${base}/#/querylog` });
  await sleep(1500);
  await step('query log block button', `
    const row = await wait(() => $$('tbody tr').find(r => button('Block', r)));
    click('Block', row);
    return (await wait(() => $('.alert.ok'))).textContent;`);

  console.log(errors.length ? `JS errors:\n  ${errors.join('\n  ')}` : 'no JS errors');
  if (errors.length) process.exitCode = 1;
} finally {
  ws?.close();
  chrome.kill();
}
