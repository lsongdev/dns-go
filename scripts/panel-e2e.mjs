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
    click('新建区域');
    const modal = await wait(() => $('.modal'));
    type(modal.querySelector('input'), 'test.lan');
    await tick(); $('#create-zone').requestSubmit();
    await wait(() => location.hash === '#/zones/test.lan');
    await wait(() => $('h1')?.textContent === 'test.lan');
    return location.hash;`);
  await step('add record', `
    click('添加记录');
    const modal = await wait(() => $('.modal'));
    const inputs = modal.querySelectorAll('input');
    type(inputs[0], 'www');
    type(inputs[inputs.length - 1], '10.1.2.3');
    await tick(); $('#record-form').requestSubmit();
    await wait(() => !$('.modal'));
    return $$('table tbody tr').map(r => r.textContent.replace(/\\s+/g, ' ').trim());`);
  await step('invalid record shows error in modal', `
    click('添加记录');
    const modal = await wait(() => $('.modal'));
    const inputs = modal.querySelectorAll('input');
    type(inputs[0], 'bad');
    type(inputs[inputs.length - 1], 'not-an-ip');
    await tick(); $('#record-form').requestSubmit();
    const err = await wait(() => modal.querySelector('.notice-error'));
    return err.textContent.trim();`);
  await shot('ui-record-error');
  await step('close modal with escape', `
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    await wait(() => !$('.modal'));`);
  await step('switch kind to transparent', `
    choose($('.page-actions select'), 'transparent');
    await wait(() => $('.page-subtitle')?.textContent.includes('只覆盖'));`);
  await step('delete record', `
    const row = $$('table tbody tr').find(r => r.textContent.includes('www'));
    click('删除', row);
    await wait(() => !$$('table tbody tr').some(r => r.textContent.includes('www')));`);

  await send('Page.navigate', { url: `${base}/#/filters` });
  await sleep(1200);
  await step('invalid custom rules list line errors', `
    const ta = await wait(() => $('textarea'));
    type(ta, '||ok.example^\\n||bad domain^\\nexample.com$third-party');
    await tick(); click('保存规则');
    await wait(() => $('.line-errors'));
    return $$('.line-errors li').map(li => li.textContent);`);
  await shot('ui-rule-errors');
  await step('valid custom rules save', `
    type($('textarea'), '||ok.example^\\n||tracker.example^');
    await tick(); click('保存规则');
    await wait(() => !$('.line-errors') && $('.toast')?.textContent.includes('已保存'));`);
  await step('check domain', `
    type($('.inline-form input'), 'a.tracker.example');
    await tick(); $('.inline-form').closest('form').requestSubmit();
    return (await wait(() => $('.result'))).textContent.replace(/\\s+/g, ' ').trim();`);
  await step('change block mode', `
    $$('input[name=block_mode]')[1].click();
    await new Promise(r => setTimeout(r, 500));
    await wait(() => $$('input[name=block_mode]')[1].checked);`);
  await step('add list modal', `
    click('添加列表');
    const modal = await wait(() => $('.modal'));
    return [...modal.querySelectorAll('.chips button')].map(c => c.textContent);`);
  await shot('ui-add-list');
  await evaluate(helpers + `window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));`);

  await send('Page.navigate', { url: `${base}/#/clients` });
  await sleep(1200);
  await step('add client', `
    click('添加客户端');
    const modal = await wait(() => $('.modal'));
    type(modal.querySelector('input'), 'phone');
    await wait(() => modal.querySelector('.setup code'));
    return modal.querySelector('.setup code').textContent;`);
  await shot('ui-add-client');
  await step('save client', `
    await tick(); $('#client-form').requestSubmit();
    await wait(() => !$('.modal'));
    return $$('table tbody tr .cell-main').map(c => c.textContent);`);

  await send('Page.navigate', { url: `${base}/#/tools` });
  await sleep(1000);
  await step('resolve', `
    type($('.inline-form input'), 'nas.home.lan');
    await tick(); $('.inline-form').closest('form').requestSubmit();
    return (await wait(() => $('.result'))).textContent.replace(/\\s+/g, ' ').trim();`);
  await shot('ui-resolve');

  await send('Page.navigate', { url: `${base}/#/settings` });
  await sleep(1000);
  await step('settings add upstream and save', `
    const count = $$('.spec-row').length;
    click('添加上游');
    const rows = await wait(() => $$('.spec-row').length > count && $$('.spec-row'));
    const last = rows[rows.length - 1];
    type(last.querySelector('input'), '119.29.29.29:53');
    await tick(); click('保存并应用');
    await wait(() => $('.toast')?.textContent.includes('已生效'));
    return $$('.spec-row input.mono').map(i => i.value);`);
  await shot('ui-settings');

  await send('Page.navigate', { url: `${base}/#/querylog` });
  await sleep(1500);
  await step('query log block button', `
    const row = await wait(() => $$('tbody tr').find(r => button('拦截', r)));
    click('拦截', row);
    return (await wait(() => $$('.toast').find(t => t.textContent.includes('已添加规则')))).textContent;`);

  console.log(errors.length ? `JS errors:\n  ${errors.join('\n  ')}` : 'no JS errors');
  if (errors.length) process.exitCode = 1;
} finally {
  ws?.close();
  chrome.kill();
}
