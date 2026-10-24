import { html, useEffect, useState } from '../lib/html.js';
import { useAction } from '../lib/hooks.js';
import { Page, Notice, Loading, Empty, Badge, Field, Modal, confirmDanger, toast } from '../lib/ui.js';
import { usePanel } from '../lib/panel.js';
import { useApi, useStatus, request, number, Link } from '../dns.js';
import { ago } from '../lib/format.js';

const BLOCK_MODES = {
  zero_ip: ['返回 0.0.0.0 / ::', '其它类型返回空应答'],
  nxdomain: ['返回 NXDOMAIN', '域名不存在'],
  refused: ['返回 REFUSED', '拒绝应答'],
};

const SUGGESTED = [
  { name: 'adguard-dns', url: 'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt' },
  { name: 'oisd-small', url: 'https://small.oisd.nl/' },
  { name: 'easylist-china', url: 'https://easylist-downloads.adblockplus.org/easylistchina.txt' },
];

export default function Filters() {
  const status = useStatus();
  if (status.data?.mode === 'authoritative') {
    return html`<${Page} title="过滤规则">
      <${Notice} tone="info">权威服务器不做过滤。需要拦截广告时，在<${Link} to="/settings">服务设置<//>中切换为转发解析。<//>
    <//>`;
  }
  return html`<${FilterPage} />`;
}

function FilterPage() {
  const { api } = usePanel();
  const filters = useApi('/filters', 15000);
  const action = useAction();
  const [form, setForm] = useState(null); // { isNew, list }
  const [current, setCurrent] = useState(null);
  const f = current || filters.data;

  const update = fn => action.run(async () => { setCurrent(await fn()); filters.reload(); });
  const setBlockMode = mode => update(async () => { await api.put('/filters/block_mode', { block_mode: mode }); return null; });
  const listPath = l => `/filters/lists/${encodeURIComponent(l.name)}`;
  const toggle = l => update(() => api.put(listPath(l), { ...strip(l), enabled: !l.enabled }));
  const refresh = l => update(() => api.post(listPath(l) + '/refresh'));
  const remove = l => confirmDanger(`删除列表 ${l.name}？`) && update(() => api.del(listPath(l)));

  return html`<${Page} title="过滤规则"
    subtitle=${html`AdBlock 风格的 DNS 规则：<code>||ads.example^</code> 拦截域名及其子域名，<code>@@||ok.example^</code> 放行，<code>$important</code> 优先于放行。`}>
    <${Notice} error=${filters.error || (!form && action.error)} />
    ${!f ? (filters.error ? null : html`<${Loading} />`) : html`
      <${CheckDomain} />
      <div class="card section">
        <h2>拦截方式</h2>
        <div class="choices">${Object.entries(BLOCK_MODES).map(([k, [label, hint]]) => html`<label class="choice" key=${k}>
          <input type="radio" name="block_mode" checked=${f.block_mode === k} disabled=${action.busy} onChange=${() => setBlockMode(k)} />
          <span><strong>${label}</strong><span class="field-hint">${hint}</span></span>
        </label>`)}</div>
      </div>
      <section class="section">
        <div class="card-head">
          <h2>订阅列表</h2>
          <button class="btn btn-primary" onClick=${() => setForm({ isNew: true, list: { name: '', kind: 'block', url: '', file: '', refresh: '24h', enabled: true } })}>添加列表</button>
        </div>
        ${f.lists.length === 0 ? html`<${Empty}>还没有列表。添加一个即可在整个网络拦截广告和跟踪器。<//>` : html`
          <div class="table-wrap"><table class="table">
            <thead><tr><th>列表</th><th>类型</th><th class="num">规则</th><th>更新</th><th class="actions"></th></tr></thead>
            <tbody>${f.lists.map(l => html`<tr key=${l.name} class=${l.enabled ? '' : 'row-disabled'}>
              <td>
                <label class="check"><input type="checkbox" checked=${l.enabled} disabled=${action.busy} onChange=${() => toggle(l)} />
                  <span class="cell-main">${l.name}</span></label>
                <div class="cell-sub truncate" style="max-width:420px" title=${l.url || l.file}>${l.url || l.file}</div>
                ${l.status?.error ? html`<div class="small text-error">${l.status.error}</div>` : null}
              </td>
              <td><${Badge} tone=${l.kind === 'allow' ? 'green' : 'gray'}>${l.kind === 'allow' ? '放行' : '拦截'}<//></td>
              <td class="num">${l.status ? number(l.status.rules) : '—'}</td>
              <td class="nowrap muted">${l.status?.updated_at ? ago(l.status.updated_at) : '—'}</td>
              <td class="actions"><span class="btn-group">
                <button class="btn btn-sm" disabled=${action.busy || !l.enabled} onClick=${() => refresh(l)}>刷新</button>
                <button class="btn btn-sm" onClick=${() => setForm({ isNew: false, list: { ...l, refresh: l.refresh || '' } })}>编辑</button>
                <button class="btn btn-sm btn-danger" disabled=${action.busy} onClick=${() => remove(l)}>删除</button>
              </span></td>
            </tr>`)}</tbody>
          </table></div>`}
      </section>
      <${CustomRules} rules=${f.rules} onSaved=${filters.reload} />`}
    ${form ? html`<${ListForm} ...${form} busy=${action.busy} error=${action.error}
      onClose=${() => { setForm(null); action.setError(null); }}
      onSave=${async l => {
        const saved = await action.run(() => (form.isNew ? api.post('/filters/lists', strip(l)) : api.put(listPath(l), strip(l))));
        if (saved) { setCurrent(saved); setForm(null); filters.reload(); }
      }} />` : null}
  <//>`;
}

// strip keeps only the fields the API accepts for a list.
function strip(l) {
  const out = { name: l.name, kind: l.kind, enabled: l.enabled, refresh: l.refresh || '' };
  if (l.url) out.url = l.url;
  if (l.file) out.file = l.file;
  return out;
}

function ListForm({ isNew, list, busy, error, onSave, onClose }) {
  const [l, setL] = useState(list);
  const [source, setSource] = useState(list.file ? 'file' : 'url');
  const set = key => e => { const value = e.currentTarget.value; setL(prev => ({ ...prev, [key]: value })); };
  const submit = e => {
    e.preventDefault();
    onSave(source === 'url' ? { ...l, file: '' } : { ...l, url: '' });
  };
  return html`<${Modal} title=${isNew ? '添加过滤列表' : `编辑 ${l.name}`} onClose=${onClose} footer=${html`
    <span class="spacer"></span>
    <button class="btn" type="button" onClick=${onClose}>取消</button>
    <button class="btn btn-primary" type="submit" form="list-form" disabled=${busy}>${isNew ? '添加' : '保存'}</button>`}>
    <form id="list-form" class="form" onSubmit=${submit}>
      <${Notice} error=${error} />
      ${isNew ? html`<div class="chips"><span class="muted small">常用：</span>
        ${SUGGESTED.map(s => html`<button type="button" class="btn btn-sm" key=${s.name} onClick=${() => { setL(prev => ({ ...prev, ...s })); setSource('url'); }}>${s.name}</button>`)}
      </div>` : null}
      <${Field} label="名称" required>
        <input class="input" required disabled=${!isNew} value=${l.name} onInput=${set('name')} pattern="[^/]+" />
      <//>
      <div class="form-grid">
        <${Field} label="来源">
          <select class="input" value=${source} onChange=${e => setSource(e.currentTarget.value)}>
            <option value="url">URL</option><option value="file">服务器上的文件</option>
          </select>
        <//>
        <${Field} label=${source === 'url' ? 'URL' : '文件路径'} required>
          ${source === 'url'
            ? html`<input class="input" type="url" required value=${l.url || ''} onInput=${set('url')} placeholder="https://…" />`
            : html`<input class="input mono" required value=${l.file || ''} onInput=${set('file')} placeholder="/etc/dns-go/list.txt" />`}
        <//>
        <${Field} label="类型">
          <select class="input" value=${l.kind} onChange=${set('kind')}>
            <option value="block">拦截</option><option value="allow">放行（每条规则都是例外）</option>
          </select>
        <//>
        <${Field} label="刷新间隔" hint="Go 时长，例如 24h">
          <input class="input" value=${l.refresh} onInput=${set('refresh')} placeholder=${source === 'url' ? '24h' : '不刷新'} />
        <//>
      </div>
    </form>
  <//>`;
}

function CustomRules({ rules, onSaved }) {
  const { client } = usePanel();
  const [text, setText] = useState(rules.join('\n'));
  const [dirty, setDirty] = useState(false);
  const action = useAction();
  useEffect(() => { if (!dirty) setText(rules.join('\n')); }, [rules.join('\n')]);
  const save = () => action.run(async () => {
    await request(client, 'PUT', '/filters/rules', { rules: text.split('\n') });
    setDirty(false);
    toast('规则已保存', 'success');
    onSaved();
  });
  const lineErrors = action.error?.details || [];
  return html`<div class="card section">
    <div class="card-head">
      <h2>自定义规则</h2>
      <button class="btn btn-primary" disabled=${!dirty || action.busy} onClick=${save}>保存规则</button>
    </div>
    <textarea class="input" rows="10" spellcheck="false" value=${text}
      placeholder=${'||ads.example.com^\n@@||allowed.example.com^'}
      onInput=${e => { setText(e.currentTarget.value); setDirty(true); }} />
    ${lineErrors.length
      ? html`<ul class="line-errors">${lineErrors.map(e => html`<li key=${e.line}>第 ${e.line} 行：<code>${e.rule}</code> — ${e.error}</li>`)}</ul>`
      : html`<div style="margin-top:10px"><${Notice} error=${action.error} /></div>`}
  </div>`;
}

function CheckDomain() {
  const { api } = usePanel();
  const [name, setName] = useState('');
  const [result, setResult] = useState(null);
  const action = useAction();
  const check = e => {
    e.preventDefault();
    action.run(async () => {
      const r = await api.get('/filters/check', { query: { name: name.trim() } });
      setResult({ ...r, name: name.trim() });
    });
  };
  const verdict = { block: ['拦截', 'red'], allow: ['放行', 'green'], pass: ['未命中', 'gray'] };
  return html`<form class="card" onSubmit=${check}>
    <h2>检查域名</h2>
    <div class="inline-form">
      <input class="input mono" required placeholder="ads.example.com" value=${name} onInput=${e => setName(e.currentTarget.value)} aria-label="域名" />
      <button class="btn" disabled=${action.busy}>检查</button>
    </div>
    ${result ? html`<div class="result" style="margin-top:12px">
      <span class="mono">${result.name}</span>
      <${Badge} tone=${verdict[result.action]?.[1] || 'gray'}>${verdict[result.action]?.[0] || result.action}<//>
      ${result.rule ? html`<code>${result.rule}</code> <span class="tag">${result.list}</span>` : null}
    </div>` : null}
    <div style="margin-top:10px"><${Notice} error=${action.error} /></div>
  </form>`;
}
