import { html, useEffect, useState } from '../lib/html.js';
import { useAction } from '../lib/hooks.js';
import { Page, Notice, Loading, Empty, Badge, Field, Modal, confirmDanger, toast, Table } from '../lib/ui.js';
import { usePanel } from '../lib/panel.js';
import { useApi, useStatus, request, number, Link } from '../dns.js';
import { ago } from '../lib/format.js';

const BLOCK_MODES = {
  zero_ip: ['Answer 0.0.0.0 / ::', 'Empty answers for other types'],
  nxdomain: ['Answer NXDOMAIN', 'The name does not exist'],
  refused: ['Answer REFUSED', 'Refuse to answer'],
};

const SUGGESTED = [
  { name: 'adguard-dns', url: 'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt' },
  { name: 'oisd-small', url: 'https://small.oisd.nl/' },
  { name: 'easylist-china', url: 'https://easylist-downloads.adblockplus.org/easylistchina.txt' },
];

export default function Filters() {
  const status = useStatus();
  if (status.data?.mode === 'authoritative') {
    return html`<${Page} title="Filters">
      <${Notice} tone="info">An authoritative server does not filter. To block ads, switch to forwarding in <${Link} to="/settings">Settings<//>.<//>
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
  const remove = l => confirmDanger(`Delete the list ${l.name}?`) && update(() => api.del(listPath(l)));

  return html`<${Page} title="Filters"
    subtitle=${html`AdBlock-style DNS rules: <code>||ads.example^</code> blocks a name and its subdomains, <code>@@||ok.example^</code> allows, and <code>$important</code> wins over allowing.`}>
    <${Notice} error=${filters.error || (!form && action.error)} />
    ${!f ? (filters.error ? null : html`<${Loading} />`) : html`
      <${CheckDomain} />
      <div class="card section">
        <h2>Blocking</h2>
        <div class="choices">${Object.entries(BLOCK_MODES).map(([k, [label, hint]]) => html`<label class="choice" key=${k}>
          <input type="radio" name="block_mode" checked=${f.block_mode === k} disabled=${action.busy} onChange=${() => setBlockMode(k)} />
          <span><strong>${label}</strong><span class="field-hint">${hint}</span></span>
        </label>`)}</div>
      </div>
      <section class="section">
        <div class="card-head">
          <h2>Lists</h2>
          <button class="button button-primary" onClick=${() => setForm({ isNew: true, list: { name: '', kind: 'block', url: '', file: '', refresh: '24h', enabled: true } })}>Add list</button>
        </div>
        ${f.lists.length === 0 ? html`<${Empty}>No lists yet. Add one to block ads and trackers across the network.<//>` : html`
          <${Table}>
            <thead><tr><th>List</th><th>Kind</th><th class="num">Rules</th><th>Updated</th><th class="actions"></th></tr></thead>
            <tbody>${f.lists.map(l => html`<tr key=${l.name} class=${l.enabled ? '' : 'row-disabled'}>
              <td>
                <label class="field-check"><input type="checkbox" checked=${l.enabled} disabled=${action.busy} onChange=${() => toggle(l)} />
                  <span class="cell-main">${l.name}</span></label>
                <div class="cell-sub truncate" style="max-width:420px" title=${l.url || l.file}>${l.url || l.file}</div>
                ${l.status?.error ? html`<div class="small text-error">${l.status.error}</div>` : null}
              </td>
              <td><${Badge} tone=${l.kind === 'allow' ? 'green' : 'gray'}>${l.kind === 'allow' ? 'Allow' : 'Block'}<//></td>
              <td class="num">${l.status ? number(l.status.rules) : '—'}</td>
              <td class="nowrap muted">${l.status?.updated_at ? ago(l.status.updated_at) : '—'}</td>
              <td class="actions"><span class="button-row">
                <button class="button button-small" disabled=${action.busy || !l.enabled} onClick=${() => refresh(l)}>Refresh</button>
                <button class="button button-small" onClick=${() => setForm({ isNew: false, list: { ...l, refresh: l.refresh || '' } })}>Edit</button>
                <button class="button button-small button-danger" disabled=${action.busy} onClick=${() => remove(l)}>Delete</button>
              </span></td>
            </tr>`)}</tbody>
          <//>`}
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
  return html`<${Modal} title=${isNew ? 'Add list' : `Edit ${l.name}`} onClose=${onClose} footer=${html`
    <span class="spacer"></span>
    <button class="button" type="button" onClick=${onClose}>Cancel</button>
    <button class="button button-primary" type="submit" form="list-form" disabled=${busy}>${isNew ? 'Add' : 'Save'}</button>`}>
    <form id="list-form" class="form" onSubmit=${submit}>
      <${Notice} error=${error} />
      ${isNew ? html`<div class="chips"><span class="muted small">Popular:</span>
        ${SUGGESTED.map(s => html`<button type="button" class="button button-small" key=${s.name} onClick=${() => { setL(prev => ({ ...prev, ...s })); setSource('url'); }}>${s.name}</button>`)}
      </div>` : null}
      <${Field} label="Name" required>
        <input class="input" required disabled=${!isNew} value=${l.name} onInput=${set('name')} pattern="[^/]+" />
      <//>
      <div class="form-grid">
        <${Field} label="Source">
          <select class="input" value=${source} onChange=${e => setSource(e.currentTarget.value)}>
            <option value="url">URL</option><option value="file">A file on the server</option>
          </select>
        <//>
        <${Field} label=${source === 'url' ? 'URL' : 'File path'} required>
          ${source === 'url'
            ? html`<input class="input" type="url" required value=${l.url || ''} onInput=${set('url')} placeholder="https://…" />`
            : html`<input class="input mono" required value=${l.file || ''} onInput=${set('file')} placeholder="/etc/dns-go/list.txt" />`}
        <//>
        <${Field} label="Kind">
          <select class="input" value=${l.kind} onChange=${set('kind')}>
            <option value="block">Block</option><option value="allow">Allow (every rule is an exception)</option>
          </select>
        <//>
        <${Field} label="Refresh every" hint="A Go duration, such as 24h">
          <input class="input" value=${l.refresh} onInput=${set('refresh')} placeholder=${source === 'url' ? '24h' : 'Never'} />
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
    toast('Rules saved', 'success');
    onSaved();
  });
  const lineErrors = action.error?.details || [];
  return html`<div class="card section">
    <div class="card-head">
      <h2>Custom rules</h2>
      <button class="button button-primary" disabled=${!dirty || action.busy} onClick=${save}>Save rules</button>
    </div>
    <textarea class="input" rows="10" spellcheck="false" value=${text}
      placeholder=${'||ads.example.com^\n@@||allowed.example.com^'}
      onInput=${e => { setText(e.currentTarget.value); setDirty(true); }} />
    ${lineErrors.length
      ? html`<ul class="line-errors">${lineErrors.map(e => html`<li key=${e.line}>Line ${e.line}: <code>${e.rule}</code> — ${e.error}</li>`)}</ul>`
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
  const verdict = { block: ['Blocked', 'red'], allow: ['Allowed', 'green'], pass: ['No match', 'gray'] };
  return html`<form class="card" onSubmit=${check}>
    <h2>Check a name</h2>
    <div class="inline-form">
      <input class="input mono" required placeholder="ads.example.com" value=${name} onInput=${e => setName(e.currentTarget.value)} aria-label="Name" />
      <button class="button" disabled=${action.busy}>Check</button>
    </div>
    ${result ? html`<div class="result" style="margin-top:12px">
      <span class="mono">${result.name}</span>
      <${Badge} tone=${verdict[result.action]?.[1] || 'gray'}>${verdict[result.action]?.[0] || result.action}<//>
      ${result.rule ? html`<code>${result.rule}</code> <span class="tag">${result.list}</span>` : null}
    </div>` : null}
    <div style="margin-top:10px"><${Notice} error=${action.error} /></div>
  </form>`;
}
