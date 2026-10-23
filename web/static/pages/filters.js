import { useState, useEffect } from '../vendor/hooks.js';
import { html, api, useApi, useAction, fmtNumber, fmtAgo, ErrorBox, Loading, Empty, Modal } from '../lib.js';

const BLOCK_MODES = {
  zero_ip: 'Answer 0.0.0.0 / :: (other types empty)',
  nxdomain: 'Answer NXDOMAIN',
  refused: 'Answer REFUSED',
};

const SUGGESTED = [
  { name: 'adguard-dns', url: 'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt' },
  { name: 'oisd-small', url: 'https://small.oisd.nl/' },
  { name: 'easylist-china', url: 'https://easylist-downloads.adblockplus.org/easylistchina.txt' },
];

export function Filters() {
  const filters = useApi('/filters', { interval: 15000 });
  const action = useAction();
  const [listForm, setListForm] = useState(null);
  const f = filters.data;

  const setBlockMode = async (mode) => {
    await action.run(() => api('PUT', '/filters/block_mode', { block_mode: mode })).catch(() => {});
    filters.reload();
  };
  const listAction = async (fn) => {
    const updated = await action.run(fn).catch(() => null);
    if (updated) filters.setData(updated);
    else filters.reload();
  };
  const toggle = (l) => listAction(() => api('PUT', `/filters/lists/${encodeURIComponent(l.name)}`, { ...strip(l), enabled: !l.enabled }));
  const refresh = (l) => listAction(() => api('POST', `/filters/lists/${encodeURIComponent(l.name)}/refresh`));
  const remove = (l) => confirm(`Remove list ${l.name}?`) && listAction(() => api('DELETE', `/filters/lists/${encodeURIComponent(l.name)}`));

  return html`
    <section class="page">
      <header class="page-head"><h2>Filters</h2>
        <p class="muted">AdBlock-style DNS rules: <code>||ads.example^</code> blocks a domain and its subdomains, <code>@@||ok.example^</code> allows it, <code>$important</code> overrides allows.</p>
      </header>
      <${ErrorBox} error=${filters.error || (!listForm && action.error)} />
      ${!f ? html`<${Loading} />` : html`
        <${CheckDomain} />
        <div class="panel">
          <h3>Blocked queries</h3>
          <div class="segmented" role="radiogroup" aria-label="Block mode">
            ${Object.entries(BLOCK_MODES).map(([k, label]) => html`
              <label class=${f.block_mode === k ? 'active' : ''}>
                <input type="radio" name="block_mode" checked=${f.block_mode === k} onChange=${() => setBlockMode(k)} />${label}
              </label>`)}
          </div>
        </div>
        <div class="panel">
          <div class="panel-head">
            <h3>Subscriptions</h3>
            <button class="primary" onClick=${() => setListForm({ isNew: true, list: { name: '', kind: 'block', url: '', refresh: '24h', enabled: true } })}>Add list</button>
          </div>
          ${f.lists.length === 0 ? html`<${Empty}>No lists. Add one to block ads and trackers network-wide.</${Empty}>` : html`
            <div class="table-wrap"><table class="table">
              <thead><tr><th>List</th><th>Kind</th><th class="num">Rules</th><th>Updated</th><th></th></tr></thead>
              <tbody>
                ${f.lists.map((l) => html`
                  <tr class=${l.enabled ? '' : 'row-disabled'}>
                    <td>
                      <label class="switch" title=${l.enabled ? 'Enabled' : 'Disabled'}>
                        <input type="checkbox" checked=${l.enabled} disabled=${action.busy} onChange=${() => toggle(l)} /><span></span>
                      </label>
                      <strong>${l.name}</strong>
                      <div class="small muted ellipsis" title=${l.url || l.file}>${l.url || l.file}</div>
                      ${l.status?.error && html`<div class="small text-error">${l.status.error}</div>`}
                    </td>
                    <td><span class=${`badge kind-${l.kind}`}>${l.kind}</span></td>
                    <td class="num">${l.status ? fmtNumber(l.status.rules) : '–'}</td>
                    <td class="nowrap muted">${l.status ? fmtAgo(l.status.updated_at) : '–'}</td>
                    <td class="actions nowrap">
                      <button class="small" disabled=${action.busy || !l.enabled} onClick=${() => refresh(l)}>Refresh</button>
                      <button class="small" onClick=${() => setListForm({ isNew: false, list: { ...l, refresh: l.refresh || '' } })}>Edit</button>
                      <button class="small danger" disabled=${action.busy} onClick=${() => remove(l)}>Remove</button>
                    </td>
                  </tr>`)}
              </tbody>
            </table></div>`}
        </div>
        <${CustomRules} rules=${f.rules} onSaved=${filters.reload} />`}
      ${listForm && html`<${ListForm} ...${listForm} busy=${action.busy} error=${action.error}
          onClose=${() => { setListForm(null); action.setError(null); }}
          onSave=${async (l) => {
            const path = listForm.isNew ? '/filters/lists' : `/filters/lists/${encodeURIComponent(l.name)}`;
            const updated = await action.run(() => api(listForm.isNew ? 'POST' : 'PUT', path, strip(l))).catch(() => null);
            if (updated) { filters.setData(updated); setListForm(null); }
          }} />`}
    </section>`;
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
  const set = (k) => (e) => {
    const v = e.target.value;
    setL((prev) => ({ ...prev, [k]: v }));
  };
  const submit = (e) => {
    e.preventDefault();
    onSave(source === 'url' ? { ...l, file: '' } : { ...l, url: '' });
  };
  return html`
    <${Modal} title=${isNew ? 'Add filter list' : `Edit ${l.name}`} onClose=${onClose}>
      <form class="form" onSubmit=${submit}>
        ${isNew && html`<div class="chips"><span class="muted small">Popular:</span>
          ${SUGGESTED.map((s) => html`<button type="button" class="chip" onClick=${() => { setL((prev) => ({ ...prev, ...s })); setSource('url'); }}>${s.name}</button>`)}
        </div>`}
        <label>Name<input required disabled=${!isNew} value=${l.name} onInput=${set('name')} pattern="[^/]+" /></label>
        <div class="form-row">
          <label>Source<select value=${source} onChange=${(e) => setSource(e.target.value)}>
            <option value="url">URL</option><option value="file">Local file</option></select></label>
          <label class="grow">${source === 'url' ? 'URL' : 'Path on the server'}
            ${source === 'url'
              ? html`<input type="url" required value=${l.url || ''} onInput=${set('url')} placeholder="https://…" />`
              : html`<input required value=${l.file || ''} onInput=${set('file')} placeholder="/etc/dns-go/list.txt" />`}
          </label>
        </div>
        <div class="form-row">
          <label>Kind<select value=${l.kind} onChange=${set('kind')}>
            <option value="block">block</option><option value="allow">allow (every rule is an exception)</option></select></label>
          <label>Refresh<input value=${l.refresh} onInput=${set('refresh')} placeholder=${source === 'url' ? '24h' : 'never'} /></label>
        </div>
        <${ErrorBox} error=${error} />
        <footer><button type="button" onClick=${onClose}>Cancel</button><button class="primary" disabled=${busy}>${isNew ? 'Add' : 'Save'}</button></footer>
      </form>
    </${Modal}>`;
}

function CustomRules({ rules, onSaved }) {
  const [text, setText] = useState(rules.join('\n'));
  const [dirty, setDirty] = useState(false);
  const [saved, setSaved] = useState(false);
  const action = useAction();
  useEffect(() => { if (!dirty) setText(rules.join('\n')); }, [rules.join('\n')]);
  const save = async () => {
    setSaved(false);
    await action.run(() => api('PUT', '/filters/rules', { rules: text.split('\n') })).catch(() => null);
    setDirty(false);
    setSaved(true);
    onSaved();
  };
  const lineErrors = action.error?.details || [];
  return html`
    <div class="panel">
      <div class="panel-head">
        <h3>Custom rules</h3>
        <div class="btn-row">
          ${saved && !dirty && html`<span class="muted small">Saved</span>`}
          <button class="primary" disabled=${!dirty || action.busy} onClick=${save}>Save rules</button>
        </div>
      </div>
      <textarea class="mono rules" rows="10" spellcheck="false" value=${text}
        placeholder=${'||ads.example.com^\n@@||allowed.example.com^'}
        onInput=${(e) => { setText(e.target.value); setDirty(true); setSaved(false); }} />
      ${lineErrors.length > 0
        ? html`<ul class="alert error line-errors">${lineErrors.map((e) => html`<li>Line ${e.line}: <code>${e.rule}</code> — ${e.error}</li>`)}</ul>`
        : html`<${ErrorBox} error=${action.error} />`}
    </div>`;
}

function CheckDomain() {
  const [name, setName] = useState('');
  const [result, setResult] = useState(null);
  const action = useAction();
  const check = async (e) => {
    e.preventDefault();
    const r = await action.run(() => api('GET', `/filters/check?name=${encodeURIComponent(name.trim())}`)).catch(() => null);
    setResult(r && { ...r, name: name.trim() });
  };
  return html`
    <form class="panel inline-form" onSubmit=${check}>
      <input type="text" required placeholder="Check a domain, e.g. ads.example.com" value=${name} onInput=${(e) => setName(e.target.value)} aria-label="Domain" />
      <button disabled=${action.busy}>Check</button>
      ${result && html`<span class=${`result action-${result.action}`}>
        <strong>${result.name}</strong> → ${result.action}
        ${result.rule && html` by <code>${result.rule}</code> <span class="tag">${result.list}</span>`}
      </span>`}
      <${ErrorBox} error=${action.error} />
    </form>`;
}
