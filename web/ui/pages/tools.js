import { html, useState } from '../lib/html.js';
import { useAction } from '../lib/hooks.js';
import { Page, Notice, Badge, toast, Table } from '../lib/ui.js';
import { usePanel } from '../lib/panel.js';
import { useStatus, SourceBadge, micros, number } from '../dns.js';

const TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'HTTPS', 'SRV', 'PTR', 'CAA', 'DS', 'DNSKEY', 'ANY'];

export default function Tools() {
  const { api } = usePanel();
  const status = useStatus();
  const [q, setQ] = useState({ name: '', type: 'A', do: false });
  const [result, setResult] = useState(null);
  const action = useAction();
  const flush = useAction();
  const set = patch => setQ(p => ({ ...p, ...patch }));

  const resolve = e => {
    e.preventDefault();
    action.run(async () => {
      const r = await api.post('/resolve', { ...q, name: q.name.trim() });
      setResult({ ...r, query: { ...q } });
    });
  };
  const flushCache = () => flush.run(async () => {
    await api.del('/cache');
    toast('Cache flushed', 'success');
    status.reload();
  });

  return html`<${Page} title="Tools">
    <form class="card" onSubmit=${resolve}>
      <h2>Test a query</h2>
      <p class="muted" style="margin-top:0">Resolved like a client query, through zones, filters, cache and upstreams (skipping access control).</p>
      <div class="inline-form">
        <input class="input mono" required placeholder="example.com" value=${q.name} onInput=${e => set({ name: e.currentTarget.value })} aria-label="Name" />
        <select class="input" value=${q.type} onChange=${e => set({ type: e.currentTarget.value })} aria-label="Type">
          ${TYPES.map(t => html`<option>${t}</option>`)}
        </select>
        <label class="field-check"><input type="checkbox" checked=${q.do} onChange=${e => set({ do: e.currentTarget.checked })} />DNSSEC</label>
        <button class="button button-primary" disabled=${action.busy}>Resolve</button>
      </div>
      <div style="margin-top:12px"><${Notice} error=${action.error} /></div>
      ${result ? html`<${ResolveResult} r=${result} />` : null}
    </form>
    ${status.data?.cache ? html`<div class="card section">
      <div class="card-head">
        <div><h2>Cache</h2><span class="muted">${number(status.data.cache.entries)} entries</span></div>
        <button class="button button-danger" disabled=${flush.busy} onClick=${flushCache}>Flush cache</button>
      </div>
      <${Notice} error=${flush.error} />
    </div>` : null}
  <//>`;
}

function ResolveResult({ r }) {
  const sections = [['Answer', r.answers], ['Authority', r.authorities], ['Additional', r.additionals]].filter(([, rs]) => rs.length);
  return html`<div class="section">
    <div class="result">
      <strong class="mono">${r.query.name}</strong> ${r.query.type}
      <${Badge} tone=${r.rcode === 'NOERROR' ? 'green' : 'amber'}>${r.rcode}<//>
      <${SourceBadge} source=${r.source} />
      ${r.flags.map(f => html`<span class="tag" key=${f}>${f}</span>`)}
      <span class="muted small">${micros(r.duration_us)}</span>
    </div>
    ${r.filter ? html`<p class="small">Filter: ${r.filter.action}, rule <code>${r.filter.rule}</code> <span class="tag">${r.filter.list}</span></p>` : null}
    ${r.error ? html`<p class="small text-error">${r.error}</p>` : null}
    ${sections.length === 0 ? html`<p class="muted small">No records.</p>` : sections.map(([title, records]) => html`
      <h3 class="small muted" style="margin:14px 0 6px">${title}</h3>
      <${Table}>
        <tbody>${records.map((rec, i) => html`<tr key=${i}>
          <td class="mono">${rec.name}</td><td class="num muted">${rec.ttl}</td><td><${Badge}>${rec.type}<//></td><td class="mono data">${rec.data}</td>
        </tr>`)}</tbody>
      <//>`)}
  </div>`;
}
