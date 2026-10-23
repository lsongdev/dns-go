import { useState } from '../vendor/hooks.js';
import { html, api, useAction, fmtMicros, ErrorBox, SourceBadge } from '../lib.js';

const TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'HTTPS', 'SRV', 'PTR', 'CAA', 'DS', 'DNSKEY', 'ANY'];

export function Tools({ status }) {
  const [q, setQ] = useState({ name: '', type: 'A', do: false });
  const [result, setResult] = useState(null);
  const action = useAction();
  const flush = useAction();
  const [flushed, setFlushed] = useState(false);

  const resolve = async (e) => {
    e.preventDefault();
    const r = await action.run(() => api('POST', '/resolve', { ...q, name: q.name.trim() })).catch(() => null);
    setResult(r && { ...r, query: { ...q } });
  };

  return html`
    <section class="page">
      <header class="page-head"><h2>Tools</h2></header>
      <form class="panel" onSubmit=${resolve}>
        <h3>Test a query</h3>
        <p class="muted small">Runs through zones, filters, cache and upstreams exactly like a client query (access control is skipped).</p>
        <div class="inline-form">
          <input required placeholder="example.com" value=${q.name} onInput=${(e) => { const name = e.target.value; setQ((p) => ({ ...p, name })); }} aria-label="Name" />
          <select value=${q.type} onChange=${(e) => { const type = e.target.value; setQ((p) => ({ ...p, type })); }} aria-label="Type">
            ${TYPES.map((t) => html`<option>${t}</option>`)}
          </select>
          <label class="check"><input type="checkbox" checked=${q.do} onChange=${(e) => { const on = e.target.checked; setQ((p) => ({ ...p, do: on })); }} /> DNSSEC</label>
          <button class="primary" disabled=${action.busy}>Resolve</button>
        </div>
        <${ErrorBox} error=${action.error} />
        ${result && html`<${ResolveResult} r=${result} />`}
      </form>
      ${status.cache && html`
        <div class="panel">
          <div class="panel-head">
            <div><h3>Cache</h3><p class="muted small">${status.cache.entries} ${status.cache.entries === 1 ? 'entry' : 'entries'}</p></div>
            <div class="btn-row">
              ${flushed && html`<span class="muted small">Flushed</span>`}
              <button class="danger" disabled=${flush.busy} onClick=${async () => { await flush.run(() => api('DELETE', '/cache')).catch(() => {}); setFlushed(true); }}>Flush cache</button>
            </div>
          </div>
          <${ErrorBox} error=${flush.error} />
        </div>`}
    </section>`;
}

function ResolveResult({ r }) {
  const sections = [['Answer', r.answers], ['Authority', r.authorities], ['Additional', r.additionals]].filter(([, rs]) => rs.length);
  return html`
    <div class="resolve">
      <div class="resolve-head">
        <strong>${r.query.name}</strong> ${r.query.type}
        <span class=${`badge rcode-${r.rcode}`}>${r.rcode}</span>
        <${SourceBadge} source=${r.source} />
        ${r.flags.map((f) => html`<span class="tag">${f}</span>`)}
        <span class="muted small">${fmtMicros(r.duration_us)}</span>
      </div>
      ${r.filter && html`<p class="small">Filter: ${r.filter.action} by <code>${r.filter.rule}</code> <span class="tag">${r.filter.list}</span></p>`}
      ${r.error && html`<p class="small text-error">${r.error}</p>`}
      ${sections.length === 0 ? html`<p class="muted small">No records.</p>` : sections.map(([title, records]) => html`
        <h4>${title}</h4>
        <div class="table-wrap"><table class="table records compact">
          <tbody>${records.map((rec) => html`
            <tr><td class="mono">${rec.name}</td><td class="num muted">${rec.ttl}</td><td><span class="badge">${rec.type}</span></td><td class="mono data">${rec.data}</td></tr>`)}
          </tbody>
        </table></div>`)}
    </div>`;
}
