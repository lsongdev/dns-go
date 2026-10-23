import { useState } from '../vendor/hooks.js';
import { html, api, useApi, useAction, fmtTime, fmtMicros, ErrorBox, Loading, Empty, SourceBadge } from '../lib.js';

const SOURCES = ['', 'upstream', 'cache', 'zone', 'filter', 'denied', 'error', 'policy', 'invalid'];

// addRule appends an AdBlock rule to the custom rule list (deduplicated).
export async function addRule(rule) {
  const filters = await api('GET', '/filters');
  if (filters.rules.includes(rule)) return;
  await api('PUT', '/filters/rules', { rules: [...filters.rules, rule] });
}

export function QueryLog({ status }) {
  const [search, setSearch] = useState('');
  const [source, setSource] = useState('');
  const [live, setLive] = useState(true);
  const [notice, setNotice] = useState('');
  const params = new URLSearchParams({ limit: '200', search, source });
  const log = useApi(`/querylog?${params}`, { interval: live ? 3000 : 0 });
  const action = useAction();
  const canFilter = status.mode === 'forwarding';

  const quickRule = async (rule) => {
    await action.run(() => addRule(rule)).catch(() => {});
    setNotice(`Added rule ${rule}`);
    setTimeout(() => setNotice(''), 4000);
  };

  return html`
    <section class="page">
      <header class="page-head">
        <h2>Query log</h2>
        <p class="muted">The most recent 5,000 queries, newest first.</p>
      </header>
      <div class="toolbar">
        <input type="search" placeholder="Search domain or client" value=${search}
               onInput=${(e) => setSearch(e.target.value.trim())} aria-label="Search" />
        <select value=${source} onChange=${(e) => setSource(e.target.value)} aria-label="Source">
          ${SOURCES.map((s) => html`<option value=${s}>${s || 'All sources'}</option>`)}
        </select>
        <label class="check"><input type="checkbox" checked=${live} onChange=${(e) => setLive(e.target.checked)} /> Live</label>
      </div>
      ${notice && html`<div class="alert ok">${notice}</div>`}
      <${ErrorBox} error=${log.error || action.error} />
      ${log.loading && !log.data ? html`<${Loading} />` : !log.data?.length ? html`<${Empty}>No matching queries.</${Empty}>` : html`
        <div class="table-wrap">
          <table class="table">
            <thead><tr>
              <th>Time</th><th>Client</th><th>Domain</th><th>Type</th><th>Result</th><th>Source</th><th class="num">Took</th>${canFilter && html`<th></th>`}
            </tr></thead>
            <tbody>
              ${log.data.map((e) => html`
                <tr class=${e.source === 'filter' ? 'row-blocked' : ''}>
                  <td class="nowrap muted">${fmtTime(e.time)}</td>
                  <td class="nowrap">
                    ${e.client_name ? html`<strong>${e.client_name}</strong> <span class="muted">${e.client}</span>` : e.client}
                    <div class="muted small">${e.transport}</div>
                  </td>
                  <td class="domain">
                    ${e.name}
                    ${e.filter_rule && html`<div class="small muted" title=${e.filter_list}>${e.filter_rule} <span class="tag">${e.filter_list}</span></div>`}
                    ${e.error && html`<div class="small text-error">${e.error}</div>`}
                  </td>
                  <td>${e.type}</td>
                  <td class="nowrap">${e.rcode}${e.answers ? html` <span class="muted">· ${e.answers}</span>` : ''}</td>
                  <td><${SourceBadge} source=${e.source} /></td>
                  <td class="num muted">${fmtMicros(e.duration_us)}</td>
                  ${canFilter && html`<td class="actions">
                    ${e.source === 'filter'
                      ? html`<button class="small" disabled=${action.busy} onClick=${() => quickRule(`@@||${e.name}^`)}>Allow</button>`
                      : (e.source === 'upstream' || e.source === 'cache') &&
                        html`<button class="small" disabled=${action.busy} onClick=${() => quickRule(`||${e.name}^`)}>Block</button>`}
                  </td>`}
                </tr>`)}
            </tbody>
          </table>
        </div>`}
    </section>`;
}
