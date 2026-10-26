import { html, useState } from '../lib/html.js';
import { useAction } from '../lib/hooks.js';
import { Page, Notice, Loading, Empty, toast, Table } from '../lib/ui.js';
import { usePanel } from '../lib/panel.js';
import { useApi, useStatus, SourceBadge, SOURCE_KEYS, sourceLabel, clock, micros } from '../dns.js';

// addRule appends a rule to the custom rules, unless it is already there.
export async function addRule(api, rule) {
  const filters = await api.get('/filters');
  if (filters.rules.includes(rule)) return;
  await api.put('/filters/rules', { rules: [...filters.rules, rule] });
}

export default function QueryLog({ query, setQuery }) {
  const { api } = usePanel();
  const search = query.search || '';
  const source = query.source || '';
  const [live, setLive] = useState(true);
  const params = new URLSearchParams({ limit: '200', search, source });
  const log = useApi(`/querylog?${params}`, live ? 3000 : 0);
  const status = useStatus();
  const action = useAction();
  const canFilter = status.data?.mode === 'forwarding';

  const quickRule = rule => action.run(async () => {
    await addRule(api, rule);
    toast(`Added the rule ${rule}`, 'success');
  });

  return html`<${Page} title="Query log" subtitle="The latest 5,000 queries, newest first">
    <div class="toolbar">
      <input class="input" type="search" placeholder="Search names or clients" value=${search}
        onInput=${e => setQuery({ search: e.currentTarget.value.trim() })} aria-label="Search" />
      <select class="input" style="flex:0 0 auto" value=${source} onChange=${e => setQuery({ source: e.currentTarget.value })} aria-label="Source">
        <option value="">All sources</option>
        ${SOURCE_KEYS.map(s => html`<option value=${s}>${sourceLabel(s)}</option>`)}
      </select>
      <label class="field-check"><input type="checkbox" checked=${live} onChange=${e => setLive(e.currentTarget.checked)} />Live</label>
    </div>
    <${Notice} error=${log.error || action.error} />
    ${log.data === undefined ? (log.error ? null : html`<${Loading} />`) : !log.data.length ? html`<${Empty}>No matching queries.<//>` : html`
      <${Table}>
        <thead><tr>
          <th>Time</th><th>Client</th><th>Name</th><th>Type</th><th>Result</th><th>Source</th><th class="num">Duration</th>${canFilter ? html`<th class="actions"></th>` : null}
        </tr></thead>
        <tbody>${log.data.map((e, i) => html`<tr key=${i} class=${e.source === 'filter' ? 'row-blocked' : ''}>
          <td class="nowrap muted">${clock(e.time)}</td>
          <td class="nowrap">
            ${e.client_name ? html`<div class="cell-main">${e.client_name}</div><div class="cell-sub">${e.client}</div>` : e.client}
            <div class="cell-sub">${e.transport}</div>
          </td>
          <td class="domain">
            <span class="mono">${e.name}</span>
            ${e.filter_rule ? html`<div class="cell-sub"><code>${e.filter_rule}</code> <span class="tag">${e.filter_list}</span></div>` : null}
            ${e.error ? html`<div class="small text-error">${e.error}</div>` : null}
          </td>
          <td>${e.type}</td>
          <td class="nowrap">${e.rcode}${e.answers ? html` <span class="muted">· ${e.answers}</span>` : null}</td>
          <td><${SourceBadge} source=${e.source} /></td>
          <td class="num muted">${micros(e.duration_us)}</td>
          ${canFilter ? html`<td class="actions">
            ${e.source === 'filter'
              ? html`<button class="button button-small" disabled=${action.busy} onClick=${() => quickRule(`@@||${e.name}^`)}>Allow</button>`
              : (e.source === 'upstream' || e.source === 'cache')
                ? html`<button class="button button-small button-danger" disabled=${action.busy} onClick=${() => quickRule(`||${e.name}^`)}>Block</button>`
                : null}
          </td>` : null}
        </tr>`)}</tbody>
      <//>`}
  <//>`;
}
