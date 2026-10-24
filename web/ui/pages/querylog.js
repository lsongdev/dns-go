import { html, useState } from '../lib/html.js';
import { useAction } from '../lib/hooks.js';
import { Page, Notice, Loading, Empty, toast } from '../lib/ui.js';
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
    toast(`已添加规则 ${rule}`, 'success');
  });

  return html`<${Page} title="查询日志" subtitle="最近 5000 条查询，最新的在前">
    <div class="toolbar">
      <input class="input" type="search" placeholder="搜索域名或客户端" value=${search}
        onInput=${e => setQuery({ search: e.currentTarget.value.trim() })} aria-label="搜索" />
      <select class="input" style="flex:0 0 auto" value=${source} onChange=${e => setQuery({ source: e.currentTarget.value })} aria-label="来源">
        <option value="">全部来源</option>
        ${SOURCE_KEYS.map(s => html`<option value=${s}>${sourceLabel(s)}</option>`)}
      </select>
      <label class="check"><input type="checkbox" checked=${live} onChange=${e => setLive(e.currentTarget.checked)} />实时刷新</label>
    </div>
    <${Notice} error=${log.error || action.error} />
    ${log.data === undefined ? (log.error ? null : html`<${Loading} />`) : !log.data.length ? html`<${Empty}>没有匹配的查询。<//>` : html`
      <div class="table-wrap"><table class="table">
        <thead><tr>
          <th>时间</th><th>客户端</th><th>域名</th><th>类型</th><th>结果</th><th>来源</th><th class="num">耗时</th>${canFilter ? html`<th class="actions"></th>` : null}
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
              ? html`<button class="btn btn-sm" disabled=${action.busy} onClick=${() => quickRule(`@@||${e.name}^`)}>放行</button>`
              : (e.source === 'upstream' || e.source === 'cache')
                ? html`<button class="btn btn-sm btn-danger" disabled=${action.busy} onClick=${() => quickRule(`||${e.name}^`)}>拦截</button>`
                : null}
          </td>` : null}
        </tr>`)}</tbody>
      </table></div>`}
  <//>`;
}
