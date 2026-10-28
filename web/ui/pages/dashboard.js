import { html } from '../lib/html.js';
import { Page, Notice, Loading, Empty, Badge } from '../lib/ui.js';
import { useApi, useStatus, MODES, SOURCE_KEYS, sourceLabel, number, share, uptime, Link } from '../dns.js';

export default function Dashboard() {
  const status = useStatus();
  const stats = useApi('/stats?top=10&bucket=30', 10000);
  const st = status.data;
  const s = stats.data;
  const down = st?.enabled ? st.listens.filter(l => l.error) : [];
  return html`<${Page} title="Dashboard" subtitle="Statistics live in memory and reset on restart">
    <${Notice} error=${status.error || stats.error} />
    ${st && !st.enabled ? html`<${Notice} tone="info">The DNS server is off: nothing answers queries. Turn it on in <${Link} to="/settings">Settings<//>.<//>` : null}
    ${down.length ? html`<${Notice} tone="warn">
      ${down.map(l => html`<div key=${l.type + l.addr}>The ${l.type} listener on ${l.addr} is down: ${l.error}</div>`)}
      <${Link} to="/settings">Check the settings<//>
    <//>` : null}
    ${!st || !s ? html`<${Loading} />` : html`
      <div class="grid">
        <${Stat} label="Queries" value=${number(s.total)} sub=${`${MODES[st.mode] || st.mode} · up ${uptime(st.uptime_seconds)}`} />
        <${Stat} label="Blocked" value=${number(s.blocked)} sub=${share(s.blocked, s.total)} />
        <${Stat} label="Cache hits" value=${number(s.by_source.cache || 0)} sub=${st.cache ? `${share(s.by_source.cache || 0, s.total)} · ${number(st.cache.entries)} entries` : 'Cache off'} />
        <${Stat} label="Zones" value=${number(st.zones)} sub=${st.filter ? `${number(st.filter.rules)} filter rules in ${st.filter.lists} lists` : `${st.clients} clients`} />
      </div>
      <div class="card section">
        <div class="card-head">
          <h2>Last 24 hours</h2>
          <span class="legend"><span><i class="total"></i>Queries</span><span><i class="blocked"></i>Blocked</span></span>
        </div>
        <${Chart} series=${s.series} />
      </div>
      <div class="card section">
        <h2>Answered from</h2>
        <${Sources} bySource=${s.by_source} total=${s.total} />
      </div>
      <div class="grid section">
        <${TopList} title="Top names" items=${s.top_names} total=${s.total} />
        <${TopList} title="Top blocked" items=${s.top_blocked} total=${s.blocked} blocked />
        <${TopList} title="Top clients" items=${s.top_clients} total=${s.total} />
      </div>
      <div class="card section">
        <h2>Listeners</h2>
        ${!st.enabled ? html`<p class="muted" style="margin:0">Off</p>` : null}
        <div class="tags">${st.listens.map(l => html`<${Badge} key=${l.type + l.addr} tone=${l.error ? 'red' : 'green'} title=${l.error}>
          ${l.type}${l.tls ? '+tls' : ''} ${l.addr}<//>`)}</div>
      </div>`}
  <//>`;
}

function Stat({ label, value, sub }) {
  return html`<div class="card stat">
    <span class="stat-label">${label}</span>
    <span class="stat-value">${value}</span>
    ${sub ? html`<span class="stat-sub">${sub}</span>` : null}
  </div>`;
}

function Chart({ series }) {
  const max = Math.max(1, ...series.map(p => p.total));
  const w = 100 / series.length;
  return html`<div class="chart" role="img" aria-label="Queries per 30 minutes over the last 24 hours">
    <svg viewBox="0 0 100 40" preserveAspectRatio="none">
      ${series.map((p, i) => {
        const th = (p.total / max) * 38;
        const bh = (p.blocked / max) * 38;
        return html`<g key=${p.time}>
          <title>${new Date(p.time).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })}: ${p.total} queries, ${p.blocked} blocked</title>
          <rect class="bar-total" x=${i * w + w * 0.1} y=${40 - th} width=${w * 0.8} height=${th} />
          <rect class="bar-blocked" x=${i * w + w * 0.1} y=${40 - bh} width=${w * 0.8} height=${bh} />
        </g>`;
      })}
    </svg>
    <div class="chart-axis"><span>24 hours ago</span><span>12 hours ago</span><span>Now</span></div>
  </div>`;
}

function Sources({ bySource, total }) {
  if (!total) return html`<${Empty}>No queries yet.<//>`;
  const entries = SOURCE_KEYS.filter(k => bySource[k]).map(k => [k, bySource[k]]);
  return html`
    <div class="stack">${entries.map(([k, v]) => html`<span key=${k} class=${`src-${k}`} style=${`flex:${v}`} title=${`${sourceLabel(k)}：${v}`}></span>`)}</div>
    <div class="stack-legend">${entries.map(([k, v]) => html`<span key=${k}><i class=${`src-${k}`}></i>${sourceLabel(k)} ${share(v, total)}</span>`)}</div>`;
}

function TopList({ title, items, total, blocked }) {
  const max = items.length ? items[0].count : 1;
  return html`<div class="card">
    <h2>${title}</h2>
    ${items.length === 0 ? html`<div class="muted">No data yet</div>` : html`<ol class="toplist">
      ${items.map(it => html`<li key=${it.key}>
        <span class=${`toplist-bar ${blocked ? 'blocked' : ''}`} style=${`width:${(it.count / max) * 100}%`}></span>
        <span class="toplist-key" title=${it.key}>${it.key}</span>
        <span class="toplist-count">${number(it.count)}<small>${share(it.count, total)}</small></span>
      </li>`)}
    </ol>`}
  </div>`;
}
