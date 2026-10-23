import { html, useApi, fmtNumber, fmtPercent, fmtDuration, ErrorBox, Loading, Empty } from '../lib.js';

const SOURCES = ['upstream', 'cache', 'zone', 'filter', 'denied', 'error', 'policy', 'invalid'];

export function Dashboard({ status }) {
  const stats = useApi('/stats?top=10&bucket=30', { interval: 10000 });
  const s = stats.data;
  return html`
    <section class="page">
      <header class="page-head">
        <h2>Dashboard</h2>
        <p class="muted">Since start · statistics are kept in memory and reset on restart</p>
      </header>
      <${ErrorBox} error=${stats.error} />
      <div class="cards">
        <${Card} label="Queries" value=${s ? fmtNumber(s.total) : '–'} />
        <${Card} label="Blocked" value=${s ? fmtNumber(s.blocked) : '–'} hint=${s ? fmtPercent(s.blocked, s.total) : ''} tone="block" />
        <${Card} label="Cache hits" value=${s ? fmtNumber(s.by_source.cache || 0) : '–'} hint=${s ? fmtPercent(s.by_source.cache || 0, s.total) : ''} />
        <${Card} label="Uptime" value=${fmtDuration(status.uptime_seconds)} hint=${status.mode} />
        <${Card} label="Zones" value=${fmtNumber(status.zones)} />
        ${status.filter && html`<${Card} label="Filter rules" value=${fmtNumber(status.filter.rules)} hint=${`${status.filter.lists} lists`} />`}
      </div>
      ${!s ? html`<${Loading} />` : html`
        <div class="panel">
          <div class="panel-head">
            <h3>Last 24 hours</h3>
            <span class="legend"><i class="dot total"></i>queries <i class="dot blocked"></i>blocked</span>
          </div>
          <${Chart} series=${s.series} />
        </div>
        <div class="panel">
          <h3>Answers by source</h3>
          <${SourceBar} bySource=${s.by_source} total=${s.total} />
        </div>
        <div class="grid3">
          <${TopList} title="Top domains" items=${s.top_names} total=${s.total} />
          <${TopList} title="Top blocked" items=${s.top_blocked} total=${s.blocked} tone="block" />
          <${TopList} title="Top clients" items=${s.top_clients} total=${s.total} />
        </div>`}
    </section>`;
}

function Card({ label, value, hint, tone }) {
  return html`
    <div class=${`card${tone ? ` tone-${tone}` : ''}`}>
      <div class="card-label">${label}</div>
      <div class="card-value">${value}</div>
      ${hint && html`<div class="card-hint">${hint}</div>`}
    </div>`;
}

function Chart({ series }) {
  const max = Math.max(1, ...series.map((p) => p.total));
  const w = 100 / series.length;
  return html`
    <div class="chart" role="img" aria-label="Queries per 30 minutes over the last 24 hours">
      <svg viewBox="0 0 100 40" preserveAspectRatio="none">
        ${series.map((p, i) => {
          const th = (p.total / max) * 38;
          const bh = (p.blocked / max) * 38;
          return html`<g>
            <title>${new Date(p.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}: ${p.total} queries, ${p.blocked} blocked</title>
            <rect class="bar-total" x=${i * w + w * 0.1} y=${40 - th} width=${w * 0.8} height=${th} />
            <rect class="bar-blocked" x=${i * w + w * 0.1} y=${40 - bh} width=${w * 0.8} height=${bh} />
          </g>`;
        })}
      </svg>
      <div class="chart-axis">
        <span>24h ago</span>
        <span>12h ago</span>
        <span>now</span>
      </div>
    </div>`;
}

function SourceBar({ bySource, total }) {
  if (!total) return html`<${Empty}>No queries yet.</${Empty}>`;
  const entries = SOURCES.filter((k) => bySource[k]).map((k) => [k, bySource[k]]);
  return html`
    <div class="stack">
      ${entries.map(([k, v]) => html`<span class=${`seg src-${k}`} style=${`flex:${v}`} title=${`${k}: ${v}`}></span>`)}
    </div>
    <div class="stack-legend">
      ${entries.map(([k, v]) => html`<span><i class=${`dot src-${k}`}></i>${k} ${fmtPercent(v, total)}</span>`)}
    </div>`;
}

function TopList({ title, items, total, tone }) {
  const max = items.length ? items[0].count : 1;
  return html`
    <div class="panel">
      <h3>${title}</h3>
      ${items.length === 0
        ? html`<${Empty}>Nothing yet.</${Empty}>`
        : html`<ol class="toplist">
            ${items.map((it) => html`
              <li>
                <span class="toplist-bar${tone ? ` tone-${tone}` : ''}" style=${`width:${(it.count / max) * 100}%`}></span>
                <span class="toplist-key" title=${it.key}>${it.key}</span>
                <span class="toplist-count">${fmtNumber(it.count)} <small>${fmtPercent(it.count, total)}</small></span>
              </li>`)}
          </ol>`}
    </div>`;
}
