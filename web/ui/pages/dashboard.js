import { html } from '../lib/html.js';
import { Page, Notice, Loading, Empty, Badge } from '../lib/ui.js';
import { useApi, useStatus, MODES, SOURCE_KEYS, sourceLabel, number, share, uptime, Link } from '../dns.js';

export default function Dashboard() {
  const status = useStatus();
  const stats = useApi('/stats?top=10&bucket=30', 10000);
  const st = status.data;
  const s = stats.data;
  const down = st?.listens?.filter(l => l.error) || [];
  return html`<${Page} title="仪表盘" subtitle="统计保存在内存中，重启后清零">
    <${Notice} error=${status.error || stats.error} />
    ${down.length ? html`<${Notice} tone="warn">
      ${down.map(l => html`<div key=${l.type + l.addr}>监听 ${l.type} ${l.addr} 未启动：${l.error}</div>`)}
      <${Link} to="/settings">检查服务设置<//>
    <//>` : null}
    ${!st || !s ? html`<${Loading} />` : html`
      <div class="grid">
        <${Stat} label="查询" value=${number(s.total)} sub=${`${MODES[st.mode] || st.mode} · 运行 ${uptime(st.uptime_seconds)}`} />
        <${Stat} label="已拦截" value=${number(s.blocked)} sub=${share(s.blocked, s.total)} />
        <${Stat} label="缓存命中" value=${number(s.by_source.cache || 0)} sub=${st.cache ? `${share(s.by_source.cache || 0, s.total)} · ${number(st.cache.entries)} 条缓存` : '未启用缓存'} />
        <${Stat} label="区域" value=${number(st.zones)} sub=${st.filter ? `${number(st.filter.rules)} 条过滤规则，${st.filter.lists} 个列表` : `${st.clients} 个客户端`} />
      </div>
      <div class="card section">
        <div class="card-head">
          <h2>最近 24 小时</h2>
          <span class="legend"><span><i class="total"></i>查询</span><span><i class="blocked"></i>拦截</span></span>
        </div>
        <${Chart} series=${s.series} />
      </div>
      <div class="card section">
        <h2>应答来源</h2>
        <${Sources} bySource=${s.by_source} total=${s.total} />
      </div>
      <div class="grid section">
        <${TopList} title="热门域名" items=${s.top_names} total=${s.total} />
        <${TopList} title="拦截最多" items=${s.top_blocked} total=${s.blocked} blocked />
        <${TopList} title="活跃客户端" items=${s.top_clients} total=${s.total} />
      </div>
      <div class="card section">
        <h2>监听</h2>
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
  return html`<div class="chart" role="img" aria-label="最近 24 小时每 30 分钟的查询数">
    <svg viewBox="0 0 100 40" preserveAspectRatio="none">
      ${series.map((p, i) => {
        const th = (p.total / max) * 38;
        const bh = (p.blocked / max) * 38;
        return html`<g key=${p.time}>
          <title>${new Date(p.time).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' })}：${p.total} 次查询，${p.blocked} 次拦截</title>
          <rect class="bar-total" x=${i * w + w * 0.1} y=${40 - th} width=${w * 0.8} height=${th} />
          <rect class="bar-blocked" x=${i * w + w * 0.1} y=${40 - bh} width=${w * 0.8} height=${bh} />
        </g>`;
      })}
    </svg>
    <div class="chart-axis"><span>24 小时前</span><span>12 小时前</span><span>现在</span></div>
  </div>`;
}

function Sources({ bySource, total }) {
  if (!total) return html`<${Empty}>还没有查询。<//>`;
  const entries = SOURCE_KEYS.filter(k => bySource[k]).map(k => [k, bySource[k]]);
  return html`
    <div class="stack">${entries.map(([k, v]) => html`<span key=${k} class=${`src-${k}`} style=${`flex:${v}`} title=${`${sourceLabel(k)}：${v}`}></span>`)}</div>
    <div class="stack-legend">${entries.map(([k, v]) => html`<span key=${k}><i class=${`src-${k}`}></i>${sourceLabel(k)} ${share(v, total)}</span>`)}</div>`;
}

function TopList({ title, items, total, blocked }) {
  const max = items.length ? items[0].count : 1;
  return html`<div class="card">
    <h2>${title}</h2>
    ${items.length === 0 ? html`<div class="muted">暂无数据</div>` : html`<ol class="toplist">
      ${items.map(it => html`<li key=${it.key}>
        <span class=${`toplist-bar ${blocked ? 'blocked' : ''}`} style=${`width:${(it.count / max) * 100}%`}></span>
        <span class="toplist-key" title=${it.key}>${it.key}</span>
        <span class="toplist-count">${number(it.count)}<small>${share(it.count, total)}</small></span>
      </li>`)}
    </ol>`}
  </div>`;
}
