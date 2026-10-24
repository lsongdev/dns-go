import { html, useEffect, useState } from '../lib/html.js';
import { useAction } from '../lib/hooks.js';
import { Page, Notice, Loading, Field, Badge, toast } from '../lib/ui.js';
import { usePanel } from '../lib/panel.js';
import { useApi, useStatus, MODES, lines } from '../dns.js';

const MODE_HELP = {
  forwarding: '经上游解析，带本地区域、过滤和缓存。适合局域网或私人 DoH/DoT。',
  authoritative: '只应答自己的区域，其余返回 REFUSED，不递归。适合作为域名的 NS。',
};

const TRANSPORTS = ['udp', 'tcp', 'dot', 'doh'];

// TLS choices for a listener: none, the host's certificates, or files.
const tlsOf = l => (l.tls ? 'host' : l.cert_file ? 'files' : 'none');

export default function Settings() {
  const { api } = usePanel();
  const settings = useApi('/settings');
  const status = useStatus();
  const action = useAction();
  const [draft, setDraft] = useState(null);
  useEffect(() => { if (settings.data) setDraft(toDraft(settings.data)); }, [settings.data]);

  if (!draft) return html`<${Page} title="服务设置">${settings.error ? html`<${Notice} error=${settings.error} />` : html`<${Loading} />`}<//>`;
  const editable = settings.data.editable;
  const set = patch => setDraft(d => ({ ...d, ...patch }));
  const save = e => {
    e.preventDefault();
    action.run(async () => {
      const saved = await api.put('/settings', fromDraft(draft));
      setDraft(toDraft(saved));
      status.reload();
      toast('服务设置已生效', 'success');
    });
  };
  const listenerState = l => status.data?.listens?.find(s => s.type === l.type && s.addr === l.addr);

  return html`<${Page} title="服务设置" subtitle="保存后立即重建解析器，只有改动过的监听会重新绑定。">
    ${!editable ? html`<${Notice} tone="info">这里的设置是只读的：编辑配置文件后重启服务。<//>` : null}
    <form class="form" onSubmit=${save}>
      <fieldset disabled=${!editable} style="border:0;padding:0;margin:0;display:grid;gap:16px">
        <div class="card">
          <h2>模式</h2>
          <div class="choices">${Object.entries(MODES).map(([k, label]) => html`<label class="choice" key=${k}>
            <input type="radio" name="mode" checked=${draft.mode === k} onChange=${() => set({ mode: k, ...(k === 'authoritative' ? { upstreams: [], cache: { ...draft.cache, enabled: false } } : {}) })} />
            <span><strong>${label}</strong><span class="field-hint">${MODE_HELP[k]}</span></span>
          </label>`)}</div>
        </div>

        <div class="card">
          <div class="card-head">
            <h2>监听</h2>
            <button type="button" class="btn btn-sm" onClick=${() => set({ listens: [...draft.listens, { type: 'udp', addr: ':53', tlsMode: 'none' }] })}>添加监听</button>
          </div>
          ${draft.listens.map((l, i) => html`<${ListenRow} key=${i} value=${l} state=${listenerState(l)}
            onChange=${v => set({ listens: draft.listens.map((x, j) => (j === i ? v : x)) })}
            onRemove=${() => set({ listens: draft.listens.filter((_, j) => j !== i) })} />`)}
        </div>

        ${draft.mode === 'forwarding' ? html`<div class="card">
          <div class="card-head">
            <h2>上游</h2>
            <button type="button" class="btn btn-sm" onClick=${() => set({ upstreams: [...draft.upstreams, { type: 'udp', addr: '', method: 'post', timeout: '5s' }] })}>添加上游</button>
          </div>
          <p class="muted" style="margin-top:0">按顺序尝试；SERVFAIL、REFUSED 或出错时换下一个。</p>
          ${draft.upstreams.map((u, i) => html`<${UpstreamRow} key=${i} value=${u}
            onChange=${v => set({ upstreams: draft.upstreams.map((x, j) => (j === i ? v : x)) })}
            onRemove=${() => set({ upstreams: draft.upstreams.filter((_, j) => j !== i) })} />`)}
        </div>

        <div class="card">
          <h2>缓存</h2>
          <label class="check" style="margin-bottom:12px"><input type="checkbox" checked=${draft.cache.enabled}
            onChange=${e => set({ cache: { ...draft.cache, enabled: e.currentTarget.checked } })} />启用缓存</label>
          ${draft.cache.enabled ? html`<div class="form-grid">
            ${[['min_ttl', '最小 TTL', '0s'], ['max_ttl', '最大 TTL', '24h'], ['negative_ttl', '否定应答 TTL', '5m']].map(([k, label, ph]) => html`
              <${Field} label=${label} key=${k}>
                <input class="input" value=${draft.cache[k]} placeholder=${ph} onInput=${e => set({ cache: { ...draft.cache, [k]: e.currentTarget.value } })} />
              <//>`)}
            <${Field} label="最多条目">
              <input class="input" type="number" min="1" value=${draft.cache.max_entries}
                onInput=${e => set({ cache: { ...draft.cache, max_entries: Number(e.currentTarget.value) } })} />
            <//>
          </div>` : null}
        </div>` : null}
      </fieldset>
      <${Notice} error=${action.error} />
      ${editable ? html`<div class="form-actions">
        <button class="btn btn-primary" disabled=${action.busy}>保存并应用</button>
        <button class="btn" type="button" onClick=${() => { setDraft(toDraft(settings.data)); action.setError(null); }}>还原</button>
      </div>` : null}
    </form>
  <//>`;
}

function ListenRow({ value: l, state, onChange, onRemove }) {
  const set = patch => onChange({ ...l, ...patch });
  const secure = l.type === 'dot' || l.type === 'doh';
  return html`<div class="spec-row">
    <select class="input" value=${l.type} onChange=${e => set({ type: e.currentTarget.value, tlsMode: e.currentTarget.value === 'dot' && l.tlsMode === 'none' ? 'host' : l.tlsMode })} aria-label="类型">
      ${TRANSPORTS.map(t => html`<option value=${t}>${t.toUpperCase()}</option>`)}
    </select>
    <div>
      <input class="input mono" required value=${l.addr} placeholder=":53" onInput=${e => set({ addr: e.currentTarget.value })} aria-label="地址" />
      ${state ? html`<div style="margin-top:4px">${state.error
        ? html`<${Badge} tone="red" title=${state.error}>未启动：${state.error}<//>`
        : html`<${Badge} tone="green">运行中<//>`}</div>` : null}
    </div>
    <button type="button" class="btn btn-ghost btn-icon" aria-label="移除" onClick=${onRemove}>✕</button>
    ${secure ? html`<div class="spec-extra">
      <${Field} label="TLS">
        <select class="input" value=${l.tlsMode} onChange=${e => set({ tlsMode: e.currentTarget.value })}>
          ${l.type === 'doh' ? html`<option value="none">不加密（由反向代理终止 TLS）</option>` : null}
          <option value="host">使用证书管理器的证书</option>
          <option value="files">证书文件</option>
        </select>
      <//>
      ${l.tlsMode === 'files' ? html`
        <${Field} label="证书文件"><input class="input mono" required value=${l.cert_file || ''} onInput=${e => set({ cert_file: e.currentTarget.value })} /><//>
        <${Field} label="私钥文件"><input class="input mono" required value=${l.key_file || ''} onInput=${e => set({ key_file: e.currentTarget.value })} /><//>` : null}
      ${l.tlsMode !== 'none' ? html`<${Field} label="主机名" hint="设置后，连接 <id>.主机名 的客户端被识别为 <id>（需要通配符证书）">
        <input class="input mono" value=${l.hostname || ''} placeholder="dns.example.com" onInput=${e => set({ hostname: e.currentTarget.value })} />
      <//>` : null}
      ${l.type === 'doh' ? html`<${Field} label="可信反向代理" hint="每行一个，信任其 X-Forwarded-For">
        <textarea class="input" rows="2" value=${l.proxiesText || ''} placeholder="127.0.0.1" onInput=${e => set({ proxiesText: e.currentTarget.value })} />
      <//>` : null}
    </div>` : null}
  </div>`;
}

function UpstreamRow({ value: u, onChange, onRemove }) {
  const set = patch => onChange({ ...u, ...patch });
  const placeholder = { udp: '8.8.8.8:53', tcp: '8.8.8.8:53', dot: '1.1.1.1:853', doh: 'https://doh.pub/dns-query' }[u.type];
  return html`<div class="spec-row">
    <select class="input" value=${u.type} onChange=${e => set({ type: e.currentTarget.value })} aria-label="类型">
      ${TRANSPORTS.map(t => html`<option value=${t}>${t.toUpperCase()}</option>`)}
    </select>
    <input class="input mono" required value=${u.addr} placeholder=${placeholder} onInput=${e => set({ addr: e.currentTarget.value })} aria-label="地址" />
    <button type="button" class="btn btn-ghost btn-icon" aria-label="移除" onClick=${onRemove}>✕</button>
    <div class="spec-extra">
      <${Field} label="超时"><input class="input" value=${u.timeout} placeholder="5s" onInput=${e => set({ timeout: e.currentTarget.value })} /><//>
      ${u.type === 'doh' ? html`<${Field} label="请求方式">
        <select class="input" value=${u.method || 'post'} onChange=${e => set({ method: e.currentTarget.value })}>
          <option value="post">POST</option><option value="get">GET</option>
        </select>
      <//>` : null}
    </div>
  </div>`;
}

// toDraft turns API settings into form state; fromDraft reverses it.
function toDraft(s) {
  return {
    mode: s.mode,
    listens: (s.listens || []).map(l => ({ ...l, tlsMode: tlsOf(l), proxiesText: (l.trusted_proxies || []).join('\n') })),
    upstreams: (s.upstreams || []).map(u => ({ ...u })),
    cache: { ...s.cache },
  };
}

function fromDraft(d) {
  const listens = d.listens.map(({ tlsMode, proxiesText, ...l }) => {
    const out = { type: l.type, addr: l.addr.trim() };
    const secure = l.type === 'dot' || l.type === 'doh';
    if (secure && tlsMode === 'host') out.tls = true;
    if (secure && tlsMode === 'files') Object.assign(out, { cert_file: l.cert_file, key_file: l.key_file });
    if (secure && tlsMode !== 'none' && l.hostname) out.hostname = l.hostname.trim();
    if (l.type === 'doh' && lines(proxiesText || '').length) out.trusted_proxies = lines(proxiesText);
    return out;
  });
  const upstreams = d.mode === 'forwarding'
    ? d.upstreams.map(u => ({ type: u.type, addr: u.addr.trim(), timeout: u.timeout || '', ...(u.type === 'doh' ? { method: u.method || 'post' } : {}) }))
    : [];
  return { mode: d.mode, listens, upstreams, cache: d.mode === 'forwarding' ? d.cache : { ...d.cache, enabled: false } };
}
