import { html, useEffect, useState } from '../lib/html.js';
import { useAction } from '../lib/hooks.js';
import { Page, Notice, Loading, Field, Badge, toast } from '../lib/ui.js';
import { usePanel } from '../lib/panel.js';
import { useApi, useStatus, MODES, lines } from '../dns.js';

const MODE_HELP = {
  forwarding: 'Resolve through upstreams, with local zones, filters and a cache. For a LAN or private DoH/DoT.',
  authoritative: 'Answer only for its own zones and refuse the rest, without recursion. For serving as a domain\'s NS.',
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

  if (!draft) return html`<${Page} title="Settings">${settings.error ? html`<${Notice} error=${settings.error} />` : html`<${Loading} />`}<//>`;
  const editable = settings.data.editable;
  const set = patch => setDraft(d => ({ ...d, ...patch }));
  const save = e => {
    e.preventDefault();
    action.run(async () => {
      const saved = await api.put('/settings', fromDraft(draft));
      setDraft(toDraft(saved));
      status.reload();
      toast('Settings applied', 'success');
    });
  };
  const listenerState = l => status.data?.listens?.find(s => s.type === l.type && s.addr === l.addr);

  return html`<${Page} title="Settings" subtitle="Saving rebuilds the resolver at once; only changed listeners rebind.">
    ${!editable ? html`<${Notice} tone="info">These settings are read-only: edit the configuration file and restart.<//>` : null}
    <form class="form" onSubmit=${save}>
      <fieldset class="settings-fields" disabled=${!editable}>
        <div class="card">
          <label class="field-check"><input type="checkbox" checked=${draft.enabled}
            onChange=${e => set({ enabled: e.currentTarget.checked })} />Serve DNS</label>
          <p class="field-hint" style="margin:8px 0 0">When off, no listener is bound and nothing answers queries; zones, filters and clients are kept.</p>
        </div>
        <div class="card">
          <h2>Mode</h2>
          <div class="choices">${Object.entries(MODES).map(([k, label]) => html`<label class="choice" key=${k}>
            <input type="radio" name="mode" checked=${draft.mode === k} onChange=${() => set({ mode: k, ...(k === 'authoritative' ? { upstreams: [], cache: { ...draft.cache, enabled: false } } : {}) })} />
            <span><strong>${label}</strong><span class="field-hint">${MODE_HELP[k]}</span></span>
          </label>`)}</div>
        </div>

        <div class="card">
          <div class="card-head">
            <h2>Listeners</h2>
            <button type="button" class="button button-small" onClick=${() => set({ listens: [...draft.listens, { type: 'udp', addr: ':53', tlsMode: 'none' }] })}>Add listener</button>
          </div>
          ${draft.listens.map((l, i) => html`<${ListenRow} key=${i} value=${l} state=${listenerState(l)}
            onChange=${v => set({ listens: draft.listens.map((x, j) => (j === i ? v : x)) })}
            onRemove=${() => set({ listens: draft.listens.filter((_, j) => j !== i) })} />`)}
        </div>

        ${draft.mode === 'forwarding' ? html`<div class="card">
          <div class="card-head">
            <h2>Upstreams</h2>
            <button type="button" class="button button-small" onClick=${() => set({ upstreams: [...draft.upstreams, { type: 'udp', addr: '', method: 'post', timeout: '5s' }] })}>Add upstream</button>
          </div>
          <p class="muted" style="margin-top:0">Tried in order; on SERVFAIL, REFUSED or an error, the next is tried.</p>
          ${draft.upstreams.map((u, i) => html`<${UpstreamRow} key=${i} value=${u}
            onChange=${v => set({ upstreams: draft.upstreams.map((x, j) => (j === i ? v : x)) })}
            onRemove=${() => set({ upstreams: draft.upstreams.filter((_, j) => j !== i) })} />`)}
        </div>

        <div class="card">
          <h2>Cache</h2>
          <label class="field-check" style="margin-bottom:12px"><input type="checkbox" checked=${draft.cache.enabled}
            onChange=${e => set({ cache: { ...draft.cache, enabled: e.currentTarget.checked } })} />Enable the cache</label>
          ${draft.cache.enabled ? html`<div class="form-grid">
            ${[['min_ttl', 'Minimum TTL', '0s'], ['max_ttl', 'Maximum TTL', '24h'], ['negative_ttl', 'Negative TTL', '5m']].map(([k, label, ph]) => html`
              <${Field} label=${label} key=${k}>
                <input class="input" value=${draft.cache[k]} placeholder=${ph} onInput=${e => set({ cache: { ...draft.cache, [k]: e.currentTarget.value } })} />
              <//>`)}
            <${Field} label="Maximum entries">
              <input class="input" type="number" min="1" value=${draft.cache.max_entries}
                onInput=${e => set({ cache: { ...draft.cache, max_entries: Number(e.currentTarget.value) } })} />
            <//>
          </div>` : null}
        </div>` : null}
      </fieldset>
      <${Notice} error=${action.error} />
      ${editable ? html`<div class="form-actions">
        <button class="button button-primary" disabled=${action.busy}>Save and apply</button>
        <button class="button" type="button" onClick=${() => { setDraft(toDraft(settings.data)); action.setError(null); }}>Revert</button>
      </div>` : null}
    </form>
  <//>`;
}

function ListenRow({ value: l, state, onChange, onRemove }) {
  const set = patch => onChange({ ...l, ...patch });
  const secure = l.type === 'dot' || l.type === 'doh';
  return html`<div class="spec-row">
    <select class="input" value=${l.type} onChange=${e => set({ type: e.currentTarget.value, tlsMode: e.currentTarget.value === 'dot' && l.tlsMode === 'none' ? 'host' : l.tlsMode })} aria-label="Type">
      ${TRANSPORTS.map(t => html`<option value=${t}>${t.toUpperCase()}</option>`)}
    </select>
    <div class="spec-address">
      <input class="input mono" required value=${l.addr} placeholder=":53" onInput=${e => set({ addr: e.currentTarget.value })} aria-label="Address" />
      ${state ? html`<div style="margin-top:4px">${state.error
        ? html`<${Badge} tone="red" title=${state.error}>Down: ${state.error}<//>`
        : html`<${Badge} tone="green">Running<//>`}</div>` : null}
    </div>
    <button type="button" class="button button-ghost icon-button" aria-label="Remove" onClick=${onRemove}>✕</button>
    ${secure ? html`<div class="spec-extra">
      <${Field} label="TLS">
        <select class="input" value=${l.tlsMode} onChange=${e => set({ tlsMode: e.currentTarget.value })}>
          ${l.type === 'doh' ? html`<option value="none">No TLS (a reverse proxy terminates it)</option>` : null}
          <option value="host">Certificates from the certificate manager</option>
          <option value="files">Certificate files</option>
        </select>
      <//>
      ${l.tlsMode === 'files' ? html`
        <${Field} label="Certificate file"><input class="input mono" required value=${l.cert_file || ''} onInput=${e => set({ cert_file: e.currentTarget.value })} /><//>
        <${Field} label="Key file"><input class="input mono" required value=${l.key_file || ''} onInput=${e => set({ key_file: e.currentTarget.value })} /><//>` : null}
      ${l.tlsMode !== 'none' ? html`<${Field} label="Hostname" hint="When set, a client connecting to <id>.hostname is identified as <id> (needs a wildcard certificate)">
        <input class="input mono" value=${l.hostname || ''} placeholder="dns.example.com" onInput=${e => set({ hostname: e.currentTarget.value })} />
      <//>` : null}
      ${l.type === 'doh' ? html`<${Field} label="Trusted proxies" hint="One per line; their X-Forwarded-For is trusted">
        <textarea class="input" rows="2" value=${l.proxiesText || ''} placeholder="127.0.0.1" onInput=${e => set({ proxiesText: e.currentTarget.value })} />
      <//>` : null}
    </div>` : null}
  </div>`;
}

function UpstreamRow({ value: u, onChange, onRemove }) {
  const set = patch => onChange({ ...u, ...patch });
  const placeholder = { udp: '8.8.8.8:53', tcp: '8.8.8.8:53', dot: '1.1.1.1:853', doh: 'https://doh.pub/dns-query' }[u.type];
  return html`<div class="spec-row">
    <select class="input" value=${u.type} onChange=${e => set({ type: e.currentTarget.value })} aria-label="Type">
      ${TRANSPORTS.map(t => html`<option value=${t}>${t.toUpperCase()}</option>`)}
    </select>
    <input class="input mono spec-address" required value=${u.addr} placeholder=${placeholder} onInput=${e => set({ addr: e.currentTarget.value })} aria-label="Address" />
    <button type="button" class="button button-ghost icon-button" aria-label="Remove" onClick=${onRemove}>✕</button>
    <div class="spec-extra">
      <${Field} label="Timeout"><input class="input" value=${u.timeout} placeholder="5s" onInput=${e => set({ timeout: e.currentTarget.value })} /><//>
      ${u.type === 'doh' ? html`<${Field} label="Method">
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
    enabled: !s.disabled,
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
  return { disabled: !d.enabled, mode: d.mode, listens, upstreams, cache: d.mode === 'forwarding' ? d.cache : { ...d.cache, enabled: false } };
}
