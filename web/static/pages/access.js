import { useState, useEffect } from '../vendor/hooks.js';
import { html, api, useApi, useAction, ErrorBox, Loading, Empty, Modal, ListInput, randomID, copyText } from '../lib.js';

export function Access({ status }) {
  const access = useApi('/access');
  const action = useAction();
  const [draft, setDraft] = useState(null);
  const [editing, setEditing] = useState(null); // { index, client }
  const [saved, setSaved] = useState(false);

  useEffect(() => { if (access.data) setDraft(structuredClone(access.data)); }, [access.data]);

  const persist = async (next) => {
    setSaved(false);
    const updated = await action.run(() => api('PUT', '/access', next));
    access.setData(updated);
    setSaved(true);
    return updated;
  };
  if (access.error) return html`<section class="page"><${ErrorBox} error=${access.error} /></section>`;
  if (!draft) return html`<section class="page"><${Loading} /></section>`;

  const useDefault = draft.allow === null;
  const dirty = JSON.stringify(draft) !== JSON.stringify(access.data);
  const defaultLabel = status.mode === 'forwarding' ? 'private networks only (loopback, LAN, CGNAT, ULA)' : 'everyone';
  const saveClient = async (client) => {
    const clients = [...draft.clients];
    if (editing.index < 0) clients.push(client);
    else clients[editing.index] = client;
    await persist({ ...access.data, clients }).then(() => setEditing(null)).catch(() => {});
  };
  const removeClient = (i) => confirm(`Remove client ${draft.clients[i].name}?`) &&
    persist({ ...access.data, clients: draft.clients.filter((_, j) => j !== i) }).catch(() => {});

  return html`
    <section class="page">
      <header class="page-head"><h2>Clients & access</h2>
        <p class="muted">Order of checks: denied networks → client ID → client networks → allowed networks. Unknown client IDs are always refused.</p>
      </header>
      <${ErrorBox} error=${!editing && action.error} />
      <div class="panel">
        <div class="panel-head">
          <h3>Clients</h3>
          <button class="primary" onClick=${() => setEditing({ index: -1, client: { name: '', ids: [randomID()], networks: [] } })}>Add client</button>
        </div>
        ${draft.clients.length === 0 ? html`<${Empty}>No clients. Add one to identify a device in the logs or to let it in from anywhere with a secret ID.</${Empty}>` : html`
          <div class="table-wrap"><table class="table">
            <thead><tr><th>Name</th><th>Identified by</th><th></th></tr></thead>
            <tbody>${draft.clients.map((c, i) => html`
              <tr>
                <td><strong>${c.name}</strong></td>
                <td>
                  ${c.ids.map((id) => html`<span class="tag mono" title="Client ID">id: ${id.slice(0, 4)}…</span>`)}
                  ${c.networks.map((n) => html`<span class="tag mono">${n}</span>`)}
                </td>
                <td class="actions nowrap">
                  <button class="small" onClick=${() => setEditing({ index: i, client: structuredClone(c) })}>Edit</button>
                  <button class="small danger" disabled=${action.busy} onClick=${() => removeClient(i)}>Remove</button>
                </td>
              </tr>`)}
            </tbody>
          </table></div>`}
      </div>
      <div class="panel">
        <div class="panel-head">
          <h3>Networks</h3>
          <div class="btn-row">
            ${saved && !dirty && html`<span class="muted small">Saved</span>`}
            <button class="primary" disabled=${!dirty || action.busy} onClick=${() => persist(draft).catch(() => {})}>Save</button>
          </div>
        </div>
        <div class="form">
          <fieldset class="radios">
            <legend>Who may query without a client ID</legend>
            <label class="radio"><input type="radio" checked=${useDefault} onChange=${() => setDraft((d) => ({ ...d, allow: null }))} />
              <span><strong>Default</strong><small class="muted">${defaultLabel}</small></span></label>
            <label class="radio"><input type="radio" checked=${!useDefault} onChange=${() => setDraft((d) => ({ ...d, allow: [] }))} />
              <span><strong>Only these networks</strong><small class="muted">Leave empty to require a client ID from everyone.</small></span></label>
          </fieldset>
          ${!useDefault && html`<label>Allowed networks
            <${ListInput} value=${draft.allow} onInput=${(v) => setDraft((d) => ({ ...d, allow: v }))} placeholder=${'private\n203.0.113.0/24'} />
            <small class="muted">One per line: CIDR, address, or <code>private</code>. <code>0.0.0.0/0</code> and <code>::/0</code> make an open resolver.</small></label>`}
          <label>Denied networks
            <${ListInput} value=${draft.deny} onInput=${(v) => setDraft((d) => ({ ...d, deny: v }))} placeholder="192.168.1.66" rows="2" /></label>
          <label>Refused queries
            <select value=${draft.deny_action} onChange=${(e) => { const v = e.target.value; setDraft((d) => ({ ...d, deny_action: v })); }}>
              <option value="refuse">Answer REFUSED</option>
              <option value="drop">Drop silently over UDP (REFUSED elsewhere)</option>
            </select></label>
        </div>
      </div>
      ${editing && html`<${ClientForm} ...${editing} status=${status} busy=${action.busy} error=${action.error}
          onSave=${saveClient} onClose=${() => { setEditing(null); action.setError(null); }} />`}
    </section>`;
}

function ClientForm({ index, client, status, busy, error, onSave, onClose }) {
  const [c, setC] = useState(client);
  const [host, setHost] = useState(() => { try { return localStorage.getItem('dns-go.host') || location.hostname; } catch { return location.hostname; } });
  const [copied, setCopied] = useState('');
  useEffect(() => { try { localStorage.setItem('dns-go.host', host); } catch { /* ignore */ } }, [host]);
  const doh = status.listens.find((l) => l.type === 'doh');
  const dot = status.listens.find((l) => l.type === 'dot');
  const copy = async (text) => { if (await copyText(text)) { setCopied(text); setTimeout(() => setCopied(''), 2000); } };
  return html`
    <${Modal} title=${index < 0 ? 'Add client' : `Edit ${client.name}`} onClose=${onClose} wide>
      <form class="form" onSubmit=${(e) => { e.preventDefault(); onSave(c); }}>
        <label>Name<input required value=${c.name} onInput=${(e) => { const name = e.target.value; setC((prev) => ({ ...prev, name })); }} placeholder="alice-laptop" autofocus /></label>
        <label>Client IDs
          <${ListInput} value=${c.ids} onInput=${(ids) => setC((prev) => ({ ...prev, ids }))} rows="2" placeholder="random secret" />
          <small class="muted">Letters, digits and hyphens. Treat them as passwords on public servers.${' '}
            <button type="button" class="link" onClick=${() => setC((prev) => ({ ...prev, ids: [...prev.ids, randomID()] }))}>Generate another</button></small>
        </label>
        <label>Networks
          <${ListInput} value=${c.networks} onInput=${(networks) => setC((prev) => ({ ...prev, networks }))} rows="2" placeholder="192.168.1.20" />
          <small class="muted">Source addresses that identify this client on your LAN (e.g. a DHCP reservation).</small>
        </label>
        ${c.ids.length > 0 && html`
          <div class="setup">
            <h4>Device setup</h4>
            <label>Server hostname<input value=${host} onInput=${(e) => setHost(e.target.value.trim())} /></label>
            ${c.ids.slice(0, 1).map((id) => html`
              <dl>
                <dt>DNS over HTTPS <small class="muted">browsers, Windows 11, macOS/iOS profiles</small></dt>
                <dd><code>https://${host}/dns-query/${id}</code>
                  <button type="button" class="small" onClick=${() => copy(`https://${host}/dns-query/${id}`)}>${copied === `https://${host}/dns-query/${id}` ? 'Copied' : 'Copy'}</button></dd>
                <dt>DNS over TLS <small class="muted">Android "Private DNS", routers</small></dt>
                <dd><code>${id}.${host}</code>
                  <button type="button" class="small" onClick=${() => copy(`${id}.${host}`)}>${copied === `${id}.${host}` ? 'Copied' : 'Copy'}</button></dd>
              </dl>`)}
            ${(!doh || !dot) && html`<p class="small muted">${!doh ? 'No DoH listener is configured. ' : ''}${!dot ? 'No DoT listener is configured; DoT IDs also need listens[].hostname and a wildcard certificate.' : ''}</p>`}
          </div>`}
        <${ErrorBox} error=${error} />
        <footer><button type="button" onClick=${onClose}>Cancel</button><button class="primary" disabled=${busy}>Save</button></footer>
      </form>
    </${Modal}>`;
}
