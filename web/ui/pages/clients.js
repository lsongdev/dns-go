import { html, useEffect, useState } from '../lib/html.js';
import { useAction } from '../lib/hooks.js';
import { Page, Notice, Loading, Empty, Field, Modal, CopyButton, confirmDanger, toast, Table } from '../lib/ui.js';
import { usePanel } from '../lib/panel.js';
import { useApi, useStatus, randomID, lines } from '../dns.js';

export default function Clients() {
  const { api } = usePanel();
  const access = useApi('/access');
  const status = useStatus();
  const action = useAction();
  const [saved, setSaved] = useState(null); // latest access returned by a write
  const [editing, setEditing] = useState(null); // { index, client }
  const data = saved || access.data;

  const persist = next => action.run(async () => {
    const updated = await api.put('/access', next);
    setSaved(updated);
    return updated;
  });
  const saveClient = async client => {
    const clients = [...data.clients];
    if (editing.index < 0) clients.push(client);
    else clients[editing.index] = client;
    if (await persist({ ...data, clients })) setEditing(null);
  };
  const removeClient = i => confirmDanger(`Delete the client ${data.clients[i].name}?`) &&
    persist({ ...data, clients: data.clients.filter((_, j) => j !== i) });

  if (!data || !status.data) {
    return html`<${Page} title="Clients & access">${access.error || status.error ? html`<${Notice} error=${access.error || status.error} />` : html`<${Loading} />`}<//>`;
  }
  return html`<${Page} title="Clients & access"
    subtitle="Checked in order: denied networks → client ID → client networks → allowed networks. Unknown client IDs are always refused."
    actions=${html`<button class="button button-primary" onClick=${() => setEditing({ index: -1, client: { name: '', ids: [randomID()], networks: [] } })}>Add client</button>`}>
    <${Notice} error=${!editing && action.error} />
    ${data.clients.length === 0 ? html`<${Empty}>No clients yet. A client names a device in the logs, or lets it query from anywhere with a secret ID.<//>` : html`
      <${Table}>
        <thead><tr><th>Name</th><th>Identified by</th><th class="actions"></th></tr></thead>
        <tbody>${data.clients.map((c, i) => html`<tr key=${c.name}>
          <td class="cell-main">${c.name}</td>
          <td>
            ${c.ids.map(id => html`<span class="tag mono" key=${id} title="Client ID">id: ${id.slice(0, 4)}…</span>`)}
            ${c.networks.map(n => html`<span class="tag mono" key=${n}>${n}</span>`)}
          </td>
          <td class="actions"><span class="button-row">
            <button class="button button-small" onClick=${() => setEditing({ index: i, client: structuredClone(c) })}>Edit</button>
            <button class="button button-small button-danger" disabled=${action.busy} onClick=${() => removeClient(i)}>Delete</button>
          </span></td>
        </tr>`)}</tbody>
      <//>`}
    <${Networks} access=${data} mode=${status.data.mode} busy=${action.busy}
      onSave=${async next => { if (await persist(next)) toast('Access settings saved', 'success'); }} />
    ${editing ? html`<${ClientForm} ...${editing} listens=${status.data.listens} busy=${action.busy} error=${action.error}
      onSave=${saveClient} onClose=${() => { setEditing(null); action.setError(null); }} />` : null}
  <//>`;
}

function Networks({ access, mode, busy, onSave }) {
  const toDraft = a => ({ ...a, allowText: (a.allow || []).join('\n'), denyText: (a.deny || []).join('\n') });
  const [draft, setDraft] = useState(() => toDraft(access));
  useEffect(() => setDraft(toDraft(access)), [access]);
  const set = patch => setDraft(d => ({ ...d, ...patch }));
  const useDefault = draft.allow === null;
  const submit = e => {
    e.preventDefault();
    const { allowText, denyText, ...rest } = draft;
    onSave({ ...rest, allow: useDefault ? null : lines(allowText), deny: lines(denyText) });
  };
  const defaultLabel = mode === 'forwarding' ? 'Private networks only (loopback, LAN, CGNAT, ULA)' : 'Everyone';
  return html`<form class="card section form" onSubmit=${submit}>
    <h2>Networks</h2>
    <fieldset class="field"><span class="field-label">Who may query without a client ID</span><div class="choices">
      <label class="choice"><input type="radio" checked=${useDefault} onChange=${() => set({ allow: null })} />
        <span><strong>Default</strong><span class="field-hint">${defaultLabel}</span></span></label>
      <label class="choice"><input type="radio" checked=${!useDefault} onChange=${() => set({ allow: [] })} />
        <span><strong>Only these networks</strong><span class="field-hint">Empty requires a client ID from everyone.</span></span></label>
    </div></fieldset>
    ${!useDefault ? html`<${Field} label="Allowed networks" hint=${html`One per line: a CIDR, an address or <code>private</code>. <code>0.0.0.0/0</code> and <code>::/0</code> make an open resolver.`}>
      <textarea class="input" rows="3" value=${draft.allowText} placeholder=${'private\n203.0.113.0/24'} onInput=${e => set({ allowText: e.currentTarget.value })} />
    <//>` : null}
    <div class="form-grid">
      <${Field} label="Denied networks" hint="One per line">
        <textarea class="input" rows="2" value=${draft.denyText} placeholder="192.168.1.66" onInput=${e => set({ denyText: e.currentTarget.value })} />
      <//>
      <${Field} label="Refused queries">
        <select class="input" value=${draft.deny_action || 'refuse'} onChange=${e => set({ deny_action: e.currentTarget.value })}>
          <option value="refuse">Answer REFUSED</option>
          <option value="drop">Drop silently over UDP (REFUSED elsewhere)</option>
        </select>
      <//>
    </div>
    <div class="form-actions"><button class="button button-primary" disabled=${busy}>Save</button></div>
  </form>`;
}

function readHost() {
  try { return localStorage.getItem('dns-go.host') || location.hostname; } catch { return location.hostname; }
}

function ClientForm({ index, client, listens, busy, error, onSave, onClose }) {
  const [c, setC] = useState(() => ({ ...client, idsText: client.ids.join('\n'), networksText: client.networks.join('\n') }));
  const [host, setHost] = useState(readHost);
  useEffect(() => { try { localStorage.setItem('dns-go.host', host); } catch { /* storage unavailable */ } }, [host]);
  const set = patch => setC(prev => ({ ...prev, ...patch }));
  const ids = lines(c.idsText);
  const doh = listens.find(l => l.type === 'doh');
  const dot = listens.find(l => l.type === 'dot');
  const submit = e => {
    e.preventDefault();
    onSave({ name: c.name.trim(), ids, networks: lines(c.networksText) });
  };
  return html`<${Modal} wide title=${index < 0 ? 'Add client' : `Edit ${client.name}`} onClose=${onClose} footer=${html`
    <span class="spacer"></span>
    <button class="button" type="button" onClick=${onClose}>Cancel</button>
    <button class="button button-primary" type="submit" form="client-form" disabled=${busy}>Save</button>`}>
    <form id="client-form" class="form" onSubmit=${submit}>
      <${Notice} error=${error} />
      <${Field} label="Name" required>
        <input class="input" required value=${c.name} onInput=${e => set({ name: e.currentTarget.value })} placeholder="alice-laptop" autofocus />
      <//>
      <div class="form-grid">
        <${Field} label="Client IDs" hint=${html`Letters, digits and hyphens, one per line; on a public server, keep them like passwords.
          <button type="button" class="button button-ghost button-small" onClick=${() => set({ idsText: [...ids, randomID()].join('\n') })}>Generate another</button>`}>
          <textarea class="input" rows="2" value=${c.idsText} onInput=${e => set({ idsText: e.currentTarget.value })} />
        <//>
        <${Field} label="Networks" hint="Source addresses that identify this client on the LAN (such as DHCP reservations), one per line.">
          <textarea class="input" rows="2" value=${c.networksText} placeholder="192.168.1.20" onInput=${e => set({ networksText: e.currentTarget.value })} />
        <//>
      </div>
      ${ids.length ? html`<div class="setup">
        <h3>Device setup</h3>
        <${Field} label="Server hostname">
          <input class="input mono" value=${host} onInput=${e => setHost(e.currentTarget.value.trim())} />
        <//>
        <${Field} label="DNS over HTTPS" hint="Browsers, Windows 11, macOS / iOS profiles">
          <span class="copy-row"><code>https://${host}/dns-query/${ids[0]}</code><${CopyButton} text=${`https://${host}/dns-query/${ids[0]}`} /></span>
        <//>
        <${Field} label="DNS over TLS" hint="Android Private DNS, routers">
          <span class="copy-row"><code>${ids[0]}.${host}</code><${CopyButton} text=${`${ids[0]}.${host}`} /></span>
        <//>
        ${!doh || !dot ? html`<p class="small muted" style="margin:0">
          ${!doh ? 'No DoH listener yet. ' : ''}${!dot ? 'No DoT listener yet; DoT client IDs also need the listener hostname and a wildcard certificate.' : ''}
        </p>` : null}
      </div>` : null}
    </form>
  <//>`;
}
