import { useState } from '../vendor/hooks.js';
import { html, api, useApi, useAction, fmtNumber, ErrorBox, Loading, Empty, Modal, RECORD_TYPES } from '../lib.js';

const KIND_HELP = {
  static: 'Owns the whole domain: names without records answer NXDOMAIN.',
  transparent: 'Overrides only the names listed; everything else resolves normally.',
};

const PLACEHOLDERS = {
  A: '192.168.1.10', AAAA: 'fd00::10', CNAME: 'target.example.com.', MX: '10 mail',
  TXT: '"v=spf1 -all"', NS: 'ns1.example.com.', SRV: '10 5 443 host', PTR: 'host.example.com.',
  CAA: '0 issue "letsencrypt.org"', HTTPS: '1 . alpn=h2,h3', SVCB: '1 svc.example.com.',
  SOA: 'ns1 hostmaster 1 7200 3600 1209600 300', TLSA: '3 1 1 ABCDEF…', DS: '12345 13 2 ABCDEF…', DNSKEY: '257 3 13 base64…',
};

export function Zones({ status, route }) {
  return route ? html`<${ZoneDetail} id=${route} status=${status} />` : html`<${ZoneList} status=${status} />`;
}

function ZoneList({ status }) {
  const zones = useApi('/zones');
  const [creating, setCreating] = useState(false);
  return html`
    <section class="page">
      <header class="page-head row">
        <div>
          <h2>Zones</h2>
          <p class="muted">Local DNS data. ${status.mode === 'authoritative'
            ? 'In authoritative mode every zone needs an SOA and at least one NS record.'
            : 'Use static zones for domains you own, transparent zones to override single names.'}</p>
        </div>
        <button class="primary" onClick=${() => setCreating(true)}>New zone</button>
      </header>
      <${ErrorBox} error=${zones.error} />
      ${zones.loading && !zones.data ? html`<${Loading} />` : !zones.data?.length ? html`<${Empty}>No zones yet.</${Empty}>` : html`
        <div class="table-wrap">
          <table class="table">
            <thead><tr><th>Zone</th><th>Kind</th><th>Source</th><th class="num">Records</th></tr></thead>
            <tbody>
              ${zones.data.map((z) => html`
                <tr class="link" onClick=${() => { location.hash = `#/zones/${encodeURIComponent(z.id)}`; }}>
                  <td><a href=${`#/zones/${encodeURIComponent(z.id)}`}><strong>${z.origin}</strong></a></td>
                  <td><span class=${`badge kind-${z.kind}`}>${z.kind}</span></td>
                  <td>${z.source === 'records' ? 'panel / config' : html`<span title=${z.path}>${z.source.replace('_', ' ')}</span>`}</td>
                  <td class="num">${fmtNumber(z.records)}</td>
                </tr>`)}
            </tbody>
          </table>
        </div>`}
      ${creating && html`<${CreateZone} status=${status} onClose=${() => setCreating(false)} />`}
    </section>`;
}

function CreateZone({ status, onClose }) {
  const authoritative = status.mode === 'authoritative';
  const [origin, setOrigin] = useState('');
  const [kind, setKind] = useState('static');
  const [ns, setNS] = useState('ns1');
  const action = useAction();
  const submit = async (e) => {
    e.preventDefault();
    const records = authoritative
      ? [
          { name: '@', ttl: 3600, type: 'SOA', data: `${ns} hostmaster 1 7200 3600 1209600 300` },
          { name: '@', ttl: 3600, type: 'NS', data: ns },
        ]
      : [];
    const zone = await action.run(() => api('POST', '/zones', { origin, kind, records })).catch(() => null);
    if (zone) location.hash = `#/zones/${encodeURIComponent(zone.id)}`;
  };
  return html`
    <${Modal} title="New zone" onClose=${onClose}>
      <form onSubmit=${submit} class="form">
        <label>Domain<input required placeholder="home.lan" value=${origin} onInput=${(e) => setOrigin(e.target.value)} autofocus /></label>
        ${authoritative
          ? html`<label>Primary name server<input required value=${ns} onInput=${(e) => setNS(e.target.value)} />
              <small class="muted">An SOA and NS record are created for you; add the server's A record next.</small></label>`
          : html`<fieldset class="radios">
              <legend>Kind</legend>
              ${['static', 'transparent'].map((k) => html`
                <label class="radio"><input type="radio" name="kind" checked=${kind === k} onChange=${() => setKind(k)} />
                  <span><strong>${k}</strong><small class="muted">${KIND_HELP[k]}</small></span></label>`)}
            </fieldset>`}
        <${ErrorBox} error=${action.error} />
        <footer><button type="button" onClick=${onClose}>Cancel</button><button class="primary" disabled=${action.busy}>Create</button></footer>
      </form>
    </${Modal}>`;
}

function ZoneDetail({ id, status }) {
  const zone = useApi(`/zones/${encodeURIComponent(id)}`);
  const action = useAction();
  const [editing, setEditing] = useState(null); // { index, record } ; index -1 = new
  const z = zone.data;

  const save = async (records, kind = z.kind) => {
    const updated = await action.run(() => api('PUT', `/zones/${encodeURIComponent(id)}`, { kind, records }));
    zone.setData(updated);
  };
  const saveRecord = async (record) => {
    const records = [...z.record_list];
    if (editing.index < 0) records.push(record);
    else records[editing.index] = record;
    await save(records);
    setEditing(null);
  };
  const remove = (index) => save(z.record_list.filter((_, i) => i !== index)).catch(() => {});
  const removeZone = async () => {
    if (!confirm(`Delete zone ${z.origin} and all its records?`)) return;
    await action.run(() => api('DELETE', `/zones/${encodeURIComponent(id)}`)).catch(() => null);
    location.hash = '#/zones';
  };

  if (zone.error) return html`<section class="page"><a href="#/zones">← Zones</a><${ErrorBox} error=${zone.error} /></section>`;
  if (!z) return html`<section class="page"><${Loading} /></section>`;
  return html`
    <section class="page">
      <a href="#/zones" class="back">← Zones</a>
      <header class="page-head row">
        <div>
          <h2>${z.origin}</h2>
          <p class="muted">${z.editable
            ? KIND_HELP[z.kind]
            : `Loaded from ${z.path}. Edit that file and reload the server (SIGHUP) to change it.`}</p>
        </div>
        ${z.editable && html`<div class="btn-row">
          ${status.mode === 'forwarding' && html`
            <select value=${z.kind} onChange=${(e) => save(z.record_list, e.target.value).catch(() => {})} aria-label="Zone kind">
              <option value="static">static</option><option value="transparent">transparent</option>
            </select>`}
          <button class="primary" onClick=${() => setEditing({ index: -1, record: { name: '', ttl: 300, type: 'A', data: '' } })}>Add record</button>
          <button class="danger" onClick=${removeZone}>Delete zone</button>
        </div>`}
      </header>
      <${ErrorBox} error=${!editing && action.error} />
      ${z.record_list.length === 0 ? html`<${Empty}>No records yet.</${Empty}>` : html`
        <div class="table-wrap">
          <table class="table records">
            <thead><tr><th>Name</th><th>Type</th><th class="num">TTL</th><th>Data</th>${z.editable && html`<th></th>`}</tr></thead>
            <tbody>
              ${z.record_list.map((r, i) => html`
                <tr>
                  <td class="mono">${r.name}</td>
                  <td><span class="badge">${r.type}</span></td>
                  <td class="num muted">${r.ttl}</td>
                  <td class="mono data">${r.data}</td>
                  ${z.editable && html`<td class="actions nowrap">
                    <button class="small" onClick=${() => setEditing({ index: i, record: { ...r } })}>Edit</button>
                    <button class="small danger" disabled=${action.busy} onClick=${() => remove(i)}>Delete</button>
                  </td>`}
                </tr>`)}
            </tbody>
          </table>
        </div>`}
      ${editing && html`<${RecordForm} origin=${z.origin} initial=${editing.record} isNew=${editing.index < 0}
          busy=${action.busy} error=${action.error} onSave=${(r) => saveRecord(r).catch(() => {})}
          onClose=${() => { setEditing(null); action.setError(null); }} />`}
    </section>`;
}

function RecordForm({ origin, initial, isNew, busy, error, onSave, onClose }) {
  const [r, setR] = useState(initial);
  const set = (k) => (e) => {
    const v = k === 'ttl' ? Number(e.target.value) : e.target.value;
    setR((prev) => ({ ...prev, [k]: v }));
  };
  const suffix = origin === '.' ? '' : `.${origin}`;
  return html`
    <${Modal} title=${isNew ? 'Add record' : 'Edit record'} onClose=${onClose}>
      <form class="form" onSubmit=${(e) => { e.preventDefault(); onSave(r); }}>
        <div class="form-row">
          <label class="grow">Name
            <span class="input-suffix"><input placeholder="@" value=${r.name} onInput=${set('name')} autofocus /><span>${suffix}</span></span>
          </label>
          <label>Type<select value=${r.type} onChange=${set('type')}>
            ${(RECORD_TYPES.includes(r.type) ? RECORD_TYPES : [r.type, ...RECORD_TYPES]).map((t) => html`<option>${t}</option>`)}
          </select></label>
          <label class="ttl">TTL<input type="number" min="0" max="2147483647" value=${r.ttl} onInput=${set('ttl')} /></label>
        </div>
        <label>Data<input class="mono" required placeholder=${PLACEHOLDERS[r.type] || ''} value=${r.data} onInput=${set('data')} />
          <small class="muted">Zone-file syntax. Names without a trailing dot are relative to ${origin}; "@" is the zone itself.</small></label>
        <${ErrorBox} error=${error} />
        <footer><button type="button" onClick=${onClose}>Cancel</button><button class="primary" disabled=${busy}>Save</button></footer>
      </form>
    </${Modal}>`;
}
