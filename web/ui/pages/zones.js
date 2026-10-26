import { html, useState } from '../lib/html.js';
import { useAction } from '../lib/hooks.js';
import { Page, Notice, Loading, Empty, Badge, Field, Modal, Table } from '../lib/ui.js';
import { usePanel } from '../lib/panel.js';
import { useApi, useStatus, number, Link } from '../dns.js';

export const KINDS = {
  static: ['Static', 'Owns the whole domain: names without records answer NXDOMAIN.'],
  transparent: ['Transparent', 'Overrides only the listed names; others resolve as usual.'],
};

const SOURCES = { zone_file: 'zone file', hosts_file: 'hosts file' };

export const zonePath = id => `/zones/${encodeURIComponent(id)}`;

export default function Zones() {
  const zones = useApi('/zones');
  const status = useStatus();
  const [creating, setCreating] = useState(false);
  const authoritative = status.data?.mode === 'authoritative';
  return html`<${Page} title="Zones"
    subtitle=${authoritative ? 'In authoritative mode, every zone needs an SOA and at least one NS record.' : 'Use a static zone for a domain you own, and a transparent zone to override a few public names.'}
    actions=${html`<button class="button button-primary" onClick=${() => setCreating(true)}>New zone</button>`}>
    <${Notice} error=${zones.error} />
    ${zones.data === undefined ? (zones.error ? null : html`<${Loading} />`) : !zones.data.length ? html`<${Empty}>No zones yet.<//>` : html`
      <${Table}>
        <thead><tr><th>Zone</th><th>Kind</th><th>Source</th><th class="num">Records</th></tr></thead>
        <tbody>${zones.data.map(z => html`<tr key=${z.id}>
          <td><${Link} to=${zonePath(z.id)} class="cell-main mono">${z.origin}<//></td>
          <td><${Badge} tone=${z.kind === 'static' ? 'blue' : 'gray'}>${KINDS[z.kind]?.[0] || z.kind}<//></td>
          <td>${z.source === 'records' ? 'Managed here' : html`<span title=${z.path}>${SOURCES[z.source] || z.source} (read-only)</span>`}</td>
          <td class="num">${number(z.records)}</td>
        </tr>`)}</tbody>
      <//>`}
    ${creating ? html`<${CreateZone} authoritative=${authoritative} onClose=${() => setCreating(false)} />` : null}
  <//>`;
}

function CreateZone({ authoritative, onClose }) {
  const { api, navigate } = usePanel();
  const [origin, setOrigin] = useState('');
  const [kind, setKind] = useState('static');
  const [ns, setNS] = useState('ns1');
  const { busy, error, run } = useAction();
  const submit = e => {
    e.preventDefault();
    run(async () => {
      const records = authoritative
        ? [
            { name: '@', ttl: 3600, type: 'SOA', data: `${ns} hostmaster 1 7200 3600 1209600 300` },
            { name: '@', ttl: 3600, type: 'NS', data: ns },
          ]
        : [];
      const zone = await api.post('/zones', { origin, kind, records });
      navigate(zonePath(zone.id));
    });
  };
  return html`<${Modal} title="New zone" onClose=${onClose} footer=${html`
    <span class="spacer"></span>
    <button class="button" type="button" onClick=${onClose}>Cancel</button>
    <button class="button button-primary" type="submit" form="create-zone" disabled=${busy}>Create</button>`}>
    <form id="create-zone" class="form" onSubmit=${submit}>
      <${Notice} error=${error} />
      <${Field} label="Domain" required>
        <input class="input mono" required placeholder="home.lan" value=${origin} onInput=${e => setOrigin(e.currentTarget.value)} autofocus />
      <//>
      ${authoritative
        ? html`<${Field} label="Primary name server" required hint="The SOA and NS records are created for you; then add an A record for it.">
            <input class="input mono" required value=${ns} onInput=${e => setNS(e.currentTarget.value)} />
          <//>`
        : html`<fieldset class="field"><span class="field-label">Kind</span><div class="choices">
            ${Object.entries(KINDS).map(([k, [label, help]]) => html`<label class="choice" key=${k}>
              <input type="radio" name="kind" checked=${kind === k} onChange=${() => setKind(k)} />
              <span><strong>${label}</strong><span class="field-hint">${help}</span></span>
            </label>`)}
          </div></fieldset>`}
    </form>
  <//>`;
}
