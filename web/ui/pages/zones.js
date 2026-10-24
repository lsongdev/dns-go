import { html, useState } from '../lib/html.js';
import { useAction } from '../lib/hooks.js';
import { Page, Notice, Loading, Empty, Badge, Field, Modal } from '../lib/ui.js';
import { usePanel } from '../lib/panel.js';
import { useApi, useStatus, number, Link } from '../dns.js';

export const KINDS = {
  static: ['静态', '拥有整个域名：没有记录的名字返回 NXDOMAIN。'],
  transparent: ['透明', '只覆盖列出的名字，其余名字照常解析。'],
};

const SOURCES = { zone_file: 'zone 文件', hosts_file: 'hosts 文件' };

export const zonePath = id => `/zones/${encodeURIComponent(id)}`;

export default function Zones() {
  const zones = useApi('/zones');
  const status = useStatus();
  const [creating, setCreating] = useState(false);
  const authoritative = status.data?.mode === 'authoritative';
  return html`<${Page} title="区域"
    subtitle=${authoritative ? '权威模式下每个区域都需要 SOA 和至少一条 NS 记录。' : '自有域名用静态区域，覆盖个别公网域名用透明区域。'}
    actions=${html`<button class="btn btn-primary" onClick=${() => setCreating(true)}>新建区域</button>`}>
    <${Notice} error=${zones.error} />
    ${zones.data === undefined ? (zones.error ? null : html`<${Loading} />`) : !zones.data.length ? html`<${Empty}>还没有区域。<//>` : html`
      <div class="table-wrap"><table class="table">
        <thead><tr><th>区域</th><th>类型</th><th>来源</th><th class="num">记录</th></tr></thead>
        <tbody>${zones.data.map(z => html`<tr key=${z.id}>
          <td><${Link} to=${zonePath(z.id)} class="cell-main mono">${z.origin}<//></td>
          <td><${Badge} tone=${z.kind === 'static' ? 'blue' : 'gray'}>${KINDS[z.kind]?.[0] || z.kind}<//></td>
          <td>${z.source === 'records' ? '面板管理' : html`<span title=${z.path}>${SOURCES[z.source] || z.source}（只读）</span>`}</td>
          <td class="num">${number(z.records)}</td>
        </tr>`)}</tbody>
      </table></div>`}
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
  return html`<${Modal} title="新建区域" onClose=${onClose} footer=${html`
    <span class="spacer"></span>
    <button class="btn" type="button" onClick=${onClose}>取消</button>
    <button class="btn btn-primary" type="submit" form="create-zone" disabled=${busy}>创建</button>`}>
    <form id="create-zone" class="form" onSubmit=${submit}>
      <${Notice} error=${error} />
      <${Field} label="域名" required>
        <input class="input mono" required placeholder="home.lan" value=${origin} onInput=${e => setOrigin(e.currentTarget.value)} autofocus />
      <//>
      ${authoritative
        ? html`<${Field} label="主域名服务器" required hint="会自动创建 SOA 和 NS 记录；接着为它添加 A 记录。">
            <input class="input mono" required value=${ns} onInput=${e => setNS(e.currentTarget.value)} />
          <//>`
        : html`<fieldset class="field"><span class="field-label">类型</span><div class="choices">
            ${Object.entries(KINDS).map(([k, [label, help]]) => html`<label class="choice" key=${k}>
              <input type="radio" name="kind" checked=${kind === k} onChange=${() => setKind(k)} />
              <span><strong>${label}</strong><span class="field-hint">${help}</span></span>
            </label>`)}
          </div></fieldset>`}
    </form>
  <//>`;
}
