import { html, useState } from '../lib/html.js';
import { useAction } from '../lib/hooks.js';
import { Page, Notice, Loading, Empty, Badge, Field, Modal, confirmDanger } from '../lib/ui.js';
import { usePanel } from '../lib/panel.js';
import { useApi, useStatus, RECORD_TYPES, Link } from '../dns.js';
import { KINDS, zonePath } from './zones.js';

const PLACEHOLDERS = {
  A: '192.168.1.10', AAAA: 'fd00::10', CNAME: 'target.example.com.', MX: '10 mail',
  TXT: '"v=spf1 -all"', NS: 'ns1.example.com.', SRV: '10 5 443 host', PTR: 'host.example.com.',
  CAA: '0 issue "letsencrypt.org"', HTTPS: '1 . alpn=h2,h3', SVCB: '1 svc.example.com.',
  SOA: 'ns1 hostmaster 1 7200 3600 1209600 300', TLSA: '3 1 1 ABCDEF…', DS: '12345 13 2 ABCDEF…', DNSKEY: '257 3 13 base64…',
};

export default function Zone({ params }) {
  const { api, navigate } = usePanel();
  const base = zonePath(params.zone);
  const zone = useApi(base);
  const status = useStatus();
  const action = useAction();
  const [editing, setEditing] = useState(null); // { id, record }; id is empty for a new record
  const [current, setCurrent] = useState(null); // latest zone returned by a write
  const z = current && current.id === params.zone ? current : zone.data;

  const mutate = fn => action.run(async () => setCurrent(await fn()));
  const setKind = kind => mutate(() => api.put(base, { kind, records: z.record_list }));
  const remove = r => mutate(() => api.del(`${base}/records/${r.id}`));
  const removeZone = () => {
    if (!confirmDanger(`删除区域 ${z.origin} 及其全部记录？`)) return;
    action.run(async () => { await api.del(base); navigate('/zones'); });
  };

  if (!z) return html`<${Page} title=${params.zone}>${zone.error ? html`<${Notice} error=${zone.error} />` : html`<${Loading} />`}<//>`;
  return html`<${Page} title=${z.origin}
    subtitle=${html`<${Link} to="/zones">← 区域<//> · ${z.editable ? KINDS[z.kind]?.[1] : `从 ${z.path} 加载；修改该文件后重新加载服务（SIGHUP）。`}`}
    actions=${z.editable ? html`
      ${status.data?.mode === 'forwarding' ? html`<select class="input" style="width:auto" value=${z.kind} onChange=${e => setKind(e.currentTarget.value)} aria-label="区域类型">
        ${Object.entries(KINDS).map(([k, [label]]) => html`<option value=${k}>${label}</option>`)}
      </select>` : null}
      <button class="btn btn-primary" onClick=${() => setEditing({ id: '', record: { name: '', ttl: 300, type: 'A', data: '' } })}>添加记录</button>
      <button class="btn btn-danger" onClick=${removeZone}>删除区域</button>` : null}>
    <${Notice} error=${!editing && action.error} />
    ${z.record_list.length === 0 ? html`<${Empty}>还没有记录。<//>` : html`
      <div class="table-wrap"><table class="table">
        <thead><tr><th>名称</th><th>类型</th><th class="num">TTL</th><th>数据</th>${z.editable ? html`<th class="actions"></th>` : null}</tr></thead>
        <tbody>${z.record_list.map(r => html`<tr key=${r.id}>
          <td class="mono">${r.name}</td>
          <td><${Badge}>${r.type}<//></td>
          <td class="num muted">${r.ttl}</td>
          <td class="mono data">${r.data}</td>
          ${z.editable ? html`<td class="actions">
            <span class="btn-group">
              <button class="btn btn-sm" onClick=${() => setEditing({ id: r.id, record: { ...r } })}>编辑</button>
              <button class="btn btn-sm btn-danger" disabled=${action.busy} onClick=${() => remove(r)}>删除</button>
            </span>
          </td>` : null}
        </tr>`)}</tbody>
      </table></div>`}
    ${editing ? html`<${RecordForm} origin=${z.origin} initial=${editing.record} isNew=${!editing.id}
      busy=${action.busy} error=${action.error}
      onSave=${async record => {
        const { id, ...body } = record;
        const saved = await action.run(() => (editing.id ? api.put(`${base}/records/${editing.id}`, body) : api.post(`${base}/records`, body)));
        if (saved) { setCurrent(saved); setEditing(null); }
      }}
      onClose=${() => { setEditing(null); action.setError(null); }} />` : null}
  <//>`;
}

function RecordForm({ origin, initial, isNew, busy, error, onSave, onClose }) {
  const [r, setR] = useState(initial);
  const set = key => e => {
    const value = key === 'ttl' ? Number(e.currentTarget.value) : e.currentTarget.value;
    setR(prev => ({ ...prev, [key]: value }));
  };
  const suffix = origin === '.' ? '' : `.${origin}`;
  const types = RECORD_TYPES.includes(r.type) ? RECORD_TYPES : [r.type, ...RECORD_TYPES];
  return html`<${Modal} title=${isNew ? '添加记录' : '编辑记录'} onClose=${onClose} footer=${html`
    <span class="spacer"></span>
    <button class="btn" type="button" onClick=${onClose}>取消</button>
    <button class="btn btn-primary" type="submit" form="record-form" disabled=${busy}>保存</button>`}>
    <form id="record-form" class="form" onSubmit=${e => { e.preventDefault(); onSave(r); }}>
      <${Notice} error=${error} />
      <${Field} label="名称" hint="@ 表示区域本身">
        <span class="suffix"><input class="input mono" placeholder="@" value=${r.name} onInput=${set('name')} autofocus />${suffix ? html`<span>${suffix}</span>` : null}</span>
      <//>
      <div class="form-grid">
        <${Field} label="类型">
          <select class="input" value=${r.type} onChange=${set('type')}>${types.map(t => html`<option>${t}</option>`)}</select>
        <//>
        <${Field} label="TTL（秒）">
          <input class="input" type="number" min="0" max="2147483647" value=${r.ttl} onInput=${set('ttl')} />
        <//>
      </div>
      <${Field} label="数据" required hint=${`zone 文件语法。不以点结尾的名字相对于 ${origin}。`}>
        <input class="input mono" required placeholder=${PLACEHOLDERS[r.type] || ''} value=${r.data} onInput=${set('data')} />
      <//>
    </form>
  <//>`;
}
