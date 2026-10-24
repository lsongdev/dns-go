import { html, useEffect, useState } from '../lib/html.js';
import { useAction } from '../lib/hooks.js';
import { Page, Notice, Loading, Empty, Field, Modal, CopyButton, confirmDanger, toast } from '../lib/ui.js';
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
  const removeClient = i => confirmDanger(`删除客户端 ${data.clients[i].name}？`) &&
    persist({ ...data, clients: data.clients.filter((_, j) => j !== i) });

  if (!data || !status.data) {
    return html`<${Page} title="客户端与访问">${access.error || status.error ? html`<${Notice} error=${access.error || status.error} />` : html`<${Loading} />`}<//>`;
  }
  return html`<${Page} title="客户端与访问"
    subtitle="检查顺序：拒绝的网络 → 客户端 ID → 客户端网络 → 允许的网络。未知的客户端 ID 总是被拒绝。"
    actions=${html`<button class="btn btn-primary" onClick=${() => setEditing({ index: -1, client: { name: '', ids: [randomID()], networks: [] } })}>添加客户端</button>`}>
    <${Notice} error=${!editing && action.error} />
    ${data.clients.length === 0 ? html`<${Empty}>还没有客户端。添加客户端可以在日志中识别设备，或让它凭密钥 ID 从任何地方访问。<//>` : html`
      <div class="table-wrap"><table class="table">
        <thead><tr><th>名称</th><th>识别方式</th><th class="actions"></th></tr></thead>
        <tbody>${data.clients.map((c, i) => html`<tr key=${c.name}>
          <td class="cell-main">${c.name}</td>
          <td>
            ${c.ids.map(id => html`<span class="tag mono" key=${id} title="客户端 ID">id: ${id.slice(0, 4)}…</span>`)}
            ${c.networks.map(n => html`<span class="tag mono" key=${n}>${n}</span>`)}
          </td>
          <td class="actions"><span class="btn-group">
            <button class="btn btn-sm" onClick=${() => setEditing({ index: i, client: structuredClone(c) })}>编辑</button>
            <button class="btn btn-sm btn-danger" disabled=${action.busy} onClick=${() => removeClient(i)}>删除</button>
          </span></td>
        </tr>`)}</tbody>
      </table></div>`}
    <${Networks} access=${data} mode=${status.data.mode} busy=${action.busy}
      onSave=${async next => { if (await persist(next)) toast('访问设置已保存', 'success'); }} />
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
  const defaultLabel = mode === 'forwarding' ? '仅私有网络（回环、局域网、CGNAT、ULA）' : '所有人';
  return html`<form class="card section form" onSubmit=${submit}>
    <h2>网络</h2>
    <fieldset class="field"><span class="field-label">无需客户端 ID 即可查询的来源</span><div class="choices">
      <label class="choice"><input type="radio" checked=${useDefault} onChange=${() => set({ allow: null })} />
        <span><strong>默认</strong><span class="field-hint">${defaultLabel}</span></span></label>
      <label class="choice"><input type="radio" checked=${!useDefault} onChange=${() => set({ allow: [] })} />
        <span><strong>仅以下网络</strong><span class="field-hint">留空则所有人都需要客户端 ID。</span></span></label>
    </div></fieldset>
    ${!useDefault ? html`<${Field} label="允许的网络" hint=${html`每行一个：CIDR、地址或 <code>private</code>。<code>0.0.0.0/0</code> 与 <code>::/0</code> 会成为开放解析器。`}>
      <textarea class="input" rows="3" value=${draft.allowText} placeholder=${'private\n203.0.113.0/24'} onInput=${e => set({ allowText: e.currentTarget.value })} />
    <//>` : null}
    <div class="form-grid">
      <${Field} label="拒绝的网络" hint="每行一个">
        <textarea class="input" rows="2" value=${draft.denyText} placeholder="192.168.1.66" onInput=${e => set({ denyText: e.currentTarget.value })} />
      <//>
      <${Field} label="被拒绝的查询">
        <select class="input" value=${draft.deny_action || 'refuse'} onChange=${e => set({ deny_action: e.currentTarget.value })}>
          <option value="refuse">返回 REFUSED</option>
          <option value="drop">UDP 下静默丢弃（其它传输返回 REFUSED）</option>
        </select>
      <//>
    </div>
    <div class="form-actions"><button class="btn btn-primary" disabled=${busy}>保存</button></div>
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
  return html`<${Modal} wide title=${index < 0 ? '添加客户端' : `编辑 ${client.name}`} onClose=${onClose} footer=${html`
    <span class="spacer"></span>
    <button class="btn" type="button" onClick=${onClose}>取消</button>
    <button class="btn btn-primary" type="submit" form="client-form" disabled=${busy}>保存</button>`}>
    <form id="client-form" class="form" onSubmit=${submit}>
      <${Notice} error=${error} />
      <${Field} label="名称" required>
        <input class="input" required value=${c.name} onInput=${e => set({ name: e.currentTarget.value })} placeholder="alice-laptop" autofocus />
      <//>
      <div class="form-grid">
        <${Field} label="客户端 ID" hint=${html`字母、数字和连字符，每行一个；公网服务器上请当作密码保管。
          <button type="button" class="btn btn-ghost btn-sm" onClick=${() => set({ idsText: [...ids, randomID()].join('\n') })}>再生成一个</button>`}>
          <textarea class="input" rows="2" value=${c.idsText} onInput=${e => set({ idsText: e.currentTarget.value })} />
        <//>
        <${Field} label="网络" hint="在局域网中识别此客户端的来源地址（例如 DHCP 保留地址），每行一个。">
          <textarea class="input" rows="2" value=${c.networksText} placeholder="192.168.1.20" onInput=${e => set({ networksText: e.currentTarget.value })} />
        <//>
      </div>
      ${ids.length ? html`<div class="setup">
        <h3>设备配置</h3>
        <${Field} label="服务器主机名">
          <input class="input mono" value=${host} onInput=${e => setHost(e.currentTarget.value.trim())} />
        <//>
        <${Field} label="DNS over HTTPS" hint="浏览器、Windows 11、macOS / iOS 描述文件">
          <span class="copy-row"><code>https://${host}/dns-query/${ids[0]}</code><${CopyButton} text=${`https://${host}/dns-query/${ids[0]}`} /></span>
        <//>
        <${Field} label="DNS over TLS" hint="Android「私人 DNS」、路由器">
          <span class="copy-row"><code>${ids[0]}.${host}</code><${CopyButton} text=${`${ids[0]}.${host}`} /></span>
        <//>
        ${!doh || !dot ? html`<p class="small muted" style="margin:0">
          ${!doh ? '尚未配置 DoH 监听。' : ''}${!dot ? 'DoT 尚未配置；DoT 客户端 ID 还需要监听的 hostname 和通配符证书。' : ''}
        </p>` : null}
      </div>` : null}
    </form>
  <//>`;
}
