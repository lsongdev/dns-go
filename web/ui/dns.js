// dns-go UI helpers: API access, formatting and small components shared by
// the pages. Generic components are in lib/.
import { html } from './lib/html.js';
import { useResource } from './lib/hooks.js';
import { usePanel } from './lib/panel.js';
import { Badge } from './lib/ui.js';

// useApi loads a GET endpoint of this module, polling every interval
// milliseconds while it is positive.
export function useApi(path, interval) {
  const { api } = usePanel();
  return useResource(signal => api.get(path, { signal }), [path], { interval });
}

// useStatus loads /status: mode, listeners, counts.
export const useStatus = () => useApi('/status', 15000);

// Link points at a page of this module.
export function Link({ to, children, ...props }) {
  const { href } = usePanel();
  return html`<a href=${href(to)} ...${props}>${children}</a>`;
}

// request sends a write and returns the parsed body; unlike the shared
// client it keeps the server's error details (e.g. the invalid rule lines).
export async function request(client, method, path, body) {
  const response = await fetch(client.url(path), {
    method,
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const payload = response.status === 204 ? null : await response.json().catch(() => null);
  if (!response.ok) {
    const err = new Error(payload?.error || response.statusText);
    err.status = response.status;
    err.details = payload?.details;
    throw err;
  }
  return payload;
}

const SOURCES = {
  upstream: ['上游', 'blue'], cache: ['缓存', 'green'], zone: ['本地区域', 'green'], filter: ['已拦截', 'red'],
  denied: ['拒绝访问', 'amber'], error: ['错误', 'red'], policy: ['策略', 'gray'], invalid: ['无效请求', 'gray'],
};

export const SOURCE_KEYS = Object.keys(SOURCES);
export const sourceLabel = source => SOURCES[source]?.[0] || source;

export function SourceBadge({ source }) {
  const [label, tone] = SOURCES[source] || [source, 'gray'];
  return html`<${Badge} tone=${tone}>${label}<//>`;
}

export const MODES = { forwarding: '转发解析', authoritative: '权威服务器' };

export const RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'PTR', 'CAA', 'HTTPS', 'SVCB', 'SOA', 'TLSA', 'DS', 'DNSKEY'];

export const number = n => new Intl.NumberFormat('zh-CN').format(n || 0);

export const share = (part, total) => (total ? `${((part / total) * 100).toFixed(1)}%` : '0%');

export function micros(us) {
  if (us < 1000) return `${us}µs`;
  return `${(us / 1000).toFixed(us < 10000 ? 1 : 0)}ms`;
}

export function uptime(seconds) {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d) return `${d} 天 ${h} 小时`;
  if (h) return `${h} 小时 ${m} 分`;
  if (m) return `${m} 分钟`;
  return `${seconds} 秒`;
}

export function clock(iso) {
  return new Date(iso).toLocaleTimeString('zh-CN', { hour12: false });
}

// randomID returns a client identifier usable in a DoH path and an SNI label.
export function randomID(length = 16) {
  const alphabet = 'abcdefghijkmnpqrstuvwxyz23456789';
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes, b => alphabet[b % alphabet.length]).join('');
}

// lines splits a textarea into trimmed, non-empty lines.
export const lines = text => text.split('\n').map(s => s.trim()).filter(Boolean);
