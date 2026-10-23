// Shared helpers: the htm binding, the API client, and small UI utilities.
import { h } from './vendor/preact.js';
import { useState, useEffect, useCallback, useRef } from './vendor/hooks.js';
import htm from './vendor/htm.js';

export const html = htm.bind(h);

const TOKEN_KEY = 'dns-go.token';

export function getToken() {
  try { return localStorage.getItem(TOKEN_KEY) || ''; } catch { return ''; }
}

export function setToken(token) {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    else localStorage.removeItem(TOKEN_KEY);
  } catch { /* storage unavailable: token lives for this page only */ }
}

// ApiError carries the HTTP status and the server's error details.
export class ApiError extends Error {
  constructor(status, message, details) {
    super(message);
    this.status = status;
    this.details = details;
  }
}

const unauthorizedListeners = new Set();
export function onUnauthorized(fn) {
  unauthorizedListeners.add(fn);
  return () => unauthorizedListeners.delete(fn);
}

// api('GET', '/zones') calls /api/zones with the stored bearer token.
export async function api(method, path, body) {
  const headers = { Accept: 'application/json' };
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(`/api${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401) unauthorizedListeners.forEach((fn) => fn());
    throw new ApiError(res.status, data.error || res.statusText, data.details);
  }
  return data;
}

// useApi loads a GET endpoint, optionally polling. Returns
// { data, error, loading, reload, setData }.
export function useApi(path, { interval = 0 } = {}) {
  const [state, setState] = useState({ data: null, error: null, loading: true });
  const alive = useRef(true);
  const reload = useCallback(async () => {
    try {
      const data = await api('GET', path);
      if (alive.current) setState({ data, error: null, loading: false });
    } catch (error) {
      if (alive.current) setState((s) => ({ ...s, error, loading: false }));
    }
  }, [path]);
  useEffect(() => {
    alive.current = true;
    setState((s) => ({ ...s, loading: true }));
    reload();
    let timer;
    if (interval) timer = setInterval(() => document.hidden || reload(), interval);
    return () => { alive.current = false; clearInterval(timer); };
  }, [reload, interval]);
  const setData = (data) => setState((s) => ({ ...s, data }));
  return { ...state, reload, setData };
}

// useAction wraps an async mutation with busy/error state.
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const run = useCallback(async (fn) => {
    setBusy(true);
    setError(null);
    try {
      return await fn();
    } catch (e) {
      setError(e);
      throw e;
    } finally {
      setBusy(false);
    }
  }, []);
  return { busy, error, setError, run };
}

// ---- formatting ----

export function fmtNumber(n) {
  return new Intl.NumberFormat().format(n || 0);
}

export function fmtPercent(part, total) {
  if (!total) return '0%';
  return `${((part / total) * 100).toFixed(1)}%`;
}

export function fmtDuration(seconds) {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m`;
  return `${seconds}s`;
}

export function fmtMicros(us) {
  if (us < 1000) return `${us}µs`;
  return `${(us / 1000).toFixed(us < 10000 ? 1 : 0)}ms`;
}

export function fmtTime(iso) {
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function fmtAgo(iso) {
  if (!iso) return 'never';
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return 'just now';
  return `${fmtDuration(s)} ago`;
}

// randomID returns a client identifier usable in a DoH path and an SNI label.
export function randomID(length = 16) {
  const alphabet = 'abcdefghijkmnpqrstuvwxyz23456789';
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join('');
}

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

// ---- small shared components ----

export function ErrorBox({ error }) {
  if (!error) return null;
  return html`<div class="alert error" role="alert">${error.message || String(error)}</div>`;
}

export function Empty({ children }) {
  return html`<div class="empty">${children}</div>`;
}

export function Loading() {
  return html`<div class="empty">Loading…</div>`;
}

export function SourceBadge({ source }) {
  return html`<span class=${`badge src-${source}`}>${source}</span>`;
}

// Modal renders a dialog over the page. Closes on Escape or backdrop click.
export function Modal({ title, onClose, children, wide }) {
  useEffect(() => {
    const onKey = (e) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);
  return html`
    <div class="backdrop" onClick=${(e) => e.target === e.currentTarget && onClose()}>
      <div class=${`modal${wide ? ' wide' : ''}`} role="dialog" aria-modal="true" aria-label=${title}>
        <header>
          <h3>${title}</h3>
          <button class="icon" onClick=${onClose} aria-label="Close">×</button>
        </header>
        ${children}
      </div>
    </div>`;
}

// ListInput edits a list of short strings as one entry per line.
export function ListInput({ value, onInput, placeholder, rows = 3 }) {
  return html`<textarea
    rows=${rows}
    placeholder=${placeholder}
    value=${(value || []).join('\n')}
    onInput=${(e) => onInput(e.target.value.split('\n').map((s) => s.trim()).filter(Boolean))}
  />`;
}

export const RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'PTR', 'CAA', 'HTTPS', 'SVCB', 'SOA', 'TLSA', 'DS', 'DNSKEY'];
