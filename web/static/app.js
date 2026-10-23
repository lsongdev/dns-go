import { render } from './vendor/preact.js';
import { useState, useEffect } from './vendor/hooks.js';
import { html, api, getToken, setToken, onUnauthorized, ErrorBox, Loading } from './lib.js';
import { Dashboard } from './pages/dashboard.js';
import { QueryLog } from './pages/querylog.js';
import { Zones } from './pages/zones.js';
import { Filters } from './pages/filters.js';
import { Access } from './pages/access.js';
import { Tools } from './pages/tools.js';

const PAGES = [
  { id: 'dashboard', label: 'Dashboard', icon: '◔', component: Dashboard },
  { id: 'querylog', label: 'Query log', icon: '≡', component: QueryLog },
  { id: 'zones', label: 'Zones', icon: '◇', component: Zones },
  { id: 'filters', label: 'Filters', icon: '⊘', component: Filters, forwardingOnly: true },
  { id: 'access', label: 'Clients', icon: '◎', component: Access },
  { id: 'tools', label: 'Tools', icon: '⚙', component: Tools },
];

// Routes look like #/zones/home.lan → { page: 'zones', rest: 'home.lan' }.
function parseHash() {
  const [page = 'dashboard', ...rest] = location.hash.replace(/^#\/?/, '').split('/');
  return { page: page || 'dashboard', rest: rest.length ? decodeURIComponent(rest.join('/')) : '' };
}

function useRoute() {
  const [route, setRoute] = useState(parseHash());
  useEffect(() => {
    const onChange = () => setRoute(parseHash());
    window.addEventListener('hashchange', onChange);
    return () => window.removeEventListener('hashchange', onChange);
  }, []);
  return route;
}

function App() {
  const route = useRoute();
  const [status, setStatus] = useState(null);
  const [error, setError] = useState(null);
  const [needLogin, setNeedLogin] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);

  const loadStatus = async () => {
    try {
      setStatus(await api('GET', '/status'));
      setError(null);
      setNeedLogin(false);
    } catch (e) {
      if (e.status === 401) setNeedLogin(true);
      else setError(e);
    }
  };
  useEffect(() => onUnauthorized(() => setNeedLogin(true)), []);
  useEffect(() => {
    loadStatus();
    const timer = setInterval(() => document.hidden || loadStatus(), 15000);
    return () => clearInterval(timer);
  }, []);
  useEffect(() => setMenuOpen(false), [route.page, route.rest]);

  if (needLogin) return html`<${Login} onLogin=${loadStatus} />`;
  if (!status) return html`<div class="boot">${error ? html`<${ErrorBox} error=${error} />` : html`<${Loading} />`}</div>`;

  const pages = PAGES.filter((p) => !p.forwardingOnly || status.mode === 'forwarding');
  const page = pages.find((p) => p.id === route.page) || pages[0];
  const Page = page.component;
  return html`
    <div class="layout">
      <aside class=${`sidebar${menuOpen ? ' open' : ''}`}>
        <div class="brand">
          <span class="logo" aria-hidden="true">◆</span>
          <span>dns-go</span>
          <button class="icon menu" aria-label="Menu" aria-expanded=${menuOpen} onClick=${() => setMenuOpen(!menuOpen)}>☰</button>
        </div>
        <nav>
          ${pages.map((p) => html`
            <a href=${`#/${p.id}`} class=${p.id === page.id ? 'active' : ''} aria-current=${p.id === page.id ? 'page' : undefined}>
              <span class="nav-icon" aria-hidden="true">${p.icon}</span>${p.label}
            </a>`)}
        </nav>
        <footer class="sidebar-foot">
          <div><span class=${`badge mode-${status.mode}`}>${status.mode}</span></div>
          <div class="muted small">${status.version}</div>
          ${getToken() && html`<button class="link small" onClick=${() => { setToken(''); setNeedLogin(true); }}>Sign out</button>`}
        </footer>
      </aside>
      <main>
        ${error && html`<${ErrorBox} error=${error} />`}
        <${Page} key=${page.id} status=${status} route=${route.rest} />
      </main>
    </div>`;
}

function Login({ onLogin }) {
  const [token, setValue] = useState('');
  const [error, setError] = useState(null);
  const submit = async (e) => {
    e.preventDefault();
    setToken(token.trim());
    try {
      await api('GET', '/status');
      onLogin();
    } catch (err) {
      setToken('');
      setError(err.status === 401 ? new Error('That token was not accepted.') : err);
    }
  };
  return html`
    <div class="boot">
      <form class="login panel" onSubmit=${submit}>
        <div class="brand"><span class="logo" aria-hidden="true">◆</span><span>dns-go</span></div>
        <label>API token
          <input type="password" autocomplete="current-password" required autofocus value=${token} onInput=${(e) => setValue(e.target.value)} />
          <small class="muted">The <code>api.token</code> value from the server's config file.</small>
        </label>
        <${ErrorBox} error=${error} />
        <button class="primary">Sign in</button>
      </form>
    </div>`;
}

render(html`<${App} />`, document.getElementById('app'));
