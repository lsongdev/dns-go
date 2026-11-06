// dns-go entry point (panel module contract, version 1). The host is a
// panel shell, or standalone.js on its own.
import { createMount } from './lib/mount.js';

const page = load => ({ load });

const routes = [
  { path: '/', ...page(() => import('./pages/dashboard.js')) },
  { path: '/querylog', ...page(() => import('./pages/querylog.js')) },
  { path: '/zones', ...page(() => import('./pages/zones.js')) },
  { path: '/zones/:zone', ...page(() => import('./pages/zone.js')) },
  { path: '/filters', ...page(() => import('./pages/filters.js')) },
  { path: '/clients', ...page(() => import('./pages/clients.js')) },
  { path: '/tools', ...page(() => import('./pages/tools.js')) },
  { path: '/settings', ...page(() => import('./pages/settings.js')) },
];

// The API answers plain JSON bodies, not {"data": …}.
export const mount = createMount({ routes, envelope: false });
