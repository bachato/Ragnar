// RuSense loader — mounts the RuView SPA views into a Shadow DOM island inside
// Ragnar's #rusense-tab. The shadow root fully isolates RuView's compiled
// Tailwind build (assets/app.css) from Ragnar's own styles in both directions.
// Navigation is driven by Ragnar's native sub-tab buttons (ragnar_modern.js).
import { html, setQueryRoot } from './lib.js';
import { sensingService } from '../services/sensing.service.js';
import dashboard from './views/dashboard.js?v=20260701-loadanim';
import sensing from './views/sensing.js?v=20260701-presencehold';
import nodes from './views/nodes.js?v=20260701-nodenames';
import training from './views/training.js?v=20260630-recstate';
import settings from './views/settings.js?v=20260701-alertdefaults';
import about from './views/about.js?v=20260701-credits';

const VIEWS = { dashboard, sensing, nodes, training, settings, about };
const CSS_HREF = new URL('../assets/app.css', import.meta.url).href;

let shadow = null;
let viewEl = null;
let current = null; // { route, cleanup }
let activeRoute = null; // route currently shown or mid-mount (idempotency guard)
let started = false;
let cssReady = Promise.resolve(); // resolves once app.css has applied (avoids FOUC)

/** Fill the view with self-styled skeleton cards — shown instantly while app.css
 *  loads and the first frame arrives, so the tab never flashes unstyled. */
function renderSkeleton() {
  if (!viewEl) return;
  const card = (h) => `<div class="rs-skel-card" style="height:${h}"></div>`;
  viewEl.innerHTML =
    '<div class="rs-skel">' +
    card('64px') +
    '<div class="rs-skel-stats">' + card('76px').repeat(4) + '</div>' +
    '<div class="rs-skel-two">' + card('184px') + card('184px') + '</div>' +
    card('120px') +
    '</div>';
}

function ensureShadow(host) {
  if (shadow) return;
  shadow = host.attachShadow({ mode: 'open' });

  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = CSS_HREF;
  cssReady = new Promise((resolve) => {
    link.addEventListener('load', resolve, { once: true });
    link.addEventListener('error', resolve, { once: true });
    setTimeout(resolve, 1500); // fallback so we never sit on the skeleton forever
  });
  shadow.appendChild(link);

  // Layout containment: a live value changing inside one card can't reflow its
  // neighbours, and tabular figures keep numeric widths constant frame-to-frame.
  const stable = document.createElement('style');
  stable.textContent =
    '.card,.stat{contain:layout}' +
    '.stat-value,.font-mono,dd{font-variant-numeric:tabular-nums}' +
    '.stat-value{white-space:nowrap}' +
    // Loading animation for the pre-first-frame state (shadow-isolated, so it
    // works even before/without the Tailwind build applying).
    '@keyframes rs-pulse{0%,100%{opacity:.35}50%{opacity:.9}}' +
    '.rs-pulse{animation:rs-pulse 1.1s ease-in-out infinite}' +
    '@keyframes rs-spin{to{transform:rotate(360deg)}}' +
    '.rs-spin{display:inline-block;width:.9rem;height:.9rem;border:2px solid currentColor;' +
    'border-right-color:transparent;border-radius:9999px;animation:rs-spin .7s linear infinite;vertical-align:-1px}' +
    // Skeleton shown INSTANTLY (before app.css loads) so there's never a flash
    // of unstyled "terminal" content. Fully self-styled — no Tailwind needed.
    '.rs-skel{display:flex;flex-direction:column;gap:1rem;padding:1.25rem 1rem}' +
    '.rs-skel-stats{display:grid;grid-template-columns:repeat(2,1fr);gap:.75rem}' +
    '.rs-skel-two{display:grid;grid-template-columns:1fr;gap:1rem}' +
    '@media(min-width:1024px){.rs-skel-stats{grid-template-columns:repeat(4,1fr)}.rs-skel-two{grid-template-columns:1fr 1fr}}' +
    '.rs-skel-card{background:#121820;border:1px solid #1e2730;border-radius:.75rem;position:relative;overflow:hidden}' +
    '.rs-skel-card::after{content:"";position:absolute;inset:0;transform:translateX(-100%);' +
    'background:linear-gradient(90deg,transparent,rgba(120,160,200,.08),transparent);animation:rs-shimmer 1.3s infinite}' +
    '@keyframes rs-shimmer{100%{transform:translateX(100%)}}';
  shadow.appendChild(stable);

  // app.css `body{}` rules don't cross the shadow boundary — reproduce the
  // essential page surface (background, text colour, font) on a wrapper.
  const surface = document.createElement('div');
  surface.style.cssText =
    'background:#0b0f12;color:#e8eef3;min-height:60vh;border-radius:.75rem;' +
    'font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;';

  viewEl = document.createElement('main');
  viewEl.id = 'view';
  viewEl.className = 'px-4 py-5 sm:px-6';
  surface.appendChild(viewEl);

  const toastRoot = document.createElement('div');
  toastRoot.id = 'toast-root';
  toastRoot.className =
    'fixed bottom-4 inset-x-0 z-50 flex flex-col items-center gap-2 px-4 pointer-events-none';
  surface.appendChild(toastRoot);

  shadow.appendChild(surface);

  // Route $/$$ and toast() lookups into this shadow root.
  setQueryRoot(shadow);
}

/** Mount a view by id into the shadow island. */
export async function show(routeId) {
  if (!shadow) return null;
  const id = VIEWS[routeId] ? routeId : 'dashboard';
  // Idempotent: re-showing the route that's already mounted must NOT tear the
  // view down and rebuild it. The old behaviour wiped innerHTML and reset
  // scroll (scrollTo(0,0)) on every call, so any stray re-invocation of
  // init()/show() for the current route produced a visible twitch + jump to
  // top. `activeRoute` is set synchronously so rapid double-calls also no-op.
  if (id === activeRoute) return id;
  activeRoute = id;
  if (current && current.cleanup) {
    try { current.cleanup(); } catch (e) { console.warn('[rusense] cleanup', e); }
  }
  // Show skeleton instantly, then wait for app.css to apply before mounting the
  // real view — otherwise the raw markup flashes unstyled ("terminal" screen).
  renderSkeleton();
  viewEl.scrollTo && viewEl.scrollTo(0, 0);
  await cssReady;
  if (activeRoute !== id) return id; // route changed while we waited
  viewEl.innerHTML = '';
  let cleanup = null;
  try {
    cleanup = (await VIEWS[id].mount(viewEl)) || null;
  } catch (err) {
    console.error(`[rusense] view "${id}" failed:`, err);
    viewEl.appendChild(
      html`<div class="card card-pad text-bad">View failed to load: ${err && err.message}</div>`
    );
  }
  current = { route: id, cleanup };
  return id;
}

/** Open the RuSense island and show `route`. Idempotent (safe to call repeatedly). */
export function init(host, route) {
  ensureShadow(host);
  if (!started) { sensingService.start(); started = true; }
  return show(route || (current && current.route) || 'dashboard');
}

/** Leave the RuSense tab — stop the stream and free the mounted view. */
export function suspend() {
  if (current && current.cleanup) {
    try { current.cleanup(); } catch (e) { /* ignore */ }
    current = { route: current.route, cleanup: null };
  }
  if (viewEl) viewEl.innerHTML = '';
  // Allow the next init()/show() to remount the (now-wiped) view.
  activeRoute = null;
  try { sensingService.stop(); } catch (e) { /* ignore */ }
  started = false;
}
