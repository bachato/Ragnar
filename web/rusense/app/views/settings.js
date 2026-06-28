// Settings — RuSense camera-free surveillance alerts (Pushover). Reads and
// writes Ragnar's own config (/api/config) plus the shared Pushover key status
// (/api/pushover/keys). The server-side monitor in webapp_modern.py does the
// edge detection and sending; this view only edits the rusense_notify_* config.
import { icons } from '../icons.js';
import { html, $, fetchJSON, toast } from '../lib.js';

// Action helper that — unlike fetchJSON — keeps HTTP ok/fail and the JSON body
// separate, so we never toast a false success (mirrors training.js).
async function req(method, url, body) {
  try {
    const res = await fetch(url, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
    let data = null;
    try { data = await res.json(); } catch { /* empty / non-JSON is fine */ }
    return { ok: res.ok, status: res.status, data };
  } catch (e) {
    return { ok: false, status: 0, data: null, error: String(e) };
  }
}

// Each alert kind: config key + label + helper text.
const TOGGLES = [
  ['rusense_notify_presence', 'Presence / occupancy', 'When a monitored space goes from empty to occupied (and back).'],
  ['rusense_notify_motion', 'Motion', 'When significant (active) motion is detected.'],
  ['rusense_notify_people', 'People-count threshold', 'When the estimated number of people crosses the threshold below.'],
  ['rusense_notify_node_offline', 'Node offline', 'When a provisioned CSI sensor node stops streaming.'],
];

function row(key, label, help, checked) {
  return `<label class="flex items-start justify-between gap-4 py-3 border-b border-ink-3 last:border-0 cursor-pointer">
    <span class="min-w-0">
      <span class="block text-sm font-medium">${label}</span>
      <span class="block text-xs text-ink-muted">${help}</span>
    </span>
    <input type="checkbox" data-key="${key}" ${checked ? 'checked' : ''}
      class="mt-1 shrink-0 w-5 h-5 accent-brand-400 cursor-pointer" />
  </label>`;
}

export default {
  id: 'settings',
  label: 'Settings',
  icon: icons.settings,

  async mount(root) {
    // Pull current config + Pushover key status together.
    const [cfg, keys] = await Promise.all([
      fetchJSON('/api/config'),
      fetchJSON('/api/pushover/keys'),
    ]);
    const c = cfg || {};
    const configured = !!(keys && keys.user_key_configured && keys.api_token_configured);
    const enabledGlobally = !!c.pushover_enabled;
    const ready = configured && enabledGlobally;

    const banner = ready
      ? `<div class="rounded-lg bg-ok/15 text-ok px-3 py-2 text-sm">✓ Pushover is configured and enabled. RuSense alerts will be delivered.</div>`
      : `<div class="rounded-lg bg-warn/15 text-warn px-3 py-2 text-sm">
           ⚠ Pushover ${configured ? 'is configured but disabled' : 'keys are not set'}.
           Set your User Key and API Token under <strong>Config → Pushover Notifications</strong> in the main
           Ragnar dashboard first — RuSense alerts use the same account.
         </div>`;

    root.appendChild(html`
      <section class="space-y-5 max-w-2xl">
        <div class="card card-pad space-y-2">
          <h2 class="text-xl font-bold">Sensing Alerts</h2>
          <p class="text-ink-soft text-sm">Get a push notification when RuSense detects activity in a monitored
            space — no camera, no app open. Alerts are evaluated on the server, so they fire even when this tab is closed.</p>
          ${banner}
        </div>

        <div class="card card-pad space-y-1">
          <label class="flex items-center justify-between gap-4 py-1 cursor-pointer">
            <span>
              <span class="block text-sm font-semibold">Enable RuSense alerts</span>
              <span class="block text-xs text-ink-muted">Master switch for all sensing notifications below.</span>
            </span>
            <input type="checkbox" id="st-master" data-key="rusense_notify_enabled"
              ${c.rusense_notify_enabled ? 'checked' : ''}
              class="shrink-0 w-6 h-6 accent-brand-400 cursor-pointer" />
          </label>
        </div>

        <div class="card card-pad space-y-1">
          <h3 class="card-title mb-1">Alert on</h3>
          ${TOGGLES.map(([k, l, h]) => row(k, l, h, c[k])).join('')}
        </div>

        <div class="card card-pad grid gap-4 sm:grid-cols-2">
          <label class="block">
            <span class="block text-sm font-medium mb-1">People-count threshold</span>
            <input type="number" id="st-threshold" min="1" max="20" step="1"
              value="${Number(c.rusense_notify_people_threshold ?? 1)}"
              class="w-full bg-ink-1 border border-ink-3 rounded-lg px-3 py-2 text-sm font-mono" />
            <span class="block text-xs text-ink-muted mt-1">Alert when estimated people ≥ this.</span>
          </label>
          <label class="block">
            <span class="block text-sm font-medium mb-1">Cooldown (seconds)</span>
            <input type="number" id="st-cooldown" min="5" max="3600" step="5"
              value="${Number(c.rusense_notify_cooldown_s ?? 60)}"
              class="w-full bg-ink-1 border border-ink-3 rounded-lg px-3 py-2 text-sm font-mono" />
            <span class="block text-xs text-ink-muted mt-1">Minimum gap between repeats of the same alert kind.</span>
          </label>
        </div>

        <div class="flex flex-wrap gap-3">
          <button id="st-save" class="btn-primary">Save settings</button>
          <button id="st-test" class="btn-ghost">Send test notification</button>
        </div>
        <p class="text-xs text-ink-muted">Powered by RuView · alerts delivered via your Pushover account.</p>
      </section>`);

    const clampInt = (el, lo, hi, dflt) => {
      let v = parseInt(el && el.value, 10);
      if (isNaN(v)) v = dflt;
      return Math.max(lo, Math.min(hi, v));
    };

    $('#st-save').addEventListener('click', async () => {
      const payload = { rusense_notify_enabled: $('#st-master').checked };
      for (const [k] of TOGGLES) {
        const box = root.querySelector(`input[data-key="${k}"]`);
        payload[k] = !!(box && box.checked);
      }
      payload.rusense_notify_people_threshold = clampInt($('#st-threshold'), 1, 20, 1);
      payload.rusense_notify_cooldown_s = clampInt($('#st-cooldown'), 5, 3600, 60);

      const r = await req('POST', '/api/config', payload);
      toast(r.ok ? 'Settings saved' : ((r.data && r.data.error) || 'Could not save settings'),
        r.ok ? 'ok' : 'bad');
    });

    $('#st-test').addEventListener('click', async () => {
      const r = await req('POST', '/api/pushover/test');
      const ok = r.ok && r.data && r.data.success;
      toast(ok ? 'Test notification sent' : ((r.data && r.data.message) || 'Test failed — check Pushover keys'),
        ok ? 'ok' : 'bad');
    });
  },
};
