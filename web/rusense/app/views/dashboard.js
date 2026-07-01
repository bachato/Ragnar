// Dashboard — live operator overview. No marketing; leads with real data.
import { icons } from '../icons.js';
import { html, $, fetchJSON, fmt, sparkPath, throttleLatest } from '../lib.js';
import { sensingService } from '../../services/sensing.service.js';
import { makeVitalHold } from '../vital-hold.js?v=20260701-vitalhold';
import { makePresenceHold } from '../presence-hold.js?v=20260701-presencehold';

function bigStat(label, id, unit = '') {
  return `<div class="stat">
    <span class="stat-label">${label}</span>
    <span class="flex items-baseline gap-1"><span class="stat-value" id="${id}">—</span>
    ${unit ? `<span class="text-sm text-ink-muted">${unit}</span>` : ''}</span>
  </div>`;
}

export default {
  id: 'dashboard',
  label: 'Dashboard',
  icon: icons.dashboard,

  async mount(root) {
    // Hold vitals through brief confidence dips / dropped frames; clear to "—"
    // only after holdMs of no confident reading. Both the live WS frames and the
    // 4 s REST poll feed the same holders, so they reinforce rather than fight.
    this._hrHold = makeVitalHold({ holdMs: 4000, decimals: 0 });
    this._brHold = makeVitalHold({ holdMs: 4000, decimals: 1 });
    // Presence toggles 0↔1 at ~46 Hz (even in an empty room); smooth it with a
    // duty-cycle hysteresis biased toward PRESENT. Fed at full frame rate below.
    this._presence = makePresenceHold();
    this._present = false;
    this._lastPeople = 0;
    this._lastMotion = '';
    this._presSig = null;
    // Custom node names live in Ragnar config (set in Settings), not in the
    // sensing-server's /api/v1/nodes roster — fetch them once to label nodes.
    this._nodeNames = {};
    fetchJSON('/api/config').then((c) => { this._nodeNames = (c && c.rusense_node_names) || {}; });

    root.appendChild(html`
      <section class="space-y-5">
        <!-- Presence banner -->
        <div id="presence-card" class="card card-pad flex items-center gap-4">
          <span id="presence-dot" class="dot w-3.5 h-3.5 bg-ink-4"></span>
          <div class="flex-1">
            <div id="presence-text" class="text-lg font-semibold">Waiting for data…</div>
            <div id="presence-sub" class="text-sm text-ink-muted">Connecting to sensing stream</div>
          </div>
          <span id="motion-badge" class="badge-mut">—</span>
        </div>

        <!-- Key live stats -->
        <div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
          ${bigStat('People', 'stat-people')}
          ${bigStat('Confidence', 'stat-conf')}
          ${bigStat('Breathing', 'stat-br', 'bpm')}
          ${bigStat('Heart rate', 'stat-hr', 'bpm')}
        </div>

        <div class="grid gap-4 lg:grid-cols-2">
          <!-- Signal -->
          <div class="card card-pad space-y-4">
            <div class="flex items-center justify-between">
              <h2 class="card-title">Signal</h2>
              <span id="rssi-now" class="text-sm font-mono text-ink-soft">—</span>
            </div>
            <svg id="rssi-spark" viewBox="0 0 300 60" preserveAspectRatio="none" class="w-full h-16">
              <path id="rssi-path" fill="none" stroke="currentColor" class="text-brand-400" stroke-width="1.5"/>
            </svg>
            <dl class="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
              <div class="flex justify-between"><dt class="text-ink-muted">Variance</dt><dd id="f-var" class="font-mono">—</dd></div>
              <div class="flex justify-between"><dt class="text-ink-muted">Motion band</dt><dd id="f-motion" class="font-mono">—</dd></div>
              <div class="flex justify-between"><dt class="text-ink-muted">Breath band</dt><dd id="f-breath" class="font-mono">—</dd></div>
              <div class="flex justify-between"><dt class="text-ink-muted">Dom. freq</dt><dd id="f-freq" class="font-mono">—</dd></div>
            </dl>
          </div>

          <!-- RuSense + node health -->
          <div class="card card-pad space-y-4">
            <div class="flex items-center justify-between">
              <h2 class="card-title">RuSense health</h2>
              <span id="rs-backend" class="badge-mut">—</span>
            </div>
            <dl class="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
              <div class="flex justify-between"><dt class="text-ink-muted">Source</dt><dd id="rs-source" class="font-mono">—</dd></div>
              <div class="flex justify-between"><dt class="text-ink-muted">Nodes online</dt><dd id="rs-nodes" class="font-mono">—</dd></div>
            </dl>
            <div id="rs-node-list" class="space-y-2 pt-1 border-t border-ink-3 text-sm">
              <div class="text-ink-muted">Loading nodes…</div>
            </div>
          </div>
        </div>

        <!-- Recent sightings — a reviewable log of confirmed presence alerts -->
        <div class="card card-pad space-y-3">
          <div class="flex items-center justify-between">
            <h2 class="card-title">Recent sightings</h2>
            <span class="text-xs text-ink-muted">last 5 · presence alerts</span>
          </div>
          <div id="sightings-body">
            <div class="text-sm text-ink-muted py-2">Loading…</div>
          </div>
        </div>
      </section>`);

    // ── Live sensing frames ──
    // Frames can arrive 10-20×/s; coalesce to a calm cadence so the cards
    // don't re-render (and visibly jitter) several times a second.
    const off = sensingService.onData(throttleLatest((d) => this.applyFrame(d), 250));
    // Presence needs the raw ~46 Hz signal to measure its duty cycle, so feed it
    // from a separate un-throttled listener (cheap: no DOM unless state changes).
    const offP = sensingService.onData((d) => this.applyPresence(d));

    // RuSense backend + node health (replaces generic host CPU/mem/disk).
    const refreshHealth = async () => {
      const [st, svc, n] = await Promise.all([
        fetchJSON('/api/v1/status'),
        fetchJSON('/api/sensing/status'),
        fetchJSON('/api/v1/nodes'),
      ]);
      const be = $('#rs-backend');
      if (be) {
        const running = svc?.active === true;
        be.textContent = running ? (st?.status || 'running') : (st ? 'reachable' : 'unreachable');
        be.className = running ? 'badge-ok' : (st ? 'badge-warn' : 'badge-bad');
      }
      const src = $('#rs-source'); if (src) src.textContent = st?.source || '—';
      const nodes = (n?.nodes || []).slice().sort((a, b) => (a.node_id || 0) - (b.node_id || 0));
      const active = nodes.filter((x) => x.status === 'active').length;
      const ne = $('#rs-nodes'); if (ne) ne.textContent = `${active}/${nodes.length}`;
      const list = $('#rs-node-list');
      if (list) {
        list.innerHTML = nodes.length ? nodes.map((x) => {
          const on = x.status === 'active';
          const rssi = x.rssi_dbm != null ? `${Number(x.rssi_dbm).toFixed(0)} dBm` : '—';
          const nm = this._nodeNames[String(x.node_id)];
          const label = nm ? `${nm} <span class="text-ink-muted">#${x.node_id}</span>` : `Node ${x.node_id}`;
          return `<div class="flex items-center justify-between">
            <span class="flex items-center gap-2"><span class="dot w-2 h-2 ${on ? 'bg-ok' : 'bg-bad'}"></span>${label}</span>
            <span class="font-mono text-ink-soft">${rssi}</span>
          </div>`;
        }).join('') : '<div class="text-ink-muted">No nodes reporting</div>';
      }
    };
    const fmtLocal = (ts) => {
      try {
        return new Date(ts * 1000).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
      } catch { return '—'; }
    };
    const refreshSightings = async () => {
      const r = await fetchJSON('/api/rusense/sightings');
      const body = $('#sightings-body'); if (!body) return;
      const rows = (r?.sightings || []).slice(0, 5);
      if (!rows.length) {
        body.innerHTML = '<div class="text-sm text-ink-muted py-2">No sightings yet — confirmed presence alerts will appear here.</div>';
        return;
      }
      const cell = (v) => `<td class="text-right font-mono py-2">${v}</td>`;
      body.innerHTML = `<table class="w-full text-sm">
        <thead><tr class="text-ink-muted">
          <th class="text-left font-semibold py-2">Time</th>
          <th class="text-right font-semibold py-2">Confidence</th>
          <th class="text-right font-semibold py-2">Heart rate</th>
          <th class="text-right font-semibold py-2">Breathing</th>
        </tr></thead>
        <tbody>${rows.map((s) => {
          const conf = s.confidence != null ? `${Math.round(s.confidence * 100)}%` : '—';
          const hr = s.hr != null ? `${Math.round(s.hr)} bpm` : '—';
          const br = s.br != null ? `${Number(s.br).toFixed(1)} bpm` : '—';
          const live = s.ended_ts == null ? ' <span class="text-ok">• live</span>' : '';
          return `<tr class="border-t border-ink-3">
            <td class="text-left font-mono text-ink-soft py-2">${fmtLocal(s.ts)}${live}</td>
            ${cell(conf)}${cell(hr)}${cell(br)}</tr>`;
        }).join('')}</tbody></table>`;
    };
    const refreshVitals = async () => {
      // Vitals may not ride every WS frame — poll the dedicated endpoint.
      const v = await fetchJSON('/api/v1/vital-signs');
      const vs = v?.vital_signs; if (!vs) return;
      const present = this._present === true;
      this._brHold.push(vs.breathing_rate_bpm, vs.breathing_confidence, present);
      this._hrHold.push(vs.heart_rate_bpm, vs.heartbeat_confidence, present);
      this.renderVitals();
    };

    refreshHealth(); refreshVitals(); refreshSightings();
    const t1 = setInterval(refreshHealth, 5000);
    const t2 = setInterval(refreshSightings, 7000);
    const t3 = setInterval(refreshVitals, 4000);
    // Re-render on a steady tick so a held value still clears to "—" after the
    // hold window even if frames/polls stop arriving (stalled stream).
    const t4 = setInterval(() => this.renderVitals(), 1000);

    return () => { off(); offP(); clearInterval(t1); clearInterval(t2); clearInterval(t3); clearInterval(t4); };
  },

  renderVitals() {
    const set = (id, v) => { const e = $(id); if (e) e.textContent = v; };
    set('#stat-br', this._brHold.text());
    set('#stat-hr', this._hrHold.text());
  },

  // Full-rate presence: smooth the flickering boolean and only touch the DOM
  // when the displayed state actually changes.
  applyPresence(d) {
    if (!d || !d.classification) return;
    const c = d.classification;
    this._present = this._presence.push(c);
    // Remember the last "occupied" people count + motion label so the banner
    // shows a stable value while presence is held (those raw fields flicker too).
    const rawPeople = d.estimated_persons ?? (d.persons?.length) ?? null;
    const ml = c.motion_level || '';
    if (rawPeople != null && rawPeople > 0) this._lastPeople = rawPeople;
    if (ml.startsWith('present') || ml === 'active') this._lastMotion = ml;

    const present = this._present === true;
    const people = present ? (this._lastPeople || 1) : 0;
    const motion = present ? (this._lastMotion || 'present') : 'absent';
    const sig = `${present}|${people}|${motion}|${d.source}`;
    if (sig === this._presSig) return;
    this._presSig = sig;

    const dot = $('#presence-dot'), txt = $('#presence-text'), sub = $('#presence-sub'), mb = $('#motion-badge');
    if (dot) dot.className = `dot w-3.5 h-3.5 ${present ? 'bg-ok pulse-live' : 'bg-ink-4'}`;
    if (txt) txt.textContent = present ? (people > 1 ? `${people} people present` : 'Person present') : 'Room empty';
    if (sub) sub.textContent = d.source === 'simulated' ? 'Simulated data (no live hardware)' : `${motion.replace(/_/g, ' ')} · source: ${d.source}`;
    if (mb) {
      const kind = motion === 'active' ? 'badge-ok' : (present ? 'badge-warn' : 'badge-mut');
      mb.className = kind; mb.textContent = motion.replace(/_/g, ' ');
    }
    const pe = $('#stat-people'); if (pe) pe.textContent = String(people);
  },

  applyFrame(d) {
    if (!d || !d.classification) return;
    const c = d.classification;

    const set = (id, v) => { const e = $(id); if (e) e.textContent = v; };
    set('#stat-conf', fmt.pct(c.confidence, 0));
    const vs = d.vital_signs || {};
    const present = this._present === true;
    this._brHold.push(vs.breathing_rate_bpm, vs.breathing_confidence, present);
    this._hrHold.push(vs.heart_rate_bpm, vs.heartbeat_confidence, present);
    this.renderVitals();

    const f = d.features || {};
    set('#f-var', fmt.num(f.variance, 3));
    set('#f-motion', fmt.num(f.motion_band_power, 3));
    set('#f-breath', fmt.num(f.breathing_band_power, 3));
    set('#f-freq', `${fmt.num(f.dominant_freq_hz, 2)} Hz`);
    set('#rssi-now', fmt.dbm(f.mean_rssi));

    const hist = sensingService.getRssiHistory();
    const path = $('#rssi-path');
    if (path && hist.length > 1) path.setAttribute('d', sparkPath(hist, 300, 60, -90, -30));
  },
};
