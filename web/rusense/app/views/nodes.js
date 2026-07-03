// Nodes — per-node CSI sensor health, mesh status, hardware spec.
import { icons } from '../icons.js';
import { html, $, fetchJSON, fmt } from '../lib.js';

// Graduated node health from last_seen. The sensing-server exposes a binary
// active/stale that flips the instant a node gaps for ~a second, which reads as
// "dead" even though the node is still streaming and recovers immediately. Base
// the shown status on how long ago we actually heard from it:
//   live    (<5s)  — streaming normally
//   lagging (5-45s)— a recent gap; still around, RF/mesh hiccup (see mesh offsets)
//   offline (>=45s)— genuinely silent
function nodeHealth(lastSeenMs) {
  const s = (lastSeenMs == null) ? Infinity : lastSeenMs / 1000;
  if (s < 5) return { label: 'live', badge: 'badge-ok', dot: 'bg-ok', key: 'live' };
  if (s < 45) return { label: 'lagging', badge: 'badge-warn', dot: 'bg-warn', key: 'lagging' };
  return { label: 'offline', badge: 'badge-bad', dot: 'bg-bad', key: 'offline' };
}

function nodeRow(n, names = {}) {
  const h = nodeHealth(n.last_seen_ms);
  const nm = names[String(n.node_id)];
  const label = nm ? `${nm} <span class="text-ink-muted text-xs">#${n.node_id}</span>` : `#${n.node_id}`;
  return `<tr class="border-b border-ink-3 last:border-0">
    <td class="py-2.5 pr-3 font-mono">${label}</td>
    <td class="py-2.5 pr-3"><span class="${h.badge}" title="last frame ${fmt.ago((n.last_seen_ms ?? 0) / 1000)}"><span class="dot ${h.dot}"></span>${h.label}</span></td>
    <td class="py-2.5 pr-3 font-mono text-right">${fmt.dbm(n.rssi_dbm)}</td>
    <td class="py-2.5 pr-3 text-ink-soft">${(n.motion_level || '—').replace(/_/g, ' ')}</td>
    <td class="py-2.5 pr-3 text-right font-mono">${n.person_count ?? 0}</td>
    <td class="py-2.5 text-right text-ink-muted">${fmt.ago((n.last_seen_ms ?? 0) / 1000)}</td>
  </tr>`;
}

export default {
  id: 'nodes',
  label: 'Nodes',
  icon: icons.nodes,

  async mount(root) {
    // Custom node names come from Ragnar config (Settings), not the sensing
    // roster; load them once so the table shows names instead of just "#id".
    let nodeNames = {};
    fetchJSON('/api/config').then((c) => { nodeNames = (c && c.rusense_node_names) || {}; });

    root.appendChild(html`
      <section class="space-y-5">
        <div class="grid grid-cols-3 gap-3">
          <div class="stat"><span class="stat-label">Live</span><span class="stat-value text-ok" id="n-live">—</span></div>
          <div class="stat"><span class="stat-label">Lagging</span><span class="stat-value text-warn" id="n-lagging">—</span></div>
          <div class="stat"><span class="stat-label">Offline</span><span class="stat-value text-bad" id="n-offline">—</span></div>
        </div>

        <div class="card card-pad space-y-3">
          <div class="flex items-center justify-between">
            <h2 class="card-title">Sensor nodes</h2>
            <div class="flex items-center gap-2">
              <button id="n-logs" class="btn-ghost !py-1.5 !px-3 text-xs" title="Capture ~30s of node + mesh + engine state to a JSON file for debugging">Download logs</button>
              <button id="n-refresh" class="btn-ghost !py-1.5 !px-3 text-xs">Refresh</button>
            </div>
          </div>
          <div class="overflow-x-auto -mx-1">
            <table class="w-full text-sm min-w-[480px]">
              <thead><tr class="text-left text-xs uppercase tracking-wide text-ink-muted border-b border-ink-3">
                <th class="py-2 pr-3 font-medium">Node</th><th class="py-2 pr-3 font-medium">Status</th>
                <th class="py-2 pr-3 font-medium text-right">RSSI</th><th class="py-2 pr-3 font-medium">Motion</th>
                <th class="py-2 pr-3 font-medium text-right">People</th><th class="py-2 font-medium text-right">Last seen</th>
              </tr></thead>
              <tbody id="n-body"><tr><td colspan="6" class="py-6 text-center text-ink-muted">Loading…</td></tr></tbody>
            </table>
          </div>
        </div>

        <div class="grid gap-4 sm:grid-cols-2">
          <div class="card card-pad space-y-2">
            <h2 class="card-title">Mesh</h2>
            <pre id="mesh-box" class="text-xs font-mono text-ink-soft whitespace-pre-wrap break-words">—</pre>
          </div>
          <div class="card card-pad space-y-2">
            <h2 class="card-title">Hardware reference</h2>
            <dl class="text-sm space-y-2">
              ${[['Node chip', 'ESP32-S3 / C6'], ['Band', '2.4 GHz WiFi CSI'], ['Subcarriers', 'up to 114'], ['Sample rate', '~100 Hz'], ['mmWave option', 'Seeed MR60BHA2 (60 GHz)']]
                .map(([k, v]) => `<div class="flex justify-between border-b border-ink-3 pb-2 last:border-0"><dt class="text-ink-muted">${k}</dt><dd class="font-mono text-right">${v}</dd></div>`).join('')}
            </dl>
          </div>
        </div>
      </section>`);

    const refresh = async () => {
      const data = await fetchJSON('/api/v1/nodes');
      const body = $('#n-body');
      const list = data?.nodes || [];
      const by = { live: 0, lagging: 0, offline: 0 };
      for (const nd of list) by[nodeHealth(nd.last_seen_ms).key]++;
      $('#n-live').textContent = by.live;
      $('#n-lagging').textContent = by.lagging;
      $('#n-offline').textContent = by.offline;
      body.innerHTML = list.length
        ? list.map((n) => nodeRow(n, nodeNames)).join('')
        : '<tr><td colspan="6" class="py-6 text-center text-ink-muted">No nodes reporting. Power on an ESP32 CSI node and provision it to this server.</td></tr>';
    };
    const refreshMesh = async () => {
      const m = await fetchJSON('/api/v1/mesh');
      const el = $('#mesh-box');
      if (el) el.textContent = m ? JSON.stringify(m, null, 2) : 'Mesh data unavailable';
    };

    // Download logs: a ROLLING capture (not a single snapshot) of node roster +
    // mesh + engine trust, so a reboot loop (mesh `sequence` resetting), clock-
    // offset drift, or an engine demotion is visible over time. ~30s @ 3s.
    let capturing = false;
    const captureLogs = async (btn) => {
      if (capturing) return;
      capturing = true;
      const CAP_MS = 30000, STEP = 3000, started = Date.now(), samples = [];
      const orig = btn.textContent;
      btn.disabled = true;
      const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
      try {
        while (Date.now() - started < CAP_MS && capturing) {
          const [nodes, mesh, status, adaptive] = await Promise.all([
            fetchJSON('/api/v1/nodes'), fetchJSON('/api/v1/mesh'),
            fetchJSON('/api/v1/status'), fetchJSON('/api/v1/adaptive/status'),
          ]);
          samples.push({ t: new Date().toISOString(), nodes, mesh, status, adaptive });
          const left = Math.max(0, Math.ceil((CAP_MS - (Date.now() - started)) / 1000));
          btn.textContent = `Capturing… ${left}s`;
          if (Date.now() - started < CAP_MS && capturing) await sleep(STEP);
        }
        if (!samples.length) return;
        const bundle = {
          captured_at: new Date().toISOString(),
          capture_seconds: Math.round((Date.now() - started) / 1000),
          sample_count: samples.length,
          node_names: nodeNames,
          hint: 'Watch mesh[].sequence per node: resets to low numbers = the node is rebooting. Large/growing offset_us = clock desync. status.trust.demoted/engine_error_count climbing = the engine is degrading.',
          samples,
        };
        const url = URL.createObjectURL(new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' }));
        const a = document.createElement('a');
        a.href = url;
        a.download = `rusense-node-logs-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
        document.body.appendChild(a); a.click(); a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 2000);
      } finally {
        capturing = false;
        btn.disabled = false;
        btn.textContent = orig;
      }
    };

    refresh(); refreshMesh();
    $('#n-refresh').addEventListener('click', refresh);
    const logsBtn = $('#n-logs');
    if (logsBtn) logsBtn.addEventListener('click', (e) => captureLogs(e.currentTarget));
    const t = setInterval(refresh, 4000);
    return () => { clearInterval(t); capturing = false; };
  },
};
