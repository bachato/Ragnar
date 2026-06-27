// Training — models, recordings and training-run control. Wired to /api/v1/*.
import { icons } from '../icons.js';
import { html, $, fetchJSON, fmt, toast } from '../lib.js';

// Action helper: unlike fetchJSON (which collapses every failure to null), this
// reports HTTP success/failure separately and keeps any JSON body so we can
// surface the backend's own error text ("training already running", etc.) and
// never toast a false "success" when the sensing-server is down or rejects us.
async function req(method, url, body) {
  try {
    const res = await fetch(url, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
    let data = null;
    try { data = await res.json(); } catch { /* empty / non-JSON body is fine */ }
    return { ok: res.ok, status: res.status, data };
  } catch (e) {
    return { ok: false, status: 0, data: null, error: String(e) };
  }
}
const post = (url, body) => req('POST', url, body);
const del = (url) => req('DELETE', url);

// Pull a human message out of a response, preferring the backend's own text.
function msgOf(r, fallback) {
  return (r && r.data && (r.data.error || r.data.message || r.data.detail)) || fallback;
}

function modelCard(m, activeId) {
  const id = m.id ?? m.name ?? '?';
  const isActive = activeId && id === activeId;
  const meta = [m.kind, m.size_mb ? `${fmt.num(m.size_mb, 1)} MB` : null, m.created].filter(Boolean).join(' · ');
  return `<div class="flex items-center gap-3 rounded-lg bg-ink-1 border border-ink-3 p-3">
    <div class="flex-1 min-w-0">
      <div class="font-medium truncate">${id} ${isActive ? '<span class="badge-ok ml-1">active</span>' : ''}</div>
      <div class="text-xs text-ink-muted truncate">${meta || '—'}</div>
    </div>
    ${isActive
      ? `<button data-act="unload" class="btn-ghost !py-1.5 !px-3 text-xs">Unload</button>`
      : `<button data-act="load" data-id="${id}" class="btn-primary !py-1.5 !px-3 text-xs">Load</button>`}
    <button data-act="del-model" data-id="${id}" class="btn-danger !py-1.5 !px-3 text-xs" aria-label="Delete model">✕</button>
  </div>`;
}

export default {
  id: 'training',
  label: 'Training',
  icon: icons.training,

  async mount(root) {
    root.appendChild(html`
      <section class="space-y-5">
        <!-- Recording -->
        <div class="card card-pad space-y-3">
          <div class="flex items-center justify-between">
            <h2 class="card-title">CSI recording</h2>
            <span id="rec-state" class="badge-mut">idle</span>
          </div>
          <p class="text-xs text-ink-muted">Capture raw WiFi Channel State Information to disk. These recordings are the dataset the adaptive classifier learns from.</p>
          <div class="flex gap-2">
            <input id="rec-id" placeholder="recording id (optional)" class="flex-1 rounded-lg bg-ink-1 border border-ink-3 px-3 py-2.5 text-sm focus-visible:ring-2 focus-visible:ring-brand-400" />
            <button id="rec-start" class="btn-primary">Record</button>
            <button id="rec-stop" class="btn-ghost">Stop</button>
          </div>
          <div id="rec-list" class="space-y-2"></div>
        </div>

        <!-- Adaptive (on-device) training -->
        <div class="card card-pad space-y-3">
          <div class="flex items-center justify-between">
            <h2 class="card-title">Adaptive training <span class="badge-mut ml-1">on-device</span></h2>
            <span id="ad-status" class="badge-mut">—</span>
          </div>
          <p class="text-xs text-ink-muted">Fits a lightweight classifier to <em>this</em> environment from captured CSI (per-class signal statistics). Fast, runs on the Pi, and becomes the active model immediately. Label frames live via the ground-truth control while recording.</p>
          <div id="ad-stats" class="text-xs font-mono text-ink-muted"></div>
          <div class="flex gap-2">
            <button id="ad-train" class="btn-primary flex-1">Train adaptive model</button>
            <button id="ad-unload" class="btn-ghost flex-1">Unload</button>
          </div>
        </div>

        <!-- Training run (dataset deep-training) -->
        <div class="card card-pad space-y-3">
          <div class="flex items-center justify-between">
            <h2 class="card-title">Training run <span class="badge-mut ml-1">dataset</span></h2>
            <span id="tr-status" class="badge-mut">—</span>
          </div>
          <p class="text-xs text-ink-muted">Heavy deep-model training from an external pose dataset directory (MM-Fi / Wi-Pose) on the server. Produces an .rvf model. This does not use the CSI recordings above.</p>
          <div class="flex gap-2">
            <button id="tr-start" class="btn-primary flex-1">Start training</button>
            <button id="tr-stop" class="btn-ghost flex-1">Stop</button>
          </div>
          <pre id="tr-config" class="text-xs font-mono text-ink-muted whitespace-pre-wrap break-words max-h-32 overflow-auto"></pre>
        </div>

        <!-- Models -->
        <div class="card card-pad space-y-3">
          <div class="flex items-center justify-between">
            <h2 class="card-title">Models</h2>
            <button id="m-refresh" class="btn-ghost !py-1.5 !px-3 text-xs">Refresh</button>
          </div>
          <div id="m-list" class="space-y-2"><div class="text-sm text-ink-muted">Loading…</div></div>
        </div>
      </section>`);

    // ── Models ──
    const loadModels = async () => {
      const [list, active] = await Promise.all([fetchJSON('/api/v1/models'), fetchJSON('/api/v1/models/active')]);
      const models = list?.models || [];
      const activeId = active?.active?.id ?? null;
      const box = $('#m-list');
      box.innerHTML = models.length ? models.map((m) => modelCard(m, activeId)).join('')
        : '<div class="text-sm text-ink-muted">No models found. Record CSI data and train a model, or drop an .rvf file in the models directory.</div>';
    };
    $('#m-list').addEventListener('click', async (e) => {
      const btn = e.target.closest('[data-act]'); if (!btn) return;
      const { act, id } = btn.dataset;
      let r;
      if (act === 'load') { r = await post('/api/v1/models/load', { id }); toast(r.ok ? `Loading ${id}` : msgOf(r, `Could not load ${id}`), r.ok ? 'ok' : 'bad'); }
      else if (act === 'unload') { r = await post('/api/v1/models/unload'); toast(r.ok ? 'Model unloaded' : msgOf(r, 'Could not unload model'), r.ok ? 'ok' : 'bad'); }
      else if (act === 'del-model') { if (!confirm(`Delete model ${id}?`)) return; r = await del(`/api/v1/models/${encodeURIComponent(id)}`); toast(r.ok ? `Deleted ${id}` : msgOf(r, `Could not delete ${id}`), r.ok ? 'warn' : 'bad'); }
      loadModels();
    });
    $('#m-refresh').addEventListener('click', loadModels);

    // ── Recording ──
    const loadRecordings = async () => {
      const r = await fetchJSON('/api/v1/recording/list');
      const recs = r?.recordings || [];
      const box = $('#rec-list');
      box.innerHTML = recs.length ? recs.map((rec) => {
        const id = rec.id ?? rec.name ?? rec;
        return `<div class="flex items-center gap-3 rounded-lg bg-ink-1 border border-ink-3 p-2.5 text-sm">
          <span class="flex-1 truncate font-mono">${id}</span>
          ${rec.size_mb ? `<span class="text-xs text-ink-muted">${fmt.num(rec.size_mb, 1)} MB</span>` : ''}
          <button data-rid="${id}" class="btn-danger !py-1 !px-2.5 text-xs">✕</button>
        </div>`;
      }).join('') : '<div class="text-sm text-ink-muted">No recordings yet.</div>';
    };
    $('#rec-list').addEventListener('click', async (e) => {
      const btn = e.target.closest('[data-rid]'); if (!btn) return;
      if (!confirm(`Delete recording ${btn.dataset.rid}?`)) return;
      const r = await del(`/api/v1/recording/${encodeURIComponent(btn.dataset.rid)}`);
      toast(r.ok ? 'Recording deleted' : msgOf(r, 'Could not delete recording'), r.ok ? 'warn' : 'bad');
      loadRecordings();
    });
    const setRecState = (recording) => {
      const el = $('#rec-state');
      el.textContent = recording ? 'recording' : 'idle';
      el.className = recording ? 'badge-bad' : 'badge-mut';
    };
    $('#rec-start').addEventListener('click', async () => {
      const id = $('#rec-id').value.trim();
      const r = await post('/api/v1/recording/start', id ? { id } : {});
      const started = r.ok && r.data?.success !== false;
      toast(started ? 'Recording started' : msgOf(r, 'Could not start recording'), started ? 'ok' : 'bad');
      if (started) setRecState(true);
      loadRecordings();
    });
    $('#rec-stop').addEventListener('click', async () => {
      const r = await post('/api/v1/recording/stop');
      toast(r.ok ? 'Recording stopped' : msgOf(r, 'Could not stop recording'), r.ok ? 'ok' : 'bad');
      if (r.ok) setRecState(false);
      loadRecordings();
    });

    // ── Adaptive (on-device) training ──
    const loadAdaptive = async () => {
      const a = await fetchJSON('/api/v1/adaptive/status');
      const st = $('#ad-status');
      const stats = $('#ad-stats');
      if (!a) { st.textContent = 'unavailable'; st.className = 'badge-mut'; stats.textContent = ''; return; }
      // A trained model reports frame counts / accuracy / classes; otherwise none.
      const frames = a.trained_frames ?? a.frames;
      const trained = a.trained === true || frames != null || (Array.isArray(a.class_names) && a.class_names.length > 0);
      if (trained) {
        st.textContent = 'trained'; st.className = 'badge-ok';
        const acc = a.training_accuracy != null ? `${fmt.num(a.training_accuracy * (a.training_accuracy <= 1 ? 100 : 1), 1)}% acc` : null;
        const classes = Array.isArray(a.class_names) && a.class_names.length ? `classes: ${a.class_names.join(', ')}` : null;
        stats.textContent = [frames != null ? `${fmt.int(frames)} frames` : null, acc, classes].filter(Boolean).join('  ·  ');
      } else {
        st.textContent = 'none'; st.className = 'badge-mut';
        stats.textContent = a.message || 'No adaptive model yet — record CSI (with ground-truth labels), then train.';
      }
    };
    $('#ad-train').addEventListener('click', async () => {
      $('#ad-train').disabled = true;
      const r = await post('/api/v1/adaptive/train');
      toast(r.ok ? (msgOf(r, 'Adaptive model trained')) : msgOf(r, 'Adaptive training failed'), r.ok ? 'ok' : 'bad');
      $('#ad-train').disabled = false;
      loadAdaptive(); loadModels();
    });
    $('#ad-unload').addEventListener('click', async () => {
      const r = await post('/api/v1/adaptive/unload');
      toast(r.ok ? 'Adaptive model unloaded' : msgOf(r, 'Could not unload adaptive model'), r.ok ? 'warn' : 'bad');
      loadAdaptive(); loadModels();
    });

    // ── Training run (dataset) ──
    const loadTrain = async () => {
      const t = await fetchJSON('/api/v1/train/status');
      const st = $('#tr-status');
      const status = t?.status || (t === null ? 'unavailable' : 'idle');
      st.textContent = status;
      st.className = /run|train|active/i.test(String(status)) ? 'badge-ok' : 'badge-mut';
      $('#tr-config').textContent = t?.config ? JSON.stringify(t.config, null, 2) : '';
    };
    $('#tr-start').addEventListener('click', async () => {
      const r = await post('/api/v1/train/start');
      toast(r.ok ? msgOf(r, 'Training started') : msgOf(r, 'Could not start training'), r.ok ? 'ok' : 'bad');
      loadTrain();
    });
    $('#tr-stop').addEventListener('click', async () => {
      const r = await post('/api/v1/train/stop');
      toast(r.ok ? msgOf(r, 'Training stopped') : msgOf(r, 'Could not stop training'), r.ok ? 'warn' : 'bad');
      loadTrain();
    });

    loadModels(); loadRecordings(); loadTrain(); loadAdaptive();
    const t = setInterval(() => { loadTrain(); loadAdaptive(); }, 4000);
    return () => clearInterval(t);
  },
};
