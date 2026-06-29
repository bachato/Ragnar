# 📡 RuSense — Camera-Free Surveillance

RuSense is Ragnar's **no-camera surveillance** system. Instead of pointing a lens at
a room, it listens to the ordinary 2.4 GHz WiFi already filling your space and reads
the tiny distortions that a moving body imprints on those radio waves. From those
distortions it can tell you whether a room is **occupied**, whether there is
**motion**, roughly **how many people** are present, and — with a trained model —
coarse **posture / pose** and **vital signs** (breathing and heart rate at rest).

No images are ever captured. There is nothing to leak, nothing to point at a bed or a
desk, and it works in total darkness and through walls. That makes it suited to places
a camera is unwelcome or impractical: **homes, offices, care/elderly monitoring,
bathrooms and bedrooms, server rooms, warehouses, and after-hours premises**.

> [!IMPORTANT]
> For monitoring spaces **you own or are authorized to monitor**. Sensing people
> through walls carries the same privacy responsibilities as any surveillance system —
> use it lawfully and disclose it where required.

← Back to the [Ragnar README](../README.md).

---

## How it works

### 1. WiFi Channel State Information (CSI)

Every WiFi packet is carried across dozens of frequency *subcarriers*. The receiver
measures the amplitude and phase of each one — this is **Channel State Information
(CSI)**. When a person moves, breathes, or simply stands in the room, their body
reflects, absorbs and scatters those subcarriers in a measurable way. RuSense treats
the stream of CSI as a kind of low-resolution radar.

A RuSense sensor node samples up to **114 subcarriers at roughly 100 Hz** on 2.4 GHz.
That continuous fingerprint of the room is what gets analysed — never any video.

### 2. The pieces

```
  ESP32 CSI node(s)  ──UDP CSI frames──▶  sensing-server  ──HTTP/WS──▶  Ragnar web UI
   (ESP32-S3 / C6)        :5005             (127.0.0.1:3000)            (RuSense tabs)
```

| Component | What it is | Where it lives |
|---|---|---|
| **CSI sensor node** | An ESP32-S3 or ESP32-C6 running the RuSense CSI firmware. Listens to 2.4 GHz WiFi and streams CSI frames over UDP to the server. | Flashed from the browser — see [Flashing a node](#flashing-a-sensor-node) |
| **sensing-server** | A prebuilt Rust engine (`bin/sensing-server`, crate `wifi-densepose-sensing-server`) that ingests CSI, runs inference, and exposes a REST + WebSocket API on `127.0.0.1:3000`. | Vendored in this repo; installed as `ragnar-sensing.service` |
| **Ragnar web UI** | The dashboard tabs (Nodes, Live, Training, Models) that visualise presence/motion/people and let you record and train. `webapp_modern.py` proxies `/api/v1/*` and `/ws/sensing` to the sensing-server. | `web/rusense/` |

One node gives you presence and motion for a room. **Multiple nodes** placed around a
space let the engine fuse their views (multistatic fusion) for better people-counting
and coarse positioning.

### 3. What it can report

- **Presence / occupancy** — is anyone in the room?
- **Motion** — movement intensity and events.
- **People count** — estimated number of people present.
- **Pose / posture** — coarse body keypoints and posture, with a trained model.
- **Vital signs** — breathing and heart rate for a still subject (e.g. someone at rest).
- **Signal quality** — so you know when a reading is trustworthy.

---

## Flashing a sensor node

You don't need a toolchain. The firmware is flashed straight from your browser over
USB using the **RuSense CSI Node Flasher** (Web Serial / esptool-js):

### → **[Open the RuSense Flasher](https://pierregode.github.io/Ragnar/)**

1. Open the flasher page in **Chrome or Edge** (Web Serial isn't available in Firefox/Safari).
2. Plug your ESP32 into a **data-capable** USB-C cable (charge-only cables won't work).
3. Pick your board:
   - **ESP32-S3** *(recommended, production)* — dual-core, 8 MB flash, the steadiest platform for live CSI.
   - **ESP32-C6** *(Wi-Fi 6 research)* — RISC-V, 4 MB flash, dual-band 802.11ax for experiments.
4. Click **Forge**, select the `USB JTAG/serial debug unit` port, and let it flash.
5. If the board isn't detected, hold **BOOT** while tapping **RST**, then retry.

The firmware bins served by the flasher are vendored bit-identically from upstream
**RuView** at a pinned commit (see `rusense_flasher/rusense-csi-node.version`).

---

## Running the sensing backend on Ragnar

The sensing engine is bundled with Ragnar — no separate RuView checkout needed.

```bash
cd /home/ragnar/Ragnar
sudo ./scripts/install_sensing.sh
```

This installs and starts `ragnar-sensing.service`:

- On **Raspberry Pi (arm64)** it installs the prebuilt binary at `bin/sensing-server`.
- On **other architectures** (or with `--rebuild`) it installs Rust and compiles from
  the pinned RuView source.

Default ports: HTTP `3000`, WebSocket `3100`, UDP CSI ingest `5005`. The service is
idempotent — safe to re-run.

> By default the sensing API (`/api/v1/*`) is unauthenticated and bound to localhost,
> reached only through Ragnar's web proxy. If you expose it directly, set
> `RUVIEW_API_TOKEN=<token>` to enforce bearer auth.

---

## Using it from the web UI

Open Ragnar's dashboard at `http://<ragnar-ip>:8000` and use the RuSense tabs:

1. **Nodes** — provisioned CSI nodes appear here once they start streaming. Confirm
   frames-per-second is climbing.
2. **Live** — real-time presence, motion and people-count for the monitored space.
3. **Training** — the **Record → Train → Active** loop. Record CSI while you act out
   labelled scenarios (empty room, one person, two people, walking, sitting…), then
   train a lightweight on-device adaptive classifier tuned to *your* space. Ground-truth
   labels are set under the config endpoints.
4. **Models** — load, activate, or unload trained models (`.rvf` containers and LoRA
   profiles).
5. **Settings** — configure **push notifications** for sensing events (see below).

---

## Push notifications (alerts)

RuSense can send a **Pushover** push notification when it detects activity — so a
camera-free space can still alert your phone. Alerts are evaluated **server-side**, so
they fire even when no browser has the RuSense tab open.

Configure them in the RuSense **Settings** tab. Available triggers:

- **Presence / occupancy** — a monitored space goes from empty to occupied (and back).
- **Motion** — significant (active) motion is detected.
- **People-count threshold** — the number of people crosses a value you set. The engine
  exposes only a *per-node* count (which ghosts on individual nodes), so RuSense uses the
  **median across active nodes** — a single node spiking can't move the median, so a count
  is only believed when a majority of nodes agree.
- **Node offline** — a provisioned CSI sensor node stops streaming.

A configurable **cooldown** prevents a flapping signal from spamming you, and each
trigger can be toggled independently under a master on/off switch.

To suppress false positives, an event only fires when **all** of these hold:

- **Minimum confidence** — the detector must be at least this confident (default 80%);
  low-confidence flickers are ignored. (`rusense_notify_min_confidence`)
- **Must last** — the condition has to hold continuously for at least this long
  (default 2 seconds) before an alert is sent. (`rusense_notify_sustain_s`)
- **Geofence** — the disturbance must sit *inside* the mapped room perimeter, not be a
  hallway walk-by or through-wall neighbour. See [Geofence](#geofence--confining-alerts-to-the-room).

All are adjustable in the Settings tab.

Alerts reuse Ragnar's existing **Pushover** account: set your **User Key** and **API
Token** once under the main dashboard's **Config → Pushover Notifications**, then enable
the RuSense triggers in the Settings tab. Use **Send test notification** to confirm
delivery. (Config keys: `rusense_notify_*` in `shared.py`.)

> [!IMPORTANT]
> The alert monitor runs inside the `ragnar` service process. After you change alert
> settings **or pull new code**, restart it so the changes take effect:
> ```bash
> sudo systemctl restart ragnar
> ```

### Geofence — confining alerts to the room

The biggest source of false alerts is motion *outside* the room — neighbours through a
wall, people in the hallway. The **geofence** rejects these: it treats each node as a
disturbance sensor anchored at its mapped corner and only lets an alert through when the
disturbance is **corroborated and interior** to the polygon of node corners. A lone-node
or edge-pinned disturbance (a walk-by) is suppressed. The "room empty" alert is never
suppressed.

To use it:

1. Map each node's **X / Y** corner position in **Settings → Observatory → Room & Nodes**
   (these auto-sync to the backend). You need **≥ 3 nodes mapped**; with fewer the geofence
   is a no-op and alerts behave as before.
2. Leave **"Confine alerts to the room (geofence)"** enabled in the Settings tab.
3. Validate it live: `GET /api/rusense/geofence` (or the status line under the toggle)
   shows the current verdict — `inside perimeter`, `edge/outside`, or `quiet`.

It's a coarse RSSI-based filter, not a hard RF wall (2.4 GHz leaks through walls); tune the
`_GF_*` constants in `webapp_modern.py` if ghosts persist. Config keys:
`rusense_geofence_enabled`, `rusense_node_positions`, `rusense_geofence_window`.

### Two training paths

RuSense can learn in two different ways:

- **Adaptive (on-device)** — a lightweight classifier learned directly from your own
  recorded/live CSI. Fast, runs on the Pi, tuned to your room. This is the
  Record→Train→Active loop in the Training tab.
- **Deep-model dataset training** — heavy training from an external MM-Fi / Wi-Pose
  dataset into a `.rvf` model, for pose/vital-sign capable models. Done offline, not
  from live CSI.

---

## Placement & tuning tips

- Position nodes so the area you care about sits **between the node and the WiFi
  traffic** it's listening to — CSI is richest along that path.
- More nodes around a room = better people-counting and coarser positioning via fusion.
- Keep nodes powered and on a stable WiFi channel; CSI yield (pps) should be non-zero
  and steady once provisioned.
- Vital-sign readings need a **still** subject; expect motion to dominate otherwise.

---

## Credits

RuSense is powered by **[RuView](https://github.com/PierreGode/RuView)** — the
WiFi-CSI DensePose sensing engine (crate `wifi-densepose-sensing-server`) by
PierreGode. Ragnar vendors RuView's prebuilt sensing server and the ESP32 CSI-node
firmware; all of the CSI ingestion, inference, pose estimation and training logic
originates there. Full credit and thanks to the RuView project.

- Sensing engine & firmware: **[github.com/PierreGode/RuView](https://github.com/PierreGode/RuView)**
- This integration lives in Ragnar: see the [README](../README.md).

---

← Back to the [Ragnar README](../README.md).
