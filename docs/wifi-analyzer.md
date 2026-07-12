# 📊 WiFi Spectrum Analyzer

A passive, tri-band Wi-Fi RF troubleshooter built into Ragnar's web UI —
**Network → WiFi Analyzer** (the sub-tab after *Interfaces*). Think of it as a
software [Ekahau Sidekick 2](https://www.ekahau.com/products/sidekick/): the
same survey-and-heatmap workflow a wireless engineer expects, on a Raspberry Pi
Zero 2 W with an off-the-shelf Wi-Fi 6E dongle instead of a $4,000 instrument.

> **Strictly passive.** The analyzer only ever runs `iw dev <iface> scan
> passive`, which *listens for beacons* and **never transmits a probe request**
> to any AP, and reads the radio's own channel table with `iw phy`. No frame is
> injected. It is a diagnostic/troubleshooting tool, not an attack tool.

---

## What it shows

For every beaconing BSS it hears:

| Field | Source |
|-------|--------|
| **SSID** (or *hidden*) | beacon SSID IE |
| **BSSID** | beacon header |
| **RSSI (dBm)** | radiotap signal |
| **Band** — 2.4 / 5 / 6 GHz | centre frequency |
| **Channel** (number) | centre frequency |
| **Channel width** — 20/40/80/160 MHz | HT / VHT / HE operation IEs |
| **Security** — Open/WEP/WPA/WPA2/WPA3 | RSN / WPA IE (SAE ⇒ WPA3) |
| **Channel utilisation %** | the AP-advertised **BSS-Load IE** — a real, passive medium-busy metric |
| **Stations** | BSS-Load IE station count |
| **DFS/radar** | flagged live from `iw phy <phy> channels` |
| **Vendor** | OUI lookup (nmap/IEEE prefix DB; locally-administered bit ⇒ *Randomized/private*) |
| **Generation** — Wi-Fi 4/5/6/6E/7 | HT/VHT/HE/EHT capability IEs |
| **Max PHY rate** | derived from generation × width × spatial streams (NSS) |
| **Spatial streams (NSS)** | HT/VHT/HE MCS maps |
| **SNR** | RSSI − noise floor from `iw survey dump` (when the radio reports it) |
| **Security detail** | PMF/MFP (off/capable/required), 802.1X-Enterprise, WPS, 802.11k/v/r roaming |
| **TX power / country / DTIM** | TPC report, Country and TIM IEs when advertised |

Supported bands are detected **per radio**, so the tool lights up 2.4/5/6 GHz on
the Alfa AWUS036AXM and 2.4/5 GHz on the Pi's onboard radio automatically.

---

## AP inventory, networks & export

The AP table is sortable on 9 columns (SSID, Vendor, Band, Channel, Width, Rate,
Signal, Security, Utilisation), with a **search** box and an **issues-only**
filter. Generation and security are shown as inline badges (Wi‑Fi 6E, 802.1X,
PMF, WPS, 11k/v/r). A **Networks** view collapses BSSIDs that share an SSID into
one logical network (bands, AP count, best signal). **Export CSV** dumps the full
enriched inventory for offline analysis.

---

## Change tracking (session history)

Every BSSID is remembered across scans in `data/wifi_analyzer_db.json`
(`seen_count`, `first_seen`, a rolling RSSI history and per-AP max/min). Each
scan diffs against the previous one and surfaces a **"Since last scan"** strip:

- **＋ new** — a BSSID heard for the first time,
- **－ gone** — a previously-seen BSSID that dropped out,
- **▼ weakened** — an AP now ≥18 dB below its own peak (moved/failing/blocked).

New APs carry a **NEW** badge and each row shows an inline **RSSI sparkline** of
its recent history. `POST /api/net/wifi/history` resets the store. This is an
**operational** aid (coverage/movement), not the security WIDS — that lives in
the separate **WiFi Defense** tab.

---

## The spectrum graph — two views

A big center horizontal graph plots every AP on a per-band segmented axis
(2.4 | 5 | 6 GHz), x = channel, y = RSSI (−30 dBm top … −95 dBm bottom), colour =
signal strength (green = strong → red = very weak). DFS/radar channels are
shaded. Toggle between:

- **📊 Bar** — one bar per AP at its channel; bar **width tracks the channel
  width** (an 80 MHz AP is 4× wider than a 20 MHz one), height = RSSI.
- **◗ Cone/Dome** — the classic Wi-Fi-analyzer filled **bell curve** per AP,
  centred on its operating channel and spanning its channel width, peak = RSSI.
  This is the view that makes channel overlap and crowding obvious at a glance.

---

## Interference & channel planning

Per band you get a congestion chip (`clear` / `moderate` / `congested`) and a
**"best channel"** recommendation. The analysis surfaces:

- **Co-channel interference** — APs sharing the exact same channel (they take
  turns on the air, so each one's throughput drops).
- **Adjacent-channel overlap** — mainly a 2.4 GHz problem; the recommender only
  ever suggests the non-overlapping **1 / 6 / 11**.
- A per-channel **congestion score** weighting the number of co-/overlapping APs
  by their relative power and their advertised channel utilisation.

---

## Signal-radius estimate

Click any AP row to model its coverage. Using a **log-distance path-loss model**
(`RSSI = RSSI@1m − 10·n·log₁₀(d)`) the analyzer draws concentric coverage rings
for three thresholds and estimates how far *you* currently are from the AP:

| Ring | Threshold | Meaning |
|------|-----------|---------|
| voice | −67 dBm | VoIP / seamless roaming |
| data | −72 dBm | reliable data / video |
| edge | −80 dBm | usable edge of coverage |

The transmit-power assumption (`Tx dBm`, default 20 — auto-filled from the AP's
advertised TPC power when present) and the environment path-loss exponent (`n`,
default 3.0 for indoor) are adjustable, and the model and its assumptions are
shown so the numbers stay honest. An **Env preset** dropdown sets `n` for common
environments — Open/LOS (2.0), Open indoor (2.5), Light indoor (3.0), Office/few
walls (3.5), Heavy walls (5.0) — or **Custom** to type your own; the preset and
the manual `n` field stay in sync. Through walls, a single free-space model reads
*long* (it attributes wall loss to distance), so bump `n` up (or use two-point
calibration) for wall-heavy paths.

### Calibration (make the estimate site-accurate)

Four knobs let you calibrate the model to your adapter and environment rather
than a textbook assumption:

- **RSSI offset (dB)** — per-adapter correction added to every reading (e.g. an
  Alfa that reads 3 dB low → `+3`).
- **Antenna gain (dBi)** / **Cable loss (dB)** — receive-chain EIRP correction
  folded into the reference level.
- **Two-point calibration** — enter two measured `(distance, RSSI)` points and
  the analyzer solves the **path-loss exponent** and the **reference RSSI@1m**
  for *this* site (`n = (RSSI₁−RSSI₂) / (10·log₁₀(d₂/d₁))`), then applies them.
  The model is then labelled **calibrated** rather than *assumed*.

Even calibrated, it remains an **estimate**, not a survey-grade measurement.

---

## Coverage heatmap (walk-around survey)

The Ekahau workflow, in miniature:

1. Pick the **target AP** to map.
2. Optionally **load a floorplan** image.
3. **Walk the space and click where you're standing** — each click takes a live
   passive reading of that AP (RSSI, SNR, noise, band/channel) and drops a
   sample at that spot.
4. Samples are interpolated (**inverse-distance weighting**) into a coverage
   heatmap with a **calibrated colour scale** and labelled legend
   (excellent/good/fair/weak/dead break points).

**Active survey (throughput + latency)** — tick **Active test on click** to also
run an Ekahau-style performance measurement at each point: it pings the gateway
for **latency / jitter / loss** and measures **throughput**. Give it a LAN
**iperf3 server** (best — measures both up *and* down) or leave it blank to use a
WAN **download speed test**. The result is stored on the sample, so the heatmap
**Metric** toggle can map **RSSI (dBm)** (−90→−30), **SNR (dB)** (5→40),
**Throughput ↓/↑ (Mbps)** or **Latency (ms)** (lower = greener). **Test now** runs
a one-off measurement without dropping a sample. Samples lacking the chosen
metric render grey and are excluded from interpolation.

**Named surveys** — save the current floorplan + samples under a name, then
list/load/delete them (`data/wifi_surveys.json`) to keep several sites or
before/after comparisons. **📄 Report** opens a printable one-page survey report
(heatmap image, coverage stats, band/channel plan, interference, security issues
and the full AP inventory) — print or "Save as PDF" from the browser dialog.

### Mesh survey (whole-SSID, per-node coverage)

Tick **Mesh** to survey an entire mesh / ESS instead of one AP. Pick the **SSID**
and each click records the RSSI of **every node (BSSID)** of that network at that
spot, tagging the **serving** (strongest) node — what a client there would
associate with. Two mesh-only metrics then light up:

- **Serving node** — colours each area by *which* node owns it (Node A / B / C…),
  so you can see each node's real coverage footprint and where a client hands off.
- **Hand-off zones** — colours by the margin between the two strongest nodes:
  **green** = good overlap (&lt;6 dB, clean roaming), **amber** = marginal,
  **red** = "sticky"/no overlap (&gt;12 dB — a client may cling to a far node),
  grey = only one node heard. The node registry + per-point node vectors persist
  with the survey.

### Design / predictive coverage

Switch the heatmap to **Design / Predict** mode to *plan* coverage instead of
measuring it — Ekahau's predictive-design feature in miniature:

1. **Draw walls** on the floorplan (click two points per wall) and pick the
   **material** — each carries a real attenuation: drywall 3 dB, wood 4, glass 6,
   brick 10, concrete 15, metal 20. Walls and columns are **colour-coded by
   material** so the construction reads at a glance — 🧱 brick red, glass white,
   concrete grey, steel/metal blue, drywall beige, wood brown (a legend sits
   under the Design tools).
2. **Place AP nodes** — click where an AP would go. **Click again to drop more
   nodes and plan a whole mesh** (they're labelled AP1, AP2, …); **Undo AP** /
   **Clear APs** manage them. Set the **floor width (m)** so distances are metric.
3. **Place columns** — structural pillars are a *major* open-floor coverage
   killer, so drop them with the **⬤ Column** tool: pick the **material**
   (concrete 15 dB, steel/metal 20, brick 10) and the **radius (m)** (a typical
   pillar is ~0.3 m). Each column is drawn to scale (amber, hatched) and **casts
   a signal shadow** on the far side — any AP→point line that passes through the
   pillar loses its dB. **Undo column** / **Clear columns** manage them.
4. Tick **Predict coverage** — the map fills with **modelled RSSI** everywhere.
   With several nodes, each spot shows the **best signal any node delivers**
   (served by its strongest node — exactly how a real mesh behaves), using the
   log-distance path-loss model **minus the summed loss of every wall the
   node→point line crosses and every column it passes through**. Move nodes,
   walls or columns and it updates live.

**Drag to rearrange:** in Design mode you can **grab and drag** any placed
object — drag an **AP node** or a **column** to move it, drag a **wall endpoint**
(the small handles) to re-angle a wall, or drag a **wall's body** to slide the
whole wall. The cursor shows a grab hand over anything draggable, and the
predicted coverage re-renders live as you move. (Dragging never drops a new
object; click empty space to add one.)

Walls, columns and the modelled AP nodes persist with the heatmap (and inside
saved surveys). The prediction math (`predict_point_rssi` per node with wall
segment-crossing + `_seg_circle_hit` column shadowing, `predict_point_rssi_multi`
for the best-node mesh combine) is identical in the Python backend and the JS
renderer, and is covered by selftest.

Live samples persist in `data/wifi_heatmap.json`; **Clear** starts a fresh
survey.

---

## Hardware

Tuned for the **Alfa AWUS036AXM** (MediaTek MT7921AU, `mt7921u` driver — a
Wi-Fi 6E 2.4/5/6 GHz USB dongle) on a **Raspberry Pi Zero 2 W**, but it runs on
any `nl80211`/`cfg80211` radio `iw` can drive (it also works on the Pi's onboard
`brcmfmac`). 6 GHz and DFS/radar channels require **passive** scanning by
regulation — which is exactly what this tool does.

Requires the `iw` package (installed by `install_ragnar.sh` /
`install_packages.sh`).

---

## API & CLI

All endpoints are passive and read-only except the heatmap store.

| Endpoint | Purpose |
|----------|---------|
| `GET /api/net/wifi/interfaces` | wireless interfaces + supported bands |
| `GET /api/net/wifi/scan?interface=&band=` | passive survey + spectrum + interference + groups + change diff |
| `GET /api/net/wifi/radius?interface=&bssid=&tx=&ple=&rssi_offset=&antenna_gain=&cable_loss=&rssi0=` | signal-radius rings (with calibration) |
| `GET /api/net/wifi/calibrate?d1=&rssi1=&d2=&rssi2=` | two-point path-loss fit (n + ref RSSI@1m) |
| `GET/POST /api/net/wifi/heatmap` | get / add-sample / sample-live (optional `active` throughput) / `throughput` one-off / floorplan / clear |
| `GET/POST /api/net/wifi/surveys` | list / save / load / delete named surveys |
| `GET/POST /api/net/wifi/history` | get AP history DB / reset it |
| `GET /api/net/wifi/selftest` | parser + analyzer self-test |

```bash
python3 wifi_analyzer.py interfaces
python3 wifi_analyzer.py scan --interface wlan0 --band all
python3 wifi_analyzer.py radius --interface wlan0 --bssid aa:bb:cc:dd:ee:ff
python3 wifi_analyzer.py selftest
```

The self-test (`selftest`) drives the beacon parser (2.4/5/6 GHz, HT/VHT/HE
widths, BSS-Load, security, generation, NSS, roaming, TPC), the
congestion/interference analysis, SSID/device grouping, the AP-history change
detector, the frequency↔channel conversions, the radius model and its
two-point calibration, and the named-survey store — all against synthetic `iw`
output, **54 checks, all offline**.
