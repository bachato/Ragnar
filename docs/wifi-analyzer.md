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

Supported bands are detected **per radio**, so the tool lights up 2.4/5/6 GHz on
the Alfa AWUS036AXM and 2.4/5 GHz on the Pi's onboard radio automatically.

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

The transmit-power assumption (`Tx dBm`, default 20) and the environment
path-loss exponent (`n`, default 3.0 for indoor) are adjustable — the model and
its assumptions are shown so the numbers stay honest. This is an **estimate**,
not a calibrated measurement.

---

## Coverage heatmap (walk-around survey)

The Ekahau workflow, in miniature:

1. Pick the **target AP** to map.
2. Optionally **load a floorplan** image.
3. **Walk the space and click where you're standing** — each click takes a live
   passive RSSI reading of that AP and drops a sample at that spot.
4. Samples are interpolated (**inverse-distance weighting**) into a coverage
   heatmap: green where the AP is strong, red where it's weak, so dead zones and
   coverage holes are obvious.

Samples persist in `data/wifi_heatmap.json`; **Clear** starts a fresh survey.

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
| `GET /api/net/wifi/scan?interface=&band=` | passive survey + spectrum + interference |
| `GET /api/net/wifi/radius?interface=&bssid=&tx=&ple=` | signal-radius rings for one AP |
| `GET/POST /api/net/wifi/heatmap` | get / add-sample / floorplan / clear |
| `GET /api/net/wifi/selftest` | parser + analyzer self-test |

```bash
python3 wifi_analyzer.py interfaces
python3 wifi_analyzer.py scan --interface wlan0 --band all
python3 wifi_analyzer.py radius --interface wlan0 --bssid aa:bb:cc:dd:ee:ff
python3 wifi_analyzer.py selftest
```

The self-test (`selftest`) drives the beacon parser (2.4/5/6 GHz, HT/VHT/HE
widths, BSS-Load, security), the congestion/interference analysis, the
frequency↔channel conversions and the radius model against synthetic `iw`
output — 25 checks, all offline.
