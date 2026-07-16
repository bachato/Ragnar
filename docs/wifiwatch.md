# wifiwatch — passive 802.11 attack monitor

`wifiwatch` is a standalone, **passive-only (RX-only)** wireless IDS — the deep,
daemon-shaped companion to the integrated [WiFi Defense](wifi-defense.md) WIDS.
It never transmits: no probe requests, no association, no deauth — nothing on
air. It sniffs 802.11 management frames in monitor mode and flags four attack
classes.

The 802.11 + radiotap parsing is **raw-byte** (no Scapy dissectors), so
`--self-test` and `--replay` of a pcap run with no radio and the self-test needs
no Scapy at all. Scapy is used purely as the live-capture front-end. Detectors
key off each frame's **capture timestamp** (not wall clock), so a replayed
capture timestamps each alert to when the attack actually happened.

- **Test floor:** Raspberry Pi Zero 2 W + Alfa AWUS036AXM (mt7921u).
- **Self-test:** 30/30 (`python3 python/wifiwatch.py --self-test`).
- **Deps:** Python 3.8+, Scapy (live capture only), `iw`.

## Detectors

| Detector | What it catches | Frames |
|---|---|---|
| `deauth_flood` | deauth/disassoc floods — broadcast, per-BSSID, targeted | subtype 12 / 10 |
| `beacon_flood` | fake-AP storms (mdk3/mdk4 beacon mode) | subtype 8 |
| `evil_twin` | rogue APs / evil twins (allowlist) | subtype 8 / 5 |
| `karma_mana` | KARMA / MANA rogue APs | subtype 5 / 4 |

- **deauth_flood** — thresholds per scope: broadcast **6 / 5 s** (critical),
  per-BSSID (deauth+disassoc) **25 / 5 s** (critical), targeted **12 / 5 s**
  (warning). Each event carries the reason code and the **Protected-Frame** bit:
  on a PMF/802.11w (6 GHz/WPA3) network an unprotected deauth is ignored by
  clients but is itself an anomalous spoof attempt.
- **beacon_flood** — a burst of **new** BSSIDs (post-warmup) in an 8 s window;
  **critical** when the burst's locally-administered-MAC ratio ≥ 0.5 (mdk4 emits
  random MACs), **warning** otherwise (dense but non-randomized). See *Warmup*.
- **evil_twin** — an allowlisted SSID beaconed from a BSSID **not** in the
  allowlist → **critical**. An unlisted SSID from ≥ 2 BSSIDs → **info** (allowlist
  it to promote real threats to critical and silence the guesswork).
- **karma_mana** — one BSSID answering ≥ 5 distinct SSIDs.

## Event schema (web-UI ready)

One JSON object per line. Stable top-level keys: `ts`, `module`, `detector`,
`severity` (`info`/`warning`/`critical`), `band`, `channel`, `bssid`, `ssid`,
`signal_dbm`, `summary`. Detector-specific fields live under `detail`.

```json
{"ts":"2026-07-16T18:04:11.402000+00:00","module":"wifiwatch",
 "detector":"deauth_flood","severity":"critical","band":"2.4","channel":6,
 "bssid":"aa:bb:cc:dd:ee:ff","ssid":null,"signal_dbm":-47,
 "summary":"Broadcast deauth flood from aa:bb:cc:dd:ee:ff: 9 frames/5s to all clients (reason 7)",
 "detail":{"kind":"deauth","scope":"broadcast","count":9,"window_sec":5.0,"reason":7,"protected":false}}
```

## Warmup — why it exists

When wifiwatch starts in a dense area, **every AP already on air looks "new"** in
the first window — 40+ neighbours would trip a beacon flood the instant you boot.
So the beacon detector spends `beacon_warmup_sec` (default 30 s) *learning* the
ambient AP set without counting it; only BSSIDs first seen **after** warmup count
toward a flood burst. Deauth/disassoc has no warmup (transient events, no boot
census). Tunable to `0` in a known-clean environment.

## Run

```bash
python3 python/wifiwatch.py --self-test                       # 30/30, no root/Scapy
sudo python3 python/wifiwatch.py --iface wlan1 --echo         # live, echo to stderr
sudo python3 python/wifiwatch.py --iface wlan1 --jsonl /var/lib/ragnar/wifiwatch/events.jsonl
python3 python/wifiwatch.py --replay attack.pcap --echo       # replay a capture (no radio)
python3 python/wifiwatch.py --replay attack.pcap --replay-freq 2437   # force channel if no radiotap
```

Monitor mode (bench): `sudo ./wifiwatch-setup-mon.sh wlan1 US`.

### Hardware note (Alfa AWUS036AXM / mt7921u)

On this chipset **active** monitor (injecting while monitoring) is the buggy path
that can reset the interface; **passive** monitor is stable, and wifiwatch lives
entirely there. Channel retuning uses `iw set freq` (RX-only) — nothing on air.
2.4/5 GHz are solid; 6 GHz is best-effort and off by default (confirm `iw list`
shows a 6 GHz band and you can `set freq` there first).

## Calibrating to your noise floor

`wifiwatch-baseline.py` runs the same passive parse but profiles the
neighbourhood — distinct APs, LA-MAC ratio, p95/max new-BSSID- and
deauth-per-window, busiest channels — then prints a `thresholds` block sized
above your measured ambient (real attacks run 10–100× higher). Capture during a
representative, **attack-free** period; it excludes the warmup census so it
measures steady-state churn.

```bash
sudo python3 python/wifiwatch-baseline.py --iface wlan1 --minutes 15
python3 python/wifiwatch-baseline.py --replay ambient.pcap
```

## Validating against real captures (`--replay`)

The self-test proves the logic; a pcap replay proves it against real frames
without a radio. Alerts during replay are stamped with the **frame's capture
time**. Replay honors `beacon_warmup_sec` — if a capture's beacon flood begins in
the first `beacon_warmup_sec`, front-load ambient beacons or set
`beacon_warmup_sec: 0` in a throwaway config.

## systemd

`scripts/wifiwatch.service` runs `DynamicUser=yes` with exactly `CAP_NET_RAW` +
`CAP_NET_ADMIN`, a strict syscall filter, and `MemoryMax=128M`; state lands in
`/var/lib/ragnar/wifiwatch/`. It puts the NIC in monitor mode via
`wifiwatch-setup-mon.sh` first.

## Relation to the integrated WiFi Defense

- **WiFi Defense** (`wifi_defense.py`, web-UI tab) is the capture-window WIDS:
  ensure monitor mode, capture a window, analyze — with the LA-ratio beacon-flood
  and deauth scope/PMF logic added inline.
- **wifiwatch** is the standalone continuous daemon: raw-byte parsers, warmup
  census, per-scope refractory alerting, channel-aware detection, JSON-lines,
  replay, a calibration tool, and a hardened unit.

## OSI coverage

Link-layer (L2) wireless attack detection, alongside `macwatch` and `arp_guard`
on the passive-detection floor.
