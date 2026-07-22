# Wardriving — Ragnar

## Overview

Ragnar's wardriving engine collects WiFi networks, BLE devices, Zigbee / 802.15.4 devices, cell towers, and GPS positions while driving. Data is stored in SQLite per session and can be exported to WiGLE CSV or KML.

Ragnar supports **five operating modes**, in any combination — all five can run at the same time and merge into one session DB:

| # | Mode | Hardware | What it adds |
|---|------|----------|--------------|
| 1 | **Standalone wardriver** | Raspberry Pi (or PC) with its built-in Wi-Fi and/or one or more USB Wi-Fi adapters | WiFi scanning via `iw`, multi-adapter antenna coverage |
| 2 | **+ HuginnESP (USB)** | ESP32-S3-Touch-LCD-4B or ESP32-C5 running [HuginnESP](https://github.com/PierreGode/HuginnESP) | Real-time WiFi + BLE + AirTag/Flipper/skimmer/pineapple detection (+ Zigbee/802.15.4 on ESP32-C5) |
| 3 | **+ Piglet (USB)** | Any [Piglet](https://github.com/Hamspiced/piglet) board (XIAO ESP32-S3/C5/C6, LilyGo T-Dongle C5) Works only with my fork till tested and aprooved by [Hamspiced](https://github.com/Hamspiced/), flash [here](https://pierregode.github.io/piglet/) | Live WiGLE-CSV stream over serial |
| 4 | **+ Piglet Coordinator (USB)** | Dedicated [Coordinator](https://pierregode.github.io/Ragnar/) firmware on a Waveshare ESP32-C5 *or* ESP32-S3-Touch-LCD-4B | Receives records from a fleet of Piglet mesh nodes over ESP-Now and forwards them to Ragnar live |
| 5 | **+ Piglet Core (USB)** | A regular Piglet board running mesh `core` mode, tethered to Ragnar | Same idea as #4 but on a standard Piglet — the Core scans locally *and* aggregates its mesh nodes, streaming the combined feed to Ragnar |

All modes can be combined simultaneously — including multiples of the same type. Ragnar scans all `/dev/ttyACM*` and `/dev/ttyUSB*` ports at startup, starts a dedicated thread for every Espressif device it finds, and identifies each one from its boot banner. Example fleet: 2 USB WiFi antennas + 1 HuginnESP + 1 Piglet + 1 Piglet Core with 5 mesh nodes — all streams merge into the same session DB.

**Companion identification banner** (emitted at boot over USB-serial):

| Companion | Banner key | Banner value |
|-----------|-----------|--------------|
| HuginnESP | `{"device":"HuginnESP",...}` | Detected via `device` field |
| Piglet (standard) | `{"device":"Piglet",...}` | Falls back to WiGLE CSV header |
| Piglet Core (T-Dongle C5, mesh-core mode) | `{"device":"PigletCore",...}` | Upgraded after config load |
| Piglet Coordinator (dedicated FW) | `{"device":"RagnarCoord",...}` | Dedicated coordinator firmware |

Everything logged automatically receives GPS coordinates if a GPS receiver is connected.

### GPS recovery during dropouts

Most wardrivers log observations with GPS-at-scan-time and discard the rest. Ragnar logs a GPS breadcrumb track during the session and runs a post-pass that backfills missing positions for any observation seen within 5 minutes of a real GPS point. The interpolation is speed-aware — when endpoint speeds differ (slowing for a tunnel, accelerating out the far side), it uses constant-acceleration math instead of constant-velocity, shifting positions toward whichever endpoint the device actually spent more time near.

Details and the math are in the [GPS section](#gps) below.

---

## Hardware

### HuginnESP (ESP32-S3)

| Property | Value |
|----------|-------|
| Board | Waveshare ESP32-S3 Smart 86 Box |
| Display | 4" 480×480 RGB IPS, GT911 touch (I2C) |
| Processor | ESP32-S3, 240 MHz |
| Flash | 16 MB |
| PSRAM | 8 MB OPI |
| Serial | USB CDC, 460800 baud |
| Firmware | [HuginnESP](https://github.com/PierreGode/HuginnESP) (PlatformIO Arduino) |
| Libraries | LovyanGFX 1.1.16, NimBLE-Arduino 1.4.1 |

### Piglet Coordinator — dedicated firmware (ESP32-C5 / ESP32-S3-LCD)

Purpose-built ESP-Now mesh coordinator for Piglet nodes. Doesn't scan WiFi
itself — it just listens to the mesh and forwards everything to Ragnar over USB
as one-object-per-line JSON. Two boards are supported with the same firmware
image; flash either one from the browser at the
[GitHub Pages flasher](https://pierregode.github.io/Ragnar/) (no toolchain
required).

| Property | C5 (headless) | S3-LCD (with display) |
|----------|---------------|-----------------------|
| Board | Waveshare ESP32-C5-WIFI6-KIT | Waveshare ESP32-S3-Touch-LCD-4B |
| Processor | RISC-V @240 MHz | LX7 dual-core @240 MHz |
| Flash | 16 MB | 16 MB |
| PSRAM | 4 MB | 8 MB OPI |
| Display | none | 4″ 480×480 RGB IPS touch |
| Radio | Wi-Fi 6 dual-band, BLE 5 | Wi-Fi 4, BLE 5 |
| Serial | USB CDC, 460800 baud | USB CDC, 460800 baud |
| ESP-Now channel | 6 | 6 |
| Announce banner | `{"device":"RagnarCoord","fw":"c5-1","board":"ESP32-C5",...}` | `{"device":"RagnarCoord","fw":"s3-lcd-1","board":"ESP32-S3-LCD",...}` |
| Source | [`espnow_bridge_firmware/`](../espnow_bridge_firmware/) | same |

### GPS

Optional USB GPS receiver (NMEA via pyserial). Auto-detected at startup.

**u-blox receivers stuck in UBX binary mode.** Some u-blox 7 USB pucks
(VID 1546) come up emitting only UBX binary frames instead of NMEA, which
looks like a healthy receiver that never finds a position ("Searching..."
forever). Ragnar detects this and reconfigures the receiver in place over
the same serial port — no action needed; the journal logs
`sent the NMEA-enable config (attempt N/3)` when it happens. The cheap
pucks have no battery-backed RAM or flash, so the fix cannot be persisted
on them and is reapplied automatically after every power cycle or replug.
If the automatic recovery fails, the manual path is:

```bash
sudo systemctl stop ragnar
sudo python3 scripts/gps_set_nmea.py /dev/ttyACM0 --verify
sudo systemctl restart ragnar
```

`scripts/gps_diag.sh` answers "is it the receiver or is it us" — it reports
whether the port is emitting NMEA, UBX binary, or nothing at all.

---

## Architecture

Ragnar is the host. WiFi adapters scan locally; one (optional) serial companion
adds a second feed; an optional GPS receiver stamps everything. All sources
write into the same per-session SQLite DB.

```
                                                ┌───────────────────────────┐
                                          ┌────►│  HuginnESP                │  ← mode 2
                                          │     │  WiFi + BLE + threats     │
                                          │     │  (480×480 touch)          │
                                          │     └───────────────────────────┘
                                          │
                                          │     ┌───────────────────────────┐
                                          ├────►│  Piglet (plain)           │  ← mode 3
┌─────────────────────────────┐           │     │  WigleWifi-1.4 CSV stream │
│  Raspberry Pi / PC          │           │     └───────────────────────────┘
│                             │ USB CDC   │
│  Ragnar                     │◄──────────┤     ┌───────────────────────────┐
│   ├─ wardriving.py          │  460800   ├────►│  Piglet Coordinator       │  ← mode 4
│   ├─ webapp_modern.py       │           │     │  (dedicated C5 / S3-LCD)  │
│   └─ web UI                 │           │     │  receives mesh via ESPNow │
│                             │           │     └───────────────────────────┘
│  wlan0..N  ←─ iw scan       │           │                  ▲
│  (built-in + USB antennas)  │ ← mode 1  │                  │ ESP-Now ch 6
│                             │           │                  ▼
│  GPS (USB NMEA, opt.)       │           │     ┌───────────────────────────┐
│                             │           │     │  Piglet mesh nodes        │
│  SQLite session DB          │           │     └───────────────────────────┘
└─────────────────────────────┘           │
                                          │     ┌───────────────────────────┐
                                          └────►│  Piglet Core (regular     │  ← mode 5
                                                │  Piglet, mesh-core mode)  │
                                                │  scans + aggregates mesh  │
                                                └───────────────────────────┘
                                                                  ▲
                                                                  │ ESP-Now ch 6
                                                                  ▼
                                                ┌───────────────────────────┐
                                                │  Piglet mesh nodes        │
                                                └───────────────────────────┘
```

One serial companion at a time — they all share `/dev/ttyACM*`. Modes 4 and 5
are different implementations of "coordinator for a Piglet mesh"; you'd pick
one based on which hardware you have. The HuginnESP protocol below is the most
elaborate of the four; Piglet variants speak a simpler one-line-per-record
protocol described later.

---

## HuginnESP Serial Protocol

### Commands (Ragnar → ESP)

| Command | Description |
|---------|-------------|
| `scanap` | Start WiFi scanning |
| `blescan -f` | BLE filtered (Flipper + AirTag) |
| `blescan -a` | BLE all (all devices + threat detection) |
| `capture -skimmer` | BLE skimmer detection |
| `pineap` | Pineapple/Evil Twin detection |
| `stop` | Stop active scan, return to auto-cycle |
| `capture -stop` | Stop BLE capture |
| `status` | Get current mode (JSON) |
| `wardrive` | Enter the fast wardrive loop (default for HuginnESP) |

### Wardrive Mode (default for HuginnESP)

When a HuginnESP companion is detected, Ragnar issues `wardrive` once at handshake and reads the resulting stream continuously. The firmware then alternates two exclusive radio phases:

| Phase | Duration | Activity | Mode label |
|-------|----------|----------|------------|
| WiFi  | ~2–5 s   | Per-channel active scans walking a weighted channel list | `wardrive` |
| BLE   | 1.5 s    | `BLE_MODE_ALL` — every advertisement emitted as JSON | `wardrive` |

The WiFi phase walks a fixed channel schedule that visits high-traffic channels (1/6/11 on 2.4 GHz, the non-DFS UNII subset on 5 GHz) several times per pass and the rarer/DFS channels once. Each per-channel scan emits results immediately on completion, so observations stream in throughout the phase rather than batching at the end of a full sweep. On the C5 dual-band build the full schedule is ~50 channels; on the S3 (2.4 GHz only) it's ~20.

The firmware also keeps a bounded on-device set of recently-emitted BSSIDs and suppresses duplicate emissions within a wardrive session — the same AP scanned on the same channel four times per cycle is only sent once. The set resets every time the host issues `wardrive`, so stopping and starting a session re-emits every visible BSSID. Ragnar's `upsert_network` still dedupes on receive; on-device dedup primarily saves serial bytes and host parse time.

Flipper / AirTag / skimmer / BLE-spam alerts still fire passively from the same BLE phase. Dedicated evil-twin/pineapple scan windows are not included in the wardrive loop — run `pineap` manually if a one-shot evil-twin check is needed.

### Rotating Cycle (legacy)

Used when the companion identifies as something other than HuginnESP — Ragnar drives a manual rotation of `scanap` / `blescan -f` / `blescan -a` / `capture -skimmer` / `pineap` commands (94 s total cycle). The rotation is preserved for compatibility but is not the active path during normal HuginnESP operation.

### Serial Output (ESP → Ragnar)

#### WiFi Networks (JSON, one line per AP)
```json
{"type":"WIFI","mac":"00:00:00:00:00:00","ssid":"wifiSSID","rssi":-84,"channel":1,"auth":"WPA2"}
```

**Band split.** Companion counts are bucketed into 2.4 GHz and 5 GHz. The band
is taken from an explicit `"band"` field when the firmware sends one (the
multi-line text format's `Band:` line also counts), otherwise inferred from the
channel — 1–14 is 2.4 GHz, 32+ is 5 GHz. A record with an unknown channel still
counts toward the companion total but lands in neither bucket, so the two never
over-report. The companion status bar shows `2.4G` / `5G` alongside the total
**only once a 5 GHz network has actually been seen**, so a 2.4-only board
(plain ESP32-S3) keeps its compact single-total display.

#### BLE Devices (JSON, ALL mode, one line per device)
```json
{"type":"BLE","mac":"AA:BB:CC:DD:EE:FF","name":"DeviceName","rssi":-60}
```

#### Zigbee / 802.15.4 Devices (JSON, one line per sighting)

Emitted by HuginnESP builds with an IEEE 802.15.4 radio (ESP32-C5). Ragnar
stores these in a dedicated `zigbee_devices` table and counts them separately
from BLE — the live status bar and displays show a `Zigbee` total alongside
`BT` and `Cell`, and `/api/wardriving/zigbee` returns the full list.

> **WiGLE export is opt-in.** WiGLE has no standard 802.15.4 record type, so
> Zigbee devices are **excluded from WiGLE CSV export by default**. Enable
> **Config → Wardriving → Include Zigbee in WiGLE CSV** (`wardriving_wigle_include_zigbee`)
> to append them with a `ZIGBEE` type token — intended for your own tooling,
> not for submitting to WiGLE. Applies to both manual export and Auto Export on Stop.

```json
{"type":"ZIGBEE","panid":"0x1A2B","addr":"AABBCCDDEEFF0011","short":"0x1234","channel":15,"rssi":-70,"lqi":180,"ftype":"beacon"}
```

Each device is identified by its 64-bit extended address (`addr` / EUI-64) when
the frame carries one; otherwise Ragnar falls back to `"<panid>:<short>"` as the
identity so a device is still counted once. `lqi` (link quality) and the
802.15.4 `channel` (11–26) are retained; `ftype` (e.g. `beacon` / `data` /
`cmd`) is stored as the device type. GPS is stamped from Ragnar's fix when the
frame has none, exactly like WiFi/BLE rows.

#### AirTag (multi-line, FILTERED + ALL mode)
```
AirTag found!
Tag: 1
MAC Address: D3:59:9B:E4:2C:3A
RSSI: -89
```

#### Flipper Zero (multi-line, FILTERED + ALL mode)
```
Found White Flipper Device:
MAC: AA:BB:CC:DD:EE:FF,
Name: Flipper-X,
RSSI: -70
```

#### Skimmer (multi-line, SKIMMER + ALL mode)
```
POTENTIAL SKIMMER DETECTED!
Device Name: HC-05
MAC Address: 11:22:33:44:55:66
RSSI: -55
Reason: Suspicious BLE module near payment terminal
```

Known skimmer names: `HC-05`, `HC-06`, `HC-08`, `BT05`, `BT06`, `JDY-30`, `JDY-31`, `JDY-33`, `SPP-CA`

#### Pineapple/Evil Twin (multi-line)
```
Pineapple detected: NetworkName
BSSID: AA:BB:CC:DD:EE:FF
Channel: 6
```

#### BLE Spam (single line)
```
BLE Spam detected from AA:BB:CC:DD:EE:FF
```
Triggered at 20+ advertisements from the same MAC within 5 seconds.

#### Status (JSON, response to `status` command)
```json
{"mode":"auto","wifi_count":5,"ble_count":12}
```

#### Boot Messages
```
[BOOT] HuginnESP starting...
[BOOT] Free heap: 234567
[BOOT] PSRAM: 8388608
[BOOT] Init WiFi...
[BOOT] WiFi OK
[BOOT] Init BLE...
[BOOT] BLE OK
[BOOT] All tasks started — entering main loop
```

---

## Ragnar Parser

`wardriving.py → _parse_serial_line()` handles all output:

| Data type | Detection | Storage | GPS |
|-----------|-----------|---------|-----|
| WiFi JSON | `line.startswith('{')` → `type == WIFI` | `upsert_network()` | ✅ |
| BLE JSON | `line.startswith('{')` → `type == BLE` | `upsert_bluetooth()` | ✅ |
| AirTag | `line.startswith('AirTag found')` → buffer | `upsert_bluetooth('AirTag')` | ✅ |
| Flipper | `re.match('Found .* Flipper')` → buffer | `upsert_bluetooth('Flipper')` | ✅ |
| Skimmer | `'POTENTIAL SKIMMER' in line` → buffer | `upsert_bluetooth('Skimmer')` | ✅ |
| Pineapple | `'Pineapple detected' in line` | `_esp_alerts` list | ✅ |
| BLE Spam | `'BLE Spam detected' in line` | `_esp_alerts` list | ✅ |
| WiGLE CSV | Comma-separated with MAC format | `upsert_network()` / `upsert_bluetooth()` | ✅ |
| Multi-line WiFi | `[N] SSID: ...` → buffer | `upsert_network()` | ✅ |

Ignored lines:
- `huginn>`, `Wardrive:`, `Registered`, `Unsupported`
- `WiFi scan`, `Started`, `Stopped`, `Usage:`, `BLE initialized`, etc.
- `[BOOT]` prefix (not explicitly filtered but matches no parser)

---

## GPS

### Sources

Auto-detected at startup, in priority order:

1. **gpsd** on `localhost:2947` — if a `gpsd` instance is running it owns the serial device; Ragnar reads its JSON stream (`TPV` / `SKY`).
2. **Direct NMEA serial** — `/dev/serial/by-id/*` symlinks containing GPS keywords (`gps`, `u-blox`, `ublox`, `nmea`, `gnss`, `bn-`, `vk-`).
3. **NMEA probe** — other `by-id` entries that aren't already claimed by an ESP companion are probed at 9600/4800/38400/115200 baud for `$GP`/`$GN`/`$GL` sentences.
4. **Raw device nodes** — `/dev/ttyACM*`, `/dev/ttyUSB*`, `/dev/ttyS*`, `/dev/ttyAMA*`, `/dev/serial0`, `/dev/serial1` — probed the same way.

### gpsd setup

`gpsd` + `gpsd-clients` are installed by the wardriving installer (`install_wifi_management.sh`), which then runs `scripts/setup_gpsd.sh`:

- **Generic detection.** The script pins `DEVICES` to whatever USB GPS the standard detector (`gps_manager.detect_gps_device`) finds — any NMEA puck, not a single VID:PID — preferring a stable `/dev/serial/by-id/*` symlink so the pin survives a replug.
- **`USBAUTO="false"` (deliberate).** This stops gpsd's udev hotplug from seizing a companion ESP32 (Piglet/Huginn) `/dev/ttyACM*` port. Pinning + USBAUTO-off is what keeps gpsd and the companion serial readers from fighting over the same device.
- **`GPSD_OPTIONS="-n"`.** gpsd polls the receiver before any client connects, so `satellites_in_view` / `snr_max` update while still searching for a fix.
- **Runtime ensure.** On `start()`, wardriving best-effort re-runs `setup_gpsd.sh` if gpsd isn't active or a *different* GPS has been swapped in, then `gps_manager` consumes the gpsd socket (`source: gpsd`). If gpsd isn't installed it silently falls back to direct serial.
- **Verify live.** `cgps` or `gpsmon` show per-satellite SNR in real time — useful for antenna placement / sky-test checks.

Re-run `sudo scripts/setup_gpsd.sh` manually after swapping to a different GPS receiver.

### NMEA Parser

- **Permissive talker IDs.** The GGA/RMC/GSV regexes accept any two-letter talker prefix (GP, GN, GL, GA, GB, GI, GQ, …) so multi-GNSS modules are covered.
- **Optional time field.** Pre-fix receivers emit GGA/RMC with empty time and position. The parser accepts these so `last_update` and satellite counters move as soon as any NMEA is received — not only after first fix.
- **GSV parsing.** Per-constellation `$xxGSV` sentences are aggregated; the API exposes `satellites_in_view` (sum across all reporting constellations) and `snr_max` (highest reported SNR in dB-Hz). The multi-message GSV sweep is also stitched back into a **per-satellite list** (PRN, elevation, azimuth, SNR) per constellation, which the diagnostics endpoint surfaces as `gps.sky` for the sky-view plot; the NMEA 4.10+ trailing signal-ID field is ignored. Entries that haven't been heard from in 30 s are pruned so a constellation that stops reporting doesn't inflate the total.
- **Liveness signal.** `last_sentence` updates on any recognized NMEA line (including GSV / GSA / VTG / GLL / TXT and pre-fix GGA/RMC). `last_update` continues to mean "last positional/fix update". Together they distinguish "GPS is alive but has no fix yet" from "GPS isn't transmitting at all".

### Status Fields (`/api/wardriving/gps`)

| Field | Meaning |
|-------|---------|
| `connected` | Port open and reader thread alive |
| `source` | `gpsd` or `serial` |
| `port` | Device path |
| `has_fix` | `fix_quality > 0` and lat/lon set and `last_update` within 10 s |
| `fix_quality` | `0` no fix, `1` GPS, `2` DGPS |
| `satellites` | Used in fix (from GGA) |
| `satellites_in_view` | Total visible across constellations (from GSV) |
| `snr_max` | Highest current SNR, dB-Hz |
| `hdop` | Horizontal dilution of precision |
| `latitude` / `longitude` / `altitude` | Most recent position |
| `speed_kmh` / `course` | Velocity / heading |
| `last_update` | Epoch of last GGA/RMC with position info |
| `last_sentence` | Epoch of last *any* parsed NMEA |
| `error` | Last error string, or `null` |

### Wardriving GPS Card (UI)

Shows the most actionable signals at a glance:

- **Status line** — `GPS-Fix OK` / `Searching (N visible)` / `Connected` / `No GPS`. The visible count appears when there's no fix but the antenna is seeing satellites — it tells you whether you're antenna-limited or signal-limited.
- **Coords line** — `lat, lon` once a fix is established.
- **Sats line** — `Sats: used/in-view · SNR N dB · HDOP H`. HDOP is hidden while it's still the pre-fix 99.99 placeholder.
- **Speed line** — velocity in the configured unit. Set **Config → Wardriving → Speed Unit** (`wardriving_speed_unit`, `kmh` or `mph`) to choose km/h or mph. This is display-only and applies everywhere speed is shown — GPS card, live map marker, kiosk readout, and the hardware display. Recorded data (`speed_kmh`) is always stored in km/h regardless of the setting.

### Diagnostics Panel (UI)

> Full reference: **[Diagnostics Panel Guide](diagnostics.md)** — the endpoint,
> every group, the Radios exclusion reasons, the Power/throttle fields, and the
> feed-stall correlation logic.

At the bottom of the **Wardriving** tab (and of the phone-access AP page,
`web/wardrive_mobile.html`) sits a **Diagnostics** panel, collapsed by default.
It is a native `<details>` element, so the toggle keeps working even if a script
errors — which is precisely when the panel gets opened.

Its summary always shows a live hint (`GPS fix` / `GPS searching` / `no GPS`,
with `· error` appended when the engine or GPS reports one), so a glance is
often enough without expanding. Expanded, it lists everything the
[Status Object](#status-object) exposes, grouped:

The **GPS**, **Session**, **Scanning**, **Coverage**, **Companions** and
**Device** groups come from the status object the panel already polls. The
**GPS constellations**, **GPS sky view**, **Radios**, **Power** and **Errors**
groups come from a second endpoint, `GET /api/wardriving/diagnostics`, which the
panel fetches **only while it is expanded** (and at most every 8 s; the backend
caches 5 s).
That walk touches sysfs and shells out to `vcgencmd`, so it deliberately does
not ride the 3-second status poll.

| Group | Contents |
|-------|----------|
| **GPS** | fix + quality, satellites used/in-view, SNR max, HDOP, lat/lon/altitude, speed, course, source, port, age of last update and last NMEA sentence, time-to-first-fix (or how long it has been searching), error |
| **GPS constellations** | per-constellation satellites in view and peak SNR (GPS / GLONASS / Galileo / BeiDou / QZSS / NavIC) |
| **GPS sky view** | polar plot of every satellite by azimuth/elevation, coloured per constellation — North up, zenith at centre, horizon at the rim. Fill opacity tracks SNR (untracked satellites render hollow); hover a dot for PRN / elevation / azimuth / SNR. This is the graphical half of the same GSV data u-center draws |
| **Radios** | every wireless interface present, whether it is scanning, its driver / mode / link state, the USB adapter behind it — and **when it is not scanning, the reason** |
| **Power** | per-USB-device declared draw and which interface it backs, summed USB budget, `usb_max_current_enable`, supply throttle/under-voltage flags (now and since boot), core voltage, temperature, and Pi 5 PMIC board power |
| **Errors** | everything currently complaining — engine, GPS, radios, companions, supply and **stalled feeds** — gathered into one list |

> **Declared, not measured.** The per-device milliamps come from the USB
> descriptor's `bMaxPower`. No Pi meters per-port current, and the figure is
> frequently understated — a tri-band adapter that really pulls several hundred
> milliamps may declare 100 mA. Treat the total as the budget the host *thinks*
> it has handed out, not as consumption. `usb_max_current_enable` is a Pi 5
> setting and is only shown on a Pi 5.

> **Stalled feeds.** A feed that has *stopped* looks identical to a weak one in
> the summary numbers — the last-known satellite count and SNR simply sit at
> their final value. So **Last NMEA** and **Last scan** turn red once they go
> stale (30 s and 60 s), and the Errors group says so in words. When GPS and
> scanning go quiet within a minute of each other, it adds a note that both hang
> off USB, so a bus/hub glitch or a dip on the USB rail fits better than an RF
> or per-device fault — check `dmesg` for USB resets. That correlation is
> invisible if you only read the satellite counts.
| **Session** | id, duration, network totals, open/WEP/WPA, per-band, Bluetooth, cell towers, Zigbee devices, cameras, trackpoints, strongest AP, DB path |
| **Scanning** | running, band mode, scans completed, networks last scan, last scan age, interfaces, plus per-adapter driver / bands / USB / manufacturer / network count |
| **Coverage** | BSSIDs seen by 2+ adapters, and per adapter its unique count, *only-here* count and median best RSSI — the antenna-comparison view (dashboard only) |
| **Companions** | per-device up/down, network counts, 2.4/5 split, ESP mode, BLE count, Zigbee count (802.15.4 boards), mesh nodes, coordinator board/firmware, recent alerts |
| **Device** | device name, Bluetooth/cell totals, GPS-backfill setting |

Fields with no value are omitted rather than rendered blank, and the panel skips
its DOM work entirely while collapsed (re-rendering from the last status when
expanded), so the polling loop costs nothing extra when it is closed.

> **Diagnosing "sees satellites but never gets a fix":** open **GPS** and read
> **SNR max** together with **Satellites** (`used / in view`) and **Searching
> for**. A cold start must demodulate the ephemeris — roughly 30 s of continuous
> reception at ≥30 dB-Hz — while an already-established fix tracks down to
> ~20 dB-Hz. So a receiver showing satellites in view with `0 used` and a low
> SNR is signal-limited (antenna placement, or RF desense from an adapter sat
> next to the puck), whereas comparable SNR with the fix repeatedly resetting
> points at power instead. **Power** settles that second half: compare the
> summed USB draw against what the board allows, and check whether
> `under-voltage` appears under *Right now* or *Since boot* — the "since boot"
> flags are what catch a brownout that has already passed.

> **Diagnosing "only wlan0 is scanning":** open **Radios**. Every wireless
> interface the kernel knows about is listed, and any radio that is not in the
> scan set carries a *why not* line — `rfkill-blocked` (with the unblock
> command), `held as the uplink / management radio` (wardriving never claims the
> interface carrying Ragnar's own connectivity — see `_management_ifaces`), `in
> AP mode (lent to the phone-access AP)`, a monitor child, or simply *present
> but not claimed*. A radio that does not appear at all was never enumerated by
> the kernel, which points at the adapter, cable or power rather than at Ragnar.

### Network Position Preservation

`upsert_network` uses `COALESCE(?, col)` for `latitude`, `longitude`, `altitude`, `best_lat`, `best_lon`, `speed_kmh`, and `hdop` on both the stronger-RSSI and weaker-RSSI update paths. Concretely: an existing row's GPS columns are **never** overwritten with NULL. A re-scan with a stronger signal but no current GPS fix keeps the previously-recorded position instead of erasing it.

### GPS Backfill

Each session writes one row to `gps_track` every 5 s while GPS has a fix:

```
gps_track (timestamp, latitude, longitude, altitude, speed_kmh, satellites, hdop)
```

> **Opt-in only.** Backfilled positions are **estimated, not measured** — interpolated coordinates, not real observations. The "Backfill GPS" map button is hidden by default; enable it under **Config → Wardriving → Allow GPS Backfill** (sets `wardriving_allow_backfill`). The endpoint returns `403` while the flag is off. Any row backfilled this way is flagged `gps_backfilled = 1` and is **excluded from WiGLE CSV export** so interpolated coordinates aren't submitted as real observations (it still appears on the map and in KML).

`POST /api/wardriving/backfill_gps` (or the "Backfill GPS" button) fills in missing positions on `networks`, `bluetooth_devices`, and `cells` rows by looking up each row's `first_seen` against the breadcrumb track:

1. `bisect` the track to find the two trackpoints bracketing the row's timestamp.
2. **Both within 5 minutes:** interpolate position between them.
3. **One side within 5 minutes:** use the nearest single trackpoint.
4. **Neither within 5 minutes:** leave the row's coords as NULL.

The interpolation is **speed-aware**. When both bracketing trackpoints have a non-zero `speed_kmh`, the position fraction along the chord uses a constant-acceleration model instead of constant-velocity:

```
v(f_time) = v1 + (v2 - v1) · f_time
f_pos = (2·v1·f_time + (v2 − v1)·f_time²) / (v1 + v2)
lat   = lat1 + (lat2 − lat1) · f_pos     (same for lon, alt)
```

For symmetric speeds the formula reduces to linear — steady cruising is unaffected. For asymmetric speeds (slowing into a tunnel mouth then accelerating out the far side, for example) the placement shifts toward whichever endpoint was moving slower, where the device actually spent more time. On a 1 km gap with 20→60 km/h endpoints, a time-midpoint sample moves from 50 % chord (linear) to 37.5 % chord — a 125 m correction.

Falls back to linear when either endpoint speed is NULL or both are zero. The chord assumption itself isn't corrected — backfill cannot recover curve geometry from speed alone.

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/wardriving/status` | Full status incl. GPS, serial, counters |
| GET | `/api/wardriving/diagnostics` | Deep diagnostics: radios + exclusion reasons, USB power budget, supply health, GPS constellations, errors ([panel](#diagnostics-panel-ui)) |
| POST | `/api/wardriving/start` | Start wardriving session |
| POST | `/api/wardriving/stop` | Stop session |
| GET | `/api/wardriving/networks` | List captured WiFi networks |
| GET | `/api/wardriving/bluetooth` | List BLE devices |
| GET | `/api/wardriving/cells` | List cell towers |
| GET | `/api/wardriving/sessions` | List sessions |
| GET | `/api/wardriving/export/<id>` | Export session (WiGLE CSV / KML) |
| POST | `/api/wardriving/import` | Import WiGLE CSV |
| GET | `/api/wardriving/gps` | GPS status |
| GET | `/api/wardriving/interfaces` | Available WiFi interfaces |
| GET | `/api/wardriving/serial/detect` | Auto-detect ESP32 port |
| GET/POST | `/api/wardriving/serial` | Serial status / start/stop listener |
| GET | `/api/wardriving/track` | GPS track (lat/lon history) |
| POST | `/api/wardriving/backfill_gps` | Fill missing GPS on observations from the track |
| GET/POST | `/api/wardriving/huginn_config` | Read / push HuginnESP runtime knobs |
| POST | `/api/wardriving/device_name` | Set device name |
| GET/POST | `/api/wardriving/on_boot` | Auto-start on boot |

---

## Status Object

`GET /api/wardriving/status` returns:

```json
{
  "running": true,
  "session_id": "20260520_122919",
  "interfaces": ["wlan0"],
  "scans_completed": 42,
  "total_networks": 156,
  "gps": {
    "connected": true,
    "source": "serial",
    "port": "/dev/ttyACM1",
    "has_fix": true,
    "fix_quality": 1,
    "satellites": 5,
    "satellites_in_view": 9,
    "snr_max": 41,
    "hdop": 1.3,
    "latitude": 59.3293,
    "longitude": 18.0686,
    "altitude": 28.0,
    "speed_kmh": 47.2,
    "course": 184.0,
    "last_update": 1779272835.24,
    "last_sentence": 1779272835.24,
    "error": null
  },
  "companion_name": "Huginn",
  "serial_connected": true,
  "serial_port": "/dev/ttyACM0",
  "serial_networks": 75,
  "serial_unique": 62,
  "serial_seen_unique": 70,
  "esp_mode": "wardrive",
  "esp_ble_count": 87,
  "esp_alerts": [
    {"time": 1683456789, "alert": "AirTag found!"}
  ],
  "bluetooth_count": 87,
  "cell_count": 3,
  "stats": { ... }
}
```

---

## Data Storage

Each session creates a SQLite database at `data/wardriving/session_<id>.db`.

### Table: networks
| Column | Type | Description |
|--------|------|-------------|
| bssid | TEXT | MAC address (primary key) |
| ssid | TEXT | Network name |
| security | TEXT | WPA2, WPA3, Open, etc. |
| channel | INT | WiFi channel |
| frequency | INT | Frequency in MHz |
| band | TEXT | `2.4GHz`, `5GHz`, `6GHz` |
| rssi | INT | Most recent signal strength (dBm) |
| best_rssi | INT | Strongest signal ever observed |
| latitude / longitude / altitude | REAL | Most recent observed position |
| best_lat / best_lon | REAL | Position at strongest-signal observation |
| speed_kmh / hdop | REAL | Velocity / DOP at last observation |
| first_seen / last_seen | TEXT | ISO timestamps |
| scan_count | INT | Number of times observed |
| interface | TEXT | `wlan0`, `wlan1`, `esp32-serial`, `import`, etc. |
| is_camera | INT | 1 if MAC OUI or SSID matches a known camera pattern |

### Table: bluetooth_devices
| Column | Type | Description |
|--------|------|-------------|
| mac | TEXT | BLE MAC address |
| name | TEXT | Device name |
| rssi | INT | Signal strength |
| device_type | TEXT | `BLE`, `AirTag`, `Flipper`, `Skimmer` |
| latitude / longitude / altitude | REAL | GPS position |
| first_seen / last_seen | TEXT | ISO timestamps |

### Table: gps_track
GPS breadcrumb trail — one row every 5 s during a session, only while GPS has a fix. Used by `backfill_gps_from_track` to assign positions to observations made during GPS dropouts.

| Column | Type | Description |
|--------|------|-------------|
| timestamp | REAL | Unix epoch when the point was logged |
| latitude / longitude / altitude | REAL | Position |
| speed_kmh | REAL | Velocity at that point (used for constant-accel interpolation) |
| satellites | INT | Sats used in fix |
| hdop | REAL | Horizontal dilution of precision |

---

## Export

### WiGLE CSV
Standard format for uploading to wigle.net. Contains MAC, SSID, AuthMode, channel, RSSI, GPS coordinates.

### KML
Google Earth format with network positions as markers.

---

## Setup

### 1. Pick (and flash) a companion — optional

You only need a companion for modes 2–5. Standalone mode (1) works without one.

| Mode | Companion | Flash with |
|------|-----------|-----------|
| 2 | HuginnESP | `cd HuginnESP && pio run --target upload` (COM8 on Windows, `/dev/ttyACM*` on Linux) |
| 3 | Piglet (plain) | Piglet's own flasher / Arduino IDE — see the [Piglet repo](https://github.com/Hamspiced/piglet) |
| 4 | Piglet Coordinator (dedicated) | Browser-flash from [pierregode.github.io/Ragnar/](https://pierregode.github.io/Ragnar/) |
| 5 | Piglet Core | Flash Piglet as in mode 3, then set `meshModeOnBoot=core` in `wardriver.cfg` |

### 2. Connect to Ragnar

**Auto-detect (Linux):**
Click 🔍 Search in the web UI — finds the ESP32 automatically via `udevadm`,
regardless of which companion firmware is on it.

**Manual:**
Enter the port (`/dev/ttyACM0` or `COM8`) in the serial field and click Connect.

The serial card's companion label updates from `Companion` → `Huginn` /
`Piglet` / `Piglet Coordinator` once the boot banner is parsed.

### 3. GPS (optional)

Connect a USB GPS receiver. Ragnar auto-detects NMEA devices.

In modes 3 and 5 the Piglet board itself has a GPS module — those positions
ride along inside the WigleWifi CSV rows, so Ragnar's own GPS is optional but
recommended (it backfills network observations made during Piglet dropouts).
In modes 2 and 4 the companion has no GPS, so Ragnar's GPS is the only source.

### 4. Start Wardriving

Click **Start Wardriving** in the web UI. Ragnar begins scanning with all
active wlan interfaces and ingesting whatever is on the serial port.

### Adapter detection — "I plugged in a third adapter but only see wlan0/wlan1"

Radios are enumerated from **both** `nmcli` **and** `/sys/class/net`, and the two
lists are **unioned**. This matters because NetworkManager omits a radio
entirely when it is unmanaged (Ragnar marks its own scan adapters unmanaged so
NM doesn't add competing routes), left in monitor mode, or its driver loaded
after NM started — so nmcli alone is never authoritative. Monitor child vifs
(`wlan1mon`, `mon0`) are filtered out so they don't double up with their parent.

On start, the log lists exactly what was found:

```
Wardriving detected 3 WiFi interface(s): wlan0, wlan1, wlan2
```

If an adapter is still missing, check in this order:

```bash
ls /sys/class/net          # is the radio enumerating at all?
rfkill list                # soft/hard blocked? -> sudo rfkill unblock all
dmesg | tail -30           # driver/power errors on plug-in
```

If the interface is **absent from `/sys/class/net`** it is not a Ragnar problem —
the adapter isn't enumerating (driver, power, or a hard rfkill block). A
freshly-plugged USB dongle commonly comes up **soft-blocked**: it appears in
`/sys/class/net` and in the adapter list but scans zero networks. Ragnar logs a
warning naming any blocked radio; clear it with `sudo rfkill unblock all`.

**Hot-plug is live — no restart needed.** The scan set is reconciled with the
radios actually present every ~12 s, so an adapter plugged in *after* wardriving
started (e.g. booting without the Alfa, then connecting it) joins the sweep on
its own, and a yanked one drops out. The scan-set change is logged:

```
Wardriving: scan set changed (added=['wlan1'], removed=—); now scanning ['wlan0', 'wlan1']
```

The rescan deliberately leaves alone the radio currently hosting the phone-access
AP and any radio in AP/monitor mode (e.g. WiFi Defense), and re-checks a
soft-blocked adapter on the next pass once you `rfkill unblock` it.

### "Adding a second dongle crashes the whole box"

Two distinct causes, and they look identical from the outside.

**1. Power (most common).** A USB Wi-Fi adapter is the heaviest load you can add
— an Alfa draws roughly **0.5–1 A**. On a Pi whose 5 V rail is already marginal,
the second dongle browns out the board and it **resets**. Nothing appears in the
logs, because the OS never got the chance to write any. Check the SoC's throttle
register:

```bash
vcgencmd get_throttled     # 0x0 is healthy
dmesg | grep -i voltage    # "Undervoltage detected!"
```

Any non-zero value means the supply has no headroom. Ragnar now reads this at
wardriving start and logs a `Wardriving: POWER — …` warning naming the
condition. The fix is hardware: a stronger PSU, or run the dongles from a
**powered** USB hub so they don't draw off the Pi.

**2. Losing the uplink (looks like a crash, box is actually still running).**
Wardriving claims each scan adapter from NetworkManager (`managed no`) so NM's
autoscan doesn't race the scan trigger. That operation is **unrecoverable** — NM
will not reconnect a device it has been told not to manage. If it were applied
to the radio carrying Ragnar's own connectivity, the box would drop off the
network permanently while still running happily headless.

The uplink is therefore protected by **stable identity** — the interface holding
the default route, plus the configured/auto-detected management interface — and
never by association state alone, which is a point-in-time check that loses the
race while roaming, during the boot race, or when a scan knocks the link off.
The protected radio is still scanned; only the NM claim and the mode reset are
skipped. The log names it on start:

```
Wardriving: wlan0 is the management/uplink radio — scanning it but leaving
NetworkManager and its mode alone
```

If a box ever does end up unmanaged, `sudo nmcli dev set wlan0 managed yes`
restores it.

---

## Camera Recognition

Ragnar identifies surveillance cameras based on MAC OUI prefixes (manufacturers):
Axis, Hikvision, Dahua, Vivotek, Bosch, Samsung, Reolink, Amcrest, Foscam, and more.

Cameras are marked in the network list with type and manufacturer.

---

## Piglet Integration

[Piglet](https://github.com/Hamspiced/piglet) is an open-source ESP32-based wardriving platform by Hamspiced. It scans WiFi networks with GPS positioning and logs WiGLE-compatible CSV files to its SD card.

### Supported Piglet Hardware

| Board | Notes |
|-------|-------|
| Seeed XIAO ESP32-S3 | 2.4 GHz only |
| Seeed XIAO ESP32-C5 | 2.4 + 5 GHz |
| Seeed XIAO ESP32-C6 | 2.4 GHz only |
| LilyGo T-Dongle C5 | Standalone variant with built-in TFT |

Piglet peripherals: I2C GPS (ATGM336H), SSD1306 OLED, SPI SD card module.

### How It Connects to Ragnar

Piglet can talk to Ragnar **three ways** — all three coexist with each other and
with HuginnESP:

| Path | When to use | Live? |
|------|-------------|-------|
| **CSV import** (file upload) | After a standalone field trip where Piglet logged to its SD card | ❌ Offline |
| **Live USB serial** (mode 3) | Piglet plugged into Ragnar — streams WigleWifi-1.4 CSV rows as it scans | ✅ Yes |
| **Mesh Core via USB** (mode 5) | Piglet running in mesh `core` mode, plugged into Ragnar — relays its own scans **plus** every record received from mesh nodes | ✅ Yes |

#### Live USB serial (mode 3)

A regular Piglet that's tethered to Ragnar via USB just emits its normal WiGLE
CSV output over the serial port — first a `WigleWifi-1.4,…` banner, then the
column header row, then one CSV row per AP. Ragnar reads the header to build a
column-name → index map (so format bumps like 1.4 → 1.6 don't break anything)
and inserts each row live into the session DB with `interface='esp32-serial'`.

Detection signal: the boot banner contains `Piglet`, `[CORE]`, or `WigleWifi-`.
Once identified, no commands are sent — the parser just listens. The status bar
chip reads **Piglet · /dev/ttyACM0**.

#### CSV import (offline)

Same end result, file-based:

1. Take Piglet out wardriving — it logs WiFi networks + GPS to SD card
2. When home, download the CSV files via Piglet's web UI (connects to your WiFi) or remove the SD card
3. Upload the CSV file(s) to Ragnar via **Import CSV** in the wardriving section (`POST /api/wardriving/import`)
4. Ragnar imports all networks with GPS coordinates into the active session
5. View the imported data on the map and in the network table

### What Gets Imported

| Piglet CSV Column | Ragnar Mapping | Status |
|-------------------|----------------|--------|
| MAC | `bssid` | ✅ |
| SSID | `ssid` | ✅ |
| AuthMode | `security` | ✅ |
| Channel | `channel` + `frequency` | ✅ |
| RSSI | `rssi` | ✅ |
| CurrentLatitude | `lat` | ✅ |
| CurrentLongitude | `lon` | ✅ |
| AltitudeMeters | `alt` | ✅ |
| Type | WiFi / BT routing | ✅ |

The importer handles Piglet's `WigleWifi-1.4` metadata header line automatically.

### Companion comparison

| Feature | HuginnESP (mode 2) | Piglet — live USB (mode 3) | Piglet Coordinator (mode 4) | Piglet Core via USB (mode 5) |
|---------|-------------------|----------------------------|-----------------------------|------------------------------|
| Hardware | ESP32-S3-Touch-LCD-4B | Any Piglet board | Waveshare C5 or S3-LCD | Any Piglet board |
| Firmware | HuginnESP | Piglet (stock) | `espnow_bridge_*` (this repo) | Piglet, `meshModeOnBoot=core` |
| Connection | USB serial (live) | USB serial (live) | USB serial (live) | USB serial (live) |
| Companion name in UI | `Huginn` | `Piglet` | `Piglet Coordinator` | `Piglet` |
| Local WiFi scan | ✅ Active per-channel | ✅ | ❌ (no radio scan) | ✅ |
| BLE / threats | ✅ Full suite | ❌ | ❌ | ❌ |
| ESP-Now mesh aggregation | ❌ | ❌ | ✅ Receives from N nodes | ✅ Receives from N nodes |
| Built-in GPS | ❌ (uses Ragnar's) | ✅ Own GPS | ❌ (uses Ragnar's) | ✅ Own GPS |
| SD-card logging | ❌ | ✅ | ❌ | ✅ |
| Wire protocol | JSON + multi-line | WigleWifi-1.4 CSV stream | One-line-per-record JSON | WigleWifi-1.4 CSV stream |
| Display | 480×480 RGB touch | 128×64 OLED | none / 480×480 (S3-LCD) | 128×64 OLED |

All four companions can be used together with the **standalone wardriver** mode
(mode 1, Ragnar's own Wi-Fi adapters) — they're additive, not exclusive. The
only constraint is that there's just one serial port at a time, so only one
companion can be wired up per Ragnar.

---

## Piglet ESP-Now Mesh Network

Piglet supports ESP-Now mesh networking for multi-node wardriving. One device
acts as the **coordinator** while one or more Piglets act as **Nodes**,
forwarding their WiFi scan results over ESP-Now on channel 6.

You can run the coordinator role two ways, and Ragnar treats them as separate
operating modes:

- **Piglet Core (mode 5)** — a regular Piglet board flipped into mesh `core`
  mode via `meshModeOnBoot=core`. Same hardware as a node, just promoted. It
  scans WiFi *and* aggregates the mesh, and can either log everything to its
  own SD card or stream live to Ragnar over USB.
- **Piglet Coordinator (mode 4)** — the dedicated `espnow_bridge_*` firmware
  in this repo, flashed onto a Waveshare ESP32-C5 or ESP32-S3-Touch-LCD-4B.
  Purpose-built for the coordinator role — it doesn't scan WiFi itself, just
  receives mesh records and forwards them to Ragnar live as JSON.

Both expose the same end result (mesh-wide records hitting Ragnar's session
DB) with different ergonomics — pick by hardware availability.

### Architecture

```
                  ESP-Now (ch 6)
┌────────────┐   ─────────────►   ┌────────────────┐
│ Piglet     │                    │ Piglet Core     │
│ Node #1    │                    │ (coordinator)   │
│ ESP32-C5   │                    │ ESP32 + GPS     │       USB
│ No GPS/SD  │                    │ + SD card       │ ────────────────► Ragnar
└────────────┘                    │                 │     CSV import
                  ESP-Now (ch 6)  │ Logs ALL nodes  │
┌────────────┐   ─────────────►   │ to WiGLE CSV    │
│ Piglet     │                    └────────────────┘
│ Node #2    │
│ ESP32-S3   │
│ No GPS/SD  │
└────────────┘
```

### Setup

#### 1. Core (Coordinator) Piglet

The Core needs GPS + SD card. Set `meshModeOnBoot` in `/wardriver.cfg`:

```
meshModeOnBoot=core
```

Or navigate to the Mesh Node page on the Core and it enters Core mode automatically.

When set to `core`, the SoftAP window is skipped on boot — ESP-Now owns the WiFi stack. The Core receives scan results from all connected Nodes and logs them to SD card with GPS coordinates.

#### 2. Node Piglets

Nodes are lightweight — no SD card or GPS required. Set:

```
meshModeOnBoot=node
```

Or press the button to cycle to the Mesh Node page (page 5, after the pig animation).

Each Node:
- Automatically searches for a Core on ESP-Now channel 6
- Receives a channel range assignment from the Core
- Begins scanning WiFi and forwarding results to the Core
- OLED shows link status, coordinator MAC, assigned channels, and records forwarded

#### 3. Import to Ragnar

After the wardriving session:

1. Power down the Nodes (or exit Mesh mode with a button press)
2. On the Core Piglet, connect to its WiFi AP or your home network
3. Download the CSV files from the Core's web UI — they contain data from **all nodes**, GPS-stamped by the Core
4. Upload to Ragnar via **Import CSV** (`POST /api/wardriving/import`)
5. All networks appear on the map with GPS coordinates

### Node Display

While in Mesh Node mode the OLED shows:

| Field | Description |
|-------|-------------|
| Link status | `Searching` or `Core linked` |
| Coordinator MAC | MAC address of the Core |
| Channel range | Assigned WiFi channels to scan |
| Networks found | Total unique networks discovered |
| Records forwarded | Records sent to the Core |

### Compatible Hardware

| Role | Recommended Board | Notes |
|------|-------------------|-------|
| Core (mode 5) | XIAO ESP32-C5 | 2.4 + 5 GHz, needs GPS + SD |
| Core (mode 5) | XIAO ESP32-S3 | 2.4 GHz only, needs GPS + SD |
| Coordinator (mode 4) | Waveshare ESP32-C5-WIFI6-KIT | Headless, uses Ragnar's GPS — no SD card needed |
| Coordinator (mode 4) | Waveshare ESP32-S3-Touch-LCD-4B | 480×480 display showing live mesh stats |
| Node | Any supported XIAO | No GPS or SD required |
| Node | LilyGo T-Dongle C5 | Compact node with built-in TFT |

---

### Piglet Coordinator firmware (mode 4) — dedicated coordinator

The `espnow_bridge_firmware/` directory ships two builds of a purpose-built
coordinator firmware (one for ESP32-C5, one for ESP32-S3-Touch-LCD-4B). It
replaces Piglet's Core role with a thinner, USB-tethered bridge:

- No local WiFi scan, no SD card, no GPS dependency on the ESP — Ragnar
  handles all of that.
- Receives `MSG_NODE_REPORT` frames from every paired Piglet on ESP-Now
  channel 6, distributes the 40-entry scan-channel table evenly across the
  nodes, and forwards each record to Ragnar over USB CDC at 460800 baud.
- Announces itself on boot with
  `{"device":"RagnarCoord","fw":"<build>","board":"<board>","caps":["espnow","piglet-core"]}`
  so Ragnar can flip the companion identity to `Piglet Coordinator` and adjust
  the UI accordingly.
- Emits one `{"type":"WIFI",...}` JSON line per record and one
  `{"type":"NODE",...}` row per active mesh node every ~10 s (used by Ragnar
  to render the per-node breakdown bar with each node's MAC, records-rx, and
  age-since-last-update).
- The S3-LCD build also draws live mesh stats on its 480×480 panel.

#### Flashing

Browser-flash either board at
[pierregode.github.io/Ragnar/](https://pierregode.github.io/Ragnar/) — pick the
matching board, plug it into Ragnar over USB-C, click Forge. The GitHub Actions
workflow rebuilds both binaries on every `main` push and redeploys the pages
site.

#### Status integration

When a Piglet Coordinator is connected, the `/api/wardriving/status` payload
includes:

```json
"companion_name": "Piglet Coordinator",
"coordinator_board": "ESP32-C5",
"coordinator_fw": "c5-1",
"mesh_node_count": 1,
"coordinator_nodes": [
  {"mac": "AA:BB:CC:DD:EE:FF", "idx": 0, "records_rx": 4637, "age_s": 3}
]
```

The wardriving card shows:

```
Piglet Coordinator · /dev/ttyACM0 · Records: 4637 | WiFi: 70 · Unique: 8 | Mesh: 1 nodes
```

where **Records** is total mesh records relayed (sum of every node's
`records_rx`), **WiFi** is the count of distinct BSSIDs the mesh side has
ever observed (`serial_seen_unique`), **Unique** is BSSIDs only the mesh
saw — never picked up by Ragnar's local wlan adapters (`serial_unique`), and
**Mesh** is the live node count.

### Tips

- **Channel coverage**: The Core assigns different channel ranges to each Node, so more Nodes = better frequency coverage
- **Range**: ESP-Now has ~200m line-of-sight range; nodes can be spread across a building or vehicle convoy
- **Battery**: Nodes without GPS/SD draw less power — ideal for small LiPo-powered Piglet builds (~$14 BOM)
- **5 GHz**: Use ESP32-C5 boards for 5 GHz scanning capability
- **Exit mesh**: Press the button on a Node to leave mesh mode and return to normal standalone wardriving
