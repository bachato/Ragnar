# 🛡️ WiFi Defense — 802.11 Frame Monitor / WIDS

A passive **wireless intrusion-detection system** built into Ragnar's web UI —
its own top-level **WiFi Defense** tab (next to *Network*). It listens on a
**monitor-mode** adapter for 802.11 management frames and flags the classic
Wi-Fi attacks a defender cares about.

> **Receive-only.** WiFi Defense never transmits a frame — it does not deauth
> attackers back, inject, or probe. It is a detection tool (a WIDS), not an
> attack tool. It complements the passive **[WiFi Analyzer](wifi-analyzer.md)**
> (which surveys the spectrum); this tab watches for *attacks*.

---

## What it detects

| Attack | What it is | How it's flagged |
|--------|-----------|------------------|
| **Deauth / disassoc flood** | The 802.11 deauthentication DoS (`aireplay-ng`, `mdk4`): spoofed deauth/disassoc frames kick clients off an AP. | A burst of deauth/disassoc management frames; ≥ 15 in a window is called a **flood**. The attacker (transmitter) and target are listed. |
| **Beacon flood** | A storm of fake APs (`mdk3`/`mdk4` beacon mode, ESP32 spammers) — bogus SSIDs to drown the air or bait clients. | Distinct beaconed **SSIDs** ≥ a **user-tunable threshold** (default 100) in one capture, or BSSIDs ≥ 150. A real flood produces hundreds; the threshold is calibrated to your local RF density (there is no passive "shape" signal that separates a flood from a crowded block — randomized MACs are also used by ordinary multi-SSID/guest routers). The capture's live SSID/BSSID counts are shown next to the threshold so you can set it just above your normal density. |
| **Rogue AP / evil twin** | A look-alike AP advertising a **known** SSID from a BSSID that isn't yours, set up to harvest clients. | An SSID in the **trusted baseline** appearing from an untrusted BSSID → *evil twin*; or one SSID from ≥ 2 BSSIDs → *duplicate SSID* (set a baseline to confirm). |
| **KARMA / MANA** | An AP that answers probe requests for **many different SSIDs** — it pretends to be every network a client has ever joined. | A single BSSID that beacons/probe-responds for ≥ 5 distinct SSIDs. |

A big banner summarises the capture: **CLEAR**, **WARNING**, or **⚠ UNDER
ATTACK** (critical). Below it, one card per detection with the offending
BSSIDs/attackers, then frame counts and an inventory of every AP heard.

---

## Monitor mode (how it's set up)

WiFi Defense needs an adapter in **monitor mode**, configured with plain `iw`
(no `aircrack-ng` required):

- Where the driver allows it (e.g. the **Alfa AWUS036AXM** / `mt7921u`), a
  **separate monitor vif** (`ragmon0`) is added so the box **keeps its normal
  Wi-Fi link** while it sniffs.
- Otherwise the adapter itself is switched into monitor mode — which takes it
  **off your network** until you disable monitor mode (the UI warns you).

The Pi's **onboard `brcmfmac` radio does not support monitor mode** at all, so
you need a capable USB adapter. **Enable monitor** sets it up; **Disable
monitor** restores the interface.

**Channel:** a monitor radio only hears one channel at a time. Leave the channel
box on **`hop`** to cycle the common 2.4/5 GHz channels during the capture
(catches attacks on any channel), or pin a specific channel number to dwell on
it (best when you already know where the attack is).

---

## Using it

1. Plug in a monitor-capable adapter and pick it in **Monitor adapter**.
2. **Enable monitor** (adds `ragmon0`, or switches the adapter).
3. **Trust current APs** in a known-good environment — this **adds** the
   currently-shown APs to the SSID→BSSID baseline that powers **evil-twin**
   detection. It *accumulates* (union), so run it a few times / across a scan or
   two: a single capture window can't hear every BSSID of every SSID (dual-band
   radios, mesh nodes and band-steering publish one SSID from several BSSIDs),
   and any legit BSSID not yet trusted would otherwise be flagged as an evil
   twin. **Reset baseline** clears it to start over.
4. **Scan** for a capture window (default 15 s), or tick **Continuous** to
   re-scan on a loop as a live monitor — each capture starts only after the
   previous one finishes (no overlap). Hit **■ Stop** to end the loop.

---

## API & CLI

Detection-only; the only state written is the trusted-AP baseline.

| Endpoint | Purpose |
|----------|---------|
| `GET /api/wifidef/interfaces` | wireless adapters + monitor capability + current monitor state |
| `POST /api/wifidef/monitor` | `{action: enable|disable, interface}` — set up / tear down monitor mode |
| `GET /api/wifidef/scan?interface=&seconds=&channel=` | capture window + WIDS analysis |
| `GET/POST /api/wifidef/baseline` | get / add-to (`{aps}` or capture) / `{action:clear}` the trusted SSID→BSSID baseline |
| `GET/POST /api/wifidef/thresholds` | get / set the beacon-flood thresholds (`{beacon_ssids, beacon_bssids}`) |
| `GET /api/wifidef/airtime?interface=&seconds=&channel=` | passive airtime / retry / PHY-rate / roaming diagnostics |
| `GET /api/wifidef/selftest` | parser + detector self-test |

## Airtime & link quality

A separate passive diagnostic (the "why is it slow" view). Capture all 802.11
frames — ideally on a **fixed channel** (airtime % is only meaningful when not
hopping) — and get, per AP: **airtime %** (estimated on-air time / capture time),
**retry rate** (retransmit flag), the **PHY-rate spread** (min/median/max Mbps),
plus **roaming churn** (clients re-associating/authing repeatedly). Findings flag
high retry (≥30%), airtime hogs (≥50%) and unstable roaming. Route
`GET /api/wifidef/airtime`; analysis is a pure function covered by selftest.

```bash
python3 wifi_defense.py interfaces
python3 wifi_defense.py monitor --interface wlan1 --enable
python3 wifi_defense.py scan --interface wlan1 --seconds 15         # or --channel 6
python3 wifi_defense.py baseline --interface wlan1 --seconds 20     # learn trusted APs
python3 wifi_defense.py monitor --interface wlan1 --disable
python3 wifi_defense.py selftest
```

The self-test crafts real 802.11 frames with **Scapy** (deauth flood, 35-SSID
beacon flood, a 6-SSID KARMA AP, an evil twin), writes them to a pcap, then runs
the full parse → analyse pipeline and asserts each detection fires (and that
clean traffic stays **CLEAR**) — 11 checks, all offline.

Requires `iw` and **Scapy** (both installed by `install_ragnar.sh` /
`requirements.txt`).
