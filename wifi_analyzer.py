#!/usr/bin/env python3
"""
wifi_analyzer.py — Passive tri-band Wi-Fi spectrum analyzer & troubleshooter.

A software "Ekahau Sidekick"-style RF troubleshooter for Ragnar. Everything here
is *strictly passive*: we only ever run ``iw dev <iface> scan passive`` which
listens for beacons and never transmits a probe request to any AP, and we read
the radio's channel table with ``iw phy``. No frame is ever injected.

Capabilities
------------
* Tri-band survey (2.4 / 5 / 6 GHz) of every beaconing BSS: SSID, BSSID, RSSI
  (dBm), primary channel + band, channel width (20/40/80/160 MHz from the
  HT/VHT/HE operation IEs), security, and the AP-advertised **channel
  utilisation** (BSS-Load IE) which is a real, passive interference metric.
* Spectrum / congestion analysis: co-channel and adjacent-channel (overlap)
  interference, the classic 2.4 GHz 1/6/11 crowding picture, and a per-channel
  congestion score with "least congested channel" recommendations.
* DFS / radar awareness: the set of radar/DFS channels is read *live* from the
  radio's own channel table (``iw phy <phy> channels``) rather than hardcoded,
  and any BSS parked on a radar channel is flagged.
* Signal-radius estimate for a chosen AP using a log-distance path-loss model,
  producing coverage-ring radii (VoIP / data / edge thresholds) plus an estimate
  of your current distance from the AP — the data the web UI draws as rings.
* Heatmap sample store: drop (x, y, rssi) samples on a floorplan; the web layer
  interpolates (IDW) them into a coverage heatmap.

Tuned for the Alfa AWUS036AXM (MediaTek MT7921AU, ``mt7921u`` driver — a Wi-Fi
6E 2.4/5/6 GHz dongle) on a Raspberry Pi Zero 2 W, but band support is detected
per-radio from ``iw phy`` so it also runs on the Pi's onboard brcmfmac radio.

CLI
---
    python3 wifi_analyzer.py interfaces
    python3 wifi_analyzer.py scan [--interface wlan0] [--band 2.4|5|6|all]
    python3 wifi_analyzer.py radius --interface wlan0 --bssid <mac>
    python3 wifi_analyzer.py selftest
"""

import json
import math
import os
import re
import subprocess
import sys
import time

# --------------------------------------------------------------------------
# Constants / tunables
# --------------------------------------------------------------------------

_IW = "/usr/sbin/iw"
if not os.path.exists(_IW):
    _IW = "iw"  # fall back to PATH

_SCAN_TIMEOUT = 20          # seconds; a passive scan of all channels is slow
_HEATMAP_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "data", "wifi_heatmap.json"
)

# Coverage thresholds (dBm) used for the signal-radius rings.
_RADIUS_THRESHOLDS = [
    ("voice", -67, "VoIP / seamless roaming"),
    ("data", -72, "reliable data / video"),
    ("edge", -80, "usable edge of coverage"),
]

# Default path-loss model parameters (overridable per request).
_DEFAULT_TX_DBM = 20.0      # assumed AP EIRP; consumer APs are ~17-23 dBm
_DEFAULT_PLE = 3.0          # path-loss exponent: 2.0 free space, ~3.0 indoor

# 2.4 GHz channels overlap unless spaced >= 5 apart (1/6/11 are the non-overlap set).
_NON_OVERLAP_24 = [1, 6, 11]


# --------------------------------------------------------------------------
# iw plumbing
# --------------------------------------------------------------------------

def _run(args, timeout=_SCAN_TIMEOUT):
    """Run an iw command, returning (rc, stdout, stderr). Never raises."""
    try:
        p = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, check=False
        )
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "iw not found"
    except subprocess.TimeoutExpired:
        return 124, "", "iw timed out"
    except Exception as exc:  # pragma: no cover - defensive
        return 1, "", str(exc)


def _valid_iface(iface):
    return bool(iface) and re.match(r"^[A-Za-z0-9_.-]{1,32}$", iface) is not None


def _valid_bssid(mac):
    return bool(mac) and re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", mac or "") is not None


def _iface_is_up(iface):
    """True if the interface's admin state is up (has IFF_UP flag)."""
    try:
        with open("/sys/class/net/%s/flags" % iface) as f:
            return bool(int(f.read().strip(), 16) & 0x1)  # IFF_UP
    except Exception:
        return True  # assume up if we can't tell; don't block on it


def _bring_iface_up(iface):
    """Bring the link up (needed to scan a freshly-plugged, DOWN dongle).

    Non-destructive: only sets the link admin-up, never associates. Requires
    root; the webapp runs as root so this succeeds in production.
    """
    _run(["/usr/bin/rfkill", "unblock", "all"], timeout=5)
    rc, _, _ = _run(["ip", "link", "set", iface, "up"], timeout=5)
    return rc == 0


# --------------------------------------------------------------------------
# Frequency <-> channel <-> band
# --------------------------------------------------------------------------

def freq_to_channel(freq_mhz):
    """Return (band, channel) for a centre frequency in MHz. band in {'2.4','5','6'}."""
    f = int(round(float(freq_mhz)))
    if f == 2484:
        return "2.4", 14
    if 2400 <= f < 2500:
        return "2.4", (f - 2407) // 5
    if f == 5935:
        return "6", 2
    if f >= 5925:
        return "6", (f - 5950) // 5
    if 5000 <= f < 5925:
        return "5", (f - 5000) // 5
    # Below 5 GHz but not 2.4 (shouldn't happen for Wi-Fi) -> best effort
    return "5", (f - 5000) // 5


def channel_to_freq(channel, band):
    """Inverse of freq_to_channel for a primary/centre channel number."""
    ch = int(channel)
    if band == "2.4":
        return 2484 if ch == 14 else 2407 + ch * 5
    if band == "6":
        return 5935 if ch == 2 else 5950 + ch * 5
    return 5000 + ch * 5


# --------------------------------------------------------------------------
# Radio capability / DFS map  (iw phy <phy> channels)
# --------------------------------------------------------------------------

def _phy_for_iface(iface):
    rc, out, _ = _run([_IW, "dev"], timeout=5)
    if rc != 0:
        return None
    cur_phy = None
    for line in out.splitlines():
        m = re.match(r"^(phy#\d+)", line)
        if m:
            cur_phy = m.group(1).replace("#", "")
            continue
        m = re.match(r"^\s*Interface\s+(\S+)", line)
        if m and m.group(1) == iface:
            return cur_phy
    return None


def radio_capabilities(iface):
    """Parse ``iw phy <phy> channels`` into supported bands + DFS/radar channel set.

    Returns dict: {phy, bands: {'2.4':[chans], '5':[...], '6':[...]},
                   radar_channels: {band: set(ch)}, disabled: {band: set(ch)}}.
    """
    phy = _phy_for_iface(iface)
    caps = {
        "phy": phy,
        "bands": {"2.4": [], "5": [], "6": []},
        "radar_channels": {"2.4": set(), "5": set(), "6": set()},
        "disabled": {"2.4": set(), "5": set(), "6": set()},
    }
    if not phy:
        return caps
    rc, out, _ = _run([_IW, "phy", phy, "channels"], timeout=8)
    if rc != 0:
        return caps
    cur = None  # (band, ch, disabled)
    for raw in out.splitlines():
        m = re.search(r"\*\s*(\d+)\s*MHz\s*\[(\d+)\]\s*(\(disabled\))?", raw)
        if m:
            if cur:
                _commit_channel(caps, cur)
            band, ch = freq_to_channel(int(m.group(1)))
            cur = {"band": band, "ch": ch, "disabled": bool(m.group(3)), "radar": False}
            continue
        if cur and re.search(r"[Rr]adar detection", raw):
            cur["radar"] = True
    if cur:
        _commit_channel(caps, cur)
    for b in caps["bands"]:
        caps["bands"][b] = sorted(set(caps["bands"][b]))
    # Band *support* is more reliably read from `iw phy info`, which lists every
    # frequency the radio can do regardless of whether the interface is up or a
    # channel is regulatory-disabled. This keeps the band labels correct for a
    # freshly-plugged, still-down dongle (channels would otherwise be empty).
    rc2, info, _ = _run([_IW, "phy", phy, "info"], timeout=8)
    if rc2 == 0:
        for m in re.finditer(r"\*\s*(\d+)(?:\.\d+)?\s*MHz\s*\[(\d+)\]", info):
            band, ch = freq_to_channel(int(m.group(1)))
            if band in caps["bands"] and ch not in caps["bands"][band]:
                caps["bands"][band].append(ch)
        for b in caps["bands"]:
            caps["bands"][b] = sorted(set(caps["bands"][b]))
    return caps


def _commit_channel(caps, cur):
    band, ch = cur["band"], cur["ch"]
    if band not in caps["bands"]:
        return
    if not cur["disabled"]:
        caps["bands"][band].append(ch)
    else:
        caps["disabled"][band].add(ch)
    if cur["radar"]:
        caps["radar_channels"][band].add(ch)


def _sysfs_wifi_interfaces():
    """Every wireless netdev in /sys/class/net (nl80211 *and* wext dongles)."""
    names = set()
    try:
        for name in os.listdir("/sys/class/net/"):
            base = "/sys/class/net/" + name
            if os.path.exists(base + "/wireless") or os.path.exists(base + "/phy80211"):
                names.add(name)
    except Exception:
        pass
    return names


def list_wifi_interfaces():
    """Return [{iface, phy, type, bands:[...]}] for every wireless interface.

    Interfaces are enumerated from BOTH ``iw dev`` (nl80211) and
    ``/sys/class/net`` so a dongle still shows up if it reports an unusual
    interface type or uses a wext-only driver that ``iw dev`` doesn't list.
    We deliberately do NOT filter by interface type — the only entries ``iw
    dev`` omits from a name are the "Unnamed/non-netdev" P2P-device stanzas,
    which never carry an ``Interface <name>`` line in the first place.
    """
    by_name = {}
    order = []
    rc, out, _ = _run([_IW, "dev"], timeout=5)
    if rc == 0:
        cur_phy = None
        cur = None
        for line in out.splitlines():
            m = re.match(r"^(phy#\d+)", line)
            if m:
                cur_phy = m.group(1).replace("#", "")
                continue
            m = re.match(r"^\s*Interface\s+(\S+)", line)
            if m:
                cur = {"iface": m.group(1), "phy": cur_phy, "type": None, "bands": []}
                by_name[cur["iface"]] = cur
                order.append(cur["iface"])
                continue
            if cur:
                mt = re.match(r"^\s*type\s+(\S+)", line)
                if mt:
                    cur["type"] = mt.group(1)
    # Union with sysfs so wext-only / oddly-typed dongles are never hidden.
    for name in sorted(_sysfs_wifi_interfaces()):
        if name not in by_name:
            entry = {"iface": name, "phy": _phy_for_iface(name), "type": None, "bands": []}
            by_name[name] = entry
            order.append(name)
    ifaces = [by_name[n] for n in order]
    for i in ifaces:
        caps = radio_capabilities(i["iface"])
        i["bands"] = [b for b in ("2.4", "5", "6") if caps["bands"].get(b)]
    return ifaces


# --------------------------------------------------------------------------
# Channel-width extraction from an iw scan BSS block
# --------------------------------------------------------------------------

def _parse_width(block):
    """Return (width_mhz, center_channel_or_None) from HT/VHT/HE operation lines."""
    width = 20
    center_ch = None

    # VHT operation: 'channel width: N (X MHz)' + 'center freq segment 1: C'
    mv = re.search(r"VHT operation:.*?channel width:\s*(\d+)", block, re.S)
    if mv:
        code = int(mv.group(1))
        if code == 1:
            width = max(width, 80)
        elif code in (2, 3):
            width = max(width, 160)
        mc = re.search(r"center freq segment 1:\s*(\d+)", block)
        if mc and int(mc.group(1)) > 0:
            center_ch = int(mc.group(1))

    # HE operation (802.11ax / 6 GHz): look for an explicit MHz width token
    if re.search(r"HE operation", block):
        for w in (320, 160, 80, 40):
            if re.search(r"HE operation.*?(\b%d MHz\b|channel width:\s*%d)" % (w, w),
                         block, re.S):
                width = max(width, w)
                break
        mhe = re.search(r"HE operation.*?(?:center freq|centre freq|channel center).*?(\d+)",
                        block, re.S)
        if mhe and center_ch is None and int(mhe.group(1)) > 0:
            center_ch = int(mhe.group(1))

    # HT operation: secondary channel offset above/below => 40 MHz
    mh = re.search(r"secondary channel offset:\s*(above|below)", block)
    if mh and width < 40:
        width = 40

    # Textual widths anywhere ('(160 MHz)', '(80 MHz)', '(40 MHz)')
    for w in (320, 160, 80, 40):
        if re.search(r"\(%d MHz\)" % w, block):
            width = max(width, w)
            break
    return width, center_ch


# --------------------------------------------------------------------------
# iw scan parser
# --------------------------------------------------------------------------

_BSS_HDR = re.compile(r"^BSS\s+([0-9a-fA-F:]{17})\b(.*)$")


def parse_scan(text):
    """Parse ``iw scan`` output into a list of BSS dicts.

    Pure function (no I/O) so it is unit-testable against captured output.
    """
    blocks = []
    cur = None
    for line in text.splitlines():
        m = _BSS_HDR.match(line)
        if m:
            if cur is not None:
                blocks.append(cur)
            cur = {"bssid": m.group(1).lower(), "_hdr": m.group(2), "_lines": []}
            continue
        if cur is not None:
            cur["_lines"].append(line)
    if cur is not None:
        blocks.append(cur)

    results = []
    for b in blocks:
        block = "\n".join(b["_lines"])
        bss = {"bssid": b["bssid"]}

        m = re.search(r"^\s*freq:\s*([\d.]+)", block, re.M)
        if not m:
            continue
        freq = float(m.group(1))
        band, channel = freq_to_channel(freq)
        bss["freq"] = freq
        bss["band"] = band
        bss["channel"] = channel

        m = re.search(r"^\s*signal:\s*(-?[\d.]+)\s*dBm", block, re.M)
        bss["signal"] = round(float(m.group(1)), 1) if m else None

        m = re.search(r"^[ \t]*SSID:[ \t]*(.*)$", block, re.M)
        ssid = m.group(1) if m else ""
        # Strip nul-padded / whitespace SSIDs; hidden APs advertise empty/\x00
        ssid = ssid.replace("\\x00", "").strip()
        bss["ssid"] = ssid
        bss["hidden"] = ssid == ""

        width, center_ch = _parse_width(block)
        bss["width"] = width
        if center_ch:
            bss["center_freq"] = channel_to_freq(center_ch, band)
        else:
            bss["center_freq"] = freq

        # BSS-Load IE: the AP's own advertised medium utilisation + client count.
        m = re.search(r"channel util[il]s?ation:\s*(\d+)/255", block)
        bss["channel_util"] = round(int(m.group(1)) / 255.0 * 100.0, 1) if m else None
        m = re.search(r"station count:\s*(\d+)", block)
        bss["stations"] = int(m.group(1)) if m else None

        # Security summary
        has_rsn = "RSN:" in block
        has_wpa = "WPA:" in block
        privacy = "Privacy" in (b["_hdr"] or "")
        if re.search(r"Authentication suites:.*SAE", block):
            sec = "WPA3"
        elif has_rsn:
            sec = "WPA2"
        elif has_wpa:
            sec = "WPA"
        elif privacy:
            sec = "WEP"
        else:
            sec = "Open"
        bss["security"] = sec

        m = re.search(r"last seen:\s*(\d+)\s*ms ago", block)
        bss["last_seen_ms"] = int(m.group(1)) if m else None

        results.append(bss)
    return results


# --------------------------------------------------------------------------
# Spectrum / interference analysis
# --------------------------------------------------------------------------

def _channels_covered(channel, width, band, center_freq=None):
    """Set of 20 MHz channel indices a BSS occupies given its width.

    For 5/6 GHz the occupied 20 MHz sub-channels are centred on the operating
    *centre* frequency (the primary channel is only one edge of a wide channel),
    so we walk 20 MHz steps across [centre - width/2, centre + width/2].
    """
    if band == "2.4":
        # 2.4 GHz channels overlap; model +/- (width/2) MHz spread in freq.
        span = width // 2
        prim = channel_to_freq(channel, band)
        chans = set()
        for f in range(int(prim - span), int(prim + span) + 1, 5):
            _, c = freq_to_channel(f)
            if 1 <= c <= 14:
                chans.add(c)
        return chans
    n = max(1, width // 20)
    c = center_freq if center_freq else channel_to_freq(channel, band)
    first = c - (width / 2.0) + 10  # centre of the lowest 20 MHz sub-channel
    chans = set()
    for i in range(n):
        _, ch = freq_to_channel(first + i * 20)
        chans.add(ch)
    return chans


def analyze_spectrum(bss_list, caps=None):
    """Build per-band congestion picture + channel recommendations."""
    caps = caps or {"radar_channels": {"2.4": set(), "5": set(), "6": set()}}
    radar = caps.get("radar_channels", {})
    out = {}
    for band in ("2.4", "5", "6"):
        aps = [b for b in bss_list if b["band"] == band]
        if not aps:
            continue
        # occupancy[ch] = list of (rssi, is_primary)
        occupancy = {}
        for ap in aps:
            covered = _channels_covered(ap["channel"], ap["width"], band,
                                        ap.get("center_freq"))
            for ch in covered:
                occupancy.setdefault(ch, []).append(
                    (ap.get("signal"), ch == ap["channel"], ap.get("channel_util"))
                )
        channels = []
        for ch in sorted(occupancy):
            entries = occupancy[ch]
            signals = [s for s, _p, _u in entries if s is not None]
            utils = [u for _s, _p, u in entries if u is not None]
            primaries = sum(1 for _s, p, _u in entries if p)
            # Congestion score: co-channel APs weighted by relative power +
            # advertised utilisation. Higher = worse.
            score = 0.0
            for s, is_primary, _u in entries:
                w = 1.0 if is_primary else 0.5  # overlap counts half of co-channel
                # louder neighbours hurt more; map -30..-90 dBm -> 1.0..0.1
                if s is not None:
                    w *= max(0.1, min(1.0, (s + 95) / 65.0))
                score += w
            if utils:
                score += (sum(utils) / len(utils)) / 100.0 * 2.0
            channels.append({
                "channel": ch,
                "ap_count": len(entries),
                "primary_count": primaries,
                "max_signal": max(signals) if signals else None,
                "avg_util": round(sum(utils) / len(utils), 1) if utils else None,
                "score": round(score, 2),
                "radar": ch in radar.get(band, set()),
            })
        # Recommendations: least-congested channels (for 2.4, restrict to 1/6/11)
        candidates = channels
        if band == "2.4":
            cand = [c for c in channels if c["channel"] in _NON_OVERLAP_24]
            # include unused 1/6/11 as zero-score candidates
            seen = {c["channel"] for c in cand}
            for ch in _NON_OVERLAP_24:
                if ch not in seen:
                    cand.append({"channel": ch, "ap_count": 0, "score": 0.0,
                                 "radar": False, "max_signal": None,
                                 "avg_util": None, "primary_count": 0})
            candidates = cand
        recommend = sorted(candidates, key=lambda c: (c["score"], c["ap_count"]))[:3]
        # Overall band rating
        prim_aps = len(aps)
        total_score = sum(c["score"] for c in channels)
        if total_score < 3:
            rating = "clear"
        elif total_score < 8:
            rating = "moderate"
        else:
            rating = "congested"
        out[band] = {
            "ap_count": prim_aps,
            "channels": channels,
            "recommend": [c["channel"] for c in recommend],
            "rating": rating,
            "score": round(total_score, 2),
        }
    return out


def find_interference(bss_list):
    """Return co-channel and adjacent-channel (overlap) interference groups."""
    co = {}
    for ap in bss_list:
        key = (ap["band"], ap["channel"])
        co.setdefault(key, []).append(ap)
    co_channel = []
    for (band, ch), aps in co.items():
        if len(aps) >= 2:
            co_channel.append({
                "band": band, "channel": ch,
                "ssids": sorted({a["ssid"] or "<hidden>" for a in aps}),
                "count": len(aps),
            })
    # Adjacent/overlap (mainly a 2.4 GHz problem)
    overlap = []
    aps24 = [a for a in bss_list if a["band"] == "2.4"]
    for i, a in enumerate(aps24):
        acov = _channels_covered(a["channel"], a["width"], "2.4", a.get("center_freq"))
        for b in aps24[i + 1:]:
            if a["channel"] == b["channel"]:
                continue
            bcov = _channels_covered(b["channel"], b["width"], "2.4", b.get("center_freq"))
            if acov & bcov:
                overlap.append({
                    "band": "2.4",
                    "a": {"ssid": a["ssid"] or "<hidden>", "channel": a["channel"]},
                    "b": {"ssid": b["ssid"] or "<hidden>", "channel": b["channel"]},
                })
    return {"co_channel": sorted(co_channel, key=lambda x: -x["count"]),
            "adjacent_overlap": overlap}


# --------------------------------------------------------------------------
# Signal-radius estimate (log-distance path-loss model)
# --------------------------------------------------------------------------

def _rssi_at_1m(freq_mhz, tx_dbm):
    """Reference RSSI at 1 m = TxPower - free-space path loss at 1 m."""
    fspl_1m = 20 * math.log10(freq_mhz) - 27.55  # d=1m => 20log10(1)=0
    return tx_dbm - fspl_1m


def estimate_radius(bss, tx_dbm=_DEFAULT_TX_DBM, ple=_DEFAULT_PLE):
    """Coverage rings + your current distance for one BSS (from its measured RSSI)."""
    freq = bss.get("center_freq") or bss.get("freq")
    rssi0 = _rssi_at_1m(freq, tx_dbm)

    def dist_for(rssi):
        # rssi = rssi0 - 10*n*log10(d)  =>  d = 10^((rssi0-rssi)/(10n))
        return round(10 ** ((rssi0 - rssi) / (10.0 * ple)), 2)

    rings = [
        {"name": name, "threshold_dbm": thr, "label": label, "radius_m": dist_for(thr)}
        for name, thr, label in _RADIUS_THRESHOLDS
    ]
    cur = None
    if bss.get("signal") is not None:
        cur = dist_for(bss["signal"])
    return {
        "bssid": bss.get("bssid"),
        "ssid": bss.get("ssid"),
        "band": bss.get("band"),
        "channel": bss.get("channel"),
        "signal": bss.get("signal"),
        "assumptions": {"tx_dbm": tx_dbm, "path_loss_exponent": ple,
                        "rssi_at_1m": round(rssi0, 1)},
        "current_distance_m": cur,
        "rings": rings,
    }


# --------------------------------------------------------------------------
# Top-level scan orchestration
# --------------------------------------------------------------------------

def do_scan(interface="wlan0", band="all", passive=True):
    """Run a passive scan and return the full analysed survey."""
    if not _valid_iface(interface):
        return {"error": "invalid interface"}
    # A freshly-plugged dongle is usually admin-down; you can't scan a down
    # radio. Bring the link up first (link-up only, never associates).
    if not _iface_is_up(interface):
        _bring_iface_up(interface)
    caps = radio_capabilities(interface)
    args = [_IW, "dev", interface, "scan"]
    if passive:
        args.append("passive")
    rc, out, err = _run(args)
    if rc != 0 and re.search(r"not ready|network is down|no such device", err or "", re.I):
        # Down/asleep radio: try once more after forcing the link up.
        if _bring_iface_up(interface):
            rc, out, err = _run(args)
    if rc != 0:
        # 'Device or resource busy' / 'Operation not permitted' are common
        hint = (err or "scan failed").strip()
        low = hint.lower()
        if "busy" in low:
            hint += " — the radio is mid-scan or connecting; retry in a moment."
        elif "not permitted" in low or "operation not permitted" in low:
            hint += " — passive scan needs root (the Ragnar service runs as root)."
        elif "down" in low or "not ready" in low:
            hint += " — bring the interface up: sudo ip link set %s up" % interface
        return {"error": hint, "rc": rc,
                "interface": interface, "supported_bands": caps["bands"]}
    bss_list = parse_scan(out)
    # Flag radar/DFS occupancy
    for b in bss_list:
        b["dfs"] = b["channel"] in caps["radar_channels"].get(b["band"], set())
    if band in ("2.4", "5", "6"):
        bss_list = [b for b in bss_list if b["band"] == band]
    bss_list.sort(key=lambda b: (b["band"], b["channel"], -(b["signal"] or -999)))
    spectrum = analyze_spectrum(bss_list, caps)
    interference = find_interference(bss_list)
    return {
        "interface": interface,
        "phy": caps["phy"],
        "timestamp": int(time.time()),
        "passive": passive,
        "supported_bands": {b: bool(caps["bands"].get(b)) for b in ("2.4", "5", "6")},
        "radar_channels": {b: sorted(caps["radar_channels"].get(b, set()))
                           for b in ("2.4", "5", "6")},
        "ap_count": len(bss_list),
        "aps": bss_list,
        "spectrum": spectrum,
        "interference": interference,
    }


def do_radius(interface, bssid, tx_dbm=_DEFAULT_TX_DBM, ple=_DEFAULT_PLE):
    """Passive scan then compute the signal radius for one BSSID."""
    if not _valid_bssid(bssid):
        return {"error": "invalid bssid"}
    survey = do_scan(interface=interface, band="all")
    if "error" in survey:
        return survey
    for b in survey["aps"]:
        if b["bssid"] == bssid.lower():
            return estimate_radius(b, tx_dbm=tx_dbm, ple=ple)
    return {"error": "bssid not found in latest scan", "bssid": bssid}


# --------------------------------------------------------------------------
# Heatmap sample store (interpolation happens client-side)
# --------------------------------------------------------------------------

def _heatmap_load():
    try:
        with open(_HEATMAP_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {"floorplan": None, "target_bssid": None, "target_ssid": None,
                "samples": []}


def _heatmap_save(data):
    os.makedirs(os.path.dirname(_HEATMAP_FILE), exist_ok=True)
    tmp = _HEATMAP_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.replace(tmp, _HEATMAP_FILE)


def heatmap_get():
    return _heatmap_load()


def heatmap_set_floorplan(floorplan_data_uri, target_bssid=None, target_ssid=None):
    data = _heatmap_load()
    data["floorplan"] = floorplan_data_uri
    data["target_bssid"] = target_bssid
    data["target_ssid"] = target_ssid
    data["samples"] = []  # new floorplan => reset survey
    _heatmap_save(data)
    return data


def heatmap_add_sample(x, y, rssi, bssid=None, ssid=None):
    data = _heatmap_load()
    data["samples"].append({
        "x": float(x), "y": float(y), "rssi": float(rssi),
        "bssid": bssid, "ssid": ssid, "t": int(time.time()),
    })
    _heatmap_save(data)
    return data


def heatmap_sample_live(interface, x, y, bssid):
    """Take a live passive reading of `bssid` and record it at (x, y)."""
    survey = do_scan(interface=interface, band="all")
    if "error" in survey:
        return survey
    match = next((b for b in survey["aps"] if b["bssid"] == (bssid or "").lower()), None)
    if not match:
        return {"error": "target bssid not heard in this reading", "bssid": bssid}
    return heatmap_add_sample(x, y, match["signal"], match["bssid"], match["ssid"])


def heatmap_clear():
    data = _heatmap_load()
    data["samples"] = []
    _heatmap_save(data)
    return data


# --------------------------------------------------------------------------
# Self-test (synthetic iw output => parser + analyzer assertions)
# --------------------------------------------------------------------------

_SELFTEST_SCAN = r"""BSS aa:bb:cc:00:00:01(on wlan0) -- associated
	freq: 2412.0
	signal: -45.00 dBm
	SSID: HomeNet
	last seen: 0 ms ago
	RSN:	 * Version: 1
		 * Authentication suites: PSK
	BSS Load:
		 * station count: 4
		 * channel utilisation: 128/255
	HT operation:
		 * primary channel: 1
		 * secondary channel offset: no secondary
BSS aa:bb:cc:00:00:02(on wlan0)
	freq: 2412.0
	signal: -70.00 dBm
	SSID: Neighbour
	HT operation:
		 * primary channel: 1
		 * secondary channel offset: above
BSS aa:bb:cc:00:00:03(on wlan0)
	freq: 5260.0
	signal: -55.00 dBm
	SSID: HomeNet_5G
	RSN:	 * Version: 1
		 * Authentication suites: SAE
	HT operation:
		 * primary channel: 52
		 * secondary channel offset: above
	VHT operation:
		 * channel width: 1 (80 MHz)
		 * center freq segment 1: 58
BSS aa:bb:cc:00:00:04(on wlan0)
	freq: 5955.0
	signal: -60.00 dBm
	SSID: HomeNet_6G
	HE operation
		 * primary channel: 1
		 * channel width: 160
BSS aa:bb:cc:00:00:05(on wlan0)
	freq: 2437.0
	signal: -80.00 dBm
	SSID:
	HT operation:
		 * primary channel: 6
		 * secondary channel offset: no secondary
"""


def selftest():
    results = []

    def check(name, cond, detail=""):
        results.append({"name": name, "pass": bool(cond), "detail": detail})

    aps = parse_scan(_SELFTEST_SCAN)
    check("parses all 5 BSS", len(aps) == 5, f"got {len(aps)}")

    by_id = {a["bssid"]: a for a in aps}
    a1 = by_id.get("aa:bb:cc:00:00:01", {})
    check("2.4GHz ch1 detected", a1.get("band") == "2.4" and a1.get("channel") == 1,
          f"{a1.get('band')}/{a1.get('channel')}")
    check("RSSI parsed", a1.get("signal") == -45.0, str(a1.get("signal")))
    check("channel util % from BSS load", a1.get("channel_util") == 50.2,
          str(a1.get("channel_util")))
    check("station count parsed", a1.get("stations") == 4, str(a1.get("stations")))
    check("WPA2 (RSN/PSK) security", a1.get("security") == "WPA2", a1.get("security"))

    a3 = by_id.get("aa:bb:cc:00:00:03", {})
    check("5GHz ch52 detected", a3.get("band") == "5" and a3.get("channel") == 52,
          f"{a3.get('band')}/{a3.get('channel')}")
    check("VHT 80MHz width", a3.get("width") == 80, str(a3.get("width")))
    check("WPA3 (SAE) security", a3.get("security") == "WPA3", a3.get("security"))
    check("center freq from segment", a3.get("center_freq") == channel_to_freq(58, "5"),
          str(a3.get("center_freq")))

    a4 = by_id.get("aa:bb:cc:00:00:04", {})
    check("6GHz ch1 detected", a4.get("band") == "6" and a4.get("channel") == 1,
          f"{a4.get('band')}/{a4.get('channel')}")
    check("HE 160MHz width", a4.get("width") == 160, str(a4.get("width")))

    a5 = by_id.get("aa:bb:cc:00:00:05", {})
    check("hidden SSID flagged", a5.get("hidden") is True, str(a5.get("hidden")))

    # Width/channel conversions
    check("freq_to_channel 2484 -> ch14", freq_to_channel(2484) == ("2.4", 14))
    check("freq_to_channel 5180 -> 5/36", freq_to_channel(5180) == ("5", 36))
    check("freq_to_channel 5955 -> 6/1", freq_to_channel(5955) == ("6", 1))
    check("channel_to_freq roundtrip 5/149",
          freq_to_channel(channel_to_freq(149, "5")) == ("5", 149))

    # Spectrum analysis
    caps = {"radar_channels": {"2.4": set(), "5": {52}, "6": set()}}
    spec = analyze_spectrum(aps, caps)
    check("2.4GHz band present in spectrum", "2.4" in spec)
    check("ch1 shows 2 co-channel APs",
          any(c["channel"] == 1 and c["primary_count"] == 2
              for c in spec.get("2.4", {}).get("channels", [])),
          json.dumps(spec.get("2.4", {}).get("channels", [])))
    check("2.4 recommends from 1/6/11",
          set(spec.get("2.4", {}).get("recommend", [])) <= set(_NON_OVERLAP_24),
          str(spec.get("2.4", {}).get("recommend")))
    check("5GHz ch52 flagged radar in spectrum",
          any(c["channel"] == 52 and c["radar"]
              for c in spec.get("5", {}).get("channels", [])))

    # Interference
    inter = find_interference(aps)
    check("co-channel interference on ch1",
          any(g["channel"] == 1 and g["count"] == 2 for g in inter["co_channel"]),
          json.dumps(inter["co_channel"]))

    # Radius model
    rad = estimate_radius(a3)
    check("radius rings computed (3 thresholds)", len(rad["rings"]) == 3)
    check("closer threshold => smaller radius",
          rad["rings"][0]["radius_m"] < rad["rings"][2]["radius_m"],
          str([r["radius_m"] for r in rad["rings"]]))
    check("current distance positive", (rad["current_distance_m"] or 0) > 0,
          str(rad["current_distance_m"]))

    passed = sum(1 for r in results if r["pass"])
    return {"pass": passed == len(results), "passed": passed,
            "total": len(results), "results": results}


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _main(argv):
    import argparse
    ap = argparse.ArgumentParser(description="Passive tri-band Wi-Fi spectrum analyzer")
    sub = ap.add_subparsers(dest="cmd")

    sub.add_parser("interfaces")
    ps = sub.add_parser("scan")
    ps.add_argument("--interface", default="wlan0")
    ps.add_argument("--band", default="all", choices=["all", "2.4", "5", "6"])
    ps.add_argument("--active", action="store_true", help="(NOT passive) send probes")
    pr = sub.add_parser("radius")
    pr.add_argument("--interface", default="wlan0")
    pr.add_argument("--bssid", required=True)
    pr.add_argument("--tx", type=float, default=_DEFAULT_TX_DBM)
    pr.add_argument("--ple", type=float, default=_DEFAULT_PLE)
    sub.add_parser("selftest")

    args = ap.parse_args(argv)
    if args.cmd == "interfaces":
        print(json.dumps(list_wifi_interfaces(), indent=2))
    elif args.cmd == "scan":
        print(json.dumps(do_scan(args.interface, args.band, passive=not args.active),
                         indent=2))
    elif args.cmd == "radius":
        print(json.dumps(do_radius(args.interface, args.bssid, args.tx, args.ple),
                         indent=2))
    elif args.cmd == "selftest":
        r = selftest()
        for item in r["results"]:
            print(f"  [{'PASS' if item['pass'] else 'FAIL'}] {item['name']}"
                  + (f"  ({item['detail']})" if not item["pass"] else ""))
        print(f"\n{r['passed']}/{r['total']} checks pass — "
              f"{'OK' if r['pass'] else 'FAILURES'}")
        return 0 if r["pass"] else 1
    else:
        ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
