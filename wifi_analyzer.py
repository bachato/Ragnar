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
# Per-AP enrichment  (802.11 generation, streams, vendor, security, roaming …)
# --------------------------------------------------------------------------

# Vendor OUI lookup: prefer the system IEEE/nmap databases, fall back to a small
# curated map of common Wi-Fi AP makers. Loaded once, lazily.
_OUI_CACHE = None
_OUI_FALLBACK = {
    "00:0b:86": "Aruba", "6c:f3:7f": "Aruba", "d8:c7:c8": "Aruba",
    "00:1a:1e": "Aruba", "00:24:6c": "Aruba",
    "00:0c:29": "VMware", "00:1b:0c": "Cisco", "00:1e:14": "Cisco",
    "00:1e:bd": "Cisco", "58:97:bd": "Cisco", "e0:cb:bc": "Cisco",
    "00:18:0a": "Meraki", "88:15:44": "Meraki", "e0:55:3d": "Meraki",
    "24:a4:3c": "Ubiquiti", "78:8a:20": "Ubiquiti", "fc:ec:da": "Ubiquiti",
    "68:d7:9a": "Ubiquiti", "b4:fb:e4": "Ubiquiti", "e0:63:da": "Ubiquiti",
    "00:13:92": "Ruckus", "c0:c5:20": "Ruckus", "2c:c5:d3": "Ruckus",
    "00:24:b2": "Netgear", "a0:40:a0": "Netgear", "b0:7f:b9": "Netgear",
    "50:c7:bf": "TP-Link", "00:25:86": "TP-Link", "60:32:b1": "TP-Link",
    "4c:5e:0c": "TP-Link", "c4:6e:1f": "TP-Link",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    "24:0a:c4": "Espressif", "a4:cf:12": "Espressif", "7c:9e:bd": "Espressif",
    "3c:71:bf": "Espressif", "84:0d:8e": "Espressif",
    "00:03:93": "Apple", "a4:83:e7": "Apple", "f0:18:98": "Apple",
    "00:09:5b": "Netgear", "48:8f:5a": "Mikrotik", "cc:2d:e0": "Mikrotik",
    "dc:2c:6e": "Mikrotik", "18:fd:74": "Mikrotik", "d4:ca:6d": "Mikrotik",
}
_OUI_FILES = ("/usr/share/nmap/nmap-mac-prefixes",
              "/usr/share/ieee-data/oui.txt")


def _load_oui():
    global _OUI_CACHE
    if _OUI_CACHE is not None:
        return _OUI_CACHE
    table = {}
    # nmap format: "AABBCC Vendor Name" (one per line).
    try:
        with open("/usr/share/nmap/nmap-mac-prefixes") as f:
            for line in f:
                if line.startswith("#") or len(line) < 8:
                    continue
                pfx, _, name = line.partition(" ")
                if len(pfx) == 6:
                    table[pfx.lower()] = name.strip()
    except Exception:
        pass
    # IEEE oui.txt fallback: "AA-BB-CC   (hex)\t\tVendor".
    if not table:
        try:
            with open("/usr/share/ieee-data/oui.txt") as f:
                for line in f:
                    m = re.match(r"^([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})"
                                 r"\s+\(hex\)\s+(.+)$", line)
                    if m:
                        table[(m.group(1) + m.group(2) + m.group(3)).lower()] = m.group(4).strip()
        except Exception:
            pass
    if not table:
        table = {k.replace(":", ""): v for k, v in _OUI_FALLBACK.items()}
    _OUI_CACHE = table
    return table


def _oui_lookup(bssid):
    """Vendor for a BSSID, or 'Randomized' for a locally-administered MAC."""
    if not bssid or len(bssid) < 8:
        return None
    try:
        first = int(bssid[:2], 16)
    except ValueError:
        return None
    if first & 0x02:                       # locally-administered bit
        return "Randomized/private"
    pfx = bssid.replace(":", "")[:6].lower()
    return _load_oui().get(pfx) or _OUI_FALLBACK.get(bssid[:8])


def _parse_generation(block, band):
    """(standard label, phy_mode) from the capability IEs present."""
    if re.search(r"\bEHT (capabilities|Operation)", block):
        return ("Wi-Fi 7", "be")
    if re.search(r"\bHE (capabilities|operation)", block):
        return ("Wi-Fi 6E" if band == "6" else "Wi-Fi 6", "ax")
    if "VHT capabilities" in block or "VHT Capabilities" in block:
        return ("Wi-Fi 5", "ac")
    if "HT capabilities" in block:
        return ("Wi-Fi 4", "n")
    return ("legacy", "abg")


def _parse_nss(block):
    """Best-effort spatial-stream count from MCS/NSS sets."""
    nss = None
    # VHT/HE print 'N streams: MCS 0-9' — the highest supported N is the NSS.
    streams = [int(m.group(1)) for m in
               re.finditer(r"(\d+) streams: MCS", block)]
    if streams:
        nss = max(streams)
    # HT: 'HT RX MCS rate indexes supported: 0-31' -> (31+1)/8 streams.
    mh = re.search(r"HT RX MCS rate indexes supported:\s*0-(\d+)", block)
    if mh:
        nss = max(nss or 0, (int(mh.group(1)) + 1) // 8)
    return nss or None


# Approximate top PHY rate (Mbps) per spatial stream at 20 MHz, short-GI, top MCS.
_PHY_BASE = {"n": 72.2, "ac": 86.7, "ax": 143.4, "be": 172.1, "abg": 54.0}
_WIDTH_MULT = {20: 1.0, 40: 2.08, 80: 4.5, 160: 9.0, 320: 18.0}


def _estimate_max_phy(phy_mode, width, nss):
    """Rough 'up to' PHY rate — width x streams x per-stream base. Estimate only."""
    if not nss:
        return None
    base = _PHY_BASE.get(phy_mode)
    if base is None:
        return None
    return int(round(base * _WIDTH_MULT.get(width, 1.0) * nss))


def _parse_security(block, hdr):
    """Detailed security posture: mode, AKM, PMF, enterprise, WPS."""
    has_rsn = "RSN:" in block
    has_wpa = "WPA:" in block
    privacy = "Privacy" in (hdr or "")
    akms = ""
    m = re.search(r"Authentication suites:\s*(.+)", block)
    if m:
        akms = m.group(1)
    sae = "SAE" in akms
    owe = "OWE" in akms
    dot1x = "802.1X" in akms or "8021X" in akms.replace(".", "").replace(" ", "")
    ft = "FT/" in akms or "FT over" in block or "Mobility Domain" in block
    enterprise = dot1x
    # PMF / 802.11w
    if re.search(r"MFP-required", block):
        pmf = "required"
    elif re.search(r"MFP-capable", block):
        pmf = "capable"
    else:
        pmf = "disabled"
    # Mode label
    if owe:
        mode = "OWE"
    elif sae and has_rsn:
        mode = "WPA3-Enterprise" if enterprise else "WPA3"
    elif has_rsn:
        mode = "WPA2-Enterprise" if enterprise else "WPA2"
    elif has_wpa:
        mode = "WPA"
    elif privacy:
        mode = "WEP"
    else:
        mode = "Open"
    wps = "WPS:" in block
    wps_ver = None
    if wps:
        mv = re.search(r"WPS:\s*\*\s*Version:\s*([\d.]+)", block)
        wps_ver = mv.group(1) if mv else None
    return {
        "security": mode,
        "akm": akms.strip() or None,
        "pmf": pmf,
        "enterprise": enterprise,
        "wps": wps,
        "wps_version": wps_ver,
        "ft": ft,
    }


def _security_findings(bss):
    """Weak-posture flags for one AP (list of short strings)."""
    out = []
    sec = bss.get("security")
    if sec == "Open":
        out.append("open (no encryption)")
    elif sec == "WEP":
        out.append("WEP (broken)")
    elif sec == "WPA":
        out.append("WPA/TKIP (legacy)")
    if bss.get("wps"):
        out.append("WPS enabled")
    if bss.get("pmf") == "disabled" and sec not in ("Open", "WEP", None):
        out.append("PMF off (deauth-exposed)")
    return out


def _parse_roaming(block):
    """802.11k / v / r assisted-roaming support."""
    k = "RM enabled capabilities" in block
    v = "BSS Transition" in block
    r = ("Mobility Domain" in block) or ("FT/" in block) or ("FT over" in block)
    return {"k": k, "v": v, "r": r}


def _enrich(block, hdr, bss):
    """Attach the enterprise-grade fields to a parsed BSS dict (in place)."""
    band = bss["band"]
    bss["vendor"] = _oui_lookup(bss["bssid"])
    bss["standard"], phy = _parse_generation(block, band)
    bss["phy_mode"] = phy
    bss["nss"] = _parse_nss(block)
    bss["max_phy_mbps"] = _estimate_max_phy(phy, bss.get("width", 20), bss["nss"])
    sec = _parse_security(block, hdr)
    bss.update(sec)
    bss["security_findings"] = _security_findings(bss)
    bss["roaming"] = _parse_roaming(block)
    m = re.search(r"TPC report: TX power:\s*(-?\d+)", block)
    bss["tx_power_dbm"] = int(m.group(1)) if m else None
    m = re.search(r"Country:\s*([A-Z]{2})", block)
    bss["country"] = m.group(1) if m else None
    m = re.search(r"beacon interval:\s*(\d+)", block)
    bss["beacon_interval"] = int(m.group(1)) if m else None
    m = re.search(r"DTIM Period\s*(\d+)", block)
    bss["dtim"] = int(m.group(1)) if m else None
    return bss


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

        m = re.search(r"last seen:\s*(\d+)\s*ms ago", block)
        bss["last_seen_ms"] = int(m.group(1)) if m else None

        # Enterprise enrichment: generation, streams, vendor, security depth,
        # roaming (11k/v/r), tx-power, country, DTIM.
        _enrich(block, b["_hdr"], bss)

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
        # Width advice: dense bands should narrow their channels so more
        # non-overlapping channels exist; empty bands can go wide.
        if band == "2.4":
            width_advice = (20, "2.4 GHz only has 3 non-overlapping channels — "
                                "use 20 MHz and stick to 1/6/11")
        else:
            avg_w = sum(a["width"] for a in aps) / len(aps)
            if prim_aps >= 12:
                width_advice = (40, "dense band — 40 MHz keeps enough clear "
                                    "channels")
            elif prim_aps >= 6:
                width_advice = (80, "80 MHz is a good balance here")
            else:
                width_advice = (160, "few APs — 160 MHz is viable for peak speed")
            width_advice = (width_advice[0],
                            width_advice[1] + f" (APs average {int(avg_w)} MHz now)")
        out[band] = {
            "ap_count": prim_aps,
            "channels": channels,
            "recommend": [c["channel"] for c in recommend],
            "rating": rating,
            "score": round(total_score, 2),
            "width_advice": {"mhz": width_advice[0], "reason": width_advice[1]},
        }
    return out


def _mac_prefix(bssid, octets=5):
    return ":".join(bssid.split(":")[:octets])


def group_aps(bss_list):
    """Collapse the flat BSS list into two enterprise views:

    * **networks** — one entry per SSID (an ESS): how many BSSIDs serve it,
      which bands it spans, its security/best signal. The "how many APs is this
      network on" view.
    * **devices** — physical radios: BSSIDs that share their top-5 MAC octets
      (an enterprise AP hands out consecutive BSSIDs per SSID/band) collapsed
      into one logical AP.
    """
    networks = {}
    for a in bss_list:
        if a.get("hidden") or not a.get("ssid"):
            continue
        n = networks.setdefault(a["ssid"], {
            "ssid": a["ssid"], "bssids": [], "bands": set(),
            "security": a.get("security"), "best_signal": None,
            "vendor": a.get("vendor"), "standard": a.get("standard")})
        n["bssids"].append(a["bssid"])
        n["bands"].add(a["band"])
        if a.get("signal") is not None and (n["best_signal"] is None
                                            or a["signal"] > n["best_signal"]):
            n["best_signal"] = a["signal"]
    net_list = []
    for n in networks.values():
        n["bands"] = sorted(n["bands"])
        n["ap_count"] = len(n["bssids"])
        net_list.append(n)
    net_list.sort(key=lambda n: -(n["best_signal"] or -999))

    devices = {}
    for a in bss_list:
        key = _mac_prefix(a["bssid"])
        d = devices.setdefault(key, {
            "mac_prefix": key, "bssids": [], "ssids": set(), "bands": set(),
            "vendor": a.get("vendor"), "best_signal": None})
        d["bssids"].append(a["bssid"])
        if a.get("ssid"):
            d["ssids"].add(a["ssid"])
        d["bands"].add(a["band"])
        if a.get("signal") is not None and (d["best_signal"] is None
                                            or a["signal"] > d["best_signal"]):
            d["best_signal"] = a["signal"]
    dev_list = []
    for d in devices.values():
        d["ssids"] = sorted(d["ssids"])
        d["bands"] = sorted(d["bands"])
        d["radio_count"] = len(d["bssids"])
        dev_list.append(d)
    dev_list.sort(key=lambda d: -(d["best_signal"] or -999))

    return {
        "networks": net_list,
        "network_count": len(net_list),
        "devices": dev_list,
        "device_count": len(dev_list),
    }


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


def estimate_radius(bss, tx_dbm=None, ple=_DEFAULT_PLE):
    """Coverage rings + your current distance for one BSS (from its measured RSSI).

    Uses the AP's *advertised* TX power (TPC report IE) when it published one, so
    the model is measured rather than assumed; falls back to `tx_dbm` / the
    default otherwise."""
    tx_measured = bss.get("tx_power_dbm")
    tx_source = "measured" if tx_measured is not None else "assumed"
    if tx_dbm is None:
        tx_dbm = tx_measured if tx_measured is not None else _DEFAULT_TX_DBM
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
        "assumptions": {"tx_dbm": tx_dbm, "tx_source": tx_source,
                        "path_loss_exponent": ple, "rssi_at_1m": round(rssi0, 1)},
        "current_distance_m": cur,
        "rings": rings,
    }


# --------------------------------------------------------------------------
# Top-level scan orchestration
# --------------------------------------------------------------------------

_DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "data", "wifi_analyzer_db.json")
_DB_HISTORY_CAP = 60      # RSSI samples kept per BSSID
_WEAKENED_DROP = 18       # dB below an AP's own max => "weakened"


def _db_load():
    try:
        with open(_DB_FILE) as f:
            return json.load(f)
    except Exception:
        return {"aps": {}, "last_bssids": []}


def _db_save(db):
    os.makedirs(os.path.dirname(_DB_FILE), exist_ok=True)
    tmp = _DB_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(db, f)
    os.replace(tmp, _DB_FILE)


def _db_update(aps):
    """Persist per-BSSID history, annotate each AP with it, and diff against the
    previous scan to surface new / disappeared / weakened APs."""
    db = _db_load()
    recs = db.get("aps", {})
    now = int(time.time())
    prev = set(db.get("last_bssids", []))
    cur = set()
    new_aps, weakened = [], []
    for a in aps:
        b = a["bssid"]
        cur.add(b)
        r = recs.get(b)
        if r is None:
            r = recs[b] = {"first_seen": now, "seen_count": 0,
                           "max_rssi": a.get("signal"), "min_rssi": a.get("signal"),
                           "history": []}
            if b not in prev:
                new_aps.append({"bssid": b, "ssid": a.get("ssid"),
                                "vendor": a.get("vendor"), "band": a.get("band"),
                                "channel": a.get("channel"), "signal": a.get("signal")})
        r["seen_count"] += 1
        r["last_seen"] = now
        r["ssid"] = a.get("ssid")
        r["vendor"] = a.get("vendor")
        s = a.get("signal")
        if s is not None:
            r["max_rssi"] = max(r.get("max_rssi") or s, s)
            r["min_rssi"] = min(r.get("min_rssi") if r.get("min_rssi") is not None else s, s)
            r["history"] = (r.get("history", []) + [[now, s, a.get("channel_util")]])[-_DB_HISTORY_CAP:]
            if (r["max_rssi"] - s) >= _WEAKENED_DROP and r["seen_count"] > 2:
                weakened.append({"bssid": b, "ssid": a.get("ssid"),
                                 "band": a.get("band"), "channel": a.get("channel"),
                                 "signal": s, "rssi_max": r["max_rssi"],
                                 "drop": r["max_rssi"] - s})
        # Annotate the live AP with its tracked history
        a["first_seen"] = r["first_seen"]
        a["seen_count"] = r["seen_count"]
        a["is_new"] = b not in prev and r["seen_count"] <= 1
        a["rssi_history"] = [h[1] for h in r.get("history", [])]
        a["rssi_max"] = r.get("max_rssi")
        a["rssi_min"] = r.get("min_rssi")
    gone = [{"bssid": b, "ssid": recs.get(b, {}).get("ssid")}
            for b in (prev - cur)]
    db["aps"] = recs
    db["last_bssids"] = sorted(cur)
    _db_save(db)
    return {"new_aps": new_aps, "gone_aps": gone, "weakened": weakened}


def db_get():
    return _db_load().get("aps", {})


def db_reset():
    _db_save({"aps": {}, "last_bssids": []})
    return {"ok": True}


def _survey_noise(interface):
    """Return {freq_mhz: noise_dbm} from `iw survey dump` (best-effort; some
    drivers, incl. brcmfmac, don't report a noise floor)."""
    rc, out, _ = _run([_IW, "dev", interface, "survey", "dump"], timeout=8)
    if rc != 0:
        return {}
    noise = {}
    cur_freq = None
    for line in out.splitlines():
        m = re.search(r"frequency:\s*(\d+)\s*MHz", line)
        if m:
            cur_freq = int(m.group(1))
            continue
        m = re.search(r"noise:\s*(-?\d+)\s*dBm", line)
        if m and cur_freq is not None:
            noise[cur_freq] = int(m.group(1))
    return noise


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
    noise = _survey_noise(interface)
    noise_floor = round(sum(noise.values()) / len(noise), 1) if noise else None
    # Flag radar/DFS occupancy + compute SNR from the noise floor where known.
    for b in bss_list:
        b["dfs"] = b["channel"] in caps["radar_channels"].get(b["band"], set())
        nf = noise.get(int(round(b["freq"])))
        if nf is None and noise_floor is not None:
            nf = noise_floor
        b["noise"] = nf
        b["snr"] = (round(b["signal"] - nf, 1)
                    if (b.get("signal") is not None and nf is not None) else None)
    if band in ("2.4", "5", "6"):
        bss_list = [b for b in bss_list if b["band"] == band]
    bss_list.sort(key=lambda b: (b["band"], b["channel"], -(b["signal"] or -999)))
    changes = _db_update(bss_list)
    spectrum = analyze_spectrum(bss_list, caps)
    interference = find_interference(bss_list)
    groups = group_aps(bss_list)
    return {
        "interface": interface,
        "phy": caps["phy"],
        "timestamp": int(time.time()),
        "passive": passive,
        "supported_bands": {b: bool(caps["bands"].get(b)) for b in ("2.4", "5", "6")},
        "radar_channels": {b: sorted(caps["radar_channels"].get(b, set()))
                           for b in ("2.4", "5", "6")},
        "noise_floor": noise_floor,
        "ap_count": len(bss_list),
        "aps": bss_list,
        "spectrum": spectrum,
        "interference": interference,
        "groups": groups,
        "changes": changes,
    }


def do_radius(interface, bssid, tx_dbm=None, ple=_DEFAULT_PLE):
    """Passive scan then compute the signal radius for one BSSID. tx_dbm=None
    lets estimate_radius use the AP's advertised TX power when it has one."""
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
	beacon interval: 100 TUs
	TIM: DTIM Count 0 DTIM Period 2
	Country: SE	Environment: Indoor/Outdoor
	TPC report: TX power: 20 dBm
	RSN:	 * Version: 1
		 * Authentication suites: PSK
		 * Capabilities: 16-PTKSA-RC 1-GTKSA-RC (0x000c)
	WPS:	 * Version: 1.0
	BSS Load:
		 * station count: 4
		 * channel utilisation: 128/255
	HT capabilities:
		HT RX MCS rate indexes supported: 0-15
	HT operation:
		 * primary channel: 1
		 * secondary channel offset: no secondary
	RM enabled capabilities:
	Extended capabilities:
		 * BSS Transition
BSS aa:bb:cc:00:00:02(on wlan0)
	freq: 2412.0
	signal: -70.00 dBm
	SSID: Neighbour
	HT capabilities:
	HT operation:
		 * primary channel: 1
		 * secondary channel offset: above
BSS aa:bb:cc:00:00:03(on wlan0)
	freq: 5260.0
	signal: -55.00 dBm
	SSID: HomeNet_5G
	RSN:	 * Version: 1
		 * Authentication suites: SAE
		 * Capabilities: MFP-required 16-PTKSA-RC (0x00cc)
	Mobility Domain:
		 * MDID: 0x1234
	HT operation:
		 * primary channel: 52
		 * secondary channel offset: above
	VHT capabilities:
	VHT operation:
		 * channel width: 1 (80 MHz)
		 * center freq segment 1: 58
	VHT RX MCS set:
		1 streams: MCS 0-9
		2 streams: MCS 0-9
		3 streams: MCS 0-9
		4 streams: MCS 0-9
BSS aa:bb:cc:00:00:04(on wlan0)
	freq: 5955.0
	signal: -60.00 dBm
	SSID: HomeNet_6G
	RSN:	 * Version: 1
		 * Authentication suites: IEEE 802.1X
		 * Capabilities: MFP-capable (0x0080)
	HE capabilities:
		HE RX MCS and NSS set <= 80 MHz
			1 streams: MCS 0-11
			2 streams: MCS 0-11
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

    # Radius model — should use the AP's advertised TX power (a1 has TPC 20 dBm)
    rad = estimate_radius(a3)
    check("radius rings computed (3 thresholds)", len(rad["rings"]) == 3)
    check("closer threshold => smaller radius",
          rad["rings"][0]["radius_m"] < rad["rings"][2]["radius_m"],
          str([r["radius_m"] for r in rad["rings"]]))
    check("current distance positive", (rad["current_distance_m"] or 0) > 0,
          str(rad["current_distance_m"]))
    rad1 = estimate_radius(a1)
    check("radius uses measured TX power",
          rad1["assumptions"]["tx_source"] == "measured"
          and rad1["assumptions"]["tx_dbm"] == 20,
          json.dumps(rad1["assumptions"]))

    # --- Enterprise enrichment (Tier 1) ---
    check("802.11 generation: Wi-Fi 4/5/6E",
          a1.get("standard") == "Wi-Fi 4" and a3.get("standard") == "Wi-Fi 5"
          and a4.get("standard") == "Wi-Fi 6E",
          f"{a1.get('standard')}/{a3.get('standard')}/{a4.get('standard')}")
    check("spatial streams (NSS) parsed",
          a1.get("nss") == 2 and a3.get("nss") == 4 and a4.get("nss") == 2,
          f"{a1.get('nss')}/{a3.get('nss')}/{a4.get('nss')}")
    check("max PHY rate estimated", (a3.get("max_phy_mbps") or 0) > 1000,
          str(a3.get("max_phy_mbps")))
    check("security depth: WPA2 / WPA3 / WPA2-Enterprise",
          a1.get("security") == "WPA2" and a3.get("security") == "WPA3"
          and a4.get("security") == "WPA2-Enterprise",
          f"{a1.get('security')}/{a3.get('security')}/{a4.get('security')}")
    check("PMF parsed (disabled/required/capable)",
          a1.get("pmf") == "disabled" and a3.get("pmf") == "required"
          and a4.get("pmf") == "capable",
          f"{a1.get('pmf')}/{a3.get('pmf')}/{a4.get('pmf')}")
    check("enterprise (802.1X) flagged", a4.get("enterprise") is True,
          str(a4.get("enterprise")))
    check("WPS enabled detected", a1.get("wps") is True and not a3.get("wps"),
          f"{a1.get('wps')}/{a3.get('wps')}")
    check("weak-security findings (WPS + PMF-off on a1)",
          "WPS enabled" in a1.get("security_findings", [])
          and any("PMF off" in f for f in a1.get("security_findings", [])),
          str(a1.get("security_findings")))
    check("roaming 11k/v on a1, 11r on a3",
          a1["roaming"]["k"] and a1["roaming"]["v"] and a3["roaming"]["r"],
          f"{a1.get('roaming')} / {a3.get('roaming')}")
    check("country + DTIM + beacon parsed",
          a1.get("country") == "SE" and a1.get("dtim") == 2
          and a1.get("beacon_interval") == 100,
          f"{a1.get('country')}/{a1.get('dtim')}/{a1.get('beacon_interval')}")
    check("locally-administered MAC => Randomized",
          a1.get("vendor") == "Randomized/private", str(a1.get("vendor")))
    check("OUI vendor lookup (TP-Link)",
          _oui_lookup("00:25:86:11:22:33") in ("TP-Link", "TP-Link Technologies",
                                               "Tp-Link Technologies Co.,Ltd."),
          str(_oui_lookup("00:25:86:11:22:33")))

    # --- Grouping + width advice (Tier 2) ---
    grp = group_aps(aps)
    homenet = next((n for n in grp["networks"] if n["ssid"] == "HomeNet"), None)
    check("networks grouped by SSID", grp["network_count"] >= 4, str(grp["network_count"]))
    check("device grouping by MAC prefix", grp["device_count"] >= 1,
          str(grp["device_count"]))
    check("width advice present per band",
          "width_advice" in spec.get("5", {})
          and spec["2.4"]["width_advice"]["mhz"] == 20,
          json.dumps(spec.get("5", {}).get("width_advice")))

    # --- AP history DB + change detection (Tier 3) — temp file, no real state ---
    global _DB_FILE
    _orig_db, _DB_FILE = _DB_FILE, __import__("tempfile").mktemp(suffix=".json")
    try:
        db_reset()
        base = {"bssid": "a0:00:00:00:00:01", "ssid": "H", "channel_util": 10,
                "band": "2.4", "channel": 1, "vendor": None}
        first = dict(base, signal=-40)
        c1 = _db_update([first])
        check("new AP detected on first sighting",
              any(n["bssid"] == base["bssid"] for n in c1["new_aps"])
              and first.get("is_new") is True)
        check("rssi history annotated", first.get("rssi_history") == [-40])
        _db_update([dict(base, signal=-70)])
        weak = dict(base, signal=-70)
        c3 = _db_update([weak])
        check("weakened AP detected (>=18 dB below its max)",
              any(w["bssid"] == base["bssid"] for w in c3["weakened"]),
              json.dumps(c3["weakened"]))
        c4 = _db_update([])       # AP vanished this scan
        check("disappeared AP detected",
              any(g["bssid"] == base["bssid"] for g in c4["gone_aps"]))
    finally:
        try:
            os.unlink(_DB_FILE)
        except OSError:
            pass
        _DB_FILE = _orig_db

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
