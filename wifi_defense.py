#!/usr/bin/env python3
"""
wifi_defense.py — Passive 802.11 frame monitor / Wireless IDS for Ragnar.

Listens on a **monitor-mode** adapter for 802.11 management frames and flags the
classic wireless attacks a defender cares about:

* **Deauth / disassoc flood** — the 802.11 deauthentication DoS (aireplay/mdk4):
  spoofed deauth/disassoc frames knock clients off an AP.
* **Beacon flood** — a storm of fake APs (mdk4 beacon mode): many bogus SSIDs /
  BSSIDs appearing at once to drown the airspace or bait clients.
* **Rogue AP / evil twin** — a *known* SSID advertised from a BSSID that isn't in
  the trusted baseline (a look-alike AP set up to harvest clients), or one SSID
  suddenly served by two BSSIDs.
* **KARMA / MANA** — an AP that answers probe requests for *many different* SSIDs
  from a single BSSID (it pretends to be every network a client has ever joined).

Everything here only **receives** — it never transmits a frame, never deauths
anyone back. It's detection-only (a WIDS), not an attack tool.

Monitor mode is set up with plain `iw` (no aircrack-ng needed): where the driver
allows it a *separate* monitor vif is added so the box keeps its normal Wi-Fi
link; otherwise the adapter itself is switched to monitor. Tuned for the Alfa
AWUS036AXM (mt7921u) which supports a concurrent monitor vif; the Pi's onboard
brcmfmac radio does not do monitor mode at all.

CLI:
    python3 wifi_defense.py interfaces
    python3 wifi_defense.py monitor --interface wlan1 --enable
    python3 wifi_defense.py scan --interface wlan1 --seconds 15 [--channel 6]
    python3 wifi_defense.py monitor --interface wlan1 --disable
    python3 wifi_defense.py selftest
"""

import json
import os
import re
import subprocess
import sys
import threading
import time

_IW = "/usr/sbin/iw" if os.path.exists("/usr/sbin/iw") else "iw"
_STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "data", "wifi_defense.json")

# Detection thresholds (per capture window)
_DEAUTH_FLOOD_MIN = 15      # deauth+disassoc frames => flood
# Beacon flood. There is no reliable "shape" signal that separates a flood from a
# dense neighbourhood passively: raw SSID/BSSID counts scale with how crowded the
# airspace is, and randomized/locally-administered BSSIDs are ALSO used by ordinary
# multi-SSID routers (guest/IoT VAPs derive their BSSID by setting the 0x02 bit),
# so a block full of them trips any LA-based rule. The only robust lever is the raw
# distinct-SSID/BSSID count with a threshold the user calibrates to their own RF
# environment — a real mdk3/mdk4/ESP32 flood produces hundreds, far above any home.
_BEACON_FLOOD_SSIDS = 100         # distinct beaconed SSIDs => flood (tunable)
_BEACON_FLOOD_BSSIDS = 150        # distinct beaconing BSSIDs => flood (tunable)
_KARMA_SSID_MIN = 5               # distinct SSIDs answered by ONE bssid => KARMA

# Channels the hopper cycles when no fixed channel is requested (2.4 GHz + the
# common U-NII-1/3 5 GHz set). Kept short so each channel gets real dwell time.
_HOP_CHANNELS = [1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161]

# 802.11 management subtype -> event kind
_MGMT_SUBTYPES = {
    0: "assoc_req", 1: "assoc_resp", 2: "reassoc_req", 3: "reassoc_resp",
    4: "probe_req", 5: "probe_resp", 8: "beacon", 10: "disassoc",
    11: "auth", 12: "deauth",
}


# --------------------------------------------------------------------------
# Subprocess plumbing
# --------------------------------------------------------------------------

def _run(args, timeout=10):
    try:
        p = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout, check=False)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"{args[0]} not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timed out"
    except Exception as exc:  # pragma: no cover
        return 1, "", str(exc)


def _valid_iface(iface):
    return bool(iface) and re.match(r"^[A-Za-z0-9_.-]{1,32}$", iface or "") is not None


# --------------------------------------------------------------------------
# Interface / monitor-mode management  (plain iw, no aircrack-ng)
# --------------------------------------------------------------------------

def _phy_for_iface(iface):
    rc, out, _ = _run([_IW, "dev"], timeout=5)
    cur = None
    for line in out.splitlines():
        m = re.match(r"^(phy#\d+)", line)
        if m:
            cur = m.group(1).replace("#", "")
        m = re.match(r"^\s*Interface\s+(\S+)", line)
        if m and m.group(1) == iface:
            return cur
    return None


def _phy_supports_monitor(phy):
    if not phy:
        return False
    rc, out, _ = _run([_IW, "phy", phy, "info"], timeout=8)
    if rc != 0:
        return False
    block = re.search(r"Supported interface modes:(.*?)(?:\n\s*\n|\n\tband|\Z)",
                      out, re.S)
    return bool(block and re.search(r"\*\s*monitor", block.group(1)))


def _iw_dev_list():
    """Return {iface: {phy, type}} for every wireless interface."""
    rc, out, _ = _run([_IW, "dev"], timeout=5)
    devs = {}
    cur_phy, cur = None, None
    for line in out.splitlines():
        m = re.match(r"^(phy#\d+)", line)
        if m:
            cur_phy = m.group(1).replace("#", "")
            continue
        m = re.match(r"^\s*Interface\s+(\S+)", line)
        if m:
            cur = m.group(1)
            devs[cur] = {"phy": cur_phy, "type": None}
            continue
        if cur:
            mt = re.match(r"^\s*type\s+(\S+)", line)
            if mt:
                devs[cur]["type"] = mt.group(1)
    return devs


def list_monitor_capable():
    """Wireless interfaces whose radio can do monitor mode, plus current state."""
    devs = _iw_dev_list()
    state = _load_state()
    out = []
    seen_phys = {}
    for iface, info in devs.items():
        phy = info["phy"]
        if phy not in seen_phys:
            seen_phys[phy] = _phy_supports_monitor(phy)
        out.append({
            "iface": iface, "phy": phy, "type": info["type"],
            "monitor_capable": seen_phys[phy],
            "is_monitor": info["type"] == "monitor",
        })
    return {"interfaces": out, "active_monitor": state.get("mon_iface"),
            "base_iface": state.get("base_iface")}


def _mon_name(base):
    # Deterministic, short, and unlikely to collide with a user's naming.
    return "ragmon0"


def enable_monitor(iface):
    """Put a monitor interface up for `iface`'s radio.

    Prefers adding a *separate* monitor vif (keeps the managed link alive on
    drivers that allow it, e.g. mt7921u). Falls back to switching the interface
    itself into monitor mode. Returns {mon_iface, mode, warning?} or {error}.
    """
    if not _valid_iface(iface):
        return {"error": "invalid interface"}
    phy = _phy_for_iface(iface)
    if not _phy_supports_monitor(phy):
        return {"error": f"{iface}'s radio ({phy}) does not support monitor mode"}
    _run(["/usr/bin/rfkill", "unblock", "all"], timeout=5)
    mon = _mon_name(iface)

    # Already have it?
    if mon in _iw_dev_list():
        _run(["ip", "link", "set", mon, "up"], timeout=5)
        _save_state({"mon_iface": mon, "base_iface": iface, "mode": "vif"})
        return {"mon_iface": mon, "mode": "vif"}

    # Try a concurrent monitor vif first.
    rc, _, err = _run([_IW, "phy", phy, "interface", "add", mon,
                       "type", "monitor"], timeout=8)
    if rc == 0:
        _run(["ip", "link", "set", mon, "up"], timeout=5)
        _save_state({"mon_iface": mon, "base_iface": iface, "mode": "vif"})
        return {"mon_iface": mon, "mode": "vif"}

    # Fallback: switch the interface itself to monitor (disrupts its link).
    _run(["ip", "link", "set", iface, "down"], timeout=5)
    rc2, _, err2 = _run([_IW, "dev", iface, "set", "type", "monitor"], timeout=8)
    _run(["ip", "link", "set", iface, "up"], timeout=5)
    if rc2 == 0:
        _save_state({"mon_iface": iface, "base_iface": iface, "mode": "switch"})
        return {"mon_iface": iface, "mode": "switch",
                "warning": "switched the adapter to monitor — its normal Wi-Fi "
                           "link is down until you disable monitor mode."}
    return {"error": f"could not enable monitor: {(err or err2 or '').strip()}"}


def disable_monitor(mon_iface=None):
    """Tear down monitor mode, restoring the managed interface."""
    state = _load_state()
    mon = mon_iface or state.get("mon_iface")
    mode = state.get("mode")
    base = state.get("base_iface")
    if not mon:
        return {"ok": True, "note": "no active monitor"}
    if mode == "vif" or (mon in _iw_dev_list() and _iw_dev_list().get(mon, {}).get("type") == "monitor" and mon == _mon_name(base)):
        _run(["ip", "link", "set", mon, "down"], timeout=5)
        _run([_IW, "dev", mon, "del"], timeout=8)
    else:
        # We switched the base iface into monitor; switch it back to managed.
        _run(["ip", "link", "set", mon, "down"], timeout=5)
        _run([_IW, "dev", mon, "set", "type", "managed"], timeout=8)
        _run(["ip", "link", "set", mon, "up"], timeout=5)
    _save_state({})
    return {"ok": True, "restored": base or mon}


def _set_channel(mon_iface, channel):
    _run([_IW, "dev", mon_iface, "set", "channel", str(int(channel))], timeout=5)


# --------------------------------------------------------------------------
# State (trusted-AP baseline + monitor bookkeeping)
# --------------------------------------------------------------------------

def _load_state():
    try:
        with open(_STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_state(extra):
    state = _load_state()
    # Preserve the baseline across monitor start/stop bookkeeping writes.
    baseline = state.get("baseline")
    state = dict(extra)
    if baseline is not None and "baseline" not in state:
        state["baseline"] = baseline
    os.makedirs(os.path.dirname(_STATE_FILE), exist_ok=True)
    tmp = _STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, _STATE_FILE)


def get_baseline():
    return _load_state().get("baseline") or {}


def _write_baseline(baseline):
    state = _load_state()
    state["baseline"] = baseline
    os.makedirs(os.path.dirname(_STATE_FILE), exist_ok=True)
    tmp = _STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, _STATE_FILE)
    return baseline


def set_baseline(ssid_bssids, merge=True):
    """Persist the trusted SSID->[BSSID] map.

    A single capture window can never hear every BSSID of every SSID (dual-band
    radios, mesh nodes and band-steering all publish the same SSID from several
    BSSIDs, and channel-hopping only samples each channel briefly). Replacing the
    baseline each time therefore leaves most legitimate BSSIDs "untrusted" and
    they get flagged as evil twins on the next scan. So by default we **merge**
    (union BSSIDs per SSID) rather than overwrite, letting the baseline build up
    a complete picture across repeated Trust actions."""
    if merge:
        base = get_baseline()
        for ssid, bssids in (ssid_bssids or {}).items():
            have = base.setdefault(ssid, [])
            for b in bssids:
                b = (b or "").lower()
                if b and b not in have:
                    have.append(b)
        ssid_bssids = base
    else:
        ssid_bssids = {s: sorted({(b or "").lower() for b in bs if b})
                       for s, bs in (ssid_bssids or {}).items()}
    return _write_baseline(ssid_bssids)


def clear_baseline():
    return _write_baseline({})


def get_thresholds():
    """User-tunable beacon-flood thresholds (persisted), with sane defaults."""
    st = _load_state().get("thresholds") or {}
    return {
        "beacon_ssids": int(st.get("beacon_ssids", _BEACON_FLOOD_SSIDS)),
        "beacon_bssids": int(st.get("beacon_bssids", _BEACON_FLOOD_BSSIDS)),
    }


def set_thresholds(beacon_ssids=None, beacon_bssids=None):
    cur = get_thresholds()
    if beacon_ssids is not None:
        cur["beacon_ssids"] = max(10, min(2000, int(beacon_ssids)))
    if beacon_bssids is not None:
        cur["beacon_bssids"] = max(10, min(2000, int(beacon_bssids)))
    state = _load_state()
    state["thresholds"] = cur
    os.makedirs(os.path.dirname(_STATE_FILE), exist_ok=True)
    tmp = _STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, _STATE_FILE)
    return cur


def _aps_to_mapping(aps):
    """SSID -> [BSSID] from an AP inventory list (skips hidden/empty SSIDs)."""
    mapping = {}
    for ap in aps or []:
        ssid = ap.get("ssid")
        bssid = (ap.get("bssid") or "").lower()
        if ssid and bssid:
            mapping.setdefault(ssid, [])
            if bssid not in mapping[ssid]:
                mapping[ssid].append(bssid)
    return mapping


# --------------------------------------------------------------------------
# Frame parsing  (Scapy Dot11 -> normalized event dict)
# --------------------------------------------------------------------------

def _frame_to_event(pkt):
    """Normalize one Scapy 802.11 packet into an event dict, or None if it isn't
    a management frame we care about. Pure w.r.t. Scapy objects."""
    from scapy.all import Dot11, Dot11Elt  # lazy import
    if not pkt.haslayer(Dot11):
        return None
    d = pkt.getlayer(Dot11)
    if d.type != 0:                      # 0 = management
        return None
    kind = _MGMT_SUBTYPES.get(d.subtype)
    if kind is None:
        return None
    ev = {
        "kind": kind,
        "src": (d.addr2 or "").lower() or None,     # transmitter
        "dst": (d.addr1 or "").lower() or None,     # receiver
        "bssid": (d.addr3 or "").lower() or None,
        "ssid": None,
        "channel": None,
        "rssi": None,
        "reason": None,
        "ts": float(getattr(pkt, "time", 0) or 0),
    }
    # SSID from the first SSID element (ID 0). Empty = wildcard/hidden.
    el = pkt.getlayer(Dot11Elt)
    while el is not None and isinstance(el, Dot11Elt):
        if el.ID == 0:
            try:
                ev["ssid"] = el.info.decode(errors="replace")
            except Exception:
                ev["ssid"] = None
            break
        el = el.payload.getlayer(Dot11Elt)
    # Reason code for deauth/disassoc
    if kind in ("deauth", "disassoc"):
        for lname in ("Dot11Deauth", "Dot11Disas"):
            lyr = pkt.getlayer(lname)
            if lyr is not None:
                ev["reason"] = getattr(lyr, "reason", None)
                break
    # RSSI + channel from RadioTap, if present
    try:
        from scapy.all import RadioTap
        if pkt.haslayer(RadioTap):
            rt = pkt.getlayer(RadioTap)
            ev["rssi"] = getattr(rt, "dBm_AntSignal", None)
            freq = getattr(rt, "ChannelFrequency", None)
            if freq:
                ev["channel"] = _freq_to_channel(int(freq))
    except Exception:
        pass
    return ev


def _is_locally_administered(mac):
    """True if a MAC is locally-administered (the 0x02 bit of the first octet) —
    i.e. randomized/spoofed rather than a vendor-assigned (global) address. Real
    APs almost always use global OUIs; beacon-flood tools use random MACs."""
    if not mac:
        return False
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def _freq_to_channel(freq):
    if 2412 <= freq <= 2484:
        return 14 if freq == 2484 else (freq - 2407) // 5
    if freq >= 5955:
        return (freq - 5950) // 5
    if 5000 <= freq < 5925:
        return (freq - 5000) // 5
    return None


def parse_pcap(path):
    """Read a pcap of 802.11 frames into event dicts (for tests / offline runs)."""
    from scapy.all import rdpcap
    return [e for e in (_frame_to_event(p) for p in rdpcap(path)) if e]


# --------------------------------------------------------------------------
# Live capture
# --------------------------------------------------------------------------

def _capture(mon_iface, seconds, channel=None):
    """Sniff management frames on `mon_iface` for `seconds`, hopping channels
    unless a fixed `channel` is given. Returns a list of event dicts."""
    from scapy.all import sniff
    events = []

    def _cb(pkt):
        ev = _frame_to_event(pkt)
        if ev:
            events.append(ev)

    stop = threading.Event()
    if channel:
        _set_channel(mon_iface, channel)
    else:
        def _hopper():
            i = 0
            while not stop.is_set():
                _set_channel(mon_iface, _HOP_CHANNELS[i % len(_HOP_CHANNELS)])
                i += 1
                stop.wait(0.35)
        threading.Thread(target=_hopper, daemon=True).start()

    # Only management frames (type 0) — keeps the sniffer cheap.
    try:
        sniff(iface=mon_iface, prn=_cb, timeout=seconds, store=False,
              filter="type mgt", monitor=True)
    except Exception:
        # Some drivers reject the BPF/monitor kwarg; retry unfiltered.
        try:
            sniff(iface=mon_iface, prn=_cb, timeout=seconds, store=False)
        except Exception as exc:
            stop.set()
            return {"error": f"capture failed: {exc}"}
    stop.set()
    return events


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------

def analyze(events, baseline=None, window_secs=None, thresholds=None):
    """Classify a list of frame events into WIDS detections. Pure function."""
    baseline = baseline or {}
    th = thresholds or {}
    beacon_ssid_max = int(th.get("beacon_ssids", _BEACON_FLOOD_SSIDS))
    beacon_bssid_max = int(th.get("beacon_bssids", _BEACON_FLOOD_BSSIDS))
    deauths = [e for e in events if e["kind"] in ("deauth", "disassoc")]
    beacons = [e for e in events if e["kind"] == "beacon"]
    presp = [e for e in events if e["kind"] == "probe_resp"]

    detections = []

    # --- Deauth / disassoc flood ---
    if deauths:
        pairs = {}
        for e in deauths:
            key = (e.get("src") or "?", e.get("dst") or "?")
            pairs[key] = pairs.get(key, 0) + 1
        top = sorted(pairs.items(), key=lambda kv: -kv[1])[:5]
        sev = "flood" if len(deauths) >= _DEAUTH_FLOOD_MIN else "seen"
        detections.append({
            "type": "deauth", "severity": sev, "count": len(deauths),
            "attackers": [{"src": k[0], "dst": k[1], "count": n} for k, n in top],
            "detail": f"{len(deauths)} deauth/disassoc frames"
                      + (" — flood/DoS in progress" if sev == "flood" else ""),
        })

    # --- Beacon flood ---
    # A real flood produces hundreds of distinct SSIDs/BSSIDs — far above any home
    # or apartment block. The threshold is user-tunable so it can be calibrated to
    # the local RF density (see get/set_thresholds). The live counts are always
    # reported (below, in `airspace`) so the user can see where they sit.
    if beacons:
        ssids = {e["ssid"] for e in beacons if e.get("ssid")}
        bssids = {e["src"] for e in beacons if e.get("src")}
        rnd_bssids = {b for b in bssids if _is_locally_administered(b)}
        reasons = []
        if len(ssids) >= beacon_ssid_max:
            reasons.append(f"{len(ssids)} distinct SSIDs (≥{beacon_ssid_max})")
        if len(bssids) >= beacon_bssid_max:
            reasons.append(f"{len(bssids)} distinct BSSIDs (≥{beacon_bssid_max})")
        if reasons:
            detections.append({
                "type": "beacon_flood", "severity": "flood",
                "ssids": len(ssids), "bssids": len(bssids),
                "random_bssids": len(rnd_bssids),
                "detail": "fake-AP/beacon flood — " + ", ".join(reasons),
            })

    # --- KARMA / MANA: one BSSID answering many SSIDs ---
    by_ap = {}
    for e in presp + beacons:
        src = e.get("src")
        if src and e.get("ssid"):
            by_ap.setdefault(src, set()).add(e["ssid"])
    karma = [{"bssid": b, "ssids": sorted(s), "count": len(s)}
             for b, s in by_ap.items() if len(s) >= _KARMA_SSID_MIN]
    for k in sorted(karma, key=lambda x: -x["count"]):
        detections.append({
            "type": "karma", "severity": "karma", "bssid": k["bssid"],
            "ssid_count": k["count"], "ssids": k["ssids"][:12],
            "detail": f"{k['bssid']} answered {k['count']} different SSIDs — "
                      "KARMA/MANA rogue AP",
        })

    # --- Rogue AP / evil twin: SSID from an unexpected BSSID ---
    seen = {}
    for e in beacons + presp:
        if e.get("ssid") and e.get("src"):
            seen.setdefault(e["ssid"], set()).add(e["src"])
    for ssid, bssids in seen.items():
        trusted = set(baseline.get(ssid, []))
        if trusted:
            rogue = bssids - trusted
            if rogue:
                detections.append({
                    "type": "rogue_ap", "severity": "evil_twin", "ssid": ssid,
                    "rogue_bssids": sorted(rogue), "trusted_bssids": sorted(trusted),
                    "detail": f"SSID '{ssid}' seen from untrusted BSSID(s) "
                              + ", ".join(sorted(rogue)),
                })
        elif len(bssids) >= 2:
            detections.append({
                "type": "rogue_ap", "severity": "duplicate_ssid", "ssid": ssid,
                "bssids": sorted(bssids),
                "detail": f"SSID '{ssid}' advertised by {len(bssids)} BSSIDs "
                          "(possible evil twin — set a baseline to confirm)",
            })

    # Access-point inventory (for the UI table + baseline building)
    aps = {}
    for e in beacons:
        src = e.get("src")
        if not src:
            continue
        ap = aps.setdefault(src, {"bssid": src, "ssid": e.get("ssid"),
                                  "channel": e.get("channel"), "rssi": e.get("rssi"),
                                  "beacons": 0})
        ap["beacons"] += 1
        if e.get("rssi") is not None:
            ap["rssi"] = e["rssi"]
        if e.get("channel") is not None:
            ap["channel"] = e["channel"]

    sev_rank = {"flood": 3, "evil_twin": 3, "karma": 3,
                "duplicate_ssid": 2, "seen": 1}
    threat = "clear"
    if detections:
        worst = max(sev_rank.get(d["severity"], 1) for d in detections)
        threat = "critical" if worst >= 3 else "warning"

    # Live airspace stats so the UI can show where the capture sits relative to
    # the beacon-flood threshold (for calibration).
    b_ssids = {e["ssid"] for e in beacons if e.get("ssid")}
    b_bssids = {e["src"] for e in beacons if e.get("src")}
    airspace = {
        "ssids": len(b_ssids), "bssids": len(b_bssids),
        "random_bssids": len({b for b in b_bssids if _is_locally_administered(b)}),
        "beacon_ssid_threshold": beacon_ssid_max,
        "beacon_bssid_threshold": beacon_bssid_max,
    }

    return {
        "threat": threat,
        "frames": len(events),
        "counts": {"deauth": len(deauths), "beacon": len(beacons),
                   "probe_resp": len(presp),
                   "probe_req": sum(1 for e in events if e["kind"] == "probe_req")},
        "airspace": airspace,
        "detections": detections,
        "aps": sorted(aps.values(), key=lambda a: -(a.get("rssi") or -999)),
    }


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

def do_scan(interface, seconds=15, channel=None, auto_enable=True):
    """Ensure monitor mode, capture a window, and analyze it."""
    if not _valid_iface(interface):
        return {"error": "invalid interface"}
    seconds = max(3, min(120, int(seconds)))
    state = _load_state()
    mon = state.get("mon_iface")
    # Enable monitor on demand if none is active for this radio.
    if not mon:
        if not auto_enable:
            return {"error": "monitor mode not enabled"}
        res = enable_monitor(interface)
        if "error" in res:
            return res
        mon = res["mon_iface"]
    events = _capture(mon, seconds, channel=channel)
    if isinstance(events, dict) and "error" in events:
        return events
    result = analyze(events, baseline=get_baseline(), window_secs=seconds,
                     thresholds=get_thresholds())
    result.update({"interface": interface, "monitor": mon,
                   "seconds": seconds, "channel": channel,
                   "timestamp": int(time.time())})
    return result


def learn_baseline(interface, seconds=20, channel=None, merge=True):
    """Capture, then merge every SSID->BSSID mapping seen into the trusted
    baseline. Merges by default so repeated captures accumulate all the BSSIDs a
    single window can't hear at once (see set_baseline)."""
    res = do_scan(interface, seconds=seconds, channel=channel)
    if "error" in res:
        return res
    mapping = _aps_to_mapping(res.get("aps", []))
    baseline = set_baseline(mapping, merge=merge)
    return {"ok": True, "baseline": baseline, "ssids": len(baseline),
            "added": len(mapping)}


def trust_aps(aps, merge=True):
    """Trust an already-captured AP inventory (what the user is looking at) —
    no re-capture, so 'Trust current APs' trusts exactly what's on screen and
    accumulates into the baseline."""
    mapping = _aps_to_mapping(aps)
    if not mapping:
        return {"error": "no APs with SSIDs to trust — run a scan first"}
    baseline = set_baseline(mapping, merge=merge)
    return {"ok": True, "baseline": baseline, "ssids": len(baseline),
            "added": len(mapping)}


# --------------------------------------------------------------------------
# Self-test  (craft real Dot11 frames -> pcap -> parse -> analyze)
# --------------------------------------------------------------------------

def _selftest_pcap(path):
    from scapy.all import (RadioTap, Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt,
                           Dot11ProbeResp, wrpcap)
    pkts = []

    def beacon(bssid, ssid, ch=6, rssi=-50):
        return (RadioTap(dBm_AntSignal=rssi, ChannelFrequency=2437) /
                Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                      addr2=bssid, addr3=bssid) /
                Dot11Beacon() / Dot11Elt(ID=0, info=ssid.encode()))

    def deauth(src, dst):
        return (RadioTap() /
                Dot11(type=0, subtype=12, addr1=dst, addr2=src, addr3=src) /
                Dot11Deauth(reason=7))

    def proberesp(bssid, ssid):
        return (RadioTap() /
                Dot11(type=0, subtype=5, addr1="00:11:22:33:44:55",
                      addr2=bssid, addr3=bssid) /
                Dot11ProbeResp() / Dot11Elt(ID=0, info=ssid.encode()))

    # Legit home AP
    pkts += [beacon("aa:aa:aa:00:00:01", "HomeNet")] * 3
    # Deauth flood (20 frames) against it
    pkts += [deauth("aa:aa:aa:00:00:01", "cc:cc:cc:00:00:09") for _ in range(20)]
    # Beacon flood: 35 distinct fake SSIDs
    pkts += [beacon(f"de:ad:be:ef:%02x:00" % i, f"FAKE_{i}") for i in range(35)]
    # KARMA AP answering 6 different SSIDs from one BSSID
    for s in ["Starbucks", "attwifi", "HomeNet", "xfinitywifi", "TP-LINK", "Netgear"]:
        pkts.append(proberesp("ba:ad:ba:ad:00:01", s))
    # Evil twin: HomeNet also from an untrusted BSSID
    pkts.append(beacon("99:99:99:99:99:99", "HomeNet"))
    wrpcap(path, pkts)


def selftest():
    import tempfile
    results = []

    def check(name, cond, detail=""):
        results.append({"name": name, "pass": bool(cond), "detail": detail})

    try:
        from scapy.all import Dot11  # noqa: F401
    except Exception as e:
        return {"pass": False, "passed": 0, "total": 1,
                "results": [{"name": "scapy import", "pass": False, "detail": str(e)}]}

    tmp = tempfile.mktemp(suffix=".pcap")
    try:
        _selftest_pcap(tmp)
        events = parse_pcap(tmp)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass

    check("frames parsed from pcap", len(events) > 50, f"{len(events)} events")
    kinds = {e["kind"] for e in events}
    check("beacon/deauth/probe_resp all parsed",
          {"beacon", "deauth", "probe_resp"} <= kinds, str(sorted(kinds)))
    check("SSID extracted from beacon",
          any(e["kind"] == "beacon" and e["ssid"] == "HomeNet" for e in events))
    check("deauth reason code parsed",
          any(e["kind"] == "deauth" and e["reason"] == 7 for e in events))

    res = analyze(events, baseline={"HomeNet": ["aa:aa:aa:00:00:01"]})
    types = {d["type"]: d for d in res["detections"]}

    check("deauth flood detected",
          types.get("deauth", {}).get("severity") == "flood",
          json.dumps(types.get("deauth", {})))
    check("deauth attacker identified",
          any(a["src"] == "aa:aa:aa:00:00:01" for a in
              types.get("deauth", {}).get("attackers", [])))
    # 35 fake SSIDs is a flood in a home but below the default (100) threshold;
    # the point of the fix is that beacon flood must be TUNABLE, not fire on
    # raw density. Default => quiet; a lowered threshold => fires.
    check("beacon flood NOT flagged at default threshold (35 < 100)",
          "beacon_flood" not in types, str(types.get("beacon_flood")))
    res_low = analyze(events, thresholds={"beacon_ssids": 25})
    check("beacon flood fires when threshold is lowered",
          any(d["type"] == "beacon_flood" for d in res_low["detections"]),
          json.dumps([d.get("detail") for d in res_low["detections"]]))
    check("airspace counts reported for calibration",
          res["airspace"]["ssids"] >= 35
          and res["airspace"]["beacon_ssid_threshold"] == _BEACON_FLOOD_SSIDS,
          json.dumps(res["airspace"]))
    # A dense-but-legit airspace (many SSIDs from GLOBAL/vendor MACs) must NOT
    # trip beacon flood at the default threshold — this is the user's false pos.
    dense = [{"kind": "beacon", "src": "00:1a:2b:%02x:%02x:00" % (i // 256, i % 256),
              "ssid": "Neighbour_%d" % i} for i in range(60)]
    dense_res = analyze(dense, baseline={})
    check("dense legit airspace is NOT a beacon flood (default)",
          not any(d["type"] == "beacon_flood" for d in dense_res["detections"]),
          json.dumps([d["detail"] for d in dense_res["detections"]]))
    check("KARMA detected", "karma" in types and types["karma"]["ssid_count"] >= 5,
          str(types.get("karma")))
    check("evil twin detected against baseline",
          types.get("rogue_ap", {}).get("severity") == "evil_twin"
          and "99:99:99:99:99:99" in types.get("rogue_ap", {}).get("rogue_bssids", []),
          str(types.get("rogue_ap")))
    check("overall threat = critical", res["threat"] == "critical", res["threat"])

    # Clean traffic => no detections
    from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt
    clean = []
    for p in [(RadioTap(dBm_AntSignal=-40, ChannelFrequency=2437) /
               Dot11(type=0, subtype=8, addr2="aa:aa:aa:00:00:01",
                     addr3="aa:aa:aa:00:00:01") /
               Dot11Beacon() / Dot11Elt(ID=0, info=b"HomeNet"))] * 3:
        ev = _frame_to_event(p)
        if ev:
            clean.append(ev)
    clean_res = analyze(clean, baseline={"HomeNet": ["aa:aa:aa:00:00:01"]})
    check("clean traffic => no detections", clean_res["threat"] == "clear",
          json.dumps(clean_res["detections"]))

    # --- Baseline merge/accumulate (the trust fix) — temp state file ---
    global _STATE_FILE
    _orig_state, _STATE_FILE = _STATE_FILE, __import__("tempfile").mktemp(suffix=".json")
    try:
        clear_baseline()
        # First trust: HomeNet on its 2.4 GHz BSSID (one capture window).
        set_baseline({"HomeNet": ["aa:aa:aa:00:00:01"]})
        # Second trust later sees the SAME SSID from its 5 GHz BSSID.
        set_baseline({"HomeNet": ["aa:aa:aa:00:00:02"]})
        base = get_baseline()
        check("baseline merges BSSIDs across trusts (multi-band SSID)",
              set(base.get("HomeNet", [])) == {"aa:aa:aa:00:00:01", "aa:aa:aa:00:00:02"},
              json.dumps(base))
        # A later scan seeing both trusted BSSIDs must NOT flag an evil twin.
        seen_events = [
            {"kind": "beacon", "src": "aa:aa:aa:00:00:01", "ssid": "HomeNet"},
            {"kind": "beacon", "src": "aa:aa:aa:00:00:02", "ssid": "HomeNet"},
        ]
        r_ok = analyze(seen_events, baseline=get_baseline())
        check("no evil-twin false positive once both BSSIDs are trusted",
              not any(d["type"] == "rogue_ap" for d in r_ok["detections"]),
              json.dumps(r_ok["detections"]))
        # trust_aps trusts a shown inventory (case-insensitive) without capture.
        trust_aps([{"ssid": "Cafe", "bssid": "BB:BB:BB:00:00:01"}])
        check("trust_aps stores shown APs lowercased",
              get_baseline().get("Cafe") == ["bb:bb:bb:00:00:01"],
              json.dumps(get_baseline().get("Cafe")))
        check("clear_baseline empties it", clear_baseline() == {} and get_baseline() == {})
        # Tunable thresholds persist and survive a baseline clear.
        set_thresholds(beacon_ssids=250)
        check("threshold persists and is clamped/read back",
              get_thresholds()["beacon_ssids"] == 250)
        set_baseline({"X": ["aa:bb:cc:dd:ee:ff"]})
        check("threshold survives a later baseline write",
              get_thresholds()["beacon_ssids"] == 250)
    finally:
        try:
            os.unlink(_STATE_FILE)
        except OSError:
            pass
        _STATE_FILE = _orig_state

    passed = sum(1 for r in results if r["pass"])
    return {"pass": passed == len(results), "passed": passed,
            "total": len(results), "results": results}


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _main(argv):
    import argparse
    ap = argparse.ArgumentParser(description="802.11 frame monitor / WIDS")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("interfaces")
    pm = sub.add_parser("monitor")
    pm.add_argument("--interface", required=True)
    pm.add_argument("--enable", action="store_true")
    pm.add_argument("--disable", action="store_true")
    ps = sub.add_parser("scan")
    ps.add_argument("--interface", required=True)
    ps.add_argument("--seconds", type=int, default=15)
    ps.add_argument("--channel", type=int, default=None)
    pb = sub.add_parser("baseline")
    pb.add_argument("--interface", required=True)
    pb.add_argument("--seconds", type=int, default=20)
    sub.add_parser("selftest")

    args = ap.parse_args(argv)
    if args.cmd == "interfaces":
        print(json.dumps(list_monitor_capable(), indent=2))
    elif args.cmd == "monitor":
        if args.disable:
            print(json.dumps(disable_monitor(), indent=2))
        else:
            print(json.dumps(enable_monitor(args.interface), indent=2))
    elif args.cmd == "scan":
        print(json.dumps(do_scan(args.interface, args.seconds, args.channel), indent=2))
    elif args.cmd == "baseline":
        print(json.dumps(learn_baseline(args.interface, args.seconds), indent=2))
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
