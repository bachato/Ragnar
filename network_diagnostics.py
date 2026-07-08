"""Network diagnostics endpoints for Ragnar.

Registers a set of /api/net/* routes that wrap standard Linux networking
tools (ping, traceroute, mtr, whois, speedtest, arp-scan, lldpctl, ethtool,
ip, nmcli) and surface the results as JSON for the Network > Diagnostics /
Switch & L2 / Interfaces sub-tabs in the web UI.

The whole module is self-contained (no import from webapp_modern) to avoid a
circular import: webapp_modern imports register_network_diagnostics() and calls
it once with the Flask app. Auth is enforced globally by webapp_modern's
before_request handler, so these routes inherit it automatically.

The Ragnar service runs as root, so the wrapped tools are invoked directly
(no sudo); they still work if the app is ever run as a normal user with the
appropriate sudoers entries.
"""

import bisect
import json
import re
import secrets
import shutil
import subprocess
import ipaddress
import os
import threading
import time
import socket
import tempfile
import urllib.parse
from datetime import datetime

try:
    from flask import request, jsonify
except Exception:  # pragma: no cover - flask always present in the app
    request = None
    jsonify = None

# --------------------------------------------------------------------------
# Input validation — these endpoints run system commands, so user-supplied
# targets/interfaces are strictly validated. Commands are always invoked with
# an argument list (never shell=True), and a leading '-' is rejected so a
# target can't be smuggled in as a tool flag.
# --------------------------------------------------------------------------

_TARGET_RE = re.compile(r'^[A-Za-z0-9._:\-/]{1,255}$')
_IFACE_RE = re.compile(r'^[A-Za-z0-9._@\-]{1,32}$')


def _valid_target(t):
    return bool(t and isinstance(t, str) and t[0] != '-' and _TARGET_RE.match(t))


def _valid_iface(i):
    return bool(i and isinstance(i, str) and i[0] != '-' and _IFACE_RE.match(i))


def _clamp_int(val, default, lo, hi):
    try:
        n = int(val)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, n))


def _run(cmd, timeout=30, env=None):
    """Run a command (list of args) and return {rc, out, err}.

    Never raises: missing binary -> rc 127, timeout -> rc 124.
    """
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env=env)
        return {'rc': r.returncode, 'out': r.stdout, 'err': r.stderr}
    except FileNotFoundError:
        return {'rc': 127, 'out': '',
                'err': f"{cmd[0]}: not installed (run the Ragnar installer/update to add it)"}
    except subprocess.TimeoutExpired:
        return {'rc': 124, 'out': '', 'err': f"{cmd[0]}: timed out after {timeout}s"}
    except Exception as e:  # pragma: no cover - defensive
        return {'rc': 1, 'out': '', 'err': str(e)}


def _have(binname):
    return shutil.which(binname) is not None


# --------------------------------------------------------------------------
# Diagnostics: ping / traceroute / mtr / whois / speedtest
# --------------------------------------------------------------------------

def do_ping(target, count=4):
    count = _clamp_int(count, 4, 1, 15)
    deadline = count + 3
    res = _run(['ping', '-n', '-c', str(count), '-w', str(deadline), target],
               timeout=deadline + 5)
    out = res['out'] or res['err']
    summary = {}
    m = re.search(r'(\d+) packets transmitted, (\d+) received.*?([\d.]+)% packet loss', out, re.S)
    if m:
        summary['transmitted'] = int(m.group(1))
        summary['received'] = int(m.group(2))
        summary['loss_pct'] = float(m.group(3))
    m = re.search(r'=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms', out)
    if m:
        summary['rtt_min'] = float(m.group(1))
        summary['rtt_avg'] = float(m.group(2))
        summary['rtt_max'] = float(m.group(3))
    # ping returns non-zero on 100% loss; treat "ran" as success and let the
    # summary/output convey the result.
    if res['rc'] == 127:
        return {'success': False, 'output': '', 'summary': {},
                'error': 'ping is not installed. Click Install to add it.',
                'missing_tool': 'ping'}
    return {'success': True, 'output': out.strip(), 'summary': summary, 'error': None}


def do_traceroute(target, max_hops=20):
    max_hops = _clamp_int(max_hops, 20, 1, 30)
    res = _run(['traceroute', '-n', '-q', '1', '-w', '2', '-m', str(max_hops), target],
               timeout=max_hops * 3 + 10)
    if res['rc'] == 127:
        return {'success': False, 'output': '',
                'error': 'traceroute is not installed. Click Install to add it.',
                'missing_tool': 'traceroute'}
    return {'success': True, 'output': (res['out'] or res['err']).strip(), 'error': None}


def _local_ipv4_addrs():
    """Set of this host's IPv4 addresses (no CIDR), across all interfaces.
    Used to validate an mtr source ('start point') binding."""
    addrs = set()
    for name in _list_iface_names(include_virtual=True):
        v4, _ = _iface_addrs(name)
        for a in v4:
            addrs.add(a.split('/')[0])
    return addrs


def do_mtr(target, count=5, source=None):
    """Snapshot per-hop loss/latency from this host to `target` over `count`
    probe cycles. `source`, if given, binds the trace to one of this host's
    local IPv4 addresses (mtr -a) so a multi-homed box can choose which
    interface/path the probes leave from."""
    count = _clamp_int(count, 5, 1, 20)
    cmd = ['mtr', '-n', '-r', '-c', str(count)]
    if source:
        try:
            ipaddress.ip_address(source)
        except ValueError:
            return {'success': False, 'error': f'Invalid source IP: {source}'}
        local = _local_ipv4_addrs()
        if source not in local:
            valid = ', '.join(sorted(local)) or 'none'
            return {'success': False,
                    'error': f'Source {source} is not a local address on this host '
                             f'(mtr can only originate from a local IP). Valid: {valid}'}
        cmd += ['-a', source]
    cmd += ['-j', target]
    res = _run(cmd, timeout=count * 3 + 15)
    if res['rc'] == 127:
        return {'success': False,
                'error': 'mtr is not installed. Click Install to add it.',
                'missing_tool': 'mtr'}
    hops = []
    try:
        data = json.loads(res['out'])
        for h in data.get('report', {}).get('hubs', []):
            hops.append({
                'hop': h.get('count'),
                'host': h.get('host'),
                'loss_pct': h.get('Loss%'),
                'sent': h.get('Snt'),
                'last': h.get('Last'),
                'avg': h.get('Avg'),
                'best': h.get('Best'),
                'worst': h.get('Wrst'),
                'stdev': h.get('StDev'),
            })
        return {'success': True, 'hops': hops}
    except (ValueError, KeyError) as e:
        return {'success': False, 'error': f'could not parse mtr output: {e}',
                'output': res['out'] or res['err']}


def do_whois(target):
    res = _run(['whois', target], timeout=25)
    if res['rc'] == 127:
        return {'success': False, 'output': '',
                'error': 'whois is not installed. Click Install to add it.',
                'missing_tool': 'whois'}
    return {'success': True, 'output': (res['out'] or res['err']).strip(), 'error': None}


def do_speedtest():
    """Run a bandwidth test. Supports both the Ookla `speedtest` CLI and the
    python `speedtest-cli`; returns download/upload in Mbps."""
    # Self-heal: if neither client is present, install speedtest-cli on demand.
    # A device updated from the UI may not have finished (or may have missed)
    # background tool provisioning, and the old behaviour was to just error out
    # telling the user to run the installer. Install it here so the button works.
    if not _have('speedtest-cli') and not _have('speedtest'):
        do_install_tool('speedtest-cli')
    if _have('speedtest-cli'):
        res = _run(['speedtest-cli', '--json'], timeout=120)
        if res['rc'] == 0:
            try:
                d = json.loads(res['out'])
                return {'success': True,
                        'download_mbps': round(d.get('download', 0) / 1e6, 2),
                        'upload_mbps': round(d.get('upload', 0) / 1e6, 2),
                        'ping_ms': round(d.get('ping', 0), 2),
                        'server': (d.get('server') or {}).get('sponsor'),
                        'server_location': (d.get('server') or {}).get('name'),
                        'isp': (d.get('client') or {}).get('isp')}
            except ValueError:
                pass
        return {'success': False, 'error': res['err'] or res['out'] or 'speedtest failed'}
    if _have('speedtest'):
        res = _run(['speedtest', '--format=json', '--accept-license', '--accept-gdpr'],
                   timeout=120)
        if res['rc'] == 0:
            try:
                d = json.loads(res['out'])
                dl = d.get('download', {}).get('bandwidth', 0) * 8 / 1e6
                ul = d.get('upload', {}).get('bandwidth', 0) * 8 / 1e6
                return {'success': True,
                        'download_mbps': round(dl, 2),
                        'upload_mbps': round(ul, 2),
                        'ping_ms': round(d.get('ping', {}).get('latency', 0), 2),
                        'server': (d.get('server') or {}).get('name'),
                        'server_location': (d.get('server') or {}).get('location'),
                        'isp': d.get('isp')}
            except ValueError:
                pass
        return {'success': False, 'error': res['err'] or res['out'] or 'speedtest failed'}
    return {'success': False,
            'error': 'speedtest is not installed. Click Install to add it.',
            'missing_tool': 'speedtest-cli'}


# --------------------------------------------------------------------------
# Switch & L2: LLDP/CDP/EDP neighbor discovery + ARP scan
# --------------------------------------------------------------------------

def do_lldp():
    """Return discovered switch neighbors via lldpctl. lldpd (configured with
    -c -e -f -s) also decodes CDPv1/v2 (Cisco), EDP (Extreme), FDP (Foundry)
    and SONMP (Nortel) in addition to LLDP. VLAN id/name are included when the
    neighbor advertises them."""
    if not _have('lldpctl'):
        return {'success': False,
                'error': 'lldpd/lldpctl is not installed. Click Install to add it '
                         '(configured for LLDP + CDPv1/v2, EDP, FDP and SONMP so '
                         'Cisco, Extreme, Foundry and Nortel switches are seen too).',
                'missing_tool': 'lldpd',
                'neighbors': []}
    res = _run(['lldpctl', '-f', 'json'], timeout=15)
    if res['rc'] != 0 and not res['out']:
        return {'success': False, 'error': res['err'] or 'lldpctl failed', 'neighbors': []}
    neighbors = []
    try:
        data = json.loads(res['out'])
        ifaces = data.get('lldp', {}).get('interface', [])
        if isinstance(ifaces, dict):
            ifaces = [ifaces]
        for entry in ifaces:
            for local_if, info in entry.items():
                neighbors.append(_parse_lldp_iface(local_if, info))
    except ValueError as e:
        return {'success': False, 'error': f'could not parse lldpctl output: {e}',
                'neighbors': [], 'output': res['out']}
    return {'success': True, 'neighbors': neighbors,
            'note': ('No neighbors yet? Switches announce every ~30s; give it up '
                     'to a minute after connecting, and ensure the port isn\'t on a hub.')
            if not neighbors else None}


def _first_key(d):
    """lldpctl json nests some objects under a single dynamic key (e.g. the
    chassis name). Return (key, value) of the first item, or (None, {})."""
    if isinstance(d, dict) and d:
        k = next(iter(d))
        return k, d[k]
    return None, {}


def _scalar(v):
    """lldpctl represents values either as a scalar or as {'value': X}."""
    if isinstance(v, dict):
        return v.get('value')
    return v


def _poe_watts(mw):
    """lldpd reports 802.3at/LLDP-MED power values in milliwatts. Convert to
    watts, tolerating strings and junk. Returns a float or None."""
    try:
        w = round(int(str(mw).strip()) / 1000.0, 1)
        return w if 0 < w <= 200 else None  # sanity bound (802.3bt tops out ~90W)
    except (TypeError, ValueError):
        return None


def _poe_class_num(class_str):
    """Pull the numeric class out of an lldpctl class string ('class 4' -> 4)."""
    if not class_str:
        return None
    m = re.search(r'(\d+)', str(class_str))
    return int(m.group(1)) if m else None


def _poe_standard(power_type, class_num):
    """Resolve the PoE standard to a short code (af/at/bt) and a long label.

    802.3bt (Type 3/4) introduced classes 5-8, so any class >=5 is bt. Otherwise
    the dot3 'power-type' field distinguishes Type 2 (802.3at) from Type 1
    (802.3af); when it's absent we fall back to the class (class 4 requires at)."""
    if class_num is not None and class_num >= 5:
        return 'bt', '802.3bt (Type 3/4)'
    pt = str(power_type).strip() if power_type is not None else ''
    if pt.startswith('2'):
        return 'at', '802.3at (Type 2)'
    if pt.startswith('1'):
        return 'af', '802.3af (Type 1)'
    if class_num is not None:
        return ('at', '802.3at (Type 2)') if class_num >= 4 else ('af', '802.3af (Type 1)')
    return None, None


def _parse_poe(port):
    """Extract Power-over-Ethernet state from an lldpctl port's Power-via-MDI
    TLV (dot3 / LLDP-MED). A PoE-capable switch advertises this, so it tells us
    whether the port supplies power and at what class/wattage. Returns None when
    the neighbour advertised no power TLV."""
    if not isinstance(port, dict):
        return None
    power = port.get('power')
    if isinstance(power, list) and power:
        power = power[0]
    if not isinstance(power, dict) or not power:
        return None

    def val(k):
        v = _scalar(power.get(k))
        return str(v).strip() if v is not None else None

    def truthy(v):
        return str(v).strip().lower() in ('yes', 'true', '1', 'on', 'enabled')

    device_type = val('device-type') or val('device_type')
    enabled = val('enabled')
    supported = val('supported')
    ptype = val('power-type') or val('power_type')
    class_str = val('class')
    class_num = _poe_class_num(class_str)
    poe_type, standard = _poe_standard(ptype, class_num)
    allocated_w = _poe_watts(power.get('allocated') if isinstance(power.get('allocated'), (str, int)) else _scalar(power.get('allocated')))
    requested_w = _poe_watts(power.get('requested') if isinstance(power.get('requested'), (str, int)) else _scalar(power.get('requested')))
    # The switch port is a PSE (Power Sourcing Equipment) and power is enabled
    # => it is delivering, or ready to deliver, PoE to us.
    powered = bool(device_type and device_type.upper() == 'PSE' and truthy(enabled))

    # Active vs passive: an LLDP Power-via-MDI TLV means the PSE does 802.3
    # detection/classification handshaking, i.e. ACTIVE (standards) PoE. Passive
    # PoE injectors put voltage straight on the wire with no negotiation and no
    # TLV, so they are undetectable from the PD side over LLDP -- we can only
    # affirm 'active', never confirm 'passive' here.
    mode = 'active'

    # EndSpan vs MidSpan: not an explicit LLDP field, but the powered pairs are
    # a strong hint. Alternative A (data pairs / 'signal') is how switch-
    # integrated PSEs (endspan) deliver power; Alternative B (spare pairs /
    # 'spare') is the classic mid-span injector. Best-effort; 802.3at/bt drive
    # all four pairs so treat this as indicative, not definitive.
    pairs = val('pairs')
    power_via = None
    if pairs:
        p = pairs.lower()
        if 'spare' in p:
            power_via = 'midspan'
        elif 'signal' in p or 'both' in p:
            power_via = 'endspan'

    return {
        'device_type': device_type,          # PSE (switch) or PD (powered device)
        'supported': truthy(supported) if supported is not None else None,
        'enabled': truthy(enabled) if enabled is not None else None,
        'powered': powered,
        'type': poe_type,                     # af / at / bt
        'mode': mode,                         # active (passive not LLDP-detectable)
        'power_via': power_via,               # endspan (switch) / midspan (injector)
        'class': class_str,
        'class_num': class_num,
        'standard': standard,
        'pairs': pairs,
        'allocated_w': allocated_w,
        'requested_w': requested_w,
    }


def _parse_lldp_iface(local_if, info):
    via = info.get('via') or info.get('protocol')
    chassis = info.get('chassis', {})
    ch_name, ch = _first_key(chassis) if isinstance(chassis, dict) and 'id' not in chassis else (None, chassis)
    if ch_name is None and isinstance(chassis, dict):
        ch = chassis
    port = info.get('port', {})
    vlan = info.get('vlan', {})
    vlan_id = None
    vlan_name = None
    if isinstance(vlan, list) and vlan:
        vlan = vlan[0]
    if isinstance(vlan, dict):
        vlan_id = vlan.get('vlan-id') or vlan.get('vlan_id') or _scalar(vlan)
        vlan_name = vlan.get('value') if isinstance(vlan.get('value'), str) else None
    mgmt = ch.get('mgmt-ip') if isinstance(ch, dict) else None
    if isinstance(mgmt, list):
        mgmt = ', '.join(str(x) for x in mgmt)
    return {
        'local_interface': local_if,
        'protocol': via,
        'switch_name': ch_name or (_scalar(ch.get('name')) if isinstance(ch, dict) else None),
        'switch_descr': _scalar(ch.get('descr')) if isinstance(ch, dict) else None,
        'mgmt_ip': mgmt,
        'port_id': _scalar(port.get('id')) if isinstance(port, dict) else None,
        'port_descr': _scalar(port.get('descr')) if isinstance(port, dict) else None,
        'vlan_id': vlan_id,
        'vlan_name': vlan_name,
        'poe': _parse_poe(port),
    }


def do_arp_scan(interface):
    if not _have('arp-scan'):
        return {'success': False,
                'error': 'arp-scan is not installed. Click Install to add it.',
                'missing_tool': 'arp-scan', 'hosts': []}
    res = _run(['arp-scan', f'--interface={interface}', '--localnet'], timeout=40)
    if res['rc'] == 127:
        return {'success': False, 'error': res['err'] or 'arp-scan not found',
                'missing_tool': 'arp-scan', 'hosts': []}
    hosts = []
    for line in res['out'].splitlines():
        m = re.match(r'^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s*(.*)$', line)
        if m:
            hosts.append({'ip': m.group(1), 'mac': m.group(2),
                          'vendor': m.group(3).strip() or None})
    return {'success': True, 'hosts': hosts, 'count': len(hosts), 'interface': interface}


# --------------------------------------------------------------------------
# ARP spoofing / poisoning detection: watch the gateway's IP->MAC binding
# against a learned baseline (a MITM inserting itself changes it), and flag a
# single MAC answering for many IPs (one host impersonating the whole subnet).
# The kernel neighbour table is authoritative and needs no capture, so this is
# cheap enough to run on a schedule from the integrity monitor.
# --------------------------------------------------------------------------

_ARP_BASELINE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  'data', 'arp_baseline.json')
_arp_baseline_lock = threading.Lock()
# A MAC bound to at least this many IPs in the neighbour table is treated as a
# possible impersonator. Proxy-ARP routers can legitimately answer for a few, so
# keep the floor above normal noise.
_ARP_IMPERSONATOR_MIN_IPS = 4


def _neigh_entries():
    """Parse `ip -4 neigh` into [(ip, mac, state)] for entries with a lladdr."""
    res = _run(['ip', '-4', 'neigh', 'show'], timeout=5)
    out = []
    for line in res['out'].splitlines():
        m = re.match(r'^(\d+\.\d+\.\d+\.\d+)\b.*?\blladdr\s+([0-9a-fA-F:]{17})\s+(\w+)', line)
        if m:
            out.append((m.group(1), m.group(2).lower(), m.group(3)))
    return out


def _neigh_mac(ip):
    """Current MAC bound to `ip` in the kernel neighbour table, or None. Sends a
    single ping first if the entry is missing, to populate it."""
    if not ip:
        return None
    for i, mac, _ in _neigh_entries():
        if i == ip:
            return mac
    _run(['ping', '-n', '-c', '1', '-W', '1', ip], timeout=3)
    for i, mac, _ in _neigh_entries():
        if i == ip:
            return mac
    return None


def _arp_baseline_load():
    try:
        with open(_ARP_BASELINE_PATH) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _arp_baseline_save(d):
    try:
        os.makedirs(os.path.dirname(_ARP_BASELINE_PATH), exist_ok=True)
        tmp = _ARP_BASELINE_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, _ARP_BASELINE_PATH)
    except OSError:
        pass


def do_arp_baseline(action='get'):
    """Manage the trusted gateway IP->MAC baseline the spoof check compares
    against. action='reset' clears it so the current binding is re-learned on
    the next check (use after a legitimate router/gateway change)."""
    with _arp_baseline_lock:
        if action == 'reset':
            _arp_baseline_save({})
            return {'success': True, 'reset': True, 'gateways': {}}
        return {'success': True, 'gateways': (_arp_baseline_load().get('gateways') or {})}


def do_arp_check(interface=None, learn=True):
    """Detect ARP spoofing / poisoning from the kernel neighbour table.

    Signals: (1) the default gateway's MAC no longer matches the trusted
    baseline — the classic MITM signature (an attacker ARP-replies as the
    gateway to intercept traffic); (2) one MAC answering for many IPs — a host
    impersonating much of the subnet. First run learns the gateway baseline.

    verdict: 'spoofed'    -- gateway MAC changed from the trusted baseline
             'suspicious' -- a MAC is impersonating several IPs
             'clean'      -- gateway matches baseline, no impersonators
             'unknown'    -- no gateway, or its MAC couldn't be resolved"""
    gw = _default_gateway()
    if not gw:
        return {'success': True, 'verdict': 'unknown', 'gateway': None,
                'reasons': ['no default gateway on this host — nothing to check'],
                'impersonators': [], 'neighbor_count': 0}

    gw_mac = _neigh_mac(gw)
    reasons = []
    verdict = 'clean'
    learned = False
    with _arp_baseline_lock:
        baseline = _arp_baseline_load()
        gws = baseline.setdefault('gateways', {})
        base_mac = gws.get(gw)
        if gw_mac and not base_mac and learn:
            gws[gw] = gw_mac
            _arp_baseline_save(baseline)
            base_mac = gw_mac
            learned = True

    if not gw_mac:
        verdict = 'unknown'
        reasons.append(f'could not resolve the gateway {gw} MAC (no ARP reply)')
    elif base_mac and gw_mac != base_mac:
        verdict = 'spoofed'
        reasons.append(f'gateway {gw} MAC changed from trusted {base_mac} to {gw_mac} '
                       '— classic ARP-spoofing / MITM signature')

    # One MAC claiming many IPs (attacker impersonating multiple hosts). The
    # gateway MAC is excluded — a router legitimately fronts its own address.
    entries = _neigh_entries()
    mac_ips = {}
    for ip, mac, _ in entries:
        mac_ips.setdefault(mac, set()).add(ip)
    impersonators = [{'mac': mac, 'ips': sorted(ips)}
                     for mac, ips in mac_ips.items()
                     if len(ips) >= _ARP_IMPERSONATOR_MIN_IPS and mac != gw_mac]
    if impersonators:
        if verdict == 'clean':
            verdict = 'suspicious'
        for imp in impersonators:
            ips = imp['ips']
            reasons.append(f"MAC {imp['mac']} answers for {len(ips)} IPs "
                           f"({', '.join(ips[:4])}{'…' if len(ips) > 4 else ''}) "
                           '— possible ARP spoofing')

    return {'success': True, 'verdict': verdict,
            'gateway': {'ip': gw, 'mac': gw_mac, 'baseline': base_mac,
                        'learned': learned},
            'impersonators': impersonators,
            'neighbor_count': len(entries),
            'reasons': reasons}


# --------------------------------------------------------------------------
# MAC Watch — detection-only MAC-spoofing + randomization detector & tracker.
#
# Three jobs, all passive (reads the kernel neighbour table, optionally an
# arp-scan sweep — no capture, and it never spoofs anything itself):
#   1. Spoofing / cloning: a vendor OUI wearing the locally-administered bit
#      (disguised vendor), the same MAC bound to several IPs (a clone), and an
#      IP whose MAC changed identity over time (the past-spoofing signature).
#   2. Randomization: privacy (locally-administered, vendor-less) MACs on the
#      segment, reported as an aggregate inventory rather than per-MAC noise so
#      a busy Wi-Fi segment full of iPhones doesn't drown a real spoof.
#   3. Tracking: an IP that cycles through several randomized MACs over time is
#      one device rotating to hide — grouped into a track so it can be followed
#      across the addresses it hides behind.
#
# A small JSON store keeps first/last-seen, per-IP MAC history and change
# events, so "current AND past" spoofing/rotation survives across checks and
# restarts. True cross-MAC device tracking on a switched/Wi-Fi segment needs
# probe-request fingerprinting (monitor-mode only); this IP-anchored version is
# the honest, capture-free approximation and is labelled as such in the UI.
# --------------------------------------------------------------------------

_MAC_WATCH_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'data', 'mac_watch.json')
_mac_watch_lock = threading.Lock()

# A randomized MAC seen within this window counts as "current" segment activity.
_MAC_WATCH_WINDOW_S = 24 * 3600
# A randomized MAC whose whole lifetime was shorter than this is "ephemeral" —
# the fingerprint of active privacy rotation (device changing address rapidly).
_MAC_EPHEMERAL_S = 15 * 60
# Keep at most this many change events in the store (newest wins).
_MAC_EVENTS_CAP = 200
# One MAC bound to at least this many distinct IPs at once is a clone candidate.
_MAC_CLONE_MIN_IPS = 2

# Locally-administered VM / container prefixes — tracked apart from privacy
# randomization so virtual NICs don't inflate the randomized count or look like
# a spoof. Keyed by the leading octets (lowercase, colon-separated).
_MAC_VIRTUAL_PREFIXES = {
    '02:42': 'Docker',
    '52:54:00': 'QEMU/KVM',
    '0a:00:27': 'VirtualBox host-only',
    '02:00:4c': 'Microsoft NDIS loopback',
    '02:50:41': 'Parallels',
}

# Always-present universal (LAA-clear) vendor OUI seed, used even when the
# arp-scan / nmap OUI database isn't installed. Only universal prefixes belong
# here — a prefix with the locally-administered bit set can never be a
# legitimately-registered OUI, and seeding one would make it read as a spoof.
_MAC_VENDOR_SEED = {
    'b8:27:eb': 'Raspberry Pi', 'dc:a6:32': 'Raspberry Pi',
    'e4:5f:01': 'Raspberry Pi', 'd8:3a:dd': 'Raspberry Pi',
    '2c:cf:67': 'Raspberry Pi', '28:cd:c1': 'Raspberry Pi',
    '3c:22:fb': 'Apple', 'a4:83:e7': 'Apple', 'f0:18:98': 'Apple',
    '00:1b:63': 'Apple', 'ac:bc:32': 'Apple', '90:9c:4a': 'Apple',
    '00:50:56': 'VMware', '00:0c:29': 'VMware', '00:05:69': 'VMware',
    '08:00:27': 'VirtualBox', '00:15:5d': 'Microsoft Hyper-V',
    '00:16:6c': 'Samsung', 'e8:50:8b': 'Samsung', '5c:0a:5b': 'Samsung',
    '3c:97:0e': 'Intel', '00:1b:21': 'Intel', '34:13:e8': 'Intel',
    '00:1a:a1': 'Cisco', '00:1b:0d': 'Cisco',
    '50:c7:bf': 'TP-Link', 'a4:2b:b0': 'TP-Link', 'c0:06:c3': 'TP-Link',
    '00:14:6c': 'Netgear', '20:e5:2a': 'Netgear',
    '24:0a:c4': 'Espressif', '30:ae:a4': 'Espressif',
    '7c:9e:bd': 'Espressif', 'a0:20:a6': 'Espressif',
    '00:e0:fc': 'Huawei', 'ec:b5:fa': 'Philips',
}

_OUI_DB_PATHS = ('/usr/share/arp-scan/ieee-oui.txt',
                 '/usr/share/nmap/nmap-mac-prefixes')
# Cap the loaded OUI table so a pathological file can't blow memory.
_OUI_DB_CAP = 60000
_oui_db_cache = None
_oui_db_lock = threading.Lock()


def _mac_norm(mac):
    """Normalise a MAC to lowercase colon form, or None if it isn't a MAC."""
    if not mac or not isinstance(mac, str):
        return None
    hexs = re.sub(r'[^0-9a-fA-F]', '', mac)
    if len(hexs) != 12:
        return None
    hexs = hexs.lower()
    return ':'.join(hexs[i:i + 2] for i in range(0, 12, 2))


def _mac_first_octet(mac):
    try:
        return int(mac[0:2], 16)
    except (ValueError, TypeError):
        return None


def _is_laa(mac):
    """True if the locally-administered (privacy/spoof) bit is set."""
    b0 = _mac_first_octet(mac)
    return b0 is not None and bool(b0 & 0x02)


def _is_universal_prefix(oui):
    """True if a 6-hex OUI could be a legitimately-registered (LAA-clear) OUI.
    Filters junk out of the vendor table so an LAA/randomization range in a full
    manuf file can't be mistaken for a real vendor by the spoof check."""
    try:
        b0 = int(oui[0:2], 16)
    except (ValueError, TypeError, IndexError):
        return False
    return not (b0 & 0x02) and not (b0 & 0x01)


def _load_oui_db():
    """Load {6-hex-prefix: vendor} from the arp-scan / nmap OUI DB if present,
    merged over the built-in seed. Universal prefixes only; cached."""
    global _oui_db_cache
    if _oui_db_cache is not None:
        return _oui_db_cache
    with _oui_db_lock:
        if _oui_db_cache is not None:
            return _oui_db_cache
        db = {}
        for oui, vendor in _MAC_VENDOR_SEED.items():
            db[oui.replace(':', '')] = vendor
        for path in _OUI_DB_PATHS:
            try:
                with open(path, encoding='utf-8', errors='replace') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        parts = re.split(r'\s+', line, maxsplit=1)
                        if len(parts) != 2:
                            continue
                        pfx = re.sub(r'[^0-9a-fA-F]', '', parts[0]).lower()
                        if len(pfx) < 6:
                            continue
                        pfx = pfx[:6]
                        if not _is_universal_prefix(pfx):
                            continue
                        db.setdefault(pfx, parts[1].strip())
                        if len(db) >= _OUI_DB_CAP:
                            break
            except OSError:
                continue
            if len(db) >= _OUI_DB_CAP:
                break
        _oui_db_cache = db
        return db


def _vendor_for_prefix(prefix6):
    return _load_oui_db().get(prefix6)


def _classify_mac(mac):
    """Classify one MAC. Returns {klass, vendor, note}.

    klass ∈ {'universal', 'spoofed_vendor_oui', 'virtual_laa', 'randomized',
             'invalid'}. A universal address is a normal burned-in NIC; the
    three LAA buckets are kept distinct so privacy randomization (benign, an
    aggregate) never gets conflated with a vendor OUI wearing the LAA bit
    (impersonation) or with a VM/container NIC."""
    m = _mac_norm(mac)
    if not m:
        return {'klass': 'invalid', 'vendor': None, 'note': 'not a MAC'}
    b0 = _mac_first_octet(m)
    prefix6 = m.replace(':', '')[:6]
    if b0 & 0x01:  # multicast/broadcast — never a valid source address
        return {'klass': 'invalid', 'vendor': None, 'note': 'multicast/broadcast'}
    if not (b0 & 0x02):  # universal — legitimately-registered OUI
        vendor = _vendor_for_prefix(prefix6)
        return {'klass': 'universal', 'vendor': vendor, 'note': None}
    # Locally-administered: virtual, disguised-vendor, or privacy randomization.
    for pfx, name in _MAC_VIRTUAL_PREFIXES.items():
        if m.startswith(pfx):
            return {'klass': 'virtual_laa', 'vendor': name, 'note': 'VM/container NIC'}
    # Clear the LAA bit and see whether the underlying OUI is a real vendor — a
    # registered vendor OUI can't legitimately carry the LAA bit, so this is the
    # impersonation signature (a spoofer picked a plausible vendor prefix).
    deladdr = '%02x%s' % (b0 & ~0x02, prefix6[2:])
    vendor = _vendor_for_prefix(deladdr)
    if vendor:
        return {'klass': 'spoofed_vendor_oui', 'vendor': vendor,
                'note': f'vendor OUI ({vendor}) with the locally-administered bit set'}
    return {'klass': 'randomized', 'vendor': None, 'note': 'privacy-randomized MAC'}


def _local_macs():
    """Own NIC MACs, so this host's interfaces are never counted or flagged."""
    macs = set()
    res = _run(['ip', '-o', 'link', 'show'], timeout=5)
    for m in re.finditer(r'link/\w+\s+([0-9a-fA-F:]{17})', res['out']):
        norm = _mac_norm(m.group(1))
        if norm:
            macs.add(norm)
    return macs


def _mac_watch_load():
    try:
        with open(_MAC_WATCH_PATH) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _mac_watch_save(d):
    try:
        os.makedirs(os.path.dirname(_MAC_WATCH_PATH), exist_ok=True)
        tmp = _MAC_WATCH_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, _MAC_WATCH_PATH)
    except OSError:
        pass


def _fmt_ago(seconds):
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f'{seconds}s ago'
    if seconds < 3600:
        return f'{seconds // 60}m ago'
    if seconds < 86400:
        return f'{seconds // 3600}h ago'
    return f'{seconds // 86400}d ago'


def do_mac_watch_reset():
    """Clear the MAC-watch history (first/last-seen, per-IP history, events)."""
    with _mac_watch_lock:
        _mac_watch_save({})
    return {'success': True, 'reset': True}


def do_mac_watch(scan=True, interface=None):
    """Detect current + past MAC spoofing/cloning and randomization, and track
    devices that rotate randomized MACs. Detection-only; nothing is spoofed.

    scan=True adds an arp-scan sweep (active but harmless) to widen coverage
    beyond whatever is already in the neighbour table; scan=False reads the
    neighbour table only (works unprivileged, no traffic generated)."""
    now = time.time()
    gw = _default_gateway()
    gw_mac = _neigh_mac(gw) if gw else None
    local = _local_macs()

    # Current (ip, mac) observations from the neighbour table, optionally
    # widened by an arp-scan sweep. Deduped; own-NIC MACs dropped.
    seen = {}  # mac -> set(ips)
    for ip, mac, _state in _neigh_entries():
        m = _mac_norm(mac)
        if m and m not in local:
            seen.setdefault(m, set()).add(ip)
    scan_iface = None       # interface the arp-scan sweep actually ran on
    scanned = False         # whether an arp-scan sweep was performed
    if scan and _have('arp-scan'):
        scan_iface = interface if _valid_iface(interface or '') else _default_route_iface()
        if scan_iface:
            scanned = True
            sweep = do_arp_scan(scan_iface)
            for h in (sweep.get('hosts') or []):
                m = _mac_norm(h.get('mac'))
                if m and m not in local:
                    seen.setdefault(m, set()).add(h.get('ip'))

    # Classify every currently-seen MAC.
    current = []
    for mac, ips in seen.items():
        info = _classify_mac(mac)
        if info['klass'] == 'invalid':
            continue
        current.append({'mac': mac, 'ips': sorted(i for i in ips if i),
                        'klass': info['klass'], 'vendor': info['vendor'],
                        'note': info['note']})

    # --- update the persistent store (this is what makes "past" possible) ----
    with _mac_watch_lock:
        store = _mac_watch_load()
        macs = store.setdefault('macs', {})
        ip_hist = store.setdefault('ip_history', {})
        events = store.setdefault('events', [])

        for c in current:
            rec = macs.setdefault(c['mac'], {'first': now, 'count': 0,
                                             'ips': [], 'klass': c['klass'],
                                             'vendor': c['vendor']})
            rec['last'] = now
            rec['count'] = rec.get('count', 0) + 1
            rec['klass'] = c['klass']
            rec['vendor'] = c['vendor']
            rec['ips'] = sorted(set(rec.get('ips', [])) | set(c['ips']))
            # Per-IP identity history — a change here is the past-spoof signal.
            for ip in c['ips']:
                hist = ip_hist.setdefault(ip, [])
                if not hist or hist[-1]['mac'] != c['mac']:
                    if hist and hist[-1]['mac'] != c['mac']:
                        old = hist[-1]
                        oc = _classify_mac(old['mac'])
                        # A randomized<->randomized flip on one IP is ordinary
                        # privacy rotation (DHCP re-lease); only flag identity
                        # changes that involve a real/burned-in vendor address.
                        privacy_only = (oc['klass'] in ('randomized', 'virtual_laa')
                                        and c['klass'] in ('randomized', 'virtual_laa'))
                        events.append({
                            'ts': now, 'ip': ip,
                            'old_mac': old['mac'], 'new_mac': c['mac'],
                            'old_klass': oc['klass'], 'new_klass': c['klass'],
                            'severity': 'low' if privacy_only else 'high',
                        })
                    hist.append({'mac': c['mac'], 'first': now, 'last': now})
                else:
                    hist[-1]['last'] = now
                # Bound per-IP history growth.
                if len(hist) > 40:
                    del hist[:len(hist) - 40]

        if len(events) > _MAC_EVENTS_CAP:
            del events[:len(events) - _MAC_EVENTS_CAP]
        _mac_watch_save(store)

    # --- assemble findings ---------------------------------------------------
    reasons = []
    verdict = 'clean'

    # (1) Disguised-vendor spoofs seen right now.
    spoofed = [c for c in current if c['klass'] == 'spoofed_vendor_oui']
    for c in spoofed:
        reasons.append(f"{c['mac']} is a {c['vendor']} vendor OUI with the "
                       f"locally-administered bit set — MAC-spoofing signature "
                       f"(IP {', '.join(c['ips']) or 'unknown'})")

    # (2) Clones — one MAC currently bound to several IPs (gateway excluded).
    clones = [c for c in current
              if len(c['ips']) >= _MAC_CLONE_MIN_IPS and c['mac'] != gw_mac]
    for c in clones:
        reasons.append(f"{c['mac']} answers for {len(c['ips'])} IPs "
                       f"({', '.join(c['ips'][:4])}"
                       f"{'…' if len(c['ips']) > 4 else ''}) — cloned/duplicated MAC")

    # (3) Past spoofing — identity changes on an IP within the window.
    with _mac_watch_lock:
        events = (_mac_watch_load().get('events') or [])
    recent_events = [e for e in events if now - e.get('ts', 0) <= _MAC_WATCH_WINDOW_S]
    hi_events = [e for e in recent_events if e.get('severity') == 'high']
    for e in hi_events[-8:]:
        reasons.append(f"IP {e['ip']} changed MAC {e['old_mac']} → {e['new_mac']} "
                       f"({_fmt_ago(now - e['ts'])}) — possible spoof/clone in the past")

    # (4) Randomization inventory (aggregate, not per-MAC).
    randomized = [c for c in current if c['klass'] == 'randomized']
    virtual = [c for c in current if c['klass'] == 'virtual_laa']
    with _mac_watch_lock:
        macs_store = (_mac_watch_load().get('macs') or {})
    ephemeral = 0
    for mac, rec in macs_store.items():
        if rec.get('klass') != 'randomized':
            continue
        life = rec.get('last', 0) - rec.get('first', 0)
        if 0 <= life < _MAC_EPHEMERAL_S and rec.get('count', 0) >= 1:
            ephemeral += 1
    randomization = {
        'count': len(randomized),
        'ephemeral': ephemeral,
        'virtual': len(virtual),
        'macs': [c['mac'] for c in randomized],
        'virtual_macs': [{'mac': c['mac'], 'vendor': c['vendor']} for c in virtual],
    }
    if randomized:
        note = (f"{len(randomized)} randomized (privacy) MAC(s) on the segment"
                + (f", {ephemeral} short-lived (active rotation)" if ephemeral else ""))
        reasons.append(note)

    # (5) Tracking — an IP that cycled through >=2 randomized MACs is one device
    # rotating to hide. Group its randomized addresses into a followable track.
    tracks = []
    with _mac_watch_lock:
        ip_hist = (_mac_watch_load().get('ip_history') or {})
    for ip, hist in ip_hist.items():
        rand_macs, first, last = [], None, None
        for h in hist:
            if _classify_mac(h['mac'])['klass'] == 'randomized':
                rand_macs.append(h['mac'])
                first = h['first'] if first is None else min(first, h['first'])
                last = h['last'] if last is None else max(last, h['last'])
        uniq = sorted(set(rand_macs))
        if len(uniq) >= 2 and last and now - last <= _MAC_WATCH_WINDOW_S:
            tracks.append({'ip': ip, 'macs': uniq, 'changes': len(uniq) - 1,
                           'first': first, 'last': last,
                           'span': _fmt_ago(now - first) if first else None})
    tracks.sort(key=lambda t: len(t['macs']), reverse=True)
    for t in tracks[:6]:
        reasons.append(f"device at {t['ip']} rotated through {len(t['macs'])} "
                       f"randomized MACs — tracked across its address changes")

    if spoofed or clones or hi_events:
        verdict = 'spoofed'
    elif tracks or randomized:
        verdict = 'suspicious' if tracks else 'randomization'

    return {
        'success': True, 'verdict': verdict,
        'summary': {
            'observed': len(current),
            'spoofed': len(spoofed),
            'clones': len(clones),
            'past_events': len(hi_events),
            'randomized': len(randomized),
            'virtual': len(virtual),
            'tracks': len(tracks),
        },
        'spoofed': spoofed,
        'clones': clones,
        # Every MAC seen this pass, worst class first, so the UI can list them.
        'observed_macs': sorted(
            current,
            key=lambda c: ({'spoofed_vendor_oui': 0, 'universal': 1,
                            'randomized': 2, 'virtual_laa': 3}.get(c['klass'], 4),
                           c['ips'][0] if c['ips'] else '', c['mac'])),
        'events': [dict(e, ago=_fmt_ago(now - e['ts'])) for e in recent_events[-20:]][::-1],
        'randomization': randomization,
        'tracks': tracks,
        'gateway': {'ip': gw, 'mac': gw_mac},
        'interface': scan_iface,
        'scanned': scanned,
        'source': (f'arp-scan sweep on {scan_iface}' if scanned
                   else 'neighbour table (all interfaces)'),
        'oui_db': bool(len(_load_oui_db()) > len(_MAC_VENDOR_SEED)),
        'reasons': reasons,
    }


# --------------------------------------------------------------------------
# DHCP Guardian — DHCP-snooping-style monitor (detection-only).
#
# The DHCP layer is the one L2 service Ragnar hadn't covered, and it's arguably
# the second-highest-value one after DNS: whoever answers DHCP hands you your
# gateway and DNS, so a rogue DHCP server is a turnkey man-in-the-middle. Two
# jobs, both passive/harmless (it never runs a DHCP server or hands out leases):
#
#   1. Rogue / fake DHCP server — an active `broadcast-dhcp-discover` provokes
#      *every* DHCP server on the segment to OFFER. More than one distinct
#      server, or a server offering a gateway/DNS that differs from the trusted
#      one, is the rogue-server / MITM signature. The offered gateway's MAC is
#      cross-checked against the ARP baseline (do_arp_check) so a DHCP steer
#      backed by ARP spoofing reads as one combined finding.
#   2. DHCP starvation — a short passive tcpdump capture counts client DISCOVER/
#      REQUEST messages and the distinct client hardware addresses behind them;
#      a burst of many distinct chaddrs in a few seconds is the pool-exhaustion
#      signature (the classic precursor that clears the field for the rogue).
#
# A trusted-server baseline (data/dhcp_baseline.json) is learned on first run —
# like the ARP baseline — so a *new* server or a *changed* offered gateway is
# flagged even against an otherwise-quiet segment. verdict: clean / suspicious /
# rogue / starvation.
# --------------------------------------------------------------------------

_DHCP_BASELINE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   'data', 'dhcp_baseline.json')
_dhcp_baseline_lock = threading.Lock()

# Distinct client hardware addresses seen in the capture window at or above
# which we call it starvation (a normal segment shows a handful at most).
_DHCP_STARV_MIN_CLIENTS = 12
# nmap's per-server OFFER wait; long enough for a slow server to answer, short
# enough to keep the whole scan bounded.
_DHCP_DISCOVER_TIMEOUT_S = 8


def _dhcp_baseline_load():
    try:
        with open(_DHCP_BASELINE_PATH) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _dhcp_baseline_save(d):
    try:
        os.makedirs(os.path.dirname(_DHCP_BASELINE_PATH), exist_ok=True)
        tmp = _DHCP_BASELINE_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, _DHCP_BASELINE_PATH)
    except OSError:
        pass


def do_dhcp_baseline(action='get'):
    """Manage the trusted DHCP-server baseline the rogue check compares against.
    action='reset' clears it so the current server(s) are re-learned on the next
    scan (use after a legitimate DHCP-server/gateway change)."""
    with _dhcp_baseline_lock:
        if action == 'reset':
            _dhcp_baseline_save({})
            return {'success': True, 'reset': True, 'servers': {}}
        return {'success': True, 'servers': (_dhcp_baseline_load().get('servers') or {})}


def _parse_dhcp_discover(output):
    """Parse `nmap --script broadcast-dhcp-discover` output into a list of
    OFFERs: {server_id, router, dns[], offered_ip, lease, domain, iface}. Each
    'Response N of M' block is one responding DHCP server."""
    offers = []
    cur = None

    def _flush():
        if cur and (cur.get('server_id') or cur.get('offered_ip')):
            offers.append(cur)

    for raw in output.splitlines():
        line = raw.strip().lstrip('|_').strip()
        m = re.match(r'Response\s+\d+\s+of\s+\d+', line)
        if m:
            _flush()
            cur = {'server_id': None, 'router': None, 'dns': [],
                   'offered_ip': None, 'lease': None, 'domain': None, 'iface': None}
            continue
        if cur is None:
            continue
        m = re.match(r'Server Identifier:\s*(\d+\.\d+\.\d+\.\d+)', line)
        if m:
            cur['server_id'] = m.group(1); continue
        m = re.match(r'Router:\s*(.+)', line)
        if m:
            cur['router'] = m.group(1).strip(); continue
        m = re.match(r'Domain Name Server:\s*(.+)', line)
        if m:
            cur['dns'] = [x.strip() for x in re.split(r'[,\s]+', m.group(1).strip()) if x.strip()]
            continue
        m = re.match(r'IP Offered:\s*(\d+\.\d+\.\d+\.\d+)', line)
        if m:
            cur['offered_ip'] = m.group(1); continue
        m = re.match(r'IP Address Lease Time:\s*(.+)', line)
        if m:
            cur['lease'] = m.group(1).strip(); continue
        m = re.match(r'Domain Name:\s*(.+)', line)
        if m:
            cur['domain'] = m.group(1).strip(); continue
        m = re.match(r'Interface:\s*(\S+)', line)
        if m:
            cur['iface'] = m.group(1); continue
    _flush()
    return offers


def _dhcp_discover(interface, timeout_s=_DHCP_DISCOVER_TIMEOUT_S):
    """Provoke every DHCP server on the segment to OFFER, via nmap's
    broadcast-dhcp-discover. Returns (offers, error)."""
    if not _have('nmap'):
        return [], 'nmap is not installed (needed for rogue-DHCP discovery)'
    cmd = ['nmap', '--script', 'broadcast-dhcp-discover',
           '--script-args', f'broadcast-dhcp-discover.timeout={int(timeout_s)}']
    if interface and _valid_iface(interface):
        cmd += ['-e', interface]
    res = _run(cmd, timeout=int(timeout_s) + 25)
    if res['rc'] == 127:
        return [], 'nmap not found'
    return _parse_dhcp_discover(res['out']), None


def _parse_dhcp_capture(output):
    """Parse verbose `tcpdump` DHCP output into client-request stats:
    (requests, distinct_client_macs). Counts DISCOVER/REQUEST (client→server)
    and the distinct BOOTP client hardware addresses (chaddr) behind them —
    chaddr is what a starvation tool spoofs, so distinct chaddrs is the signal."""
    requests = 0
    clients = set()
    kind = None
    for raw in output.splitlines():
        line = raw.strip()
        m = re.search(r'DHCP-Message.*?:\s*(\w+)', line)
        if m:
            kind = m.group(1).lower()
            if kind in ('discover', 'request'):
                requests += 1
            continue
        m = re.search(r'Client-Ethernet-Address\s+([0-9a-fA-F:]{17})', line)
        if m and kind in ('discover', 'request'):
            clients.add(m.group(1).lower())
    return requests, clients


def _dhcp_capture(interface, seconds):
    """Passively capture DHCP client requests for `seconds` and return
    (requests, distinct_clients, error). No traffic generated."""
    if not _have('tcpdump'):
        return 0, 0, 'tcpdump is not installed (needed for starvation capture)'
    iface = interface if _valid_iface(interface or '') else _default_route_iface()
    if not iface:
        return 0, 0, 'no interface to capture on'
    cmd = ['tcpdump', '-i', iface, '-n', '-e', '-v', '-l',
           'udp and (port 67 or port 68)']
    # tcpdump has no built-in duration cap; run it under a timeout and read what
    # it buffered. SIGTERM (rc 124) is the normal, expected end of the window.
    res = _run(cmd, timeout=max(2, int(seconds)))
    if res['rc'] == 127:
        return 0, 0, 'tcpdump not found'
    requests, clients = _parse_dhcp_capture(res['out'])
    return requests, len(clients), None


def do_dhcp_guardian(interface=None, capture_seconds=6, learn=True, quick=False):
    """DHCP-snooping-style rogue-server + starvation detector (detection-only).

    quick=True skips the passive starvation capture (rogue-server discovery
    only) — used by the background integrity monitor and the e-Paper page so
    they stay fast. verdict: clean / suspicious / rogue / starvation."""
    iface = interface if _valid_iface(interface or '') else _default_route_iface()
    gw = _default_gateway()
    _, resolv_dns, _ = _read_resolv_conf()
    reasons = []
    verdict = 'clean'

    # --- (1) rogue / fake DHCP server -------------------------------------
    # quick mode (background monitor / e-Paper / "Check now") uses a shorter
    # OFFER wait — a legitimate local server answers in well under a second, so
    # 4s is plenty and keeps the interactive path snappy.
    offers, offer_err = _dhcp_discover(iface, 4 if quick else _DHCP_DISCOVER_TIMEOUT_S)
    server_ids = sorted({o['server_id'] for o in offers if o.get('server_id')})
    learned = False
    rogue_servers = []

    with _dhcp_baseline_lock:
        baseline = _dhcp_baseline_load()
        trusted = baseline.setdefault('servers', {})
        # First scan with exactly one server learns it as the trusted baseline
        # (mirrors the ARP gateway-baseline learn-on-first-run behaviour).
        if learn and not trusted and len(server_ids) == 1:
            sid = server_ids[0]
            o = next(o for o in offers if o.get('server_id') == sid)
            trusted[sid] = {'router': o.get('router'), 'dns': o.get('dns') or []}
            _dhcp_baseline_save(baseline)
            learned = True
        trusted_ids = set(trusted.keys())

    # A server that isn't the trusted one — or a trusted one whose offered
    # gateway changed — is rogue. If nothing is trusted yet, ≥2 servers is the
    # rogue signal on its own.
    for o in offers:
        sid = o.get('server_id')
        if not sid:
            continue
        base = trusted.get(sid)
        if trusted_ids and sid not in trusted_ids:
            rogue_servers.append(o)
            reasons.append(f"rogue DHCP server {sid} on the segment "
                           f"(offers gateway {o.get('router') or '?'}, "
                           f"DNS {', '.join(o.get('dns') or []) or '?'})")
        elif base and o.get('router') and base.get('router') and o['router'] != base['router']:
            rogue_servers.append(o)
            reasons.append(f"DHCP server {sid} changed the offered gateway from "
                           f"trusted {base['router']} to {o['router']} — DHCP steering")
        elif gw and o.get('router') and o['router'] != gw:
            # Offered gateway differs from the one actually in use — steering.
            rogue_servers.append(o)
            reasons.append(f"DHCP server {sid} offers gateway {o['router']}, "
                           f"but your active gateway is {gw} — possible DHCP steering")

    if not trusted_ids and len(server_ids) >= 2:
        reasons.append(f"{len(server_ids)} DHCP servers answered "
                       f"({', '.join(server_ids)}) — only one is legitimate")

    # Cross-check the active gateway's ARP binding: a rogue DHCP steer is far
    # more dangerous when the gateway MAC is also spoofed (full MITM).
    arp = {}
    try:
        arp = do_arp_check(learn=False)
    except Exception:
        arp = {}
    if rogue_servers and arp.get('verdict') == 'spoofed':
        reasons.append("gateway MAC is ALSO ARP-spoofed — combined DHCP+ARP "
                       "man-in-the-middle")

    # --- (2) starvation ----------------------------------------------------
    starv = {'requests': 0, 'clients': 0, 'captured': False, 'error': None}
    if not quick:
        req, clients, cap_err = _dhcp_capture(iface, capture_seconds)
        starv = {'requests': req, 'clients': clients,
                 'captured': cap_err is None, 'error': cap_err}
        if clients >= _DHCP_STARV_MIN_CLIENTS:
            reasons.append(f"{clients} distinct DHCP clients requested leases in "
                           f"{capture_seconds}s ({req} requests) — DHCP starvation "
                           "(pool-exhaustion) signature")

    # --- verdict -----------------------------------------------------------
    if starv['clients'] >= _DHCP_STARV_MIN_CLIENTS:
        verdict = 'starvation'
    elif rogue_servers or (not trusted_ids and len(server_ids) >= 2):
        verdict = 'rogue'
    elif offer_err and not offers:
        # No server answered at all — could be a static segment, or a pool that
        # a starvation attack already drained. Informational, not an alarm.
        verdict = 'clean'
        reasons.append(offer_err)
    elif not offers:
        reasons.append("no DHCP server answered — static addressing, or the "
                       "pool may be exhausted")

    return {
        'success': True, 'verdict': verdict, 'interface': iface,
        'gateway': gw, 'resolver_dns': resolv_dns,
        'servers': [{
            'server_id': o.get('server_id'), 'router': o.get('router'),
            'dns': o.get('dns') or [], 'offered_ip': o.get('offered_ip'),
            'lease': o.get('lease'), 'domain': o.get('domain'),
            'trusted': o.get('server_id') in trusted_ids,
            'rogue': o in rogue_servers,
        } for o in offers],
        'server_count': len(server_ids),
        'trusted_count': len(trusted_ids),
        'learned': learned,
        'rogue_count': len(rogue_servers),
        'arp_verdict': arp.get('verdict'),
        'starvation': starv,
        'reasons': reasons,
    }


# --------------------------------------------------------------------------
# DHCP Snooping (inline bridge) — enterprise-grade rogue-DHCP detection.
#
# When the Pi sits INLINE with two NICs bridged (rgsnoop0 = eth_a + eth_b), it
# sees every DHCP packet transiting the link, per ingress port. That unlocks the
# managed-switch "DHCP snooping" model, which is strictly stronger than the
# active-probe DHCP Guardian above:
#
#   * Trusted vs. untrusted ports. You designate the uplink NIC (toward the real
#     DHCP server) trusted and the client NIC untrusted. A DHCP *server* message
#     (OFFER/ACK/NAK) that ingresses the UNTRUSTED port is, by definition, a
#     rogue server — no baseline, no guessing, zero false positives.
#   * Binding table. From the OFFER/ACK it records client-MAC ↔ assigned-IP ↔
#     server ↔ lease ↔ ingress-port — the same table a switch keeps, and the
#     basis for spotting IP spoofing / feeding dynamic ARP inspection later.
#   * Starvation. Distinct client hardware addresses (chaddr) flooding DISCOVERs
#     on the untrusted side are counted directly off the wire.
#
# Detection-only for now (it never drops or rewrites a frame); inline *blocking*
# with an nftables/ebtables bridge rule is a deliberate future opt-in. Ingress
# port comes from `tcpdump -i any -Q in` (LINUX_SLL2 tags each packet with its
# interface). The bridge itself is optional — bring your own br0/SPAN, or use
# the guarded setup helper to enslave two wired NICs into rgsnoop0.
# --------------------------------------------------------------------------

_DHCP_SNOOP_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                'data', 'dhcp_snoop.json')
_dhcp_snoop_lock = threading.Lock()
_DHCP_SNOOP_BRIDGE = 'rgsnoop0'          # bridge the setup helper creates
_DHCP_SNOOP_WIRED_RE = re.compile(r'^(eth|en|usb)')   # eligible wired NICs


def _dhcp_snoop_load():
    try:
        with open(_DHCP_SNOOP_PATH) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _dhcp_snoop_save(d):
    try:
        os.makedirs(os.path.dirname(_DHCP_SNOOP_PATH), exist_ok=True)
        tmp = _DHCP_SNOOP_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, _DHCP_SNOOP_PATH)
    except OSError:
        pass


def _iface_master(iface):
    """The bridge (or bond) an interface is enslaved to, or None."""
    res = _run(['ip', '-o', 'link', 'show', 'dev', iface], timeout=5)
    m = re.search(r'\bmaster\s+(\S+)', res['out'])
    return m.group(1) if m else None


def _bridge_members(bridge):
    """Interfaces enslaved to `bridge`."""
    res = _run(['ip', '-o', 'link', 'show', 'master', bridge], timeout=5)
    out = []
    for line in res['out'].splitlines():
        m = re.match(r'^\d+:\s+([^:@]+)', line)
        if m:
            out.append(m.group(1).strip())
    return out


def _list_bridges():
    res = _run(['ip', '-o', 'link', 'show', 'type', 'bridge'], timeout=5)
    out = []
    for line in res['out'].splitlines():
        m = re.match(r'^\d+:\s+([^:@]+)', line)
        if m:
            name = m.group(1).strip()
            out.append({'name': name, 'members': _bridge_members(name)})
    return out


def _wired_nics():
    """Physical wired NICs eligible to be bridged (eth*/en*/usb*), excluding the
    default-route interface and anything already in a non-snoop bridge."""
    names = []
    for n in _list_iface_names(include_virtual=False):
        if _DHCP_SNOOP_WIRED_RE.match(n) and not _is_wireless(n):
            names.append(n)
    return names


def do_dhcp_snoop_config(trusted=None, untrusted=None):
    """Get or set the trusted/untrusted port designation (persisted). Pass both
    to set; pass neither to just read."""
    with _dhcp_snoop_lock:
        cfg = _dhcp_snoop_load()
        if trusted is not None and untrusted is not None:
            if not _valid_iface(trusted) or not _valid_iface(untrusted):
                return {'success': False, 'error': 'invalid interface name'}
            if trusted == untrusted:
                return {'success': False, 'error': 'trusted and untrusted must differ'}
            cfg['trusted'] = trusted
            cfg['untrusted'] = untrusted
            _dhcp_snoop_save(cfg)
        return {'success': True, 'trusted': cfg.get('trusted'),
                'untrusted': cfg.get('untrusted')}


def do_dhcp_snoop_status():
    """Report the inline-snooping setup: bridges present, eligible wired NICs,
    the default-route interface (never bridged), and the trusted/untrusted
    config — everything the UI needs to guide wiring."""
    bridges = _list_bridges()
    snoop_bridge = next((b for b in bridges if b['name'] == _DHCP_SNOOP_BRIDGE), None)
    with _dhcp_snoop_lock:
        cfg = _dhcp_snoop_load()
    return {
        'success': True,
        'bridges': bridges,
        'snoop_bridge': snoop_bridge,
        'wired_nics': _wired_nics(),
        'default_iface': _default_route_iface(),
        'trusted': cfg.get('trusted'),
        'untrusted': cfg.get('untrusted'),
        'inline_ready': bool(snoop_bridge and len(snoop_bridge['members']) >= 2),
    }


def do_dhcp_snoop_setup(iface_a, iface_b, action='create'):
    """Guarded bridge setup: enslave two wired NICs into rgsnoop0 so the box is
    inline. Refuses the default-route / wireless / management interface so it
    can't cut its own link. Detection-only bridge (no IP on it)."""
    if action == 'destroy':
        with _dhcp_snoop_lock:
            for m in _bridge_members(_DHCP_SNOOP_BRIDGE):
                _run(['ip', 'link', 'set', m, 'nomaster'], timeout=5)
                _run(['ip', 'link', 'set', m, 'down'], timeout=5)
            _run(['ip', 'link', 'set', _DHCP_SNOOP_BRIDGE, 'down'], timeout=5)
            r = _run(['ip', 'link', 'del', _DHCP_SNOOP_BRIDGE], timeout=5)
        if r['rc'] not in (0, 1):
            return {'success': False, 'error': r['err'] or 'failed to remove bridge'}
        return {'success': True, 'destroyed': True}

    # ---- create: validate hard before touching any link --------------------
    default_if = _default_route_iface()
    for i in (iface_a, iface_b):
        if not _valid_iface(i):
            return {'success': False, 'error': f'invalid interface {i!r}'}
        if not _DHCP_SNOOP_WIRED_RE.match(i) or _is_wireless(i):
            return {'success': False, 'error': f'{i} is not an eligible wired NIC'}
        if i == default_if:
            return {'success': False,
                    'error': f'{i} carries the default route — refusing to bridge the '
                             'management interface (you would cut your own link)'}
        if i not in _list_iface_names(include_virtual=True):
            return {'success': False, 'error': f'{i} not found'}
        m = _iface_master(i)
        if m and m != _DHCP_SNOOP_BRIDGE:
            return {'success': False, 'error': f'{i} is already enslaved to {m}'}
    if iface_a == iface_b:
        return {'success': False, 'error': 'need two different interfaces'}

    with _dhcp_snoop_lock:
        # Create the bridge if absent; enslave both members; bring everything up.
        if _DHCP_SNOOP_BRIDGE not in [b['name'] for b in _list_bridges()]:
            r = _run(['ip', 'link', 'add', 'name', _DHCP_SNOOP_BRIDGE, 'type', 'bridge'], timeout=5)
            if r['rc'] != 0:
                return {'success': False, 'error': r['err'] or 'failed to create bridge'}
        for i in (iface_a, iface_b):
            _run(['ip', 'link', 'set', i, 'master', _DHCP_SNOOP_BRIDGE], timeout=5)
            _run(['ip', 'link', 'set', i, 'up'], timeout=5)
        _run(['ip', 'link', 'set', _DHCP_SNOOP_BRIDGE, 'up'], timeout=5)
        members = _bridge_members(_DHCP_SNOOP_BRIDGE)

    return {'success': True, 'bridge': _DHCP_SNOOP_BRIDGE, 'members': members}


# DHCP message types by the direction they flow, so we can tell a *server*
# message (only a DHCP server sends these) from a *client* request.
_DHCP_SERVER_MSGS = {'offer', 'ack', 'nak'}
_DHCP_CLIENT_MSGS = {'discover', 'request', 'decline', 'release', 'inform'}


def _parse_dhcp_snoop(output, members=None):
    """Parse `tcpdump -i any -Q in -e -n -v` DHCP output into per-packet records:
    {iface, src_ip, src_port, dst_port, is_server, msg_type, chaddr, yiaddr,
     server_id, router, lease}. `members` (if given) filters to those ingress
     interfaces. Each packet is a header line (timestamp + ingress iface + IP
     src>dst) followed by indented option lines until the next header."""
    packets = []
    cur = None

    def _flush():
        if cur and cur.get('msg_type'):
            packets.append(cur)

    for raw in output.splitlines():
        # Header line: "<ts> <iface> In  ifindex N <mac> ethertype ...: IP a.b.c.d.p > e.f.g.h.q: ..."
        h = re.match(r'^\d\d:\d\d:\d\d\.\d+\s+(\S+)\s+In\b', raw)
        if h:
            _flush()
            iface = h.group(1)
            cur = None
            mip = re.search(r'\bIP\s+(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+)', raw)
            if not mip:
                continue
            src_port, dst_port = int(mip.group(2)), int(mip.group(4))
            if {src_port, dst_port} & {67, 68} == set():
                continue
            if members is not None and iface not in members:
                continue
            cur = {'iface': iface, 'src_ip': mip.group(1), 'src_port': src_port,
                   'dst_ip': mip.group(3), 'dst_port': dst_port,
                   'is_server': src_port == 67, 'msg_type': None,
                   'chaddr': None, 'yiaddr': None, 'server_id': None,
                   'router': None, 'lease': None}
            continue
        if cur is None:
            continue
        line = raw.strip()
        m = re.search(r'DHCP-Message.*?:\s*(\w+)', line)
        if m:
            cur['msg_type'] = m.group(1).lower(); continue
        m = re.search(r'Client-Ethernet-Address\s+([0-9a-fA-F:]{17})', line)
        if m:
            cur['chaddr'] = m.group(1).lower(); continue
        m = re.match(r'Your-IP\s+(\d+\.\d+\.\d+\.\d+)', line)
        if m:
            cur['yiaddr'] = m.group(1); continue
        m = re.search(r'Server-ID.*?:\s*(\d+\.\d+\.\d+\.\d+)', line)
        if m:
            cur['server_id'] = m.group(1); continue
        m = re.search(r'(?:Default-Gateway|Router).*?:\s*(\d+\.\d+\.\d+\.\d+)', line)
        if m:
            cur['router'] = m.group(1); continue
        m = re.search(r'Lease-Time.*?:\s*(\d+)', line)
        if m:
            cur['lease'] = int(m.group(1)); continue
    _flush()
    return packets


def _dhcp_snoop_capture(members, seconds):
    """Passively capture inbound DHCP on all interfaces for `seconds`, tagged by
    ingress port. Returns (packets, error). No traffic generated."""
    if not _have('tcpdump'):
        return [], 'tcpdump is not installed'
    cmd = ['tcpdump', '-i', 'any', '-Q', 'in', '-n', '-e', '-v', '-l',
           'udp and (port 67 or port 68)']
    res = _run(cmd, timeout=max(2, int(seconds)))
    if res['rc'] == 127:
        return [], 'tcpdump not found'
    return _parse_dhcp_snoop(res['out'], members=members), None


def do_dhcp_snoop(trusted=None, untrusted=None, seconds=20):
    """Inline DHCP-snooping pass. Captures real DHCP off the wire per ingress
    port and applies the trusted/untrusted model:

      * any DHCP *server* message on the UNTRUSTED port  -> rogue (definitive)
      * OFFER/ACK anywhere                               -> binding-table entry
      * many distinct chaddrs in DISCOVERs               -> starvation

    verdict: clean / rogue / starvation. Detection-only."""
    with _dhcp_snoop_lock:
        cfg = _dhcp_snoop_load()
    trusted = trusted or cfg.get('trusted')
    untrusted = untrusted or cfg.get('untrusted')
    if not trusted or not untrusted:
        return {'success': False,
                'error': 'trusted and untrusted ports are not set — designate them first',
                'need_config': True}

    members = [trusted, untrusted]
    packets, err = _dhcp_snoop_capture(members, seconds)
    if err:
        return {'success': False, 'error': err}

    reasons = []
    rogue_msgs = []          # server messages seen on the untrusted port
    bindings = {}            # chaddr -> latest binding
    servers = {}             # server_id/ip -> {port, trusted}
    client_macs = set()

    for p in packets:
        on_trusted = p['iface'] == trusted
        if p['is_server'] and p['msg_type'] in _DHCP_SERVER_MSGS:
            sid = p.get('server_id') or p.get('src_ip')
            servers.setdefault(sid, {'port': p['iface'],
                                     'trusted': on_trusted,
                                     'router': p.get('router')})
            if not on_trusted:
                rogue_msgs.append(p)
            if p['msg_type'] in ('offer', 'ack') and p.get('chaddr'):
                bindings[p['chaddr']] = {
                    'mac': p['chaddr'], 'ip': p.get('yiaddr'),
                    'server': sid, 'router': p.get('router'),
                    'lease': p.get('lease'), 'port': p['iface'],
                    'via': p['msg_type']}
        elif p['msg_type'] in _DHCP_CLIENT_MSGS and p.get('chaddr'):
            client_macs.add(p['chaddr'])

    rogue_servers = sorted({(m.get('server_id') or m['src_ip']) for m in rogue_msgs})
    for sid in rogue_servers:
        info = servers.get(sid, {})
        reasons.append(f"rogue DHCP server {sid} answering on the UNTRUSTED port "
                       f"{untrusted}" + (f" (offers gateway {info.get('router')})"
                                         if info.get('router') else "")
                       + " — a DHCP server must never appear on the client side")

    starvation = len(client_macs)
    if starvation >= _DHCP_STARV_MIN_CLIENTS:
        reasons.append(f"{starvation} distinct DHCP clients requested leases in "
                       f"{seconds}s — starvation (pool-exhaustion) signature")

    verdict = 'clean'
    if rogue_servers:
        verdict = 'rogue'
    elif starvation >= _DHCP_STARV_MIN_CLIENTS:
        verdict = 'starvation'
    if not packets:
        reasons.append("no DHCP seen on the wire during the window — quiet segment, "
                       "or the box may not actually be inline (bridge the two NICs)")

    return {
        'success': True, 'verdict': verdict,
        'trusted': trusted, 'untrusted': untrusted,
        'packets': len(packets),
        'servers': [{'server': sid, 'port': i['port'], 'trusted': i['trusted'],
                     'router': i.get('router'),
                     'rogue': not i['trusted']} for sid, i in servers.items()],
        'bindings': list(bindings.values()),
        'binding_count': len(bindings),
        'rogue_count': len(rogue_servers),
        'client_count': starvation,
        'reasons': reasons,
    }


# --------------------------------------------------------------------------
# Interfaces: link speed / duplex / auto-neg, static-vs-DHCP, IP/CIDR, VLAN
# --------------------------------------------------------------------------

# Container/virtual interfaces that are just noise on the Interfaces tab.
_VIRTUAL_IFACE_RE = re.compile(r'^(veth|docker|br-|virbr|vmnet|vboxnet|vnet|macvtap)')


def _list_iface_names(include_virtual=False):
    res = _run(['ip', '-o', 'link', 'show'], timeout=5)
    names = []
    for line in res['out'].splitlines():
        m = re.match(r'^\d+:\s+([^:@]+)', line)
        if m:
            name = m.group(1).strip()
            if name == 'lo':
                continue
            if not include_virtual and _VIRTUAL_IFACE_RE.match(name):
                continue
            names.append(name)
    return names


def _iface_link_details(iface):
    """MAC, operstate, and VLAN info from `ip -d link show`."""
    res = _run(['ip', '-d', 'link', 'show', 'dev', iface], timeout=5)
    out = res['out']
    d = {'mac': None, 'operstate': None, 'vlan_id': None, 'vlan_proto': None}
    m = re.search(r'state (\S+)', out)
    if m:
        d['operstate'] = m.group(1)
    m = re.search(r'link/\w+\s+([0-9a-fA-F:]{17})', out)
    if m:
        d['mac'] = m.group(1)
    m = re.search(r'vlan protocol (\S+) id (\d+)', out)
    if m:
        d['vlan_proto'] = m.group(1)
        d['vlan_id'] = int(m.group(2))
    return d


def _iface_addrs(iface):
    v4 = []
    res = _run(['ip', '-o', '-4', 'addr', 'show', 'dev', iface], timeout=5)
    for line in res['out'].splitlines():
        m = re.search(r'inet (\S+)', line)
        if m:
            v4.append(m.group(1))
    v6 = []
    res6 = _run(['ip', '-o', '-6', 'addr', 'show', 'dev', iface], timeout=5)
    for line in res6['out'].splitlines():
        m = re.search(r'inet6 (\S+)', line)
        if m:
            v6.append(m.group(1))
    return v4, v6


def _iface_ethtool(iface):
    """Speed / duplex / auto-negotiation / link. Wireless & virtual ifaces
    typically don't support this -> fields stay None."""
    d = {'speed': None, 'duplex': None, 'autoneg': None, 'link_detected': None}
    res = _run(['ethtool', iface], timeout=6)
    if res['rc'] != 0:
        return d
    out = res['out']
    m = re.search(r'Speed:\s*(.+)', out)
    if m and 'Unknown' not in m.group(1):
        d['speed'] = m.group(1).strip()
    m = re.search(r'Duplex:\s*(.+)', out)
    if m and 'Unknown' not in m.group(1):
        d['duplex'] = m.group(1).strip()
    m = re.search(r'Auto-negotiation:\s*(\w+)', out)
    if m:
        d['autoneg'] = (m.group(1).strip().lower() == 'on')
    m = re.search(r'Link detected:\s*(\w+)', out)
    if m:
        d['link_detected'] = (m.group(1).strip().lower() == 'yes')
    return d


def _iface_ip_method(iface, v4):
    """Determine DHCP vs static via nmcli; fall back to APIPA / heuristic.

    Returns 'dhcp', 'static', 'dhcp-failed' (APIPA 169.254), 'link-down', or
    'unknown'."""
    # APIPA: got a 169.254 address only -> DHCP attempted and failed.
    if v4 and all(a.startswith('169.254.') for a in v4):
        return 'dhcp-failed'
    # No address at all: report link-down without asking nmcli. Skipping the
    # two nmcli calls (up to ~12 s each worst-case) keeps the Interfaces tab
    # fast on boxes with several disconnected NICs (eth0 unplugged, usb0, ...).
    if not v4:
        return 'link-down'
    if _have('nmcli'):
        conn = None
        res = _run(['nmcli', '-t', '-g', 'GENERAL.CONNECTION', 'device', 'show', iface],
                   timeout=6)
        if res['rc'] == 0:
            conn = res['out'].strip()
        if conn and conn != '--':
            r2 = _run(['nmcli', '-t', '-g', 'ipv4.method', 'connection', 'show', conn],
                      timeout=6)
            method = r2['out'].strip()
            if method == 'auto':
                return 'dhcp'
            if method == 'manual':
                return 'static'
    if not v4:
        return 'link-down'
    return 'unknown'


def _is_wireless(iface):
    import os
    return os.path.isdir(f'/sys/class/net/{iface}/wireless')


# Interface name prefixes that denote a VPN / tunnel link (not a physical NIC).
_VPN_IFACE_PREFIXES = ('tun', 'tap', 'wg', 'tailscale', 'ppp', 'ipsec',
                       'zt', 'nordlynx', 'proton', 'gpd', 'utun', 'vpn', 'nebula')

# VPN *product* recognised anywhere in the interface name (most specific).
_VPN_PRODUCTS = (
    ('tailscale', 'Tailscale'), ('nordlynx', 'NordVPN'), ('mullvad', 'Mullvad'),
    ('proton', 'ProtonVPN'), ('zerotier', 'ZeroTier'), ('nebula', 'Nebula'),
    ('globalprotect', 'GlobalProtect'), ('expressvpn', 'ExpressVPN'),
)
# Generic VPN kind by interface-name prefix (fallback when the product is
# unknown and the link kind is only a bare tun/tap).
_VPN_PREFIX_KINDS = (
    ('wg', 'WireGuard'), ('tun', 'OpenVPN'), ('tap', 'OpenVPN'),
    ('ppp', 'PPP/L2TP'), ('ipsec', 'IPsec'), ('zt', 'ZeroTier'),
    ('gpd', 'GlobalProtect'), ('utun', 'VPN tunnel'), ('vpn', 'VPN tunnel'),
)
# Tunnel link kinds from `ip -d link show` (authoritative, needs no extra tools).
# ('strong' kinds are unambiguously a VPN/tunnel; bare tun/tap are weaker.)
_VPN_LINK_KINDS = (
    ('wireguard', 'WireGuard'), ('vti6', 'IPsec/VTI'), ('vti', 'IPsec/VTI'),
    ('gretap', 'GRE'), ('gre', 'GRE'), ('ip6tnl', 'IPv6 tunnel'),
    ('ipip', 'IPIP'), ('sit', 'SIT tunnel'), ('ppp', 'PPP'),
    ('tun', 'tunnel'), ('tap', 'tunnel'),
)
_VPN_STRONG_KINDS = ('WireGuard', 'IPsec/VTI', 'GRE', 'IPv6 tunnel',
                     'IPIP', 'SIT tunnel', 'PPP')


def _iface_arphrd_none(iface):
    """True if the interface's link type is ARPHRD_NONE (65534) -- typical of
    point-to-point tunnels (tun/wireguard/tailscale)."""
    try:
        with open(f'/sys/class/net/{iface}/type') as f:
            return f.read().strip() == '65534'
    except OSError:
        return False


def _iface_link_kind(name):
    """Authoritative tunnel kind from `ip -d link show` (iproute2 is always
    present), or None. Returns a friendly name like 'WireGuard' / 'GRE'."""
    res = _run(['ip', '-d', 'link', 'show', 'dev', name], timeout=5)
    if res['rc'] != 0:
        return None
    for tok, friendly in _VPN_LINK_KINDS:
        if re.search(r'(?:^|\s)' + tok + r'(?:\s|$)', res['out'], re.M):
            return friendly
    return None


def _wg_interfaces():
    """Names of active WireGuard interfaces (definitive, catches custom-named
    tunnels the running iproute2 may not tag as 'wireguard'). Needs `wg`."""
    if not _have('wg'):
        return frozenset()
    res = _run(['wg', 'show', 'interfaces'], timeout=5)
    return frozenset(res['out'].split()) if res['rc'] == 0 else frozenset()


def _wg_endpoint(name):
    """WireGuard peer endpoint (the VPN server's IP:port), if `wg` is available."""
    if not _have('wg'):
        return None
    res = _run(['wg', 'show', name, 'endpoints'], timeout=5)
    if res['rc'] != 0:
        return None
    for line in res['out'].splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1] not in ('(none)', 'none', ''):
            return parts[-1]
    return None


def _iface_vpn_info(name):
    """Rich VPN/tunnel classification of an interface.

    Returns {is_vpn, kind, endpoint}: `kind` names the VPN technology/product
    (WireGuard, Tailscale, OpenVPN, GRE, ...) and `endpoint` is the peer/server
    address when it can be determined (WireGuard via `wg`)."""
    n = name.lower()
    product = next((f for sub, f in _VPN_PRODUCTS if sub in n), None)
    link_kind = _iface_link_kind(name)
    prefix_kind = next((f for pre, f in _VPN_PREFIX_KINDS if n.startswith(pre)), None)
    arphrd_none = _iface_arphrd_none(name)
    strong = link_kind in _VPN_STRONG_KINDS
    # Definitive: a tun/tap character device exposes tun_flags in sysfs. This
    # catches OpenVPN in BOTH tun and tap (bridged) mode — a tap is ARPHRD_ETHER,
    # so the arphrd_none heuristic alone missed it. (VM taps like vnet*/macvtap
    # are filtered out of the interface list before typing.)
    is_tuntap = os.path.exists(f'/sys/class/net/{name}/tun_flags')
    # Definitive WireGuard, even for custom-named tunnels on an iproute2 that
    # doesn't print the 'wireguard' link kind.
    is_wg = (link_kind == 'WireGuard') or (arphrd_none and name in _wg_interfaces())

    is_vpn = bool(product or prefix_kind or strong or is_wg or is_tuntap
                  or n.startswith(_VPN_IFACE_PREFIXES)
                  or (link_kind and arphrd_none))
    if not is_vpn:
        return {'is_vpn': False, 'kind': None, 'endpoint': None}

    kind = (product
            or ('WireGuard' if is_wg else None)
            or (link_kind if strong else None)
            or prefix_kind
            or (link_kind if link_kind and link_kind != 'tunnel' else None)
            or 'VPN tunnel')
    endpoint = _wg_endpoint(name) if kind == 'WireGuard' else None
    return {'is_vpn': True, 'kind': kind, 'endpoint': endpoint}


def _is_vpn(iface):
    """Backwards-compatible boolean wrapper around _iface_vpn_info."""
    return _iface_vpn_info(iface)['is_vpn']


def do_interfaces(include_virtual=False):
    interfaces = []
    for name in _list_iface_names(include_virtual=include_virtual):
        link = _iface_link_details(name)
        v4, v6 = _iface_addrs(name)
        vpn = _iface_vpn_info(name)
        if _is_wireless(name):
            itype = 'wifi'
        elif vpn['is_vpn']:
            itype = 'vpn'
        else:
            itype = 'ethernet'
        eth = _iface_ethtool(name) if itype == 'ethernet' else {
            'speed': None, 'duplex': None, 'autoneg': None, 'link_detected': None}
        method = _iface_ip_method(name, v4)
        interfaces.append({
            'name': name,
            'type': itype,
            'vpn_kind': vpn['kind'],
            'vpn_endpoint': vpn['endpoint'],
            'mac': link['mac'],
            'operstate': link['operstate'],
            'ipv4': v4,
            'ipv6': [a for a in v6 if not a.lower().startswith('fe80')],
            'ip_method': method,
            'speed': eth['speed'],
            'duplex': eth['duplex'],
            'autoneg': eth['autoneg'],
            'link_detected': eth['link_detected'],
            'vlan_id': link['vlan_id'],
            'vlan_proto': link['vlan_proto'],
        })
    return {'success': True, 'interfaces': interfaces, 'count': len(interfaces)}


# --------------------------------------------------------------------------
# Network identity: DNS search domain(s), nameservers, hostname/FQDN, gateway
# --------------------------------------------------------------------------

def _read_resolv_conf():
    """Parse /etc/resolv.conf for search domains and nameservers.

    Returns (domains, nameservers, stub) where `stub` is True when the only
    nameserver is the systemd-resolved stub (127.0.0.53) -- in that case the
    real upstream servers must come from nmcli/resolvectl instead."""
    domains, nameservers = [], []
    try:
        with open('/etc/resolv.conf', 'r') as f:
            text = f.read()
    except OSError:
        return domains, nameservers, False
    for line in text.splitlines():
        line = line.strip()
        if line.startswith('#') or not line:
            continue
        parts = line.split()
        if parts[0] in ('search', 'domain'):
            for d in parts[1:]:
                if d not in domains:
                    domains.append(d)
        elif parts[0] == 'nameserver' and len(parts) > 1:
            if parts[1] not in nameservers:
                nameservers.append(parts[1])
    stub = nameservers == ['127.0.0.53'] or nameservers == ['127.0.0.1']
    return domains, nameservers, stub


def _nmcli_global_values(field):
    """Collect values for an nmcli field (e.g. IP4.DOMAINS, IP4.DNS) across all
    devices. nmcli prints repeated keys as `FIELD[1]:value`."""
    vals = []
    if not _have('nmcli'):
        return vals
    res = _run(['nmcli', '-t', '-f', field, 'device', 'show'], timeout=6)
    if res['rc'] != 0:
        return vals
    for line in res['out'].splitlines():
        if ':' not in line:
            continue
        _, _, v = line.partition(':')
        v = v.strip()
        if v and v != '--' and v not in vals:
            vals.append(v)
    return vals


def _default_gateway():
    """Return the IPv4 default gateway IP, or None."""
    res = _run(['ip', '-4', 'route', 'show', 'default'], timeout=5)
    m = re.search(r'default\s+via\s+(\d+\.\d+\.\d+\.\d+)', res['out'])
    return m.group(1) if m else None


def _default_route_iface():
    """Return the interface carrying the IPv4 default route, or None. Used to
    tell whether this host's internet traffic egresses through a VPN tunnel."""
    res = _run(['ip', '-4', 'route', 'show', 'default'], timeout=5)
    # First (lowest-metric) default route is the active one.
    m = re.search(r'default\b.*?\bdev\s+(\S+)', res['out'])
    return m.group(1) if m else None


# Substrings that mark a public egress as a commercial-VPN / VPN-hosting ASN.
# Brand names are high-confidence; the trailing hosting backbones (M247,
# DataCamp/DataPacket, 31173 = Mullvad's operator) are where most consumer VPNs
# terminate, so a *public egress* on them is very likely a VPN -- reported as
# best-effort ("likely VPN").
_VPN_PROVIDER_HINTS = (
    'mullvad', 'nordvpn', 'expressvpn', 'protonvpn', 'proton ag', 'surfshark',
    'cyberghost', 'ipvanish', 'tunnelbear', 'windscribe', 'vyprvpn', 'hide.me',
    'purevpn', 'torguard', 'azirevpn', 'perfect privacy', 'mozilla vpn',
    'private internet access', 'privateinternetaccess',
    'm247', 'datacamp', 'datapacket', '31173',
)


def _vpn_provider_match(*fields):
    """Return the matched VPN-provider hint if any egress field looks like a VPN
    provider/hosting ASN, else None."""
    hay = ' '.join(str(f) for f in fields if f).lower()
    return next((k for k in _VPN_PROVIDER_HINTS if k in hay), None)


# --------------------------------------------------------------------------
# Known-VPN egress IP ranges (X4BNet lists_vpn, ASN-derived, rebuilt upstream
# daily). This is the signal that catches a VPN running on the *router*: the
# public egress IP is the VPN server's no matter where the tunnel terminates,
# so an IP-range match works even when Ragnar's own NIC looks ordinary and
# the ISP-name match misses (most VPN ASNs don't carry a brand name).
# Synced to a local file and checked offline -- no per-lookup network call.
# --------------------------------------------------------------------------

_VPN_LIST_URL = 'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt'
_VPN_LIST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              'data', 'vpn_ip_ranges.txt')
_VPN_LIST_MAX_AGE = 7 * 24 * 3600  # ASN-derived, moves slowly; weekly is plenty
_VPN_LIST_MIN_BYTES = 10000        # sanity floor -- the real list is ~150 KB
_vpn_list_lock = threading.Lock()
_vpn_list_ranges = None            # sorted [(first_int, last_int)], parsed cache
_vpn_list_mtime = None             # mtime the cache was parsed from


def _vpn_list_refresh():
    """Ensure a reasonably fresh local copy of the VPN-range list; download
    (atomically) when missing or older than _VPN_LIST_MAX_AGE. Returns the
    path if a usable -- possibly stale -- file exists afterwards, else None."""
    try:
        if time.time() - os.path.getmtime(_VPN_LIST_PATH) < _VPN_LIST_MAX_AGE:
            return _VPN_LIST_PATH
    except OSError:
        pass
    if _have('curl'):
        try:
            os.makedirs(os.path.dirname(_VPN_LIST_PATH), exist_ok=True)
        except OSError:
            pass
        tmp = _VPN_LIST_PATH + '.tmp'
        res = _run(['curl', '-sf', '--max-time', '20', '-o', tmp, _VPN_LIST_URL],
                   timeout=25)
        try:
            if res['rc'] == 0 and os.path.getsize(tmp) >= _VPN_LIST_MIN_BYTES:
                os.replace(tmp, _VPN_LIST_PATH)
                return _VPN_LIST_PATH
            os.unlink(tmp)
        except OSError:
            pass
    return _VPN_LIST_PATH if os.path.exists(_VPN_LIST_PATH) else None


def _vpn_list_load():
    """Sorted (first, last) int ranges from the cached list, reparsed only when
    the file changes. Returns None when no list is available (never synced and
    currently offline)."""
    global _vpn_list_ranges, _vpn_list_mtime
    with _vpn_list_lock:
        path = _vpn_list_refresh()
        if not path:
            return None
        try:
            mtime = os.path.getmtime(path)
            if _vpn_list_ranges is not None and mtime == _vpn_list_mtime:
                return _vpn_list_ranges
            ranges = []
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    try:
                        net = ipaddress.ip_network(line, strict=False)
                    except ValueError:
                        continue
                    if net.version == 4:
                        ranges.append((int(net.network_address),
                                       int(net.broadcast_address)))
        except OSError:
            return _vpn_list_ranges  # keep whatever was parsed before
        ranges.sort()
        _vpn_list_ranges = ranges
        _vpn_list_mtime = mtime
        return _vpn_list_ranges


def _vpn_ip_lookup(ip):
    """Is this public IP inside a known VPN-provider range? True/False, or
    None when it can't be checked (no list available, or not an IPv4)."""
    try:
        n = int(ipaddress.IPv4Address(ip))
    except (ValueError, TypeError):
        return None
    ranges = _vpn_list_load()
    if not ranges:
        return None
    i = bisect.bisect_right(ranges, (n, 0xFFFFFFFF)) - 1
    return i >= 0 and ranges[i][1] >= n


def _tor_exit_check(iface):
    """Authoritatively detect whether egress through `iface` leaves via a Tor
    exit node, by asking the Tor Project's own checker (which sees our exit IP).

    This is the only reliable way to catch Tor/VPN running on the *router*: in
    that case Ragnar's own interface is an ordinary LAN NIC, so the interface
    heuristics and the commercial-VPN ISP name match both miss it. Bound to the
    interface like the geo lookup. Returns True/False, or None if the check
    couldn't be performed (offline / curl missing)."""
    if not _have('curl'):
        return None
    res = _run(['curl', '-s', '--max-time', '8', '--interface', iface,
                'https://check.torproject.org/api/ip'], timeout=12)
    if res['rc'] == 0 and res['out'].strip():
        try:
            return bool(json.loads(res['out']).get('IsTor'))
        except ValueError:
            pass
    return None


def _reverse_dns(ip):
    """Reverse-DNS an IP via getent (honours nsswitch, bounded by _run's
    timeout). Returns the PTR hostname or None."""
    if not ip:
        return None
    res = _run(['getent', 'hosts', ip], timeout=5)
    if res['rc'] != 0:
        return None
    # Format: "192.168.1.1   gateway.lan alias1 alias2"
    parts = res['out'].split()
    if len(parts) >= 2 and parts[1] != ip:
        return parts[1]
    return None


def do_network_identity():
    """Best-effort identity of the network Ragnar is attached to: DNS search
    domain(s), nameservers, this host's name/FQDN, and the default gateway
    (with reverse-DNS). No single source is authoritative, so several are
    merged and the provenance is reported."""
    sources = []

    rc_domains, rc_ns, stub = _read_resolv_conf()

    # Search domains: union of resolv.conf and NetworkManager (DHCP option 15 /
    # 119). NM is preferred when resolv.conf is the systemd stub.
    domains = list(rc_domains)
    for d in _nmcli_global_values('IP4.DOMAINS'):
        if d not in domains:
            domains.append(d)
    if rc_domains:
        sources.append('resolv.conf')
    if _have('nmcli'):
        sources.append('nmcli')

    # Nameservers: resolv.conf, unless it only holds the local stub -- then use
    # the upstream servers NetworkManager learned from DHCP.
    nameservers = list(rc_ns)
    nm_ns = _nmcli_global_values('IP4.DNS')
    if stub or not nameservers:
        nameservers = nm_ns or nameservers
    else:
        for n in nm_ns:
            if n not in nameservers:
                nameservers.append(n)

    # Hostname / FQDN. `hostname -f` can resolve the FQDN via DNS; bounded by
    # _run's timeout so a misconfigured resolver can't hang the request.
    hostname = None
    res = _run(['hostname'], timeout=5)
    if res['rc'] == 0:
        hostname = res['out'].strip() or None
    fqdn = None
    resf = _run(['hostname', '-f'], timeout=5)
    if resf['rc'] == 0:
        cand = resf['out'].strip()
        if cand and cand != hostname and '.' in cand:
            fqdn = cand

    gw_ip = _default_gateway()
    gateway = {'ip': gw_ip, 'ptr': _reverse_dns(gw_ip)} if gw_ip else None

    # Is this host's traffic egressing through a VPN? True when the default
    # route leaves via a tunnel interface (full-tunnel VPN / exit node), even
    # if the physical uplink is a normal eth0/wlan0.
    route_if = _default_route_iface()
    route_vpn = _iface_vpn_info(route_if) if route_if else {'is_vpn': False, 'kind': None, 'endpoint': None}
    vpn_egress = {'interface': route_if,
                  'via_vpn': route_vpn['is_vpn'],
                  'kind': route_vpn['kind'],
                  'endpoint': route_vpn['endpoint']}

    # If no explicit search domain but the gateway/FQDN reveals one, surface it
    # as a best-effort guess so the field isn't just empty.
    guessed_domain = None
    for cand in (fqdn, gateway['ptr'] if gateway else None):
        if cand and '.' in cand:
            guessed_domain = cand.split('.', 1)[1]
            break

    return {
        'success': True,
        'hostname': hostname,
        'fqdn': fqdn,
        'domains': domains,
        'guessed_domain': guessed_domain if not domains else None,
        'nameservers': nameservers,
        'dns_stub': stub,
        'gateway': gateway,
        'vpn_egress': vpn_egress,
        'sources': sources,
    }


# --------------------------------------------------------------------------
# Per-interface ISP / WAN detection (multi-WAN troubleshooting)
# --------------------------------------------------------------------------

def _parse_ipinfo_org(org):
    """ipinfo.io returns org as 'AS3301 Telia Company AB'. Split the leading
    ASN from the ISP/org name."""
    if not org:
        return None, None
    m = re.match(r'^(AS\d+)\s+(.*)$', org.strip())
    if m:
        return m.group(1), m.group(2).strip() or None
    return None, org.strip() or None


def _isp_lookup_iface(iface):
    """Query a public geo-IP/ASN service *through* one interface, so on a
    multi-WAN box each WAN's own public IP + ISP is reported. curl --interface
    binds the socket to that device (SO_BINDTODEVICE), forcing egress out it
    regardless of the routing table."""
    # The interface itself may be a VPN tunnel (egress is definitionally VPN).
    vpn = _iface_vpn_info(iface)
    iface_is_vpn = vpn['is_vpn']
    vpn_fields = {'iface_is_vpn': iface_is_vpn,
                  'vpn_kind': vpn['kind'], 'vpn_endpoint': vpn['endpoint']}

    def _vpn_only_result():
        """A tunnel we can't reach a geo service through isn't a dead WAN --
        present it as the VPN it is (kind/endpoint), not a red error row."""
        return {'interface': iface, 'behind_vpn': True,
                'isp': vpn['kind'] or 'VPN tunnel',
                'note': 'VPN tunnel — no separate internet egress to geolocate',
                **vpn_fields}

    if not _have('curl'):
        if iface_is_vpn:
            return _vpn_only_result()
        return {'interface': iface, 'behind_vpn': False,
                'error': 'curl is not installed', 'missing_tool': 'curl', **vpn_fields}

    # Fast pre-check: probing binds to the device (SO_BINDTODEVICE), which
    # needs a default route via that device. On a dual-homed box where only
    # the other uplink got a gateway (e.g. LAN segment without a DHCP gateway
    # while WiFi carries the default route) every probe is doomed — say so
    # immediately instead of burning ~24 s of Tor + geo timeouts per NIC.
    route_check = _run(['ip', '-4', 'route', 'show', 'default', 'dev', iface],
                       timeout=5)
    if route_check['rc'] == 0 and not route_check['out'].strip():
        if iface_is_vpn:
            return _vpn_only_result()
        return {'interface': iface, 'behind_vpn': False, 'no_route': True,
                'error': 'no default route via this interface — the kernel '
                         'routes internet traffic through another uplink, so '
                         'egress cannot be probed here (check the gateway/DHCP '
                         'on this segment)', **vpn_fields}

    # Is this egress a Tor exit? Catches Tor/VPN on the *router* (Ragnar's own
    # NIC looks ordinary in that case, so the geo ISP-name match alone misses it).
    tor_exit = _tor_exit_check(iface)
    vpn_fields['tor_exit'] = bool(tor_exit)

    # Primary: ipinfo.io over HTTPS (no API key needed for basic fields).
    res = _run(['curl', '-s', '--max-time', '8', '--interface', iface,
                'https://ipinfo.io/json'], timeout=12)
    if res['rc'] == 0 and res['out'].strip():
        try:
            d = json.loads(res['out'])
            if d.get('ip'):
                asn, isp = _parse_ipinfo_org(d.get('org'))
                vp = _vpn_provider_match(isp, d.get('org'), asn) or ('Tor' if tor_exit else None)
                ip_match = _vpn_ip_lookup(d.get('ip'))
                return {'interface': iface, 'public_ip': d.get('ip'),
                        'isp': isp, 'asn': asn, 'org': d.get('org'),
                        'vpn_provider': vp, 'vpn_ip_match': ip_match,
                        'behind_vpn': bool(vp or iface_is_vpn or tor_exit or ip_match),
                        'city': d.get('city'), 'region': d.get('region'),
                        'country': d.get('country'), 'source': 'ipinfo.io', **vpn_fields}
        except ValueError:
            pass

    # Fallback: ip-api.com (HTTP only on the free tier).
    res = _run(['curl', '-s', '--max-time', '8', '--interface', iface,
                'http://ip-api.com/json/?fields=status,message,query,isp,org,as,country,city,regionName'],
               timeout=12)
    if res['rc'] == 0 and res['out'].strip():
        try:
            d = json.loads(res['out'])
            if d.get('status') == 'success':
                asn, _ = _parse_ipinfo_org(d.get('as'))
                vp = _vpn_provider_match(d.get('isp'), d.get('org'), d.get('as')) or ('Tor' if tor_exit else None)
                ip_match = _vpn_ip_lookup(d.get('query'))
                return {'interface': iface, 'public_ip': d.get('query'),
                        'isp': d.get('isp'), 'asn': asn, 'org': d.get('org') or d.get('as'),
                        'vpn_provider': vp, 'vpn_ip_match': ip_match,
                        'behind_vpn': bool(vp or iface_is_vpn or tor_exit or ip_match),
                        'city': d.get('city'), 'region': d.get('regionName'),
                        'country': d.get('country'), 'source': 'ip-api.com', **vpn_fields}
        except ValueError:
            pass

    if iface_is_vpn:
        return _vpn_only_result()
    return {'interface': iface, 'behind_vpn': False,
            'error': 'could not reach a geo-IP service through this interface '
                     '(no internet via this WAN, or both services unreachable)',
            **vpn_fields}


def do_isp(interface=None):
    """Detect the public IP and ISP/ASN reached through each network interface.
    On a multi-WAN box this reveals which physical link goes to which ISP --
    essential for troubleshooting when one of several uplinks is flaky.

    Makes an outbound call to a third-party geo-IP service (ipinfo.io, then
    ip-api.com) per interface, bound to that interface. On-demand only."""
    if not _have('curl'):
        return {'success': False,
                'error': 'curl is not installed. Click Install to add it.',
                'missing_tool': 'curl', 'results': []}

    # Candidate interfaces: real (non-virtual) NICs that hold a routable-ish
    # IPv4 (skip loopback 127.* and APIPA 169.254.*). Private addresses are
    # kept -- they egress to a public IP via NAT, which is exactly what we
    # want to identify per WAN. NICs *without* a usable IPv4 are not silently
    # dropped any more -- they get an explanatory row, so a LAN port that
    # never completed DHCP (or has no carrier) is visible instead of missing.
    ifaces = do_interfaces(include_virtual=False).get('interfaces', [])
    candidates, skipped = [], []
    for i in ifaces:
        if interface and i['name'] != interface:
            continue
        v4 = [a.split('/')[0] for a in (i.get('ipv4') or [])]
        v4 = [a for a in v4 if not a.startswith('127.') and not a.startswith('169.254.')]
        if v4:
            candidates.append(i['name'])
        else:
            if i.get('link_detected') is False or i.get('operstate') == 'DOWN':
                why = 'no link (cable unplugged / not associated)'
            elif i.get('ip_method') == 'dhcp-failed':
                why = 'DHCP failed (APIPA 169.254.x address) — no usable IPv4'
            else:
                why = 'no IPv4 address — DHCP not completed or unconfigured'
            skipped.append({'interface': i['name'], 'behind_vpn': False,
                            'error': why, 'no_ipv4': True})

    if not candidates and not skipped:
        return {'success': False,
                'error': 'No interface has a usable IPv4 address to query through.',
                'results': []}

    results = [_isp_lookup_iface(name) for name in candidates] + skipped
    return {'success': True, 'results': results, 'count': len(results)}


def do_vpn_check(interface=None):
    """Egress VPN verdict, combining every signal we have. Catches both a VPN
    on this host (tunnel default route) and one running upstream on the
    router, where the local interface looks ordinary: the egress public IP is
    then the VPN server's, so the known-VPN IP-range match and the Tor exit
    check still see it.

    By default the check follows the *default route* (whatever uplink the
    kernel actually uses — on a dual-homed box that's the lowest-metric one,
    often WiFi). Pass `interface` to force the check through a specific NIC
    instead, e.g. to test the LAN path while WiFi carries the default route.

    verdict: 'vpn'     -- confirmed (local tunnel, Tor exit, or egress IP in a
                          known VPN range)
             'likely'  -- ISP/ASN name looks like a VPN provider/hosting
                          backbone, but the IP-range list didn't confirm
             'no'      -- egress identified and no signal fired
             'unknown' -- couldn't identify the egress (offline / no route)

    Makes outbound calls (geo-IP + Tor checker); on-demand only."""
    route_if = interface or _default_route_iface()
    if not route_if:
        return {'success': True, 'verdict': 'unknown', 'interface': None,
                'reasons': ['no default route -- this host has no internet egress']}

    r = _isp_lookup_iface(route_if)
    reasons = []
    if r.get('iface_is_vpn'):
        via = (r.get('vpn_kind') or 'tunnel') \
            + (' → ' + r['vpn_endpoint'] if r.get('vpn_endpoint') else '')
        reasons.append(f'default route is a local tunnel ({via})')
    if r.get('tor_exit'):
        reasons.append('egress is a Tor exit node (check.torproject.org)')
    if r.get('vpn_ip_match'):
        reasons.append('egress IP is in a known VPN-provider range')
    confirmed = bool(reasons)
    if r.get('vpn_provider') and r['vpn_provider'] != 'Tor':
        reasons.append(f"ISP/ASN name matches '{r['vpn_provider']}'")

    if confirmed:
        verdict = 'vpn'
    elif r.get('vpn_provider'):
        verdict = 'likely'
    elif r.get('public_ip'):
        verdict = 'no'
    else:
        verdict = 'unknown'
        reasons.append(r.get('error') or 'could not identify the public egress')

    return {'success': True, 'verdict': verdict, 'interface': route_if,
            'reasons': reasons, 'public_ip': r.get('public_ip'),
            'isp': r.get('isp'), 'asn': r.get('asn'),
            'tor_exit': r.get('tor_exit'), 'vpn_ip_match': r.get('vpn_ip_match'),
            'vpn_provider': r.get('vpn_provider'),
            'iface_is_vpn': r.get('iface_is_vpn'),
            'vpn_kind': r.get('vpn_kind'), 'vpn_endpoint': r.get('vpn_endpoint'),
            # was the IP-range list actually consulted? (None = unavailable)
            'ip_list_checked': r.get('vpn_ip_match') is not None}


# --------------------------------------------------------------------------
# DNS Doctor / Path-MTU / Captive-portal diagnostics
# --------------------------------------------------------------------------

def _system_resolvers():
    """This host's real upstream DNS servers (resolv.conf, or nmcli when only
    the systemd-resolved stub is present)."""
    _, ns, _ = _read_resolv_conf()
    if not ns or ns in (['127.0.0.53'], ['127.0.0.1']):
        nm = _nmcli_global_values('IP4.DNS')
        if nm:
            ns = nm
    return ns


def _dig(name, resolver=None, rtype='A'):
    """One dig query; returns status/AD-flag/query-time/answers, parsed."""
    cmd = ['dig', '+tries=1', '+time=3']
    if resolver:
        cmd.append('@' + resolver)
    cmd += [name, rtype, '+dnssec']
    res = _run(cmd, timeout=8)
    out = res['out']
    m = re.search(r'status:\s*(\w+)', out)
    status = m.group(1) if m else None
    ad = bool(re.search(r'flags:[^;]*\bad\b', out))
    m = re.search(r'Query time:\s*(\d+)\s*msec', out)
    query_ms = int(m.group(1)) if m else None
    answers, in_ans = [], False
    for line in out.splitlines():
        if line.startswith(';; ANSWER SECTION'):
            in_ans = True
            continue
        if in_ans:
            if not line.strip() or line.startswith(';'):
                in_ans = False
                continue
            # Answer line: NAME TTL CLASS TYPE RDATA. Keep only the queried
            # record type, so DNSSEC RRSIG/NSEC records don't pollute the set.
            parts = line.split()
            if len(parts) >= 5 and parts[3] == rtype:
                answers.append(parts[-1])
    return {'status': status, 'ad': ad, 'query_ms': query_ms, 'answers': answers,
            'error': None if (status or answers) else
                     ((res['err'] or 'no response').strip()[:120])}


# Hostname TLDs that are legitimately internal, so a private/RFC1918 answer for
# them is expected rather than a hijack signal.
_INTERNAL_TLDS = ('.local', '.lan', '.internal', '.home', '.corp', '.intranet',
                  '.localdomain', '.home.arpa')


def _looks_public_name(name):
    """True if `name` is a public FQDN (has a dot and a non-internal TLD), so a
    private/loopback answer for it would be a hijack smell rather than normal
    intranet resolution. Bare hostnames and internal TLDs return False."""
    n = (name or '').strip().lower().rstrip('.')
    if not n or '.' not in n:
        return False
    try:
        ipaddress.ip_address(n)   # a literal IP isn't a name to poison
        return False
    except ValueError:
        pass
    return not n.endswith(_INTERNAL_TLDS)


def _is_bogon(ip):
    """True if `ip` is a private / loopback / link-local / unspecified / reserved
    address — i.e. not a real public destination a public name should resolve to."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (a.is_private or a.is_loopback or a.is_unspecified
            or a.is_link_local or a.is_reserved or a.is_multicast)


def _dns_nxdomain_probe(resolver, nonce_name):
    """Ask `resolver` to resolve a random name that cannot exist. A well-behaved
    resolver returns NXDOMAIN; a resolver that *synthesizes* an address (ISP
    NXDOMAIN-redirect / typo-squat / portal) is rewriting DNS. Returns
    {'rewriting': bool, 'redirect_ip': str|None, 'status': str|None}."""
    d = _dig(nonce_name, resolver)
    rewriting = (d['status'] == 'NOERROR' and bool(d['answers']))
    return {'rewriting': rewriting,
            'redirect_ip': d['answers'][0] if d['answers'] else None,
            'status': d['status']}


def _doh_lookup(name, rtype='A'):
    """Resolve `name` over Cloudflare DNS-over-HTTPS (encrypted, tamper-resistant
    to on-path :53 spoofing). Returns a set of A-record answers, or None when the
    check couldn't run (curl missing / offline). An empty set means the encrypted
    path returned no address (NXDOMAIN / no A record)."""
    if not _have('curl'):
        return None
    q = urllib.parse.quote((name or '').strip(), safe='')
    res = _run(['curl', '-s', '--max-time', '6',
                '-H', 'accept: application/dns-json',
                f'https://cloudflare-dns.com/dns-query?name={q}&type={rtype}'],
               timeout=10)
    if res['rc'] != 0 or not res['out'].strip():
        return None
    try:
        d = json.loads(res['out'])
    except ValueError:
        return None
    return {a['data'] for a in (d.get('Answer') or [])
            if a.get('type') == 1 and a.get('data')}   # type 1 = A record


def do_dns_doctor(name):
    """Resolve `name` through every system resolver plus public 1.1.1.1 / 8.8.8.8,
    reporting per-resolver answers, query latency and the DNSSEC AD flag, whether
    the resolvers agree (split-DNS / hijack smell), and DoH/DoT reachability.

    Also runs active DNS-poisoning / hijack probes: an NXDOMAIN-rewrite test (a
    random name that must not resolve), a private-IP-for-a-public-name check, a
    SERVFAIL/DNSSEC-bogus check, and a DoH cross-check comparing the encrypted
    answer against the plaintext one. The combined verdict is in `poison`."""
    name = (name or '').strip()
    if not name:
        return {'success': False, 'error': 'hostname required'}
    if not _have('dig'):
        return {'success': False, 'missing_tool': 'dig',
                'error': 'dig is not installed. Click Install to add it.'}

    tested, seen = [], set()
    for r in _system_resolvers():
        tested.append((r, 'system'))
        seen.add(r)
    for pub in ('1.1.1.1', '8.8.8.8'):
        if pub not in seen:
            tested.append((pub, 'public'))

    public_name = _looks_public_name(name)
    nonce_name = 'nx-' + secrets.token_hex(10) + '.com'   # cannot be registered

    results, answer_sets = [], []
    for resolver, kind in tested:
        d = _dig(name, resolver)
        d.update({'resolver': resolver, 'kind': kind})
        # Private/loopback answer for a public name = redirect/portal/blocklist.
        d['bogon_answers'] = ([a for a in d['answers'] if _is_bogon(a)]
                              if public_name else [])
        # NXDOMAIN-rewrite probe against this same resolver (random name).
        nx = _dns_nxdomain_probe(resolver, nonce_name)
        d['nxdomain_rewrite'] = nx['rewriting']
        d['nxdomain_redirect_ip'] = nx['redirect_ip']
        results.append(d)
        if d['answers']:
            answer_sets.append(set(d['answers']))
    # "Consistent" = the resolvers share at least one answer. Exact-match is too
    # strict: CDN/anycast names legitimately return different IP subsets per
    # resolver, so only a *disjoint* answer set (no address in common) is the
    # real split-DNS / hijack smell.
    consistent = len(answer_sets) < 2 or bool(set.intersection(*answer_sets))

    # --- Poisoning / hijack verdict -------------------------------------------
    # Public resolvers (1.1.1.1 / 8.8.8.8) are the trust anchor; the system/ISP
    # resolvers are what an attacker or captive network would tamper with.
    public_union = set()
    for r in results:
        if r['kind'] == 'public' and r['answers']:
            public_union |= set(r['answers'])

    reasons = []

    # 1. NXDOMAIN rewriting: a resolver invented an address for a name that
    #    cannot exist. Public resolvers act as the control (they must NXDOMAIN).
    nx_rewriters = [{'resolver': r['resolver'], 'kind': r['kind'],
                     'redirect_ip': r['nxdomain_redirect_ip']}
                    for r in results if r['nxdomain_rewrite']]
    if nx_rewriters:
        who = ', '.join(x['resolver'] for x in nx_rewriters)
        reasons.append(f'NXDOMAIN rewriting: {who} synthesized an address for a '
                       f'name that does not exist (ISP redirect / portal / typo page)')

    # 2. Private/bogon address returned for a public name.
    bogon_hits = [{'resolver': r['resolver'], 'kind': r['kind'],
                   'ips': r['bogon_answers']}
                  for r in results if r['bogon_answers']]
    if bogon_hits:
        who = ', '.join(x['resolver'] for x in bogon_hits)
        reasons.append(f'private/bogon address for a public name from {who} '
                       f'(redirect, blocklist sinkhole or captive portal)')

    # 3. SERVFAIL where another resolver answered — a validating resolver
    #    refusing a name others resolve is the DNSSEC-bogus (tampered) signature.
    servfail = [r['resolver'] for r in results if r['status'] == 'SERVFAIL']
    if servfail and answer_sets:
        reasons.append(f'SERVFAIL from {", ".join(servfail)} while other resolvers '
                       f'answered — possible DNSSEC validation failure (tampered record)')

    # 4. System resolver's answer shares nothing with the public resolvers'.
    #    Soft signal (CDN/anycast can legitimately differ), so it's "suspected".
    sys_disjoint = [r['resolver'] for r in results
                    if r['kind'] == 'system' and r['answers']
                    and public_union and set(r['answers']).isdisjoint(public_union)]
    if sys_disjoint:
        reasons.append(f'{", ".join(sys_disjoint)} returned an answer with nothing in '
                       f'common with public resolvers (split-DNS, or a hijack if unexpected)')

    # 5. DoH cross-check: compare the encrypted (tamper-resistant) answer with the
    #    plaintext public answer. Disjoint => on-path :53 spoofing of the clear path.
    doh_answers = _doh_lookup(name)
    doh = {'checked': doh_answers is not None,
           'answers': sorted(doh_answers) if doh_answers else [],
           'mismatch': None}
    if doh_answers is not None and doh_answers and public_union:
        doh['mismatch'] = doh_answers.isdisjoint(public_union)
        if doh['mismatch']:
            reasons.append('DoH (encrypted) answer disjoint from the plaintext answer '
                           '— strong sign of on-path DNS spoofing')

    # Strong = confirmed tampering; soft = worth a second look.
    strong = bool(nx_rewriters or bogon_hits or doh['mismatch'])
    soft = bool(servfail or sys_disjoint)
    verdict = 'hijacked' if strong else ('suspicious' if soft else 'clean')

    poison = {
        'verdict': verdict,                 # clean | suspicious | hijacked
        'hijack_suspected': verdict != 'clean',
        'reasons': reasons,
        'public_name': public_name,
        'nxdomain_rewriters': nx_rewriters,
        'bogon_hits': bogon_hits,
        'servfail_resolvers': servfail,
        'system_disjoint_resolvers': sys_disjoint,
        'doh': doh,
    }

    return {'success': True, 'name': name, 'results': results,
            'consistent': consistent,
            'dnssec_ok': any(r['ad'] for r in results),
            'doh_reachable': _tcp_reachable('1.1.1.1', 443),
            'dot_reachable': _tcp_reachable('1.1.1.1', 853),
            'poison': poison}


def _tcp_reachable(host, port, timeout=4):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def do_pmtu(target):
    """Discover the path MTU to `target` and flag an MTU black hole (a hop that
    silently drops full-size packets -- the classic 'ping works, big transfers
    hang' fault).

    Uses a `ping -M do` (don't-fragment) binary search: the largest payload that
    gets through without fragmentation gives the path MTU. This needs no extra
    tool and, unlike a full tracepath, doesn't stall on unresponsive hops."""
    target = (target or '').strip()
    if not target:
        return {'success': False, 'error': 'target required'}
    if not _have('ping'):
        return {'success': False, 'missing_tool': 'ping',
                'error': 'ping is not installed. Click Install to add it.'}

    def fits(mtu):
        # payload = MTU - 28 (20-byte IP header + 8-byte ICMP header)
        r = _run(['ping', '-n', '-c', '1', '-W', '2', '-M', 'do', '-s', str(mtu - 28), target],
                 timeout=6)
        return r['rc'] == 0

    if fits(1500):
        pmtu = 1500
    elif not fits(576):
        # Even a 576-byte DF probe fails: the path likely filters ICMP or blocks
        # DF. Fall back to a plain ping to say whether the host is reachable.
        reach = _run(['ping', '-n', '-c', '1', '-W', '2', target], timeout=6)['rc'] == 0
        return {'success': True, 'target': target, 'pmtu': None, 'reduced': False,
                'reachable': reach,
                'note': 'Could not measure PMTU — the path filters ICMP or blocks '
                        'don\'t-fragment probes. ' + ('Host answers normal pings.'
                        if reach else 'Host did not answer normal pings either.')}
    else:
        lo, hi = 576, 1500
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if fits(mid):
                lo = mid
            else:
                hi = mid - 1
        pmtu = lo

    reduced = pmtu < 1500
    return {'success': True, 'target': target, 'pmtu': pmtu, 'reduced': reduced,
            'reachable': True,
            'note': (f'Largest unfragmented packet is {pmtu} bytes — below the standard '
                     '1500, which points to tunnel overhead (PPPoE/VPN) or an MTU-mismatched '
                     'hop.' if reduced else 'Full 1500-byte path — no MTU black hole.')}


_CAPTIVE_CHECKS = (
    ('http://connectivitycheck.gstatic.com/generate_204', '204', ''),
    ('http://captive.apple.com/hotspot-detect.html', '200', 'Success'),
)


def do_captive_portal():
    """Detect a captive portal (hotel/guest-WiFi HTTP hijack) by probing the
    same connectivity-check endpoints operating systems use. A mismatch (wrong
    status, a redirect, or a login page instead of the expected body) means the
    network is intercepting HTTP."""
    if not _have('curl'):
        return {'success': False, 'missing_tool': 'curl',
                'error': 'curl is not installed. Click Install to add it.'}
    checks, portal = [], False
    for url, expect_code, expect_body in _CAPTIVE_CHECKS:
        res = _run(['curl', '-s', '-m', '6', '-o', '-',
                    '-w', '\n__HTTP__%{http_code}__%{redirect_url}', url], timeout=10)
        m = re.search(r'\n__HTTP__(\d+)__(.*)$', res['out'], re.S)
        code = m.group(1) if m else None
        redirect = ((m.group(2) or '').strip() or None) if m else None
        body = res['out'][:m.start()] if m else res['out']
        ok = (code == expect_code) and (expect_body in body if expect_body else True)
        if not ok:
            portal = True
        checks.append({'url': url, 'code': code, 'redirect': redirect, 'ok': ok})
    return {'success': True, 'captive_portal': portal, 'checks': checks}


# --------------------------------------------------------------------------
# iperf3 LAN throughput (client to a peer, + optional built-in server)
# --------------------------------------------------------------------------

_IPERF3_PORT = 5201
_iperf3_server = {'proc': None}


def do_iperf3_client(server, port=_IPERF3_PORT, duration=5, reverse=False, udp=False):
    """Measure real throughput to an iperf3 peer on the LAN — the thing an
    internet speed test can't do (switch/cable/link validation between two
    nodes). `reverse` tests download (peer->here); `udp` reports jitter/loss."""
    server = (server or '').strip()
    if not server:
        return {'success': False, 'error': 'iperf3 server address required'}
    if not _have('iperf3'):
        return {'success': False, 'missing_tool': 'iperf3',
                'error': 'iperf3 is not installed. Click Install to add it.'}
    # iperf3 `-c` takes the host only (port is `-p`). Accept a "host:port" or
    # "[v6addr]:port" typed into the server box: split the port out so the
    # common mistake works, and it doubles as a way to target a non-5201 port.
    m6 = re.match(r'^\[(.+)\]:(\d+)$', server)
    m4 = re.match(r'^([^:]+):(\d+)$', server)
    if m6:
        server, port = m6.group(1), m6.group(2)
    elif m4:
        server, port = m4.group(1), m4.group(2)
    server = server.strip('[]')
    port = _clamp_int(port, _IPERF3_PORT, 1, 65535)
    duration = _clamp_int(duration, 5, 1, 30)
    cmd = ['iperf3', '-c', server, '-p', str(port), '-t', str(duration), '-J']
    if reverse:
        cmd.append('-R')
    if udp:
        cmd.append('-u')
    res = _run(cmd, timeout=duration + 15)
    try:
        d = json.loads(res['out'])
    except ValueError:
        return {'success': False,
                'error': (res['err'] or res['out'] or 'iperf3 failed').strip()[:200]}
    if d.get('error'):
        return {'success': False, 'error': d['error']}
    end = d.get('end', {})
    out = {'success': True, 'server': server, 'port': port,
           'direction': 'download' if reverse else 'upload',
           'protocol': 'UDP' if udp else 'TCP', 'duration_s': duration}
    if udp:
        s = end.get('sum', {})
        out['mbps'] = round(s.get('bits_per_second', 0) / 1e6, 2)
        out['jitter_ms'] = round(s.get('jitter_ms', 0), 3)
        out['lost_percent'] = round(s.get('lost_percent', 0), 2)
    else:
        sent = end.get('sum_sent', {})
        recv = end.get('sum_received', {})
        out['mbps'] = round(recv.get('bits_per_second', 0) / 1e6, 2)
        out['sent_mbps'] = round(sent.get('bits_per_second', 0) / 1e6, 2)
        out['retransmits'] = sent.get('retransmits')
    return out


def do_iperf3_server(action):
    """Run/stop a built-in iperf3 server so another device can throughput-test
    *against* this box. Returns the addresses to point the other end at."""
    if not _have('iperf3'):
        return {'success': False, 'missing_tool': 'iperf3',
                'error': 'iperf3 is not installed. Click Install to add it.'}
    proc = _iperf3_server['proc']
    running = proc is not None and proc.poll() is None

    if action == 'start':
        if not running:
            try:
                _iperf3_server['proc'] = subprocess.Popen(
                    ['iperf3', '-s', '-p', str(_IPERF3_PORT)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                running = True
            except OSError as e:
                return {'success': False, 'error': f'could not start iperf3 server: {e}'}
    elif action == 'stop':
        if running:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        _iperf3_server['proc'] = None
        running = False

    addrs = []
    for i in do_interfaces(include_virtual=False).get('interfaces', []):
        for cidr in (i.get('ipv4') or []):
            ip = cidr.split('/')[0]
            if not ip.startswith('127.'):
                addrs.append(ip)
    return {'success': True, 'running': running, 'port': _IPERF3_PORT, 'addresses': addrs}


# --------------------------------------------------------------------------
# Locate Port: flap a wired link so its switch LED blinks (find the port on an
# unmanaged switch, the way a cable tester / toner probe does)
# --------------------------------------------------------------------------

_locate_lock = threading.Lock()
_locate_active = {}  # interface -> True while a flap sequence is running


def _flap_sequence(interface, count, on_ms, off_ms):
    """Bring the link down/up `count` times so the switch's LINK LED blinks in
    a recognisable cadence. Always leaves the interface up when finished."""
    try:
        for _ in range(count):
            _run(['ip', 'link', 'set', interface, 'down'], timeout=10)
            time.sleep(off_ms / 1000.0)
            _run(['ip', 'link', 'set', interface, 'up'], timeout=10)
            time.sleep(on_ms / 1000.0)
    finally:
        # Never leave the port down, whatever happened above.
        _run(['ip', 'link', 'set', interface, 'up'], timeout=10)
        with _locate_lock:
            _locate_active.pop(interface, None)


def do_locate_port(interface, count=6, on_ms=800, off_ms=800, force=False):
    """Physically locate which switch port this device is plugged into by
    flapping the link in a timed pattern (link LED blinks). Managed switches
    already report the port via LLDP/CDP (Switch Discovery) -- this is the
    fallback for unmanaged switches. Runs in the background and returns at once.

    Refuses the interface carrying this host's default route unless force=True,
    since flapping it briefly drops Ragnar's own connectivity."""
    interface = (interface or '').strip()
    if not interface:
        return {'success': False, 'error': 'interface required'}

    match = next((i for i in do_interfaces(include_virtual=True).get('interfaces', [])
                  if i['name'] == interface), None)
    if match is None:
        return {'success': False, 'error': f'unknown interface: {interface}'}
    if match.get('type') != 'ethernet' or not interface.startswith(('eth', 'en')):
        return {'success': False,
                'error': f'{interface} is not a physical Ethernet port; a link-flap '
                         'only identifies a switch port on a wired link.'}

    count = _clamp_int(count, 6, 1, 30)
    on_ms = _clamp_int(on_ms, 800, 100, 3000)
    off_ms = _clamp_int(off_ms, 800, 100, 3000)

    # Guard: flapping the default-route interface drops our own uplink.
    if not force and _default_route_iface() == interface:
        return {'success': False, 'needs_force': True, 'interface': interface,
                'error': f'{interface} carries this device\'s default route — flapping '
                         'it will briefly drop Ragnar\'s connectivity (the UI freezes '
                         'until the sequence finishes, then it auto-restores). '
                         'Confirm to proceed anyway.'}

    with _locate_lock:
        if _locate_active.get(interface):
            return {'success': False, 'error': f'a locate sequence is already running on {interface}.'}
        _locate_active[interface] = True

    threading.Thread(target=_flap_sequence, args=(interface, count, on_ms, off_ms),
                     daemon=True).start()
    total = round(count * (on_ms + off_ms) / 1000.0, 1)
    return {'success': True, 'interface': interface, 'count': count,
            'on_ms': on_ms, 'off_ms': off_ms, 'duration_s': total,
            'message': f'Flapping {interface} {count}× (~{round(total)}s). Watch the '
                       'switch — the port whose LINK LED blinks in this cadence is the one.'}


# --------------------------------------------------------------------------
# L2 Link Health: a short passive capture that flags Layer-2 problems
# --------------------------------------------------------------------------

def do_l2_health(interface, seconds=12):
    """Listen passively for a few seconds and report Layer-2 health: STP root
    bridge(s) and topology churn (loop smell), CDP/LLDP/DTP/VTP control frames,
    broadcast/multicast storm rate, rogue DHCP servers, rogue IPv6 RA sources,
    and duplicate IPs (conflicting ARP). One 'what's wrong at L2' snapshot."""
    interface = (interface or '').strip()
    if not interface:
        return {'success': False, 'error': 'interface required'}
    if not _have('tcpdump'):
        return {'success': False, 'missing_tool': 'tcpdump',
                'error': 'tcpdump is not installed. Click Install to add it.'}
    if interface not in _list_iface_names(include_virtual=True):
        return {'success': False, 'error': f'unknown interface: {interface}'}
    seconds = _clamp_int(seconds, 12, 3, 30)

    res = _run(['timeout', str(seconds), 'tcpdump', '-i', interface,
                '-nn', '-e', '-t', '-s', '256', '-c', '20000'], timeout=seconds + 8)
    out = res['out']
    if not out and res['err'] and ('permission' in res['err'].lower()
                                   or "couldn't" in res['err'].lower()):
        return {'success': False, 'error': res['err'].strip()[:200]}

    total = bcast = mcast = tcn = 0
    protos = {}
    stp_roots, dhcp_servers, ra_sources = set(), set(), set()
    arp_ip_macs = {}

    def bump(p):
        protos[p] = protos.get(p, 0) + 1

    for line in out.splitlines():
        if not line.strip():
            continue
        total += 1
        m = re.match(r'^(\S+)\s+>\s+([0-9a-fA-F:]{17})', line)
        src = m.group(1).lower() if m else None
        dst = m.group(2).lower() if m else None
        if dst == 'ff:ff:ff:ff:ff:ff':
            bcast += 1
        elif dst:
            try:
                if int(dst[0:2], 16) & 1:
                    mcast += 1
            except ValueError:
                pass
        if 'STP' in line or '802.1d' in line or '802.1w' in line:
            bump('STP')
            rr = re.search(r'root-id\s+([0-9a-fA-F.:]+)', line) or re.search(r'\broot\s+([0-9a-fA-F.:]+)', line)
            if rr:
                stp_roots.add(rr.group(1))
            if 'TCN' in line or 'topology' in line.lower():
                tcn += 1
        if 'CDP' in line:
            bump('CDP')
        if 'LLDP' in line:
            bump('LLDP')
        if 'DTP' in line:
            bump('DTP')
        if 'VTP' in line:
            bump('VTP')
        if 'router advertisement' in line.lower():
            bump('IPv6-RA')
            sm = re.search(r'ethertype IPv6.*?:\s*([0-9a-fA-F:]+)\s*>', line)
            ra_sources.add(sm.group(1) if sm else (src or '?'))
        if 'BOOTP/DHCP' in line or 'DHCP' in line:
            bump('DHCP')
            if any(k in line for k in ('Reply', 'Offer', 'ACK')):
                sm = (re.search(r'(\d+\.\d+\.\d+\.\d+)\.67\s*>', line)
                      or re.search(r'server-id\s+(\d+\.\d+\.\d+\.\d+)', line))
                if sm:
                    dhcp_servers.add(sm.group(1))
        if 'ARP' in line:
            bump('ARP')
            am = re.search(r'(\d+\.\d+\.\d+\.\d+) is-at ([0-9a-fA-F:]{17})', line)
            if am:
                arp_ip_macs.setdefault(am.group(1), set()).add(am.group(2).lower())

    dup_ips = {ip: sorted(macs) for ip, macs in arp_ip_macs.items() if len(macs) > 1}
    rate = round((bcast + mcast) / seconds, 1)

    findings = []
    if len(stp_roots) > 1:
        findings.append(('warn', f'Multiple STP root bridges seen ({len(stp_roots)}) — possible L2 loop or merged/segmented domains'))
    if tcn > 5:
        findings.append(('warn', f'{tcn} STP topology-change notifications — flapping or a loop somewhere'))
    if 'STP' not in protos:
        findings.append(('info', 'No STP/BPDUs seen — the switch may have STP disabled or filtered on this port'))
    if len(dhcp_servers) > 1:
        findings.append(('warn', 'Multiple DHCP servers answering: ' + ', '.join(sorted(dhcp_servers)) + ' — possible rogue DHCP'))
    if len(ra_sources) > 1:
        findings.append(('warn', f'Multiple IPv6 RA sources ({len(ra_sources)}) — possible rogue Router Advertisement'))
    if dup_ips:
        findings.append(('warn', 'Duplicate IP(s) via conflicting ARP: ' + ', '.join(dup_ips.keys())))
    if rate > 100:
        findings.append(('warn', f'High broadcast/multicast rate ({rate}/s) — possible broadcast storm'))
    if 'DTP' in protos:
        findings.append(('info', 'DTP (Dynamic Trunking) frames seen — this port may auto-negotiate a trunk; consider hard-setting the mode'))
    if not findings:
        findings.append(('ok', 'No obvious Layer-2 problems in the capture window.'))

    return {'success': True, 'interface': interface, 'seconds': seconds,
            'packets': total, 'broadcast': bcast, 'multicast': mcast,
            'bcast_mcast_per_s': rate, 'protocols': protos,
            'stp_roots': sorted(stp_roots), 'tcn': tcn,
            'dhcp_servers': sorted(dhcp_servers), 'ra_sources': sorted(ra_sources),
            'duplicate_ips': dup_ips,
            'findings': [{'level': l, 'text': t} for l, t in findings]}


# --------------------------------------------------------------------------
# PCAP Analyzer: triage an uploaded capture with tshark/capinfos
# --------------------------------------------------------------------------

# pcap (LE/BE, us & ns) and pcapng magic numbers.
_PCAP_MAGICS = (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4',
                b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d', b'\x0a\x0d\x0d\x0a')

# IEEE 802.11 deauth/disassoc reason codes (the "why did the client drop" field).
_WIFI_REASONS = {
    1: 'Unspecified', 2: 'Previous auth no longer valid', 3: 'Deauth — STA leaving',
    4: 'Disassoc — inactivity', 5: 'Disassoc — AP out of resources',
    6: 'Class-2 frame from non-authed STA', 7: 'Class-3 frame from non-assoc STA',
    8: 'Disassoc — STA leaving BSS', 9: 'STA not authenticated',
    13: 'Invalid information element', 14: 'MIC failure',
    15: '4-way handshake timeout', 16: 'Group-key handshake timeout',
    17: '4-way handshake IE mismatch', 18: 'Invalid group cipher',
    19: 'Invalid pairwise cipher', 20: 'Invalid AKMP', 23: '802.1X auth failed',
    24: 'Cipher suite rejected (policy)', 34: 'Disassoc — poor RF / low ACK',
}
# 802.11 auth/assoc status codes (0 = success).
_WIFI_STATUS = {
    1: 'Unspecified failure', 10: 'Cannot support all capabilities',
    11: 'Reassoc denied', 12: 'Assoc denied (unspecified)',
    13: 'Auth algorithm unsupported', 15: 'Auth timeout',
    17: 'AP unable to handle more STAs (capacity)', 18: 'Assoc denied — basic-rate mismatch',
    40: 'Invalid IE', 43: 'Invalid pairwise cipher', 45: 'Invalid AKMP',
}


def _tshark_fields(path, display_filter, fields, timeout=120):
    cmd = ['tshark', '-r', path, '-Y', display_filter, '-T', 'fields']
    for f in fields:
        cmd += ['-e', f]
    return _run(cmd, timeout=timeout)['out'].splitlines()


def _to_int(v):
    try:
        return int(v, 16) if v.lower().startswith('0x') else int(v)
    except (ValueError, AttributeError):
        return None


def _pcap_wifi(path, total_wlan_frames):
    """Extract the 802.11 events that explain client drops: deauth/disassoc
    reason codes (per client), auth/assoc failure status codes, EAPOL 4-way
    handshake volume, retry rate, and SSIDs. tshark gives reason/status as hex."""
    def code_table(counter, table):
        return sorted(({'code': c, 'label': table.get(c, f'code {c}'), 'count': n}
                       for c, n in counter.items()), key=lambda x: x['count'], reverse=True)

    def collect(subtypes_filter):
        deauth_reasons, deauth_clients = {}, {}
        for line in _tshark_fields(path, subtypes_filter,
                                   ['wlan.fc.type_subtype', 'wlan.fixed.reason_code',
                                    'wlan.da', 'wlan.sa']):
            cols = (line.split('\t') + ['', '', '', ''])[:4]
            rc = _to_int(cols[1])
            client = cols[2] or cols[3]
            if rc is not None:
                deauth_reasons[rc] = deauth_reasons.get(rc, 0) + 1
            if client:
                deauth_clients[client] = deauth_clients.get(client, 0) + 1
        return deauth_reasons, deauth_clients

    de_reasons, de_clients = collect('wlan.fc.type_subtype==0x0c')     # deauth
    dis_reasons, dis_clients = collect('wlan.fc.type_subtype==0x0a')   # disassoc

    # auth (0x0b) + assoc/reassoc responses (0x01/0x03): non-zero status = failure
    status = {}
    for line in _tshark_fields(path,
                               'wlan.fc.type_subtype==0x0b||wlan.fc.type_subtype==0x01||wlan.fc.type_subtype==0x03',
                               ['wlan.fixed.status_code']):
        sc = _to_int(line.split('\t')[0])
        if sc:  # non-zero only
            status[sc] = status.get(sc, 0) + 1

    eapol = len([l for l in _tshark_fields(path, 'eapol', ['frame.number']) if l.strip()])
    retries = len([l for l in _tshark_fields(path, 'wlan.fc.retry==1', ['frame.number']) if l.strip()])
    ssids = set()
    for line in _tshark_fields(path, 'wlan.fc.type_subtype==0x08', ['wlan.ssid']):
        v = line.strip()
        if v:
            try:
                ssids.add(bytes.fromhex(v).decode('utf-8', 'replace'))
            except ValueError:
                ssids.add(v)

    retry_pct = round(100.0 * retries / total_wlan_frames, 1) if total_wlan_frames else None

    def top_clients(d):
        return sorted(({'mac': m, 'count': n} for m, n in d.items()),
                      key=lambda x: x['count'], reverse=True)[:8]

    de = code_table(de_reasons, _WIFI_REASONS)
    dis = code_table(dis_reasons, _WIFI_REASONS)
    st = code_table(status, _WIFI_STATUS)

    # Quick heuristics (useful even without AI, and they seed the AI prompt).
    findings = []
    reasons_present = {r['code'] for r in de} | {r['code'] for r in dis}
    if 15 in reasons_present or 16 in reasons_present:
        findings.append('4-way/group-key handshake timeouts — wrong PSK, RADIUS/EAP timing, or a flaky supplicant.')
    if 14 in reasons_present:
        findings.append('MIC failures — mismatched passphrase or possible attack.')
    if 23 in reasons_present:
        findings.append('802.1X authentication failed — RADIUS/cert/credentials issue.')
    if 4 in reasons_present:
        findings.append('Inactivity deauths — idle/power-save clients being aged out (often benign).')
    if reasons_present & {6, 7}:
        findings.append('Class-2/3 frames from unassociated STAs — clients losing association / roaming churn.')
    if 2 in reasons_present:
        findings.append('"Previous auth no longer valid" — roaming, or the AP reset/rebooted.')
    if any(s['code'] == 17 for s in st):
        findings.append('AP returning "unable to handle more STAs" — capacity/association-limit reached.')
    if retry_pct is not None and retry_pct > 30:
        findings.append(f'High retry rate ({retry_pct}%) — RF interference, weak signal, or distance/co-channel.')

    return {
        'is_wifi': True, 'wlan_frames': total_wlan_frames, 'retry_pct': retry_pct,
        'eapol_frames': eapol, 'ssids': sorted(ssids),
        'deauth': {'total': sum(de_reasons.values()), 'by_reason': de, 'top_clients': top_clients(de_clients)},
        'disassoc': {'total': sum(dis_reasons.values()), 'by_reason': dis, 'top_clients': top_clients(dis_clients)},
        'auth_assoc_failures': {'total': sum(status.values()), 'by_status': st},
        'findings': findings,
    }


def do_pcap_analyze(path):
    """Triage a capture file: summary (packets/bytes/duration/rate), protocol
    hierarchy, top talkers (by bytes), and tshark's expert info (errors/warnings
    /notes — retransmissions, resets, dup-ACKs, malformed …). Read-only analysis
    via tshark/capinfos, the way you'd eyeball a pcap in Wireshark's Statistics."""
    if not _have('tshark'):
        return {'success': False, 'missing_tool': 'tshark',
                'error': 'tshark is not installed. Click Install to add it.'}
    if not os.path.isfile(path):
        return {'success': False, 'error': 'capture file not found'}

    # 1) File summary (capinfos ships with tshark).
    summary = {}
    if _have('capinfos'):
        t = _run(['capinfos', '-M', path], timeout=30)['out']

        def cap(pat, cast=float):
            m = re.search(pat, t)
            if not m:
                return None
            try:
                return cast(m.group(1))
            except ValueError:
                return m.group(1)
        summary = {
            'packets': cap(r'Number of packets:\s*(\d+)', int),
            'file_size': cap(r'File size:\s*(\d+)', int),
            'data_size': cap(r'Data size:\s*(\d+)', int),
            'duration_s': cap(r'Capture duration:\s*([\d.]+)'),
            'avg_packet_size': cap(r'Average packet size:\s*([\d.]+)'),
            'data_byte_rate': cap(r'Data byte rate:\s*([\d.]+)'),
            'start_time': cap(r'(?:Earliest packet time|First packet time|Start time):\s*(.+)', str),
            'end_time': cap(r'(?:Latest packet time|Last packet time|End time):\s*(.+)', str),
            'encapsulation': cap(r'File encapsulation:\s*(.+)', str),
        }

    # 2) Protocol hierarchy (io,phs gives raw byte counts).
    protocols = []
    for line in _run(['tshark', '-r', path, '-q', '-z', 'io,phs'], timeout=90)['out'].splitlines():
        m = re.match(r'^(\s*)([\w:.-]+)\s+frames:(\d+)\s+bytes:(\d+)', line)
        if m:
            protocols.append({'proto': m.group(2), 'depth': len(m.group(1)) // 2,
                              'frames': int(m.group(3)), 'bytes': int(m.group(4))})

    # 3) Top talkers by bytes. conv,ip humanises bytes ("24 kB"), so aggregate
    #    raw frame lengths per IP pair from -T fields instead.
    agg = {}
    fields = _run(['tshark', '-r', path, '-T', 'fields', '-e', 'ip.src',
                   '-e', 'ip.dst', '-e', 'frame.len'], timeout=120)
    for line in fields['out'].splitlines():
        parts = line.split('\t')
        if len(parts) < 3 or not parts[0] or not parts[1]:
            continue
        try:
            blen = int((parts[2] or '0').split(',')[0])
        except ValueError:
            blen = 0
        key = tuple(sorted((parts[0], parts[1])))
        e = agg.setdefault(key, [0, 0])
        e[0] += 1
        e[1] += blen
    talkers = sorted(({'a': k[0], 'b': k[1], 'frames': v[0], 'bytes': v[1]}
                      for k, v in agg.items()), key=lambda t: t['bytes'], reverse=True)[:12]

    # 4) Expert info (Errors / Warns / Notes / Chats).
    expert = {'errors': 0, 'warnings': 0, 'notes': 0, 'items': []}
    sev = None
    sev_key = {'Errors': 'errors', 'Warns': 'warnings', 'Notes': 'notes'}
    for line in _run(['tshark', '-r', path, '-q', '-z', 'expert'], timeout=90)['out'].splitlines():
        hm = re.match(r'^(Errors|Warns|Notes|Chats)\s*\((\d+)\)', line)
        if hm:
            sev = hm.group(1)
            if sev in sev_key:
                expert[sev_key[sev]] = int(hm.group(2))
            continue
        rm = re.match(r'^\s+(\d+)\s+(\S+)\s+(\S+)\s+(.+?)\s*$', line)
        if rm and sev and sev != 'Chats':
            expert['items'].append({'severity': sev_key.get(sev, sev.lower()),
                                    'count': int(rm.group(1)), 'protocol': rm.group(3),
                                    'summary': rm.group(4).strip()})
    expert['items'].sort(key=lambda i: i['count'], reverse=True)
    expert['items'] = expert['items'][:20]

    # If this is an 802.11 capture, add the WiFi/AP drop analysis.
    wifi = None
    wlan_frames = next((p['frames'] for p in protocols if p['proto'] == 'wlan'), 0)
    if wlan_frames:
        try:
            wifi = _pcap_wifi(path, wlan_frames)
        except Exception:  # pragma: no cover - WiFi extraction is best-effort
            wifi = None

    return {'success': True, 'summary': summary, 'protocols': protocols,
            'talkers': talkers, 'expert': expert, 'wifi': wifi}


def do_pcap_from_upload(file_storage, max_bytes=100 * 1024 * 1024):
    """Save an uploaded capture to a temp file (size-guarded, magic-checked) and
    analyze it, then delete it."""
    if file_storage is None:
        return {'success': False, 'error': 'no file uploaded'}
    fd, tmp = tempfile.mkstemp(suffix='.pcap')
    try:
        total = 0
        with os.fdopen(fd, 'wb') as out:
            while True:
                chunk = file_storage.stream.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    return {'success': False,
                            'error': f'file too large (max {max_bytes // (1024 * 1024)} MB)'}
                out.write(chunk)
        if total == 0:
            return {'success': False, 'error': 'uploaded file is empty'}
        with open(tmp, 'rb') as fh:
            if fh.read(4) not in _PCAP_MAGICS:
                return {'success': False,
                        'error': 'not a valid pcap/pcapng capture (bad magic bytes)'}
        return do_pcap_analyze(tmp)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


# --------------------------------------------------------------------------
# Flow telemetry (per-connection RTT / retransmits) + PTP timing detection
# --------------------------------------------------------------------------

def do_flow_telemetry(limit=15):
    """Per-connection kernel telemetry from `ss -ti`: RTT, min-RTT and TCP
    retransmits for every established flow — the light, dependency-free version
    of the eBPF per-flow visibility big shops run. A flow with retransmits or an
    RTT far above its min-RTT is where loss/bufferbloat is biting."""
    if not _have('ss'):
        return {'success': False, 'error': 'ss (iproute2) is not available'}
    res = _run(['ss', '-tino'], timeout=8)
    conns, cur = [], None
    for line in res['out'].splitlines():
        if line.startswith('State') or not line.strip():
            continue
        if not line[0].isspace():
            parts = line.split()
            if len(parts) >= 5 and parts[0] == 'ESTAB' and not parts[4].startswith('127.'):
                cur = {'local': parts[3], 'peer': parts[4]}
            else:
                cur = None
        elif cur is not None:
            def g(pat, info=line):
                m = re.search(pat, info)
                return m.group(1) if m else None
            rtt, minrtt = g(r'\brtt:([\d.]+)'), g(r'\bminrtt:([\d.]+)')
            retr = g(r'\bretrans:\d+/(\d+)')
            mss = g(r'\bmss:(\d+)')
            cur.update({'rtt_ms': float(rtt) if rtt else None,
                        'min_rtt_ms': float(minrtt) if minrtt else None,
                        'retransmits': int(retr) if retr else 0,
                        'mss': int(mss) if mss else None})
            conns.append(cur)
            cur = None
    conns.sort(key=lambda c: (c.get('retransmits') or 0, c.get('rtt_ms') or 0), reverse=True)
    return {'success': True, 'total': len(conns),
            'with_retransmits': sum(1 for c in conns if c.get('retransmits')),
            'connections': conns[:_clamp_int(limit, 15, 1, 100)],
            'engine': 'bpftrace' if _have('bpftrace') else 'ss'}


def do_ptp_detect(interface, seconds=8):
    """Detect PTP (IEEE-1588 / PTPv2) on a segment by sniffing the PTP event/
    general UDP ports and the 802.1AS ethertype. Reports whether a grandmaster
    is announcing, which message types are present, and the domain(s). Precise
    clock-offset needs ptp4l running; this is the field 'is PTP here?' check for
    AV-over-IP / finance / 5G-fronthaul networks."""
    interface = (interface or '').strip()
    if not interface:
        return {'success': False, 'error': 'interface required'}
    if not _have('tcpdump'):
        return {'success': False, 'missing_tool': 'tcpdump',
                'error': 'tcpdump is not installed. Click Install to add it.'}
    if interface not in _list_iface_names(include_virtual=True):
        return {'success': False, 'error': f'unknown interface: {interface}'}
    seconds = _clamp_int(seconds, 8, 3, 30)
    res = _run(['timeout', str(seconds), 'tcpdump', '-i', interface, '-nn', '-v', '-c', '200',
                'udp port 319 or udp port 320 or ether proto 0x88f7'], timeout=seconds + 8)
    out = res['out']
    pkt_lines = [l for l in out.splitlines() if re.search(r'\bIP6?\b|PTP|ethertype', l)]
    present = bool(pkt_lines) or 'PTP' in out
    msg_types = set()
    for kw in ('announce', 'sync', 'follow_up', 'delay_req', 'delay_resp', 'pdelay'):
        if kw in out.lower():
            msg_types.add(kw)
    domains = set(re.findall(r'domain\s*(?:number)?\s*:?\s*(\d+)', out, re.I))
    return {'success': True, 'interface': interface, 'seconds': seconds,
            'ptp_present': present,
            'packets': len(pkt_lines),
            'message_types': sorted(msg_types),
            'domains': sorted(domains),
            'note': ('PTP traffic detected on this segment.' if present else
                     'No PTP traffic seen — no grandmaster here, or PTP isn\'t in use.'),
            'offset_note': 'Detection only — precise clock-offset measurement needs a running ptp4l.'}


# --------------------------------------------------------------------------
# On-demand tool install (whitelisted apt packages, invoked from the UI)
# --------------------------------------------------------------------------

# Stable tool key -> (binary to probe, apt package name). Only these packages
# can be installed via /api/net/install-tool, so the tool name is never
# interpolated into a shell command.
_NET_TOOL_PKGS = {
    'ping': ('ping', 'iputils-ping'),
    'lldpd': ('lldpctl', 'lldpd'),
    'arp-scan': ('arp-scan', 'arp-scan'),
    'ethtool': ('ethtool', 'ethtool'),
    'mtr': ('mtr', 'mtr-tiny'),
    'whois': ('whois', 'whois'),
    'traceroute': ('traceroute', 'traceroute'),
    'speedtest-cli': ('speedtest-cli', 'speedtest-cli'),
    'curl': ('curl', 'curl'),
    'dig': ('dig', 'dnsutils'),
    'iperf3': ('iperf3', 'iperf3'),
    'tcpdump': ('tcpdump', 'tcpdump'),
    'wg': ('wg', 'wireguard-tools'),
    'tshark': ('tshark', 'tshark'),
}


def _configure_lldpd():
    """Enable CDPv1/v2/EDP/FDP/SONMP decoding and (re)start lldpd -- mirrors the
    Ragnar installer/updater so on-demand installs also see non-LLDP switches."""
    try:
        os.makedirs('/etc/default', exist_ok=True)
        with open('/etc/default/lldpd', 'w') as f:
            f.write('# Ragnar: decode CDPv1/v2 (Cisco), EDP (Extreme), FDP (Foundry), '
                    'SONMP (Nortel)\n')
            f.write('# neighbours in addition to LLDP, so switch discovery covers '
                    'non-LLDP gear.\n')
            f.write('DAEMON_ARGS="-c -e -f -s"\n')
    except OSError:
        pass
    _run(['systemctl', 'enable', 'lldpd'], timeout=15)
    _run(['systemctl', 'restart', 'lldpd'], timeout=15)


def do_install_tool(tool):
    """Install a missing network tool on demand via apt. Whitelisted packages
    only. The Ragnar service runs as root, so apt is invoked directly."""
    entry = _NET_TOOL_PKGS.get(tool)
    if entry is None:
        return {'success': False, 'error': f'Unknown or non-installable tool: {tool}'}
    binary, pkg = entry
    if _have(binary):
        if tool == 'lldpd':
            _configure_lldpd()
        return {'success': True, 'already_installed': True, 'tool': tool,
                'message': f'{binary} is already installed.'}
    if not _have('apt-get'):
        return {'success': False, 'tool': tool,
                'error': 'apt-get is not available; install the package manually.'}
    env = dict(os.environ)
    env['DEBIAN_FRONTEND'] = 'noninteractive'
    res = _run(['apt-get', 'install', '-y', pkg], timeout=300, env=env)
    if not _have(binary):
        # A stale or empty package index is the usual reason apt can't find the
        # package on an updated (vs freshly installed) box. Refresh once and
        # retry before giving up.
        _run(['apt-get', 'update', '-y'], timeout=180, env=env)
        res = _run(['apt-get', 'install', '-y', pkg], timeout=300, env=env)
    if not _have(binary) and 'dpkg was interrupted' in (res['err'] or '') + (res['out'] or ''):
        # A previously interrupted apt/dpkg run leaves the package system
        # half-configured; apt then refuses to do anything until it's fixed.
        # Recover automatically ('dpkg --configure -a') and retry so the user
        # doesn't have to drop to a shell.
        _run(['dpkg', '--configure', '-a'], timeout=300, env=env)
        res = _run(['apt-get', 'install', '-y', pkg], timeout=300, env=env)
    if not _have(binary):
        tail = (res['err'] or res['out'] or '').strip()
        tail = tail[-400:] if tail else 'no output'
        return {'success': False, 'tool': tool,
                'error': f'Installing {pkg} did not provide {binary}. '
                         f'apt may need a working network / package index. Detail: {tail}'}
    if tool == 'lldpd':
        _configure_lldpd()
    return {'success': True, 'tool': tool, 'message': f'Installed {pkg}.'}


# --------------------------------------------------------------------------
# Route registration
# --------------------------------------------------------------------------

def register_network_diagnostics(app, logger=None):
    """Register all /api/net/* diagnostic routes on the given Flask app."""

    def _log(msg):
        if logger is not None:
            try:
                logger.info(msg)
            except Exception:
                pass

    def _bad(msg, code=400):
        return jsonify({'success': False, 'error': msg}), code

    @app.route('/api/net/ping', methods=['POST'])
    def net_ping():
        data = request.get_json(silent=True) or {}
        target = (data.get('target') or '').strip()
        if not _valid_target(target):
            return _bad('Invalid target')
        _log(f"net/ping {target}")
        return jsonify(do_ping(target, data.get('count', 4)))

    @app.route('/api/net/traceroute', methods=['POST'])
    def net_traceroute():
        data = request.get_json(silent=True) or {}
        target = (data.get('target') or '').strip()
        if not _valid_target(target):
            return _bad('Invalid target')
        _log(f"net/traceroute {target}")
        return jsonify(do_traceroute(target, data.get('max_hops', 20)))

    @app.route('/api/net/mtr', methods=['POST'])
    def net_mtr():
        data = request.get_json(silent=True) or {}
        target = (data.get('target') or '').strip()
        if not _valid_target(target):
            return _bad('Invalid target')
        source = (data.get('source') or '').strip() or None
        if source is not None and not _valid_target(source):
            return _bad('Invalid source')
        _log(f"net/mtr {target}" + (f" from {source}" if source else ""))
        return jsonify(do_mtr(target, data.get('count', 5), source))

    @app.route('/api/net/whois', methods=['POST'])
    def net_whois():
        data = request.get_json(silent=True) or {}
        target = (data.get('target') or '').strip()
        if not _valid_target(target):
            return _bad('Invalid target')
        _log(f"net/whois {target}")
        return jsonify(do_whois(target))

    @app.route('/api/net/speedtest', methods=['POST'])
    def net_speedtest():
        _log("net/speedtest")
        return jsonify(do_speedtest())

    @app.route('/api/net/lldp', methods=['GET'])
    def net_lldp():
        _log("net/lldp")
        return jsonify(do_lldp())

    @app.route('/api/net/arp-scan', methods=['GET'])
    def net_arp_scan():
        iface = (request.args.get('interface') or '').strip()
        if not _valid_iface(iface):
            return _bad('Invalid or missing interface')
        _log(f"net/arp-scan {iface}")
        return jsonify(do_arp_scan(iface))

    @app.route('/api/net/arp-check', methods=['GET'])
    def net_arp_check():
        _log("net/arp-check")
        return jsonify(do_arp_check())

    @app.route('/api/net/arp-baseline', methods=['GET', 'POST'])
    def net_arp_baseline():
        # POST {action:'reset'} clears the trusted gateway baseline so the
        # current binding is re-learned (after a legitimate gateway change).
        action = 'get'
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            action = 'reset' if (data.get('action') == 'reset') else 'get'
        _log(f"net/arp-baseline {action}")
        return jsonify(do_arp_baseline(action))

    @app.route('/api/net/dhcp-guardian', methods=['GET'])
    def net_dhcp_guardian():
        iface = (request.args.get('interface') or '').strip() or None
        secs = _clamp_int(request.args.get('seconds'), 6, 2, 20)
        quick = request.args.get('quick', '0') in ('1', 'true', 'yes')
        _log(f"net/dhcp-guardian iface={iface} quick={quick}")
        return jsonify(do_dhcp_guardian(interface=iface, capture_seconds=secs, quick=quick))

    @app.route('/api/net/dhcp-baseline', methods=['GET', 'POST'])
    def net_dhcp_baseline():
        action = 'get'
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            action = 'reset' if (data.get('action') == 'reset') else 'get'
        _log(f"net/dhcp-baseline {action}")
        return jsonify(do_dhcp_baseline(action))

    @app.route('/api/net/dhcp-snoop/status', methods=['GET'])
    def net_dhcp_snoop_status():
        _log("net/dhcp-snoop/status")
        return jsonify(do_dhcp_snoop_status())

    @app.route('/api/net/dhcp-snoop/config', methods=['GET', 'POST'])
    def net_dhcp_snoop_config():
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            t = (data.get('trusted') or '').strip() or None
            u = (data.get('untrusted') or '').strip() or None
            _log(f"net/dhcp-snoop/config trusted={t} untrusted={u}")
            return jsonify(do_dhcp_snoop_config(trusted=t, untrusted=u))
        return jsonify(do_dhcp_snoop_config())

    @app.route('/api/net/dhcp-snoop/setup', methods=['POST'])
    def net_dhcp_snoop_setup():
        data = request.get_json(silent=True) or {}
        action = 'destroy' if (data.get('action') == 'destroy') else 'create'
        a = (data.get('iface_a') or '').strip()
        b = (data.get('iface_b') or '').strip()
        _log(f"net/dhcp-snoop/setup {action} {a} {b}")
        return jsonify(do_dhcp_snoop_setup(a, b, action=action))

    @app.route('/api/net/dhcp-snoop', methods=['GET'])
    def net_dhcp_snoop():
        t = (request.args.get('trusted') or '').strip() or None
        u = (request.args.get('untrusted') or '').strip() or None
        secs = _clamp_int(request.args.get('seconds'), 20, 4, 60)
        _log(f"net/dhcp-snoop trusted={t} untrusted={u} secs={secs}")
        return jsonify(do_dhcp_snoop(trusted=t, untrusted=u, seconds=secs))

    @app.route('/api/net/mac-watch', methods=['GET'])
    def net_mac_watch():
        # scan=0 reads the neighbour table only (no arp-scan sweep, silent);
        # default runs an arp-scan sweep to widen coverage.
        scan = request.args.get('scan', '1') not in ('0', 'false', 'no')
        iface = (request.args.get('interface') or '').strip() or None
        _log(f"net/mac-watch scan={scan}")
        return jsonify(do_mac_watch(scan=scan, interface=iface))

    @app.route('/api/net/mac-watch-reset', methods=['POST'])
    def net_mac_watch_reset():
        _log("net/mac-watch-reset")
        return jsonify(do_mac_watch_reset())

    @app.route('/api/net/identity', methods=['GET'])
    def net_identity():
        _log("net/identity")
        return jsonify(do_network_identity())

    @app.route('/api/net/install-tool', methods=['POST'])
    def net_install_tool():
        data = request.get_json(silent=True) or {}
        tool = (data.get('tool') or '').strip()
        _log(f"net/install-tool {tool}")
        return jsonify(do_install_tool(tool))

    @app.route('/api/net/interfaces', methods=['GET'])
    def net_interfaces():
        _log("net/interfaces")
        include_virtual = request.args.get('all') in ('1', 'true', 'yes')
        return jsonify(do_interfaces(include_virtual=include_virtual))

    @app.route('/api/net/isp', methods=['GET'])
    def net_isp():
        iface = (request.args.get('interface') or '').strip() or None
        _log(f"net/isp {iface or 'all'}")
        return jsonify(do_isp(interface=iface))

    @app.route('/api/net/vpn-check', methods=['GET'])
    def net_vpn_check():
        iface = (request.args.get('interface') or '').strip() or None
        if iface is not None and not _valid_iface(iface):
            return _bad('Invalid interface')
        _log(f"net/vpn-check {iface or 'default-route'}")
        return jsonify(do_vpn_check(interface=iface))

    @app.route('/api/net/dns', methods=['POST'])
    def net_dns():
        data = request.get_json(silent=True) or {}
        _log("net/dns")
        return jsonify(do_dns_doctor(data.get('name') or data.get('target')))

    @app.route('/api/net/pmtu', methods=['POST'])
    def net_pmtu():
        data = request.get_json(silent=True) or {}
        _log("net/pmtu")
        return jsonify(do_pmtu(data.get('target')))

    @app.route('/api/net/captive-portal', methods=['GET'])
    def net_captive_portal():
        _log("net/captive-portal")
        return jsonify(do_captive_portal())

    @app.route('/api/net/iperf3', methods=['POST'])
    def net_iperf3():
        data = request.get_json(silent=True) or {}
        _log(f"net/iperf3 client {data.get('server')}")
        return jsonify(do_iperf3_client(data.get('server'), data.get('port', 5201),
                                        data.get('duration', 5),
                                        bool(data.get('reverse')), bool(data.get('udp'))))

    @app.route('/api/net/iperf3-server', methods=['POST'])
    def net_iperf3_server():
        data = request.get_json(silent=True) or {}
        action = (data.get('action') or 'status').strip()
        _log(f"net/iperf3-server {action}")
        return jsonify(do_iperf3_server(action))

    @app.route('/api/net/pcap', methods=['POST'])
    def net_pcap():
        _log("net/pcap upload")
        return jsonify(do_pcap_from_upload(request.files.get('file')))

    @app.route('/api/net/flows', methods=['GET'])
    def net_flows():
        _log("net/flows")
        return jsonify(do_flow_telemetry(request.args.get('limit', 15)))

    @app.route('/api/net/ptp', methods=['POST'])
    def net_ptp():
        data = request.get_json(silent=True) or {}
        iface = (data.get('interface') or '').strip()
        _log(f"net/ptp {iface}")
        return jsonify(do_ptp_detect(iface, data.get('seconds', 8)))

    @app.route('/api/net/l2-health', methods=['POST'])
    def net_l2_health():
        data = request.get_json(silent=True) or {}
        iface = (data.get('interface') or '').strip()
        _log(f"net/l2-health {iface}")
        return jsonify(do_l2_health(iface, data.get('seconds', 12)))

    @app.route('/api/net/locate-port', methods=['POST'])
    def net_locate_port():
        data = request.get_json(silent=True) or {}
        iface = (data.get('interface') or '').strip()
        _log(f"net/locate-port {iface}")
        return jsonify(do_locate_port(iface, data.get('count', 6),
                                      data.get('on_ms', 800), data.get('off_ms', 800),
                                      bool(data.get('force'))))

    if logger is not None:
        try:
            logger.info("Network diagnostics routes registered (/api/net/*)")
        except Exception:
            pass
    return app
