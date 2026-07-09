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

import bgp_speaker
import path_asymmetry

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


def _have_scapy():
    """True if the Scapy Python module is importable (not just the CLI). Scapy is
    optional — only the scanners' end-to-end self-test leg uses it — so this is a
    lightweight spec check that doesn't pay Scapy's slow import."""
    try:
        import importlib.util
        return importlib.util.find_spec('scapy') is not None
    except Exception:
        return False


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
# IGMP Watch: passive IGMP-snooping security scanner (detection-only)
# --------------------------------------------------------------------------
# IGMP is the low-volume control plane of IPv4 multicast: hosts announce group
# membership (reports/joins), the multicast router periodically queries. That
# makes it a cheap, high-signal thing to watch on a Pi Zero 2 W — a few
# packets a minute on a healthy segment. This scanner is PASSIVE: one short
# tcpdump window, parsed and classified. It never joins a group, never sends a
# query, never becomes a querier. Four things it looks for:
#   1. Storm / flood   — an IGMP report/query rate far above normal noise
#      (report floods are a real multicast DoS and a switch-CPU exhaustion vector).
#   2. Anomaly         — >1 querier on the segment. There must be exactly one;
#      a second, lower-IP querier is the classic "become the querier to draw all
#      multicast to yourself" attack, plus version downgrades (v3->v2/v1).
#   3. Reconnaissance  — one host joining a wide spread of distinct groups (or
#      sweeping group-specific queries): multicast stream enumeration.
#   4. Unauthorized join — a host joining an admin-scoped / globally-scoped group
#      it has never been seen on, measured against a learned baseline.
#
# Passive-floor doctrine (see MAC Watch / L2 Health): thresholds sit above the
# ordinary chatter (mDNS 224.0.0.251, SSDP 239.255.255.250, ~125s general
# queries) so a normal segment reads clean. First run learns the querier(s) and
# host->group memberships into data/igmp_watch.json; "Trust current" re-learns.

_IGMP_WATCH_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                'data', 'igmp_watch.json')
_igmp_watch_lock = threading.Lock()

# Total IGMP messages/sec at or above which the window is a storm. IGMP is
# intrinsically low-rate, so even a modest sustained rate is abnormal.
_IGMP_STORM_RATE = 30.0
# One source emitting at or above this many messages in the window is flooding
# on its own (report-flood DoS), independent of the aggregate rate.
_IGMP_SRC_FLOOD = 120
# One source joining at or above this many distinct groups in the window is
# enumerating multicast (reconnaissance).
_IGMP_RECON_GROUPS = 20
# Keep at most this many anomaly events in the store (newest wins).
_IGMP_EVENTS_CAP = 200

# Well-known multicast groups, for readable output and to avoid flagging normal
# service discovery as an unauthorized join.
_IGMP_WELL_KNOWN = {
    '224.0.0.1': 'all-hosts', '224.0.0.2': 'all-routers',
    '224.0.0.5': 'OSPF', '224.0.0.6': 'OSPF-DR', '224.0.0.9': 'RIPv2',
    '224.0.0.13': 'PIM', '224.0.0.18': 'VRRP', '224.0.0.22': 'IGMPv3',
    '224.0.0.102': 'HSRPv2/GLBP', '224.0.0.251': 'mDNS', '224.0.0.252': 'LLMNR',
    '224.0.1.1': 'NTP', '224.0.1.129': 'PTP', '239.255.255.250': 'SSDP/UPnP',
    '239.255.255.253': 'SLP',
}


def _igmp_scope(group):
    """Classify a multicast group address into a readable scope. Returns
    (scope, sensitive) — sensitive=True means a join there is worth policing
    (admin/global/SSM), False for link-local control traffic (normal)."""
    try:
        octets = [int(x) for x in group.split('.')]
        if len(octets) != 4:
            return ('invalid', False)
    except (ValueError, AttributeError):
        return ('invalid', False)
    a, b, c, _d = octets
    if a == 224 and b == 0 and c == 0:
        return ('link-local control', False)   # 224.0.0.0/24 — normal
    if a == 239:
        return ('admin-scoped (private)', True)  # 239.0.0.0/8
    if a == 232:
        return ('source-specific (SSM)', True)   # 232.0.0.0/8
    if 224 <= a <= 238:
        return ('globally-scoped', True)
    return ('other', False)


_IGMP_IP_RE = r'(\d{1,3}(?:\.\d{1,3}){3})'


def _parse_igmp_capture(output):
    """Parse `tcpdump -nn -t -v 'igmp'` text into a list of membership events:
    {src, group, kind, version}. kind is 'query' | 'report' | 'leave'.

    Handles v1/v2 reports (dst == group), v2 leaves, and v3 reports whose group
    records tcpdump prints as `gaddr <addr> ...` (one event per group record).
    Robust to tcpdump version differences: it keys off the `igmp` keyword and
    pulls every group address it can find rather than a single rigid format."""
    events = []
    ver_re = re.compile(r'igmp\s+v(\d)', re.I)
    src_re = re.compile(r'^' + _IGMP_IP_RE + r'\s*>\s*' + _IGMP_IP_RE)
    gaddr_re = re.compile(r'gaddr\s+' + _IGMP_IP_RE, re.I)
    # v3 record modes that mean "leaving / no interest" vs joining.
    leave_modes = ('to_in', 'is_in', 'block')
    for raw in output.splitlines():
        line = raw.strip()
        if 'igmp' not in line.lower():
            continue
        sm = src_re.search(line)
        src = sm.group(1) if sm else None
        dst = sm.group(2) if sm else None
        vm = ver_re.search(line)
        version = int(vm.group(1)) if vm else 2
        low = line.lower()
        if 'query' in low:
            events.append({'src': src, 'group': None, 'kind': 'query',
                           'version': version})
            continue
        if 'leave' in low:
            # v2 leave-group: the left group is named after "leave" or is dst.
            lm = re.search(r'leave.*?' + _IGMP_IP_RE, low)
            grp = (lm.group(1) if lm else None) or (dst if dst != '224.0.0.2' else None)
            events.append({'src': src, 'group': grp, 'kind': 'leave',
                           'version': version})
            continue
        if 'report' in low:
            gaddrs = gaddr_re.findall(line)
            if gaddrs:
                # v3 report — one event per group record.
                for g in gaddrs:
                    # crude record-mode read near this gaddr; default to report.
                    seg = low.split(g.lower(), 1)[-1][:24]
                    kind = 'leave' if any(m in seg for m in leave_modes) and '{ }' in seg else 'report'
                    events.append({'src': src, 'group': g, 'kind': kind,
                                   'version': version})
            else:
                # v1/v2 report — the destination address IS the group.
                grp = None
                rm = re.search(r'report\s+' + _IGMP_IP_RE, low)
                grp = rm.group(1) if rm else (dst if dst and dst not in _IGMP_WELL_KNOWN else dst)
                events.append({'src': src, 'group': grp, 'kind': 'report',
                               'version': version})
    return events


def _igmp_watch_load():
    try:
        with open(_IGMP_WATCH_PATH) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _igmp_watch_save(d):
    try:
        os.makedirs(os.path.dirname(_IGMP_WATCH_PATH), exist_ok=True)
        tmp = _IGMP_WATCH_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, _IGMP_WATCH_PATH)
    except OSError:
        pass


def do_igmp_baseline(action='get'):
    """Manage the learned IGMP baseline (trusted querier(s) + known host->group
    memberships). action='reset' clears it so the current segment is re-learned
    on the next scan (use after a legitimate multicast/router change)."""
    with _igmp_watch_lock:
        if action == 'reset':
            _igmp_watch_save({})
            return {'success': True, 'reset': True, 'baseline': {}}
        b = _igmp_watch_load()
        return {'success': True, 'baseline': {
            'queriers': sorted(b.get('queriers') or []),
            'groups': sorted((b.get('members') or {}).keys()),
        }}


def _igmp_analyze(events, seconds, baseline, learn=True):
    """Pure classifier over parsed IGMP events. Returns the result payload
    (minus interface). Separated from capture so the self-test can drive it with
    synthetic packets. May mutate+persist `baseline` when learn=True."""
    seconds = max(1, int(seconds))
    total = len(events)
    rate = round(total / seconds, 1)

    queriers = sorted({e['src'] for e in events if e['kind'] == 'query' and e['src']})
    per_src = {}
    src_groups = {}
    members = {}
    for e in events:
        s = e.get('src')
        if s:
            per_src[s] = per_src.get(s, 0) + 1
        g = e.get('group')
        if g and e['kind'] == 'report':
            src_groups.setdefault(s, set()).add(g)
            members.setdefault(g, set()).add(s)

    trusted_q = set(baseline.get('queriers') or [])
    known_members = {g: set(v) for g, v in (baseline.get('members') or {}).items()}
    learned = False
    # Learn-on-first-run: an empty baseline adopts the current querier(s) and
    # memberships as trusted (mirrors ARP/DHCP baseline behaviour).
    if learn and not trusted_q and not known_members and (queriers or members):
        baseline['queriers'] = queriers
        baseline['members'] = {g: sorted(v) for g, v in members.items()}
        learned = True
        trusted_q = set(queriers)
        known_members = {g: set(v) for g, v in members.items()}

    findings = []       # (level, category, text)
    categories = set()

    # (1) storm / flood
    if rate >= _IGMP_STORM_RATE:
        categories.add('storm')
        findings.append(('crit', 'storm',
                         f'IGMP rate {rate}/s over {seconds}s ({total} msgs) — '
                         'far above normal; multicast report/query flood'))
    floods = sorted([(s, n) for s, n in per_src.items() if n >= _IGMP_SRC_FLOOD],
                    key=lambda x: -x[1])
    for s, n in floods:
        categories.add('storm')
        findings.append(('crit', 'storm',
                         f'{s} sent {n} IGMP messages in {seconds}s — single-source flood'))

    # (2) anomaly — rogue / extra querier, version downgrade
    if len(queriers) > 1:
        categories.add('anomaly')
        extra = [q for q in queriers if q not in trusted_q] or queriers[1:]
        findings.append(('crit', 'anomaly',
                         f'{len(queriers)} IGMP queriers on the segment '
                         f'({", ".join(queriers)}) — there must be exactly one; '
                         f'possible rogue querier ({", ".join(extra)}) drawing multicast'))
    elif queriers and trusted_q and queriers[0] not in trusted_q:
        categories.add('anomaly')
        findings.append(('warn', 'anomaly',
                         f'querier is {queriers[0]}, not the trusted '
                         f'{", ".join(sorted(trusted_q))} — querier takeover'))
    q_versions = sorted({e['version'] for e in events if e['kind'] == 'query'})
    if len(q_versions) > 1:
        categories.add('anomaly')
        findings.append(('warn', 'anomaly',
                         f'mixed IGMP query versions {q_versions} — possible '
                         'version-downgrade to force weaker v1/v2'))

    # (3) reconnaissance — a source joining many distinct groups
    recon = sorted([(s, len(g)) for s, g in src_groups.items() if len(g) >= _IGMP_RECON_GROUPS],
                   key=lambda x: -x[1])
    recon_srcs = {s for s, _n in recon}
    for s, n in recon:
        categories.add('recon')
        findings.append(('warn', 'recon',
                         f'{s} joined {n} distinct multicast groups in {seconds}s '
                         '— multicast group enumeration (reconnaissance)'))

    # (4) unauthorized join — a new host on a sensitive (admin/global/SSM) group.
    # A source already flagged as recon is folded under that finding — its joins
    # are the enumeration, not N separate unauthorized alerts.
    unauth = []
    if trusted_q or known_members:   # only meaningful once a baseline exists
        for g, srcs in members.items():
            scope, sensitive = _igmp_scope(g)
            if not sensitive:
                continue
            for s in srcs:
                if s in recon_srcs:
                    continue
                if s not in known_members.get(g, set()):
                    unauth.append((s, g, scope))
    for s, g, scope in unauth:
        categories.add('unauthorized')
        name = _IGMP_WELL_KNOWN.get(g)
        findings.append(('warn', 'unauthorized',
                         f'{s} joined {g}{" (" + name + ")" if name else ""} '
                         f'[{scope}] — not in the learned baseline (unauthorized join)'))

    # verdict = most severe triggered category
    order = ['storm', 'anomaly', 'unauthorized', 'recon']
    verdict = next((c for c in order if c in categories), 'clean')
    if not findings:
        findings.append(('ok', 'clean', 'No IGMP anomalies in the capture window.'))

    groups_out = []
    for g in sorted(members.keys()):
        scope, sensitive = _igmp_scope(g)
        srcs = sorted(members[g])
        new = bool((trusted_q or known_members) and
                   any(s not in known_members.get(g, set()) for s in srcs))
        groups_out.append({'group': g, 'name': _IGMP_WELL_KNOWN.get(g),
                           'scope': scope, 'sensitive': sensitive,
                           'members': srcs, 'new': new})

    top_joiners = sorted(([{'src': s, 'groups': len(g)} for s, g in src_groups.items()]),
                         key=lambda x: -x['groups'])[:8]

    return {
        'success': True, 'verdict': verdict, 'seconds': seconds,
        'packets': total, 'rate_per_s': rate, 'learned': learned,
        'queriers': queriers, 'trusted_queriers': sorted(trusted_q),
        'groups': groups_out, 'top_joiners': top_joiners,
        'findings': [{'level': l, 'category': c, 'text': t} for l, c, t in findings],
        'reasons': [t for _l, _c, t in findings if _l != 'ok'],
    }


def _igmp_capture(interface, seconds):
    """Run one passive tcpdump IGMP window and return (raw_text, error)."""
    if not _have('tcpdump'):
        return '', 'tcpdump is not installed. Click Install to add it.'
    res = _run(['timeout', str(seconds), 'tcpdump', '-i', interface,
                '-nn', '-t', '-v', '-s', '256', '-c', '20000', 'igmp'],
               timeout=seconds + 8)
    out = res['out']
    if not out and res['err'] and ('permission' in res['err'].lower()
                                   or "couldn't" in res['err'].lower()
                                   or 'no such device' in res['err'].lower()):
        return '', res['err'].strip()[:200]
    return out, None


def do_igmp_watch(interface=None, seconds=12, learn=True, quick=False):
    """Passive IGMP-snooping security scanner (detection-only). Captures IGMP for
    a few seconds and classifies the segment: storm / anomaly / recon /
    unauthorized / clean. Learns the querier(s) + memberships on first run."""
    iface = interface if _valid_iface(interface or '') else _default_route_iface()
    if not iface:
        return {'success': False, 'error': 'no interface to capture on'}
    if iface not in _list_iface_names(include_virtual=True):
        return {'success': False, 'error': f'unknown interface: {iface}'}
    seconds = _clamp_int(seconds, 12, 4, 30)

    text, err = _igmp_capture(iface, seconds)
    if err:
        return {'success': False, 'interface': iface, 'error': err,
                'missing_tool': 'tcpdump' if 'not installed' in err else None}
    events = _parse_igmp_capture(text)

    with _igmp_watch_lock:
        baseline = _igmp_watch_load()
        result = _igmp_analyze(events, seconds, baseline, learn=learn)
        # Persist a freshly-learned baseline, and append anomaly events to history.
        if result.get('learned'):
            _igmp_watch_save(baseline)
        if result['verdict'] != 'clean':
            b = _igmp_watch_load()
            evs = b.get('events') or []
            evs.append({'ts': int(time.time()), 'verdict': result['verdict'],
                        'reasons': result['reasons'][:6]})
            b['events'] = evs[-_IGMP_EVENTS_CAP:]
            _igmp_watch_save(b)

    result['interface'] = iface
    return result


def _igmp_selftest():
    """Self-test the IGMP detectors with synthetic captures (no root, no live
    traffic). Feeds crafted tcpdump text through the real parser + classifier,
    and — if Scapy is available — also builds real IGMP packets into a pcap and
    parses them back through tcpdump, exercising the capture->parse path end to
    end (mirrors the MAC Watch self-test approach). Returns a results dict."""
    scenarios = []

    def run(name, text, seconds, baseline, expect):
        events = _parse_igmp_capture(text)
        res = _igmp_analyze(events, seconds, dict(baseline), learn=not baseline)
        ok = res['verdict'] == expect
        scenarios.append({'name': name, 'expect': expect,
                          'got': res['verdict'], 'events': len(events),
                          'pass': ok})
        return res

    # 1. clean: one querier + normal service-discovery joins.
    clean = "\n".join([
        "192.168.1.1 > 224.0.0.1: igmp query v2",
        "192.168.1.50 > 224.0.0.251: igmp v2 report 224.0.0.251",
        "192.168.1.51 > 239.255.255.250: igmp v2 report 239.255.255.250",
    ])
    run('clean', clean, 12, {}, 'clean')

    # 2. storm: a report flood from one host.
    storm = "\n".join(
        [f"192.168.1.77 > 239.1.2.3: igmp v2 report 239.1.2.3" for _ in range(400)])
    run('storm', storm, 5, {'queriers': ['192.168.1.1'], 'members': {}}, 'storm')

    # 3. anomaly: a second (rogue) querier appears.
    anomaly = "\n".join([
        "192.168.1.1 > 224.0.0.1: igmp query v2",
        "192.168.1.9 > 224.0.0.1: igmp query v2",
    ])
    run('anomaly', anomaly, 12, {'queriers': ['192.168.1.1'], 'members': {}}, 'anomaly')

    # 4. recon: one host enumerates many groups.
    recon = "\n".join(
        [f"192.168.1.66 > 239.0.0.{i}: igmp v2 report 239.0.0.{i}" for i in range(1, 41)])
    run('recon', recon, 10, {'queriers': ['192.168.1.1'],
                             'members': {'239.0.0.1': ['192.168.1.66']}}, 'recon')

    # 5. unauthorized: a new host joins an admin-scoped group not in baseline.
    unauth = "192.168.1.200 > 239.5.5.5: igmp v2 report 239.5.5.5"
    run('unauthorized', unauth, 12,
        {'queriers': ['192.168.1.1'], 'members': {'239.1.1.1': ['192.168.1.50']}},
        'unauthorized')

    # 6. v3 group-record parse (via gaddr) — assert the group is extracted.
    v3 = ("192.168.1.50 > 224.0.0.22: igmp v3 report, 1 group record(s) "
          "[gaddr 239.9.9.9 to_ex { }]")
    v3_events = _parse_igmp_capture(v3)
    v3_ok = any(e['group'] == '239.9.9.9' and e['kind'] == 'report' for e in v3_events)
    scenarios.append({'name': 'v3-parse', 'expect': 'group 239.9.9.9',
                      'got': str([e.get('group') for e in v3_events]),
                      'pass': v3_ok})

    # Optional Scapy end-to-end: craft real IGMP packets -> pcap -> tcpdump -> parse.
    scapy_result = {'ran': False, 'reason': 'scapy or tcpdump unavailable'}
    try:
        import tempfile
        from scapy.all import IP, Ether, wrpcap  # noqa
        try:
            from scapy.contrib.igmp import IGMP
        except Exception:
            IGMP = None
        if IGMP is not None and _have('tcpdump'):
            pkts = [Ether() / IP(src='192.168.1.50', dst='239.7.7.7') /
                    IGMP(type=0x16, gaddr='239.7.7.7')]
            with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tf:
                pcap_path = tf.name
            wrpcap(pcap_path, pkts)
            res = _run(['tcpdump', '-nn', '-t', '-v', '-r', pcap_path, 'igmp'],
                       timeout=10)
            evs = _parse_igmp_capture(res['out'])
            got = [e.get('group') for e in evs]
            scapy_result = {'ran': True, 'groups': got,
                            'pass': any(g == '239.7.7.7' for g in got),
                            'tcpdump_out': res['out'].strip()[:200]}
            try:
                os.remove(pcap_path)
            except OSError:
                pass
    except Exception as e:
        scapy_result = {'ran': False, 'reason': f'{type(e).__name__}: {e}'}

    passed = all(s['pass'] for s in scenarios) and \
        (not scapy_result.get('ran') or scapy_result.get('pass'))
    return {'success': passed, 'scenarios': scenarios, 'scapy': scapy_result}


# --------------------------------------------------------------------------
# OSPF Watch: passive OSPF security scanner (detection-only)
# --------------------------------------------------------------------------
# OSPF is the interior routing control plane (IP proto 89, multicast 224.0.0.5/6).
# It is the classic target for route poisoning: without cryptographic auth, any
# host on the segment can inject/spoof LSAs and silently redirect traffic
# (persistent OSPF poisoning, disguised-LSA and fight-back-bypass attacks —
# Nakibly et al.). This scanner is PASSIVE: one short tcpdump window, parsed and
# classified. It never forms an adjacency, never floods an LSA, never touches the
# LSDB — inspired by OSPFwatcher (topology-change monitoring) and FRR-MAD
# (expected-vs-observed LSDB anomaly detection), approximated here from the wire
# with a learned baseline. What it looks for:
#   * weak_auth — Auth Type 0 (none) / 1 (plaintext). The enabler for every
#     injection attack, and the one thing we can always see. Surfaces advisories.
#   * anomaly   — a new/rogue OSPF router (adjacency spoofing), a duplicate
#     Router-ID (RID conflict/spoof), DR takeover, or Hello parameter mismatch.
#   * injection — an LSA whose Advertising Router isn't a known router (spoofed
#     LSA), a MaxSequence (0x7fffffff) or MaxAge fight-provoking LSA, rapid
#     re-origination of one LSA (fight-back = active injection in progress), or a
#     new AS-External (Type-5) originator (route injection / default hijack).
#   * storm     — an LS-Update flood (control-plane DoS).
# Version-specific CVEs (FRR/Quagga ospfd crashes via malformed/opaque LSAs) are
# NOT visible on the wire, so instead of guessing a version we detect the
# exposure conditions and point at OSV for a version lookup (honest by design).

_OSPF_WATCH_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                'data', 'ospf_watch.json')
_ospf_watch_lock = threading.Lock()

_OSPF_MAXAGE = 3600            # LSA MaxAge — used by the premature-aging attack
_OSPF_MAXSEQ = 0x7fffffff      # LSA MaxSequence — used by the seq-wrap attack
# LS-Update rate/sec at or above which the window is a flood (LSU is low-rate).
_OSPF_LSU_STORM_RATE = 20.0
# Distinct increasing sequence numbers for one (lsa-id, adv-router) in the window
# at or above which it's rapid re-origination — the fight-back signature.
_OSPF_FIGHTBACK_SEQS = 4
_OSPF_EVENTS_CAP = 200

# Curated OSPF vulnerability references, surfaced by observed condition. Version-
# specific CVEs can't be fingerprinted passively, so these tie to what IS visible
# (auth posture, opaque/malformed LSAs) and point at OSV for the version lookup.
_OSPF_OSV_URL = 'https://osv.dev/list?ecosystem=&q=frr%20ospfd'
_OSPF_ADVISORIES = {
    'no_auth': {
        'severity': 'high',
        'title': 'OSPF without cryptographic authentication',
        'detail': ('Auth Type 0 (none) or 1 (plaintext) lets any host on the '
                   'segment inject or spoof LSAs — the enabler for persistent '
                   'route poisoning, disguised-LSA and fight-back-bypass attacks '
                   '(Nakibly et al.). Enable RFC 5709 HMAC-SHA cryptographic auth '
                   '(OSPFv2) or IPsec AH/ESP (OSPFv3).'),
        'refs': ['RFC 5709'],
    },
    'opaque_lsa': {
        'severity': 'medium',
        'title': 'Opaque/TE LSAs present — patch ospfd for malformed-LSA crashes',
        'detail': ('Opaque (Type 9/10/11) / TE LSAs are on the segment. Several '
                   'FRRouting ospfd DoS crashes are triggered by malformed opaque '
                   'LSAs (e.g. CVE-2024-27913, CVE-2025-61107, CVE-2025-61105). '
                   'The software version is not visible on the wire — check OSV '
                   'for your ospfd build and patch. Cisco ASA/FTD have had '
                   'equivalent OSPF-LSA DoS advisories.'),
        'refs': ['CVE-2024-27913', 'CVE-2025-61107', 'CVE-2025-61105', _OSPF_OSV_URL],
    },
}

_OSPF_LSA_TYPES = [
    (re.compile(r'\bRouter\s+LSA\b', re.I), 'router'),
    (re.compile(r'\bNetwork\s+LSA\b', re.I), 'network'),
    (re.compile(r'\bASBR[- ]Summary\s+LSA\b', re.I), 'asbr-summary'),
    (re.compile(r'\bSummary\s+LSA\b', re.I), 'summary'),
    (re.compile(r'\b(?:AS[- ]?)?External\s+LSA\b', re.I), 'external'),
    (re.compile(r'\bNSSA\s+LSA\b', re.I), 'nssa'),
    (re.compile(r'\b(?:Opaque|Grace|TE)\s+LSA\b', re.I), 'opaque'),
]
_OSPF_IPRE = r'(\d{1,3}(?:\.\d{1,3}){3})'
_OSPF_HDR_RE = re.compile(r'(?:IP6?\s+)?' + _OSPF_IPRE + r'(?:\.\d+)?\s+>\s+\S+:\s+OSPFv(\d),\s*([^,]+)')


def _ospf_pkt_type(kw):
    k = kw.strip().lower()
    if k.startswith('hello'):
        return 'hello'
    if k.startswith('ls-update') or k.startswith('ls update'):
        return 'lsupdate'
    if k.startswith('ls-ack') or k.startswith('ls ack'):
        return 'lsack'
    if k.startswith('database') or k == 'dd':
        return 'dd'
    if k.startswith('ls-request') or k.startswith('ls request'):
        return 'lsrequest'
    return k.split()[0] if k else 'other'


def _parse_ospf_capture(output):
    """Parse `tcpdump -nn -v 'proto ospf'` text into a list of packet dicts:
    {src, version, type, router_id, area, auth, hello{...}, lsas[...]}. Tolerant
    of tcpdump version differences — it keys off the OSPFv2/OSPFv3 header line and
    pulls whatever fields it can from the indented body of each packet."""
    packets = []
    cur = None

    def flush():
        if cur is not None:
            packets.append(cur)

    for raw in output.splitlines():
        line = raw.rstrip()
        h = _OSPF_HDR_RE.search(line)
        if h:
            flush()
            cur = {'src': h.group(1), 'version': int(h.group(2)),
                   'type': _ospf_pkt_type(h.group(3)), 'router_id': None,
                   'area': None, 'auth': None,
                   'hello': None, 'adv_router': None, 'lsas': []}
            continue
        if cur is None:
            continue
        rid = re.search(r'Router-ID\s+' + _OSPF_IPRE, line)
        if rid:
            cur['router_id'] = rid.group(1)
        if cur['area'] is None:
            if re.search(r'Backbone Area', line):
                cur['area'] = '0.0.0.0'
            else:
                am = re.search(r'\bArea\s+' + _OSPF_IPRE, line)
                if am:
                    cur['area'] = am.group(1)
        au = re.search(r'Authentication Type:\s*\w+\s*\((\d)\)', line)
        if au:
            cur['auth'] = int(au.group(1))
        av = re.search(r'Advertising Router:?\s+' + _OSPF_IPRE, line)
        if av and cur['adv_router'] is None:
            cur['adv_router'] = av.group(1)
        if cur['type'] == 'hello':
            hp = cur['hello'] or {'hello_timer': None, 'dead_timer': None,
                                  'mask': None, 'dr': None, 'neighbors': []}
            ht = re.search(r'Hello Timer\s+(\d+)s', line)
            if ht:
                hp['hello_timer'] = int(ht.group(1))
            dt = re.search(r'Dead Timer\s+(\d+)s', line)
            if dt:
                hp['dead_timer'] = int(dt.group(1))
            mk = re.search(r'Mask\s+' + _OSPF_IPRE, line)
            if mk:
                hp['mask'] = mk.group(1)
            dr = re.search(r'Designated Router(?:\s+\(ID\))?\s+' + _OSPF_IPRE, line)
            if dr:
                hp['dr'] = dr.group(1)
            nb = re.search(r'Neighbor\s+' + _OSPF_IPRE, line)
            if nb:
                hp['neighbors'].append(nb.group(1))
            cur['hello'] = hp
        # LSA record line (LS-Update / DD carry these)
        for rx, lsa_type in _OSPF_LSA_TYPES:
            if rx.search(line):
                lid = re.search(r'LSA-ID:?\s+' + _OSPF_IPRE, line)
                adv = re.search(r'Advertising Router:?\s+' + _OSPF_IPRE, line)
                sq = re.search(r'seq\s+(0x[0-9a-fA-F]+)', line)
                ag = re.search(r'age\s+(\d+)', line)
                cur['lsas'].append({
                    'lsa_type': lsa_type,
                    'lsa_id': lid.group(1) if lid else None,
                    'adv_router': (adv.group(1) if adv else cur.get('adv_router')),
                    'seq': int(sq.group(1), 16) if sq else None,
                    'age': int(ag.group(1)) if ag else None,
                })
                break
    flush()
    return packets


def _ospf_watch_load():
    try:
        with open(_OSPF_WATCH_PATH) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _ospf_watch_save(d):
    try:
        os.makedirs(os.path.dirname(_OSPF_WATCH_PATH), exist_ok=True)
        tmp = _OSPF_WATCH_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, _OSPF_WATCH_PATH)
    except OSError:
        pass


def do_ospf_baseline(action='get'):
    """Manage the learned OSPF baseline (trusted routers + Type-5 originators).
    action='reset' clears it so the current segment is re-learned next scan."""
    with _ospf_watch_lock:
        if action == 'reset':
            _ospf_watch_save({})
            return {'success': True, 'reset': True, 'baseline': {}}
        b = _ospf_watch_load()
        return {'success': True, 'baseline': {
            'routers': sorted(b.get('routers') or []),
            'asbrs': sorted(b.get('asbrs') or []),
        }}


def _ospf_analyze(packets, seconds, baseline, learn=True):
    """Pure classifier over parsed OSPF packets. Returns the result payload
    (minus interface). Split from capture so the self-test can drive it with
    synthetic packets. May mutate+persist `baseline` when learn=True."""
    seconds = max(1, int(seconds))
    hellos = [p for p in packets if p['type'] == 'hello']
    lsupdates = [p for p in packets if p['type'] == 'lsupdate']
    total = len(packets)

    # routers seen (via Hello Router-ID), and the src IP(s) each was seen from
    rid_srcs = {}
    for p in hellos:
        if p.get('router_id'):
            rid_srcs.setdefault(p['router_id'], set()).add(p.get('src'))
    routers_seen = set(rid_srcs.keys())

    # auth posture
    auth_types = sorted({p['auth'] for p in packets if p.get('auth') is not None})

    # all LSAs, flattened
    lsas = []
    for p in lsupdates:
        for l in p['lsas']:
            l = dict(l)
            l['pkt_src'] = p.get('src')
            l['pkt_router_id'] = p.get('router_id')
            lsas.append(l)
    adv_routers = {l['adv_router'] for l in lsas if l.get('adv_router')}
    asbrs_seen = {l['adv_router'] for l in lsas
                  if l.get('lsa_type') == 'external' and l.get('adv_router')}
    has_opaque = any(l.get('lsa_type') == 'opaque' for l in lsas)

    trusted_routers = set(baseline.get('routers') or [])
    trusted_asbrs = set(baseline.get('asbrs') or [])
    known_advs = set(baseline.get('advs') or []) | trusted_routers
    learned = False
    have_baseline = bool(trusted_routers or known_advs or baseline.get('asbrs') is not None)
    if learn and not have_baseline and (routers_seen or adv_routers):
        baseline['routers'] = sorted(routers_seen)
        baseline['advs'] = sorted(adv_routers | routers_seen)
        baseline['asbrs'] = sorted(asbrs_seen)
        learned = True
        trusted_routers = set(routers_seen)
        known_advs = adv_routers | routers_seen
        trusted_asbrs = set(asbrs_seen)
        have_baseline = True

    findings = []      # (level, category, text)
    categories = set()
    advisories = []

    # weak / no authentication
    if 0 in auth_types:
        categories.add('weak_auth')
        advisories.append(dict(_OSPF_ADVISORIES['no_auth'], key='no_auth'))
        findings.append(('warn', 'weak_auth',
                         'OSPF packets use Authentication Type 0 (none) — any host '
                         'can inject LSAs; enable cryptographic auth'))
    if 1 in auth_types:
        categories.add('weak_auth')
        if not any(a.get('key') == 'no_auth' for a in advisories):
            advisories.append(dict(_OSPF_ADVISORIES['no_auth'], key='no_auth'))
        findings.append(('warn', 'weak_auth',
                         'OSPF uses Authentication Type 1 (plaintext) — trivially '
                         'forged; move to cryptographic (HMAC) auth'))

    # storm
    lsu_rate = round(len(lsupdates) / seconds, 1)
    if lsu_rate >= _OSPF_LSU_STORM_RATE:
        categories.add('storm')
        findings.append(('crit', 'storm',
                         f'{len(lsupdates)} LS-Updates in {seconds}s ({lsu_rate}/s) '
                         '— OSPF flooding / control-plane DoS'))

    # rogue / new router (adjacency spoofing)
    if have_baseline:
        for rid in sorted(routers_seen - trusted_routers):
            categories.add('anomaly')
            findings.append(('warn', 'anomaly',
                             f'new OSPF router {rid} (from {", ".join(sorted(s for s in rid_srcs[rid] if s))}) '
                             '— not in the learned baseline (possible rogue adjacency)'))
    # duplicate Router-ID (conflict / spoof)
    for rid, srcs in rid_srcs.items():
        real = {s for s in srcs if s}
        if len(real) > 1:
            categories.add('anomaly')
            findings.append(('crit', 'anomaly',
                             f'Router-ID {rid} claimed by multiple sources '
                             f'({", ".join(sorted(real))}) — Router-ID conflict or spoof'))
    # Hello parameter mismatch on the segment
    hp_params = {(p['hello'].get('hello_timer'), p['hello'].get('dead_timer'), p.get('area'))
                 for p in hellos if p.get('hello')}
    hp_params = {x for x in hp_params if x != (None, None, None)}
    if len(hp_params) > 1:
        categories.add('anomaly')
        findings.append(('warn', 'anomaly',
                         'mismatched Hello parameters (hello/dead timer or area) on '
                         'the segment — misconfig or an attacker probing for adjacency'))

    # injection — spoofed advertising router
    if have_baseline:
        spoofed = sorted({a for a in adv_routers if a not in known_advs and a not in routers_seen})
        for a in spoofed:
            categories.add('injection')
            findings.append(('crit', 'injection',
                             f'LSA advertised by {a}, which never announced itself via '
                             'Hello and is not in the baseline — spoofed/injected LSA'))
        # new AS-External (Type-5) originator — route injection / default hijack
        for a in sorted(asbrs_seen - trusted_asbrs):
            categories.add('injection')
            findings.append(('crit', 'injection',
                             f'new AS-External (Type-5) LSAs from {a} — not a known '
                             'ASBR; possible route injection / default-route hijack'))

    # MaxSequence / MaxAge attack signatures
    if any(l.get('seq') == _OSPF_MAXSEQ for l in lsas):
        categories.add('injection')
        findings.append(('crit', 'injection',
                         'LSA with MaxSequence (0x7fffffff) — sequence-wrap attack to '
                         'force LSDB reset'))
    # MaxAge for an LSA-ID that is ALSO seen fresh in the window = premature-aging
    fresh_ids = {l['lsa_id'] for l in lsas if l.get('age') is not None and l['age'] < _OSPF_MAXAGE}
    maxage_hot = sorted({l['lsa_id'] for l in lsas
                         if l.get('age') is not None and l['age'] >= _OSPF_MAXAGE
                         and l['lsa_id'] in fresh_ids and l['lsa_id']})
    for lid in maxage_hot:
        categories.add('injection')
        findings.append(('warn', 'injection',
                         f'LSA {lid} flooded at MaxAge while also fresh — premature-'
                         'aging (MaxAge) attack to flush it from the LSDB'))

    # fight-back — rapid re-origination of one (lsa-id, adv-router)
    seq_by_lsa = {}
    for l in lsas:
        if l.get('lsa_id') and l.get('adv_router') and l.get('seq') is not None:
            seq_by_lsa.setdefault((l['lsa_id'], l['adv_router']), set()).add(l['seq'])
    for (lid, adv), seqs in seq_by_lsa.items():
        if len(seqs) >= _OSPF_FIGHTBACK_SEQS:
            categories.add('injection')
            findings.append(('crit', 'injection',
                             f'LSA {lid} from {adv} re-originated {len(seqs)} times with '
                             'rising sequence — fight-back: the owner is countering an '
                             'active LSA injection'))

    if has_opaque:
        advisories.append(dict(_OSPF_ADVISORIES['opaque_lsa'], key='opaque_lsa'))

    # version anomaly
    versions = sorted({p['version'] for p in packets})
    if len(versions) > 1:
        categories.add('anomaly')
        findings.append(('warn', 'anomaly',
                         f'mixed OSPF versions {versions} on the segment'))

    order = ['storm', 'injection', 'anomaly', 'weak_auth']
    verdict = next((c for c in order if c in categories), 'clean')
    if not findings:
        findings.append(('ok', 'clean', 'No OSPF anomalies in the capture window.'))

    routers_out = []
    for rid in sorted(routers_seen):
        routers_out.append({'router_id': rid,
                            'sources': sorted(s for s in rid_srcs[rid] if s),
                            'new': bool(have_baseline and rid not in trusted_routers)})
    lsa_summary = {}
    for l in lsas:
        lsa_summary[l['lsa_type']] = lsa_summary.get(l['lsa_type'], 0) + 1

    return {
        'success': True, 'verdict': verdict, 'seconds': seconds,
        'packets': total, 'hellos': len(hellos), 'ls_updates': len(lsupdates),
        'lsu_per_s': lsu_rate, 'learned': learned,
        'auth_types': auth_types, 'versions': versions,
        'routers': routers_out, 'trusted_routers': sorted(trusted_routers),
        'lsa_counts': lsa_summary,
        'advisories': [{'key': a.get('key'), 'severity': a['severity'],
                        'title': a['title'], 'detail': a['detail'],
                        'refs': a.get('refs', [])} for a in advisories],
        'findings': [{'level': l, 'category': c, 'text': t} for l, c, t in findings],
        'reasons': [t for _l, _c, t in findings if _l != 'ok'],
    }


def _ospf_capture(interface, seconds):
    """Run one passive tcpdump OSPF window and return (raw_text, error)."""
    if not _have('tcpdump'):
        return '', 'tcpdump is not installed. Click Install to add it.'
    res = _run(['timeout', str(seconds), 'tcpdump', '-i', interface,
                '-nn', '-t', '-v', '-s', '512', '-c', '20000', 'proto', 'ospf'],
               timeout=seconds + 8)
    out = res['out']
    if not out and res['err'] and ('permission' in res['err'].lower()
                                   or "couldn't" in res['err'].lower()
                                   or 'no such device' in res['err'].lower()):
        return '', res['err'].strip()[:200]
    return out, None


def do_ospf_watch(interface=None, seconds=15, learn=True, quick=False):
    """Passive OSPF security scanner (detection-only). Captures OSPF for a few
    seconds and classifies the segment: weak_auth / anomaly / injection / storm /
    clean, with CVE/OSV advisories for observed exposure conditions. Learns the
    routers + Type-5 originators on first run; never forms an adjacency."""
    iface = interface if _valid_iface(interface or '') else _default_route_iface()
    if not iface:
        return {'success': False, 'error': 'no interface to capture on'}
    if iface not in _list_iface_names(include_virtual=True):
        return {'success': False, 'error': f'unknown interface: {iface}'}
    seconds = _clamp_int(seconds, 15, 5, 40)

    text, err = _ospf_capture(iface, seconds)
    if err:
        return {'success': False, 'interface': iface, 'error': err,
                'missing_tool': 'tcpdump' if 'not installed' in err else None}
    packets = _parse_ospf_capture(text)

    with _ospf_watch_lock:
        baseline = _ospf_watch_load()
        result = _ospf_analyze(packets, seconds, baseline, learn=learn)
        if result.get('learned'):
            _ospf_watch_save(baseline)
        if result['verdict'] != 'clean':
            b = _ospf_watch_load()
            evs = b.get('events') or []
            evs.append({'ts': int(time.time()), 'verdict': result['verdict'],
                        'reasons': result['reasons'][:6]})
            b['events'] = evs[-_OSPF_EVENTS_CAP:]
            _ospf_watch_save(b)

    if not packets:
        result['note'] = ('No OSPF seen — this segment may not run OSPF, or the Pi '
                          'is not on the OSPF broadcast domain (put it on a SPAN/'
                          'mirror or the routed VLAN to observe).')
    result['interface'] = iface
    return result


def _ospf_selftest():
    """Self-test the OSPF detectors with synthetic tcpdump captures (no root, no
    live traffic), plus an optional Scapy end-to-end leg (scapy.contrib.ospf ->
    pcap -> tcpdump -> parse). Mirrors the IGMP/MAC Watch self-tests."""
    scenarios = []

    def run(name, text, seconds, baseline, expect):
        pkts = _parse_ospf_capture(text)
        res = _ospf_analyze(pkts, seconds, dict(baseline), learn=not baseline)
        ok = res['verdict'] == expect
        scenarios.append({'name': name, 'expect': expect, 'got': res['verdict'],
                          'packets': len(pkts), 'pass': ok})
        return res

    base = {'routers': ['10.0.0.1', '10.0.0.2'],
            'advs': ['10.0.0.1', '10.0.0.2'], 'asbrs': ['10.0.0.1']}

    clean = "\n".join([
        "10.0.0.1 > 224.0.0.5: OSPFv2, Hello, length 48",
        "\tRouter-ID 10.0.0.1, Backbone Area, Authentication Type: Cryptographic (2)",
        "\tHello Timer 10s, Dead Timer 40s, Mask 255.255.255.0",
        "10.0.0.2 > 224.0.0.5: OSPFv2, LS-Update, length 64",
        "\tRouter-ID 10.0.0.2, Backbone Area, Authentication Type: Cryptographic (2)",
        "\tRouter LSA (1), LSA-ID: 10.0.0.2, Advertising Router: 10.0.0.2, seq 0x80000005, age 12",
    ])
    run('clean', clean, 15, base, 'clean')

    weak = "\n".join([
        "10.0.0.1 > 224.0.0.5: OSPFv2, Hello, length 48",
        "\tRouter-ID 10.0.0.1, Backbone Area, Authentication Type: none (0)",
        "\tHello Timer 10s, Dead Timer 40s, Mask 255.255.255.0",
    ])
    run('weak_auth', weak, 15, base, 'weak_auth')

    rogue = "\n".join([
        "10.0.0.9 > 224.0.0.5: OSPFv2, Hello, length 48",
        "\tRouter-ID 10.0.0.9, Backbone Area, Authentication Type: Cryptographic (2)",
        "\tHello Timer 10s, Dead Timer 40s, Mask 255.255.255.0",
    ])
    run('anomaly', rogue, 15, base, 'anomaly')

    inject = "\n".join([
        "10.0.0.66 > 224.0.0.5: OSPFv2, LS-Update, length 64",
        "\tRouter-ID 10.0.0.1, Backbone Area, Authentication Type: Cryptographic (2)",
        "\tRouter LSA (1), LSA-ID: 10.0.0.66, Advertising Router: 10.0.0.66, seq 0x80000002, age 1",
    ])
    run('injection', inject, 15, base, 'injection')

    maxseq = "\n".join([
        "10.0.0.1 > 224.0.0.5: OSPFv2, LS-Update, length 64",
        "\tRouter-ID 10.0.0.1, Backbone Area, Authentication Type: Cryptographic (2)",
        "\tRouter LSA (1), LSA-ID: 10.0.0.1, Advertising Router: 10.0.0.1, seq 0x7fffffff, age 1",
    ])
    run('injection-maxseq', maxseq, 15, base, 'injection')

    # parser check: a full LS-Update parses out the LSA fields.
    p = _parse_ospf_capture(clean)
    lsu = [x for x in p if x['type'] == 'lsupdate']
    parse_ok = bool(lsu and lsu[0]['lsas'] and
                    lsu[0]['lsas'][0]['adv_router'] == '10.0.0.2' and
                    lsu[0]['lsas'][0]['seq'] == 0x80000005)
    scenarios.append({'name': 'lsa-parse', 'expect': 'adv=10.0.0.2 seq=0x80000005',
                      'got': str(lsu[0]['lsas'][0] if lsu and lsu[0]['lsas'] else None),
                      'pass': parse_ok})

    scapy_result = {'ran': False, 'reason': 'scapy or tcpdump unavailable'}
    try:
        import tempfile
        from scapy.all import IP, Ether, wrpcap  # noqa
        try:
            from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello
        except Exception:
            OSPF_Hdr = None
        if OSPF_Hdr is not None and _have('tcpdump'):
            pkt = (Ether() / IP(src='10.0.0.5', dst='224.0.0.5', proto=89) /
                   OSPF_Hdr(version=2, type=1, src='10.0.0.5', area='0.0.0.0',
                            authtype=0) / OSPF_Hello(mask='255.255.255.0'))
            with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tf:
                pcap_path = tf.name
            wrpcap(pcap_path, [pkt])
            res = _run(['tcpdump', '-nn', '-t', '-v', '-r', pcap_path, 'proto', 'ospf'],
                       timeout=10)
            parsed = _parse_ospf_capture(res['out'])
            got_auth = next((x.get('auth') for x in parsed if x.get('auth') is not None), None)
            scapy_result = {'ran': True, 'parsed_packets': len(parsed),
                            'auth': got_auth, 'pass': len(parsed) >= 1,
                            'tcpdump_out': res['out'].strip()[:200]}
            try:
                os.remove(pcap_path)
            except OSError:
                pass
    except Exception as e:
        scapy_result = {'ran': False, 'reason': f'{type(e).__name__}: {e}'}

    passed = all(s['pass'] for s in scenarios) and \
        (not scapy_result.get('ran') or scapy_result.get('pass'))
    return {'success': passed, 'scenarios': scenarios, 'scapy': scapy_result}


# --------------------------------------------------------------------------
# BGP Path Watch: passive BGP routing-security scanner (detection-only)
# --------------------------------------------------------------------------
# BGP is the exterior/edge routing control plane (TCP 179). Unlike OSPF it is
# unicast between peers, so the Pi only sees it when it is INLINE, on a SPAN/
# mirror, or is itself a peer — this is made explicit in the UI. Where visible,
# BGP is the highest-value thing to watch: origin hijacks, sub-prefix hijacks,
# route leaks and session resets are how traffic gets silently redirected across
# the Internet edge. This scanner is PASSIVE: one short tcpdump window parsed and
# classified. It never opens a session, never announces or withdraws a route.
# Companion to OSPF Watch (L3 routing security). What it looks for:
#   * injection — an announced prefix whose ORIGIN AS changed vs the baseline
#     (prefix / origin hijack), or a new more-specific of a baseline prefix
#     (sub-prefix hijack — the most effective real-world BGP attack).
#   * anomaly   — a new/rogue peer (new AS or BGP-ID), a NOTIFICATION / session
#     reset (teardown / flap), a private or bogon ASN in a received AS-path
#     (route leak), a bogon/martian prefix announcement, an AS-path loop, or a
#     BLACKHOLE community (65535:666).
#   * storm     — a route-churn / UPDATE flood, or a per-peer prefix-count spike
#     (full-table leak).
#   * weak_session — BGP seen but no TCP-MD5/TCP-AO signature (RFC 2385/5925);
#     exposed to off-path session-reset attacks. Advisory only.
# Version CVEs (FRR/BIRD bgpd crashes on malformed UPDATE attributes) aren't on
# the wire, so — as with OSPF — the exposure conditions are flagged and OSV is
# pointed at for the version lookup.

_BGP_WATCH_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'data', 'bgp_watch.json')
_bgp_watch_lock = threading.Lock()

# UPDATE messages/sec at or above which the window is churn/flood.
_BGP_STORM_RATE = 40.0
# A peer announcing at or above this many prefixes in the window, when the
# baseline saw far fewer, is a route-leak (full-table) signature.
_BGP_LEAK_PREFIXES = 500
_BGP_EVENTS_CAP = 200

# Bogon / martian IPv4 prefixes that should never be announced in BGP.
_BGP_BOGON_NETS = [
    ('0.0.0.0', 8), ('10.0.0.0', 8), ('100.64.0.0', 10), ('127.0.0.0', 8),
    ('169.254.0.0', 16), ('172.16.0.0', 12), ('192.0.0.0', 24),
    ('192.0.2.0', 24), ('192.168.0.0', 16), ('198.18.0.0', 15),
    ('198.51.100.0', 24), ('203.0.113.0', 24), ('224.0.0.0', 4), ('240.0.0.0', 4),
]

_BGP_OSV_URL = 'https://osv.dev/list?ecosystem=&q=frr%20bgpd'
_BGP_ADVISORIES = {
    'no_md5': {
        'severity': 'medium',
        'title': 'BGP sessions without TCP-MD5 / TCP-AO authentication',
        'detail': ('No TCP-MD5 (RFC 2385) or TCP-AO (RFC 5925) signature was seen '
                   'on the BGP session. Unauthenticated sessions are exposed to '
                   'off-path RST/session-reset attacks and easier hijacking. '
                   'Enable TCP-MD5/TCP-AO and RPKI Route Origin Validation to '
                   'reject invalid origins.'),
        'refs': ['RFC 2385', 'RFC 5925', 'RFC 6811'],
    },
    'malformed_attr': {
        'severity': 'medium',
        'title': 'Patch bgpd for malformed BGP-UPDATE attribute crashes',
        'detail': ('Malformed BGP path attributes have repeatedly crashed router '
                   'BGP daemons (e.g. FRRouting CVE-2023-38802 via a corrupted '
                   'Tunnel-Encapsulation attribute; CERT VU#347067 covers multiple '
                   'implementations). The software version is not visible on the '
                   'wire — check OSV for your bgpd build and patch.'),
        'refs': ['CVE-2023-38802', 'VU#347067', _BGP_OSV_URL],
    },
}

# Classify an ASN. Only 'reserved' / 'documentation' ASNs are truly illegitimate
# in any AS-path; 'private' (RFC 6996) is normal on internal/DC BGP fabric — which
# is exactly where a passive Pi is most likely to sit — so it is NOT alerted on.
def _bgp_asn_class(asn):
    if asn in (0, 23456, 65535, 4294967295):
        return 'reserved'
    if 64496 <= asn <= 64511 or 65536 <= asn <= 65551:   # RFC 5398 documentation
        return 'documentation'
    if 64512 <= asn <= 65534 or 4200000000 <= asn <= 4294967294:  # RFC 6996 private
        return 'private'
    return None


def _ip_to_int(ip):
    try:
        a, b, c, d = (int(x) for x in ip.split('.'))
        return (a << 24) | (b << 16) | (c << 8) | d
    except (ValueError, AttributeError):
        return None


def _bgp_is_bogon(prefix):
    """True if an IPv4 CIDR announcement falls inside a bogon/martian net."""
    try:
        net, length = prefix.split('/')
        length = int(length)
    except ValueError:
        return False
    n = _ip_to_int(net)
    if n is None:
        return False
    if length < 8:            # absurdly short — /0../7 (near-default hijack)
        return True
    for bnet, blen in _BGP_BOGON_NETS:
        bn = _ip_to_int(bnet)
        if bn is None:
            continue
        mask = (0xffffffff << (32 - blen)) & 0xffffffff
        if length >= blen and (n & mask) == (bn & mask):
            return True
    return False


_BGP_IPRE = r'(\d{1,3}(?:\.\d{1,3}){3})'
_BGP_CIDR_RE = re.compile(r'^' + _BGP_IPRE + r'/(\d{1,2})\s*$')
_BGP_HDR_RE = re.compile(r'(?:IP6?\s+)?' + _BGP_IPRE + r'\.(\d+)\s+>\s+' + _BGP_IPRE + r'\.(\d+):')


def _parse_bgp_capture(output):
    """Parse `tcpdump -nn -t -v 'tcp port 179'` text into BGP messages:
    {src, dst, type, ...}. Tolerant of tcpdump version differences — keys off the
    'Open/Update/Notification/Keepalive Message' lines and pulls whatever path
    attributes and NLRI it can from the indented body."""
    messages = []
    cur = None
    flow = (None, None)   # (src, dst) of the current TCP segment
    nlri_mode = None      # 'announced' | 'withdrawn'
    md5_seen = ['md5' in output.lower()]

    def flush():
        if cur is not None:
            messages.append(cur)

    for raw in output.splitlines():
        line = raw.rstrip()
        h = _BGP_HDR_RE.search(line)
        if h:
            # 179 side is the sender's BGP port; keep src/dst as printed.
            flow = (h.group(1), h.group(3))
        mt = re.search(r'\b(Open|Update|Notification|Keepalive|Route Refresh)\s+Message\b', line)
        if mt:
            flush()
            nlri_mode = None
            cur = {'src': flow[0], 'dst': flow[1],
                   'type': mt.group(1).lower().replace(' ', '_'),
                   'my_as': None, 'holdtime': None, 'bgp_id': None, 'version': None,
                   'as_path': [], 'origin': None, 'next_hop': None,
                   'communities': [], 'announced': [], 'withdrawn': [],
                   'notif_code': None, 'notif_sub': None}
            if cur['type'] == 'open':
                m = re.search(r'my AS\s+(\d+)', line)
                if m:
                    cur['my_as'] = int(m.group(1))
                m = re.search(r'Holdtime\s+(\d+)', line)
                if m:
                    cur['holdtime'] = int(m.group(1))
                m = re.search(r'\bID\s+' + _BGP_IPRE, line)
                if m:
                    cur['bgp_id'] = m.group(1)
            if cur['type'] == 'notification':
                m = re.search(r'Message\s*\(3\),[^,]*,\s*([A-Za-z /]+?)\s*\((\d+)\)', line)
                if m:
                    cur['notif_code'] = m.group(1).strip()
                m = re.search(r'subcode\s+([A-Za-z /]+?)\s*\((\d+)\)', line)
                if m:
                    cur['notif_sub'] = m.group(1).strip()
            continue
        if cur is None:
            continue
        # OPEN continuation
        if cur['type'] == 'open':
            if cur['my_as'] is None:
                m = re.search(r'my AS\s+(\d+)', line)
                if m:
                    cur['my_as'] = int(m.group(1))
            if cur['bgp_id'] is None:
                m = re.search(r'\bID\s+' + _BGP_IPRE, line)
                if m:
                    cur['bgp_id'] = m.group(1)
        # UPDATE attributes + NLRI
        if cur['type'] == 'update':
            # AS numbers come after the final colon (past "length: N, Flags [T]:").
            ap = re.search(r'AS Path\b.*:\s*([0-9][0-9 {},]*)\s*$', line)
            if ap and not cur['as_path']:
                cur['as_path'] = [int(x) for x in re.findall(r'\d+', ap.group(1))]
            og = re.search(r'\bOrigin\b.*?:\s*(IGP|EGP|Incomplete)', line)
            if og:
                cur['origin'] = og.group(1)
            nh = re.search(r'Next Hop\b.*?:\s*' + _BGP_IPRE, line)
            if nh:
                cur['next_hop'] = nh.group(1)
            if re.search(r'\bCommunity\b', line):
                for tok in re.findall(r'\b(\d{1,10}:\d{1,10})\b', line):
                    cur['communities'].append(tok)
            if re.search(r'blackhole', line, re.I):
                cur['communities'].append('blackhole')
            if re.search(r'Updated routes|Advertised routes|Prefixes', line, re.I):
                nlri_mode = 'announced'
            elif re.search(r'Withdrawn routes', line, re.I):
                nlri_mode = 'withdrawn'
            cidr = _BGP_CIDR_RE.match(line.strip())
            if cidr and nlri_mode:
                pfx = f'{cidr.group(1)}/{cidr.group(2)}'
                cur[nlri_mode].append(pfx)
    flush()
    for m in messages:
        m['md5'] = md5_seen[0]
    return messages


def _bgp_watch_load():
    try:
        with open(_BGP_WATCH_PATH) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _bgp_watch_save(d):
    try:
        os.makedirs(os.path.dirname(_BGP_WATCH_PATH), exist_ok=True)
        tmp = _BGP_WATCH_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, _BGP_WATCH_PATH)
    except OSError:
        pass


def do_bgp_baseline(action='get'):
    """Manage the learned BGP baseline (trusted peer ASNs + prefix→origin map).
    action='reset' re-learns the current peers/origins on the next scan."""
    with _bgp_watch_lock:
        if action == 'reset':
            _bgp_watch_save({})
            return {'success': True, 'reset': True, 'baseline': {}}
        b = _bgp_watch_load()
        return {'success': True, 'baseline': {
            'peers': sorted(b.get('peers') or []),
            'prefixes': len((b.get('origins') or {})),
        }}


def _bgp_analyze(messages, seconds, baseline, learn=True):
    """Pure classifier over parsed BGP messages. Returns the result payload
    (minus interface). Split from capture so the self-test can drive it."""
    seconds = max(1, int(seconds))
    opens = [m for m in messages if m['type'] == 'open']
    updates = [m for m in messages if m['type'] == 'update']
    notifs = [m for m in messages if m['type'] == 'notification']
    total = len(messages)

    peers = sorted({m['my_as'] for m in opens if m.get('my_as')})
    peer_ids = sorted({m['bgp_id'] for m in opens if m.get('bgp_id')})
    md5 = any(m.get('md5') for m in messages)

    # prefix -> origin AS (rightmost ASN in the path), and per-peer prefix counts
    origins = {}
    per_peer_prefixes = {}
    for m in updates:
        origin_as = m['as_path'][-1] if m.get('as_path') else None
        src = m.get('src')
        for pfx in m.get('announced', []):
            origins.setdefault(pfx, origin_as)
            per_peer_prefixes.setdefault(src, set()).add(pfx)

    trusted_peers = set(baseline.get('peers') or [])
    base_origins = dict(baseline.get('origins') or {})
    base_counts = dict(baseline.get('prefix_count') or {})
    have_baseline = bool(trusted_peers or base_origins or baseline.get('peers') is not None)
    learned = False
    if learn and not have_baseline and (peers or origins):
        baseline['peers'] = peers
        baseline['origins'] = {p: o for p, o in origins.items() if o is not None}
        baseline['prefix_count'] = {s: len(v) for s, v in per_peer_prefixes.items()}
        learned = True
        trusted_peers = set(peers)
        base_origins = dict(baseline['origins'])
        have_baseline = True

    findings = []
    categories = set()
    advisories = []

    # storm — UPDATE churn
    upd_rate = round(len(updates) / seconds, 1)
    if upd_rate >= _BGP_STORM_RATE:
        categories.add('storm')
        findings.append(('crit', 'storm',
                         f'{len(updates)} BGP UPDATEs in {seconds}s ({upd_rate}/s) '
                         '— route churn / flooding'))
    # route leak — per-peer prefix-count spike
    for src, pfxs in per_peer_prefixes.items():
        base_n = base_counts.get(src, 0)
        if len(pfxs) >= _BGP_LEAK_PREFIXES and (not base_n or len(pfxs) > base_n * 5):
            categories.add('storm')
            findings.append(('crit', 'storm',
                             f'peer {src} announced {len(pfxs)} prefixes '
                             f'(baseline {base_n or "—"}) — possible full-table route leak'))

    # injection — origin hijack (same prefix, different origin AS)
    if have_baseline:
        for pfx, origin_as in origins.items():
            b = base_origins.get(pfx)
            if b is not None and origin_as is not None and origin_as != b:
                categories.add('injection')
                findings.append(('crit', 'injection',
                                 f'prefix {pfx} now originated by AS{origin_as} '
                                 f'(baseline AS{b}) — BGP origin hijack'))
        # sub-prefix hijack — a new more-specific of a baseline prefix
        for pfx, origin_as in origins.items():
            if pfx in base_origins:
                continue
            for bpfx, bas in base_origins.items():
                if _bgp_prefix_covers(bpfx, pfx) and origin_as != bas:
                    categories.add('injection')
                    findings.append(('crit', 'injection',
                                     f'more-specific {pfx} (inside baseline {bpfx}) '
                                     f'from AS{origin_as} — sub-prefix hijack'))
                    break

    # anomaly — new/rogue peer
    if have_baseline:
        for asn in peers:
            if asn not in trusted_peers:
                categories.add('anomaly')
                findings.append(('warn', 'anomaly',
                                 f'new BGP peer AS{asn} — not in the learned baseline'))
    # session reset / teardown
    for m in notifs:
        categories.add('anomaly')
        findings.append(('warn', 'anomaly',
                         f'BGP NOTIFICATION ({m.get("notif_code") or "?"}'
                         f'{"/" + m["notif_sub"] if m.get("notif_sub") else ""}) '
                         '— session reset / teardown'))
    # private / bogon ASN in a received path
    seen_bad_asn = set()
    for m in updates:
        for asn in m.get('as_path', []):
            klass = _bgp_asn_class(asn)
            # private ASNs are normal on internal/DC fabric — only alert on
            # reserved/documentation ASNs, which are never legitimate in a path.
            if klass in ('reserved', 'documentation') and asn not in seen_bad_asn:
                seen_bad_asn.add(asn)
                categories.add('anomaly')
                findings.append(('warn', 'anomaly',
                                 f'{klass} ASN {asn} in a received AS-path — route leak / misconfig'))
        # AS-path loop (an ASN appears more than once non-adjacently)
        path = m.get('as_path', [])
        # collapse consecutive repeats (legitimate prepending), then a repeat
        # of the same ASN is a loop
        dedup = [a for i, a in enumerate(path) if i == 0 or a != path[i - 1]]
        if len(dedup) != len(set(dedup)):
            categories.add('anomaly')
            findings.append(('warn', 'anomaly',
                             f'AS-path loop in {" ".join(map(str, path))}'))
    # bogon / martian prefix announcement
    bogons = sorted({p for p in origins if _bgp_is_bogon(p)})
    for p in bogons:
        categories.add('anomaly')
        findings.append(('warn', 'anomaly',
                         f'bogon/martian prefix {p} announced in BGP — route leak or hijack'))
    # blackhole community
    if any('blackhole' in c.lower() or '65535:666' in c for m in updates for c in m.get('communities', [])):
        categories.add('anomaly')
        findings.append(('warn', 'anomaly',
                         'BLACKHOLE community (65535:666) seen — RTBH in use (verify it is intended)'))

    # weak session — no TCP-MD5/TCP-AO seen while BGP is present
    if messages and not md5:
        categories.add('weak_session')
        advisories.append(dict(_BGP_ADVISORIES['no_md5'], key='no_md5'))
        findings.append(('warn', 'weak_session',
                         'no TCP-MD5/TCP-AO signature on the BGP session — exposed to '
                         'off-path session-reset attacks'))
    if updates:
        advisories.append(dict(_BGP_ADVISORIES['malformed_attr'], key='malformed_attr'))

    order = ['storm', 'injection', 'anomaly', 'weak_session']
    verdict = next((c for c in order if c in categories), 'clean')
    if not findings:
        findings.append(('ok', 'clean', 'No BGP anomalies in the capture window.'))

    prefixes_out = []
    for pfx in sorted(origins):
        oa = origins[pfx]
        prefixes_out.append({'prefix': pfx, 'origin_as': oa,
                             'baseline_as': base_origins.get(pfx),
                             'hijack': bool(have_baseline and base_origins.get(pfx) is not None
                                            and oa is not None and oa != base_origins.get(pfx)),
                             'bogon': _bgp_is_bogon(pfx)})

    return {
        'success': True, 'verdict': verdict, 'seconds': seconds,
        'messages': total, 'opens': len(opens), 'updates': len(updates),
        'notifications': len(notifs), 'update_per_s': upd_rate, 'learned': learned,
        'peers': peers, 'peer_ids': peer_ids, 'trusted_peers': sorted(trusted_peers),
        'md5': md5, 'prefixes': prefixes_out[:100], 'prefix_total': len(origins),
        'advisories': [{'key': a.get('key'), 'severity': a['severity'],
                        'title': a['title'], 'detail': a['detail'],
                        'refs': a.get('refs', [])} for a in advisories],
        'findings': [{'level': l, 'category': c, 'text': t} for l, c, t in findings],
        'reasons': [t for _l, _c, t in findings if _l != 'ok'],
    }


def _bgp_prefix_covers(supernet, subnet):
    """True if CIDR `supernet` strictly contains CIDR `subnet` (more-specific)."""
    try:
        sn, sl = supernet.split('/'); sl = int(sl)
        tn, tl = subnet.split('/'); tl = int(tl)
    except ValueError:
        return False
    if tl <= sl:
        return False
    a, b = _ip_to_int(sn), _ip_to_int(tn)
    if a is None or b is None:
        return False
    mask = (0xffffffff << (32 - sl)) & 0xffffffff
    return (a & mask) == (b & mask)


# --- ASN enrichment via Team Cymru IP-to-ASN whois (TCP/43) -----------------
# Turns raw AS numbers / peer IPs into AS names + owner country. Purely additive
# and SOFT-FAILING: a NOC that egress-filters outbound TCP/43 just gets IP/AS-
# number-only output (per Solarflere's note). Results are cached, and a failed
# lookup is negatively cached for a few minutes so a blocked egress doesn't add
# a connect-timeout to every scan.
_CYMRU_HOST = 'whois.cymru.com'
_CYMRU_PORT = 43
_CYMRU_TTL = 86400          # ASN mappings are stable — cache a day
_CYMRU_FAIL_TTL = 300       # after a failure, don't retry for 5 min (fast soft-fail)
_cymru_cache = {}           # ('ip'|'as', key) -> (ts, value)
_cymru_lock = threading.Lock()
_cymru_blocked_until = [0.0]


def _cymru_query(lines, timeout):
    """Send a bulk Team Cymru whois query; return the raw response or None on any
    failure (soft-fail: outbound TCP/43 may be filtered)."""
    payload = ('begin\nverbose\n' + '\n'.join(lines) + '\nend\n').encode()
    try:
        with socket.create_connection((_CYMRU_HOST, _CYMRU_PORT), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(payload)
            chunks = []
            while True:
                b = s.recv(4096)
                if not b:
                    break
                chunks.append(b)
        return b''.join(chunks).decode('utf-8', 'replace')
    except Exception:
        return None


def _parse_cymru(resp, out):
    now = time.time()
    for raw in resp.splitlines():
        line = raw.strip()
        if not line or '|' not in line or line.lower().startswith('bulk mode') \
           or 'AS Name' in line:
            continue
        parts = [p.strip() for p in line.split('|')]
        if len(parts) >= 7:            # AS | IP | Prefix | CC | Registry | Alloc | Name
            asn, ip, prefix, cc = parts[0], parts[1], parts[2], parts[3]
            name = parts[6]
            try:
                asn_i = int(asn)
            except ValueError:
                asn_i = None
            rec = {'asn': asn_i, 'name': name or None,
                   'prefix': prefix if prefix and prefix != 'NA' else None,
                   'cc': cc if cc and cc != 'NA' else None}
            out['ips'][ip] = rec
            with _cymru_lock:
                _cymru_cache[('ip', ip)] = (now, rec)
            if asn_i is not None:
                out['asns'].setdefault(asn_i, name or None)
                with _cymru_lock:
                    _cymru_cache[('as', asn_i)] = (now, name or None)
        elif len(parts) >= 5:          # AS | CC | Registry | Alloc | Name
            try:
                asn_i = int(parts[0])
            except ValueError:
                continue
            name = parts[4]
            out['asns'][asn_i] = name or None
            with _cymru_lock:
                _cymru_cache[('as', asn_i)] = (now, name or None)


def _cymru_asn_lookup(ips=None, asns=None, timeout=4):
    """Enrich IPs -> {asn,name,prefix,cc} and ASNs -> name via Team Cymru. Cached;
    soft-fails to whatever the cache holds (possibly nothing) so callers degrade
    to IP/AS-number-only output. `out['ok']` is False when the live lookup was
    skipped/failed and nothing came back."""
    ips = sorted({i for i in (ips or []) if i})
    asns = sorted({int(a) for a in (asns or []) if a is not None})
    out = {'ips': {}, 'asns': {}, 'ok': False, 'filtered': False}
    if not ips and not asns:
        out['ok'] = True
        return out
    now = time.time()
    need_ips, need_asns = [], []
    with _cymru_lock:
        for ip in ips:
            c = _cymru_cache.get(('ip', ip))
            if c and now - c[0] < _CYMRU_TTL:
                out['ips'][ip] = c[1]
            else:
                need_ips.append(ip)
        for a in asns:
            c = _cymru_cache.get(('as', a))
            if c and now - c[0] < _CYMRU_TTL:
                out['asns'][a] = c[1]
            else:
                need_asns.append(a)
        blocked = now < _cymru_blocked_until[0]
    if need_ips or need_asns:
        if blocked:
            out['filtered'] = True
        else:
            resp = _cymru_query(need_ips + [f'AS{a}' for a in need_asns], timeout)
            if resp:
                _parse_cymru(resp, out)
            else:
                out['filtered'] = True
                with _cymru_lock:
                    _cymru_blocked_until[0] = now + _CYMRU_FAIL_TTL
    out['ok'] = not out['filtered'] or bool(out['ips'] or out['asns'])
    return out


def _bgp_capture(interface, seconds):
    """Run one passive tcpdump BGP window and return (raw_text, error)."""
    if not _have('tcpdump'):
        return '', 'tcpdump is not installed. Click Install to add it.'
    res = _run(['timeout', str(seconds), 'tcpdump', '-i', interface,
                '-nn', '-t', '-v', '-s', '1500', '-c', '20000', 'tcp', 'port', '179'],
               timeout=seconds + 8)
    out = res['out']
    if not out and res['err'] and ('permission' in res['err'].lower()
                                   or "couldn't" in res['err'].lower()
                                   or 'no such device' in res['err'].lower()):
        return '', res['err'].strip()[:200]
    return out, None


def do_bgp_watch(interface=None, seconds=15, learn=True, quick=False, enrich=True):
    """Passive BGP path/security scanner (detection-only). Captures BGP for a few
    seconds and classifies the edge: injection (hijack) / anomaly / storm /
    weak_session / clean, with CVE/OSV advisories. Learns peers + prefix origins
    on first run; never opens a session or announces a route.

    enrich=True adds Team Cymru ASN names/owner (outbound TCP/43, soft-fails to
    AS-number-only if egress filters it)."""
    iface = interface if _valid_iface(interface or '') else _default_route_iface()
    if not iface:
        return {'success': False, 'error': 'no interface to capture on'}
    if iface not in _list_iface_names(include_virtual=True):
        return {'success': False, 'error': f'unknown interface: {iface}'}
    seconds = _clamp_int(seconds, 15, 5, 40)

    text, err = _bgp_capture(iface, seconds)
    if err:
        return {'success': False, 'interface': iface, 'error': err,
                'missing_tool': 'tcpdump' if 'not installed' in err else None}
    messages = _parse_bgp_capture(text)

    with _bgp_watch_lock:
        baseline = _bgp_watch_load()
        result = _bgp_analyze(messages, seconds, baseline, learn=learn)
        if result.get('learned'):
            _bgp_watch_save(baseline)
        if result['verdict'] != 'clean':
            b = _bgp_watch_load()
            evs = b.get('events') or []
            evs.append({'ts': int(time.time()), 'verdict': result['verdict'],
                        'reasons': result['reasons'][:6]})
            b['events'] = evs[-_BGP_EVENTS_CAP:]
            _bgp_watch_save(b)

    # ASN enrichment (additive, soft-failing). Kept out of _bgp_analyze so the
    # self-test stays offline/deterministic.
    if enrich and (result.get('peers') or result.get('prefixes')):
        asns = set(result.get('peers') or [])
        for p in result.get('prefixes', []):
            if p.get('origin_as') is not None:
                asns.add(p['origin_as'])
        enr = _cymru_asn_lookup(ips=result.get('peer_ids') or [], asns=asns)
        result['asn_names'] = {str(k): v for k, v in enr['asns'].items() if v}
        result['enriched'] = enr['ok'] and bool(enr['asns'] or enr['ips'])
        if enr.get('filtered'):
            result['enrich_note'] = ('ASN name enrichment unavailable — needs '
                                     'outbound TCP/43 to whois.cymru.com; showing '
                                     'AS numbers only.')
        for p in result.get('prefixes', []):
            oa = p.get('origin_as')
            if oa is not None and enr['asns'].get(oa):
                p['origin_name'] = enr['asns'][oa]
        result['peer_info'] = enr.get('ips') or {}

    if not messages:
        result['note'] = ('No BGP seen — BGP is unicast TCP/179 between routers, so '
                          'the Pi must be inline, on a SPAN/mirror, or a peer to '
                          'observe it (unlike OSPF, it is not on the broadcast domain).')
    result['interface'] = iface
    return result


def _bgp_selftest():
    """Self-test the BGP detectors with synthetic tcpdump captures (no root, no
    live traffic), plus an optional Scapy end-to-end leg (scapy.contrib.bgp ->
    pcap -> tcpdump -> parse). Mirrors the OSPF/IGMP self-tests."""
    scenarios = []

    def run(name, text, seconds, baseline, expect):
        msgs = _parse_bgp_capture(text)
        res = _bgp_analyze(msgs, seconds, dict(baseline), learn=not baseline)
        ok = res['verdict'] == expect
        scenarios.append({'name': name, 'expect': expect, 'got': res['verdict'],
                          'messages': len(msgs), 'pass': ok})
        return res

    base = {'peers': [65001, 65002],
            'origins': {'93.184.216.0/24': 65002, '45.33.0.0/16': 65003},
            'prefix_count': {'10.0.0.1': 2}}

    clean = "\n".join([
        "10.0.0.1.179 > 10.0.0.2.179: Flags [P.], length 60: BGP md5",
        "\tUpdate Message (2), length: 55",
        "\t  Origin (1), length: 1, Flags [T]: IGP",
        "\t  AS Path (2), length: 6, Flags [T]: 65001 65002",
        "\t  Updated routes:",
        "\t    93.184.216.0/24",
    ])
    run('clean', clean, 15, base, 'clean')

    hijack = "\n".join([
        "10.0.0.1.179 > 10.0.0.2.179: Flags [P.], length 60: BGP md5",
        "\tUpdate Message (2), length: 55",
        "\t  AS Path (2), length: 6, Flags [T]: 65001 65666",
        "\t  Updated routes:",
        "\t    93.184.216.0/24",
    ])
    run('injection-hijack', hijack, 15, base, 'injection')

    subprefix = "\n".join([
        "10.0.0.1.179 > 10.0.0.2.179: Flags [P.], length 60: BGP md5",
        "\tUpdate Message (2), length: 55",
        "\t  AS Path (2), length: 6, Flags [T]: 65001 65666",
        "\t  Updated routes:",
        "\t    93.184.216.128/25",
    ])
    run('injection-subprefix', subprefix, 15, base, 'injection')

    notif = "\n".join([
        "10.0.0.9.179 > 10.0.0.2.179: Flags [P.], length 40: BGP md5",
        "\tNotification Message (3), length: 21, Cease (6), subcode Administrative Reset (4)",
    ])
    run('anomaly-notif', notif, 15, base, 'anomaly')

    bogon = "\n".join([
        "10.0.0.1.179 > 10.0.0.2.179: Flags [P.], length 60: BGP md5",
        "\tUpdate Message (2), length: 55",
        "\t  AS Path (2), length: 6, Flags [T]: 65001 65002",
        "\t  Updated routes:",
        "\t    192.168.0.0/16",
    ])
    run('anomaly-bogon', bogon, 15, base, 'anomaly')

    # parser check
    msgs = _parse_bgp_capture(clean)
    up = [m for m in msgs if m['type'] == 'update']
    parse_ok = bool(up and up[0]['as_path'] == [65001, 65002] and
                    '93.184.216.0/24' in up[0]['announced'])
    scenarios.append({'name': 'update-parse',
                      'expect': 'path=[65001,65002] pfx=93.184.216.0/24',
                      'got': str({'as_path': up[0]['as_path'], 'announced': up[0]['announced']} if up else None),
                      'pass': parse_ok})

    scapy_result = {'ran': False, 'reason': 'scapy or tcpdump unavailable'}
    try:
        import tempfile
        from scapy.all import IP, TCP, Ether, wrpcap  # noqa
        try:
            from scapy.contrib.bgp import BGPHeader, BGPKeepAlive
        except Exception:
            BGPHeader = None
        if BGPHeader is not None and _have('tcpdump'):
            pkt = (Ether() / IP(src='10.0.0.1', dst='10.0.0.2') /
                   TCP(sport=179, dport=50000, flags='PA') /
                   BGPHeader(type=4) / BGPKeepAlive())
            with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tf:
                pcap_path = tf.name
            wrpcap(pcap_path, [pkt])
            res = _run(['tcpdump', '-nn', '-t', '-v', '-r', pcap_path, 'tcp', 'port', '179'],
                       timeout=10)
            parsed = _parse_bgp_capture(res['out'])
            scapy_result = {'ran': True, 'parsed_messages': len(parsed),
                            'pass': True, 'tcpdump_out': res['out'].strip()[:200]}
            try:
                os.remove(pcap_path)
            except OSError:
                pass
    except Exception as e:
        scapy_result = {'ran': False, 'reason': f'{type(e).__name__}: {e}'}

    passed = all(s['pass'] for s in scenarios) and \
        (not scapy_result.get('ran') or scapy_result.get('pass'))
    return {'success': passed, 'scenarios': scenarios, 'scapy': scapy_result}


def do_routing_selftest():
    """Run the IGMP / OSPF / BGP detector self-tests and report a combined result
    plus whether Scapy is available for the end-to-end packet-crafting leg. Drives
    the web 'validate detectors' panel. No root, no live traffic, no persistence."""
    suites = {'igmp': _igmp_selftest(), 'ospf': _ospf_selftest(), 'bgp': _bgp_selftest(),
              'bgp_speaker': bgp_speaker.selftest(), 'path_asymmetry': path_asymmetry.selftest()}
    return {
        'success': all(s['success'] for s in suites.values()),
        'scapy_available': _have_scapy(),
        'suites': {k: {
            'success': v['success'],
            'passed': sum(1 for s in v['scenarios'] if s['pass']),
            'total': len(v['scenarios']),
            'scenarios': v['scenarios'],
            'scapy': v.get('scapy'),
        } for k, v in suites.items()},
    }


# --------------------------------------------------------------------------
# BGP Route Collector (receive-only speaker) + Path Asymmetry (OWD) + correlator
# --------------------------------------------------------------------------
# Control-plane truth (bgp_speaker.BGPSpeaker's Adj-RIB-In) tied to data-plane
# measurement (path_asymmetry's measured one-way delay), via path_asymmetry.
# correlate(). Both the collector session and the OWD reflector are long-lived
# daemons, so these managers keep a single instance each with start/stop/status.

_bgp_collector = {'speaker': None, 'events': []}     # correlated asymmetry events
_bgp_collector_lock = threading.Lock()
_owd_reflector = {'reflector': None}
_owd_lock = threading.Lock()
_COLLECTOR_EVENT_CAP = 100


def _collector_on_update(upd, changed):
    """RIB update hook — reserved for pushing churn into a live correlation feed.
    Kept lightweight; correlation is done on demand in do_path_asymmetry."""
    return None


def do_bgp_collector(action='status', peer_ip=None, peer_as=None, local_as=None,
                     router_id=None, port=179, hold=90):
    """Manage the receive-only BGP collector session. Actions: start / stop /
    status / rib. Never advertises a route — it only learns the peer's RIB."""
    with _bgp_collector_lock:
        sp = _bgp_collector['speaker']
        if action == 'start':
            if sp and sp.state != 'Idle':
                return {'success': False, 'error': 'collector already running',
                        'status': sp.status()}
            try:
                ipaddress.ip_address(peer_ip or '')
                ipaddress.ip_address(router_id or '')
                peer_as = int(peer_as); local_as = int(local_as)
                port = _clamp_int(port, 179, 1, 65535)
                hold = _clamp_int(hold, 90, 0, 65535)
            except (ValueError, TypeError):
                return {'success': False, 'error': 'need valid peer_ip, router_id, '
                        'peer_as, local_as'}
            if not (0 < peer_as <= 0xFFFFFFFF and 0 < local_as <= 0xFFFFFFFF):
                return {'success': False, 'error': 'AS numbers out of range'}
            sp = bgp_speaker.BGPSpeaker(peer_ip, peer_as, local_as, router_id,
                                        hold_time=hold, port=port,
                                        on_update=_collector_on_update)
            sp.start()
            _bgp_collector['speaker'] = sp
            time.sleep(0.3)
            return {'success': True, 'status': sp.status()}
        if action == 'stop':
            if sp:
                sp.stop()
            return {'success': True, 'stopped': True}
        if action == 'rib':
            limit = 200
            return {'success': True,
                    'rib': sp.rib.snapshot(limit) if sp else {'total': 0, 'routes': []},
                    'state': sp.state if sp else 'Idle'}
        # status (default)
        return {'success': True,
                'status': sp.status() if sp else {'state': 'Idle', 'peer_ip': None},
                'events': _bgp_collector['events'][-20:]}


def do_owd_reflector(action='status', port=path_asymmetry.DEFAULT_PORT):
    """Manage the local one-way-delay reflector so another node can probe THIS
    box for measured asymmetry. Actions: start / stop / status."""
    with _owd_lock:
        r = _owd_reflector['reflector']
        if action == 'start':
            if r and r._thread and r._thread.is_alive():
                return {'success': True, 'already_running': True, 'port': r.port}
            port = _clamp_int(port, path_asymmetry.DEFAULT_PORT, 1, 65535)
            try:
                r = path_asymmetry.Reflector(port=port)
                r.start()
            except OSError as e:
                return {'success': False, 'error': f'could not bind udp/{port}: {e}'}
            _owd_reflector['reflector'] = r
            return {'success': True, 'running': True, 'port': port}
        if action == 'stop':
            if r:
                r.stop()
            return {'success': True, 'stopped': True}
        running = bool(r and r._thread and r._thread.is_alive())
        return {'success': True, 'running': running,
                'port': r.port if r else path_asymmetry.DEFAULT_PORT,
                'reflected': r.count if r else 0}


def do_path_asymmetry(target, port=path_asymmetry.DEFAULT_PORT, count=20,
                      threshold_ms=5.0, clock_synced=False):
    """Measure one-way-delay asymmetry to a target running the OWD reflector, and
    correlate any asymmetry event against the BGP collector's RIB (control-plane
    truth). Falls back to a note if no reflector answers."""
    try:
        ipaddress.ip_address(target or '')
    except (ValueError, TypeError):
        # allow hostnames — resolve
        try:
            target = socket.gethostbyname(target)
        except (OSError, TypeError):
            return {'success': False, 'error': 'invalid or unresolvable target'}
    port = _clamp_int(port, path_asymmetry.DEFAULT_PORT, 1, 65535)
    count = _clamp_int(count, 20, 5, 100)
    det = path_asymmetry.AsymmetryDetector(threshold_ms=float(threshold_ms),
                                           clock_synced=bool(clock_synced), target=target)
    samples = path_asymmetry.probe_series(target, port=port, count=count, interval=0.03)
    events = []
    for s in samples:
        ev = det.add(*s)
        if ev:
            events.append(ev)
    # correlate events against the live RIB (control-plane truth)
    rib = None
    with _bgp_collector_lock:
        sp = _bgp_collector['speaker']
        if sp and sp.state == 'Established':
            rib = sp.rib
    correlated = [path_asymmetry.correlate(e, rib) for e in events] if rib else events
    if correlated:
        with _bgp_collector_lock:
            _bgp_collector['events'] = (_bgp_collector['events'] + correlated)[-_COLLECTOR_EVENT_CAP:]
    out = {'success': True, 'target': target, 'port': port,
           'probes_sent': count, 'replies': len(samples),
           'summary': det.summary(), 'events': correlated,
           'rib_correlation': bool(rib)}
    if not samples:
        out['note'] = ('No reply from the OWD reflector at %s:%d. Run the reflector '
                       'on the target (`python3 path_asymmetry.py reflector %d`) or '
                       'enable it there, then retry. Without a reflector, only the '
                       'passive TTL hop-count fallback is available.' % (target, port, port))
    return out


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


def _install_scapy():
    """Install the Scapy Python module (used by the scanners' end-to-end self-test
    leg). Prefers the Debian package python3-scapy so it lands in the system
    interpreter the service runs under; falls back to pip (PEP-668 override on
    Pi OS). Idempotent."""
    if _have_scapy():
        return {'success': True, 'already_installed': True, 'tool': 'scapy',
                'message': 'scapy is already installed.'}
    env = dict(os.environ)
    env['DEBIAN_FRONTEND'] = 'noninteractive'
    res = {'err': '', 'out': ''}
    if _have('apt-get'):
        res = _run(['apt-get', 'install', '-y', 'python3-scapy'], timeout=300, env=env)
        if not _have_scapy():
            _run(['apt-get', 'update', '-y'], timeout=180, env=env)
            res = _run(['apt-get', 'install', '-y', 'python3-scapy'], timeout=300, env=env)
    if not _have_scapy():
        import sys
        py = sys.executable or 'python3'
        res = _run([py, '-m', 'pip', 'install', '--break-system-packages', 'scapy'],
                   timeout=300, env=env)
    if not _have_scapy():
        tail = (res.get('err') or res.get('out') or '').strip()[-400:]
        return {'success': False, 'tool': 'scapy',
                'error': 'Could not install scapy (tried apt python3-scapy and pip). '
                         + (f'Detail: {tail}' if tail else '')}
    return {'success': True, 'tool': 'scapy', 'message': 'Installed scapy.'}


def do_install_tool(tool):
    """Install a missing network tool on demand via apt. Whitelisted packages
    only. The Ragnar service runs as root, so apt is invoked directly."""
    if tool == 'scapy':
        return _install_scapy()
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

    @app.route('/api/net/igmp-watch', methods=['GET'])
    def net_igmp_watch():
        iface = (request.args.get('interface') or '').strip() or None
        if iface is not None and not _valid_iface(iface):
            return _bad('Invalid interface')
        secs = _clamp_int(request.args.get('seconds'), 12, 4, 30)
        _log(f"net/igmp-watch iface={iface or 'default-route'} secs={secs}")
        return jsonify(do_igmp_watch(interface=iface, seconds=secs))

    @app.route('/api/net/igmp-baseline', methods=['GET', 'POST'])
    def net_igmp_baseline():
        action = 'get'
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            action = 'reset' if (data.get('action') == 'reset') else 'get'
        _log(f"net/igmp-baseline {action}")
        return jsonify(do_igmp_baseline(action))

    @app.route('/api/net/ospf-watch', methods=['GET'])
    def net_ospf_watch():
        iface = (request.args.get('interface') or '').strip() or None
        if iface is not None and not _valid_iface(iface):
            return _bad('Invalid interface')
        secs = _clamp_int(request.args.get('seconds'), 15, 5, 40)
        _log(f"net/ospf-watch iface={iface or 'default-route'} secs={secs}")
        return jsonify(do_ospf_watch(interface=iface, seconds=secs))

    @app.route('/api/net/ospf-baseline', methods=['GET', 'POST'])
    def net_ospf_baseline():
        action = 'get'
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            action = 'reset' if (data.get('action') == 'reset') else 'get'
        _log(f"net/ospf-baseline {action}")
        return jsonify(do_ospf_baseline(action))

    @app.route('/api/net/bgp-watch', methods=['GET'])
    def net_bgp_watch():
        iface = (request.args.get('interface') or '').strip() or None
        if iface is not None and not _valid_iface(iface):
            return _bad('Invalid interface')
        secs = _clamp_int(request.args.get('seconds'), 15, 5, 40)
        enrich = request.args.get('enrich', '1') not in ('0', 'false', 'no')
        _log(f"net/bgp-watch iface={iface or 'default-route'} secs={secs} enrich={enrich}")
        return jsonify(do_bgp_watch(interface=iface, seconds=secs, enrich=enrich))

    @app.route('/api/net/bgp-baseline', methods=['GET', 'POST'])
    def net_bgp_baseline():
        action = 'get'
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            action = 'reset' if (data.get('action') == 'reset') else 'get'
        _log(f"net/bgp-baseline {action}")
        return jsonify(do_bgp_baseline(action))

    @app.route('/api/net/bgp-collector', methods=['GET', 'POST'])
    def net_bgp_collector():
        if request.method == 'GET':
            action = (request.args.get('action') or 'status').strip()
            if action not in ('status', 'rib'):
                action = 'status'
            _log(f"net/bgp-collector {action}")
            return jsonify(do_bgp_collector(action))
        data = request.get_json(silent=True) or {}
        action = (data.get('action') or 'status').strip()
        if action not in ('start', 'stop', 'status', 'rib'):
            return _bad('action must be start/stop/status/rib')
        _log(f"net/bgp-collector {action} peer={data.get('peer_ip')}")
        return jsonify(do_bgp_collector(
            action, peer_ip=data.get('peer_ip'), peer_as=data.get('peer_as'),
            local_as=data.get('local_as'), router_id=data.get('router_id'),
            port=data.get('port', 179), hold=data.get('hold', 90)))

    @app.route('/api/net/owd-reflector', methods=['GET', 'POST'])
    def net_owd_reflector():
        if request.method == 'GET':
            return jsonify(do_owd_reflector('status'))
        data = request.get_json(silent=True) or {}
        action = (data.get('action') or 'status').strip()
        if action not in ('start', 'stop', 'status'):
            return _bad('action must be start/stop/status')
        _log(f"net/owd-reflector {action}")
        return jsonify(do_owd_reflector(action, port=data.get('port', path_asymmetry.DEFAULT_PORT)))

    @app.route('/api/net/path-asymmetry', methods=['POST'])
    def net_path_asymmetry():
        data = request.get_json(silent=True) or {}
        target = (data.get('target') or '').strip()
        if not target:
            return _bad('target required')
        _log(f"net/path-asymmetry target={target}")
        return jsonify(do_path_asymmetry(
            target, port=data.get('port', path_asymmetry.DEFAULT_PORT),
            count=data.get('count', 20), threshold_ms=data.get('threshold_ms', 5.0),
            clock_synced=bool(data.get('clock_synced', False))))

    @app.route('/api/net/routing-selftest', methods=['GET'])
    def net_routing_selftest():
        _log("net/routing-selftest")
        return jsonify(do_routing_selftest())

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


# --------------------------------------------------------------------------
# Small CLI — currently the IGMP Watch scanner and its self-test, so the
# passive multicast checks can run standalone (cron, SSH, CI) without the web
# app.  Usage:
#     python3 network_diagnostics.py igmp-watch [--iface eth0] [--seconds 12] [--json]
#     python3 network_diagnostics.py igmp-selftest [--json]
# --------------------------------------------------------------------------

def _cli(argv=None):
    import argparse
    p = argparse.ArgumentParser(
        prog='network_diagnostics',
        description='Ragnar passive network diagnostics (CLI subset).')
    sub = p.add_subparsers(dest='cmd')

    w = sub.add_parser('igmp-watch', help='passive IGMP-snooping security scan')
    w.add_argument('--iface', '-i', default=None, help='interface (default: route)')
    w.add_argument('--seconds', '-s', type=int, default=12, help='capture window (4-30)')
    w.add_argument('--no-learn', action='store_true', help='do not learn/update baseline')
    w.add_argument('--json', action='store_true', help='emit JSON')

    st = sub.add_parser('igmp-selftest', help='self-test the IGMP detectors (no root)')
    st.add_argument('--json', action='store_true', help='emit JSON')

    o = sub.add_parser('ospf-watch', help='passive OSPF security scan')
    o.add_argument('--iface', '-i', default=None, help='interface (default: route)')
    o.add_argument('--seconds', '-s', type=int, default=15, help='capture window (5-40)')
    o.add_argument('--no-learn', action='store_true', help='do not learn/update baseline')
    o.add_argument('--json', action='store_true', help='emit JSON')

    ost = sub.add_parser('ospf-selftest', help='self-test the OSPF detectors (no root)')
    ost.add_argument('--json', action='store_true', help='emit JSON')

    b = sub.add_parser('bgp-watch', help='passive BGP path/security scan')
    b.add_argument('--iface', '-i', default=None, help='interface (default: route)')
    b.add_argument('--seconds', '-s', type=int, default=15, help='capture window (5-40)')
    b.add_argument('--no-learn', action='store_true', help='do not learn/update baseline')
    b.add_argument('--no-enrich', action='store_true', help='skip Team Cymru ASN enrichment (no TCP/43)')
    b.add_argument('--json', action='store_true', help='emit JSON')

    bst = sub.add_parser('bgp-selftest', help='self-test the BGP detectors (no root)')
    bst.add_argument('--json', action='store_true', help='emit JSON')

    args = p.parse_args(argv)
    if args.cmd == 'igmp-watch':
        r = do_igmp_watch(interface=args.iface, seconds=args.seconds,
                          learn=not args.no_learn)
        if args.json:
            print(json.dumps(r, indent=2))
        elif not r.get('success'):
            print(f"error: {r.get('error')}")
        else:
            v = r['verdict'].upper()
            print(f"IGMP Watch [{r['interface']}] {r['seconds']}s: {v}  "
                  f"({r['packets']} msgs, {r['rate_per_s']}/s)")
            if r.get('learned'):
                print("  (baseline learned this run)")
            if r.get('queriers'):
                print(f"  queriers: {', '.join(r['queriers'])}")
            for g in r.get('groups', []):
                flag = ' *NEW*' if g.get('new') else ''
                nm = f" {g['name']}" if g.get('name') else ''
                print(f"  group {g['group']}{nm} [{g['scope']}]"
                      f" <- {', '.join(g['members'])}{flag}")
            for f in r.get('findings', []):
                print(f"  [{f['level']}] {f['text']}")
        return 0 if r.get('success') else 1

    if args.cmd == 'igmp-selftest':
        r = _igmp_selftest()
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            for s in r['scenarios']:
                mark = 'PASS' if s['pass'] else 'FAIL'
                print(f"  [{mark}] {s['name']}: expect={s['expect']} got={s['got']}")
            sc = r['scapy']
            if sc.get('ran'):
                print(f"  [{'PASS' if sc.get('pass') else 'FAIL'}] scapy-e2e: "
                      f"groups={sc.get('groups')}")
            else:
                print(f"  [skip] scapy-e2e: {sc.get('reason')}")
            print(f"IGMP self-test: {'OK' if r['success'] else 'FAILED'}")
        return 0 if r['success'] else 1

    if args.cmd == 'ospf-watch':
        r = do_ospf_watch(interface=args.iface, seconds=args.seconds,
                          learn=not args.no_learn)
        if args.json:
            print(json.dumps(r, indent=2))
        elif not r.get('success'):
            print(f"error: {r.get('error')}")
        else:
            print(f"OSPF Watch [{r['interface']}] {r['seconds']}s: {r['verdict'].upper()}  "
                  f"({r['packets']} pkts, {r['hellos']} hello, {r['ls_updates']} LSU)")
            if r.get('note'):
                print(f"  note: {r['note']}")
            if r.get('learned'):
                print("  (baseline learned this run)")
            if r.get('auth_types'):
                print(f"  auth types seen: {r['auth_types']}")
            for rt in r.get('routers', []):
                print(f"  router {rt['router_id']}{' *NEW*' if rt.get('new') else ''}"
                      f" <- {', '.join(rt['sources'])}")
            for a in r.get('advisories', []):
                print(f"  [advisory:{a['severity']}] {a['title']}"
                      f"{' (' + ', '.join(a['refs']) + ')' if a.get('refs') else ''}")
            for f in r.get('findings', []):
                print(f"  [{f['level']}] {f['text']}")
        return 0 if r.get('success') else 1

    if args.cmd == 'ospf-selftest':
        r = _ospf_selftest()
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            for s in r['scenarios']:
                print(f"  [{'PASS' if s['pass'] else 'FAIL'}] {s['name']}: "
                      f"expect={s['expect']} got={s['got']}")
            sc = r['scapy']
            if sc.get('ran'):
                print(f"  [{'PASS' if sc.get('pass') else 'FAIL'}] scapy-e2e: "
                      f"parsed={sc.get('parsed_packets')} auth={sc.get('auth')}")
            else:
                print(f"  [skip] scapy-e2e: {sc.get('reason')}")
            print(f"OSPF self-test: {'OK' if r['success'] else 'FAILED'}")
        return 0 if r['success'] else 1

    if args.cmd == 'bgp-watch':
        r = do_bgp_watch(interface=args.iface, seconds=args.seconds,
                         learn=not args.no_learn, enrich=not args.no_enrich)
        if args.json:
            print(json.dumps(r, indent=2))
        elif not r.get('success'):
            print(f"error: {r.get('error')}")
        else:
            print(f"BGP Watch [{r['interface']}] {r['seconds']}s: {r['verdict'].upper()}  "
                  f"({r['messages']} msgs, {r['updates']} UPDATE, {r['prefix_total']} prefixes)")
            if r.get('note'):
                print(f"  note: {r['note']}")
            if r.get('enrich_note'):
                print(f"  {r['enrich_note']}")
            if r.get('learned'):
                print("  (baseline learned this run)")
            if r.get('peers'):
                names = r.get('asn_names') or {}
                ps = ', '.join('AS' + str(a) + (' (' + names[str(a)] + ')' if names.get(str(a)) else '') for a in r['peers'])
                print(f"  peers: {ps} · MD5: {r['md5']}")
            for a in r.get('advisories', []):
                print(f"  [advisory:{a['severity']}] {a['title']}"
                      f"{' (' + ', '.join(a['refs']) + ')' if a.get('refs') else ''}")
            for f in r.get('findings', []):
                print(f"  [{f['level']}] {f['text']}")
        return 0 if r.get('success') else 1

    if args.cmd == 'bgp-selftest':
        r = _bgp_selftest()
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            for s in r['scenarios']:
                print(f"  [{'PASS' if s['pass'] else 'FAIL'}] {s['name']}: "
                      f"expect={s['expect']} got={s['got']}")
            sc = r['scapy']
            if sc.get('ran'):
                print(f"  [{'PASS' if sc.get('pass') else 'FAIL'}] scapy-e2e: "
                      f"parsed={sc.get('parsed_messages')}")
            else:
                print(f"  [skip] scapy-e2e: {sc.get('reason')}")
            print(f"BGP self-test: {'OK' if r['success'] else 'FAILED'}")
        return 0 if r['success'] else 1

    p.print_help()
    return 2


if __name__ == '__main__':
    import sys
    sys.exit(_cli())
