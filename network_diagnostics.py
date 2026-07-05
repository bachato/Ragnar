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

import json
import re
import shutil
import subprocess
import ipaddress
import os
import threading
import time
import socket
import tempfile
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
                return {'interface': iface, 'public_ip': d.get('ip'),
                        'isp': isp, 'asn': asn, 'org': d.get('org'),
                        'vpn_provider': vp, 'behind_vpn': bool(vp or iface_is_vpn or tor_exit),
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
                return {'interface': iface, 'public_ip': d.get('query'),
                        'isp': d.get('isp'), 'asn': asn, 'org': d.get('org') or d.get('as'),
                        'vpn_provider': vp, 'behind_vpn': bool(vp or iface_is_vpn or tor_exit),
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
    # want to identify per WAN.
    ifaces = do_interfaces(include_virtual=False).get('interfaces', [])
    candidates = []
    for i in ifaces:
        if interface and i['name'] != interface:
            continue
        v4 = [a.split('/')[0] for a in (i.get('ipv4') or [])]
        v4 = [a for a in v4 if not a.startswith('127.') and not a.startswith('169.254.')]
        if v4:
            candidates.append(i['name'])

    if not candidates:
        return {'success': False,
                'error': 'No interface has a usable IPv4 address to query through.',
                'results': []}

    results = [_isp_lookup_iface(name) for name in candidates]
    return {'success': True, 'results': results, 'count': len(results)}


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


def do_dns_doctor(name):
    """Resolve `name` through every system resolver plus public 1.1.1.1 / 8.8.8.8,
    reporting per-resolver answers, query latency and the DNSSEC AD flag, whether
    the resolvers agree (split-DNS / hijack smell), and DoH/DoT reachability."""
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

    results, answer_sets = [], []
    for resolver, kind in tested:
        d = _dig(name, resolver)
        d.update({'resolver': resolver, 'kind': kind})
        results.append(d)
        if d['answers']:
            answer_sets.append(set(d['answers']))
    # "Consistent" = the resolvers share at least one answer. Exact-match is too
    # strict: CDN/anycast names legitimately return different IP subsets per
    # resolver, so only a *disjoint* answer set (no address in common) is the
    # real split-DNS / hijack smell.
    consistent = len(answer_sets) < 2 or bool(set.intersection(*answer_sets))

    return {'success': True, 'name': name, 'results': results,
            'consistent': consistent,
            'dnssec_ok': any(r['ad'] for r in results),
            'doh_reachable': _tcp_reachable('1.1.1.1', 443),
            'dot_reachable': _tcp_reachable('1.1.1.1', 853)}


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
