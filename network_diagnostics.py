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
_VIRTUAL_IFACE_RE = re.compile(r'^(veth|docker|br-|virbr|vmnet|vboxnet)')


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

    is_vpn = bool(product or prefix_kind or strong
                  or n.startswith(_VPN_IFACE_PREFIXES)
                  or (link_kind and arphrd_none))
    if not is_vpn:
        return {'is_vpn': False, 'kind': None, 'endpoint': None}

    kind = (product
            or (link_kind if strong else None)
            or prefix_kind
            or (link_kind if link_kind and link_kind != 'tunnel' else None)
            or 'VPN tunnel')
    endpoint = _wg_endpoint(name) if (kind == 'WireGuard' or link_kind == 'WireGuard') else None
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

    # Primary: ipinfo.io over HTTPS (no API key needed for basic fields).
    res = _run(['curl', '-s', '--max-time', '8', '--interface', iface,
                'https://ipinfo.io/json'], timeout=12)
    if res['rc'] == 0 and res['out'].strip():
        try:
            d = json.loads(res['out'])
            if d.get('ip'):
                asn, isp = _parse_ipinfo_org(d.get('org'))
                vp = _vpn_provider_match(isp, d.get('org'), asn)
                return {'interface': iface, 'public_ip': d.get('ip'),
                        'isp': isp, 'asn': asn, 'org': d.get('org'),
                        'vpn_provider': vp, 'behind_vpn': bool(vp or iface_is_vpn),
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
                vp = _vpn_provider_match(d.get('isp'), d.get('org'), d.get('as'))
                return {'interface': iface, 'public_ip': d.get('query'),
                        'isp': d.get('isp'), 'asn': asn, 'org': d.get('org') or d.get('as'),
                        'vpn_provider': vp, 'behind_vpn': bool(vp or iface_is_vpn),
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
