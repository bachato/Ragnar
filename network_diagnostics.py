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


def do_interfaces(include_virtual=False):
    interfaces = []
    for name in _list_iface_names(include_virtual=include_virtual):
        link = _iface_link_details(name)
        v4, v6 = _iface_addrs(name)
        wireless = _is_wireless(name)
        eth = _iface_ethtool(name) if not wireless else {
            'speed': None, 'duplex': None, 'autoneg': None, 'link_detected': None}
        method = _iface_ip_method(name, v4)
        interfaces.append({
            'name': name,
            'type': 'wifi' if wireless else 'ethernet',
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
        'sources': sources,
    }


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

    if logger is not None:
        try:
            logger.info("Network diagnostics routes registered (/api/net/*)")
        except Exception:
            pass
    return app
