#!/usr/bin/env python3
"""wifiwatch_selftest.py — offline self-test (no radio, no Scapy).

Builds real radiotap + 802.11 frame bytes in pure Python and drives them through
the same WifiWatch.handle() path live capture and replay use. Includes negative
controls (stable AP, sparse deauths, honest probe-responder) and a dense-boot
warmup test. Run via `python3 wifiwatch.py --self-test`.
"""

import struct
import sys

import wifiwatch as w


def _mac(s):
    return bytes(int(x, 16) for x in s.split(':'))


def radiotap(freq=2437, sig=-50):
    present = (1 << 3) | (1 << 5)                     # Channel + dBm signal
    return struct.pack('<BBHI', 0, 0, 13, present) + struct.pack('<HHb', freq, 0, sig)


def _dot11(subtype, a1, a2, a3, body=b'', protected=False):
    fc0 = (subtype << 4)                              # type 0 = management
    fc1 = 0x40 if protected else 0
    return bytes([fc0, fc1, 0, 0]) + _mac(a1) + _mac(a2) + _mac(a3) + b'\x00\x00' + body


def _ie(eid, data):
    return bytes([eid, len(data)]) + data


def beacon(bssid, ssid, freq=2437, sig=-50):
    body = b'\x00' * 8 + b'\x64\x00' + b'\x01\x00' + _ie(0, ssid.encode())
    return radiotap(freq, sig) + _dot11(8, 'ff:ff:ff:ff:ff:ff', bssid, bssid, body)


def proberesp(bssid, ssid):
    body = b'\x00' * 8 + b'\x64\x00' + b'\x01\x00' + _ie(0, ssid.encode())
    return radiotap() + _dot11(5, '00:11:22:33:44:55', bssid, bssid, body)


def probereq(ssid):
    return radiotap() + _dot11(4, 'ff:ff:ff:ff:ff:ff', '00:11:22:33:44:55',
                               'ff:ff:ff:ff:ff:ff', _ie(0, ssid.encode()))


def deauth(src, dst, reason=7, protected=False, subtype=12):
    return radiotap() + _dot11(subtype, dst, src, src, struct.pack('<H', reason), protected)


class H:
    def __init__(self, verbose):
        self.n = self.fail = 0
        self.verbose = verbose

    def ck(self, name, cond):
        self.n += 1
        if not cond:
            self.fail += 1
        if self.verbose:
            print('  [%s] %s' % ('PASS' if cond else 'FAIL', name))


def _watch(cfg=None):
    evs = []
    return w.WifiWatch(cfg or {}, emit=evs.append), evs


def _rules(evs):
    return {e['detector'] for e in evs}


def run(verbose=True):
    h = H(verbose)

    # ---- raw parse --------------------------------------------------------
    f = w.parse_frame(beacon('aa:bb:cc:dd:ee:ff', 'HomeNet'))
    h.ck('parse beacon subtype', f and f['subtype'] == 8)
    h.ck('parse beacon bssid', f and f['bssid'] == 'aa:bb:cc:dd:ee:ff')
    h.ck('parse beacon ssid', f and f['ssid'] == 'HomeNet')
    h.ck('parse radiotap freq/band/channel', f and f['band'] == '2.4' and f['channel'] == 6)
    h.ck('parse radiotap signal', f and f['signal'] == -50)
    f = w.parse_frame(deauth('aa:bb:cc:00:00:01', 'ff:ff:ff:ff:ff:ff', reason=7))
    h.ck('parse deauth subtype/reason', f and f['subtype'] == 12 and f['reason'] == 7)
    h.ck('parse deauth broadcast dst', f and f['da'] == w.BROADCAST)
    f = w.parse_frame(deauth('a', 'b', protected=True) if False else
                      deauth('aa:bb:cc:00:00:01', 'cc:cc:cc:00:00:09', protected=True))
    h.ck('parse deauth protected bit', f and f['protected'] is True)
    f = w.parse_frame(beacon('00:11:22:33:44:55', 'Net5', freq=5220))
    h.ck('parse 5GHz band/channel', f and f['band'] == '5' and f['channel'] == 44)
    f = w.parse_frame(beacon('00:11:22:33:44:55', 'Net6', freq=5975))
    h.ck('parse 6GHz band', f and f['band'] == '6')

    # ---- deauth flood -----------------------------------------------------
    wt, evs = _watch()
    for i in range(6):
        wt.handle(deauth('aa:bb:cc:00:00:01', w.BROADCAST), ts=100 + i * 0.1)
    bc = [e for e in evs if e['detector'] == 'deauth_flood']
    h.ck('broadcast deauth flood fires', bc and bc[0]['severity'] == 'critical')
    h.ck('broadcast deauth scope', bc and bc[0]['detail']['scope'] == 'broadcast')
    h.ck('broadcast deauth reason in detail', bc and bc[0]['detail']['reason'] == 7)
    wt, evs = _watch()
    for i in range(3):
        wt.handle(deauth('aa:bb:cc:00:00:01', w.BROADCAST), ts=100 + i * 0.1)
    h.ck('sparse broadcast deauth quiet', not evs)
    # targeted
    wt, evs = _watch()
    for i in range(12):
        wt.handle(deauth('aa:bb:cc:00:00:01', 'cc:cc:cc:00:00:09'), ts=200 + i * 0.1)
    tg = [e for e in evs if e['detector'] == 'deauth_flood']
    h.ck('targeted deauth flood fires (warning)', tg and tg[0]['severity'] == 'warning')
    h.ck('targeted deauth scope', tg and tg[0]['detail']['scope'] == 'targeted')
    # per-BSSID deauth+disassoc combined
    wt, evs = _watch()
    for i in range(25):
        st = 12 if i % 2 == 0 else 10                # mix deauth + disassoc
        wt.handle(deauth('aa:bb:cc:00:00:01', 'cc:cc:cc:00:%02x:09' % i, subtype=st),
                  ts=300 + i * 0.1)
    pb = [e for e in evs if e['detail'].get('scope') == 'per_bssid']
    h.ck('per-BSSID deauth+disassoc flood fires', pb and pb[0]['severity'] == 'critical')
    # protected posture carried
    wt, evs = _watch()
    for i in range(6):
        wt.handle(deauth('aa:bb:cc:00:00:01', w.BROADCAST, protected=False), ts=400 + i * 0.1)
    h.ck('deauth protected=false in detail',
         any(e['detail'].get('protected') is False for e in evs))

    # ---- beacon flood -----------------------------------------------------
    cfg = {'beacon_warmup_sec': 0, 'beacon_new_bssid_burst': 18}
    wt, evs = _watch(cfg)
    for i in range(20):                              # randomized (LA) BSSIDs
        wt.handle(beacon('de:ad:be:%02x:%02x:01' % (i // 256, i % 256), 'FAKE_%d' % i),
                  ts=1 + i * 0.1)
    bf = [e for e in evs if e['detector'] == 'beacon_flood']
    h.ck('beacon flood (LA burst) -> critical', bf and bf[-1]['severity'] == 'critical')
    h.ck('beacon flood la_ratio reported', bf and bf[-1]['detail']['la_ratio'] >= 0.5)
    wt, evs = _watch(cfg)
    for i in range(20):                              # global (burned-in) MACs
        wt.handle(beacon('00:1a:2b:%02x:%02x:00' % (i // 256, i % 256), 'Nbr_%d' % i),
                  ts=1 + i * 0.1)
    bf = [e for e in evs if e['detector'] == 'beacon_flood']
    h.ck('beacon flood (global MACs) -> warning', bf and bf[-1]['severity'] == 'warning')
    # warmup: dense boot is absorbed as census; a real post-warmup flood still trips
    cfg2 = {'beacon_warmup_sec': 30, 'beacon_new_bssid_burst': 18}
    wt, evs = _watch(cfg2)
    for i in range(40):                              # 40 ambient APs at boot (t<30)
        wt.handle(beacon('de:ad:00:%02x:%02x:01' % (i // 256, i % 256), 'Amb_%d' % i),
                  ts=0 + i * 0.05)
    h.ck('dense boot raises no false flood (warmup)',
         not any(e['detector'] == 'beacon_flood' for e in evs))
    for i in range(20):                              # real flood after warmup (t>30)
        wt.handle(beacon('ba:ad:be:%02x:%02x:01' % (i // 256, i % 256), 'Storm_%d' % i),
                  ts=40 + i * 0.1)
    h.ck('post-warmup flood still trips',
         any(e['detector'] == 'beacon_flood' for e in evs))
    # negative: a stable single AP beaconing 50x is not a flood
    wt, evs = _watch({'beacon_warmup_sec': 0})
    for i in range(50):
        wt.handle(beacon('aa:aa:aa:00:00:01', 'HomeNet'), ts=1 + i * 0.1)
    h.ck('stable single AP is not a flood',
         not any(e['detector'] == 'beacon_flood' for e in evs))

    # ---- evil twin --------------------------------------------------------
    cfg = {'beacon_warmup_sec': 0, 'allowlist': {'HomeNet': ['aa:aa:aa:00:00:01']}}
    wt, evs = _watch(cfg)
    wt.handle(beacon('99:99:99:99:99:99', 'HomeNet'), ts=1)
    et = [e for e in evs if e['detector'] == 'evil_twin']
    h.ck('evil twin (un-allowlisted BSSID) -> critical', et and et[0]['severity'] == 'critical')
    wt, evs = _watch(cfg)
    wt.handle(beacon('aa:aa:aa:00:00:01', 'HomeNet'), ts=1)
    h.ck('allowlisted BSSID -> no evil twin',
         not any(e['detector'] == 'evil_twin' and e['severity'] == 'critical' for e in evs))

    # ---- KARMA / MANA -----------------------------------------------------
    wt, evs = _watch({'beacon_warmup_sec': 0})
    for s in ['Starbucks', 'attwifi', 'HomeNet', 'xfinitywifi', 'TP-LINK', 'Netgear']:
        wt.handle(proberesp('ba:ad:ba:ad:00:01', s), ts=1)
    km = [e for e in evs if e['detector'] == 'karma_mana']
    h.ck('KARMA fires (one BSSID, many SSIDs)', km and km[0]['severity'] == 'critical')
    h.ck('KARMA ssid_count in detail', km and km[0]['detail']['ssid_count'] >= 5)
    # honest AP probe-responding for its own SSID only -> no KARMA
    wt, evs = _watch({'beacon_warmup_sec': 0})
    for _ in range(6):
        wt.handle(proberesp('cc:cc:cc:00:00:01', 'HomeNet'), ts=1)
    h.ck('honest single-SSID responder -> no KARMA',
         not any(e['detector'] == 'karma_mana' for e in evs))

    # ---- refractory: sustained flood is rate-limited ----------------------
    wt, evs = _watch({'refractory_sec': 5.0})
    for i in range(60):                              # 60 frames over 30s
        wt.handle(deauth('aa:bb:cc:00:00:01', w.BROADCAST), ts=500 + i * 0.5)
    n_alerts = sum(1 for e in evs if e['detector'] == 'deauth_flood')
    h.ck('refractory rate-limits alerts (not one per frame)', 1 <= n_alerts <= 8)

    total = h.n
    passed = total - h.fail
    print('wifiwatch self-test: %d/%d %s' % (passed, total, 'OK' if h.fail == 0 else 'FAILED'))
    return 0 if h.fail == 0 else 1


if __name__ == '__main__':
    sys.exit(run(verbose=True))
