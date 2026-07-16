#!/usr/bin/env python3
"""wifiwatch.py — passive 802.11 attack monitor (Ragnar).

Passive-only (RX-only) wireless IDS: it never transmits — no probes, no assoc,
no deauth. It sniffs 802.11 management frames in monitor mode and flags four
attack classes: deauth/disassoc floods, beacon (fake-AP) floods, evil twins,
and KARMA/MANA rogue APs.

The 802.11 + radiotap parsing is raw-byte (no Scapy dissectors), so `--self-test`
and `--replay` of a pcap run with no radio and the self-test needs no Scapy at
all. Scapy is used purely as the live-capture front-end. Detectors key off each
frame's *capture* timestamp (not wall clock), so replay timing matches the
original capture. See docs/wifiwatch.md.
"""

import argparse
import json
import os
import struct
import sys
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

MODULE = 'wifiwatch'
SEV_RANK = {'info': 0, 'warning': 1, 'critical': 2}

# ===========================================================================
# Radiotap (raw) — extract channel frequency + signal
# ===========================================================================
# bit -> (align, size) for the standard low fields (enough to reach Channel/dBm).
_RT_FIELDS = {0: (8, 8), 1: (1, 1), 2: (1, 1), 3: (2, 4), 4: (2, 2), 5: (1, 1),
              6: (1, 1), 7: (2, 2), 8: (2, 2), 9: (2, 2), 10: (1, 1), 11: (1, 1),
              12: (1, 1), 13: (1, 1), 14: (2, 2)}


def _u16(b, i):
    return b[i] | (b[i + 1] << 8)


def _u32(b, i):
    return struct.unpack_from('<I', b, i)[0]


def _s8(v):
    return v - 256 if v > 127 else v


def parse_radiotap(buf):
    """Return (freq_mhz, signal_dbm, header_len). Best-effort; unknown high
    fields are fine because Channel (bit 3) and dBm signal (bit 5) precede them."""
    if len(buf) < 8 or buf[0] != 0:
        return None, None, 0
    hdrlen = _u16(buf, 2)
    if hdrlen < 8 or hdrlen > len(buf):
        return None, None, 0
    present = _u32(buf, 4)
    off = 8
    p = present
    while p & 0x80000000 and off + 4 <= hdrlen:      # presence extensions
        p = _u32(buf, off)
        off += 4
    freq = signal = None
    pos = off
    for bit in range(15):
        if not (present & (1 << bit)):
            continue
        a, sz = _RT_FIELDS[bit]
        pos = (pos + a - 1) & ~(a - 1)                # align from radiotap start
        if pos + sz > hdrlen:
            break
        if bit == 3:
            freq = _u16(buf, pos)
        elif bit == 5:
            signal = _s8(buf[pos])
        pos += sz
    return freq, signal, hdrlen


def band_of(freq):
    if freq is None:
        return None
    if 2400 <= freq < 2500:
        return '2.4'
    if 5150 <= freq < 5895:
        return '5'
    if freq >= 5925:
        return '6'
    return None


def channel_of(freq):
    if freq is None:
        return None
    if freq == 2484:
        return 14
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if band_of(freq) == '6':
        return (freq - 5950) // 5
    if freq >= 5000:
        return (freq - 5000) // 5
    return None


# ===========================================================================
# 802.11 management frame (raw)
# ===========================================================================
BROADCAST = 'ff:ff:ff:ff:ff:ff'


def _mac(b, i):
    return ':'.join('%02x' % x for x in b[i:i + 6])


def is_locally_administered(mac):
    try:
        return bool(int(mac.split(':')[0], 16) & 0x02)
    except (ValueError, IndexError, AttributeError):
        return False


def _parse_ies(b, i, out):
    """Walk tagged params from offset i; fill SSID and RSN (MFP/AKM)."""
    n = len(b)
    while i + 2 <= n:
        eid = b[i]
        elen = b[i + 1]
        i += 2
        if i + elen > n:
            break
        val = b[i:i + elen]
        if eid == 0:                                 # SSID
            try:
                out['ssid'] = val.decode('utf-8', 'replace') if val else ''
            except Exception:
                out['ssid'] = ''
        elif eid == 48 and elen >= 8:                # RSN
            out['rsn'] = _parse_rsn(val)
        i += elen


def _parse_rsn(v):
    """Extract AKM suites + PMF (MFPC/MFPR) from an RSN element body."""
    try:
        i = 2 + 4                                    # version + group cipher
        pcnt = _u16(v, i); i += 2 + 4 * pcnt         # pairwise ciphers
        acnt = _u16(v, i); i += 2
        akms = [_u32(v, i + 4 * k) & 0xff for k in range(acnt)]
        i += 4 * acnt
        caps = _u16(v, i) if i + 2 <= len(v) else 0
        return {'akms': akms, 'mfpc': bool(caps & 0x80), 'mfpr': bool(caps & 0x40)}
    except Exception:
        return {'akms': [], 'mfpc': False, 'mfpr': False}


def parse_dot11(buf):
    """Parse an 802.11 management frame (no radiotap). Returns a dict or None."""
    if len(buf) < 24:
        return None
    fc0, fc1 = buf[0], buf[1]
    ftype = (fc0 >> 2) & 0x3
    subtype = (fc0 >> 4) & 0xf
    if ftype != 0:                                   # management only
        return None
    out = {'subtype': subtype, 'protected': bool(fc1 & 0x40),
           'da': _mac(buf, 4), 'sa': _mac(buf, 10), 'bssid': _mac(buf, 16),
           'ssid': None, 'reason': None, 'rsn': None}
    body = buf[24:]
    if subtype in (8, 5):                            # beacon / probe-resp
        _parse_ies(body, 12, out)                    # skip fixed params
    elif subtype == 4:                               # probe-req
        _parse_ies(body, 0, out)
    elif subtype in (10, 12):                        # disassoc / deauth
        if len(body) >= 2:
            out['reason'] = _u16(body, 0)
    return out


def parse_frame(raw):
    """Radiotap + 802.11 → normalized event dict, or None."""
    freq, signal, hdrlen = parse_radiotap(raw)
    d11 = parse_dot11(raw[hdrlen:]) if hdrlen else parse_dot11(raw)
    if d11 is None:
        return None
    d11['freq'] = freq
    d11['signal'] = signal
    d11['band'] = band_of(freq)
    d11['channel'] = channel_of(freq)
    return d11


# ===========================================================================
# Detector engine
# ===========================================================================
DEFAULTS = {
    'deauth_broadcast_burst': 6, 'deauth_broadcast_window': 5.0,
    'deauth_per_bssid_burst': 25, 'deauth_per_bssid_window': 5.0,
    'deauth_per_target_burst': 12, 'deauth_per_target_window': 5.0,
    'beacon_new_bssid_burst': 18, 'beacon_window': 8.0,
    'beacon_warmup_sec': 30.0, 'beacon_la_ratio': 0.5,
    'karma_ssid_min': 5,
    'refractory_sec': 5.0,
    'allowlist': {},                                 # ssid -> [bssids]
}
SUBTYPE_NAME = {4: 'probe_req', 5: 'probe_resp', 8: 'beacon', 10: 'disassoc',
                12: 'deauth'}


class WifiWatch:
    def __init__(self, config=None, emit=None):
        c = dict(DEFAULTS)
        c.update(config or {})
        self.cfg = c
        self.emit = emit or (lambda ev: None)
        self.allow = {s.lower(): {b.lower() for b in v}
                      for s, v in (c.get('allowlist') or {}).items()}
        self.start_ts = None
        self.census = set()                          # BSSIDs seen during warmup
        self.first_seen = {}                         # bssid -> ts
        self._new_bssids = deque()                   # (ts, bssid) post-warmup
        self._deauth_bcast = deque()                 # ts
        self._deauth_bssid = defaultdict(deque)      # bssid -> ts
        self._deauth_target = defaultdict(deque)     # dst -> ts
        self._ap_ssids = defaultdict(set)            # bssid -> ssids answered
        self._beaconed = defaultdict(set)            # bssid -> ssids beaconed
        self._probe_reqs = deque()                   # (ts, ssid) directed probes
        self._refractory = {}                        # (detector, scope) -> ts
        self.frames = 0
        self.stats = defaultdict(int)

    # -- helpers -------------------------------------------------------------
    def _warm(self, ts):
        return (ts - self.start_ts) < self.cfg['beacon_warmup_sec']

    @staticmethod
    def _trim(dq, ts, window, keyed=False):
        while dq and ts - (dq[0][0] if keyed else dq[0]) > window:
            dq.popleft()

    def _fire(self, detector, scope, sev, ev_fields, ts):
        """Emit unless within the per-scope refractory window (every frame is
        still counted; only the alert is rate-limited)."""
        key = (detector, scope)
        last = self._refractory.get(key)
        if last is not None and ts - last < self.cfg['refractory_sec']:
            return
        self._refractory[key] = ts
        ev = {'ts': datetime.fromtimestamp(ts, timezone.utc).isoformat(),
              'module': MODULE, 'detector': detector, 'severity': sev}
        ev.update(ev_fields)
        self.stats[detector] += 1
        self.emit(ev)

    # -- main path (live, replay, and self-test all call this) ---------------
    def handle(self, raw, ts=None, freq=None):
        f = parse_frame(raw)
        if f is None:
            return
        if ts is None:
            ts = time.time()
        if self.start_ts is None:
            self.start_ts = ts
        self.frames += 1
        if freq is not None and f['freq'] is None:
            f['freq'] = freq
            f['band'] = band_of(freq)
            f['channel'] = channel_of(freq)
        st = f['subtype']
        if st == 8:
            self._on_beacon(f, ts)
        elif st == 5:
            self._on_probe_resp(f, ts)
        elif st == 4:
            self._on_probe_req(f, ts)
        elif st in (10, 12):
            self._on_deauth(f, ts)

    # -- beacon flood + evil twin -------------------------------------------
    def _on_beacon(self, f, ts):
        bssid = f['bssid']
        ssid = f.get('ssid')
        if ssid:
            self._beaconed[bssid].add(ssid)
            self._ap_ssids[bssid].add(ssid)
        if bssid not in self.first_seen:
            self.first_seen[bssid] = ts
            if self._warm(ts):
                self.census.add(bssid)
            else:
                self._new_bssids.append((ts, bssid))
        self._eval_beacon_flood(f, ts)
        self._eval_evil_twin(f, ts, ssid, bssid)

    def _eval_beacon_flood(self, f, ts):
        self._trim(self._new_bssids, ts, self.cfg['beacon_window'], keyed=True)
        burst = [b for _t, b in self._new_bssids]
        if len(set(burst)) < self.cfg['beacon_new_bssid_burst']:
            return
        uniq = set(burst)
        la = sum(1 for b in uniq if is_locally_administered(b))
        la_ratio = la / len(uniq)
        sev = 'critical' if la_ratio >= self.cfg['beacon_la_ratio'] else 'warning'
        self._fire('beacon_flood', 'segment', sev, {
            'band': f['band'], 'channel': f['channel'], 'bssid': f['bssid'],
            'ssid': f.get('ssid'), 'signal_dbm': f['signal'],
            'summary': '%d new BSSIDs in %.0fs (LA ratio %.0f%%) — fake-AP storm'
                       % (len(uniq), self.cfg['beacon_window'], la_ratio * 100),
            'detail': {'new_bssids': len(uniq), 'la_bssids': la,
                       'la_ratio': round(la_ratio, 2),
                       'window_sec': self.cfg['beacon_window']}}, ts)

    def _eval_evil_twin(self, f, ts, ssid, bssid):
        if not ssid:
            return
        trusted = self.allow.get(ssid.lower())
        if trusted is not None:
            if bssid not in trusted:
                self._fire('evil_twin', ssid, 'critical', {
                    'band': f['band'], 'channel': f['channel'], 'bssid': bssid,
                    'ssid': ssid, 'signal_dbm': f['signal'],
                    'summary': "SSID '%s' beaconed from un-allowlisted BSSID %s "
                               '(evil twin)' % (ssid, bssid),
                    'detail': {'reason': 'unauthorized_bssid',
                               'trusted': sorted(trusted)}}, ts)
        else:
            aps = {b for b, s in self._ap_ssids.items() if ssid in s}
            if len(aps) >= 2:
                self._fire('evil_twin', ssid, 'info', {
                    'band': f['band'], 'channel': f['channel'], 'bssid': bssid,
                    'ssid': ssid, 'signal_dbm': f['signal'],
                    'summary': "SSID '%s' seen from %d BSSIDs (unlisted; allowlist "
                               'it to confirm)' % (ssid, len(aps)),
                    'detail': {'reason': 'multi_bssid_unlisted',
                               'bssids': sorted(aps)}}, ts)

    # -- KARMA / MANA --------------------------------------------------------
    def _on_probe_resp(self, f, ts):
        bssid = f['bssid']
        ssid = f.get('ssid')
        if ssid:
            self._ap_ssids[bssid].add(ssid)
        n = len(self._ap_ssids[bssid])
        if n >= self.cfg['karma_ssid_min']:
            self._fire('karma_mana', bssid, 'critical', {
                'band': f['band'], 'channel': f['channel'], 'bssid': bssid,
                'ssid': ssid, 'signal_dbm': f['signal'],
                'summary': '%s answered %d different SSIDs — KARMA/MANA rogue AP'
                           % (bssid, n),
                'detail': {'ssid_count': n,
                           'ssids': sorted(self._ap_ssids[bssid])[:12]}}, ts)
        self._eval_evil_twin(f, ts, ssid, bssid)

    def _on_probe_req(self, f, ts):
        ssid = f.get('ssid')
        if ssid:                                     # directed probe (has SSID)
            self._probe_reqs.append((ts, ssid))
            self._trim(self._probe_reqs, ts, 30.0, keyed=True)

    # -- deauth / disassoc flood --------------------------------------------
    def _on_deauth(self, f, ts):
        kind = SUBTYPE_NAME[f['subtype']]
        bssid = f['bssid']
        dst = f['da']
        protected = f['protected']
        reason = f.get('reason')
        common = {'band': f['band'], 'channel': f['channel'], 'bssid': bssid,
                  'ssid': None, 'signal_dbm': f['signal']}
        if dst == BROADCAST:
            dq = self._deauth_bcast
            dq.append(ts)
            self._trim(dq, ts, self.cfg['deauth_broadcast_window'])
            if len(dq) >= self.cfg['deauth_broadcast_burst']:
                self._fire('deauth_flood', 'broadcast:' + bssid, 'critical', dict(
                    common, summary='Broadcast %s flood from %s: %d frames/%.0fs '
                    'to all clients (reason %s)' % (kind, bssid, len(dq),
                    self.cfg['deauth_broadcast_window'], reason),
                    detail={'kind': kind, 'scope': 'broadcast', 'count': len(dq),
                            'window_sec': self.cfg['deauth_broadcast_window'],
                            'reason': reason, 'protected': protected}), ts)
        else:
            dq = self._deauth_target[dst]
            dq.append(ts)
            self._trim(dq, ts, self.cfg['deauth_per_target_window'])
            if len(dq) >= self.cfg['deauth_per_target_burst']:
                self._fire('deauth_flood', 'target:' + dst, 'warning', dict(
                    common, summary='Directed %s flood at %s from %s: %d frames/%.0fs'
                    % (kind, dst, bssid, len(dq), self.cfg['deauth_per_target_window']),
                    detail={'kind': kind, 'scope': 'targeted', 'target': dst,
                            'count': len(dq), 'reason': reason,
                            'protected': protected}), ts)
        # per-BSSID (deauth + disassoc combined)
        bq = self._deauth_bssid[bssid]
        bq.append(ts)
        self._trim(bq, ts, self.cfg['deauth_per_bssid_window'])
        if len(bq) >= self.cfg['deauth_per_bssid_burst']:
            self._fire('deauth_flood', 'bssid:' + bssid, 'critical', dict(
                common, summary='%s: %d deauth/disassoc frames/%.0fs — DoS'
                % (bssid, len(bq), self.cfg['deauth_per_bssid_window']),
                detail={'kind': kind, 'scope': 'per_bssid', 'count': len(bq),
                        'reason': reason, 'protected': protected}), ts)


# ===========================================================================
# Live capture / replay (scapy, lazy)
# ===========================================================================
def run_replay(path, watch, replay_freq=None):
    from scapy.all import PcapReader
    with PcapReader(path) as pr:
        for pkt in pr:
            raw = bytes(pkt)
            ts = float(getattr(pkt, 'time', 0)) or time.time()
            watch.handle(raw, ts=ts, freq=replay_freq)


def run_live(iface, watch, hopper=None):
    from scapy.all import sniff

    def cb(pkt):
        watch.handle(bytes(pkt), ts=float(getattr(pkt, 'time', 0)) or time.time())
    sys.stderr.write('wifiwatch: passive on %s (monitor) — Ctrl-C to stop\n' % iface)
    if hopper:
        hopper.start()
    sniff(iface=iface, prn=cb, store=False)


# ===========================================================================
# Output
# ===========================================================================
def make_emitter(out_fh, echo, min_sev, pushover=None):
    floor = SEV_RANK.get(min_sev, 1)

    def emit(ev):
        line = json.dumps(ev)
        if out_fh:
            out_fh.write(line + '\n')
            out_fh.flush()
        if echo:
            sys.stderr.write('  [%s] %s/%s %s\n' % (ev['severity'], ev['detector'],
                             ev.get('bssid') or '', ev.get('summary', '')))
        if pushover and SEV_RANK.get(ev['severity'], 0) >= floor:
            pushover(ev)
    return emit


# ===========================================================================
# CLI
# ===========================================================================
def _load_config(path):
    if not path:
        return {}
    with open(path) as f:
        return json.load(f)


def main(argv=None):
    ap = argparse.ArgumentParser(prog='wifiwatch',
                                 description='Passive 802.11 attack monitor (RX-only).')
    ap.add_argument('-i', '--iface', help='monitor-mode capture interface')
    ap.add_argument('--replay', help='replay a pcap instead of live capture')
    ap.add_argument('--replay-freq', type=int, help='force a channel freq (MHz) for replay')
    ap.add_argument('-c', '--config', help='JSON config path')
    ap.add_argument('--jsonl', '-o', help="JSON-lines output path ('-' = stdout)")
    ap.add_argument('--echo', action='store_true', help='echo events to stderr')
    ap.add_argument('--min-alert-severity', default='warning',
                    choices=['info', 'warning', 'critical'])
    ap.add_argument('--self-test', action='store_true')
    args = ap.parse_args(argv)

    if args.self_test:
        import wifiwatch_selftest
        return wifiwatch_selftest.run(verbose=True)

    cfg = _load_config(args.config)
    out_fh = None
    if args.jsonl == '-':
        out_fh = sys.stdout
    elif args.jsonl:
        os.makedirs(os.path.dirname(args.jsonl) or '.', exist_ok=True)
        out_fh = open(args.jsonl, 'a')
    emit = make_emitter(out_fh, args.echo or not args.jsonl, args.min_alert_severity)
    watch = WifiWatch(cfg, emit=emit)

    if args.replay:
        run_replay(args.replay, watch, replay_freq=args.replay_freq)
    elif args.iface:
        if os.geteuid() != 0:
            sys.stderr.write('error: live capture needs root / CAP_NET_RAW.\n')
            return 2
        try:
            run_live(args.iface, watch)
        except KeyboardInterrupt:
            pass
    else:
        ap.error('one of --iface, --replay or --self-test is required')
    sys.stderr.write('wifiwatch: %d frames, alerts %s\n' % (watch.frames, dict(watch.stats)))
    if out_fh and out_fh is not sys.stdout:
        out_fh.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
