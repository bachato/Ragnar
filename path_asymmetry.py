"""Path-asymmetry / one-way-delay (OWD) detector for Ragnar — the data-plane side.

Replaces hop-count (TTL) inference with *measured* one-way delay. A tiny UDP
reflector stamps the reverse leg, a prober stamps the forward leg, giving the
OWAMP/TWAMP 4-timestamp set per probe:

    T1 = prober send      T2 = reflector recv
    T3 = reflector send   T4 = prober recv

    fwd = T2 - T1         rev = T4 - T3         RTT = (T4-T1) - (T3-T2)   [offset-free]

The honest catch (see the design note in the code review): a single unsynced
clock pair CANNOT separate a *constant* clock offset theta from a *constant* path
asymmetry — they alias. So this detector:
  * estimates the slowly-varying clock offset with Paxson's min-pair method over
    a sliding window (theta_hat = (min(fwd) - min(rev)) / 2), and
  * reports **de-offset asymmetry** = (fwd - rev) - 2*theta_hat, which cancels
    the window baseline and is therefore sensitive to asymmetry *changes/events*
    (a path shift that adds delay in one direction) — the thing you actually want
    to alarm on — at millisecond resolution instead of integer hops.
Absolute asymmetry is only trustworthy when the clocks are synchronised (PTP/GPS);
set clock_synced=True and the raw asymmetry is reported as authoritative too.

Layers, each unit-testable with no network:
  * Reflector / Prober — the measurement wire
  * AsymmetryDetector  — offset estimator + hysteretic event emitter
  * passive_hopcount_asymmetry — TTL fallback when there is no reflector
  * correlate — ties a data-plane event to control-plane truth from a RIB
"""

import re
import socket
import struct
import threading
import time
from collections import deque

_MAGIC = b'RGWD'
_PKT = struct.Struct('!4sIddd')       # magic, seq, t1, t2, t3
DEFAULT_PORT = 33434


# --- reflector: stamps T2 (recv) and T3 (send) -----------------------------
class Reflector:
    """UDP one-way-delay reflector. Echoes each probe with reflector recv/send
    timestamps. Passive to the network — it only answers probes sent to it."""

    def __init__(self, bind='0.0.0.0', port=DEFAULT_PORT):
        self.bind = bind
        self.port = port
        self._sock = None
        self._thread = None
        self._stop = threading.Event()
        self.count = 0

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.bind, self.port))
        self._sock.settimeout(0.5)
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name='owd-reflector')
        self._thread.start()

    def stop(self):
        self._stop.set()
        try:
            if self._sock:
                self._sock.close()
        except OSError:
            pass

    def _run(self):
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(2048)
            except (socket.timeout, OSError):
                continue
            t2 = time.time()
            if len(data) < _PKT.size or data[:4] != _MAGIC:
                continue
            _m, seq, t1, _a, _b = _PKT.unpack(data[:_PKT.size])
            t3 = time.time()
            try:
                self._sock.sendto(_PKT.pack(_MAGIC, seq, t1, t2, t3), addr)
                self.count += 1
            except OSError:
                pass


# --- prober: sends T1, records T4 ------------------------------------------
def probe_once(target, port=DEFAULT_PORT, seq=0, timeout=1.0):
    """Send one probe; return (t1, t2, t3, t4) or None on loss/timeout."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        t1 = time.time()
        s.sendto(_PKT.pack(_MAGIC, seq, t1, 0.0, 0.0), (target, port))
        data, _ = s.recvfrom(2048)
        t4 = time.time()
        if len(data) < _PKT.size or data[:4] != _MAGIC:
            return None
        _m, rseq, rt1, t2, t3 = _PKT.unpack(data[:_PKT.size])
        if rseq != seq:
            return None
        return (rt1, t2, t3, t4)
    except (socket.timeout, OSError):
        return None
    finally:
        s.close()


def probe_series(target, port=DEFAULT_PORT, count=20, interval=0.05, timeout=1.0):
    """Send a burst of probes; return the list of (t1,t2,t3,t4) samples received."""
    samples = []
    for i in range(count):
        s = probe_once(target, port, seq=i, timeout=timeout)
        if s:
            samples.append(s)
        time.sleep(interval)
    return samples


# --- detector: offset estimation + asymmetry events ------------------------
class AsymmetryDetector:
    """Consumes (T1,T2,T3,T4) samples, removes the slowly-varying clock offset
    with Paxson's min-pair estimator over a sliding window, and emits hysteretic
    asymmetry events carrying measured OWD (ms) — not hop-count inference."""

    def __init__(self, window=64, threshold_ms=5.0, enter_n=3, exit_ratio=0.5,
                 clock_synced=False, target=None):
        self.window = window
        self.threshold_ms = threshold_ms
        self.enter_n = enter_n
        self.exit_ratio = exit_ratio
        self.clock_synced = clock_synced
        self.target = target
        self._fwd = deque(maxlen=window)
        self._rev = deque(maxlen=window)
        self._rtt = deque(maxlen=window)
        self._over = 0
        self._under = 0
        self.state = 'symmetric'
        self.samples = 0
        self.last = None

    def theta_ms(self):
        """Estimated clock offset (ms). Paxson min-pair over the window."""
        if not self._fwd:
            return 0.0
        return (min(self._fwd) - min(self._rev)) / 2.0 * 1000.0

    def add(self, t1, t2, t3, t4):
        """Add a sample; return an event dict on a state transition, else None."""
        fwd = t2 - t1
        rev = t4 - t3
        rtt = (t4 - t1) - (t3 - t2)
        self._fwd.append(fwd)
        self._rev.append(rev)
        self._rtt.append(rtt)
        self.samples += 1
        theta = (min(self._fwd) - min(self._rev)) / 2.0
        # de-offset asymmetry: (fwd-rev) - 2*theta, cancels the window baseline
        asym_ms = ((fwd - rev) - 2.0 * theta) * 1000.0
        raw_asym_ms = (fwd - rev) * 1000.0
        self.last = {
            'fwd_ms': round(fwd * 1000.0, 3), 'rev_ms': round(rev * 1000.0, 3),
            'rtt_ms': round(rtt * 1000.0, 3), 'theta_ms': round(theta * 1000.0, 3),
            'asymmetry_ms': round(asym_ms, 3), 'raw_asymmetry_ms': round(raw_asym_ms, 3),
            'samples': self.samples,
        }
        # hysteresis on |de-offset asymmetry|
        mag = abs(asym_ms)
        event = None
        if mag >= self.threshold_ms:
            self._over += 1
            self._under = 0
            if self.state == 'symmetric' and self._over >= self.enter_n:
                self.state = 'asymmetric'
                event = self._event('asymmetry_detected', asym_ms)
        else:
            self._under += 1
            self._over = 0
            if self.state == 'asymmetric' and mag <= self.threshold_ms * self.exit_ratio \
                    and self._under >= self.enter_n:
                self.state = 'symmetric'
                event = self._event('asymmetry_cleared', asym_ms)
        return event

    def _event(self, kind, asym_ms):
        return {
            'kind': kind, 'target': self.target, 'ts': time.time(),
            'asymmetry_ms': round(asym_ms, 3),
            'direction': 'forward-longer' if asym_ms > 0 else 'reverse-longer',
            'measured': True, 'method': 'owd',
            'clock_synced': self.clock_synced,
            'absolute_trustworthy': self.clock_synced,
            'rtt_ms': self.last['rtt_ms'], 'theta_ms': self.last['theta_ms'],
            'fwd_ms': self.last['fwd_ms'], 'rev_ms': self.last['rev_ms'],
        }

    def summary(self):
        return {'state': self.state, 'samples': self.samples,
                'target': self.target, 'clock_synced': self.clock_synced,
                'threshold_ms': self.threshold_ms, 'last': self.last,
                'rtt_min_ms': round(min(self._rtt) * 1000.0, 3) if self._rtt else None,
                'theta_ms': round(self.theta_ms(), 3)}


# --- passive fallback: hop-count asymmetry from TTL -------------------------
_TTL_RE = re.compile(r'\bttl\s+(\d+)', re.I)
_SRC_RE = re.compile(r'\bIP6?\s+(\d{1,3}(?:\.\d{1,3}){3})')


def _guess_initial_ttl(observed):
    for base in (64, 128, 255):
        if observed <= base:
            return base
    return 255


def passive_hopcount_asymmetry(tcpdump_text, local_ip=None):
    """Coarse fallback when there is no reflector: infer per-peer hop distance
    from observed TTL (initial_ttl - observed). Reports hop counts, and — if a
    local_ip and its reverse-direction TTL are both seen — a hop-count delta.
    This is the OLD inference; the OWD detector supersedes it when a reflector
    is reachable."""
    hops = {}
    for line in tcpdump_text.splitlines():
        sm = _SRC_RE.search(line)
        tm = _TTL_RE.search(line)
        if sm and tm:
            ttl = int(tm.group(1))
            h = _guess_initial_ttl(ttl) - ttl
            hops.setdefault(sm.group(1), []).append(h)
    per_peer = {ip: min(v) for ip, v in hops.items() if v}   # min hop = shortest seen
    return {'method': 'hopcount', 'measured': False,
            'per_peer_hops': per_peer,
            'note': 'TTL-inferred hop distance (fallback); use the OWD reflector '
                    'for measured, millisecond-resolution asymmetry'}


# --- correlator: control-plane truth (RIB) <- data-plane event -------------
def correlate(event, rib):
    """Annotate a data-plane asymmetry `event` (needs a 'target' IP) with the
    control-plane truth from a BGP RIB: the covering prefix, AS-path, origin AS,
    and whether that prefix is currently flapping / recently changed. This is
    what ties measured asymmetry back to *why* — a route change rather than a
    transient — turning a symptom into an attributable event."""
    out = dict(event)
    target = event.get('target')
    route = rib.lookup(target) if (rib and target) else None
    if route is None:
        out['control_plane'] = None
        out['attribution'] = 'no covering route in RIB (target off-domain or RIB empty)'
        return out
    out['control_plane'] = {
        'prefix': route['prefix'], 'origin_as': route['origin_as'],
        'as_path': route['as_path'], 'next_hop': route['next_hop'],
        'flapping': route['flapping'], 'flap_rate': route['flap_rate'],
        'change_age_s': route['change_age_s'],
    }
    # attribution heuristic: a recent control-plane change coincident with the
    # data-plane asymmetry event strongly implicates a route change.
    if route['flapping']:
        out['attribution'] = ('correlated with a FLAPPING route for %s (%d changes/window) '
                              '— asymmetry is route-churn driven'
                              % (route['prefix'], route['flap_rate']))
    elif route['change_age_s'] is not None and route['change_age_s'] < 120:
        out['attribution'] = ('coincides with a route change for %s %.0fs ago via AS-path %s '
                              '— likely a path shift'
                              % (route['prefix'], route['change_age_s'],
                                 ' '.join(map(str, route['as_path']))))
    else:
        out['attribution'] = ('route for %s stable (last change %ss ago) — asymmetry is '
                              'data-plane (congestion/TE), not a routing change'
                              % (route['prefix'], route['change_age_s']))
    return out


# --- self-test (no network for the detector; loopback for the wire) --------
def selftest():
    scen = []

    def check(name, ok, detail=''):
        scen.append({'name': name, 'pass': bool(ok), 'detail': str(detail)})

    # 1. offset removal + step-asymmetry event. Inject a CONSTANT clock offset
    #    theta=20ms and a STEP: forward path gains +12ms after sample 40. The
    #    detector must (a) not fire on the constant offset, (b) fire at the step.
    det = AsymmetryDetector(window=64, threshold_ms=5.0, enter_n=3, target='198.51.100.7')
    theta = 0.020                      # 20 ms clock offset (prober ahead)
    base_fwd, base_rev = 0.010, 0.010  # symmetric 10ms each way at baseline
    fired_before = fired_after = None
    t = 1000.0
    for i in range(90):
        extra = 0.012 if i >= 45 else 0.0          # forward path shift at i=45
        fwd = base_fwd + extra
        rev = base_rev
        # build timestamps with the offset: reflector clock = prober clock - theta
        t1 = t
        t2 = t1 + fwd - theta                       # reflector recv (its clock)
        t3 = t2 + 0.0002                            # reflector send
        t4 = t3 + rev + theta                       # prober recv (its clock)
        ev = det.add(t1, t2, t3, t4)
        if ev and i < 45:
            fired_before = ev
        if ev and i >= 45 and ev['kind'] == 'asymmetry_detected':
            fired_after = fired_after or ev
        t += 0.05
    theta_ok = abs(abs(det.theta_ms()) - 20.0) < 3.0   # recovered ~20ms offset (sign is convention)
    mag_ok = fired_after and abs(fired_after['asymmetry_ms'] - 12.0) < 3.0
    check('owd-offset-removed-no-false-event', theta_ok and fired_before is None,
          'theta=%.1f fired_before=%s' % (det.theta_ms(), fired_before))
    check('owd-step-event-measured-magnitude', bool(mag_ok),
          'event=%s' % (fired_after,))

    # 2. reflector <-> prober loopback: symmetric, ~0 asymmetry, no event
    refl = Reflector(bind='127.0.0.1', port=33500)
    refl.start()
    time.sleep(0.2)
    samples = probe_series('127.0.0.1', port=33500, count=20, interval=0.01)
    refl.stop()
    ld = AsymmetryDetector(threshold_ms=5.0, target='127.0.0.1')
    loop_events = [e for s in samples for e in [ld.add(*s)] if e]
    check('loopback-wire', len(samples) >= 15 and ld.state == 'symmetric'
          and not loop_events, 'n=%d state=%s' % (len(samples), ld.state))

    # 3. correlator ties an event to a flapping RIB route
    import bgp_speaker
    rib = bgp_speaker.RIB(flap_window_s=60, flap_threshold=3)
    now = time.time()
    for k in range(4):
        rib.apply_update({'announced': ['198.51.100.0/24'], 'withdrawn': [],
                          'as_path': [65001, 65002 + k], 'next_hop': '10.0.0.2',
                          'communities': []}, now=now + k)
    ev = {'kind': 'asymmetry_detected', 'target': '198.51.100.7', 'asymmetry_ms': 12.0}
    ann = correlate(ev, rib)
    check('correlator-attributes-flap',
          ann['control_plane'] and ann['control_plane']['flapping']
          and 'route-churn' in ann['attribution'], ann.get('attribution'))

    # 4. passive TTL fallback parses hop counts
    txt = ("IP 8.8.8.8 > 10.0.0.1: ICMP echo reply, ttl 57\n"
           "IP 1.1.1.1 > 10.0.0.1: tcp, ttl 250\n")
    hc = passive_hopcount_asymmetry(txt)
    check('passive-hopcount', hc['per_peer_hops'].get('8.8.8.8') == 7
          and hc['per_peer_hops'].get('1.1.1.1') == 5, hc['per_peer_hops'])

    return {'success': all(s['pass'] for s in scen), 'scenarios': scen}


if __name__ == '__main__':
    import json
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'reflector':
        port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
        r = Reflector(port=port)
        r.start()
        print('OWD reflector on udp/%d — Ctrl-C to stop' % port)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            r.stop()
        sys.exit(0)
    res = selftest()
    for s in res['scenarios']:
        print('  [%s] %s%s' % ('PASS' if s['pass'] else 'FAIL', s['name'],
                               '' if s['pass'] else '  -> ' + s['detail']))
    print('Path-asymmetry self-test:', 'OK' if res['success'] else 'FAILED')
    if '--json' in sys.argv:
        print(json.dumps(res, indent=2, default=str))
    sys.exit(0 if res['success'] else 1)
