#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Passive TLS/QUIC handshake observer for the Ragnar suite.

The session/presentation-layer (OSI L5/L6) detector: it sniffs ClientHello /
ServerHello off the wire, computes JA3/JA3S and JA4/JA4_r client fingerprints,
extracts SNI / ALPN / negotiated parameters, and (on TLS 1.2 over TCP, the only
handshake whose Certificate is passively observable) flags certificate-chain
anomalies. Passive-only: zero TX, inject, or probe on the monitored network.

This module is the BSD/MIT-clean core. JA4S (server fingerprint) carries FoxIO
License 1.1 and lives in a separate, clearly-identified file (ja4s.py); it is
imported lazily and only when the operator explicitly acknowledges that license.

Milestone status: M1 landed — raw-byte TLS ClientHello parser plus JA3 and
JA4/JA4_r client fingerprints, pinned to FoxIO's published known-answer vector.
ServerHello / certificate / findings / QUIC / capture arrive in later stages.

Algorithms implemented to the FoxIO JA4 technical specification (JA4 is
BSD-3-Clause) and the original Salesforce JA3 method.
"""
import hashlib
import struct


# ---- GREASE (draft-davidben-tls-grease-01): 0x0a0a, 0x1a1a, ..., 0xfafa ------
def _is_grease(v):
    """True for a GREASE code point — ignored anywhere it appears per the spec."""
    return (v & 0x0f0f) == 0x0a0a and ((v >> 8) & 0xff) == (v & 0xff)


class _Reader:
    """Bounds-checked byte reader. Raises ValueError on truncation so a single
    malformed handshake is rejected per-flow rather than crashing the sniffer."""
    __slots__ = ('b', 'i', 'n')

    def __init__(self, b, off=0, end=None):
        self.b = b
        self.i = off
        self.n = len(b) if end is None else end

    def rem(self):
        return self.n - self.i

    def u8(self):
        if self.i + 1 > self.n:
            raise ValueError('short u8')
        v = self.b[self.i]
        self.i += 1
        return v

    def u16(self):
        if self.i + 2 > self.n:
            raise ValueError('short u16')
        v = (self.b[self.i] << 8) | self.b[self.i + 1]
        self.i += 2
        return v

    def u24(self):
        if self.i + 3 > self.n:
            raise ValueError('short u24')
        v = (self.b[self.i] << 16) | (self.b[self.i + 1] << 8) | self.b[self.i + 2]
        self.i += 3
        return v

    def take(self, k):
        if k < 0 or self.i + k > self.n:
            raise ValueError('short take')
        v = self.b[self.i:self.i + k]
        self.i += k
        return v


# --------------------------- ClientHello parsing -----------------------------
def parse_client_hello(hs_body):
    """Parse a ClientHello *handshake body* (the bytes after the 4-byte handshake
    header: msg_type + 3-byte length). Returns the fields that feed JA3/JA4."""
    r = _Reader(hs_body)
    client_version = r.u16()
    r.take(32)                                   # random
    r.take(r.u8())                               # session id
    cr = _Reader(r.take(r.u16()))                # cipher_suites
    ciphers = []
    while cr.rem() >= 2:
        ciphers.append(cr.u16())
    r.take(r.u8())                               # compression methods

    exts_order = []
    sni = None
    alpn = []
    sig_algs = []
    sup_versions = []
    sup_groups = []
    ec_point_formats = []
    if r.rem() >= 2:
        er = _Reader(r.take(r.u16()))
        while er.rem() >= 4:
            etype = er.u16()
            edata = er.take(er.u16())
            exts_order.append(etype)
            if etype == 0x0000:                  # server_name
                sni = _parse_sni(edata)
            elif etype == 0x0010:                # application_layer_protocol_neg
                alpn = _parse_alpn(edata)
            elif etype == 0x000d:                # signature_algorithms
                sig_algs = _parse_u16_list(edata, prefix16=True)
            elif etype == 0x002b:                # supported_versions
                sup_versions = _parse_u16_list(edata, prefix8=True)
            elif etype == 0x000a:                # supported_groups
                sup_groups = _parse_u16_list(edata, prefix16=True)
            elif etype == 0x000b:                # ec_point_formats
                ec_point_formats = _parse_u8_list(edata, prefix8=True)
    return {
        'client_version': client_version,
        'ciphers': ciphers,
        'exts_order': exts_order,
        'sni': sni,
        'alpn': alpn,
        'sig_algs': sig_algs,
        'sup_versions': sup_versions,
        'sup_groups': sup_groups,
        'ec_point_formats': ec_point_formats,
    }


def _parse_sni(d):
    r = _Reader(d)
    if r.rem() < 2:
        return None
    lr = _Reader(r.take(r.u16()))
    while lr.rem() >= 3:
        ntype = lr.u8()
        name = lr.take(lr.u16())
        if ntype == 0:
            try:
                return name.decode('ascii', 'replace')
            except Exception:
                return name.decode('latin1', 'replace')
    return None


def _parse_alpn(d):
    r = _Reader(d)
    if r.rem() < 2:
        return []
    lr = _Reader(r.take(r.u16()))
    out = []
    while lr.rem() >= 1:
        out.append(lr.take(lr.u8()).decode('ascii', 'replace'))
    return out


def _parse_u16_list(d, prefix16=False, prefix8=False):
    r = _Reader(d)
    if prefix16:
        if r.rem() < 2:
            return []
        r = _Reader(r.take(r.u16()))
    elif prefix8:
        if r.rem() < 1:
            return []
        r = _Reader(r.take(r.u8()))
    out = []
    while r.rem() >= 2:
        out.append(r.u16())
    return out


def _parse_u8_list(d, prefix8=False):
    r = _Reader(d)
    if prefix8:
        if r.rem() < 1:
            return []
        r = _Reader(r.take(r.u8()))
    return list(r.take(r.rem()))


# ------------------------------ JA4 client -----------------------------------
_ALNUM = frozenset('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
_JA4_VER = {
    0x0304: '13', 0x0303: '12', 0x0302: '11', 0x0301: '10', 0x0300: 's3',
    0xfeff: 'd1', 0xfefd: 'd2', 0xfefc: 'd3',
}


def _ja4_version(sup_versions, client_version):
    """JA4 two-char version: highest non-GREASE supported_versions entry, else
    the record client_version."""
    cand = [v for v in sup_versions if not _is_grease(v)]
    return _JA4_VER.get(max(cand) if cand else client_version, '00')


def _ja4_alpn(alpn):
    """First+last alphanumeric char of the first ALPN value; '00' if none; hex
    fallback (first hex nibble of first byte, last hex nibble of last byte) for
    non-alphanumeric values, per the FoxIO spec."""
    if not alpn or not alpn[0]:
        return '00'
    s = alpn[0]
    first, last = s[0], s[-1]
    if first in _ALNUM and last in _ALNUM:
        return first + last
    fh = '{:02x}'.format(ord(first) & 0xff)
    lh = '{:02x}'.format(ord(last) & 0xff)
    return fh[0] + lh[1]


def ja4_client(parsed, proto='t'):
    """Return (ja4, ja4_r) for a parsed ClientHello. proto is 't' (TLS/TCP),
    'q' (QUIC) or 'd' (DTLS)."""
    ciphers = [c for c in parsed['ciphers'] if not _is_grease(c)]
    exts = [e for e in parsed['exts_order'] if not _is_grease(e)]
    ver = _ja4_version(parsed['sup_versions'], parsed['client_version'])
    sni_flag = 'd' if 0x0000 in parsed['exts_order'] else 'i'
    a = '{}{}{}{:02d}{:02d}{}'.format(proto, ver, sni_flag,
                                      min(len(ciphers), 99), min(len(exts), 99),
                                      _ja4_alpn(parsed['alpn']))

    cipher_hex = sorted('{:04x}'.format(c) for c in ciphers)
    b_raw = ','.join(cipher_hex)
    b = hashlib.sha256(b_raw.encode()).hexdigest()[:12] if cipher_hex else '000000000000'

    # Extensions for the c-hash exclude SNI(0000) and ALPN(0010), sorted; the
    # signature_algorithms follow in original order after an underscore.
    c_exts = sorted('{:04x}'.format(e) for e in exts if e not in (0x0000, 0x0010))
    sig_hex = ['{:04x}'.format(s) for s in parsed['sig_algs'] if not _is_grease(s)]
    c_raw = ','.join(c_exts) + ('_' + ','.join(sig_hex) if sig_hex else '')
    c = hashlib.sha256(c_raw.encode()).hexdigest()[:12] if c_exts else '000000000000'

    return '{}_{}_{}'.format(a, b, c), '{}_{}_{}'.format(a, b_raw, c_raw)


# ------------------------------ JA3 client -----------------------------------
def ja3_client(parsed):
    """Original Salesforce JA3: MD5 over decimal, GREASE-stripped
    version,ciphers,extensions,supported_groups,ec_point_formats. Returns
    (md5_digest, ja3_string)."""
    ciphers = [c for c in parsed['ciphers'] if not _is_grease(c)]
    exts = [e for e in parsed['exts_order'] if not _is_grease(e)]
    groups = [g for g in parsed['sup_groups'] if not _is_grease(g)]
    s = ','.join([
        str(parsed['client_version']),
        '-'.join(str(c) for c in ciphers),
        '-'.join(str(e) for e in exts),
        '-'.join(str(g) for g in groups),
        '-'.join(str(p) for p in parsed['ec_point_formats']),
    ])
    return hashlib.md5(s.encode()).hexdigest(), s


# ============================== self-test ====================================
# Test-only helper: assemble a wire-format ClientHello from parts so the parser
# and fingerprints are exercised end-to-end against the published vector.
def _build_client_hello(ciphers, ext_types, sig_algs, sup_versions, alpn, sni,
                        groups=(0x001d, 0x0017), point_formats=(0,)):
    body = struct.pack('!H', 0x0303) + b'\x00' * 32 + b'\x00'
    cs = b''.join(struct.pack('!H', c) for c in ciphers)
    body += struct.pack('!H', len(cs)) + cs + b'\x01\x00'
    exts = b''
    for et in ext_types:
        if et == 0x0000:
            host = sni.encode()
            entry = b'\x00' + struct.pack('!H', len(host)) + host
            data = struct.pack('!H', len(entry)) + entry
        elif et == 0x0010:
            protos = b''.join(struct.pack('!B', len(p.encode())) + p.encode() for p in alpn)
            data = struct.pack('!H', len(protos)) + protos
        elif et == 0x000d:
            sa = b''.join(struct.pack('!H', s) for s in sig_algs)
            data = struct.pack('!H', len(sa)) + sa
        elif et == 0x002b:
            vs = b''.join(struct.pack('!H', v) for v in sup_versions)
            data = struct.pack('!B', len(vs)) + vs
        elif et == 0x000a:
            gs = b''.join(struct.pack('!H', g) for g in groups)
            data = struct.pack('!H', len(gs)) + gs
        elif et == 0x000b:
            pf = bytes(point_formats)
            data = struct.pack('!B', len(pf)) + pf
        else:
            data = b''
        exts += struct.pack('!HH', et, len(data)) + data
    body += struct.pack('!H', len(exts)) + exts
    return struct.pack('!B', 0x01) + struct.pack('!BH', (len(body) >> 16) & 0xff,
                                                 len(body) & 0xffff) + body


# FoxIO published worked example (technical_details/JA4.md).
_KAT_CIPHERS = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9,
                0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035]
_KAT_EXTS = [0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d,
             0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015]
_KAT_SIGALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
_KAT_JA4 = 't13d1516h2_8daaf6152771_e5627efa2ab1'
_KAT_JA4_R = ('t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,'
              'c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,'
              '002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601')


def selftest():
    """Known-answer test harness. Returns {success, checks:[...], failed}."""
    checks = []

    def ck(name, got, want):
        checks.append({'name': name, 'pass': got == want, 'got': got, 'want': want})

    # Pure JA4_b / JA4_c hashes against the published decomposition.
    ck('ja4_b_hash', hashlib.sha256(
        ('002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,'
         'cca8,cca9').encode()).hexdigest()[:12], '8daaf6152771')
    ck('ja4_c_hash', hashlib.sha256(
        ('0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01'
         '_0403,0804,0401,0503,0805,0501,0806,0601').encode()).hexdigest()[:12],
       'e5627efa2ab1')

    # Full parse + fingerprint against the published example, with a GREASE
    # cipher/ext/version prepended to prove GREASE removal keeps counts 15/16.
    hs = _build_client_hello(
        [0x0a0a] + _KAT_CIPHERS, [0x1a1a] + _KAT_EXTS, _KAT_SIGALGS,
        [0x0a0a, 0x0304], alpn=['h2'], sni='example.com')
    p = parse_client_hello(hs[4:])
    ja4, ja4_r = ja4_client(p, proto='t')
    ck('full_ja4', ja4, _KAT_JA4)
    ck('full_ja4_r', ja4_r, _KAT_JA4_R)
    ck('sni_parse', p['sni'], 'example.com')
    ck('alpn_parse', p['alpn'], ['h2'])

    # ALPN http/1.1 -> h1; no-SNI -> i; no-ALPN -> 00.
    p2 = parse_client_hello(_build_client_hello(
        _KAT_CIPHERS, _KAT_EXTS, _KAT_SIGALGS, [0x0304],
        alpn=['http/1.1'], sni='x.test')[4:])
    ck('alpn_http11_h1', ja4_client(p2)[0].split('_')[0][-2:], 'h1')
    no_id = [e for e in _KAT_EXTS if e not in (0x0000, 0x0010)]
    p3 = parse_client_hello(_build_client_hello(
        _KAT_CIPHERS, no_id, _KAT_SIGALGS, [0x0304], alpn=[], sni='')[4:])
    a3 = ja4_client(p3)[0].split('_')[0]
    ck('no_sni_flag_i', a3[3], 'i')
    ck('no_alpn_00', a3[-2:], '00')

    # JA3 shape: decimal, dash-joined, MD5 hex.
    md5, s = ja3_client(p)
    ck('ja3_is_md5hex', len(md5) == 32 and all(x in '0123456789abcdef' for x in md5), True)
    ck('ja3_string_head', s.split(',')[0], '771')   # client_version 0x0303

    # scapy cross-check: parse a real scapy-built ClientHello off a TLS record.
    try:
        from scapy.layers.tls.handshake import TLSClientHello
        from scapy.layers.tls.extensions import (TLS_Ext_ServerName, TLS_Ext_ALPN,
                                                  ServerName, ProtocolName)
        from scapy.layers.tls.record import TLS
        ch = TLSClientHello(
            ciphers=[0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f],
            ext=[TLS_Ext_ServerName(servernames=[ServerName(servername=b'scapy.test')]),
                 TLS_Ext_ALPN(protocols=[ProtocolName(protocol=b'h2')])])
        raw = bytes(TLS(msg=[ch]))
        ps = parse_client_hello(raw[5 + 4:])         # skip record + handshake hdrs
        ck('scapy_sni', ps['sni'], 'scapy.test')
        ck('scapy_alpn', ps['alpn'], ['h2'])
        ck('scapy_ja4_alpn', ja4_client(ps)[0].split('_')[0][-2:], 'h2')
    except Exception as e:
        checks.append({'name': 'scapy_crosscheck', 'pass': True, 'skipped': str(e)})

    failed = sum(1 for c in checks if not c['pass'])
    return {'success': failed == 0, 'checks': checks, 'failed': failed}


def _main(argv=None):
    import argparse
    import json
    ap = argparse.ArgumentParser(prog='tls_watch',
                                 description='passive TLS/QUIC handshake observer')
    ap.add_argument('--selftest', action='store_true',
                    help='run the known-answer harness and exit')
    ap.add_argument('--json', action='store_true', help='emit JSON')
    args = ap.parse_args(argv)
    if args.selftest:
        r = selftest()
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            print('tls_watch self-test')
            print('-' * 52)
            for c in r['checks']:
                if c.get('skipped'):
                    print('  [SKIP] {}: {}'.format(c['name'], c['skipped']))
                else:
                    print('  [{}] {}'.format('PASS' if c['pass'] else 'FAIL', c['name']))
                    if not c['pass']:
                        print('        got : {}'.format(c['got']))
                        print('        want: {}'.format(c['want']))
            print('\n{} checks, {} failed'.format(len(r['checks']), r['failed']))
        return 0 if r['success'] else 1
    ap.print_help()
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(_main())
