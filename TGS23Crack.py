#!/usr/bin/env python3
# tgs23_match.py — verify $krb5tgs$23$ tickets against NT hashes, with timing stats

import argparse, sys, time, hashlib, hmac

def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xff
        j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) & 0xff]
        out.append(b ^ K)
    return bytes(out)

def parse_tgs23(line: str):
    core = line.strip().split(':', 1)[0]
    if not core.startswith("$krb5tgs$23$"):
        return None
    parts = core.split('$')
    if len(parts) < 8:
        return None
    user = parts[3].lstrip('*')
    realm = parts[4]
    spn  = parts[5].rstrip('*')
    try:
        checksum = bytes.fromhex(parts[-2])
        ciphertext = bytes.fromhex(parts[-1])
    except ValueError:
        return None
    return user, realm, spn, checksum, ciphertext

def load_hashes(path: str):
    out = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith('#'): continue
            if ':' in s:
                h, label = s.split(':', 1)
            else:
                h, label = s, None
            h = h.strip().lower()
            if len(h) == 32 and all(c in '0123456789abcdef' for c in h):
                out.append((h, label))
    return out

def iter_lines(path: str):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            s = line.strip()
            if s: yield s

def main():
    ap = argparse.ArgumentParser(description="Match $krb5tgs$23$ tickets against NT hashes (with stats)")
    ap.add_argument('-t','--tickets', required=True, help='File with $krb5tgs$23$ lines')
    ap.add_argument('-d','--dict',    required=True, help='File with NT hashes (32-hex), optional :label')
    ap.add_argument('-o','--out',     default=None,  help='Write matches to this file')
    ap.add_argument('--stop-first',   action='store_true', help='Stop after first match per ticket')
    ap.add_argument('--progress',     type=int, default=0, help='Print progress every N tickets')
    ap.add_argument('--quiet',        action='store_true', help='Only print summary and matches')
    args = ap.parse_args()

    # Load inputs
    t0 = time.perf_counter()
    nthashes = load_hashes(args.dict)
    if not nthashes:
        print('[!] No valid NT hashes loaded', file=sys.stderr)
        sys.exit(1)

    # Precompute K1/K2 for T=2 once per NT hash (saves work in the inner loop)
    T = (2).to_bytes(4, 'little')
    pre_t1 = time.perf_counter()
    precomp = []
    for hhex, label in nthashes:
        K = bytes.fromhex(hhex)
        K1 = hmac.new(K, T, hashlib.md5).digest()
        K2 = K1[:16]
        precomp.append((hhex, label, K1, K2))
    pre_t2 = time.perf_counter()

    # Iterate tickets and test
    tickets_total = 0
    matches = []
    checks = 0                       # actual (ticket,hash) verifications performed
    loop_t0 = time.perf_counter()

    for line in iter_lines(args.tickets):
        parsed = parse_tgs23(line)
        if not parsed:
            continue
        tickets_total += 1
        user, realm, spn, cks, ct = parsed

        found_any = False
        for hhex, label, K1, K2 in precomp:
            K3 = hmac.new(K1, cks, hashlib.md5).digest()
            edata = rc4(K3, ct)
            calc  = hmac.new(K2, edata, hashlib.md5).digest()
            checks += 1
            if calc[:16] == cks:
                matches.append({
                    'user': user, 'realm': realm, 'spn': spn,
                    'nthash': hhex, 'label': label, 'ticket': line
                })
                if not args.quiet:
                    print(f"[+] MATCH user={user} realm={realm} spn={spn} nt={hhex}"
                          + (f" label={label}" if label else ""))
                found_any = True
                if args.stop_first:
                    break

        if not found_any and not args.quiet:
            print(f"[-] no match for user={user} realm={realm} spn={spn}")

        if args.progress and tickets_total % args.progress == 0:
            now = time.perf_counter()
            elapsed = now - loop_t0
            total_elapsed = now - t0
            # instantaneous rates since loop start; conservative if progress used late
            rate_checks = checks / total_elapsed if total_elapsed > 0 else 0.0
            rate_tickets = tickets_total / total_elapsed if total_elapsed > 0 else 0.0
            print(f"[=] progress: {tickets_total} tickets | {checks} checks | "
                  f"{rate_tickets:.2f} tickets/s | {rate_checks:.0f} checks/s")

    t1 = time.perf_counter()
    cpu_s = time.process_time()  # CPU time (approx; not split per phase)

    # Summary
    total_elapsed = t1 - t0
    precompute_elapsed = pre_t2 - pre_t1
    loop_elapsed = t1 - loop_t0
    rate_checks = checks / loop_elapsed if loop_elapsed > 0 else 0.0
    rate_tickets = tickets_total / loop_elapsed if loop_elapsed > 0 else 0.0

    print("\n=== Summary ===")
    print(f"Tickets processed : {tickets_total}")
    print(f"NT hashes loaded  : {len(precomp)}")
    print(f"Matches found     : {len(matches)}")
    print(f"Checks performed  : {checks}")
    print(f"Precompute K1/K2  : {precompute_elapsed:.4f} s")
    print(f"Time (matching)   : {loop_elapsed:.4f} s")
    print(f"Total time        : {total_elapsed:.4f} s")
    print(f"Throughput        : {rate_tickets:.2f} tickets/s | {rate_checks:.0f} checks/s")
    if checks:
        print(f"Avg per check     : {1000.0 * loop_elapsed / checks:.3f} ms")
    if tickets_total:
        print(f"Avg per ticket    : {1000.0 * loop_elapsed / tickets_total:.3f} ms")
    print(f"CPU time (proc)   : {cpu_s:.4f} s")

    if args.out and matches:
        with open(args.out, 'w', encoding='utf-8') as f:
            for m in matches:
                label = f":{m['label']}" if m['label'] else ""
                f.write(f"{m['user']}@{m['realm']} {m['spn']} {m['nthash']}{label}\n")

if __name__ == '__main__':
    main()
