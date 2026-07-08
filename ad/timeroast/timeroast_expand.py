#!/usr/bin/env python3
import argparse, os, re, sys, time, math
from pathlib import Path
import multiprocessing as mp

# ==============================================================================
# Parallel, streaming expansion of digit runs in names
# - Deduplicates by digit-run pattern (e.g., DESKTOP####) so repeated variants
#   like DESKTOP1234 / DESKTOP0001 don't trigger duplicate expansions.
# - Also writes every original input line exactly once so the raw candidates
#   are guaranteed to be present even if expansion is capped by --max-line.
# - Splits large expansion spaces into chunks and processes them in parallel.
# ==============================================================================

DIGITS_RE = re.compile(r'\d+')

# -------- size parsing (K/M/G or raw bytes) ----------------------------------
def parse_size(s: str) -> int:
    s = s.strip().upper().rstrip('B')
    if s.endswith('K'): return int(s[:-1]) * 1024
    if s.endswith('M'): return int(s[:-1]) * 1024**2
    if s.endswith('G'): return int(s[:-1]) * 1024**3
    if s.isdigit():     return int(s)
    raise argparse.ArgumentTypeError(f"Invalid size (use K/M/G or bytes): {s}")

# -------- line analysis ------------------------------------------------------
def split_line(name: str):
    """
    Return (segs, lens) where:
      - segs are the non-digit parts between digit runs
      - lens are lengths of each digit run
    Example: 'DESKTOP1234-XY09' -> segs=['DESKTOP', '-XY', ''], lens=[4,2]
    """
    name = name.rstrip("\r\n")
    segs, lens, pos = [], [], 0
    for m in DIGITS_RE.finditer(name):
        segs.append(name[pos:m.start()])
        lens.append(len(m.group(0)))
        pos = m.end()
    segs.append(name[pos:])  # tail after last run
    return segs, lens

def combos_count(lens):
    total = 1
    for L in lens:
        total *= 10 ** L
        if total > 10**19:  # early bail for absurd numbers
            return total
    return total

def make_bases_strides_fmts(lens):
    """Precompute per-run base (10^L), stride (product of later bases), and zero-pad fmt."""
    n = len(lens)
    bases = [10 ** L for L in lens]
    strides = [1] * n
    for i in range(n - 2, -1, -1):  # stride[i] = product(bases[i+1:])
        strides[i] = strides[i + 1] * bases[i + 1]
    fmts = [("{:0" + str(L) + "d}") for L in lens]
    return bases, strides, fmts

def index_to_tuple(idx, bases, strides):
    """Mixed-radix decode: idx -> tuple of digit-run values."""
    vals = []
    for b, s in zip(bases, strides):
        vals.append((idx // s) % b)
    return vals

# -------- pattern helpers ----------------------------------------------------
def normalize_digits(name: str) -> str:
    """Replace every digit with '#' (for logging/visibility of the pattern)."""
    return DIGITS_RE.sub(lambda m: "#" * len(m.group(0)), name.rstrip("\r\n"))

def pattern_key_from_segs_lens(segs, lens):
    """
    Key identifying the *pattern*, independent of the specific numbers.
    Example: 'DESKTOP1234' and 'DESKTOP0001' share the same key.
    """
    return (tuple(segs), tuple(lens))

# -------- emitters -----------------------------------------------------------
def emit_range(segs, lens, bases, strides, fmts, start, count, stop_evt, out_q):
    """Emit [start, start+count) expansions to out_q, respecting stop_evt."""
    n = len(lens)
    end = start + count
    vec = index_to_tuple(start, bases, strides)
    for _ in range(start, end):
        if stop_evt.is_set(): break
        parts = []
        for i in range(n):
            parts.append(segs[i])
            parts.append(fmts[i].format(vec[i]))
        parts.append(segs[-1])
        out_q.put(''.join(parts) + "\n")
        # odometer increment
        for k in range(n - 1, -1, -1):
            vec[k] += 1
            if vec[k] < bases[k]:
                break
            vec[k] = 0

def emit_sequential(raw_line, max_line, stop_evt, out_q):
    """
    Simple sequential expansion for smaller cases (or when chunking not needed).
    Respects --max-line cap.
    """
    name = raw_line.rstrip("\r\n")
    segs, lens = split_line(name)
    if not lens:
        out_q.put(name + "\n")
        return
    bases, strides, fmts = make_bases_strides_fmts(lens)
    total = min(max_line, combos_count(lens))
    emit_range(segs, lens, bases, strides, fmts, 0, total, stop_evt, out_q)

# -------- task handling ------------------------------------------------------
# task types:
#   ("LINE", raw_line, max_line)
#   ("CHUNK", segs, lens, bases, strides, fmts, start, count, name_for_log)

def worker(in_q: mp.Queue, out_q: mp.Queue, stop_evt: mp.Event,
           verbose: bool, slow_thresh: float):
    while not stop_evt.is_set():
        try:
            task = in_q.get(timeout=0.5)
        except Exception:
            continue
        if task is None:
            break

        t0 = time.time()

        kind = task[0]
        if kind == "LINE":
            _, raw, max_line = task
            emit_sequential(raw, max_line, stop_evt, out_q)
            name_for_log = raw.rstrip("\r\n")
        else:  # "CHUNK"
            _, segs, lens, bases, strides, fmts, start, count, name_for_log = task
            emit_range(segs, lens, bases, strides, fmts, start, count, stop_evt, out_q)

        t1 = time.time()
        if verbose and (t1 - t0) >= slow_thresh:
            sys.stderr.write(f"[slow] '{name_for_log}': chunk/line in {t1 - t0:.2f}s\n")

    # let writer know this worker is done
    out_q.put(None)

def writer(out_q: mp.Queue, out_path: Path, limit_bytes: int,
           stop_evt: mp.Event, workers: int, start_size: int, line_counter: mp.Value):
    """
    Single writer process:
      - Appends lines to output file until reaching limit_bytes.
      - Counts '\n' to derive 'lines appended' (includes raw originals).
      - Receives 'None' sentinel once per worker to know when to exit.
    """
    written = start_size
    done_markers = 0
    with out_path.open("ab", buffering=1024*1024) as fh:
        while done_markers < workers:
            item = out_q.get()
            if item is None:
                done_markers += 1
                continue
            b = item.encode("utf-8")
            if stop_evt.is_set():
                continue
            if written + len(b) > limit_bytes:
                stop_evt.set()
                continue
            fh.write(b)
            written += len(b)
            # count lines appended
            nl = b.count(b"\n")
            if nl:
                with line_counter.get_lock():
                    line_counter.value += nl
            # flush every 10MB boundary to show progress on disk
            if (written // (10*1024*1024)) != ((written - len(b)) // (10*1024*1024)):
                fh.flush()
    stop_evt.set()

# -------- main ---------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description=(
            "Parallel, streaming expansion of digit runs in names. "
            "Automatically splits huge per-line spaces into parallel chunks. "
            "Deduplicates expansions by digit-run pattern while also emitting original lines."
        )
    )
    ap.add_argument("-i","--input",  required=True, help="input file (one name per line)")
    ap.add_argument("-o","--output", required=True, help="output file (appends)")
    ap.add_argument("-L","--limit",  type=parse_size, default=parse_size("10G"),
                    help="max output size (default 10G; accepts K/M/G or raw bytes)")
    ap.add_argument("-w","--workers", type=int, default=max(1, (os.cpu_count() or 1) - 1),
                    help="worker processes (default = CPU-1)")
    ap.add_argument("--max-line", type=int, default=1_000_000,
                    help="cap expansions per input line (default 1,000,000)")
    ap.add_argument("--chunk-threshold", type=int, default=1_000_000,
                    help="if estimated combos ≥ this, split into chunks (default 1,000,000)")
    ap.add_argument("--chunk-size", type=int, default=100_000,
                    help="target expansions per chunk (default 100,000)")
    ap.add_argument("--progress-every", type=int, default=0,
                    help="print progress every N input lines (default 0 = off)")
    ap.add_argument("-v","--verbose", action="store_true",
                    help="log slow/chunking/truncation/dedup info to stderr")
    ap.add_argument("--slow-threshold", type=float, default=3.0,
                    help="seconds to consider a unit 'slow' (default 3.0)")
    # Behavior toggles (defaults ON):
    ap.add_argument("--no-pattern-dedup", action="store_true",
                    help="disable deduplication by digit-run pattern (expand duplicates too)")
    ap.add_argument("--no-emit-originals", action="store_true",
                    help="do not also emit each raw input line verbatim")

    args = ap.parse_args()

    in_path  = Path(args.input)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    t_start = time.perf_counter()
    start_size = out_path.stat().st_size if out_path.exists() else 0
    if start_size >= args.limit:
        sys.stderr.write(f"[!] Output already at/over limit ({start_size} bytes). Exiting.\n")
        return

    # context (prefer fork on *nix; Windows will use spawn)
    try:
        ctx = mp.get_context("fork")
    except ValueError:
        ctx = mp.get_context()

    in_q  = ctx.Queue(maxsize=4000)
    out_q = ctx.Queue(maxsize=8192)
    stop_evt = ctx.Event()
    line_counter = ctx.Value('Q', 0)  # 64-bit count of appended lines

    # writer
    wproc = ctx.Process(
        target=writer,
        args=(out_q, out_path, args.limit, stop_evt, args.workers, start_size, line_counter),
        daemon=True
    )
    wproc.start()

    # workers
    workers = []
    for _ in range(max(1, args.workers)):
        p = ctx.Process(target=worker, args=(in_q, out_q, stop_evt, args.verbose, args.slow_threshold), daemon=True)
        p.start()
        workers.append(p)

    fed = 0  # input lines read
    seen_patterns = set()

    try:
        # feeder: stream input, decide LINE vs CHUNK tasks
        with in_path.open("r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                if stop_evt.is_set():
                    break
                name = raw.rstrip("\r\n")

                # 1) Always enqueue the exact original, unless user opted out.
                if not args.no_emit_originals:
                    out_q.put(name + "\n")

                segs, lens = split_line(name)

                # 2) If there are no digit runs, nothing to expand (original already emitted).
                if not lens:
                    fed += 1
                    if args.progress_every and (fed % args.progress_every == 0):
                        appended = line_counter.value
                        elapsed = time.perf_counter() - t_start
                        rate_in  = fed / elapsed if elapsed > 0 else 0.0
                        rate_out = appended / elapsed if elapsed > 0 else 0.0
                        sys.stderr.write(f"[=] progress: in={fed:,} out≈{appended:,} "
                                         f"({rate_in:,.0f} in/s, {rate_out:,.0f} out/s)\n")
                    continue

                # 3) Deduplicate by pattern key (same segs + same digit-run lengths).
                pkey = pattern_key_from_segs_lens(segs, lens)
                if not args.no_pattern_dedup:
                    if pkey in seen_patterns:
                        if args.verbose:
                            sys.stderr.write(f"[dedup] skip expansion for '{name}' "
                                             f"(pattern {normalize_digits(name)})\n")
                        fed += 1
                        if args.progress_every and (fed % args.progress_every == 0):
                            appended = line_counter.value
                            elapsed = time.perf_counter() - t_start
                            rate_in  = fed / elapsed if elapsed > 0 else 0.0
                            rate_out = appended / elapsed if elapsed > 0 else 0.0
                            sys.stderr.write(f"[=] progress: in={fed:,} out≈{appended:,} "
                                             f"({rate_in:,.0f} in/s, {rate_out:,.0f} out/s)\n")
                        continue
                    seen_patterns.add(pkey)

                # 4) Schedule one expansion job per unique pattern.
                est = combos_count(lens)
                if args.verbose and est > args.max_line:
                    sys.stderr.write(f"[truncate] '{name}': combos≈{est:,} -> capped at {args.max_line:,}\n")

                total_emit = min(est, args.max_line)

                if total_emit < args.chunk_threshold or args.workers <= 1:
                    # Use the LINE path (it recomputes segs/lens in the worker; simple and fine).
                    in_q.put(("LINE", raw, args.max_line))
                else:
                    bases, strides, fmts = make_bases_strides_fmts(lens)
                    chunks = math.ceil(total_emit / args.chunk_size)
                    if args.verbose:
                        sys.stderr.write(f"[chunk] '{name}': total={total_emit:,}, "
                                         f"chunks={chunks} (size≈{args.chunk_size:,}), "
                                         f"pattern={normalize_digits(name)}\n")
                    start = 0
                    remaining = total_emit
                    while remaining > 0 and not stop_evt.is_set():
                        this = min(args.chunk_size, remaining)
                        in_q.put(("CHUNK", segs, lens, bases, strides, fmts, start, this, name))
                        start += this
                        remaining -= this

                fed += 1
                if args.progress_every and (fed % args.progress_every == 0):
                    appended = line_counter.value
                    elapsed = time.perf_counter() - t_start
                    rate_in  = fed / elapsed if elapsed > 0 else 0.0
                    rate_out = appended / elapsed if elapsed > 0 else 0.0
                    sys.stderr.write(f"[=] progress: in={fed:,} out≈{appended:,} "
                                     f"({rate_in:,.0f} in/s, {rate_out:,.0f} out/s)\n")
    except KeyboardInterrupt:
        sys.stderr.write("\n[!] Ctrl-C received — stopping...\n")
        stop_evt.set()
    finally:
        # close input
        for _ in workers:
            in_q.put(None)
        # wait workers then writer
        for p in workers:
            p.join()
        wproc.join(timeout=2.0)
        if wproc.is_alive():
            stop_evt.set()
            wproc.terminate()

    # --- summary ---
    t_end = time.perf_counter()
    try:
        end_size = out_path.stat().st_size if out_path.exists() else start_size
    except Exception:
        end_size = start_size
    appended_lines = line_counter.value
    delta_bytes = end_size - start_size
    elapsed = t_end - t_start
    rate_out = appended_lines / elapsed if elapsed > 0 else 0.0
    exp_factor = (appended_lines / fed) if fed > 0 else 0.0

    print("\n=== Summary ===")
    print(f"Start time              : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(t_start))}")
    print(f"End time                : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(t_end))}")
    print(f"Elapsed time            : {elapsed:.2f} s")
    print(f"Input lines read        : {fed:,}")
    print(f"Output lines appended   : {appended_lines:,}")
    if fed:
        print(f"Expansion factor        : {exp_factor:,.2f}x per input line")
    print(f"Output file size        : {start_size:,} → {end_size:,} bytes (Δ {delta_bytes:,})")
    print(f"Throughput (lines out)  : {rate_out:,.0f} lines/s")
    print("Good luck!")

if __name__ == "__main__":
    mp.freeze_support()
    main()
