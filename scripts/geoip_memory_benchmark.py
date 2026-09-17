#!/usr/bin/env python3
"""Reproducible memory benchmark for the GeoIP/map pipeline (Issue #45).

Generates a synthetic, DB-IP-City-Lite-shaped CSV of a configurable row
count and loads it through the *real* `CsvCityGeoIPProvider` in `app.py` --
not a reimplementation of its parsing logic -- reporting resident memory
(RSS, read from `/proc/self/status`) at each stage: process baseline, after
generating the synthetic CSV, after the provider load, after `gc.collect()`,
after an explicit `malloc_trim(0)`, after a batch of lookups (latency), and
after a simulated hot-reload (a second load with the old provider dropped).
This is the diagnostic Issue #45's real ~1.4 -> 2.687 -> 3.26 -> 5.77 GiB
TrueNAS escalation needs: an actual number at each stage of the real
implementation, not a guess -- see docs/GEOIP.md and the Issue #45 PR
description for how to read the output.

Unlike `scripts/verify_geoip.py` (deliberately standalone, no `app.py`
dependency), this script imports `app.py` on purpose: it has to measure the
exact production provider classes DNS Inspector actually runs, not a mirror
of their parsing logic, and a memory benchmark of a mirror would prove
nothing about the real process. This does mean it pulls in `app.py`'s own
dependencies (Flask, requests) and, like the test suite (see
`tests/conftest.py`), needs a couple of environment variables set before
import so it never touches a real `/data` volume.

Usage:
    python scripts/geoip_memory_benchmark.py
    python scripts/geoip_memory_benchmark.py --rows 7750000   # real City Lite scale
    python scripts/geoip_memory_benchmark.py --rows 500000 --keep-csv /tmp/city.csv

RSS reporting reads `/proc/self/status` (Linux only); on any other platform
it fails soft to "unknown" and the rest of the benchmark still runs, just
without memory numbers.
"""

import argparse
import gc
import os
import random
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# Same rationale as tests/conftest.py: app.py reads its configuration into
# module-level constants at import time, so anything that would otherwise
# touch a real /data volume or make a network call has to be pointed
# somewhere harmless *before* `import app` runs.
_TMP = tempfile.mkdtemp(prefix="dns-inspector-geoip-bench-")
os.environ.setdefault("DB_PATH", os.path.join(_TMP, "inspector.db"))
os.environ.setdefault("TRACKERDB_PATH", os.path.join(_TMP, "trackerdb.sqlite"))
os.environ.setdefault("NEIGHBORS_PATH", os.path.join(_TMP, "neighbors.txt"))
os.environ.setdefault("AGH_URL", "")
os.environ.setdefault("AGH_USER", "")
os.environ.setdefault("AGH_PASS", "")
os.environ.setdefault("GEOIP_AUTO_UPDATE", "false")

import app  # noqa: E402  (see module docstring: deliberately not standalone)

# A bounded set of country/city combinations that repeat across many rows,
# same as a real DB-IP City Lite export -- this is what actually exercises
# the interning optimization (CsvCityGeoIPProvider._intern_country/_city).
COUNTRIES = [
    ("US", "United States"), ("DE", "Germany"), ("FR", "France"), ("GB", "United Kingdom"),
    ("JP", "Japan"), ("BR", "Brazil"), ("IN", "India"), ("AU", "Australia"), ("CA", "Canada"),
    ("NL", "Netherlands"),
]
CITIES = [
    "Mountain View", "Berlin", "Paris", "London", "Tokyo",
    "Sao Paulo", "Mumbai", "Sydney", "Toronto", "Amsterdam",
]

_IPV4_RANGE_START = 1 << 24  # arbitrary; stays well clear of 0.0.0.0/8
_IPV4_RANGE_END = (1 << 32) - 512


def _rss_mb():
    """Current process resident set size, in MB, or None off Linux."""
    try:
        with open("/proc/self/status", "r") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024.0
    except OSError:
        return None
    return None


def _int_to_ipv4(value):
    return ".".join(str((value >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def _generate_city_csv(path, rows):
    """Streams a synthetic but realistically-shaped city CSV directly to
    disk -- ascending, non-overlapping /24-sized IPv4 ranges cycling through
    a bounded set of repeated country/city combinations -- without ever
    holding more than one row in memory at a time."""
    rng = random.Random(1234)
    addr = _IPV4_RANGE_START
    with open(path, "w", newline="") as f:
        for i in range(rows):
            start = addr
            end = addr + 255
            addr = end + 1
            if addr >= _IPV4_RANGE_END:
                addr = _IPV4_RANGE_START  # wrap rather than overflow IPv4 space
            code, name = COUNTRIES[i % len(COUNTRIES)]
            city = CITIES[i % len(CITIES)]
            lat = rng.uniform(-60.0, 60.0)
            lon = rng.uniform(-179.0, 179.0)
            f.write(f"{_int_to_ipv4(start)},{_int_to_ipv4(end)},{code},{name},{city},{lat:.4f},{lon:.4f}\n")


def _report(stage, rss_before, rss_after):
    delta = None if rss_before is None or rss_after is None else rss_after - rss_before
    delta_str = f"{delta:+.1f} MB" if delta is not None else "n/a"
    rss_str = f"{rss_after:.1f} MB" if rss_after is not None else "unknown (not Linux?)"
    print(f"{stage:<58} RSS={rss_str:<12} delta={delta_str}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--rows", type=int, default=2_000_000,
        help="Synthetic city CSV row count (default: %(default)s; a real DB-IP "
             "City Lite export is documented at ~7.75M -- see docs/GEOIP.md)",
    )
    parser.add_argument("--lookups", type=int, default=50_000, help="Lookup count for the latency benchmark (default: %(default)s)")
    parser.add_argument("--keep-csv", default=None, help="Write the generated CSV here and keep it, instead of a temp file that gets deleted")
    args = parser.parse_args(argv)

    csv_path = args.keep_csv or os.path.join(_TMP, "geoip_city_bench.csv")

    gc.collect()
    baseline = _rss_mb()
    _report("0. process baseline (app.py imported)", baseline, baseline)

    t0 = time.time()
    _generate_city_csv(csv_path, args.rows)
    gen_seconds = time.time() - t0
    after_gen = _rss_mb()
    _report(f"1. after generating {args.rows} synthetic rows ({gen_seconds:.1f}s)", baseline, after_gen)

    t0 = time.time()
    provider = app.CsvCityGeoIPProvider(csv_path)
    load_seconds = time.time() - t0
    after_load = _rss_mb()
    _report(f"2. after CsvCityGeoIPProvider load ({load_seconds:.1f}s, {provider.range_count} ranges)", after_gen, after_load)

    gc.collect()
    after_gc = _rss_mb()
    _report("3. after gc.collect()", after_load, after_gc)

    app._malloc_trim()
    after_trim = _rss_mb()
    _report("4. after malloc_trim(0)", after_gc, after_trim)

    rng = random.Random(99)
    sample_ips = [_int_to_ipv4(rng.randint(_IPV4_RANGE_START, _IPV4_RANGE_END)) for _ in range(args.lookups)]
    t0 = time.time()
    hits = sum(1 for ip in sample_ips if provider.lookup_city(ip) is not None)
    lookup_seconds = time.time() - t0
    after_lookups = _rss_mb()
    per_lookup_us = (lookup_seconds * 1_000_000 / args.lookups) if args.lookups else 0.0
    _report(f"5. after {args.lookups} lookups ({per_lookup_us:.2f}us/lookup, {hits} hits)", after_trim, after_lookups)

    t0 = time.time()
    old_provider = provider
    provider = app.CsvCityGeoIPProvider(csv_path)
    del old_provider
    gc.collect()
    app._malloc_trim()
    reload_seconds = time.time() - t0
    after_reload = _rss_mb()
    _report(f"6. after simulated hot-reload ({reload_seconds:.1f}s: load + drop old + gc + trim)", after_lookups, after_reload)

    stages = (baseline, after_gen, after_load, after_gc, after_trim, after_lookups, after_reload)
    known = [v for v in stages if v is not None]
    print()
    if known:
        print(f"Peak RSS observed: {max(known):.1f} MB")
        print(f"Final RSS: {after_reload:.1f} MB (baseline was {baseline:.1f} MB, net delta {after_reload - baseline:+.1f} MB)")
    else:
        print("RSS reporting unavailable on this platform (/proc/self/status not found).")

    if not args.keep_csv:
        try:
            os.remove(csv_path)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
