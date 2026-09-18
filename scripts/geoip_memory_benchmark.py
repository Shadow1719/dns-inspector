#!/usr/bin/env python3
"""Reproducible memory benchmark for the GeoIP provider redesign (Issue #52).

Generates synthetic, DB-IP-{Country,City}-Lite-shaped CSVs of a configurable
row count and loads them through the *real* `CsvRangeGeoIPProvider`/
`CsvCityGeoIPProvider` in `app.py` -- not a reimplementation of their parsing
logic -- reporting resident memory (RSS, read from `/proc/self/status`) at
each stage Issue #52 asks for:

    0. baseline RSS (app.py imported, nothing loaded)
    1. peak RSS while the country database loads
    2. peak RSS while the city database loads
    3. steady-state RSS after load (post `gc.collect()`/`malloc_trim`)
    4. RSS after a batch of repeated lookups
    5. RSS after repeated provider reloads
    6. each provider's own compact storage size (bytes, computed directly
       from its `array.array` column buffers/interned tables -- not RSS,
       which also includes the CSV text, the interpreter, Flask, etc.)

"Peak while loading" is sampled by a lightweight background thread that polls
RSS every few milliseconds for the duration of the load call, not just
measured before/after -- a single before/after delta would understate a
transient peak that comes back down before the load call returns.

Unlike `scripts/verify_geoip.py` (deliberately standalone, no `app.py`
dependency), this script imports `app.py` on purpose: it has to measure the
exact production provider classes DNS Inspector actually runs, not a mirror
of their parsing logic, and a memory benchmark of a mirror would prove
nothing about the real process.

Usage:
    python scripts/geoip_memory_benchmark.py
    python scripts/geoip_memory_benchmark.py --city-rows 7750000   # real City Lite scale
    python scripts/geoip_memory_benchmark.py --country-rows 400000 --keep-csv /tmp/geoip

RSS reporting reads `/proc/self/status` (Linux only, e.g. the project's own
Debian-slim container image); on any other platform it fails soft to
"unknown" and the rest of the benchmark still runs, just without memory
numbers.
"""

import argparse
import gc
import os
import random
import sys
import tempfile
import threading
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
# same as a real DB-IP export -- this is what actually exercises the
# interning optimization (`_intern_country`/`_intern_city`).
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


class _PeakRssSampler:
    """Polls RSS on a background thread while a load call runs, so a
    transient peak that settles back down before the call returns is still
    captured -- a plain before/after delta would understate it."""

    def __init__(self, interval_seconds=0.01):
        self._interval = interval_seconds
        self._stop = threading.Event()
        self._peak = None
        self._thread = None

    def __enter__(self):
        self._peak = _rss_mb()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def _run(self):
        while not self._stop.is_set():
            sample = _rss_mb()
            if sample is not None and (self._peak is None or sample > self._peak):
                self._peak = sample
            self._stop.wait(self._interval)

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join(timeout=5)
        final = _rss_mb()
        if final is not None and (self._peak is None or final > self._peak):
            self._peak = final
        return False

    @property
    def peak_mb(self):
        return self._peak


def _generate_country_csv(path, rows):
    """Streams a synthetic but realistically-shaped country CSV directly to
    disk -- ascending, non-overlapping /24-sized IPv4 ranges cycling through
    a bounded set of repeated country codes/names -- without ever holding
    more than one row in memory at a time."""
    addr = _IPV4_RANGE_START
    with open(path, "w", newline="") as f:
        for i in range(rows):
            start = addr
            end = addr + 255
            addr = end + 1
            if addr >= _IPV4_RANGE_END:
                addr = _IPV4_RANGE_START
            code, name = COUNTRIES[i % len(COUNTRIES)]
            f.write(f"{_int_to_ipv4(start)},{_int_to_ipv4(end)},{code},{name}\n")


def _generate_city_csv(path, rows):
    """Same shape as `_generate_country_csv()` plus a city + coordinate pair
    per row, matching `CsvCityGeoIPProvider`'s expected schema."""
    rng = random.Random(1234)
    addr = _IPV4_RANGE_START
    with open(path, "w", newline="") as f:
        for i in range(rows):
            start = addr
            end = addr + 255
            addr = end + 1
            if addr >= _IPV4_RANGE_END:
                addr = _IPV4_RANGE_START
            code, name = COUNTRIES[i % len(COUNTRIES)]
            city = CITIES[i % len(CITIES)]
            lat = rng.uniform(-60.0, 60.0)
            lon = rng.uniform(-179.0, 179.0)
            f.write(f"{_int_to_ipv4(start)},{_int_to_ipv4(end)},{code},{name},{city},{lat:.4f},{lon:.4f}\n")


def _country_provider_storage_bytes(provider):
    """The provider's own compact storage, in bytes -- distinct from RSS
    (which also includes the CSV text, the interpreter, Flask, etc). Sums
    the real packed `array.array` buffers plus a rough estimate for the
    small interned-country table and the (much smaller) IPv6 tuple list."""
    arrays = (provider._v4_start, provider._v4_end, provider._v4_country_idx)
    array_bytes = sum(a.buffer_info()[1] * a.itemsize for a in arrays)
    interned_bytes = sum(sys.getsizeof(c) + sys.getsizeof(n) for c, n in provider._countries)
    v6_bytes = sum(sys.getsizeof(row) for row in provider._v6)
    return array_bytes + interned_bytes + v6_bytes


def _city_provider_storage_bytes(provider):
    arrays = (
        provider._v4_start, provider._v4_end, provider._v4_lat, provider._v4_lon,
        provider._v4_country_idx, provider._v4_city_idx,
    )
    array_bytes = sum(a.buffer_info()[1] * a.itemsize for a in arrays)
    interned_bytes = sum(sys.getsizeof(c) + sys.getsizeof(n) for c, n in provider._countries)
    interned_bytes += sum(sys.getsizeof(city) for city in provider._cities)
    v6_bytes = sum(sys.getsizeof(row) for row in provider._v6)
    return array_bytes + interned_bytes + v6_bytes


def _report(stage, rss_before, rss_after):
    delta = None if rss_before is None or rss_after is None else rss_after - rss_before
    delta_str = f"{delta:+.1f} MB" if delta is not None else "n/a"
    rss_str = f"{rss_after:.1f} MB" if rss_after is not None else "unknown (not Linux?)"
    print(f"{stage:<62} RSS={rss_str:<12} delta={delta_str}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--country-rows", type=int, default=400_000,
        help="Synthetic country CSV row count (default: %(default)s)",
    )
    parser.add_argument(
        "--city-rows", type=int, default=2_000_000,
        help="Synthetic city CSV row count (default: %(default)s; a real DB-IP "
             "City Lite export is documented at ~7.75M -- see docs/GEOIP.md)",
    )
    parser.add_argument("--lookups", type=int, default=50_000, help="Lookup count for the latency/RSS benchmark (default: %(default)s)")
    parser.add_argument("--reloads", type=int, default=3, help="Number of simulated hot-reloads to run (default: %(default)s)")
    parser.add_argument("--keep-csv", default=None, help="Directory to write the generated CSVs into and keep, instead of a temp dir that gets deleted")
    args = parser.parse_args(argv)

    csv_dir = args.keep_csv or _TMP
    os.makedirs(csv_dir, exist_ok=True)
    country_csv = os.path.join(csv_dir, "geoip_country_bench.csv")
    city_csv = os.path.join(csv_dir, "geoip_city_bench.csv")

    gc.collect()
    baseline = _rss_mb()
    _report("0. process baseline (app.py imported)", baseline, baseline)

    t0 = time.time()
    _generate_country_csv(country_csv, args.country_rows)
    after_country_gen = _rss_mb()
    _report(f"1a. after generating {args.country_rows} synthetic country rows ({time.time() - t0:.1f}s)", baseline, after_country_gen)

    t0 = time.time()
    _generate_city_csv(city_csv, args.city_rows)
    after_city_gen = _rss_mb()
    _report(f"1b. after generating {args.city_rows} synthetic city rows ({time.time() - t0:.1f}s)", after_country_gen, after_city_gen)

    t0 = time.time()
    with _PeakRssSampler() as country_sampler:
        country_provider = app.CsvRangeGeoIPProvider(country_csv)
    country_load_seconds = time.time() - t0
    after_country_load = _rss_mb()
    country_peak_rss = country_sampler.peak_mb
    _report(
        f"2. PEAK RSS while country loads ({country_load_seconds:.1f}s, {country_provider.range_count} ranges)",
        after_city_gen, country_peak_rss,
    )
    _report("2b. RSS immediately after country load", after_city_gen, after_country_load)

    t0 = time.time()
    with _PeakRssSampler() as city_sampler:
        city_provider = app.CsvCityGeoIPProvider(city_csv)
    city_load_seconds = time.time() - t0
    after_city_load = _rss_mb()
    city_peak_rss = city_sampler.peak_mb
    _report(
        f"3. PEAK RSS while city loads ({city_load_seconds:.1f}s, {city_provider.range_count} ranges)",
        after_country_load, city_peak_rss,
    )
    _report("3b. RSS immediately after city load", after_country_load, after_city_load)

    app._geoip_allocator_cleanup()
    after_cleanup = _rss_mb()
    _report("4. steady-state RSS after gc.collect()/malloc_trim", after_city_load, after_cleanup)

    rng = random.Random(99)
    sample_ips = [_int_to_ipv4(rng.randint(_IPV4_RANGE_START, _IPV4_RANGE_END)) for _ in range(args.lookups)]
    t0 = time.time()
    country_hits = sum(1 for ip in sample_ips if country_provider.lookup(ip) != (None, None))
    city_hits = sum(1 for ip in sample_ips if city_provider.lookup_city(ip) is not None)
    lookup_seconds = time.time() - t0
    after_lookups = _rss_mb()
    per_lookup_us = (lookup_seconds * 1_000_000 / (2 * args.lookups)) if args.lookups else 0.0
    _report(
        f"5. after {args.lookups} country+city lookups each ({per_lookup_us:.2f}us/lookup, "
        f"{country_hits}/{city_hits} hits)",
        after_cleanup, after_lookups,
    )

    t0 = time.time()
    for _ in range(max(1, args.reloads)):
        old_country, old_city = country_provider, city_provider
        country_provider = app.CsvRangeGeoIPProvider(country_csv)
        del old_country
        city_provider = app.CsvCityGeoIPProvider(city_csv)
        del old_city
        app._geoip_allocator_cleanup()
    reload_seconds = time.time() - t0
    after_reloads = _rss_mb()
    _report(f"6. after {args.reloads} repeated reloads ({reload_seconds:.1f}s total)", after_lookups, after_reloads)

    country_bytes = _country_provider_storage_bytes(country_provider)
    city_bytes = _city_provider_storage_bytes(city_provider)
    print()
    print(f"Country provider's own compact storage: {country_bytes / (1024 * 1024):.2f} MB for {country_provider.range_count} ranges")
    print(f"City provider's own compact storage:    {city_bytes / (1024 * 1024):.2f} MB for {city_provider.range_count} ranges")

    stages = (
        baseline, after_country_gen, after_city_gen, country_peak_rss, after_country_load,
        city_peak_rss, after_city_load, after_cleanup, after_lookups, after_reloads,
    )
    known = [v for v in stages if v is not None]
    print()
    if known:
        print(f"Peak RSS observed: {max(known):.1f} MB")
        print(f"Final RSS: {after_reloads:.1f} MB (baseline was {baseline:.1f} MB, net delta {after_reloads - baseline:+.1f} MB)")
    else:
        print("RSS reporting unavailable on this platform (/proc/self/status not found).")

    if not args.keep_csv:
        for path in (country_csv, city_csv):
            try:
                os.remove(path)
            except OSError:
                pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
