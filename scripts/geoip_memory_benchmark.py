#!/usr/bin/env python3
"""Reproducible peak-RSS memory benchmark for the GeoIP providers (Issue #52).

0.8.5.10's chunk/yield throttle (`_iter_csv_rows_throttled()`) only changed
*when* CSV parsing happens, not how much memory it peaks at. This script
measures the actual RSS impact of loading `CsvRangeGeoIPProvider`/
`CsvCityGeoIPProvider` against a synthetic dataset generated on the fly (or,
with `--country-csv`/`--city-csv`, a real converted database), so a change to
the loader's memory representation can be judged by measurement instead of a
claim.

It imports `app.py` directly (unlike `verify_geoip.py`, which deliberately
avoids that import) because the whole point is to measure the real runtime
provider classes' actual memory footprint, not a mirror implementation.

Measured checkpoints, each a process RSS snapshot in MiB:
    baseline                  -- right after import, before any provider load
    after_country_load        -- immediately after CsvRangeGeoIPProvider loads
    after_city_load           -- immediately after CsvCityGeoIPProvider loads
    steady_state               -- after gc.collect() once both are loaded
    after_repeated_lookups     -- after --lookups repeated random lookups
    after_repeated_reloads     -- after --reloads repeated provider reloads

RSS is read from `ru_maxrss` (`resource.getrusage(RUSAGE_SELF)`), which is a
high-water mark on Linux: it only ever increases, so the value captured right
after a step reflects the peak reached up to and including that step (not
just its final resting size) -- exactly the "peak RSS while X loads" figures
Issue #52 asks for. The delta between consecutive checkpoints is what that
step actually cost.

Usage:
    # Fast synthetic smoke run (a few hundred thousand rows):
    python scripts/geoip_memory_benchmark.py --country-rows 200000 --city-rows 200000

    # Representative multi-million-row run (default sizes approximate a real
    # DB-IP Country/City Lite export):
    python scripts/geoip_memory_benchmark.py

    # Against real converted databases instead of synthetic data:
    python scripts/geoip_memory_benchmark.py --country-csv data/geoip_country_ranges.csv --city-csv data/geoip_city_ranges.csv

No network access, no Flask server, no background workers -- this only
imports `app.py`'s module-level definitions and constructs providers
directly.
"""

import argparse
import gc
import os
import random
import resource
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

_COUNTRY_CODES = ["US", "DE", "FR", "GB", "JP", "BR", "IN", "CA", "AU", "NL"]
_CITIES = ["Springfield", "Riverside", "Franklin", "Georgetown", "Clinton", "Madison", "Arlington", "Oxford"]


def _rss_mb():
    """Peak RSS so far, in MiB. `ru_maxrss` is KiB on Linux, bytes on macOS."""
    raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    divisor = 1024.0 if sys.platform != "darwin" else 1024.0 * 1024.0
    return round(raw / divisor, 1)


def _write_synthetic_country_csv(path, rows, shuffle):
    """Non-overlapping /24-sized IPv4 blocks plus a small IPv6 tail, streamed
    straight to disk -- never held as a Python list, so generating the fixture
    itself does not distort the peak-RSS measurement that follows."""
    order = list(range(rows))
    if shuffle:
        random.Random(1337).shuffle(order)
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write("start_ip,end_ip,country_code,country_name\n")
        for i in order:
            base = i * 256
            a, b = (base // 256) % 256, (base // 65536) % 256
            c = (base // 16777216) % 256
            code = _COUNTRY_CODES[i % len(_COUNTRY_CODES)]
            f.write(f"{c}.{b}.{a}.0,{c}.{b}.{a}.255,{code},{code} Country\n")
        f.write("2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,DE,DE Country\n")


def _write_synthetic_city_csv(path, rows, shuffle):
    order = list(range(rows))
    if shuffle:
        random.Random(1337).shuffle(order)
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write("start_ip,end_ip,country_code,country_name,city,latitude,longitude\n")
        for i in order:
            base = i * 256
            a, b = (base // 256) % 256, (base // 65536) % 256
            c = (base // 16777216) % 256
            code = _COUNTRY_CODES[i % len(_COUNTRY_CODES)]
            city = _CITIES[i % len(_CITIES)]
            lat = -60.0 + (i % 1200) / 10.0
            lon = -170.0 + (i % 3400) / 10.0
            f.write(f"{c}.{b}.{a}.0,{c}.{b}.{a}.255,{code},{code} Country,{city},{lat:.4f},{lon:.4f}\n")
        f.write("2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,DE,DE Country,Berlin,52.52,13.405\n")


def _compact_storage_bytes(provider):
    """The provider's own steady-state compact-array/interned-table size --
    distinct from process RSS, which also includes Python/CPython overhead,
    the CSV parser's transient state, and allocator fragmentation."""
    total = 0
    for attr in ("_v4_start", "_v4_end", "_v4_country_idx", "_v4_city_idx", "_v4_lat", "_v4_lon"):
        arr = getattr(provider, attr, None)
        if arr is not None:
            total += arr.buffer_info()[1] * arr.itemsize
    v6 = getattr(provider, "_v6", None)
    if v6:
        total += sys.getsizeof(v6) + sum(sys.getsizeof(row) for row in v6)
    for attr in ("_countries", "_cities"):
        table = getattr(provider, attr, None)
        if table:
            total += sys.getsizeof(table) + sum(sys.getsizeof(item) for item in table)
    return total


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--country-rows", type=int, default=2_000_000, help="Synthetic country CSV row count (ignored with --country-csv).")
    parser.add_argument("--city-rows", type=int, default=2_000_000, help="Synthetic city CSV row count (ignored with --city-csv).")
    parser.add_argument("--country-csv", help="Use a real/existing country CSV instead of generating one.")
    parser.add_argument("--city-csv", help="Use a real/existing city CSV instead of generating one.")
    parser.add_argument("--shuffle", action="store_true", help="Generate synthetic rows out of start-IP order, exercising the sort fallback path instead of the streamed fast path.")
    parser.add_argument("--lookups", type=int, default=200_000, help="Number of repeated random lookups to perform after loading.")
    parser.add_argument("--reloads", type=int, default=3, help="Number of full provider reload cycles to perform after loading.")
    parser.add_argument("--keep-files", action="store_true", help="Do not delete generated synthetic CSVs on exit.")
    args = parser.parse_args()

    bench_tmp_dir = Path(tempfile.mkdtemp(prefix="geoip-benchmark-state-"))
    os.environ.setdefault("DB_PATH", str(bench_tmp_dir / "inspector.db"))
    os.environ.setdefault("TRACKERDB_PATH", str(bench_tmp_dir / "trackerdb.sqlite"))
    os.environ.setdefault("NEIGHBORS_PATH", str(bench_tmp_dir / "neighbors.txt"))
    os.environ.setdefault("AGH_URL", "")
    os.environ.setdefault("AGH_USER", "")
    os.environ.setdefault("AGH_PASS", "")
    os.environ.setdefault("TRACKERDB_URL", "http://127.0.0.1:9/trackerdb.sql")
    os.environ.setdefault("RDAP_URL", "http://127.0.0.1:9/domain/")
    os.environ.setdefault("MACVENDOR_URL", "http://127.0.0.1:9")
    os.environ.setdefault("NETIFY_URL", "http://127.0.0.1:9/hostnames/")
    os.environ.setdefault("GEOIP_LOAD_YIELD_SECONDS", "0")  # benchmark load time, not the throttle sleeps

    def snapshot(label):
        mb = _rss_mb()
        print(f"{label:<28} {mb:>10.1f} MiB", flush=True)
        return mb

    tmp_dir = Path(tempfile.mkdtemp(prefix="geoip-benchmark-"))
    country_csv = Path(args.country_csv) if args.country_csv else tmp_dir / "country.csv"
    city_csv = Path(args.city_csv) if args.city_csv else tmp_dir / "city.csv"

    if not args.country_csv:
        print(f"Generating synthetic country CSV ({args.country_rows} rows, shuffle={args.shuffle})...", flush=True)
        _write_synthetic_country_csv(country_csv, args.country_rows, args.shuffle)
    if not args.city_csv:
        print(f"Generating synthetic city CSV ({args.city_rows} rows, shuffle={args.shuffle})...", flush=True)
        _write_synthetic_city_csv(city_csv, args.city_rows, args.shuffle)

    import app as dns_inspector  # noqa: E402  (env vars must be set first)

    print()
    print(f"{'checkpoint':<28} {'RSS':>10}")
    snapshot("baseline")

    t0 = time.monotonic()
    country_provider = dns_inspector.CsvRangeGeoIPProvider(str(country_csv))
    country_load_s = time.monotonic() - t0
    snapshot("after_country_load")

    t0 = time.monotonic()
    city_provider = dns_inspector.CsvCityGeoIPProvider(str(city_csv))
    city_load_s = time.monotonic() - t0
    snapshot("after_city_load")

    gc.collect()
    snapshot("steady_state")

    rng = random.Random(42)
    for _ in range(args.lookups):
        octet_a = rng.randint(0, 255)
        octet_b = rng.randint(0, 255)
        octet_c = rng.randint(0, 255)
        country_provider.lookup(f"{octet_c}.{octet_b}.{octet_a}.1")
        city_provider.lookup_city(f"{octet_c}.{octet_b}.{octet_a}.1")
    snapshot("after_repeated_lookups")

    for _ in range(args.reloads):
        country_provider = dns_inspector.CsvRangeGeoIPProvider(str(country_csv))
        city_provider = dns_inspector.CsvCityGeoIPProvider(str(city_csv))
    gc.collect()
    dns_inspector._trim_allocator_memory()
    snapshot("after_repeated_reloads")

    print()
    print(f"country provider: {country_provider.range_count} ranges loaded in {country_load_s:.2f}s, "
          f"compact storage = {_compact_storage_bytes(country_provider) / (1024 * 1024):.2f} MiB")
    print(f"city provider:    {city_provider.range_count} ranges loaded in {city_load_s:.2f}s, "
          f"compact storage = {_compact_storage_bytes(city_provider) / (1024 * 1024):.2f} MiB")

    if not args.keep_files:
        for p in (country_csv, city_csv):
            try:
                if not (args.country_csv or args.city_csv):
                    p.unlink(missing_ok=True)
            except OSError:
                pass
    else:
        print(f"\nSynthetic CSVs kept at: {tmp_dir}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
