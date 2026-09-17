#!/usr/bin/env python3
"""Reproducible memory/latency benchmark for the GeoIP/map pipeline
(Issue #45: real TrueNAS deployment observed ~1.4 GiB RSS after the
GeoIP-backed destination map became populated).

Generates synthetic country/city CSV databases at the same *shape* as a real
DB-IP Lite export (millions of IPv4 ranges, a few hundred/thousand distinct
country/city names shared across them), then measures process RSS at each
stage of the real pipeline: before any GeoIP code runs, after importing
`app.py`, after loading the country provider, after loading the city
provider, after running `geoip_map_payload()` repeatedly, and after dropping
a provider (simulating hot-reload). It also times lookups so a memory fix
can be checked against a latency regression, per the task's own requirement
to benchmark both rather than trade one for the other blindly.

This is a manual diagnostic, not part of the default `pytest` run -- a
multi-million-row synthetic dataset takes real time and memory to generate
and load, which does not belong in every CI run. Run it directly:

    python scripts/geoip_memory_benchmark.py
    python scripts/geoip_memory_benchmark.py --city-rows 6000000 --country-rows 450000
    python scripts/geoip_memory_benchmark.py --disable-memory-diagnostics

Never downloads anything and never touches a real deployment's `/data` --
every path used is a fresh temporary directory.
"""

import argparse
import gc
import ipaddress
import json
import os
import random
import sqlite3
import sys
import tempfile
import time
import weakref
from contextlib import closing
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# A representative (not exhaustive) sample of ISO 3166-1 alpha-2 codes -- real
# DB-IP exports use on the order of ~250 distinct country codes, shared across
# every range row, which is exactly the interning behaviour under test.
_COUNTRIES = [
    "US", "DE", "GB", "FR", "JP", "CN", "BR", "IN", "CA", "AU", "NL", "RU",
    "IT", "ES", "SE", "KR", "MX", "PL", "TR", "ZA", "SG", "AE", "CH", "NO",
]


def _rss_mb():
    """Current resident set size in MB. Prefers `/proc/self/status` (exact,
    live) over `resource.getrusage().ru_maxrss` (peak-only, coarser) since
    this benchmark wants the RSS *at this moment*, including after it drops
    back down -- not just the high-water mark. Falls back to the latter on
    non-Linux."""
    try:
        with open("/proc/self/status", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return round(float(line.split()[1]) / 1024.0, 1)
    except OSError:
        pass
    import resource
    return round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0, 1)


def _report(label, baseline_mb, width=58):
    gc.collect()
    rss = _rss_mb()
    print(f"{label:<{width}} {rss:>10.1f} MB   (delta from baseline {rss - baseline_mb:+.1f} MB)")
    return rss


def _write_synthetic_country_csv(path, rows, seed=1234):
    rng = random.Random(seed)
    start = 1
    with open(path, "w", encoding="utf-8") as f:
        f.write("start_ip,end_ip,country_code,country_name\n")
        for i in range(rows):
            end = start + rng.randint(1, 4096)
            if end >= 2**32 - 1:
                break
            code = _COUNTRIES[i % len(_COUNTRIES)]
            f.write(f"{ipaddress.IPv4Address(start)},{ipaddress.IPv4Address(end)},{code},{code}-Country\n")
            start = end + rng.randint(1, 32)


def _write_synthetic_city_csv(path, rows, seed=5678, city_pool_size=4000):
    rng = random.Random(seed)
    cities = [f"City-{i}" for i in range(city_pool_size)]
    start = 1
    with open(path, "w", encoding="utf-8") as f:
        f.write("start_ip,end_ip,country_code,country_name,city,latitude,longitude\n")
        for i in range(rows):
            end = start + rng.randint(1, 64)
            if end >= 2**32 - 1:
                break
            code = _COUNTRIES[i % len(_COUNTRIES)]
            city = cities[i % len(cities)]
            lat = rng.uniform(-90, 90)
            lon = rng.uniform(-180, 180)
            f.write(
                f"{ipaddress.IPv4Address(start)},{ipaddress.IPv4Address(end)},"
                f"{code},{code}-Country,{city},{lat:.4f},{lon:.4f}\n"
            )
            start = end + rng.randint(1, 32)


def _seed_map_workload(dns_inspector, sample_ips, domain_count=500, ips_per_domain=6):
    """Populate `domains`/`domain_destination_ips` with a small synthetic
    workload so `geoip_map_payload()` (the real aggregation function the map
    widget calls) has something to aggregate over -- exercises the full
    pipeline, not just provider construction."""
    dns_inspector.init_db()
    now = dns_inspector.utcnow()
    rng = random.Random(42)
    with closing(sqlite3.connect(dns_inspector.DB_PATH)) as conn:
        for d in range(domain_count):
            domain = f"benchmark-{d}.example"
            conn.execute(
                "INSERT OR REPLACE INTO domains"
                "(domain,first_seen,last_seen,requests,clients_json,blocked_requests,"
                "allowed_requests,unknown_requests,last_status,current_status)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (domain, now, now, ips_per_domain, json.dumps({}), 0, ips_per_domain, 0, "Allowed", "Allowed"),
            )
            for ip in rng.sample(sample_ips, ips_per_domain):
                conn.execute(
                    "INSERT OR REPLACE INTO domain_destination_ips"
                    "(domain,ip,first_seen,last_seen,observations) VALUES(?,?,?,?,?)",
                    (domain, ip, now, now, rng.randint(1, 50)),
                )
        conn.commit()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--country-rows", type=int, default=400_000,
                         help="Synthetic IPv4 country ranges to generate (default: 400,000, roughly a real DB-IP Country Lite IPv4 export)")
    parser.add_argument("--city-rows", type=int, default=2_000_000,
                         help="Synthetic IPv4 city ranges to generate (default: 2,000,000; a real DB-IP City Lite IPv4 export can be several million -- raise this to match your deployment)")
    parser.add_argument("--lookups", type=int, default=20_000, help="Random lookups to time per provider")
    parser.add_argument("--map-requests", type=int, default=200,
                         help="How many times to call geoip_map_payload() back-to-back, bypassing its cache each time, to check for growth")
    parser.add_argument("--disable-memory-diagnostics", action="store_true",
                         help="Set MEMORY_DIAGNOSTICS_ENABLED=0 before importing app.py, to isolate this always-on tracemalloc "
                              "subsystem's own overhead (docs/GEOIP.md / CHANGELOG 0.7.13-hotfix.1) from the GeoIP providers' own cost")
    parser.add_argument("--keep-files", action="store_true", help="Do not delete the generated synthetic CSVs on exit")
    args = parser.parse_args()

    tmpdir = Path(tempfile.mkdtemp(prefix="geoip-benchmark-"))
    os.environ["DB_PATH"] = str(tmpdir / "inspector.db")
    os.environ["TRACKERDB_PATH"] = str(tmpdir / "trackerdb.sqlite")
    os.environ["NEIGHBORS_PATH"] = str(tmpdir / "neighbors.txt")
    os.environ["AGH_URL"] = ""
    os.environ["AGH_USER"] = ""
    os.environ["AGH_PASS"] = ""
    os.environ["TRACKERDB_URL"] = "http://127.0.0.1:9/trackerdb.sql"
    os.environ["RDAP_URL"] = "http://127.0.0.1:9/domain/"
    os.environ["MACVENDOR_URL"] = "http://127.0.0.1:9"
    os.environ["NETIFY_URL"] = "http://127.0.0.1:9/hostnames/"
    os.environ["GEOIP_AUTO_UPDATE"] = "false"
    os.environ.setdefault("GEOIP_DB_PATH", str(tmpdir / "unused_country.csv"))
    os.environ.setdefault("GEOIP_CITY_DB_PATH", str(tmpdir / "unused_city.csv"))
    if args.disable_memory_diagnostics:
        os.environ["MEMORY_DIAGNOSTICS_ENABLED"] = "0"

    country_csv = tmpdir / "geoip_country_ranges.csv"
    city_csv = tmpdir / "geoip_city_ranges.csv"

    print("GeoIP/map memory benchmark (Issue #45)")
    print(f"MEMORY_DIAGNOSTICS_ENABLED={os.environ.get('MEMORY_DIAGNOSTICS_ENABLED', '1 (default)')}")
    print(f"Generating {args.country_rows:,} synthetic country rows -> {country_csv}")
    _write_synthetic_country_csv(country_csv, args.country_rows)
    print(f"Generating {args.city_rows:,} synthetic city rows -> {city_csv}")
    _write_synthetic_city_csv(city_csv, args.city_rows)

    gc.collect()
    baseline_mb = _rss_mb()
    print()
    print(f"{'stage':<58} {'RSS':>10}")
    print(f"{'baseline (before importing app.py)':<58} {baseline_mb:>10.1f} MB")

    import app as dns_inspector  # noqa: E402  (deliberately imported after env vars are set)

    _report("after importing app.py", baseline_mb)

    t0 = time.perf_counter()
    country_provider = dns_inspector.CsvRangeGeoIPProvider(str(country_csv))
    load_country_s = time.perf_counter() - t0
    _report(f"after loading country provider ({country_provider.range_count:,} ranges, {load_country_s:.2f}s)", baseline_mb)

    t0 = time.perf_counter()
    city_provider = dns_inspector.CsvCityGeoIPProvider(str(city_csv))
    load_city_s = time.perf_counter() - t0
    after_city_mb = _report(f"after loading city provider ({city_provider.range_count:,} ranges, {load_city_s:.2f}s)", baseline_mb)

    # Wire the freshly loaded providers into the module the way
    # `_reload_geoip_providers()` does, then exercise the real request path.
    dns_inspector._geoip_provider = country_provider
    dns_inspector._geoip_city_provider = city_provider
    dns_inspector._geoip_cache.clear()
    dns_inspector._geoip_cache_order.clear()
    dns_inspector._geoip_city_cache.clear()
    dns_inspector._geoip_city_cache_order.clear()

    rng = random.Random(999)
    sample_ips = [str(ipaddress.IPv4Address(rng.randint(1, 2**32 - 2))) for _ in range(args.lookups)]

    t0 = time.perf_counter()
    matched = sum(1 for ip in sample_ips if country_provider.lookup(ip)[0])
    country_lookup_s = time.perf_counter() - t0
    print()
    print(f"{args.lookups:,} random country lookups: {country_lookup_s:.3f}s total, "
          f"{country_lookup_s / args.lookups * 1e6:.2f} us/lookup, {matched:,} matched a range")

    t0 = time.perf_counter()
    matched_city = sum(1 for ip in sample_ips if city_provider.lookup_city(ip))
    city_lookup_s = time.perf_counter() - t0
    print(f"{args.lookups:,} random city lookups: {city_lookup_s:.3f}s total, "
          f"{city_lookup_s / args.lookups * 1e6:.2f} us/lookup, {matched_city:,} matched a range")

    # Full pipeline: seed a synthetic workload and hammer the real
    # geoip_map_payload() aggregation, bypassing its short-TTL cache each
    # time, to check for unbounded growth across repeated map requests.
    _seed_map_workload(dns_inspector, sample_ips)
    print()
    before_map_mb = _rss_mb()
    t0 = time.perf_counter()
    for _ in range(args.map_requests):
        dns_inspector._geoip_map_cache["at"] = 0.0  # force recompute every call
        dns_inspector.geoip_map_payload()
    map_s = time.perf_counter() - t0
    after_map_mb = _report(
        f"after {args.map_requests} uncached geoip_map_payload() calls ({map_s / args.map_requests * 1000:.1f} ms/call)",
        baseline_mb,
    )
    print(f"  (delta across the {args.map_requests} repeated calls themselves: {after_map_mb - before_map_mb:+.1f} MB -- "
          f"should stay small/flat, not grow with call count)")

    # Hot-reload lifecycle: the old provider must not remain resident once
    # nothing references it (see _reload_geoip_providers()).
    old_city_ref = weakref.ref(city_provider)
    del city_provider
    dns_inspector._geoip_city_provider = dns_inspector.NullCityGeoIPProvider()
    gc.collect()
    print()
    _report("after dropping the old city provider + gc.collect()", baseline_mb)
    print(f"  old city provider still referenced anywhere: {old_city_ref() is not None} (must be False)")

    if not args.keep_files:
        try:
            country_csv.unlink()
            city_csv.unlink()
        except OSError:
            pass
    else:
        print(f"\nSynthetic CSVs kept at: {country_csv}, {city_csv}")

    print("\nTo see the effect of this change, run this same script against the pre-fix "
          "and post-fix `app.py` (e.g. `git stash` / `git worktree`) and compare the "
          "\"after loading city provider\" line -- that is the dominant cost this task "
          "measured and reduced.")


if __name__ == "__main__":
    main()
