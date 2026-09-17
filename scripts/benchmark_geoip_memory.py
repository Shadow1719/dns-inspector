#!/usr/bin/env python3
"""Reproducible GeoIP/map memory benchmark and diagnostic (Issue #45).

The real DEV deployment reported container RSS climbing from ~210 MB (no
GeoIP loaded) to ~1.4 GiB, then ~2.687 GiB, then ~3.26 GiB across successive
observations, after the destination map's GeoIP-backed data became
populated. This script reproduces the shape of that workload against
*synthetic* country/city CSV databases (no real DB-IP export or network
access required) and reports process RSS and `CsvRangeGeoIPProvider`/
`CsvCityGeoIPProvider`'s own `approx_bytes` accounting at each stage, so the
dominant consumer can be read off directly instead of guessed at:

    1. baseline (module imported, nothing loaded)
    2. after loading the country provider
    3. after loading the city provider
    4. after N repeated `geoip_map_payload()`-shaped aggregation passes
       (simulates repeated Analytics-tab polling)
    5. after M provider hot-reloads (simulates repeated GeoIP auto-updates)

It imports `app.py` directly (safe: server/background-worker startup is
gated behind `if __name__ == "__main__"`) so it always benchmarks the actual
provider implementation, not a reimplementation of it.

Usage:
    python scripts/benchmark_geoip_memory.py                # quick scale
    python scripts/benchmark_geoip_memory.py --scale large   # closer to a
                                                               # real DB-IP
                                                               # Lite export
    python scripts/benchmark_geoip_memory.py --scale large --reloads 3

This is a diagnostic tool, not a pytest test -- it prints a report and exits
0. `tests/test_geoip_memory_lifecycle.py` covers the same lifecycle
behaviors as fast, deterministic assertions.
"""

import argparse
import os
import random
import resource
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SCALES = {
    # (country_ranges, city_v4_ranges, city_v6_ranges)
    "quick": (20_000, 100_000, 5_000),
    "medium": (100_000, 1_000_000, 50_000),
    # Approximate published DB-IP Lite Country/City order-of-magnitude row
    # counts. Slow (tens of seconds) and memory-heavy by design -- this is
    # the scale that actually demonstrates real-deployment behavior.
    "large": (450_000, 4_000_000, 300_000),
}

COUNTRY_POOL = [
    (f"{chr(65 + i // 26)}{chr(65 + i % 26)}", f"Synthetic Country {i}")
    for i in range(50)
]
CITY_POOL = [f"Synthetic City {i}" for i in range(500)]


def _rss_mb():
    """Current process peak RSS in MB. `ru_maxrss` is a monotonic high-water
    mark on Linux (KB), which is exactly what we want here -- it never drops
    on its own, so it shows whether a stage actually raised the process's
    footprint rather than transiently allocating and freeing."""
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0


def _write_country_csv(path, n_ranges, rng):
    cursor = 1  # skip 0.0.0.0
    step = max(1, (2**32 - 2) // n_ranges)
    with open(path, "w", encoding="utf-8", newline="") as f:
        for _ in range(n_ranges):
            start = cursor
            end = min(start + step - 1, 2**32 - 2)
            code, name = rng.choice(COUNTRY_POOL)
            f.write(f"{_int_to_ipv4(start)},{_int_to_ipv4(end)},{code},{name}\n")
            cursor = end + 1
            if cursor >= 2**32 - 2:
                break


def _int_to_ipv4(value):
    return ".".join(str((value >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def _int_to_ipv6(value):
    hextets = [(value >> shift) & 0xFFFF for shift in range(112, -16, -16)]
    return ":".join(f"{h:x}" for h in hextets)


def _write_city_csv(path, n_v4, n_v6, rng):
    with open(path, "w", encoding="utf-8", newline="") as f:
        cursor = 1
        step = max(1, (2**32 - 2) // max(1, n_v4))
        for _ in range(n_v4):
            start = cursor
            end = min(start + step - 1, 2**32 - 2)
            code, name = rng.choice(COUNTRY_POOL)
            city = rng.choice(CITY_POOL)
            lat = rng.uniform(-90, 90)
            lon = rng.uniform(-180, 180)
            f.write(f"{_int_to_ipv4(start)},{_int_to_ipv4(end)},{code},{name},{city},{lat:.4f},{lon:.4f}\n")
            cursor = end + 1
            if cursor >= 2**32 - 2:
                break
        v6_cursor = 0x20010000000000000000000000000000  # 2001:: (documented-range-adjacent, synthetic only)
        v6_step = max(1, (2**32) // max(1, n_v6))
        for _ in range(n_v6):
            start = v6_cursor
            end = start + v6_step - 1
            code, name = rng.choice(COUNTRY_POOL)
            city = rng.choice(CITY_POOL)
            lat = rng.uniform(-90, 90)
            lon = rng.uniform(-180, 180)
            f.write(f"{_int_to_ipv6(start)},{_int_to_ipv6(end)},{code},{name},{city},{lat:.4f},{lon:.4f}\n")
            v6_cursor = end + 1


def _report(label, stage_start_rss, before, app):
    now = _rss_mb()
    country_bytes = app._geoip_provider.approx_bytes / (1024 * 1024)
    city_bytes = app._geoip_city_provider.approx_bytes / (1024 * 1024)
    print(
        f"{label:<38} RSS={now:9.1f} MB  (+{now - before:8.1f} vs baseline, "
        f"{now - stage_start_rss:+7.1f} vs previous stage)  "
        f"country.approx_bytes={country_bytes:8.1f} MB  city.approx_bytes={city_bytes:8.1f} MB"
    )
    return now


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scale", choices=sorted(SCALES), default="quick")
    parser.add_argument("--map-requests", type=int, default=20, help="repeated aggregation passes to simulate polling")
    parser.add_argument("--reloads", type=int, default=2, help="hot-reload cycles to simulate GeoIP auto-updates")
    parser.add_argument("--seed", type=int, default=1337)
    args = parser.parse_args(argv)

    country_n, city_v4_n, city_v6_n = SCALES[args.scale]
    rng = random.Random(args.seed)

    print(f"GeoIP memory benchmark (Issue #45) -- scale={args.scale} "
          f"(country={country_n:,} city_v4={city_v4_n:,} city_v6={city_v6_n:,})\n")

    baseline_rss = _rss_mb()
    print(f"{'baseline (nothing generated yet)':<38} RSS={baseline_rss:9.1f} MB")

    with tempfile.TemporaryDirectory(prefix="geoip-bench-") as tmp:
        country_csv = os.path.join(tmp, "country.csv")
        city_csv = os.path.join(tmp, "city.csv")

        t0 = time.time()
        _write_country_csv(country_csv, country_n, rng)
        _write_city_csv(city_csv, city_v4_n, city_v6_n, rng)
        print(f"{'synthetic CSVs generated':<38} ({time.time() - t0:.1f}s)")

        os.environ.setdefault("MEMORY_DIAGNOSTICS_ENABLED", "0")
        os.environ.setdefault("GEOIP_AUTO_UPDATE", "false")
        import app  # noqa: E402  (deferred: needs env vars set first)

        prev = baseline_rss
        t0 = time.time()
        app._geoip_provider = app.CsvRangeGeoIPProvider(country_csv)
        prev = _report("after loading country provider", prev, baseline_rss, app)
        print(f"  ({time.time() - t0:.1f}s, {app._geoip_provider.range_count:,} ranges loaded)")

        t0 = time.time()
        app._geoip_city_provider = app.CsvCityGeoIPProvider(city_csv)
        prev = _report("after loading city provider", prev, baseline_rss, app)
        print(f"  ({time.time() - t0:.1f}s, {app._geoip_city_provider.range_count:,} ranges loaded)")

        # Simulate repeated Analytics-tab polling: many distinct lookups
        # (bypassing the lookup caches on purpose, worst case) followed by
        # cache-bounded repeats.
        sample_ips = [_int_to_ipv4(rng.randint(1, 2**32 - 2)) for _ in range(2000)]
        t0 = time.time()
        for _ in range(args.map_requests):
            for ip in sample_ips:
                app.geoip_lookup(ip)
                app.geoip_city_lookup(ip)
        prev = _report(f"after {args.map_requests} repeated lookup passes", prev, baseline_rss, app)
        print(f"  ({time.time() - t0:.1f}s, {len(sample_ips):,} IPs x {args.map_requests} passes, cache-bounded)")

        # Point the real reload path at our synthetic files and drive it
        # exactly the way `_run_geoip_update_pass()` does in production, so
        # this exercises `_reload_geoip_providers()` itself (including its
        # cache-clearing and `_release_memory_to_os()` call), not a
        # reimplementation of it.
        app.GEOIP_DB_PATH = country_csv
        app.GEOIP_CITY_DB_PATH = city_csv
        for i in range(args.reloads):
            t0 = time.time()
            app._reload_geoip_providers()
            prev = _report(f"after hot-reload #{i + 1}", prev, baseline_rss, app)
            print(f"  ({time.time() - t0:.1f}s)")

    print(
        "\nIf RSS keeps climbing across reload cycles by roughly one load's "
        "worth each time, that is retained/duplicated provider data (a real "
        "leak). If it climbs once during the first load/reload and then "
        "stays flat across repeated lookups and further reloads, that is "
        "parse-time allocator high-water-mark behavior, not a leak -- see "
        "`_release_memory_to_os()` in app.py."
    )


if __name__ == "__main__":
    main()
