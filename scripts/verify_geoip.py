#!/usr/bin/env python3
"""Verify a DNS Inspector GeoIP database actually loads and resolves IPs.

This is the "does it actually work" companion to
`convert_dbip_country_lite.py` / `convert_dbip_city_lite.py` (Issue #39 /
0.8.5.4): an operator can run this against the exact file/path they intend to
mount into the container *before* restarting the Inspector, to prove the CSV
parses and produces real lookups, rather than discovering after a restart
that `/api/analytics/map` still reports 0% geolocated.

It is a standalone, offline, dependency-free script -- it does not import
`app.py` (so it has no Flask/requests dependency and can run anywhere Python
3 runs) and makes no network request of its own. The range-parsing logic
mirrors `CsvRangeGeoIPProvider`/`CsvCityGeoIPProvider` in `app.py` closely
enough to catch the same malformed rows, but is a plain list + bisect here
since a one-shot CLI check has no need for the running server's
`array.array`-packed representation.

Usage:
    # Check the country database at the same default path/env var the
    # Inspector itself uses (GEOIP_DB_PATH, default /data/geoip_country_ranges.csv):
    python scripts/verify_geoip.py

    # Check specific files and IPs:
    python scripts/verify_geoip.py --db data/geoip_country_ranges.csv --city-db data/geoip_city_ranges.csv --ip 8.8.8.8 --ip 2001:4860:4860::8888

Exit status is non-zero if the country database is missing/unreadable/
produced zero ranges, so this can be used as a pre-flight check in a
deployment script.
"""

import argparse
import bisect
import csv
import ipaddress
import os
import sys

# Same defaults app.py resolves GEOIP_DB_PATH/GEOIP_CITY_DB_PATH to (0.8.5.4:
# corrected to /data, matching DB_PATH/NEIGHBORS_PATH/TRACKERDB_PATH and the
# Dockerfile-created, README-documented single-volume mount).
DEFAULT_COUNTRY_DB = os.getenv("GEOIP_DB_PATH", "/data/geoip_country_ranges.csv")
DEFAULT_CITY_DB = os.getenv("GEOIP_CITY_DB_PATH", "/data/geoip_city_ranges.csv")

# A handful of long-lived, well-known public IPs (Google/Cloudflare public
# DNS) used as default sample lookups when the operator doesn't pass --ip.
# These are just convenient known-public addresses to sanity-check a
# database against -- not something DNS Inspector queries at runtime.
DEFAULT_SAMPLE_IPS = ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"]

_HEADER_FIRST_COLUMNS = ("start_ip", "start", "network_start", "ip_start")


def load_country_ranges(path):
    """Same tolerant parsing as `CsvRangeGeoIPProvider._load()` in app.py:
    skips a header row, skips malformed rows individually, never raises for
    bad data (only for an unreadable file)."""
    v4, v6 = [], []
    with open(path, "r", encoding="utf-8", newline="") as f:
        for row in csv.reader(f):
            if not row or len(row) < 4:
                continue
            start_raw, end_raw = row[0].strip(), row[1].strip()
            if start_raw.lower() in _HEADER_FIRST_COLUMNS:
                continue
            code, name = row[2].strip().upper(), row[3].strip()
            try:
                start_addr = ipaddress.ip_address(start_raw)
                end_addr = ipaddress.ip_address(end_raw)
            except ValueError:
                continue
            if start_addr.version != end_addr.version or not code:
                continue
            bucket = v4 if start_addr.version == 4 else v6
            bucket.append((int(start_addr), int(end_addr), code, name or code))
    v4.sort(key=lambda r: r[0])
    v6.sort(key=lambda r: r[0])
    return v4, v6


def load_city_ranges(path):
    """Same tolerant parsing as `CsvCityGeoIPProvider._load()` in app.py."""
    v4, v6 = [], []
    with open(path, "r", encoding="utf-8", newline="") as f:
        for row in csv.reader(f):
            if not row or len(row) < 7:
                continue
            start_raw, end_raw = row[0].strip(), row[1].strip()
            if start_raw.lower() in _HEADER_FIRST_COLUMNS:
                continue
            code, name, city = row[2].strip().upper(), row[3].strip(), row[4].strip()
            if not code:
                continue
            try:
                start_addr = ipaddress.ip_address(start_raw)
                end_addr = ipaddress.ip_address(end_raw)
                lat, lon = float(row[5]), float(row[6])
            except ValueError:
                continue
            if start_addr.version != end_addr.version:
                continue
            if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
                continue
            bucket = v4 if start_addr.version == 4 else v6
            bucket.append((int(start_addr), int(end_addr), code, name or code, city, lat, lon))
    v4.sort(key=lambda r: r[0])
    v6.sort(key=lambda r: r[0])
    return v4, v6


def lookup_range(v4, v6, ip):
    addr = ipaddress.ip_address(ip)
    bucket = v4 if addr.version == 4 else v6
    if not bucket:
        return None
    starts = [r[0] for r in bucket]
    value = int(addr)
    idx = bisect.bisect_right(starts, value) - 1
    if idx < 0:
        return None
    row = bucket[idx]
    start, end = row[0], row[1]
    if start <= value <= end:
        return row
    return None


def check_country_db(path, ips):
    print(f"Country database: {path}")
    if not os.path.exists(path):
        print("  NOT FOUND -- the Inspector falls back to NullGeoIPProvider and honestly")
        print("  reports 0% geolocated until a file exists at this path. See docs/GEOIP.md.")
        return False
    try:
        v4, v6 = load_country_ranges(path)
    except OSError as e:
        print(f"  FAILED TO READ: {e}")
        return False
    total = len(v4) + len(v6)
    if total == 0:
        print("  loaded the file but found zero usable ranges -- check the CSV schema")
        print("  (start_ip,end_ip,country_code,country_name) and that rows aren't all malformed.")
        return False
    print(f"  loaded {total} ranges ({len(v4)} IPv4, {len(v6)} IPv6)")
    for ip in ips:
        try:
            hit = lookup_range(v4, v6, ip)
        except ValueError:
            print(f"  {ip}: not a valid IP address, skipped")
            continue
        if hit:
            print(f"  {ip}: {hit[3]} ({hit[2]})")
        else:
            print(f"  {ip}: unmapped (outside every loaded range)")
    return True


def check_city_db(path, ips):
    print(f"City/coordinate database: {path}")
    if not os.path.exists(path):
        print("  not configured -- Destinations mode will report coordinate-level data as")
        print("  unavailable until a file exists at this path. This is optional; Countries")
        print("  mode does not need it. See docs/GEOIP.md.")
        return
    try:
        v4, v6 = load_city_ranges(path)
    except OSError as e:
        print(f"  FAILED TO READ: {e}")
        return
    total = len(v4) + len(v6)
    if total == 0:
        print("  loaded the file but found zero usable ranges -- check the seven-column")
        print("  schema (start_ip,end_ip,country_code,country_name,city,latitude,longitude).")
        return
    print(f"  loaded {total} ranges ({len(v4)} IPv4, {len(v6)} IPv6)")
    for ip in ips:
        try:
            hit = lookup_range(v4, v6, ip)
        except ValueError:
            print(f"  {ip}: not a valid IP address, skipped")
            continue
        if hit:
            _, _, code, name, city, lat, lon = hit
            where = f"{city}, {name}" if city else name
            print(f"  {ip}: {where} ({code}) @ {lat},{lon}")
        else:
            print(f"  {ip}: unmapped (outside every loaded range)")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db", default=DEFAULT_COUNTRY_DB, help="Country CSV database path (default: %(default)s)")
    parser.add_argument("--city-db", default=DEFAULT_CITY_DB, help="City/coordinate CSV database path (default: %(default)s)")
    parser.add_argument("--ip", action="append", dest="ips", help="Sample IP to look up (repeatable). Default: a few well-known public IPs.")
    args = parser.parse_args(argv)
    ips = args.ips or DEFAULT_SAMPLE_IPS

    country_ok = check_country_db(args.db, ips)
    print()
    check_city_db(args.city_db, ips)
    return 0 if country_ok else 1


if __name__ == "__main__":
    sys.exit(main())
