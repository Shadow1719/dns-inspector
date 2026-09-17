#!/usr/bin/env python3
"""Convert a DB-IP City Lite CSV export into DNS Inspector's coordinate/city
GeoIP schema (Issue #37 / 0.8.6).

DB-IP City Lite (https://db-ip.com/db/lite.php, CC BY 4.0, monthly releases)
ships unheadered rows shaped

    ip_start,ip_end,continent,country,stateprov,city,latitude,longitude

`CsvCityGeoIPProvider` (see `app.py` and `docs/GEOIP.md`) expects seven
columns:

    start_ip,end_ip,country_code,country_name,city,latitude,longitude

This script drops the `continent`/`stateprov` columns DNS Inspector doesn't
use, adds a full country name from the same bundled ISO 3166-1 alpha-2 table
`convert_dbip_country_lite.py` uses (so the two converters stay consistent),
and validates latitude/longitude are in range. It does not download
anything, make any network request, or depend on the `db-ip` package/service
at runtime -- it is a one-shot, offline conversion you run yourself against a
file you already downloaded.

Attribution: DB-IP City Lite is licensed CC BY 4.0. If you use it, follow the
attribution instructions on its download page
(https://db-ip.com/db/lite.php) in your deployment's documentation/about
page -- DNS Inspector itself does not ship or embed the database, so no
attribution is bundled automatically.

Usage:
    python scripts/convert_dbip_city_lite.py dbip-city-lite.csv -o data/geoip_city_ranges.csv
    python scripts/convert_dbip_city_lite.py dbip-city-lite.csv > data/geoip_city_ranges.csv

Rows are processed one at a time (a streaming `csv.reader` over the input
file, not a full read into memory), so the conversion stays bounded against
DB-IP's full multi-million-row city export. Malformed rows (wrong column
count, unparsable IP/coordinates, mismatched address family, out-of-range
latitude/longitude) and a header row (if present) are skipped individually
rather than aborting the conversion.
"""

import argparse
import csv
import ipaddress
import sys

try:
    from scripts.convert_dbip_country_lite import ISO_COUNTRY_NAMES
except ImportError:  # running as a standalone script, not as part of the `scripts` package
    from convert_dbip_country_lite import ISO_COUNTRY_NAMES

# First-column values that mean "this is a header row, not data".
_HEADER_FIRST_COLUMNS = {"start_ip", "start", "network_start", "ip_start"}


def convert_row(row):
    """Convert one raw `ip_start,ip_end,continent,country,stateprov,city,
    latitude,longitude` row into a `[start_ip, end_ip, country_code,
    country_name, city, latitude, longitude]` row, or return `None` if the
    row is empty, a header, or malformed and should be skipped."""
    if not row or len(row) < 8:
        return None
    start_raw, end_raw = row[0].strip(), row[1].strip()
    if start_raw.lower() in _HEADER_FIRST_COLUMNS:
        return None
    code = row[3].strip().upper()
    city = row[5].strip()
    lat_raw, lon_raw = row[6].strip(), row[7].strip()
    if not code:
        return None
    try:
        start_addr = ipaddress.ip_address(start_raw)
        end_addr = ipaddress.ip_address(end_raw)
    except ValueError:
        return None
    if start_addr.version != end_addr.version:
        return None
    try:
        lat = float(lat_raw)
        lon = float(lon_raw)
    except ValueError:
        return None
    if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
        return None
    return [
        str(start_addr), str(end_addr), code, ISO_COUNTRY_NAMES.get(code, code),
        city, repr(lat), repr(lon),
    ]


def convert(rows):
    """Yield converted schema rows from an iterable of raw input rows.

    A generator over the (already lazily-iterated) `csv.reader` input, so a
    caller streaming from a file never holds more than one row in memory at
    a time.
    """
    for row in rows:
        converted = convert_row(row)
        if converted is not None:
            yield converted


def run(input_path, output_path=None):
    """Convert `input_path` to `output_path` (or write to stdout when
    `output_path` is None). Returns the number of rows written."""
    out_file = open(output_path, "w", encoding="utf-8", newline="") if output_path else sys.stdout
    count = 0
    try:
        writer = csv.writer(out_file)
        with open(input_path, "r", encoding="utf-8", newline="") as in_file:
            for converted in convert(csv.reader(in_file)):
                writer.writerow(converted)
                count += 1
    finally:
        if output_path:
            out_file.close()
    return count


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "Convert a DB-IP City Lite CSV (ip_start,ip_end,continent,country,"
            "stateprov,city,latitude,longitude) into DNS Inspector's seven-"
            "column coordinate/city GeoIP schema (start_ip,end_ip,country_code,"
            "country_name,city,latitude,longitude). Makes no network requests; "
            "only reads the input file you already downloaded. DB-IP City Lite "
            "is CC BY 4.0 -- see https://db-ip.com/db/lite.php for the required "
            "attribution text if you use it."
        ),
    )
    parser.add_argument(
        "input",
        help="Path to a DB-IP City Lite CSV export (IPv4, IPv6, or a concatenation of both).",
    )
    parser.add_argument(
        "-o", "--output",
        help="Path to write the converted CSV to. Defaults to stdout.",
    )
    args = parser.parse_args(argv)

    count = run(args.input, args.output)
    destination = args.output or "stdout"
    print(f"Converted {count} range(s) to {destination}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
