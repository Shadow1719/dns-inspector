# GeoIP / DNS Destinations map

This document covers the destination map added in 0.8.5.1: what data it is
built from, how the GeoIP lookup works, why no database ships in the
repository by default, and how to supply one. 0.8.5.2 adds the operator
setup guide, conversion utility and end-to-end verification steps below --
the data model and semantics are unchanged from 0.8.5.1. 0.8.6 (Issue #37)
adds an optional, independent coordinate/city provider that powers the
map's Destinations mode -- see
["Destinations mode: optional coordinate/city GeoIP"](#destinations-mode-optional-coordinatecity-geoip)
below; the country-only provider and Countries mode described in the rest of
this document are completely unchanged. 0.8.5.4 (Issue #39) fixes the
default `GEOIP_DB_PATH`/`GEOIP_CITY_DB_PATH` to actually match the `/data`
volume the rest of this document and the README already document (see the
fix note in "Why no database ships by default" below) and adds a `state`
diagnostic field to `/api/analytics/map` and `/api/observability` so an
operator can tell exactly why coverage is zero -- see "Verifying the
provider loaded" and "Verifying map coverage" below.

If you just want to get the map populated, skip to
["Quick setup: DB-IP Country Lite"](#quick-setup-db-ip-country-lite).

## What the map represents

The map aggregates **observed DNS destinations**, not verified physical
server locations: for each DNS query AdGuard actually answered, the
Inspector captures the real A/AAAA answer IP(s) from that query's own
`answer` section and looks up the country each public IP is allocated to.
This is the IP AdGuard's query log says the query received -- not a
separately, asynchronously re-resolved snapshot (see "Why not
`dns_records_cache`" below). CDN, anycast and multi-region services
legitimately resolve to whichever country the answering edge node's IP
happens to be allocated in -- the UI always labels this "observed
destinations", never "server locations", and reports an honest
`% geolocated` coverage figure rather than implying full coverage. Each
destination IP's own observation count drives its country's weight, so a
domain that legitimately answers from more than one country (multi-CDN)
contributes to each of them instead of having its whole query volume
attributed to a single arbitrarily-picked IP.

## Data flow

```text
DNS query (AdGuard query log, already ingested)
    -> that query's own `answer` records (extract_observed_answer_ips())
    -> domain_destination_ips -- bounded per-domain observed-IP counter,
       populated at ingestion time (_record_domain_destination_ips())
    -> normalize_public_ip() -- drop private/loopback/link-local/multicast/
       reserved/unspecified/CGNAT addresses
    -> geoip_lookup() -- local/offline table lookup, cached
    -> aggregated by country in geoip_map_payload()
    -> GET /api/analytics/map
    -> the DNS Destinations widget in Analytics
```

No step in this path makes a network request. GeoIP lookups are always a
local table scan against a CSV file, and destination-IP capture is a plain
read of data AdGuard already returned for that query -- not a new resolution
step, so it adds no blocking work to ingestion.

### Why not `dns_records_cache`?

`dns_records_cache` is populated by `dns_records_lookup()`, which
independently re-resolves a domain's current A/AAAA records via
DNS-over-HTTPS in the background (for the domain detail page). Because it
resolves asynchronously and independently of any specific query, it can
disagree with -- and go stale relative to -- what a given AdGuard query
actually received, especially for CDNs and any DNS load-balancing/rotation.
The map instead reads `domain_destination_ips`, which is filled in directly
from each query's own answer at ingestion time, so it represents genuinely
observed destinations rather than a relabeled independent lookup.

## Why no database ships by default

A destination map is only honest if the underlying IP-to-country data is
actually correct. This release does not bundle a geolocation database because:

- a comprehensive, accurate database (MaxMind GeoLite2-Country, DB-IP
  Country Lite, etc.) is either **licensed** (MaxMind requires a free
  account and a license key, with usage/redistribution terms) or, even when
  more permissively licensed (DB-IP Lite is CC BY 4.0), is tens of megabytes
  and changes monthly -- committing a snapshot to this repository would make
  it stale immediately and bloat the repository for every deployment,
  including ones that never use the map;
- hand-authoring IP ranges from memory would risk exactly the kind of
  invented/incorrect destination data this feature is explicitly required to
  avoid.

Instead, `GeoIPProvider` (in `app.py`) is a small abstraction with two
implementations:

- `NullGeoIPProvider` -- the default when no database file is configured.
  Every lookup is honestly reported as unmapped; the map widget shows a
  clear "No GeoIP database configured" state and `% geolocated` reports 0%.
- `CsvRangeGeoIPProvider` -- loads a CSV database from `GEOIP_DB_PATH` (an
  environment variable, defaulting to `/data/geoip_country_ranges.csv` --
  the same persistent volume `DB_PATH`/`TRACKERDB_PATH`/`NEIGHBORS_PATH`
  already use, see "Container volume path" below) into a sorted, bisected
  range table per address family.

> **0.8.5.4 fix:** before this release, the default was `data/geoip_country_ranges.csv`
> resolved relative to `app.py` (i.e. `/app/data/...` inside the container
> image) -- a directory the Dockerfile never creates and that is not part of
> the `/data` volume the rest of this document and the README tell you to
> mount. An operator who mounted `-v /path/to/data:/data` (as documented) and
> dropped the converted CSV there had it silently ignored: the file existed on
> the host, but the container process was looking somewhere else entirely, so
> `CsvRangeGeoIPProvider` was never even constructed and the map fell back to
> `NullGeoIPProvider` with no error. If you previously worked around this by
> setting `GEOIP_DB_PATH=/data/geoip_country_ranges.csv` explicitly, nothing
> changes for you -- that is now also the default.

Swapping in a different backing source later only requires a new
`GeoIPProvider` subclass; nothing else in the aggregation/API/UI path
depends on the specific provider.

## CSV schema

```text
start_ip,end_ip,country_code,country_name
1.2.3.0,1.2.3.255,US,United States
2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,DE,Germany
```

- One row per contiguous IPv4 or IPv6 range (`start_ip`/`end_ip` inclusive,
  same address family per row).
- `country_code` should be an ISO 3166-1 alpha-2 code; the map's bubble
  placement (`COUNTRY_CENTROIDS` in `app.py`) only covers a bounded set of
  commonly-hosting-relevant countries -- an unmapped code still counts
  toward the aggregate totals/legend, it just has no plotted bubble.
- A header row is tolerated (a first column literally named `start_ip`,
  `start` or `network_start` is skipped).
- Malformed rows are skipped individually; they do not fail the whole load.

## Quick setup: DB-IP Country Lite

This is the recommended, reproducible path. DB-IP Country Lite is free,
requires no account/license key, and is licensed CC BY 4.0 (permissive,
attribution-only -- read the license on the download page for the exact
attribution text DB-IP asks for).

1. **Download.** Go to https://db-ip.com/db/lite.php and download the
   current month's **IP to Country Lite** CSV (the IPv4 and IPv6 files are
   separate downloads; grab both if you want IPv6 coverage). This is a
   manual download from DB-IP's site -- the Inspector itself never fetches
   it, and nothing in the container has a runtime dependency on DB-IP.
   The file ships as `start_ip,end_ip,country_code` rows with no header and
   no country name column, which is close to but not exactly the Inspector's
   schema (see "CSV schema" above).

2. **Convert.** Run the bundled converter to add the missing
   `country_name` column and produce the exact four-column schema
   `CsvRangeGeoIPProvider` expects:

   ```bash
   python scripts/convert_dbip_country_lite.py dbip-country-lite.csv -o geoip_country_ranges.csv
   # or, concatenating separate IPv4 + IPv6 exports:
   cat dbip-country-lite-ipv4.csv dbip-country-lite-ipv6.csv | python scripts/convert_dbip_country_lite.py /dev/stdin -o geoip_country_ranges.csv
   ```

   The converter (`scripts/convert_dbip_country_lite.py`) is a small, offline,
   dependency-free script: it streams the input file row by row (never loads
   the whole file into memory), adds the country name from a bundled ISO
   3166-1 alpha-2 table, skips malformed/header rows individually rather than
   aborting, and makes no network request of its own. Run
   `python scripts/convert_dbip_country_lite.py --help` for full usage.

3. **Place the converted file in your mounted `/data` volume.** The
   Inspector's default `GEOIP_DB_PATH` is `/data/geoip_country_ranges.csv` --
   the exact same host-mounted directory the README's `docker run` example
   already mounts for `DB_PATH`/`TRACKERDB_PATH`/`NEIGHBORS_PATH`
   (`-v /path/to/data:/data`). Copy the converted CSV into that host
   directory as `geoip_country_ranges.csv` and you do not need to set
   `GEOIP_DB_PATH` at all. Only set `GEOIP_DB_PATH` explicitly if you want a
   different filename or a path outside `/data` -- and if you do, note that
   an explicitly-set path that fails to load is now reported as a distinct
   `load_failed` state (see "Verifying the provider loaded" below) rather
   than looking identical to "never configured".

4. **Restart.** `CsvRangeGeoIPProvider` loads the CSV once, at process
   startup (see `_geoip_provider = CsvRangeGeoIPProvider(GEOIP_DB_PATH) ...`
   in `app.py`) -- there is no hot-reload or in-app updater. Restart the
   Inspector container/process after adding or replacing the file.

5. **Verify.** See "Verifying the provider loaded" and "Verifying map
   coverage" below.

## Building a database from another source

MaxMind GeoLite2-Country is a free alternative to DB-IP (requires a free
account + license key; MaxMind's EULA applies -- read the redistribution
terms). It ships as `GeoLite2-Country-Blocks-IPv4.csv` /
`-IPv6.csv` (CIDR + `geoname_id`) plus `GeoLite2-Country-Locations-en.csv`
(`geoname_id` -> country name/code). `scripts/convert_dbip_country_lite.py`
does not support this format (its column layout and CIDR-vs-range shape both
differ from DB-IP's); join the two GeoLite2 files yourself, expand each CIDR
to its first/last address, and write the same four columns
(`start_ip,end_ip,country_code,country_name`) by hand or with your own short
script.

## Destinations mode: optional coordinate/city GeoIP

The map's Countries mode (everything above) only ever needs a country-level
database. 0.8.6 (Issue #37) adds an entirely separate, optional Destinations
mode that plots real observed destination IPs by coordinate -- it needs a
city/coordinate-capable database, configured independently via
`GEOIP_CITY_DB_PATH`.

This is additive, not a replacement: a deployment can have the country
database, the city database, both, or neither configured. The country
provider and Countries mode behave exactly as documented above regardless of
whether a city database is present. If no city database is configured,
Destinations mode says so explicitly in the UI and offers to switch back to
Countries -- it never substitutes a country centroid for a missing
city/IP coordinate, because that would misrepresent approximate country-level
data as a specific location.

### CSV schema

```text
start_ip,end_ip,country_code,country_name,city,latitude,longitude
1.2.3.0,1.2.3.255,US,United States,Mountain View,37.386,-122.0838
2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,DE,Germany,Berlin,52.52,13.405
```

Same range-per-row shape as the country schema, with `city`, `latitude` and
`longitude` appended. A header row (`start_ip`/`start`/`network_start`/
`ip_start` in the first column) is tolerated. Rows with an out-of-range
latitude/longitude (outside -90..90 / -180..180) or an unparsable
coordinate are skipped individually rather than failing the whole load.

### Quick setup: DB-IP City Lite

[DB-IP City Lite](https://db-ip.com/db/lite.php) is the documented source
for this provider -- free, no account/license key, licensed **CC BY 4.0**.
**If you use it, follow the attribution instructions on that download page
in your own deployment's documentation/about page** -- DNS Inspector does
not ship or embed the database, and does not automate that attribution for
you.

1. **Download** the current month's IP to City Lite CSV (IPv4/IPv6 are
   separate downloads). As of the September 2026 release this ships as
   unheadered `ip_start,ip_end,continent,country,stateprov,city,latitude,
   longitude` rows.
2. **Convert** it with the bundled utility, which drops the
   `continent`/`stateprov` columns DNS Inspector doesn't use and reshapes
   the rest into the schema above:

   ```bash
   python scripts/convert_dbip_city_lite.py dbip-city-lite.csv -o geoip_city_ranges.csv
   # or, concatenating separate IPv4 + IPv6 exports:
   cat dbip-city-lite-ipv4.csv dbip-city-lite-ipv6.csv | python scripts/convert_dbip_city_lite.py /dev/stdin -o geoip_city_ranges.csv
   ```

   Like the country converter, this streams the input row by row (never
   loads the whole file into memory), makes no network request of its own,
   and skips malformed/out-of-range/header rows individually.
3. **Place the converted file in your mounted `/data` volume** as
   `geoip_city_ranges.csv` -- the default `GEOIP_CITY_DB_PATH` is
   `/data/geoip_city_ranges.csv`, the same volume as everything above. Only
   set `GEOIP_CITY_DB_PATH` explicitly if you want a different filename or
   location.
4. **Restart** the Inspector -- `CsvCityGeoIPProvider` also loads once, at
   startup; there is no hot-reload.
5. **Verify** via `/api/observability`'s new `geoip_city` field (same shape
   as the existing `geoip` field) or the startup log line
   (`GeoIP city: CsvCityGeoIPProvider loaded <N> ranges ... -- Destinations
   mode available`, or the honest `no coordinate/city database configured`
   line if it didn't load).

### Runtime representation

A real city-level database can have several million IPv4 rows. Rather than
loading that into a plain Python list of per-row tuples/strings,
`CsvCityGeoIPProvider` (`app.py`) stores IPv4 ranges as parallel fixed-width
`array.array` columns (8-byte integer start/end keys, 4-byte float
latitude/longitude) plus small integer indices into interned country/city
string tables -- the actual set of distinct country/city names in a real
database is a few hundred to a few thousand, shared across millions of
rows, not re-allocated per row. IPv6 ranges are far fewer in a real city
export, so they stay a plain sorted list, matching the existing country
provider's approach. Lookup is the same `bisect` binary search the country
provider uses.

### MaxMind for Destinations mode

The same caution from "Building a database from another source" above
applies here: MaxMind GeoLite2-City requires a free account/license key and
its own EULA/redistribution terms. `scripts/convert_dbip_city_lite.py` does
not support MaxMind's CIDR+`geoname_id` join format; build the seven-column
schema above yourself if you choose MaxMind instead of DB-IP.

## Update mechanism

There is no in-app updater. Regenerate the CSV from your chosen source on
whatever cadence you're comfortable with (the underlying allocations change
slowly) and replace the file at `GEOIP_DB_PATH` (and/or `GEOIP_CITY_DB_PATH`),
then restart the container/process -- each provider loads its file once at
startup.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `GEOIP_DB_PATH` | `/data/geoip_country_ranges.csv` | Path to the country CSV database above -- the same `/data` volume as `DB_PATH`. |
| `GEOIP_CACHE_MAX_ENTRIES` | `8192` | Bounded FIFO cache size for per-IP country lookup results. |
| `GEOIP_MAP_CACHE_SECONDS` | `30` | How long an aggregated map payload is reused before recomputing. |
| `GEOIP_MAP_DOMAIN_LIMIT` | `1500` | Upper bound on domains scanned per aggregation pass (most-recently-active first). |
| `GEOIP_DESTINATION_IPS_PER_DOMAIN_LIMIT` | `32` | Upper bound on distinct observed destination IPs retained per domain. |
| `GEOIP_CITY_DB_PATH` | `/data/geoip_city_ranges.csv` | Path to the optional coordinate/city CSV database (Destinations mode) -- same `/data` volume. |
| `GEOIP_CITY_CACHE_MAX_ENTRIES` | `8192` | Bounded FIFO cache size for per-IP city lookup results. |
| `GEOIP_MAP_DESTINATION_POINTS_LIMIT` | `600` | Upper bound on individual coordinate points returned to the browser per map payload (a rendering-size cap only -- `coverage` is always computed over every observed destination regardless of this cap). |

## Verifying the provider loaded

After restarting, check either of these -- both come from the same
provider-status snapshot (`_geoip_diagnostics()` in `app.py`), so they always
agree:

- **Startup log.** The Inspector logs GeoIP status exactly once at startup
  (never per query, so this never spams normal operation logs):
  - configured and loaded: `GeoIP: CsvRangeGeoIPProvider loaded <N> ranges
    from geoip_country_ranges.csv`
  - explicitly configured (`GEOIP_DB_PATH` set) but nothing loaded: `GeoIP:
    GEOIP_DB_PATH is set but no database was loaded from it (missing file,
    unreadable, or empty/malformed CSV) -- ...`
  - never configured (using the default, and no file exists there): `GeoIP:
    no database configured (NullGeoIPProvider) -- the destination map will
    honestly report 0% geolocated until GEOIP_DB_PATH points at a loaded CSV
    database.`

  If you expected the first line and got one of the other two, double-check
  the in-container path `GEOIP_DB_PATH` actually resolves to (not just the
  host path) and that the container process can read it -- see the 0.8.5.4
  fix note above if your volume is mounted at `/data`.

- **`/api/observability`.** The `geoip` field reports the same thing over
  HTTP, so you can check it without container log access:

  ```bash
  curl -s http://<inspector-host>:8080/api/observability | python3 -m json.tool
  ```

  Look for a `geoip` object with `configured: true`, `state: "loaded"`, a
  `range_count` greater than zero, and `provider_type: "CsvRangeGeoIPProvider"`.
  `state` is one of `not_configured` (never set, default path has no file),
  `load_failed` (you set `GEOIP_DB_PATH` explicitly but nothing loaded from
  it) or `loaded`. `db_path_basename` reports only the filename, not the
  full path, so this endpoint doesn't leak host filesystem layout.

## Verifying map coverage

Loading a database only proves the file parsed -- it doesn't prove the map
has anything to show yet, since that also depends on the Inspector having
observed real DNS answers. After generating some traffic (see "End-to-end
smoke test" below), check the aggregation endpoint directly:

```bash
curl -s http://<inspector-host>:8080/api/analytics/map | python3 -m json.tool
```

- `provider.configured` should be `true` and `provider.state` should be
  `full_coverage` (both a country and a city database loaded and matching
  observed traffic) or `country_only` (country database working, no city
  database configured). The other possible `provider.state` values --
  `not_configured`, `load_failed`, `no_public_destinations` (nothing observed
  yet) and `no_country_matches` (traffic observed, but none of it fell inside
  your loaded ranges) -- tell you exactly which link in the chain to look at
  next instead of just one generic empty map.
- `coverage.geolocated_pct` should be greater than `0` once at least one
  observed destination IP falls inside your loaded database's ranges.
- `countries` should be a non-empty list, each with a `country_code`,
  `observation_count` and `sample_domains`.
- `capabilities.country` should be `true`; `capabilities.coordinates` is
  only `true` once a city database is also configured (see "Destinations
  mode" above) -- until then `destinations` is honestly an empty list.

Then open Analytics in the UI -- the DNS Destinations widget should show
country bubbles instead of the "No GeoIP database configured" banner, with
the same `% geolocated` figure the API reports. If you've also configured a
city database, switch the widget to Destinations mode to see individual/
clustered coordinate points instead.

## End-to-end smoke test

This exercises the real data path end-to-end: real DNS queries, through your
normal AdGuard resolver, captured by the Inspector's ingestion, geolocated by
whatever database you configured above.

[`nelsonjchen/cloud-geoip-dns-testing`](https://github.com/nelsonjchen/cloud-geoip-dns-testing)
publishes DNS test domains that intentionally exercise geo-routed answers
(GCP/AWS/Azure Traffic Manager anycast and region-specific endpoints). It is
**not** a GeoIP database and must never be imported into the Inspector as
one -- it is only a source of real-world domains whose answers vary by
resolver location, useful for generating traffic that lands in more than one
country on the map.

1. Make sure your test machine's DNS actually goes through AdGuard (the
   Inspector only ever sees what AdGuard's query log records -- if your
   client bypasses AdGuard, e.g. a browser with DNS-over-HTTPS enabled, the
   Inspector will not see the query at all).

2. Resolve a few of the test domains through your normal resolver path.

   **Windows PowerShell:**

   ```powershell
   Resolve-DnsName test.gcp.geoip-test.mindflakes.com -Type A
   Resolve-DnsName geo-eu-geoip-test.trafficmanager.net -Type A
   Resolve-DnsName geo-na-geoip-test.trafficmanager.net -Type A
   Resolve-DnsName test.eu-geoip-test.aws.geoip-test.mindflakes.com -Type A
   ```

   **Linux/macOS:**

   ```bash
   dig +short test.gcp.geoip-test.mindflakes.com A
   dig +short geo-eu-geoip-test.trafficmanager.net A
   dig +short geo-na-geoip-test.trafficmanager.net A
   dig +short test.eu-geoip-test.aws.geoip-test.mindflakes.com A
   ```

   The project's README documents additional continent-specific variants
   (EU/NA/AS/etc.) if you want broader country coverage for the test.

3. Wait for the Inspector to ingest the new queries (see `POLL_SECONDS`),
   then check `/api/analytics/map` and Analytics as described in "Verifying
   map coverage" above. You should see at least one new country appear, tied
   to the domains you just resolved.

**The exact IP/country each domain returns is not fixed.** These are real
anycast/CDN/traffic-manager endpoints, and DNS geolocation depends on
resolver location and/or EDNS Client Subnet -- the same domain can
legitimately return a different destination IP (and therefore a different
observed country) depending on where your AdGuard resolver sits, which
upstream it uses, and how that upstream's own routing behaves at the moment
of the query. That variability is expected and is exactly what these test
domains are designed to exercise; it does not mean the map is wrong. The map
always reports the destination IP *actually observed in that query's AdGuard
answer* -- never a guess, and never the client's or the Inspector's own
location.
