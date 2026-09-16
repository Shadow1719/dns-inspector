# GeoIP / DNS Destinations map (0.8.5.1)

This document covers the destination map added in 0.8.5.1: what data it is
built from, how the GeoIP lookup works, why no database ships in the
repository by default, and how to supply one.

## What the map represents

The map aggregates **observed DNS destinations**, not verified physical
server locations: for each domain the Inspector has seen queried, it uses
the domain's already-cached resolved A/AAAA answers and looks up the
country each public IP is allocated to. CDN, anycast and multi-region
services legitimately resolve to whichever country the answering edge node's
IP happens to be allocated in -- the UI always labels this "observed
destinations", never "server locations", and reports an honest
`% geolocated` coverage figure rather than implying full coverage.

## Data flow

```text
DNS query (AdGuard query log, already ingested)
    -> domain (domains.domain / domains.requests / domains.clients_json)
    -> cached A/AAAA answers (dns_records_cache, resolved in the background
       by dns_records_lookup() via DNS-over-HTTPS -- unchanged from 0.8.5,
       just read here instead of only being used for the domain detail page)
    -> normalize_public_ip() -- drop private/loopback/link-local/multicast/
       reserved/unspecified/CGNAT addresses
    -> geoip_lookup() -- local/offline table lookup, cached
    -> aggregated by country in geoip_map_payload()
    -> GET /api/analytics/map
    -> the DNS Destinations widget in Analytics
```

No step in this path makes a network request. GeoIP lookups are always a
local table scan against a CSV file; per-query enrichment already happens in
the existing background worker, not on this path.

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
  environment variable, defaulting to `data/geoip_country_ranges.csv` next
  to `app.py`) into a sorted, bisected range table per address family.

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

## Building a database

Either source below can be converted into the schema above with a short
script (not included, since the exact conversion depends on which source you
use and its current export format):

- **DB-IP Country Lite** (CC BY 4.0, free, monthly CSV releases) --
  https://db-ip.com/db/lite.php. Its CSV is already `start_ip,end_ip,
  country_code` per row; add a `country_name` column (e.g. via a small
  ISO 3166 lookup table) and save it to `GEOIP_DB_PATH`.
- **MaxMind GeoLite2-Country** (free with account + license key, MaxMind
  EULA applies -- read the redistribution terms) -- ships as
  `GeoLite2-Country-Blocks-IPv4.csv` / `-IPv6.csv` (CIDR + `geoname_id`) plus
  `GeoLite2-Country-Locations-en.csv` (`geoname_id` -> country name/code).
  Join the two, expand each CIDR to its first/last address, and write the
  four columns above.

## Update mechanism

There is no in-app updater. Regenerate the CSV from your chosen source on
whatever cadence you're comfortable with (the underlying allocations change
slowly) and replace the file at `GEOIP_DB_PATH`, then restart the
container/process -- the provider loads the file once at startup.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `GEOIP_DB_PATH` | `data/geoip_country_ranges.csv` next to `app.py` | Path to the CSV database above. |
| `GEOIP_CACHE_MAX_ENTRIES` | `8192` | Bounded FIFO cache size for per-IP lookup results. |
| `GEOIP_MAP_CACHE_SECONDS` | `30` | How long an aggregated map payload is reused before recomputing. |
| `GEOIP_MAP_DOMAIN_LIMIT` | `1500` | Upper bound on domains scanned per aggregation pass (most-recently-active first). |
