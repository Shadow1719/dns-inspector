# GeoIP / DNS Destinations map (0.8.5.1)

This document covers the destination map added in 0.8.5.1: what data it is
built from, how the GeoIP lookup works, why no database ships in the
repository by default, and how to supply one.

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
| `GEOIP_DESTINATION_IPS_PER_DOMAIN_LIMIT` | `32` | Upper bound on distinct observed destination IPs retained per domain. |
