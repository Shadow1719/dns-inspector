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
this document are completely unchanged. 0.8.5.4 (Issue #39) fixes the actual
root cause of the map staying empty on a real deployment that followed this
document's own container instructions -- `GEOIP_DB_PATH`/`GEOIP_CITY_DB_PATH`
now default under `/data` like every other persistent path instead of an
`/app/data` directory the image never creates -- and adds a six-state
`diagnostics` field to `/api/analytics/map` plus a standalone
`scripts/verify_geoip.py` pre-flight check; see "Verifying with
`scripts/verify_geoip.py`" and "Diagnostic states" below. 0.8.5.5
(Issue #42) adds the automatic monthly updater described in
["Automatic updates"](#automatic-updates) below, which replaces the manual
"Quick setup"/"Update mechanism" steps for an operator who leaves it enabled
-- the manual steps remain accurate for anyone who prefers (or needs, with
`GEOIP_AUTO_UPDATE=false`) to convert and place a database by hand.

0.8.5.x (Issue #63) adds one additive `/api/analytics/map` field, `history`
(`tracked_domains_all_time`, `tracking_since`), computed from an unbounded
`SELECT COUNT(DISTINCT domain), MIN(first_seen) FROM domain_destination_ips`
-- i.e. over the *whole* persistent table, not the `GEOIP_MAP_DOMAIN_LIMIT`-
bounded window the rest of this payload uses. It exists purely so the map
widget can show direct evidence that this observation history already lives
in the same persistent SQLite file as everything else (`DB_PATH`, under
`/data`) and is not reset by an application restart; see
`docs/MAP_BASEMAP.md` for the accompanying frontend basemap work from the
same issue. No other field, lookup semantics, or storage architecture
changed.

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
   python scripts/convert_dbip_country_lite.py dbip-country-lite.csv -o data/geoip_country_ranges.csv
   # or, concatenating separate IPv4 + IPv6 exports:
   cat dbip-country-lite-ipv4.csv dbip-country-lite-ipv6.csv | python scripts/convert_dbip_country_lite.py /dev/stdin -o data/geoip_country_ranges.csv
   ```

   The converter (`scripts/convert_dbip_country_lite.py`) is a small, offline,
   dependency-free script: it streams the input file row by row (never loads
   the whole file into memory), adds the country name from a bundled ISO
   3166-1 alpha-2 table, skips malformed/header rows individually rather than
   aborting, and makes no network request of its own. Run
   `python scripts/convert_dbip_country_lite.py --help` for full usage.

3. **Configure `GEOIP_DB_PATH`.** Point the Inspector at the converted file.
   For a container deployment, this means two things together:
   - mount a host directory containing the converted CSV into the container
     at `/data` -- the same volume the README documents for `DB_PATH`
     (`-v /path/to/data:/data`), so it persists across image upgrades;
   - drop the converted file in as `/data/geoip_country_ranges.csv`. That is
     `GEOIP_DB_PATH`'s default (0.8.5.4), so if you're already using the
     documented single `/data` volume you don't need to set the environment
     variable explicitly at all -- just place the file there. Only set
     `GEOIP_DB_PATH` if you want a different filename/path inside the
     container.

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
DNS Inspector does not ship or embed the database itself, but as of 0.8.5.5
the Settings > About panel and the destination map widget footer both
display the required "IP Geolocation by DB-IP" attribution/link back to
db-ip.com automatically, whether the database was placed manually or by the
automatic updater (see ["Automatic updates"](#automatic-updates) above).
Read DB-IP's own attribution text on the download page if your deployment
has additional documentation of its own that should mention it too.

1. **Download** the current month's IP to City Lite CSV (IPv4/IPv6 are
   separate downloads). As of the September 2026 release this ships as
   unheadered `ip_start,ip_end,continent,country,stateprov,city,latitude,
   longitude` rows.
2. **Convert** it with the bundled utility, which drops the
   `continent`/`stateprov` columns DNS Inspector doesn't use and reshapes
   the rest into the schema above:

   ```bash
   python scripts/convert_dbip_city_lite.py dbip-city-lite.csv -o data/geoip_city_ranges.csv
   # or, concatenating separate IPv4 + IPv6 exports:
   cat dbip-city-lite-ipv4.csv dbip-city-lite-ipv6.csv | python scripts/convert_dbip_city_lite.py /dev/stdin -o data/geoip_city_ranges.csv
   ```

   Like the country converter, this streams the input row by row (never
   loads the whole file into memory), makes no network request of its own,
   and skips malformed/out-of-range/header rows individually.
3. **Configure `GEOIP_CITY_DB_PATH`** to point at the converted file, the
   same way `GEOIP_DB_PATH` is configured above (mount a persistent volume,
   set the env var to the in-container path).
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
rows, not re-allocated per row. `CsvRangeGeoIPProvider` (the country-only
database) uses the same array-column-plus-interned-table representation for
its own (fewer, but still potentially several-million-row) IPv4 ranges. IPv6
ranges are far fewer in a real export for either database, so they stay a
plain sorted list referencing the same interned table. Lookup is the same
`bisect` binary search for both providers.

Both providers' CSV parse loop (`_load()`) streams rows directly into these
compact `array.array` columns as they're read, via a shared
`_CompactRangeTableBuilder` helper, instead of ever buffering the whole
database as a Python list of row tuples first and compacting it only
afterwards (Issue #52). A source file that is already sorted by start IP
(true of a real DB-IP Lite export) needs no extra pass at all; an unsorted
source falls back to one index-permutation pass over the already-compact
columns, never over Python tuples. `scripts/geoip_memory_benchmark.py`
measures peak RSS at each load/lookup/reload stage against a synthetic (or
real) dataset if you want to reproduce these figures for your own database
size.

### MaxMind for Destinations mode

The same caution from "Building a database from another source" above
applies here: MaxMind GeoLite2-City requires a free account/license key and
its own EULA/redistribution terms. `scripts/convert_dbip_city_lite.py` does
not support MaxMind's CIDR+`geoname_id` join format; build the seven-column
schema above yourself if you choose MaxMind instead of DB-IP.

## Automatic updates

**0.8.5.5 (Issue #42):** by default, DNS Inspector now keeps both GeoIP
databases current on its own -- the "Quick setup" steps above are still
correct for a first-time manual conversion, or for a deployment that
disables this and manages the file(s) by hand (`GEOIP_AUTO_UPDATE=false`),
but a default deployment does not need to repeat them every month.

**0.8.5.7 (Issue #44):** the worker previously ran its first check/update
pass immediately when its background thread started, and treated a missing
state file the same as "an update is due" -- so a fresh deployment (empty
`/data`, no `geoip_update_state.json` yet) could start the DB-IP Lite
Country/City Lite download and Python CSV conversion (City Lite is roughly
650MB / ~7.75M rows) at the same time the application was trying to become
healthy. The worker (`geoip_auto_update_worker()` in `app.py`) now never
runs a check/update pass at thread startup: it sleeps until a configured
daily local-time window --

- `GEOIP_AUTO_UPDATE_HOUR` / `GEOIP_AUTO_UPDATE_MINUTE` (default `3:00`)
- `GEOIP_AUTO_UPDATE_TIMEZONE` (default `UTC`; e.g. `Europe/Bucharest`) --
  resolved via the standard library's `zoneinfo`, so it needs an IANA time
  zone database available at runtime. The container image installs the
  `tzdata` PyPI package for this so it doesn't depend on the base image's
  own system tzdata; an unknown/unavailable zone name falls back to UTC with
  a logged warning rather than crashing the worker.

and only then runs a single pass. That pass still independently gates each
database's real network check on `GEOIP_UPDATE_INTERVAL_DAYS` (a cheap local
state-file read, no network) -- the daily wake just controls *when* that
gate is re-evaluated, so first-ever installs simply wait for the next
scheduled window instead of downloading at startup, and the worker never
polls the network hourly to discover nothing is due.

Because a heavy City Lite conversion running inside the same process as
Flask could still compete for the interpreter (the GIL) even from a
background thread, and a thread that hangs cannot actually be killed, the
scheduled pass now runs `scripts/geoip_updater.py` as a **subprocess** --
the same CLI entry point documented below -- rather than calling
`run_update()` in-process. `GEOIP_AUTO_UPDATE_WATCHDOG_SECONDS` (default
1800s) is enforced as a hard deadline on that child process: if it's still
running past the deadline, the parent terminates it (`SIGTERM`, then
`SIGKILL` if it doesn't exit promptly) and records a timeout error for
whichever target never recorded its own outcome -- the Flask process itself
is never at risk of being starved or hung by a stuck decompress/convert.

A failed check (a stale URL template, a transient network error, or simply
no release published yet) is retried at the **next scheduled window**, not
after another full `GEOIP_UPDATE_INTERVAL_DAYS` -- only a check that
actually succeeds, or confirms the current release is still the latest,
resets that cadence. (0.8.5.5/0.8.5.6 had a latent bug here: every check
attempt, including a failed one, reset the 30-day timer, so a single bad
month could silently lock a target out of ever retrying for another 30
days.)

Once awake and due, the child process calls `scripts/geoip_updater.run_update()`,
which:

1. **Checks** whether `GEOIP_UPDATE_INTERVAL_DAYS` (default 30) has elapsed
   since the last non-error check for each database independently -- a
   cheap local read of the persisted state file, no network call.
2. **Discovers** the newest available DB-IP Lite release by probing DB-IP's
   Lite distribution convention with an HTTP `HEAD` (current month, then a
   bounded number of prior months via `GEOIP_UPDATE_LOOKBACK_MONTHS`, in
   case a release is published a few days late). If the current release is
   already the one in use, or nothing resolves, the worker no-ops.
3. **Downloads and validates** the export: a successful HTTP status, a real
   gzip header, an optional checksum (only if you've configured a checksum
   source -- see below; DB-IP's free Lite tier is not confirmed to publish
   one, so this is opt-in rather than assumed) and a minimum converted
   row-count floor all have to pass.
4. **Converts** it with the *exact same* `scripts/convert_dbip_country_lite.py`
   / `convert_dbip_city_lite.py` logic the manual setup above uses -- no
   second, drifting implementation.
5. **Replaces the file atomically.** The download and conversion happen in
   temp files next to the destination; only a final `os.replace()` touches
   `GEOIP_DB_PATH`/`GEOIP_CITY_DB_PATH`, the same download-to-temp-then-
   atomic-rename pattern `refresh_trackerdb()` already uses for TrackerDB.
   A failure at any earlier step leaves the previously working database
   completely untouched -- the map keeps using last month's data rather than
   losing coverage.
6. **Reloads in place.** `_reload_geoip_providers()` reconstructs the
   in-process `GeoIPProvider`/`CityGeoIPProvider` from the file that was
   just written and clears their lookup caches, so the new data is live
   immediately -- no container restart needed.

This all happens outside the request-serving path -- in the worker's own
scheduling thread and, since 0.8.5.7, in a separate child process for the
actual check/download/convert work -- so a multi-hundred-thousand-row City
Lite conversion never blocks DNS ingestion or a browser request, and GeoIP
lookups themselves remain a purely local/offline table scan exactly as
before -- the updater changes *which file* backs that table, never how
lookups happen.

**On the download URL.** The default URL templates
(`GEOIP_UPDATE_COUNTRY_URL_TEMPLATE` / `GEOIP_UPDATE_CITY_URL_TEMPLATE`)
follow DB-IP's long-documented Lite distribution convention
(`https://download.db-ip.com/free/dbip-<product>-lite-<year>-<month>.csv.gz`).
This implementation's build environment had no outbound network access to
re-fetch https://db-ip.com/db/download/ip-to-country-lite /
ip-to-city-lite and confirm the exact current pattern live, so **please
verify it against those pages before relying on unattended updates in
production**, and override the template env var if DB-IP has changed it --
no code change is required. A wrong or stale template is treated exactly
like "no release published this month" (see `no_release_found` in the
diagnostics below): it never corrupts, blocks use of, or silently degrades
the database currently in use, it just means the automatic check keeps
failing safely until the template is corrected.

**Manual one-shot CLI.** `scripts/geoip_updater.py` is the same code path
the background worker uses, runnable by hand:

```bash
python scripts/geoip_updater.py              # one check/update pass, exits
python scripts/geoip_updater.py --force      # re-download even if already current
python scripts/geoip_updater.py --dry-run    # download/validate/convert for real, but
                                              # never replace the active database or
                                              # persist state -- for CI/troubleshooting
python scripts/geoip_updater.py --status     # print persisted state, no network call
python scripts/geoip_updater.py --country-only   # or --city-only
```

It reads the same `GEOIP_*`/`GEOIP_UPDATE_*` environment variables as the
background worker, so a manual run and the automatic one behave identically.

**Diagnostics.** `/api/observability`'s `geoip_update` field reports
`auto_update_enabled`, `interval_days`, a `schedule` object
(`hour`/`minute`/`timezone`), a single `status` value (`disabled` /
`scheduled` -- waiting for its next window -- / `in_progress`), the
in-memory `next_scheduled_run_at` timestamp for the next window, the same
in-memory `in_progress` flag (guaranteed to clear again once a pass
finishes or times out -- it can never sit at `true` forever), and
per-database `current_release`/`last_checked_at`/`last_checked_ok_at`/
`last_success_at`/`last_error`/`last_error_at`/`next_check_at`
(`last_checked_ok_at`, 0.8.5.7, is the timestamp the 30-day cadence
actually gates on -- see above). The worker and CLI also log when a pass is
scheduled, when it actually starts, which target is being processed, and
when it completes, fails or times out.

**Disabling it.** Set `GEOIP_AUTO_UPDATE=false` to fall back entirely to the
manual "Quick setup" workflow above -- the background worker logs that it's
disabled and returns immediately without ever making a network request.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `GEOIP_DB_PATH` | `/data/geoip_country_ranges.csv` | Path to the country CSV database above. |
| `GEOIP_CACHE_MAX_ENTRIES` | `8192` | Bounded FIFO cache size for per-IP country lookup results. |
| `GEOIP_INITIAL_LOAD_DELAY_SECONDS` | `1` | Safety ceiling (seconds) the deferred initial GeoIP provider load will wait for the HTTP server to prove it can actually serve a request before proceeding anyway. As of Issue #51 this is no longer a blind sleep: the load starts as soon as the server serves its first response (any route), and only falls back to waiting out this full ceiling if no request arrives at all. |
| `GEOIP_LOAD_CHUNK_ROWS` | `5000` | Row count per throttled chunk while parsing a GeoIP CSV database (initial load and reload after an auto-update both use this). |
| `GEOIP_LOAD_YIELD_SECONDS` | `0.01` | Sleep inserted after every `GEOIP_LOAD_CHUNK_ROWS` chunk during CSV parsing, so a large database (city-level in particular) doesn't monopolize CPU/disk for the whole load. Set to `0` to disable throttling. |
| `GEOIP_MAP_CACHE_SECONDS` | `30` | How long an aggregated map payload is reused before recomputing. |
| `GEOIP_MAP_DOMAIN_LIMIT` | `1500` | Upper bound on domains scanned per aggregation pass (most-recently-active first). |
| `GEOIP_DESTINATION_IPS_PER_DOMAIN_LIMIT` | `32` | Upper bound on distinct observed destination IPs retained per domain. |
| `GEOIP_CITY_DB_PATH` | `/data/geoip_city_ranges.csv` | Path to the optional coordinate/city CSV database (Destinations mode). |
| `GEOIP_CITY_CACHE_MAX_ENTRIES` | `8192` | Bounded FIFO cache size for per-IP city lookup results. |
| `GEOIP_MAP_DESTINATION_POINTS_LIMIT` | `600` | Upper bound on individual coordinate points returned to the browser per map payload (a rendering-size cap only -- `coverage` is always computed over every observed destination regardless of this cap). |
| `GEOIP_AUTO_UPDATE` | `true` | Enables the automatic monthly updater described above. Set to `false` to manage both files by hand. |
| `GEOIP_UPDATE_INTERVAL_DAYS` | `30` | How often (in days) each database independently checks for a newer release. |
| `GEOIP_UPDATE_LOOKBACK_MONTHS` | `2` | How many prior months to probe if the current month's release hasn't been published yet. |
| `GEOIP_UPDATE_COUNTRY_URL_TEMPLATE` | `https://download.db-ip.com/free/dbip-country-lite-{year:04d}-{month:02d}.csv.gz` | `str.format`-style template for the Country Lite download URL. Verify against DB-IP's download page before relying on it (see above). |
| `GEOIP_UPDATE_CITY_URL_TEMPLATE` | `https://download.db-ip.com/free/dbip-city-lite-{year:04d}-{month:02d}.csv.gz` | Same, for City Lite. |
| `GEOIP_UPDATE_COUNTRY_CHECKSUM_URL_TEMPLATE` | *(empty)* | Optional sidecar checksum URL template (SHA-256, bare digest or `sha256sum` output). Skipped when empty -- structural/row-count validation still applies regardless. |
| `GEOIP_UPDATE_CITY_CHECKSUM_URL_TEMPLATE` | *(empty)* | Same, for City Lite. |
| `GEOIP_UPDATE_MIN_COUNTRY_RANGES` | `10000` | Safety floor: a converted country release with fewer ranges than this is rejected rather than installed. |
| `GEOIP_UPDATE_MIN_CITY_RANGES` | `100000` | Same, for City Lite. |
| `GEOIP_UPDATE_STATE_PATH` | `/data/geoip_update_state.json` | Where the updater persists last-checked/current-release/last-error state per database. |
| `GEOIP_UPDATE_CONNECT_TIMEOUT_SECONDS` / `GEOIP_UPDATE_READ_TIMEOUT_SECONDS` | `10` / `300` | Network timeouts for the updater's own requests. |
| `GEOIP_UPDATE_CHUNK_SIZE` | `1048576` (1 MiB) | Streaming download chunk size. |
| `GEOIP_AUTO_UPDATE_HOUR` | `3` | Hour (0-23, local to `GEOIP_AUTO_UPDATE_TIMEZONE`) of the daily maintenance window. A real check/download only actually happens if `GEOIP_UPDATE_INTERVAL_DAYS` has also elapsed. |
| `GEOIP_AUTO_UPDATE_MINUTE` | `0` | Minute (0-59) of the daily maintenance window. |
| `GEOIP_AUTO_UPDATE_TIMEZONE` | `UTC` | IANA time zone name (e.g. `Europe/Bucharest`) the hour/minute above are local to. An unknown/unavailable name falls back to UTC with a logged warning rather than crashing the worker. |
| `GEOIP_AUTO_UPDATE_WATCHDOG_SECONDS` | `1800` | Hard deadline for one scheduled check/update child process. A child still running past this is terminated (`SIGTERM` then `SIGKILL`) and the pass is recorded as timed out; the parent Flask process is never blocked waiting for it. |

**0.8.5.7 (Issue #44):** replaced `GEOIP_AUTO_UPDATE_POLL_SECONDS` (an hourly
"wake up and re-check whether anything is due" poll, which also ran its
first pass immediately at worker startup) with the daily
`GEOIP_AUTO_UPDATE_HOUR`/`GEOIP_AUTO_UPDATE_MINUTE`/`GEOIP_AUTO_UPDATE_TIMEZONE`
schedule described above -- the worker now only wakes once a day, and never
at process startup.

**0.8.5.4:** `GEOIP_DB_PATH`/`GEOIP_CITY_DB_PATH` used to default under
`BASE_DIR/data/...` (`/app/data/...` inside the container) -- a directory the
Dockerfile never creates and the README's documented `-v host/path:/data`
single-volume mount does not cover. Every other persistent path (`DB_PATH`,
`NEIGHBORS_PATH`, `TRACKERDB_PATH`) already defaulted under `/data`; an
operator who followed the documented single-volume setup and dropped a
converted CSV into their mounted `/data` never had it picked up. The
defaults above now match `/data` like everything else. If you were already
working around this by setting `GEOIP_DB_PATH`/`GEOIP_CITY_DB_PATH`
explicitly to a path under your mounted volume, nothing changes for you.

## Verifying with `scripts/verify_geoip.py`

Before mounting a converted CSV into a container at all, you can check it
loads and produces sane lookups with the bundled, offline, dependency-free
verification script (0.8.5.4):

```bash
python scripts/verify_geoip.py --db data/geoip_country_ranges.csv --city-db data/geoip_city_ranges.csv \
  --ip 8.8.8.8 --ip 2001:4860:4860::8888
```

Run with no arguments and it checks the same paths `GEOIP_DB_PATH`/
`GEOIP_CITY_DB_PATH` default to (or whatever those environment variables are
set to in your shell) against a few well-known public sample IPs. It prints
the loaded range count per address family and the resolved country/city for
each sample IP, and exits non-zero if the country database is missing,
unreadable, or produced zero usable ranges -- suitable as a pre-flight check
in a deployment script, before you ever restart the Inspector container.

## Verifying the provider loaded

After restarting, check either of these -- both come from the same
provider-status snapshot (`_geoip_diagnostics()` in `app.py`), so they always
agree:

- **Startup log.** The Inspector logs GeoIP status exactly once at startup
  (never per query, so this never spams normal operation logs):
  - configured and loaded: `GeoIP: CsvRangeGeoIPProvider loaded <N> ranges
    from geoip_country_ranges.csv`
  - not configured / failed to load: `GeoIP: no database configured
    (NullGeoIPProvider) -- the destination map will honestly report 0%
    geolocated until GEOIP_DB_PATH points at a loaded CSV database.`

  If you expected the first line and got the second, double-check the
  in-container path `GEOIP_DB_PATH` actually resolves to (not just the host
  path) and that the container process can read it.

- **`/api/observability`.** The `geoip` field reports the same thing over
  HTTP, so you can check it without container log access:

  ```bash
  curl -s http://<inspector-host>:8080/api/observability | python3 -m json.tool
  ```

  Look for a `geoip` object with `configured: true`, a `range_count` greater
  than zero, and `provider_type: "CsvRangeGeoIPProvider"`. `db_path_basename`
  reports only the filename, not the full path, so this endpoint doesn't leak
  host filesystem layout.

- **`/api/observability`'s `startup` field** (Issue #51) separates "the
  process is running" from "the HTTP service has proven it can serve a
  request": `http_ready` and `first_response_seconds_after_start` reflect
  the readiness gate described above, and `geoip_initial_load_started`/
  `geoip_initial_load_complete`/`geoip_initial_load_seconds_after_start`/
  `geoip_initial_load_duration_seconds` report when the deferred load
  actually ran relative to that first response. `/health` itself
  deliberately does not expose or depend on any of this -- it stays a
  plain, fast, unconditional 200 so it remains a trustworthy liveness check.

## Verifying map coverage

Loading a database only proves the file parsed -- it doesn't prove the map
has anything to show yet, since that also depends on the Inspector having
observed real DNS answers. After generating some traffic (see "End-to-end
smoke test" below), check the aggregation endpoint directly:

```bash
curl -s http://<inspector-host>:8080/api/analytics/map | python3 -m json.tool
```

- `provider.configured` should be `true`, with `provider.range_count`
  greater than zero (`provider.db_path_basename` reports only the filename,
  never the full configured path -- 0.8.5.4 stopped returning that here).
- `coverage.geolocated_pct` should be greater than `0` once at least one
  observed destination IP falls inside your loaded database's ranges.
- `countries` should be a non-empty list, each with a `country_code`,
  `observation_count` and `sample_domains`.
- `capabilities.country` should be `true`; `capabilities.coordinates` is
  only `true` once a city database is also configured (see "Destinations
  mode" above) -- until then `destinations` is honestly an empty list.
- `diagnostics.state` (0.8.5.4) should read `full_coverage` once both a
  country match and (if a city database is configured) a coordinate match
  exist -- see "Diagnostic states" below for the full list.

Then open Analytics in the UI -- the DNS Destinations widget should show
country bubbles instead of the "No GeoIP database configured" banner, with
the same `% geolocated` figure the API reports. If you've also configured a
city database, switch the widget to Destinations mode to see individual/
clustered coordinate points instead.

## Diagnostic states

`/api/analytics/map`'s `diagnostics` field (0.8.5.4) is a single state
machine that replaces the old configured/not-configured boolean, so an
operator (or the UI banner) can tell these apart without container log
access:

| `diagnostics.state` | Meaning |
| --- | --- |
| `not_configured` | No file exists at `GEOIP_DB_PATH` -- the default `NullGeoIPProvider` is in use. |
| `load_failed` | A file exists at `GEOIP_DB_PATH` but failed to parse into any usable range -- check the CSV schema and file permissions. |
| `no_public_destinations` | The country database loaded, but no observed public destination IPs have been recorded yet. |
| `no_country_matches` | Observed public destination IPs exist, but none matched a range in the loaded database -- check IPv4/IPv6 coverage and that the database is current. |
| `country_only` | Country-level geolocation is working; no city/coordinate database is configured, so Destinations mode is unavailable. |
| `partial_coordinate_coverage` | Country-level geolocation is working and a city database is configured, but it doesn't yet cover the observed destination IPs. |
| `full_coverage` | Both country and coordinate-level geolocation are working. |

`diagnostics.message` is the same human-readable copy the map widget's
banner shows. `diagnostics.country`/`diagnostics.city` are the existing
`_geoip_diagnostics()`/`_geoip_city_diagnostics()` snapshots (provider type,
configured, range count, basename only) already used by
`/api/observability`.

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
