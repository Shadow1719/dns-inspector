# DNS Inspector

DNS Inspector is a self-hosted, read-only network visibility and DNS intelligence dashboard built around AdGuard Home.

> **What is doing what on my network, and what can I reliably tell about the domains my devices contact?**

AdGuard Home remains the resolver/filter and query source. DNS Inspector imports query activity into local SQLite history, tracks devices, enriches domains with multiple evidence sources, and presents the result through a lightweight web UI.

## Current build: v0.8.0-dev.1

0.8.0 is a **foundation release**. It contains no new features and no intentional
behaviour changes.

This build is tagged `0.8.0-dev.1` and lives on the `dev` branch. The content is
the 0.8.0 foundation exactly as described below; the suffix marks it as
pre-integration. It becomes `0.8.0` when merged to `main`.

Up to 0.7.14, the Docker image was not built from this repository. The Dockerfile
copied sixteen `build_*.py` scripts into the image and ran them at build time,
each rewriting `app.py` through text substitution. The committed source was 2,062
lines; the program that actually ran was 3,173. Around 1,100 lines of live
behaviour existed only inside the image.

0.8.0 removes that arrangement:

- the complete application is now committed source, and the Dockerfile only copies it
- all sixteen patch scripts are deleted
- startup is a named `main()` instead of an inline `__main__` block
- a 55-test suite covers configuration, schema, HTTP surface, startup and status logic
- CI runs the tests before anything is published, and verifies the built container answers `/health`
- the container declares a `HEALTHCHECK`

The only source change between the 0.7.14 runtime program and 0.8.0 is the entry
point restructuring. Every other line is byte-identical.

The design goal remains **observability first, enrichment second**: a new domain should appear immediately even when its public metadata takes time to arrive.

## Architecture

```text
AdGuard Home
  │  read-only query/client/status API
  ▼
DNS Inspector
  ├─ ingest worker
  ├─ device identity / IP history
  ├─ status tracking
  ├─ bounded enrichment worker
  └─ SQLite + local caches
       │
       └── Web UI / Analytics
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the concrete code map, and
[docs/MODULARIZATION.md](docs/MODULARIZATION.md) for the planned module
boundaries and the register of known deferred issues.

## Running

### Docker

```bash
docker build -t dns-inspector --build-arg APP_VERSION="$(cat VERSION)" .

docker run -d \
  --name dns-inspector \
  -p 8080:8080 \
  -v /path/to/data:/data \
  -e AGH_URL=http://adguard.local:3000 \
  -e AGH_USER=admin \
  -e AGH_PASS=secret \
  dns-inspector
```

The dashboard is then on port 8080, and `/health` reports version, AdGuard
target, TrackerDB readiness and the polling intervals.

### Locally

```bash
pip install -r requirements.txt
DB_PATH=./inspector.db TRACKERDB_PATH=./trackerdb.sqlite AGH_URL=http://adguard.local:3000 python app.py
```

## Configuration

All configuration is environment variables, read once at startup.

| Variable | Default | Purpose |
| --- | --- | --- |
| `AGH_URL` | *(empty)* | AdGuard Home base URL. Empty disables ingestion. |
| `AGH_USER` / `AGH_PASS` | *(empty)* | AdGuard credentials |
| `PORT` | `8080` | Listening port |
| `DB_PATH` | `/data/inspector.db` | Main SQLite database |
| `TRACKERDB_PATH` | `/data/trackerdb.sqlite` | Local TrackerDB snapshot |
| `TRACKERDB_URL` | WhoTracks.me snapshot | TrackerDB source |
| `TRACKERDB_REFRESH_HOURS` | `24` | TrackerDB refresh interval |
| `NEIGHBORS_PATH` | `/data/neighbors.txt` | ARP/neighbour table for MAC correlation |
| `POLL_SECONDS` | `10` | Query-log poll interval (minimum 5) |
| `UI_REFRESH_SECONDS` | `10` | Dashboard refresh interval (minimum 5) |
| `RDAP_URL` | `https://rdap.org/domain/` | RDAP endpoint |
| `MACVENDOR_URL` | `https://api.macvendors.com` | MAC vendor lookup |
| `NETIFY_URL` | Netify hostnames | Netify enrichment source |
| `RDAP_CACHE_HOURS` | `720` | RDAP cache TTL |
| `NETIFY_CACHE_HOURS` | `360` | Netify cache TTL |
| `MACVENDOR_CACHE_HOURS` | `168` | MAC vendor cache TTL |
| `DNS_RECORDS_CACHE_HOURS` | `168` | DNS record cache TTL |
| `HOSTNAME_CACHE_HOURS` | `24` | Reverse hostname cache TTL |
| `GEOIP_DB_PATH` | `data/geoip_country_ranges.csv` | Local/offline GeoIP CSV database for the DNS Destinations map. No database ships by default -- see [`docs/GEOIP.md`](docs/GEOIP.md) |
| `GEOIP_CACHE_MAX_ENTRIES` | `8192` | Bounded per-IP GeoIP lookup cache size |
| `GEOIP_MAP_CACHE_SECONDS` | `30` | Server-side cache TTL for the aggregated destination map payload |
| `GEOIP_MAP_DOMAIN_LIMIT` | `1500` | Max domains scanned per map aggregation pass |
| `GEOIP_DESTINATION_IPS_PER_DOMAIN_LIMIT` | `32` | Max distinct observed destination IPs retained per domain |

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

The suite is hermetic: it uses a temporary database, no AdGuard instance and no
outbound network. It runs in about two seconds.

## Endpoints

| Path | Purpose |
| --- | --- |
| `/` | Dashboard |
| `/search` | Domain / device / IP search |
| `/device` | Device detail (`?key=`) |
| `/ip` | IP detail (`?addr=`) |
| `/health` | Health and runtime configuration |
| `/api/state` | Dashboard refresh payload |
| `/api/device/label` | Read/write a manual device label |
| `/api/ip/ping` | Trigger a reachability check |
| `/api/ip/ping/status` | Read cached reachability |
| `/debug/bundle` | Diagnostic bundle download |
| `/api/observability` | Runtime diagnostics — **currently broken**, see D-1 in [docs/MODULARIZATION.md](docs/MODULARIZATION.md) |
