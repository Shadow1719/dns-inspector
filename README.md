# DNS Inspector

**Self-hosted, read-only network visibility and DNS intelligence for AdGuard Home.**

[![Docker](https://img.shields.io/badge/Docker-GHCR-2496ED?logo=docker&logoColor=white)](https://github.com/Shadow1719/dns-inspector/pkgs/container/dns-inspector)
[![GitHub Actions](https://github.com/Shadow1719/dns-inspector/actions/workflows/docker.yml/badge.svg)](https://github.com/Shadow1719/dns-inspector/actions/workflows/docker.yml)
[![Latest release](https://img.shields.io/github/v/release/Shadow1719/dns-inspector?display_name=tag)](https://github.com/Shadow1719/dns-inspector/releases)

> **What is doing what on my network, and what can I reliably tell about the domains my devices contact?**

DNS Inspector observes AdGuard Home traffic, keeps local history, correlates devices and IPs, enriches domains with public intelligence, and turns the result into an investigation-friendly dashboard.

**AdGuard Home remains responsible for DNS resolution and filtering. DNS Inspector does not modify AdGuard policy.**

## What it provides

- DNS query history and request counts
- device/client identity and IP observations
- MAC/OUI vendor information
- domain ownership and infrastructure details
- TrackerDB / Ghostery classification
- Netify application/company context
- RDAP registration signals
- DNS A/AAAA/CNAME/NS/MX/TXT/SOA/CAA/SRV records
- conservative classification, confidence and severity signals
- persistent local enrichment cache
- clickable domain / device / IP investigation views
- Overview, Devices and Analytics dashboards

Unknown is deliberately **not** treated as malicious.

## Architecture

```text
                 AdGuard Home
              DNS + filtering
                    │
                    │ read-only
                    ▼
             ┌───────────────┐
             │ DNS Inspector │
             │               │
             │ ingest worker │
             │ identity      │
             │ enrichment    │
             │ history/cache │
             └───────┬───────┘
                     │
                     ▼
                  SQLite
                     │
             ┌───────┴───────┐
             ▼               ▼
           Web UI         Local cache
```

Browser refreshes read local state. AdGuard Query Log polling is performed by the background worker rather than by every browser request.

## Deployment

Primary target: **TrueNAS SCALE Custom App** using the published GHCR image.

```text
ghcr.io/shadow1719/dns-inspector:stable
```

Container port: `8080`

Typical TrueNAS host port: `8085`

Persistent application data should be mounted at:

```text
/data
```

Example host dataset:

```text
/mnt/Apps/dns-inspector/data
```

### Required environment

```text
AGH_URL=http://<adguard-host>:<port>
AGH_USER=<adguard-user>
AGH_PASS=<adguard-password>
```

Recommended timezone for Romanian deployments:

```text
Europe/Bucharest
```

Do not put credentials into source code, commits, issues or screenshots.

## Optional enrichment sources

DNS Inspector can use public services for metadata enrichment:

| Source | Purpose | Cached locally |
|---|---|---|
| Ghostery / WhoTracks.me TrackerDB | tracker/service classification | Yes |
| Netify | application/company context | Yes |
| RDAP | registration/ownership signals | Yes |
| Google DNS-over-HTTPS | DNS infrastructure records | Yes |
| MAC vendor service | OUI/vendor attribution | Yes |

The application does not send your AdGuard configuration or blocklists to these services.

## Device identity

Identity is intentionally conservative:

1. AdGuard client information when a stable identifier/MAC is available
2. local neighbor observations for IP → MAC correlation
3. IP addresses remain observations rather than permanent device identity

The optional `neighbors.txt` file is generated outside the container and mounted into `/data`.

A MAC vendor identifies the organization associated with a prefix; it does not prove an exact device model.

## Read-only design

DNS Inspector does **not** manage:

- blocklists
- allowlists
- DNS rewrites
- upstream DNS servers
- protection settings
- filtering policy

This separation is intentional: **AdGuard decides; DNS Inspector observes and explains.**

## Performance and caching

External enrichment is cached locally. Inspection serves cached information immediately and refreshes missing/expired metadata in the background.

Default TTLs:

| Source | TTL |
|---|---:|
| Netify | 15 days |
| RDAP | 30 days |
| DNS records | 7 days |
| MAC vendor | 7 days |
| Hostname | 24 hours |
| TrackerDB | 24 hours |

The values can be overridden through environment variables.

## Current release line

The `main` branch currently represents the **0.6.x** line. The next planned release is **0.7.0**, focused on Overview filtering, pagination and large-result usability.

### 0.7.0 prepared changes

The 0.7.0 development build includes:

- All / Allowed / Blocked / Mixed / Unknown status filters
- `<24h` quick filter and NEW markers for recently first-seen domains
- live new-domain notification banner
- classification, severity, device and vendor filters
- configurable page sizes from 10 to 500
- paginated Overview domain table
- server-side filtering/pagination for larger datasets

The 0.7.0 build should be considered **pre-release until deployed and verified**.

## Version history

### 0.6.8

- standardized external lookup controls around the magnifier icon
- added native hover titles / accessibility labels for external lookups
- kept internal navigation distinct from external lookups
- fixed HOST navigation so it opens device details

### 0.6.5

- added Allowed / Blocked / Mixed / Unknown status semantics
- added conservative Info / Low / Medium / High / Unknown severity
- added local favicon and bundled vendor visuals
- added persistent per-domain status counters and latest query reason

### 0.6.1

- added sortable Overview and Devices tables
- improved domain classification using cached TrackerDB, Netify and RDAP evidence
- hardened IP/device/domain navigation

### 0.5.7

- persistent Netify, RDAP and DNS-record enrichment cache
- background refresh for missing/expired enrichment
- removed hardcoded AdGuard URL defaults

Earlier release history is preserved in [`CHANGELOG.md`](CHANGELOG.md).

## Development

Requirements:

- Python 3
- Docker (for container builds)

Local syntax check:

```bash
python -m py_compile app.py
```

Container build:

```bash
docker build -t dns-inspector:dev .
```

The GitHub Actions workflow builds and publishes the container to GHCR. Version tags matching `v*.*.*` also produce GitHub Releases with a source archive.

## Project principles

1. **Read-only integration with AdGuard Home.**
2. **Unknown ≠ malicious.**
3. **Prefer multiple evidence sources over one authoritative guess.**
4. **Cache external intelligence locally.**
5. **Keep stable device identity separate from transient IP observations.**
6. **Keep policy and blocking outside DNS Inspector.**
7. **Prefer useful, explainable intelligence over opaque scores.**

## Roadmap

- **0.7.x** — stabilization, large-result performance and UI filtering
- **0.8.x** — stronger device intelligence and probabilistic identity/type evidence
- **0.9.x** — activity, purpose and historical change detection
- **1.0** — production hardening, retention, migrations, backup/export, authentication and maintenance tooling
- **1.x** — anomaly detection, timelines and network relationship views

## Security

See [`SECURITY.md`](SECURITY.md) for reporting guidance and deployment notes.

## License / third-party data

DNS Inspector is an independent project. External services, datasets, trademarks and logos remain subject to their own terms, licenses and availability.
