# DNS Inspector

DNS Inspector is a self-hosted, read-only network visibility and DNS intelligence dashboard built around AdGuard Home.

It was created to answer a simple question:

> **What is doing what on my network, and what can I reliably tell about the domains my devices contact?**

DNS Inspector does **not** replace AdGuard Home in the current architecture. AdGuard Home remains the DNS resolver/filter and the source of query activity. DNS Inspector observes that activity, keeps its own local history, enriches domains and devices with additional intelligence, and presents the result in a human-friendly way.

The project is intentionally designed so that the current AdGuard-backed architecture can later evolve into a standalone DNS/filtering product without throwing away the intelligence, history, cache and UI layers.

## What DNS Inspector does

DNS Inspector continuously imports DNS query activity from AdGuard Home into a local SQLite database and builds a local view of:

- domains contacted by devices;
- request counts and activity history;
- devices/clients and their IP observations;
- stable MAC/client identities when available;
- hostname information;
- MAC/OUI vendor information;
- domain ownership and metadata;
- DNS infrastructure such as A/AAAA/CNAME/NS/MX/TXT/SOA/CAA/SRV data;
- classification and confidence signals;
- evidence explaining why a domain is considered known, telemetry, advertising, ownership-related, or unknown;
- locally cached enrichment so the UI does not wait for external services on every inspection;
- analytics such as most requested domains, most active devices, most active vendors and most active IPs.

It is an **observation and intelligence layer**, not a second blocking engine.

## Current architecture

```text
                    ┌────────────────────┐
                    │    AdGuard Home    │
                    │ DNS + filtering    │
                    │ Query Log          │
                    └─────────┬──────────┘
                              │
                              │ read-only
                              ▼
                    ┌────────────────────┐
                    │   DNS Inspector    │
                    │                    │
                    │ background worker  │
                    │ device discovery   │
                    │ domain intelligence│
                    │ cache / history    │
                    └─────────┬──────────┘
                              │
                              ▼
                         ┌─────────┐
                         │ SQLite  │
                         └────┬────┘
                              │
                    ┌─────────┴─────────┐
                    │                   │
                    ▼                   ▼
                 Web UI            local cache
```

Browser refreshes read the local SQLite state. The AdGuard query log is polled by the background worker, not by every browser refresh.

## Platforms / operating system

The application is built as a **Linux/Docker application**.

The primary deployment target for this project is:

- **TrueNAS SCALE Custom App**;
- Docker-compatible Linux environments.

The container exposes the Flask web application on port `8080` by default. In the user's TrueNAS deployment it is published on host port `8085`.

A future standalone Windows/Android version is possible, but that is a roadmap direction, not a current requirement.

## Dependencies

### Required

**A functioning AdGuard Home installation is currently required.**

DNS Inspector does not currently contain its own DNS resolver/filtering engine. It expects an already-running AdGuard Home instance with an accessible Query Log/API endpoint.

At minimum, the container must be able to reach the configured `AGH_URL` and authenticate with the configured credentials.

### Optional / supporting data sources

DNS Inspector can enrich data from external public sources. These are enrichment sources, not mandatory replacements for AdGuard Home:

- **WhoTracks.me / Ghostery TrackerDB** — tracker/service classification and related metadata;
- **Netify public hostname/application intelligence** — application/company context and secondary ownership evidence;
- **RDAP** — registration/ownership information when available;
- **Google DNS-over-HTTPS** — direct DNS record enrichment for infrastructure details;
- **MAC vendor service** — organization/vendor information for MAC prefixes.

The application caches enrichment locally so these services are not queried on every page refresh.

## How domain enrichment works

When a domain is inspected, DNS Inspector does not blindly trust one source.

It combines multiple signals where available:

```text
Domain
  │
  ├── TrackerDB
  │      └── tracker/category/service information
  │
  ├── Netify
  │      └── application/company context
  │
  ├── RDAP
  │      └── registration/ownership signals
  │
  └── DNS records
         └── A/AAAA/CNAME/NS/MX/TXT/SOA/CAA/SRV
```

The strongest available evidence is shown in the **Who**, **Infrastructure**, and **Why is this here?** sections.

Unknown is intentionally **not** treated as malicious. A domain can be unknown simply because the available public intelligence does not identify it confidently.

## Local enrichment cache

A key performance decision is that external enrichment is cached locally.

The inspection path serves cached data immediately. Missing or expired enrichment is refreshed in the background and stored in SQLite.

Default TTLs:

| Source | Default TTL |
|---|---:|
| Netify | 15 days |
| RDAP | 30 days |
| DNS records | 7 days |
| MAC vendor | 7 days |
| Hostname cache | 24 hours |
| TrackerDB snapshot | 24 hours |

These values can be overridden with environment variables.

This design is deliberate: the first discovery of a new domain can be slower, but subsequent inspections should be fast and should not depend on third-party response time.

## Device identity

Device identity is intentionally conservative.

Preferred stable identity sources are:

1. AdGuard client information when a stable client identifier/MAC is exposed;
2. MAC address discovered through the local neighbor snapshot;
3. IP addresses are kept as **observations**, not permanent device identity.

The optional `neighbors.txt` file is generated outside the container (for example by a TrueNAS scheduled task) and mounted read-only/read-write according to deployment needs.

MAC vendor lookup identifies the organization associated with the MAC prefix. It does **not** prove the exact device model.

## Why the application is read-only

DNS Inspector was intentionally designed so that it does not modify AdGuard Home configuration.

It does not own or change:

- blocklists;
- allowlists;
- DNS rewrites;
- upstream servers;
- protection settings;
- AdGuard filtering policy.

AdGuard remains the component responsible for DNS resolution and filtering in the current architecture. DNS Inspector only observes and explains.

## UI

The dashboard is divided into three tabs:

### Overview

A compact operational view containing:

- live search/Inspect;
- inspected-domain details;
- **At a glance** top domain activity;
- classification and confidence signals.

### Devices

A device-focused view containing:

- device name / hostname;
- vendor and vendor mark;
- stable identity / MAC;
- current and recent IP observations;
- request volume;
- device type and confidence.

### Analytics

A lightweight, dependency-free local analytics view with bar charts for:

- most requested domains;
- most active devices;
- most active vendors;
- most active IP addresses.

The charts are generated in the browser from data returned by DNS Inspector. No external charting CDN is required.

## Installation on TrueNAS SCALE

### 1. Create persistent storage

Create a dataset or directory for DNS Inspector data, for example:

```text
/mnt/Apps/dns-inspector/data
```

Mount it in the container as:

```text
/data
```

This stores the Inspector database and persistent cache data.

### 2. Create a Custom App

Use the Docker/Custom App interface in TrueNAS SCALE.

Recommended image:

```text
ghcr.io/shadow1719/dns-inspector:stable
```

Container port:

```text
8080
```

Example host port:

```text
8085
```

### 3. Configure AdGuard Home

Set:

```text
AGH_URL=http://<adguard-host>:<adguard-port>
AGH_USER=<adguard-user>
AGH_PASS=<adguard-password>
```

Do not put real passwords into source code or public repositories.

### 4. Configure persistent storage

Mount:

```text
/mnt/Apps/dns-inspector/data  ->  /data
```

### 5. Timezone

For Romanian deployments:

```text
Europe/Bucharest
```

### 6. Recommended image policy

Use an always-pull policy when deploying the `stable` tag if you want TrueNAS to retrieve the newest published image on redeploy.

## Docker / manual installation

The project includes a Dockerfile and requirements file.

Build:

```bash
docker build -t dns-inspector .
```

Run:

```bash
docker run -d \
  --name dns-inspector \
  -p 8085:8080 \
  -v /path/to/data:/data \
  -e AGH_URL=http://adguard:3000 \
  -e AGH_USER=... \
  -e AGH_PASS=... \
  ghcr.io/shadow1719/dns-inspector:stable
```

Exact AdGuard URL and port depend on the AdGuard deployment.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `AGH_URL` | none | AdGuard Home URL |
| `AGH_USER` | none | AdGuard authentication username |
| `AGH_PASS` | none | AdGuard authentication password |
| `POLL_SECONDS` | `10` | Background AdGuard poll interval |
| `UI_REFRESH_SECONDS` | `10` | Browser refresh interval |
| `DB_PATH` | `/data/inspector.db` | SQLite database path |
| `TRACKERDB_PATH` | `/data/trackerdb.sqlite` | TrackerDB snapshot path |
| `TRACKERDB_REFRESH_HOURS` | `24` | TrackerDB refresh interval |
| `RDAP_URL` | `https://rdap.org/domain/` | RDAP base URL |
| `NEIGHBORS_PATH` | `/data/neighbors.txt` | Local IP→MAC observation file |
| `MACVENDOR_URL` | `https://api.macvendors.com` | MAC vendor lookup endpoint |
| `MACVENDOR_CACHE_HOURS` | `168` | MAC vendor cache TTL |
| `HOSTNAME_CACHE_HOURS` | `24` | Hostname cache TTL |
| `NETIFY_URL` | `https://www.netify.ai/resources/hostnames/` | Netify public hostname endpoint |
| `NETIFY_CACHE_HOURS` | `360` | Netify cache TTL |
| `RDAP_CACHE_HOURS` | `720` | RDAP cache TTL |
| `DNS_RECORDS_CACHE_HOURS` | `168` | DNS record cache TTL |

## Data and privacy model

DNS Inspector keeps its local operational history in SQLite under `/data`.

External enrichment requests are made only for metadata/enrichment purposes. The application does not send your DNS blocklists or AdGuard configuration to the external intelligence sites listed above.

Because domains and device identities are sensitive network information, the `/data` directory should be treated as private infrastructure data.

## Why this design

The project deliberately separates four jobs:

1. **AdGuard Home** — DNS resolution and filtering;
2. **DNS Inspector ingestion** — importing query activity into local history;
3. **Metadata/enrichment** — explaining what the observed names likely represent;
4. **UI/analytics** — turning that information into something useful for a human.

This prevents the Inspector from becoming a second DNS policy engine and lets the intelligence/history layer evolve independently.

## Roadmap

### Current / 0.6

- three-tab dashboard: Overview, Devices, Analytics;
- local analytics charts;
- persistent enrichment cache;
- read-only AdGuard integration;
- device/IP/domain contextual navigation.

### Planned

- dedicated **Servers** view with Allowed / Blocked / Mixed / Unknown query status derived from AdGuard query results;
- stronger vendor metadata resolver with locally cached vendor websites and logos;
- decoupled source adapters so AdGuard Home is not hardwired into the intelligence core;
- improved read-only AdGuard authentication/integration where supported by the installed AdGuard Home version;
- richer trends and historical analytics;
- eventual standalone DNS/filtering engine research for Windows and Android.

## Version history

### 0.7.2

- keeps device/hostname/vendor enrichment network calls out of the critical SQLite/ingest path;
- hostname reverse-DNS and MAC-vendor lookups are now cache-first and refreshed asynchronously;
- prevents startup reconciliation and continuous ingest from holding the main database lock while waiting on network lookups;
- specifically fixes the symptom where `/health` remained responsive while the dashboard and `/api/state` could stall during device enrichment.

### 0.7.1

- added SQLite compatibility for TrackerDB snapshots using `unistr()` on older SQLite runtimes;
- TrackerDB downloads are streamed instead of being loaded as both bytes and text in memory;
- TrackerDB refresh runs in the background so the web UI is not blocked by metadata refresh.

### 0.7.0
- Overview status filters for All / Allowed / Blocked / Mixed / Unknown.
- New <24h quick filter and NEW markers on recently first-seen domains.
- Live new-domain banner when fresh domains appear between UI refreshes.
- Classification, severity, device, and vendor filters.
- Configurable page size: 10 / 25 / 50 / 100 / 250 / 500.
- Pagination for the Overview domain table.
- Server-side filtering/pagination keeps the UI responsive while allowing larger result sets.

### 0.6.0

- replaced the single long dashboard with three local tabs: **Overview**, **Devices**, **Analytics**;
- added dependency-free analytics bar charts for top domains, devices, vendors and IPs;
- made analytics entries clickable into the existing domain/device/IP views;
- kept the current read-only AdGuard architecture intact;
- prepared the UI structure for future **Servers** and additional analytics views;
- preserved local SQLite/cache behavior from the 0.5.x releases.

### 0.5.12

- added `devices.first_seen` migration/backfill;
- hardened device/vendor navigation paths;
- preserved first/last-seen metadata during legacy IP→MAC reconciliation;
- tightened rendering paths before the 0.6 feature work.

### 0.5.7

- added persistent local enrichment caching for Netify, RDAP and DNS records;
- expired enrichment is refreshed in the background instead of blocking Inspect;
- removed the hardcoded local AdGuard URL default.

## License / third-party data

DNS Inspector is an independent project. External services and datasets used for enrichment are subject to their own terms, licenses and availability.

## v0.6.5

- kept **Classification** and moved it two columns to the right in Overview;
- added **Status** with Allowed / Blocked / Mixed / Unknown semantics derived from AdGuard query-log reasons;
- added **Severity** as a conservative presentation layer: Info / Low / Medium / High / Unknown;
- preserved **Unknown ≠ Malicious**; severity is an interpretation aid, not a blocking verdict;
- added a local browser favicon for DNS Inspector;
- vendor visuals now prefer official vendor favicons downloaded during the GitHub Actions build and bundled locally in the Docker image; existing local SVG marks remain as fallback;
- added persistent per-domain DNS status counters and latest reason with backward-compatible SQLite migration;
- preserved the existing read-only AdGuard architecture.

## v0.6.1

- Click-to-sort headers on Overview and Devices tables (ascending/descending).
- Domain classification now uses cached TrackerDB + Netify + RDAP evidence, so known services no longer remain Unknown when enrichment identifies them.
- Classification keeps conservative semantics: Advertising, Telemetry / tracking, Known service, Known ownership, and Unknown.
- Robust client-side navigation for IP, device and domain links.



### v0.6.5
- Replaces platform-dependent stock emoji device icons with consistent local SVG device-type icons.
- Removes global click interception so native IP/device/domain links navigate normally.
- Keeps IP detail focused on known devices and domains contacted.


## v0.6.8
- External lookup controls consistently use a magnifying-glass icon.
- Native hover titles/ARIA labels explain where each external lookup goes (Netify, DNS records, Google Search, MAC vendor, vendor/device search).
- Internal links consistently open DNS Inspector domain, device, or IP detail views.
- Fixed the HOST link so it opens the device detail view instead of behaving like an IP link.


## v0.6.9
- Standardized all external lookup actions to one visual pattern: magnifier icon + visible label.
- External actions consistently open in a new tab.
- Domain tools use `Netify`, `DNS records`, and `Search`.
- Vendor/device/MAC lookups use the same magnifier-and-label pattern.
- The icon is intentionally centralized so changing it changes every external lookup button.

## v0.6.11
- AdGuard Home current filtering status is checked read-only via `/control/filtering/check_host` and cached locally for 5 minutes.
- Current status is separate from historical query counters, so previously ingested queries no longer remain Unknown forever.
