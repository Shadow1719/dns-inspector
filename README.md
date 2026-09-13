# DNS Inspector

DNS Inspector is a self-hosted, read-only network visibility and DNS intelligence dashboard built around AdGuard Home.

> **What is doing what on my network, and what can I reliably tell about the domains my devices contact?**

AdGuard Home remains the resolver/filter and query source. DNS Inspector imports query activity into local SQLite history, tracks devices, enriches domains with multiple evidence sources, and presents the result through a lightweight web UI.

## Current release: v0.7.8

The current release is focused on long-running stability and bounded background work:

- one cancellable browser refresh loop;
- no permanent polling timers left behind by filter/page interactions;
- serialized domain enrichment using one background worker;
- enrichment queue capped at 500 domains and de-duplicated;
- TTL checked again immediately before an enrichment job runs;
- Netify cache: 180 days;
- RDAP cache: 30 days;
- DNS-record cache: 10 days;
- configurable delay between enrichment jobs, default 1 second;
- UI requests never wait for slow external enrichment;
- bounded AdGuard current-status refresh workers, with a hard cap of 20 pending/running jobs.

The design goal is **observability first, enrichment second**: a new domain should appear immediately even when its public metadata takes time to arrive.

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

Slow public lookups are deliberately outside the UI request path.

## What it tracks

- domains and request counts;
- first/last seen activity;
- historical Allowed / Blocked / Unknown counters;
- current AdGuard filtering status;
- device/client identities;
- MAC addresses and DHCP/IP observations;
- hostnames;
- MAC/OUI vendor information;
- device type and confidence hints;
- TrackerDB classification;
- Netify application/company context;
- RDAP ownership/registration data;
- DNS infrastructure: A/AAAA/CNAME/NS/MX/TXT/SOA/CAA/SRV;
- evidence for **Why is this here?**;
- locally cached enrichment;
- analytics for domains, devices, vendors and IPs.

## Read-only by design

DNS Inspector does not modify AdGuard Home policy. It does not manage blocklists, allowlists, rewrites, upstream servers, protection settings, or filtering rules.

## Domain intelligence

The inspector combines multiple evidence sources rather than treating one source as authoritative:

```text
Domain
 ├─ TrackerDB      → tracker/category/service metadata
 ├─ Netify         → application/company context
 ├─ RDAP           → ownership/registration signals
 └─ DNS-over-HTTPS → DNS infrastructure
```

**Unknown does not mean malicious.** Classification and severity are explanatory aids, not blocking verdicts.

## Enrichment/cache model

Existing metadata is reused until its TTL expires. Missing or expired data is queued for background enrichment.

| Source | Default TTL | Purpose |
|---|---:|---|
| Netify | 180 days | Long-lived application/company metadata |
| RDAP | 30 days | Domain ownership/registration |
| DNS records | 10 days | Infrastructure details |
| MAC vendor | 168 hours | OUI/organization information |
| Hostname cache | 24 hours | Device observations |
| TrackerDB snapshot | 24 hours | Classification snapshot |

A failed refresh does not intentionally replace good cached information with an empty result.

### Enrichment queue

- maximum 500 pending domains;
- duplicate domains are not queued more than once;
- exactly one worker drains the queue;
- TTLs are rechecked before a request is made;
- jobs are delayed slightly to avoid bursts;
- UI requests never wait for the queue.

## Device identity

Identity prefers stable identifiers over DHCP addresses:

1. AdGuard stable client identifier/MAC;
2. MAC learned from the local neighbor snapshot;
3. stable non-IP client identifier;
4. hostname/name;
5. bare IP only as a last resort.

IPs are observations, not permanent identity. Historical IPs can therefore follow a MAC across DHCP changes.

Hostnames are observations. Planned manual device labels will be tied to stable device identity, primarily MAC, so a DHCP change will not lose a user-assigned label.

## UI

### Overview

- live domain inspection;
- All / Allowed / Blocked / Mixed / Unknown filters;
- NEW / <24h filtering;
- live new-domain banner with per-domain status;
- classification and severity;
- device and vendor filters;
- configurable page size and server-side pagination;
- clickable domains, devices and IPs.

### Devices

- stable identity, hostname and vendor;
- MAC address and IP history;
- request volume;
- device type and confidence;
- device/IP/domain navigation;
- external MAC/vendor lookups.

### Analytics

Dependency-free browser charts for top domains, devices, vendors and IPs.

## External sources

- WhoTracks.me / Ghostery TrackerDB;
- Netify public hostname/application pages;
- RDAP;
- Google DNS-over-HTTPS;
- MAC vendor service.

These services provide metadata only; they are not part of AdGuard filtering policy.

## Deployment

Primary target: **TrueNAS SCALE Custom App** and Docker-compatible Linux systems.

Default container port:

```text
8080
```

Example host mapping:

```text
8085 -> 8080
```

Recommended image:

```text
ghcr.io/shadow1719/dns-inspector:stable
```

Persist `/data`, for example:

```text
/mnt/Apps/dns-inspector/data -> /data
```

## AdGuard Home

```text
AGH_URL=http://<adguard-host>:<adguard-port>
AGH_USER=<adguard-user>
AGH_PASS=<adguard-password>
```

Do not store real credentials in source control.

Recommended timezone for Romanian deployments:

```text
Europe/Bucharest
```

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `AGH_URL` | none | AdGuard Home URL |
| `AGH_USER` | none | AdGuard username |
| `AGH_PASS` | none | AdGuard password |
| `POLL_SECONDS` | `10` | AdGuard ingestion interval |
| `UI_REFRESH_SECONDS` | `10` | Browser refresh interval |
| `DB_PATH` | `/data/inspector.db` | Main SQLite database |
| `TRACKERDB_PATH` | `/data/trackerdb.sqlite` | TrackerDB snapshot |
| `TRACKERDB_REFRESH_HOURS` | `24` | TrackerDB refresh interval |
| `RDAP_URL` | `https://rdap.org/domain/` | RDAP endpoint |
| `RDAP_CACHE_HOURS` | `720` | RDAP TTL, 30 days |
| `NETIFY_URL` | `https://www.netify.ai/resources/hostnames/` | Netify endpoint |
| `NETIFY_CACHE_HOURS` | `4320` | Netify TTL, 180 days |
| `DNS_RECORDS_CACHE_HOURS` | `240` | DNS record TTL, 10 days |
| `MACVENDOR_URL` | `https://api.macvendors.com` | MAC vendor endpoint |
| `MACVENDOR_CACHE_HOURS` | `168` | MAC vendor TTL |
| `HOSTNAME_CACHE_HOURS` | `24` | Hostname cache TTL |
| `NEIGHBORS_PATH` | `/data/neighbors.txt` | IP→MAC snapshot |
| `ENRICHMENT_DELAY_SECONDS` | `1.0` | Delay between enrichment jobs |

## Privacy / remote access

The `/data` directory contains sensitive network history and device identity information.

For remote access, use an authenticated reverse proxy or **Cloudflare Access + Cloudflare Tunnel** rather than exposing the container directly to the Internet.

## Build and release

GitHub Actions builds the Docker image with Buildx, bundles local vendor favicons, publishes to GHCR, and creates source archives/releases for version tags.

The Docker build applies the current runtime/performance patches at image-build time.

---

# Complete version history

### v0.7.8 — current

**Memory, polling and enrichment architecture**

- one cancellable UI refresh timer;
- in-flight refresh guard to prevent overlap;
- one bounded background enrichment worker;
- 500-domain enrichment queue with de-duplication;
- TTL re-check immediately before external enrichment;
- Netify 180d / RDAP 30d / DNS 10d defaults;
- configurable delay between enrichment jobs;
- UI never waits on enrichment;
- bounded AdGuard status workers, capped at 20 jobs.

### v0.7.7

**Overview performance**

- SQL-level Allowed / Blocked / Mixed / NEW filtering;
- SQL-level pagination for simple filters;
- enrichment limited to displayed rows;
- bounded AdGuard status worker pool;
- de-duplicated status refreshes;
- hard cap of 20 pending/running status jobs.

### v0.7.6

**Lookup/UI polish**

- stable Vendor lookup alignment;
- stable MAC lookup alignment;
- new-domain banner domain names remain clickable.

### v0.7.5

**New-domain banner**

- per-domain Allowed / Blocked / Mixed / Unknown status pills;
- clickable new-domain names.

### v0.7.4

**Device enrichment scheduling restored**

- cache-first hostname/MAC vendor handling;
- network lookups removed from the critical SQLite/ingest path;
- missing device metadata refreshed asynchronously;
- device enrichment de-duplicated by device key.

### v0.7.3

**Device enrichment simplification**

- simplified hostname/MAC-vendor lookup flow;
- removed the previous background device-enrichment scheduler;
- kept cached information available while direct lookups were used where needed;
- removed an unnecessary TrackerDB commit during snapshot replacement.

This approach was superseded by v0.7.4 because slow network work did not belong in the ingest path.

### v0.7.2

**Ingest/API responsiveness**

- cache-first hostname and MAC-vendor enrichment;
- network lookups no longer hold the main database lock;
- missing device metadata refreshed asynchronously;
- fixed stalls where `/health` remained responsive while dashboard/API calls could block during enrichment.

### v0.7.1

**TrackerDB compatibility and memory**

- SQLite `unistr()` compatibility for older runtimes;
- streamed TrackerDB downloads;
- background TrackerDB refresh.

### v0.7.0

**Overview filtering milestone**

- All / Allowed / Blocked / Mixed / Unknown;
- <24h / NEW filter and markers;
- live new-domain banner;
- classification, severity, device and vendor filters;
- page sizes 10–500;
- server-side pagination/filtering.

### v0.6.11

**Current AdGuard status**

- read-only `filtering/check_host` integration;
- current status cached for 5 minutes;
- current status kept separate from historical counters.

### v0.6.10

No separate surviving version bump was found in the `VERSION` history; surrounding work was folded into adjacent 0.6.x revisions.

### v0.6.9

**External lookup standardization**

- magnifier + label pattern for external lookups;
- new-tab behavior;
- standardized Netify, DNS records, Search, vendor, device and MAC tools;
- centralized lookup presentation.

### v0.6.8

**Navigation semantics**

- standardized lookup icons;
- hover titles and ARIA labels;
- internal vs external navigation separation;
- HOST links fixed to device detail views.

### v0.6.7

**Vendor/status/UI fixes**

- restored vendor logos;
- backfilled previously missing query status;
- aligned Overview columns.

### v0.6.6

**Detail navigation and vendor favicons**

- repaired detail navigation;
- switched supported vendor visuals to official favicons bundled during the build;
- kept local fallback marks.

### v0.6.5

**Status, severity and local visuals**

- Allowed / Blocked / Mixed / Unknown semantics;
- Severity: Info / Low / Medium / High / Unknown;
- Unknown kept distinct from maliciousness;
- local favicon;
- bundled vendor visuals;
- persistent domain status counters and latest reason;
- local SVG device-type icons;
- native IP/device/domain navigation restored.

### v0.6.4

**Query status and severity milestone**

- introduced status derived from AdGuard query reasons;
- introduced severity presentation;
- added local vendor favicon support.

### v0.6.3

**Local favicon polish**

- local DNS Inspector favicon;
- favicon assets kept inside the Docker image;
- dashboard presentation polish.

### v0.6.2

**Vendor metadata/cache**

- automatic vendor metadata;
- local vendor/logo cache;
- continued removal of runtime external asset dependencies.

### v0.6.1

**Sorting and classification**

- sortable Overview/Devices tables;
- stronger TrackerDB + Netify + RDAP classification;
- conservative classification categories;
- hardened navigation.

### v0.6.0

**Three-tab dashboard**

- Overview, Devices and Analytics tabs;
- local analytics charts;
- clickable analytics entries;
- established the UI foundation used by later releases.

### v0.5.12

**Maintenance / identity stabilization**

- `devices.first_seen` migration/backfill;
- tightened device/vendor navigation;
- preserved first/last-seen metadata during legacy IP→MAC reconciliation;
- stabilization milestone before 0.6.

### v0.5.11

No separate surviving version bump was found in the `VERSION` history.

### v0.5.10

**Lookup helper hotfix**

- corrected external lookup helper usage;
- compact magnifier controls in domain/vendor/MAC/device views;
- internal and external navigation kept separate.

### v0.5.9

**Device/IP reconciliation hotfix**

- added client display helper;
- fixed legacy IP→MAC merging without violating `(device_key, ip)` uniqueness;
- preserved historical IP observations.

### v0.5.8

**Hotfix**

- restored omitted `classify()` / device helpers;
- fixed dashboard/Inspect `NameError` and HTTP 500 failures;
- removed duplicate RDAP refresh.

### v0.5.7

**Persistent enrichment**

- persistent Netify/RDAP/DNS caches;
- background refresh of expired enrichment;
- removed hardcoded local AdGuard URL default.

### v0.5.6

**Domain intelligence expansion**

- Netify public hostname/application evidence;
- DNS-over-HTTPS A/AAAA/CNAME/NS/MX/TXT/SOA/CAA/SRV enrichment;
- RDAP apex-domain fallback;
- RDAP organization/country/registrar fields;
- DNSChecker kept as an external verification link;
- explicit external vendor/MAC lookup controls.

### v0.5.5

**Domain “Who” enrichment**

- Netify used as secondary ownership evidence;
- local Netify cache;
- vendor lookup controls beside vendor names;
- clearer separation between internal navigation and external lookups.

### v0.5.4

**External lookups and identity columns**

- external lookup actions;
- device identity column fixes;
- corrected IP/MAC dashboard mapping.

### v0.5.3

**Maintenance/repackaging**

- two surviving v0.5.3 release commits exist, but no distinct feature description can be reconstructed confidently from the surviving notes.

### v0.5.2

**Contextual details and local vendor assets**

- device/IP contextual detail navigation;
- local vendor logos;
- reduced third-party image/CDN dependency.

### v0.5.1

**Contextual navigation**

- domain/device/IP navigation;
- dedicated device and IP detail views.

### v0.5.0

**Explainable intelligence**

- evidence-based **Why is this here?**;
- severity-aware classification colours;
- local DNS intelligence layer.

### v0.4.6

**Device identity and At-a-glance UI**

- improved stable device identity;
- improved At-a-glance overview presentation.

### v0.4.5

**Initial enrichment**

- MAC vendor lookup with local cache;
- hostname lookup and device vendor enrichment.

### v0.4.4

**First surviving public lineage**

- fixed duplicate IP/MAC device rows;
- reconciled legacy IP identities to MAC identities;
- canonicalized hostname/client display;
- hostname inspection Reset action;
- preserved DHCP IP history;
- read-only AdGuard integration baseline.

## Historical scope note

A deleted bootstrap file named `dns-inspector-github-0.2.0.zip` exists in the early repository history, but the surviving source history does not contain enough reliable implementation detail to reconstruct 0.2.x/0.3.x accurately. The changelog therefore starts at the earliest version that can be documented from surviving source/release history: **v0.4.4**.

## Roadmap

- persistent manual device labels tied to stable device identity;
- richer historical/trend analytics;
- deeper device identity modelling;
- stronger local vendor metadata;
- dedicated Servers/service view;
- more read-only integrations;
- longer-term research into a standalone DNS/filtering engine.

## License / third-party data

DNS Inspector is an independent project. External services and datasets used for enrichment are subject to their own terms, licenses and availability.
