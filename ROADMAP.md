# DNS Inspector → Inspector BEMO Roadmap

> **Note (0.8.0):** versioning changed with the 0.8.0 foundation release. Development
> now proceeds as `0.8.1`, `0.8.2`, `0.8.3`, each carrying one focused change, with no
> `-hotfix.N` or `-dev.N` suffixes. The `v0.7.13-hotfix.2.x` headings below describe
> *scope*, not version numbers that will be used again. The 2.5 and 2.6 work described
> here remains the intended product direction; see `docs/MODULARIZATION.md` for the
> structural steps that have to land alongside it.

The roadmap has changed direction slightly after the recent memory investigation and the review of commercial DNS-visibility reports and DNS-security guidance.

The goal is no longer to make DNS Inspector a prettier AdGuard query log. The product direction is **network intelligence**: observe what happened, identify what it is, explain why we think that, score confidence/severity, detect unusual behavior, and surface the things worth investigating.

## Current state — v0.7.13-hotfix.2.4

### Stability / observability
- SQLite connection lifetime stabilized in 2.3.
- Long-running memory behavior investigated with deep diagnostics.
- Uptime and RAM indicators restored in 2.4.
- Debug Bundle and runtime diagnostics remain available for future investigations.
- No new memory hotfixes unless the running build produces new evidence of a real leak.

---

# Next releases

## v0.7.13-hotfix.2.5 — DNS Catalog & Search

**Goal: make domain intelligence consistent and searchable.**

- Replace exact-match global search with partial matching.
- Search across all useful entities: domains, devices, labels, hostnames, IPs and MACs where applicable.
- Establish a clearer domain catalog model:
  - service/application;
  - company/vendor;
  - category;
  - classification;
  - evidence;
  - confidence;
  - first/last seen;
  - associated devices.
- Add live DNS lookup for inspected domains.
- Surface useful record types including A, AAAA, CNAME, NS, MX, TXT, SOA, CAA and SRV, with additional record types added when useful.
- Keep DNS lookup outside the ingest/UI critical path and cache results.
- Prefer direct public DNS APIs/resolvers rather than coupling the UI to a third-party web tool.
- Where useful, compare local/known resolver results with public resolvers such as Google or Cloudflare.
- Keep `Unknown` neutral: unknown must not imply malicious.

## v0.7.13-hotfix.2.6 — Classification 2.0

**Goal: move from “some metadata” to a repeatable evidence model.**

- Formalize classification categories and service/application identity.
- Introduce a visible **Confidence** score separate from severity.
- Define evidence sources and their contribution to confidence.
- Make the `Why is this here?` panel evidence-driven and consistent.
- Distinguish:
  - observed fact;
  - inferred classification;
  - external evidence;
  - confidence;
  - severity.
- Improve handling of conflicting evidence between TrackerDB, Netify, RDAP and DNS records.
- Add clearer fallbacks for domains with incomplete enrichment.

## v0.7.13-hotfix.2.7 — Security Signals

**Goal: detect suspicious DNS behavior without pretending to be an antivirus or SIEM.**

Initial signals, ordered by practicality:

- unusual NXDOMAIN volume per device;
- public DNS-over-HTTPS / DNS-over-TLS resolver activity;
- newly registered domains;
- suspicious/high-entropy or unusually long DNS labels;
- DNS tunneling heuristics based on query volume, uniqueness, label length and entropy;
- fast-flux-style infrastructure changes where DNS evidence supports it;
- abnormal changes in a domain's IP/ASN footprint;
- optional future signals for DNS poisoning/hijacking indicators when reliable evidence exists.

Every detection should produce:

```text
Finding
 ├─ What was observed?
 ├─ Why is it suspicious?
 ├─ Evidence
 ├─ Severity
 ├─ Confidence
 ├─ Affected device(s)
 └─ Suggested review/action
```

Detections are **advisory findings**, not automatic blocking decisions.

## v0.7.13-hotfix.2.8 — Analytics Live Activity

**Goal: make Analytics feel alive without creating another polling/memory problem.**

- Add a compact **Live DNS Activity** panel to Analytics.
- Show the latest 5–10 events.
- Display at minimum:
  - time;
  - domain;
  - device;
  - Allowed / Blocked / other status.
- Use status colour as the primary visual signal:
  - green for Allowed;
  - red for Blocked.
- Use severity/intensity to refine the colour when a finding exists:
  - muted for Info/low significance;
  - stronger red for higher severity.
- Keep text/status visible so the UI does not depend on colour alone.
- Reuse the existing ingest/state refresh path; do not add a new high-frequency polling loop.
- Allow clicking a live event into the normal domain/device inspection flow.

## v0.7.13-hotfix.2.9 — Findings & Reports

**Goal: turn raw analytics into an actionable summary.**

- Findings dashboard with severity and confidence.
- Top security findings by device and domain.
- Application/service visibility.
- Category distribution.
- Top clients/devices.
- Top queried domains.
- New-domain and unusual-behavior summaries.
- 7-day / 30-day report views.
- Export-friendly report data (JSON/CSV first; polished PDF later).
- Every reported finding links back to the underlying Inspector evidence.

The desired reporting model is inspired by strong commercial DNS-visibility reports, but remains technically inspectable rather than management-only.

---

# v0.8.0 — Inspector BEMO foundation

**This is the first intentional product-level evolution beyond DNS Inspector.**

The project stops being conceptually “a DNS dashboard” and becomes a broader **Inspector BEMO** platform.

## Brand direction

### Product
**Inspector BEMO**

### Concept
One BEMO platform with multiple small, focused **Inspectors** instead of one giant application that tries to do everything.

DNS Inspector becomes the first mature mini-inspector under the BEMO umbrella.

Initial direction:

```text
Inspector BEMO
│
├─ DNS Inspector
│    └─ DNS activity, catalog, enrichment, security signals
│
├─ Device Inspector
│    └─ identity, IP history, vendor, reachability, behavior
│
├─ Security Inspector
│    └─ findings, anomalies, severity, confidence, evidence
│
└─ Future Inspectors
     └─ added only when there is a clear source of data and a useful problem to solve
```

These are intentionally **mini-inspectors**: small focused modules sharing a common BEMO shell, identity model and evidence philosophy.

## BEMO platform work

- shared application shell/navigation;
- shared device identity;
- shared event model;
- shared finding/severity/confidence model;
- shared evidence presentation;
- common search across inspectors;
- consistent visual language;
- module boundaries so one inspector can evolve without destabilizing the others;
- preserve the lightweight/self-hosted deployment model.

The DNS Inspector functionality remains fully usable; the rebrand is architectural as well as visual.

---

# Post-0.8 direction
## v0.9.0 — Native DNS capture / AdGuard-independent ingestion

**Goal: make DNS Inspector able to observe DNS traffic without requiring AdGuard Home.**

This is intentionally planned as a **0.9.0** feature rather than part of the
0.8.x visual/security work because it changes the data-acquisition layer and
introduces a second ingestion source. The existing AdGuard integration remains
supported; this adds a native collector that feeds the same Inspector data
model.

Planned architecture:

```text
DNS source
│
├─ AdGuard Home API        (existing)
│
└─ Native packet capture   (new)
       │
       └── common ingest / normalization
                │
                ├─ devices / identities
                ├─ domains
                ├─ observed A/AAAA destinations
                ├─ SQLite persistence
                └─ GeoIP / Analytics / Map
```

Initial scope:

- capture DNS traffic directly from a selected network interface using a
  packet-capture backend (Scapy/libpcap-compatible approach is one reference
  implementation; the final backend is intentionally not locked here)
- support plaintext DNS over UDP/53 and TCP/53 first, with IPv4/IPv6 handling
  where the capture backend exposes it cleanly
- extract the actual query name plus observed DNS response A/AAAA addresses so
  the map continues to represent destinations that were really observed on
  the wire, rather than re-resolving domains later
- feed native-capture observations through the same normalization, identity,
  persistence, analytics and GeoIP paths used by AdGuard ingestion
- make the DNS source selectable/configurable without duplicating the rest of
  the application logic
- keep the existing AdGuard mode fully functional; native capture is an
  alternative source, not a replacement
- surface capture status, selected interface and any required OS/container
  capabilities clearly in the UI/diagnostics
- handle permission/capability failures cleanly (for example packet-capture
  access denied) instead of failing the whole application startup
- explicitly report the visibility boundary: encrypted DNS such as DoH/DoT
  is not visible as plaintext DNS packets unless the deployment provides a
  separate, supported observation point
- preserve persistent history so changing/restarting the DNS source does not
  reset accumulated domain/device/destination data

Non-goals for 0.9.0:

- becoming a DNS server/resolver itself
- silently decrypting DoH/DoT
- replacing AdGuard's filtering/policy engine
- making packet capture mandatory when AdGuard ingestion is configured

Reference implementation investigated: HalilDeniz/DNSWatch, a Python/Scapy
DNS packet sniffer that captures UDP/TCP 53 traffic and extracts DNS request
and response data. DNSWatch is a reference for the native capture mechanism,
not a planned runtime dependency of DNS Inspector.


The exact version numbers after 0.8 are intentionally not locked yet.

Likely areas:

- additional BEMO mini-inspectors;
- cross-inspector correlations;
- stronger network behavior analytics;
- long-term baselines and anomaly detection;
- richer reporting/export;
- optional authenticated multi-user access;
- extensible evidence providers;
- better local-network discovery where technically and operationally justified.

The rule for future inspectors is simple:

> **A mini-inspector earns its place by answering a question that the existing inspectors cannot answer cleanly.**

## Implemented: destination / GeoIP map (0.8.5.1)

0.8.5 (Analytics Visual 2.0 + Dashboard Builder) investigated a lightweight
destination/GeoIP map for Analytics and deliberately did not implement it (see
the 0.8.5 CHANGELOG.md entry for why). 0.8.5.1 implements it:

- destination IPs are the real A/AAAA answer(s) each AdGuard query actually
  received, captured at ingestion time from that query's own answer data
  (`domain_destination_ips`) -- not the RDAP/company `country` field, not a
  new synchronous resolution step, and not the independently/asynchronously
  DNS-over-HTTPS-re-resolved `dns_records_cache`, which can disagree with
  what a specific query actually received
- GeoIP lookup is a `GeoIPProvider` abstraction (`app.py`) over a local CSV
  range database (`GEOIP_DB_PATH`); no database ships in the repository by
  default (see `docs/GEOIP.md` for why and how to supply one), so out of the
  box the map honestly reports 0% geolocated rather than guessing -- there is
  no live third-party GeoIP API call on any path
- aggregation is by country and observed destination count, not one marker
  per request or per domain name; CDN/anycast/multi-region destinations are
  represented as whichever country's IP actually answered, each weighted by
  its own observation count (not the domain's whole query volume) so a
  multi-destination domain can appear in more than one country, with UI copy
  that consistently says "observed destinations"

## Implemented: Destination Map Visual 2.0 (0.8.6)

0.8.6 (Issue #37) turns the map above from a static country bubble map into
an interactive, configurable one, without changing its data model or
semantics:

- a new, optional `CityGeoIPProvider` abstraction (`NullCityGeoIPProvider`/
  `CsvCityGeoIPProvider`) is additive to and fully independent of the
  country-only `GeoIPProvider` above; a Destinations mode plots real
  observed destination IPs by coordinate when a city/coordinate database is
  configured (`GEOIP_CITY_DB_PATH`), client-side grid-clustered so nearby
  points stay readable and separate again on zoom -- it never substitutes a
  country centroid for a missing coordinate
- `CsvCityGeoIPProvider` stores the (potentially several-million-row) IPv4
  side of a real city database as parallel fixed-width `array.array`
  columns with interned country/city string tables, not a plain Python list
  of per-row tuples/strings, per the task contract's memory-efficiency
  requirement
- `/api/analytics/map` gains additive `capabilities` and `destinations`
  fields; existing fields are unchanged in shape
- map appearance (BEMO Dark/Aurora/White/Minimal, independent of the
  application theme) and the bubble/cluster sizing metric are new
  `dnsInspectorPrefs` keys, persisted the same client-side-only way as every
  other Inspector BEMO preference
- Heatmap mode is deliberately left as a documented follow-up rather than a
  half-working implementation

---

# Design principles

### 1. Evidence before confidence
Never present an inference without showing what supports it.

### 2. Confidence is not severity
A high-confidence benign classification is not a security finding. A low-confidence suspicious signal should remain visibly uncertain.

### 3. Unknown is valid
Unknown data is still useful data. Do not force a category merely to make the UI look complete.

### 4. Live visibility without runaway polling
Reuse existing ingest/state flows before adding timers, workers or duplicate API traffic.

### 5. Enrichment is asynchronous
Slow public services must never block normal ingestion or the main UI path.

### 6. Findings should be explainable
Every security signal should be traceable to observable facts.

### 7. BEMO should stay modular
Each mini-inspector should have a clear job and a clear boundary.

### 8. Read-only by default
Inspector BEMO observes and explains. It should not silently turn into a policy-enforcement engine.
