# DNS Inspector Architecture

This document has two halves. The first describes the *intended* responsibility
boundaries and has been stable across releases. The second is a concrete map of
what the code actually looks like as of 0.8.0, which is new — before 0.8.0 no
accurate map was possible, for reasons explained under "Build model".

---

## Responsibility boundaries

DNS Inspector is deliberately split from DNS policy enforcement.

```text
AdGuard Home
  ├─ resolves DNS
  ├─ applies filtering policy
  └─ exposes query activity
          │
          │ read-only
          ▼
DNS Inspector
  ├─ ingests activity
  ├─ stores local history
  ├─ correlates device/IP identity
  ├─ enriches domains
  ├─ caches external intelligence
  └─ presents investigation views
```

The Inspector must not silently become an AdGuard configuration editor or
blocking engine.

## Data model concepts

### Domain

A DNS name observed in AdGuard Home. Domain records hold activity counters,
client associations, classification/evidence and cached enrichment.

### Device

A stable identity when possible, preferably based on MAC/client identity. IP
addresses are observations attached to a device over time.

### IP

A network observation that may be associated with one or more devices across
time.

### Enrichment

External metadata is cached locally with source-specific TTLs. Inspection should
prefer cached data and refresh stale data asynchronously.

## Evidence model

No single public source should be treated as infallible. TrackerDB, Netify, RDAP
and DNS records provide different signals.

The UI should distinguish:

- known service / ownership
- telemetry / tracking
- advertising
- unknown
- suspicious only when evidence justifies it

**Unknown is not malicious.**

## Performance rule

The browser must not cause direct AdGuard ingestion. Query-log polling belongs to
the background worker. Read paths should primarily read local SQLite state and
cached enrichment.

Persistent storage is part of the application's performance model, so unnecessary
SQLite writes and repeated reconciliation work should be avoided.

---

# Current implementation map (0.8.0)

## Build model

**Up to 0.7.14**, the Docker image was not built from the repository. The
Dockerfile copied sixteen `build_*.py` scripts into the image and ran them in
sequence, each performing `str.replace()` surgery on `app.py`:

```text
repo app.py (2,062 lines)
    │
    ├─ build_perf_patch.py
    ├─ build_perf_hardcap.py
    ├─ build_memory_patch.py
    ├─ ... twelve more ...
    └─ build_0_7_14_features.py
    │
    ▼
image app.py (3,173 lines)  ← the program that actually ran
```

Roughly 1,100 lines of live behaviour — the enrichment queue, IP reachability,
device labels, observability, the debug bundle, the SQLite connection-lifetime
fix and the 0.7.14 search work — existed only inside the image.

**From 0.8.0**, the patch chain is gone. The repository contains the complete
program, and the Dockerfile only copies it. `tests/test_source_integrity.py`
fails the build if this ever regresses.

## Runtime shape

```text
                       app.py  (single module, 3,205 lines)
                             │
   ┌─────────────────────────┼──────────────────────────┐
   │                         │                          │
main()                  Flask routes              background threads
   │                         │                          │
   ├ init_db()               ├ /                        ├ agh-ingest
   ├ _prune_stale_device_ips ├ /search                  ├ enrichment-queue
   ├ start_background_workers├ /api/state               ├ device-ip-cleanup
   └ serve()                 ├ /api/device/label        └ ip-ping
                             ├ /api/ip/ping[/status]        │
                             ├ /device  /ip                 │ bounded pools:
                             ├ /health                      │  agh-status (4)
                             ├ /api/observability           │  enrichment queue
                             └ /debug/bundle                │  ping semaphore
                                     │                      │
                                     └──────────┬───────────┘
                                                ▼
                                    SQLite  /data/inspector.db
                                    TrackerDB /data/trackerdb.sqlite
```

## Regions within `app.py`

`app.py` is still one file. It is not yet modular, but the code does fall into
recognisable contiguous regions. Approximate line ranges as of 0.8.2:

| Region | Lines | Key entry points |
| --- | --- | --- |
| Imports and configuration constants | 1–114 | `APP_VERSION`, `DB_PATH`, `AGH_URL`, cache TTLs |
| UI template (HTML/CSS/JS as one string) | 115–522 | `HTML` |
| Database schema and helpers | 525–688 | `init_db`, `add_column_if_missing` |
| TrackerDB acquisition | 689–728 | `refresh_trackerdb`, `trackerdb_ready` |
| AdGuard client | 729–832 | `agh_get`, `fetch_querylog`, `fetch_clients` |
| Device / IP identity | 833–1161 | `upsert_device`, `extract_identity`, `normalize_mac` |
| Ingestion | 1162–1312 | `ingest`, `query_status`, `query_fingerprint` |
| IP reachability | 1313–1428 | `_ip_ping_worker`, `_prune_stale_device_ips` |
| Domain enrichment | 1429–1987 | `tracker_lookup`, `rdap_lookup`, `netify_lookup`, `_enrichment_worker` |
| Presentation helpers | 1988–2336 | `inspect_html`, `classify`, `vendor_visual` |
| Query / analytics | 2337–2814 | `get_recent`, `get_stats`, `analytics_payload`, `state_payload` |
| Workers and routes | 2815–3510 | `worker`, `index`, `health`, `api_analytics` |
| Diagnostics and observability | 3511–3563 | `debug_bundle`, `_observability_payload` |
| Entry point | 3564–3588 | `main`, `serve`, `start_background_workers` |

The "Query / analytics" region grew in 0.8.2 to add the Analytics dashboard's
data-selection functions (`get_query_volume_series`, `get_new_domains_series`,
`get_new_devices_series`, `get_status_breakdown`, `get_recent_activity`,
`_analytics_live_snapshot`) alongside the existing `get_recent`/`get_stats`.
They read from data the ingestion pipeline already persists (`processed_queries`,
`domains.first_seen`/`last_seen`, `devices.first_seen`/`last_seen`); no new
sampling pipeline or time-series store was introduced.

These regions are observations, not module boundaries. See
[MODULARIZATION.md](MODULARIZATION.md) for how they are expected to become real
boundaries, and for the constraints that make some of them harder to move than
their size suggests.

## Database ownership

`init_db()` is the sole owner of schema creation and migration. It creates
fourteen tables and is idempotent — it is called both at startup and at the top
of the ingest worker, and running it repeatedly is a supported operation.

| Concern | Tables |
| --- | --- |
| Activity | `domains`, `processed_queries` |
| Identity | `devices`, `device_ips`, `client_cache` |
| Enrichment cache | `rdap_cache`, `netify_cache`, `netify_ip_cache`, `dns_records_cache`, `mac_vendor_cache`, `hostname_cache` |
| Status cache | `adguard_status_cache` |
| Scheduling | `enrichment_attempts`, `ip_ping_status` |

Schema migration is additive only, via `add_column_if_missing`. There is no
migration framework and 0.8.0 does not introduce one.

Connections are opened per operation with `closing(sqlite3.connect(DB_PATH))`.
Writes that must not interleave take the module-level `db_lock` first. This is
the connection model the 0.7.13-hotfix.2.3 fix established, and 0.8.0 preserves
it unchanged.

## Configuration

All configuration is read from environment variables into module-level constants
at import time. There is no configuration file and no runtime reload.

`APP_VERSION` is read from the `VERSION` file next to `app.py`, falling back to
the `APP_VERSION` environment variable.

Values with enforced floors: `POLL_SECONDS` and `UI_REFRESH_SECONDS` clamp to a
minimum of 5; `TRACKERDB_DOWNLOAD_CHUNK_SIZE` clamps to a minimum of 64 KiB.

## Boundedness

Background work is bounded in four separate ways, all of which predate 0.8.0 and
are preserved by it:

- `_status_executor` — a 4-worker `ThreadPoolExecutor` for AdGuard status
  refreshes, plus a 20-slot `BoundedSemaphore` hard cap and an in-flight set that
  prevents duplicate work for the same domain.
- The enrichment queue — a single consumer thread draining a bounded queue, with
  per-domain retry cooldowns persisted in `enrichment_attempts`.
- IP ping — one worker on a fixed interval, with validated targets and a
  subprocess timeout.
- Device IP retention — a cleanup worker pruning observations past their
  retention window.

External HTTP calls go through a shared `requests.Session` with explicit
timeouts.
