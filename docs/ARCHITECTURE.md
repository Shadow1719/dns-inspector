# DNS Inspector Architecture

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

The Inspector must not silently become an AdGuard configuration editor or blocking engine.

## Data model concepts

### Domain

A DNS name observed in AdGuard Home. Domain records hold activity counters, client associations, classification/evidence and cached enrichment.

### Device

A stable identity when possible, preferably based on MAC/client identity. IP addresses are observations attached to a device over time.

### IP

A network observation that may be associated with one or more devices across time.

### Enrichment

External metadata is cached locally with source-specific TTLs. Inspection should prefer cached data and refresh stale data asynchronously.

## Evidence model

No single public source should be treated as infallible. TrackerDB, Netify, RDAP and DNS records provide different signals.

The UI should distinguish:

- known service / ownership
- telemetry / tracking
- advertising
- unknown
- suspicious only when evidence justifies it

**Unknown is not malicious.**

## Performance rule

The browser must not cause direct AdGuard ingestion. Query-log polling belongs to the background worker. Read paths should primarily read local SQLite state and cached enrichment.

Persistent storage is part of the application's performance model, so unnecessary SQLite writes and repeated reconciliation work should be avoided.
