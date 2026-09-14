# DNS Inspector

DNS Inspector is a self-hosted, read-only network visibility and DNS intelligence dashboard built around AdGuard Home.

> **What is doing what on my network, and what can I reliably tell about the domains my devices contact?**

AdGuard Home remains the resolver/filter and query source. DNS Inspector imports query activity into local SQLite history, tracks devices, enriches domains with multiple evidence sources, and presents the result through a lightweight web UI.

## Current release: v0.7.14

The current release adds two user-facing improvements:

- Overview > Device filtering now uses the same friendly/manual device name shown in the Devices view when one is available.
- Search now supports partial matching instead of requiring an exact domain, including lookup by domain fragment, device name/hostname, MAC, vendor or recent IP.

The existing 0.7.13-hotfix.2.4 observability and SQLite-lifetime fixes remain included.

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
