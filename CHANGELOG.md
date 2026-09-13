# Changelog

All notable DNS Inspector changes are tracked here.

## [0.7.6]

- fixed Vendor lookup action alignment so the lookup control stays in a consistent column regardless of vendor-name length
- fixed MAC lookup action alignment with the same fixed-width lookup slot
- kept domain names in the new-domain banner directly clickable for inspection

## [0.7.5]

- new-domain notification banner now shows per-domain Allowed / Blocked / Mixed / Unknown status pills
- new-domain names in the banner link directly to domain inspection

## [0.7.0] — prepared / pre-release

- Overview status filters: All, Allowed, Blocked, Mixed, Unknown
- `<24h` quick filter and NEW markers for recently first-seen domains
- live new-domain banner between refreshes
- classification, severity, device and vendor filters
- configurable page size: 10 / 25 / 50 / 100 / 250 / 500
- Overview pagination
- server-side filtering and pagination for larger result sets

> 0.7.0 is not marked as released until the build is deployed and verified.

## [0.6.11]

- read-only current AdGuard filtering status via `filtering/check_host`
- cached current status, separate from historical query counters

## [0.6.9]

- standardized external lookup actions around magnifier + label
- consistent new-tab behavior for external actions
- centralized external lookup presentation

## [0.6.8]

- standardized external lookup icons
- added hover titles / ARIA labels for external lookups
- separated internal navigation from external lookup navigation
- fixed HOST links to device detail views

## [0.6.5]

- added Allowed / Blocked / Mixed / Unknown status semantics
- added conservative severity presentation
- added local favicon and bundled vendor visuals
- added persistent domain status counters and latest query reason

## [0.6.1]

- sortable Overview and Devices tables
- stronger classification using cached TrackerDB, Netify and RDAP evidence
- hardened IP/device/domain navigation

## [0.5.7]

- persistent Netify, RDAP and DNS record caches
- background enrichment refresh
- removed hardcoded local AdGuard URL defaults

## [0.5.2]

- local vendor logos bundled into the application
- removed dependency on third-party image CDN for vendor visuals

## [0.5.1]

- contextual internal navigation for devices, IPs and domains
- device and IP detail views

## [0.5.0]

- evidence-based "Why is this here?" presentation
- severity-aware classification colors
- local DNS intelligence UI improvements

## [0.4.5]

- MAC vendor lookup with local cache
- hostname lookup and device vendor enrichment

## [0.4.4]
