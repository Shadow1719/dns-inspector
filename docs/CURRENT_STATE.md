# DNS Inspector — Current State

> This file records the repository's current project state for all AI agents. It is not a replacement for the source code. When this file conflicts with the implementation, investigate the repository and Git history before changing code.

## Baseline

- Repository: `Shadow1719/dns-inspector`
- Working branch: `dev`
- Foundation version: `0.8.0`, current release: `0.8.5.1`
- AI collaboration contract: `AGENTS.md`
- Claude Code instructions: `CLAUDE.md`

## Architecture state

The 0.8.0 repository contains the complete application source; the historical generated Docker patch chain is no longer the runtime source of truth. The current architecture document records the concrete implementation map and the intended responsibility boundaries.

The application is still structurally centered on `app.py`, with recognizable regions for configuration, UI, database helpers, AdGuard access, device/IP identity, ingestion, reachability, enrichment, presentation, analytics, workers/routes, diagnostics, and the entry point. Modularization is an active architectural direction, not a claim that those regions are already independent modules.

## Important architectural principles

- DNS Inspector observes AdGuard activity; it is not an AdGuard policy editor or blocking engine.
- Background ingestion belongs outside the browser request path.
- Persistent state is local SQLite; unnecessary writes and repeated reconciliation should be avoided.
- External enrichment is asynchronous and cached.
- Unknown is neutral and must not be presented as malicious without evidence.
- Confidence and severity are separate concepts.
- Findings are advisory and explainable.
- Read-only-by-default behaviour is preferred.

See `docs/ARCHITECTURE.md` for the detailed architecture and `docs/MODULARIZATION.md` for the structural migration plan.

## Current development direction

The project is evolving from a DNS dashboard toward the Inspector BEMO platform, with DNS Inspector as the first mature mini-inspector. The roadmap defines the broader product direction and should be treated as product intent rather than a statement that every planned feature already exists.

## Current collaboration state

ChatGPT and Claude Code are separate AI instances. They share no conversation memory. GitHub is the synchronization boundary.

The canonical hand-off is:

`decision -> task/ADR -> implementation -> tests -> Git commit -> current-state update`

Do not rely on either model's memory to preserve project-specific decisions.

## Branching model

- `main` is the production/release branch.
- `dev` is the active development/integration branch.
- Feature/fix branches are created from `dev` and target `dev`.
- Development work must not be committed directly to `main`.

The previous `dev-0.8` branch name is retired as the active development branch.

## Recent implementation note

The repository recently underwent a modularization/observability refactor. Focused fixes must be based on the actual code at the requested commit/branch, not on older ZIP archives or remembered pre-0.8 structure.

0.8.3 (Issue #20) is a front-end-only UI overhaul: a single token-driven "Inspector BEMO" visual design system (colors, spacing, radii, shadows, typography) now spans Overview, DNS Inspector, device/IP views, the shared shell/navigation and Analytics. It restyles the existing `HTML` template string and its CSS in place — same IDs, classes, routes and JSON payload shapes — so no Python data/route logic changed. Treat the `HTML` string in `app.py` as carrying real product design intent now, not placeholder styling.

0.8.4 (Issue #22) is also front-end-only, layered on top of the same `HTML` template: a Settings dialog (Appearance/Dashboard/Monitoring/Diagnostics/System/About) reachable from the shared shell without adding a fourth primary tab; four themes (BEMO Dark/Light/Aurora/Natural, plus System) implemented as `html[data-theme]` overrides of the existing design tokens; accent-color and density preferences that never touch the semantic `--sem-*` status variables; a client-side-only `dnsInspectorPrefs` localStorage preference object (no database migration); a bounded client-side refresh-interval preference and a default-view preference; and a reusable `renderMetricVisual` JS abstraction so every Analytics chart (live sparkline + the three historical timelines) can render the same underlying data through a Digital, Analog or Specter presentation. No Python route, data model or JSON payload shape changed — Diagnostics and System reuse the existing `/api/observability` and `/health` routes instead of adding new ones.

0.8.5 (Issue #23) is also front-end-only, layered on the same `HTML` template. Analytics Visual 2.0 substantially reworks `renderMetricVisual` (and replaces the old `liveGaugeSvg` with `digitalRingSvg`/`analogGaugeSvg`/`specterRadarSvg`) so Digital, Analog and Specter are genuinely different presentations of the same series/live data — bars+ring, an instrument-cluster gauge, and an oscilloscope/radar sweep respectively — plus a client-side-only "spike" marker (mean + 2 standard deviations within the already-fetched bucket series) on every chart; no new metric, backend route or payload field was added. The Analytics tab's widgets (live activity, query volume, new domains/devices, status breakdown, recently-active domains/devices, top activity) are now wrapped as `.dash-widget` elements inside a `.dash-grid` "Dashboard Builder": a Customize mode adds drag/move, bounded half-full width and compact/normal/tall height controls, per-widget show/hide, four presets (Default/Monitoring/Compact/Investigation) plus an automatic Custom state, and a `dnsInspectorDashboardLayout` localStorage layout — all client-side, same underlying widgets and data. A destination/GeoIP map was investigated and deliberately not implemented (see `ROADMAP.md`'s former "Deferred: destination / GeoIP map" note, now "Implemented") because the project had no IP geolocation source and a domain name does not by itself identify a resolved destination's geography. The release also did a focused runtime cleanup: the background `/api/state` poll no longer rebuilds the Overview/Devices table `innerHTML` while that tab isn't active (rendered from cache when the tab is activated instead), and four leftover section-marker comments and several CSS rules/the old gauge function made fully dead by the above were removed.

0.8.5.1 (Issue #27) implements the destination/GeoIP map deferred above, plus two new bounded-ratio instrument gauges. The map's destination IPs are the domain's already-cached resolved A/AAAA answers (`dns_records_cache`, resolved in the background via DNS-over-HTTPS since earlier releases, previously only read by the domain detail page) -- no ingestion-path change. `normalize_public_ip()` filters those to public addresses, and a new `GeoIPProvider` abstraction (`NullGeoIPProvider` / `CsvRangeGeoIPProvider`, `app.py`) resolves each to a country from a local CSV range database at `GEOIP_DB_PATH`; no database ships by default (see `docs/GEOIP.md`), so out of the box the map honestly reports 0% geolocated instead of guessing, and no path ever makes a live GeoIP network request. Aggregation (`geoip_map_payload()`) is bounded (`GEOIP_MAP_DOMAIN_LIMIT` domains scanned, `GEOIP_MAP_CACHE_SECONDS` server-side cache) and served from a new dedicated route, `GET /api/analytics/map`, kept separate from `/api/analytics` so its heavier aggregation runs on its own cadence/cache. `/api/analytics` itself gains one additive field, `total_devices`, the denominator the new active-devices gauge needs. Both new gauges (blocked ratio, active devices) reuse the existing Analog instrument-gauge visual language via a new generalized `instrumentPercentGaugeSvg()` renderer; `analogGaugeSvg()` itself is untouched. All new motion (gauge needle transitions, the map's top-country pulse ring) respects the existing reduced-motion preference/media query.

## How to update this file

Update this document when a change materially alters the project's current architecture, active development state, or important known constraints. Do not turn it into a changelog or duplicate the source code.
