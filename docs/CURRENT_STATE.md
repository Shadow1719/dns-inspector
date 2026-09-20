# DNS Inspector — Current State

> This file records the repository's current project state for all AI agents. It is not a replacement for the source code. When this file conflicts with the implementation, investigate the repository and Git history before changing code.

## Baseline

- Repository: `Shadow1719/dns-inspector`
- Working branch: `dev`
- Foundation version: `0.8.0`, current release: `0.8.5.15` (the `VERSION`
  file is authoritative). The project stays in the `0.8.5.x` series
  deliberately until the UI/dashboard/operational work is fully resolved;
  0.8.6 is not to be started until that gate is explicitly lifted.
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

0.8.5.1 (Issue #27) implements the destination/GeoIP map deferred above, plus two new bounded-ratio instrument gauges. The map's destination IPs are the real A/AAAA answer(s) AdGuard returned for each query, captured at ingestion time from that query's own `answer` data into a new bounded table, `domain_destination_ips` (`extract_observed_answer_ips()` / `_record_domain_destination_ips()`) -- a small, bounded, read-only addition to `ingest()`, not the independently/asynchronously DNS-over-HTTPS-re-resolved `dns_records_cache` (which can disagree with what a specific query actually received; still used only by the domain detail page, unchanged). Each destination IP's own observation count -- not the domain's whole request count -- drives its country's weight in the aggregate, so a multi-A/AAAA/CDN domain can appear in more than one country instead of having its full query volume attributed to a single arbitrarily-chosen IP. `normalize_public_ip()` filters observed answers to public addresses, and a `GeoIPProvider` abstraction (`NullGeoIPProvider` / `CsvRangeGeoIPProvider`, `app.py`) resolves each to a country from a local CSV range database at `GEOIP_DB_PATH` via a real O(log n) bisect over a precomputed per-address-family start-key array; no database ships by default (see `docs/GEOIP.md`), so out of the box the map honestly reports 0% geolocated instead of guessing, and no path ever makes a live GeoIP network request. Aggregation (`geoip_map_payload()`) is bounded (`GEOIP_MAP_DOMAIN_LIMIT` domains scanned, `GEOIP_DESTINATION_IPS_PER_DOMAIN_LIMIT` destination IPs retained per domain, `GEOIP_MAP_CACHE_SECONDS` server-side cache) and served from a new dedicated route, `GET /api/analytics/map`, kept separate from `/api/analytics` so its heavier aggregation runs on its own cadence/cache. Because `COUNTRY_CENTROIDS` only plots a bounded subset of countries, the widget explicitly reports plotted-vs-total geolocated countries rather than silently dropping the rest. `/api/analytics` itself gains one additive field, `total_devices`, the denominator the new active-devices gauge needs. Both new gauges (blocked ratio, active devices) reuse the existing Analog instrument-gauge visual language via a new generalized `instrumentPercentGaugeSvg()` renderer, with the needle rotated via CSS `transform` and updated in place on re-render (rather than SVG `x2`/`y2`, which are not themselves animatable CSS properties, and rather than replacing the whole gauge each poll) so its transition genuinely animates; `analogGaugeSvg()` itself is untouched. All new motion (gauge needle transitions, the map's top-country pulse ring) respects the existing reduced-motion preference/media query.

0.8.5.1 (Issue #31 follow-up) fixes the Dashboard Builder's layout-merge so widgets added in a later release (the destination-map/instrument-gauges pair above) are not lost for a browser that already has an older `dnsInspectorDashboardLayout` saved. `loadLayout()` previously reconciled a saved layout's `order` against the live `WIDGET_IDS` by blindly `push`ing any newly-introduced id onto the very end of the array, and `presetLayout()`'s `monitoring`/`investigation` presets set `base.order` to a hard-coded list that simply predated those widgets and omitted them outright; on a dashboard that already had eight-plus widgets and a "Top activity" chart grid at the end, this put the new widget below everything the user already had on screen -- effectively invisible without scrolling well past where the page used to end, which is what an operator upgrading from 0.8.5 actually saw. Both call sites now run their ids through a new pure helper, `insertWidgetsAtDefaultPosition(order, defaultOrder)`, which inserts a missing id next to its default neighbour instead of at the tail, so an upgraded browser's layout (and every named preset) ends up with new widgets positioned the same way a brand-new layout would, while still preserving the user's existing customization of the widgets that were already there. No widget markup, route or payload changed.

0.8.5.2 (Issue #35) makes the 0.8.5.1 destination/GeoIP map practical to actually populate and verify, without touching its data model, semantics or visuals. `docs/GEOIP.md` now has an operator-ready "Quick setup: DB-IP Country Lite" walkthrough (source, conversion, `GEOIP_DB_PATH`/container volume configuration, restart requirement, and how to verify both provider load and map coverage) plus a documented end-to-end smoke-test procedure using the real DNS test domains from `nelsonjchen/cloud-geoip-dns-testing`, run through the operator's normal AdGuard resolver path (that project is a source of geo-routed test domains only, never imported as a GeoIP database itself, and the docs explain that the exact returned IP/country can vary with resolver location/EDNS Client Subnet/DNS routing). A new small, dependency-free, offline conversion utility, `scripts/convert_dbip_country_lite.py`, adds the missing `country_name` column to a DB-IP Country Lite export to produce the existing unchanged four-column `CsvRangeGeoIPProvider` schema -- streaming, IPv4/IPv6, deterministic output, no network access of its own. `GeoIPProvider` gains a `path`/`range_count` surface and a new `_geoip_diagnostics()` snapshot (provider type, configured/not, database filename only -- not the full path, loaded range count) that is logged once at startup (never per query) and exposed via `/api/observability`'s new `geoip` field, so an operator can confirm the provider loaded without container log access. New fixture-backed tests cover the conversion utility, the diagnostics snapshot/log line, a domain with mixed mapped/unmapped destination IPs, and `/api/analytics/map` returning non-zero geolocated coverage over real HTTP with a fixture provider configured.

0.8.6 (Issue #37) reworks the 0.8.5.1/0.8.5.2 destination/GeoIP map from a
static country bubble map into an interactive, configurable one, while
keeping `/api/analytics/map`, `domain_destination_ips` and the observed-DNS-
destination semantics as the unchanged source of truth -- no DNS
re-resolution, no invented coordinates. Countries mode is the existing
country-level aggregation, now sized by a selectable metric. Destinations
mode plots real observed destination IPs by coordinate when a new, optional
`CityGeoIPProvider` (`NullCityGeoIPProvider`/`CsvCityGeoIPProvider`, fully
additive to and independent of the existing country-only `GeoIPProvider`) is
configured via `GEOIP_CITY_DB_PATH`; nearby points are grid-clustered
client-side, with click-to-zoom re-clustering at a finer scale. If only a
country database is configured, Destinations mode explicitly says
coordinate data is unavailable rather than substituting a country centroid.
`CsvCityGeoIPProvider` stores IPv4 ranges (the bulk of a real city database)
as parallel fixed-width `array.array` columns with interned country/city
string tables instead of a plain Python list of millions of row tuples; a
new offline conversion utility, `scripts/convert_dbip_city_lite.py`, builds
its CSV schema from a DB-IP City Lite export the same way
`convert_dbip_country_lite.py` already does for the country database (see
`docs/GEOIP.md` for the CC BY 4.0 attribution requirement). `/api/analytics
/map` gains two additive fields, `capabilities` (what the current
configuration can actually show) and `destinations` (bounded, deduplicated
per-IP coordinate points); `countries` entries gain one additive
`unique_ip_count` field; all other existing fields are unchanged in shape.
Map appearance (four styles -- BEMO Dark/Aurora/White/Minimal, expressed as
scoped `--map-*` custom properties, independent of the application theme)
and the bubble/cluster sizing metric (Observations/Unique IPs/Domains) are
new `dnsInspectorPrefs` keys (`mapMode`/`mapMetric`/`mapStyle`), persisted
the same client-side-only way as every other Inspector BEMO preference. A
discrete zoom control and a reset/recenter control were added; the bundled
offline world-landmass basemap, country-bubble rendering path and
reduced-motion handling from Issue #33/#27 are unchanged. Heatmap mode is
deliberately left as a documented follow-up rather than a half-working
implementation, matching the task contract's own allowance for that case.

0.8.5.4 (Issue #39) fixes real-DEV problems found after 0.8.6/Issue #37
shipped, without changing `/api/analytics/map`'s existing fields, the
observed-DNS-destination semantics, or the bounded destination-IP model.
The actual root cause of the map staying empty on a real deployment was
`GEOIP_DB_PATH`/`GEOIP_CITY_DB_PATH` defaulting under `BASE_DIR/data/...`
(`/app/data/...` inside the container) while every other persistent path
(`DB_PATH`, `NEIGHBORS_PATH`, `TRACKERDB_PATH`) already defaulted under
`/data` -- the directory the Dockerfile creates and the README's documented
single-volume mount actually covers; the defaults now match `/data` like
everything else, and a new standalone script, `scripts/verify_geoip.py`,
lets an operator prove a converted CSV loads and resolves sample IPs before
ever mounting it into the container. `geoip_map_payload()` also gains a
`_geoip_diagnostic_state()` state machine (`not_configured`/`load_failed`/
`no_public_destinations`/`no_country_matches`/`country_only`/
`partial_coordinate_coverage`/`full_coverage`), exposed as `/api/analytics
/map`'s new `diagnostics` field, replacing the single `provider.configured`
boolean the map widget used to render one empty-state banner from;
`provider` no longer returns the full configured `GEOIP_DB_PATH`, only its
basename and range count, matching what `/api/observability` already did.
On the frontend, the destination map SVG gained real pointer-drag panning,
wheel/pinch zoom toward the cursor, keyboard panning/zooming, touch support
and an on-demand "Fit to data" control, additive to the existing discrete
zoom/reset buttons; the four map styles (BEMO Dark/Aurora/White/Minimal) now
each set a double-digit number of distinct `--map-*` properties (ocean
gradient, land glow, grid opacity, marker glow, empty-state banner
treatment) instead of effectively only recoloring one accent variable; and
the bundled offline world-landmass silhouette gained extra vertices on its
longest, flattest edges (still a stylized hand-authored outline, not
survey-accurate coastline data) plus a soft blurred depth layer behind the
crisp coastline on the glow-capable styles.

0.8.5.5 (Issue #42) makes the GeoIP databases the 0.8.5.1-0.8.5.4 destination
map depends on self-maintaining, without changing the map's data model,
`/api/analytics/map`'s existing fields, or the observed-DNS-destination
semantics. A new background worker (`geoip_auto_update_worker()` in `app.py`,
registered in `BACKGROUND_WORKERS`) and its supporting module,
`scripts/geoip_updater.py` (no `app.py`/Flask dependency, so it also runs as
a standalone CLI), check DB-IP Lite for a newer monthly Country/City Lite
release on a configurable cadence (`GEOIP_UPDATE_INTERVAL_DAYS`, default 30
days; `GEOIP_AUTO_UPDATE=true` by default), download and validate it
(HTTP status, gzip integrity, an optional checksum when a source for one is
configured, and a minimum converted-row-count floor), convert it with the
*same* converters `docs/GEOIP.md`'s manual setup already used
(`scripts/convert_dbip_country_lite.py` / `convert_dbip_city_lite.py` --
no duplicated conversion logic), and atomically replace
`GEOIP_DB_PATH`/`GEOIP_CITY_DB_PATH` only once the replacement is fully
validated -- a failed or incomplete check/download/conversion always leaves
the previously working database untouched, using the same
download-to-temp-then-`os.replace()` pattern `refresh_trackerdb()` already
used. `_reload_geoip_providers()` swaps the in-process
`GeoIPProvider`/`CityGeoIPProvider` and clears their lookup caches
immediately after a successful replacement, so an update takes effect
without a container restart. Per-database updater state (current release,
last checked/succeeded, last error) persists at `GEOIP_UPDATE_STATE_PATH`
(default `/data/geoip_update_state.json`) and is exposed via
`/api/observability`'s new `geoip_update` field alongside an in-memory-only
`in_progress` flag. `scripts/geoip_updater.py` also provides a manual
one-shot CLI (`--force`, `--dry-run` for CI/troubleshooting verification
without mutating anything, `--status`, `--country-only`/`--city-only`).
**This implementation's build environment had no outbound network access to
re-verify DB-IP's exact current download URL pattern against
https://db-ip.com/db/download/ip-to-country-lite live** -- the default
templates (`download.db-ip.com/free/dbip-<product>-lite-<year>-<month>.csv.gz`)
follow DB-IP's long-documented Lite convention and are fully overridable via
`GEOIP_UPDATE_COUNTRY_URL_TEMPLATE`/`GEOIP_UPDATE_CITY_URL_TEMPLATE`; an
operator should confirm the pattern before relying on unattended updates in
production. A mismatch fails safe (treated as "no release found this
check", never as a reason to touch the existing database). DB-IP attribution
("IP Geolocation by DB-IP", linking to db-ip.com) was added to the Settings
> About panel and the destination map widget footer to satisfy DB-IP Lite's
CC BY 4.0 attribution requirement. The Dockerfile now also copies `scripts/`
into the image, since `app.py` imports `scripts.geoip_updater` directly and
previously only `app.py`/`VERSION`/`static/` shipped.

0.8.5.6 (Issue #43) fixes the Dashboard Builder's layout system, adds a
functional restart control, and fixes the 0.8.5.5 GeoIP updater's indefinite
`in_progress` regression. The Analytics `.dash-grid` is now a real 4-column
grid: every widget picks an actual 1-4 column span (`data-w="1".."4"`,
replacing the old binary `half`/`full`), `grid-auto-flow:dense` back-fills
gaps a mix of spans would otherwise leave, and two responsive breakpoints
(1300px/900px) keep the same span proportions readable as the viewport
narrows. A `normalizeWidth()` helper in the same script migrates a browser's
pre-existing `dnsInspectorDashboardLayout` (or an older named preset) from
the old strings to the equivalent span so no saved customization silently
resets; no widget, route or payload changed. Settings > System gained a real
"Restart DNS Inspector" control (two-step in-panel confirm, a `Restarting…`
state, a client + server guard against a duplicate/concurrent request)
backed by a new `POST /api/system/restart` route; because the container runs
`app.py` directly as PID 1 with no supervisor (see the Dockerfile) and
Flask's built-in dev server, the backend performs a real restart via
`os.execv` (`_perform_self_restart()`) rather than depending on a Docker
restart policy or only restarting a background worker thread -- `main()`
runs again from scratch exactly as on a fresh container start, and `/data`
is untouched. Runtime evidence showed the 0.8.5.5 GeoIP auto-updater stuck
at `geoip_update.in_progress=true` with both targets' `last_checked_at=null`
for several minutes with no success/error; `scripts/geoip_updater.py`'s
`run_update()` now saves state after each target instead of once at the
end, and `app.py`'s `geoip_auto_update_worker()` is split into a new
`_run_geoip_update_pass()` that runs the pass in its own thread and enforces
a whole-pass deadline (`GEOIP_AUTO_UPDATE_WATCHDOG_SECONDS`, default 1800s)
independent of `geoip_updater`'s own per-request timeouts; on timeout, a new
`geoip_updater.mark_stuck_checks_as_timed_out()` records an explicit error
for whichever target never recorded its own outcome and `in_progress` is
cleared so the next poll can retry.

0.8.5.7 (Issue #44) fixes real-deployment evidence of `geoip_update.in_progress=true`
appearing immediately after startup: `geoip_auto_update_worker()` previously
ran its first check/update pass at background-thread startup, before its
first `time.sleep`, and `geoip_updater._is_check_due()` treated a missing
`last_checked_at` as due -- so a fresh `/data` (no `geoip_update_state.json`
yet) could start the ~650MB / ~7.75M-row DB-IP City Lite download and Python
CSV conversion while the application was still trying to become healthy.
The worker now sleeps until a configured daily local-time window
(`GEOIP_AUTO_UPDATE_HOUR`/`GEOIP_AUTO_UPDATE_MINUTE`, default `03:00`,
resolved against `GEOIP_AUTO_UPDATE_TIMEZONE` via `zoneinfo`, default `UTC`)
via two new pure functions in `scripts/geoip_updater.py`
(`resolve_auto_update_timezone()`, `next_scheduled_run()`) and never runs a
pass at thread startup -- replacing the previous hourly
`GEOIP_AUTO_UPDATE_POLL_SECONDS` re-check loop. `_is_check_due()` is
unchanged in spirit (still gates the real 30-day network check locally) but
now reads a new persisted field, `last_checked_ok_at`, instead of
`last_checked_at`: the latter is stamped at the *start* of every attempt
including a failed one, so gating on it meant a single failed check (a
stale URL template, a transient network error, no release published yet)
silently locked a target out of retrying for another full
`GEOIP_UPDATE_INTERVAL_DAYS` -- `last_checked_ok_at` only advances on an
attempt that did not end in an error, so a failed check is retried at the
next scheduled window instead. The scheduled pass itself now runs
`scripts/geoip_updater.py` as a **subprocess** (`app.py`'s
`_run_geoip_update_pass()`/`_geoip_updater_cli_command()`) rather than an
in-process daemon thread, so a City Lite conversion can never contend with
Flask's own threads for the GIL, and `GEOIP_AUTO_UPDATE_WATCHDOG_SECONDS`
is enforced via `Popen.communicate(timeout=...)`: a child still running
past the deadline is actually terminated
(`_terminate_geoip_subprocess()` -- `SIGTERM` then `SIGKILL`), something the
previous same-process thread watchdog could time out on but never stop.
`/api/observability`'s `geoip_update` field gains `schedule`
(`hour`/`minute`/`timezone`), a single `status` value (`disabled`/
`scheduled`/`in_progress`) and `next_scheduled_run_at`, so an operator (or
the eventual UI) can distinguish "waiting for its window" from "actively
running" without guessing from `in_progress` alone. The container image now
also installs the `tzdata` PyPI package so `GEOIP_AUTO_UPDATE_TIMEZONE`
values like `Europe/Bucharest` resolve reliably regardless of the base
image's own system tzdata. **A strengthened Docker CI smoke-test step was
written but could not be committed from this hand-off**: the bot's GitHub
App token lacks the `workflows` permission needed to push a change to
`.github/workflows/docker.yml`, so that file is unchanged in this release.
The intended step (run the built image with `GEOIP_AUTO_UPDATE=true` and a
genuinely empty `/data`, assert `/health` responds within 15s, and grep the
container's own logs for "scheduled for" without ever seeing "starting
scheduled check/update pass") is recorded in the Issue #44 PR description
for the repository owner to add by hand.

0.8.5.8 (Issue #47) is a CI repair for the two real test failures left by
0.8.5.7/Issue #44's scheduler (CI run `35274175672` on the PR #46 merge
commit, `aba7744`: 371 passed, 2 failed). `next_scheduled_run()` used
`candidate < now`, so calling it again at the *exact* configured instant
(e.g. a pass that starts precisely at `03:00:00`) returned that same
already-consumed instant instead of rolling to tomorrow, which would have
spun the worker's loop into re-running a pass every iteration instead of
waiting a day; it now uses `candidate <= now` so an exact hit always counts
as consumed. `resolve_auto_update_timezone()` resolved even the default/
empty-string UTC case through `zoneinfo.ZoneInfo("UTC")`, so callers relying
on identity comparison against `datetime.timezone.utc` (a fixed-offset type
distinct from a `ZoneInfo` instance) would not match; the explicit/default
UTC case now returns the real `timezone.utc` object directly and only falls
through to `ZoneInfo` for a real IANA zone name, so non-UTC timezones
(including DST-observing ones like `Europe/Bucharest`) are unaffected. No
other scheduler behaviour, `/api/observability` field, or route changed.
**This hand-off's sandbox could not execute `pytest` or `docker` at all
(both required approval that was never available in this session)**, so
the fix is verified by direct code inspection against the existing test
bodies in `tests/test_geoip_updater.py` rather than an actual local test
run; the repository owner or the real CI run should confirm the full suite
and the Docker smoke path referenced in the issue before relying on this
fix.

0.8.5.9 (no tracked issue) deferred the initial GeoIP provider load
(`_geoip_initial_load_worker()`) off Python module import and off `main()`'s
synchronous startup path into a background worker, tunable via
`GEOIP_INITIAL_LOAD_DELAY_SECONDS` (default 1s), so a large configured
database can no longer block PID 1 from reaching a healthy `/health`. It
declared that worker inside `BACKGROUND_WORKERS`, which broke the fixed
five-long-lived-worker contract two `tests/test_startup.py` tests assert
(CI run `35317057142`: 371 passed, 2 failed) -- fixed in 0.8.5.10 below.

0.8.5.10 (Issue #50) is a CI repair plus the requested GeoIP load
throttling, staying in the 0.8.5.x series per the roadmap gate (0.8.6 is not
to start until the UI/dashboard/operational work is fully resolved).
`_geoip_initial_load_worker()` is no longer declared in `BACKGROUND_WORKERS`
-- it is a one-shot task, not a long-lived loop like the other five workers
-- and is instead started as its own daemon thread directly from `main()`
when a GeoIP database file is present, preserving both the deferred-startup
behaviour and the original fixed-worker-set test contract.
`CsvRangeGeoIPProvider`/`CsvCityGeoIPProvider`'s CSV parse loop (the actual
CPU/disk-heavy step behind both the initial load and a completed
auto-update's in-process reload via `_reload_geoip_providers()`) now runs
through a new `_iter_csv_rows_throttled()` generator that sleeps briefly
after every bounded chunk of rows -- `GEOIP_LOAD_CHUNK_ROWS` (default 5000)
and `GEOIP_LOAD_YIELD_SECONDS` (default 0.01s, `0` disables throttling) --
so a multi-million-row City Lite database doesn't monopolize CPU/disk for
the whole load on a modest host. Download bandwidth is deliberately left
unthrottled; the Issue #44 scheduled 03:00/30-day updater still
downloads/converts in its own isolated subprocess, unchanged. No lookup,
ordering, map-coverage, or destination-map-UI semantics changed.
**As with the 0.8.5.8 hand-off, this session's sandbox could not execute
`pytest` or `docker` at all (both required approval that was never available
in this session)**, so the fix is verified by (a) reproducing the change
byte-for-byte against a prior same-session attempt that a different sandbox
instance had already prepared on `origin/claude/issue-50-20260918-0659`
(commit `1badc69`, itself unvalidated locally) and (b) direct code
inspection against the existing and new test bodies in
`tests/test_startup.py` and `tests/test_geoip_load_throttle.py`. The real CI
run (`pytest` + Docker build/health smoke) must confirm the full suite
before this is relied upon.

Runtime evidence from the real DEV container on TrueNAS (2026-09-18,
~10:03-10:07 local): `/health`, `/api/analytics`, `/api/analytics/map`,
`/api/state`, `/api/ip/ping/status`, and `/search` all continued returning
HTTP 200 while DNS ingest kept running, with the process holding steady at
roughly 3.88 GiB RSS and ~9% CPU. This confirms the service stays responsive
during/after GeoIP activity; the RAM figure is not by itself evidence of a
leak and should be read as a baseline to compare against once 0.8.5.10's
throttled load ships, not as a bug in this own right. (The same log excerpt
also showed every request/ingest line triplicated byte-for-byte at identical
timestamps -- treated as log aggregation/duplication, not three real
requests, absent code evidence otherwise.)

0.8.5.11 (Issue #51) fixes a real-startup semantic problem confirmed by
TrueNAS evidence in the 0.8.5.10 entry above: the container could report
RUNNING (listening socket bound, Flask's own startup banner printed) while
`/health` itself stayed unanswered for several more seconds once the
0.8.5.9/0.8.5.10 deferred initial GeoIP load started on a fixed
`GEOIP_INITIAL_LOAD_DELAY_SECONDS` (default 1s) clock delay -- "process is
running" and "HTTP service is actually ready" were conflated. The fixed
delay is replaced with a real readiness gate: a new `after_request` hook,
`_mark_first_response_ready()`, sets a module-level `threading.Event`
(`_first_response_ready`) the first time the HTTP service finishes serving
any response, and `_geoip_initial_load_worker()` now waits on that event
before starting instead of guessing a delay was long enough --
`GEOIP_INITIAL_LOAD_DELAY_SECONDS` (same env var, same default) becomes only
a safety ceiling for a deployment that never receives a single request at
all. `serve()` also now runs Flask's built-in server with `threaded=True`
so a request already in flight can no longer fully block a concurrent
request behind it. `/api/observability` gains an additive `startup` field
(`http_ready`, `first_response_seconds_after_start`,
`geoip_initial_load_started`/`geoip_initial_load_complete`/
`geoip_initial_load_seconds_after_start`/`geoip_initial_load_duration_seconds`)
so this distinction is observable without container log access; `/health`
itself is deliberately unchanged -- still a plain, fast, unconditional 200,
never gated on GeoIP or on this new field. `refresh_trackerdb()` was
inspected and confirmed already safely off the request-serving path (it is
started from its own daemon thread inside the `agh-ingest` background
worker, itself started before `serve()` but never blocking it), so no
change was made there. No change to GeoIP lookup/map-coverage semantics,
the 0.8.5.10 CSV row-load throttle, or the fixed five-long-lived-worker
contract (`test_background_workers_are_declared`/
`test_start_background_workers_starts_daemon_threads` in
`tests/test_startup.py`, unchanged).
**This session's sandbox could not execute `pytest` or `docker` at all**
(both required approval that was never available in this non-interactive
GitHub Actions session, consistent with the 0.8.5.7-0.8.5.10 hand-offs
above) -- the new/changed tests
(`tests/test_startup_readiness.py`, covering the readiness gate, the
fallback ceiling, the `startup` observability field, and two real
`werkzeug.serving.make_server` end-to-end checks that `/health` answers
promptly while a slow request or the GeoIP load itself is held deliberately
busy) are verified only by direct code inspection against the existing test
patterns in `tests/test_startup.py` and `tests/test_geoip_load_throttle.py`.
The real CI run (`pytest` + Docker build/health smoke) must confirm the
full suite before this is relied upon in production.

0.8.5.11 (Issue #52) fixes the real memory-architecture problem 0.8.5.10's
throttling did not: on real TrueNAS deployment evidence, leaving GeoIP
running could drive the container toward 5+ GiB RSS. The root cause was
`CsvCityGeoIPProvider._load()` parsing every row into a Python tuple,
appending it to a `v4_rows` list, sorting that list, and only then copying it
into compact `array.array` columns -- for a multi-million-row DB-IP City
Lite export, that temporary Python list could itself reach gigabytes before
the compact representation became usable; 0.8.5.10's chunk/yield throttle
changed only the timing of that parse, not its peak memory. `_load()` for
both `CsvCityGeoIPProvider` and `CsvRangeGeoIPProvider` now streams rows
directly into `array.array` columns via a new shared
`_CompactRangeTableBuilder` (`app.py`): the common case -- input already
sorted by start IP, true of a real DB-IP Lite export -- needs no extra
buffering pass, and an out-of-order source falls back to a single
index-permutation pass over the already-compact columns, never over a list
of Python tuples. `CsvRangeGeoIPProvider` (previously a permanent plain
Python-tuple-per-row list, unlike the city provider) now uses the same
array-column-plus-interned-country-table representation, with the previous
duplicate `_v4_starts` list removed since the compact start-key array itself
is the bisect key. `_reload_geoip_providers()` now builds and swaps the
country and city providers one at a time (rather than both up front) and
drops its local reference to each immediately after its swap, so the old
provider plus a second full provider are never both required to be
memory-resident together; a new `_trim_allocator_memory()`
(`gc.collect()` + best-effort glibc `malloc_trim(0)`) runs after every reload
as an explicitly secondary mitigation, not a substitute for the storage
redesign. A new standalone script, `scripts/geoip_memory_benchmark.py`,
measures baseline/after-country-load/after-city-load/steady-state/
after-repeated-lookups/after-repeated-reload RSS plus each provider's own
compact storage size against a synthetic dataset it generates (or a real
database via `--country-csv`/`--city-csv`); a CI-safe regression guard in the
new `tests/test_geoip_compact_storage.py` bounds a moderate synthetic load's
RSS growth to a fixed bytes-per-row budget. Lookup semantics, IPv4/IPv6
coverage, map UI/coverage, country aggregation, destination/city lookup
results, DB-IP attribution, the 0.8.5.10 throttling controls, and the Issue
#44 03:00/30-day updater are all unchanged; no 0.8.6 work is included.
**This hand-off's sandbox could not execute `pytest`, the new benchmark
script, or Docker at all -- running Python, with or without `-m`/`-c`, itself
required approval that was never available in this session**, matching the
same limitation recorded against the 0.8.5.8 and 0.8.5.10 hand-offs. The
change is verified by direct code inspection and by updating/extending the
existing test bodies that asserted the old internal representation
(`tests/test_geoip_destinations_map.py`'s `_v4_starts`/`_v4` bisect test) plus
new tests in `tests/test_geoip_compact_storage.py`. The real CI run (pytest +
Docker build/health smoke) must confirm the full suite, and an operator
should run `scripts/geoip_memory_benchmark.py` against a representative
multi-million-row dataset, before the measured RAM reduction this issue asks
for is treated as confirmed rather than a code-inspection-only claim.

0.8.5.12 (Issue #56) is a visual/interaction-only redesign of the 0.8.5.1-
0.8.5.4 DNS Destinations map into a traffic-intensity infographic, with no
change to `/api/analytics/map`, the observed-DNS-destination source of
truth, GeoIP lookup/storage architecture, the bundled offline basemap, or
the existing pan/zoom/Fit/Reset/keyboard navigation and Countries/
Destinations/style/metric selectors from Issues #33/#37/#39. Every country
bubble and destination cluster now derives both its radius and its fill/
stroke color from one shared value/max-in-view ratio via a new
`mapIntensityColor()` helper (green -> lime/yellow -> orange -> red), so
"large + red" always reads as high observed volume and "small + green" as
low volume without opening the detail panel; markers at/above a high ratio
get the existing pulse-ring treatment (previously hard-coded to only the
single top country) and large-enough markers get a compact numeric count
label (`mapCompactNumber()`). A new `.map-legend` panel above the map
spells out the size/color encoding using the exact same HSL stops as
`mapIntensityColor()`, with its size-metric caption kept in sync with the
Observations/Unique IPs/Domains selector via `mapMetricLabel()`. Every
marker is keyboard-focusable (`tabindex="0" role="button"`) and Enter/Space
now triggers the identical `activateCountry()`/`activateCluster()` handler
a click/tap does, so mouse, touch and keyboard users reach the same
persistent detail card; the card gained an explicit close control
(`#map-detail-close-btn`) rather than relying only on re-clicking the same
marker or the Reset button, satisfying the issue's no-delayed-hover-tooltip
requirement. All new visual treatment (marker color/size transitions, the
pulse ring) continues to respect `html[data-motion="reduced"]` and the
global `prefers-reduced-motion` override; no new per-frame or per-poll DOM
churn was introduced. New tests: `tests/test_map_infographic_visual3.py`.
**This hand-off's sandbox could not execute `pytest`/`python` at all**
(matching the same limitation recorded against the Issue #44/#47/#50/#51/#52
hand-offs above) -- the change is verified by direct code inspection, with
every new string/attribute the new tests assert on independently
grep-verified against the actual rendered `app.py` template in this
session. The real CI run (`pytest` + Docker build/health smoke) must
confirm the full suite, and a manual click/keyboard/legend/reduced-motion
pass in a real browser is recommended before merge since this repository
has no headless-browser test harness to exercise the new interaction code
paths automatically.

0.8.5.13 (Issue #56 follow-up) replaces 0.8.5.12's single `mapStyle` preset
(BEMO Dark/Aurora/White/Minimal) with two independent preferences --
`mapBasemap` (Satellite Heat/Satellite Density/Real Map + Pins/Dark NOC:
structural rendering -- background treatment plus how observed activity is
drawn) and `mapTheme` (Indigo + Gold/Cyan/BEMO Dark Accent: color ramp only,
via a new `mapThemeColor()`/`MAP_THEME_STOPS`, with the existing
`mapIntensityColor()` kept as the literal "BEMO / Dark Accent" ramp) -- and
replaces the flat filled `WORLD_LAND_D` silhouette with an offline dot-matrix
world (`mapWorldDots()`, sampled from the same bundled vector rings via a
plain point-in-ring test, no new geometry/asset/network access). Observed
activity now recolors/brightens the real world dots within a ratio-scaled
radius of each entity's own coordinate rather than only drawing a separate
overlay on top of an inert background. A shared `mapEntityMarkup()` renders
both Countries-mode bubbles and Destinations-mode clusters with the unchanged
sqrt-scaled anchor/pulse/count-label plus new basemap-appropriate activity
particles/pin whose count scales with observed volume (deterministic,
seeded from the entity's own stable id via a small FNV-1a+mulberry32 PRNG,
never `Math.random()`, so a cluster's cloud doesn't jitter between refreshes)
-- all inside one focusable `<g data-country|data-cluster>` wrapper, so
clicking/tapping/keyboard-activating any particle resolves to the same real
entity as before. `/api/analytics/map`'s payload shape, GeoIP lookup/storage
architecture, pan/zoom/Fit/Reset/keyboard navigation, the Countries/
Destinations modes, the Observations/Unique IPs/Domains metric selector and
the DB-IP attribution footer are all unchanged. Literal satellite/street
raster imagery was judged infeasible under the task's own offline/no-
external-tile constraint and was not attempted; all four basemaps render the
same offline dot-matrix world with a different background/activity-rendering
treatment, which is called out explicitly as a scope interpretation rather
than silently shipping a mismatch with the reference concepts' literal
artwork. New tests: `tests/test_map_basemap_theme_visual4.py`; the four
existing map test files that pinned the exact 0.8.5.12 `mapStyle`/flat-
landmass markup this follow-up intentionally replaces
(`tests/test_map_visual2_frontend.py`, `tests/test_map_navigation_visual21.py`,
`tests/test_geoip_destinations_map.py`, `tests/test_map_infographic_visual3.py`)
were updated in place rather than duplicated.
**This hand-off's sandbox could not execute `pytest`/`python`/`node` at all**
(matching the same limitation recorded against the 0.8.5.12 and several
earlier 0.8.5.x hand-offs above) -- the change is verified by direct code
inspection, with every new/changed string the tests assert on independently
grep-verified against the actual rendered `app.py` template, plus a whole-
file brace-balance sanity check against the pre-edit baseline. The real CI
run (`pytest` + Docker build/health smoke) must confirm the full suite, and
a manual browser pass across all four basemaps x three themes (click/
keyboard activation on a dense particle cluster, reduced-motion toggle) is
strongly recommended before merge, since this repository has no headless-
browser test harness to exercise the new rendering/interaction code paths
automatically.

0.8.5.14 (Issue #61 P0 follow-up) fixes a real render-storm that was still
present in `dev` after 0.8.5.13 shipped: `fetchAnalyticsFull()` still called
`fetchDestinationMap()` unconditionally on every `/api/analytics` poll tick,
with no in-flight guard, `AbortController` or unchanged-data check, so the
heavier `/api/analytics/map` GeoIP aggregation ran at the same cadence as the
light poll. **Scoping note for future agents:** an earlier session (branch
`claude/issue-61-20260918-0930`, commit `09863f851d4b2dec28ad27bdfa20a4df0f79170e`)
implemented this exact P0 fix plus a Basemap/Theme split, but that branch was
never merged; `dev`'s actual 0.8.5.13 (`0335860`/`0fd8f83`) is a separate,
independently-authored implementation of the Basemap/Theme split only, built
from the same `b412140` base, that did not carry the P0 fix, the
`mapCompactNumber()`/TrackerDB cleanup fixes, or their dedicated tests over.
This release re-implements the P0 fix and the two cleanup fixes against the
current `dev` code (porting the reviewed logic from the abandoned branch
where compatible; the map-visual portions of that old branch are obsolete
against the current Basemap/Theme implementation and were not used). See
`/api/analytics/map` polling: `mapRefreshMs()` (`max(20000, refreshMs*3)`)
now drives its own `mapRefreshTimer`, independent of `analyticsFullTimer`;
both `fetchAnalyticsFull()`/`fetchDestinationMap()` use an `AbortController` +
monotonic sequence number so a slow response can't overwrite newer state,
`fetchDestinationMap()` also has an in-flight guard, and `mapPayloadFingerprint()`
skips `renderDestinationMap()`'s SVG rebuild when the polled payload is
structurally unchanged. A client-side perf trace
(`window.__dnsInspectorPerf`/`recordPerf()`) is surfaced in Settings >
Diagnostics. Reusing DOM nodes inside `renderDestinationMap()` instead of
`innerHTML` replacement, and giving charts/gauges/map fully independent
render paths, are explicitly **not** done -- see `CHANGELOG.md` for why.
Also fixes two real-DEV bugs from the issue's debug log: `mapCompactNumber()`'s
JS regex had a Python-invalid escape sequence (`SyntaxWarning` at import,
correct JS output regardless) -- compiling the whole file with `SyntaxWarning`
escalated to an error found a second, previously-unreported instance of the
same root cause in 0.8.5.13's `mapLandRings()` dot-matrix sampling regex,
fixed the same way -- and `refresh_trackerdb()`'s `_execute_sql_file()`
ran each dump statement through `executescript()`, which implicitly commits
any pending transaction and silently defeated the dump's own
`BEGIN TRANSACTION;`/`COMMIT;` wrapper (`cannot commit - no transaction is
active`); both now use `conn.execute()` per statement instead. New tests:
`tests/test_analytics_polling_performance.py`,
`tests/test_app_source_no_syntax_warnings.py`,
`tests/test_trackerdb_sql_dump_transaction.py`.
**This hand-off's sandbox could not execute `pytest`/`python` at all**
(matching every 0.8.5.x hand-off above since 0.8.5.7) -- verified by direct
code inspection, with every new/changed string the new tests assert on
independently grep-verified against the actual rendered `app.py` template,
and every inserted JS block read back in full to check brace balance. The
real CI run (`pytest` + Docker build/health smoke) must confirm the full
suite before merge.

The full tile-based/photographic basemap source abstraction (satellite/street
tiles + offline fallback) and the full 2026 Analytics charts/gauges visual
rewrite requested in Issue #61 remain **not implemented** -- same rationale
as 0.8.5.13's deferral: too large and rendering-sensitive to ship unverified
in a sandbox with no Python execution permission and no browser. They should
be tracked as separate follow-up issues rather than folded into further
0.8.5.x point releases.

0.8.5.14 (Issue #63) is a DNS Destinations map usability follow-up on top of
0.8.5.13, with no change to `/api/analytics/map`'s existing fields, GeoIP
lookup/storage architecture, or the observed-DNS-destination semantics.
A country breakdown/ranking panel (`.destination-map-layout`) now sits
beside the map on desktop and below it on narrower widths, listing every
geolocated country from the same `data.countries` payload the map already
renders (no second backend query) -- sortable by the active metric or by
name, scrollable, and highlighting the current selection; a row's
click/keyboard activation (a real `<button>`) calls a new shared
`mapSelectCountry()`, the exact same path a map marker's click/keydown now
also calls, so the two selection surfaces can never diverge. The marker
click/selection bug reported in the issue was real and has a concrete root
cause: an SVG `<g>`'s default `:focus-visible` outline draws a *rectangle*
around its whole bounding box (the invisible enlarged hit-area plus spread
particles), not around the visible marker -- `.map-entity:focus-visible` no
longer sets an outline at all, and focus/selection instead rings the real
anchor circle (`.map-entity:focus-visible .map-bubble`, unchanged
`.map-bubble-selected`). `mapSelectCountry()`/`activateCluster()` now render
the detail card *before* the fuller bubble re-render (the issue's own
guidance, to avoid a click flow that risks losing/invalidating detail state
behind that re-render), and a monotonic request counter in
`fetchDestinationMap()` drops an out-of-order/late analytics-poll response
rather than letting it silently overwrite a newer render; click/keyboard
selection never depends on that poll. Satellite Heat, Satellite Density and
Real Map + Pins now attempt to load one real zoom-0 world tile image each
(`MAP_TILE_PROVIDERS`: OpenStreetMap standard tiles / Esri World Imagery, no
API key) instead of only the stylized dot-matrix background -- Dark NOC
intentionally keeps its stylized treatment, as the issue allows. Tile
loading is async and never blocks rendering; a new true Web Mercator
projection (`mapProjectMercator()`) is used for marker placement only once
a basemap's own tile has actually finished loading
(`mapUsesMercatorProjection()`), so it never mixes with the existing
offline dot-matrix world's original equirectangular projection (kept
byte-for-byte as the automatic, graceful fallback whenever a tile hasn't
loaded or fails to -- the two are never shown at once). See
`docs/MAP_BASEMAP.md` for the tile-provider/attribution details and the
explicit network-verification caveat. Separately, this issue's "resets to
~20-30 after restart" persistence claim was investigated against the real
source and was not reproducible: `domains`/`domain_destination_ips` are
already plain persistent SQLite tables under `DB_PATH` (`/data`) with no
deletion/truncation code path anywhere, and the map's own domain scan limit
(`GEOIP_MAP_DOMAIN_LIMIT`) already defaults to 1500, not ~20-30 -- no
storage architecture was changed on that unverified premise. A new additive
`/api/analytics/map` field, `history` (`tracked_domains_all_time`,
`tracking_since`, from an unbounded `COUNT`/`MIN(first_seen)` over the whole
`domain_destination_ips` table), surfaces real evidence of this persistence
in the widget itself. New tests:
`tests/test_map_breakdown_selection_basemap.py`;
`tests/test_map_infographic_visual3.py`'s keyboard-activation test was
updated in place for the country marker's new shared `mapSelectCountry()`
call. **This hand-off's sandbox could not execute `pytest`/`python` or make
any outbound network request at all** (matching the same limitation
recorded against several 0.8.5.x hand-offs above) -- verified by direct
code inspection and manual regex/brace-balance review of the new/changed
JS and CSS against the actual rendered `app.py` template. The real CI run
(`pytest` + Docker build/health smoke) must confirm the full suite, and a
manual browser pass (all basemaps actually showing tile imagery, breakdown
row selection, keyboard marker activation, reduced-motion) is strongly
recommended before merge, since this repository has no headless-browser
test harness to exercise the new interaction/tile-loading code paths
automatically.

0.8.5.15 (Issue #69) replaces the DNS Destinations map's renderer with
Leaflet + OpenStreetMap standard tiles as a real geographic viewport,
superseding both the fixed-image/dot-matrix basemap approach from Issues
#33/#37/#39/#56/#63 and a same-day amCharts experiment (added, briefly
DEV-default-enabled, then explicitly superseded by this issue before it was
ever the shipped default) that this branch had added and this issue's own
instructions said to stop and remove. `AMCHARTS_MAP_ENABLED`,
`static/amcharts-map-poc.js`, `docs/AMCHARTS_MAP_POC.md` and
`tests/test_map_amcharts_poc.py` are all removed; there is no environment
variable that brings amCharts back. `/api/analytics/map`'s payload, the
GeoIP lookup/storage architecture and the observed-DNS-destination
semantics are all unchanged -- this is a frontend rendering replacement
only. The previous renderer's core problem, called out explicitly in this
issue, was architectural: its "basemap" was a fixed CSS/SVG background (or,
for three of its four presets, a single stretched zoom-0 tile image -- see
`docs/MAP_BASEMAP.md`) that did not pan/zoom with the marker overlay drawn
on top of it; only the overlay's own hand-rolled `mapZoom`/`mapViewCenter`
moved. A new file, `static/leaflet-map.js`, loads Leaflet 1.9.4 (CSS+JS,
unconditionally from `unpkg.com`, no integrity/crossorigin attributes,
matching the existing amCharts CDN include's own convention) and, once
`window.L` is confirmed available and a real `L.map()` instance actually
initializes, replaces `window.renderDestinationMap` -- the single function
`fetchDestinationMap()` calls with whatever it fetched. `fetchDestinationMap()`
itself and its Issue #61 AbortController/monotonic-sequence/in-flight/
fingerprint protections are completely untouched and remain the map
widget's only network-request owner. Unlike the amCharts POC (a reference
implementation only, per this issue's own instructions, never the shipped
renderer), this renderer deliberately reuses the existing shared
`mapSelectCountry()`/`renderMapDetail()`/`mapLastPayload`/`mapMetricValue()`/
`mapThemeColor()` functions instead of re-implementing selection/detail/
sizing/color independently, so a marker click and a country-breakdown-row
click (Issue #63) can never diverge, and both renderers agree on what "high
intensity" looks like. Countries mode plots one marker per geolocated
country centroid; Destinations mode plots real observed destination
coordinates, grid-clustered by real lat/lon (a new, independent clustering
heuristic -- the legacy renderer's own `clusterDestinationPoints()` assumes
a fixed equirectangular pixel canvas that doesn't apply once Leaflet owns
real geographic coordinates) and re-clusters as Leaflet's own zoom level
changes. `state.layers` is a small named `{ countries, destinations }` map
of real `L.layerGroup()`s so future infrastructure-location datasets this
issue explicitly says not to implement yet can register another named
layer group later without replacing the map engine. If Leaflet's library
never loads, or `L.map()` itself throws (checked lazily on the first real
payload), the original legacy SVG renderer -- captured by reference before
being overridden -- is called directly as a genuine fallback, not just a
console warning, so the widget never renders blank; this satisfies the
issue's explicit "legacy SVG as fallback only when Leaflet cannot be
initialized" requirement. Reduced-motion disables Leaflet's own zoom/pan/
marker animation options; OpenStreetMap attribution stays visible via
Leaflet's built-in attribution control. Two disclosed scope decisions: the
legacy renderer's four `mapBasemap` presets (a stylized-background concept
tied to the old fixed-image approach) don't apply once Leaflet/OSM tiles
are the real viewport, so that control is hidden once Leaflet initializes
(the stored preference itself is untouched, so it still governs the legacy
SVG fallback if this ever falls back to it); and selecting a country from
the breakdown panel opens its detail card exactly like a marker click but,
unlike the legacy renderer, does not also recenter/zoom the Leaflet
viewport onto it (to avoid fighting a user's own in-progress pan/zoom on a
real slippy map) -- "Fit" remains the explicit way to frame all currently
plotted markers. See `docs/LEAFLET_MAP.md` for the full architecture
writeup. New tests: `tests/test_map_leaflet_renderer.py`.
**This hand-off's sandbox could not execute `pytest`/`python` or make any
outbound network request at all** (matching numerous 0.8.5.x hand-offs
above, e.g. Issues #44/#50/#52/#56/#63) -- the change is verified by direct
code inspection, with every string the new tests assert on independently
grep-verified against the actual rendered `app.py` template and
`static/leaflet-map.js`, and the whole new JS file read back in full to
check brace/paren balance and control flow by hand. The real CI run
(`pytest` + Docker build/health smoke) must confirm the full suite, and a
manual browser pass is strongly recommended before merge: confirm
OpenStreetMap tiles actually render (not a blank/gray host), zoom 2-3 steps
into Europe/North America and pan around to confirm tiles/markers/clusters
genuinely move and scale together with no fixed image left behind underneath,
confirm a marker click and a breakdown-row click open the identical detail
card, toggle Countries/Destinations mode, and confirm the reduced-motion
preference disables Leaflet's zoom/pan animation.

**Documentation gap noted, not fixed as part of this entry:** `7567baf`
("fix: constrain DNS map country breakdown (#71)"), merged to `dev` after
0.8.5.15/Issue #69 above, has no corresponding `CURRENT_STATE.md` entry or
`VERSION` bump of its own; this hand-off bumps `VERSION` from the pre-existing
`0.8.5.15` straight to `0.8.5.16` rather than guessing at an intermediate
number that was never recorded.

0.8.5.16 (Issue #73) fixes two separate, code-confirmed causes of long-run
RAM growth ("~240 MB short-run baseline growing to ~17 GB after ~12h of
normal runtime", plus a further "~5 GB" transient spike specifically from
Generate Debug Bundle) reported against a real DEV container. Both root
causes were identified by reading the actual `dev` code paths the symptoms
implicate, not by guessing or by simply capping/restarting the process.

**Normal-runtime growth:** `ingest()` called `reconcile_neighbors()`
unconditionally at the end of *every* poll cycle (every `POLL_SECONDS`,
default 10s, for the life of the process). `reconcile_neighbors()`'s own
domain-side pass does a full `SELECT domain,clients_json FROM domains`
`fetchall()` -- every historical row, no `LIMIT` -- and JSON-decodes/re-
encodes each one, looking for legacy `"ip:"`-keyed clients to migrate to a
`"mac:"` key. `domains` is a plain persistent table with no pruning (see the
0.8.5.14/Issue #63 entry above), so this full-table JSON scan's cost grows
with total DNS history and it never stops running: over a busy 12h period
that is thousands of repeated large-temporary-allocation passes over an
ever-larger table on a background thread, which is exactly the class of
workload that inflates long-run RSS in CPython through allocator/arena
fragmentation even without a genuine reference leak -- worsened further by
`MEMORY_DIAGNOSTICS_ENABLED` defaulting to on, since tracemalloc's own
bookkeeping scales with however many of those allocations are alive at any
given instant. Critically, this full scan very rarely had anything to do:
`extract_identity()` already resolves a query's device key straight to
`"mac:..."` via `neighbor_mac_for_ips()` at ingestion time whenever
neighbors.txt already covers that IP, so a domain can only pick up a fresh
`"ip:"`-keyed client while that IP is still missing from the *current*
neighbors.txt snapshot -- there is nothing new to migrate between two calls
where neighbors.txt itself hasn't changed. `reconcile_neighbors()` now
tracks the neighbors.txt mtime it last successfully reconciled against
(`_neighbors_reconciled_mtime`) and returns immediately, before touching the
database at all, whenever that mtime is unchanged -- collapsing the
steady-state cost from "every ~10s, forever, scaling with all DNS history"
to "once, the poll cycle after neighbors.txt actually changes" (in practice
about once a day, per the file's own "daily TrueNAS IP->MAC snapshot"
comment), with migration timing otherwise unchanged. `refresh_runtime_clients()`
was inspected and left alone: it scans `client_cache`, which is bounded by
the number of distinct clients AdGuard has ever reported, not by DNS/domain
history. The other four background workers (`_enrichment_worker`,
`_device_ip_cleanup_worker`, `_ip_ping_worker`, `geoip_auto_update_worker`)
were also inspected: none run more than hourly and none perform an unbounded,
ever-growing table scan, so they were left untouched. The GeoIP/GeoIP-city/
destination-map in-memory caches were also inspected and are already bounded
(fixed-size LRU via `_geoip_cache_order`/`_geoip_city_cache_order`, or a
single-slot cache like `_geoip_map_cache`), so no change was needed there.

**Debug Bundle transient spike:** `/debug/bundle` built `runtime.json` from
`_observability_payload()` (which, since the memory-diagnostics extension,
always runs `_memory_diagnostics()`) *and* `memory-deep.json` from
`_deep_debug_memory_snapshot_safe()` -- and both independently called
`tracemalloc.take_snapshot()` (cost proportional to however many allocations
are currently traced -- unbounded by design, tracemalloc keeps one traceback
per currently-live traced block) and `gc.get_objects()` (cost proportional to
however many objects are currently live), back to back, in the same request.
`memory-deep.json`'s own `tracemalloc`/`python_object_types` collectors
already report a superset (full traceback-grouped top 40, complete GC
type/count breakdown) of what `_memory_diagnostics()`'s lineno-grouped top
25/`large_globals` scan added, so the second pair of snapshots was pure
duplicate cost with no new information -- doubling the bundle's own peak
transient memory use for nothing. `debug_bundle()` now builds `runtime.json`
from the pre-memory-diagnostics `_original_observability_payload()` instead,
so each of `tracemalloc.take_snapshot()`/`gc.get_objects()` runs exactly once
per bundle; the bundle's actual diagnostic content is unchanged (still the
same `manifest.txt`/`runtime.json`/`memory-deep.json`/`config-safe.json`/
`logs-note.txt`/`storage.json` members), just without doing the same two
expensive full-process scans twice.

Both fixes are scoped exactly to the confirmed root causes: no polling
cadence, cache size, GeoIP/enrichment/HTTP-session behaviour, or Issue #61
polling protection (`AbortController`/monotonic-sequence/in-flight guard/
fingerprint skip on `/api/analytics` and `/api/analytics/map`) was touched.
New tests: `tests/test_reconcile_neighbors_scan_bound.py` (pins that a
second `reconcile_neighbors()` call with an unchanged neighbors.txt performs
no domain migration at all, and that a genuine neighbors.txt change still
triggers one), `tests/test_debug_bundle_memory_spike.py` (pins that
`/debug/bundle` calls `tracemalloc.take_snapshot()`/`gc.get_objects()`
exactly once each, and that `runtime.json` no longer carries a duplicate
`memory_diagnostics` block).

**This hand-off's sandbox could not execute `pytest`/`python` at all**
(matching essentially every 0.8.5.x hand-off above, e.g. Issues #44/#50/#52/
#56/#61/#63/#69) -- the change is verified by direct code inspection: tracing
every caller of `reconcile_neighbors()` and confirming `extract_identity()`'s
ingestion-time neighbor resolution makes the mtime-gate safe, tracing every
caller of `tracemalloc.take_snapshot()`/`gc.get_objects()` reachable from
`/debug/bundle` before and after the change, and a full manual re-read of the
edited functions for brace/indentation/control-flow correctness. The real CI
run (`pytest` + Docker build/health smoke) must confirm the full suite, and
an operator should re-check real container RSS over a comparable 12h+ window
before the measured RAM reduction this issue asks for is treated as
confirmed rather than a code-inspection-only claim.


0.8.5.17 (Issue #76) is a second-stage fix for the long-run RAM growth Issue
#73/PR #74 (0.8.5.16) did not fully resolve: real DEV evidence on
`bafd5dd`/0.8.5.16 still showed roughly 3.5 GB of RSS growth in ~35 minutes of
normal (non-debug-bundle) runtime. `reconcile_neighbors()`'s mtime-gate from
0.8.5.16 was re-inspected against the current code and is correct as written
(a stable `neighbors.txt` mtime does make it return immediately without
touching the database), so this release looked for a second, independent
cause rather than assuming that fix was wrong.

Every module-level mutable container in `app.py` was enumerated by hand
(`neighbors_cache`, `enrichment_refreshing`, `_status_inflight`,
`_enrich_inflight`, `_geoip_cache`/`_geoip_cache_order`,
`_geoip_city_cache`/`_geoip_city_cache_order`, `_enrichment_queued`,
`_enrichment_retry_until`, `_enrichment_retry_loaded`). All but the last two
are already either a bounded FIFO (the GeoIP lookup caches, capped by
`GEOIP_CACHE_MAX_ENTRIES`/`GEOIP_CITY_CACHE_MAX_ENTRIES`) or an add/discard
pair that never outlives a single in-flight lookup. `_enrichment_retry_until`
(domain -> next-allowed-retry timestamp) and `_enrichment_retry_loaded`
(domains whose retry state has been read from the persistent
`enrichment_attempts` table at least once) had no eviction at all:
`_enrichment_retry_allowed()`/`_mark_enrichment_attempt()`, called from
`_queue_domain_enrichment()` for every domain `ingest()` discovers as new
(plus every domain a user opens the detail page for), added an entry and
never removed it, growing both structures for the entire lifetime of the
process by one entry per distinct domain ever seen -- exactly the "global/
module-level ... caches ... that can grow with query volume" pattern the
issue asked to look for, and a plausible driver on a busy network where
ad/tracking infrastructure frequently mints a unique subdomain per request
specifically to defeat blocklists and caching. `_bound_enrichment_retry_cache()`
now evicts the oldest tracked domain once a new shared FIFO
(`_enrichment_retry_order`) exceeds `ENRICHMENT_RETRY_CACHE_MAX_ENTRIES`
(default 8192, same default/env-var convention as
`GEOIP_CACHE_MAX_ENTRIES`) -- the identical bounding pattern the GeoIP lookup
caches already used elsewhere in this file. An evicted domain is simply
re-read from `enrichment_attempts` on its next check, so eviction changes
memory bound only, never which domains are actually allowed to retry; no
enrichment scheduling/backoff timing, queue, or worker behaviour changed.

**Scope note:** every other candidate the issue's checklist named was
inspected and ruled out on this pass without code changes: `fetch_querylog()`
is bounded to 500 entries per poll; `refresh_runtime_clients()` scans
`client_cache`, bounded by distinct-client count, not DNS history;
`geoip_map_payload()` is bounded to `GEOIP_MAP_DOMAIN_LIMIT` domains and
cached for `GEOIP_MAP_CACHE_SECONDS`; `_schedule_adguard_status()` explicitly
bounds concurrent status-refresh threads via a semaphore plus an in-flight
set; `_status_executor`/`_enrichment_worker`/`_ip_ping_worker`/
`_device_ip_cleanup_worker`/`geoip_auto_update_worker` were all inspected and
do not perform an unbounded per-poll scan. `MEMORY_DIAGNOSTICS_ENABLED`
defaulting to on (tracemalloc tracing every allocation for the life of the
process) was also inspected: it adds real per-allocation bookkeeping overhead
but is not itself a growing collection, and `/api/observability`'s
`_memory_diagnostics()` already discards its snapshot immediately after each
call (0.8.5.16 already deduplicated the debug-bundle path's own double
snapshot). **This hand-off's sandbox could not execute `pytest`/`python` at
all** (matching essentially every 0.8.5.x hand-off above) -- the change is
verified by direct code inspection and manual dry-run tracing of the new
test's control flow against the edited functions, not an actual local test
run. New tests: `tests/test_enrichment_retry_cache_bound.py`. **The real CI
run (`pytest` + Docker build/health smoke) must confirm the full suite, and
an operator should re-check real container RSS over a comparable 35+ minute
window of normal runtime before the measured RAM reduction this issue asks
for is treated as confirmed** -- this fix removes a genuine, previously
undocumented unbounded growth path, but this hand-off cannot prove by itself
that it fully accounts for the entire previously-observed ~100 MB/min rate;
if real-DEV evidence after this ships still shows comparable growth, the
next investigation should capture an actual `tracemalloc`/`objgraph` snapshot
diff from the live container (impossible from this sandbox) rather than
re-deriving further hypotheses from static code reading alone.

## How to update this file

Update this document when a change materially alters the project's current architecture, active development state, or important known constraints. Do not turn it into a changelog or duplicate the source code.

