# Changelog

## [Unreleased] - 0.8.6-dev.7 live widget merge + known-datacenter provenance (Issue #88 follow-up)

- merged the "Live activity" widget (live rate, gauge, sparkline, Allowed/Blocked/Active devices/New domains tiles) into the "Visibility report" widget instead of shipping two adjacent Analytics widgets, so the first widget on the dashboard is always a single, always-populated, useful surface rather than a separate one that could look inert
- added a second, strictly lower-priority destination coordinate layer for **known datacenter/cloud/hosting provider** ranges (`GEOIP_DATACENTER_DB_PATH`, documented in `docs/GEOIP.md`): only consulted once the real city/coordinate GeoIP database has already missed for an IP, never overrides a real city match, and coordinates are always region-derived (e.g. a cloud region's published location), never presented as an exact server address
- every observed destination IP now resolves to exactly one provenance tier -- `city_geoip`, `known_datacenter`, `country_only` or `unmapped` -- exposed via `/api/analytics/map`'s `coverage.provenance` counts; `country_only` still contributes to the Countries aggregate but, consistent with the existing rule, is never placed as a Destinations-mode bubble
- the destination map (marker labels, click-to-investigate detail card, legend), the in-app destination coverage note and the PDF export's destination section all label which provenance tier a given point/count came from, instead of treating every destination as equally precise
- bumped candidate to `0.8.6-dev.7`

## [Unreleased] - 0.8.6-dev.6 ShadowDNS-style visibility report, interactive charts, scheduling (Issue #88)

- fixed the Docker image not actually containing `analytics_report.py` (only `app.py`/`VERSION`/`static` were `COPY`'d), which would crash the container at import time; also copies the new `report_scheduler.py` and pre-creates `/data/reports`
- added a bounded, hourly-aggregated `analytics_buckets` history table (independent of the 100k-row `processed_queries` cap, retained up to `ANALYTICS_HISTORY_RETENTION_HOURS` / 90 days by default, pruned every tick) backing new 30d/90d Analytics ranges
- added real click/tap-to-investigate on the "DNS activity over time" chart: the selected bucket stays highlighted (crosshair + marker) across polling refreshes, and `/api/analytics/interval` returns the exact query count, status mix, new domains/devices and top domains/devices for that interval -- computed from real per-query attribution (processed_queries now also retains `domain`/`device_key`/`status` for its existing bounded rows) while still in the raw retention window, and honestly falls back to the bounded hourly aggregate (clearly labeled) once it has rolled off; domains/devices in the popover link to the existing search/device views
- added a "Visibility report" executive-overview widget to Analytics: headline KPIs, peak-interval/blocked-share/new-domains observations, all derived from the same payload the charts render (no separate fetch, no invented findings)
- added an optional, separate coordinate-capable GeoIP CSV (`GEOIP_CITY_DB_PATH`, documented in `docs/GEOIP.md`) so Destinations map mode can show real per-location coordinates; still never falls back to a country centroid, and Destinations mode stays honestly disabled when it isn't configured
- added destination route/arc visualization: a subtle geodesic (great-circle) line from an explicitly operator-configured origin (`/api/settings/map-origin` -- never derived/guessed) to each destination cluster, toggled independently, labeled as a geographic/visual path rather than the real network route, and automatically disabled without both a real origin and real coordinate data
- added a "Dark / NOC" Leaflet basemap layer alongside OpenStreetMap/OpenTopoMap/Esri Satellite, with correct attribution
- added scheduled report generation: one bounded background worker (explicit start/next-due/execute/shutdown, never overlapping, resumes correctly after a restart from a persisted last-run timestamp), configurable hourly/daily/weekly/custom cadence and report window, safe storage (configurable base directory + validated relative filename only, path traversal rejected, bounded retention with oldest-file pruning), optional SMTP delivery (password only from the `SMTP_PASSWORD` env var, never stored/returned by the API; a failed send never blocks the local save), and "Export now" / "Save report now" / "Send test email" controls, all reusing the exact same report generator as the PDF endpoint
- scheduler/report state (enabled, next/last run, last result, last saved file, last email result) is now visible in Diagnostics
- PDF export: every page now has a consistent footer (page N of 4, analysis window, generated timestamp)
- bumped candidate to `0.8.6-dev.6`

## [Unreleased] - 0.8.6-dev.5 visual Analytics PDF report

- added a report-style PDF export from the currently selected Analytics range
- PDF uses a visual executive-summary layout with KPI cards, timeline chart, status donut, ranked bars, destination context and concise interpretation cards
- report distinguishes period activity from the current visibility snapshot instead of presenting all values as period-only statistics
- export is bounded to the retained Analytics history and does not invoke the old deep debug collectors or create a giant in-memory diagnostic archive
- added ReportLab 5.0.1 as the PDF generation dependency

## [Unreleased] - 0.8.6-dev.4 dashboard polish + diagnostics

- made Analytics the default landing view while keeping Overview and Devices one click away for deeper investigation
- added bounded DevLog export and a safe Debug Snapshot download that does not run deep proc/GC/tracemalloc collectors or build an in-memory ZIP
- restored RAM/Uptime data on the normal /api/state refresh payload so the header and Diagnostics panel use the same lightweight runtime snapshot
- added pointer-based widget resizing with 4-column width snapping and persisted height snapping
- constrained the DNS country breakdown to its widget and made the list independently scrollable
- restored additional interactive basemap choices for the Leaflet map: OpenStreetMap Standard, OpenTopoMap, and Esri World Imagery
- kept OpenStreetMap attribution visible and preserved the existing bounded destination/country rendering

## [Unreleased] - 0.8.6-dev.3 UI + Analytics + Map

- restored the Inspector BEMO shell, persistent DEV environment banner/badge/title/favicon behavior, Analytics visual system, live/historical analytics views, gauges and dashboard presentation from the 0.8.x product layer onto the clean Milestone 1 foundation
- restored bounded analytics API reads over the existing `processed_queries`, `domains` and `devices` history without adding a second time-series store
- restored persistent device labels and the safe observability/restart/stop controls without reintroducing the unsafe debug-bundle implementation
- added actual observed A/AAAA destination tracking, bounded country GeoIP lookup, DNS Destinations hotspot rendering, coverage diagnostics and the bounded ephemeral DevLog; coordinate-level Destinations mode remains explicit/unavailable until a city GeoIP provider is added


All notable DNS Inspector changes are tracked here.

## [Unreleased] - 0.8.6 foundation, Milestone 1 (Issue #81)

- rebuilt `app.py` directly from stable 0.7.14, removing the 16-script build-time patch chain the Dockerfile used to apply at image-build time; the 17 `build_*.py` files (16 wired into the Dockerfile plus one dead file) are deleted
- every `sqlite3.connect()` call site (33 total) now uses `contextlib.closing()`, including `_open_trackerdb()`'s two call sites and `tracker_lookup()`'s direct TrackerDB connection, which the historical SQLite-close hotfix had left unpatched
- reimplemented, directly and cleanly rather than via patch: the friendly device-filter label + partial/device/IP search from 0.7.14, the bounded AdGuard-status executor and SQL-pushed-down `get_recent()` filtering, the bounded single-worker enrichment queue with persisted retry cooldown, and bounded device/IP retention with periodic cleanup
- fixed a real bug found while reimplementing device-IP retention (not present in the shipped 0.7.14 image's behavior as observed, since the historical patch's own cutoff comparison could never match): the retention cutoff is now formatted as ISO-8601 to match the `device_ips.last_seen` column instead of being compared as a raw Unix timestamp
- added `tests/` (pytest) and `requirements-dev.txt` for the first time on this line; not executed in this hand-off's sandbox, see `docs/tasks/ISSUE-81-MILESTONE-1-FOUNDATION.md`
- explicitly not ported yet: device-label UI, observability header/`/debug/bundle`, memory diagnostics, and IP reachability ping (feature + UI) -- see the task doc for the full list and reasoning
- `VERSION` is set to `0.8.6-dev.1` for this test candidate; this is foundation work on an unmerged branch, not a production release

## [0.7.14]

- Overview > Device filter now uses the same friendly/manual device name as the Devices view when one is available
- partial search is now supported instead of requiring an exact domain match
- search can resolve domains by partial domain text and by known device identity fields such as custom name, hostname, MAC, vendor or recent IP
- indirect device/IP matches resolve to the most relevant observed domain so the existing inspection UI remains unchanged
- no ingest, enrichment, SQLite lifecycle or background polling changes

## [0.7.13-hotfix.2.4]

- fixed the Uptime / RAM header indicators that could remain stuck on `—`
- moved the lightweight runtime values onto the existing `/api/state` refresh path instead of using a separate browser polling loop
- removed the extra 5-second observability request loop from the header
- populate uptime and RSS memory immediately on page load through the normal dashboard refresh
- no ingest, enrichment, SQLite behavior, classification or memory-management logic changes

## [0.7.13-hotfix.2.3]

- fixed SQLite connection lifetime for the main `/data/inspector.db` database by explicitly closing connections used by DB_PATH context-manager blocks
- prevents each repeated request from leaving another native SQLite connection/file descriptor behind
- this targets the observed growth from 18 startup file descriptors to 67 after 6m42s, including 59 open descriptors for `/data/inspector.db`
- application query/ingest/enrichment logic is unchanged; the fix changes connection cleanup only

## [0.7.13-hotfix.2.2]

- fixed the deep Debug Bundle `/proc`, thread and file-descriptor collectors by injecting the required `Path` import into the generated app
- hardened the Python GC object-type collector so unusual runtime objects cannot abort that diagnostic section
- kept the change debug-only; no ingest, enrichment, polling, cache, worker or normal UI behavior changes
- corrected the bundle manifest to report the actual 0.7.13-hotfix.2.2 diagnostic patch

## [0.7.13-hotfix.2.1]

- made the deep Debug Bundle resilient to individual diagnostic collector failures
- each memory diagnostic section is now isolated and records its own error/traceback instead of aborting the complete ZIP
- the bundle remains usable even when a `/proc`, allocator, SQLite, HTTP-pool or other optional diagnostic source is unavailable
- no ingest, enrichment, polling, cache, worker or normal UI behavior changes

## [0.7.13-hotfix.2]

- debug-bundle-only hotfix focused on locating RSS memory outside Python-tracked allocations
- added raw `/proc/self/status` memory fields including anonymous/file/shmem RSS, data, stack, swap and mappings
- added `/proc/self/smaps_rollup` PSS/private/shared/anonymous memory breakdown when available
- added top process memory mappings from `/proc/self/smaps`
- added cgroup memory usage/limit/event statistics when available
- added glibc `mallinfo2()` allocator statistics when available
- added thread-level diagnostics from `/proc/self/task`
- added file-descriptor classification and target listing
- added SQLite PRAGMA diagnostics for page/cache/journal/mmap state
- added HTTP connection-pool diagnostics for the global requests session
- added top Python GC-tracked object types
- expanded on-demand `tracemalloc` output with top traceback allocation sites
- added process resource-limit diagnostics
- existing application ingest, enrichment, polling, cache and worker behavior is unchanged; the extra diagnostics run only when `Generate Debug Bundle` is requested

## [0.7.13-hotfix.1]

- added Python allocation diagnostics with `tracemalloc` to investigate the long-running memory buildup observed in 0.7.12
- added current and peak Python-traced memory to the observability payload
- added top allocation sites from on-demand snapshots, limited to the top 25 entries
- added garbage-collector counters and tracked object count to the diagnostic payload
- added shallow visibility into large module-level containers and queue-like globals, including type, length and shallow size
- added open-file-descriptor count when `/proc/self/fd` is available
- diagnostics do not retain historical tracemalloc snapshots or change ingest/enrichment scheduling behavior
- diagnostic overhead is intentionally kept bounded by using a configurable 5–20 frame traceback depth (`MEMORY_DIAGNOSTICS_FRAMES`, default 10)
- memory diagnostics can be disabled with `MEMORY_DIAGNOSTICS_ENABLED=0`

## [0.7.12]

- added per-IP reachability status in the Devices tab
- each displayed IP shows a gray/yellow/green/red reachability indicator based on the latest ping result
- added a manual `Ping` button beside every displayed IP
- active private LAN IPs are checked automatically every 4 hours in the background
- first automatic reachability sweep starts 60 seconds after application startup
- ping results persist in SQLite with last-check time, latency and failure reason
- ping targets are restricted to private LAN addresses
- bundled `iputils-ping` in the Docker image so ICMP checks work without host-side packages
- automatic IP probing only considers device IP associations still inside the 12-hour retention window
- configurable with `IP_PING_INTERVAL_HOURS`, `IP_PING_INITIAL_DELAY_SECONDS`, and `IP_PING_TIMEOUT_SECONDS`
- added process uptime and current RSS memory to the UI header
- added a read-only `/api/observability` runtime snapshot
- added a one-click `Generate Debug Bundle` action with sanitized runtime/config/database statistics
- debug bundles explicitly avoid secrets and do not add persistent application log writes

## [0.7.11]

- stale device/IP associations are pruned automatically from `device_ips`
- default IP-observation retention is 12 hours, preventing recycled DHCP addresses from remaining attached to the wrong device indefinitely
- stale-IP cleanup runs immediately at startup and every 30 minutes in the background
- retention is configurable with `DEVICE_IP_RETENTION_HOURS`

## [0.7.10]

- manual device labels are presented in a dedicated Devices-table column
- added visible refresh feedback with a spinner while the dashboard state is loading
- refresh starts immediately on page load instead of waiting for the regular polling interval

## [0.7.9]

- persistent manual device labels stored on `/data`, keyed by stable device identity
- fixed browser MAC lookup URLs so the Devices tab no longer opens the `macvendors.com/<MAC>` API path that returns 404 in a browser
- enrichment attempts now have a persistent minimum retry interval of 24 hours
- a missing or failed enrichment result is not retried on every 10-second `/api/state` poll
- retry cooldown survives container restarts through the `enrichment_attempts` SQLite table
- newly discovered domains are queued for enrichment once and processed serially by the single background worker
