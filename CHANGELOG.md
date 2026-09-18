# Changelog

All notable DNS Inspector changes are tracked here.

## [0.8.5.13]
DNS Destinations map follow-up (Issue #56): splits the single 0.8.5.12
`mapStyle` preset into two independent preferences and replaces the flat
filled world silhouette with an offline dot-matrix world, without changing
`/api/analytics/map`, GeoIP lookup/storage architecture, the bundled offline
world geometry (`WORLD_LAND_D`, still the source data), pan/zoom/Fit/Reset/
keyboard navigation, the Countries/Destinations modes, the Observations/
Unique IPs/Domains metric selector, click/tap+keyboard marker activation, the
persistent detail card or the DB-IP attribution footer.

- **Two independent selectors replace the four flat style presets.**
  `mapBasemap` (Satellite Heat/Satellite Density/Real Map + Pins/Dark NOC)
  controls structural rendering -- background treatment plus how observed
  activity is drawn (heat glow, scattered density particles, a pin glyph, or
  bright NOC-grid points); `mapTheme` (Indigo + Gold/Cyan/BEMO Dark Accent)
  only recolors the intensity ramp via a new `mapThemeColor()`/
  `MAP_THEME_STOPS`, independently of the chosen basemap. `mapIntensityColor()`
  is unchanged and is now simply the "BEMO / Dark Accent" theme's ramp.
- **The world is now a dot matrix, not a flat filled silhouette.** A new
  `mapWorldDots()` samples the same bundled `WORLD_LAND_D` vector rings on a
  grid (plain ray-cast point-in-ring test, `mapPointInRing()`) instead of
  filling one `<path>` -- no new geometry, no raster asset, no network
  access. Observed activity recolors/brightens the real world dots within a
  ratio-scaled radius of each entity's own coordinate ("the data is the
  map"), rather than only drawing a separate overlay on top of an inert
  background.
- **Deterministic, bounded activity particles scale with observed volume.**
  A shared `mapEntityMarkup()` renders both Countries-mode bubbles and
  Destinations-mode clusters: the existing sqrt-scaled anchor circle,
  optional pulse ring and count label are unchanged, plus new
  basemap-appropriate particles/pin (`mapParticleCount()`/
  `mapParticleOffsets()`, capped per basemap) placed around the entity's one
  real coordinate. Placement is seeded from the entity's own stable id (a
  tiny FNV-1a hash + mulberry32 PRNG) rather than `Math.random()`, so a
  country/cluster's cloud renders in the same relative spots on every
  refresh instead of jittering. Everything (hit-area, pulse, particles,
  anchor, label) lives inside one focusable `<g data-country|data-cluster>`
  wrapper, so clicking/tapping/keyboard-activating any particle in a dense
  cluster resolves to the same real entity as before -- no fabricated
  coordinates, and the legend explicitly discloses that particles are an
  intensity visualization, not independent physical servers.
- **True satellite/street raster imagery was judged infeasible and was not
  attempted.** The task's own constraints (offline/self-contained, no
  external tile/API dependency, prefer a compact bundled/vector/point
  representation) rule out real satellite/street map art; all four basemaps
  render the same offline dot-matrix world with a different background
  gradient/grid treatment and activity-rendering style, so "Satellite"/
  "Real Map" are stylistic approximations rather than literal imagery. This
  is called out explicitly rather than silently shipping a mismatch with the
  reference concepts' literal artwork.
- New focused tests in `tests/test_map_basemap_theme_visual4.py` cover the
  basemap/theme constant lists and CSS, the theme color-ramp ordering,
  seeded/bounded particle placement and count, the shared entity-group click/
  keyboard-resolution behavior, the active-dot-recoloring mechanism, the
  "not independent physical servers" disclosure and `/api/analytics/map`
  payload-shape regression. `tests/test_map_visual2_frontend.py`,
  `tests/test_map_navigation_visual21.py`, `tests/test_geoip_destinations_map.py`
  and `tests/test_map_infographic_visual3.py` were updated in place (not
  duplicated) where they pinned the exact 0.8.5.12 `mapStyle`/flat-landmass
  markup this follow-up intentionally replaces.
- No GeoIP/backend change of any kind; stays in the 0.8.5.x series per the
  roadmap gate (0.8.6 is not started).
**This hand-off's sandbox could not execute `pytest`/`python`/`node` at all
-- running any of them, with or without approval, was unavailable in this
non-interactive session**, matching the same limitation recorded against
several recent 0.8.5.x hand-offs (Issues #44, #47, #50, #51, #52, and 0.8.5.12
itself). The change is verified by direct code inspection: every new string/
attribute the new and updated tests assert on was independently
grep-verified against the actual rendered `app.py` template in this session,
and a whole-file brace-balance check (`{` vs `}` count delta) was confirmed
unchanged from the pre-edit baseline despite the size of the diff. The real
CI run (`pytest` + Docker build/health smoke) must confirm the full suite
before this is relied upon, and a manual pass in a real browser (all four
basemaps x three themes, click/keyboard activation on a dense particle
cluster, reduced-motion toggle) is strongly recommended before merge, since
this repository has no headless-browser harness to exercise the new
rendering/interaction code paths automatically.

## [0.8.5.12]
DNS Destinations map visual/interaction redesign (Issue #56): a data-driven
traffic-intensity infographic, not a GeoIP/data-semantics rewrite.
`/api/analytics/map`'s payload shape, the observed-DNS-destination source of
truth, the bundled offline basemap, pan/zoom/Fit/Reset/keyboard navigation,
the Countries/Destinations modes, the Observations/Unique IPs/Domains metric
selector, the four map styles and the DB-IP attribution footer are all
unchanged.

- **Size and color now encode the same traffic intensity.** Every country
  bubble and destination cluster derives both its radius (sqrt-scaled,
  unchanged in spirit) and its fill/stroke color from one shared
  value/max-in-view ratio via a new `mapIntensityColor()` helper -- a
  green -> lime/yellow -> orange -> red gradient, so "large + red" always
  means high observed volume and "small + green" always means low volume,
  readable without opening the detail panel. Markers at or above a high
  ratio also get the existing pulse-ring treatment (previously hard-coded to
  only the single top country), and markers large enough to fit one get a
  compact numeric count label (`mapCompactNumber()`, e.g. `1.2k`).
- **Explicit legend.** A new `.map-legend` panel above the map spells out
  what size and color mean, using the exact same HSL stops as
  `mapIntensityColor()` so the legend can never visually drift from what a
  marker actually renders; its size-metric caption stays in sync with the
  current Observations/Unique IPs/Domains selection via `mapMetricLabel()`.
- **Click/tap is the only interaction needed for details; no delayed hover
  dependency.** Every marker is keyboard-focusable (`tabindex="0"
  role="button"`) and Enter/Space triggers the exact same
  `activateCountry()`/`activateCluster()` handler as a click/tap, so mouse,
  touch and keyboard users all reach the same persistent detail card. The
  card now has an explicit close control (`#map-detail-close-btn`) instead
  of only "click the same marker again," and stays open until dismissed or
  another marker is selected, per the issue's no-hover-tooltip requirement.
- **Restrained, bounded, reduced-motion-respecting animation.** No new
  per-frame or per-poll DOM churn was introduced; the existing
  `html[data-motion="reduced"]` pulse-ring suppression and the global
  `prefers-reduced-motion` transition-duration override both continue to
  apply unchanged to the new intensity-driven markers.
- New focused tests in `tests/test_map_infographic_visual3.py` cover the
  size/color ratio-sharing, the legend's presence and metric-label sync,
  click+keyboard activation parity, the dismissible detail card, and
  regression guards that the map API fields, widget/content ids, pan/zoom/
  Fit/Reset controls, mode/metric/style selectors, world-landmass asset and
  DB-IP attribution footer are all unchanged.
- No GeoIP/backend change of any kind; stays in the 0.8.5.x series per the
  roadmap gate (0.8.6 is not started).
**This hand-off's sandbox could not execute `pytest`/`python` at all --
running either, with or without approval, was unavailable in this
non-interactive session**, matching the same limitation recorded against
several recent 0.8.5.x hand-offs (Issues #44, #47, #50, #51, #52). The
change is verified by direct code inspection: every new string/attribute the
new tests assert on was independently grep-verified against the actual
rendered `app.py` template in this session. The real CI run (`pytest` +
Docker build/health smoke) must confirm the full suite before this is relied
upon, and a manual click/keyboard/legend/reduced-motion pass in a real
browser is recommended before merge since there is no headless-browser
harness in this repository to exercise the new interaction code paths
automatically.

## [0.8.5.11]
Startup reachability fix (Issue #51): real TrueNAS evidence showed the
container reporting RUNNING (socket bound) while `/health` stayed
unanswered for several seconds once the 0.8.5.9/0.8.5.10 deferred initial
GeoIP load started on a fixed 1s clock delay.

- **Readiness gate replaces the fixed delay.** `_geoip_initial_load_worker()`
  no longer sleeps a fixed `GEOIP_INITIAL_LOAD_DELAY_SECONDS` before
  starting -- it waits on `_first_response_ready`, a `threading.Event` set
  once by a new `after_request` hook (`_mark_first_response_ready()`) the
  first time the HTTP service actually finishes serving any response.
  `GEOIP_INITIAL_LOAD_DELAY_SECONDS` (same env var, same default) is now
  only the safety ceiling for a deployment that never receives a single
  request at all, not the thing every startup waits out.
- **Explicit threaded serving.** `serve()` now runs `app.run(..., threaded=True)`,
  so a request already in flight can no longer fully block a concurrent
  request behind it.
- **New `/api/observability` `startup` field** distinguishes "the process is
  running" from "the HTTP service has proven it's ready": `http_ready`,
  `first_response_seconds_after_start`, and `geoip_initial_load_started`/
  `geoip_initial_load_complete`/`geoip_initial_load_seconds_after_start`/
  `geoip_initial_load_duration_seconds`. `/health` itself is unchanged --
  still a plain, fast, unconditional 200, never gated on GeoIP.
- **TrackerDB confirmed already safe.** `refresh_trackerdb()` was already
  started from its own daemon thread inside the `agh-ingest` background
  worker, entirely off the request-serving path; no change was needed
  there.
- No change to GeoIP lookup/map-coverage semantics, the existing
  `GEOIP_LOAD_CHUNK_ROWS`/`GEOIP_LOAD_YIELD_SECONDS` row throttle, or the
  fixed five-long-lived-worker contract.

GeoIP RAM-explosion fix (Issue #52): a real memory-architecture change, not another throttling pass.

- **Eliminated the multi-million-row Python staging list.** `CsvCityGeoIPProvider._load()` used to parse every row into a Python tuple, append it to a `v4_rows` list, sort that list, and only then copy it into compact `array.array` columns -- so a real DB-IP City Lite export (several million rows) could peak at gigabytes of temporary Python objects before the compact representation became usable. Both `CsvCityGeoIPProvider` and `CsvRangeGeoIPProvider` now stream rows directly into `array.array` columns as they're parsed, via a new shared `_CompactRangeTableBuilder` helper: the common case (input already sorted by start IP, true of a real DB-IP Lite export) needs no extra buffering pass at all; an out-of-order source falls back to a single index-permutation pass over the already-compact columns, never over a list of Python tuples.
- **Compact storage for the country provider too.** `CsvRangeGeoIPProvider` previously stored every IPv4/IPv6 range permanently as a Python tuple of boxed ints/strings, plus a second duplicate list of just the start keys for bisecting. It now uses the same array-column-plus-interned-country-table representation `CsvCityGeoIPProvider` already used, with no duplicate start-key list for IPv4.
- **Atomic, sequential reload.** `_reload_geoip_providers()` now builds and swaps the country and city providers one at a time (not both built up-front) and drops its local reference to each as soon as the swap completes, so the old provider plus a second full provider are never both required to stay memory-resident.
- **Allocator cleanup as a secondary mitigation only**, not a substitute for the storage redesign above: a new `_trim_allocator_memory()` runs `gc.collect()` plus a best-effort glibc `malloc_trim(0)` after every reload.
- **New reproducible memory benchmark:** `scripts/geoip_memory_benchmark.py` measures baseline/after-country-load/after-city-load/steady-state/after-repeated-lookups/after-repeated-reload RSS (plus each provider's own compact storage size) against a synthetic dataset it generates on the fly, or a real converted database via `--country-csv`/`--city-csv`. A CI-safe regression guard (`tests/test_geoip_compact_storage.py`) pins loading a moderate synthetic row count to a bounded bytes-per-row budget.
- Lookup semantics, IPv4/IPv6 coverage, map UI/coverage, country aggregation, destination/city lookup results, DB-IP attribution, the 0.8.5.10 load/reload throttling controls, and the Issue #44 03:00/30-day updater are all unchanged.
- **This hand-off's sandbox could not execute `pytest` or run the new benchmark script at all (running Python, with or without `-m`/`-c`, required approval that was never available in this session)** -- the same limitation recorded against the 0.8.5.8 and 0.8.5.10 hand-offs. The change is verified by direct code inspection and by updating/extending the existing test bodies in `tests/test_geoip_destinations_map.py`/`tests/test_geoip_city_map.py`/`tests/test_geoip_auto_update.py` plus new tests in `tests/test_geoip_compact_storage.py`; the real CI run (pytest + Docker build/health smoke) must confirm the full suite and the benchmark's actual numbers before this is relied upon.

## [0.8.5.10]

CI repair (Issue #50, CI run 35317057142) and low-impact GeoIP load throttling.

- **CI fix:** the 0.8.5.9 deferred initial GeoIP load (`_geoip_initial_load_worker()`) was declared in `BACKGROUND_WORKERS` alongside the five long-lived workers, which broke `test_background_workers_are_declared`/`test_start_background_workers_starts_daemon_threads`'s fixed five-worker contract (371 passed / 2 failed). It is now started as its own one-shot daemon thread directly from `main()`, preserving both the deferred-startup behaviour and the original worker contract.
- **GeoIP CSV parse/reload throttling:** `CsvRangeGeoIPProvider`/`CsvCityGeoIPProvider` now parse their CSV database through a new `_iter_csv_rows_throttled()` hook that sleeps briefly after every bounded chunk of rows, so a multi-million-row database (DB-IP City Lite in particular) doesn't monopolize CPU/disk on a modest host during the initial load or a post-update reload. Configurable via `GEOIP_LOAD_CHUNK_ROWS` (default 5000 rows) and `GEOIP_LOAD_YIELD_SECONDS` (default 0.01s); set the latter to 0 to disable throttling. Download bandwidth is unthrottled by design -- the scheduled 03:00/30-day updater (Issue #44) still downloads/converts in its own isolated subprocess, unchanged.
- No change to lookup/ordering/map coverage semantics, the destination map UI, or the Issue #44 scheduled updater's own behaviour.

## [0.8.5.9]

Startup responsiveness fix for GeoIP-backed deployments.

- GeoIP Country/City CSV databases are no longer parsed synchronously during Python module import.
- The application now starts its HTTP server first and performs the initial GeoIP provider load in a background worker.
- The map remains available during loading and reports no geolocation until the providers finish loading; existing lookup/map semantics are unchanged.
- The deferred load can be tuned with `GEOIP_INITIAL_LOAD_DELAY_SECONDS` (default: 1 second).


## [0.8.5.8]

CI repair (Issue #47): fixes the two real test failures left by the
0.8.5.7 GeoIP update scheduler.

- **`next_scheduled_run()` no longer returns an already-consumed instant.**
  An exact hit (`now` equal to today's configured window, e.g. a pass
  starting precisely at `03:00:00`) now counts as passed and rolls to
  tomorrow (`candidate <= now`, not `candidate < now`), instead of handing
  the worker the same instant again and risking a tight re-run loop.
- **`resolve_auto_update_timezone()` returns the real `timezone.utc`
  object for the default/empty-string case**, instead of a `ZoneInfo("UTC")`
  instance that fails identity comparison against `datetime.timezone.utc`.
  Real IANA zone names (including DST-observing ones) still resolve via
  `zoneinfo.ZoneInfo` unchanged.

## [0.8.5.6]

Dashboard widget layout fix, a functional restart control, and a GeoIP
updater watchdog (Issue #43).

- **Dashboard Builder: a real layout grid, not a preset picker.** The
  Analytics `.dash-grid` moves from a 2-column grid with a binary
  `half`/`full` width to a real 4-column grid where every widget picks an
  actual 1-4 column span (`data-w="1".."4"`); `grid-auto-flow:dense`
  back-fills the gaps a mix of spans would otherwise leave, and two
  responsive breakpoints (`1300px`, `900px`) keep the same span proportions
  legible as the viewport narrows instead of only collapsing straight to one
  column. The width toggle button now cycles through all four spans instead
  of flipping between two, and its tooltip shows the widget's current
  width. A `normalizeWidth()` helper migrates a browser's pre-existing
  `dnsInspectorDashboardLayout` (or an older preset) from the old
  `half`/`full` strings to the equivalent span, so nobody's saved
  customization silently resets. No widget was removed, and every widget's
  underlying data/route is unchanged.
- **Restart DNS Inspector.** Settings > System gets a real restart control:
  a two-step in-panel confirm (click once, click again within 5 seconds),
  a `Restarting…` state, and a client-side guard against a second click
  while one is already in flight. It calls a new `POST /api/system/restart`
  (requires an explicit `{"confirm": true}` body; rejects a concurrent
  request with 409). Because the container runs `app.py` directly as PID 1
  with no supervisor (`Dockerfile`'s `CMD ["python", "/app/app.py"]`) and
  Flask's built-in dev server, the backend performs a real restart via
  `os.execv` -- replacing the process image in place rather than depending
  on a Docker restart policy or only restarting a background worker thread.
  `main()` runs again from scratch exactly as on a fresh container start;
  `/data` (a bind-mounted volume the process itself never touches) is
  unaffected. The frontend polls `/health` until the restarted process
  answers again, then reloads the page.
- **GeoIP updater: fix the indefinite `in_progress` regression.** Runtime
  evidence showed `geoip_update.in_progress=true` with both Country and City
  targets' `last_checked_at=null` for several minutes with no success/error.
  `scripts/geoip_updater.py`'s `run_update()` now calls `save_state()` after
  *each* target instead of once at the very end, so a slow target no longer
  hides that an earlier one already finished. `app.py`'s
  `geoip_auto_update_worker()` is also split into a new
  `_run_geoip_update_pass()` that runs the check/update pass in its own
  thread and enforces a whole-pass deadline
  (`GEOIP_AUTO_UPDATE_WATCHDOG_SECONDS`, default 1800s) via `Thread.join()`
  -- a second, independent safety net on top of `geoip_updater`'s own
  per-request connect/read timeouts. If the deadline is hit, a new
  `geoip_updater.mark_stuck_checks_as_timed_out()` records an explicit error
  for whichever target never recorded its own outcome, and
  `_geoip_update_in_progress` is cleared so the next poll can retry --
  `in_progress` can no longer stay stuck at `true` indefinitely.

## [0.8.5.5]

Automatic DB-IP Lite GeoIP updates (Issue #42): the destination map's GeoIP
databases (`docs/GEOIP.md`) no longer require an operator to manually
download, convert and restart every month. A new background worker
(`geoip_auto_update_worker()` in `app.py`, backed by `scripts/geoip_updater.py`)
checks DB-IP Lite for a newer monthly Country/City Lite release on a
configurable cadence (`GEOIP_UPDATE_INTERVAL_DAYS`, default 30 days),
downloads and validates it, converts it with the *same* existing converters
(`scripts/convert_dbip_country_lite.py` / `convert_dbip_city_lite.py` --
no duplicated conversion logic), and atomically replaces
`/data/geoip_country_ranges.csv` / `/data/geoip_city_ranges.csv` only once
the replacement is fully validated. A failed or incomplete check, download or
conversion always leaves the previously working database completely
untouched, and the whole pipeline runs in its own background thread so a
large City Lite download/conversion never blocks DNS ingestion or request
handling. Once a database is replaced, `_reload_geoip_providers()` swaps the
in-process `GeoIPProvider`/`CityGeoIPProvider` and clears their lookup
caches, so the update takes effect immediately -- no container restart
required.

- **Release discovery.** `scripts/geoip_updater.find_latest_release()`
  probes DB-IP's Lite distribution convention
  (`download.db-ip.com/free/dbip-<product>-lite-<year>-<month>.csv.gz`) with
  a cheap `HEAD` (falling back to a closed streamed `GET` if the host
  doesn't support `HEAD`), trying the current month and a bounded number of
  prior months (`GEOIP_UPDATE_LOOKBACK_MONTHS`, default 2) so a release
  published a few days late is still found. Both URL templates are fully
  configurable (`GEOIP_UPDATE_COUNTRY_URL_TEMPLATE` /
  `GEOIP_UPDATE_CITY_URL_TEMPLATE`) -- **this build's environment had no
  outbound network access to re-verify the exact current pattern against
  https://db-ip.com/db/download/ip-to-country-lite /
  ip-to-city-lite live, so an operator should confirm it before relying on
  unattended updates**; a wrong or since-changed pattern is treated the same
  as "no release published this month" (see "Diagnostics" below), never as
  a reason to corrupt or block use of the existing database.
- **Validation before replacing anything.** Every download is checked for a
  successful HTTP status, a real gzip magic-byte header, an optional
  checksum (`GEOIP_UPDATE_COUNTRY_CHECKSUM_URL_TEMPLATE` /
  `..._CITY_CHECKSUM_URL_TEMPLATE`, honoring a bare SHA-256 digest or
  `sha256sum`-style output when a source is configured for one -- DB-IP's
  free Lite tier is not confirmed to publish one, so this is opt-in rather
  than assumed), and a minimum converted row-count floor
  (`GEOIP_UPDATE_MIN_COUNTRY_RANGES`/`GEOIP_UPDATE_MIN_CITY_RANGES`) before
  `download_and_convert()` ever calls `os.replace()` -- the same
  download-to-temp-then-atomic-rename pattern `refresh_trackerdb()` already
  used for TrackerDB.
- **Persistent updater state.** `geoip_updater.load_state()`/`save_state()`
  track, per database, the current release, last checked/succeeded
  timestamps and last error at `GEOIP_UPDATE_STATE_PATH`
  (default `/data/geoip_update_state.json`) -- enough to avoid redundant
  downloads across restarts and to answer "when did this last actually
  update" without container log access.
- **Diagnostics.** `/api/observability`'s new `geoip_update` field reports
  `auto_update_enabled`, `interval_days`, an in-memory-only `in_progress`
  flag, and each target's current release/last check/last success/last
  error/next check. The background worker and `scripts/geoip_updater.py`'s
  CLI both log every check/download/failure.
- **Configuration.** `GEOIP_AUTO_UPDATE` (default `true`),
  `GEOIP_UPDATE_INTERVAL_DAYS` (default `30`), plus the URL/checksum
  templates, row-count floors, state path and timeouts above -- see
  `docs/GEOIP.md` for the full list and defaults.
- **Manual one-shot CLI + dry run.** `python scripts/geoip_updater.py` runs
  a single check/update pass and exits (no-op if already current unless
  `--force`); `--dry-run` exercises the full download/validate/convert
  pipeline without ever replacing the active database or persisting state
  (for CI/troubleshooting); `--status` prints the persisted state without
  making any network call; `--country-only`/`--city-only` scope a run to one
  database.
- **Attribution.** The Settings > About panel and the DNS Destinations map
  widget footer now both show "IP Geolocation by DB-IP" linking to
  https://db-ip.com, satisfying DB-IP Lite's CC BY 4.0 attribution
  requirement for web applications.
- New tests (`tests/test_geoip_updater.py`, `tests/test_geoip_auto_update.py`)
  cover release discovery/fallback, no-op-when-current, download/validation
  failures leaving the active database untouched, atomic replacement,
  checksum verification, state persistence, disabled mode, the hot-reload,
  and manual CLI invocation -- all against a fake HTTP session, never the
  real network.

## [0.8.5.4]

Destination Map Visual 2.1 (Issue #39): fixes the real root cause of the
0.8.5.3 map staying empty on a real deployment, replaces the old single
configured/not-configured boolean with a six-state diagnostic, adds real
pointer/wheel/keyboard map navigation, makes the four map styles genuinely
distinct presets, and improves the bundled offline basemap's geometry --
without changing `/api/analytics/map`'s existing fields, the observed-DNS-
destination semantics, or the bounded destination-IP model from prior
releases.

**Root cause fix: `GEOIP_DB_PATH`/`GEOIP_CITY_DB_PATH` now default under `/data`**

- Both variables previously defaulted to `BASE_DIR/data/...`
  (`/app/data/...` inside the container) while every other persistent path
  (`DB_PATH`, `NEIGHBORS_PATH`, `TRACKERDB_PATH`) already defaulted under
  `/data` -- the directory the Dockerfile creates and the README's
  documented `-v host/path:/data` single-volume mount actually covers.
  `/app/data` is never created by the image and is outside that documented
  volume, so an operator who followed the README and dropped a converted
  CSV into their mounted `/data` never had it picked up -- the map stayed
  honestly empty not because GeoIP wasn't set up, but because the default
  path didn't match the documented deployment convention. The defaults are
  now `/data/geoip_country_ranges.csv` / `/data/geoip_city_ranges.csv`; an
  explicit `GEOIP_DB_PATH`/`GEOIP_CITY_DB_PATH` override is unaffected.
- A new standalone, offline, dependency-free script,
  `scripts/verify_geoip.py`, lets an operator check a converted CSV loads
  and produces real lookups *before* mounting/restarting the Inspector --
  it prints the loaded range count per address family and resolves sample
  IPs against both the country and city databases, and exits non-zero if
  the country database is missing/unreadable/empty.

**Six-state GeoIP diagnostics**

- `/api/analytics/map` gains a `diagnostics` field
  (`_geoip_diagnostic_state()` in `app.py`) that distinguishes
  `not_configured`, `load_failed`, `no_public_destinations`,
  `no_country_matches`, `country_only`, `partial_coordinate_coverage` and
  `full_coverage` -- replacing the old single `provider.configured` boolean
  the map widget used to render just one empty-state banner from. The map
  widget now shows a distinct, honest banner for the "not configured" and
  "database failed to load" cases, and for the "observed IPs exist but none
  matched a range" case in Countries mode.
- `provider` no longer returns the full configured `GEOIP_DB_PATH` -- only
  `db_path_basename` (matching `/api/observability`'s existing `geoip`
  field) and `range_count`, so the payload doesn't leak host filesystem
  layout.

**Real map navigation**

- The destination map SVG is now pointer-drag pannable, wheel/pinch
  zoomable toward the cursor, keyboard-navigable (arrow keys pan, +/-/0
  zoom/reset) when focused, and touch-draggable (`touch-action:none` stops
  the page from scrolling during a drag) -- on top of, not instead of, the
  existing discrete +/- and Reset buttons. A new "Fit" control zooms/pans
  to the currently visible data's bounding box on demand; it never runs
  automatically on refresh, so the viewport doesn't jump while an operator
  is looking at it.
- A drag release over a country bubble/destination cluster no longer also
  toggles its selection (a native `click` firing after a pan gesture used
  to do this).

**Genuinely distinct map styles**

- BEMO Dark, Aurora, White and Minimal now each set their own ocean
  gradient, land fill/glow, grid opacity, marker glow and empty-state
  banner treatment through the existing `--map-*` custom properties scoped
  under `[data-map-style]` -- not just one accent color as in 0.8.6/Visual
  2.0. Minimal additionally disables the top-country pulse-ring animation
  for a lower-noise empty state. Map style remains independent of the
  application theme, unchanged from 0.8.6.

**Basemap polish**

- The bundled offline world-landmass silhouette (`WORLD_LAND_D`) gained
  extra vertices on its longest, flattest edges (the most visible offender
  was a perfectly straight 100px line across the top of Eurasia), reducing
  the "obviously low-poly flat polygon" look without changing the overall
  silhouette/bounding shape bubble and cluster placement rely on. A soft
  blurred duplicate of the coastline renders behind the crisp fill for
  depth on the glow-capable styles. This remains a stylized, hand-authored
  outline, not survey-accurate coastline data.

**Tests**

- New `tests/test_geoip_map_diagnostics.py` (default-path regression via
  the existing `importlib.reload()` pattern, every diagnostic state
  transition, the no-path-leak regression), `tests/test_verify_geoip_script.py`
  and `tests/test_map_navigation_visual21.py` (pan/zoom/keyboard wiring,
  per-style property-count regression, denser basemap point count).

## [0.8.6]

Destination Map Visual 2.0 (Issue #37): turns the 0.8.5.2 static country
bubble map into an interactive, configurable map, while keeping
`/api/analytics/map`, `domain_destination_ips` and the existing
observed-DNS-destination semantics as the unchanged source of truth. No DNS
re-resolution and no invented coordinates were added anywhere in this path.

**Two data modes**

- **Countries** -- the existing 0.8.5.1/0.8.5.2 country-level aggregation,
  now sized by a selectable metric (see below) and restyled.
- **Destinations** -- plots real observed destination IPs by coordinate when
  an optional city/coordinate GeoIP database is configured
  (`GEOIP_CITY_DB_PATH`), grid-clustering nearby points client-side so the
  map stays readable; clicking a multi-point cluster zooms in and the grid
  re-clusters at the finer scale, separating points that were merged before.
  If only a country database is configured, Destinations mode explicitly
  says coordinate-level data is unavailable and offers to switch back to
  Countries -- it never substitutes a country centroid for a real
  city/IP coordinate.

**Optional coordinate/city GeoIP provider**

- A new `CityGeoIPProvider` abstraction (`NullCityGeoIPProvider` /
  `CsvCityGeoIPProvider`, `app.py`) is additive to and fully independent of
  the existing country-only `GeoIPProvider` -- a deployment can have either,
  both, or neither database configured, and the country provider's own
  behaviour is completely unchanged.
- `CsvCityGeoIPProvider` loads `start_ip,end_ip,country_code,country_name,
  city,latitude,longitude` rows into a bounded, indexed runtime
  representation rather than a plain Python list of millions of per-row
  tuples: IPv4 ranges (the overwhelming majority of a real city database)
  are stored as parallel fixed-width `array.array` columns with interned
  country/city string tables, so the small set of distinct names is only
  ever stored once each; the far smaller set of IPv6 ranges stays a plain
  sorted list, matching the existing country provider's approach.
- A new offline, dependency-free, streaming conversion utility,
  `scripts/convert_dbip_city_lite.py`, converts a DB-IP City Lite export
  into that schema, the same way `convert_dbip_country_lite.py` already
  does for the country database. DB-IP City Lite is documented as an
  acceptable source (CC BY 4.0, attribution required -- see
  `docs/GEOIP.md`); no database is committed to the repository.
- `_geoip_city_diagnostics()` and a new `geoip_city` field on
  `/api/observability` mirror the existing country diagnostics, and the
  one-time startup log line now also reports city provider status.

**Backend/API**

- `/api/analytics/map` gains two additive fields: `capabilities`
  (`country`/`coordinates`/`heatmap` booleans reporting what the current
  configuration can actually show) and `destinations` (bounded, deduplicated
  per-IP coordinate points -- two domains observed answering from the same
  IP produce one point with a combined observation/domain count, not two
  overlapping points). Existing `countries`/`unknown`/`coverage`/`provider`
  fields are unchanged in shape; `countries` entries gain one additive
  `unique_ip_count` field. Heatmap is left as a documented follow-up rather
  than a half-working implementation.
- New bounded config: `GEOIP_CITY_DB_PATH`, `GEOIP_CITY_CACHE_MAX_ENTRIES`,
  `GEOIP_MAP_DESTINATION_POINTS_LIMIT` (rendering-size cap only --
  `coverage` is always computed over every observed destination regardless
  of how many individual points are returned).

**Configurable map appearance and metric**

- Four map styles -- BEMO Dark, Aurora, White, Minimal -- expressed as
  `--map-*` custom properties scoped under `[data-map-style]` on the map
  element, entirely independent of the application theme (a BEMO Dark app
  theme with a White map is a supported combination). Dark styles use a
  luminous cyan/teal (BEMO Dark) or violet/cyan (Aurora) point/cluster glow;
  White and Minimal stay restrained.
- A bubble/cluster sizing metric -- Observations (default), Unique IPs or
  Domains -- drives both Countries mode bubbles and Destinations mode
  clusters from each entity's own already-aggregated field.
- Map mode, metric and style are persisted via the existing client-side
  `dnsInspectorPrefs` mechanism (`mapMode`/`mapMetric`/`mapStyle`) -- no
  database migration.
- Zoom (discrete steps, click-to-zoom into a multi-point cluster) and a
  reset/recenter control were added; the bundled offline world-landmass
  basemap, country-bubble rendering path and reduced-motion handling from
  Issue #33/#27 are unchanged.

## [0.8.5.2]

Operator-facing GeoIP setup/verification build (Issue #35): makes the
0.8.5.1 destination/GeoIP map practical to actually populate and verify with
real DNS observations. No change to the map's data model, semantics or
visuals -- functionality/documentation only.

**Practical GeoIP setup**

- `docs/GEOIP.md` gains an operator-ready "Quick setup: DB-IP Country Lite"
  walkthrough: where to get the database, how to convert it, `GEOIP_DB_PATH`
  configuration and container volume/mount considerations, the restart
  requirement, and how to verify the provider loaded and the map has
  non-zero geolocated coverage
- a new small, dependency-free, offline conversion utility,
  `scripts/convert_dbip_country_lite.py`, adds the missing `country_name`
  column to a DB-IP Country Lite export (`start_ip,end_ip,country_code`) to
  produce the Inspector's existing four-column CSV schema unchanged -- it
  streams the input file row by row, supports IPv4 and IPv6, produces
  deterministic output, and makes no network request of its own
- a documented end-to-end smoke-test procedure using the real DNS test
  domains from `nelsonjchen/cloud-geoip-dns-testing` (PowerShell and
  Linux/macOS examples), performed through the operator's normal AdGuard
  resolver path so the Inspector observes AdGuard's real answers; the docs
  explain that the exact returned IP/country can vary because DNS
  geolocation depends on resolver location/EDNS Client Subnet and DNS
  routing responses can be region-specific

**Operator diagnostics**

- a new `_geoip_diagnostics()` snapshot (provider type, configured/not
  configured, database filename -- not the full path, and loaded range
  count) is logged once at startup (never per query) and exposed via the
  existing `/api/observability` route's new `geoip` field, so an operator
  can confirm the provider loaded without needing container log access

**Test coverage**

- new fixture-backed tests for the conversion utility (representative
  IPv4/IPv6 rows, malformed/header handling, CLI usage, round-tripping
  through `CsvRangeGeoIPProvider`), the new diagnostics snapshot/log line,
  a domain with a mix of mapped and unmapped destination IPs, and
  `/api/analytics/map` returning non-zero geolocated coverage over real HTTP
  once a fixture provider is configured -- no external network access
  required

## [0.8.5.1]

Functional DNS Destinations / GeoIP map and instrument gauges (Issue #27):
the first real functional map in Analytics, plus a focused expansion of the
Analog gauge direction from 0.8.5. No new mandatory dependency; one small,
bounded, read-only addition to ingestion (see below), otherwise builds on
the existing data model.

**DNS Destinations map**

- destination IPs are the real A/AAAA answer(s) each AdGuard query actually
  received, captured at ingestion time from that query's own `answer` data
  into a new bounded table, `domain_destination_ips`
  (`extract_observed_answer_ips()` / `_record_domain_destination_ips()`) --
  not `dns_records_cache`, which is an independently, asynchronously
  DNS-over-HTTPS-re-resolved snapshot that can disagree with what a given
  query actually received (see `docs/GEOIP.md`)
- data flow: `domain_destination_ips` -> `normalize_public_ip()` filters out
  private/loopback/link-local/multicast/reserved/unspecified/CGNAT addresses
  -> a local/offline `GeoIPProvider.lookup()` -> aggregated by country in
  `geoip_map_payload()`, served from the new `GET /api/analytics/map` route
- each destination IP's own observation count drives its country's weight,
  not the domain's whole query volume -- a multi-A/AAAA/CDN domain answering
  from more than one country now contributes to each of them, instead of
  having its full request count attributed to whichever IP was checked first
- `GeoIPProvider` is a small abstraction (`NullGeoIPProvider` /
  `CsvRangeGeoIPProvider`) over a CSV range database at `GEOIP_DB_PATH`; no
  database ships in the repository by default, so out of the box every
  destination is honestly reported as unmapped (0% geolocated) rather than
  guessed -- see `docs/GEOIP.md` for the schema, recommended sources
  (DB-IP Lite / MaxMind GeoLite2-Country) and how to supply one
- GeoIP lookups are always local (a bounded, FIFO-capped in-process cache
  over a per-address-family range table, sorted and bisected against a
  precomputed start-key array so each lookup is a real O(log n) binary
  search, not a per-lookup list rebuild) -- never a per-query network call
- the new "DNS Destinations" Analytics widget renders a bounded SVG
  graticule with country bubbles sized by observed destination count (not
  one marker per request), a click-through detail panel (sample
  domains/devices per country) and an explicit `% geolocated` coverage line;
  copy consistently says "observed destinations", never "server locations".
  `COUNTRY_CENTROIDS` only plots a bounded, commonly-hosting-relevant subset
  of countries, so the widget explicitly reports how many geolocated
  countries are plotted vs. the total rather than silently dropping the rest
- bounded by design: aggregation scans at most `GEOIP_MAP_DOMAIN_LIMIT`
  domains (most-recently-active first), retains at most
  `GEOIP_DESTINATION_IPS_PER_DOMAIN_LIMIT` distinct destination IPs per
  domain, and is cached for `GEOIP_MAP_CACHE_SECONDS` per the new dedicated
  route, independent of the `/api/analytics` poll cadence

**Instrument gauges**

- two new bounded-ratio gauges reusing the existing Analog instrument-gauge
  look (ticks/needle/numeric readout): blocked-vs-allowed ratio and active
  devices (of all known devices) -- both have a genuine 0-100% range, unlike
  a raw KPI count
- the gauge needle is a fixed-length line rotated around the hub via CSS
  `transform`, updated in place on re-render rather than the whole gauge
  being replaced, so it genuinely transitions between values via CSS instead
  of jumping (SVG `<line>` endpoints such as `x2`/`y2` are not themselves
  animatable CSS properties); that transition (along with the map's pulse
  ring on the top country) is suppressed under `prefers-reduced-motion` /
  the existing in-app reduced-motion preference

**Analytics payload**

- `/api/analytics` gains one additional field, `total_devices` (count of all
  known devices, regardless of recency) -- the denominator the active-devices
  gauge needs; every existing field is unchanged

## [0.8.5]

Analytics Visual 2.0, Dashboard Builder and a focused runtime/code cleanup
(Issue #23): the second of the three sequential UI releases before BEMO 0.9.
Front-end-only -- no new backend route, no database migration, no change to
the underlying DNS data/API behaviour or metric semantics.

**Analytics Visual 2.0**

- Digital, Analog and Specter are now genuinely distinct presentations of the
  same live/historical metrics, not palette variations of one chart: Digital
  adds hard-edged bars behind the line and a radial "current vs. peak" ring
  for the live card; Analog gets a real instrument-cluster gauge (tick marks,
  needle, numeric center readout) instead of a bare semicircle; Specter adds
  an oscilloscope-style scanning sweep, a live pulse on the last point and a
  radar-style live indicator
- every historical chart now shows a `Current / Average / Peak` readout, and
  every chart (live and historical) marks buckets that are a real statistical
  outlier (mean + 2 standard deviations) against the others in the same
  series, with a factual "Spike: N at &lt;time&gt;" tooltip -- no severity or
  cause is invented, only that the observed count stands out
- `reduce motion` continues to disable the new sweep/pulse/radar animations,
  matching the existing accessibility preference

**Dashboard Builder**

- a new "Customize" mode on the Analytics tab turns every Analytics widget
  (live activity, DNS activity over time, new domains/devices, status
  breakdown, recently-active domains/devices, top activity) into a
  reorderable, resizable, hideable unit: a drag handle plus move-up/move-down
  buttons for reordering (the buttons are the touch- and keyboard-accessible
  path, since HTML5 drag-and-drop is unreliable on touch), a bounded
  half/full width toggle and compact/normal/tall height toggle, and a hide
  toggle per widget
- four presets (`Default`, `Monitoring`, `Compact`, `Investigation`) plus an
  automatic `Custom` state once a layout is hand-edited, a `Reset layout`
  button, and a `dnsInspectorDashboardLayout` `localStorage` object so the
  chosen layout persists per-browser; normal (non-customizing) Analytics
  stays visually unchanged from 0.8.4 aside from the new toolbar
  - a mobile media query keeps every widget full-width regardless of its
    saved width, since half-width has no useful meaning on a single-column
    layout

**Destination / GeoIP map (not implemented this release)**

- investigated per the task scope; the project has no IP geolocation source
  today (`requirements.txt` is still just `flask`/`requests`), and a DNS
  hostname does not by itself identify where a resolved destination is
  actually served from (CDN/anycast/multi-region), so a truthful map needs a
  real GeoIP data source, not the existing RDAP/company "country" field.
  Adding a GeoIP dependency for this alone was judged out of scope for a
  "lightweight home/server deployment" cleanup release; see `ROADMAP.md` for
  the documented follow-up instead of a fabricated domain-to-country map

**Runtime / code cleanup**

- the background `/api/state` poll no longer rebuilds the (potentially
  hundreds-of-rows) Overview and Devices table `innerHTML` while their tab
  isn't visible; the fetched rows are still cached and the table is rendered
  from cache the moment its tab becomes active, removing that DOM work from
  every poll tick spent on the Analytics tab (and vice versa)
- removed four leftover section-marker comments (`SQLITE CLOSE PATCH`,
  `DEEP DEBUG BUNDLE PATCH`, etc.) referencing the retired generated-patch
  chain that `docs/CURRENT_STATE.md` already documents as no longer the
  runtime source of truth
- removed the `.analytics-timeline-grid` / `.activity-feed-grid` /
  `.analytics-feed-heading` / `.live-gauge` CSS rules and the old
  `liveGaugeSvg()` function, all made fully dead by the Dashboard Builder and
  Analytics Visual 2.0 markup changes above

## [0.8.4]

Settings, themes and configurable Analytics visual styles (Issue #22): the
first of three sequential UI releases before BEMO 0.9, turning the 0.8.3
visual overhaul into a configurable product without touching the DNS data
model or starting BEMO Core work. Front-end-only -- no new backend route, no
database migration, no change to the existing DNS data/API behaviour.

**Settings**

- a gear button in the shared shell opens a Settings dialog (a native
  `<dialog>`, not a fourth primary tab, so the Overview/Devices/Analytics
  navigation stays uncluttered) with six sections: Appearance, Dashboard,
  Monitoring, Diagnostics, System and About
- Diagnostics and System read the existing `/api/observability` and
  `/health` routes; About reuses the existing `version`/`is_dev_environment`
  template context -- no section was invented without real data behind it
- preferences persist as a single `dnsInspectorPrefs` localStorage object
  (client-side only, per the 0.8.x constraint against a database migration
  for UI preferences) and survive page reloads

**Themes**

- four coherent themes on top of the existing token-driven design system --
  BEMO Dark (the current/default look), BEMO Light, BEMO Aurora (a dark
  observability theme with cyan/blue/violet accents) and BEMO Natural
  (dark/warm/sage/teal) -- plus a System option that follows the OS
  `prefers-color-scheme`
- each theme only redeclares surface/border/text/semantic tokens; applied
  via `html[data-theme]` before first paint to avoid a flash of the wrong
  theme, and consistent across Overview, Devices, DNS views and Analytics
  because they all render through the one shared `HTML` template
- a curated accent-color preset (6 choices) recolors links/active states
  via `--accent`, with `--accent-strong`/`--accent-soft`/`--accent-contrast`
  now derived from it through `color-mix()`; the semantic status variables
  (`--sem-ok`/`--sem-blocked`/`--sem-warn`/`--sem-crit`/`--sem-live`) are
  never touched by an accent choice, so Allowed/Blocked/Warning/Critical
  keep their meaning regardless of theme or accent
- Comfortable/Compact/Dense density (spacing/typography tokens only) and an
  explicit reduce-motion toggle (in addition to the OS setting)

**Monitoring**

- the existing client-side refresh/poll cadence is now a bounded preference
  (5/10/15/30/60s, or the server's configured default) instead of a fixed
  value baked into the page; no new polling loop or backend work was added
- a "default view" preference (Last viewed / Overview / Devices / Analytics)
  sits alongside the existing last-viewed-tab memory

**Analytics visual styles**

- a reusable `renderMetricVisual` abstraction now backs every Analytics
  chart (the live-activity sparkline and the three historical timelines),
  with three selectable presentation styles -- Digital (the 0.8.3 default:
  a straight line, monospace live readout), Analog (a smoothed trace plus a
  semicircular gauge on the live card) and Specter (a smoothed, glowing
  gradient-filled trail using the current accent) -- switching styles only
  changes how the same underlying `{count}` points are drawn, never what
  they mean; no metric was invented and no new data source was added

## [0.8.3]

UI overhaul (Issue #20): a single "Inspector BEMO" visual design system
replaces the ad-hoc styling that had accumulated across Overview, DNS
Inspector, device/IP views, shared shell/navigation and Analytics. This is a
front-end-only change — no API contract, route, database schema or JSON
payload shape changed.

**Design system**

- a token layer (`--surface-*`, `--border*`, `--text-*`, `--accent*`,
  `--radius-*`, `--space-*`, `--shadow-*`, `--font-*`, `--transition`) drives
  color, spacing, radius, shadow and typography everywhere; the existing
  semantic status variables (`--sem-ok`/`--sem-info`/`--sem-blocked`/
  `--sem-warn`/`--sem-crit`/`--sem-live`) are unchanged in name so the
  Analytics charts and status pills keep working without a JS change
- every existing selector (cards, tables, tags, status pills, filters,
  pager, device chips, ping indicators, tabs, forms) is re-styled through
  those tokens rather than renamed, so Python-rendered and JS-rendered
  markup stay visually identical
- a dedicated `.empty-state` treatment for "no data yet" / "no activity yet"
  messages, used consistently across Analytics charts, recent-activity feeds
  and device/IP detail tables

**Shell / navigation**

- the header is now a proper product shell: an "Inspector BEMO" platform
  label above the "DNS Inspector" module title, with the observability
  strip and live status grouped to one side
- the tab bar gained inline SVG icons and a pill-style active indicator;
  the DEV banner keeps its exact `DEVELOPMENT ENVIRONMENT` / `NOT
  PRODUCTION` / `dev-badge` markup so `tests/test_environment.py` still
  passes, with the emoji glyph replaced by an inline SVG warning icon

**Analytics**

- the live-activity card and sparkline get a distinct accent treatment so
  live data reads as a first-class component, not a bolted-on panel; the
  same status colors and legend now match the rest of the app
- no changes to the live sampling behavior, the `/api/analytics` endpoint,
  or the historical range logic

**Polish**

- replaced a stray non-English loading-state string with English text
- focus-visible outlines added across interactive controls so keyboard
  focus is never conveyed by color alone

## [0.8.2]

Analytics overhaul (Issue #16): the Analytics tab is redesigned as an
observability dashboard instead of four static "most active" lists. Every
number comes from data the ingestion pipeline already persists — no new
sampling pipeline, no time-series database, no per-sample persistence.

**Live activity**

- a "Live activity" card shows queries observed in the last 60 seconds, with
  an in-browser rolling sparkline (up to 100 samples)
- the sample rides the existing `/api/state` refresh loop (`live` field) at
  the app's normal refresh cadence rather than a second, faster polling
  loop — see the "Analytics Live Activity" note in `ROADMAP.md`
- recently active domains and devices lists, sourced from `domains.last_seen`
  / `devices.last_seen`

**Historical trends**

- new `GET /api/analytics?range=1h|6h|24h|7d` endpoint: DNS query volume
  (bucketed from `processed_queries.seen_at`, the query-log dedup table the
  ingest worker already writes), new-domains and new-devices-discovered
  series (bucketed from `first_seen`), and a domain status breakdown
  (Allowed/Blocked/Mixed/Unknown)
- `processed_queries` is capped at 100k rows (unchanged); buckets older than
  the oldest retained row are reported as `null`, not a fabricated zero
- four new indexes (`idx_domains_last_seen`, `idx_domains_first_seen`,
  `idx_devices_last_seen`, `idx_devices_first_seen`) back the new queries

**Visual semantics**

- a consistent color palette (`--sem-ok`, `--sem-info`, `--sem-blocked`,
  `--sem-warn`, `--sem-crit`, `--sem-live`) applied across the new charts,
  stat tiles, status legend and activity rows; text/labels are always shown
  alongside color, never color alone

**Tests**

- `tests/test_analytics.py`: the new data-selection functions, the new
  route, the `live` field on `/api/state`, and the new indexes

## [0.8.1]

Fixes D-1: `/api/observability` returned HTTP 500 on every request because a
blank line separated the `@app.route('/api/observability')` decorator from the
function it was meant to decorate, binding the route to the
`_memory_diagnostics_container_summary` helper instead of `api_observability`.

- moved the decorator so it directly precedes `def api_observability():`
- `_memory_diagnostics_container_summary` is no longer a registered route
- added regression tests asserting `/api/observability` returns 200 with the
  expected payload shape, and that the route maps to the `api_observability`
  endpoint

## [0.8.0-dev.1]

Foundation release. No new features, no intentional behaviour changes.

**The repository is now the application.**

- removed the build-time patch chain: the Dockerfile no longer copies and executes sixteen `build_*.py` scripts that rewrote `app.py` during the image build
- `app.py` now contains the complete program (3,205 lines). Up to 0.7.14 the committed source was 2,062 lines and the program that actually ran was 3,173 — roughly 1,100 lines of live behaviour existed only inside the Docker image
- deleted all seventeen `build_*.py` scripts, including `build_ui_patch_v2.py`, which was already unreferenced by any build

**Entry point**

- startup moved from an inline `if __name__ == "__main__"` block into `main()`, with `serve()`, `start_background_workers()` and a `BACKGROUND_WORKERS` declaration
- the same steps run in the same order; the ingest thread is now named `agh-ingest` rather than taking Python's default thread name
- this is the only difference between the 0.7.14 runtime source and 0.8.0; every other line is byte-identical

**Tests**

- added a 55-test pytest suite covering configuration, database schema and migration, the HTTP surface, startup and route registration, and domain status classification
- added `tests/test_source_integrity.py`, which fails if build-time patch scripts or Dockerfile source mutation are ever reintroduced
- the suite is hermetic and deterministic: temporary database, no AdGuard instance, no outbound network
- added `requirements-dev.txt` and `pytest.ini`

**Build and CI**

- CI gained a `test` job; `build-and-push` now depends on it, so nothing is published unless the suite passes
- CI now builds the image and verifies the container starts and answers `/health` before the release step
- CI also runs on pull requests, without publishing
- the Dockerfile declares a `HEALTHCHECK` against `/health`
- `.dockerignore` excludes tests and documentation from the image

**Documentation**

- `docs/ARCHITECTURE.md` gained a concrete map of the real code: runtime shape, region line ranges, database ownership, configuration and boundedness
- added `docs/MODULARIZATION.md` with the planned module boundaries, a suggested version sequence, and a register of deferred findings

**Known issue carried forward unchanged**

- `/api/observability` is bound to the wrong function and returns 500. This was introduced by the patch chain in 0.7.12 and is preserved exactly in 0.8.0 rather than fixed, because 0.8.0 is scoped to the foundation. See D-1 in `docs/MODULARIZATION.md`. Recommended as the 0.8.1 scope.

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
