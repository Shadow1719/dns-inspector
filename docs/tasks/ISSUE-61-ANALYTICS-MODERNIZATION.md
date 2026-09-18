# Issue #61 — Analytics UI modernization — scope record

Status: PARTIALLY IMPLEMENTED (0.8.5.13); remaining scope deferred, not dropped

This document was written by the implementing agent (not supplied as a
pre-existing `READY` task contract) because Issue #61's request spans several
independently large pieces of work -- a P0 performance fix, a real
configurable basemap engine, a full charts/gauges visual rewrite -- with no
existing task document scoping them, unlike `ISSUE-37-MAP-VISUAL-2.md`'s
precedent for the original destination map redesign. It records what was
implemented, what was deliberately deferred, and why, per `AGENTS.md`'s
"smallest correct change" / "one coherent change per version" discipline and
this repository's own established pattern of documenting deferred scope
(see `ISSUE-37-MAP-VISUAL-2.md`'s Heatmap-mode deferral) rather than shipping
a half-working version of everything at once.

**Constraint that shaped every scoping decision below:** this hand-off's
sandbox could not execute Python, `pytest`, or the application at all (the
same limitation recorded against nearly every 0.8.5.7-0.8.5.12 hand-off in
`docs/CURRENT_STATE.md`). Every change in this release was verified only by
direct code inspection and by grep-verifying new strings against the
rendered template -- never by an actual test run or a browser. Given that,
attempting a large, correctness-sensitive rewrite (e.g. switching the map's
coordinate projection to real Mercator tiles) fully blind was judged too
risky to ship in the same change as a P0 fix; see "Deferred" below.

## Implemented in 0.8.5.13

### 1. P0 responsiveness fix

Root cause: `fetchAnalyticsFull()` called `fetchDestinationMap()`
unconditionally on every `/api/analytics` poll tick, with no in-flight
guard, no request cancellation, and no check for whether the map's
aggregated data had actually changed.

- The destination map now polls on its own bounded timer, independent of
  the analytics poll (`mapRefreshMs()` -- at least 3x the analytics interval,
  never faster than 20s).
- Both `fetchAnalyticsFull()` and `fetchDestinationMap()` use a real
  `AbortController` (aborting their own previous in-flight request) plus a
  monotonic sequence number, so a slow response can never overwrite state a
  newer request already replaced.
- `fetchDestinationMap()` has an in-flight guard so a slow tick can't pile
  up overlapping requests.
- `mapPayloadFingerprint()` lets an unchanged poll response skip the full
  SVG rebuild entirely; interaction-triggered re-renders (mode/metric/
  basemap/theme/zoom/pan/selection) are untouched and still redraw
  immediately, since they call `renderDestinationMap()` directly.
- A new client-side perf trace (`window.__dnsInspectorPerf`, surfaced in
  Settings > Diagnostics) records HTTP-fetch time separately from render
  time for the last 20 analytics/map cycles, to help attribute a slow
  interaction to network vs. main-thread rendering vs. GeoIP work.
- Animation (the pulse ring, gauge needle transitions) was already CSS-
  driven and reduced-motion-aware with no JS animation loop -- inspected and
  confirmed already compliant with "animation must never require continuous
  polling," no change needed.
- Background GeoIP loading was already deferred/throttled/yielding as of
  0.8.5.9-0.8.5.11 (see `docs/CURRENT_STATE.md`); this task did not touch
  GeoIP storage/loading architecture, per the task's own explicit
  constraint.

**Not done:** full SVG/DOM node reuse (diffing individual bubbles/clusters
in place rather than replacing the map's `innerHTML` on every genuine data
change). The fingerprint-skip above eliminates the *redundant* rebuilds that
were the actual reported problem (identical data re-rendered every few
seconds); a real diffing renderer for the case where data *has* changed is a
larger, separable optimization not required to fix the reported bug.

### 2. Root-caused cleanup items

- `mapCompactNumber()`'s two regex literals had inconsistent backslash
  escaping in the plain (non-raw) `HTML` Python string -- fixed to be
  consistent; the JS output is byte-for-byte identical either way, only the
  Python-level `SyntaxWarning` is gone.
- `refresh_trackerdb()`'s SQL-dump importer (`_execute_sql_file()`) now
  skips a dump's own literal `BEGIN TRANSACTION;`/`COMMIT;` lines
  (`_execute_sql_dump_statement()`/`_SQL_DUMP_TRANSACTION_CONTROL_RE`) since
  `conn.executescript()` already issues an implicit commit before every
  statement it's given here; running the dump's own `COMMIT;` on top of that
  was raising `sqlite3.OperationalError: cannot commit - no transaction is
  active`, exactly matching the debug log evidence.

### 3. Basemap vs. Theme split (DNS Destinations map)

- `dnsInspectorPrefs.mapStyle` (BEMO Dark/Aurora/White/Minimal, one
  `--map-*` CSS variable set) is replaced by two independent preferences and
  widget selectors:
  - **Basemap** (`mapBasemap`): Dark NOC/Urban, Satellite Heat, Satellite
    Density, Real Map/Pins. Controls the `--map-*` background/land/grid/
    vignette CSS variables *and* which marker rendering strategy
    `mapEntityMarkerSvg()` draws -- a pulse-ring bubble, a heat/glow blob, a
    deterministically-seeded particle field anchored on the real observed
    coordinate, or a real pin glyph. These are four different rendering
    strategies over the same underlying data, not four recolors of one
    circle.
  - **Theme** (`mapTheme`): BEMO Dark Accent, Indigo + Gold, Cyan. Controls
    only the point/glow CSS variables and its own low-to-high intensity
    color ramp (`MAP_THEME_INTENSITY_STOPS`), independent of which Basemap
    is active -- any of the 3 themes pairs with any of the 4 basemaps (12
    combinations), matching the issue's "4 basemaps x 3 themes, not 7
    unrelated styles" requirement.
- A browser with an older saved `mapStyle` preference migrates to a
  matching `mapBasemap` default (`MAP_STYLE_TO_BASEMAP_MIGRATION`) instead
  of silently losing its choice, the same care the Issue #31 layout-merge
  fix took for the Dashboard Builder.
- Satellite Density's particles are seeded deterministically from the
  entity's own stable key (`seededRandomFor()`/`mulberry32()`), so refreshes
  never make the map visually jump for unchanged data, and are explicitly a
  bounded visualization of volume around the real anchor coordinate -- never
  an additional claimed destination, matching the issue's own "never
  fabricate real coordinates" requirement.
- `/api/analytics/map` gained one additive field, `basemap` (see below);
  `countries`/`destinations`/`coverage`/`capabilities`/`provider`/
  `diagnostics` are all unchanged.

### 4. Configurable basemap tile-source plumbing (backend only)

Two new optional env vars, `MAP_TILE_URL_TEMPLATE`/`MAP_TILE_ATTRIBUTION`,
unset by default (no hard-coded vendor, no required API key, no runtime
network access unless an operator explicitly opts in), are surfaced via
`/api/analytics/map`'s new `basemap` field
(`{tile_url_template, attribution, configured}`). This exists so a future
change can wire an actual tile layer in without another backend change.

## Deferred (not implemented in 0.8.5.13)

### A. Real online raster-tile compositing

The issue's most emphatic requirement is that "the current low-poly SVG
world must actually disappear as the primary map background in the new
real-map/satellite modes." Doing this correctly requires real map tiles
(Satellite/Real Map/street imagery), which are served as Web
Mercator (EPSG:3857) XYZ/TMS tiles addressed by discrete zoom/x/y -- a
fundamentally different projection from this widget's current 720x360
equirectangular projection (`mapProject()`/`mapViewBoxAttr()`/the existing
pan-zoom math), which the destination coordinates, clustering, and hit-
testing are all built on.

Correctly bridging the two requires reprojecting the pan/zoom/viewport math
to Web Mercator so real tiles and the plotted destination points/clusters
stay pixel-aligned. That is a substantial, correctness-sensitive rewrite of
the map's coordinate system -- a misalignment bug here would visually
misplace real observed-destination data, which this project treats as a
hard correctness requirement (see `ISSUE-37-MAP-VISUAL-2.md`'s "Honest data
semantics" section). Attempting that rewrite with zero ability to execute
the code or look at it in a browser (this session's sandbox constraint,
recorded above) was judged too risky to ship blind in the same change as a
P0 performance fix.

**What exists today as a foundation:** the tile-source config plumbing
(env vars, additive payload field, attribution reporting) from section 4
above. The widget's basemap note (`syncMapBasemapNote()`) tells an operator
who configures `MAP_TILE_URL_TEMPLATE` that the source was received but
tile rendering isn't wired in yet, rather than silently ignoring their
configuration or showing incorrect attribution for a layer that isn't
actually drawn.

**Recommended follow-up scope:** a dedicated task that (1) reprojects
`mapProject()`/the pan-zoom/viewBox math to Web Mercator (or introduces a
small, dependency-justified tile-rendering helper scoped only to the
basemap/navigation layer, per the issue's own allowance), (2) composites
tiles behind the existing vector/marker layers, (3) implements the "fails
clean" fallback to the bundled offline vector map when a tile request 404s
or the operator hasn't configured a source, and (4) is validated in a real
browser before merge, since this repository has no headless-browser test
harness to catch a coordinate-projection bug automatically.

### B. Charts/gauges 2026 visual rewrite (issue sections 5-7)

Not started in this release: the area/spline time-series redesign, stacked/
segmented status bars, heatmap/calendar activity view, ranked bars,
sparkline KPI cards, and the gauge/KPI instrument redesign
(`digitalRingSvg()`/`analogGaugeSvg()`/`specterRadarSvg()`/
`instrumentPercentGaugeSvg()`/`renderMetricVisual()`).

This is a large, separable body of work (multiple new chart primitives, a
full visual-language pass, its own reduced-motion/empty-state/interaction
requirements) that does not depend on the map work above and can be
implemented and validated independently. Bundling it into this release would
have meant shipping a much larger unverified diff against the same
zero-test-execution constraint, well past "smallest correct change." No data
semantics change either way -- deferring this does not block any other
Analytics functionality.

**Recommended follow-up scope:** a dedicated task/PR per the issue's
sections 5-7, ideally with its own task document the same way this one and
`ISSUE-37-MAP-VISUAL-2.md` were written, so the visual direction (2026
observability/NOC aesthetic, specific chart types per metric) is an explicit
contract rather than inferred by the implementing agent.

## Non-goals (unchanged from the issue)

- No GeoIP lookup/storage architecture change (explicit task constraint).
- No 0.8.6 work (roadmap gate stays in place).
- No invented coordinates/destinations; Satellite Density's particles are a
  bounded, deterministic visualization of volume around a real anchor, never
  an additional claimed destination.
- No hard-coded commercial tile vendor; the tile-source abstraction is
  strictly operator-opt-in.

## Git workflow

- Branch: `claude/issue-61-20260918-0930`, based on `dev` at `0.8.5.12`.
- Targets `dev`. Not merged by the implementing agent.
- Report the tests added, and that the real CI run (`pytest` + Docker
  build/health smoke) must confirm the full suite before this is relied
  upon, since this session could not execute either.
