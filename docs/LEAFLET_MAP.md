# DNS Destinations map: Leaflet + OpenStreetMap real map viewport (Issue #69)

This document covers the DNS Destinations map's renderer, which now uses
[Leaflet](https://leafletjs.com/) with [OpenStreetMap](https://www.openstreetmap.org/)
standard tiles as its actual geographic viewport. It supersedes the amCharts
map experiment (`docs/AMCHARTS_MAP_POC.md`, now removed) and the fixed-image
basemap approach it replaced. It does not change `/api/analytics/map`'s
payload, the GeoIP lookup/storage architecture, or the observed-DNS-
destination semantics described in `docs/GEOIP.md` -- this is a frontend
rendering change only.

## Why this replaced the previous renderer

The pre-existing renderer drew its "basemap" as a fixed CSS/SVG background
(a bundled offline dot-matrix world, or a single stretched zoom-0 tile image
for three of its four presets -- see `docs/MAP_BASEMAP.md`) underneath a
separately hand-projected marker overlay. That background did not pan/zoom
with the markers; only the overlay's own `mapZoom`/`mapViewCenter` moved.
Leaflet is a real slippy-map engine: the tiles, the markers and the map's
own pan/zoom state are all the same scene, so zooming or panning genuinely
moves and rescales geography, tiles and markers together, with no fixed
image left behind underneath.

## Architecture

- `static/leaflet-map.js` is the only new file. It loads after the main
  inline `<script>` in `app.py`'s `HTML` template (same load-order pattern
  the amCharts experiment used) and, if `window.L` (the Leaflet library) is
  available, replaces `window.renderDestinationMap` -- the single function
  `fetchDestinationMap()` already calls with whatever it fetched.
  `fetchDestinationMap()` itself, and its Issue #61 AbortController/
  monotonic-sequence/in-flight/fingerprint protections, are completely
  untouched; this file only ever changes what happens to an already-fetched
  payload.
- **Fallback contract:** if `window.L` never loads (offline build, blocked
  CDN, ad blocker) this file returns immediately without touching
  `window.renderDestinationMap`, so the legacy SVG renderer already defined
  earlier in the same template stays in control. If the library *did* load
  but `L.map()` itself throws (checked lazily, on the first real payload),
  the captured original renderer is called directly as a real fallback --
  not just a console warning -- so the widget never renders blank.
- **Selection stays synchronized with the country breakdown panel (Issue
  #63)** by calling the exact same shared `mapSelectCountry()` a breakdown
  row click already calls, and the same `renderMapDetail()`/`mapLastPayload`
  state both surfaces already share -- there is no second, independent
  selection/detail implementation (the amCharts POC had one; this renderer
  intentionally does not, per this issue's own guidance to treat that POC
  as reference only).
- **Future-ready layers:** `state.layers` is a small named
  `{ countries, destinations }` map of real `L.layerGroup()`s. Additional
  datasets this issue explicitly says not to implement yet (Google/AWS/
  Azure/Cloudflare/CDN PoPs, a future `infrastructure_locations` table) can
  register another named layer group here later the same way, without
  replacing the map engine.

## Countries and Destinations modes

- **Countries mode** plots one marker per geolocated country with a plotted
  centroid (`data.countries[].centroid`, unchanged), sized by the selected
  metric (Observations/Unique IPs/Domains, via the existing
  `mapMetricValue()`) and colored via the existing `mapThemeColor()` ramp.
- **Destinations mode** plots real observed destination coordinates
  (`data.destinations[]`), grid-clustered by real lat/lon (independent of
  the legacy SVG's own pixel-space `clusterDestinationPoints()`, which
  assumes a fixed equirectangular canvas that no longer applies once Leaflet
  owns real geographic coordinates). The cluster grid shrinks as Leaflet's
  own zoom level increases; clicking a multi-point cluster below the map's
  max zoom zooms in and re-clusters at the new zoom, exactly like the
  legacy renderer's own staged reveal.
- Both modes use `L.marker` with a small `L.divIcon` bubble (not
  `L.circleMarker`) specifically so Leaflet's built-in keyboard support
  (`tabindex`/`role="button"`/Enter-to-activate on the marker icon) keeps
  working, matching the legacy SVG renderer's own Issue #63 keyboard
  accessibility.

## OpenStreetMap tiles and attribution

Leaflet is loaded unconditionally from `unpkg.com` (`leaflet@1.9.4`, no
integrity/crossorigin attributes -- matching the existing amCharts CDN
include's own convention already in this codebase); the map's only tile
layer is OpenStreetMap's standard raster tiles
(`https://tile.openstreetmap.org/{z}/{x}/{y}.png`), with Leaflet's built-in
attribution control left enabled so the required "© OpenStreetMap
contributors" attribution is always visible in the map's corner -- never
silently removed.

**Operator note:** OpenStreetMap's tile usage policy discourages heavy
automated/production embedding without a distinct `User-Agent` and
reasonable request volume, and recommends self-hosting or a commercial
tile provider for anything beyond light/development use. This is now the
map's *only* basemap (not one of several opt-in presets), so an operator
running DNS Inspector at real scale should review
<https://operations.osmfoundation.org/policies/tiles/> and consider
pointing `OSM_TILE_URL`/`OSM_ATTRIBUTION` in `static/leaflet-map.js` at a
self-hosted or commercial tile source if warranted.

## Scope decisions

- The legacy SVG renderer's four `mapBasemap` presets (Satellite Heat/
  Density, Real Map + Pins, Dark NOC) were a stylized-background concept
  tied to the old fixed-image approach; they don't apply once Leaflet/OSM
  tiles are the real map viewport. The `map-basemap-select` control is
  hidden once Leaflet successfully initializes (the stored `mapBasemap`
  preference itself is left untouched, so it still governs the legacy SVG
  fallback if this ever falls back to it). The `mapTheme` color-ramp
  preference is unaffected and still recolors markers in both renderers.
- Clicking a country in the right-hand breakdown panel selects/highlights
  the same marker and opens the same detail card a direct marker click
  would (Issue #63 parity), but -- unlike the legacy SVG renderer's own
  `centerZoom` behavior -- does not also recenter/zoom the Leaflet viewport
  onto it. Re-centering a real slippy map on every breakdown click risked
  fighting a user's own in-progress pan/zoom in a way the old fixed-canvas
  `mapZoom`/`mapViewCenter` re-render didn't; "Fit" already provides an
  explicit, user-initiated way to frame all currently plotted markers.
- Marker clustering is a small bounded lat/lon grid heuristic (see above),
  not the `leaflet.markercluster` plugin -- avoids a second external
  dependency for a widget whose destination-point count is already bounded
  server-side (`GEOIP_DESTINATION_IPS_PER_DOMAIN_LIMIT`, `GEOIP_MAP_DOMAIN_LIMIT`, etc.).

## Issue #72 follow-up: country list UX, basemap layer control, DTC pins

- **Selected-marker contrast.** The previous `.leaflet-dns-marker-selected`
  style was a single 2px white outline, reported as too subtle to see
  against a busy OSM/Tracestrack tile. It's now a white-then-dark double
  ring plus a soft shadow (`box-shadow:0 0 0 3px #fff,0 0 0 6px #0b0f14,...`),
  which stays legible against both light and dark tile imagery, and the
  selected marker is drawn above its neighbors via a real Leaflet
  `zIndexOffset`, not CSS `z-index` alone.
- **Double-click to focus.** A single click on a country row in the
  breakdown panel keeps its existing Issue #63 selection/detail behavior
  unchanged. A **double**-click additionally pans/zooms the real Leaflet
  viewport to that country's centroid via a new exported
  `window.leafletFocusCountryOnMap(code)`, called from the row's `dblclick`
  handler in `app.py`. This was necessary because `mapSelectCountry()`'s
  existing `centerZoom` option only ever updates `mapZoom`/`mapViewCenter`,
  the *legacy SVG renderer's* own pan/zoom state -- Leaflet owns its own
  independent viewport and was never looking at those variables, which is
  why the scope decision above ("breakdown click does not recenter Leaflet")
  was correct for single-click but needed an explicit additional path for
  the new double-click requirement.
- **Basemap layer control.** `ensureMap()` now builds Leaflet's own native
  `L.control.layers()` (a real, built-in layer-switcher UI in the map's
  corner) from a small `LEAFLET_BASEMAPS` registry, instead of a single
  hard-coded OSM tile layer. OpenStreetMap Standard remains the default,
  always-available, no-key basemap. **Tracestrack Topo** is a second
  selectable basemap; because it requires a personal Tracestrack API key
  (free registration at <https://tracestrack.com/>) and DNS Inspector has no
  existing backend secret-plumbing pattern for third-party map keys, the key
  is a new plain client-side-only `dnsInspectorPrefs.tracestrackApiKey`
  field (same architecture as every other map preference -- no new
  persistence layer), entered via a "Tracestrack API key" text field next to
  the other map controls. Leaflet's own `{key}` URL-template substitution
  (`options.key`) reads it, and `window.mapUpdateTracestrackKey(key)`
  updates the already-created layer in place when the field changes, so no
  reload is required. **This session's sandbox had no outbound network
  access to re-confirm Tracestrack's exact current tile URL path/style
  token/file extension or attribution wording live** -- the same disclosed
  limitation recorded against numerous other 0.8.5.x hand-offs in
  `docs/CURRENT_STATE.md` (e.g. the DB-IP update URL templates). The URL
  lives in one overridable constant, `TRACESTRACK_TILE_URL_TEMPLATE` in
  `static/leaflet-map.js`, specifically so an operator/maintainer can
  correct it without touching any other map code once confirmed against
  Tracestrack's current documentation. `LEAFLET_BASEMAPS` is the extension
  point for adding further basemaps later (Issue #72 Section 5).
- **DTC / Data Centre pins (Section 3 investigation).** A new, additive,
  off-by-default overlay layer (`state.layers.dtc`, toggled via the same
  layer control's overlay checkbox, labeled "Data Centers (beta)") plots a
  small, explicit, hand-maintained seed list (`DTC_LOCATIONS` in
  `static/leaflet-map.js`) of major public cloud provider regions/PoPs at
  city-level precision, each citing the provider's own public documentation
  page as its source -- per the issue's explicit instruction not to invent
  DTC locations. **This is a proof-of-concept seed list (5 entries), not a
  claim of comprehensive coverage, and this session's sandbox had no
  outbound network access to re-verify the cited entries live** -- an
  operator/maintainer should confirm them against each cited source before
  relying on this layer in production. This layer is completely independent
  of `/api/analytics/map`, the GeoIP lookup/storage architecture and the
  observed-DNS-destination semantics; it never touches Countries or
  Destinations mode. It uses a visually distinct diamond marker
  (`.leaflet-dtc-marker`) so the three datasets (countries, destinations,
  DTC pins) are never confused with each other.
- **Destinations mode: investigated, not removed.** The issue asked whether
  Destinations mode (real observed destination coordinates, requiring an
  optional city/coordinate GeoIP database) should be removed in favor of
  DTC pins. Those are answering two different questions -- Destinations mode
  shows *where DNS Inspector's own observed traffic actually resolved to*;
  DTC pins show *where a small set of known public infrastructure is
  located*, independent of any observed traffic -- so removing one is not a
  substitute for the other. Destinations mode is also an existing,
  presumably-in-use feature for any operator who already configured a city
  GeoIP database (Issue #37/#39/#42/#52), and AGENTS.md's task discipline
  ("do not invent architecture... report a mismatch rather than silently
  choosing") means a removal is a decision that needs its own explicit
  sign-off, not something to fold into this pass. **Smallest safe migration
  path, if removal is still wanted**: add DTC pins first as a fully additive
  layer (done here), let it run alongside Destinations mode for a release or
  two, and only then decide whether to demote/hide Destinations mode behind
  an explicit opt-in once real usage evidence (or its absence) is available
  -- never a same-PR delete of a working, data-backed mode in favor of an
  unverified static seed list. Countries mode, Destinations mode and
  `/api/analytics/map`'s payload are all unchanged by this release.
- **Traffic/network arcs: deferred.** Section 4 (curved traffic-volume
  arcs from "the BEMO/server public location" to destination/DTC locations)
  was not implemented this pass. It depends on a piece of data this codebase
  does not currently have: DNS Inspector is self-hosted per-operator with no
  existing concept of "the server's own public location" (no outbound
  geolocation call is made anywhere in this codebase, by design -- see
  `docs/GEOIP.md`'s "no path ever makes a live GeoIP network request"
  principle) -- inventing one would mean either a new outbound network call
  every operator would need to opt into, or a guessed/hard-coded origin,
  neither of which is a small, safe addition. It also depends on the DTC
  layer above maturing past a 5-entry proof of concept, and on a real
  geodesic-arc renderer (great-circle waypoints reprojected correctly under
  Leaflet's own pan/zoom, most reliably via the `Leaflet.Geodesic` plugin or
  an equivalent hand-rolled implementation) that has not been written or
  reviewed. Rather than ship a partial/guessed version, this is recorded
  here as a follow-up recommendation for its own dedicated issue, matching
  this project's established pattern of deferring speculative,
  rendering-sensitive features with a written rationale (e.g. 0.8.6's
  heatmap mode, 0.8.5.14's full tile-source abstraction).

## Verification status

**This implementation's sandbox could not execute `pytest`/`python` or make
any outbound network request at all** -- the same limitation recorded
against numerous 0.8.5.x hand-offs in `docs/CURRENT_STATE.md` (e.g. Issues
#44/#50/#52/#56/#63). The change is verified by direct code inspection: every
string the new tests in `tests/test_map_leaflet_renderer.py` assert on was
independently grep-verified against the actual rendered `app.py` template
and `static/leaflet-map.js`, and the whole new JS file was read back in full
to check brace/paren balance and control flow by hand. **The real CI run
(`pytest` + Docker build/health smoke) must confirm the full suite, and a
manual browser pass is strongly recommended before merge**: load the DNS
Destinations widget, confirm OpenStreetMap tiles actually render (not a
blank/gray host), zoom 2-3 steps into Europe/North America and pan around to
confirm tiles/markers/clusters move and scale together with no fixed image
left behind, click a marker and a breakdown row and confirm the same detail
card opens for both, toggle Countries/Destinations mode, and confirm the
reduced-motion preference disables Leaflet's zoom/pan animation.
