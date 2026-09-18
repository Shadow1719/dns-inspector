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
