# DNS Destinations map: real tile basemap (Issue #63)

This document covers the raster tile background added to the destination
map's Satellite Heat, Satellite Density and Real Map + Pins basemaps in
0.8.5.x (Issue #63). It does not change `/api/analytics/map`'s payload, the
GeoIP lookup/storage architecture, or the observed-DNS-destination semantics
described in `docs/GEOIP.md` -- this is a frontend rendering addition only.

## What changed

Prior to this change, all four `mapBasemap` presets (Satellite Heat,
Satellite Density, Real Map + Pins, Dark NOC) rendered the same bundled
offline dot-matrix world silhouette with a different color/particle
treatment -- explicitly documented at the time as a stylistic approximation,
not literal imagery, because the project had no bundled raster asset and no
network access to verify a tile provider from its own build environment.

Three of the four basemaps now additionally attempt to load a single real
tile image as their background:

| `mapBasemap` value   | Tile provider                       | Kept as-is |
|----------------------|--------------------------------------|------------|
| `satellite-heat`     | Esri World Imagery                   | --         |
| `satellite-density`  | Esri World Imagery                   | --         |
| `real-pins`          | OpenStreetMap standard tiles         | --         |
| `dark-noc`           | *(none -- stylized NOC treatment)*   | yes, per the issue's own allowance |

## Why a single zoom-0 tile, not a slippy tile grid

A single tile at zoom level 0 already covers the *entire* world (clipped to
the standard Web Mercator latitude range, roughly ±85.05°) in one 256x256
image. Stretching that one image to fill the map widget's fixed canvas:

- never requests more than one image per basemap (no "huge world tile set"),
- needs no per-tile pan/zoom-level fetch logic, cache-eviction, or
  overlapping-request bookkeeping,
- loads and fails exactly like any other `<img>` -- asynchronously, cached
  by the browser's normal HTTP cache, and gracefully (see below) if it
  can't load.

The tradeoff is resolution: at world-map scale this is indistinguishable
from a higher-resolution tile set, but zooming the widget in (`mapZoom`)
enlarges the *same* image rather than fetching sharper tiles. Given the
widget's own scale (a compact analytics card, not a full navigable map),
this was judged the right tradeoff against the complexity/risk of a full
per-tile slippy-map implementation.

## Coordinate correctness: two projections, never mixed

Real XYZ/slippy tiles use Web Mercator. The map's existing offline
dot-matrix silhouette (`WORLD_LAND_D`/`mapWorldDots()` in `app.py`) was
hand-authored directly in pixel space, not derived from real lat/lon, and
was tuned against the *original* plain equirectangular projection
(`(lon,lat) -> (x,y)` linear scaling). Reprojecting markers to Mercator
while leaving that hand-drawn silhouette in its original coordinates would
have made every marker drift from the outline as latitude increased --
exactly the "correct coordinate placement" regression the issue's own
performance/technical guidance warns against.

Instead, `app.py`'s map script keeps both projections and never shows their
outputs together:

- `mapProject()` (equirectangular, unchanged) + the offline dot-matrix --
  used whenever a basemap has no tile provider (Dark NOC) or its tile hasn't
  loaded (yet, or at all).
- `mapProjectMercator()` (new) + the loaded tile image -- used only once a
  basemap's own tile has actually finished loading successfully
  (`mapTileState.status === 'ready'` in the script), at which point
  `.map-tiles-active` hides the dot-matrix so the two never overlap.

The first successful tile load for a basemap triggers exactly one extra
re-render so markers move from the fallback projection to the real one;
every render after that already starts from the real projection, so no
further "extra" re-render happens on subsequent polls/clicks.

## Graceful fallback, no blocking

- Tile loading is a plain `<img src=...>` element appended after the SVG
  finishes rendering -- it is added to the DOM and left to load in the
  background; nothing in the click/detail/analytics-polling path waits on
  it.
- On `error`, the basemap simply keeps showing the existing offline
  dot-matrix world (unchanged visual/interaction behavior) -- the widget
  never breaks or shows a broken-image icon.
- Because the whole map wrapper is replaced on every render (its existing,
  unchanged 0.8.5.x re-render strategy), losing a previously-loaded `<img>`
  DOM node and recreating one pointed at the same URL is expected; the
  browser's own HTTP cache (not application code) is what keeps that cheap
  across the 5-10s analytics poll cycle, rather than a real repeated
  network fetch.

## Attribution and usage-policy verification

Both default providers are the same no-API-key sources long used by
open-source map tooling for exactly this purpose, chosen per the issue's
own "does not require a private API key for the default/dev setup"
requirement:

- **OpenStreetMap standard tiles** (`real-pins`): attribution "© OpenStreetMap
  contributors" is shown in the map's own corner attribution overlay.
  OpenStreetMap's tile usage policy has historically discouraged heavy
  automated/production embedding without a distinct User-Agent and
  reasonable request volume, and recommends self-hosting or a commercial
  tile provider for anything beyond light/development use.
- **Esri World Imagery** (`satellite-heat`, `satellite-density`):
  attribution "Tiles © Esri — Source: Esri, Maxar, Earthstar Geographics, and
  the GIS User Community" is shown the same way.

**This implementation's sandbox had no outbound network access to confirm
either URL currently resolves or that the attribution text above still
matches each provider's live terms** -- the same limitation recorded against
several 0.8.5.x GeoIP-provider hand-offs in `docs/CURRENT_STATE.md` (e.g. the
0.8.5.5/Issue #42 DB-IP download-URL caveat). Before relying on this in a
real deployment, an operator should:

1. Load the map with each basemap selected and confirm the tile image
   actually renders (not just the offline dot-matrix fallback).
2. Re-check both providers' current terms of use/attribution requirements.
3. If either provider is unsuitable for the deployment's actual traffic
   volume, point `MAP_TILE_PROVIDERS` (in `app.py`) at a different,
   suitably-licensed no-key or self-hosted tile source -- the URL is a
   single configurable string per basemap; no other code depends on which
   provider it points to.

If a tile provider is ever unreachable (offline environment, provider
outage, or a deliberately blocked default), the widget requires no
configuration change to keep working: it already falls back to the bundled
offline dot-matrix world automatically.
