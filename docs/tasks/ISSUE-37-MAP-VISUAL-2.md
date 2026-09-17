# Issue #37 — Destination Map Visual 2.0 — implementation contract

Status: IMPLEMENTED (0.8.6)

Implemented as described below, with one documented scope reduction: Heatmap
mode (section "2. Optional Heatmap mode") was left as a follow-up rather
than shipped, per this document's own allowance ("If this becomes too large
for one coherent implementation, leave Heatmap as a clearly documented
follow-up rather than creating a half-working implementation"). Everything
else in "Product requirements" was implemented, including both data modes,
the four configurable styles, the configurable metric, interaction (hover/
click/zoom/reset/empty-states/reduced-motion), honest data semantics, the
extended `GeoIPProvider` architecture (`CityGeoIPProvider`), and the no-
remote-map-dependency constraint. See `CHANGELOG.md`'s `[0.8.6]` entry and
`docs/CURRENT_STATE.md` for what changed, and `docs/GEOIP.md` for the new
Destinations-mode setup/attribution documentation. Focused automated tests
were written for the new backend/frontend logic (see the implementing PR's
description for exactly what could and could not be executed in this
session, and why); the real-deployment acceptance test in this document's
"Acceptance test — real deployment" section was not performed and remains
an operator validation step.

This document is the implementation contract for Issue #37. It is intentionally explicit so the implementation agent does not have to infer the desired product behaviour from a chat conversation.

## Goal

Turn the existing 0.8.5.2 DNS Destinations map from a static country-level bubble map into a genuinely useful, interactive, configurable geospatial visualization while preserving the existing observed-DNS-destination semantics and the existing backend architecture.

The widget must be functional with real data, not merely visually impressive.

## Current baseline

- Branch: `dev`
- Current version: `0.8.5.2`
- Existing widget: DNS Destinations (observed)
- Existing endpoint: `GET /api/analytics/map`
- Existing observed destination source: real A/AAAA answer IPs returned by AdGuard for the actual query, captured at ingestion time.
- Existing GeoIP country provider: local/offline operator-supplied database.
- Existing `domain_destination_ips` table and `geoip_map_payload()` must remain the source of truth for observed destination data.
- Existing Dashboard Builder/layout reconciliation from Issue #31 must remain intact.
- Existing no-GeoIP state must continue to show the map, with an honest non-blocking status.

Read `AGENTS.md`, `CLAUDE.md`, `docs/CURRENT_STATE.md`, `docs/GEOIP.md`, and the actual current implementation/tests before changing anything.

## Visual references

The product direction is inspired by three kinds of maps:

1. **Simple bubble/circle map** — country/region circles where size represents volume. This is useful as a clean overview.
2. **World geolocation point map** — many small points with clustering and larger bubbles where many destinations overlap.
3. **Dark network/security map** — dark basemap with luminous cyan/teal points, clusters/hotspots, subtle borders and optional connection/flow treatment.

The desired dark-mode result is much closer to #3 than the current plain dark SVG. The desired light/white result may use a restrained grey/white basemap similar to a conventional blank world map.

Reference blank world-map geometry (reference only, NOT a runtime dependency):
https://upload.wikimedia.org/wikipedia/commons/4/4d/BlankMap-World.svg

Do NOT make the Wikimedia image a required runtime network dependency. Do NOT load a remote map/CDN at runtime.

The visual examples are references for visual language, not permission to copy their exact assets, branding, labels, or proprietary map tiles.

## Product requirements

### 1. Two real data modes

Implement at minimum these user-selectable modes:

#### A. Countries

Country-level overview using the data already available in 0.8.5.2.

- One bubble per country.
- Bubble size represents the selected metric.
- Preserve the existing country aggregation semantics.
- This mode must work with the current Country GeoIP database.
- It must not require city-level GeoIP data.

#### B. Destinations

Coordinate-level destination visualization when city/coordinate GeoIP data is configured.

- Each observed public destination IP can resolve to a geographic coordinate through the configured GeoIP provider.
- Nearby destinations must be clustered so the map remains readable.
- A cluster/bubble represents multiple observations/points and grows with the selected metric.
- Zooming into a cluster must reveal more granular points/clusters where practical.
- Do NOT invent random coordinates for IPs that only have country-level information.
- If only Country GeoIP is configured, the UI must clearly explain that coordinate-level destination mode is unavailable and provide the country mode instead.

The implementation must not silently turn a country centroid into a fake city/IP location.

### 2. Optional Heatmap mode

If it can be implemented cleanly without compromising the above, add:

- Heatmap / density visualization based on real observed destination coordinates.
- Intensity must be based on real observations, not decorative noise.
- It must be disabled or unavailable when coordinate-level data is unavailable.

If this becomes too large for one coherent implementation, leave Heatmap as a clearly documented follow-up rather than creating a half-working implementation.

### 3. Configurable visual style

The map appearance must be configurable independently from the application theme.

At minimum support:

- `BEMO Dark` — dark navy/black basemap, subdued land/borders, bright cyan/teal destination points and clusters.
- `Aurora` — dark map with more colorful cyan/violet/purple accents.
- `White` — light/grey basemap, restrained borders, conventional coloured bubbles/points.
- `Minimal` — low-detail basemap with minimal borders/grid and emphasis on data.

Do not hard-wire map appearance to `html[data-theme]` alone. A user may use BEMO Dark application theme with a White map style, for example.

Persist the map preference using the existing client-side preference mechanism (`dnsInspectorPrefs`) or an equivalent existing preference mechanism. Do not add a database migration merely for UI preferences.

### 4. Configurable data metric

Provide a small, understandable control for the point/bubble weighting. At minimum:

- `Observations` — default.
- `Unique IPs` — if supported by the available payload.
- `Domains` — if supported without distorting the existing semantics.

Do not expose controls for metrics that the backend cannot calculate accurately.

### 5. Interaction

The map should support, within reasonable scope:

- hover tooltip for a country/point/cluster;
- click to select a country/cluster/destination;
- useful detail panel or tooltip containing available data;
- zoom for destination mode;
- reset/recenter control;
- graceful empty/no-data state;
- reduced-motion compliance.

Do not make hover/click depend on a third-party hosted map service.

### 6. Honest data semantics

This is mandatory.

The widget represents:

> observed DNS destinations

It does NOT prove:

- the physical location of a server;
- the user's location;
- the location of a household/device;
- that an IP belongs permanently to one city;
- that a CDN/Anycast answer represents the application's origin server.

Keep an explanatory subtitle or info affordance. Coordinate-level GeoIP must be described as approximate. Where the provider supplies an accuracy radius, preserve it in the data model and use it appropriately rather than implying pinpoint accuracy.

### 7. Anycast/CDN handling

Do not collapse multiple real observed destination IPs merely because they share a domain.

The existing model intentionally allows one domain to have multiple observed A/AAAA destination IPs. Keep that behaviour.

When several IPs map to nearby coordinates, clustering may visually aggregate them, but the underlying records must remain distinguishable when zoomed/selected.

### 8. GeoIP provider architecture

Extend the current provider abstraction rather than replacing it.

The current Country provider must continue working.

Add coordinate/city support in a way that is:

- local/offline at lookup time;
- operator-supplied;
- bounded and performant;
- testable without shipping a real 100+ MB database in Git;
- compatible with IPv4 and IPv6;
- safe when the optional city database is absent.

DB-IP IP to City Lite is an acceptable documented source. Its September 2026 CSV contains `ip_start,ip_end,continent,country,stateprov,city,latitude,longitude`; DB-IP Lite is CC BY 4.0 and requires attribution when used in a web application. Do not commit the database to Git. Document the attribution requirement if DB-IP is used.

Do not choose MaxMind/GeoLite as the default implementation merely because it is familiar if its redistribution/display licensing would complicate this project. If MaxMind support is added, make the licensing implications explicit and do not bundle the data.

Prefer a runtime format that does NOT load ~7.7 million city CSV ranges into giant Python lists. A memory-mapped/indexed MMDB reader, SQLite/range index, or another bounded indexed representation is preferable to a naive in-memory CSV expansion. If a new dependency is introduced, justify it in the task docs and add tests.

### 9. No remote map dependency

The application must render its basemap from bundled/static/offline-safe assets or code.

Allowed:
- repository-bundled SVG/geometry;
- static local assets;
- inline SVG generated from bundled geometry;
- client-side math/geometry.

Not allowed:
- Google Maps runtime dependency;
- Mapbox runtime dependency;
- Leaflet tiles from a public server;
- OpenStreetMap tile requests;
- remote CDN JavaScript required for the map;
- runtime fetches to a geolocation API.

The map must still render when the server has no Internet access.

### 10. Basemap quality

The current 720x360 continent silhouette is a useful fallback but is visually too basic for the target.

Improve the basemap enough that it can support a dark network/security-map appearance:

- recognizable continents;
- sensible coastlines;
- optional country boundaries;
- subtle graticule/grid;
- no excessive labels;
- no copyrighted third-party tile imagery.

For White mode, a clean grey/white world map is desired.

Do not spend the majority of the task building a GIS engine. The map is an analytics widget, not a general-purpose GIS.

## Backend/API requirements

Keep `/api/analytics/map` as the dedicated map endpoint unless the existing architecture requires a small additive change.

Prefer an additive payload evolution such as:

```json
{
  "provider": { ... },
  "coverage": { ... },
  "countries": [ ... ],
  "destinations": [ ... ],
  "unknown": { ... },
  "capabilities": {
    "country": true,
    "coordinates": false,
    "heatmap": false
  }
}
```

Exact shape is up to the implementation, but:

- existing consumers must not break;
- existing `countries` data should remain compatible where practical;
- do not return unbounded raw DNS data;
- respect existing domain/IP bounds;
- aggregate/cap server-side where appropriate;
- cache expensive aggregation;
- do not perform per-browser-request DNS resolution.

If coordinate destinations are exposed, include enough identity to make selection useful without exposing more raw data than necessary, for example:

- normalized IP or a safe display form;
- country code/name;
- city when available;
- latitude/longitude;
- observation count;
- domain count;
- sample domains, bounded;
- optional accuracy radius;
- optional provider/ASN metadata only if already available and justified.

## Performance requirements

The widget must remain responsive with realistic home-network data.

Do not render thousands of individual SVG elements if clustering/aggregation can reduce them.

Set explicit bounds for:

- maximum destinations returned to browser;
- maximum sample domains per point;
- cache lifetime;
- maximum cluster/detail work;
- maximum tooltip content.

Do not regress the existing Analytics polling cadence.

If the map has no new data, avoid replacing the entire SVG unnecessarily.

## UI layout

Keep the existing card/widget shell and Dashboard Builder integration.

Suggested controls inside the widget header, compact enough not to consume the map:

```text
DNS Destinations (observed)                         [⚙]
Country-level aggregate ...

[ Countries ▾ ] [ Observations ▾ ] [ BEMO Dark ▾ ]

┌─────────────────────────────────────────────────┐
│                                                 │
│                  WORLD MAP                      │
│                                                 │
│       •      •         ●●                       │
│             ●●●                                 │
│                             •                   │
│                                                 │
└─────────────────────────────────────────────────┘

94.7% geolocated · 18 countries · 143 destinations
```

Exact visual layout may adapt to the existing Inspector BEMO design system.

Do not make controls oversized. The map should remain the dominant element.

## Empty and partial states

### No GeoIP database

Map remains visible.

Show a compact message such as:

> GeoIP not configured — destinations are shown as unmapped. Configure a local GeoIP database to enable destination plotting.

Do not hide the widget.

### Country GeoIP only

Countries mode works normally.

Destinations mode shows an honest capability message, not fake points.

### GeoIP configured but no observed destinations

Show the map with:

> No geolocated destinations yet.

### Partial coverage

Show the map plus coverage information such as:

> 82.4% of observed destination observations geolocated · 17.6% unmapped

Never silently discard the unmapped fraction.

## Testing requirements

Add focused tests for all new logic.

At minimum:

1. Existing Country provider regression tests still pass.
2. Coordinate provider lookup:
   - IPv4 mapped;
   - IPv6 mapped;
   - unmapped IP;
   - private/reserved IP ignored;
   - malformed input handled safely.
3. Country + coordinate aggregation from the same observed destination model.
4. Multiple IPs for one domain remain separate underlying destinations.
5. Nearby destinations aggregate into a cluster without losing their total observation count.
6. Different far-apart destinations do not incorrectly merge at a sufficiently zoomed level.
7. `/api/analytics/map` advertises capabilities accurately.
8. No-GeoIP endpoint/UI state remains correct.
9. Partial GeoIP coverage reports the correct percentage.
10. Map preferences persist and restore.
11. Every supported map style renders without throwing.
12. Reduced-motion preference disables/reduces map animation.
13. Existing dashboard layout/preset behaviour remains intact.

Use small synthetic fixtures, not a real GeoIP database, for tests.

## Acceptance test — real deployment

Before calling the task complete, the implementation must be suitable for this real-world sequence:

1. Deploy the build to the DEV container.
2. Mount/configure a supported local city-capable GeoIP database.
3. Restart Inspector.
4. Verify `/api/observability` reports the GeoIP provider and loaded database correctly.
5. Query real geo-routed test domains through the normal AdGuard path documented in `docs/GEOIP.md`.
6. Verify `/api/analytics/map` returns non-zero coordinate/country coverage.
7. Open Analytics and confirm actual destination points/bubbles appear.
8. Generate additional queries to the same and different destinations.
9. Confirm repeated observations increase the corresponding bubble/cluster metric rather than creating unbounded duplicate visual noise.
10. Zoom in and confirm clusters separate when the data warrants it.
11. Switch Countries/Destinations modes.
12. Switch BEMO Dark/Aurora/White/Minimal styles.
13. Reload the page and verify map preferences persist.
14. Verify no-GeoIP and partial-coverage states still behave honestly.

Do not claim the real deployment acceptance test passed unless it was actually performed.

## Non-goals

- No map tiles or hosted map provider.
- No browser geolocation.
- No user-location visualization.
- No claim of exact physical server location.
- No DNS re-resolution to manufacture destination data.
- No replacement of the existing observed destination source.
- No unrelated Analytics redesign.
- No redesign of the entire Dashboard Builder.
- No workflow changes unless explicitly required by the repository contract.
- No giant GeoIP database committed to Git.

## Versioning/documentation

This should become the next coherent version after 0.8.5.2. If the repository's versioning convention supports it, bump to `0.8.6` and update:

- `VERSION`
- `CHANGELOG.md`
- `docs/CURRENT_STATE.md`
- `docs/GEOIP.md`
- relevant architecture/decision docs if the provider/map architecture materially changes.

## Git workflow

- Branch from `dev`.
- Use a feature/fix branch.
- Commit the complete coherent implementation.
- Push the branch.
- Open a PR targeting `dev`.
- Do NOT merge the PR.
- Report the branch, commit, PR, tests actually run, and any validation that could not be performed.
