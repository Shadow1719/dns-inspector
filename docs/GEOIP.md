# GeoIP and DNS Destinations

DNS Inspector's Destination Map is driven by **observed DNS answers captured from AdGuard Home**. The application does not re-resolve domains through another DNS service and does not fabricate destination coordinates.

## Country map

The clean 0.8.x rebuild uses an optional local country-range CSV:

`/data/geoip_country_ranges.csv`

The expected schema is:

```text
start_ip,end_ip,country_code,country_name
8.8.8.0,8.8.8.255,US,United States
```

The runtime keeps IPv4 ranges in fixed-width `array.array` columns and performs binary-search lookups. IPv6 ranges are kept separately. GeoIP is loaded in a background worker after the HTTP service starts.

No GeoIP database is committed to the repository.

## Observed destinations

For each new AdGuard query, DNS Inspector records only public `A` / `AAAA` answers that actually appeared in the query-log response.

Private, loopback, link-local, multicast, reserved, unspecified and IPv4 CGNAT addresses are ignored.

A bounded `domain_destination_ips` table retains the observed domain/IP pairs. The map aggregates those observations by country. Marker size and color are driven by the selected real metric (observations, unique IPs or domains).

Country centroids are used only to place a **country-level aggregate marker on the country map**. They are not presented as the physical location of an individual destination IP.

## Coordinate-level Destinations mode

DNS Inspector never invents city coordinates. When no coordinate-capable provider is configured, the UI keeps Countries mode available and explicitly reports that Destinations mode requires a city/coordinate GeoIP database.

An **optional**, separate coordinate-capable CSV can be configured at:

`/data/geoip_city_coordinates.csv` (override with `GEOIP_CITY_DB_PATH`)

The expected schema is:

```text
start_ip,end_ip,country_code,country_name,city,lat,lon
8.8.8.0,8.8.8.255,US,United States,Mountain View,37.4056,-122.0775
```

This is intentionally a **separate file** from `GEOIP_DB_PATH` (country-range-only): Destinations map mode, the destination breakdown-by-coordinate, and destination route/arc rendering only ever activate once this file is configured and loads successfully. Country mode continues to use the country-range CSV and country centroids regardless of whether this file exists. No fallback from missing coordinates to a country centroid is ever performed for an individual destination point.

### Destination route/arc visualization

When coordinate-level data is available, the map can optionally draw a subtle line from a configured **origin** point to each observed destination cluster. This is a **geographic/visual path** (a great-circle/geodesic arc), not the actual network route DNS traffic took, and the UI labels it as such.

The origin point is never derived or guessed. It must be set explicitly via `POST /api/settings/map-origin` (or cleared via `{"clear": true}`) with real `lat`/`lon` coordinates -- for example, the operator's own approximate network location. Routes are automatically disabled (nothing is drawn) whenever either the origin or coordinate-level destination data is unavailable.

## Known-datacenter provenance layer (second, lower-priority coordinate source)

Real GeoIP -- even a good coordinate-capable database -- routinely has no city-level match for IPs that belong to large cloud/hosting/CDN providers. Rather than leaving every one of those unmapped, DNS Inspector supports an **optional, second, strictly lower-priority** coordinate layer for *known datacenter/provider* locations.

This layer is only ever consulted for an IP once the real city/coordinate GeoIP database (`GEOIP_CITY_DB_PATH`) has already missed for that same IP. It never overrides a real city match, and it is never presented as an exact physical server location -- only as a provider/region.

An **optional** CSV can be configured at:

`/data/geoip_datacenter_ranges.csv` (override with `GEOIP_DATACENTER_DB_PATH`)

The expected schema is:

```text
start_ip,end_ip,country_code,provider,region,lat,lon
34.64.0.0,34.127.255.255,US,Google Cloud,us-central1,41.2619,-95.8608
```

`lat`/`lon` here are the provider's own published **region** coordinates (or another authoritative, explicit location for that specific range/provider/region) -- never a geographic guess, and never a claim about an individual server's physical address.

### Sourcing this data safely

Only add rows you can trace back to an explicit, authoritative statement that a given IP range belongs to a given provider/region -- for example, a cloud provider's own published IP-range document (AWS `ip-ranges.json`, Google Cloud's published ranges, Azure's published Service Tags, etc. -- each already lists a `region`). Region coordinates can then be taken from the provider's own public region-location documentation.

Do not:

- invent or interpolate a coordinate for a range that has no explicit region attached;
- treat an anycast network (e.g. a CDN edge that serves the same IP from many physical locations) as if it has one true location;
- commit a third-party database to the repository -- this file is operator-supplied, like the other two GeoIP CSVs.

Keep the file bounded and refresh it periodically (e.g. regenerate it from the providers' published range documents on a schedule that suits your deployment) -- there is no live/runtime fetch, and the loaded ranges live in the same bounded, fixed-width in-memory table and bounded LRU lookup cache pattern as the other two GeoIP providers, so an operator refresh never grows unbounded memory.

### Provenance hierarchy

For every observed destination IP, DNS Inspector resolves exactly one of:

1. **City GeoIP** (`city_geoip`) -- an exact coordinate match from `GEOIP_CITY_DB_PATH`.
2. **Known datacenter** (`known_datacenter`) -- no city match, but a match in `GEOIP_DATACENTER_DB_PATH`; region-derived, not exact.
3. **Country only** (`country_only`) -- neither coordinate layer matched, but the country-range database did. This still contributes to the Countries aggregate view, but -- consistent with the existing "no country-centroid destinations" rule -- it is never placed as a Destinations-mode bubble.
4. **Unmapped** (`unmapped`) -- no database matched at all.

The map, the in-app report and the PDF export all label which tier a given destination point came from, and `/api/analytics/map` exposes the observation counts for all four tiers under `coverage.provenance` so the actual coverage split is never hidden.

## DB-IP Lite

DB-IP Lite is an acceptable source for an operator-supplied converted dataset. If DB-IP data is used, preserve the source's attribution/licensing requirements (DB-IP Lite is distributed under CC BY 4.0 for the applicable datasets). Do not commit the database itself.

## Diagnostics

`/api/analytics/map` reports:

- provider availability and loaded range count;
- mapped vs unmapped observations;
- mapped-domain coverage;
- whether coordinate-level data is available;
- a human-readable diagnostic state.

The supported diagnostic states distinguish an unconfigured provider from a load failure, no public destinations, no country matches and a working country-only provider.
