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

The current clean milestone intentionally does **not** invent city coordinates. When no coordinate-capable provider is available, the UI keeps Countries mode available and explicitly reports that Destinations mode requires a city/coordinate GeoIP database.

The next GeoIP milestone can add a memory-conscious city provider using the same observed destination IP table.

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
