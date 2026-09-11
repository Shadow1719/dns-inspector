# DNS Inspector

Read-only local DNS visibility tool for AdGuard Home.

## v0.3
- polls AdGuard Home every 10s by default (`POLL_SECONDS`)
- browser refreshes every 10s by default (`UI_REFRESH_SECONDS`)
- recent-domain classification now performs normal cached RDAP lookups instead of cache-only lookups
- records client identifiers and AdGuard `client_info`
- enriches client names from AdGuard `/control/clients` (read-only GET)
- shows current client identifiers/IPs and conservative device-type hints
- does not write to AdGuard Home or change filtering settings

## Environment
- `AGH_URL`
- `AGH_USER`
- `AGH_PASS`
- `POLL_SECONDS` (default `10`)
- `UI_REFRESH_SECONDS` (default same as `POLL_SECONDS`)
- `DB_PATH`
- `TRACKERDB_PATH`
- `TRACKERDB_REFRESH_HOURS`
- `RDAP_URL`
