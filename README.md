# DNS Inspector

Read-only local DNS visibility tool for AdGuard Home.

## v0.4
- app version is read dynamically from `VERSION` and shown in the web UI
- browser refreshes data every 10s by default without reloading the page or losing scroll position (`UI_REFRESH_SECONDS`)
- the UI refresh triggers a read-only AdGuard Query Log poll, while background polling continues independently (`POLL_SECONDS`)
- repeated Query Log entries are deduplicated so counters do not inflate on every refresh
- recent domains show a severity dot and clearer classifications
- client identity is kept separate from DHCP IP observations
- when AdGuard exposes MAC/client identifiers, the MAC becomes the stable device key; IPs are retained as changing observations
- consumes AdGuard `/control/clients` read-only data to enrich names/hostnames
- shows per-domain device/IP/MAC activity when inspecting a hostname
- adds conservative device-type hints and icons (TV, AC, dryer, phone/tablet, computer, console, camera, speaker, network, IoT)
- confidence is intentionally conservative; unknown does not mean malicious
- no writes to AdGuard Home and no blocking decisions

## Environment
- `AGH_URL`
- `AGH_USER`
- `AGH_PASS`
- `POLL_SECONDS` (default `10`)
- `UI_REFRESH_SECONDS` (default `10`)
- `DB_PATH`
- `TRACKERDB_PATH`
- `TRACKERDB_REFRESH_HOURS`
- `RDAP_URL`

## Device identity
The app prefers a stable AdGuard client identifier or MAC address when AdGuard exposes one. IP addresses are stored as observations and are not treated as permanent device identities, which keeps DHCP changes from corrupting the device history.
