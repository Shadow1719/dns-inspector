## v0.5.8

Hotfix release: restored classification/device helper functions accidentally omitted from v0.5.7, which caused `NameError: classify is not defined` and HTTP 500 responses when opening the dashboard/Inspect view. Also removes the duplicate RDAP background refresh call present in the initial 0.5.7 build.

# DNS Inspector

Read-only local DNS visibility tool for AdGuard Home.

## v0.5.5
- completes domain **Who** enrichment by using Netify public hostname intelligence as secondary evidence when TrackerDB/RDAP do not identify the owner
- falls back to the registered/apex domain for RDAP when a hostname-level lookup is unavailable
- extracts RDAP organization/country/registrar fields when available
- caches Netify enrichment locally to avoid repeated requests on UI refresh
- moves vendor lookup to a magnifying-glass action directly beside the vendor name
- removes internal navigation links from MAC and vendor text; only the magnifying-glass lookup is clickable
- keeps device name, hostname, IP and other contextual navigation unchanged


## v0.5.4
- fixes the dashboard column mapping so IPs appear under IP(s) and MAC addresses under MAC
- keeps internal navigation separate from external lookups
- adds dedicated external lookup buttons for MAC vendor lookup and device search
- adds domain-level external buttons for Netify hostname intelligence, DNSChecker records, and web search
- opens external lookups in a new tab without changing the read-only local navigation model

## v0.5.3
- Fixed Docker image packaging so bundled vendor logos under `static/vendor-logos/` are actually included in the image.
- Device names, hostnames, MACs, device chips, IP addresses, and DNS address chips are clickable.
- Added dedicated device view (`/device`) with identity, IP history, and top DNS activity.
- Added dedicated IP view (`/ip`) with known devices and domains contacted.
- Domain links remain available through the existing Inspect view.

## v0.5.2
- bundles supported vendor marks locally under `static/vendor-logos/`, so the UI no longer depends on a third-party CDN for vendor imagery
- uses the vendor mark as the leading device visual when available, replacing the generic box for known vendors
- keeps a generic device icon only when no vendor mark is available

## v0.5.1
- makes device names, MAC identities, and IP addresses clickable for contextual inspection
- adds device/IP-focused views while preserving the read-only architecture

## v0.5.0
- adds explainable “Why is this here?” signals with evidence and confidence levels
- uses severity-aware colors for telemetry, advertising, known services, ownership, and unknown domains
- presents DNS addresses as readable IP chips instead of a dense comma-separated line
- makes the live timestamp human-readable with separate time and date styling
- shows vendor marks for supported manufacturers with a generic fallback
- keeps the UI read-only and preserves MAC-based device identity

## v0.4.6
- keeps MAC addresses as stable device identity when available
- stores DHCP IPs as observations and preserves historical IPs per device
- uses TrueNAS `neighbors.txt` to correlate IP → MAC
- discovers device hostnames from AdGuard client information when available
- falls back to reverse DNS (PTR) for known device IPs and caches the result
- looks up the registered MAC vendor/manufacturer and caches the result locally
- shows hostname and MAC vendor in device views
- continues to keep the UI read-only against AdGuard Home
- browser refresh reads local SQLite state; AdGuard polling is performed by the background worker

## v0.4.4
- fixed duplicate legacy IP + MAC device rows after neighbor reconciliation
- canonicalized IP-keyed clients to MAC-keyed clients in inspected domain views
- added one-click Reset button for hostname inspection

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
- `NEIGHBORS_PATH` (default `/data/neighbors.txt`)
- `MACVENDOR_URL` (default `https://api.macvendors.com`)
- `MACVENDOR_CACHE_HOURS` (default `168`)
- `HOSTNAME_CACHE_HOURS` (default `24`)
- `NETIFY_URL` (default `https://www.netify.ai/resources/hostnames/`)
- `NETIFY_CACHE_HOURS` (default `360` / 15 days)
- `RDAP_CACHE_HOURS` (default `720` / 30 days)
- `DNS_RECORDS_CACHE_HOURS` (default `168` / 7 days)

## Device identity
The app prefers a stable AdGuard client identifier or MAC address when AdGuard exposes one. IP addresses are stored as observations and are not treated as permanent device identities.

Hostnames are discovered from AdGuard client information when available; otherwise the app attempts a reverse-DNS lookup for the device IP and caches the result.

MAC vendor lookup is informational only. It does not identify a specific device model; it identifies the organization registered for the MAC prefix.

## v0.5.6

Polish release before v0.6:
- enriches domain inspection with Netify public hostname/application evidence when available;
- adds direct DNS-over-HTTPS record enrichment (A/AAAA/CNAME/NS/MX/TXT/SOA/CAA/SRV) with local cache;
- keeps DNSChecker as an external verification link rather than scraping its UI;
- populates the existing Who/Infrastructure fields from the strongest available TrackerDB, RDAP, Netify and DNS signals;
- vendor names and MAC addresses are plain text, not hyperlinks;
- external vendor/MAC lookup is represented by a compact magnifier button placed immediately to the right of the value;
- keeps internal device/IP navigation separate from external lookups.

## v0.5.7
- Added persistent local enrichment caching for Netify, RDAP and DNS records.
- Inspect pages now read cached enrichment immediately and never wait on slow external enrichment requests.
- Missing or expired enrichment is refreshed in the background and stored in SQLite for the next visit.
- Default cache TTLs: Netify 15 days, RDAP 30 days, DNS records 7 days; override with `NETIFY_CACHE_HOURS`, `RDAP_CACHE_HOURS`, and `DNS_RECORDS_CACHE_HOURS`.
- DNS A/AAAA display reuses the DNS records cache instead of performing a second live lookup when cached records exist.
- Vendor/MAC text is no longer treated as an internal device link when vendor is only the fallback identity; the external magnifier remains the lookup action.
- Removed the hardcoded local AdGuard URL from the application defaults; configure `AGH_URL` explicitly in the container environment.

The request path never performs a slow external enrichment fetch. Cached data is served immediately; missing or expired Netify/RDAP/DNS enrichment is refreshed by a deduplicated background worker.
