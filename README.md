# DNS Inspector

Local, read-only DNS activity inspector for AdGuard Home.

## What it does

- Polls AdGuard Home Query Log using read-only requests.
- Stores local query counts and clients in SQLite.
- Enriches hostnames with the Ghostery/WhoTracks.me TrackerDB snapshot.
- Shows tracker category, tracker name, company, description and website when available.
- Performs cached RDAP lookups for ownership when TrackerDB has no answer.
- Resolves current A/AAAA addresses for inspected hostnames.
- Never changes AdGuard filtering, rewrites, protection settings or configuration.

## Container

The image listens on port `8080` and exposes `/health`.

The persistent `/data` directory contains:

- `inspector.db`
- `trackerdb.sqlite`

## Environment

- `AGH_URL` default `http://192.168.1.100:30004`
- `AGH_USER`
- `AGH_PASS`
- `POLL_SECONDS` default `60`
- `DB_PATH` default `/data/inspector.db`
- `TRACKERDB_PATH` default `/data/trackerdb.sqlite`
- `TRACKERDB_REFRESH_HOURS` default `24`
- `RDAP_URL` default `https://rdap.org/domain`

## Image

GitHub Actions publishes the image to GHCR on every push to `main` and on version tags.

The `stable` tag is intended for a TrueNAS installation that should automatically receive new builds.
