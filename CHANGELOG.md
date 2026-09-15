# Changelog

All notable DNS Inspector changes are tracked here.

## [0.8.0-dev.1]

Foundation release. No new features, no intentional behaviour changes.

**The repository is now the application.**

- removed the build-time patch chain: the Dockerfile no longer copies and executes sixteen `build_*.py` scripts that rewrote `app.py` during the image build
- `app.py` now contains the complete program (3,205 lines). Up to 0.7.14 the committed source was 2,062 lines and the program that actually ran was 3,173 — roughly 1,100 lines of live behaviour existed only inside the Docker image
- deleted all seventeen `build_*.py` scripts, including `build_ui_patch_v2.py`, which was already unreferenced by any build

**Entry point**

- startup moved from an inline `if __name__ == "__main__"` block into `main()`, with `serve()`, `start_background_workers()` and a `BACKGROUND_WORKERS` declaration
- the same steps run in the same order; the ingest thread is now named `agh-ingest` rather than taking Python's default thread name
- this is the only difference between the 0.7.14 runtime source and 0.8.0; every other line is byte-identical

**Tests**

- added a 55-test pytest suite covering configuration, database schema and migration, the HTTP surface, startup and route registration, and domain status classification
- added `tests/test_source_integrity.py`, which fails if build-time patch scripts or Dockerfile source mutation are ever reintroduced
- the suite is hermetic and deterministic: temporary database, no AdGuard instance, no outbound network
- added `requirements-dev.txt` and `pytest.ini`

**Build and CI**

- CI gained a `test` job; `build-and-push` now depends on it, so nothing is published unless the suite passes
- CI now builds the image and verifies the container starts and answers `/health` before the release step
- CI also runs on pull requests, without publishing
- the Dockerfile declares a `HEALTHCHECK` against `/health`
- `.dockerignore` excludes tests and documentation from the image

**Documentation**

- `docs/ARCHITECTURE.md` gained a concrete map of the real code: runtime shape, region line ranges, database ownership, configuration and boundedness
- added `docs/MODULARIZATION.md` with the planned module boundaries, a suggested version sequence, and a register of deferred findings

**Known issue carried forward unchanged**

- `/api/observability` is bound to the wrong function and returns 500. This was introduced by the patch chain in 0.7.12 and is preserved exactly in 0.8.0 rather than fixed, because 0.8.0 is scoped to the foundation. See D-1 in `docs/MODULARIZATION.md`. Recommended as the 0.8.1 scope.

## [0.7.14]

- Overview > Device filter now uses the same friendly/manual device name as the Devices view when one is available
- partial search is now supported instead of requiring an exact domain match
- search can resolve domains by partial domain text and by known device identity fields such as custom name, hostname, MAC, vendor or recent IP
- indirect device/IP matches resolve to the most relevant observed domain so the existing inspection UI remains unchanged
- no ingest, enrichment, SQLite lifecycle or background polling changes

## [0.7.13-hotfix.2.4]

- fixed the Uptime / RAM header indicators that could remain stuck on `—`
- moved the lightweight runtime values onto the existing `/api/state` refresh path instead of using a separate browser polling loop
- removed the extra 5-second observability request loop from the header
- populate uptime and RSS memory immediately on page load through the normal dashboard refresh
- no ingest, enrichment, SQLite behavior, classification or memory-management logic changes

## [0.7.13-hotfix.2.3]

- fixed SQLite connection lifetime for the main `/data/inspector.db` database by explicitly closing connections used by DB_PATH context-manager blocks
- prevents each repeated request from leaving another native SQLite connection/file descriptor behind
- this targets the observed growth from 18 startup file descriptors to 67 after 6m42s, including 59 open descriptors for `/data/inspector.db`
- application query/ingest/enrichment logic is unchanged; the fix changes connection cleanup only

## [0.7.13-hotfix.2.2]

- fixed the deep Debug Bundle `/proc`, thread and file-descriptor collectors by injecting the required `Path` import into the generated app
- hardened the Python GC object-type collector so unusual runtime objects cannot abort that diagnostic section
- kept the change debug-only; no ingest, enrichment, polling, cache, worker or normal UI behavior changes
- corrected the bundle manifest to report the actual 0.7.13-hotfix.2.2 diagnostic patch

## [0.7.13-hotfix.2.1]

- made the deep Debug Bundle resilient to individual diagnostic collector failures
- each memory diagnostic section is now isolated and records its own error/traceback instead of aborting the complete ZIP
- the bundle remains usable even when a `/proc`, allocator, SQLite, HTTP-pool or other optional diagnostic source is unavailable
- no ingest, enrichment, polling, cache, worker or normal UI behavior changes

## [0.7.13-hotfix.2]

- debug-bundle-only hotfix focused on locating RSS memory outside Python-tracked allocations
- added raw `/proc/self/status` memory fields including anonymous/file/shmem RSS, data, stack, swap and mappings
- added `/proc/self/smaps_rollup` PSS/private/shared/anonymous memory breakdown when available
- added top process memory mappings from `/proc/self/smaps`
- added cgroup memory usage/limit/event statistics when available
- added glibc `mallinfo2()` allocator statistics when available
- added thread-level diagnostics from `/proc/self/task`
- added file-descriptor classification and target listing
- added SQLite PRAGMA diagnostics for page/cache/journal/mmap state
- added HTTP connection-pool diagnostics for the global requests session
- added top Python GC-tracked object types
- expanded on-demand `tracemalloc` output with top traceback allocation sites
- added process resource-limit diagnostics
- existing application ingest, enrichment, polling, cache and worker behavior is unchanged; the extra diagnostics run only when `Generate Debug Bundle` is requested

## [0.7.13-hotfix.1]

- added Python allocation diagnostics with `tracemalloc` to investigate the long-running memory buildup observed in 0.7.12
- added current and peak Python-traced memory to the observability payload
- added top allocation sites from on-demand snapshots, limited to the top 25 entries
- added garbage-collector counters and tracked object count to the diagnostic payload
- added shallow visibility into large module-level containers and queue-like globals, including type, length and shallow size
- added open-file-descriptor count when `/proc/self/fd` is available
- diagnostics do not retain historical tracemalloc snapshots or change ingest/enrichment scheduling behavior
- diagnostic overhead is intentionally kept bounded by using a configurable 5–20 frame traceback depth (`MEMORY_DIAGNOSTICS_FRAMES`, default 10)
- memory diagnostics can be disabled with `MEMORY_DIAGNOSTICS_ENABLED=0`

## [0.7.12]

- added per-IP reachability status in the Devices tab
- each displayed IP shows a gray/yellow/green/red reachability indicator based on the latest ping result
- added a manual `Ping` button beside every displayed IP
- active private LAN IPs are checked automatically every 4 hours in the background
- first automatic reachability sweep starts 60 seconds after application startup
- ping results persist in SQLite with last-check time, latency and failure reason
- ping targets are restricted to private LAN addresses
- bundled `iputils-ping` in the Docker image so ICMP checks work without host-side packages
- automatic IP probing only considers device IP associations still inside the 12-hour retention window
- configurable with `IP_PING_INTERVAL_HOURS`, `IP_PING_INITIAL_DELAY_SECONDS`, and `IP_PING_TIMEOUT_SECONDS`
- added process uptime and current RSS memory to the UI header
- added a read-only `/api/observability` runtime snapshot
- added a one-click `Generate Debug Bundle` action with sanitized runtime/config/database statistics
- debug bundles explicitly avoid secrets and do not add persistent application log writes

## [0.7.11]

- stale device/IP associations are pruned automatically from `device_ips`
- default IP-observation retention is 12 hours, preventing recycled DHCP addresses from remaining attached to the wrong device indefinitely
- stale-IP cleanup runs immediately at startup and every 30 minutes in the background
- retention is configurable with `DEVICE_IP_RETENTION_HOURS`

## [0.7.10]

- manual device labels are presented in a dedicated Devices-table column
- added visible refresh feedback with a spinner while the dashboard state is loading
- refresh starts immediately on page load instead of waiting for the regular polling interval

## [0.7.9]

- persistent manual device labels stored on `/data`, keyed by stable device identity
- fixed browser MAC lookup URLs so the Devices tab no longer opens the `macvendors.com/<MAC>` API path that returns 404 in a browser
- enrichment attempts now have a persistent minimum retry interval of 24 hours
- a missing or failed enrichment result is not retried on every 10-second `/api/state` poll
- retry cooldown survives container restarts through the `enrichment_attempts` SQLite table
- newly discovered domains are queued for enrichment once and processed serially by the single background worker
