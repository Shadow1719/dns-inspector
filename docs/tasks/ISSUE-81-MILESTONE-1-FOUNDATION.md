# Issue #81 -- Milestone 1: 0.8.6 rebuild foundation from 0.7.14

**Status:** IMPLEMENTED (code + tests written and verified by direct
inspection only -- pytest could not be executed in this hand-off's sandbox;
see "Validation" below).

## Contract

This branch (`rebuild/0.8-clean-0.7.14`) was created from stable `main` at
0.7.14 (`52f6095`) specifically so this milestone could start from a clean,
un-forked baseline instead of `dev`'s accumulated 0.8.5.x state. Per the
PR #82 description and the maintainer's follow-up instruction on that PR:

- Rebuild a clean foundation from 0.7.14, using the 16 build-time patch
  scripts only as *behavioral reference*, not as something to mechanically
  re-run or copy.
- Remove the build-time patch-chain dependency entirely.
- Reimplement only validated, required behavior directly in `app.py`.
- Fix `_open_trackerdb()` so every SQLite connection is explicitly closed.
- Add tests for the foundation + SQLite lifecycle.
- Benchmark/report against the production 0.7.14 baseline (~244 MiB RSS
  after 3d17h uptime, 11 threads, 11 FDs, tracemalloc 0.77 MiB current /
  97.8 MiB peak).
- Do **not** port analytics, map, GeoIP, UI, Restart/Stop, or Debug Bundle
  yet, and do not mechanically copy `dev/app.py`.
- Do not merge this PR until this milestone is complete and validated.

## Conflict noted before implementation

`dev`'s `docs/CURRENT_STATE.md` (the canonical current-state document per
`AGENTS.md`) states: *"the project stays in the 0.8.5.x series deliberately
until the UI/dashboard/operational work is fully resolved; 0.8.6 is not to
be started until that gate is explicitly lifted."* No ADR or task document
in `docs/decisions/` or `docs/tasks/` on `dev` records that this gate has
been lifted. This branch is not based on `dev` and this PR is explicitly
held back from merging, so the gate's effect on the live `dev` line is
preserved either way -- but `docs/CURRENT_STATE.md` should be updated (or a
new ADR recorded) once this rebuild direction is confirmed, so a future
agent working from `dev` does not hit this same contradiction unexplained.

## What the 16 build scripts actually were

The Dockerfile applied 16 of the 17 `build_*.py` files in sequence against
the committed `app.py` at image-build time (`build_ui_patch_v2.py` was dead
code, never referenced by the Dockerfile, and has been deleted). Read as
behavioral reference, they fell into two groups:

**Foundation / backend, no UI or Debug Bundle surface** (reimplemented
directly in `app.py`, cleanly, in this milestone):
- `build_sqlite_close_patch.py` -- the requested fix, generalized to every
  `sqlite3.connect()` call site in the file, not just the `DB_PATH` ones
  the original patch's own comment said it deliberately left the TrackerDB
  connections untouched.
- `build_0_7_14_features.py` -- friendly device-filter labels reusing
  `real_device_label()`, and partial/device/IP search resolution
  (`_resolve_search_domain()`). This is literally what the "0.7.14" version
  name refers to.
- `build_perf_patch.py` / `build_perf_hardcap.py` -- a bounded
  `ThreadPoolExecutor` + semaphore for AdGuard status refreshes (replacing
  one thread per stale domain per request), and `get_recent()` pushing
  status/NEW filtering into SQL instead of scanning+enriching every domain.
- `build_memory_patch.py` (backend portion) -- a bounded queue + single
  worker thread for enrichment (replacing one thread per domain), plus
  cache TTL increases. Its JS refresh-loop dedup/cancel fix was also kept
  since it is an internal robustness fix (no new UI), not a UI feature.
- `build_enrichment_retry_patch.py` -- persisted retry-cooldown state
  (`enrichment_attempts` table) so a missing/failed lookup is not retried
  on every ~10s UI poll.
- `build_device_ip_retention_patch.py` -- bounded device/IP association
  retention + periodic cleanup worker. **A real bug in the reference
  script was found and fixed, not reproduced**: it compared the
  ISO-8601-text `device_ips.last_seen` column against a raw
  `time.time()` float cutoff. SQLite's TEXT-affinity comparison rules mean
  that comparison is always false (an epoch-string like `"175..."` sorts
  before any `"20xx-..."` ISO date string), so the original patch's DELETE
  would never actually have deleted anything. The reimplementation
  formats the cutoff as ISO-8601 to match the column it's compared against
  -- see `tests/test_enrichment_and_retention.py::test_prune_stale_device_ips_cutoff_is_iso8601_not_epoch`.

**Explicitly excluded from this milestone** (UI and/or Debug Bundle
surface, matching the task's own exclusion list -- these did not exist yet
in `dev`'s sense, since `dev`'s analytics/map/GeoIP/Restart/Stop are 0.8.x
additions that never existed in 0.7.14 at all; the *0.7.x-era* UI and
Debug Bundle build scripts are what the exclusion actually applies to
here):
- `build_device_labels_patch_v2.py` (manual device-label UI + API)
- `build_ui_followup_patch.py` (device-label column layout, loading
  indicator)
- `build_observability_patch.py` (`/api/observability`, `/debug/bundle`,
  the header uptime/RAM pill)
- `build_memory_diagnostics_patch.py` (extends the excluded observability
  payload with tracemalloc/gc diagnostics)
- `build_debug_bundle_deep_patch.py`, `build_debug_bundle_resilience_patch.py`,
  `build_debug_bundle_deep_fix_patch.py` (all three extend `/debug/bundle`
  only)
- `build_observability_ui_hotfix.py` (rewires the header pill to `/api/state`)
- `build_ip_ping_patch.py` -- **not explicitly named in the exclusion
  list, but deferred anyway**: it is a distinct feature (a background LAN
  ping worker + `/api/ip/ping*` routes + its own device-table UI markup),
  not a foundation/robustness fix, and shares the same
  `time.time()`-vs-ISO8601-text cutoff bug as the device-IP-retention
  patch in its own `_ping_active_ips()`. Left for a future, explicitly
  scoped milestone; the Dockerfile's `iputils-ping` system package was
  dropped accordingly since nothing else needs it.

## SQLite connection lifetime fix

Every `sqlite3.connect(...)` call site in `app.py` (33 sites) now goes
through `contextlib.closing(...)`, including the two `_open_trackerdb()`
call sites (`trackerdb_ready()`, `refresh_trackerdb()`) and the direct
`sqlite3.connect(TRACKERDB_PATH)` in `tracker_lookup()` that the historical
`build_sqlite_close_patch.py` explicitly left unpatched. `_open_trackerdb()`
itself still returns a bare `Connection` (it must call `create_function()`
before any `with` block starts), so the contract is "every *caller* wraps
it in `closing()`", not that the helper closes on your behalf.
`tests/test_sqlite_lifecycle.py` pins this with both a static source-pattern
check (so a future connect call added without `closing()` fails CI) and a
functional check (a spy on `sqlite3.connect` confirms every connection
opened by `init_db()` / `trackerdb_ready()` / `tracker_lookup()` is actually
closed afterward).

## Removed

- The 16-script build-time patch chain: the Dockerfile no longer copies or
  runs any `build_*.py` file; `app.py` is copied and run as-is.
- All 17 `build_*.py` files (16 previously wired into the Dockerfile, plus
  the dead `build_ui_patch_v2.py`).
- The `iputils-ping` system package from the Dockerfile (only the deferred
  IP-ping feature needed it).

## Validation

- **Tests were written, not executed.** This sandbox could not run
  `python3` in any form (`-m pytest`, `-c`, or a plain script file all
  required interactive approval that was never available in this
  non-interactive session). New tests live in `tests/` (`conftest.py`,
  `test_sqlite_lifecycle.py`, `test_enrichment_and_retention.py`,
  `test_search_and_filters.py`) and a `requirements-dev.txt`
  (`-r requirements.txt` + `pytest==8.3.4`, matching `dev`'s existing
  convention) was added so they're runnable via `pip install -r
  requirements-dev.txt && pytest`. Every test was traced by hand against
  the actual edited code paths (SQL results, dict/set state transitions)
  rather than executed. **The real CI/operator run of this suite must
  confirm it before this milestone is relied upon.**
- **The requested benchmark was not collected**, for the same reason:
  `scripts/foundation_benchmark.py` is written and ready to run
  (`python3 scripts/foundation_benchmark.py --duration 60` after setting
  `DB_PATH`/`TRACKERDB_PATH`/`AGH_URL`), but no numbers were produced in
  this hand-off. It measures RSS/thread-count/FD-count/tracemalloc
  current+peak from inside the actual process (in-process import, not a
  subprocess, so tracemalloc traces the real app) over a configurable
  duration, with the same background workers `main()` starts. Run against
  an idle process (no configured AdGuard) it reports foundation idle
  overhead only -- it is not a substitute for a real multi-day,
  real-traffic soak comparable to the production 0.7.14 baseline
  (~244 MiB RSS after 3d17h, 11 threads, 11 FDs, tracemalloc 0.77 MiB
  current / 97.8 MiB peak), which this sandbox has no way to run.
- `app.py` was not run either, so no `/health` smoke check was performed.
  Every edit was verified by direct reading: a full diff review, a grep
  sweep confirming no orphaned references to the removed
  `refresh_domain_enrichment()`, and a check for duplicate/missing
  function definitions.

## Explicitly not done (by design, per the task contract)

Analytics, GeoIP/map, the BEMO UI system, Settings, Restart/Stop, and
Debug Bundle are all 0.8.x-era work on `dev` that has no 0.7.14 equivalent
at all on this branch; none of it was ported here, and none of it should
be until a later, explicitly scoped milestone says so.
