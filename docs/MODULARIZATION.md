# Modularization

This is the working document for turning `app.py` into independently developable
modules. It exists because 0.8.0 is a foundation release: it made the repository
trustworthy, and deliberately did *not* start the split.

It also holds the **deferred findings register** — problems found while building
0.8.0 that were documented rather than fixed, per the development process.

---

## Why 0.8.0 did not split anything

Splitting a module requires knowing what the module currently does. Until 0.8.0,
the repository did not contain the running program: sixteen build-time patch
scripts produced it inside the Docker image. Any split performed against the
committed source would have been a split of the wrong code, and would have
silently broken the patch markers that the real build depended on.

0.8.0 therefore did exactly three things that make a split possible later:

1. The repository now contains the whole program.
2. Startup is a named function (`main`) rather than an inline `__main__` block.
3. A test suite exists that can tell you whether a change broke something.

Everything below is future work.

---

## Target boundaries

The long-term boundaries, ordered by how safely they can be extracted *today*.
The ordering matters more than the names.

### Tier 1 — low coupling, safe to move early

| Boundary | Current location | Why it is safe |
| --- | --- | --- |
| `config` | lines 1–90 | Pure constant reads from the environment. Nothing imports back into it. |
| `status` | `query_status`, `status_summary`, `_status_from_counts`, `severity_for_classification` | Pure functions, no I/O, already covered by tests. |
| `external_links` | `netify_url`, `dnschecker_url`, `mac_lookup_url`, `vendor_lookup_url`, `device_search_url` | String builders with no state. |

### Tier 2 — single clear owner, moderate coupling

| Boundary | Current location | Main obstacle |
| --- | --- | --- |
| `db` | `init_db`, `add_column_if_missing` | Every caller opens its own connection against the module-level `DB_PATH`. Moving the schema is easy; moving *connection ownership* is the real work. |
| `adguard` | `agh_login`, `agh_get`, `fetch_querylog`, `fetch_clients`, `adguard_current_status` | Shares the module-level `session` object. |
| `trackerdb` | `refresh_trackerdb`, `trackerdb_ready`, `_open_trackerdb`, `_execute_sql_file` | Self-contained apart from config. |
| `observability` | lines 2547–3180 | Large but weakly coupled. Reads globals for diagnostics, which is inherent to what it does. |

### Tier 3 — high coupling, split last

| Boundary | Current location | Main obstacle |
| --- | --- | --- |
| `enrichment` | lines 1208–1692 | Four independent external sources, each with its own cache table, TTL and retry policy. Splitting these apart from each other is probably more valuable than splitting them from `app.py`. |
| `devices` | lines 608–940 | Identity resolution reads and writes `devices`, `device_ips`, `client_cache` *and* the `clients_json` column on `domains`. The device/domain relationship is denormalised. |
| `analytics` | `get_recent`, `get_stats`, `get_filter_options`, `state_payload` | `get_recent` performs filtering, pagination, enrichment lookups and background scheduling in one function. It needs decomposing before it can be moved. |
| `ui` | `HTML` string, plus every `*_html` function | The entire interface is one Python string containing HTML, CSS and JavaScript, rendered with `render_template_string`. See the note below. |

### The UI is a special case

`HTML` is a ~210-line string literal holding the complete interface. The
`*_html` helper functions build fragments that are interpolated into it, and
`/api/state` returns pre-rendered HTML alongside JSON.

This means the UI cannot be extracted by moving functions. It requires a decision
first: move to real Jinja template files, or move to a JSON-only API with the
rendering done client-side. That decision should be made explicitly in its own
version, not as a side effect of a refactor.

---

## Suggested sequence

Each of these is intended to be one version, in the sense the development process
uses — one focused change, independently testable.

1. Fix `/api/observability` (see finding D-1). Small, isolated, adds an endpoint
   test, and proves the new CI gate works on a real defect.
2. Extract `config` into a module. Lowest risk, and every later extraction
   depends on it.
3. Extract the pure `status` helpers with their existing tests.
4. Establish a single database access helper so connection ownership is in one
   place, without changing the connection model itself.
5. Extract `trackerdb` and `adguard`.
6. Decompose `get_recent` in place, before attempting to move analytics.
7. Decide the UI direction.

Steps 1–5 do not require any behaviour change. Steps 6 and 7 do, and should be
scoped accordingly.

---

## Deferred findings register

Problems found during 0.8.0 that were **documented and not fixed**, per the
strict scope rule. Each is a candidate for a future version.

### D-1 — `/api/observability` is bound to the wrong function (broken in production)

**Severity: real defect, currently live.**

A patch inserted code between the route decorator and the function it was meant
to decorate. The result, in 0.7.14 and preserved unchanged in 0.8.0:

```python
@app.route('/api/observability')

def _memory_diagnostics_container_summary(value):   # ← receives the route
    ...

def api_observability():                            # ← never registered
    ...
```

Flask's URL map confirms the binding:

```text
/api/observability  ->  _memory_diagnostics_container_summary
```

Because `_memory_diagnostics_container_summary` requires a positional argument,
any request to `/api/observability` raises `TypeError` and returns 500.
`api_observability()` is unreachable dead code.

The dashboard header is unaffected — 0.7.13-hotfix.2.4 moved uptime and RAM onto
the `/api/state` refresh path, which is why this has not been visible in normal
use.

Fix is one blank line plus a decorator move. Recommended as 0.8.1.

All other route decorators were checked; this is the only one affected.

### D-2 — `_observability_payload` is defined twice

The second definition wraps the first via
`_original_observability_payload = _observability_payload`. This works, and was a
reasonable way to extend a payload from a patch script, but in a normal source
file it is just a confusing redefinition. It should be collapsed into a single
function when `observability` is extracted.

### D-3 — Additive-only schema migration

`add_column_if_missing` can add columns but cannot rename, drop, change a type or
backfill conditionally. This has been sufficient so far. It will not be
sufficient if the catalog model in the roadmap requires restructuring `domains`.

Not a reason to adopt Alembic now. It is a reason to decide deliberately when the
first non-additive migration is needed, rather than discovering the limit mid-change.

### D-4 — Production serving uses the Werkzeug development server

`app.run()` prints its own warning about this on every start. For a single-user
hobby deployment on a trusted LAN this is a defensible tradeoff, not a bug. Worth
revisiting only if the Inspector is ever exposed beyond the local network, at
which point a WSGI server would be a one-line change plus a Dockerfile `CMD`
update.

### D-5 — `get_recent` does too much

It handles status filtering, pagination, enrichment lookups, background refresh
scheduling and row rendering in a single function, with two distinct code paths
depending on whether a "simple" filter is in use. It is the single largest
obstacle to extracting analytics, and the place where a behaviour regression is
most likely to hide.

### D-6 — Device/domain relationship is denormalised

Client associations live both in the `device_ips` / `client_cache` tables and in
the `clients_json` text column on `domains`. `migrate_legacy_domain_clients` and
`reconcile_neighbors` exist to keep these consistent. Any devices refactor has to
address this first.

### D-7 — Removed dead patch script

`build_ui_patch_v2.py` existed in the repository but was never referenced by the
Dockerfile, so it had no effect on any build. Removed with the rest of the patch
chain in 0.8.0. Recorded here only so its disappearance is not mistaken for a
lost feature.
