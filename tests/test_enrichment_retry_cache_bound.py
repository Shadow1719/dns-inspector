"""Issue #76: normal-runtime RAM growth that survived the Issue #73 fix.

Issue #73 / PR #74 fixed `reconcile_neighbors()`'s unconditional full
`domains`/`devices` table scan on every poll cycle. Real DEV evidence after
that fix still showed ~3.5 GB of RAM growth in ~35 minutes of normal
(non-debug-bundle) runtime, so this is a second, independent root cause.

Root cause: `_enrichment_retry_until` (domain -> next-allowed-retry timestamp)
and `_enrichment_retry_loaded` (domains whose retry state has been read from
the persistent `enrichment_attempts` table at least once) are an in-memory
front-cache populated by `_enrichment_retry_allowed()`/`_mark_enrichment_attempt()`,
called from `_queue_domain_enrichment()` for every newly-discovered domain
`ingest()` sees. Every other in-process cache in `app.py` is either a bounded
FIFO (`_geoip_cache`, `_geoip_city_cache`, both capped by
`GEOIP_CACHE_MAX_ENTRIES`/`GEOIP_CITY_CACHE_MAX_ENTRIES`) or an add/discard
pair that never outlives an in-flight lookup (`_status_inflight`,
`_enrich_inflight`, `_enrichment_queued`, `enrichment_refreshing`) -- these two
dicts/sets were the only ones with no eviction at all, so they grew by one
entry per *distinct* domain ever seen, for the entire lifetime of the process.
A busy network can see a very large number of distinct domains (ad/tracking
infrastructure frequently mints a unique subdomain per request specifically to
defeat blocklists/caching), so this scales with real DNS traffic exactly the
way the issue describes, independent of the already-fixed `domains` table
scan.

`_bound_enrichment_retry_cache()` now evicts the oldest tracked domain once a
shared FIFO (`_enrichment_retry_order`) exceeds
`ENRICHMENT_RETRY_CACHE_MAX_ENTRIES`, the same pattern the GeoIP lookup caches
already use elsewhere in this file. An evicted domain is simply re-read from
the persistent `enrichment_attempts` table on its next check -- a cache miss,
never a correctness change, which the second test below pins directly.
"""

import time


def _reset_enrichment_retry_state(app_module):
    app_module._enrichment_retry_until.clear()
    app_module._enrichment_retry_loaded.clear()
    app_module._enrichment_retry_order.clear()


def test_enrichment_retry_cache_is_bounded(app_module, initialised_db, monkeypatch):
    _reset_enrichment_retry_state(app_module)
    monkeypatch.setattr(app_module, "ENRICHMENT_RETRY_CACHE_MAX_ENTRIES", 25)

    for i in range(500):
        app_module._enrichment_retry_allowed(f"issue76-bound-{i}.example.test")

    assert len(app_module._enrichment_retry_order) <= 25, (
        "the enrichment retry-state FIFO grew past its configured bound -- "
        "this is the unbounded per-distinct-domain growth behind Issue #76"
    )
    assert len(app_module._enrichment_retry_loaded) <= 25
    assert len(app_module._enrichment_retry_until) <= 25

    _reset_enrichment_retry_state(app_module)


def test_enrichment_retry_eviction_preserves_persisted_retry_state(app_module, initialised_db, monkeypatch):
    """Evicting a domain from the bounded in-memory cache must never let it
    bypass its real, persisted retry-until timestamp -- the cache is a
    performance optimization over `enrichment_attempts`, not the source of
    truth."""
    _reset_enrichment_retry_state(app_module)
    monkeypatch.setattr(app_module, "ENRICHMENT_RETRY_CACHE_MAX_ENTRIES", 10)

    domain = "issue76-evicted.example.test"
    now_ts = time.time()
    app_module._mark_enrichment_attempt(domain, now_ts=now_ts)
    assert app_module._enrichment_retry_allowed(domain, now_ts=now_ts) is False

    # Push the tracked domain out of the bounded in-memory cache with enough
    # unrelated traffic that a real busy network would generate.
    for i in range(50):
        app_module._enrichment_retry_allowed(f"issue76-other-{i}.example.test", now_ts=now_ts)
    assert domain not in app_module._enrichment_retry_until
    assert domain not in app_module._enrichment_retry_loaded

    # Still not allowed: the real retry-until timestamp lives in
    # `enrichment_attempts` and is re-read on this cache miss.
    assert app_module._enrichment_retry_allowed(domain, now_ts=now_ts) is False

    _reset_enrichment_retry_state(app_module)
