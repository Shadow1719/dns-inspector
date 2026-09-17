"""GeoIP/map memory-sensitive behavior (Issue #45).

A real TrueNAS deployment observed ~1.4 GiB RSS once the GeoIP-backed
destination map became populated. Investigation found the dominant transient
cost was `CsvRangeGeoIPProvider`/`CsvCityGeoIPProvider` building a plain
Python list of one tuple per CSV row, sorting it, then copying it into the
final packed `array.array` columns -- for a multi-million-row city database,
that temporary list (not the final columns) was the expensive part, and
CPython/glibc do not reliably return that freed memory to the OS. Both
providers now stream rows directly into the final columns (falling back to
an index-permutation sort only for genuinely out-of-order input).

These tests use small in-memory CSV fixtures -- never a real, multi-million-
row database (see `scripts/geoip_memory_benchmark.py` for a synthetic-scale
benchmark to run manually). They pin the packed representation itself (so a
future change can't silently reintroduce a per-row tuple list without a test
noticing), bounded-cache behavior across many repeated lookups/map requests,
and that a hot-reload genuinely drops the old provider rather than merely
replacing the name it's bound to.
"""

import array
import gc
import json
import sqlite3
import uuid
import weakref
from contextlib import closing


def _unique(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _insert_domain(db_path, domain, now, requests=1):
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO domains"
            "(domain,first_seen,last_seen,requests,clients_json,blocked_requests,"
            "allowed_requests,unknown_requests,last_status,current_status)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            (domain, now, now, requests, json.dumps({}), 0, requests, 0, "Allowed", "Allowed"),
        )
        conn.commit()


def _add_destination_ip(db_path, domain, now, ip, observations=1):
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO domain_destination_ips(domain,ip,first_seen,last_seen,observations) "
            "VALUES(?,?,?,?,?)",
            (domain, ip, now, now, observations),
        )
        conn.commit()


# --- Packed representation regression guards --------------------------------

def test_country_provider_v4_columns_are_packed_arrays_not_tuple_lists(tmp_path, app_module):
    csv_path = tmp_path / "geoip.csv"
    csv_path.write_text(
        "203.0.113.0,203.0.113.63,US,United States\n"
        "198.51.100.0,198.51.100.63,DE,Germany\n"
    )
    provider = app_module.CsvRangeGeoIPProvider(str(csv_path))
    assert isinstance(provider._v4_start, array.array)
    assert isinstance(provider._v4_end, array.array)
    assert isinstance(provider._v4_country_idx, array.array)
    # Country/name strings are interned once each, not duplicated per range.
    assert len(provider._countries) == 2


def test_city_provider_v4_columns_are_packed_arrays_not_tuple_lists(tmp_path, app_module):
    csv_path = tmp_path / "geoip_city.csv"
    csv_path.write_text(
        "203.0.113.0,203.0.113.63,US,United States,Springfield,39.78,-89.65\n"
        "198.51.100.0,198.51.100.63,DE,Germany,Berlin,52.52,13.405\n"
    )
    provider = app_module.CsvCityGeoIPProvider(str(csv_path))
    for attr in ("_v4_start", "_v4_end", "_v4_lat", "_v4_lon", "_v4_country_idx", "_v4_city_idx"):
        assert isinstance(getattr(provider, attr), array.array), attr
    assert len(provider._countries) == 2
    assert len(provider._cities) == 2


def test_city_provider_handles_out_of_order_input(tmp_path, app_module):
    """A real DB-IP export is already sorted ascending by start address, so
    `_load()` streams straight into the final columns in that case -- but
    out-of-order input must still sort correctly via the index-permutation
    fallback."""
    csv_path = tmp_path / "geoip_city.csv"
    csv_path.write_text(
        "198.51.100.0,198.51.100.63,DE,Germany,Berlin,52.52,13.405\n"
        "203.0.113.0,203.0.113.63,US,United States,Springfield,39.78,-89.65\n"
        "10.0.0.0,10.0.0.63,ZZ,Nowhereland,Nowhere,0.0,0.0\n"
    )
    provider = app_module.CsvCityGeoIPProvider(str(csv_path))
    assert list(provider._v4_start) == sorted(provider._v4_start)
    assert provider.lookup_city("198.51.100.10")["city"] == "Berlin"
    assert provider.lookup_city("203.0.113.10")["city"] == "Springfield"
    assert provider.lookup_city("10.0.0.10")["city"] == "Nowhere"


# --- Bounded caches -----------------------------------------------------------

def test_geoip_lookup_cache_stays_bounded_across_many_distinct_ips(app_module, monkeypatch):
    """`GEOIP_CACHE_MAX_ENTRIES` bounds the per-IP country cache with FIFO
    eviction -- looking up far more distinct IPs than the limit must never
    let the cache (or its eviction-order queue) grow past that bound."""
    monkeypatch.setattr(app_module, "GEOIP_CACHE_MAX_ENTRIES", 64)
    monkeypatch.setattr(app_module, "_geoip_provider", app_module.NullGeoIPProvider())
    app_module._geoip_cache.clear()
    app_module._geoip_cache_order.clear()
    try:
        for i in range(64 * 5):
            app_module.geoip_lookup(f"203.0.{i // 256}.{i % 256}")
        assert len(app_module._geoip_cache) <= 64
        assert len(app_module._geoip_cache_order) <= 64
    finally:
        app_module._geoip_cache.clear()
        app_module._geoip_cache_order.clear()


def test_geoip_city_lookup_cache_stays_bounded_across_many_distinct_ips(app_module, monkeypatch):
    monkeypatch.setattr(app_module, "GEOIP_CITY_CACHE_MAX_ENTRIES", 64)
    monkeypatch.setattr(app_module, "_geoip_city_provider", app_module.NullCityGeoIPProvider())
    app_module._geoip_city_cache.clear()
    app_module._geoip_city_cache_order.clear()
    try:
        for i in range(64 * 5):
            app_module.geoip_city_lookup(f"203.0.{i // 256}.{i % 256}")
        assert len(app_module._geoip_city_cache) <= 64
        assert len(app_module._geoip_city_cache_order) <= 64
    finally:
        app_module._geoip_city_cache.clear()
        app_module._geoip_city_cache_order.clear()


def test_repeated_map_requests_hold_a_single_cached_payload_not_a_growing_history(app_module, monkeypatch, initialised_db):
    """`geoip_map_payload()`'s own cache (`_geoip_map_cache`) is a single
    `{"at": ..., "data": ...}` slot that the next call overwrites -- repeated
    map requests (even with the cache forced to recompute every time) must
    never accumulate a history of past payloads."""
    domain = _unique("mem-map-domain")
    now = app_module.utcnow()
    _insert_domain(initialised_db, domain, now, requests=3)
    _add_destination_ip(initialised_db, domain, now, "203.0.113.10", observations=3)

    provider = app_module.CsvRangeGeoIPProvider.__new__(app_module.CsvRangeGeoIPProvider)
    provider._path = None
    provider._v4_start = array.array('I', [0])
    provider._v4_end = array.array('I', [2**32 - 1])
    provider._v4_country_idx = array.array('H', [0])
    provider._countries = [("US", "United States")]
    provider._v6, provider._v6_starts = [], []
    provider._loaded = True
    monkeypatch.setattr(app_module, "_geoip_provider", provider)
    monkeypatch.setattr(app_module, "_geoip_city_provider", app_module.NullCityGeoIPProvider())
    app_module._geoip_cache.clear()
    app_module._geoip_cache_order.clear()
    try:
        for _ in range(20):
            app_module._geoip_map_cache["at"] = 0.0  # force recompute every call
            app_module.geoip_map_payload()
        assert set(app_module._geoip_map_cache.keys()) == {"at", "data"}
        assert app_module._geoip_map_cache["data"]["coverage"]["total_observations"] == 3
    finally:
        app_module._geoip_map_cache["data"] = None
        app_module._geoip_map_cache["at"] = 0.0
        app_module._geoip_cache.clear()
        app_module._geoip_cache_order.clear()


# --- Hot-reload lifecycle ------------------------------------------------------

def test_reload_geoip_providers_drops_the_old_country_provider(app_module, monkeypatch, tmp_path):
    """Issue #45: a reload must not leave the previous provider instance
    reachable/resident once every in-flight lookup that grabbed it has
    returned -- checked with a real `weakref`, not just "the module attribute
    now points somewhere else"."""
    original_provider = app_module._geoip_provider
    original_city_provider = app_module._geoip_city_provider
    csv_path = tmp_path / "geoip.csv"
    csv_path.write_text("203.0.113.0,203.0.113.255,US,United States\n")
    monkeypatch.setattr(app_module, "GEOIP_DB_PATH", str(csv_path))
    monkeypatch.setattr(app_module, "GEOIP_CITY_DB_PATH", str(tmp_path / "missing-city.csv"))

    old_provider = app_module.CsvRangeGeoIPProvider(str(tmp_path / "also-missing.csv"))
    monkeypatch.setattr(app_module, "_geoip_provider", old_provider)
    old_ref = weakref.ref(old_provider)
    del old_provider

    try:
        app_module._reload_geoip_providers()
        assert app_module._geoip_provider is not None
        gc.collect()
        assert old_ref() is None, "old GeoIP provider is still referenced somewhere after reload"
    finally:
        app_module._geoip_provider = original_provider
        app_module._geoip_city_provider = original_city_provider
        app_module._geoip_cache.clear()
        app_module._geoip_cache_order.clear()
        app_module._geoip_city_cache.clear()
        app_module._geoip_city_cache_order.clear()


def test_reload_geoip_providers_drops_the_old_city_provider(app_module, monkeypatch, tmp_path):
    original_provider = app_module._geoip_provider
    original_city_provider = app_module._geoip_city_provider
    monkeypatch.setattr(app_module, "GEOIP_DB_PATH", str(tmp_path / "missing-country.csv"))
    monkeypatch.setattr(app_module, "GEOIP_CITY_DB_PATH", str(tmp_path / "missing-city.csv"))

    old_city_provider = app_module.CsvCityGeoIPProvider(str(tmp_path / "also-missing.csv"))
    monkeypatch.setattr(app_module, "_geoip_city_provider", old_city_provider)
    old_ref = weakref.ref(old_city_provider)
    del old_city_provider

    try:
        app_module._reload_geoip_providers()
        assert app_module._geoip_city_provider is not None
        gc.collect()
        assert old_ref() is None, "old GeoIP city provider is still referenced somewhere after reload"
    finally:
        app_module._geoip_provider = original_provider
        app_module._geoip_city_provider = original_city_provider
        app_module._geoip_cache.clear()
        app_module._geoip_cache_order.clear()
        app_module._geoip_city_cache.clear()
        app_module._geoip_city_cache_order.clear()
