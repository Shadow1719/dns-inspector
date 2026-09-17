"""GeoIP provider memory accounting and hot-reload lifecycle (Issue #45).

The real DEV deployment reported container RSS climbing from ~210 MB before
GeoIP data was populated to ~1.4 GiB, then ~2.687 GiB, then ~3.26 GiB across
successive observations -- growth that kept happening rather than settling,
which pointed at the hot-reload lifecycle and parse-time allocator behavior
rather than just the size of the final loaded representation (see
`_release_memory_to_os()`, `CsvRangeGeoIPProvider`/`CsvCityGeoIPProvider` and
`_reload_geoip_providers()` in app.py). These tests are fast/deterministic
correctness checks for that lifecycle; `scripts/benchmark_geoip_memory.py`
is the larger-scale, human-readable RSS benchmark for the same behavior.
"""

import gc
import weakref


class _LegacyFixedProvider:
    """A duck-typed `GeoIPProvider`-shaped test double that predates the
    `approx_bytes` property (Issue #45) and doesn't implement it -- the
    existing test suite has several of these (see test_geoip_destinations_map.py,
    test_geoip_city_map.py, test_geoip_map_diagnostics.py). Diagnostics code
    must tolerate this rather than raising `AttributeError`."""

    def __init__(self, mapping):
        self._mapping = mapping

    def lookup(self, ip):
        return self._mapping.get(ip, (None, None))

    @property
    def available(self):
        return True

    @property
    def path(self):
        return None

    @property
    def range_count(self):
        return len(self._mapping)


def _country_csv(tmp_path, rows):
    path = tmp_path / "country.csv"
    path.write_text("\n".join(",".join(row) for row in rows) + "\n")
    return str(path)


def _city_csv(tmp_path, rows):
    path = tmp_path / "city.csv"
    path.write_text("\n".join(",".join(row) for row in rows) + "\n")
    return str(path)


# --- approx_bytes accounting -------------------------------------------------


def test_null_providers_report_zero_approx_bytes(app_module):
    assert app_module.NullGeoIPProvider().approx_bytes == 0
    assert app_module.NullCityGeoIPProvider().approx_bytes == 0


def test_csv_range_provider_reports_positive_approx_bytes_once_loaded(tmp_path, app_module):
    csv_path = _country_csv(tmp_path, [
        ("203.0.113.0", "203.0.113.255", "US", "United States"),
        ("198.51.100.0", "198.51.100.255", "DE", "Germany"),
    ])
    provider = app_module.CsvRangeGeoIPProvider(csv_path)
    assert provider.available is True
    assert provider.approx_bytes > 0


def test_csv_range_provider_approx_bytes_is_zero_when_unloaded(tmp_path, app_module):
    provider = app_module.CsvRangeGeoIPProvider(str(tmp_path / "does-not-exist.csv"))
    assert provider.available is False
    assert provider.approx_bytes == 0


def test_csv_city_provider_reports_positive_approx_bytes_once_loaded(tmp_path, app_module):
    csv_path = _city_csv(tmp_path, [
        ("203.0.113.0", "203.0.113.255", "US", "United States", "Springfield", "39.1", "-89.6"),
        ("2001:db8::", "2001:db8::ffff", "DE", "Germany", "Berlin", "52.5", "13.4"),
    ])
    provider = app_module.CsvCityGeoIPProvider(csv_path)
    assert provider.available is True
    assert provider.approx_bytes > 0


def test_diagnostics_report_approx_bytes_alongside_range_count(tmp_path, app_module, monkeypatch):
    csv_path = _country_csv(tmp_path, [("203.0.113.0", "203.0.113.255", "US", "United States")])
    provider = app_module.CsvRangeGeoIPProvider(csv_path)
    monkeypatch.setattr(app_module, "_geoip_provider", provider)

    diag = app_module._geoip_diagnostics()

    assert diag["range_count"] == 1
    assert diag["approx_bytes"] > 0


def test_diagnostics_tolerate_a_provider_without_approx_bytes(app_module, monkeypatch):
    """A duck-typed provider (e.g. a pre-existing test double, or any future
    third-party `GeoIPProvider` implementation) that doesn't implement the
    new `approx_bytes` surface must not break diagnostics -- it should just
    report 0, not raise."""
    monkeypatch.setattr(app_module, "_geoip_provider", _LegacyFixedProvider({"203.0.113.10": ("US", "United States")}))

    diag = app_module._geoip_diagnostics()

    assert diag["configured"] is True
    assert diag["approx_bytes"] == 0


# --- string interning ---------------------------------------------------


def test_csv_range_provider_interns_repeated_country_strings(tmp_path, app_module):
    """A real country database repeats the same `code`/`name` across tens or
    hundreds of thousands of rows -- interning means every row sharing a
    country shares one string object rather than allocating a fresh one per
    row (Issue #45). This is the concrete, testable half of that claim: two
    rows with the same country string are the *same* object, not just
    equal."""
    csv_path = _country_csv(tmp_path, [
        ("203.0.113.0", "203.0.113.127", "US", "United States"),
        ("203.0.113.128", "203.0.113.255", "US", "United States"),
    ])
    provider = app_module.CsvRangeGeoIPProvider(csv_path)
    assert len(provider._v4) == 2
    first_code, second_code = provider._v4[0][2], provider._v4[1][2]
    first_name, second_name = provider._v4[0][3], provider._v4[1][3]
    assert first_code is second_code
    assert first_name is second_name


def test_csv_city_provider_interns_repeated_ipv6_strings(tmp_path, app_module):
    """The IPv6 side of `CsvCityGeoIPProvider` stays a plain list of tuples
    (see the class docstring -- IPv6 rows are far fewer in a real export
    than the array-backed IPv4 side), but repeated country/city strings
    across those tuples should still be shared objects, not one fresh
    allocation per row (Issue #45)."""
    csv_path = _city_csv(tmp_path, [
        ("2001:db8::", "2001:db8::ffff", "US", "United States", "Springfield", "39.1", "-89.6"),
        ("2001:db8:1::", "2001:db8:1::ffff", "US", "United States", "Springfield", "39.1", "-89.6"),
    ])
    provider = app_module.CsvCityGeoIPProvider(csv_path)
    assert len(provider._v6) == 2
    first, second = provider._v6[0], provider._v6[1]
    assert first[2] is second[2]  # country_code
    assert first[3] is second[3]  # country_name
    assert first[4] is second[4]  # city


# --- hot-reload lifecycle: old provider is actually released ----------------


def _restore_providers(app_module, provider, city_provider):
    """`_reload_geoip_providers()` mutates `app_module._geoip_provider`/
    `_geoip_city_provider` directly (real module globals, not something
    `monkeypatch` tracks) -- every test that calls it must put the
    session-scoped `app_module` back the way it found it, the same way
    `test_reload_geoip_providers_swaps_the_provider_and_clears_the_cache`
    (test_geoip_auto_update.py) already does, or later tests in the same
    session observe a leaked provider."""
    app_module._geoip_provider = provider
    app_module._geoip_city_provider = city_provider
    app_module._geoip_cache.clear()
    app_module._geoip_cache_order.clear()
    app_module._geoip_city_cache.clear()
    app_module._geoip_city_cache_order.clear()


def test_reload_geoip_providers_allows_the_old_country_provider_to_be_collected(tmp_path, app_module, monkeypatch):
    original_provider = app_module._geoip_provider
    original_city_provider = app_module._geoip_city_provider
    csv_path = _country_csv(tmp_path, [("203.0.113.0", "203.0.113.255", "US", "United States")])
    monkeypatch.setattr(app_module, "GEOIP_DB_PATH", csv_path)
    monkeypatch.setattr(app_module, "GEOIP_CITY_DB_PATH", str(tmp_path / "no-city.csv"))

    try:
        app_module._reload_geoip_providers()
        old_ref = weakref.ref(app_module._geoip_provider)

        app_module._reload_geoip_providers()
        gc.collect()

        assert old_ref() is None, "the pre-reload provider is still referenced somewhere and was never released"
    finally:
        _restore_providers(app_module, original_provider, original_city_provider)


def test_reload_geoip_providers_allows_the_old_city_provider_to_be_collected(tmp_path, app_module, monkeypatch):
    original_provider = app_module._geoip_provider
    original_city_provider = app_module._geoip_city_provider
    csv_path = _city_csv(tmp_path, [
        ("203.0.113.0", "203.0.113.255", "US", "United States", "Springfield", "39.1", "-89.6"),
    ])
    monkeypatch.setattr(app_module, "GEOIP_DB_PATH", str(tmp_path / "no-country.csv"))
    monkeypatch.setattr(app_module, "GEOIP_CITY_DB_PATH", csv_path)

    try:
        app_module._reload_geoip_providers()
        old_ref = weakref.ref(app_module._geoip_city_provider)

        app_module._reload_geoip_providers()
        gc.collect()

        assert old_ref() is None, "the pre-reload city provider is still referenced somewhere and was never released"
    finally:
        _restore_providers(app_module, original_provider, original_city_provider)


def test_reload_geoip_providers_does_not_grow_approx_bytes_across_repeated_reloads(tmp_path, app_module, monkeypatch):
    """Repeated reloads against the *same* unchanged database must settle at
    the same `approx_bytes`, not accumulate -- a regression guard for "old
    provider instances remain alive after hot reload"."""
    original_provider = app_module._geoip_provider
    original_city_provider = app_module._geoip_city_provider
    csv_path = _country_csv(tmp_path, [
        ("203.0.113.0", "203.0.113.127", "US", "United States"),
        ("198.51.100.0", "198.51.100.255", "DE", "Germany"),
    ])
    monkeypatch.setattr(app_module, "GEOIP_DB_PATH", csv_path)
    monkeypatch.setattr(app_module, "GEOIP_CITY_DB_PATH", str(tmp_path / "no-city.csv"))

    try:
        app_module._reload_geoip_providers()
        first_bytes = app_module._geoip_provider.approx_bytes
        first_count = app_module._geoip_provider.range_count

        for _ in range(3):
            app_module._reload_geoip_providers()

        assert app_module._geoip_provider.range_count == first_count
        assert app_module._geoip_provider.approx_bytes == first_bytes
    finally:
        _restore_providers(app_module, original_provider, original_city_provider)


# --- _release_memory_to_os() is always safe ----------------------------


def test_release_memory_to_os_never_raises(app_module):
    app_module._release_memory_to_os()


def test_release_memory_to_os_is_safe_when_malloc_trim_is_unavailable(app_module, monkeypatch):
    import ctypes

    class _NoTrimLibc:
        pass  # no `malloc_trim` attribute -- exercises the `hasattr` guard

    monkeypatch.setattr(ctypes, "CDLL", lambda *_a, **_k: _NoTrimLibc())

    app_module._release_memory_to_os()


def test_release_memory_to_os_is_safe_when_libc_cannot_be_found(app_module, monkeypatch):
    import ctypes.util

    monkeypatch.setattr(ctypes.util, "find_library", lambda *_a, **_k: None)

    app_module._release_memory_to_os()
