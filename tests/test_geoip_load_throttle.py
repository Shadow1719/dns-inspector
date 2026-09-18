"""Low-impact GeoIP CSV parse/reload throttling (Issue #50 / 0.8.5.10).

`CsvRangeGeoIPProvider`/`CsvCityGeoIPProvider` are the actual CPU/disk-heavy
step behind both the deferred initial GeoIP load
(`_geoip_initial_load_worker()`) and a completed auto-update's in-process
reload (`_reload_geoip_providers()`); a real DB-IP City Lite export is
several million rows. These tests pin the throttle hook
(`_iter_csv_rows_throttled()`) that yields the process after every bounded
chunk of parsed rows, its env-configurable defaults, and that correctness
(row content, order, and lookup behaviour) is unchanged by throttling.
"""

import pytest


def _country_csv_rows(n):
    lines = ["start_ip,end_ip,country_code,country_name"]
    for i in range(n):
        base = i * 4
        lines.append(f"10.0.{base // 256}.{base % 256},10.0.{base // 256}.{base % 256 + 1},US,United States")
    return "\n".join(lines) + "\n"


def test_default_chunk_and_yield_config_are_sane_dev_defaults(app_module):
    """Env-overridable, but must ship with usable out-of-the-box values."""
    assert app_module.GEOIP_LOAD_CHUNK_ROWS >= 1
    assert app_module.GEOIP_LOAD_YIELD_SECONDS >= 0.0


def test_throttled_iterator_yields_every_row_in_order(app_module):
    rows = [["a"], ["b"], ["c"], ["d"], ["e"]]
    out = list(app_module._iter_csv_rows_throttled(iter(rows), chunk_rows=2, yield_seconds=0))
    assert out == rows


def test_throttled_iterator_sleeps_once_per_full_chunk(app_module, monkeypatch):
    sleeps = []
    monkeypatch.setattr(app_module.time, "sleep", lambda s: sleeps.append(s))

    rows = [[str(i)] for i in range(11)]  # 11 rows, chunk of 3 -> 3 full chunks
    list(app_module._iter_csv_rows_throttled(iter(rows), chunk_rows=3, yield_seconds=0.02))

    assert sleeps == [0.02, 0.02, 0.02]


def test_throttled_iterator_does_not_sleep_when_yield_seconds_is_zero(app_module, monkeypatch):
    sleeps = []
    monkeypatch.setattr(app_module.time, "sleep", lambda s: sleeps.append(s))

    rows = [[str(i)] for i in range(20)]
    list(app_module._iter_csv_rows_throttled(iter(rows), chunk_rows=3, yield_seconds=0))

    assert sleeps == []


def test_throttled_iterator_does_not_sleep_when_chunk_rows_disabled(app_module, monkeypatch):
    sleeps = []
    monkeypatch.setattr(app_module.time, "sleep", lambda s: sleeps.append(s))

    rows = [[str(i)] for i in range(20)]
    list(app_module._iter_csv_rows_throttled(iter(rows), chunk_rows=0, yield_seconds=0.5))

    assert sleeps == []


def test_csv_range_provider_load_uses_module_throttle_defaults(app_module, monkeypatch, tmp_path):
    """`_load()` must route through the throttle hook using the module-level
    `GEOIP_LOAD_CHUNK_ROWS`/`GEOIP_LOAD_YIELD_SECONDS` config by default."""
    calls = []
    real_iter = app_module._iter_csv_rows_throttled

    def spy(reader, chunk_rows=None, yield_seconds=None):
        calls.append((chunk_rows, yield_seconds))
        return real_iter(reader, chunk_rows=chunk_rows, yield_seconds=yield_seconds)

    monkeypatch.setattr(app_module, "_iter_csv_rows_throttled", spy)
    monkeypatch.setattr(app_module, "GEOIP_LOAD_CHUNK_ROWS", 7)
    monkeypatch.setattr(app_module, "GEOIP_LOAD_YIELD_SECONDS", 0.0)

    csv_path = tmp_path / "geoip.csv"
    csv_path.write_text(_country_csv_rows(5))
    provider = app_module.CsvRangeGeoIPProvider(str(csv_path))

    assert provider.available is True
    assert calls == [(None, None)]


def test_csv_range_provider_correctness_is_unchanged_under_a_tight_throttle(app_module, monkeypatch, tmp_path):
    """A tiny chunk size (heavy throttling) must not change what gets loaded
    or how lookups resolve -- only how often the loop yields."""
    monkeypatch.setattr(app_module, "GEOIP_LOAD_CHUNK_ROWS", 1)
    monkeypatch.setattr(app_module, "GEOIP_LOAD_YIELD_SECONDS", 0.0)

    csv_path = tmp_path / "geoip.csv"
    csv_path.write_text(
        "start_ip,end_ip,country_code,country_name\n"
        "203.0.113.0,203.0.113.255,US,United States\n"
        "198.51.100.0,198.51.100.255,DE,Germany\n"
    )
    provider = app_module.CsvRangeGeoIPProvider(str(csv_path))

    assert provider.available is True
    assert provider.range_count == 2
    assert provider.lookup("203.0.113.42") == ("US", "United States")
    assert provider.lookup("198.51.100.7") == ("DE", "Germany")
    assert provider.lookup("192.0.2.1") == (None, None)


def test_csv_city_provider_correctness_is_unchanged_under_a_tight_throttle(app_module, monkeypatch, tmp_path):
    monkeypatch.setattr(app_module, "GEOIP_LOAD_CHUNK_ROWS", 1)
    monkeypatch.setattr(app_module, "GEOIP_LOAD_YIELD_SECONDS", 0.0)

    csv_path = tmp_path / "geoip_city.csv"
    csv_path.write_text(
        "start_ip,end_ip,country_code,country_name,city,latitude,longitude\n"
        "203.0.113.0,203.0.113.255,US,United States,Springfield,39.78,-89.65\n"
    )
    provider = app_module.CsvCityGeoIPProvider(str(csv_path))

    assert provider.available is True
    result = provider.lookup_city("203.0.113.42")
    assert result["country_code"] == "US"
    assert result["country_name"] == "United States"
    assert result["city"] == "Springfield"
    assert result["lat"] == pytest.approx(39.78)
    assert result["lon"] == pytest.approx(-89.65)


def test_csv_range_provider_load_chunks_across_a_real_yield_boundary(app_module, monkeypatch, tmp_path):
    """End-to-end: a database larger than one chunk actually triggers a sleep
    between chunks, and every row still loads correctly."""
    sleeps = []
    monkeypatch.setattr(app_module.time, "sleep", lambda s: sleeps.append(s))
    monkeypatch.setattr(app_module, "GEOIP_LOAD_CHUNK_ROWS", 3)
    monkeypatch.setattr(app_module, "GEOIP_LOAD_YIELD_SECONDS", 0.001)

    csv_path = tmp_path / "geoip.csv"
    csv_path.write_text(_country_csv_rows(10))
    provider = app_module.CsvRangeGeoIPProvider(str(csv_path))

    assert provider.available is True
    assert provider.range_count == 10
    # 10 data rows + 1 header row = 11 rows through the throttle hook,
    # chunk size 3 -> 3 full chunks -> 3 sleeps.
    assert sleeps == [0.001, 0.001, 0.001]
