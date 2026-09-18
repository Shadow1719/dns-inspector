"""Compact-storage GeoIP loader redesign (Issue #52).

0.8.5.10's chunk/yield throttle only changed *when* CSV parsing happened,
not the peak memory it used: `CsvCityGeoIPProvider._load()` used to buffer
every IPv4 row as a Python tuple in a `v4_rows` list, sort that list, and
only then copy it into compact `array.array` columns -- so a multi-million-
row DB-IP City Lite database could peak at gigabytes of temporary Python
objects before the compact representation became usable.
`CsvRangeGeoIPProvider` had the equivalent problem permanently (its
`self._v4`/`self._v6` were never anything but Python tuples).

These tests cover the replacement, `_CompactRangeTableBuilder`, and pin that
both providers now stream straight into `array.array` columns (with a
sort-by-permutation fallback for input that is not already ordered by start
IP) instead of ever materializing a list of row tuples.
"""

import array
import gc
import resource
import sys

import pytest


# --- _CompactRangeTableBuilder ------------------------------------------------


def test_builder_stores_sorted_input_without_reordering(app_module):
    builder = app_module._CompactRangeTableBuilder(('H',))
    builder.append(10, 20, 1)
    builder.append(30, 40, 2)
    builder.append(50, 60, 3)
    builder.finalize()
    assert list(builder.start) == [10, 30, 50]
    assert list(builder.end) == [20, 40, 60]
    assert list(builder.extra[0]) == [1, 2, 3]


def test_builder_detects_and_corrects_out_of_order_input(app_module):
    builder = app_module._CompactRangeTableBuilder(('H', 'f'))
    builder.append(50, 60, 3, 3.5)
    builder.append(10, 20, 1, 1.5)
    builder.append(30, 40, 2, 2.5)
    builder.finalize()
    assert list(builder.start) == [10, 30, 50]
    assert list(builder.end) == [20, 40, 60]
    assert list(builder.extra[0]) == [1, 2, 3]
    assert list(builder.extra[1]) == pytest.approx([1.5, 2.5, 3.5])


def test_builder_columns_are_array_array_not_python_lists(app_module):
    """The whole point of the redesign: the storage columns must be primitive
    `array.array` buffers, never a Python list of tuples."""
    builder = app_module._CompactRangeTableBuilder(('H',))
    builder.append(1, 2, 1)
    builder.finalize()
    assert isinstance(builder.start, array.array)
    assert isinstance(builder.end, array.array)
    assert isinstance(builder.extra[0], array.array)


def test_builder_handles_empty_and_single_row_input(app_module):
    builder = app_module._CompactRangeTableBuilder(('H',))
    builder.finalize()
    assert list(builder.start) == []

    builder2 = app_module._CompactRangeTableBuilder(('H',))
    builder2.append(5, 6, 1)
    builder2.finalize()
    assert list(builder2.start) == [5]


# --- Providers use array.array storage, never a row-tuple staging list ------


def test_csv_range_provider_v4_storage_is_compact_arrays(tmp_path, app_module):
    csv_path = tmp_path / "geoip.csv"
    csv_path.write_text("203.0.113.0,203.0.113.63,US,United States\n")
    provider = app_module.CsvRangeGeoIPProvider(str(csv_path))
    assert isinstance(provider._v4_start, array.array)
    assert isinstance(provider._v4_end, array.array)
    assert isinstance(provider._v4_country_idx, array.array)
    assert not hasattr(provider, "_v4")  # the old plain-tuple-list attribute is gone


def test_csv_city_provider_v4_storage_is_compact_arrays(tmp_path, app_module):
    csv_path = tmp_path / "geoip_city.csv"
    csv_path.write_text("203.0.113.0,203.0.113.63,US,United States,Mountain View,37.386,-122.0838\n")
    provider = app_module.CsvCityGeoIPProvider(str(csv_path))
    assert isinstance(provider._v4_start, array.array)
    assert isinstance(provider._v4_lat, array.array)
    assert not hasattr(provider, "_v4_rows")


def test_csv_city_provider_sorts_out_of_order_ipv4_rows_correctly(tmp_path, app_module):
    """Real DB-IP exports are already sorted by start IP, but the loader must
    still be correct if a source file is not (Issue #52's sort fallback)."""
    csv_path = tmp_path / "geoip_city.csv"
    csv_path.write_text(
        "198.51.100.0,198.51.100.63,DE,Germany,Berlin,52.52,13.405\n"
        "10.0.0.0,10.0.0.63,US,United States,Reston,38.95,-77.35\n"
        "203.0.113.0,203.0.113.63,FR,France,Paris,48.85,2.35\n"
    )
    provider = app_module.CsvCityGeoIPProvider(str(csv_path))
    assert list(provider._v4_start) == sorted(provider._v4_start)
    assert provider.lookup_city("10.0.0.10")["city"] == "Reston"
    assert provider.lookup_city("198.51.100.10")["city"] == "Berlin"
    assert provider.lookup_city("203.0.113.10")["city"] == "Paris"


# --- Peak-RSS regression guard (CI-safe: moderate row count, not multi-million) -


def _country_csv_text(n):
    lines = ["start_ip,end_ip,country_code,country_name"]
    codes = ["US", "DE", "FR", "GB", "JP"]
    for i in range(n):
        base = i * 256
        a, b, c = (base // 256) % 256, (base // 65536) % 256, (base // 16777216) % 256
        code = codes[i % len(codes)]
        lines.append(f"{c}.{b}.{a}.0,{c}.{b}.{a}.255,{code},{code} Country")
    return "\n".join(lines) + "\n"


def _rss_kb():
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss


@pytest.mark.skipif(sys.platform == "darwin", reason="ru_maxrss units differ on macOS; this guard is tuned for Linux CI")
def test_country_provider_load_stays_within_a_bounded_bytes_per_row_budget(tmp_path, app_module):
    """Regression guard for Issue #52: loading N rows must not cost anywhere
    near the ~150-300 bytes/row a Python tuple-per-row staging list would
    have cost. The compact `array.array` representation is ~14 bytes/row
    (8+4+2); this allows a generous multiple for CSV-parsing/interpreter
    transient overhead while still catching a regression back to a
    per-row-tuple staging list.

    This is a CI-safe regression guard at a moderate row count -- the full
    multi-million-row benchmark lives in scripts/geoip_memory_benchmark.py
    and is meant to be run manually against a representative dataset.
    """
    n = 60_000
    csv_path = tmp_path / "geoip.csv"
    csv_path.write_text(_country_csv_text(n))

    gc.collect()
    before_kb = _rss_kb()
    provider = app_module.CsvRangeGeoIPProvider(str(csv_path))
    after_kb = _rss_kb()

    assert provider.range_count == n
    delta_kb = after_kb - before_kb
    budget_kb = (n * 120) / 1024.0  # 120 bytes/row is already ~8x the compact storage size
    assert delta_kb < budget_kb, (
        f"loading {n} rows grew peak RSS by {delta_kb:.0f} KiB, "
        f"over the {budget_kb:.0f} KiB budget -- possible regression back to a "
        f"per-row Python object staging structure"
    )
