"""`scripts/geoip_memory_benchmark.py` (Issue #52).

A smoke test, not a memory-regression assertion: RSS behavior is host- and
allocator-dependent (see the script's own docstring), so this only proves
the benchmark actually runs end-to-end against the real provider classes --
generates both synthetic CSVs, loads both providers, samples peak RSS during
each load, runs a lookup batch, runs repeated reloads, and reports each
provider's own compact storage size -- without raising, at a tiny row count
so it stays fast in CI. Real before/after numbers at City-Lite scale (Issue
#52's actual acceptance criterion) have to be gathered by running this
script directly -- see docs/CURRENT_STATE.md and docs/GEOIP.md.
"""

from scripts import geoip_memory_benchmark as bench


def test_benchmark_runs_end_to_end_at_a_small_scale(tmp_path, capsys):
    exit_code = bench.main([
        "--country-rows", "200",
        "--city-rows", "300",
        "--lookups", "50",
        "--reloads", "1",
        "--keep-csv", str(tmp_path),
    ])
    assert exit_code == 0
    output = capsys.readouterr().out
    assert "PEAK RSS while country loads" in output
    assert "PEAK RSS while city loads" in output
    assert "compact storage" in output
    assert (tmp_path / "geoip_country_bench.csv").exists()
    assert (tmp_path / "geoip_city_bench.csv").exists()


def test_country_and_city_storage_byte_helpers_are_positive(tmp_path):
    country_csv = tmp_path / "country.csv"
    country_csv.write_text("203.0.113.0,203.0.113.255,US,United States\n")
    city_csv = tmp_path / "city.csv"
    city_csv.write_text("203.0.113.0,203.0.113.255,US,United States,Mountain View,37.386,-122.0838\n")

    country_provider = bench.app.CsvRangeGeoIPProvider(str(country_csv))
    city_provider = bench.app.CsvCityGeoIPProvider(str(city_csv))

    assert bench._country_provider_storage_bytes(country_provider) > 0
    assert bench._city_provider_storage_bytes(city_provider) > 0


def test_peak_rss_sampler_never_raises_when_used_as_a_context_manager():
    with bench._PeakRssSampler(interval_seconds=0.001) as sampler:
        pass
    # peak_mb is None off Linux (no /proc/self/status); either way this must
    # not raise.
    assert sampler.peak_mb is None or sampler.peak_mb >= 0
