"""`scripts/verify_geoip.py` (Issue #39 / 0.8.5.4).

A standalone, offline pre-flight check an operator runs against a converted
CSV *before* mounting/restarting the Inspector, so a broken conversion or a
wrong path is caught immediately rather than discovered later via an empty
map. It intentionally does not import `app.py` (no Flask/requests
dependency), so these tests exercise it in isolation with small temp-file
fixtures.
"""

from scripts import verify_geoip


# --- range loading/lookup ----------------------------------------------------


def test_load_country_ranges_parses_ipv4_and_ipv6_rows(tmp_path):
    csv_path = tmp_path / "geoip.csv"
    csv_path.write_text(
        "203.0.113.0,203.0.113.255,US,United States\n"
        "2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,DE,Germany\n"
    )
    v4, v6 = verify_geoip.load_country_ranges(str(csv_path))
    assert len(v4) == 1
    assert len(v6) == 1


def test_load_country_ranges_skips_a_header_row(tmp_path):
    csv_path = tmp_path / "geoip.csv"
    csv_path.write_text("start_ip,end_ip,country_code,country_name\n203.0.113.0,203.0.113.255,US,United States\n")
    v4, _ = verify_geoip.load_country_ranges(str(csv_path))
    assert len(v4) == 1


def test_load_country_ranges_skips_malformed_rows_individually(tmp_path):
    csv_path = tmp_path / "geoip.csv"
    csv_path.write_text("not,enough\n203.0.113.0,203.0.113.255,US,United States\n")
    v4, _ = verify_geoip.load_country_ranges(str(csv_path))
    assert len(v4) == 1


def test_lookup_range_finds_an_ip_inside_a_loaded_range(tmp_path):
    csv_path = tmp_path / "geoip.csv"
    csv_path.write_text("203.0.113.0,203.0.113.255,US,United States\n")
    v4, v6 = verify_geoip.load_country_ranges(str(csv_path))
    hit = verify_geoip.lookup_range(v4, v6, "203.0.113.42")
    assert hit[2:] == ("US", "United States")


def test_lookup_range_returns_none_outside_every_range(tmp_path):
    csv_path = tmp_path / "geoip.csv"
    csv_path.write_text("203.0.113.0,203.0.113.255,US,United States\n")
    v4, v6 = verify_geoip.load_country_ranges(str(csv_path))
    assert verify_geoip.lookup_range(v4, v6, "198.51.100.7") is None


def test_load_city_ranges_parses_the_seven_column_schema(tmp_path):
    csv_path = tmp_path / "geoip-city.csv"
    csv_path.write_text("203.0.113.0,203.0.113.255,US,United States,Ashburn,39.04,-77.49\n")
    v4, v6 = verify_geoip.load_city_ranges(str(csv_path))
    assert len(v4) == 1
    hit = verify_geoip.lookup_range(v4, v6, "203.0.113.10")
    assert hit[2:] == ("US", "United States", "Ashburn", 39.04, -77.49)


def test_load_city_ranges_skips_out_of_range_coordinates(tmp_path):
    csv_path = tmp_path / "geoip-city.csv"
    csv_path.write_text("203.0.113.0,203.0.113.255,US,United States,Nowhere,999,999\n")
    v4, v6 = verify_geoip.load_city_ranges(str(csv_path))
    assert len(v4) == 0 and len(v6) == 0


# --- CLI behaviour ------------------------------------------------------------


def test_check_country_db_reports_missing_file_and_returns_false(tmp_path, capsys):
    ok = verify_geoip.check_country_db(str(tmp_path / "missing.csv"), ["8.8.8.8"])
    assert ok is False
    assert "NOT FOUND" in capsys.readouterr().out


def test_check_country_db_reports_loaded_ranges_and_a_sample_lookup(tmp_path, capsys):
    csv_path = tmp_path / "geoip.csv"
    csv_path.write_text("8.8.8.0,8.8.8.255,US,United States\n")
    ok = verify_geoip.check_country_db(str(csv_path), ["8.8.8.8"])
    out = capsys.readouterr().out
    assert ok is True
    assert "loaded 1 ranges" in out
    assert "United States (US)" in out


def test_check_country_db_reports_zero_ranges_as_a_failure(tmp_path, capsys):
    csv_path = tmp_path / "geoip.csv"
    csv_path.write_text("not,a,valid,row\n")
    ok = verify_geoip.check_country_db(str(csv_path), ["8.8.8.8"])
    assert ok is False
    assert "zero usable ranges" in capsys.readouterr().out


def test_check_city_db_reports_not_configured_without_failing(tmp_path, capsys):
    verify_geoip.check_city_db(str(tmp_path / "missing.csv"), ["8.8.8.8"])
    assert "not configured" in capsys.readouterr().out


def test_main_exits_zero_when_country_db_is_present_and_loaded(tmp_path):
    csv_path = tmp_path / "geoip.csv"
    csv_path.write_text("8.8.8.0,8.8.8.255,US,United States\n")
    code = verify_geoip.main(["--db", str(csv_path), "--city-db", str(tmp_path / "missing-city.csv")])
    assert code == 0


def test_main_exits_non_zero_when_country_db_is_missing(tmp_path):
    code = verify_geoip.main(["--db", str(tmp_path / "missing.csv")])
    assert code == 1


def test_main_accepts_repeated_ip_arguments(tmp_path, capsys):
    csv_path = tmp_path / "geoip.csv"
    csv_path.write_text("8.8.8.0,8.8.8.255,US,United States\n203.0.113.0,203.0.113.255,DE,Germany\n")
    verify_geoip.main(["--db", str(csv_path), "--ip", "8.8.8.8", "--ip", "203.0.113.5"])
    out = capsys.readouterr().out
    assert "8.8.8.8: United States (US)" in out
    assert "203.0.113.5: Germany (DE)" in out
