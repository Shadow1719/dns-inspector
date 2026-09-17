"""`scripts/convert_dbip_country_lite.py` (Issue #35 / 0.8.5.2).

DB-IP Country Lite ships unheadered `start_ip,end_ip,country_code` rows; the
converter adds a fourth `country_name` column so the output matches
`CsvRangeGeoIPProvider`'s schema (docs/GEOIP.md). These tests use small
in-memory/temp-file fixtures -- no network access and no real DB-IP export is
required.
"""

import csv
import io

import pytest

from scripts import convert_dbip_country_lite as converter


# --- convert_row: representative rows ---------------------------------------


def test_convert_row_adds_country_name_for_an_ipv4_range():
    row = converter.convert_row(["1.2.3.0", "1.2.3.255", "US"])
    assert row == ["1.2.3.0", "1.2.3.255", "US", "United States"]


def test_convert_row_adds_country_name_for_an_ipv6_range():
    row = converter.convert_row([
        "2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "de",
    ])
    assert row == [
        "2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "DE", "Germany",
    ]


def test_convert_row_uppercases_a_lowercase_country_code():
    row = converter.convert_row(["1.2.3.0", "1.2.3.255", "us"])
    assert row[2] == "US"


def test_convert_row_falls_back_to_the_raw_code_for_an_unrecognised_code():
    row = converter.convert_row(["1.2.3.0", "1.2.3.255", "ZZ"])
    assert row == ["1.2.3.0", "1.2.3.255", "ZZ", "ZZ"]


# --- convert_row: malformed / header handling --------------------------------


def test_convert_row_skips_a_header_row():
    assert converter.convert_row(["start_ip", "end_ip", "country_code"]) is None
    assert converter.convert_row(["ip_range_start", "ip_range_end", "country"]) is None


def test_convert_row_skips_a_row_with_too_few_columns():
    assert converter.convert_row(["1.2.3.0", "US"]) is None
    assert converter.convert_row([]) is None


def test_convert_row_skips_a_row_with_an_unparsable_ip():
    assert converter.convert_row(["not-an-ip", "1.2.3.255", "US"]) is None


def test_convert_row_skips_a_row_with_mismatched_address_families():
    assert converter.convert_row(["1.2.3.0", "2001:db8::1", "US"]) is None


def test_convert_row_skips_a_row_with_an_empty_country_code():
    assert converter.convert_row(["1.2.3.0", "1.2.3.255", ""]) is None


# --- convert(): streams rows, skipping malformed ones without aborting ------


def test_convert_skips_malformed_rows_without_aborting_the_stream():
    rows = [
        ["start_ip", "end_ip", "country_code"],
        ["1.2.3.0", "1.2.3.255", "US"],
        ["not,enough"],
        ["198.51.100.0", "198.51.100.255", "de"],
    ]
    converted = list(converter.convert(rows))
    assert converted == [
        ["1.2.3.0", "1.2.3.255", "US", "United States"],
        ["198.51.100.0", "198.51.100.255", "DE", "Germany"],
    ]


# --- run(): file-to-file conversion, deterministic output --------------------


def test_run_writes_the_four_column_schema_to_a_file(tmp_path):
    input_path = tmp_path / "dbip-country-lite.csv"
    output_path = tmp_path / "geoip_country_ranges.csv"
    input_path.write_text(
        "1.2.3.0,1.2.3.255,US\n"
        "198.51.100.0,198.51.100.255,DE\n",
        encoding="utf-8",
    )

    count = converter.run(str(input_path), str(output_path))

    assert count == 2
    with open(output_path, newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    assert rows == [
        ["1.2.3.0", "1.2.3.255", "US", "United States"],
        ["198.51.100.0", "198.51.100.255", "DE", "Germany"],
    ]


def test_run_is_deterministic_for_the_same_input(tmp_path):
    input_path = tmp_path / "dbip-country-lite.csv"
    input_path.write_text(
        "1.2.3.0,1.2.3.255,US\n2001:db8::,2001:db8::ffff,FR\n",
        encoding="utf-8",
    )
    first = tmp_path / "first.csv"
    second = tmp_path / "second.csv"

    converter.run(str(input_path), str(first))
    converter.run(str(input_path), str(second))

    assert first.read_text(encoding="utf-8") == second.read_text(encoding="utf-8")


def test_run_writes_to_stdout_when_no_output_path_is_given(tmp_path, capsys):
    input_path = tmp_path / "dbip-country-lite.csv"
    input_path.write_text("1.2.3.0,1.2.3.255,US\n", encoding="utf-8")

    count = converter.run(str(input_path))

    assert count == 1
    captured = capsys.readouterr()
    assert "1.2.3.0,1.2.3.255,US,United States" in captured.out


# --- CLI: main() ---------------------------------------------------------


def test_main_reports_the_converted_row_count_on_stderr(tmp_path, capsys):
    input_path = tmp_path / "dbip-country-lite.csv"
    output_path = tmp_path / "out.csv"
    input_path.write_text("1.2.3.0,1.2.3.255,US\n", encoding="utf-8")

    exit_code = converter.main([str(input_path), "-o", str(output_path)])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Converted 1 range(s)" in captured.err
    assert output_path.read_text(encoding="utf-8") == "1.2.3.0,1.2.3.255,US,United States\r\n"


def test_main_prints_usage_help_without_error():
    with pytest.raises(SystemExit) as excinfo:
        converter.main(["--help"])
    assert excinfo.value.code == 0


def test_output_produced_by_the_converter_loads_in_csvrangegeoipprovider(tmp_path, app_module):
    """End-to-end: the converter's output must actually be a valid
    `CsvRangeGeoIPProvider` database, not just four comma-separated columns."""
    input_path = tmp_path / "dbip-country-lite.csv"
    output_path = tmp_path / "geoip_country_ranges.csv"
    input_path.write_text(
        "203.0.113.0,203.0.113.255,US\n"
        "2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,DE\n",
        encoding="utf-8",
    )
    converter.run(str(input_path), str(output_path))

    provider = app_module.CsvRangeGeoIPProvider(str(output_path))

    assert provider.available is True
    assert provider.range_count == 2
    assert provider.lookup("203.0.113.42") == ("US", "United States")
    assert provider.lookup("2001:db8:1234::1") == ("DE", "Germany")
