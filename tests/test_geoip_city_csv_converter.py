"""`scripts/convert_dbip_city_lite.py` (Issue #37 / 0.8.6).

DB-IP City Lite ships unheadered `ip_start,ip_end,continent,country,
stateprov,city,latitude,longitude` rows; the converter drops the columns
DNS Inspector doesn't use and reshapes the rest into the seven-column
`start_ip,end_ip,country_code,country_name,city,latitude,longitude` schema
`CsvCityGeoIPProvider` expects (see docs/GEOIP.md). These tests use small
in-memory/temp-file fixtures -- no network access and no real DB-IP export
is required.
"""

import csv

import pytest

from scripts import convert_dbip_city_lite as converter


# --- convert_row: representative rows ---------------------------------------


def test_convert_row_converts_a_valid_ipv4_city_row():
    row = converter.convert_row(
        ["1.2.3.0", "1.2.3.255", "NA", "US", "California", "Mountain View", "37.386", "-122.0838"]
    )
    assert row[:2] == ["1.2.3.0", "1.2.3.255"]
    assert row[2] == "US"
    assert row[3] == "United States"
    assert row[4] == "Mountain View"
    assert float(row[5]) == pytest.approx(37.386)
    assert float(row[6]) == pytest.approx(-122.0838)


def test_convert_row_converts_a_valid_ipv6_city_row():
    row = converter.convert_row([
        "2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
        "EU", "de", "Berlin", "Berlin", "52.52", "13.405",
    ])
    assert row[0] == "2001:db8::"
    assert row[2] == "DE"
    assert row[3] == "Germany"
    assert row[4] == "Berlin"


def test_convert_row_falls_back_to_the_raw_code_for_an_unrecognised_country():
    row = converter.convert_row(
        ["1.2.3.0", "1.2.3.255", "ZZ", "ZZ", "Nowhere", "Nowhere", "0", "0"]
    )
    assert row[2] == "ZZ"
    assert row[3] == "ZZ"


# --- convert_row: malformed / header / out-of-range handling ----------------


def test_convert_row_skips_a_header_row():
    assert converter.convert_row([
        "ip_start", "ip_end", "continent", "country", "stateprov", "city", "latitude", "longitude",
    ]) is None


def test_convert_row_skips_a_row_with_too_few_columns():
    assert converter.convert_row(["1.2.3.0", "1.2.3.255", "NA", "US"]) is None
    assert converter.convert_row([]) is None


def test_convert_row_skips_a_row_with_an_unparsable_ip():
    row = ["not-an-ip", "1.2.3.255", "NA", "US", "CA", "Mountain View", "37.386", "-122.0838"]
    assert converter.convert_row(row) is None


def test_convert_row_skips_mismatched_address_families():
    row = ["1.2.3.0", "2001:db8::", "NA", "US", "CA", "Mountain View", "37.386", "-122.0838"]
    assert converter.convert_row(row) is None


def test_convert_row_skips_unparsable_coordinates():
    row = ["1.2.3.0", "1.2.3.255", "NA", "US", "CA", "Mountain View", "not-a-lat", "-122.0838"]
    assert converter.convert_row(row) is None


def test_convert_row_skips_out_of_range_latitude():
    row = ["1.2.3.0", "1.2.3.255", "NA", "US", "CA", "Nowhere", "91.0", "0.0"]
    assert converter.convert_row(row) is None


def test_convert_row_skips_out_of_range_longitude():
    row = ["1.2.3.0", "1.2.3.255", "NA", "US", "CA", "Nowhere", "0.0", "181.0"]
    assert converter.convert_row(row) is None


def test_convert_row_skips_a_row_with_no_country_code():
    row = ["1.2.3.0", "1.2.3.255", "NA", "", "CA", "Nowhere", "0.0", "0.0"]
    assert converter.convert_row(row) is None


# --- convert() / run(): streaming conversion ---------------------------------


def test_convert_yields_only_valid_rows_from_a_mixed_input():
    rows = [
        ["ip_start", "ip_end", "continent", "country", "stateprov", "city", "latitude", "longitude"],
        ["1.2.3.0", "1.2.3.255", "NA", "US", "CA", "Mountain View", "37.386", "-122.0838"],
        ["not,enough"],
        ["4.5.6.0", "4.5.6.255", "EU", "de", "Berlin", "Berlin", "52.52", "13.405"],
    ]
    converted = list(converter.convert(rows))
    assert len(converted) == 2
    assert converted[0][2] == "US"
    assert converted[1][2] == "DE"


def test_run_writes_the_converted_schema_to_an_output_file(tmp_path):
    input_path = tmp_path / "dbip-city-lite.csv"
    with open(input_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["1.2.3.0", "1.2.3.255", "NA", "US", "CA", "Mountain View", "37.386", "-122.0838"])
        writer.writerow(["not-an-ip", "x", "NA", "US", "CA", "Nowhere", "0", "0"])

    output_path = tmp_path / "geoip_city_ranges.csv"
    count = converter.run(str(input_path), str(output_path))

    assert count == 1
    with open(output_path, newline="") as f:
        rows = list(csv.reader(f))
    assert len(rows) == 1
    assert rows[0][0] == "1.2.3.0"
    assert rows[0][2] == "US"
    assert rows[0][4] == "Mountain View"


def test_run_writes_to_stdout_when_no_output_path_is_given(tmp_path, capsys):
    input_path = tmp_path / "dbip-city-lite.csv"
    with open(input_path, "w", newline="") as f:
        csv.writer(f).writerow(
            ["1.2.3.0", "1.2.3.255", "NA", "US", "CA", "Mountain View", "37.386", "-122.0838"]
        )

    count = converter.run(str(input_path))

    assert count == 1
    assert "1.2.3.0" in capsys.readouterr().out


def test_main_reports_the_converted_count_to_stderr(tmp_path, capsys):
    input_path = tmp_path / "dbip-city-lite.csv"
    with open(input_path, "w", newline="") as f:
        csv.writer(f).writerow(
            ["1.2.3.0", "1.2.3.255", "NA", "US", "CA", "Mountain View", "37.386", "-122.0838"]
        )
    output_path = tmp_path / "out.csv"

    exit_code = converter.main([str(input_path), "-o", str(output_path)])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Converted 1 range(s)" in captured.err
