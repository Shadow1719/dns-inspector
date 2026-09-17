#!/usr/bin/env python3
"""Convert a DB-IP Country Lite CSV export into DNS Inspector's GeoIP schema.

DB-IP Country Lite (https://db-ip.com/db/lite.php, CC BY 4.0, monthly
releases) ships unheadered `start_ip,end_ip,country_code` rows -- three
columns, no country name. `CsvRangeGeoIPProvider` (see `app.py` and
`docs/GEOIP.md`) expects four columns:

    start_ip,end_ip,country_code,country_name

This script adds the fourth column from a small bundled ISO 3166-1 alpha-2
table below. It does not download anything, make any network request, or
depend on the `db-ip` package/service at runtime -- it is a one-shot, offline
conversion you run yourself against a file you already downloaded.

Usage:
    python scripts/convert_dbip_country_lite.py dbip-country-lite.csv -o data/geoip_country_ranges.csv
    python scripts/convert_dbip_country_lite.py dbip-country-lite.csv > data/geoip_country_ranges.csv

Both DB-IP's IPv4 and IPv6 Country Lite exports use the same three-column
shape, so the same conversion applies to either (or a concatenation of both).
Rows are processed one at a time (a streaming `csv.reader` over the input
file, not a full read into memory), so the conversion stays bounded even
against DB-IP's full multi-million-row export. Malformed rows (wrong column
count, unparsable IP, mismatched address family) and a header row (if
present) are skipped individually rather than aborting the conversion.
"""

import argparse
import csv
import ipaddress
import sys

# ISO 3166-1 alpha-2 -> short English country/territory name. DB-IP Country
# Lite's `country_code` column is documented as ISO 3166-1 alpha-2, plus a
# small number of user-assigned/reserved codes for special cases (e.g. `EU`,
# `AP`, `ZZ`) that DB-IP itself may emit for anycast/satellite/unknown
# allocations; those fall back to the raw code via `.get(code, code)` below
# rather than being treated as an error.
ISO_COUNTRY_NAMES = {
    "AD": "Andorra", "AE": "United Arab Emirates", "AF": "Afghanistan",
    "AG": "Antigua and Barbuda", "AI": "Anguilla", "AL": "Albania",
    "AM": "Armenia", "AO": "Angola", "AQ": "Antarctica", "AR": "Argentina",
    "AS": "American Samoa", "AT": "Austria", "AU": "Australia", "AW": "Aruba",
    "AX": "Aland Islands", "AZ": "Azerbaijan",
    "BA": "Bosnia and Herzegovina", "BB": "Barbados", "BD": "Bangladesh",
    "BE": "Belgium", "BF": "Burkina Faso", "BG": "Bulgaria", "BH": "Bahrain",
    "BI": "Burundi", "BJ": "Benin", "BL": "Saint Barthelemy",
    "BM": "Bermuda", "BN": "Brunei Darussalam", "BO": "Bolivia",
    "BQ": "Bonaire, Sint Eustatius and Saba", "BR": "Brazil",
    "BS": "Bahamas", "BT": "Bhutan", "BV": "Bouvet Island", "BW": "Botswana",
    "BY": "Belarus", "BZ": "Belize",
    "CA": "Canada", "CC": "Cocos (Keeling) Islands",
    "CD": "Congo (Democratic Republic of the)",
    "CF": "Central African Republic", "CG": "Congo", "CH": "Switzerland",
    "CI": "Cote d'Ivoire", "CK": "Cook Islands", "CL": "Chile",
    "CM": "Cameroon", "CN": "China", "CO": "Colombia", "CR": "Costa Rica",
    "CU": "Cuba", "CV": "Cabo Verde", "CW": "Curacao",
    "CX": "Christmas Island", "CY": "Cyprus", "CZ": "Czechia",
    "DE": "Germany", "DJ": "Djibouti", "DK": "Denmark", "DM": "Dominica",
    "DO": "Dominican Republic", "DZ": "Algeria",
    "EC": "Ecuador", "EE": "Estonia", "EG": "Egypt",
    "EH": "Western Sahara", "ER": "Eritrea", "ES": "Spain",
    "ET": "Ethiopia",
    "FI": "Finland", "FJ": "Fiji", "FK": "Falkland Islands",
    "FM": "Micronesia", "FO": "Faroe Islands", "FR": "France",
    "GA": "Gabon", "GB": "United Kingdom", "GD": "Grenada",
    "GE": "Georgia", "GF": "French Guiana", "GG": "Guernsey",
    "GH": "Ghana", "GI": "Gibraltar", "GL": "Greenland", "GM": "Gambia",
    "GN": "Guinea", "GP": "Guadeloupe", "GQ": "Equatorial Guinea",
    "GR": "Greece",
    "GS": "South Georgia and the South Sandwich Islands",
    "GT": "Guatemala", "GU": "Guam", "GW": "Guinea-Bissau",
    "GY": "Guyana",
    "HK": "Hong Kong", "HM": "Heard Island and McDonald Islands",
    "HN": "Honduras", "HR": "Croatia", "HT": "Haiti", "HU": "Hungary",
    "ID": "Indonesia", "IE": "Ireland", "IL": "Israel", "IM": "Isle of Man",
    "IN": "India", "IO": "British Indian Ocean Territory", "IQ": "Iraq",
    "IR": "Iran", "IS": "Iceland", "IT": "Italy",
    "JE": "Jersey", "JM": "Jamaica", "JO": "Jordan", "JP": "Japan",
    "KE": "Kenya", "KG": "Kyrgyzstan", "KH": "Cambodia", "KI": "Kiribati",
    "KM": "Comoros", "KN": "Saint Kitts and Nevis", "KP": "North Korea",
    "KR": "South Korea", "KW": "Kuwait", "KY": "Cayman Islands",
    "KZ": "Kazakhstan",
    "LA": "Laos", "LB": "Lebanon", "LC": "Saint Lucia",
    "LI": "Liechtenstein", "LK": "Sri Lanka", "LR": "Liberia",
    "LS": "Lesotho", "LT": "Lithuania", "LU": "Luxembourg", "LV": "Latvia",
    "LY": "Libya",
    "MA": "Morocco", "MC": "Monaco", "MD": "Moldova", "ME": "Montenegro",
    "MF": "Saint Martin", "MG": "Madagascar", "MH": "Marshall Islands",
    "MK": "North Macedonia", "ML": "Mali", "MM": "Myanmar",
    "MN": "Mongolia", "MO": "Macao", "MP": "Northern Mariana Islands",
    "MQ": "Martinique", "MR": "Mauritania", "MS": "Montserrat",
    "MT": "Malta", "MU": "Mauritius", "MV": "Maldives", "MW": "Malawi",
    "MX": "Mexico", "MY": "Malaysia", "MZ": "Mozambique",
    "NA": "Namibia", "NC": "New Caledonia", "NE": "Niger",
    "NF": "Norfolk Island", "NG": "Nigeria", "NI": "Nicaragua",
    "NL": "Netherlands", "NO": "Norway", "NP": "Nepal", "NR": "Nauru",
    "NU": "Niue", "NZ": "New Zealand",
    "OM": "Oman",
    "PA": "Panama", "PE": "Peru", "PF": "French Polynesia",
    "PG": "Papua New Guinea", "PH": "Philippines", "PK": "Pakistan",
    "PL": "Poland", "PM": "Saint Pierre and Miquelon", "PN": "Pitcairn",
    "PR": "Puerto Rico", "PS": "Palestine", "PT": "Portugal",
    "PW": "Palau", "PY": "Paraguay",
    "QA": "Qatar",
    "RE": "Reunion", "RO": "Romania", "RS": "Serbia", "RU": "Russia",
    "RW": "Rwanda",
    "SA": "Saudi Arabia", "SB": "Solomon Islands", "SC": "Seychelles",
    "SD": "Sudan", "SE": "Sweden", "SG": "Singapore", "SH": "Saint Helena",
    "SI": "Slovenia", "SJ": "Svalbard and Jan Mayen", "SK": "Slovakia",
    "SL": "Sierra Leone", "SM": "San Marino", "SN": "Senegal",
    "SO": "Somalia", "SR": "Suriname", "SS": "South Sudan",
    "ST": "Sao Tome and Principe", "SV": "El Salvador", "SX": "Sint Maarten",
    "SY": "Syria", "SZ": "Eswatini",
    "TC": "Turks and Caicos Islands", "TD": "Chad",
    "TF": "French Southern Territories", "TG": "Togo", "TH": "Thailand",
    "TJ": "Tajikistan", "TK": "Tokelau", "TL": "Timor-Leste",
    "TM": "Turkmenistan", "TN": "Tunisia", "TO": "Tonga", "TR": "Turkey",
    "TT": "Trinidad and Tobago", "TV": "Tuvalu", "TW": "Taiwan",
    "TZ": "Tanzania",
    "UA": "Ukraine", "UG": "Uganda",
    "UM": "United States Minor Outlying Islands", "US": "United States",
    "UY": "Uruguay", "UZ": "Uzbekistan",
    "VA": "Holy See", "VC": "Saint Vincent and the Grenadines",
    "VE": "Venezuela", "VG": "Virgin Islands (British)",
    "VI": "Virgin Islands (U.S.)", "VN": "Vietnam", "VU": "Vanuatu",
    "WF": "Wallis and Futuna", "WS": "Samoa",
    "YE": "Yemen", "YT": "Mayotte",
    "ZA": "South Africa", "ZM": "Zambia", "ZW": "Zimbabwe",
}

# First-column values that mean "this is a header row, not data" -- matches
# the header tolerance CsvRangeGeoIPProvider already applies on load.
_HEADER_FIRST_COLUMNS = {"start_ip", "start", "network_start", "ip_range_start"}


def convert_row(row):
    """Convert one raw `start_ip,end_ip,country_code[,...]` row into a
    `[start_ip, end_ip, country_code, country_name]` row, or return None if
    the row is empty, a header, or malformed and should be skipped."""
    if not row or len(row) < 3:
        return None
    start_raw, end_raw, code = row[0].strip(), row[1].strip(), row[2].strip().upper()
    if start_raw.lower() in _HEADER_FIRST_COLUMNS:
        return None
    if not code:
        return None
    try:
        start_addr = ipaddress.ip_address(start_raw)
        end_addr = ipaddress.ip_address(end_raw)
    except ValueError:
        return None
    if start_addr.version != end_addr.version:
        return None
    return [str(start_addr), str(end_addr), code, ISO_COUNTRY_NAMES.get(code, code)]


def convert(rows):
    """Yield converted schema rows from an iterable of raw input rows.

    A generator over the (already lazily-iterated) `csv.reader` input, so a
    caller streaming from a file never holds more than one row in memory at
    a time.
    """
    for row in rows:
        converted = convert_row(row)
        if converted is not None:
            yield converted


def run(input_path, output_path=None):
    """Convert `input_path` to `output_path` (or return the row count and
    write to stdout when `output_path` is None). Returns the number of rows
    written."""
    out_file = open(output_path, "w", encoding="utf-8", newline="") if output_path else sys.stdout
    count = 0
    try:
        writer = csv.writer(out_file)
        with open(input_path, "r", encoding="utf-8", newline="") as in_file:
            for converted in convert(csv.reader(in_file)):
                writer.writerow(converted)
                count += 1
    finally:
        if output_path:
            out_file.close()
    return count


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "Convert a DB-IP Country Lite CSV (start_ip,end_ip,country_code) "
            "into DNS Inspector's four-column GeoIP schema "
            "(start_ip,end_ip,country_code,country_name). Makes no network "
            "requests; only reads the input file you already downloaded."
        ),
    )
    parser.add_argument(
        "input",
        help="Path to a DB-IP Country Lite CSV export (IPv4, IPv6, or a concatenation of both).",
    )
    parser.add_argument(
        "-o", "--output",
        help="Path to write the converted CSV to. Defaults to stdout.",
    )
    args = parser.parse_args(argv)

    count = run(args.input, args.output)
    destination = args.output or "stdout"
    print(f"Converted {count} range(s) to {destination}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
