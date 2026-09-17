"""Coordinate/city GeoIP provider + Destinations mode aggregation
(Issue #37 / 0.8.6).

Entirely additive to the 0.8.5.1/0.8.5.2 country-only GeoIP path (see
test_geoip_destinations_map.py): `_geoip_city_provider` defaults to
`NullCityGeoIPProvider` because no database ships in the repository, so
Destinations mode must honestly report coordinate data as unavailable
rather than falling back to a country centroid. These tests build small
in-memory CSV fixtures -- never a real city database.
"""

import json
import sqlite3
import uuid
from contextlib import closing

import pytest


def _unique(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _insert_domain(db_path, domain, now, requests=1, clients=None):
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO domains"
            "(domain,first_seen,last_seen,requests,clients_json,blocked_requests,"
            "allowed_requests,unknown_requests,last_status,current_status)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            (domain, now, now, requests, json.dumps(clients or {}), 0, requests, 0, "Allowed", "Allowed"),
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


class _FixedProvider:
    """Deterministic country-provider test double, same shape as the one in
    test_geoip_destinations_map.py."""

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


class _FixedCityProvider:
    """Deterministic city-provider test double: maps specific IPs to a fixed
    coordinate/city dict, mirroring `CityGeoIPProvider.lookup_city()`."""

    def __init__(self, mapping):
        self._mapping = mapping

    def lookup_city(self, ip):
        return self._mapping.get(ip)

    @property
    def available(self):
        return True

    @property
    def path(self):
        return None

    @property
    def range_count(self):
        return len(self._mapping)


def _reset_map_cache(app_module):
    app_module._geoip_map_cache["data"] = None
    app_module._geoip_map_cache["at"] = 0.0


def _use_country_provider(app_module, monkeypatch, provider):
    monkeypatch.setattr(app_module, "_geoip_provider", provider)
    app_module._geoip_cache.clear()
    app_module._geoip_cache_order.clear()
    _reset_map_cache(app_module)


def _use_city_provider(app_module, monkeypatch, provider):
    monkeypatch.setattr(app_module, "_geoip_city_provider", provider)
    app_module._geoip_city_cache.clear()
    app_module._geoip_city_cache_order.clear()
    _reset_map_cache(app_module)


# --- NullCityGeoIPProvider: the default when no city database is configured -


def test_null_city_geoip_provider_is_the_default_when_unconfigured(app_module):
    assert isinstance(app_module._geoip_city_provider, app_module.NullCityGeoIPProvider)
    assert app_module._geoip_city_provider.available is False
    assert app_module._geoip_city_provider.lookup_city("8.8.8.8") is None


# --- CsvCityGeoIPProvider: loading and lookup --------------------------------


def _write_city_csv(tmp_path, rows):
    csv_path = tmp_path / "geoip_city.csv"
    csv_path.write_text("\n".join(",".join(str(c) for c in row) for row in rows) + "\n")
    return csv_path


def test_csv_city_provider_matches_an_ipv4_address_inside_a_configured_range(tmp_path, app_module):
    csv_path = _write_city_csv(tmp_path, [
        ["203.0.113.0", "203.0.113.255", "US", "United States", "Mountain View", "37.386", "-122.0838"],
    ])
    provider = app_module.CsvCityGeoIPProvider(str(csv_path))
    assert provider.available is True
    result = provider.lookup_city("203.0.113.42")
    assert result["country_code"] == "US"
    assert result["country_name"] == "United States"
    assert result["city"] == "Mountain View"
    assert result["lat"] == pytest.approx(37.386)
    assert result["lon"] == pytest.approx(-122.0838)


def test_csv_city_provider_matches_an_ipv6_address_inside_a_configured_range(tmp_path, app_module):
    csv_path = _write_city_csv(tmp_path, [
        ["2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "DE", "Germany", "Berlin", "52.52", "13.405"],
    ])
    provider = app_module.CsvCityGeoIPProvider(str(csv_path))
    result = provider.lookup_city("2001:db8:1234::1")
    assert result["country_code"] == "DE"
    assert result["city"] == "Berlin"


def test_csv_city_provider_reports_unmapped_outside_any_range(tmp_path, app_module):
    csv_path = _write_city_csv(tmp_path, [
        ["203.0.113.0", "203.0.113.255", "US", "United States", "Mountain View", "37.386", "-122.0838"],
    ])
    provider = app_module.CsvCityGeoIPProvider(str(csv_path))
    assert provider.lookup_city("198.51.100.7") is None


def test_csv_city_provider_handles_malformed_input_safely(tmp_path, app_module):
    provider = app_module.CsvCityGeoIPProvider(str(tmp_path / "geoip_city.csv"))
    assert provider.lookup_city("not-an-ip") is None
    assert provider.lookup_city("") is None


def test_csv_city_provider_is_unavailable_for_a_missing_file(tmp_path, app_module):
    provider = app_module.CsvCityGeoIPProvider(str(tmp_path / "does-not-exist.csv"))
    assert provider.available is False
    assert provider.lookup_city("8.8.8.8") is None


def test_csv_city_provider_skips_malformed_rows_without_failing(tmp_path, app_module):
    csv_path = _write_city_csv(tmp_path, [
        ["not", "enough", "columns"],
        ["203.0.113.0", "203.0.113.255", "US", "United States", "Mountain View", "37.386", "-122.0838"],
    ])
    provider = app_module.CsvCityGeoIPProvider(str(csv_path))
    assert provider.available is True
    assert provider.lookup_city("203.0.113.1")["city"] == "Mountain View"


def test_csv_city_provider_skips_out_of_range_coordinates(tmp_path, app_module):
    csv_path = _write_city_csv(tmp_path, [
        ["203.0.113.0", "203.0.113.255", "US", "United States", "Nowhere", "999", "0"],
    ])
    provider = app_module.CsvCityGeoIPProvider(str(csv_path))
    assert provider.lookup_city("203.0.113.1") is None


def test_csv_city_provider_skips_a_header_row(tmp_path, app_module):
    csv_path = _write_city_csv(tmp_path, [
        ["start_ip", "end_ip", "country_code", "country_name", "city", "latitude", "longitude"],
        ["203.0.113.0", "203.0.113.255", "US", "United States", "Mountain View", "37.386", "-122.0838"],
    ])
    provider = app_module.CsvCityGeoIPProvider(str(csv_path))
    assert provider.range_count == 1


def test_csv_city_provider_interns_repeated_country_and_city_names(tmp_path, app_module):
    """A real city database repeats the same country/city name across many
    ranges -- the provider must intern them once, not store a fresh string
    (or tuple) per row, per docs/GEOIP.md's memory-efficiency requirement."""
    csv_path = _write_city_csv(tmp_path, [
        ["203.0.113.0", "203.0.113.63", "US", "United States", "Mountain View", "37.386", "-122.0838"],
        ["203.0.113.64", "203.0.113.127", "US", "United States", "Mountain View", "37.4", "-122.09"],
    ])
    provider = app_module.CsvCityGeoIPProvider(str(csv_path))
    assert len(provider._countries) == 1
    assert len(provider._cities) == 1
    assert provider.range_count == 2


def test_csv_city_provider_range_count_covers_both_families(tmp_path, app_module):
    csv_path = _write_city_csv(tmp_path, [
        ["203.0.113.0", "203.0.113.255", "US", "United States", "Mountain View", "37.386", "-122.0838"],
        ["2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "DE", "Germany", "Berlin", "52.52", "13.405"],
    ])
    provider = app_module.CsvCityGeoIPProvider(str(csv_path))
    assert provider.range_count == 2


# --- geoip_city_lookup(): local caching --------------------------------------


def test_geoip_city_lookup_is_cached_and_bounded(app_module, monkeypatch):
    calls = []

    class _CountingCityProvider(app_module.CityGeoIPProvider):
        def lookup_city(self, ip):
            calls.append(ip)
            return {"country_code": "US", "country_name": "United States", "city": "Mountain View", "lat": 37.386, "lon": -122.0838}

        @property
        def available(self):
            return True

    _use_city_provider(app_module, monkeypatch, _CountingCityProvider())
    ip = "203.0.113.9"
    first = app_module.geoip_city_lookup(ip)
    second = app_module.geoip_city_lookup(ip)
    assert first == second
    assert calls == [ip]


def test_geoip_city_lookup_caches_unmapped_results_too(app_module, monkeypatch):
    calls = []

    class _AlwaysUnmapped(app_module.CityGeoIPProvider):
        def lookup_city(self, ip):
            calls.append(ip)
            return None

        @property
        def available(self):
            return True

    _use_city_provider(app_module, monkeypatch, _AlwaysUnmapped())
    ip = "203.0.113.10"
    assert app_module.geoip_city_lookup(ip) is None
    assert app_module.geoip_city_lookup(ip) is None
    assert calls == [ip]  # second call served from cache, not the provider


# --- geoip_map_payload(): capabilities + destinations ------------------------


def test_capabilities_reflect_configured_providers(app_module, monkeypatch):
    _use_country_provider(app_module, monkeypatch, app_module.NullGeoIPProvider())
    _use_city_provider(app_module, monkeypatch, app_module.NullCityGeoIPProvider())

    payload = app_module.geoip_map_payload()

    assert payload["capabilities"] == {"country": False, "coordinates": False, "heatmap": False}


def test_capabilities_country_true_when_only_country_provider_configured(app_module, monkeypatch):
    _use_country_provider(app_module, monkeypatch, _FixedProvider({}))
    _use_city_provider(app_module, monkeypatch, app_module.NullCityGeoIPProvider())

    payload = app_module.geoip_map_payload()

    assert payload["capabilities"]["country"] is True
    assert payload["capabilities"]["coordinates"] is False


def test_destinations_mode_never_invents_coordinates_for_a_country_only_provider(
    app_module, initialised_db, monkeypatch,
):
    """The core honesty requirement of Issue #37: with only a country
    database configured, a real geolocated destination must still produce
    zero coordinate points -- never a country centroid standing in for a
    real IP/city coordinate."""
    domain = _unique("city-unavailable")
    now = app_module.utcnow()
    _insert_domain(initialised_db, domain, now, requests=3)
    _add_destination_ip(initialised_db, domain, now, "203.0.113.77", observations=3)
    _use_country_provider(app_module, monkeypatch, _FixedProvider({"203.0.113.77": ("US", "United States")}))
    _use_city_provider(app_module, monkeypatch, app_module.NullCityGeoIPProvider())

    payload = app_module.geoip_map_payload()

    assert payload["capabilities"]["coordinates"] is False
    assert payload["destinations"] == []
    # the country-level aggregate must still work normally
    us = next(c for c in payload["countries"] if c["country_code"] == "US")
    assert domain in us["sample_domains"]


def test_destinations_mode_reports_a_real_coordinate_when_city_provider_configured(
    app_module, initialised_db, monkeypatch,
):
    domain = _unique("city-available")
    now = app_module.utcnow()
    _insert_domain(initialised_db, domain, now, requests=5)
    _add_destination_ip(initialised_db, domain, now, "203.0.113.88", observations=5)
    _use_country_provider(app_module, monkeypatch, _FixedProvider({"203.0.113.88": ("US", "United States")}))
    _use_city_provider(app_module, monkeypatch, _FixedCityProvider({
        "203.0.113.88": {"country_code": "US", "country_name": "United States", "city": "Mountain View", "lat": 37.386, "lon": -122.0838},
    }))

    payload = app_module.geoip_map_payload()

    assert payload["capabilities"]["coordinates"] is True
    assert len(payload["destinations"]) == 1
    point = payload["destinations"][0]
    assert point["ip"] == "203.0.113.88"
    assert point["city"] == "Mountain View"
    assert point["lat"] == 37.386
    assert point["observation_count"] == 5
    assert domain in point["sample_domains"]


def test_destinations_combines_the_same_ip_observed_by_two_domains_into_one_point(
    app_module, initialised_db, monkeypatch,
):
    """Two different domains that legitimately share a destination IP (a
    shared CDN edge node, for example) must produce one coordinate point
    with a combined observation/domain count, not two overlapping points."""
    domain_a = _unique("city-shared-a")
    domain_b = _unique("city-shared-b")
    now = app_module.utcnow()
    _insert_domain(initialised_db, domain_a, now, requests=2)
    _insert_domain(initialised_db, domain_b, now, requests=3)
    _add_destination_ip(initialised_db, domain_a, now, "203.0.113.99", observations=2)
    _add_destination_ip(initialised_db, domain_b, now, "203.0.113.99", observations=3)
    _use_country_provider(app_module, monkeypatch, _FixedProvider({"203.0.113.99": ("US", "United States")}))
    _use_city_provider(app_module, monkeypatch, _FixedCityProvider({
        "203.0.113.99": {"country_code": "US", "country_name": "United States", "city": "Ashburn", "lat": 39.04, "lon": -77.49},
    }))

    payload = app_module.geoip_map_payload()

    matching = [p for p in payload["destinations"] if p["ip"] == "203.0.113.99"]
    assert len(matching) == 1
    point = matching[0]
    assert point["observation_count"] == 5
    assert point["domain_count"] == 2


def test_destination_points_are_bounded_by_the_configured_limit(app_module, initialised_db, monkeypatch):
    now = app_module.utcnow()
    city_mapping = {}
    country_mapping = {}
    for i in range(5):
        domain = _unique(f"city-bounded-{i}")
        ip = f"203.0.113.{i + 1}"
        _insert_domain(initialised_db, domain, now, requests=1)
        _add_destination_ip(initialised_db, domain, now, ip, observations=i + 1)
        country_mapping[ip] = ("US", "United States")
        city_mapping[ip] = {"country_code": "US", "country_name": "United States", "city": f"City{i}", "lat": 30.0 + i, "lon": -90.0 + i}
    _use_country_provider(app_module, monkeypatch, _FixedProvider(country_mapping))
    _use_city_provider(app_module, monkeypatch, _FixedCityProvider(city_mapping))
    monkeypatch.setattr(app_module, "GEOIP_MAP_DESTINATION_POINTS_LIMIT", 2)
    _reset_map_cache(app_module)

    payload = app_module.geoip_map_payload()

    ours = [p for p in payload["destinations"] if p["ip"].startswith("203.0.113.")]
    assert len(ours) <= 2


def test_country_aggregate_reports_unique_ip_count(app_module, initialised_db, monkeypatch):
    domain = _unique("unique-ip-count")
    now = app_module.utcnow()
    _insert_domain(initialised_db, domain, now, requests=3)
    _add_destination_ip(initialised_db, domain, now, "203.0.113.1", observations=1)
    _add_destination_ip(initialised_db, domain, now, "203.0.113.2", observations=2)
    _use_country_provider(app_module, monkeypatch, _FixedProvider({
        "203.0.113.1": ("US", "United States"),
        "203.0.113.2": ("US", "United States"),
    }))
    _use_city_provider(app_module, monkeypatch, app_module.NullCityGeoIPProvider())

    payload = app_module.geoip_map_payload()

    us = next(c for c in payload["countries"] if c["country_code"] == "US")
    assert us["unique_ip_count"] >= 2


# --- diagnostics + observability ---------------------------------------------


def test_geoip_city_diagnostics_reports_unconfigured_for_the_null_provider(app_module, monkeypatch):
    _use_city_provider(app_module, monkeypatch, app_module.NullCityGeoIPProvider())
    diag = app_module._geoip_city_diagnostics()
    assert diag["provider_type"] == "NullCityGeoIPProvider"
    assert diag["configured"] is False
    assert diag["range_count"] == 0


def test_geoip_city_diagnostics_reports_range_count_for_a_loaded_provider(tmp_path, app_module, monkeypatch):
    csv_path = _write_city_csv(tmp_path, [
        ["203.0.113.0", "203.0.113.255", "US", "United States", "Mountain View", "37.386", "-122.0838"],
    ])
    provider = app_module.CsvCityGeoIPProvider(str(csv_path))
    _use_city_provider(app_module, monkeypatch, provider)

    diag = app_module._geoip_city_diagnostics()

    assert diag["provider_type"] == "CsvCityGeoIPProvider"
    assert diag["configured"] is True
    assert diag["range_count"] == 1
    assert diag["db_path_basename"] == "geoip_city.csv"


def test_log_geoip_status_mentions_destinations_mode_when_city_provider_configured(tmp_path, app_module, monkeypatch, capsys):
    csv_path = _write_city_csv(tmp_path, [
        ["203.0.113.0", "203.0.113.255", "US", "United States", "Mountain View", "37.386", "-122.0838"],
    ])
    provider = app_module.CsvCityGeoIPProvider(str(csv_path))
    _use_city_provider(app_module, monkeypatch, provider)

    app_module._log_geoip_status()

    captured = capsys.readouterr()
    assert "Destinations mode available" in captured.out


def test_log_geoip_status_is_honest_when_city_provider_unconfigured(app_module, monkeypatch, capsys):
    _use_city_provider(app_module, monkeypatch, app_module.NullCityGeoIPProvider())

    app_module._log_geoip_status()

    captured = capsys.readouterr()
    assert "coordinate/city database configured" in captured.out


def test_observability_payload_includes_geoip_city_diagnostics(app_module):
    payload = app_module._observability_payload()
    assert "geoip_city" in payload
    assert set(payload["geoip_city"]) >= {"provider_type", "configured", "db_path_basename", "range_count"}


def test_api_observability_route_exposes_geoip_city_diagnostics(client):
    response = client.get("/api/observability")
    payload = json.loads(response.data)
    assert "geoip_city" in payload
    assert "configured" in payload["geoip_city"]


# --- /api/analytics/map: additive payload shape ------------------------------


def test_api_analytics_map_advertises_capabilities_and_destinations(client):
    response = client.get("/api/analytics/map")
    assert response.status_code == 200
    payload = json.loads(response.data)
    assert "capabilities" in payload
    assert set(payload["capabilities"]) == {"country", "coordinates", "heatmap"}
    assert isinstance(payload["destinations"], list)


# --- provider.state: single unambiguous diagnostic classification (Issue #39)
#
# `/api/analytics/map`'s `provider.state` distinguishes six situations so an
# operator/the UI can tell exactly which link in the GeoIP chain is missing
# instead of one generic empty map for every failure mode -- see
# `geoip_map_payload()` in app.py.


def test_provider_state_is_no_public_destinations_when_nothing_observed_yet(app_module, initialised_db, monkeypatch):
    domain = _unique("state-no-public")
    now = app_module.utcnow()
    _insert_domain(initialised_db, domain, now, requests=2)
    _use_country_provider(app_module, monkeypatch, _FixedProvider({}))
    _use_city_provider(app_module, monkeypatch, app_module.NullCityGeoIPProvider())

    payload = app_module.geoip_map_payload()

    assert payload["provider"]["state"] == "no_public_destinations"


def test_provider_state_is_no_country_matches_when_observed_ips_do_not_match_any_range(
    app_module, initialised_db, monkeypatch,
):
    domain = _unique("state-no-match")
    now = app_module.utcnow()
    _insert_domain(initialised_db, domain, now, requests=1)
    _add_destination_ip(initialised_db, domain, now, "203.0.113.77", observations=1)
    _use_country_provider(app_module, monkeypatch, _FixedProvider({}))  # loaded, but maps nothing
    _use_city_provider(app_module, monkeypatch, app_module.NullCityGeoIPProvider())

    payload = app_module.geoip_map_payload()

    assert payload["provider"]["state"] == "no_country_matches"


def test_provider_state_is_country_only_when_no_city_database_is_configured(app_module, initialised_db, monkeypatch):
    domain = _unique("state-country-only")
    now = app_module.utcnow()
    _insert_domain(initialised_db, domain, now, requests=1)
    _add_destination_ip(initialised_db, domain, now, "203.0.113.88", observations=1)
    _use_country_provider(app_module, monkeypatch, _FixedProvider({"203.0.113.88": ("US", "United States")}))
    _use_city_provider(app_module, monkeypatch, app_module.NullCityGeoIPProvider())

    payload = app_module.geoip_map_payload()

    assert payload["provider"]["state"] == "country_only"
    assert payload["capabilities"]["coordinates"] is False


def test_provider_state_is_full_coverage_when_both_databases_are_loaded_and_matching(
    app_module, initialised_db, monkeypatch,
):
    domain = _unique("state-full-coverage")
    now = app_module.utcnow()
    _insert_domain(initialised_db, domain, now, requests=1)
    _add_destination_ip(initialised_db, domain, now, "203.0.113.99", observations=1)
    _use_country_provider(app_module, monkeypatch, _FixedProvider({"203.0.113.99": ("US", "United States")}))
    _use_city_provider(app_module, monkeypatch, _FixedCityProvider({
        "203.0.113.99": {"country_code": "US", "country_name": "United States", "city": "Ashburn", "lat": 39.04, "lon": -77.49},
    }))

    payload = app_module.geoip_map_payload()

    assert payload["provider"]["state"] == "full_coverage"
    assert payload["city_provider"]["state"] == "loaded"


def test_provider_state_is_not_configured_when_country_provider_is_the_default_null(
    app_module, initialised_db, monkeypatch,
):
    domain = _unique("state-not-configured")
    now = app_module.utcnow()
    _insert_domain(initialised_db, domain, now, requests=1)
    _use_country_provider(app_module, monkeypatch, app_module.NullGeoIPProvider())
    monkeypatch.setattr(app_module, "GEOIP_DB_PATH_EXPLICIT", False)

    payload = app_module.geoip_map_payload()

    assert payload["provider"]["state"] == "not_configured"


def test_provider_state_is_load_failed_when_explicitly_configured_but_unavailable(
    app_module, initialised_db, monkeypatch,
):
    domain = _unique("state-load-failed")
    now = app_module.utcnow()
    _insert_domain(initialised_db, domain, now, requests=1)
    _use_country_provider(app_module, monkeypatch, app_module.NullGeoIPProvider())
    monkeypatch.setattr(app_module, "GEOIP_DB_PATH_EXPLICIT", True)

    payload = app_module.geoip_map_payload()

    assert payload["provider"]["state"] == "load_failed"


def test_provider_state_does_not_leak_the_full_configured_path(app_module, initialised_db, monkeypatch):
    """`db_path_basename` replaces the old `path` field (Issue #39) -- the
    full filesystem path must never reach this public HTTP endpoint."""
    domain = _unique("state-no-leak")
    now = app_module.utcnow()
    _insert_domain(initialised_db, domain, now, requests=1)
    _add_destination_ip(initialised_db, domain, now, "203.0.113.11", observations=1)
    _use_country_provider(app_module, monkeypatch, _FixedProvider({"203.0.113.11": ("US", "United States")}))

    payload = app_module.geoip_map_payload()

    assert "path" not in payload["provider"]
    assert payload["provider"]["db_path_basename"] is None or "/" not in payload["provider"]["db_path_basename"]
