"""GeoIP root-cause fix + six-state diagnostics (Issue #39 / 0.8.5.4).

0.8.5.3's real-DEV investigation found that `GEOIP_DB_PATH`/`GEOIP_CITY_DB_PATH`
defaulted under `BASE_DIR/data/...` (`/app/data/...` inside the container)
while every other persistent path (`DB_PATH`, `NEIGHBORS_PATH`,
`TRACKERDB_PATH`) and the README's documented `-v host/path:/data` volume
convention point at `/data` -- a directory the Dockerfile creates and the
documented single-volume setup mounts, but `/app/data` is not. An operator
who followed the README and dropped a converted CSV into their mounted
`/data` never had it picked up. These tests pin the corrected default and the
new `geoip_map_payload()` diagnostic state machine that replaces the old
single configured/not-configured boolean with six distinguishable states.
"""

import importlib
import json
import sqlite3
import uuid
from contextlib import closing


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


def _use_providers(app_module, monkeypatch, provider=None, city_provider=None):
    if provider is not None:
        monkeypatch.setattr(app_module, "_geoip_provider", provider)
        app_module._geoip_cache.clear()
        app_module._geoip_cache_order.clear()
    if city_provider is not None:
        monkeypatch.setattr(app_module, "_geoip_city_provider", city_provider)
        app_module._geoip_city_cache.clear()
        app_module._geoip_city_cache_order.clear()
    _reset_map_cache(app_module)


# --- root-cause fix: default paths match the /data convention ---------------


def test_geoip_db_path_defaults_under_data_matching_other_persistent_paths(monkeypatch):
    """Same default directory as DB_PATH/NEIGHBORS_PATH/TRACKERDB_PATH -- the
    directory the Dockerfile creates and the README's documented single-
    volume mount uses, not `BASE_DIR/data` (`/app/data` in the container,
    never created and never mounted)."""
    import app

    monkeypatch.delenv("GEOIP_DB_PATH", raising=False)
    reloaded = importlib.reload(app)
    try:
        assert reloaded.GEOIP_DB_PATH == "/data/geoip_country_ranges.csv"
    finally:
        importlib.reload(app)


def test_geoip_city_db_path_defaults_under_data_matching_other_persistent_paths(monkeypatch):
    import app

    monkeypatch.delenv("GEOIP_CITY_DB_PATH", raising=False)
    reloaded = importlib.reload(app)
    try:
        assert reloaded.GEOIP_CITY_DB_PATH == "/data/geoip_city_ranges.csv"
    finally:
        importlib.reload(app)


def test_geoip_db_path_still_respects_an_explicit_override(monkeypatch):
    """The fix corrects the default only -- an operator-set GEOIP_DB_PATH is
    unaffected."""
    import app

    monkeypatch.setenv("GEOIP_DB_PATH", "/custom/geoip.csv")
    reloaded = importlib.reload(app)
    try:
        assert reloaded.GEOIP_DB_PATH == "/custom/geoip.csv"
    finally:
        monkeypatch.delenv("GEOIP_DB_PATH", raising=False)
        importlib.reload(app)


# --- diagnostic state machine ------------------------------------------------


def test_diagnostic_state_not_configured_for_the_null_provider(app_module, monkeypatch):
    _use_providers(app_module, monkeypatch, provider=app_module.NullGeoIPProvider())
    assert app_module._geoip_diagnostic_state(0, 0, False, 0) == "not_configured"


def test_diagnostic_state_load_failed_for_a_configured_but_unloaded_provider(app_module, monkeypatch, tmp_path):
    provider = app_module.CsvRangeGeoIPProvider(str(tmp_path / "missing.csv"))
    assert provider.available is False
    _use_providers(app_module, monkeypatch, provider=provider)
    assert app_module._geoip_diagnostic_state(0, 0, False, 0) == "load_failed"


def test_diagnostic_state_no_public_destinations_when_loaded_but_nothing_observed(app_module, monkeypatch):
    _use_providers(app_module, monkeypatch, provider=_FixedProvider({}))
    assert app_module._geoip_diagnostic_state(0, 0, False, 0) == "no_public_destinations"


def test_diagnostic_state_no_country_matches_when_observations_exist_but_unmapped(app_module, monkeypatch):
    _use_providers(app_module, monkeypatch, provider=_FixedProvider({}))
    assert app_module._geoip_diagnostic_state(5, 0, False, 0) == "no_country_matches"


def test_diagnostic_state_country_only_when_city_provider_is_unavailable(app_module, monkeypatch):
    _use_providers(app_module, monkeypatch, provider=_FixedProvider({"1.1.1.1": ("US", "United States")}))
    assert app_module._geoip_diagnostic_state(5, 5, False, 0) == "country_only"


def test_diagnostic_state_partial_coordinate_coverage_when_city_available_but_no_points(app_module, monkeypatch):
    _use_providers(app_module, monkeypatch, provider=_FixedProvider({"1.1.1.1": ("US", "United States")}))
    assert app_module._geoip_diagnostic_state(5, 5, True, 0) == "partial_coordinate_coverage"


def test_diagnostic_state_full_coverage_when_everything_resolves(app_module, monkeypatch):
    _use_providers(app_module, monkeypatch, provider=_FixedProvider({"1.1.1.1": ("US", "United States")}))
    assert app_module._geoip_diagnostic_state(5, 5, True, 3) == "full_coverage"


def test_every_diagnostic_state_has_a_message(app_module):
    for state in (
        "not_configured", "load_failed", "no_public_destinations", "no_country_matches",
        "country_only", "partial_coordinate_coverage", "full_coverage",
    ):
        assert app_module.GEOIP_DIAGNOSTIC_MESSAGES[state]


# --- geoip_map_payload() integration -----------------------------------------


def test_geoip_map_payload_diagnostics_state_is_not_configured_by_default(app_module, monkeypatch):
    _use_providers(app_module, monkeypatch, provider=app_module.NullGeoIPProvider())
    payload = app_module.geoip_map_payload()
    assert payload["diagnostics"]["state"] == "not_configured"
    assert payload["diagnostics"]["message"]


def test_geoip_map_payload_diagnostics_state_is_full_coverage_with_country_and_city_hits(
    app_module, initialised_db, monkeypatch,
):
    domain = _unique("geo-full-coverage")
    now = app_module.utcnow()
    _insert_domain(initialised_db, domain, now, requests=2)
    _add_destination_ip(initialised_db, domain, now, "203.0.113.77", observations=2)
    _use_providers(
        app_module, monkeypatch,
        provider=_FixedProvider({"203.0.113.77": ("US", "United States")}),
        city_provider=_FixedCityProvider({"203.0.113.77": {
            "country_code": "US", "country_name": "United States",
            "city": "Ashburn", "lat": 39.04, "lon": -77.49,
        }}),
    )

    payload = app_module.geoip_map_payload()

    assert payload["diagnostics"]["state"] == "full_coverage"
    assert payload["capabilities"]["coordinates"] is True


def test_geoip_map_payload_diagnostics_state_is_country_only_without_a_city_provider(
    app_module, initialised_db, monkeypatch,
):
    domain = _unique("geo-country-only")
    now = app_module.utcnow()
    _insert_domain(initialised_db, domain, now, requests=1)
    _add_destination_ip(initialised_db, domain, now, "203.0.113.78", observations=1)
    _use_providers(
        app_module, monkeypatch,
        provider=_FixedProvider({"203.0.113.78": ("US", "United States")}),
        city_provider=app_module.NullCityGeoIPProvider(),
    )

    payload = app_module.geoip_map_payload()

    assert payload["diagnostics"]["state"] == "country_only"


def test_geoip_map_payload_provider_field_no_longer_leaks_the_full_configured_path(
    app_module, monkeypatch, tmp_path,
):
    csv_path = tmp_path / "geoip.csv"
    csv_path.write_text("203.0.113.0,203.0.113.255,US,United States\n")
    provider = app_module.CsvRangeGeoIPProvider(str(csv_path))
    _use_providers(app_module, monkeypatch, provider=provider)

    payload = app_module.geoip_map_payload()

    assert "path" not in payload["provider"]
    assert payload["provider"]["db_path_basename"] == "geoip.csv"
    assert str(tmp_path) not in json.dumps(payload)


def test_api_analytics_map_route_exposes_diagnostics_state(client):
    response = client.get("/api/analytics/map")
    payload = json.loads(response.data)
    assert "diagnostics" in payload
    assert "state" in payload["diagnostics"]
    assert "message" in payload["diagnostics"]
