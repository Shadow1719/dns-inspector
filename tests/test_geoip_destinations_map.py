"""DNS Destinations / GeoIP map + instrument gauges (Issue #27 / 0.8.5.1).

GeoIP lookups are always local/offline (see docs/GEOIP.md); these tests build
small in-memory CSV databases rather than depending on a real one. No
database ships in the repository by default, so `app_module._geoip_provider`
is a `NullGeoIPProvider` unless a test explicitly swaps it in via
`monkeypatch` (which reverts automatically at the end of each test). Because
the underlying SQLite database is session-scoped (see conftest.py), every
aggregation assertion below is a targeted delta around a uniquely-tagged
domain, matching the style already used in test_analytics.py.
"""

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


def _set_dns_records(db_path, domain, now, records):
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO dns_records_cache(domain,fetched_at,json) VALUES(?,?,?)",
            (domain, now, json.dumps(records)),
        )
        conn.commit()


class _FixedProvider:
    """Deterministic test double: maps specific IPs to specific countries."""

    def __init__(self, mapping):
        self._mapping = mapping

    def lookup(self, ip):
        return self._mapping.get(ip, (None, None))

    @property
    def available(self):
        return True


def _reset_map_cache(app_module):
    app_module._geoip_map_cache["data"] = None
    app_module._geoip_map_cache["at"] = 0.0


def _use_provider(app_module, monkeypatch, provider):
    monkeypatch.setattr(app_module, "_geoip_provider", provider)
    app_module._geoip_cache.clear()
    app_module._geoip_cache_order.clear()
    _reset_map_cache(app_module)


# --- normalize_public_ip: public-vs-private filtering -----------------------


def test_normalize_public_ip_accepts_a_public_ipv4(app_module):
    assert app_module.normalize_public_ip("8.8.8.8") == "8.8.8.8"


def test_normalize_public_ip_rejects_private_ipv4(app_module):
    assert app_module.normalize_public_ip("192.168.1.5") is None


def test_normalize_public_ip_rejects_loopback(app_module):
    assert app_module.normalize_public_ip("127.0.0.1") is None


def test_normalize_public_ip_rejects_link_local(app_module):
    assert app_module.normalize_public_ip("169.254.1.1") is None


def test_normalize_public_ip_rejects_multicast(app_module):
    assert app_module.normalize_public_ip("224.0.0.1") is None


def test_normalize_public_ip_rejects_cgnat_shared_space(app_module):
    assert app_module.normalize_public_ip("100.64.0.1") is None


def test_normalize_public_ip_rejects_unspecified(app_module):
    assert app_module.normalize_public_ip("0.0.0.0") is None


def test_normalize_public_ip_rejects_invalid_input(app_module):
    assert app_module.normalize_public_ip("not-an-ip") is None
    assert app_module.normalize_public_ip("") is None


def test_normalize_public_ip_accepts_a_public_ipv6(app_module):
    assert app_module.normalize_public_ip("2001:4860:4860::8888") == "2001:4860:4860::8888"


def test_normalize_public_ip_rejects_ipv6_loopback(app_module):
    assert app_module.normalize_public_ip("::1") is None


def test_normalize_public_ip_rejects_ipv6_unique_local(app_module):
    assert app_module.normalize_public_ip("fc00::1") is None


def test_normalize_public_ip_unwraps_ipv4_mapped_ipv6(app_module):
    assert app_module.normalize_public_ip("::ffff:8.8.8.8") == "8.8.8.8"


# --- GeoIPProvider abstraction + local caching -------------------------------


def test_null_geoip_provider_is_the_default_when_no_database_is_configured(app_module):
    """No database ships in the repository by default (docs/GEOIP.md); the
    map must honestly report unmapped rather than guess a location."""
    assert isinstance(app_module._geoip_provider, app_module.NullGeoIPProvider)
    assert app_module._geoip_provider.available is False
    assert app_module._geoip_provider.lookup("8.8.8.8") == (None, None)


def test_csv_range_provider_matches_an_ip_inside_a_configured_range(tmp_path, app_module):
    csv_path = tmp_path / "geoip.csv"
    csv_path.write_text("start_ip,end_ip,country_code,country_name\n203.0.113.0,203.0.113.255,US,United States\n")
    provider = app_module.CsvRangeGeoIPProvider(str(csv_path))
    assert provider.available is True
    assert provider.lookup("203.0.113.42") == ("US", "United States")


def test_csv_range_provider_reports_unmapped_outside_any_range(tmp_path, app_module):
    csv_path = tmp_path / "geoip.csv"
    csv_path.write_text("203.0.113.0,203.0.113.255,US,United States\n")
    provider = app_module.CsvRangeGeoIPProvider(str(csv_path))
    assert provider.lookup("198.51.100.7") == (None, None)


def test_csv_range_provider_supports_ipv6_ranges(tmp_path, app_module):
    csv_path = tmp_path / "geoip.csv"
    csv_path.write_text("2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,DE,Germany\n")
    provider = app_module.CsvRangeGeoIPProvider(str(csv_path))
    assert provider.lookup("2001:db8:1234::1") == ("DE", "Germany")


def test_csv_range_provider_is_unavailable_for_a_missing_file(tmp_path, app_module):
    provider = app_module.CsvRangeGeoIPProvider(str(tmp_path / "does-not-exist.csv"))
    assert provider.available is False
    assert provider.lookup("8.8.8.8") == (None, None)


def test_csv_range_provider_skips_malformed_rows_without_failing(tmp_path, app_module):
    csv_path = tmp_path / "geoip.csv"
    csv_path.write_text("not,enough,columns\n203.0.113.0,203.0.113.255,US,United States\n")
    provider = app_module.CsvRangeGeoIPProvider(str(csv_path))
    assert provider.available is True
    assert provider.lookup("203.0.113.1") == ("US", "United States")


def test_geoip_lookup_is_cached_and_bounded(app_module, monkeypatch):
    calls = []

    class _CountingProvider(app_module.GeoIPProvider):
        def lookup(self, ip):
            calls.append(ip)
            return "US", "United States"

        @property
        def available(self):
            return True

    _use_provider(app_module, monkeypatch, _CountingProvider())
    ip = "203.0.113.9"
    first = app_module.geoip_lookup(ip)
    second = app_module.geoip_lookup(ip)
    assert first == second == {"country_code": "US", "country_name": "United States"}
    assert calls == [ip]  # second call was served from the cache, not the provider


# --- geoip_map_payload() aggregation semantics -------------------------------


def test_geoip_map_payload_aggregates_a_geolocated_domain_by_country(app_module, initialised_db, monkeypatch):
    domain = _unique("geo-domain")
    device_key = _unique("mac:aa:bb:cc:dd:ee")
    now = app_module.utcnow()
    _insert_domain(initialised_db, domain, now, requests=7, clients={device_key: 7})
    _set_dns_records(initialised_db, domain, now, {"A": ["203.0.113.10"]})
    _use_provider(app_module, monkeypatch, _FixedProvider({"203.0.113.10": ("US", "United States")}))

    payload = app_module.geoip_map_payload()

    us = next(c for c in payload["countries"] if c["country_code"] == "US")
    assert domain in us["sample_domains"]
    assert us["query_count"] >= 7
    assert us["domain_count"] >= 1
    assert us["centroid"] is not None
    assert payload["provider"]["configured"] is True
    assert payload["coverage"]["geolocated_pct"] > 0


def test_geoip_map_payload_filters_private_answers_before_geolocating(app_module, initialised_db, monkeypatch):
    domain = _unique("geo-private-only")
    now = app_module.utcnow()
    _insert_domain(initialised_db, domain, now, requests=3)
    _set_dns_records(initialised_db, domain, now, {"A": ["10.0.0.5"]})
    _use_provider(app_module, monkeypatch, _FixedProvider({"10.0.0.5": ("US", "United States")}))

    payload = app_module.geoip_map_payload()

    for country in payload["countries"]:
        assert domain not in country["sample_domains"]


def test_geoip_map_payload_counts_a_domain_with_no_cached_records_as_unknown(app_module, initialised_db, monkeypatch):
    domain = _unique("geo-no-records")
    now = app_module.utcnow()
    _insert_domain(initialised_db, domain, now, requests=2)
    _use_provider(app_module, monkeypatch, _FixedProvider({}))

    payload = app_module.geoip_map_payload()

    for country in payload["countries"]:
        assert domain not in country["sample_domains"]
    assert payload["unknown"]["domain_count"] >= 1
    assert payload["unknown"]["query_count"] >= 2


def test_geoip_map_payload_is_honestly_empty_when_no_provider_is_configured(app_module, initialised_db, monkeypatch):
    domain = _unique("geo-unconfigured")
    now = app_module.utcnow()
    _insert_domain(initialised_db, domain, now, requests=4)
    _set_dns_records(initialised_db, domain, now, {"A": ["203.0.113.50"]})
    _use_provider(app_module, monkeypatch, app_module.NullGeoIPProvider())

    payload = app_module.geoip_map_payload()

    assert payload["provider"]["configured"] is False
    assert payload["coverage"]["geolocated_pct"] == 0.0
    for country in payload["countries"]:
        assert domain not in country["sample_domains"]


def test_geoip_map_payload_result_is_cached_for_geoip_map_cache_seconds(app_module, initialised_db, monkeypatch):
    domain = _unique("geo-cache")
    now = app_module.utcnow()
    _insert_domain(initialised_db, domain, now, requests=1)
    _set_dns_records(initialised_db, domain, now, {"A": ["203.0.113.60"]})
    _use_provider(app_module, monkeypatch, _FixedProvider({"203.0.113.60": ("US", "United States")}))

    first = app_module.geoip_map_payload()
    # Same provider swapped for one that would answer differently -- the
    # cached payload should still be returned since the TTL has not elapsed.
    monkeypatch.setattr(app_module, "_geoip_provider", _FixedProvider({"203.0.113.60": ("DE", "Germany")}))
    second = app_module.geoip_map_payload()
    assert second is first


# --- HTTP surface -------------------------------------------------------


def test_analytics_map_route_is_registered(app_module):
    rules = {rule.rule for rule in app_module.app.url_map.iter_rules()}
    assert "/api/analytics/map" in rules


def test_api_analytics_map_returns_expected_shape(client):
    response = client.get("/api/analytics/map")
    assert response.status_code == 200
    payload = json.loads(response.data)
    assert set(payload) >= {"updated", "provider", "countries", "unknown", "coverage"}
    assert isinstance(payload["countries"], list)
    assert set(payload["coverage"]) >= {
        "total_domains", "geolocated_domains", "total_queries",
        "geolocated_queries", "geolocated_pct",
    }
    assert set(payload["unknown"]) >= {"domain_count", "query_count"}


def test_api_analytics_includes_total_devices_for_the_active_devices_gauge(client):
    response = client.get("/api/analytics")
    payload = json.loads(response.data)
    assert "total_devices" in payload
    assert isinstance(payload["total_devices"], int)


# --- rendered markup: widgets, empty state, gauges, reduced motion ----------


def test_destination_map_widget_is_registered_in_the_dashboard_grid(client):
    body = client.get("/").data.decode("utf-8")
    assert 'data-widget-id="destination-map"' in body
    assert 'id="destination-map"' in body
    assert 'id="destination-map-detail"' in body


def test_instrument_gauges_widget_is_registered_in_the_dashboard_grid(client):
    body = client.get("/").data.decode("utf-8")
    assert 'data-widget-id="instrument-gauges"' in body
    assert 'id="gauge-blocked-ratio"' in body
    assert 'id="gauge-active-devices"' in body


def test_map_and_gauge_render_functions_exist(client):
    body = client.get("/").data.decode("utf-8")
    for fn in ("renderDestinationMap", "renderMapDetail", "fetchDestinationMap",
               "instrumentPercentGaugeSvg", "renderInstrumentGauges"):
        assert f"function {fn}(" in body


def test_analog_gauge_svg_is_unchanged_by_the_new_generic_gauge_helper(client):
    """instrumentPercentGaugeSvg() is additive -- analogGaugeSvg() (the
    existing live-activity gauge toggle) keeps its own declaration."""
    body = client.get("/").data.decode("utf-8")
    assert "function analogGaugeSvg(pct, current, peak){" in body


def test_map_empty_state_copy_does_not_claim_server_locations(client):
    body = client.get("/").data.decode("utf-8")
    assert "No GeoIP database configured" in body
    assert "observed" in body.lower()
    assert "Server Locations" not in body


def test_reduced_motion_suppresses_gauge_needle_and_map_pulse_animation(client):
    body = client.get("/").data.decode("utf-8")
    assert ".analog-gauge .gauge-needle{transition:" in body
    assert 'html[data-motion="reduced"] .map-bubble-pulse-ring{display:none}' in body
