"""DNS Destinations / GeoIP map + instrument gauges (Issue #27 / 0.8.5.1).

GeoIP lookups are always local/offline (see docs/GEOIP.md); these tests build
small in-memory CSV databases rather than depending on a real one. No
database ships in the repository by default, so `app_module._geoip_provider`
is a `NullGeoIPProvider` unless a test explicitly swaps it in via
`monkeypatch` (which reverts automatically at the end of each test). Because
the underlying SQLite database is session-scoped (see conftest.py), every
aggregation assertion below is a targeted delta around a uniquely-tagged
domain, matching the style already used in test_analytics.py.

Destination IPs come from `domain_destination_ips`, populated at ingestion
time from each query's own AdGuard answer (`extract_observed_answer_ips`),
not from `dns_records_cache` (an independently, asynchronously
DNS-over-HTTPS-re-resolved snapshot used only by the domain detail page).
"""

import json
import re
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
    """Deterministic test double: maps specific IPs to specific countries."""

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


# --- extract_observed_answer_ips: real per-query destination capture --------


def test_extract_observed_answer_ips_pulls_a_and_aaaa_values(app_module):
    entry = {
        "answer": [
            {"type": "A", "value": "8.8.8.8"},
            {"type": "AAAA", "value": "2001:4860:4860::8888"},
            {"type": "CNAME", "value": "cdn.example.net."},
        ]
    }
    assert app_module.extract_observed_answer_ips(entry) == ["8.8.8.8", "2001:4860:4860::8888"]


def test_extract_observed_answer_ips_drops_private_answers(app_module):
    entry = {"answer": [{"type": "A", "value": "10.0.0.5"}]}
    assert app_module.extract_observed_answer_ips(entry) == []


def test_extract_observed_answer_ips_ignores_duplicate_values(app_module):
    entry = {"answer": [{"type": "A", "value": "8.8.8.8"}, {"type": "A", "value": "8.8.8.8"}]}
    assert app_module.extract_observed_answer_ips(entry) == ["8.8.8.8"]


def test_extract_observed_answer_ips_handles_missing_or_malformed_answer(app_module):
    assert app_module.extract_observed_answer_ips({}) == []
    assert app_module.extract_observed_answer_ips({"answer": None}) == []
    assert app_module.extract_observed_answer_ips({"answer": ["not-a-dict"]}) == []


def test_record_domain_destination_ips_accumulates_observation_counts(app_module, initialised_db):
    domain = _unique("record-destinations")
    now = app_module.utcnow()
    with closing(sqlite3.connect(initialised_db)) as conn:
        app_module._record_domain_destination_ips(conn, domain, ["203.0.113.7"], now)
        app_module._record_domain_destination_ips(conn, domain, ["203.0.113.7", "203.0.113.8"], now)
        conn.commit()
        rows = dict(conn.execute(
            "SELECT ip, observations FROM domain_destination_ips WHERE domain=?", (domain,)
        ).fetchall())
    assert rows == {"203.0.113.7": 2, "203.0.113.8": 1}


def test_record_domain_destination_ips_is_bounded_per_domain(app_module, initialised_db, monkeypatch):
    domain = _unique("bounded-destinations")
    now = app_module.utcnow()
    monkeypatch.setattr(app_module, "GEOIP_DESTINATION_IPS_PER_DOMAIN_LIMIT", 2)
    with closing(sqlite3.connect(initialised_db)) as conn:
        for i in range(5):
            app_module._record_domain_destination_ips(conn, domain, [f"203.0.113.{i + 1}"], now)
        conn.commit()
        count = conn.execute(
            "SELECT COUNT(*) FROM domain_destination_ips WHERE domain=?", (domain,)
        ).fetchone()[0]
    assert count == 2


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


def test_csv_range_provider_precomputes_start_key_arrays_for_bisect(tmp_path, app_module):
    """lookup() must bisect a precomputed start-key array (built once at load
    time) rather than rebuilding `[r[0] for r in bucket]` on every call --
    otherwise each lookup does O(n) work despite the binary search."""
    csv_path = tmp_path / "geoip.csv"
    csv_path.write_text(
        "203.0.113.0,203.0.113.63,US,United States\n"
        "198.51.100.0,198.51.100.63,DE,Germany\n"
    )
    provider = app_module.CsvRangeGeoIPProvider(str(csv_path))
    assert provider._v4_starts == [r[0] for r in provider._v4]
    assert provider.lookup("198.51.100.10") == ("DE", "Germany")
    assert provider.lookup("203.0.113.10") == ("US", "United States")


def test_csv_range_provider_interns_repeated_country_strings(tmp_path, app_module):
    """A real Country Lite export repeats the same handful of country
    codes/names across hundreds of thousands of rows (Issue #45): each row
    must share one `country_code`/`country_name` string object rather than
    allocating a fresh pair of strings per row."""
    csv_path = tmp_path / "geoip.csv"
    csv_path.write_text(
        "203.0.113.0,203.0.113.63,US,United States\n"
        "203.0.113.64,203.0.113.127,us,United States\n"
        "2001:db8::,2001:db8::ffff,US,United States\n"
    )
    provider = app_module.CsvRangeGeoIPProvider(str(csv_path))
    codes = [r[2] for r in provider._v4] + [r[2] for r in provider._v6]
    names = [r[3] for r in provider._v4] + [r[3] for r in provider._v6]
    assert all(c is codes[0] for c in codes)
    assert all(n is names[0] for n in names)


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
    _add_destination_ip(initialised_db, domain, now, "203.0.113.10", observations=7)
    _use_provider(app_module, monkeypatch, _FixedProvider({"203.0.113.10": ("US", "United States")}))

    payload = app_module.geoip_map_payload()

    us = next(c for c in payload["countries"] if c["country_code"] == "US")
    assert domain in us["sample_domains"]
    assert us["observation_count"] >= 7
    assert us["domain_count"] >= 1
    assert us["centroid"] is not None
    assert payload["provider"]["configured"] is True
    assert payload["coverage"]["geolocated_pct"] > 0


def test_geoip_map_payload_attributes_each_destination_to_its_own_country(app_module, initialised_db, monkeypatch):
    """A domain answering from more than one country (CDN/multi-region) must
    contribute to each country by that destination's own observation count --
    not have its whole request count attributed to a single arbitrary IP."""
    domain = _unique("geo-multi-destination")
    now = app_module.utcnow()
    _insert_domain(initialised_db, domain, now, requests=10)
    _add_destination_ip(initialised_db, domain, now, "203.0.113.20", observations=6)
    _add_destination_ip(initialised_db, domain, now, "198.51.100.20", observations=4)
    _use_provider(app_module, monkeypatch, _FixedProvider({
        "203.0.113.20": ("US", "United States"),
        "198.51.100.20": ("DE", "Germany"),
    }))

    payload = app_module.geoip_map_payload()

    us = next(c for c in payload["countries"] if c["country_code"] == "US")
    de = next(c for c in payload["countries"] if c["country_code"] == "DE")
    assert domain in us["sample_domains"]
    assert domain in de["sample_domains"]
    assert us["observation_count"] >= 6
    assert de["observation_count"] >= 4


def test_geoip_map_payload_filters_private_answers_before_geolocating(app_module, initialised_db, monkeypatch):
    """A query whose only answer is a private/CGNAT/etc. address must never
    reach `domain_destination_ips` at all -- filtering happens once, at
    ingestion time (`extract_observed_answer_ips`), not re-derived on every
    aggregation read."""
    domain = _unique("geo-private-only")
    now = app_module.utcnow()
    _insert_domain(initialised_db, domain, now, requests=3)
    with closing(sqlite3.connect(initialised_db)) as conn:
        observed = app_module.extract_observed_answer_ips({"answer": [{"type": "A", "value": "10.0.0.5"}]})
        app_module._record_domain_destination_ips(conn, domain, observed, now)
        conn.commit()
        stored = conn.execute(
            "SELECT COUNT(*) FROM domain_destination_ips WHERE domain=?", (domain,)
        ).fetchone()[0]
    assert stored == 0
    _use_provider(app_module, monkeypatch, _FixedProvider({"10.0.0.5": ("US", "United States")}))

    payload = app_module.geoip_map_payload()

    for country in payload["countries"]:
        assert domain not in country["sample_domains"]


def test_geoip_map_payload_counts_a_domain_with_no_observed_destinations_as_unknown(app_module, initialised_db, monkeypatch):
    domain = _unique("geo-no-destinations")
    now = app_module.utcnow()
    _insert_domain(initialised_db, domain, now, requests=2)
    _use_provider(app_module, monkeypatch, _FixedProvider({}))

    payload = app_module.geoip_map_payload()

    for country in payload["countries"]:
        assert domain not in country["sample_domains"]
    assert payload["unknown"]["domain_count"] >= 1


def test_geoip_map_payload_is_honestly_empty_when_no_provider_is_configured(app_module, initialised_db, monkeypatch):
    domain = _unique("geo-unconfigured")
    now = app_module.utcnow()
    _insert_domain(initialised_db, domain, now, requests=4)
    _add_destination_ip(initialised_db, domain, now, "203.0.113.50", observations=4)
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
    _add_destination_ip(initialised_db, domain, now, "203.0.113.60", observations=1)
    _use_provider(app_module, monkeypatch, _FixedProvider({"203.0.113.60": ("US", "United States")}))

    first = app_module.geoip_map_payload()
    # Same provider swapped for one that would answer differently -- the
    # cached payload should still be returned since the TTL has not elapsed.
    monkeypatch.setattr(app_module, "_geoip_provider", _FixedProvider({"203.0.113.60": ("DE", "Germany")}))
    second = app_module.geoip_map_payload()
    assert second is first


def test_geoip_map_payload_still_works_with_a_mix_of_mapped_and_unmapped_destinations(
    app_module, initialised_db, monkeypatch,
):
    """A domain whose answers include both a geolocatable and an unmapped
    destination IP must still produce a valid payload: the mapped IP counts
    toward its country and the domain counts as geolocated overall, while the
    unmapped observation is tracked honestly rather than silently dropped or
    crashing the aggregation."""
    domain = _unique("geo-mixed-destinations")
    now = app_module.utcnow()
    _insert_domain(initialised_db, domain, now, requests=9)
    _add_destination_ip(initialised_db, domain, now, "203.0.113.30", observations=5)
    _add_destination_ip(initialised_db, domain, now, "198.51.100.30", observations=4)
    _use_provider(app_module, monkeypatch, _FixedProvider({
        "203.0.113.30": ("US", "United States"),
        # 198.51.100.30 intentionally left unmapped.
    }))

    payload = app_module.geoip_map_payload()

    us = next(c for c in payload["countries"] if c["country_code"] == "US")
    assert domain in us["sample_domains"]
    assert us["observation_count"] >= 5
    assert payload["coverage"]["geolocated_domains"] >= 1
    assert payload["coverage"]["geolocated_pct"] > 0
    assert payload["coverage"]["geolocated_pct"] < 100


# --- GeoIP operator diagnostics ----------------------------------------------


def test_geoip_diagnostics_reports_unconfigured_for_the_null_provider(app_module, monkeypatch):
    _use_provider(app_module, monkeypatch, app_module.NullGeoIPProvider())
    diag = app_module._geoip_diagnostics()
    assert diag["provider_type"] == "NullGeoIPProvider"
    assert diag["configured"] is False
    assert diag["db_path_basename"] is None
    assert diag["range_count"] == 0


def test_geoip_diagnostics_reports_range_count_for_a_loaded_csv_provider(tmp_path, app_module, monkeypatch):
    csv_path = tmp_path / "geoip.csv"
    csv_path.write_text(
        "203.0.113.0,203.0.113.255,US,United States\n"
        "198.51.100.0,198.51.100.255,DE,Germany\n",
    )
    provider = app_module.CsvRangeGeoIPProvider(str(csv_path))
    _use_provider(app_module, monkeypatch, provider)

    diag = app_module._geoip_diagnostics()

    assert diag["provider_type"] == "CsvRangeGeoIPProvider"
    assert diag["configured"] is True
    assert diag["db_path_basename"] == "geoip.csv"
    assert diag["range_count"] == 2


def test_geoip_diagnostics_does_not_leak_the_full_configured_path(tmp_path, app_module, monkeypatch):
    """Only the basename is reported, not the full filesystem path, so an
    observability/debug-bundle payload doesn't expose host directory layout."""
    csv_path = tmp_path / "geoip.csv"
    csv_path.write_text("203.0.113.0,203.0.113.255,US,United States\n")
    provider = app_module.CsvRangeGeoIPProvider(str(csv_path))
    _use_provider(app_module, monkeypatch, provider)

    diag = app_module._geoip_diagnostics()

    assert str(tmp_path) not in json.dumps(diag)


def test_log_geoip_status_mentions_the_range_count_when_configured(tmp_path, app_module, monkeypatch, capsys):
    csv_path = tmp_path / "geoip.csv"
    csv_path.write_text("203.0.113.0,203.0.113.255,US,United States\n")
    provider = app_module.CsvRangeGeoIPProvider(str(csv_path))
    _use_provider(app_module, monkeypatch, provider)

    app_module._log_geoip_status()

    captured = capsys.readouterr()
    assert "1 ranges" in captured.out
    assert "geoip.csv" in captured.out


def test_log_geoip_status_is_honest_when_unconfigured(app_module, monkeypatch, capsys):
    _use_provider(app_module, monkeypatch, app_module.NullGeoIPProvider())

    app_module._log_geoip_status()

    captured = capsys.readouterr()
    assert "no database configured" in captured.out.lower()


def test_observability_payload_includes_geoip_diagnostics(app_module):
    payload = app_module._observability_payload()
    assert "geoip" in payload
    assert set(payload["geoip"]) >= {"provider_type", "configured", "db_path_basename", "range_count"}


def test_api_observability_route_exposes_geoip_diagnostics(client):
    response = client.get("/api/observability")
    payload = json.loads(response.data)
    assert "geoip" in payload
    assert "configured" in payload["geoip"]


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
        "total_domains", "geolocated_domains", "total_observations",
        "geolocated_observations", "geolocated_pct",
    }
    assert set(payload["unknown"]) >= {"domain_count", "observation_count"}


def test_api_analytics_map_returns_geolocated_coverage_with_a_fixture_provider_configured(
    app_module, initialised_db, client, monkeypatch,
):
    """End-to-end through the real HTTP route (not just `geoip_map_payload()`
    directly): with a fixture provider and a fixture destination IP in place,
    `/api/analytics/map` itself must report non-zero geolocated coverage and
    a plotted country -- this is what an operator checks per docs/GEOIP.md's
    verification steps."""
    domain = _unique("geo-http-route")
    now = app_module.utcnow()
    _insert_domain(initialised_db, domain, now, requests=3)
    _add_destination_ip(initialised_db, domain, now, "203.0.113.99", observations=3)
    _use_provider(app_module, monkeypatch, _FixedProvider({"203.0.113.99": ("US", "United States")}))

    response = client.get("/api/analytics/map")

    assert response.status_code == 200
    payload = json.loads(response.data)
    assert payload["provider"]["configured"] is True
    assert payload["coverage"]["geolocated_pct"] > 0
    us = next(c for c in payload["countries"] if c["country_code"] == "US")
    assert domain in us["sample_domains"]


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
               "instrumentPercentGaugeSvg", "renderInstrumentGauges", "updateGaugeNeedle"):
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


def test_map_honestly_reports_plotted_vs_total_geolocated_countries(client):
    """COUNTRY_CENTROIDS only covers a bounded subset of countries (see
    docs/GEOIP.md); the widget must not silently drop geolocated countries
    that lack a plotted bubble -- it needs to say so explicitly."""
    body = client.get("/").data.decode("utf-8")
    assert "geolocated countries plotted" in body


def test_gauge_needle_uses_a_valid_animatable_css_property(client):
    """SVG `<line>` endpoints (x1/y1/x2/y2) are not themselves animatable CSS
    properties -- `transform` is; the needle must be rotated, not stretched."""
    body = client.get("/").data.decode("utf-8")
    assert ".instrument-gauge .gauge-needle{transition:transform" in body
    assert ".gauge-needle{transition:x2" not in body


def test_reduced_motion_suppresses_gauge_needle_and_map_pulse_animation(client):
    body = client.get("/").data.decode("utf-8")
    assert 'html:not([data-motion="reduced"]) .instrument-gauge .gauge-needle{transition:' in body
    assert 'html[data-motion="reduced"] .map-bubble-pulse-ring{display:none}' in body


# --- bundled world-map background (Issue #33) --------------------------------
#
# Before this fix, an unconfigured/empty map state replaced the whole widget
# with a plain `<div class="empty-state">` card -- no map was ever visible.
# These tests pin the fix: a bundled/offline-safe landmass silhouette is
# always rendered, and the GeoIP-unconfigured/empty states now overlay a
# non-blocking status banner on top of the still-visible map instead of
# tearing it out.


def test_world_landmass_asset_is_bundled_and_offline_safe(client):
    """The map background must ship as a static asset in the page itself --
    no fetch to a CDN/external map provider, no GeoIP database required."""
    body = client.get("/").data.decode("utf-8")
    assert "const WORLD_LAND_D" in body
    assert ".map-landmass{" in body
    assert 'class="map-landmass"' in body


def test_world_landmass_coordinates_stay_within_the_map_viewbox(client):
    """Every point in the bundled silhouette must fall inside the same
    0..MAP_W x 0..MAP_H (720x360) space the graticule and country bubbles
    are projected into, or the asset would render clipped/misaligned."""
    body = client.get("/").data.decode("utf-8")
    match = re.search(r"const WORLD_LAND_D = \[(.*?)\]\.join", body, re.S)
    assert match, "WORLD_LAND_D constant not found in rendered page"
    coords = re.findall(r"[ML](-?\d+(?:\.\d+)?),(-?\d+(?:\.\d+)?)", match.group(1))
    assert len(coords) > 50  # a real multi-continent silhouette, not a stub
    for x, y in coords:
        assert 0 <= float(x) <= 720
        assert 0 <= float(y) <= 360


def test_map_render_helpers_for_the_bundled_background_exist(client):
    body = client.get("/").data.decode("utf-8")
    for fn in ("mapLandmassSvg", "mapBaseLayers", "mapStatusBanner", "mapBaseSvg"):
        assert f"function {fn}(" in body


def test_map_no_longer_replaces_itself_with_a_plain_empty_state_card(client):
    """Regression guard for the exact bug reported in Issue #33: the map
    widget must not go back to swapping its whole innerHTML for a bare
    `.empty-state` card with no visual map."""
    body = client.get("/").data.decode("utf-8")
    assert 'el.innerHTML = \'<div class="empty-state">No GeoIP database configured' not in body


def test_map_stays_visible_with_a_non_blocking_banner_when_geoip_not_configured(client):
    body = client.get("/").data.decode("utf-8")
    assert "mapStatusBanner('No GeoIP database configured" in body
    assert ".map-status-banner{" in body
    assert "pointer-events:none" in body


def test_map_configured_state_still_renders_the_bundled_background_behind_bubbles(client):
    body = client.get("/").data.decode("utf-8")
    assert "mapBaseSvg('Observed DNS destinations by country', bubbles)" in body
