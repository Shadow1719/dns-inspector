import json
from pathlib import Path


def test_public_destination_ip_filtering(app_module):
    assert app_module.normalize_public_ip("8.8.8.8") == "8.8.8.8"
    assert app_module.normalize_public_ip("192.168.1.10") is None
    assert app_module.normalize_public_ip("100.64.1.10") is None
    assert app_module.normalize_public_ip("127.0.0.1") is None
    assert app_module.normalize_public_ip("::ffff:8.8.8.8") == "8.8.8.8"


def test_extract_observed_answer_ips_only_uses_a_aaaa(app_module):
    entry = {
        "answer": [
            {"type": "A", "value": "8.8.8.8"},
            {"type": "AAAA", "value": "2001:4860:4860::8888"},
            {"type": "CNAME", "value": "example.com."},
            {"type": "A", "value": "192.168.1.5"},
            {"type": "A", "value": "8.8.8.8"},
        ]
    }
    assert app_module.extract_observed_answer_ips(entry) == ["8.8.8.8", "2001:4860:4860::8888"]


def test_compact_country_geoip_provider_lookup(app_module, tmp_path):
    db = tmp_path / "geoip.csv"
    db.write_text(
        """start_ip,end_ip,country_code,country_name
8.8.8.0,8.8.8.255,US,United States
1.1.1.0,1.1.1.255,AU,Australia
""",
        encoding="utf-8",
    )
    provider = app_module.CsvRangeGeoIPProvider(str(db))
    assert provider.available is True
    assert provider.range_count == 2
    assert provider.lookup("8.8.8.8") == ("US", "United States")
    assert provider.lookup("1.1.1.1") == ("AU", "Australia")
    assert provider.lookup("9.9.9.9") == (None, None)


def test_destination_map_aggregates_observed_ips_by_country(app_module, tmp_path):
    app_module.init_db()
    geo = tmp_path / "geoip.csv"
    geo.write_text(
        """start_ip,end_ip,country_code,country_name
8.8.8.0,8.8.8.255,US,United States
""",
        encoding="utf-8",
    )
    app_module._geoip_provider = app_module.CsvRangeGeoIPProvider(str(geo))
    app_module._geoip_map_cache["data"] = None

    now = app_module.utcnow()
    with app_module.closing(app_module.sqlite3.connect(app_module.DB_PATH)) as c:
        c.execute(
            "INSERT INTO domains(domain,first_seen,last_seen,requests,clients_json,blocked_requests,allowed_requests,unknown_requests,last_status,last_reason,current_status,current_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            ("example.com", now, now, 3, json.dumps({"mac:aa": 3}), 0, 3, 0, "Allowed", "", "Allowed", ""),
        )
        c.execute(
            "INSERT INTO domain_destination_ips(domain,ip,first_seen,last_seen,observations) VALUES(?,?,?,?,?)",
            ("example.com", "8.8.8.8", now, now, 3),
        )
        c.execute(
            "INSERT INTO devices(device_key,hostname,last_seen,first_seen,request_count) VALUES(?,?,?,?,?)",
            ("mac:aa", "office-pc", now, now, 3),
        )
        c.commit()

    payload = app_module.geoip_map_payload()
    assert payload["capabilities"]["country"] is True
    assert payload["coverage"]["total_observations"] == 3
    assert payload["coverage"]["geolocated_observations"] == 3
    assert payload["coverage"]["geolocated_pct"] == 100.0
    assert payload["countries"][0]["country_code"] == "US"
    assert payload["countries"][0]["observation_count"] == 3
    assert payload["countries"][0]["centroid"] == [39.8, -98.6]


def test_map_and_devlog_endpoints_are_bounded_and_honest(app_module):
    app_module.init_db()
    app_module.log_event("INFO", "test event", source="pytest")
    client = app_module.app.test_client()

    devlog = client.get("/api/devlog").get_json()
    assert any(row["message"] == "test event" for row in devlog["entries"])

    map_payload = client.get("/api/analytics/map").get_json()
    assert map_payload["diagnostics"]["state"] == "not_configured"
    assert map_payload["capabilities"]["coordinates"] is False
    assert map_payload["destinations"] == []


def test_dev_ui_contains_banner_and_devlog_button(monkeypatch, app_module):
    monkeypatch.setenv("DNS_INSPECTOR_ENV", "development")
    # The app module already resolved its environment at import time; assert
    # the template contract directly for the shared UI elements.
    assert "DEVELOPMENT ENVIRONMENT — NOT PRODUCTION" in app_module.HTML
    assert 'id="devlog-open-btn"' in app_module.HTML
    assert 'id="destination-map"' in app_module.HTML


def test_debug_exports_are_small_and_bounded(app_module):
    app_module.init_db()
    app_module.log_event("INFO", "export test", source="pytest")
    client = app_module.app.test_client()

    devlog = client.get("/api/devlog/export")
    assert devlog.status_code == 200
    assert devlog.content_type.startswith("text/plain")
    assert devlog.headers.get("Content-Disposition", "").startswith("attachment;")

    debug = client.get("/api/debug/snapshot")
    assert debug.status_code == 200
    assert debug.content_type.startswith("application/json")
    assert debug.headers.get("Content-Disposition", "").startswith("attachment;")
    payload = json.loads(debug.data.decode("utf-8"))
    assert payload["observability"]["version"] == app_module.APP_VERSION
    assert len(payload["devlog"]) <= 200
    assert len(payload["runtime"]["active_threads"]) >= 1


def test_state_payload_exposes_observability_for_header(app_module):
    app_module.init_db()
    client = app_module.app.test_client()
    state = client.get("/api/state?page=1&page_size=10")
    assert state.status_code == 200
    data = state.get_json()
    assert "observability" in data
    assert data["observability"]["uptime_seconds"] >= 0
    assert data["observability"]["ram_mb"] is None or data["observability"]["ram_mb"] >= 0


def test_leaflet_renderer_uses_carto_and_satellite_layers():
    js = (Path(__file__).resolve().parents[1] / "static" / "leaflet-map.js").read_text(encoding="utf-8")
    assert "Dark / NOC (CARTO)" in js
    assert "basemaps.cartocdn.com" in js
    assert "Satellite (Esri)" in js
    assert "tile.openstreetmap.org" not in js

    assert "Satellite (Esri)" in js
    assert "L.control.layers" in js


def test_dashboard_landing_and_diagnostic_controls_are_present(monkeypatch, app_module):
    monkeypatch.setenv("DNS_INSPECTOR_ENV", "development")
    app_module.init_db()
    client = app_module.app.test_client()
    html = client.get("/").get_data(as_text=True)
    assert 'data-tab="analytics"' in html
    assert 'id="debug-download-top-btn"' in html
    assert 'id="devlog-download-btn"' in html
    assert 'id="debug-download-btn"' in html
    assert "defaultView:'analytics'" in html


def test_ip_ping_validation_and_status_endpoint(app_module, monkeypatch):
    app_module.init_db()
    client = app_module.app.test_client()

    assert app_module._validate_ping_ip("192.168.1.111") == "192.168.1.111"
    for bad in ("8.8.8.8", "127.0.0.1", "224.0.0.1", "not-an-ip"):
        try:
            app_module._validate_ping_ip(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"{bad} should not be pingable")

    monkeypatch.setattr(app_module, "_run_ip_ping", lambda ip: {
        "ip": ip, "online": True, "latency_ms": 1.2, "error": "", "last_checked": 123.0
    })
    response = client.post("/api/ip/ping", json={"ip": "192.168.1.111"})
    assert response.status_code == 200
    assert response.get_json()["result"]["online"] is True

    status = client.get("/api/ip/ping/status")
    assert status.status_code == 200
    assert status.get_json()["ok"] is True


def test_ip_ping_invalid_request_is_json(app_module):
    app_module.init_db()
    response = app_module.app.test_client().post("/api/ip/ping", json={"ip": "8.8.8.8"})
    assert response.status_code == 400
    payload = response.get_json()
    assert payload["ok"] is False
    assert "private LAN" in payload["error"]
