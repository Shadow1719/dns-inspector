import json


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
        "start_ip,end_ip,country_code,country_name\\n"
        "8.8.8.0,8.8.8.255,US,United States\\n"
        "1.1.1.0,1.1.1.255,AU,Australia\\n",
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
        "start_ip,end_ip,country_code,country_name\\n"
        "8.8.8.0,8.8.8.255,US,United States\\n",
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
