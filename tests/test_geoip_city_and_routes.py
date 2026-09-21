import json
from contextlib import closing
from pathlib import Path


def _write_city_csv(tmp_path, rows):
    path = tmp_path / "geoip_city.csv"
    lines = ["start_ip,end_ip,country_code,country_name,city,lat,lon"] + rows
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_city_geoip_provider_lookup_returns_real_coordinates(app_module, tmp_path):
    csv_path = _write_city_csv(tmp_path, ["8.8.8.0,8.8.8.255,US,United States,Mountain View,37.4056,-122.0775"])
    provider = app_module.CsvRangeCityGeoIPProvider(str(csv_path))
    assert provider.available is True
    assert provider.range_count == 1
    code, name, city, lat, lon = provider.lookup("8.8.8.8")
    assert code == "US"
    assert city == "Mountain View"
    assert lat == 37.4056
    assert lon == -122.0775
    assert provider.lookup("9.9.9.9") == (None, None, None, None, None)


def test_city_geoip_provider_rejects_out_of_range_coordinates(app_module, tmp_path):
    csv_path = _write_city_csv(tmp_path, ["1.1.1.0,1.1.1.255,AU,Australia,Nowhere,999,999"])
    provider = app_module.CsvRangeCityGeoIPProvider(str(csv_path))
    # The malformed row is skipped entirely rather than stored with a bogus
    # coordinate -- no ranges are loaded.
    assert provider.range_count == 0


def test_geoip_map_payload_has_no_destinations_without_city_provider(app_module):
    app_module.init_db()
    app_module._geoip_map_cache["data"] = None
    payload = app_module.geoip_map_payload()
    assert payload["capabilities"]["coordinates"] is False
    assert payload["destinations"] == []
    assert payload["origin"] is None


def test_geoip_map_payload_populates_real_destination_coordinates(app_module, tmp_path):
    app_module.init_db()
    csv_path = _write_city_csv(tmp_path, ["8.8.8.0,8.8.8.255,US,United States,Mountain View,37.4056,-122.0775"])
    app_module._geoip_city_provider = app_module.CsvRangeCityGeoIPProvider(str(csv_path))
    app_module._geoip_city_cache.clear()
    app_module._geoip_map_cache["data"] = None

    now = app_module.utcnow()
    with closing(app_module.sqlite3.connect(app_module.DB_PATH)) as c:
        c.execute(
            "INSERT INTO domains(domain,first_seen,last_seen,requests,clients_json,blocked_requests,allowed_requests,unknown_requests,last_status,last_reason,current_status,current_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            ("example.com", now, now, 2, json.dumps({"mac:aa": 2}), 0, 2, 0, "Allowed", "", "Allowed", ""),
        )
        c.execute(
            "INSERT INTO domain_destination_ips(domain,ip,first_seen,last_seen,observations) VALUES(?,?,?,?,?)",
            ("example.com", "8.8.8.8", now, now, 2),
        )
        c.commit()

    payload = app_module.geoip_map_payload()
    assert payload["capabilities"]["coordinates"] is True
    assert len(payload["destinations"]) == 1
    dest = payload["destinations"][0]
    assert dest["lat"] == 37.4056
    assert dest["lon"] == -122.0775
    assert dest["city"] == "Mountain View"
    assert dest["observation_count"] == 2


def test_map_origin_not_derived_until_explicitly_set(app_module):
    app_module.init_db()
    app_module._geoip_map_cache["data"] = None
    payload = app_module.geoip_map_payload()
    assert payload["origin"] is None
    app_module.set_setting("map_origin", {"lat": 51.5, "lon": -0.1, "label": "Office"})
    app_module._geoip_map_cache["data"] = None
    payload2 = app_module.geoip_map_payload()
    assert payload2["origin"] == {"lat": 51.5, "lon": -0.1, "label": "Office"}


def test_leaflet_map_has_dark_noc_basemap_with_attribution():
    js = (Path(__file__).resolve().parents[1] / "static" / "leaflet-map.js").read_text(encoding="utf-8")
    assert "Dark / NOC" in js
    assert "carto.com/attributions" in js
    assert "openstreetmap.org/copyright" in js


def test_leaflet_map_route_arcs_are_geodesic_and_labeled_as_visual_only():
    js = (Path(__file__).resolve().parents[1] / "static" / "leaflet-map.js").read_text(encoding="utf-8")
    assert "greatCircleArc" in js
    assert "renderRoutes" in js
    assert "not the real network route" in js
    assert "mapRoutes" in js


def test_country_breakdown_panel_has_bounded_independent_scroll(app_module):
    html = app_module.HTML
    assert ".map-breakdown{" in html
    assert "overflow-y:auto" in html
    assert 'id="map-breakdown-list"' in html


def test_geoip_map_payload_handles_large_country_lists_without_truncating(app_module, tmp_path):
    app_module.init_db()
    rows = []
    for i in range(120):
        code = f"{chr(65 + i % 26)}{chr(65 + (i // 26) % 26)}"
        rows.append(f"10.{i}.0.0,10.{i}.255.255,{code},Country {i}")
    csv_path = tmp_path / "geoip.csv"
    csv_path.write_text("start_ip,end_ip,country_code,country_name\n" + "\n".join(rows) + "\n", encoding="utf-8")
    app_module._geoip_provider = app_module.CsvRangeGeoIPProvider(str(csv_path))
    app_module._geoip_map_cache["data"] = None

    now = app_module.utcnow()
    with closing(app_module.sqlite3.connect(app_module.DB_PATH)) as c:
        for i in range(120):
            domain = f"domain{i}.example"
            ip = f"10.{i}.1.1"
            c.execute(
                "INSERT INTO domains(domain,first_seen,last_seen,requests,clients_json,blocked_requests,allowed_requests,unknown_requests,last_status,last_reason,current_status,current_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (domain, now, now, 1, json.dumps({}), 0, 1, 0, "Allowed", "", "Allowed", ""),
            )
            c.execute(
                "INSERT INTO domain_destination_ips(domain,ip,first_seen,last_seen,observations) VALUES(?,?,?,?,?)",
                (domain, ip, now, now, 1),
            )
        c.commit()

    payload = app_module.geoip_map_payload()
    assert len(payload["countries"]) == 120
