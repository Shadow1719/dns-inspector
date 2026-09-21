import sys


def _fresh_app(monkeypatch, tmp_path, env=None):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "inspector.db"))
    monkeypatch.setenv("TRACKERDB_PATH", str(tmp_path / "trackerdb.sqlite"))
    monkeypatch.setenv("AGH_URL", "")
    monkeypatch.setenv("NEIGHBORS_PATH", str(tmp_path / "neighbors.txt"))
    if env is None:
        monkeypatch.delenv("DNS_INSPECTOR_ENV", raising=False)
    else:
        monkeypatch.setenv("DNS_INSPECTOR_ENV", env)
    sys.modules.pop("app", None)
    import app
    return app


def test_environment_defaults_to_production_and_selects_prod_assets(monkeypatch, tmp_path):
    app = _fresh_app(monkeypatch, tmp_path)
    assert app.RUNTIME_ENV == "production"
    ctx = app._environment_render_context()
    assert ctx["is_dev_environment"] is False
    assert ctx["favicon_path"] == "/static/favicon.svg"
    assert ctx["page_title"] == "DNS Inspector"


def test_environment_development_selects_dev_assets(monkeypatch, tmp_path):
    app = _fresh_app(monkeypatch, tmp_path, "development")
    assert app.RUNTIME_ENV == "development"
    ctx = app._environment_render_context()
    assert ctx["is_dev_environment"] is True
    assert ctx["favicon_path"] == "/static/favicon-dev.svg"
    assert ctx["page_title"] == f"DNS Inspector DEV v{app.APP_VERSION}"


def test_root_route_renders_dashboard_html_not_analytics_json(monkeypatch, tmp_path):
    app = _fresh_app(monkeypatch, tmp_path, "development")
    app.init_db()
    client = app.app.test_client()

    response = client.get("/")
    assert response.status_code == 200
    assert response.content_type.startswith("text/html")
    body = response.get_data(as_text=True)
    assert "DNS Inspector" in body
    assert "DEVELOPMENT ENVIRONMENT" in body
    assert "/static/favicon-dev.svg" in body


def test_health_and_analytics_payload_expose_clean_runtime_state(monkeypatch, tmp_path):
    app = _fresh_app(monkeypatch, tmp_path, "development")
    app.init_db()
    client = app.app.test_client()

    health = client.get("/health").get_json()
    assert health["environment"] == "development"
    assert health["version"] == app.APP_VERSION

    analytics = client.get("/api/analytics?range=1h").get_json()
    assert analytics["range"] == "1h"
    assert len(analytics["series"]["queries"]["points"]) == 60
    assert len(analytics["series"]["new_domains"]["points"]) == 60
    assert len(analytics["series"]["new_devices"]["points"]) == 60
    assert analytics["status_breakdown"]["All"] == 0
    assert analytics["live"]["queries_in_window"] == 0


def test_device_labels_are_persistent_and_bounded(monkeypatch, tmp_path):
    app = _fresh_app(monkeypatch, tmp_path, "development")
    app.init_db()
    client = app.app.test_client()
    assert client.post("/api/device/label", json={"device_key": "mac:aa:bb", "label": "Living Room TV"}).status_code == 200
    data = client.get("/api/device/label").get_json()
    assert data["labels"] == {"mac:aa:bb": "Living Room TV"}
    assert client.post("/api/device/label", json={"device_key": "mac:aa:bb", "label": "x" * 200}).get_json()["label"] == "x" * 80


def test_analytics_pdf_export_is_a_real_pdf(monkeypatch, tmp_path):
    app = _fresh_app(monkeypatch, tmp_path, "development")
    app.init_db()
    client = app.app.test_client()

    response = client.get("/api/analytics/report.pdf?range=1h")
    assert response.status_code == 200
    assert response.mimetype == "application/pdf"
    assert response.data.startswith(b"%PDF-")
    assert "attachment;" in response.headers.get("Content-Disposition", "")
    assert len(response.data) > 2000
