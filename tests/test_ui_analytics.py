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


def test_dashboard_html_exposes_a_report_period_selector_separate_from_chart_range(monkeypatch, tmp_path):
    app = _fresh_app(monkeypatch, tmp_path, "development")
    app.init_db()
    client = app.app.test_client()

    body = client.get("/").get_data(as_text=True)
    assert 'id="report-period-select"' in body
    assert 'id="report-custom-range"' in body
    assert 'id="report-custom-from"' in body
    assert 'id="report-custom-to"' in body
    assert 'value="30d"' in body
    assert 'value="90d"' in body
    assert 'value="custom"' in body
    # The dashboard's own live chart range control must remain the separate, unchanged set.
    assert 'data-analytics-range="1h"' in body
    assert 'data-analytics-range="30d"' not in body


def test_report_pdf_export_supports_30d_and_90d_presets_independent_of_dashboard_range(monkeypatch, tmp_path):
    app = _fresh_app(monkeypatch, tmp_path, "development")
    app.init_db()
    client = app.app.test_client()

    for range_key in ("30d", "90d"):
        response = client.get(f"/api/analytics/report.pdf?range={range_key}")
        assert response.status_code == 200
        assert response.mimetype == "application/pdf"
        assert response.data.startswith(b"%PDF-")
        disposition = response.headers.get("Content-Disposition", "")
        assert f"dns-inspector-analytics-{range_key}-" in disposition

    # The dashboard's own /api/analytics range set is untouched by the wider report options.
    assert "30d" not in app.ANALYTICS_RANGE_OPTIONS
    dashboard = client.get("/api/analytics?range=30d").get_json()
    assert dashboard["range"] == "1h"


def test_report_pdf_export_custom_range_is_reflected_in_filename_and_metadata(monkeypatch, tmp_path):
    app = _fresh_app(monkeypatch, tmp_path, "development")
    app.init_db()
    client = app.app.test_client()

    response = client.get("/api/analytics/report.pdf?range=custom&from=2026-01-01T00:00&to=2026-01-03T00:00")
    assert response.status_code == 200
    assert response.mimetype == "application/pdf"
    disposition = response.headers.get("Content-Disposition", "")
    assert "dns-inspector-analytics-custom-202601010000-202601030000-" in disposition


def test_report_pdf_export_rejects_an_invalid_custom_range_without_500(monkeypatch, tmp_path):
    app = _fresh_app(monkeypatch, tmp_path, "development")
    app.init_db()
    client = app.app.test_client()

    missing = client.get("/api/analytics/report.pdf?range=custom")
    assert missing.status_code == 400
    assert missing.get_json()["ok"] is False

    backwards = client.get("/api/analytics/report.pdf?range=custom&from=2026-01-03T00:00&to=2026-01-01T00:00")
    assert backwards.status_code == 400


def test_report_payload_window_matches_requested_preset_and_labels_custom_range(monkeypatch, tmp_path):
    app = _fresh_app(monkeypatch, tmp_path, "development")
    app.init_db()

    analytics, window = app.report_payload("7d")
    assert window["range_key"] == "7d"
    assert window["filename_part"] == "7d"
    assert len(analytics["series"]["queries"]["points"]) == 84

    analytics, window = app.report_payload("custom", "2026-01-01T00:00", "2026-01-02T00:00")
    assert window["filename_part"] == "custom-202601010000-202601020000"
    assert "Custom" in window["label"]


def test_report_payload_reports_coverage_honestly_when_history_is_short(monkeypatch, tmp_path):
    app = _fresh_app(monkeypatch, tmp_path, "development")
    app.init_db()

    # No retained processed_queries rows at all: coverage must say so rather than pretend completeness.
    analytics, window = app.report_payload("90d")
    assert window["coverage"]["complete"] is False
    assert window["coverage"]["retained_since"] is None
    assert "No retained" in window["coverage"]["note"]

    # A single very recent row cannot possibly cover a requested 90-day window.
    from contextlib import closing
    from datetime import datetime, timedelta, timezone
    import sqlite3
    with closing(sqlite3.connect(app.DB_PATH)) as c:
        c.execute("INSERT INTO processed_queries(fingerprint, seen_at, status_counted) VALUES (?, ?, 1)", ("fp1", app.utcnow()))
        c.commit()
    analytics, window = app.report_payload("90d")
    assert window["coverage"]["complete"] is False
    assert window["coverage"]["retained_since"] is not None
    assert "shorter coverage" in window["coverage"]["note"]

    # A row old enough to predate the requested 1h window means that shorter window is fully covered.
    old_seen_at = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    with closing(sqlite3.connect(app.DB_PATH)) as c:
        c.execute("INSERT INTO processed_queries(fingerprint, seen_at, status_counted) VALUES (?, ?, 1)", ("fp2", old_seen_at))
        c.commit()
    analytics, window = app.report_payload("1h")
    assert window["coverage"]["complete"] is True
    assert window["coverage"]["note"] is None


def test_report_payload_rejects_out_of_order_or_too_short_custom_windows(monkeypatch, tmp_path):
    app = _fresh_app(monkeypatch, tmp_path, "development")
    app.init_db()

    import pytest
    with pytest.raises(app.ReportRangeError):
        app.report_payload("custom", None, None)
    with pytest.raises(app.ReportRangeError):
        app.report_payload("custom", "2026-01-02T00:00", "2026-01-01T00:00")
    with pytest.raises(app.ReportRangeError):
        app.report_payload("custom", "2026-01-01T00:00:00", "2026-01-01T00:00:01")
