import os
from pathlib import Path


def test_reports_schedule_get_has_safe_defaults_and_no_secret(app_module):
    app_module.init_db()
    client = app_module.app.test_client()
    resp = client.get("/api/reports/schedule")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    cfg = data["config"]
    assert cfg["enabled"] is False
    assert "_smtp_password" not in cfg
    assert cfg["smtp_password_set"] is False
    assert "state" in data


def test_reports_schedule_post_persists_editable_fields_only(app_module):
    app_module.init_db()
    client = app_module.app.test_client()
    resp = client.post("/api/reports/schedule", json={
        "enabled": True,
        "interval": "daily",
        "window": "24h",
        "retention_count": 5,
        "filename_template": "custom-{range}-{timestamp}.pdf",
        "smtp_recipients": ["ops@example.com"],
        # Attempting to smuggle scheduler-owned state through the public API
        # must have no effect -- only EDITABLE_REPORT_SCHEDULE_FIELDS apply.
        "last_run_ts": 999999999,
        "history": [{"path": "/etc/passwd"}],
    })
    assert resp.status_code == 200
    cfg = resp.get_json()["config"]
    assert cfg["enabled"] is True
    assert cfg["retention_count"] == 5
    assert cfg["filename_template"] == "custom-{range}-{timestamp}.pdf"
    assert cfg["smtp_recipients"] == ["ops@example.com"]

    follow_up = client.get("/api/reports/schedule").get_json()["config"]
    assert follow_up["history"] == []  # untouched by the earlier smuggling attempt


def test_reports_schedule_post_rejects_invalid_interval(app_module):
    app_module.init_db()
    client = app_module.app.test_client()
    resp = client.post("/api/reports/schedule", json={"interval": "every-blue-moon"})
    assert resp.status_code == 400
    assert resp.get_json()["ok"] is False


def test_reports_schedule_post_rejects_invalid_recipient_addresses(app_module):
    app_module.init_db()
    client = app_module.app.test_client()
    resp = client.post("/api/reports/schedule", json={"smtp_recipients": ["not-an-email"]})
    assert resp.status_code == 400


def test_reports_schedule_post_rejects_path_traversal_save_dir(app_module):
    app_module.init_db()
    client = app_module.app.test_client()
    resp = client.post("/api/reports/schedule", json={"save_dir": "../../etc"})
    assert resp.status_code == 400
    assert "error" in resp.get_json()


def test_reports_save_now_reuses_the_live_generator_and_writes_a_real_pdf(app_module):
    app_module.init_db()
    client = app_module.app.test_client()
    assert client.post("/api/reports/schedule", json={"window": "1h", "filename_template": "test-{range}.pdf"}).status_code == 200

    resp = client.post("/api/reports/save-now")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    saved_file = data["saved_file"]
    assert saved_file
    assert Path(saved_file).exists()
    assert Path(saved_file).read_bytes().startswith(b"%PDF-")
    assert Path(saved_file).parent == Path(app_module.REPORTS_BASE_DIR)

    status = client.get("/api/reports/status").get_json()
    assert status["state"]["last_result"] == "success"
    assert status["state"]["last_saved_file"] == saved_file

    history = client.get("/api/reports/history").get_json()
    assert history["history"][0]["filename"] == os.path.basename(saved_file)


def test_reports_save_now_prunes_history_beyond_retention(app_module):
    app_module.init_db()
    client = app_module.app.test_client()
    client.post("/api/reports/schedule", json={"retention_count": 2, "filename_template": "r-{range}.pdf"})
    # Each save uses a distinct, deterministic filename (via {range}) so this
    # test never depends on wall-clock timestamp granularity/ordering.
    for window in ("1h", "6h", "24h"):
        assert client.post("/api/reports/schedule", json={"window": window}).status_code == 200
        resp = client.post("/api/reports/save-now")
        assert resp.get_json()["ok"] is True
    history = client.get("/api/reports/history").get_json()["history"]
    assert len(history) == 2
    saved_files = {f.name for f in Path(app_module.REPORTS_BASE_DIR).glob("*.pdf")}
    assert saved_files == {"r-6h.pdf", "r-24h.pdf"}  # oldest (1h) pruned from both history and disk


def test_reports_test_email_reports_failure_without_crashing_when_unconfigured(app_module):
    app_module.init_db()
    client = app_module.app.test_client()
    resp = client.post("/api/reports/test-email", json={})
    assert resp.status_code in (200, 502)
    data = resp.get_json()
    assert data["ok"] is False


def test_reports_test_email_rejects_invalid_recipient_override(app_module):
    app_module.init_db()
    client = app_module.app.test_client()
    resp = client.post("/api/reports/test-email", json={"recipients": ["not-an-email"]})
    assert resp.status_code == 400


def test_smtp_password_env_var_never_appears_in_any_reports_api_response(app_module, monkeypatch):
    monkeypatch.setenv(app_module.SMTP_PASSWORD_ENV_VAR, "super-secret-value")
    app_module.init_db()
    client = app_module.app.test_client()
    for resp in (
        client.get("/api/reports/schedule"),
        client.get("/api/reports/status"),
        client.post("/api/reports/schedule", json={"smtp_host": "smtp.example.com"}),
    ):
        assert b"super-secret-value" not in resp.data
    cfg = client.get("/api/reports/schedule").get_json()["config"]
    assert cfg["smtp_password_set"] is True


def test_map_origin_settings_roundtrip_and_validation(app_module):
    app_module.init_db()
    client = app_module.app.test_client()
    assert client.get("/api/settings/map-origin").get_json()["origin"] is None

    bad = client.post("/api/settings/map-origin", json={"lat": 999, "lon": 0})
    assert bad.status_code == 400

    ok = client.post("/api/settings/map-origin", json={"lat": 37.4, "lon": -122.1, "label": "Home"})
    assert ok.status_code == 200
    origin = ok.get_json()["origin"]
    assert origin["lat"] == 37.4
    assert origin["label"] == "Home"

    fetched = client.get("/api/settings/map-origin").get_json()["origin"]
    assert fetched["lon"] == -122.1

    cleared = client.post("/api/settings/map-origin", json={"clear": True})
    assert cleared.get_json()["origin"] is None
    assert client.get("/api/settings/map-origin").get_json()["origin"] is None


def test_report_scheduler_state_is_visible_in_observability(app_module):
    app_module.init_db()
    client = app_module.app.test_client()
    obs = client.get("/api/observability").get_json()
    assert "report_scheduler" in obs
    assert obs["report_scheduler"]["enabled"] is False
