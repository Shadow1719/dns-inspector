"""Regression coverage for the 0.8.6 security hardening pass.

Covers: admin-token authorization for lifecycle/mutating/diagnostic-export
endpoints, /health no longer disclosing internal configuration, LAN ping
rate limiting, and the security response headers.
"""

import base64


def _basic_auth_header(password, username="admin"):
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def test_admin_endpoints_are_open_by_default(app_module):
    # No DNS_INSPECTOR_ADMIN_TOKEN configured: preserves the existing
    # trusted-LAN/reverse-proxy trust model documented in SECURITY.md.
    app_module.init_db()
    client = app_module.app.test_client()

    assert client.get("/api/devlog").status_code == 200
    assert client.get("/api/devlog/export").status_code == 200
    assert client.get("/api/debug/snapshot").status_code == 200
    assert client.get("/api/device/label").status_code == 200
    # No "confirm" in the body: rejected by the endpoint's own validation,
    # not the (absent) auth gate.
    assert client.post("/api/system/restart", json={}).status_code == 400
    assert client.post("/api/system/stop", json={}).status_code == 400


def test_admin_endpoints_require_token_when_configured(admin_app_module):
    admin_app_module.init_db()
    client = admin_app_module.app.test_client()

    checks = (
        ("GET /api/devlog", client.get("/api/devlog")),
        ("GET /api/devlog/export", client.get("/api/devlog/export")),
        ("GET /api/debug/snapshot", client.get("/api/debug/snapshot")),
        ("GET /api/device/label", client.get("/api/device/label")),
        ("POST /api/device/label", client.post("/api/device/label", json={"device_key": "x", "label": "y"})),
        ("POST /api/system/restart", client.post("/api/system/restart", json={})),
        ("POST /api/system/stop", client.post("/api/system/stop", json={})),
    )
    for label, resp in checks:
        assert resp.status_code == 401, label
        assert resp.headers.get("WWW-Authenticate", "").startswith("Basic"), label


def test_admin_endpoints_accept_correct_token(admin_app_module):
    admin_app_module.init_db()
    client = admin_app_module.app.test_client()
    headers = _basic_auth_header("test-admin-token")

    assert client.get("/api/devlog", headers=headers).status_code == 200
    assert client.get("/api/debug/snapshot", headers=headers).status_code == 200
    assert client.get("/api/device/label", headers=headers).status_code == 200
    # Correct auth reaches the endpoint's own validation logic (missing
    # "confirm"), not the dangerous restart/stop thread.
    assert client.post("/api/system/restart", json={}, headers=headers).status_code == 400
    assert client.post("/api/system/stop", json={}, headers=headers).status_code == 400


def test_admin_endpoints_reject_wrong_token(admin_app_module):
    admin_app_module.init_db()
    client = admin_app_module.app.test_client()
    headers = _basic_auth_header("not-the-token")

    assert client.get("/api/devlog", headers=headers).status_code == 401


def test_health_does_not_disclose_internal_configuration(monkeypatch, app_module):
    monkeypatch.setattr(app_module, "AGH_URL", "http://192.168.1.50:3000")
    client = app_module.app.test_client()
    payload = client.get("/health").get_json()

    assert payload["ok"] is True
    assert "adguard" not in payload
    assert "192.168.1.50" not in str(payload)


def test_security_headers_present_on_responses(app_module):
    app_module.init_db()
    client = app_module.app.test_client()
    resp = client.get("/health")

    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    csp = resp.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    # The UI loads Leaflet from unpkg and map tiles from these hosts
    # (static/leaflet-map.js); the policy must allow exactly those, not '*'.
    assert "https://unpkg.com" in csp
    assert "https://tile.openstreetmap.org" in csp


def test_manual_ping_is_rate_limited_per_target(app_module, monkeypatch):
    app_module.init_db()
    monkeypatch.setattr(app_module, "_run_ip_ping", lambda ip: {
        "ip": ip, "online": True, "latency_ms": 1.0, "error": "", "last_checked": 1.0
    })
    client = app_module.app.test_client()

    first = client.post("/api/ip/ping", json={"ip": "192.168.1.111"})
    assert first.status_code == 200

    second = client.post("/api/ip/ping", json={"ip": "192.168.1.111"})
    assert second.status_code == 429
    assert second.get_json()["ok"] is False

    # A different target is unaffected by the first target's cooldown.
    other = client.post("/api/ip/ping", json={"ip": "192.168.1.112"})
    assert other.status_code == 200


def test_manual_ping_enforces_a_global_per_minute_cap(app_module, monkeypatch):
    app_module.init_db()
    monkeypatch.setattr(app_module, "MANUAL_PING_MAX_PER_MINUTE", 2)
    monkeypatch.setattr(app_module, "_run_ip_ping", lambda ip: {
        "ip": ip, "online": True, "latency_ms": 1.0, "error": "", "last_checked": 1.0
    })
    client = app_module.app.test_client()

    assert client.post("/api/ip/ping", json={"ip": "192.168.1.1"}).status_code == 200
    assert client.post("/api/ip/ping", json={"ip": "192.168.1.2"}).status_code == 200
    third = client.post("/api/ip/ping", json={"ip": "192.168.1.3"})
    assert third.status_code == 429
