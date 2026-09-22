"""Regression coverage for the 0.8.6 security hardening pass.

Covers browser-compatible admin authentication, session/CSRF behavior,
production information disclosure, LAN ping rate limiting, and security
response headers.
"""


def test_admin_auth_is_disabled_and_endpoints_stay_open_by_default(app_module):
    app_module.init_db()
    client = app_module.app.test_client()

    status = client.get("/api/admin/status")
    assert status.status_code == 200
    assert status.get_json() == {"ok": True, "enabled": False, "authenticated": False}
    assert client.post("/api/admin/login", json={"token": "anything"}).status_code == 404

    assert client.get("/api/devlog").status_code == 200
    assert client.get("/api/devlog/export").status_code == 200
    assert client.get("/api/debug/snapshot").status_code == 200
    assert client.get("/api/device/label").status_code == 200
    assert client.post("/api/system/restart", json={}).status_code == 400
    assert client.post("/api/system/stop", json={}).status_code == 400


def test_admin_endpoints_require_session_when_token_configured(admin_app_module):
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
        assert resp.get_json()["error"] == "Admin authentication required"


def test_admin_login_issues_secure_http_only_session(admin_app_module):
    admin_app_module.init_db()
    client = admin_app_module.app.test_client()

    wrong = client.post("/api/admin/login", json={"token": "not-the-token"})
    assert wrong.status_code == 401
    assert "Set-Cookie" not in wrong.headers

    login = client.post("/api/admin/login", json={"token": "test-admin-token"})
    assert login.status_code == 200
    payload = login.get_json()
    assert payload["ok"] is True
    assert payload["authenticated"] is True
    assert payload["expires_in"] == admin_app_module.ADMIN_SESSION_TTL_SECONDS
    assert "test-admin-token" not in login.get_data(as_text=True)

    cookie = login.headers["Set-Cookie"]
    assert "dns_inspector_admin=" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie
    assert "Path=/" in cookie
    assert "Max-Age=" in cookie
    assert "test-admin-token" not in cookie

    status = client.get("/api/admin/status")
    assert status.get_json()["authenticated"] is True
    devlog = client.get("/api/devlog")
    assert devlog.status_code == 200
    assert "no-store" in devlog.headers.get("Cache-Control", "")


def test_state_changing_admin_endpoints_require_csrf_header(admin_app_module):
    admin_app_module.init_db()
    client = admin_app_module.app.test_client()
    login = client.post("/api/admin/login", json={"token": "test-admin-token"})
    assert login.status_code == 200

    no_csrf = client.post("/api/device/label", json={"device_key": "x", "label": "y"})
    assert no_csrf.status_code == 403
    assert no_csrf.get_json()["error"] == "CSRF validation failed"

    headers = {"X-DNS-Inspector-Requested-With": "fetch"}
    invalid_payload = client.post("/api/device/label", json={}, headers=headers)
    assert invalid_payload.status_code == 400

    # Restart/stop are reached only after both the session and CSRF checks.
    assert client.post("/api/system/restart", json={}, headers=headers).status_code == 400
    assert client.post("/api/system/stop", json={}, headers=headers).status_code == 400


def test_admin_logout_invalidates_session(admin_app_module):
    admin_app_module.init_db()
    client = admin_app_module.app.test_client()
    assert client.post("/api/admin/login", json={"token": "test-admin-token"}).status_code == 200

    logout = client.post("/api/admin/logout", headers={"X-DNS-Inspector-Requested-With": "fetch"})
    assert logout.status_code == 200
    assert logout.get_json()["authenticated"] is False
    assert client.get("/api/devlog").status_code == 401
    assert client.get("/api/admin/status").get_json()["authenticated"] is False


def test_expired_admin_session_is_rejected(admin_app_module, monkeypatch):
    admin_app_module.init_db()
    client = admin_app_module.app.test_client()
    assert client.post("/api/admin/login", json={"token": "test-admin-token"}).status_code == 200

    now = admin_app_module.time.time()
    monkeypatch.setattr(
        admin_app_module.time,
        "time",
        lambda: now + admin_app_module.ADMIN_SESSION_TTL_SECONDS + 1,
    )
    assert client.get("/api/devlog").status_code == 401


def test_admin_login_is_rate_limited(admin_app_module, monkeypatch):
    monkeypatch.setattr(admin_app_module, "ADMIN_LOGIN_MAX_ATTEMPTS", 2)
    admin_app_module.init_db()
    client = admin_app_module.app.test_client()

    assert client.post("/api/admin/login", json={"token": "bad-1"}).status_code == 401
    assert client.post("/api/admin/login", json={"token": "bad-2"}).status_code == 401
    third = client.post("/api/admin/login", json={"token": "bad-3"})
    assert third.status_code == 429
    assert third.headers.get("Retry-After")


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
