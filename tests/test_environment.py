"""DEV environment identity: Issue #9.

`DNS_INSPECTOR_ENV` is read once at import time, the same way every other
setting in `app.py` is (see `tests/test_configuration.py`), so exercising a
non-default value means reloading the module with the variable set and
reloading it back afterwards. The suite never depends on the CI runner's
ambient environment: every test here pins the value it needs explicitly.
"""

import importlib


def _reload_with_env(monkeypatch, value):
    import app

    if value is None:
        monkeypatch.delenv("DNS_INSPECTOR_ENV", raising=False)
    else:
        monkeypatch.setenv("DNS_INSPECTOR_ENV", value)
    return importlib.reload(app)


def test_normalize_runtime_environment_recognizes_development(app_module):
    assert app_module.normalize_runtime_environment("development") == "development"
    assert app_module.normalize_runtime_environment("Development") == "development"
    assert app_module.normalize_runtime_environment("  DEVELOPMENT  ") == "development"


def test_normalize_runtime_environment_defaults_unknown_to_production(app_module):
    for value in (None, "", "staging", "dev", "PRODUCTION", "prod"):
        assert app_module.normalize_runtime_environment(value) == "production"


def test_runtime_env_defaults_to_production_when_unset(app_module):
    """The test suite sets no `DNS_INSPECTOR_ENV`, so this pins the real default."""
    assert app_module.RUNTIME_ENV == "production"
    assert app_module.is_development_environment() is False


def test_development_environment_end_to_end(monkeypatch, initialised_db):
    import app

    reloaded = _reload_with_env(monkeypatch, "development")
    try:
        assert reloaded.RUNTIME_ENV == "development"
        assert reloaded.is_development_environment() is True

        reloaded.app.config.update(TESTING=True)
        with reloaded.app.test_client() as test_client:
            health = test_client.get("/health").get_json()
            assert health["environment"] == "development"

            observability = test_client.get("/api/observability").get_json()
            assert observability["environment"] == "development"

            body = test_client.get("/").data.decode("utf-8")
            assert "DEVELOPMENT ENVIRONMENT" in body
            assert "NOT PRODUCTION" in body
            assert '<span class="dev-badge">DEV</span>' in body
            assert "/static/favicon-dev.svg" in body
            assert "/static/favicon.svg\"" not in body
            assert f"<title>DNS Inspector DEV v{reloaded.APP_VERSION}</title>" in body
    finally:
        monkeypatch.delenv("DNS_INSPECTOR_ENV", raising=False)
        importlib.reload(app)


def test_production_environment_end_to_end(monkeypatch, initialised_db):
    import app

    reloaded = _reload_with_env(monkeypatch, "production")
    try:
        assert reloaded.RUNTIME_ENV == "production"
        assert reloaded.is_development_environment() is False

        reloaded.app.config.update(TESTING=True)
        with reloaded.app.test_client() as test_client:
            health = test_client.get("/health").get_json()
            assert health["environment"] == "production"

            observability = test_client.get("/api/observability").get_json()
            assert observability["environment"] == "production"

            body = test_client.get("/").data.decode("utf-8")
            assert "DEVELOPMENT ENVIRONMENT" not in body
            assert '<span class="dev-badge">DEV</span>' not in body
            assert "/static/favicon-dev.svg" not in body
            assert "/static/favicon.svg\"" in body
            assert "<title>DNS Inspector</title>" in body
    finally:
        monkeypatch.delenv("DNS_INSPECTOR_ENV", raising=False)
        importlib.reload(app)


def test_health_preserves_existing_fields_alongside_environment(client):
    payload = client.get("/health").get_json()
    assert set(payload) >= {
        "ok", "version", "adguard", "trackerdb",
        "poll_seconds", "ui_refresh_seconds", "environment",
    }
    assert payload["environment"] == "production"
