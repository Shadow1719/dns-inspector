"""Automatic DB-IP Lite GeoIP updates -- `app.py` wiring (Issue #42 / 0.8.5.5).

`scripts/geoip_updater.py` (see `tests/test_geoip_updater.py`) owns the
download/validate/convert/atomic-replace pipeline itself; these tests only
cover the `app.py` side of the integration: the config/worker/diagnostics
wiring and the hot-reload that lets a completed update take effect without a
restart. Nothing here makes a real network call -- the worker is either
exercised directly with auto-update disabled (an immediate, safe return) or
its network-touching pieces are left to `test_geoip_updater.py`'s hermetic
fake-session tests.
"""

import importlib


def test_geoip_auto_update_defaults_to_enabled(monkeypatch):
    import app

    monkeypatch.delenv("GEOIP_AUTO_UPDATE", raising=False)
    reloaded = importlib.reload(app)
    try:
        assert reloaded.GEOIP_AUTO_UPDATE is True
    finally:
        importlib.reload(app)


def test_geoip_auto_update_respects_an_explicit_disable(monkeypatch):
    import app

    monkeypatch.setenv("GEOIP_AUTO_UPDATE", "false")
    reloaded = importlib.reload(app)
    try:
        assert reloaded.GEOIP_AUTO_UPDATE is False
    finally:
        monkeypatch.delenv("GEOIP_AUTO_UPDATE", raising=False)
        importlib.reload(app)


def test_update_config_tracks_the_geoip_db_path_env_vars(monkeypatch):
    import app

    monkeypatch.setenv("GEOIP_DB_PATH", "/custom/country.csv")
    monkeypatch.setenv("GEOIP_CITY_DB_PATH", "/custom/city.csv")
    reloaded = importlib.reload(app)
    try:
        assert reloaded._GEOIP_UPDATE_CONFIG.country_db_path == "/custom/country.csv"
        assert reloaded._GEOIP_UPDATE_CONFIG.city_db_path == "/custom/city.csv"
    finally:
        monkeypatch.delenv("GEOIP_DB_PATH", raising=False)
        monkeypatch.delenv("GEOIP_CITY_DB_PATH", raising=False)
        importlib.reload(app)


def test_geoip_auto_update_worker_returns_immediately_when_disabled(app_module, monkeypatch, capsys):
    """The worker must never enter its check loop when disabled -- calling it
    directly (not in a thread) proves it returns instead of blocking."""
    monkeypatch.setattr(app_module, "GEOIP_AUTO_UPDATE", False)
    app_module.geoip_auto_update_worker()
    assert "disabled" in capsys.readouterr().out.lower()


def test_geoip_update_diagnostics_has_the_expected_shape(app_module):
    diag = app_module._geoip_update_diagnostics()
    assert set(diag) >= {"auto_update_enabled", "interval_days", "in_progress", "country", "city"}
    for target in ("country", "city"):
        entry = diag[target]
        assert set(entry) >= {
            "current_release", "last_checked_at", "last_success_at",
            "last_error", "last_error_at", "next_check_at",
        }


def test_observability_endpoint_includes_geoip_update_field(client):
    resp = client.get("/api/observability")
    assert resp.status_code == 200
    payload = resp.get_json()
    assert "geoip_update" in payload
    assert "country" in payload["geoip_update"] and "city" in payload["geoip_update"]


def test_reload_geoip_providers_swaps_the_provider_and_clears_the_cache(app_module, monkeypatch, tmp_path):
    original_provider = app_module._geoip_provider
    original_city_provider = app_module._geoip_city_provider
    csv_path = tmp_path / "geoip.csv"
    csv_path.write_text("203.0.113.0,203.0.113.255,US,United States\n")
    monkeypatch.setattr(app_module, "GEOIP_DB_PATH", str(csv_path))
    monkeypatch.setattr(app_module, "GEOIP_CITY_DB_PATH", str(tmp_path / "missing-city.csv"))
    app_module._geoip_cache["203.0.113.10"] = ("XX", "Stale Country")
    app_module._geoip_cache_order.append("203.0.113.10")

    try:
        app_module._reload_geoip_providers()
        assert app_module._geoip_provider.available is True
        assert app_module._geoip_provider.lookup("203.0.113.10") == ("US", "United States")
        assert "203.0.113.10" not in app_module._geoip_cache
    finally:
        app_module._geoip_provider = original_provider
        app_module._geoip_city_provider = original_city_provider
        app_module._geoip_cache.clear()
        app_module._geoip_cache_order.clear()
        app_module._geoip_city_cache.clear()
        app_module._geoip_city_cache_order.clear()
