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
import threading

from scripts import geoip_updater as gu


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


def test_run_geoip_update_pass_completes_normally_and_reloads_on_update(app_module, monkeypatch, tmp_path):
    """Baseline/happy-path guard for the `_run_geoip_update_pass()` refactor
    (Issue #43): a normal, fast pass must still clear `in_progress` and still
    hot-reload the providers on a real update -- the watchdog must never
    fire on a pass that completes well within its deadline."""
    config = gu.UpdaterConfig(state_path=str(tmp_path / "state.json"))
    monkeypatch.setattr(app_module, "_GEOIP_UPDATE_CONFIG", config)
    monkeypatch.setattr(app_module, "GEOIP_AUTO_UPDATE_WATCHDOG_SECONDS", 5)
    reload_calls = []
    monkeypatch.setattr(app_module, "_reload_geoip_providers", lambda: reload_calls.append(True))
    monkeypatch.setattr(
        gu, "run_update",
        lambda *a, **k: [{"target": "country", "action": "updated", "release": "2026-09", "rows": 123}],
    )

    app_module._run_geoip_update_pass()

    assert app_module._geoip_update_in_progress is False
    assert reload_calls == [True]


def test_run_geoip_update_pass_watchdog_clears_in_progress_on_a_hung_pass(app_module, monkeypatch, tmp_path):
    """Issue #43 regression: real runtime evidence showed
    `geoip_update.in_progress=true` with both targets' `last_checked_at=null`
    for several minutes with no success/error -- i.e. the whole check/update
    pass hung somewhere past what `geoip_updater`'s own per-request
    connect/read timeouts cover. `_run_geoip_update_pass()`'s watchdog must
    give up once `GEOIP_AUTO_UPDATE_WATCHDOG_SECONDS` elapses, clear
    `_geoip_update_in_progress` so the next poll can retry, and leave a real,
    visible error rather than an unexplained `null`."""
    state_path = tmp_path / "state.json"
    state = gu.default_state()
    state["country"]["last_checked_at"] = gu._now_iso()
    gu.save_state(str(state_path), state)
    config = gu.UpdaterConfig(state_path=str(state_path))
    monkeypatch.setattr(app_module, "_GEOIP_UPDATE_CONFIG", config)
    monkeypatch.setattr(app_module, "GEOIP_AUTO_UPDATE_WATCHDOG_SECONDS", 0.05)

    release_event = threading.Event()

    def hanging_run_update(*args, **kwargs):
        release_event.wait(5)  # far longer than the 0.05s watchdog above
        return []

    monkeypatch.setattr(gu, "run_update", hanging_run_update)

    try:
        app_module._run_geoip_update_pass()

        assert app_module._geoip_update_in_progress is False
        saved = gu.load_state(str(state_path))
        assert saved["country"]["last_error"]
        assert "watchdog" in saved["country"]["last_error"].lower()
    finally:
        release_event.set()
        app_module._geoip_update_in_progress = False


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
