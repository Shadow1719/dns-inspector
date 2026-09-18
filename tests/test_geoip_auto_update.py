"""Automatic DB-IP Lite GeoIP updates -- `app.py` wiring (Issue #42 / 0.8.5.5,
rescheduled/isolated in Issue #44 / 0.8.5.7).

`scripts/geoip_updater.py` (see `tests/test_geoip_updater.py`) owns the
download/validate/convert/atomic-replace pipeline and the pure scheduling
math itself; these tests only cover the `app.py` side of the integration:
the config/worker/diagnostics wiring, the daily-schedule-not-startup
behaviour, the subprocess isolation + watchdog termination, and the
hot-reload that lets a completed update take effect without a restart.

Nothing here makes a real network call. Tests that need to exercise the
subprocess boundary use `sys.executable -c "..."` one-liner children instead
of the real `scripts/geoip_updater.py` CLI, so they stay hermetic and fast
while still proving the parent's process-management (timeout, termination,
output capture) against a genuine child process, not a mock.
"""

import gc
import importlib
import os
import sys
import time
import weakref

import pytest

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


def test_geoip_auto_update_schedule_env_vars_are_read_and_clamped(monkeypatch):
    import app

    monkeypatch.setenv("GEOIP_AUTO_UPDATE_HOUR", "4")
    monkeypatch.setenv("GEOIP_AUTO_UPDATE_MINUTE", "15")
    monkeypatch.setenv("GEOIP_AUTO_UPDATE_TIMEZONE", "Europe/Bucharest")
    reloaded = importlib.reload(app)
    try:
        assert reloaded.GEOIP_AUTO_UPDATE_HOUR == 4
        assert reloaded.GEOIP_AUTO_UPDATE_MINUTE == 15
        assert reloaded.GEOIP_AUTO_UPDATE_TIMEZONE_NAME == "Europe/Bucharest"
    finally:
        monkeypatch.delenv("GEOIP_AUTO_UPDATE_HOUR", raising=False)
        monkeypatch.delenv("GEOIP_AUTO_UPDATE_MINUTE", raising=False)
        monkeypatch.delenv("GEOIP_AUTO_UPDATE_TIMEZONE", raising=False)
        importlib.reload(app)


def test_geoip_auto_update_defaults_the_schedule_to_3am_utc(monkeypatch):
    import app

    monkeypatch.delenv("GEOIP_AUTO_UPDATE_HOUR", raising=False)
    monkeypatch.delenv("GEOIP_AUTO_UPDATE_MINUTE", raising=False)
    monkeypatch.delenv("GEOIP_AUTO_UPDATE_TIMEZONE", raising=False)
    reloaded = importlib.reload(app)
    try:
        assert reloaded.GEOIP_AUTO_UPDATE_HOUR == 3
        assert reloaded.GEOIP_AUTO_UPDATE_MINUTE == 0
        assert reloaded.GEOIP_AUTO_UPDATE_TIMEZONE_NAME == "UTC"
    finally:
        importlib.reload(app)


def test_geoip_auto_update_worker_returns_immediately_when_disabled(app_module, monkeypatch, capsys):
    """The worker must never enter its scheduling loop when disabled --
    calling it directly (not in a thread) proves it returns instead of
    blocking."""
    monkeypatch.setattr(app_module, "GEOIP_AUTO_UPDATE", False)
    app_module.geoip_auto_update_worker()
    assert "disabled" in capsys.readouterr().out.lower()


def test_geoip_auto_update_worker_sleeps_before_ever_running_a_pass(app_module, monkeypatch):
    """Issue #44 regression: on a fresh deployment with no state file, the
    worker used to call `_run_geoip_update_pass()` immediately at thread
    startup (before its first `time.sleep`), which meant the very first
    DB-IP Lite Country/City Lite download could start competing with the
    application becoming healthy. The worker must now always sleep until
    the next scheduled window *first* -- proven here by making the sleep
    hook raise the moment it's called, before `_run_geoip_update_pass` gets
    a chance to run at all."""
    monkeypatch.setattr(app_module, "GEOIP_AUTO_UPDATE", True)
    sleep_calls = []
    pass_calls = []

    class _StopLoop(Exception):
        pass

    def fake_sleep(seconds):
        sleep_calls.append(seconds)
        raise _StopLoop()

    monkeypatch.setattr(app_module, "_geoip_sleep", fake_sleep)
    monkeypatch.setattr(app_module, "_run_geoip_update_pass", lambda: pass_calls.append(True))

    try:
        app_module.geoip_auto_update_worker()
        assert False, "expected _StopLoop to propagate"
    except _StopLoop:
        pass

    assert len(sleep_calls) == 1
    assert sleep_calls[0] > 0  # a real, positive wait -- never "sleep(0)" as a no-op
    assert pass_calls == []  # no check/update pass ever ran before the sleep


def test_geoip_auto_update_worker_records_the_next_scheduled_run(app_module, monkeypatch):
    monkeypatch.setattr(app_module, "GEOIP_AUTO_UPDATE", True)
    monkeypatch.setattr(app_module, "_geoip_next_scheduled_run_at", None)

    class _StopLoop(Exception):
        pass

    def fake_sleep(seconds):
        raise _StopLoop()

    monkeypatch.setattr(app_module, "_geoip_sleep", fake_sleep)
    monkeypatch.setattr(app_module, "_run_geoip_update_pass", lambda: None)

    try:
        app_module.geoip_auto_update_worker()
    except _StopLoop:
        pass

    assert app_module._geoip_next_scheduled_run_at is not None


def test_geoip_update_diagnostics_has_the_expected_shape(app_module):
    diag = app_module._geoip_update_diagnostics()
    assert set(diag) >= {
        "auto_update_enabled", "interval_days", "schedule", "status",
        "in_progress", "next_scheduled_run_at", "country", "city",
    }
    assert set(diag["schedule"]) == {"hour", "minute", "timezone"}
    for target in ("country", "city"):
        entry = diag[target]
        assert set(entry) >= {
            "current_release", "last_checked_at", "last_checked_ok_at", "last_success_at",
            "last_error", "last_error_at", "next_check_at",
        }


def test_geoip_update_diagnostics_status_reflects_enabled_and_in_progress(app_module, monkeypatch):
    monkeypatch.setattr(app_module, "GEOIP_AUTO_UPDATE", False)
    assert app_module._geoip_update_diagnostics()["status"] == "disabled"

    monkeypatch.setattr(app_module, "GEOIP_AUTO_UPDATE", True)
    monkeypatch.setattr(app_module, "_geoip_update_in_progress", False)
    assert app_module._geoip_update_diagnostics()["status"] == "scheduled"

    monkeypatch.setattr(app_module, "_geoip_update_in_progress", True)
    try:
        assert app_module._geoip_update_diagnostics()["status"] == "in_progress"
    finally:
        monkeypatch.setattr(app_module, "_geoip_update_in_progress", False)


def test_observability_endpoint_includes_geoip_update_field(client):
    resp = client.get("/api/observability")
    assert resp.status_code == 200
    payload = resp.get_json()
    assert "geoip_update" in payload
    assert "country" in payload["geoip_update"] and "city" in payload["geoip_update"]
    assert "status" in payload["geoip_update"]
    assert "schedule" in payload["geoip_update"]


def test_geoip_updater_cli_command_points_at_the_real_cli_entry_point(app_module):
    command = app_module._geoip_updater_cli_command()
    assert command[0] == sys.executable
    assert command[1] == os.path.join(app_module.BASE_DIR, "scripts", "geoip_updater.py")
    assert os.path.isfile(command[1])


def test_run_geoip_update_pass_completes_normally_and_reloads_on_update(app_module, monkeypatch, tmp_path):
    """Baseline/happy-path guard for the subprocess-isolated pass (Issue #44):
    a normal, fast child pass must still clear `in_progress` and still
    hot-reload the providers when it actually installed a new release --
    the watchdog must never fire on a pass that completes well within its
    deadline. The child here is a small `python -c` one-liner that mutates
    the real state file the same way a real `updated` outcome would,
    instead of a real network-backed `scripts/geoip_updater.py` run."""
    state_path = tmp_path / "state.json"
    config = gu.UpdaterConfig(state_path=str(state_path))
    monkeypatch.setattr(app_module, "_GEOIP_UPDATE_CONFIG", config)
    reload_calls = []
    monkeypatch.setattr(app_module, "_reload_geoip_providers", lambda: reload_calls.append(True))

    script = (
        "from scripts import geoip_updater as gu\n"
        f"state = gu.load_state({str(state_path)!r})\n"
        "state['country']['current_release'] = '2026-09'\n"
        f"gu.save_state({str(state_path)!r}, state)\n"
        "print('country: updated (release 2026-09)')\n"
    )
    command = [sys.executable, "-c", script]

    app_module._run_geoip_update_pass(command=command, timeout=10)

    assert app_module._geoip_update_in_progress is False
    assert reload_calls == [True]
    saved = gu.load_state(str(state_path))
    assert saved["country"]["current_release"] == "2026-09"


def test_run_geoip_update_pass_does_not_reload_when_nothing_changed(app_module, monkeypatch, tmp_path):
    state_path = tmp_path / "state.json"
    config = gu.UpdaterConfig(state_path=str(state_path))
    monkeypatch.setattr(app_module, "_GEOIP_UPDATE_CONFIG", config)
    reload_calls = []
    monkeypatch.setattr(app_module, "_reload_geoip_providers", lambda: reload_calls.append(True))

    command = [sys.executable, "-c", "print('country: skipped_not_due')"]

    app_module._run_geoip_update_pass(command=command, timeout=10)

    assert app_module._geoip_update_in_progress is False
    assert reload_calls == []


def test_run_geoip_update_pass_terminates_a_hung_child_and_stays_healthy(app_module, monkeypatch, tmp_path):
    """Issue #44's core ask: the previous same-process daemon-thread
    watchdog (0.8.5.6) could time out waiting on a stuck pass but had no way
    to actually stop it. With the pass isolated in a subprocess, a child
    that hangs past the watchdog deadline must be genuinely terminated --
    proven here with a real child process that sleeps far longer than the
    watchdog timeout, checking that it is actually dead (not just
    abandoned) once `_run_geoip_update_pass` returns, and that the parent
    itself returns promptly rather than blocking for the child's full
    sleep."""
    state_path = tmp_path / "state.json"
    config = gu.UpdaterConfig(state_path=str(state_path))
    monkeypatch.setattr(app_module, "_GEOIP_UPDATE_CONFIG", config)
    reload_calls = []
    monkeypatch.setattr(app_module, "_reload_geoip_providers", lambda: reload_calls.append(True))

    marker = tmp_path / "child.pid"
    script = (
        "import os, time\n"
        f"with open({str(marker)!r}, 'w') as f:\n"
        "    f.write(str(os.getpid()))\n"
        "time.sleep(60)\n"
    )
    command = [sys.executable, "-c", script]

    started = time.monotonic()
    app_module._run_geoip_update_pass(command=command, timeout=3.0)
    elapsed = time.monotonic() - started

    assert app_module._geoip_update_in_progress is False
    assert reload_calls == []
    assert elapsed < 30, "parent must not block for anywhere near the child's 60s sleep"

    # The child must have started (and recorded its pid) before being killed.
    for _ in range(50):
        if marker.exists():
            break
        time.sleep(0.1)
    assert marker.exists(), "child never started -- test setup is broken, not the watchdog"
    pid = int(marker.read_text())

    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_run_geoip_update_pass_survives_a_failing_child(app_module, monkeypatch, tmp_path):
    """A child that exits non-zero (e.g. an unhandled exception in the real
    CLI) must not crash the parent or trigger a spurious reload -- it's
    logged and the flag is cleared so the next scheduled window can retry."""
    state_path = tmp_path / "state.json"
    config = gu.UpdaterConfig(state_path=str(state_path))
    monkeypatch.setattr(app_module, "_GEOIP_UPDATE_CONFIG", config)
    reload_calls = []
    monkeypatch.setattr(app_module, "_reload_geoip_providers", lambda: reload_calls.append(True))

    command = [sys.executable, "-c", "import sys; print('boom'); sys.exit(1)"]

    app_module._run_geoip_update_pass(command=command, timeout=10)

    assert app_module._geoip_update_in_progress is False
    assert reload_calls == []


def test_run_geoip_update_pass_handles_a_launch_failure_gracefully(app_module, monkeypatch, tmp_path):
    """If the subprocess can't even be started (e.g. a bad interpreter
    path), `_geoip_update_in_progress` must still be cleared rather than
    left stuck at `true` forever."""
    state_path = tmp_path / "state.json"
    config = gu.UpdaterConfig(state_path=str(state_path))
    monkeypatch.setattr(app_module, "_GEOIP_UPDATE_CONFIG", config)

    command = ["/definitely/not/a/real/executable-geoip-test", "--status"]

    app_module._run_geoip_update_pass(command=command, timeout=5)

    assert app_module._geoip_update_in_progress is False


def test_run_geoip_update_pass_watchdog_marks_an_unsettled_check_as_timed_out(app_module, monkeypatch, tmp_path):
    """Issue #43/#44: if a target's own `last_checked_at` was already
    stamped (by the real updater, inside the child, right before its slow
    network/convert step) but the child gets killed before it could record
    an outcome, the parent's watchdog must still leave a visible error for
    it -- never an unexplained `null` forever."""
    state_path = tmp_path / "state.json"
    state = gu.default_state()
    state["country"]["last_checked_at"] = gu._now_iso()
    gu.save_state(str(state_path), state)
    config = gu.UpdaterConfig(state_path=str(state_path))
    monkeypatch.setattr(app_module, "_GEOIP_UPDATE_CONFIG", config)

    command = [sys.executable, "-c", "import time; time.sleep(60)"]

    app_module._run_geoip_update_pass(command=command, timeout=0.5)

    assert app_module._geoip_update_in_progress is False
    saved = gu.load_state(str(state_path))
    assert saved["country"]["last_error"]
    assert "watchdog" in saved["country"]["last_error"].lower()


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


def test_reload_geoip_providers_releases_the_previous_country_provider(app_module, monkeypatch, tmp_path):
    """Issue #52 acceptance criterion: a hot reload must not leave the
    previous provider/database resident. Once `_reload_geoip_providers()`
    swaps the global reference and this test drops its own, nothing in
    `app.py` may still hold the stale provider alive -- CPython's refcounting
    (no reference cycle is involved here) must free it immediately, which a
    dead `weakref` proves directly rather than inferring it from RSS."""
    csv_path = tmp_path / "geoip.csv"
    csv_path.write_text("203.0.113.0,203.0.113.255,US,United States\n")
    monkeypatch.setattr(app_module, "GEOIP_DB_PATH", str(csv_path))
    monkeypatch.setattr(app_module, "GEOIP_CITY_DB_PATH", str(tmp_path / "missing-city.csv"))

    stale_provider = app_module.CsvRangeGeoIPProvider(str(csv_path))
    stale_ref = weakref.ref(stale_provider)
    app_module._geoip_provider = stale_provider
    del stale_provider
    try:
        app_module._reload_geoip_providers()
        gc.collect()
        assert stale_ref() is None, "previous country GeoIP provider is still resident after a reload"
    finally:
        app_module._geoip_provider = app_module.NullGeoIPProvider()
        app_module._geoip_city_provider = app_module.NullCityGeoIPProvider()
        app_module._geoip_cache.clear()
        app_module._geoip_cache_order.clear()
        app_module._geoip_city_cache.clear()
        app_module._geoip_city_cache_order.clear()


def test_reload_geoip_providers_releases_the_previous_city_provider(app_module, monkeypatch, tmp_path):
    """Same acceptance criterion as the country-provider test above, for the
    optional city/coordinate provider."""
    city_csv_path = tmp_path / "geoip_city.csv"
    city_csv_path.write_text(
        "203.0.113.0,203.0.113.255,US,United States,Mountain View,37.386,-122.0838\n"
    )
    monkeypatch.setattr(app_module, "GEOIP_DB_PATH", str(tmp_path / "missing-country.csv"))
    monkeypatch.setattr(app_module, "GEOIP_CITY_DB_PATH", str(city_csv_path))

    stale_city_provider = app_module.CsvCityGeoIPProvider(str(city_csv_path))
    stale_ref = weakref.ref(stale_city_provider)
    app_module._geoip_city_provider = stale_city_provider
    del stale_city_provider
    try:
        app_module._reload_geoip_providers()
        gc.collect()
        assert stale_ref() is None, "previous city GeoIP provider is still resident after a reload"
    finally:
        app_module._geoip_provider = app_module.NullGeoIPProvider()
        app_module._geoip_city_provider = app_module.NullCityGeoIPProvider()
        app_module._geoip_cache.clear()
        app_module._geoip_cache_order.clear()
        app_module._geoip_city_cache.clear()
        app_module._geoip_city_cache_order.clear()


def test_geoip_allocator_cleanup_is_a_safe_no_op(app_module):
    """`_geoip_allocator_cleanup()` (Issue #52 requirement 5, secondary
    mitigation only) must never raise, whether or not `malloc_trim` is
    actually available on the host libc -- it is a best-effort RSS-settling
    step layered on top of the compact-storage fix, not the fix itself."""
    app_module._geoip_allocator_cleanup()
