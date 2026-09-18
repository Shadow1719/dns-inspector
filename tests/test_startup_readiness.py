"""Issue #51: HTTP reachability must be provable, not just "process is up".

Real TrueNAS evidence showed the container reporting RUNNING (socket bound,
Flask's own startup banner printed) while `/health` itself stayed
unanswered for several more seconds once the deferred initial GeoIP load
started on a fixed 1s clock delay. These tests cover the two independent
guarantees that replace that fixed delay:

1. The deferred initial GeoIP load (`_geoip_initial_load_worker()`) must not
   start merely because some fixed amount of wall-clock time passed -- it
   must wait for actual proof the HTTP service served a response
   (`_first_response_ready`, set by the `_mark_first_response_ready()`
   `after_request` hook), with `GEOIP_INITIAL_LOAD_DELAY_SECONDS` remaining
   only as a bounded fallback ceiling for a deployment that never receives a
   single request at all.
2. The Flask server itself (`serve()`) must run with `threaded=True`, so a
   request already in flight (a slow view, or the GeoIP load's own
   background thread being busy) can never fully block a concurrent
   request to `/health` behind it.
"""

import threading
import time
import urllib.request

import pytest


def _write_country_csv(path):
    path.write_text("start_ip,end_ip,country_code,country_name\n")


@pytest.fixture()
def fresh_first_response_ready(app_module, monkeypatch):
    """An isolated readiness `Event`, so these assertions are never affected
    by another (session-scoped) test having already permanently set the
    real shared `_first_response_ready` by serving some earlier request."""
    event = threading.Event()
    monkeypatch.setattr(app_module, "_first_response_ready", event)
    monkeypatch.setattr(app_module, "_first_response_monotonic", None)
    return event


def test_serve_runs_the_flask_server_with_threaded_serving_enabled(app_module, monkeypatch):
    captured = {}

    def fake_run(*args, **kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(app_module.app, "run", fake_run)
    app_module.serve()

    assert captured.get("threaded") is True


def test_after_request_hook_marks_first_response_ready_on_a_real_request(
    app_module, fresh_first_response_ready, client
):
    assert not fresh_first_response_ready.is_set()

    resp = client.get("/health")

    assert resp.status_code == 200
    assert fresh_first_response_ready.is_set()


def test_mark_first_response_ready_records_timestamp_once(app_module, fresh_first_response_ready):
    app_module._mark_first_response_ready(object())
    first_timestamp = app_module._first_response_monotonic
    assert first_timestamp is not None

    app_module._mark_first_response_ready(object())

    assert app_module._first_response_monotonic == first_timestamp


def test_geoip_initial_load_worker_waits_for_first_response_before_loading(
    app_module, monkeypatch, tmp_path, fresh_first_response_ready
):
    """The core Issue #51 regression: the one-shot GeoIP load must not begin
    just because it has been running for a while -- only once the HTTP
    service has actually served something."""
    geoip_csv = tmp_path / "geoip_country_ranges.csv"
    _write_country_csv(geoip_csv)
    monkeypatch.setattr(app_module, "GEOIP_DB_PATH", str(geoip_csv))
    monkeypatch.setattr(app_module, "GEOIP_CITY_DB_PATH", str(tmp_path / "missing_city.csv"))
    monkeypatch.setattr(app_module, "GEOIP_INITIAL_LOAD_DELAY_SECONDS", 5.0)

    started = threading.Event()
    monkeypatch.setattr(app_module, "_reload_geoip_providers", started.set)

    thread = threading.Thread(target=app_module._geoip_initial_load_worker, daemon=True)
    thread.start()
    try:
        # No response has been served yet -- the load must still be waiting,
        # well short of the 5s ceiling configured above.
        assert not started.wait(timeout=0.3)

        fresh_first_response_ready.set()

        assert started.wait(timeout=2), (
            "GeoIP initial load did not start promptly after the first response was served"
        )
    finally:
        thread.join(timeout=5)


def test_geoip_initial_load_worker_falls_back_to_the_delay_ceiling_if_no_request_ever_arrives(
    app_module, monkeypatch, tmp_path, fresh_first_response_ready
):
    """If nothing ever requests anything (no health checker configured at
    all), the deferred load must still eventually run rather than waiting
    forever for a readiness signal that will never arrive."""
    geoip_csv = tmp_path / "geoip_country_ranges.csv"
    _write_country_csv(geoip_csv)
    monkeypatch.setattr(app_module, "GEOIP_DB_PATH", str(geoip_csv))
    monkeypatch.setattr(app_module, "GEOIP_CITY_DB_PATH", str(tmp_path / "missing_city.csv"))
    monkeypatch.setattr(app_module, "GEOIP_INITIAL_LOAD_DELAY_SECONDS", 0.1)

    started = threading.Event()
    monkeypatch.setattr(app_module, "_reload_geoip_providers", started.set)

    app_module._geoip_initial_load_worker()

    assert started.is_set()
    assert not fresh_first_response_ready.is_set()


def test_startup_readiness_diagnostics_distinguishes_running_from_ready(
    app_module, monkeypatch, fresh_first_response_ready
):
    monkeypatch.setattr(
        app_module,
        "_geoip_initial_load_state",
        {"started_at": None, "completed_at": None, "error": None},
    )

    before = app_module._startup_readiness_diagnostics()
    assert before["http_ready"] is False
    assert before["first_response_seconds_after_start"] is None
    assert before["geoip_initial_load_started"] is False
    assert before["geoip_initial_load_complete"] is False

    app_module._mark_first_response_ready(object())

    after = app_module._startup_readiness_diagnostics()
    assert after["http_ready"] is True
    assert after["first_response_seconds_after_start"] is not None
    assert after["first_response_seconds_after_start"] >= 0


def test_observability_payload_includes_startup_readiness_state(app_module):
    payload = app_module._observability_payload()
    assert "startup" in payload
    assert "http_ready" in payload["startup"]
    assert "geoip_initial_load_started" in payload["startup"]


def test_health_responds_via_real_server_while_geoip_initial_load_is_held_busy(
    app_module, monkeypatch, tmp_path, fresh_first_response_ready
):
    """Literal Issue #51 acceptance check: hold the deferred GeoIP load busy
    on a real running (threaded) server and prove `/health` still answers
    quickly rather than waiting for it."""
    from werkzeug.serving import make_server

    geoip_csv = tmp_path / "geoip_country_ranges.csv"
    _write_country_csv(geoip_csv)
    monkeypatch.setattr(app_module, "GEOIP_DB_PATH", str(geoip_csv))
    monkeypatch.setattr(app_module, "GEOIP_CITY_DB_PATH", str(tmp_path / "missing_city.csv"))

    release = threading.Event()
    entered = threading.Event()

    def busy_reload():
        entered.set()
        release.wait(timeout=5)

    monkeypatch.setattr(app_module, "_reload_geoip_providers", busy_reload)
    # This test is specifically about concurrent request handling while the
    # load is busy, not about the readiness gate -- start it immediately.
    fresh_first_response_ready.set()

    server = make_server("127.0.0.1", 0, app_module.app, threaded=True)
    port = server.socket.getsockname()[1]
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    load_thread = threading.Thread(target=app_module._geoip_initial_load_worker, daemon=True)
    try:
        load_thread.start()
        assert entered.wait(timeout=5), "GeoIP initial load never started"

        started_at = time.monotonic()
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=5) as resp:
            assert resp.status == 200
        elapsed = time.monotonic() - started_at

        assert elapsed < 1.0, f"/health took {elapsed:.2f}s while GeoIP initial load was held busy"
    finally:
        release.set()
        load_thread.join(timeout=5)
        server.shutdown()
        server_thread.join(timeout=5)


def test_health_is_answered_while_a_slow_concurrent_request_is_in_flight(app_module):
    """End-to-end proof of the explicit threaded serving fix itself: a
    genuinely slow request already being handled must not block a
    concurrent request to `/health` behind it."""
    from werkzeug.serving import make_server

    release = threading.Event()
    entered_slow_view = threading.Event()
    original_view = app_module.app.view_functions["api_observability"]

    def slow_view():
        entered_slow_view.set()
        release.wait(timeout=5)
        return original_view()

    app_module.app.view_functions["api_observability"] = slow_view
    server = make_server("127.0.0.1", 0, app_module.app, threaded=True)
    port = server.socket.getsockname()[1]
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    slow_request_thread = threading.Thread(
        target=lambda: urllib.request.urlopen(f"http://127.0.0.1:{port}/api/observability", timeout=5)
    )
    try:
        slow_request_thread.start()
        assert entered_slow_view.wait(timeout=5), "slow request never reached the server"

        started_at = time.monotonic()
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=5) as resp:
            assert resp.status == 200
        elapsed = time.monotonic() - started_at

        assert elapsed < 1.0, f"/health took {elapsed:.2f}s while a slow request was in flight"
    finally:
        release.set()
        slow_request_thread.join(timeout=5)
        server.shutdown()
        server_thread.join(timeout=5)
        app_module.app.view_functions["api_observability"] = original_view
