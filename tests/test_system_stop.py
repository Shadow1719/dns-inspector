"""Stop control (Issue #78): a "Stop Application" control in Settings >
System, complementary to the Restart control (Issue #43), backed by
`POST /api/system/stop`.

Stop performs a graceful shutdown -- the process sends itself SIGTERM (the
same signal `docker stop`/an orchestrator already sends to PID 1, and the
container has no custom handler installed for it, so the default disposition
terminates the process) rather than a hard kill (`SIGKILL`/`os._exit`) and
rather than a periodic restart/watchdog workaround. Unlike Restart, the
process does not come back on its own. These tests never let a real signal
reach the test process itself: `os.kill` is always monkeypatched to a
recording stub.
"""

import threading


def test_stop_control_is_present_in_the_system_panel(client):
    body = client.get("/").data.decode("utf-8")
    assert 'id="system-stop-btn"' in body
    assert 'id="system-stop-note"' in body


def test_stop_endpoint_rejects_get(client):
    resp = client.get("/api/system/stop")
    assert resp.status_code == 405


def test_stop_endpoint_requires_explicit_confirmation(client, app_module):
    resp = client.post("/api/system/stop", json={})
    assert resp.status_code == 400
    assert app_module._stop_in_progress is False


def test_stop_endpoint_rejects_a_falsy_confirm(client, app_module):
    resp = client.post("/api/system/stop", json={"confirm": False})
    assert resp.status_code == 400
    assert app_module._stop_in_progress is False


def test_confirmed_stop_sends_itself_sigterm_exactly_once(client, app_module, monkeypatch):
    kill_calls = []
    released = threading.Event()

    def fake_kill(pid, sig):
        kill_calls.append((pid, sig))
        released.set()

    monkeypatch.setattr(app_module.os, "kill", fake_kill)
    monkeypatch.setattr(app_module, "STOP_DELAY_SECONDS", 0.01)

    try:
        resp = client.post("/api/system/stop", json={"confirm": True})
        assert resp.status_code == 202
        assert resp.get_json()["ok"] is True

        assert released.wait(2), "the self-stop background thread never ran"
        assert len(kill_calls) == 1
        assert kill_calls[0] == (app_module.os.getpid(), app_module.signal.SIGTERM)
    finally:
        app_module._stop_in_progress = False


def test_duplicate_stop_requests_are_rejected_while_one_is_in_progress(client, app_module):
    """A stop already in flight must not be queued or double-executed -- a
    concurrent/duplicate request is rejected outright (409)."""
    app_module._stop_in_progress = True
    try:
        resp = client.post("/api/system/stop", json={"confirm": True})
        assert resp.status_code == 409
    finally:
        app_module._stop_in_progress = False


def test_stop_is_rejected_while_a_restart_is_in_progress(client, app_module):
    app_module._restart_in_progress = True
    try:
        resp = client.post("/api/system/stop", json={"confirm": True})
        assert resp.status_code == 409
        assert app_module._stop_in_progress is False
    finally:
        app_module._restart_in_progress = False


def test_restart_is_rejected_while_a_stop_is_in_progress(client, app_module):
    app_module._stop_in_progress = True
    try:
        resp = client.post("/api/system/restart", json={"confirm": True})
        assert resp.status_code == 409
        assert app_module._restart_in_progress is False
    finally:
        app_module._stop_in_progress = False


def test_self_stop_recovers_the_in_progress_flag_if_kill_fails(app_module, monkeypatch):
    """If signaling the process itself fails (e.g. permissions), the stop
    control must not be left permanently stuck reporting a stop in progress
    that is never going to happen."""
    def failing_kill(pid, sig):
        raise OSError("simulated kill failure")

    monkeypatch.setattr(app_module.os, "kill", failing_kill)
    monkeypatch.setattr(app_module, "STOP_DELAY_SECONDS", 0)
    app_module._stop_in_progress = True

    app_module._perform_self_stop()

    assert app_module._stop_in_progress is False
