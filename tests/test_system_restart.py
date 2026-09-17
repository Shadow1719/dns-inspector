"""Restart control (Issue #43): a functional "Restart DNS Inspector" control
in Settings > System, backed by `POST /api/system/restart`.

The container runs `app.py` directly as PID 1 with no supervisor/entrypoint
script (see the Dockerfile's `CMD ["python", "/app/app.py"]`), so a real
restart replaces the running process image in place via `os.execv` rather
than relying on a Docker restart policy or only restarting a background
worker thread -- see `_perform_self_restart()` in `app.py`. These tests never
let that actually happen: `os.execv` is always monkeypatched to a recording
stub so the test process itself keeps running.
"""

import threading


def test_restart_control_is_present_in_the_system_panel(client):
    body = client.get("/").data.decode("utf-8")
    assert 'id="system-restart-btn"' in body
    assert 'id="system-restart-note"' in body


def test_restart_endpoint_rejects_get(client):
    resp = client.get("/api/system/restart")
    assert resp.status_code == 405


def test_restart_endpoint_requires_explicit_confirmation(client, app_module):
    resp = client.post("/api/system/restart", json={})
    assert resp.status_code == 400
    assert app_module._restart_in_progress is False


def test_restart_endpoint_rejects_a_falsy_confirm(client, app_module):
    resp = client.post("/api/system/restart", json={"confirm": False})
    assert resp.status_code == 400
    assert app_module._restart_in_progress is False


def test_confirmed_restart_triggers_self_restart_exactly_once(client, app_module, monkeypatch):
    execv_calls = []
    released = threading.Event()

    def fake_execv(executable, args):
        execv_calls.append((executable, args))
        released.set()

    monkeypatch.setattr(app_module.os, "execv", fake_execv)
    monkeypatch.setattr(app_module, "RESTART_DELAY_SECONDS", 0.01)

    try:
        resp = client.post("/api/system/restart", json={"confirm": True})
        assert resp.status_code == 202
        assert resp.get_json()["ok"] is True

        assert released.wait(2), "the self-restart background thread never ran"
        assert len(execv_calls) == 1
        assert execv_calls[0][0] == app_module.sys.executable
    finally:
        app_module._restart_in_progress = False


def test_duplicate_restart_requests_are_rejected_while_one_is_in_progress(client, app_module):
    """A restart already in flight must not be queued or double-executed --
    a concurrent/duplicate request is rejected outright (409)."""
    app_module._restart_in_progress = True
    try:
        resp = client.post("/api/system/restart", json={"confirm": True})
        assert resp.status_code == 409
    finally:
        app_module._restart_in_progress = False


def test_self_restart_recovers_the_in_progress_flag_if_execv_fails(app_module, monkeypatch):
    """If the process replacement itself fails (e.g. permissions), the
    restart control must not be left permanently stuck reporting a restart
    in progress that is never going to happen."""
    def failing_execv(executable, args):
        raise OSError("simulated exec failure")

    monkeypatch.setattr(app_module.os, "execv", failing_execv)
    monkeypatch.setattr(app_module, "RESTART_DELAY_SECONDS", 0)
    app_module._restart_in_progress = True

    app_module._perform_self_restart()

    assert app_module._restart_in_progress is False
