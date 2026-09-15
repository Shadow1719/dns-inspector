"""The HTTP surface that has to keep working for the container to be usable."""

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_health_returns_ok(client):
    response = client.get("/health")
    assert response.status_code == 200

    payload = json.loads(response.data)
    assert payload["ok"] is True


def test_health_reports_the_release_version(client):
    payload = json.loads(client.get("/health").data)
    expected = (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip()
    assert payload["version"] == expected


def test_health_reports_runtime_configuration(client):
    """The health payload is the documented shape the container check uses."""
    payload = json.loads(client.get("/health").data)
    assert set(payload) >= {
        "ok", "version", "adguard", "trackerdb",
        "poll_seconds", "ui_refresh_seconds",
    }
    assert payload["poll_seconds"] >= 5
    assert payload["ui_refresh_seconds"] >= 5
    assert isinstance(payload["trackerdb"], bool)


def test_health_works_without_adguard(client):
    """With no AdGuard configured the check still succeeds, reporting empty."""
    payload = json.loads(client.get("/health").data)
    assert payload["adguard"] == ""
    assert payload["ok"] is True


def test_root_renders_the_dashboard(client):
    response = client.get("/")
    assert response.status_code == 200

    body = response.data.decode("utf-8")
    assert "<html" in body.lower()
    assert "DNS Inspector" in body


def test_api_state_returns_json(client):
    """The UI polls this endpoint; it must answer on an empty database."""
    response = client.get("/api/state")
    assert response.status_code == 200

    payload = json.loads(response.data)
    assert set(payload) >= {"updated", "recent", "clients", "stats"}
    assert isinstance(payload["recent"], list)


def test_unknown_path_is_not_found(client):
    assert client.get("/no-such-page").status_code == 404
