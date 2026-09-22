import sqlite3
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture
def app_module(tmp_path, monkeypatch):
    """Import app.py fresh, pointed at throwaway per-test SQLite files.

    app.py reads DB_PATH/TRACKERDB_PATH etc. from the environment at module
    import time, so the env vars must be set before the (re)import.
    """
    monkeypatch.setenv("DB_PATH", str(tmp_path / "inspector.db"))
    monkeypatch.setenv("TRACKERDB_PATH", str(tmp_path / "trackerdb.sqlite"))
    monkeypatch.setenv("AGH_URL", "")
    monkeypatch.setenv("NEIGHBORS_PATH", str(tmp_path / "neighbors.txt"))
    monkeypatch.delenv("DNS_INSPECTOR_ADMIN_TOKEN", raising=False)
    monkeypatch.delenv("DNS_INSPECTOR_ADMIN_COOKIE_SECURE", raising=False)
    monkeypatch.delenv("DNS_INSPECTOR_ADMIN_SESSION_TTL_SECONDS", raising=False)

    sys.modules.pop("app", None)
    import app as module

    return module


@pytest.fixture
def admin_app_module(tmp_path, monkeypatch):
    """Same as app_module, but with an admin token configured so the
    lifecycle/diagnostic-export authorization gate is active.
    """
    monkeypatch.setenv("DB_PATH", str(tmp_path / "inspector.db"))
    monkeypatch.setenv("TRACKERDB_PATH", str(tmp_path / "trackerdb.sqlite"))
    monkeypatch.setenv("AGH_URL", "")
    monkeypatch.setenv("NEIGHBORS_PATH", str(tmp_path / "neighbors.txt"))
    monkeypatch.setenv("DNS_INSPECTOR_ADMIN_TOKEN", "test-admin-token")

    sys.modules.pop("app", None)
    import app as module

    return module


@pytest.fixture
def track_connections(monkeypatch):
    """Record every sqlite3.Connection opened during the test via sqlite3.connect."""
    created = []
    real_connect = sqlite3.connect

    def spy_connect(*args, **kwargs):
        conn = real_connect(*args, **kwargs)
        created.append(conn)
        return conn

    monkeypatch.setattr(sqlite3, "connect", spy_connect)
    return created


def assert_all_closed(connections):
    """A closed sqlite3.Connection raises ProgrammingError on any operation."""
    still_open = []
    for conn in connections:
        try:
            conn.execute("SELECT 1")
        except sqlite3.ProgrammingError:
            continue
        still_open.append(conn)
    assert not still_open, f"{len(still_open)} connection(s) were never closed"
