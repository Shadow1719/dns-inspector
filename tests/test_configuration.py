"""Configuration is read from the environment exactly once, at import time.

These tests pin that contract so a future version cannot quietly move a setting
somewhere else without the suite noticing.
"""

import importlib
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_version_constant_matches_version_file(app_module):
    """`APP_VERSION` is sourced from the VERSION file, not hardcoded."""
    expected = (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip()
    assert app_module.APP_VERSION == expected


def test_environment_overrides_are_applied(app_module):
    """The values conftest exported are the values the module is using."""
    assert app_module.DB_PATH == os.environ["DB_PATH"]
    assert app_module.TRACKERDB_PATH == os.environ["TRACKERDB_PATH"]
    assert app_module.NEIGHBORS_PATH == os.environ["NEIGHBORS_PATH"]
    assert app_module.AGH_URL == ""


def test_poll_interval_has_a_lower_bound(monkeypatch):
    """POLL_SECONDS clamps to 5 so a bad value cannot hammer AdGuard."""
    import app

    monkeypatch.setenv("POLL_SECONDS", "1")
    reloaded = importlib.reload(app)
    try:
        assert reloaded.POLL_SECONDS == 5
    finally:
        monkeypatch.delenv("POLL_SECONDS", raising=False)
        importlib.reload(app)


def test_ui_refresh_interval_has_a_lower_bound(monkeypatch):
    """UI_REFRESH_SECONDS clamps to 5 for the same reason."""
    import app

    monkeypatch.setenv("UI_REFRESH_SECONDS", "0")
    reloaded = importlib.reload(app)
    try:
        assert reloaded.UI_REFRESH_SECONDS == 5
    finally:
        monkeypatch.delenv("UI_REFRESH_SECONDS", raising=False)
        importlib.reload(app)


def test_trackerdb_chunk_size_has_a_floor(app_module):
    """Download chunking never drops below 64 KiB."""
    assert app_module.TRACKERDB_DOWNLOAD_CHUNK_SIZE >= 64 * 1024
