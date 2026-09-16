"""The `inspectors/dns` module boundary.

`inspectors.dns` is importable and testable on its own, without importing
`app` or touching Flask/SQLite. That independence is the point of the
boundary: it is real module extraction, not just an alias.
"""

from bemo_core.health import HealthLevel
from bemo_core.registry import get_registry

import inspectors.dns as dns_inspector


def test_register_adds_dns_to_the_shared_registry():
    dns_inspector.register("1.2.3-test")

    info = get_registry().get(dns_inspector.SLUG)
    assert info is not None
    assert info.name == dns_inspector.NAME
    assert info.version == "1.2.3-test"


def test_health_is_unknown_with_no_activity():
    result = dns_inspector.health(blocked=0, allowed=0, unknown=0)
    assert result.level == HealthLevel.UNKNOWN


def test_health_is_warning_when_blocked_only():
    result = dns_inspector.health(blocked=5, allowed=0, unknown=0)
    assert result.level == HealthLevel.WARNING


def test_health_is_ok_when_allowed_activity_present():
    result = dns_inspector.health(blocked=0, allowed=5, unknown=0)
    assert result.level == HealthLevel.OK


def test_health_is_ok_when_mixed():
    """Mixed still means the inspector is actively observing traffic."""
    result = dns_inspector.health(blocked=5, allowed=5, unknown=0)
    assert result.level == HealthLevel.OK


def test_query_status_classification_matches_pre_extraction_behaviour():
    """Locks in the exact behaviour moved out of `app.py` (see status.py)."""
    assert dns_inspector.query_status("FilteredBlackList") == "Blocked"
    assert dns_inspector.query_status("NotFilteredWhiteList") == "Allowed"
    assert dns_inspector.query_status("NotFilteredError") == "Unknown"
    assert dns_inspector.query_status("SomethingNewFromAdGuard") == "Unknown"
