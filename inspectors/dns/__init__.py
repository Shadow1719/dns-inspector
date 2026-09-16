"""DNS Inspector module boundary within Inspector BEMO.

This is the first inspector to be migrated onto BEMO Core. Today it exposes
the query-status/severity classification slice moved from `app.py` (see
`status.py`) and registers itself with the BEMO Core inspector registry. The
rest of DNS Inspector's behaviour still lives in `app.py`; it moves here
incrementally, in its own focused changes.
"""

from bemo_core.health import HealthLevel, InspectorHealth
from bemo_core.registry import InspectorInfo, get_registry

from .status import (
    ALLOWED_REASONS,
    BLOCKED_REASONS,
    UNKNOWN_REASONS,
    _status_from_counts,
    query_status,
    severity_for_classification,
    status_summary,
)

SLUG = "dns"
NAME = "DNS Inspector"
DESCRIPTION = "AdGuard Home query activity, device/IP identity and domain enrichment."

__all__ = [
    "ALLOWED_REASONS",
    "BLOCKED_REASONS",
    "UNKNOWN_REASONS",
    "_status_from_counts",
    "query_status",
    "severity_for_classification",
    "status_summary",
    "health",
    "register",
]


def register(version: str) -> None:
    """Register the DNS inspector with the BEMO Core registry."""
    get_registry().register(
        InspectorInfo(
            slug=SLUG,
            name=NAME,
            version=version,
            description=DESCRIPTION,
        )
    )


def health(blocked: int, allowed: int, unknown: int) -> InspectorHealth:
    """Aggregate DNS Inspector health from recent blocked/allowed/unknown counts."""
    status, _css_class = status_summary(blocked, allowed, unknown)
    if status == "Unknown":
        return InspectorHealth(HealthLevel.UNKNOWN, "No recent DNS activity observed")
    if status == "Blocked":
        return InspectorHealth(HealthLevel.WARNING, "Recent activity is being blocked")
    return InspectorHealth(HealthLevel.OK, f"Recent activity: {status.lower()}")
