"""BEMO Core primitives: inspector registration and health/status.

These are plain-Python, no-I/O modules (see `bemo_core/`), so they are tested
directly rather than through the Flask app.
"""

from bemo_core.health import HealthLevel, InspectorHealth
from bemo_core.registry import InspectorInfo, InspectorRegistry


def test_registry_register_and_get():
    registry = InspectorRegistry()
    info = InspectorInfo(slug="dns", name="DNS Inspector", version="0.9.0")

    registry.register(info)

    assert registry.get("dns") == info
    assert registry.get("missing") is None


def test_registry_register_is_idempotent_by_slug():
    """Re-registering the same slug replaces the entry instead of raising.

    This matters because `importlib.reload(app)` (used by the environment
    tests) re-executes module-level registration against the same
    process-wide registry.
    """
    registry = InspectorRegistry()
    registry.register(InspectorInfo(slug="dns", name="DNS Inspector", version="0.9.0"))
    registry.register(InspectorInfo(slug="dns", name="DNS Inspector", version="0.9.1"))

    assert registry.get("dns").version == "0.9.1"
    assert len(registry.list()) == 1


def test_registry_list_is_sorted_by_slug():
    registry = InspectorRegistry()
    registry.register(InspectorInfo(slug="storage", name="Storage Inspector", version="0.9.0"))
    registry.register(InspectorInfo(slug="dns", name="DNS Inspector", version="0.9.0"))

    assert [info.slug for info in registry.list()] == ["dns", "storage"]


def test_inspector_info_to_dict():
    info = InspectorInfo(slug="dns", name="DNS Inspector", version="0.9.0", description="desc")

    assert info.to_dict() == {
        "slug": "dns",
        "name": "DNS Inspector",
        "version": "0.9.0",
        "description": "desc",
    }


def test_inspector_health_to_dict():
    health = InspectorHealth(HealthLevel.WARNING, "something is off")

    assert health.to_dict() == {"level": "warning", "summary": "something is off"}


def test_inspector_health_defaults_to_empty_summary():
    assert InspectorHealth(HealthLevel.OK).to_dict() == {"level": "ok", "summary": ""}
