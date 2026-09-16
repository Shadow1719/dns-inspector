"""BEMO Core: shared platform primitives for Inspector BEMO.

This package holds the concepts every inspector shares — inspector
registration and health/status reporting today, with observations, events,
findings and evidence to follow as real inspectors need them (see
docs/ARCHITECTURE.md and docs/MODULARIZATION.md). It intentionally stays
small: primitives are added here only once a second inspector needs them,
not speculatively.
"""

from .health import HealthLevel, InspectorHealth
from .registry import InspectorInfo, InspectorRegistry, get_registry

__all__ = [
    "HealthLevel",
    "InspectorHealth",
    "InspectorInfo",
    "InspectorRegistry",
    "get_registry",
]
