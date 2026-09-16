"""The inspector registry: BEMO Core's boundary for inspector registration.

An inspector registers a small, static description of itself. The registry
does not own inspector behaviour or data — it only lets the BEMO shell (and
later, cross-inspector features) discover what is installed.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class InspectorInfo:
    """Static, self-reported identity of one inspector."""

    slug: str
    name: str
    version: str
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "slug": self.slug,
            "name": self.name,
            "version": self.version,
            "description": self.description,
        }


class InspectorRegistry:
    """An in-memory directory of registered inspectors.

    Registration is idempotent by slug: re-registering the same slug (for
    example when a test reloads `app` with `importlib.reload`) replaces the
    previous entry instead of raising.
    """

    def __init__(self) -> None:
        self._inspectors: Dict[str, InspectorInfo] = {}

    def register(self, info: InspectorInfo) -> None:
        self._inspectors[info.slug] = info

    def get(self, slug: str) -> Optional[InspectorInfo]:
        return self._inspectors.get(slug)

    def list(self) -> List[InspectorInfo]:
        return sorted(self._inspectors.values(), key=lambda info: info.slug)


_default_registry = InspectorRegistry()


def get_registry() -> InspectorRegistry:
    """The process-wide inspector registry."""
    return _default_registry
