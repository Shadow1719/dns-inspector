"""Generic health/status primitives shared by every inspector.

This is the BEMO Core notion of health: a coarse level plus a short, human
explanation. It is deliberately generic — DNS-specific classification (query
status, severity) lives in `inspectors/dns`, not here.
"""

from dataclasses import dataclass
from enum import Enum


class HealthLevel(str, Enum):
    """Coarse inspector health, ordered from best to worst."""

    OK = "ok"
    WARNING = "warning"
    ERROR = "error"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class InspectorHealth:
    """An inspector's current health, as reported to the BEMO shell."""

    level: HealthLevel
    summary: str = ""

    def to_dict(self) -> dict:
        return {"level": self.level.value, "summary": self.summary}
