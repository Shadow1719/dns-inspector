import os
import resource
import time
from datetime import datetime, timezone

from flask import jsonify

try:
    with open(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "VERSION"), "r", encoding="utf-8") as f:
        APP_VERSION = f.read().strip()
except Exception:
    APP_VERSION = os.getenv("APP_VERSION", "dev")

OBSERVABILITY_START_MONOTONIC = time.monotonic()
OBSERVABILITY_START_AT = datetime.now(timezone.utc).isoformat()


def _observability_uptime_seconds():
    return max(0.0, time.monotonic() - OBSERVABILITY_START_MONOTONIC)


def _observability_uptime_human(seconds=None):
    total = int(max(0.0, _observability_uptime_seconds() if seconds is None else seconds))
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days}d {hours:02d}h {minutes:02d}m"
    if hours:
        return f"{hours}h {minutes:02d}m {secs:02d}s"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def _observability_rss_mb():
    try:
        # Linux reports KiB for ru_maxrss; convert to MiB.
        value = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        if os.name == "nt":
            return round(value / (1024 * 1024), 1)
        return round(value / 1024.0, 1)
    except Exception:
        return None


def _observability_payload():
    uptime = _observability_uptime_seconds()
    return {
        "ok": True,
        "version": APP_VERSION,
        "started_at": OBSERVABILITY_START_AT,
        "uptime_seconds": round(uptime, 1),
        "uptime_human": _observability_uptime_human(uptime),
        "ram_mb": _observability_rss_mb(),
    }


def _api_observability_live():
    return jsonify(_observability_payload())
