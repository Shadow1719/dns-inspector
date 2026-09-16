"""DNS query status and severity classification.

Moved out of `app.py` unchanged, as the first real module boundary (see the
Tier 1 "status" boundary in docs/MODULARIZATION.md: pure functions, no I/O,
already covered by tests). Behaviour is preserved exactly; only the location
has changed.
"""

BLOCKED_REASONS = {
    "FilteredBlackList",
    "FilteredSafeBrowsing",
    "FilteredParental",
    "FilteredBlockedService",
}
ALLOWED_REASONS = {
    "NotFilteredWhiteList",
    "NotFilteredNotFound",
    "Rewrite",
    "RewriteEtcHosts",
    "RewriteRule",
    "FilteredSafeSearch",
}
UNKNOWN_REASONS = {
    "NotFilteredError",
    "FilteredInvalid",
}


def query_status(reason, original_response=None):
    reason = str(reason or "")
    if reason in BLOCKED_REASONS:
        return "Blocked"
    if reason in ALLOWED_REASONS:
        return "Allowed"
    if reason in UNKNOWN_REASONS:
        return "Unknown"
    # Do not infer "allowed" merely because an answer exists.  AdGuard's
    # reason is the authoritative signal for query-log status.
    return "Unknown"


def status_summary(blocked, allowed, unknown):
    if blocked and allowed:
        return "Mixed", "mixed"
    if blocked:
        return "Blocked", "blocked"
    if allowed:
        return "Allowed", "allowed"
    return "Unknown", "unknown"


def severity_for_classification(classification):
    mapping = {
        "Known service": ("Info", "info"),
        "Known ownership": ("Info", "info"),
        "Telemetry / tracking": ("Low", "low"),
        "Advertising": ("Medium", "medium"),
        "Suspicious": ("High", "high"),
    }
    return mapping.get(classification, ("Unknown", "unknown"))


def _status_from_counts(blocked, allowed):
    blocked = int(blocked or 0)
    allowed = int(allowed or 0)
    if blocked and allowed:
        return "Mixed", "mixed"
    if blocked:
        return "Blocked", "blocked"
    if allowed:
        return "Allowed", "allowed"
    return "Unknown", "unknown"
