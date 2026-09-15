"""Domain status classification.

These are pure functions with no I/O, so they are the cheapest place to lock in
real behaviour and catch an accidental change during future modularisation.
"""

import pytest


@pytest.mark.parametrize("reason", [
    "FilteredBlackList",
    "FilteredSafeBrowsing",
    "FilteredParental",
    "FilteredBlockedService",
])
def test_filtered_reasons_are_blocked(app_module, reason):
    assert app_module.query_status(reason) == "Blocked"


@pytest.mark.parametrize("reason", [
    "NotFilteredWhiteList",
    "NotFilteredNotFound",
    "Rewrite",
    "RewriteEtcHosts",
    "RewriteRule",
    "FilteredSafeSearch",
])
def test_unfiltered_reasons_are_allowed(app_module, reason):
    assert app_module.query_status(reason) == "Allowed"


@pytest.mark.parametrize("reason", ["NotFilteredError", "FilteredInvalid", "", None])
def test_error_and_missing_reasons_are_unknown(app_module, reason):
    assert app_module.query_status(reason) == "Unknown"


def test_unrecognised_reason_is_not_assumed_allowed(app_module):
    """AdGuard's reason is authoritative; an answer alone proves nothing."""
    assert app_module.query_status("SomethingNewFromAdGuard") == "Unknown"
    assert app_module.query_status("", original_response=["93.184.216.34"]) == "Unknown"


@pytest.mark.parametrize("blocked,allowed,unknown,expected", [
    (0, 0, 0, "Unknown"),
    (0, 0, 7, "Unknown"),
    (0, 5, 0, "Allowed"),
    (5, 0, 0, "Blocked"),
    (5, 5, 0, "Mixed"),
    (1, 9, 3, "Mixed"),
])
def test_status_summary(app_module, blocked, allowed, unknown, expected):
    status, css_class = app_module.status_summary(blocked, allowed, unknown)
    assert status == expected
    assert css_class == expected.lower()


@pytest.mark.parametrize("blocked,allowed,expected", [
    (0, 0, "Unknown"),
    (0, 3, "Allowed"),
    (3, 0, "Blocked"),
    (3, 3, "Mixed"),
])
def test_status_from_counts(app_module, blocked, allowed, expected):
    status, css_class = app_module._status_from_counts(blocked, allowed)
    assert status == expected
    assert css_class == expected.lower()


def test_status_from_counts_tolerates_none(app_module):
    """SQLite SUM() returns NULL on an empty table."""
    assert app_module._status_from_counts(None, None) == ("Unknown", "unknown")


def test_mac_normalisation(app_module):
    """Device identity depends on a single canonical MAC form."""
    assert app_module.is_mac("AA:BB:CC:DD:EE:FF") is True
    assert app_module.is_mac("192.0.2.10") is False
    assert app_module.normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert app_module.normalize_mac("not a mac") == ""
