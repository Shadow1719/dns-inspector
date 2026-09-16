"""The Analytics overhaul (Issue #16): live activity and historical trends.

These read from data the ingestion pipeline already persists -- query
fingerprints with timestamps in `processed_queries`, and `first_seen` /
`last_seen` on `domains` and `devices`. No background worker runs during the
test session, so the database only ever contains what a test writes; every
assertion here is written as a delta around a fresh, uniquely-tagged row so
tests stay correct regardless of execution order or state left behind by
other test modules sharing the same session-scoped database.
"""

import json
import sqlite3
import uuid
from contextlib import closing


def _unique(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _insert_domain(db_path, domain, now, blocked=0, allowed=0, unknown=0, status="Unknown", requests=1):
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO domains"
            "(domain,first_seen,last_seen,requests,clients_json,blocked_requests,"
            "allowed_requests,unknown_requests,last_status,current_status)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            (domain, now, now, requests, "{}", blocked, allowed, unknown, status, status),
        )
        conn.commit()


def _insert_device(db_path, device_key, now, requests=1):
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO devices"
            "(device_key,name,hostname,mac,device_type,icon,confidence,source,first_seen,last_seen,request_count,info_json)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (device_key, "", "", "", "IoT / Unknown", "\U0001F4E6", "low", "test", now, now, requests, "{}"),
        )
        conn.commit()


def _insert_processed_query(db_path, fingerprint, seen_at):
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO processed_queries(fingerprint,seen_at,status_counted) VALUES(?,?,1)",
            (fingerprint, seen_at),
        )
        conn.commit()


# --- schema -----------------------------------------------------------------


def test_analytics_indexes_exist(initialised_db):
    with closing(sqlite3.connect(initialised_db)) as conn:
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()
    names = {row[0] for row in rows}
    assert {
        "idx_domains_last_seen", "idx_domains_first_seen",
        "idx_devices_last_seen", "idx_devices_first_seen",
    }.issubset(names)


# --- data-selection helpers ---------------------------------------------


def test_status_breakdown_counts_a_newly_inserted_blocked_domain(app_module, initialised_db):
    before = app_module.get_status_breakdown()
    _insert_domain(initialised_db, _unique("status-blocked"), app_module.utcnow(), blocked=3, allowed=0)
    after = app_module.get_status_breakdown()
    assert after["Blocked"] == before["Blocked"] + 1
    assert after["All"] == before["All"] + 1


def test_status_breakdown_counts_a_newly_inserted_allowed_domain(app_module, initialised_db):
    before = app_module.get_status_breakdown()
    _insert_domain(initialised_db, _unique("status-allowed"), app_module.utcnow(), blocked=0, allowed=5)
    after = app_module.get_status_breakdown()
    assert after["Allowed"] == before["Allowed"] + 1


def test_query_volume_series_counts_a_query_seen_right_now(app_module, initialised_db):
    before = app_module.get_query_volume_series("1h")
    before_total = sum(p["count"] or 0 for p in before["points"])
    _insert_processed_query(initialised_db, _unique("qfp"), app_module.utcnow())
    after = app_module.get_query_volume_series("1h")
    after_total = sum(p["count"] or 0 for p in after["points"])
    assert after_total == before_total + 1
    # The most recent bucket holds "now" and must not be reported as a
    # no-data gap once a query has actually been recorded inside it.
    assert after["points"][-1]["count"] is not None
    assert after["points"][-1]["count"] >= 1


def test_query_volume_series_has_one_point_per_bucket(app_module, initialised_db):
    for key, expected_points in (("1h", 60), ("6h", 72), ("24h", 96), ("7d", 84)):
        series = app_module.get_query_volume_series(key)
        assert len(series["points"]) == expected_points


def test_query_volume_series_falls_back_to_1h_for_an_unknown_range(app_module, initialised_db):
    series = app_module.get_query_volume_series("not-a-real-range")
    assert series["range"] == "not-a-real-range"
    assert len(series["points"]) == 60  # falls back to the 1h bucket layout


def test_new_domains_series_counts_a_domain_first_seen_now(app_module, initialised_db):
    before = app_module.get_new_domains_series("1h")
    before_total = sum(p["count"] or 0 for p in before["points"])
    _insert_domain(initialised_db, _unique("new-domain"), app_module.utcnow())
    after = app_module.get_new_domains_series("1h")
    after_total = sum(p["count"] or 0 for p in after["points"])
    assert after_total == before_total + 1


def test_new_devices_series_counts_a_device_first_seen_now(app_module, initialised_db):
    before = app_module.get_new_devices_series("1h")
    before_total = sum(p["count"] or 0 for p in before["points"])
    _insert_device(initialised_db, _unique("mac:aa:bb:cc:dd:ee:ff"), app_module.utcnow())
    after = app_module.get_new_devices_series("1h")
    after_total = sum(p["count"] or 0 for p in after["points"])
    assert after_total == before_total + 1


def test_recent_activity_surfaces_a_freshly_seen_domain_first(app_module, initialised_db):
    domain = _unique("recent-domain")
    _insert_domain(initialised_db, domain, app_module.utcnow(), allowed=1, status="Allowed")
    activity = app_module.get_recent_activity(limit=5)
    assert activity["domains"][0]["domain"] == domain
    assert activity["domains"][0]["status"] == "Allowed"


def test_live_snapshot_counts_a_query_inside_the_window(app_module, initialised_db):
    before = app_module._analytics_live_snapshot(window_seconds=60)
    _insert_processed_query(initialised_db, _unique("live-qfp"), app_module.utcnow())
    after = app_module._analytics_live_snapshot(window_seconds=60)
    assert after["queries_in_window"] == before["queries_in_window"] + 1
    assert after["window_seconds"] == 60


def test_active_devices_count_counts_a_device_seen_now(app_module, initialised_db):
    before = app_module._active_devices_count(window_seconds=300)
    _insert_device(initialised_db, _unique("mac:11:22:33:44:55:66"), app_module.utcnow())
    after = app_module._active_devices_count(window_seconds=300)
    assert after == before + 1


# --- HTTP surface -------------------------------------------------------


def test_analytics_route_is_registered(app_module):
    rules = {rule.rule for rule in app_module.app.url_map.iter_rules()}
    assert "/api/analytics" in rules


def test_api_analytics_returns_expected_shape(client):
    response = client.get("/api/analytics")
    assert response.status_code == 200
    payload = json.loads(response.data)
    assert set(payload) >= {
        "updated", "range", "range_options", "series",
        "status_breakdown", "recent_domains", "recent_devices",
        "active_devices", "new_domains_24h", "live",
    }
    assert payload["range"] == "1h"
    assert set(payload["series"]) == {"queries", "new_domains", "new_devices"}
    assert isinstance(payload["recent_domains"], list)
    assert isinstance(payload["recent_devices"], list)


def test_api_analytics_accepts_a_range_query_param(client):
    response = client.get("/api/analytics?range=24h")
    assert response.status_code == 200
    payload = json.loads(response.data)
    assert payload["range"] == "24h"
    assert len(payload["series"]["queries"]["points"]) == 96


def test_api_analytics_falls_back_for_an_invalid_range(client):
    response = client.get("/api/analytics?range=not-a-real-range")
    assert response.status_code == 200
    payload = json.loads(response.data)
    assert payload["range"] == "1h"


def test_state_payload_includes_a_live_sample(app_module, initialised_db):
    """The live queries-per-window counter rides the existing state refresh
    path (ROADMAP.md's "Analytics Live Activity" note) instead of a second
    high-frequency polling loop."""
    payload = app_module.state_payload()
    assert set(payload["live"]) >= {"updated", "window_seconds", "queries_in_window"}
    assert payload["live"]["window_seconds"] == 60
    assert isinstance(payload["live"]["queries_in_window"], int)


def test_api_state_includes_a_live_sample(client):
    response = client.get("/api/state")
    payload = json.loads(response.data)
    assert "live" in payload
    assert payload["live"]["window_seconds"] == 60
