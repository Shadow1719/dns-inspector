import json
from contextlib import closing
from datetime import datetime, timedelta, timezone


def _insert_query(app_module, fingerprint, seen_at, domain="", device_key="", status=""):
    with app_module.db_lock, closing(app_module.sqlite3.connect(app_module.DB_PATH)) as c:
        c.execute(
            "INSERT INTO processed_queries(fingerprint,seen_at,status_counted,domain,device_key,status) VALUES(?,?,1,?,?,?)",
            (fingerprint, seen_at, domain, device_key, status),
        )
        c.commit()


def test_analytics_buckets_table_and_columns_exist(app_module):
    app_module.init_db()
    with closing(app_module.sqlite3.connect(app_module.DB_PATH)) as c:
        cols = {row[1] for row in c.execute("PRAGMA table_info(analytics_buckets)").fetchall()}
    assert {"bucket_start", "bucket_seconds", "query_count", "unique_domains", "unique_devices",
            "allowed", "blocked", "unknown", "new_domains", "new_devices", "top_domains_json", "top_devices_json"} <= cols


def test_analytics_history_tick_closes_hour_aligned_buckets(app_module):
    app_module.init_db()
    now = datetime.now(timezone.utc)
    bucket_start = app_module._bucket_floor(now) - timedelta(hours=2)
    seen_at = (bucket_start + timedelta(minutes=5)).isoformat()
    _insert_query(app_module, "fp-a", seen_at, domain="example.com", device_key="mac:aa", status="Allowed")
    _insert_query(app_module, "fp-b", seen_at, domain="tracker.example", device_key="mac:bb", status="Blocked")

    closed = app_module.analytics_history_tick()
    assert closed >= 1

    with closing(app_module.sqlite3.connect(app_module.DB_PATH)) as c:
        row = c.execute(
            "SELECT query_count,allowed,blocked,unique_domains,unique_devices,top_domains_json FROM analytics_buckets WHERE bucket_start=?",
            (bucket_start.isoformat(),),
        ).fetchone()
    assert row is not None
    query_count, allowed, blocked, unique_domains, unique_devices, top_domains_json = row
    assert query_count == 2
    assert allowed == 1
    assert blocked == 1
    assert unique_domains == 2
    assert unique_devices == 2
    top_domains = dict(json.loads(top_domains_json))
    assert top_domains.get("example.com") == 1
    assert top_domains.get("tracker.example") == 1


def test_analytics_history_tick_is_idempotent_and_bounded(app_module):
    app_module.init_db()
    now = datetime.now(timezone.utc)
    bucket_start = app_module._bucket_floor(now) - timedelta(hours=1)
    _insert_query(app_module, "fp-c", (bucket_start + timedelta(minutes=1)).isoformat(), domain="a.com", device_key="mac:aa", status="Allowed")

    first = app_module.analytics_history_tick()
    second = app_module.analytics_history_tick()
    assert first >= 1
    assert second == 0  # nothing new to close on the very next tick

    with closing(app_module.sqlite3.connect(app_module.DB_PATH)) as c:
        count = c.execute("SELECT COUNT(*) FROM analytics_buckets WHERE bucket_start=?", (bucket_start.isoformat(),)).fetchone()[0]
    assert count == 1  # upsert, not duplicated


def test_analytics_history_retention_prunes_old_buckets(app_module):
    app_module.init_db()
    now = datetime.now(timezone.utc)
    ancient = app_module._bucket_floor(now) - timedelta(hours=app_module.ANALYTICS_HISTORY_RETENTION_HOURS + 10)
    with app_module.db_lock, closing(app_module.sqlite3.connect(app_module.DB_PATH)) as c:
        c.execute(
            "INSERT INTO analytics_buckets(bucket_start,bucket_seconds,query_count,unique_domains,unique_devices,allowed,blocked,unknown,new_domains,new_devices,top_domains_json,top_devices_json,created_at) "
            "VALUES(?,?,0,0,0,0,0,0,0,0,'[]','[]',?)",
            (ancient.isoformat(), app_module.ANALYTICS_BUCKET_SECONDS, app_module.utcnow()),
        )
        c.commit()

    app_module.analytics_history_tick()

    with closing(app_module.sqlite3.connect(app_module.DB_PATH)) as c:
        row = c.execute("SELECT 1 FROM analytics_buckets WHERE bucket_start=?", (ancient.isoformat(),)).fetchone()
    assert row is None


def test_interval_detail_exact_granularity_reflects_real_per_query_data(app_module):
    app_module.init_db()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    bucket_start = now - timedelta(minutes=10)
    seen_at = (bucket_start + timedelta(seconds=5)).isoformat()
    _insert_query(app_module, "fp-x", seen_at, domain="example.com", device_key="mac:aa", status="Allowed")
    _insert_query(app_module, "fp-y", seen_at, domain="tracker.example", device_key="mac:bb", status="Blocked")

    detail = app_module.analytics_interval_detail("1h", bucket_start)
    assert detail["ok"] is True
    assert detail["granularity"] == "exact"
    assert detail["query_count"] == 2
    assert detail["status"]["Allowed"] == 1
    assert detail["status"]["Blocked"] == 1
    assert detail["unique_domains"] == 2
    domains = {row["domain"] for row in detail["top_domains"]}
    assert domains == {"example.com", "tracker.example"}


def test_interval_detail_falls_back_to_hourly_aggregate_once_raw_has_rolled_off(app_module):
    app_module.init_db()
    now = datetime.now(timezone.utc)
    old_bucket = app_module._bucket_floor(now) - timedelta(hours=200)
    with app_module.db_lock, closing(app_module.sqlite3.connect(app_module.DB_PATH)) as c:
        c.execute(
            "INSERT INTO analytics_buckets(bucket_start,bucket_seconds,query_count,unique_domains,unique_devices,allowed,blocked,unknown,new_domains,new_devices,top_domains_json,top_devices_json,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (old_bucket.isoformat(), 3600, 10, 4, 2, 6, 4, 0, 1, 0, json.dumps([["old-domain.example", 6]]), json.dumps([["mac:cc", 6]]), app_module.utcnow()),
        )
        # A raw row that is much newer than old_bucket, so MIN(seen_at) sits
        # well after old_bucket's window -- old_bucket is unambiguously
        # outside the retained raw window.
        c.execute(
            "INSERT INTO processed_queries(fingerprint,seen_at,status_counted,domain,device_key,status) VALUES(?,?,1,?,?,?)",
            ("fp-recent", now.isoformat(), "recent.example", "mac:dd", "Allowed"),
        )
        c.commit()

    detail = app_module.analytics_interval_detail("1h", old_bucket)
    assert detail["ok"] is True
    assert detail["granularity"] == "hourly_aggregate"
    assert detail["query_count"] == 10
    assert detail["status"]["Blocked"] == 4
    assert detail["unique_domains"] is None  # honestly not available at this granularity
    assert any(d["domain"] == "old-domain.example" for d in detail["top_domains"])
    assert "note" in detail


def test_interval_detail_reports_no_data_honestly(app_module):
    app_module.init_db()
    now = datetime.now(timezone.utc)
    with app_module.db_lock, closing(app_module.sqlite3.connect(app_module.DB_PATH)) as c:
        c.execute(
            "INSERT INTO processed_queries(fingerprint,seen_at,status_counted,domain,device_key,status) VALUES(?,?,1,?,?,?)",
            ("fp-only", now.isoformat(), "example.com", "mac:aa", "Allowed"),
        )
        c.commit()
    ancient = now - timedelta(days=400)
    detail = app_module.analytics_interval_detail("1h", ancient)
    assert detail["granularity"] == "none"
    assert detail["query_count"] == 0
    assert detail["top_domains"] == []


def test_analytics_interval_api_rejects_bad_input(app_module):
    app_module.init_db()
    client = app_module.app.test_client()
    resp = client.get("/api/analytics/interval?range=bogus&bucket_start=2024-01-01T00:00:00+00:00")
    assert resp.status_code == 400
    resp2 = client.get("/api/analytics/interval?range=1h&bucket_start=not-a-date")
    assert resp2.status_code == 400


def test_analytics_range_options_include_30d_and_90d(app_module):
    app_module.init_db()
    client = app_module.app.test_client()
    for range_key in ("30d", "90d"):
        resp = client.get(f"/api/analytics?range={range_key}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["range"] == range_key
        assert "points" in data["series"]["queries"]


# --- Custom From/To analytics window (Issue #88) -----------------------------

def test_parse_custom_analytics_window_validates_input(app_module):
    window, err = app_module.parse_custom_analytics_window("not-a-date", "also-not-a-date")
    assert window is None
    assert "ISO-8601" in err

    now = datetime.now(timezone.utc)
    window, err = app_module.parse_custom_analytics_window(now.isoformat(), (now - timedelta(hours=1)).isoformat())
    assert window is None
    assert "after" in err

    start = now - timedelta(hours=2)
    window, err = app_module.parse_custom_analytics_window(start.isoformat(), now.isoformat())
    assert err is None
    assert window["start"] <= start
    assert window["end"] <= now
    assert window["bucket_count"] > 0
    assert window["use_raw"] is True
    assert "Custom" in window["label"]


def test_parse_custom_analytics_window_clamps_to_retention_floor_and_now(app_module):
    now = datetime.now(timezone.utc)
    far_future = now + timedelta(days=30)
    ancient = now - timedelta(hours=app_module.ANALYTICS_HISTORY_RETENTION_HOURS + 1000)

    window, err = app_module.parse_custom_analytics_window(ancient.isoformat(), far_future.isoformat())
    assert err is None
    retention_floor = now - timedelta(hours=app_module.ANALYTICS_HISTORY_RETENTION_HOURS)
    assert window["start"] >= retention_floor - timedelta(seconds=5)
    assert window["end"] <= now + timedelta(seconds=5)


def test_parse_custom_analytics_window_bucket_tiering(app_module):
    now = datetime.now(timezone.utc)

    short_window, _ = app_module.parse_custom_analytics_window((now - timedelta(hours=1)).isoformat(), now.isoformat())
    assert short_window["bucket_seconds"] == 60
    assert short_window["use_raw"] is True

    wide_window, _ = app_module.parse_custom_analytics_window((now - timedelta(days=10)).isoformat(), now.isoformat())
    assert wide_window["bucket_seconds"] == 21600
    assert wide_window["use_raw"] is False


def test_get_custom_query_volume_series_uses_raw_for_short_span(app_module):
    app_module.init_db()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    start = now - timedelta(hours=1)
    _insert_query(app_module, "fp-custom-a", (start + timedelta(minutes=5)).isoformat(), domain="example.com", device_key="mac:aa", status="Allowed")
    _insert_query(app_module, "fp-custom-b", (start + timedelta(minutes=6)).isoformat(), domain="tracker.example", device_key="mac:bb", status="Blocked")

    window, err = app_module.parse_custom_analytics_window(start.isoformat(), now.isoformat())
    assert err is None
    series = app_module.get_custom_query_volume_series(window)
    assert series["range"] == "custom"
    assert sum(p["count"] or 0 for p in series["points"]) == 2


def test_get_custom_query_volume_series_uses_aggregate_for_long_span(app_module):
    app_module.init_db()
    now = datetime.now(timezone.utc)
    bucket_start = app_module._bucket_floor(now) - timedelta(days=10)
    with app_module.db_lock, closing(app_module.sqlite3.connect(app_module.DB_PATH)) as c:
        c.execute(
            "INSERT INTO analytics_buckets(bucket_start,bucket_seconds,query_count,unique_domains,unique_devices,allowed,blocked,unknown,new_domains,new_devices,top_domains_json,top_devices_json,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (bucket_start.isoformat(), 3600, 7, 2, 1, 5, 2, 0, 0, 0, "[]", "[]", app_module.utcnow()),
        )
        c.commit()

    window, err = app_module.parse_custom_analytics_window((bucket_start - timedelta(hours=1)).isoformat(), now.isoformat())
    assert err is None
    assert window["use_raw"] is False
    series = app_module.get_custom_query_volume_series(window)
    assert sum(p["count"] or 0 for p in series["points"]) >= 7


def test_analytics_payload_custom_window_includes_metadata(app_module):
    app_module.init_db()
    now = datetime.now(timezone.utc)
    window, err = app_module.parse_custom_analytics_window((now - timedelta(hours=3)).isoformat(), now.isoformat())
    assert err is None
    payload = app_module.analytics_payload("custom", window)
    assert payload["range"] == "custom"
    assert "custom_window" in payload
    assert payload["custom_window"]["from"] and payload["custom_window"]["to"]


def test_analytics_api_custom_range_end_to_end(app_module):
    # A raw "+00:00" UTC offset in a query string is ambiguous with a space
    # under application/x-www-form-urlencoded decoding, so these go through
    # query_string=, which the test client encodes correctly, rather than
    # hand-built f-string URLs.
    app_module.init_db()
    client = app_module.app.test_client()
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=5)

    resp = client.get("/api/analytics", query_string={"range": "custom", "from": start.isoformat(), "to": now.isoformat()})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["range"] == "custom"
    assert "custom_window" in data

    bad = client.get("/api/analytics", query_string={"range": "custom", "from": "not-a-date", "to": "also-bad"})
    assert bad.status_code == 400

    backwards = client.get("/api/analytics", query_string={"range": "custom", "from": now.isoformat(), "to": start.isoformat()})
    assert backwards.status_code == 400


def test_analytics_report_pdf_custom_range(app_module):
    app_module.init_db()
    client = app_module.app.test_client()
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=4)

    resp = client.get("/api/analytics/report.pdf", query_string={"range": "custom", "from": start.isoformat(), "to": now.isoformat()})
    assert resp.status_code == 200
    assert resp.data.startswith(b"%PDF-")
    assert "custom-" in resp.headers.get("Content-Disposition", "")

    bad = client.get("/api/analytics/report.pdf", query_string={"range": "custom", "from": "nope", "to": "nope"})
    assert bad.status_code == 400


def test_analytics_interval_custom_range_reflects_real_data(app_module):
    app_module.init_db()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    bucket_start = now - timedelta(minutes=30)
    _insert_query(app_module, "fp-interval-custom", (bucket_start + timedelta(seconds=5)).isoformat(), domain="example.com", device_key="mac:aa", status="Allowed")

    client = app_module.app.test_client()
    window_start = now - timedelta(hours=2)
    resp = client.get(
        "/api/analytics/interval",
        query_string={"range": "custom", "from": window_start.isoformat(), "to": now.isoformat(), "bucket_start": bucket_start.isoformat()},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["range"] == "custom"
    assert data["query_count"] >= 1

    bad = client.get(
        "/api/analytics/interval",
        query_string={"range": "custom", "from": "nope", "to": "nope", "bucket_start": bucket_start.isoformat()},
    )
    assert bad.status_code == 400
