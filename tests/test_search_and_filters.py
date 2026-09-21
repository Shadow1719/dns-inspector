"""Foundation query behavior reimplemented from the 0.7.14 feature patch and
the perf patch: friendly device labels in the Overview filter dropdown,
partial/device/IP search resolution, and SQL-pushed-down status filtering.
"""

import json


def _insert_domain(app_module, conn, domain, requests=1, blocked=0, allowed=0, unknown=0, first_seen=None, clients=None):
    now = first_seen or app_module.utcnow()
    conn.execute(
        "INSERT INTO domains(domain,first_seen,last_seen,requests,clients_json,blocked_requests,allowed_requests,unknown_requests,last_status,last_reason,current_status,current_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (domain, now, now, requests, json.dumps(clients or {}), blocked, allowed, unknown, "Unknown", "", "Unknown", ""),
    )


def test_get_filter_options_uses_real_device_label(app_module):
    app_module.init_db()
    with app_module.closing(app_module.sqlite3.connect(app_module.DB_PATH)) as c:
        c.execute(
            "INSERT INTO devices(device_key,name,hostname,mac,vendor,device_type,icon,confidence,source,first_seen,last_seen,request_count) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            ("mac:aa:bb", "", "kitchen-echo.lan", "aa:bb:cc:dd:ee:ff", "Amazon", "IoT / Unknown", "📦", "high", "test", app_module.utcnow(), app_module.utcnow(), 5),
        )
        c.commit()

    options = app_module.get_filter_options()
    device = next(d for d in options["devices"] if d["value"] == "mac:aa:bb")
    # real_device_label() must prefer the hostname over the vendor/identifier.
    assert device["label"] == "kitchen-echo.lan"


def test_resolve_search_domain_exact_match_wins(app_module):
    app_module.init_db()
    with app_module.closing(app_module.sqlite3.connect(app_module.DB_PATH)) as c:
        _insert_domain(app_module, c, "example.com")
        _insert_domain(app_module, c, "sub.example.com")
        c.commit()

    assert app_module._resolve_search_domain("example.com") == "example.com"


def test_resolve_search_domain_partial_match(app_module):
    app_module.init_db()
    with app_module.closing(app_module.sqlite3.connect(app_module.DB_PATH)) as c:
        _insert_domain(app_module, c, "ads.trackers.example.net", requests=10)
        c.commit()

    assert app_module._resolve_search_domain("trackers") == "ads.trackers.example.net"


def test_resolve_search_domain_by_device_identity(app_module):
    app_module.init_db()
    with app_module.closing(app_module.sqlite3.connect(app_module.DB_PATH)) as c:
        c.execute(
            "INSERT INTO devices(device_key,name,hostname,mac,vendor,device_type,icon,confidence,source,first_seen,last_seen,request_count) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            ("mac:11:22", "Living Room TV", "", "11:22:33:44:55:66", "Sony", "TV", "📺", "high", "test", app_module.utcnow(), app_module.utcnow(), 1),
        )
        _insert_domain(app_module, c, "streaming.example.com", requests=3, clients={"mac:11:22": 3})
        _insert_domain(app_module, c, "unrelated.example.com", requests=100, clients={"mac:99:99": 100})
        c.commit()

    assert app_module._resolve_search_domain("living room") == "streaming.example.com"


def test_resolve_search_domain_empty_query_returns_empty(app_module):
    app_module.init_db()
    assert app_module._resolve_search_domain("") == ""
    assert app_module._resolve_search_domain("   ") == ""


def test_get_recent_status_filter_uses_sql_pushdown(app_module):
    app_module.init_db()
    with app_module.closing(app_module.sqlite3.connect(app_module.DB_PATH)) as c:
        _insert_domain(app_module, c, "blocked.example.com", blocked=5, allowed=0)
        _insert_domain(app_module, c, "allowed.example.com", blocked=0, allowed=5)
        _insert_domain(app_module, c, "mixed.example.com", blocked=2, allowed=3)
        c.commit()

    result = app_module.get_recent(status_filter="Blocked")
    domains = [r["domain"] for r in result["rows"]]
    assert domains == ["blocked.example.com"]
    assert result["meta"]["status_counts"] == {"All": 3, "Unknown": 0, "Allowed": 1, "Blocked": 1, "Mixed": 1}


def test_get_recent_new_only_filter(app_module):
    from datetime import datetime, timedelta, timezone

    app_module.init_db()
    old = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    with app_module.closing(app_module.sqlite3.connect(app_module.DB_PATH)) as c:
        _insert_domain(app_module, c, "old.example.com", first_seen=old)
        _insert_domain(app_module, c, "new.example.com")
        c.commit()

    result = app_module.get_recent(new_only=True)
    domains = [r["domain"] for r in result["rows"]]
    assert domains == ["new.example.com"]
