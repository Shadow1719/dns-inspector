"""Foundation backend behavior: bounded enrichment queue with retry backoff,
and device/IP retention -- both reimplemented directly in app.py instead of
depending on the historical build-time patch chain.
"""

import time

from conftest import assert_all_closed


def test_status_from_counts_table(app_module):
    assert app_module._status_from_counts(0, 0) == ("Unknown", "unknown")
    assert app_module._status_from_counts(0, 3) == ("Allowed", "allowed")
    assert app_module._status_from_counts(2, 0) == ("Blocked", "blocked")
    assert app_module._status_from_counts(2, 3) == ("Mixed", "mixed")


def test_enrichment_retry_allowed_then_blocked_after_mark(app_module):
    app_module.init_db()
    domain = "tracker.example.com"
    assert app_module._enrichment_retry_allowed(domain) is True

    now = time.time()
    app_module._mark_enrichment_attempt(domain, now_ts=now)
    assert app_module._enrichment_retry_allowed(domain, now_ts=now + 1) is False

    after_cooldown = now + app_module.ENRICHMENT_RETRY_HOURS * 3600.0 + 1
    assert app_module._enrichment_retry_allowed(domain, now_ts=after_cooldown) is True


def test_enrichment_retry_state_persists_across_process_restart(app_module):
    # A fresh process must re-read the persisted next_attempt_at from SQLite
    # instead of retrying immediately just because its in-memory cache is empty.
    app_module.init_db()
    domain = "cold-start.example.com"
    now = time.time()
    app_module._mark_enrichment_attempt(domain, now_ts=now)

    # Simulate process restart: clear the in-memory mirrors only.
    app_module._enrichment_retry_until.clear()
    app_module._enrichment_retry_loaded.clear()

    assert app_module._enrichment_retry_allowed(domain, now_ts=now + 1) is False


def test_queue_domain_enrichment_dedupes_inflight_domain(app_module):
    app_module.init_db()
    domain = "dup.example.com"
    assert app_module._queue_domain_enrichment(domain) is True
    # Already queued: a second call for the same domain must not double-queue it.
    assert app_module._queue_domain_enrichment(domain) is False
    assert app_module._enrichment_queue.qsize() == 1


def test_queue_domain_enrichment_skips_domain_within_retry_cooldown(app_module):
    app_module.init_db()
    domain = "cooldown.example.com"
    app_module._mark_enrichment_attempt(domain)
    assert app_module._queue_domain_enrichment(domain) is False
    assert app_module._enrichment_queue.qsize() == 0


def test_prune_stale_device_ips_removes_only_expired_rows(app_module, track_connections):
    app_module.init_db()
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    fresh = now.isoformat()
    stale = (now - timedelta(hours=app_module.DEVICE_IP_RETENTION_HOURS + 1)).isoformat()

    with app_module.db_lock, app_module.closing(app_module.sqlite3.connect(app_module.DB_PATH)) as c:
        c.execute(
            "INSERT INTO device_ips(device_key,ip,first_seen,last_seen,requests) VALUES(?,?,?,?,1)",
            ("mac:aa", "192.168.1.10", stale, stale),
        )
        c.execute(
            "INSERT INTO device_ips(device_key,ip,first_seen,last_seen,requests) VALUES(?,?,?,?,1)",
            ("mac:bb", "192.168.1.20", fresh, fresh),
        )
        c.commit()

    track_connections.clear()
    removed = app_module._prune_stale_device_ips()
    assert removed == 1
    assert_all_closed(track_connections)

    with app_module.closing(app_module.sqlite3.connect(app_module.DB_PATH)) as c:
        remaining = [r[0] for r in c.execute("SELECT ip FROM device_ips").fetchall()]
    assert remaining == ["192.168.1.20"]


def test_prune_stale_device_ips_cutoff_is_iso8601_not_epoch(app_module):
    # Regression guard for a real bug found in the historical reference patch:
    # comparing an ISO-8601 TEXT column against a raw time.time() float never
    # matches under SQLite's TEXT-affinity comparison rules, so nothing was
    # ever deleted. The cutoff must be an ISO-8601 string.
    app_module.init_db()
    ancient = "2000-01-01T00:00:00+00:00"
    with app_module.db_lock, app_module.closing(app_module.sqlite3.connect(app_module.DB_PATH)) as c:
        c.execute(
            "INSERT INTO device_ips(device_key,ip,first_seen,last_seen,requests) VALUES(?,?,?,?,1)",
            ("mac:cc", "192.168.1.30", ancient, ancient),
        )
        c.commit()

    removed = app_module._prune_stale_device_ips()
    assert removed == 1
