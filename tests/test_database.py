"""The database boundary: `init_db()` owns schema creation and migration."""

import sqlite3
from contextlib import closing

# Tables the application depends on at runtime. This is the schema contract the
# rest of the codebase is written against.
EXPECTED_TABLES = {
    "adguard_status_cache",
    "client_cache",
    "device_ips",
    "devices",
    "dns_records_cache",
    "domain_destination_ips",
    "domains",
    "enrichment_attempts",
    "hostname_cache",
    "ip_ping_status",
    "mac_vendor_cache",
    "netify_cache",
    "netify_ip_cache",
    "processed_queries",
    "rdap_cache",
}


def _table_names(db_path):
    with closing(sqlite3.connect(db_path)) as conn:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    return {row[0] for row in rows}


def _column_names(db_path, table):
    with closing(sqlite3.connect(db_path)) as conn:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {row[1] for row in rows}


def test_init_db_creates_the_expected_schema(initialised_db):
    assert EXPECTED_TABLES.issubset(_table_names(initialised_db))


def test_init_db_is_idempotent(app_module, initialised_db):
    """Running initialisation twice must not fail or change the schema."""
    before = _table_names(initialised_db)
    app_module.init_db()
    app_module.init_db()
    assert _table_names(initialised_db) == before


def test_migrated_columns_are_present(initialised_db):
    """Columns added by `add_column_if_missing` exist after initialisation."""
    domains = _column_names(initialised_db, "domains")
    assert {"current_status", "current_reason", "blocked_requests",
            "allowed_requests", "unknown_requests"}.issubset(domains)

    clients = _column_names(initialised_db, "client_cache")
    assert {"device_key", "mac", "hostname"}.issubset(clients)


def test_add_column_if_missing_does_not_duplicate(app_module, initialised_db):
    """Re-adding an existing column is a no-op rather than an error."""
    with closing(sqlite3.connect(initialised_db)) as conn:
        app_module.add_column_if_missing(
            conn, "domains", "current_status", "TEXT NOT NULL DEFAULT 'Unknown'"
        )
        conn.commit()
    columns = [c for c in _column_names(initialised_db, "domains")
               if c == "current_status"]
    assert len(columns) == 1


def test_domains_table_round_trip(app_module, initialised_db):
    """A domain written through the real schema reads back intact."""
    now = app_module.utcnow()
    with closing(sqlite3.connect(initialised_db)) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO domains"
            "(domain,first_seen,last_seen,requests,clients_json,blocked_requests,"
            "allowed_requests,unknown_requests,last_status)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            ("round-trip.test", now, now, 3, '{"192.0.2.10": 3}', 1, 2, 0, "Mixed"),
        )
        conn.commit()
        row = conn.execute(
            "SELECT requests, blocked_requests, allowed_requests, last_status"
            " FROM domains WHERE domain=?",
            ("round-trip.test",),
        ).fetchone()
    assert row == (3, 1, 2, "Mixed")


def test_indexes_required_by_background_work_exist(initialised_db):
    """Background pruning and ping scheduling rely on these indexes."""
    with closing(sqlite3.connect(initialised_db)) as conn:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        ).fetchall()
    names = {row[0] for row in rows}
    assert {"idx_processed_seen", "idx_device_ips_last_seen",
            "idx_ip_ping_status_last_checked"}.issubset(names)
