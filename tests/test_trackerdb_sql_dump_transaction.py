"""Regression test for a real-DEV TrackerDB refresh failure:

    TrackerDB refresh error: OperationalError('cannot commit - no transaction is active')

`_execute_sql_file()` parses a `sqlite3 .dump`-style SQL file incrementally
(one complete statement at a time) to avoid holding the whole snapshot in RAM,
and previously ran each statement through `conn.executescript()`. `executescript()`
implicitly commits any pending transaction before it runs, so the dump's own
`BEGIN TRANSACTION;` ... `COMMIT;` wrapper was silently split into separate
auto-committed statements, leaving the final `COMMIT;` with nothing open to
commit. This exercises `_execute_sql_file()` against a small fixture dump that
uses that exact wrapper, matching the real TrackerDB snapshot format.
"""

import sqlite3

import pytest

import app as dns_inspector

DUMP_WITH_TRANSACTION_WRAPPER = """\
BEGIN TRANSACTION;
CREATE TABLE trackers (id INTEGER PRIMARY KEY, name TEXT);
INSERT INTO trackers VALUES(1,'example-tracker');
INSERT INTO trackers VALUES(2,'another-tracker');
COMMIT;
"""


@pytest.fixture()
def sql_dump_path(tmp_path):
    path = tmp_path / "trackerdb.sql"
    path.write_text(DUMP_WITH_TRANSACTION_WRAPPER, encoding="utf-8")
    return path


def test_execute_sql_file_honours_dump_transaction_wrapper(tmp_path, sql_dump_path):
    db_path = tmp_path / "trackerdb.sqlite"
    conn = sqlite3.connect(str(db_path))
    try:
        # Previously raised sqlite3.OperationalError('cannot commit - no
        # transaction is active') at the dump's own COMMIT statement.
        dns_inspector._execute_sql_file(conn, str(sql_dump_path))
    finally:
        conn.close()

    verify = sqlite3.connect(str(db_path))
    try:
        rows = verify.execute("SELECT id, name FROM trackers ORDER BY id").fetchall()
    finally:
        verify.close()
    assert rows == [(1, "example-tracker"), (2, "another-tracker")]


def test_execute_sql_file_data_is_durable_without_extra_commit(tmp_path, sql_dump_path):
    """The dump's own COMMIT must be the thing that persists the data --
    `_execute_sql_file()` must not rely on a caller-side `conn.commit()`."""
    db_path = tmp_path / "trackerdb.sqlite"
    conn = sqlite3.connect(str(db_path))
    dns_inspector._execute_sql_file(conn, str(sql_dump_path))
    conn.close()  # closing without an explicit commit() would discard an open transaction

    verify = sqlite3.connect(str(db_path))
    try:
        count = verify.execute("SELECT COUNT(*) FROM trackers").fetchone()[0]
    finally:
        verify.close()
    assert count == 2
