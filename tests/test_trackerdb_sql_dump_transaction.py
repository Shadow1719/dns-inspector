"""Regression guard for a real production TrackerDB refresh error (Issue #61).

Real DEV debug evidence showed a TrackerDB refresh event logging
`cannot commit - no transaction is active`. Root cause: a `sqlite3 .dump`
snapshot wraps its INSERTs in its own literal `BEGIN TRANSACTION;`/`COMMIT;`
statements. `_execute_sql_file()` ran each complete statement in the dump
through its own `conn.executescript()` call, and `executescript()` always
issues an implicit COMMIT *before* running the statement it's given -- so by
the time the dump's own trailing `COMMIT;` statement ran, the transaction the
dump's own `BEGIN TRANSACTION;` had opened was already implicitly committed
away by the *next* chunk's own executescript() call, and SQLite raised
`OperationalError: cannot commit - no transaction is active` for the
now-orphaned `COMMIT;`. `_execute_sql_dump_statement()` now skips the dump's
own transaction-control statements entirely, since `executescript()` already
commits per call.
"""

from contextlib import closing


def test_execute_sql_file_imports_a_begin_commit_wrapped_dump_without_raising(app_module, tmp_path):
    dump = tmp_path / "dump.sql"
    dump.write_text(
        "BEGIN TRANSACTION;\n"
        "CREATE TABLE tracker_domains(domain TEXT PRIMARY KEY);\n"
        "INSERT INTO tracker_domains VALUES('example.com');\n"
        "INSERT INTO tracker_domains VALUES('example.net');\n"
        "COMMIT;\n"
    )
    db_path = tmp_path / "trackerdb.sqlite"
    # `with conn as c:` mirrors refresh_trackerdb()'s own usage exactly --
    # this is the code path where "cannot commit - no transaction is active"
    # used to surface.
    with app_module._open_trackerdb(str(db_path)) as conn:
        app_module._execute_sql_file(conn, str(dump))

    with closing(app_module._open_trackerdb(str(db_path))) as conn:
        rows = conn.execute("SELECT domain FROM tracker_domains ORDER BY domain").fetchall()
    assert rows == [("example.com",), ("example.net",)]


def test_sql_dump_transaction_control_regex_matches_begin_and_commit_variants(app_module):
    matches = [
        "BEGIN TRANSACTION;", "BEGIN;", "begin immediate transaction;",
        "COMMIT;", "COMMIT TRANSACTION;", "END;", "END TRANSACTION;",
    ]
    for stmt in matches:
        assert app_module._SQL_DUMP_TRANSACTION_CONTROL_RE.match(stmt), stmt


def test_sql_dump_transaction_control_regex_does_not_match_real_statements(app_module):
    non_matches = [
        "INSERT INTO tracker_domains VALUES('example.com');",
        "CREATE TABLE tracker_domains(domain TEXT PRIMARY KEY);",
        "-- a comment mentioning BEGIN and COMMIT, not a real statement\n",
    ]
    for stmt in non_matches:
        assert not app_module._SQL_DUMP_TRANSACTION_CONTROL_RE.match(stmt), stmt
