"""Regression coverage for the foundation SQLite connection-lifetime fix.

sqlite3.Connection.__enter__/__exit__ only commit or roll back the current
transaction -- they do not close the connection. Every `with sqlite3.connect(...)
as c:` block in the historical 0.7.x code therefore leaked one native SQLite
file descriptor per call, including inside `_open_trackerdb()`. The fix wraps
every call site in `contextlib.closing()` so the connection is always closed
on exit.
"""

from pathlib import Path

from conftest import assert_all_closed

APP_SOURCE = Path(__file__).resolve().parent.parent / "app.py"


def test_every_sqlite_connect_call_is_wrapped_in_closing():
    text = APP_SOURCE.read_text(encoding="utf-8")
    unwrapped = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if "sqlite3.connect(" not in line:
            continue
        stripped = line.strip()
        if stripped.startswith("def _open_trackerdb"):
            continue
        if stripped == "c = sqlite3.connect(path)":
            continue  # the _open_trackerdb() body itself returns a bare connection
        if "closing(sqlite3.connect(" in line:
            continue
        unwrapped.append((lineno, stripped))
    assert not unwrapped, (
        "Found sqlite3.connect() call(s) not wrapped in contextlib.closing(), "
        f"so they would never be closed: {unwrapped}"
    )


def test_every_open_trackerdb_call_site_is_wrapped_in_closing():
    text = APP_SOURCE.read_text(encoding="utf-8")
    checked = 0
    for lineno, line in enumerate(text.splitlines(), start=1):
        if "_open_trackerdb(" not in line:
            continue
        if line.strip().startswith("def _open_trackerdb"):
            continue
        checked += 1
        assert "closing(_open_trackerdb(" in line, (
            f"Line {lineno} calls _open_trackerdb() without wrapping it in "
            f"contextlib.closing(): {line.strip()}"
        )
    assert checked >= 2, "expected to find the trackerdb_ready()/refresh_trackerdb() call sites"


def test_init_db_closes_its_connection(app_module, track_connections):
    app_module.init_db()
    assert track_connections, "init_db() should open at least one connection"
    assert_all_closed(track_connections)


def test_execute_sql_file_preserves_dump_transaction_boundary(app_module, tmp_path):
    # SQLite .dump files explicitly wrap the schema/data in BEGIN/COMMIT.
    # Regression guard for the streaming importer: executescript() would
    # implicitly commit before each statement and make the final COMMIT fail.
    dump = tmp_path / "trackerdb.sql"
    dump.write_text(
        """PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE tracker_domains(domain TEXT);
INSERT INTO tracker_domains(domain) VALUES ('ads.example.com');
COMMIT;
""",
        encoding="utf-8",
    )

    import sqlite3
    from contextlib import closing

    db = tmp_path / "trackerdb.sqlite"
    with closing(sqlite3.connect(db)) as c:
        app_module._execute_sql_file(c, dump)
        assert c.execute("SELECT domain FROM tracker_domains").fetchall() == [("ads.example.com",)]
        assert c.in_transaction is False


def test_trackerdb_ready_closes_its_connection(app_module, track_connections):
    # Build a minimal valid trackerdb file the way refresh_trackerdb() would.
    import sqlite3
    from contextlib import closing

    with closing(sqlite3.connect(app_module.TRACKERDB_PATH)) as seed:
        seed.execute("CREATE TABLE tracker_domains(domain TEXT)")
        seed.commit()

    track_connections.clear()
    assert app_module.trackerdb_ready() is True
    assert track_connections, "trackerdb_ready() should open a connection via _open_trackerdb()"
    assert_all_closed(track_connections)


def test_tracker_lookup_closes_its_connection(app_module, track_connections):
    import sqlite3
    from contextlib import closing

    with closing(sqlite3.connect(app_module.TRACKERDB_PATH)) as seed:
        seed.executescript(
            """
            CREATE TABLE categories(id INTEGER PRIMARY KEY, name TEXT);
            CREATE TABLE companies(id INTEGER PRIMARY KEY, name TEXT, description TEXT, website_url TEXT, country TEXT);
            CREATE TABLE trackers(id INTEGER PRIMARY KEY, name TEXT, category_id INTEGER, website_url TEXT, company_id INTEGER);
            CREATE TABLE tracker_domains(domain TEXT, tracker INTEGER);
            INSERT INTO categories VALUES (1, 'Advertising');
            INSERT INTO companies VALUES (1, 'Example Co', '', '', '');
            INSERT INTO trackers VALUES (1, 'Example Tracker', 1, '', 1);
            INSERT INTO tracker_domains VALUES ('ads.example.com', 1);
            """
        )
        seed.commit()

    track_connections.clear()
    result = app_module.tracker_lookup("ads.example.com")
    assert result.get("name") == "Example Tracker"
    assert track_connections
    assert_all_closed(track_connections)
