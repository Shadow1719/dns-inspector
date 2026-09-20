"""Issue #73: long-run RAM growth during normal (non-debug-bundle) runtime.

Root cause: `ingest()` called `reconcile_neighbors()` unconditionally on every
poll cycle (every `POLL_SECONDS`, forever). That function's own full
`domains`/`devices` table scan -- a `fetchall()` of every historical row plus
a JSON decode/re-encode of each row's `clients_json` -- has a cost that grows
with total DNS history, which is never pruned. Running an O(all DNS history)
scan roughly every 5-10 seconds for the life of the process, on a table that
only grows, is exactly the kind of repeated large-temporary-allocation churn
that inflates long-run RSS in CPython even without a genuine reference leak.

`extract_identity()` already resolves a query's device key straight to
`"mac:..."` via `neighbor_mac_for_ips()` at ingestion time whenever
neighbors.txt already covers that IP (see `client_info_from_entry()`), so a
domain can only pick up a fresh `"ip:"`-keyed client while that IP is still
absent from the current neighbors.txt snapshot. `reconcile_neighbors()`
therefore has nothing new to migrate between two calls where neighbors.txt
itself hasn't changed -- it only needs to actually re-scan when the neighbors
mapping changes. These tests pin that gating behaviour directly.
"""

import json
import os
import sqlite3
from contextlib import closing


def _write_neighbors(path, ip, mac):
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"{ip} lladdr {mac} REACHABLE\n")


def _insert_domain_with_ip_client(db_path, domain, ip):
    now = "2026-01-01T00:00:00+00:00"
    with closing(sqlite3.connect(db_path)) as c:
        c.execute(
            "INSERT OR REPLACE INTO domains(domain, first_seen, last_seen, requests, clients_json) "
            "VALUES(?, ?, ?, 1, ?)",
            (domain, now, now, json.dumps({f"ip:{ip}": 1})),
        )
        c.commit()


def _domain_clients_json(db_path, domain):
    with closing(sqlite3.connect(db_path)) as c:
        row = c.execute("SELECT clients_json FROM domains WHERE domain=?", (domain,)).fetchone()
    return json.loads(row[0])


def test_reconcile_neighbors_migrates_ip_keyed_clients_on_first_pass(app_module, initialised_db):
    domain = "example-issue73-first.test"
    ip = "192.168.77.10"
    mac = "aa:bb:cc:dd:ee:01"

    _write_neighbors(app_module.NEIGHBORS_PATH, ip, mac)
    # Force a fresh reload/reconciliation baseline regardless of what earlier
    # tests in this session already reconciled.
    app_module.load_neighbors(force=True)
    app_module._neighbors_reconciled_mtime = None
    _insert_domain_with_ip_client(app_module.DB_PATH, domain, ip)

    app_module.reconcile_neighbors()

    assert _domain_clients_json(app_module.DB_PATH, domain) == {f"mac:{mac}": 1}


def test_reconcile_neighbors_skips_full_scan_when_neighbors_unchanged(app_module, initialised_db):
    """The actual Issue #73 regression guard: a second call with an unchanged
    neighbors.txt must not re-run the full domains/devices scan at all. We
    prove this by resetting a domain back to an `"ip:"`-keyed client after the
    first (real) reconciliation pass and confirming a second pass -- with
    neighbors.txt untouched -- leaves it alone instead of migrating it again."""
    domain = "example-issue73-skip.test"
    ip = "192.168.77.11"
    mac = "aa:bb:cc:dd:ee:02"

    _write_neighbors(app_module.NEIGHBORS_PATH, ip, mac)
    app_module.load_neighbors(force=True)
    app_module._neighbors_reconciled_mtime = None
    _insert_domain_with_ip_client(app_module.DB_PATH, domain, ip)

    app_module.reconcile_neighbors()
    assert _domain_clients_json(app_module.DB_PATH, domain) == {f"mac:{mac}": 1}

    # Simulate a domain that (somehow) still carries a stale ip:-keyed client
    # without any change to neighbors.txt. A real full scan would migrate it;
    # the bounded/gated implementation must not even look at it.
    _insert_domain_with_ip_client(app_module.DB_PATH, domain, ip)
    assert _domain_clients_json(app_module.DB_PATH, domain) == {f"ip:{ip}": 1}

    app_module.reconcile_neighbors()

    assert _domain_clients_json(app_module.DB_PATH, domain) == {f"ip:{ip}": 1}, (
        "reconcile_neighbors() re-scanned the domains table even though "
        "neighbors.txt did not change -- this is the unbounded per-tick scan "
        "that caused Issue #73's long-run RAM growth"
    )


def test_reconcile_neighbors_rescans_once_neighbors_file_actually_changes(app_module, initialised_db):
    """Correctness check: the gate must not permanently disable reconciliation
    -- once neighbors.txt is genuinely updated, the next call migrates again."""
    domain = "example-issue73-rescan.test"
    ip = "192.168.77.12"
    mac = "aa:bb:cc:dd:ee:03"

    _write_neighbors(app_module.NEIGHBORS_PATH, ip, mac)
    app_module.load_neighbors(force=True)
    app_module._neighbors_reconciled_mtime = None
    _insert_domain_with_ip_client(app_module.DB_PATH, domain, ip)

    app_module.reconcile_neighbors()
    assert _domain_clients_json(app_module.DB_PATH, domain) == {f"mac:{mac}": 1}

    _insert_domain_with_ip_client(app_module.DB_PATH, domain, ip)
    assert _domain_clients_json(app_module.DB_PATH, domain) == {f"ip:{ip}": 1}

    # Genuinely change neighbors.txt. The mtime is forced forward by a full
    # 5 seconds (rather than relying on wall-clock drift during the test) so
    # this is deterministic regardless of the filesystem's mtime resolution.
    old_mtime = os.path.getmtime(app_module.NEIGHBORS_PATH)
    other_mac = "aa:bb:cc:dd:ee:04"
    _write_neighbors(app_module.NEIGHBORS_PATH, ip, other_mac)
    os.utime(app_module.NEIGHBORS_PATH, (old_mtime + 5, old_mtime + 5))

    app_module.reconcile_neighbors()

    assert _domain_clients_json(app_module.DB_PATH, domain) == {f"mac:{other_mac}": 1}
