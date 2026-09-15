from dnsinspector.core.runtime import *
from contextlib import closing
from datetime import datetime, timezone, timedelta
import os, json, time, threading, queue, sqlite3, re, hashlib, socket, subprocess, shutil, zipfile, io, platform, gc, sys
import requests

def add_column_if_missing(c, table, column, ddl):
    cols = {row[1] for row in c.execute(f'PRAGMA table_info({table})').fetchall()}
    if column not in cols:
        c.execute(f'ALTER TABLE {table} ADD COLUMN {column} {ddl}')

def db_connect(path=DB_PATH):
    """Open a short-lived SQLite connection with a bounded busy timeout."""
    c = sqlite3.connect(path, timeout=30.0)
    c.execute('PRAGMA busy_timeout=30000')
    if path == DB_PATH:
        c.execute('PRAGMA synchronous=NORMAL')
    return c

def init_db():
    with db_lock, closing(db_connect(DB_PATH)) as c:
        c.execute('PRAGMA journal_mode=WAL')
        c.execute('PRAGMA synchronous=NORMAL')
        c.execute("CREATE TABLE IF NOT EXISTS domains(\n            domain TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT,\n            requests INTEGER NOT NULL DEFAULT 0, clients_json TEXT NOT NULL DEFAULT '{}',\n            classification TEXT NOT NULL DEFAULT 'Unknown', company TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '', blocked_requests INTEGER NOT NULL DEFAULT 0, allowed_requests INTEGER NOT NULL DEFAULT 0, unknown_requests INTEGER NOT NULL DEFAULT 0, last_status TEXT NOT NULL DEFAULT 'Unknown', last_reason TEXT NOT NULL DEFAULT '')")
        c.execute('CREATE TABLE IF NOT EXISTS rdap_cache(\n            domain TEXT PRIMARY KEY, fetched_at TEXT NOT NULL, json TEXT NOT NULL)')
        c.execute("CREATE TABLE IF NOT EXISTS mac_vendor_cache(\n            mac TEXT PRIMARY KEY, fetched_at TEXT NOT NULL, vendor TEXT NOT NULL DEFAULT '')")
        c.execute("CREATE TABLE IF NOT EXISTS hostname_cache(\n            ip TEXT PRIMARY KEY, fetched_at TEXT NOT NULL, hostname TEXT NOT NULL DEFAULT '')")
        c.execute("CREATE TABLE IF NOT EXISTS netify_cache(\n            domain TEXT PRIMARY KEY, fetched_at TEXT NOT NULL, json TEXT NOT NULL DEFAULT '{}')")
        c.execute("CREATE TABLE IF NOT EXISTS netify_ip_cache(\n            ip TEXT PRIMARY KEY, fetched_at TEXT NOT NULL, json TEXT NOT NULL DEFAULT '{}')")
        c.execute("CREATE TABLE IF NOT EXISTS dns_records_cache(\n            domain TEXT PRIMARY KEY, fetched_at TEXT NOT NULL, json TEXT NOT NULL DEFAULT '{}')")
        c.execute("CREATE TABLE IF NOT EXISTS client_cache(\n            identifier TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT '',\n            last_seen TEXT NOT NULL, request_count INTEGER NOT NULL DEFAULT 0, info_json TEXT NOT NULL DEFAULT '{}',\n            device_key TEXT NOT NULL DEFAULT '', mac TEXT NOT NULL DEFAULT '', hostname TEXT NOT NULL DEFAULT '')")
        add_column_if_missing(c, 'client_cache', 'device_key', "TEXT NOT NULL DEFAULT ''")
        add_column_if_missing(c, 'client_cache', 'mac', "TEXT NOT NULL DEFAULT ''")
        add_column_if_missing(c, 'client_cache', 'hostname', "TEXT NOT NULL DEFAULT ''")
        c.execute("CREATE TABLE IF NOT EXISTS devices(\n            device_key TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', hostname TEXT NOT NULL DEFAULT '',\n            mac TEXT NOT NULL DEFAULT '', device_type TEXT NOT NULL DEFAULT 'IoT / Unknown', icon TEXT NOT NULL DEFAULT '📦',\n            confidence TEXT NOT NULL DEFAULT 'low', source TEXT NOT NULL DEFAULT '', first_seen TEXT NOT NULL DEFAULT '', last_seen TEXT NOT NULL,\n            request_count INTEGER NOT NULL DEFAULT 0, info_json TEXT NOT NULL DEFAULT '{}')")
        add_column_if_missing(c, 'devices', 'vendor', "TEXT NOT NULL DEFAULT ''")
        add_column_if_missing(c, 'devices', 'first_seen', "TEXT NOT NULL DEFAULT ''")
        add_column_if_missing(c, 'domains', 'blocked_requests', 'INTEGER NOT NULL DEFAULT 0')
        add_column_if_missing(c, 'domains', 'allowed_requests', 'INTEGER NOT NULL DEFAULT 0')
        add_column_if_missing(c, 'domains', 'unknown_requests', 'INTEGER NOT NULL DEFAULT 0')
        add_column_if_missing(c, 'domains', 'last_status', "TEXT NOT NULL DEFAULT 'Unknown'")
        add_column_if_missing(c, 'domains', 'last_reason', "TEXT NOT NULL DEFAULT ''")
        c.execute("UPDATE devices SET first_seen=COALESCE(NULLIF(first_seen,''), last_seen) WHERE first_seen=''")
        c.execute('CREATE TABLE IF NOT EXISTS device_ips(\n            device_key TEXT NOT NULL, ip TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,\n            requests INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(device_key,ip))')
        c.execute('CREATE TABLE IF NOT EXISTS processed_queries(\n            fingerprint TEXT PRIMARY KEY, seen_at TEXT NOT NULL, status_counted INTEGER NOT NULL DEFAULT 0)')
        add_column_if_missing(c, 'processed_queries', 'status_counted', 'INTEGER NOT NULL DEFAULT 0')
        add_column_if_missing(c, 'domains', 'current_status', "TEXT NOT NULL DEFAULT 'Unknown'")
        add_column_if_missing(c, 'domains', 'current_reason', "TEXT NOT NULL DEFAULT ''")
        c.execute("CREATE TABLE IF NOT EXISTS adguard_status_cache(\n            domain TEXT PRIMARY KEY, fetched_at TEXT NOT NULL, status TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '')")
        c.execute('CREATE INDEX IF NOT EXISTS idx_processed_seen ON processed_queries(seen_at)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_device_ips_last_seen ON device_ips(last_seen)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_domains_first_seen ON domains(first_seen DESC)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_domains_requests ON domains(requests DESC)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_domains_status ON domains(blocked_requests, allowed_requests)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_devices_requests ON devices(request_count DESC)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_device_ips_ip_last_seen ON device_ips(ip, last_seen DESC)')
        c.execute("CREATE TABLE IF NOT EXISTS ip_ping_status(\n            ip TEXT PRIMARY KEY,\n            last_checked REAL NOT NULL,\n            online INTEGER NOT NULL,\n            latency_ms REAL,\n            error TEXT NOT NULL DEFAULT '')")
        c.execute('CREATE INDEX IF NOT EXISTS idx_ip_ping_status_last_checked ON ip_ping_status(last_checked)')
        c.execute('CREATE TABLE IF NOT EXISTS enrichment_attempts(\n            domain TEXT PRIMARY KEY,\n            attempted_at REAL NOT NULL,\n            next_attempt_at REAL NOT NULL)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_enrichment_attempt_next ON enrichment_attempts(next_attempt_at)')
        c.commit()

def _sqlite_unistr(value):
    if value is None:
        return None
    text = str(value)
    out = []
    i = 0
    while i < len(text):
        if text[i] != '\\':
            out.append(text[i]); i += 1; continue
        if i + 1 >= len(text):
            out.append('\\'); i += 1; continue
        nxt = text[i + 1]
        if nxt == '\\':
            out.append('\\'); i += 2; continue
        digits = None; step = 0
        if nxt in 'uU':
            width = 4 if nxt == 'u' else 8; digits = text[i + 2:i + 2 + width]; step = 2 + width
        elif nxt == '+':
            digits = text[i + 2:i + 8]; step = 8
        else:
            digits = text[i + 1:i + 5]; step = 4
        expected_len = 6 if nxt == '+' else 8 if nxt == 'U' else 4
        if digits and len(digits) == expected_len and all(ch in '0123456789abcdefABCDEF' for ch in digits):
            try:
                codepoint = int(digits, 16)
                if 0 <= codepoint <= 1114111:
                    out.append(chr(codepoint)); i += step; continue
            except (ValueError, OverflowError):
                pass
        out.append('\\'); i += 1
    return ''.join(out)

def _open_trackerdb(path):
    c = sqlite3.connect(path, timeout=30.0)
    c.execute('PRAGMA busy_timeout=30000')
    if sqlite3.sqlite_version_info < (3, 50, 0):
        c.create_function('unistr', 1, _sqlite_unistr)
    return c

def trackerdb_ready():
    if not os.path.exists(TRACKERDB_PATH): return False
    try:
        with _open_trackerdb(TRACKERDB_PATH) as c:
            c.execute('SELECT 1 FROM tracker_domains LIMIT 1').fetchone()
        return True
    except Exception:
        return False

def trackerdb_refresh_needed():
    return not trackerdb_ready() or time.time() - os.path.getmtime(TRACKERDB_PATH) > TRACKERDB_REFRESH_HOURS * 3600

def _execute_sql_file(conn, path):
    statement = []
    with open(path, 'r', encoding='utf-8-sig', errors='replace') as f:
        for raw_line in f:
            statement.append(raw_line)
            candidate = ''.join(statement)
            if sqlite3.complete_statement(candidate):
                conn.execute(candidate); statement.clear()
    if statement and ''.join(statement).strip(): conn.execute(''.join(statement))

def refresh_trackerdb(force=False):
    if not force and (not trackerdb_refresh_needed()): return
    tmp, newdb = (TRACKERDB_PATH + '.download', TRACKERDB_PATH + '.new')
    try:
        print('Downloading TrackerDB snapshot...', flush=True)
        with requests.get(TRACKERDB_URL, timeout=60, stream=True) as r:
            r.raise_for_status()
            with open(tmp, 'wb') as f:
                for chunk in r.iter_content(chunk_size=TRACKERDB_DOWNLOAD_CHUNK_SIZE):
                    if chunk: f.write(chunk)
        if os.path.exists(newdb): os.remove(newdb)
        with _open_trackerdb(newdb) as c:
            _execute_sql_file(c, tmp); c.execute('PRAGMA journal_mode=DELETE')
        os.replace(newdb, TRACKERDB_PATH)
        try: os.remove(tmp)
        except FileNotFoundError: pass
        print('TrackerDB ready.', flush=True)
    except Exception as e:
        print('TrackerDB refresh error:', repr(e), flush=True)
        for p in (tmp, newdb):
            try:
                if os.path.exists(p): os.remove(p)
            except OSError: pass

def tracker_lookup(domain):
    if not trackerdb_ready(): return {}
    labels = domain.rstrip('.').lower().split('.')
    candidates = ['.'.join(labels[i:]) for i in range(len(labels))]
    try:
        with sqlite3.connect(TRACKERDB_PATH) as c:
            for candidate in candidates:
                row = c.execute("SELECT td.domain,t.name,cat.name,t.website_url,t.company_id,\n                    coalesce(co.name,''),coalesce(co.description,''),coalesce(co.website_url,''),coalesce(co.country,'')\n                    FROM tracker_domains td JOIN trackers t ON t.id=td.tracker LEFT JOIN categories cat ON cat.id=t.category_id\n                    LEFT JOIN companies co ON co.id=t.company_id WHERE td.domain=? LIMIT 1", (candidate,)).fetchone()
                if row:
                    return {'matched_domain': row[0], 'name': row[1], 'category': row[2] or '', 'website_url': row[3] or '', 'company_id': row[4] or '', 'company_name': row[5], 'description': row[6], 'company_website': row[7], 'country': row[8]}
    except Exception as e:
        print('tracker lookup error:', repr(e), flush=True)
    return {}
