from pathlib import Path

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

# A missing/failed enrichment must not be retried on every 10-second UI poll.
# Remember the next allowed attempt persistently in SQLite and mirror it in memory.
text = text.replace(
    'DNS_RECORDS_CACHE_HOURS = int(os.getenv("DNS_RECORDS_CACHE_HOURS", "168"))\n',
    'DNS_RECORDS_CACHE_HOURS = int(os.getenv("DNS_RECORDS_CACHE_HOURS", "168"))\nENRICHMENT_RETRY_HOURS = max(24.0, float(os.getenv("ENRICHMENT_RETRY_HOURS", "24")))\n',
    1,
)

# Persist retry state in the existing Inspector database.
marker = '        c.execute("CREATE INDEX IF NOT EXISTS idx_device_ips_last_seen ON device_ips(last_seen)")\n'
insert = '''        c.execute("""CREATE TABLE IF NOT EXISTS enrichment_attempts(
            domain TEXT PRIMARY KEY,
            attempted_at REAL NOT NULL,
            next_attempt_at REAL NOT NULL)""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_enrichment_attempt_next ON enrichment_attempts(next_attempt_at)")
'''
if marker not in text:
    raise SystemExit('retry patch failed: init_db index marker not found')
text = text.replace(marker, marker + insert, 1)

# Extend the queue guard created by the 0.7.8 memory patch.
old = '''_enrichment_queue = queue.Queue(maxsize=500)
_enrichment_queue_lock = threading.Lock()
_enrichment_queued = set()

def _queue_domain_enrichment(domain):
    domain = str(domain or '').strip('.').lower()
    if not domain:
        return False
    with _enrichment_queue_lock:
        if domain in _enrichment_queued or domain in enrichment_refreshing:
            return False
        try:
            _enrichment_queue.put_nowait(domain)
        except queue.Full:
            return False
        _enrichment_queued.add(domain)
    return True
'''
new = '''_enrichment_queue = queue.Queue(maxsize=500)
_enrichment_queue_lock = threading.Lock()
_enrichment_queued = set()
_enrichment_retry_until = {}
_enrichment_retry_loaded = set()

def _enrichment_retry_allowed(domain, now_ts=None):
    now_ts = time.time() if now_ts is None else now_ts
    until = _enrichment_retry_until.get(domain)
    if until is not None:
        return until <= now_ts
    if domain in _enrichment_retry_loaded:
        return True
    try:
        with sqlite3.connect(DB_PATH) as c:
            row = c.execute("SELECT next_attempt_at FROM enrichment_attempts WHERE domain=?", (domain,)).fetchone()
        if row:
            until = float(row[0] or 0)
            _enrichment_retry_until[domain] = until
        else:
            until = 0.0
    except Exception:
        until = 0.0
    _enrichment_retry_loaded.add(domain)
    return until <= now_ts

def _mark_enrichment_attempt(domain, now_ts=None):
    now_ts = time.time() if now_ts is None else now_ts
    next_ts = now_ts + ENRICHMENT_RETRY_HOURS * 3600.0
    _enrichment_retry_until[domain] = next_ts
    try:
        with sqlite3.connect(DB_PATH) as c:
            c.execute(
                "INSERT OR REPLACE INTO enrichment_attempts(domain,attempted_at,next_attempt_at) VALUES(?,?,?)",
                (domain, now_ts, next_ts),
            )
            c.commit()
    except Exception as e:
        print('enrichment retry-state error:', repr(e), flush=True)
    return next_ts

def _queue_domain_enrichment(domain):
    domain = str(domain or '').strip('.').lower()
    if not domain:
        return False
    with _enrichment_queue_lock:
        if domain in _enrichment_queued or domain in enrichment_refreshing:
            return False
        if not _enrichment_retry_allowed(domain):
            return False
        try:
            _enrichment_queue.put_nowait(domain)
        except queue.Full:
            return False
        _enrichment_queued.add(domain)
        next_ts = _mark_enrichment_attempt(domain)
    print(f"Enrichment queued: {domain}; next retry after {datetime.fromtimestamp(next_ts, timezone.utc).isoformat()}", flush=True)
    return True
'''
if old not in text:
    raise SystemExit('retry patch failed: 0.7.8 enrichment queue block not found')
text = text.replace(old, new, 1)

# Keep the current source behavior, but add one important guard: a domain discovered
# during ingest is queued once, instead of waiting for repeated UI inspection.
old = '''        with db_lock, sqlite3.connect(DB_PATH) as c:
            new_count = 0
            status_backfilled = 0
'''
new = '''        with db_lock, sqlite3.connect(DB_PATH) as c:
            new_count = 0
            status_backfilled = 0
            new_domains_for_enrichment = []
'''
if old not in text:
    raise SystemExit('retry patch failed: ingest counters marker not found')
text = text.replace(old, new, 1)

old = '''                else:
                    blocked = 1 if qstatus == "Blocked" else 0
                    allowed = 1 if qstatus == "Allowed" else 0
                    unknown = 1 if qstatus == "Unknown" else 0
                    c.execute("INSERT INTO domains(domain,first_seen,last_seen,requests,clients_json,blocked_requests,allowed_requests,unknown_requests,last_status,last_reason,current_status,current_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (domain, now, now, 1, json.dumps(clients), blocked, allowed, unknown, qstatus, str(e.get("reason") or ""), qstatus, str(e.get("reason") or "")))
                old = c.execute("SELECT request_count FROM client_cache WHERE identifier=?", (ident,)).fetchone()
'''
new = '''                else:
                    blocked = 1 if qstatus == "Blocked" else 0
                    allowed = 1 if qstatus == "Allowed" else 0
                    unknown = 1 if qstatus == "Unknown" else 0
                    c.execute("INSERT INTO domains(domain,first_seen,last_seen,requests,clients_json,blocked_requests,allowed_requests,unknown_requests,last_status,last_reason,current_status,current_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (domain, now, now, 1, json.dumps(clients), blocked, allowed, unknown, qstatus, str(e.get("reason") or ""), qstatus, str(e.get("reason") or "")))
                    new_domains_for_enrichment.append(domain)
                old = c.execute("SELECT request_count FROM client_cache WHERE identifier=?", (ident,)).fetchone()
'''
if old not in text:
    raise SystemExit('retry patch failed: new domain insert block not found')
text = text.replace(old, new, 1)

old = '''            c.execute("DELETE FROM processed_queries WHERE rowid IN (SELECT rowid FROM processed_queries ORDER BY seen_at DESC LIMIT -1 OFFSET 100000)")
            c.commit()
        refresh_runtime_clients()
'''
new = '''            c.execute("DELETE FROM processed_queries WHERE rowid IN (SELECT rowid FROM processed_queries ORDER BY seen_at DESC LIMIT -1 OFFSET 100000)")
            c.commit()
        for new_domain in dict.fromkeys(new_domains_for_enrichment):
            _queue_domain_enrichment(new_domain)
        refresh_runtime_clients()
'''
if old not in text:
    raise SystemExit('retry patch failed: ingest post-commit marker not found')
text = text.replace(old, new, 1)

APP.write_text(text, encoding='utf-8')
print('DNS Inspector enrichment retry cooldown patch applied')
