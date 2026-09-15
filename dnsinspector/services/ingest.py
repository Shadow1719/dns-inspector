from dnsinspector.core.runtime import *
from contextlib import closing
from datetime import datetime, timezone, timedelta
import os, json, time, threading, queue, sqlite3, re, hashlib, socket, subprocess, shutil, zipfile, io, platform, gc, sys
import requests
from dnsinspector.services import adguard as _adguard
from dnsinspector.db import *
from dnsinspector.services import devices as _devices
from dnsinspector.services import domains as _domains
from dnsinspector.services import enrichment as _enrichment

def query_fingerprint(entry):
    q = entry.get('question') or {}
    payload = {'time': entry.get('time') or '', 'client': entry.get('client') or '', 'client_id': entry.get('client_id') or '', 'name': q.get('name') or '', 'type': q.get('type') or '', 'class': q.get('class') or '', 'reason': entry.get('reason') or '', 'rule': entry.get('rule') or ''}
    raw = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()

def ingest(force=False):
    global last_ingest_at
    if not AGH_URL: return
    now_ts = time.time()
    if not force and now_ts - last_ingest_at < max(2, min(POLL_SECONDS, 5)): return
    try:
        data = _adguard.fetch_querylog(); entries = data.get('data') or []; now = utcnow()
        with db_lock, closing(db_connect(DB_PATH)) as c:
            new_count = 0; status_backfilled = 0; new_domains_for_enrichment = []
            for e in entries:
                fp = query_fingerprint(e)
                existing = c.execute('SELECT status_counted FROM processed_queries WHERE fingerprint=?', (fp,)).fetchone()
                domain = ((e.get('question') or {}).get('name') or '').rstrip('.').lower()
                if existing:
                    if int(existing[0] or 0) == 0 and domain:
                        qstatus = _domains.query_status(e.get('reason'), e.get('answer'))
                        row = c.execute('SELECT blocked_requests,allowed_requests,unknown_requests FROM domains WHERE domain=?', (domain,)).fetchone()
                        if row:
                            blocked, allowed, unknown = (int(row[0] or 0), int(row[1] or 0), int(row[2] or 0))
                            if qstatus == 'Blocked': blocked += 1
                            elif qstatus == 'Allowed': allowed += 1
                            else: unknown += 1
                            c.execute('UPDATE domains SET blocked_requests=?, allowed_requests=?, unknown_requests=?, last_status=?, last_reason=?, current_status=?, current_reason=? WHERE domain=?', (blocked, allowed, unknown, qstatus, str(e.get('reason') or ''), qstatus, str(e.get('reason') or ''), domain)); status_backfilled += 1
                        c.execute('UPDATE processed_queries SET status_counted=1 WHERE fingerprint=?', (fp,))
                    elif int(existing[0] or 0) == 0:
                        c.execute('UPDATE processed_queries SET status_counted=1 WHERE fingerprint=?', (fp,))
                    continue
                ident, cname, source, info, device_key, mac, ips, hostname = _devices.client_info_from_entry(e)
                if not domain:
                    c.execute('INSERT OR IGNORE INTO processed_queries(fingerprint,seen_at,status_counted) VALUES(?,?,1)', (fp, now)); continue
                qstatus = _domains.query_status(e.get('reason'), e.get('answer'))
                row = c.execute('SELECT clients_json,blocked_requests,allowed_requests,unknown_requests FROM domains WHERE domain=?', (domain,)).fetchone()
                clients = json.loads(row[0]) if row else {}; clients[device_key] = clients.get(device_key, 0) + 1
                if row:
                    blocked, allowed, unknown = (int(row[1] or 0), int(row[2] or 0), int(row[3] or 0))
                    if qstatus == 'Blocked': blocked += 1
                    elif qstatus == 'Allowed': allowed += 1
                    else: unknown += 1
                    c.execute('UPDATE domains SET last_seen=?, requests=requests+1, clients_json=?, blocked_requests=?, allowed_requests=?, unknown_requests=?, last_status=?, last_reason=?, current_status=?, current_reason=? WHERE domain=?', (now, json.dumps(clients), blocked, allowed, unknown, qstatus, str(e.get('reason') or ''), qstatus, str(e.get('reason') or ''), domain))
                else:
                    blocked = 1 if qstatus == 'Blocked' else 0; allowed = 1 if qstatus == 'Allowed' else 0; unknown = 1 if qstatus == 'Unknown' else 0
                    c.execute('INSERT INTO domains(domain,first_seen,last_seen,requests,clients_json,blocked_requests,allowed_requests,unknown_requests,last_status,last_reason,current_status,current_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)', (domain, now, now, 1, json.dumps(clients), blocked, allowed, unknown, qstatus, str(e.get('reason') or ''), qstatus, str(e.get('reason') or ''))); new_domains_for_enrichment.append(domain)
                old = c.execute('SELECT request_count FROM client_cache WHERE identifier=?', (ident,)).fetchone()
                if old:
                    c.execute('UPDATE client_cache SET name=?, source=?, last_seen=?, request_count=request_count+1, info_json=?, device_key=?, mac=?, hostname=? WHERE identifier=?', (cname, source, now, json.dumps(info), device_key, mac, hostname, ident))
                else:
                    c.execute('INSERT INTO client_cache(identifier,name,source,last_seen,request_count,info_json,device_key,mac,hostname) VALUES(?,?,?,?,?,?,?,?,?)', (ident, cname, source, now, 1, json.dumps(info), device_key, mac, hostname))
                device_ips_now = ips or ([ident] if _devices.is_ip(ident) else [])
                _devices.upsert_device(c, device_key, cname, hostname, mac, device_ips_now, source, info, now)
                c.execute('INSERT OR IGNORE INTO processed_queries(fingerprint,seen_at,status_counted) VALUES(?,?,1)', (fp, now)); new_count += 1
            c.execute('DELETE FROM processed_queries WHERE rowid IN (SELECT rowid FROM processed_queries ORDER BY seen_at DESC LIMIT -1 OFFSET 100000)'); c.commit()
        for new_domain in dict.fromkeys(new_domains_for_enrichment): _enrichment._queue_domain_enrichment(new_domain)
        last_ingest_at = time.time()
        if new_count or status_backfilled: print(f'Ingested {new_count} new DNS queries; backfilled {status_backfilled} query statuses.', flush=True)
    except Exception as e:
        print('ingest error:', repr(e), flush=True)

def worker():
    global last_runtime_clients_refresh, last_neighbor_reconcile
    init_db()
    for fn, label in ((_devices.load_neighbors, 'neighbors init'), (_devices.refresh_runtime_clients, 'runtime client init'), (_devices.migrate_legacy_domain_clients, 'legacy migration'), (_devices.reconcile_neighbors, 'neighbor reconciliation')):
        try: fn(force=True) if fn is _devices.load_neighbors else fn()
        except Exception as e: print(f'background {label} failed:', repr(e), flush=True)
    last_runtime_clients_refresh = time.monotonic(); last_neighbor_reconcile = last_runtime_clients_refresh
    try: threading.Thread(target=refresh_trackerdb, daemon=True, name='trackerdb-refresh').start()
    except Exception as e: print('TrackerDB refresh thread start failed:', repr(e), flush=True)
    while True:
        started = time.monotonic()
        try: ingest()
        except Exception as e: print('background ingest loop error:', repr(e), flush=True)
        now = time.monotonic()
        if now - last_runtime_clients_refresh >= RUNTIME_CLIENT_REFRESH_INTERVAL:
            try: _devices.refresh_runtime_clients(); last_runtime_clients_refresh = now
            except Exception as e: print('runtime client maintenance error:', repr(e), flush=True)
        if now - last_neighbor_reconcile >= NEIGHBOR_RECONCILE_INTERVAL:
            try: _devices.reconcile_neighbors(); last_neighbor_reconcile = now
            except Exception as e: print('neighbor reconciliation error:', repr(e), flush=True)
        time.sleep(max(1, POLL_SECONDS - (time.monotonic() - started)))
