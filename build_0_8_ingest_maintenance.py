from pathlib import Path
import re

APP = Path('/app/app.py')
s = APP.read_text(encoding='utf-8')

# Maintenance cadence is intentionally slower than the query-log poll. These jobs
# used to run after every ingest cycle and repeatedly scanned/re-wrote large tables.
if 'RUNTIME_CLIENT_REFRESH_INTERVAL' not in s:
    anchor = 'app = Flask(__name__)\n'
    if anchor not in s:
        raise SystemExit('missing Flask app anchor')
    s = s.replace(
        anchor,
        anchor
        + 'RUNTIME_CLIENT_REFRESH_INTERVAL = max(30, int(os.getenv("RUNTIME_CLIENT_REFRESH_INTERVAL", "60")))\n'
        + 'NEIGHBOR_RECONCILE_INTERVAL = max(30, int(os.getenv("NEIGHBOR_RECONCILE_INTERVAL", "60")))\n'
        + 'last_runtime_clients_refresh = 0.0\n'
        + 'last_neighbor_reconcile = 0.0\n',
        1,
    )

# Never run full runtime-client or neighbor reconciliation scans as part of the
# ingest transaction/poll. Keep enrichment queues for newly observed domains only.
old_ingest = '''        for new_domain in dict.fromkeys(new_domains_for_enrichment):\n            _queue_domain_enrichment(new_domain)\n        refresh_runtime_clients()\n        reconcile_neighbors()\n        last_ingest_at = time.time()\n'''
new_ingest = '''        for new_domain in dict.fromkeys(new_domains_for_enrichment):\n            _queue_domain_enrichment(new_domain)\n        # Runtime-client reconciliation and neighbor migration are maintenance\n        # jobs. They deliberately do not run on every query-log poll.\n        last_ingest_at = time.time()\n'''
if old_ingest in s:
    s = s.replace(old_ingest, new_ingest, 1)

# The device identity network enrichment added by earlier patches is cache-only on
# the ingest path. Preserve the normalized domain/device write but avoid extending
# the critical write transaction with another device UPDATE.
old_enrich = '                enrich_device_network_identity(c, device_key, device_ips_now, mac, hostname)\n'
if old_enrich in s:
    s = s.replace(
        old_enrich,
        '                # Network identity enrichment is handled outside the ingest hot path.\n',
        1,
    )

# Keep the original worker shape (there is no start_background_services function
# in this codebase). Replace only the worker body and leave the routes untouched.
worker_re = re.compile(r'def worker\(\):\n.*?\n\n@app\.route\("/"\)', re.S)
new_worker = '''def worker():\n    """Single ingest coordinator plus low-frequency maintenance."""\n    global last_runtime_clients_refresh, last_neighbor_reconcile\n\n    init_db()\n    try:\n        load_neighbors(force=True)\n    except Exception as e:\n        print("background neighbors init failed:", repr(e), flush=True)\n    try:\n        refresh_runtime_clients()\n    except Exception as e:\n        print("background runtime client init failed:", repr(e), flush=True)\n    try:\n        migrate_legacy_domain_clients()\n    except Exception as e:\n        print("background legacy migration failed:", repr(e), flush=True)\n    try:\n        reconcile_neighbors()\n    except Exception as e:\n        print("background neighbor reconciliation failed:", repr(e), flush=True)\n\n    now = time.monotonic()\n    last_runtime_clients_refresh = now\n    last_neighbor_reconcile = now\n\n    try:\n        threading.Thread(target=refresh_trackerdb, daemon=True, name="trackerdb-refresh").start()\n    except Exception as e:\n        print("TrackerDB refresh thread start failed:", repr(e), flush=True)\n\n    while True:\n        started = time.monotonic()\n        try:\n            ingest()\n        except Exception as e:\n            print("background ingest loop error:", repr(e), flush=True)\n\n        now = time.monotonic()\n        if now - last_runtime_clients_refresh >= RUNTIME_CLIENT_REFRESH_INTERVAL:\n            try:\n                refresh_runtime_clients()\n                last_runtime_clients_refresh = now\n            except Exception as e:\n                print("runtime client maintenance error:", repr(e), flush=True)\n\n        if now - last_neighbor_reconcile >= NEIGHBOR_RECONCILE_INTERVAL:\n            try:\n                reconcile_neighbors()\n                last_neighbor_reconcile = now\n            except Exception as e:\n                print("neighbor reconciliation error:", repr(e), flush=True)\n\n        elapsed = time.monotonic() - started\n        time.sleep(max(1, POLL_SECONDS - elapsed))\n\n\n@app.route("/")'''
match = worker_re.search(s)
if not match:
    raise SystemExit('worker block not found')
s = s[:match.start()] + new_worker + s[match.end():]

compile(s, str(APP), 'exec')
APP.write_text(s, encoding='utf-8')
print('ingest maintenance patch applied')
