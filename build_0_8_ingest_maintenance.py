from pathlib import Path
import re

APP = Path('/app/app.py')
s = APP.read_text(encoding='utf-8')

# Maintenance cadence is intentionally slower than the query-log poll. These jobs
# used to run after every ingest cycle and repeatedly scanned/re-wrote large tables.
if 'RUNTIME_CLIENT_REFRESH_INTERVAL' not in s:
    anchor = 'tracker_refresh_lock = threading.Lock()\n'
    if anchor not in s:
        raise SystemExit('missing tracker_refresh_lock anchor')
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

# Replace the worker coordinator with a single ingest loop plus low-frequency
# maintenance. Match the existing worker through the next top-level function.
worker_re = re.compile(r'def worker\(\):\n.*?\n\ndef start_background_services\(\):', re.S)
new_worker = '''def worker():\n    """Single coordinator for ingest plus low-frequency maintenance."""\n    global last_runtime_clients_refresh, last_neighbor_reconcile\n\n    for name, fn, kwargs in (\n        ("prune", _prune_stale_device_ips, {}),\n        ("load-neighbors", load_neighbors, {"force": True}),\n        ("refresh-runtime-clients", refresh_runtime_clients, {}),\n        ("rebuild-domain-devices", rebuild_domain_devices, {}),\n        ("migrate-legacy", migrate_legacy_domain_clients, {}),\n        ("reconcile-neighbors", reconcile_neighbors, {"force": True}),\n    ):\n        try:\n            fn(**kwargs)\n        except Exception as e:\n            print(f"background startup step {name} failed: {e!r}", flush=True)\n\n    now = time.monotonic()\n    last_runtime_clients_refresh = now\n    last_neighbor_reconcile = now\n\n    try:\n        threading.Thread(\n            target=refresh_trackerdb, daemon=True, name="trackerdb-refresh"\n        ).start()\n    except Exception as e:\n        print("TrackerDB refresh thread start failed:", repr(e), flush=True)\n\n    while not background_stop.is_set():\n        started = time.monotonic()\n        try:\n            ingest()\n        except Exception as e:\n            print("background ingest loop error:", repr(e), flush=True)\n\n        now = time.monotonic()\n        if now - last_runtime_clients_refresh >= RUNTIME_CLIENT_REFRESH_INTERVAL:\n            try:\n                refresh_runtime_clients()\n                last_runtime_clients_refresh = now\n            except Exception as e:\n                print("runtime client maintenance error:", repr(e), flush=True)\n\n        if now - last_neighbor_reconcile >= NEIGHBOR_RECONCILE_INTERVAL:\n            try:\n                reconcile_neighbors()\n                last_neighbor_reconcile = now\n            except Exception as e:\n                print("neighbor reconciliation error:", repr(e), flush=True)\n\n        elapsed = time.monotonic() - started\n        if background_stop.wait(max(1.0, POLL_SECONDS - elapsed)):\n            return\n\n\ndef start_background_services('''
match = worker_re.search(s)
if not match:
    raise SystemExit('worker block not found')
s = s[:match.start()] + new_worker + s[match.end():]

APP.write_text(s, encoding='utf-8')
print('ingest maintenance patch applied')
