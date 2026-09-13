from pathlib import Path

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

# DHCP/IP observations must not live forever. A recycled LAN address can later
# belong to a completely different device, so only keep IP associations that
# have actually been seen recently.
retention_marker = 'HOSTNAME_CACHE_HOURS = int(os.getenv("HOSTNAME_CACHE_HOURS", "24"))\n'
retention_insert = retention_marker + 'DEVICE_IP_RETENTION_HOURS = max(1.0, float(os.getenv("DEVICE_IP_RETENTION_HOURS", "12")))\nDEVICE_IP_CLEANUP_INTERVAL_MINUTES = max(5, int(os.getenv("DEVICE_IP_CLEANUP_INTERVAL_MINUTES", "30")))\n'
if 'DEVICE_IP_RETENTION_HOURS = ' not in text:
    if retention_marker not in text:
        raise SystemExit('IP retention patch failed: cache settings marker not found')
    text = text.replace(retention_marker, retention_insert, 1)

marker = 'def refresh_runtime_clients():\n'
worker = '''def _prune_stale_device_ips():
    cutoff = time.time() - DEVICE_IP_RETENTION_HOURS * 3600.0
    try:
        with db_lock, sqlite3.connect(DB_PATH) as c:
            cur = c.execute("DELETE FROM device_ips WHERE last_seen < ?", (cutoff,))
            removed = int(cur.rowcount or 0)
            c.commit()
        if removed:
            print(f"Pruned {removed} stale device IP associations older than {DEVICE_IP_RETENTION_HOURS:g}h", flush=True)
        return removed
    except Exception as e:
        print('device IP cleanup error:', repr(e), flush=True)
        return 0


def _device_ip_cleanup_worker():
    while True:
        _prune_stale_device_ips()
        time.sleep(DEVICE_IP_CLEANUP_INTERVAL_MINUTES * 60)


'''
if marker not in text:
    raise SystemExit('IP retention patch failed: runtime client marker not found')
if 'def _device_ip_cleanup_worker()' not in text:
    text = text.replace(marker, worker + marker, 1)

old_main = '''if __name__ == "__main__":
    init_db()
    threading.Thread(target=worker, daemon=True).start()
    threading.Thread(target=_enrichment_worker, daemon=True, name="enrichment-queue").start()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
'''
new_main = '''if __name__ == "__main__":
    init_db()
    _prune_stale_device_ips()
    threading.Thread(target=worker, daemon=True).start()
    threading.Thread(target=_enrichment_worker, daemon=True, name="enrichment-queue").start()
    threading.Thread(target=_device_ip_cleanup_worker, daemon=True, name="device-ip-cleanup").start()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
'''
if old_main not in text:
    raise SystemExit('IP retention patch failed: main block marker not found')
text = text.replace(old_main, new_main, 1)

APP.write_text(text, encoding='utf-8')
print('DNS Inspector device IP retention patch applied: 12h retention + periodic cleanup')
