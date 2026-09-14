from pathlib import Path

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

MARKER = '# === 0.7.14 FEATURES: FRIENDLY DEVICE FILTER + PARTIAL SEARCH ==='
if MARKER in text:
    print('DNS Inspector 0.7.14 features already applied')
    raise SystemExit(0)

# 1) Overview > Device dropdown should use the same friendly/custom device
# naming users see in the Devices view. Prefer the explicitly stored name over
# the raw hostname, then fall back to vendor/device key.
old_filter = '''def get_filter_options():\n    with sqlite3.connect(DB_PATH) as c:\n        vendors=[r[0] for r in c.execute("SELECT DISTINCT vendor FROM devices WHERE TRIM(vendor)<>'' ORDER BY vendor COLLATE NOCASE").fetchall()]\n        devices=[{"value":k,"label":lbl} for k,lbl in c.execute("SELECT device_key,COALESCE(NULLIF(hostname,''),NULLIF(name,''),NULLIF(vendor,''),device_key) AS lbl FROM devices ORDER BY lbl COLLATE NOCASE").fetchall()]\n    return {"classifications":["Known service","Telemetry / Tracking","Advertising","Suspicious","Unknown"],"severities":["Info","Low","Medium","High","Unknown"],"vendors":vendors,"devices":devices}\n'''
new_filter = '''def get_filter_options():\n    with sqlite3.connect(DB_PATH) as c:\n        vendors=[r[0] for r in c.execute("SELECT DISTINCT vendor FROM devices WHERE TRIM(vendor)<>'' ORDER BY vendor COLLATE NOCASE").fetchall()]\n        devices=[{"value":k,"label":lbl} for k,lbl in c.execute("SELECT device_key,COALESCE(NULLIF(name,''),NULLIF(hostname,''),NULLIF(vendor,''),device_key) AS lbl FROM devices ORDER BY lbl COLLATE NOCASE").fetchall()]\n    return {"classifications":["Known service","Telemetry / Tracking","Advertising","Suspicious","Unknown"],"severities":["Info","Low","Medium","High","Unknown"],"vendors":vendors,"devices":devices}\n'''
if old_filter not in text:
    raise SystemExit('0.7.14 failed: filter-options marker not found')
text = text.replace(old_filter, new_filter, 1)

# 2) Partial/global search. The existing search path only inspected an exact
# domain name. Resolve a non-exact query against domains first, then device
# identity fields and finally IPs. The resolver returns the most-requested
# matching domain so the existing inspection UI can remain unchanged.
search_helper = '''\ndef _resolve_search_domain(query):\n    q = str(query or '').strip().lower().rstrip('.')\n    if not q:\n        return ''\n    with sqlite3.connect(DB_PATH) as c:\n        exact = c.execute("SELECT domain FROM domains WHERE domain=?", (q,)).fetchone()\n        if exact:\n            return exact[0]\n\n        # Partial domain search. Prefer a direct domain match over an indirect\n        # device/IP match because the search field is primarily a DNS inspector.\n        like = f"%{q}%"\n        rows = c.execute("SELECT domain FROM domains WHERE lower(domain) LIKE ? ORDER BY requests DESC LIMIT 20", (like,)).fetchall()\n        if rows:\n            return rows[0][0]\n\n        device_rows = c.execute(\n            "SELECT device_key FROM devices WHERE lower(device_key) LIKE ? OR lower(name) LIKE ? OR lower(hostname) LIKE ? OR lower(mac) LIKE ? OR lower(vendor) LIKE ? ORDER BY request_count DESC LIMIT 25",\n            (like, like, like, like, like),\n        ).fetchall()\n        device_keys = {r[0] for r in device_rows}\n\n        # Also accept a known current/recent IP as a search target.\n        ip_rows = c.execute(\n            "SELECT DISTINCT device_key FROM device_ips WHERE lower(ip) LIKE ? ORDER BY last_seen DESC LIMIT 25",\n            (like,),\n        ).fetchall()\n        device_keys.update(r[0] for r in ip_rows)\n\n        if not device_keys:\n            return ''\n\n        best = None\n        best_requests = -1\n        for domain, requests_count, raw_clients in c.execute("SELECT domain,requests,clients_json FROM domains ORDER BY requests DESC LIMIT 3000").fetchall():\n            try:\n                clients = json.loads(raw_clients or '{}')\n            except Exception:\n                clients = {}\n            count = sum(int(clients.get(k, 0) or 0) for k in device_keys)\n            if count > 0 and (count > best_requests or (count == best_requests and int(requests_count or 0) > int(best[1] if best else -1))):\n                best = (domain, int(requests_count or 0))\n                best_requests = count\n        return best[0] if best else ''\n\n'''
marker = '\ndef inspect_domain(domain):\n'
if marker not in text:
    raise SystemExit('0.7.14 failed: inspect_domain marker not found')
text = text.replace(marker, search_helper + marker, 1)

old_inspect = '''def inspect_domain(domain):\n    domain = domain.lower().rstrip(".")\n    with sqlite3.connect(DB_PATH) as c:\n'''
new_inspect = '''def inspect_domain(domain):\n    domain = _resolve_search_domain(domain)\n    if not domain:\n        return None\n    with sqlite3.connect(DB_PATH) as c:\n'''
if old_inspect not in text:
    raise SystemExit('0.7.14 failed: inspect_domain body marker not found')
text = text.replace(old_inspect, new_inspect, 1)

text = text.replace(MARKER, MARKER + '\n', 1)
compile(text, str(APP), 'exec')
APP.write_text(text, encoding='utf-8')
print('DNS Inspector 0.7.14 features applied: friendly device filter + partial search')
