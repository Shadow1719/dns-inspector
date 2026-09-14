from pathlib import Path
import re

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

MARKER = '# === 0.7.14 FEATURES: FRIENDLY DEVICE FILTER + PARTIAL SEARCH ==='
if MARKER in text:
    print('DNS Inspector 0.7.14 features already applied')
    raise SystemExit(0)

# 1) Overview > Device dropdown: prefer the stored/manual name over hostname.
# The SQLite close patch runs before this patch, so accept both the original
# connection spelling and the already-transformed closing(...) form.
filter_pattern = re.compile(
    r'def get_filter_options\(\):\n'
    r'    with (?:closing\(sqlite3\.connect\(DB_PATH\)\)|sqlite3\.connect\(DB_PATH\)) as c:\n'
    r'        vendors=.*?\n'
    r'        devices=\[\{"value":k,"label":lbl\} for k,lbl in c\.execute\(.*?\)\.fetchall\(\)\]\n'
    r'    return \{"classifications":\[.*?\],"severities":\[.*?\],"vendors":vendors,"devices":devices\}\n',
    re.S,
)
new_filter = '''def get_filter_options():
    with closing(sqlite3.connect(DB_PATH)) as c:
        vendors=[r[0] for r in c.execute("SELECT DISTINCT vendor FROM devices WHERE TRIM(vendor)<>'' ORDER BY vendor COLLATE NOCASE").fetchall()]
        devices=[{"value":k,"label":lbl} for k,lbl in c.execute("SELECT device_key,COALESCE(NULLIF(name,''),NULLIF(hostname,''),NULLIF(vendor,''),device_key) AS lbl FROM devices ORDER BY lbl COLLATE NOCASE").fetchall()]
    return {"classifications":["Known service","Telemetry / Tracking","Advertising","Suspicious","Unknown"],"severities":["Info","Low","Medium","High","Unknown"],"vendors":vendors,"devices":devices}
'''
text, filter_count = filter_pattern.subn(new_filter, text, count=1)
if filter_count != 1:
    raise SystemExit('0.7.14 failed: filter-options marker not found')

# 2) Partial/global search. Resolve exact domain first, then partial domain,
# then device identity fields and recent IPs. Return the most relevant observed
# domain so the existing inspection view can remain unchanged.
search_helper = '''
def _resolve_search_domain(query):
    q = str(query or '').strip().lower().rstrip('.')
    if not q:
        return ''
    with closing(sqlite3.connect(DB_PATH)) as c:
        exact = c.execute("SELECT domain FROM domains WHERE domain=?", (q,)).fetchone()
        if exact:
            return exact[0]

        like = f"%{q}%"
        rows = c.execute("SELECT domain FROM domains WHERE lower(domain) LIKE ? ORDER BY requests DESC LIMIT 20", (like,)).fetchall()
        if rows:
            return rows[0][0]

        device_rows = c.execute(
            "SELECT device_key FROM devices WHERE lower(device_key) LIKE ? OR lower(name) LIKE ? OR lower(hostname) LIKE ? OR lower(mac) LIKE ? OR lower(vendor) LIKE ? ORDER BY request_count DESC LIMIT 25",
            (like, like, like, like, like),
        ).fetchall()
        device_keys = {r[0] for r in device_rows}

        ip_rows = c.execute(
            "SELECT DISTINCT device_key FROM device_ips WHERE lower(ip) LIKE ? ORDER BY last_seen DESC LIMIT 25",
            (like,),
        ).fetchall()
        device_keys.update(r[0] for r in ip_rows)

        if not device_keys:
            return ''

        best = None
        best_requests = -1
        for domain, requests_count, raw_clients in c.execute(
            "SELECT domain,requests,clients_json FROM domains ORDER BY requests DESC LIMIT 3000"
        ).fetchall():
            try:
                clients = json.loads(raw_clients or '{}')
            except Exception:
                clients = {}
            count = sum(int(clients.get(k, 0) or 0) for k in device_keys)
            if count > 0 and (count > best_requests or (count == best_requests and int(requests_count or 0) > int(best[1] if best else -1))):
                best = (domain, int(requests_count or 0))
                best_requests = count
        return best[0] if best else ''

'''
marker = '\ndef inspect_domain(domain):\n'
if marker not in text:
    raise SystemExit('0.7.14 failed: inspect_domain marker not found')
text = text.replace(marker, search_helper + marker, 1)

inspect_pattern = re.compile(
    r'def inspect_domain\(domain\):\n'
    r'    domain = domain\.lower\(\)\.rstrip\("\."\)\n'
    r'    with (?:closing\(sqlite3\.connect\(DB_PATH\)\)|sqlite3\.connect\(DB_PATH\)) as c:\n'
)
new_inspect = '''def inspect_domain(domain):
    domain = _resolve_search_domain(domain)
    if not domain:
        return None
    with closing(sqlite3.connect(DB_PATH)) as c:
'''
text, inspect_count = inspect_pattern.subn(new_inspect, text, count=1)
if inspect_count != 1:
    raise SystemExit('0.7.14 failed: inspect_domain body marker not found')

text = text.replace(MARKER, MARKER + '\n', 1)
compile(text, str(APP), 'exec')
APP.write_text(text, encoding='utf-8')
print('DNS Inspector 0.7.14 features applied: friendly device filter + partial search')
