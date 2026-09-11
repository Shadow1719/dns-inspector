import hashlib
import ipaddress
import json
import os
import re
import socket
import sqlite3
import threading
import time
from datetime import datetime, timezone
from urllib.parse import quote

import requests
from flask import Flask, jsonify, render_template_string, request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
try:
    with open(os.path.join(BASE_DIR, "VERSION"), "r", encoding="utf-8") as f:
        APP_VERSION = f.read().strip()
except Exception:
    APP_VERSION = os.getenv("APP_VERSION", "dev")

AGH_URL = os.getenv("AGH_URL", "http://192.168.1.100:30004").rstrip("/")
AGH_USER = os.getenv("AGH_USER", "")
AGH_PASS = os.getenv("AGH_PASS", "")
POLL_SECONDS = max(5, int(os.getenv("POLL_SECONDS", "10")))
NEIGHBORS_PATH = os.getenv("NEIGHBORS_PATH", "/data/neighbors.txt")
UI_REFRESH_SECONDS = max(5, int(os.getenv("UI_REFRESH_SECONDS", "10")))
DB_PATH = os.getenv("DB_PATH", "/data/inspector.db")
TRACKERDB_PATH = os.getenv("TRACKERDB_PATH", "/data/trackerdb.sqlite")
TRACKERDB_URL = os.getenv(
    "TRACKERDB_URL",
    "https://raw.githubusercontent.com/whotracksme/whotracks.me/master/whotracksme/data/assets/trackerdb.sql",
)
TRACKERDB_REFRESH_HOURS = int(os.getenv("TRACKERDB_REFRESH_HOURS", "24"))
RDAP_URL = os.getenv("RDAP_URL", "https://rdap.org/domain/").rstrip("/")

app = Flask(__name__)
db_lock = threading.Lock()
session = requests.Session()
last_ingest_at = 0.0
neighbors_lock = threading.Lock()
neighbors_cache = {}
neighbors_mtime = None

MAC_RE = re.compile(r"^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.I)
IP_RE = re.compile(r"^[0-9a-f:.]+$")

HTML = """
<!doctype html><html><head><meta charset="utf-8"><title>DNS Inspector</title>
<style>
body{font-family:system-ui;background:#111;color:#eee;margin:30px;max-width:1300px}
input,button{background:#222;color:#eee;border:1px solid #555;padding:9px;border-radius:6px}
input{width:70%}button{cursor:pointer}.card{background:#191919;border:1px solid #333;border-radius:10px;padding:18px;margin-top:18px}
small,.muted{color:#aaa}.tag{display:inline-block;padding:4px 8px;border-radius:12px;background:#333;margin:3px}.green{background:#174d2a}.yellow{background:#5a4610}.orange{background:#6a3510}.red{background:#6a1717}.blue{background:#16395c}.gray{background:#444}
table{width:100%;border-collapse:collapse}td,th{padding:8px;border-bottom:1px solid #333;text-align:left;vertical-align:top}a{color:#8ab4f8}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.kv{padding:7px 0;border-bottom:1px solid #2b2b2b}.kv b{display:inline-block;min-width:140px}
pre{white-space:pre-wrap;word-break:break-word;color:#ddd}.source{font-size:.9em;color:#888}.error{color:#ff9b9b}.live{color:#7ee787;font-weight:700}
.device{display:flex;align-items:center;gap:10px}.icon{font-size:1.5rem}.confidence{font-size:.82em;color:#aaa}.client-chip{display:inline-block;background:#252525;border:1px solid #3b3b3b;border-radius:9px;padding:4px 7px;margin:2px;font-size:.9em}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:5px}.dot-green{background:#3fb950}.dot-blue{background:#58a6ff}.dot-yellow{background:#d29922}.dot-orange{background:#db6d28}.dot-red{background:#f85149}.dot-gray{background:#8b949e}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.sub{font-size:.9em;color:#bbb}.right{float:right}
@media(max-width:900px){.grid{grid-template-columns:1fr}input{width:60%}}
</style></head><body>
<h1>DNS Inspector <span class="muted" style="font-size:.55em">v{{version}}</span></h1>
<p class="muted">Read-only view of AdGuard Home Query Log. This app never changes AdGuard settings. <span class="live">● Live</span> · refresh every {{refresh_seconds}}s · <span id="last-update">last update {{updated}}</span></p>
<form action="/search"><input name="q" placeholder="hostname..." value="{{q}}"><button type="submit">Inspect</button><button type="button" onclick="window.location='/'">Reset</button></form>
<div id="inspect-root">
{% if result %}{{ inspect_html|safe }}{% endif %}
</div>
<div class="card"><h2>Recent domains</h2>
<table><thead><tr><th>Domain</th><th>Requests</th><th>Clients</th><th>Classification</th></tr></thead>
<tbody id="recent-body">{{ recent_html|safe }}</tbody></table></div>
<div class="card"><h2>Clients / Devices</h2>
<table><thead><tr><th>Device</th><th>Identity</th><th>Current / recent IPs</th><th>Requests</th></tr></thead>
<tbody id="clients-body">{{ clients_html|safe }}</tbody></table>
<p class="source">Identity is based on AdGuard client information when available. A DHCP IP is treated as a changing observation, not as a permanent device identity. MAC/client identifiers are used as the stable key when AdGuard exposes them.</p></div>
<script>
const refreshMs = {{refresh_seconds_ms}};
const currentQuery = {{ q|tojson }};

function esc(v){
  return String(v ?? '').replace(/[&<>\"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}[c]));
}
function dot(cls){ return `<span class="dot dot-${esc(cls)}"></span>`; }
function severityClass(r){ return r.severity_class || 'gray'; }
function deviceRow(c){
  const ips = (c.ips || []).map(x=>`<span class="client-chip mono">${esc(x)}</span>`).join(' ');
  const mac = c.mac ? `<div class="sub mono">MAC ${esc(c.mac)}</div>` : '';
  const host = c.hostname ? `<div class="sub">${esc(c.hostname)}</div>` : '';
  const source = c.source ? `<div class="sub">${esc(c.source)}</div>` : '';
  return `<tr><td><div class="device"><span class="icon">${esc(c.icon)}</span><span><b>${esc(c.display_name)}</b>${host}<br><span class="confidence">${esc(c.type)} · ${esc(c.confidence_label)}</span>${source}</span></div></td><td><span class="mono">${esc(c.identifier)}</span>${mac}</td><td>${ips || '—'}</td><td>${esc(c.requests)}</td></tr>`;
}
function renderRecent(rows){
  document.getElementById('recent-body').innerHTML = rows.map(r => `<tr><td><a href="/search?q=${encodeURIComponent(r.domain)}">${esc(r.domain)}</a></td><td>${esc(r.requests)}</td><td>${esc(r.clients)}</td><td>${dot(severityClass(r))}<span class="tag ${esc(r.badge_class)}">${esc(r.classification)}</span></td></tr>`).join('');
}
function renderClients(rows){ document.getElementById('clients-body').innerHTML = rows.map(deviceRow).join(''); }
async function refresh(){
  try{
    const url = '/api/state' + (currentQuery ? '?q=' + encodeURIComponent(currentQuery) : '');
    const r = await fetch(url, {cache:'no-store'}); if(!r.ok) return;
    const data = await r.json();
    renderRecent(data.recent); renderClients(data.clients);
    if(data.inspect_html !== null){ document.getElementById('inspect-root').innerHTML = data.inspect_html; }
    document.getElementById('last-update').textContent = 'last update ' + data.updated;
  }catch(e){ console.debug('refresh failed', e); }
  finally{ setTimeout(refresh, refreshMs); }
}
setTimeout(refresh, refreshMs);
</script>
</body></html>
"""


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def add_column_if_missing(c, table, column, ddl):
    cols = {row[1] for row in c.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in cols:
        c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


def init_db():
    with sqlite3.connect(DB_PATH) as c:
        c.execute("""CREATE TABLE IF NOT EXISTS domains(
            domain TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT,
            requests INTEGER NOT NULL DEFAULT 0, clients_json TEXT NOT NULL DEFAULT '{}',
            classification TEXT NOT NULL DEFAULT 'Unknown', company TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '')""")
        c.execute("""CREATE TABLE IF NOT EXISTS rdap_cache(
            domain TEXT PRIMARY KEY, fetched_at TEXT NOT NULL, json TEXT NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS client_cache(
            identifier TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT '',
            last_seen TEXT NOT NULL, request_count INTEGER NOT NULL DEFAULT 0, info_json TEXT NOT NULL DEFAULT '{}',
            device_key TEXT NOT NULL DEFAULT '', mac TEXT NOT NULL DEFAULT '', hostname TEXT NOT NULL DEFAULT '')""")
        # v0.3 database migration: these columns did not exist yet.
        add_column_if_missing(c, "client_cache", "device_key", "TEXT NOT NULL DEFAULT ''")
        add_column_if_missing(c, "client_cache", "mac", "TEXT NOT NULL DEFAULT ''")
        add_column_if_missing(c, "client_cache", "hostname", "TEXT NOT NULL DEFAULT ''")
        c.execute("""CREATE TABLE IF NOT EXISTS devices(
            device_key TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', hostname TEXT NOT NULL DEFAULT '',
            mac TEXT NOT NULL DEFAULT '', device_type TEXT NOT NULL DEFAULT 'IoT / Unknown', icon TEXT NOT NULL DEFAULT '📦',
            confidence TEXT NOT NULL DEFAULT 'low', source TEXT NOT NULL DEFAULT '', last_seen TEXT NOT NULL,
            request_count INTEGER NOT NULL DEFAULT 0, info_json TEXT NOT NULL DEFAULT '{}')""")
        c.execute("""CREATE TABLE IF NOT EXISTS device_ips(
            device_key TEXT NOT NULL, ip TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
            requests INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(device_key,ip))""")
        c.execute("""CREATE TABLE IF NOT EXISTS processed_queries(
            fingerprint TEXT PRIMARY KEY, seen_at TEXT NOT NULL)""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_processed_seen ON processed_queries(seen_at)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_device_ips_last_seen ON device_ips(last_seen)")
        c.commit()


def trackerdb_ready():
    if not os.path.exists(TRACKERDB_PATH):
        return False
    try:
        with sqlite3.connect(TRACKERDB_PATH) as c:
            c.execute("SELECT 1 FROM tracker_domains LIMIT 1").fetchone()
        return True
    except Exception:
        return False


def trackerdb_refresh_needed():
    return (not trackerdb_ready()) or (time.time() - os.path.getmtime(TRACKERDB_PATH) > TRACKERDB_REFRESH_HOURS * 3600)


def refresh_trackerdb(force=False):
    if not force and not trackerdb_refresh_needed():
        return
    tmp, newdb = TRACKERDB_PATH + ".download", TRACKERDB_PATH + ".new"
    try:
        print("Downloading TrackerDB snapshot...", flush=True)
        r = requests.get(TRACKERDB_URL, timeout=30)
        r.raise_for_status()
        with open(tmp, "wb") as f:
            f.write(r.content)
        if os.path.exists(newdb):
            os.remove(newdb)
        with sqlite3.connect(newdb) as c:
            c.executescript(r.text)
            c.execute("PRAGMA journal_mode=DELETE")
            c.commit()
        os.replace(newdb, TRACKERDB_PATH)
        os.remove(tmp)
        print("TrackerDB ready.", flush=True)
    except Exception as e:
        print("TrackerDB refresh error:", repr(e), flush=True)
        for p in (tmp, newdb):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except OSError:
                pass


def agh_login():
    if not AGH_USER:
        return
    r = session.post(AGH_URL + "/control/login", json={"name": AGH_USER, "password": AGH_PASS}, timeout=10)
    r.raise_for_status()


def agh_get(path, **kwargs):
    r = session.get(AGH_URL + path, timeout=15, **kwargs)
    if r.status_code in (401, 403):
        agh_login()
        r = session.get(AGH_URL + path, timeout=15, **kwargs)
    r.raise_for_status()
    return r.json()


def fetch_querylog():
    return agh_get("/control/querylog", params={"limit": 500})


def fetch_clients():
    try:
        return agh_get("/control/clients")
    except Exception as e:
        print("client discovery error:", repr(e), flush=True)
        return {"clients": [], "auto_clients": []}


def is_mac(value):
    return bool(value and MAC_RE.match(str(value).strip()))


def normalize_mac(value):
    if not is_mac(value):
        return ""
    return str(value).strip().lower().replace("-", ":")


def load_neighbors(force=False):
    """Load the daily TrueNAS IP->MAC snapshot from neighbors.txt."""
    global neighbors_cache, neighbors_mtime
    try:
        mtime = os.path.getmtime(NEIGHBORS_PATH)
    except OSError:
        return {}
    with neighbors_lock:
        if not force and neighbors_mtime == mtime:
            return dict(neighbors_cache)
        parsed = {}
        try:
            with open(NEIGHBORS_PATH, "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 3 and is_ip(parts[0]) and parts[1] == "lladdr" and is_mac(parts[2]):
                        parsed[str(parts[0]).strip()] = normalize_mac(parts[2])
        except Exception as e:
            print("neighbors load error:", repr(e), flush=True)
            return dict(neighbors_cache)
        neighbors_cache = parsed
        neighbors_mtime = mtime
        return dict(neighbors_cache)


def neighbor_mac_for_ips(ips):
    neighbors = load_neighbors()
    for ip in ips:
        mac = neighbors.get(str(ip).strip())
        if mac:
            return mac
    return ""


def is_ip(value):
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except Exception:
        return False


def extract_identity(info, identifier, client_id=None):
    """Extract the best available stable identity plus current IP observations.

    AdGuard runtime clients can expose identifiers from several sources (hosts/rDNS/ARP/DHCP),
    while persistent clients can expose explicit ids. We prefer MAC, then a non-IP client id,
    then a named/hostnamed identity; bare IP is last resort because DHCP can reuse it.
    """
    info = info or {}
    ids = info.get("ids") or info.get("id") or []
    if isinstance(ids, str):
        ids = [ids]
    values = list(ids) if isinstance(ids, list) else []
    for key in ("identifier", "client_id", "mac", "address", "ip", "ip_addr"):
        if info.get(key):
            values.append(info.get(key))
    values.append(identifier)
    if client_id:
        values.append(client_id)

    extra_ips = []
    for key in ("ip_addrs", "ips", "addresses", "ip_addresses"):
        raw = info.get(key) or []
        if isinstance(raw, str):
            raw = [raw]
        if isinstance(raw, list):
            extra_ips.extend(raw)
    values_for_ips = values + extra_ips

    mac = next((normalize_mac(v) for v in values if is_mac(v)), "")
    ips = []
    for v in values_for_ips:
        if is_ip(v):
            s = str(v).strip()
            if s not in ips:
                ips.append(s)

    name = str(info.get("name") or "").strip()
    hostname = str(info.get("hostname") or info.get("host") or info.get("name") or "").strip()
    client_identifier = str(client_id or info.get("client_id") or identifier or "").strip()

    if not mac:
        mac = neighbor_mac_for_ips(ips)
    if mac:
        device_key = "mac:" + mac
    elif client_identifier and not is_ip(client_identifier):
        device_key = "client:" + client_identifier.lower()
    elif name or hostname:
        label = name or hostname
        device_key = "name:" + re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")
    elif ips:
        device_key = "ip:" + ips[0]
    else:
        device_key = "unknown:" + str(identifier)
    return device_key, mac, ips, name, hostname


def client_info_from_entry(entry):
    ident = entry.get("client") or entry.get("client_id") or "unknown"
    info = entry.get("client_info") or {}
    client_id = entry.get("client_id") or ""
    name = (info.get("name") or "").strip()
    source = "querylog"
    if name:
        source = "AdGuard client_info"
    device_key, mac, ips, name, hostname = extract_identity(info, ident, client_id)
    if is_ip(ident) and ident not in ips:
        ips.insert(0, ident)
    return str(ident), name, source, info, device_key, mac, ips, hostname


def query_fingerprint(entry):
    q = entry.get("question") or {}
    payload = {
        "time": entry.get("time") or "",
        "client": entry.get("client") or "",
        "client_id": entry.get("client_id") or "",
        "name": q.get("name") or "",
        "type": q.get("type") or "",
        "class": q.get("class") or "",
        "reason": entry.get("reason") or "",
        "rule": entry.get("rule") or "",
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def upsert_device(c, device_key, name, hostname, mac, ips, source, info, now, increment=True):
    row = c.execute("SELECT request_count FROM devices WHERE device_key=?", (device_key,)).fetchone()
    dtype, icon, confidence = device_hint(name, hostname, info)
    if row:
        if increment:
            c.execute("""UPDATE devices SET name=?, hostname=?, mac=?, device_type=?, icon=?, confidence=?, source=?, last_seen=?, request_count=request_count+1, info_json=? WHERE device_key=?""",
                      (name, hostname, mac, dtype, icon, confidence, source, now, json.dumps(info), device_key))
        else:
            c.execute("""UPDATE devices SET name=?, hostname=?, mac=?, device_type=?, icon=?, confidence=?, source=?, last_seen=?, info_json=? WHERE device_key=?""",
                      (name, hostname, mac, dtype, icon, confidence, source, now, json.dumps(info), device_key))
    else:
        c.execute("""INSERT INTO devices(device_key,name,hostname,mac,device_type,icon,confidence,source,last_seen,request_count,info_json)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                  (device_key, name, hostname, mac, dtype, icon, confidence, source, now, 1, json.dumps(info)))
    for ip in ips:
        row2 = c.execute("SELECT requests FROM device_ips WHERE device_key=? AND ip=?", (device_key, ip)).fetchone()
        if row2:
            c.execute("UPDATE device_ips SET last_seen=?, requests=requests+1 WHERE device_key=? AND ip=?", (now, device_key, ip))
        else:
            c.execute("INSERT INTO device_ips(device_key,ip,first_seen,last_seen,requests) VALUES(?,?,?,?,1)", (device_key, ip, now, now))


def ingest(force=False):
    global last_ingest_at
    now_ts = time.time()
    if not force and now_ts - last_ingest_at < max(2, min(POLL_SECONDS, 5)):
        return
    try:
        data = fetch_querylog()
        entries = data.get("data") or []
        now = utcnow()
        with db_lock, sqlite3.connect(DB_PATH) as c:
            new_count = 0
            for e in entries:
                fp = query_fingerprint(e)
                if c.execute("SELECT 1 FROM processed_queries WHERE fingerprint=?", (fp,)).fetchone():
                    continue
                domain = ((e.get("question") or {}).get("name") or "").rstrip(".").lower()
                ident, cname, source, info, device_key, mac, ips, hostname = client_info_from_entry(e)
                if not domain:
                    c.execute("INSERT OR IGNORE INTO processed_queries(fingerprint,seen_at) VALUES(?,?)", (fp, now))
                    continue
                row = c.execute("SELECT clients_json FROM domains WHERE domain=?", (domain,)).fetchone()
                clients = json.loads(row[0]) if row else {}
                clients[device_key] = clients.get(device_key, 0) + 1
                if row:
                    c.execute("UPDATE domains SET last_seen=?, requests=requests+1, clients_json=? WHERE domain=?", (now, json.dumps(clients), domain))
                else:
                    c.execute("INSERT INTO domains(domain,first_seen,last_seen,requests,clients_json) VALUES(?,?,?,?,?)", (domain, now, now, 1, json.dumps(clients)))
                old = c.execute("SELECT request_count FROM client_cache WHERE identifier=?", (ident,)).fetchone()
                if old:
                    c.execute("""UPDATE client_cache SET name=?, source=?, last_seen=?, request_count=request_count+1, info_json=?, device_key=?, mac=?, hostname=? WHERE identifier=?""",
                              (cname, source, now, json.dumps(info), device_key, mac, hostname, ident))
                else:
                    c.execute("""INSERT INTO client_cache(identifier,name,source,last_seen,request_count,info_json,device_key,mac,hostname)
                                 VALUES(?,?,?,?,?,?,?,?,?)""", (ident, cname, source, now, 1, json.dumps(info), device_key, mac, hostname))
                upsert_device(c, device_key, cname, hostname, mac, ips or ([ident] if is_ip(ident) else []), source, info, now)
                c.execute("INSERT OR IGNORE INTO processed_queries(fingerprint,seen_at) VALUES(?,?)", (fp, now))
                new_count += 1
            # Keep the dedupe table bounded while retaining enough history for repeated 500-entry query-log snapshots.
            c.execute("DELETE FROM processed_queries WHERE rowid IN (SELECT rowid FROM processed_queries ORDER BY seen_at DESC LIMIT -1 OFFSET 100000)")
            c.commit()
        refresh_runtime_clients()
        reconcile_neighbors()
        last_ingest_at = time.time()
        if new_count:
            print(f"Ingested {new_count} new DNS queries.", flush=True)
    except Exception as e:
        print("ingest error:", repr(e), flush=True)


def refresh_runtime_clients():
    data = fetch_clients()
    auto = {str(x.get("ip")): x for x in data.get("auto_clients") or [] if x.get("ip")}
    manual = {}
    for x in data.get("clients") or []:
        for ident in x.get("ids") or []:
            manual[str(ident)] = x
    if not auto and not manual:
        return
    now = utcnow()
    with db_lock, sqlite3.connect(DB_PATH) as c:
        rows = c.execute("SELECT identifier,device_key FROM client_cache").fetchall()
        for ident, current_device_key in rows:
            x = manual.get(ident) or auto.get(ident)
            if not x:
                continue
            name = (x.get("name") or "").strip()
            source = "AdGuard configured client" if ident in manual else (x.get("source") or "AdGuard runtime client")
            info = dict(x)
            # Runtime clients normally expose the current IP as `ip`; keep it as a current observation.
            device_key, mac, ips, cname, hostname = extract_identity(info, ident, x.get("client_id") or x.get("id"))
            c.execute("""UPDATE client_cache SET name=?, source=?, info_json=?, device_key=?, mac=?, hostname=? WHERE identifier=?""",
                      (name or cname, source, json.dumps(info), device_key or current_device_key, mac, hostname, ident))
            if device_key:
                upsert_device(c, device_key, name or cname, hostname, mac, ips or ([ident] if is_ip(ident) else []), source, info, now, increment=False)
        c.commit()


def migrate_legacy_domain_clients():
    """One-time-ish reconciliation of v0.3 domain keys after stable device IDs are discovered."""
    with db_lock, sqlite3.connect(DB_PATH) as c:
        cache_rows = c.execute("SELECT identifier,device_key FROM client_cache WHERE device_key<>''").fetchall()
        aliases = {ident: dkey for ident, dkey in cache_rows}
        if not aliases:
            return
        for domain, raw in c.execute("SELECT domain,clients_json FROM domains").fetchall():
            try:
                clients = json.loads(raw or "{}")
            except Exception:
                clients = {}
            migrated = {}
            changed = False
            for key, count in clients.items():
                dkey = aliases.get(key, key)
                changed = changed or dkey != key
                migrated[dkey] = migrated.get(dkey, 0) + count
            if changed:
                c.execute("UPDATE domains SET clients_json=? WHERE domain=?", (json.dumps(migrated), domain))
        c.commit()


def tracker_lookup(domain):
    if not trackerdb_ready():
        return {}
    labels = domain.rstrip(".").lower().split(".")
    candidates = [".".join(labels[i:]) for i in range(len(labels))]
    try:
        with sqlite3.connect(TRACKERDB_PATH) as c:
            for candidate in candidates:
                row = c.execute("""SELECT td.domain,t.name,cat.name,t.website_url,t.company_id,
                    coalesce(co.name,''),coalesce(co.description,''),coalesce(co.website_url,''),coalesce(co.country,'')
                    FROM tracker_domains td JOIN trackers t ON t.id=td.tracker LEFT JOIN categories cat ON cat.id=t.category_id
                    LEFT JOIN companies co ON co.id=t.company_id WHERE td.domain=? LIMIT 1""", (candidate,)).fetchone()
                if row:
                    return {"matched_domain": row[0], "name": row[1], "category": row[2] or "", "website_url": row[3] or "", "company_id": row[4] or "", "company_name": row[5], "description": row[6], "company_website": row[7], "country": row[8]}
    except Exception as e:
        print("tracker lookup error:", repr(e), flush=True)
    return {}


def rdap_lookup(domain):
    try:
        with sqlite3.connect(DB_PATH) as c:
            row = c.execute("SELECT fetched_at,json FROM rdap_cache WHERE domain=?", (domain,)).fetchone()
        if row:
            age = datetime.now(timezone.utc) - datetime.fromisoformat(row[0])
            if age.total_seconds() < 86400:
                return json.loads(row[1])
        r = requests.get(f"{RDAP_URL}/{quote(domain, safe='')}", timeout=8, allow_redirects=True)
        result = {}
        if r.ok:
            data = r.json()
            result = {"org": "", "name": data.get("name", ""), "handle": data.get("handle", "")}
            for ent in data.get("entities") or []:
                v = ent.get("vcardArray")
                if isinstance(v, list) and len(v) == 2:
                    for item in v[1]:
                        if item and item[0] == "fn" and len(item) > 3:
                            result["org"] = item[3]
                            break
                if result["org"]:
                    break
        # Cache both successful and negative lookups for 24h so live refresh does not hammer RDAP.
        with sqlite3.connect(DB_PATH) as c:
            c.execute("INSERT OR REPLACE INTO rdap_cache(domain,fetched_at,json) VALUES(?,?,?)", (domain, utcnow(), json.dumps(result)))
            c.commit()
        return result
    except Exception as e:
        print("RDAP lookup error:", repr(e), flush=True)
    return {}


def resolve_dns(domain):
    ips = []
    try:
        for item in socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM):
            ip = item[4][0]
            if ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips[:12]


def classify(tracker, rdap):
    cat = (tracker.get("category") or "").lower()
    if cat == "advertising":
        return "Advertising", "orange", "orange"
    if cat in {"site_analytics", "social_media", "extensions"}:
        return "Tracker / telemetry", "yellow", "yellow"
    if cat:
        return "Known TrackerDB service", "green", "green"
    if rdap.get("org"):
        return "Known ownership", "blue", "blue"
    return "Unknown", "gray", "gray"


def device_hint(name, hostname, info):
    text = " ".join([str(name or ""), str(hostname or ""), json.dumps(info or {})]).lower()
    if any(x in text for x in ("webos", "smart tv", "smart-tv", "oled", "qn ed", "lgtv", "television")):
        return "TV", "📺", "high"
    if any(x in text for x in ("aircon", "air conditioner", "air-conditioner", "lg ac", "climat")):
        return "AC", "❄️", "high"
    if any(x in text for x in ("dryer", "tumble")):
        return "Dryer", "🧺", "medium"
    if any(x in text for x in ("washer", "washing machine")):
        return "Washing machine", "🧺", "medium"
    if any(x in text for x in ("iphone", "ipad", "android", "pixel", "galaxy")):
        return "Phone / Tablet", "📱", "medium"
    if any(x in text for x in ("macbook", "laptop", "windows", "desktop", "pc")):
        return "Computer", "💻", "medium"
    if any(x in text for x in ("playstation", "xbox", "switch")):
        return "Console", "🎮", "medium"
    if any(x in text for x in ("camera", "cam-", "ipc")):
        return "Camera", "📷", "medium"
    if any(x in text for x in ("speaker", "sonos", "echo", "homepod")):
        return "Speaker", "🔊", "medium"
    if any(x in text for x in ("router", "gateway", "switch", "access point", "ap-")):
        return "Network", "🛜", "medium"
    return "IoT / Unknown", "📦", "low"


def device_ip_list(c, device_key):
    rows = c.execute("SELECT ip,last_seen FROM device_ips WHERE device_key=? ORDER BY last_seen DESC LIMIT 6", (device_key,)).fetchall()
    return [r[0] for r in rows]


def client_display(c, device_key, count):
    row = c.execute("SELECT device_key,name,hostname,mac,device_type,icon,confidence,source,request_count FROM devices WHERE device_key=?", (device_key,)).fetchone()
    if row:
        _, name, hostname, mac, dtype, icon, confidence, source, total = row
        ips = device_ip_list(c, device_key)
        display = name or hostname or device_key
        return {"device_key": device_key, "identifier": device_key, "display_name": display, "hostname": hostname, "mac": mac, "type": dtype, "icon": icon, "confidence_label": confidence, "source": source, "requests": count, "ips": ips, "total_requests": total}
    return {"device_key": device_key, "identifier": device_key, "display_name": device_key, "hostname": "", "mac": "", "type": "IoT / Unknown", "icon": "📦", "confidence_label": "low", "source": "historical", "requests": count, "ips": [], "total_requests": count}


def inspect_html(result):
    if not result:
        return ""
    clients_html = "".join(
        f"<tr><td>{c['icon']} <b>{_html(c['display_name'])}</b><div class='sub'>{_html(c['type'])} · {_html(c['confidence_label'])}</div></td><td class='mono'>{_html(', '.join(c['ips']) or '—')}</td><td class='mono'>{_html(c['mac'] or '—')}</td><td>{c['requests']}</td></tr>"
        for c in result["client_details"]
    )
    return f"""
<div class='card'>
<h2>{_html(result['domain'])}</h2>
<div><span class='tag {result['badge_class']}'>{_html(result['classification'])}</span>
{f"<span class='tag'>{_html(result['tracker'].get('category'))}</span>" if result['tracker'].get('category') else ''}
{f"<span class='tag'>{_html(result['tracker'].get('name'))}</span>" if result['tracker'].get('name') else ''}</div>
<div class='grid'><div><h3>Who</h3>
<div class='kv'><b>Company:</b> {_html(result['company']['name'] or 'Unknown')}</div>
<div class='kv'><b>Country:</b> {_html(result['company']['country'] or '—')}</div>
<div class='kv'><b>Website:</b> {f"<a href='{_html(result['company']['website_url'])}' target='_blank'>{_html(result['company']['website_url'])}</a>" if result['company']['website_url'] else '—'}</div>
<div class='kv'><b>RDAP:</b> {_html(result['rdap'].get('org') or 'Not available')}</div></div>
<div><h3>What it does</h3>
<p>{_html(result['tracker'].get('description') or (f"TrackerDB classifies this endpoint under {result['tracker'].get('category')}." if result['tracker'].get('category') else 'No TrackerDB description is available. Ownership was checked separately with RDAP; the hostname\'s exact purpose cannot be established from DNS alone.'))}</p>
{f"<p><a href='{_html(result['tracker'].get('website_url'))}' target='_blank'>Tracker / service website</a></p>" if result['tracker'].get('website_url') else ''}</div></div>
<h3>Infrastructure</h3><div class='grid'><div><div class='kv'><b>DNS:</b> {_html(', '.join(result['dns']) or 'No A/AAAA result')}</div><div class='kv'><b>RDAP name:</b> {_html(result['rdap'].get('name') or '—')}</div></div>
<div><div class='kv'><b>TrackerDB domain:</b> {_html(result['tracker'].get('matched_domain') or 'No match')}</div><div class='kv'><b>Source snapshot:</b> WhoTracks.me / Ghostery TrackerDB</div></div></div>
<h3>Local activity</h3><p><b>Requests:</b> {result['requests']} &nbsp; <b>Clients:</b> {len(result['clients'])}</p>
<table><thead><tr><th>Device</th><th>IP(s)</th><th>MAC</th><th>Queries</th></tr></thead><tbody>{clients_html}</tbody></table>
<p class='source'>Stable identity prefers MAC or a non-IP AdGuard client identifier, then a named hostname; IPs are observations and may change with DHCP. AdGuard runtime clients can come from rDNS/hosts/ARP/DHCP sources.</p>
</div>"""


def _html(v):
    s = str(v or "")
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;"))


def inspect_domain(domain):
    domain = domain.lower().rstrip(".")
    with sqlite3.connect(DB_PATH) as c:
        row = c.execute("SELECT domain,first_seen,last_seen,requests,clients_json FROM domains WHERE domain=?", (domain,)).fetchone()
        if not row:
            return None
        tracker = tracker_lookup(domain)
        rdap = rdap_lookup(domain)
        classification, badge, severity = classify(tracker, rdap)
        clients_map = json.loads(row[4] or "{}")
        client_details = [client_display(c, key, count) for key, count in sorted(clients_map.items(), key=lambda kv: kv[1], reverse=True)]
    return {
        "domain": row[0], "first_seen": row[1], "last_seen": row[2], "requests": row[3], "clients": clients_map,
        "classification": classification, "badge_class": badge, "severity_class": severity, "tracker": tracker,
        "company": {"name": tracker.get("company_name") or rdap.get("org") or "", "description": tracker.get("description", ""), "website_url": tracker.get("company_website", "") or tracker.get("website_url", ""), "country": tracker.get("country", "")},
        "rdap": rdap, "dns": resolve_dns(domain), "client_details": client_details,
    }


def get_recent():
    with sqlite3.connect(DB_PATH) as c:
        rows = c.execute("SELECT domain,requests,clients_json FROM domains ORDER BY requests DESC LIMIT 50").fetchall()
        out = []
        for domain, requests_count, clients_json in rows:
            t = tracker_lookup(domain)
            r = rdap_lookup(domain)
            cls, badge, severity = classify(t, r)
            out.append({"domain": domain, "requests": requests_count, "clients": len(json.loads(clients_json or "{}")), "classification": cls, "badge_class": badge, "severity_class": severity})
    return out


def get_clients():
    with sqlite3.connect(DB_PATH) as c:
        rows = c.execute("SELECT device_key,name,hostname,mac,device_type,icon,confidence,source,request_count FROM devices ORDER BY request_count DESC").fetchall()
        out = []
        for device_key, name, hostname, mac, dtype, icon, confidence, source, count in rows:
            ips = device_ip_list(c, device_key)
            out.append({"identifier": device_key, "display_name": name or hostname or device_key, "hostname": hostname, "mac": mac, "type": dtype, "icon": icon, "confidence_label": confidence, "source": source, "requests": count, "ips": ips})
    return out


def recent_html(recent):
    return "".join(f"<tr><td><a href='/search?q={quote(r['domain'], safe='')}'>{_html(r['domain'])}</a></td><td>{r['requests']}</td><td>{r['clients']}</td><td><span class='dot dot-{r['severity_class']}'></span><span class='tag {r['badge_class']}'>{_html(r['classification'])}</span></td></tr>" for r in recent)


def clients_html(clients):
    return "".join(f"<tr><td><div class='device'><span class='icon'>{_html(c['icon'])}</span><span><b>{_html(c['display_name'])}</b><br><span class='confidence'>{_html(c['type'])} · {_html(c['confidence_label'])}</span></span></div></td><td class='mono'>{_html(c['identifier'])}{f"<div class='sub mono'>MAC {_html(c['mac'])}</div>" if c['mac'] else ''}</td><td>{''.join(f"<span class='client-chip mono'>{_html(ip)}</span>" for ip in c['ips']) or '—'}</td><td>{c['requests']}</td></tr>" for c in clients)


def state_payload(q=""):
    # UI refresh is intentionally read-only against our local SQLite state.
    # AdGuard polling is performed by the background worker every POLL_SECONDS.
    result = inspect_domain(q) if q else None
    return {"updated": utcnow(), "recent": get_recent(), "clients": get_clients(), "inspect_html": inspect_html(result) if result else None}


def reconcile_neighbors():
    """Merge legacy IP-keyed devices into MAC-keyed devices using neighbors.txt."""
    neighbors = load_neighbors()
    if not neighbors:
        return 0
    changed = 0
    now = utcnow()
    with db_lock, sqlite3.connect(DB_PATH) as c:
        # Merge per-device records first. This preserves the historical IP list.
        for ip, mac in neighbors.items():
            old_key = "ip:" + ip
            new_key = "mac:" + mac
            if old_key == new_key:
                continue
            old = c.execute("SELECT name,hostname,mac,device_type,icon,confidence,source,last_seen,request_count,info_json FROM devices WHERE device_key=?", (old_key,)).fetchone()
            if not old:
                continue
            new = c.execute("SELECT request_count FROM devices WHERE device_key=?", (new_key,)).fetchone()
            if new:
                c.execute("""UPDATE devices SET name=COALESCE(NULLIF(name,''),?), hostname=COALESCE(NULLIF(hostname,''),?), mac=?,
                            device_type=CASE WHEN device_type='IoT / Unknown' THEN ? ELSE device_type END,
                            icon=CASE WHEN icon='📦' THEN ? ELSE icon END,
                            confidence=CASE WHEN confidence='low' THEN ? ELSE confidence END,
                            last_seen=CASE WHEN last_seen < ? THEN ? ELSE last_seen END,
                            request_count=request_count+?, info_json=CASE WHEN info_json='{}' THEN ? ELSE info_json END
                            WHERE device_key=?""",
                           (old[0], old[1], mac, old[3], old[4], old[5], old[7], old[7], old[8], old[9], new_key))
            else:
                c.execute("""INSERT INTO devices(device_key,name,hostname,mac,device_type,icon,confidence,source,last_seen,request_count,info_json)
                             VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                          (new_key, old[0], old[1], mac, old[3], old[4], old[5], old[6], old[7], old[8], old[9]))
            c.execute("UPDATE device_ips SET device_key=? WHERE device_key=?", (new_key, old_key))
            c.execute("DELETE FROM devices WHERE device_key=?", (old_key,))
            changed += 1

        # Rewrite domain client keys using the current IP->MAC snapshot.
        for domain, raw in c.execute("SELECT domain,clients_json FROM domains").fetchall():
            try:
                clients = json.loads(raw or "{}")
            except Exception:
                clients = {}
            migrated = {}
            did_change = False
            for key, count in clients.items():
                if key.startswith("ip:"):
                    mac = neighbors.get(key[3:])
                    new_key = "mac:" + mac if mac else key
                else:
                    new_key = key
                did_change = did_change or (new_key != key)
                migrated[new_key] = migrated.get(new_key, 0) + count
            if did_change:
                c.execute("UPDATE domains SET clients_json=? WHERE domain=?", (json.dumps(migrated), domain))
        c.commit()
    if changed:
        print(f"Reconciled {changed} legacy IP device(s) using neighbors.txt.", flush=True)
    return changed


def worker():
    init_db()
    load_neighbors(force=True)
    refresh_runtime_clients()
    reconcile_neighbors()
    migrate_legacy_domain_clients()
    refresh_trackerdb()
    while True:
        started = time.time()
        ingest()
        elapsed = time.time() - started
        time.sleep(max(1, POLL_SECONDS - elapsed))


@app.route("/")
def index():
    q = request.args.get("q", "").strip()
    ingest(force=False)
    result = inspect_domain(q) if q else None
    recent = get_recent()
    clients = get_clients()
    return render_template_string(HTML, q=q, result=result, inspect_html=inspect_html(result) if result else "", recent_html=recent_html(recent), clients_html=clients_html(clients), version=APP_VERSION, refresh_seconds=UI_REFRESH_SECONDS, refresh_seconds_ms=UI_REFRESH_SECONDS * 1000, updated=utcnow(), error=None)


@app.route("/search")
def search():
    return index()


@app.route("/api/state")
def api_state():
    try:
        return jsonify(state_payload(request.args.get("q", "").strip()))
    except Exception as e:
        print("state error:", repr(e), flush=True)
        return jsonify({"updated": utcnow(), "recent": get_recent(), "clients": get_clients(), "inspect_html": None, "error": str(e)}), 200


@app.route("/health")
def health():
    return jsonify({"ok": True, "version": APP_VERSION, "adguard": AGH_URL, "trackerdb": trackerdb_ready(), "poll_seconds": POLL_SECONDS, "ui_refresh_seconds": UI_REFRESH_SECONDS})


if __name__ == "__main__":
    init_db()
    threading.Thread(target=worker, daemon=True).start()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
