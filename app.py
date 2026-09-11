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

AGH_URL = os.getenv("AGH_URL", "").rstrip("/")
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
MACVENDOR_URL = os.getenv("MACVENDOR_URL", "https://api.macvendors.com").rstrip("/")
MACVENDOR_CACHE_HOURS = int(os.getenv("MACVENDOR_CACHE_HOURS", "168"))
HOSTNAME_CACHE_HOURS = int(os.getenv("HOSTNAME_CACHE_HOURS", "24"))
NETIFY_CACHE_HOURS = int(os.getenv("NETIFY_CACHE_HOURS", "360"))
RDAP_CACHE_HOURS = int(os.getenv("RDAP_CACHE_HOURS", "720"))
DNS_RECORDS_CACHE_HOURS = int(os.getenv("DNS_RECORDS_CACHE_HOURS", "168"))
NETIFY_URL = os.getenv("NETIFY_URL", "https://www.netify.ai/resources/hostnames/").rstrip("/") + "/"

app = Flask(__name__)
db_lock = threading.Lock()
session = requests.Session()
last_ingest_at = 0.0
neighbors_lock = threading.Lock()
neighbors_cache = {}
neighbors_mtime = None
enrichment_lock = threading.Lock()
enrichment_refreshing = set()

MAC_RE = re.compile(r"^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.I)
IP_RE = re.compile(r"^[0-9a-f:.]+$")

HTML = """
<!doctype html><html><head><meta charset="utf-8"><title>DNS Inspector</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:28px;max-width:1450px;margin-inline:auto}
h1{margin:0 0 6px;font-size:2rem;letter-spacing:-.02em}.muted,small{color:#8b949e}.live{color:#7ee787;font-weight:700}.updated-time{color:#58a6ff;font-weight:700}.updated-date{color:#8b949e}.signal{border-left:3px solid #30363d;padding:10px 12px;background:#0d1117;border-radius:8px}.signal-green{border-color:#3fb950}.signal-blue{border-color:#58a6ff}.signal-yellow{border-color:#d29922}.signal-orange{border-color:#db6d28}.signal-red{border-color:#f85149}.signal-gray{border-color:#8b949e}.signal-title{font-weight:750;margin-bottom:5px}.evidence{margin:6px 0 0;padding-left:18px;color:#c9d1d9}.evidence li{margin:3px 0}.confidence-high{color:#3fb950;font-weight:700}.confidence-medium{color:#d29922;font-weight:700}.confidence-low{color:#8b949e;font-weight:700}.dns-list{display:flex;flex-wrap:wrap;gap:6px}.dns-ip{display:inline-block;padding:4px 8px;border:1px solid #30363d;border-radius:7px;background:#161b22;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.82rem}.vendor-logo{width:20px;height:20px;object-fit:contain;vertical-align:middle;margin-right:6px;border-radius:4px}.vendor-logo-lg{width:30px;height:30px;object-fit:contain;flex:0 0 30px}.vendor-mark{display:inline-flex;align-items:center;justify-content:center;width:20px;height:20px;margin-right:6px;border-radius:5px;background:#30363d;font-size:.7rem}.vendor-mark-lg{display:inline-flex;align-items:center;justify-content:center;width:30px;height:30px;flex:0 0 30px;border-radius:8px;background:#30363d;font-size:.75rem;font-weight:800}
.toolbar{display:flex;gap:8px;align-items:center;margin:20px 0 4px}.toolbar input{flex:1;min-width:0}.toolbar button{white-space:nowrap}
input,button{background:#161b22;color:#e6edf3;border:1px solid #30363d;padding:10px 13px;border-radius:8px;font:inherit}button{cursor:pointer}button:hover{border-color:#58a6ff}
.card{background:#11161d;border:1px solid #30363d;border-radius:14px;padding:18px;margin-top:18px;box-shadow:0 8px 28px rgba(0,0,0,.16)}
.card h2{margin-top:0;letter-spacing:-.01em}
table{width:100%;border-collapse:collapse}td,th{padding:11px 10px;border-bottom:1px solid #21262d;text-align:left;vertical-align:middle}th{font-size:.78rem;text-transform:uppercase;letter-spacing:.06em;color:#8b949e}tr:last-child td{border-bottom:0}
a{color:#79c0ff;text-decoration:none}a:hover{text-decoration:underline}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.kv{padding:8px 0;border-bottom:1px solid #21262d}.kv b{display:inline-block;min-width:140px}
pre{white-space:pre-wrap;word-break:break-word;color:#ddd}.source{font-size:.88em;color:#8b949e}.error{color:#ff9b9b}
.tag{display:inline-block;padding:4px 9px;border-radius:999px;background:#30363d;margin:2px;font-size:.82rem}.green{background:#174d2a}.yellow{background:#5a4610}.orange{background:#6a3510}.red{background:#6a1717}.blue{background:#16395c}.gray{background:#30363d}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}.dot-green{background:#3fb950}.dot-blue{background:#58a6ff}.dot-yellow{background:#d29922}.dot-orange{background:#db6d28}.dot-red{background:#f85149}.dot-gray{background:#8b949e}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.sub{font-size:.82rem;color:#8b949e}.right{float:right}
.device{display:flex;align-items:flex-start;gap:10px}.icon{font-size:1.55rem;line-height:1.2}.device-name{font-size:1rem;font-weight:700;line-height:1.25}.confidence{font-size:.78rem;color:#8b949e}.technical{font-size:.76rem;color:#6e7681;margin-top:2px}
.device-list{display:flex;flex-wrap:wrap;gap:5px}.device-chip{display:inline-flex;align-items:center;gap:5px;background:#161b22;border:1px solid #30363d;border-radius:999px;padding:4px 8px;font-size:.8rem}.device-chip .mini-icon{font-size:.9rem}
.client-chip{display:inline-block;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:4px 7px;margin:2px;font-size:.85em}
.glance-domain{font-weight:650}.external-tools{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}.external-tool{display:inline-flex;align-items:center;gap:4px;padding:3px 7px;border:1px solid #30363d;border-radius:7px;background:#161b22;color:#8b949e;font-size:.74rem;text-decoration:none}.external-tool:hover{border-color:#58a6ff;color:#79c0ff;text-decoration:none}.inline-tools{display:inline-flex;gap:5px;margin-left:6px;vertical-align:middle}.inline-tool{display:inline-flex;align-items:center;justify-content:center;width:20px;height:20px;border:1px solid #30363d;border-radius:6px;background:#161b22;color:#8b949e;font-size:.72rem;text-decoration:none}.inline-tool svg,.external-tool svg{width:13px;height:13px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}.inline-tool:hover{border-color:#58a6ff;color:#79c0ff;text-decoration:none}.external-tool.icon-only{width:20px;height:20px;padding:0;justify-content:center}.link-device{color:inherit;text-decoration:none}.link-device:hover{text-decoration:none}.link-device:hover .device-name{text-decoration:underline}.link-ip{font-weight:650}.device-chip{cursor:pointer}.device-chip:hover{border-color:#58a6ff}.clickable-label{cursor:pointer}.glance-meta{display:flex;flex-wrap:wrap;gap:6px;margin-top:4px;color:#8b949e;font-size:.78rem}.glance-devices{max-width:520px}
@media(max-width:900px){body{padding:16px}.grid{grid-template-columns:1fr}.toolbar{flex-wrap:wrap}.toolbar input{flex-basis:100%}td,th{padding:9px 6px}.hide-mobile{display:none}}
</style></head><body>
<h1>DNS Inspector <span class="muted" style="font-size:.55em">v{{version}}</span></h1>
<p class="muted">Watching AdGuard activity · <span class="live">● Live</span> · refresh every {{refresh_seconds}}s · updated <span id="last-update-time" class="updated-time"></span> · <span id="last-update-date" class="updated-date"></span></p>
<form class="toolbar" action="/search"><input name="q" placeholder="hostname..." value="{{q}}"><button type="submit">Inspect</button><button type="button" onclick="window.location='/'">Reset</button></form>
<div id="inspect-root">
{% if result %}{{ inspect_html|safe }}{% endif %}
</div>
<div class="card"><h2>At a glance</h2>
<table><thead><tr><th>Domain</th><th>Activity</th><th>Devices</th><th>Classification</th></tr></thead>
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
function formatUpdated(iso){ const d=new Date(iso); if(Number.isNaN(d.getTime())) return {time:String(iso),date:''}; return {time:d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}), date:d.toLocaleDateString([], {year:'numeric',month:'short',day:'numeric'})}; }
function deviceHref(c){ return `/device?key=${encodeURIComponent(c.device_key || c.identifier || '')}`; }
function ipHref(ip){ return `/ip?addr=${encodeURIComponent(ip)}`; }
function deviceLink(c, label, extra=''){ return `<a class="link-device ${extra}" href="${deviceHref(c)}">${label}</a>`; }
function ipLink(ip){ return `<a class="client-chip mono link-ip" href="${ipHref(ip)}">${esc(ip)}</a>`; }
function magnifierSvg(){ return `<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="6.5"></circle><path d="M16 16l5 5"></path></svg>`; }
function externalButton(url,label,icon='↗'){ const glyph = icon === '' ? magnifierSvg() : esc(icon); return `<a class="external-tool ${label ? '' : 'icon-only'}" href="${esc(url)}" target="_blank" rel="noopener noreferrer" title="${esc(label || 'External lookup')}">${glyph}${label ? ' ' + esc(label) : ''}</a>`; }
function deviceRow(c){
  const ips = (c.ips || []).map(ipLink).join(' ');
  const host = c.hostname && c.hostname !== (c.name || c.vendor || c.display_name || c.identifier) ? `<div class="technical mono"><a class="link-ip" href="${deviceHref(c)}">HOST ${esc(c.hostname)}</a></div>` : '';
  const vendor = c.vendor ? `<div class="sub">${c.vendor_logo ? `<img class="vendor-logo" src="${esc(c.vendor_logo)}" alt="" loading="lazy">` : `<span class="vendor-mark">◈</span>`}${esc(c.vendor)} ${externalButton(`https://www.google.com/search?q=${encodeURIComponent(c.vendor)}`,'','')}</div>` : '';
  const mac = c.mac ? `<div class="technical mono">${esc(c.mac)} ${externalButton(`https://macvendors.com/${encodeURIComponent(c.mac)}`,'','')}</div>` : '';
  const source = c.source ? `<div class="technical">${esc(c.source)}</div>` : '';
  const linkedPrimary = c.hostname || c.name || c.display_name || '';
  const primary = linkedPrimary || c.vendor || c.identifier;
  const primaryHtml = linkedPrimary ? deviceLink(c, `<div class="device-name">${esc(primary)}</div>`, 'primary-device') : `<div class="device-name">${esc(primary)}</div>`;
  const visual = c.vendor_logo ? `<img class="vendor-logo-lg" src="${esc(c.vendor_logo)}" alt="" loading="lazy">` : `<span class="vendor-mark-lg">${esc(c.icon || '◈')}</span>`;
  const visualHtml = linkedPrimary ? deviceLink(c, visual) : visual;
  return `<tr><td><div class="device">${visualHtml}<span>${primaryHtml}${vendor}${host}<div class="confidence">${esc(c.type)} · ${esc(c.confidence_label)}</div>${source}</span></div></td><td>${ips || '—'}</td><td>${c.mac ? `<span class="mono">${esc(c.mac)}</span> ${externalButton(`https://macvendors.com/${encodeURIComponent(c.mac)}`,'','')}` : '—'}</td><td>${esc(c.requests)}</td></tr>`;
}
function renderRecent(rows){
  document.getElementById('recent-body').innerHTML = rows.map(r => {
    const devices = (r.devices || []).map(d => `<a class="device-chip link-device" href="${deviceHref(d)}">${d.vendor_logo ? `<img class="vendor-logo" src="${esc(d.vendor_logo)}" alt="" loading="lazy">` : `<span class="mini-icon">${esc(d.icon || '📦')}</span>`}${esc(d.name)}</a>`).join('');
    return `<tr><td><a class="glance-domain" href="/search?q=${encodeURIComponent(r.domain)}">${esc(r.domain)}</a><div class="glance-meta"><span>${esc(r.requests)} requests</span><span>·</span><span>${esc(r.clients)} device${r.clients===1?'':'s'}</span></div></td><td><b>${esc(r.requests)}</b> requests</td><td class="glance-devices"><div class="device-list">${devices || '<span class="sub">No identified devices</span>'}</div></td><td><span class="tag ${esc(r.badge_class)}">${esc(r.classification)}</span></td></tr>`;
  }).join('');
}
function renderClients(rows){ document.getElementById('clients-body').innerHTML = rows.map(deviceRow).join(''); }
async function refresh(){
  try{
    const url = '/api/state' + (currentQuery ? '?q=' + encodeURIComponent(currentQuery) : '');
    const r = await fetch(url, {cache:'no-store'}); if(!r.ok) return;
    const data = await r.json();
    renderRecent(data.recent); renderClients(data.clients);
    if(data.inspect_html !== null){ document.getElementById('inspect-root').innerHTML = data.inspect_html; }
    const stamp = formatUpdated(data.updated); document.getElementById('last-update-time').textContent = stamp.time; document.getElementById('last-update-date').textContent = stamp.date;
  }catch(e){ console.debug('refresh failed', e); }
  finally{ setTimeout(refresh, refreshMs); }
}
const initialStamp = formatUpdated({{ updated|tojson }}); document.getElementById('last-update-time').textContent = initialStamp.time; document.getElementById('last-update-date').textContent = initialStamp.date;
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
        c.execute("""CREATE TABLE IF NOT EXISTS mac_vendor_cache(
            mac TEXT PRIMARY KEY, fetched_at TEXT NOT NULL, vendor TEXT NOT NULL DEFAULT '')""")
        c.execute("""CREATE TABLE IF NOT EXISTS hostname_cache(
            ip TEXT PRIMARY KEY, fetched_at TEXT NOT NULL, hostname TEXT NOT NULL DEFAULT '')""")
        c.execute("""CREATE TABLE IF NOT EXISTS netify_cache(
            domain TEXT PRIMARY KEY, fetched_at TEXT NOT NULL, json TEXT NOT NULL DEFAULT '{}')""")
        c.execute("""CREATE TABLE IF NOT EXISTS dns_records_cache(
            domain TEXT PRIMARY KEY, fetched_at TEXT NOT NULL, json TEXT NOT NULL DEFAULT '{}')""")
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
        add_column_if_missing(c, "devices", "vendor", "TEXT NOT NULL DEFAULT ''")
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


def hostname_for_ip(ip):
    if not is_ip(ip):
        return ""
    try:
        with sqlite3.connect(DB_PATH) as c:
            row = c.execute("SELECT fetched_at,hostname FROM hostname_cache WHERE ip=?", (ip,)).fetchone()
        if row:
            age = datetime.now(timezone.utc) - datetime.fromisoformat(row[0])
            if age.total_seconds() < HOSTNAME_CACHE_HOURS * 3600:
                return row[1]
    except Exception:
        pass
    hostname = ""
    try:
        hostname = socket.gethostbyaddr(ip)[0].rstrip(".")
        # Ignore an IP echo or empty result; those are not useful hostnames.
        if hostname == ip:
            hostname = ""
    except Exception:
        hostname = ""
    try:
        with sqlite3.connect(DB_PATH) as c:
            c.execute("INSERT OR REPLACE INTO hostname_cache(ip,fetched_at,hostname) VALUES(?,?,?)", (ip, utcnow(), hostname))
            c.commit()
    except Exception:
        pass
    return hostname


def mac_vendor_lookup(mac):
    mac = normalize_mac(mac)
    if not mac:
        return ""
    try:
        with sqlite3.connect(DB_PATH) as c:
            row = c.execute("SELECT fetched_at,vendor FROM mac_vendor_cache WHERE mac=?", (mac,)).fetchone()
        if row:
            age = datetime.now(timezone.utc) - datetime.fromisoformat(row[0])
            if age.total_seconds() < MACVENDOR_CACHE_HOURS * 3600:
                return row[1]
    except Exception:
        pass
    vendor = ""
    try:
        r = requests.get(f"{MACVENDOR_URL}/{quote(mac, safe='')}", timeout=8)
        if r.status_code == 200:
            vendor = r.text.strip()
    except Exception as e:
        print("MAC vendor lookup error:", repr(e), flush=True)
    try:
        with sqlite3.connect(DB_PATH) as c:
            c.execute("INSERT OR REPLACE INTO mac_vendor_cache(mac,fetched_at,vendor) VALUES(?,?,?)", (mac, utcnow(), vendor))
            c.commit()
    except Exception:
        pass
    return vendor


def enrich_device_network_identity(c, device_key, ips, mac, hostname_hint=""):
    hostname = str(hostname_hint or "").strip()
    if not hostname:
        for ip in ips or []:
            hostname = hostname_for_ip(ip)
            if hostname:
                break
    vendor = mac_vendor_lookup(mac) if mac else ""
    row = c.execute("SELECT hostname,mac,vendor FROM devices WHERE device_key=?", (device_key,)).fetchone()
    if not row:
        return hostname, vendor
    # Keep an AdGuard-provided hostname ahead of reverse DNS unless the DB is empty.
    final_hostname = row[0] or hostname
    final_mac = mac or row[1]
    final_vendor = vendor or row[2]
    c.execute("UPDATE devices SET hostname=?, mac=?, vendor=? WHERE device_key=?", (final_hostname, final_mac, final_vendor, device_key))
    return final_hostname, final_vendor


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
                device_ips_now = ips or ([ident] if is_ip(ident) else [])
                upsert_device(c, device_key, cname, hostname, mac, device_ips_now, source, info, now)
                enrich_device_network_identity(c, device_key, device_ips_now, mac, hostname)
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
                device_ips_now = ips or ([ident] if is_ip(ident) else [])
                upsert_device(c, device_key, name or cname, hostname, mac, device_ips_now, source, info, now, increment=False)
                enrich_device_network_identity(c, device_key, device_ips_now, mac, hostname)
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


def apex_domain(domain):
    labels = [x for x in str(domain or '').strip('.').lower().split('.') if x]
    if len(labels) <= 2:
        return '.'.join(labels)
    # Conservative fallback for common two-label public suffixes.
    if len(labels) >= 3 and labels[-2] in {"co", "com", "net", "org", "gov", "ac"} and len(labels[-1]) <= 3:
        return '.'.join(labels[-3:])
    return '.'.join(labels[-2:])


def _strip_html_text(html):
    text = re.sub(r"<script[\s\S]*?</script>", " ", html, flags=re.I)
    text = re.sub(r"<style[\s\S]*?</style>", " ", text, flags=re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return (text.replace("&amp;", "&").replace("&quot;", '"')
            .replace("&#39;", "'").replace("&nbsp;", " ").strip())


def _netify_value(obj, *keys):
    if not isinstance(obj, dict):
        return ""
    for key in keys:
        value = obj.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def netify_lookup(domain, force=False):
    """Best-effort enrichment from Netify's public hostname pages.
    Netify's paid Hostname API requires a key, so the Inspector uses the public
    hostname/application pages as secondary evidence and caches the result.
    """
    domain = str(domain or '').strip('.').lower()
    if not domain:
        return {}
    try:
        with sqlite3.connect(DB_PATH) as c:
            row = c.execute("SELECT fetched_at,json FROM netify_cache WHERE domain=?", (domain,)).fetchone()
        if row:
            age = datetime.now(timezone.utc) - datetime.fromisoformat(row[0])
            if (not force) or age.total_seconds() < NETIFY_CACHE_HOURS * 3600:
                return json.loads(row[1])
    except Exception:
        pass
    if not force:
        return {}

    result = {}
    candidates = [domain]
    apex = apex_domain(domain)
    if apex and apex != domain:
        candidates.append(apex)
    try:
        for candidate in candidates:
            url = f"{NETIFY_URL}{quote(candidate, safe='.-_')}"
            r = session.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0 DNS-Inspector/" + APP_VERSION})
            if not r.ok:
                continue
            html = r.text
            text = _strip_html_text(html)

            # Netify pages expose several facts as labelled fields. Keep the parser
            # deliberately generic so minor wording/layout changes do not break it.
            for label, key in (("Application", "application"), ("Platform", "platform"),
                               ("Network", "network"), ("ASN", "asn"), ("Company", "company_name"),
                               ("Country", "country"), ("Website", "website_url")):
                if result.get(key):
                    continue
                m = re.search(rf"\b{re.escape(label)}\s*[:\-]\s*([^|;]{{2,180}})", text, re.I)
                if m:
                    value = m.group(1).strip(" .,:;")
                    if value:
                        result[key] = value

            # Structured data is more stable than page prose when Netify changes its UI.
            structured = []
            for block in re.findall(r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>', html, re.I | re.S):
                try:
                    data = json.loads(block.strip())
                    structured.extend(data if isinstance(data, list) else [data])
                except Exception:
                    pass
            for obj in structured:
                if not isinstance(obj, dict):
                    continue
                if not result.get("application"):
                    result["application"] = _netify_value(obj, "name", "headline")
                if not result.get("description"):
                    result["description"] = _netify_value(obj, "description")
                if not result.get("website_url"):
                    result["website_url"] = _netify_value(obj, "url")
                author = obj.get("author") or obj.get("publisher")
                if isinstance(author, dict) and not result.get("company_name"):
                    result["company_name"] = _netify_value(author, "name")

            # Common Netify wording on hostname pages.
            patterns = [
                r"is associated with (?:the )?(.+?) application",
                r"associated with (?:the )?(.+?) application",
            ]
            for pat in patterns:
                m = re.search(pat, text, re.I)
                if m:
                    app_name = m.group(1).strip(" .,:;-")
                    if app_name:
                        result["application"] = app_name
                        break

            # Extract useful hostname/network facts when present on the public page.
            if not result.get("ips"):
                ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
                if ips:
                    result["ips"] = list(dict.fromkeys(ips))[:32]
            if not result.get("country"):
                country_map = {
                    "korean": "South Korea", "south korean": "South Korea", "american": "United States",
                    "german": "Germany", "japanese": "Japan", "chinese": "China", "french": "France",
                    "british": "United Kingdom", "canadian": "Canada"
                }
                m = re.search(r"([A-Za-z][A-Za-z -]{2,30}) is a ([A-Za-z -]+)-based", text)
                if m:
                    result["country"] = country_map.get(m.group(2).strip().lower(), "")
                    if not result.get("company_name"):
                        result["company_name"] = m.group(1).strip()
                    if not result.get("description"):
                        result["description"] = text[max(0, m.start()):m.end()+180]

            # Netify application pages can expose the primary domain/website.
            if result.get("application") and not result.get("website_url"):
                slug = re.sub(r"[^a-z0-9]+", "-", result["application"].lower()).strip("-")
                if slug:
                    try:
                        ar = session.get(
                            f"https://www.netify.ai/resources/applications/{quote(slug, safe='-')}",
                            timeout=10,
                            headers={"User-Agent": "Mozilla/5.0 DNS-Inspector/" + APP_VERSION},
                        )
                        if ar.ok:
                            at = _strip_html_text(ar.text)
                            pm = re.search(r"Primary Domains\s+(.{0,1000})", at, re.I)
                            if pm:
                                domains = re.findall(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", pm.group(1).lower())
                                if domains:
                                    result["website_url"] = "https://" + domains[0]
                    except Exception:
                        pass

            # Useful fallbacks for the UI: Netify application names often encode the owner.
            app = result.get("application", "")
            if not result.get("company_name") and app:
                for marker, owner in (("LG Smart TV", "LG Electronics"), ("LG TV", "LG Electronics"),
                                      ("Samsung", "Samsung Electronics"), ("Bosch", "Bosch"),
                                      ("Roborock", "Roborock"), ("PETKIT", "PETKIT")):
                    if marker.lower() in app.lower():
                        result["company_name"] = owner
                        break

            if result:
                result["source_url"] = url
                break
    except Exception as e:
        print("Netify lookup error:", repr(e), flush=True)

    try:
        with sqlite3.connect(DB_PATH) as c:
            c.execute("INSERT OR REPLACE INTO netify_cache(domain,fetched_at,json) VALUES(?,?,?)", (domain, utcnow(), json.dumps(result)))
            c.commit()
    except Exception:
        pass
    return result


def rdap_lookup(domain, force=False):
    domain = str(domain or '').strip('.').lower()
    candidates = [domain]
    apex = apex_domain(domain)
    if apex and apex != domain:
        candidates.append(apex)
    for candidate in candidates:
        try:
            with sqlite3.connect(DB_PATH) as c:
                row = c.execute("SELECT fetched_at,json FROM rdap_cache WHERE domain=?", (candidate,)).fetchone()
            if row:
                age = datetime.now(timezone.utc) - datetime.fromisoformat(row[0])
                if (not force) or age.total_seconds() < RDAP_CACHE_HOURS * 3600:
                    cached = json.loads(row[1])
                    if cached.get("org") or candidate == apex:
                        cached["queried_domain"] = candidate
                        return cached
            if not force:
                continue

            r = requests.get(f"{RDAP_URL}/{quote(candidate, safe='')}", timeout=8, allow_redirects=True)
            result = {}
            if r.ok:
                data = r.json()
                result = {"org": "", "name": data.get("name", ""), "handle": data.get("handle", ""), "country": "", "registrar": ""}
                for ent in data.get("entities") or []:
                    v = ent.get("vcardArray")
                    if isinstance(v, list) and len(v) == 2:
                        for item in v[1]:
                            if not item:
                                continue
                            if item[0] == "fn" and len(item) > 3 and not result["org"]:
                                result["org"] = item[3]
                            if item[0] == "adr" and len(item) > 3 and isinstance(item[3], list) and len(item[3]) >= 7:
                                result["country"] = result["country"] or str(item[3][6] or "")
                    if result["org"] and result["country"]:
                        break
                for ent in data.get("entities") or []:
                    roles = ent.get("roles") or []
                    if "registrar" in roles:
                        v = ent.get("vcardArray")
                        if isinstance(v, list) and len(v) == 2:
                            for item in v[1]:
                                if item and item[0] == "fn" and len(item) > 3:
                                    result["registrar"] = item[3]
                                    break
                        if result["registrar"]:
                            break
            with sqlite3.connect(DB_PATH) as c:
                c.execute("INSERT OR REPLACE INTO rdap_cache(domain,fetched_at,json) VALUES(?,?,?)", (candidate, utcnow(), json.dumps(result)))
                c.commit()
            if result.get("org") or candidate == apex:
                result["queried_domain"] = candidate
                return result
        except Exception as e:
            print("RDAP lookup error:", repr(e), flush=True)
    return {}


def dns_records_lookup(domain, force=False):
    """Resolve useful public DNS records through DNS-over-HTTPS.
    DNSChecker remains an external verification link; the Inspector uses direct
    DNS queries so its fields can be populated automatically without scraping UI.
    """
    domain = str(domain or '').strip('.').lower()
    if not domain:
        return {}
    try:
        with sqlite3.connect(DB_PATH) as c:
            row = c.execute("SELECT fetched_at,json FROM dns_records_cache WHERE domain=?", (domain,)).fetchone()
        if row:
            age = datetime.now(timezone.utc) - datetime.fromisoformat(row[0])
            if (not force) or age.total_seconds() < DNS_RECORDS_CACHE_HOURS * 3600:
                return json.loads(row[1])
    except Exception:
        pass
    if not force:
        return {}

    records = {}
    for rtype in ("A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA", "CAA", "SRV"):
        values = []
        try:
            resp = session.get(
                "https://dns.google/resolve",
                params={"name": domain, "type": rtype},
                headers={"Accept": "application/dns-json", "User-Agent": "DNS-Inspector/" + APP_VERSION},
                timeout=6,
            )
            if resp.ok:
                data = resp.json()
                for ans in data.get("Answer") or []:
                    value = str(ans.get("data", "")).strip()
                    if value and value not in values:
                        values.append(value)
        except Exception:
            pass
        if values:
            records[rtype] = values[:20]

    try:
        with sqlite3.connect(DB_PATH) as c:
            c.execute("INSERT OR REPLACE INTO dns_records_cache(domain,fetched_at,json) VALUES(?,?,?)", (domain, utcnow(), json.dumps(records)))
            c.commit()
    except Exception:
        pass
    return records


def _cache_needs_refresh(table, domain, max_age_hours):
    """Return True when a cache row is missing or older than its TTL."""
    try:
        with sqlite3.connect(DB_PATH) as c:
            row = c.execute(f"SELECT fetched_at FROM {table} WHERE domain=?", (domain,)).fetchone()
        if not row:
            return True
        age = datetime.now(timezone.utc) - datetime.fromisoformat(row[0])
        return age.total_seconds() >= max_age_hours * 3600
    except Exception:
        return True


def refresh_domain_enrichment(domain):
    """Refresh slow external enrichment in the background, never in the request path."""
    domain = str(domain or '').strip('.').lower()
    if not domain:
        return
    with enrichment_lock:
        if domain in enrichment_refreshing:
            return
        enrichment_refreshing.add(domain)

    def run():
        try:
            netify_lookup(domain, force=True)
            rdap_lookup(domain, force=True)
            dns_records_lookup(domain, force=True)
        except Exception as e:
            print("enrichment refresh error:", repr(e), flush=True)
        finally:
            with enrichment_lock:
                enrichment_refreshing.discard(domain)

    threading.Thread(target=run, daemon=True, name=f"enrich:{domain}").start()


def resolve_dns(domain, records=None):
    """Return A/AAAA values exclusively from the local DNS-record cache.
    A missing cache is intentionally not resolved synchronously; the background
    enrichment worker will populate it without delaying the page.
    """
    records = records or {}
    ips = []
    for rtype in ("A", "AAAA"):
        for value in records.get(rtype, []) or []:
            value = str(value).strip()
            if value and value not in ips:
                ips.append(value)
    return ips[:12]

def inline_inline_external_button(url, title, icon="↗"):
    glyph = "<svg viewBox='0 0 24 24' aria-hidden='true'><circle cx='11' cy='11' r='6.5'></circle><path d='M16 16l5 5'></path></svg>" if icon == "" else _html(icon)
    return f"<a class='inline-tool' href='{_html(url)}' title='{_html(title)}' target='_blank' rel='noopener noreferrer'>{glyph}</a>"


def netify_url(hostname):
    host = str(hostname or '').strip().rstrip('.').lower()
    return f"https://www.netify.ai/resources/hostnames/{quote(host, safe='.-_')}" if host else ''


def dnschecker_url(hostname):
    host = str(hostname or '').strip().rstrip('.').lower()
    return f"https://dnschecker.org/all-dns-records-of-domain.php?query={quote(host, safe='')}&rtype=ALL&dns=google" if host else ''


def mac_lookup_url(mac):
    mac = normalize_mac(mac)
    return f"https://macvendors.com/{quote(mac, safe=':') }" if mac else ''


def device_search_url(name, hostname='', vendor=''):
    parts = [str(x).strip() for x in (name, hostname, vendor) if str(x or '').strip()]
    q = ' '.join(dict.fromkeys(parts))
    return f"https://www.google.com/search?q={quote(q, safe='')}" if q else ''


def vendor_lookup_url(vendor):
    vendor = str(vendor or '').strip()
    return f"https://www.google.com/search?q={quote(vendor, safe='')}" if vendor else ''


def domain_external_tools(domain):
    host = str(domain or '').strip().rstrip('.').lower()
    if not host:
        return ''
    buttons = [
        inline_external_button(netify_url(host), 'Netify'),
        inline_external_button(dnschecker_url(host), 'DNS records'),
        inline_external_button(f"https://www.google.com/search?q={quote(host, safe='')}", 'Search'),
    ]
    return "<div class='external-tools'><span class='sub' style='align-self:center'>External:</span>" + ''.join(buttons) + "</div>"


def inspect_html(result):
    if not result:
        return ""
    client_rows = []
    for c in result["client_details"]:
        key = quote(c.get("device_key", ""), safe="")
        linked_name = c.get("display_name") or c.get("name") or ""
        name_value = linked_name or c.get("vendor") or c.get("device_key") or "Unknown"
        name = _html(name_value)
        name_html = f"<a class='link-device' href='/device?key={key}'><div class='device-name'>{name}</div></a>" if linked_name else f"<div class='device-name'>{name}</div>"
        logo = vendor_visual(c.get("vendor"), c.get("vendor_logo"), True, c.get("icon", "◈"))
        vendor_tools = inline_inline_external_button(vendor_lookup_url(c.get('vendor')), "Vendor lookup", "") if c.get('vendor') else ""
        vendor = f"<div class='sub'>{vendor_visual(c.get('vendor'), c.get('vendor_logo'))}{_html(c['vendor'])}{vendor_tools}</div>" if c.get("vendor") else ""
        host = f"<div class='sub mono'><a class='link-device' href='/device?key={key}'>HOST {_html(c['hostname'])}</a></div>" if c.get("hostname") and c.get("hostname") != c.get("display_name") else ""
        mac = _html(c.get("mac") or "—")
        mac_tools = inline_inline_external_button(mac_lookup_url(c.get("mac")), "MAC vendor lookup", "") if c.get("mac") else ""
        ips = ''.join(f"<a class='client-chip mono link-ip' href='/ip?addr={quote(ip, safe='')}'>{_html(ip)}</a>" for ip in c.get("ips", [])) or '—'
        client_rows.append(f"<tr><td><div class='device'><a class='link-device' href='/device?key={key}'>{logo}</a><span>{name_html}{vendor}{host}<div class='confidence'>{_html(c.get('type'))} · {_html(c.get('confidence_label'))}</div></span></div></td><td>{ips}</td><td><span class='mono'>{mac}</span> {mac_tools}</td><td>{c['requests']}</td></tr>")
    clients_html = ''.join(client_rows)
    e = result["explanation"]
    evidence_html = "".join(f"<li>{_html(x)}</li>" for x in e["evidence"])
    dns_html = "".join(f"<a class='dns-ip link-ip' href='/ip?addr={quote(ip, safe='')}'>{_html(ip)}</a>" for ip in result['dns']) or "<span class='sub'>No A/AAAA result</span>"
    return f"""
<div class='card'><h2>{_html(result['domain'])}</h2>
<div><span class='tag {result['badge_class']}'>{_html(result['classification'])}</span>
{f"<span class='tag'>{_html(result['tracker'].get('category'))}</span>" if result['tracker'].get('category') else ''}
{f"<span class='tag'>{_html(result['tracker'].get('name'))}</span>" if result['tracker'].get('name') else ''}</div>
{domain_external_tools(result['domain'])}
<div class='grid'><div><h3>Who</h3>
<div class='kv'><b>Company:</b> {_html(result['company']['name'] or 'Unknown')}</div>
<div class='kv'><b>Country:</b> {_html(result['company']['country'] or '—')}</div>
<div class='kv'><b>Website:</b> {f"<a href='{_html(result['company']['website_url'])}' target='_blank' rel='noopener noreferrer'>{_html(result['company']['website_url'])}</a>" if result['company']['website_url'] else '—'}</div>
<div class='kv'><b>RDAP:</b> {_html(result['rdap'].get('org') or 'Not available')}</div></div>
<div><h3>Why is this here?</h3>
<div class='signal signal-{e['tone']}'><div class='signal-title'>{_html(e['summary'])}</div><ul class='evidence'>{evidence_html}</ul><div>Confidence: <span class='confidence-{e['confidence'].lower()}'>{_html(e['confidence'])}</span></div></div></div></div>
<h3>Infrastructure</h3><div class='grid'><div><div class='kv'><b>DNS:</b><div class='dns-list'>{dns_html}</div></div><div class='kv'><b>CNAME:</b> {_html(' · '.join(result['dns_records'].get('CNAME', [])) or '—')}</div><div class='kv'><b>NS:</b> {_html(' · '.join(result['dns_records'].get('NS', [])) or '—')}</div><div class='kv'><b>RDAP name:</b> {_html(result['rdap'].get('name') or '—')}</div></div>
<div><div class='kv'><b>Netify:</b> {_html(result['netify'].get('application') or 'No match')}</div><div class='kv'><b>Platform:</b> {_html(result['netify'].get('platform') or '—')}</div><div class='kv'><b>Network:</b> {_html(result['netify'].get('network') or '—')}</div><div class='kv'><b>ASN:</b> {_html(result['netify'].get('asn') or '—')}</div><div class='kv'><b>TrackerDB domain:</b> {_html(result['tracker'].get('matched_domain') or 'No match')}</div><div class='kv'><b>Source snapshot:</b> WhoTracks.me / Ghostery TrackerDB</div></div></div>
<h3>Local activity</h3><p><b>Requests:</b> {result['requests']} &nbsp; <b>Clients:</b> {len(result['clients'])} &nbsp; <b>DNS addresses:</b> {len(result['dns'])}</p>
<table><thead><tr><th>Device</th><th>IP(s)</th><th>MAC</th><th>Queries</th></tr></thead><tbody>{clients_html}</tbody></table>
<p class='source'>Stable identity prefers MAC or a non-IP AdGuard client identifier, then a named hostname; IPs are observations and may change with DHCP. AdGuard runtime clients can come from rDNS/hosts/ARP/DHCP sources.</p>
</div>"""


def _html(v):
    s = str(v or "")
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;"))


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


VENDOR_LOGOS = {
    "dell": "/static/vendor-logos/dell.svg",
    "lg innotek": "/static/vendor-logos/lg.svg",
    "lge": "/static/vendor-logos/lg.svg",
    "lg": "/static/vendor-logos/lg.svg",
    "zte": "/static/vendor-logos/zte.svg",
    "bosch": "/static/vendor-logos/bosch.svg",
    "roborock": "/static/vendor-logos/roborock.svg",
    "beijing roborock technology": "/static/vendor-logos/roborock.svg",
    "petkit": "/static/vendor-logos/petkit.svg",
}

def vendor_logo_url(vendor):
    text = str(vendor or "").lower()
    for key, url in VENDOR_LOGOS.items():
        if key in text:
            return url
    return ""




def vendor_visual(vendor, logo_url="", large=False, fallback="◈"):
    cls = "vendor-logo-lg" if large else "vendor-logo"
    mark_cls = "vendor-mark-lg" if large else "vendor-mark"
    if logo_url:
        return f"<img class=\"{cls}\" src=\"{_html(logo_url)}\" alt=\"\" loading=\"lazy\">"
    return f"<span class=\"{mark_cls}\">{_html(fallback)}</span>"


def canonicalize_client_map(clients):
    """Collapse legacy IP client keys into MAC keys using the current neighbor snapshot.
    This is read-only and makes the UI correct immediately, even before the background
    reconciliation transaction has run.
    """
    neighbors = load_neighbors()
    merged = {}
    for key, count in clients.items():
        new_key = key
        if str(key).startswith("ip:"):
            mac = neighbors.get(str(key)[3:])
            if mac:
                new_key = "mac:" + mac
        merged[new_key] = merged.get(new_key, 0) + count
    return merged


def build_explanation(domain, tracker, rdap, client_details, netify=None):
    cat = (tracker.get("category") or "").lower()
    vendors = sorted({c.get("vendor", "") for c in client_details if c.get("vendor")})
    hostnames = sorted({c.get("hostname", "") for c in client_details if c.get("hostname")})
    evidence = []
    if client_details: evidence.append(f"{len(client_details)} local device(s) contacted this domain")
    if vendors: evidence.append("Vendor signals: " + ", ".join(vendors[:3]))
    if hostnames: evidence.append("Known hostnames: " + ", ".join(hostnames[:3]))
    if tracker.get("matched_domain"): evidence.append(f"TrackerDB match: {tracker.get('matched_domain')}")
    if rdap.get("org"): evidence.append(f"RDAP ownership: {rdap.get('org')}")
    if netify and netify.get("application"): evidence.append(f"Netify application: {netify.get('application')}")
    if netify and netify.get("company_name"): evidence.append(f"Netify company: {netify.get('company_name')}")
    if cat == "advertising": summary, tone, confidence = "Likely advertising / ad delivery.", "orange", "High"
    elif cat in {"site_analytics", "social_media", "extensions"}: summary, tone, confidence = "Likely telemetry or tracking.", "yellow", "High"
    elif cat: summary, tone, confidence = "Known third-party service.", "green", "Medium"
    elif rdap.get("org"): summary, tone, confidence = "Known infrastructure with ownership data.", "blue", "Medium"
    else: summary, tone, confidence = "Purpose is not established from available signals.", "gray", "Low"
    return {"summary": summary, "tone": tone, "confidence": confidence, "evidence": evidence or ["No strong identifying signals are available yet"]}


def inspect_domain(domain):
    domain = domain.lower().rstrip(".")
    with sqlite3.connect(DB_PATH) as c:
        row = c.execute("SELECT domain,first_seen,last_seen,requests,clients_json FROM domains WHERE domain=?", (domain,)).fetchone()
        if not row:
            return None
        tracker = tracker_lookup(domain)
        # Slow external enrichment is read from local cache only. Missing or
        # expired data is refreshed asynchronously below.
        rdap = rdap_lookup(domain)
        netify = netify_lookup(domain)
        dns_records = dns_records_lookup(domain)
        classification, badge, severity = classify(tracker, rdap)
        clients_map = canonicalize_client_map(json.loads(row[4] or "{}"))
        client_details = [client_display(c, key, count) for key, count in sorted(clients_map.items(), key=lambda kv: kv[1], reverse=True)]

    needs_refresh = (
        _cache_needs_refresh("netify_cache", domain, NETIFY_CACHE_HOURS)
        or _cache_needs_refresh("rdap_cache", apex_domain(domain), RDAP_CACHE_HOURS)
        or _cache_needs_refresh("dns_records_cache", domain, DNS_RECORDS_CACHE_HOURS)
    )
    if needs_refresh:
        refresh_domain_enrichment(domain)

    dns = resolve_dns(domain, dns_records)
    return {
        "domain": row[0], "first_seen": row[1], "last_seen": row[2], "requests": row[3], "clients": clients_map,
        "classification": classification, "badge_class": badge, "severity_class": severity, "tracker": tracker,
        "company": {"name": tracker.get("company_name") or rdap.get("org") or netify.get("company_name") or netify.get("application") or "", "description": tracker.get("description", "") or netify.get("description", ""), "website_url": tracker.get("company_website", "") or tracker.get("website_url", "") or netify.get("website_url", ""), "country": tracker.get("country", "") or rdap.get("country", "") or netify.get("country", "")},
        "rdap": rdap, "netify": netify, "dns": dns, "dns_records": dns_records, "client_details": client_details,
        "explanation": build_explanation(domain, tracker, rdap, client_details, netify),
    }

def get_recent():
    with sqlite3.connect(DB_PATH) as c:
        rows = c.execute("SELECT domain,requests,clients_json FROM domains ORDER BY requests DESC LIMIT 50").fetchall()
        out = []
        for domain, requests_count, clients_json in rows:
            t = tracker_lookup(domain)
            r = rdap_lookup(domain)
            cls, badge, severity = classify(t, r)
            clients = canonicalize_client_map(json.loads(clients_json or "{}"))
            device_rows = []
            for key, count in sorted(clients.items(), key=lambda kv: kv[1], reverse=True)[:6]:
                d = client_display(c, key, count)
                device_rows.append({"device_key": d.get("device_key", key), "identifier": d.get("identifier", key), "name": d.get("hostname") or d.get("name") or d.get("vendor") or d.get("display_name") or key, "icon": d.get("icon", "📦"), "vendor_logo": d.get("vendor_logo", "")})
            out.append({"domain": domain, "requests": requests_count, "clients": len(clients), "devices": device_rows, "classification": cls, "badge_class": badge, "severity_class": severity})
    return out


def get_clients():
    with sqlite3.connect(DB_PATH) as c:
        rows = c.execute("SELECT device_key,name,hostname,mac,vendor,device_type,icon,confidence,source,request_count FROM devices ORDER BY request_count DESC").fetchall()
        out = []
        for device_key, name, hostname, mac, vendor, dtype, icon, confidence, source, count in rows:
            ips = device_ip_list(c, device_key)
            out.append({"identifier": device_key, "name": name, "display_name": hostname or name or vendor or device_key, "hostname": hostname, "mac": mac, "vendor": vendor, "vendor_logo": vendor_logo_url(vendor), "type": dtype, "icon": icon, "confidence_label": confidence, "source": source, "requests": count, "ips": ips})
    return out


def domains_for_device(c, device_key, limit=25):
    rows = c.execute("SELECT domain,requests,clients_json,last_seen FROM domains ORDER BY requests DESC").fetchall()
    out = []
    for domain, requests_count, clients_json, last_seen in rows:
        try:
            clients = json.loads(clients_json or "{}")
        except Exception:
            clients = {}
        if device_key in clients:
            out.append({"domain": domain, "requests": int(clients.get(device_key, 0)), "last_seen": last_seen})
            if len(out) >= limit:
                break
    return out


def device_detail(device_key):
    if not device_key:
        return None
    with sqlite3.connect(DB_PATH) as c:
        row = c.execute("SELECT device_key,name,hostname,mac,vendor,device_type,icon,confidence,source,first_seen,last_seen,request_count FROM devices WHERE device_key=?", (device_key,)).fetchone()
        if not row:
            return None
        d = {"device_key": row[0], "name": row[1], "hostname": row[2], "mac": row[3], "vendor": row[4], "type": row[5], "icon": row[6], "confidence": row[7], "source": row[8], "first_seen": row[9], "last_seen": row[10], "request_count": row[11], "vendor_logo": vendor_logo_url(row[4])}
        d["ips"] = [{"ip": r[0], "first_seen": r[1], "last_seen": r[2], "requests": r[3]} for r in c.execute("SELECT ip,first_seen,last_seen,requests FROM device_ips WHERE device_key=? ORDER BY last_seen DESC", (device_key,)).fetchall()]
        d["domains"] = domains_for_device(c, device_key)
    return d


def ip_detail(ip):
    if not is_ip(ip):
        return None
    with sqlite3.connect(DB_PATH) as c:
        rows = c.execute("SELECT d.device_key,d.name,d.hostname,d.mac,d.vendor,d.device_type,d.icon,d.confidence,d.source,di.first_seen,di.last_seen,di.requests FROM device_ips di JOIN devices d ON d.device_key=di.device_key WHERE di.ip=? ORDER BY di.last_seen DESC", (ip,)).fetchall()
        devices = []
        device_keys = set()
        for r in rows:
            device_keys.add(r[0])
            devices.append({"device_key": r[0], "name": r[1], "hostname": r[2], "mac": r[3], "vendor": r[4], "type": r[5], "icon": r[6], "confidence": r[7], "source": r[8], "first_seen": r[9], "last_seen": r[10], "requests": r[11], "vendor_logo": vendor_logo_url(r[4])})
        domains = []
        for domain, requests_count, clients_json, last_seen in c.execute("SELECT domain,requests,clients_json,last_seen FROM domains ORDER BY requests DESC").fetchall():
            try:
                clients = json.loads(clients_json or "{}")
            except Exception:
                clients = {}
            count = sum(int(clients.get(k, 0)) for k in device_keys)
            if count:
                domains.append({"domain": domain, "requests": count, "last_seen": last_seen})
                if len(domains) >= 50:
                    break
    return {"ip": ip, "devices": devices, "domains": domains}


def detail_html_device(d):
    primary = d.get("hostname") or d.get("name") or d.get("vendor") or d.get("device_key")
    logo = vendor_visual(d.get("vendor"), d.get("vendor_logo"), True, d.get("icon", "◈"))
    ips = "".join(f"<a class='client-chip mono link-ip' href='/ip?addr={quote(x['ip'], safe='')}'>{_html(x['ip'])}</a>" for x in d['ips']) or "—"
    domains = "".join(f"<tr><td><a href='/search?q={quote(x['domain'], safe='')}'>{_html(x['domain'])}</a></td><td>{x['requests']}</td><td class='mono'>{_html(x['last_seen'])}</td></tr>" for x in d['domains']) or "<tr><td colspan='3' class='sub'>No domain activity recorded.</td></tr>"
    device_tools = []
    search_url = device_search_url(primary, d.get('hostname'), d.get('vendor'))
    if search_url: device_tools.append(inline_external_button(search_url, 'Search device'))
    if d.get('mac'): device_tools.append(inline_external_button(mac_lookup_url(d['mac']), 'MAC lookup'))
    return f"""<div class='card'><p><a href='/'>&larr; Back to dashboard</a></p><div class='device' style='margin-bottom:14px'><span>{logo}</span><span><h2 style='margin:0'>{_html(primary)}</h2><div class='sub'>{_html(d.get('vendor') or 'Unknown vendor')}</div><div class='confidence'>{_html(d.get('type'))} · {_html(d.get('confidence'))}</div></span></div><div class='external-tools'>{''.join(device_tools)}</div><div class='grid'><div><div class='kv'><b>MAC:</b> <span class='mono'>{_html(d.get('mac') or '—')}</span></div><div class='kv'><b>Hostname:</b> <span class='mono'>{_html(d.get('hostname') or '—')}</span></div><div class='kv'><b>Source:</b> {_html(d.get('source') or '—')}</div></div><div><div class='kv'><b>First seen:</b> {_html(d.get('first_seen') or '—')}</div><div class='kv'><b>Last seen:</b> {_html(d.get('last_seen') or '—')}</div><div class='kv'><b>Total queries:</b> {_html(d.get('request_count'))}</div></div></div><h3>IP history</h3><div class='dns-list'>{ips}</div><h3>Top DNS activity</h3><table><thead><tr><th>Domain</th><th>Queries</th><th>Last seen</th></tr></thead><tbody>{domains}</tbody></table></div>"""


def detail_html_ip(d):
    device_rows = []
    for x in d['devices']:
        href = quote(x['device_key'], safe='')
        linked_primary = x.get('hostname') or x.get('name') or x.get('display_name') or ''
        primary = linked_primary or x.get('vendor') or x['device_key']
        label = f"<a class='link-device' href='/device?key={href}'>{_html(primary)}</a>" if linked_primary else _html(primary)
        visual = vendor_visual(x.get('vendor'), x.get('vendor_logo'), False, x.get('icon','◈'))
        device_rows.append(f"<tr><td>{visual}{label}</td><td class='mono'>{_html(x.get('mac') or '—')} {inline_inline_external_button(mac_lookup_url(x.get('mac')), 'MAC vendor lookup', '') if x.get('mac') else ''}</td><td>{x['requests']}</td></tr>")
    devices = ''.join(device_rows) or "<tr><td colspan='3' class='sub'>No known device mapping.</td></tr>"
    domains = "".join(f"<tr><td><a href='/search?q={quote(x['domain'], safe='')}'>{_html(x['domain'])}</a></td><td>{x['requests']}</td><td class='mono'>{_html(x['last_seen'])}</td></tr>" for x in d['domains']) or "<tr><td colspan='3' class='sub'>No DNS activity recorded.</td></tr>"
    return f"""<div class='card'><p><a href='/'>&larr; Back to dashboard</a></p><h2 class='mono'>{_html(d['ip'])}</h2><p class='muted'>IP observation · {len(d['devices'])} known device(s)</p><h3>Known devices</h3><table><thead><tr><th>Device</th><th>MAC</th><th>Queries</th></tr></thead><tbody>{devices}</tbody></table><h3>Domains contacted</h3><table><thead><tr><th>Domain</th><th>Queries</th><th>Last seen</th></tr></thead><tbody>{domains}</tbody></table></div>"""

def recent_html(recent):
    return "".join(f"<tr><td><a href='/search?q={quote(r['domain'], safe='')}'>{_html(r['domain'])}</a></td><td>{r['requests']}</td><td>{r['clients']}</td><td><span class='dot dot-{r['severity_class']}'></span><span class='tag {r['badge_class']}'>{_html(r['classification'])}</span></td></tr>" for r in recent)


def clients_html(clients):
    rows = []
    for c in clients:
        key = c.get('identifier','')
        href = quote(key, safe='')
        linked_primary = c.get('hostname') or c.get('name') or c.get('display_name') or ''
        primary = linked_primary or c.get('vendor') or key
        primary_html = f"<a class='link-device' href='/device?key={href}'><div class='device-name'>{_html(primary)}</div></a>" if linked_primary else f"<div class='device-name'>{_html(primary)}</div>"
        secondary = []
        if c.get('vendor') and c.get('vendor') != primary: secondary.append(f"<div class='sub'>{_html(c['vendor'])}{inline_inline_external_button(vendor_lookup_url(c.get('vendor')), 'Vendor lookup', '')}</div>")
        if c.get('hostname') and c.get('hostname') != primary: secondary.append(f"<div class='technical mono'><a class='link-device' href='/device?key={href}'>HOST {_html(c['hostname'])}</a></div>")
        visual = vendor_visual(c.get('vendor'), c.get('vendor_logo'), True, c.get('icon','◈'))
        ips = ''.join(f"<a class='client-chip mono link-ip' href='/ip?addr={quote(ip, safe='')}'>{_html(ip)}</a>" for ip in c.get('ips', [])) or '—'
        mac = _html(c.get('mac') or '—')
        mac_tools = inline_inline_external_button(mac_lookup_url(c.get('mac')), 'MAC vendor lookup', '') if c.get('mac') else ''
        rows.append(f"<tr><td><div class='device'><a class='link-device' href='/device?key={href}'>{visual}</a><span>{primary_html}{''.join(secondary)}<div class='confidence'>{_html(c['type'])} · {_html(c['confidence_label'])}</div></span></div></td><td>{ips}</td><td><span class='mono'>{mac}</span> {mac_tools}</td><td>{c['requests']}</td></tr>")
    return ''.join(rows)


def state_payload(q=""):
    # UI refresh is intentionally read-only against our local SQLite state.
    # AdGuard polling is performed by the background worker every POLL_SECONDS.
    result = inspect_domain(q) if q else None
    return {"updated": utcnow(), "recent": get_recent(), "clients": get_clients(), "inspect_html": inspect_html(result) if result else None}


def client_display(c, device_key, count):
    row = c.execute("SELECT device_key,name,hostname,mac,vendor,device_type,icon,confidence,source,request_count FROM devices WHERE device_key=?", (device_key,)).fetchone()
    if row:
        _, name, hostname, mac, vendor, dtype, icon, confidence, source, total = row
        ips = device_ip_list(c, device_key)
        display = hostname or name or vendor or device_key
        return {"device_key": device_key, "identifier": device_key, "display_name": hostname or name or vendor or display, "name": name, "hostname": hostname, "mac": mac, "vendor": vendor, "vendor_logo": vendor_logo_url(vendor), "type": dtype, "icon": icon, "confidence_label": confidence, "source": source, "requests": count, "ips": ips, "total_requests": total}
    return {"device_key": device_key, "identifier": device_key, "display_name": device_key, "name": "", "hostname": "", "mac": "", "vendor": "", "type": "IoT / Unknown", "icon": "📦", "confidence_label": "low", "source": "historical", "requests": count, "ips": [], "total_requests": count}


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
            # Move IP observations without violating the UNIQUE(device_key, ip) constraint.
            old_ips = c.execute("SELECT ip,last_seen FROM device_ips WHERE device_key=?", (old_key,)).fetchall()
            for old_ip, old_ip_seen in old_ips:
                existing = c.execute("SELECT last_seen FROM device_ips WHERE device_key=? AND ip=?", (new_key, old_ip)).fetchone()
                if existing:
                    keep_seen = existing[0] if (existing[0] or "") >= (old_ip_seen or "") else old_ip_seen
                    c.execute("UPDATE device_ips SET last_seen=? WHERE device_key=? AND ip=?", (keep_seen, new_key, old_ip))
                    c.execute("DELETE FROM device_ips WHERE device_key=? AND ip=?", (old_key, old_ip))
                else:
                    c.execute("UPDATE device_ips SET device_key=? WHERE device_key=? AND ip=?", (new_key, old_key, old_ip))
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
        # Enrich every known device once we have its stable MAC and/or IPs. Cached lookups keep this lightweight.
        device_rows = c.execute("SELECT device_key,mac,hostname FROM devices").fetchall()
        for dkey, dmac, dhost in device_rows:
            ips = [r[0] for r in c.execute("SELECT ip FROM device_ips WHERE device_key=? ORDER BY last_seen DESC LIMIT 6", (dkey,)).fetchall()]
            enrich_device_network_identity(c, dkey, ips, dmac, dhost)
        c.commit()
    if changed:
        print(f"Reconciled {changed} legacy IP device(s) using neighbors.txt.", flush=True)
    return changed


def worker():
    init_db()
    load_neighbors(force=True)
    refresh_runtime_clients()
    # First migrate legacy client identifiers, then reconcile IP identities to MACs.
    # Doing this in the opposite order can reintroduce the old ip:* keys.
    migrate_legacy_domain_clients()
    reconcile_neighbors()
    refresh_trackerdb()
    while True:
        started = time.time()
        ingest()
        elapsed = time.time() - started
        time.sleep(max(1, POLL_SECONDS - elapsed))


@app.route("/")
def index():
    q = request.args.get("q", "").strip()
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


@app.route("/device")
def device_view():
    key = request.args.get("key", "").strip()
    d = device_detail(key)
    if not d:
        return render_template_string(HTML, q="", result=None, inspect_html=f"<div class='card'><h2>Device not found</h2><p class='error'>No device exists for this identity.</p><p><a href='/'>Back to dashboard</a></p></div>", recent_html=recent_html(get_recent()), clients_html=clients_html(get_clients()), version=APP_VERSION, refresh_seconds=UI_REFRESH_SECONDS, refresh_seconds_ms=UI_REFRESH_SECONDS * 1000, updated=utcnow(), error=None), 404
    return render_template_string(HTML, q="", result=None, inspect_html=detail_html_device(d), recent_html=recent_html(get_recent()), clients_html=clients_html(get_clients()), version=APP_VERSION, refresh_seconds=UI_REFRESH_SECONDS, refresh_seconds_ms=UI_REFRESH_SECONDS * 1000, updated=utcnow(), error=None)


@app.route("/ip")
def ip_view():
    addr = request.args.get("addr", "").strip()
    d = ip_detail(addr)
    if not d:
        return render_template_string(HTML, q="", result=None, inspect_html=f"<div class='card'><h2>IP not found</h2><p class='error'>No valid IP observation exists for this address.</p><p><a href='/'>Back to dashboard</a></p></div>", recent_html=recent_html(get_recent()), clients_html=clients_html(get_clients()), version=APP_VERSION, refresh_seconds=UI_REFRESH_SECONDS, refresh_seconds_ms=UI_REFRESH_SECONDS * 1000, updated=utcnow(), error=None), 404
    return render_template_string(HTML, q="", result=None, inspect_html=detail_html_ip(d), recent_html=recent_html(get_recent()), clients_html=clients_html(get_clients()), version=APP_VERSION, refresh_seconds=UI_REFRESH_SECONDS, refresh_seconds_ms=UI_REFRESH_SECONDS * 1000, updated=utcnow(), error=None)


@app.route("/health")
def health():
    return jsonify({"ok": True, "version": APP_VERSION, "adguard": AGH_URL, "trackerdb": trackerdb_ready(), "poll_seconds": POLL_SECONDS, "ui_refresh_seconds": UI_REFRESH_SECONDS})


if __name__ == "__main__":
    init_db()
    threading.Thread(target=worker, daemon=True).start()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
