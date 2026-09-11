import json
import os
import socket
import sqlite3
import threading
import time
from datetime import datetime, timezone
from urllib.parse import quote

import requests
from flask import Flask, jsonify, render_template_string, request

AGH_URL = os.getenv("AGH_URL", "http://192.168.1.100:30004").rstrip("/")
AGH_USER = os.getenv("AGH_USER", "")
AGH_PASS = os.getenv("AGH_PASS", "")
POLL_SECONDS = max(5, int(os.getenv("POLL_SECONDS", "10")))
UI_REFRESH_SECONDS = max(5, int(os.getenv("UI_REFRESH_SECONDS", str(POLL_SECONDS))))
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

HTML = """
<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="0"><title>DNS Inspector</title>
<style>
body{font-family:system-ui;background:#111;color:#eee;margin:30px;max-width:1250px}
input,button{background:#222;color:#eee;border:1px solid #555;padding:9px;border-radius:6px}
input{width:70%}button{cursor:pointer}.card{background:#191919;border:1px solid #333;border-radius:10px;padding:18px;margin-top:18px}
small,.muted{color:#aaa}.tag{display:inline-block;padding:4px 8px;border-radius:12px;background:#333;margin:3px}.green{background:#174d2a}.yellow{background:#5a4610}.orange{background:#5a2e10}.red{background:#5a1717}
table{width:100%;border-collapse:collapse}td,th{padding:8px;border-bottom:1px solid #333;text-align:left}a{color:#8ab4f8}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.kv{padding:7px 0;border-bottom:1px solid #2b2b2b}.kv b{display:inline-block;min-width:140px}
pre{white-space:pre-wrap;word-break:break-word;color:#ddd}.source{font-size:.9em;color:#888}.error{color:#ff9b9b}.live{color:#7ee787;font-weight:700}
.device{display:flex;align-items:center;gap:10px}.icon{font-size:1.5rem}.confidence{font-size:.85em;color:#aaa}
@media(max-width:800px){.grid{grid-template-columns:1fr}input{width:60%}}
</style></head><body>
<h1>DNS Inspector</h1>
<p class="muted">Read-only view of AdGuard Home Query Log. This app never changes AdGuard settings. <span class="live">● Live</span> · refresh every {{refresh_seconds}}s · last update {{updated}}</p>
<form action="/search"><input name="q" placeholder="hostname..." value="{{q}}"><button>Inspect</button></form>
{% if error %}<div class="card error">{{error}}</div>{% endif %}
{% if result %}
<div class="card">
<h2>{{result.domain}}</h2>
<div><span class="tag {{result.badge_class}}">{{result.classification}}</span>
{% if result.tracker.category %}<span class="tag">{{result.tracker.category}}</span>{% endif %}
{% if result.tracker.name %}<span class="tag">{{result.tracker.name}}</span>{% endif %}</div>
<div class="grid"><div><h3>Who</h3>
<div class="kv"><b>Company:</b> {{result.company.name or "Unknown"}}</div>
<div class="kv"><b>Country:</b> {{result.company.country or "—"}}</div>
<div class="kv"><b>Website:</b> {% if result.company.website_url %}<a href="{{result.company.website_url}}" target="_blank">{{result.company.website_url}}</a>{% else %}—{% endif %}</div>
<div class="kv"><b>RDAP:</b> {{result.rdap.org or "Not available"}}</div></div>
<div><h3>What it does</h3>
{% if result.tracker.description %}<p>{{result.tracker.description}}</p>{% elif result.tracker.category %}<p>TrackerDB classifies this endpoint under <b>{{result.tracker.category}}</b>.</p>{% else %}<p class="muted">No TrackerDB description is available. Ownership was checked separately with RDAP; the hostname's exact purpose cannot be established from DNS alone.</p>{% endif %}
{% if result.tracker.website_url %}<p><a href="{{result.tracker.website_url}}" target="_blank">Tracker / service website</a></p>{% endif %}</div></div>
<h3>Infrastructure</h3><div class="grid"><div><div class="kv"><b>DNS:</b> {{result.dns|join(", ") or "No A/AAAA result"}}</div><div class="kv"><b>RDAP name:</b> {{result.rdap.name or "—"}}</div></div>
<div><div class="kv"><b>TrackerDB domain:</b> {{result.tracker.matched_domain or "No match"}}</div><div class="kv"><b>Source snapshot:</b> {{result.trackerdb_snapshot or "—"}}</div></div></div>
<h3>Local activity</h3><p><b>Requests:</b> {{result.requests}} &nbsp; <b>Clients:</b> {{result.clients|length}}</p>
<ul>{% for c in result.clients %}<li>{{client_label(c)}} — {{result.clients[c]}} queries</li>{% endfor %}</ul>
<p class="source">Metadata: Ghostery TrackerDB / WhoTracks.me snapshot + RDAP + AdGuard client discovery. Enrichment only; no blocking decisions.</p>
</div>{% endif %}
<div class="card"><h2>Recent domains</h2>
<table><tr><th>Domain</th><th>Requests</th><th>Clients</th><th>Classification</th></tr>
{% for r in recent %}<tr><td><a href="/search?q={{r.domain|urlencode}}">{{r.domain}}</a></td><td>{{r.requests}}</td><td>{{r.clients}}</td><td><span class="tag {{r.badge_class}}">{{r.classification}}</span></td></tr>{% endfor %}
</table></div>
<div class="card"><h2>Clients seen</h2><table><tr><th>Client</th><th>IP / ID</th><th>Source</th><th>Requests</th></tr>
{% for c in clients %}<tr><td><div class="device"><span class="icon">{{c.icon}}</span><span><b>{{c.display_name}}</b><br><span class="confidence">{{c.confidence_label}}</span></span></div></td><td>{{c.identifier}}</td><td>{{c.source}}</td><td>{{c.requests}}</td></tr>{% endfor %}</table>
<p class="source">Device discovery is intentionally conservative. IPs are current observations; the app does not treat an IP as a permanent device identity.</p></div>
<script>setTimeout(()=>location.reload(), {{refresh_seconds_ms}});</script>
</body></html>
"""

def utcnow():
    return datetime.now(timezone.utc).isoformat()


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
            last_seen TEXT NOT NULL, request_count INTEGER NOT NULL DEFAULT 0, info_json TEXT NOT NULL DEFAULT '{}')""")
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
    if not force and not trackerdb_refresh_needed(): return
    tmp, newdb = TRACKERDB_PATH + ".download", TRACKERDB_PATH + ".new"
    try:
        print("Downloading TrackerDB snapshot...", flush=True)
        r = requests.get(TRACKERDB_URL, timeout=30); r.raise_for_status()
        with open(tmp, "wb") as f: f.write(r.content)
        if os.path.exists(newdb): os.remove(newdb)
        with sqlite3.connect(newdb) as c:
            c.executescript(r.text); c.execute("PRAGMA journal_mode=DELETE"); c.commit()
        os.replace(newdb, TRACKERDB_PATH); os.remove(tmp)
        print("TrackerDB ready.", flush=True)
    except Exception as e:
        print("TrackerDB refresh error:", repr(e), flush=True)
        for p in (tmp, newdb):
            try:
                if os.path.exists(p): os.remove(p)
            except OSError: pass


def agh_login():
    if not AGH_USER: return
    r = session.post(AGH_URL + "/control/login", json={"name": AGH_USER, "password": AGH_PASS}, timeout=10); r.raise_for_status()


def agh_get(path, **kwargs):
    r = session.get(AGH_URL + path, timeout=15, **kwargs)
    if r.status_code in (401, 403):
        agh_login(); r = session.get(AGH_URL + path, timeout=15, **kwargs)
    r.raise_for_status(); return r.json()


def fetch_querylog():
    return agh_get("/control/querylog", params={"limit": 500})


def fetch_clients():
    try:
        return agh_get("/control/clients")
    except Exception as e:
        print("client discovery error:", repr(e), flush=True)
        return {"clients": [], "auto_clients": []}


def client_info_from_entry(entry):
    ident = entry.get("client") or entry.get("client_id") or "unknown"
    info = entry.get("client_info") or {}
    name = (info.get("name") or "").strip()
    source = "querylog"
    if name: source = "AdGuard client_info"
    return str(ident), name, source, info


def ingest():
    try:
        data = fetch_querylog(); entries = data.get("data") or []; now = utcnow()
        with db_lock, sqlite3.connect(DB_PATH) as c:
            for e in entries:
                domain = ((e.get("question") or {}).get("name") or "").rstrip(".").lower()
                ident, cname, source, info = client_info_from_entry(e)
                if not domain: continue
                row = c.execute("SELECT clients_json FROM domains WHERE domain=?", (domain,)).fetchone()
                clients = json.loads(row[0]) if row else {}
                clients[ident] = clients.get(ident, 0) + 1
                if row:
                    c.execute("UPDATE domains SET last_seen=?, requests=requests+1, clients_json=? WHERE domain=?", (now, json.dumps(clients), domain))
                else:
                    c.execute("INSERT INTO domains(domain,first_seen,last_seen,requests,clients_json) VALUES(?,?,?,?,?)", (domain, now, now, 1, json.dumps(clients)))
                old = c.execute("SELECT request_count FROM client_cache WHERE identifier=?", (ident,)).fetchone()
                if old:
                    c.execute("UPDATE client_cache SET name=?, source=?, last_seen=?, request_count=request_count+1, info_json=? WHERE identifier=?", (cname, source, now, json.dumps(info), ident))
                else:
                    c.execute("INSERT INTO client_cache(identifier,name,source,last_seen,request_count,info_json) VALUES(?,?,?,?,?,?)", (ident, cname, source, now, 1, json.dumps(info)))
            c.commit()
        refresh_runtime_clients()
    except Exception as e:
        print("ingest error:", repr(e), flush=True)


def refresh_runtime_clients():
    data = fetch_clients()
    auto = {str(x.get("ip")): x for x in data.get("auto_clients") or [] if x.get("ip")}
    manual = {}
    for x in data.get("clients") or []:
        for ident in x.get("ids") or []:
            manual[str(ident)] = x
    if not auto and not manual: return
    now = utcnow()
    with db_lock, sqlite3.connect(DB_PATH) as c:
        rows = c.execute("SELECT identifier FROM client_cache").fetchall()
        for (ident,) in rows:
            x = manual.get(ident) or auto.get(ident)
            if not x: continue
            name = x.get("name") or ""
            source = "AdGuard configured client" if ident in manual else (x.get("source") or "AdGuard auto-client")
            c.execute("UPDATE client_cache SET name=?, source=?, info_json=? WHERE identifier=?", (name, source, json.dumps(x), ident))
        c.commit()


def tracker_lookup(domain):
    if not trackerdb_ready(): return {}
    labels = domain.rstrip(".").lower().split("."); candidates = [".".join(labels[i:]) for i in range(len(labels))]
    try:
        with sqlite3.connect(TRACKERDB_PATH) as c:
            for candidate in candidates:
                row = c.execute("""SELECT td.domain,t.name,cat.name,t.website_url,t.company_id,
                    coalesce(co.name,''),coalesce(co.description,''),coalesce(co.website_url,''),coalesce(co.country,'')
                    FROM tracker_domains td JOIN trackers t ON t.id=td.tracker LEFT JOIN categories cat ON cat.id=t.category_id
                    LEFT JOIN companies co ON co.id=t.company_id WHERE td.domain=? LIMIT 1""", (candidate,)).fetchone()
                if row: return {"matched_domain":row[0],"name":row[1],"category":row[2] or "","website_url":row[3] or "","company_id":row[4] or "","company_name":row[5],"description":row[6],"company_website":row[7],"country":row[8]}
    except Exception as e: print("tracker lookup error:", repr(e), flush=True)
    return {}


def rdap_lookup(domain):
    try:
        with sqlite3.connect(DB_PATH) as c: row = c.execute("SELECT fetched_at,json FROM rdap_cache WHERE domain=?", (domain,)).fetchone()
        if row:
            age = datetime.now(timezone.utc) - datetime.fromisoformat(row[0])
            if age.total_seconds() < 86400: return json.loads(row[1])
        r = requests.get(f"{RDAP_URL}/{quote(domain, safe='')}", timeout=8, allow_redirects=True)
        if r.ok:
            data = r.json(); result = {"org":"","name":data.get("name",""),"handle":data.get("handle","")}
            for ent in data.get("entities") or []:
                v = ent.get("vcardArray")
                if isinstance(v,list) and len(v)==2:
                    for item in v[1]:
                        if item and item[0]=="fn" and len(item)>3: result["org"] = item[3]; break
                if result["org"]: break
            with sqlite3.connect(DB_PATH) as c: c.execute("INSERT OR REPLACE INTO rdap_cache(domain,fetched_at,json) VALUES(?,?,?)", (domain,utcnow(),json.dumps(result))); c.commit()
            return result
    except Exception as e: print("RDAP lookup error:", repr(e), flush=True)
    return {}


def rdap_lookup_cached_only(domain):
    try:
        with sqlite3.connect(DB_PATH) as c: row = c.execute("SELECT json FROM rdap_cache WHERE domain=?", (domain,)).fetchone()
        return json.loads(row[0]) if row else {}
    except Exception: return {}


def resolve_dns(domain):
    ips=[]
    try:
        for item in socket.getaddrinfo(domain,None,socket.AF_UNSPEC,socket.SOCK_STREAM):
            ip=item[4][0]
            if ip not in ips: ips.append(ip)
    except Exception: pass
    return ips[:12]


def classify(tracker, rdap):
    cat=(tracker.get("category") or "").lower()
    if cat in {"advertising","site_analytics","social_media","extensions"}: return "Known tracker / telemetry","yellow"
    if cat: return "Known TrackerDB service","green"
    if rdap.get("org"): return "Known ownership (not in TrackerDB)","green"
    return "Unknown","orange"


def inspect_domain(domain):
    domain=domain.lower().rstrip(".")
    with sqlite3.connect(DB_PATH) as c: row=c.execute("SELECT domain,first_seen,last_seen,requests,clients_json FROM domains WHERE domain=?",(domain,)).fetchone()
    if not row: return None
    tracker=tracker_lookup(domain); rdap=rdap_lookup(domain); classification,badge=classify(tracker,rdap)
    return {"domain":row[0],"first_seen":row[1],"last_seen":row[2],"requests":row[3],"clients":json.loads(row[4]),"classification":classification,"badge_class":badge,"tracker":tracker,"company":{"name":tracker.get("company_name") or rdap.get("org") or "","description":tracker.get("description",""),"website_url":tracker.get("company_website","") or tracker.get("website_url",""),"country":tracker.get("country","")},"rdap":rdap,"dns":resolve_dns(domain),"trackerdb_snapshot":"WhoTracks.me / Ghostery TrackerDB","note":""}


def get_recent():
    with sqlite3.connect(DB_PATH) as c: rows=c.execute("SELECT domain,requests,clients_json FROM domains ORDER BY requests DESC LIMIT 50").fetchall()
    out=[]
    for domain,requests_count,clients_json in rows:
        t=tracker_lookup(domain); r=rdap_lookup(domain); cls,badge=classify(t,r)
        out.append({"domain":domain,"requests":requests_count,"clients":len(json.loads(clients_json)),"classification":cls,"badge_class":badge})
    return out


def client_device_hint(identifier, name, info):
    s=(name or "").lower()
    blob=json.dumps(info).lower()
    text=s+" "+blob
    if any(x in text for x in ("webos","smart tv","tv","oled","qn ed","lgtv")): return "📺","TV","medium"
    if any(x in text for x in ("iphone","ipad","android","pixel","galaxy")): return "📱","Phone / Tablet","medium"
    if any(x in text for x in ("macbook","laptop","windows","desktop","pc")): return "💻","Computer","medium"
    if any(x in text for x in ("aircon","air conditioner","ac-","climat")): return "❄️","AC","medium"
    return "📦","IoT / Unknown","low"


def get_clients():
    with sqlite3.connect(DB_PATH) as c: rows=c.execute("SELECT identifier,name,source,request_count,info_json FROM client_cache ORDER BY request_count DESC").fetchall()
    out=[]
    for ident,name,source,count,info_json in rows:
        try: info=json.loads(info_json or "{}")
        except Exception: info={}
        icon,typ,confidence=client_device_hint(ident,name,info)
        display_name=name or ident
        out.append({"identifier":ident,"display_name":display_name,"source":source,"requests":count,"icon":icon,"confidence_label":f"{typ} · {confidence} confidence"})
    return out


def worker():
    init_db(); refresh_trackerdb()
    while True:
        started=time.time(); ingest(); time.sleep(max(1, POLL_SECONDS-(time.time()-started)))


@app.route("/")
def index():
    q=request.args.get("q","").strip(); result=inspect_domain(q) if q else None
    return render_template_string(HTML,q=q,result=result,recent=get_recent(),clients=get_clients(),error=None,refresh_seconds=UI_REFRESH_SECONDS,refresh_seconds_ms=UI_REFRESH_SECONDS*1000,updated=utcnow())

@app.route("/search")
def search(): return index()

@app.route("/api/recent")
def api_recent(): return jsonify({"updated":utcnow(),"recent":get_recent(),"clients":get_clients()})

@app.route("/health")
def health(): return jsonify({"ok":True,"adguard":AGH_URL,"trackerdb":trackerdb_ready(),"poll_seconds":POLL_SECONDS,"ui_refresh_seconds":UI_REFRESH_SECONDS})

if __name__=="__main__":
    init_db(); threading.Thread(target=worker,daemon=True).start(); app.run(host="0.0.0.0",port=int(os.getenv("PORT","8080")))
