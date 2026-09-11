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
POLL_SECONDS = int(os.getenv("POLL_SECONDS", "60"))
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
<!doctype html><html><head><meta charset="utf-8"><title>DNS Inspector</title>
<style>
body{font-family:system-ui;background:#111;color:#eee;margin:30px;max-width:1150px}
input,button{background:#222;color:#eee;border:1px solid #555;padding:9px;border-radius:6px}
input{width:70%}button{cursor:pointer}.card{background:#191919;border:1px solid #333;border-radius:10px;padding:18px;margin-top:18px}
small,.muted{color:#aaa}.tag{display:inline-block;padding:4px 8px;border-radius:12px;background:#333;margin:3px}
.green{background:#174d2a}.yellow{background:#5a4610}.orange{background:#5a2e10}.red{background:#5a1717}
table{width:100%;border-collapse:collapse}td,th{padding:8px;border-bottom:1px solid #333;text-align:left}a{color:#8ab4f8}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.kv{padding:7px 0;border-bottom:1px solid #2b2b2b}.kv b{display:inline-block;min-width:130px}
pre{white-space:pre-wrap;word-break:break-word;color:#ddd}.source{font-size:.9em;color:#888}.error{color:#ff9b9b}
@media(max-width:800px){.grid{grid-template-columns:1fr}input{width:60%}}
</style></head><body>
<h1>DNS Inspector</h1>
<p class="muted">Read-only view of AdGuard Home Query Log. This app never changes AdGuard settings.</p>
<form action="/search"><input name="q" placeholder="hostname..." value="{{q}}"><button>Inspect</button></form>
{% if error %}<div class="card error">{{error}}</div>{% endif %}
{% if result %}
<div class="card">
<h2>{{result.domain}}</h2>
<div>
<span class="tag {{result.badge_class}}">{{result.classification}}</span>
{% if result.tracker.category %}<span class="tag">{{result.tracker.category}}</span>{% endif %}
{% if result.tracker.name %}<span class="tag">{{result.tracker.name}}</span>{% endif %}
</div>
<div class="grid">
<div>
<h3>Who</h3>
<div class="kv"><b>Company:</b> {{result.company.name or "Unknown"}}</div>
<div class="kv"><b>Country:</b> {{result.company.country or "—"}}</div>
<div class="kv"><b>Website:</b> {% if result.company.website_url %}<a href="{{result.company.website_url}}" target="_blank">{{result.company.website_url}}</a>{% else %}—{% endif %}</div>
<div class="kv"><b>RDAP:</b> {{result.rdap.org or "Not available"}}</div>
</div>
<div>
<h3>What it does</h3>
{% if result.tracker.description %}<p>{{result.tracker.description}}</p>
{% elif result.tracker.category %}<p>TrackerDB classifies this endpoint under <b>{{result.tracker.category}}</b>.</p>
{% else %}<p class="muted">No TrackerDB description is available. Ownership was checked separately with RDAP; the hostname's exact purpose cannot be established from DNS alone.</p>{% endif %}
{% if result.tracker.website_url %}<p><a href="{{result.tracker.website_url}}" target="_blank">Tracker / service website</a></p>{% endif %}
</div></div>

<h3>Infrastructure</h3>
<div class="grid">
<div><div class="kv"><b>DNS:</b> {{result.dns|join(", ") or "No A/AAAA result"}}</div>
<div class="kv"><b>RDAP name:</b> {{result.rdap.name or "—"}}</div></div>
<div><div class="kv"><b>TrackerDB domain:</b> {{result.tracker.matched_domain or "No match"}}</div>
<div class="kv"><b>Source snapshot:</b> {{result.trackerdb_snapshot or "—"}}</div></div>
</div>

<h3>Local activity</h3>
<p><b>Requests:</b> {{result.requests}} &nbsp; <b>Clients:</b> {{result.clients|length}}</p>
<p><b>First seen:</b> {{result.first_seen or "—"}}<br><b>Last seen:</b> {{result.last_seen or "—"}}</p>
<ul>{% for c,n in result.clients.items() %}<li>{{c}} — {{n}} queries</li>{% endfor %}</ul>

{% if result.company.description %}<h3>Company description</h3><p>{{result.company.description}}</p>{% endif %}
<p class="source">Metadata: Ghostery TrackerDB / WhoTracks.me snapshot + RDAP. This is enrichment, not a blocking decision.</p>
</div>
{% endif %}
<div class="card"><h2>Recent domains</h2>
<table><tr><th>Domain</th><th>Requests</th><th>Clients</th><th>Classification</th></tr>
{% for r in recent %}<tr><td><a href="/search?q={{r.domain|urlencode}}">{{r.domain}}</a></td><td>{{r.requests}}</td><td>{{r.clients}}</td><td>{{r.classification}}</td></tr>{% endfor %}
</table></div>
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
    if not trackerdb_ready():
        return True
    age = time.time() - os.path.getmtime(TRACKERDB_PATH)
    return age > TRACKERDB_REFRESH_HOURS * 3600


def refresh_trackerdb(force=False):
    if not force and not trackerdb_refresh_needed():
        return
    tmp = TRACKERDB_PATH + ".download"
    try:
        print("Downloading TrackerDB snapshot...", flush=True)
        r = requests.get(TRACKERDB_URL, timeout=30)
        r.raise_for_status()
        with open(tmp, "wb") as f:
            f.write(r.content)
        newdb = TRACKERDB_PATH + ".new"
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
        for p in (tmp, TRACKERDB_PATH + ".new"):
            try:
                if os.path.exists(p): os.remove(p)
            except OSError:
                pass


def agh_login():
    if not AGH_USER:
        return
    r = session.post(AGH_URL + "/control/login", json={"name": AGH_USER, "password": AGH_PASS}, timeout=10)
    r.raise_for_status()


def fetch_querylog():
    r = session.get(AGH_URL + "/control/querylog", params={"limit": 500}, timeout=15)
    if r.status_code in (401, 403):
        agh_login()
        r = session.get(AGH_URL + "/control/querylog", params={"limit": 500}, timeout=15)
    r.raise_for_status()
    return r.json()


def ingest():
    try:
        data = fetch_querylog()
        entries = data.get("data") or []
        now = utcnow()
        with db_lock, sqlite3.connect(DB_PATH) as c:
            for e in entries:
                domain = ((e.get("question") or {}).get("name") or "").rstrip(".").lower()
                client = e.get("client") or e.get("client_id") or "unknown"
                if not domain:
                    continue
                row = c.execute("SELECT clients_json FROM domains WHERE domain=?", (domain,)).fetchone()
                clients = json.loads(row[0]) if row else {}
                clients[client] = clients.get(client, 0) + 1
                if row:
                    c.execute("UPDATE domains SET last_seen=?, requests=requests+1, clients_json=? WHERE domain=?", (now, json.dumps(clients), domain))
                else:
                    c.execute("INSERT INTO domains(domain,first_seen,last_seen,requests,clients_json) VALUES(?,?,?,?,?)", (domain, now, now, 1, json.dumps(clients)))
            c.commit()
    except Exception as e:
        print("ingest error:", repr(e), flush=True)


def tracker_lookup(domain):
    if not trackerdb_ready():
        return {}
    labels = domain.rstrip(".").lower().split(".")
    candidates = [".".join(labels[i:]) for i in range(len(labels))]
    try:
        with sqlite3.connect(TRACKERDB_PATH) as c:
            for candidate in candidates:
                row = c.execute("""
                    SELECT td.domain, t.name, cat.name, t.website_url, t.company_id,
                           coalesce(co.name,''), coalesce(co.description,''), coalesce(co.website_url,''), coalesce(co.country,'')
                    FROM tracker_domains td
                    JOIN trackers t ON t.id=td.tracker
                    LEFT JOIN categories cat ON cat.id=t.category_id
                    LEFT JOIN companies co ON co.id=t.company_id
                    WHERE td.domain=? LIMIT 1
                """, (candidate,)).fetchone()
                if row:
                    return {"matched_domain": row[0], "name": row[1], "category": row[2] or "", "website_url": row[3] or "", "company_id": row[4] or "", "company_name": row[5], "description": row[6], "company_website": row[7], "country": row[8]}
    except Exception as e:
        print("tracker lookup error:", repr(e), flush=True)
    return {}


def rdap_lookup(domain):
    now = time.time()
    try:
        with sqlite3.connect(DB_PATH) as c:
            row = c.execute("SELECT fetched_at,json FROM rdap_cache WHERE domain=?", (domain,)).fetchone()
        if row:
            try:
                age = datetime.now(timezone.utc) - datetime.fromisoformat(row[0])
                if age.total_seconds() < 86400:
                    return json.loads(row[1])
            except Exception:
                pass
        r = requests.get(f"{RDAP_URL}/{quote(domain, safe='')}", timeout=8, allow_redirects=True)
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
    if cat:
        if cat in {"advertising", "site_analytics", "social_media", "extensions"}:
            return "Known tracker / telemetry", "yellow"
        return "Known TrackerDB service", "green"
    if rdap.get("org"):
        return "Known ownership (not in TrackerDB)", "green"
    return "Unknown", "orange"


def inspect_domain(domain):
    domain = domain.lower().rstrip(".")
    with sqlite3.connect(DB_PATH) as c:
        row = c.execute("SELECT domain,first_seen,last_seen,requests,clients_json FROM domains WHERE domain=?", (domain,)).fetchone()
    if not row:
        return None
    tracker = tracker_lookup(domain)
    rdap = rdap_lookup(domain)
    classification, badge = classify(tracker, rdap)
    company_name = tracker.get("company_name") or rdap.get("org") or ""
    company_description = tracker.get("description", "")
    company_website = tracker.get("company_website", "")
    country = tracker.get("country", "")
    return {
        "domain": row[0], "first_seen": row[1], "last_seen": row[2], "requests": row[3],
        "clients": json.loads(row[4]), "classification": classification, "badge_class": badge,
        "tracker": tracker, "company": {"name": company_name, "description": company_description, "website_url": company_website, "country": country},
        "rdap": rdap, "dns": resolve_dns(domain), "trackerdb_snapshot": "WhoTracks.me / Ghostery TrackerDB", "note": ""
    }


def get_recent():
    with sqlite3.connect(DB_PATH) as c:
        rows = c.execute("SELECT domain,requests,clients_json FROM domains ORDER BY requests DESC LIMIT 50").fetchall()
    out = []
    for domain, requests_count, clients_json in rows:
        t = tracker_lookup(domain)
        r = rdap_lookup_cached_only(domain)
        cls, _ = classify(t, r)
        out.append({"domain": domain, "requests": requests_count, "clients": len(json.loads(clients_json)), "classification": cls})
    return out


def rdap_lookup_cached_only(domain):
    try:
        with sqlite3.connect(DB_PATH) as c:
            row = c.execute("SELECT json FROM rdap_cache WHERE domain=?", (domain,)).fetchone()
        return json.loads(row[0]) if row else {}
    except Exception:
        return {}


def worker():
    init_db()
    refresh_trackerdb()
    while True:
        ingest()
        time.sleep(POLL_SECONDS)


@app.route("/")
def index():
    q = request.args.get("q", "").strip()
    result = inspect_domain(q) if q else None
    return render_template_string(HTML, q=q, result=result, recent=get_recent(), error=None)


@app.route("/search")
def search():
    return index()


@app.route("/health")
def health():
    return jsonify({"ok": True, "adguard": AGH_URL, "trackerdb": trackerdb_ready()})


if __name__ == "__main__":
    init_db()
    threading.Thread(target=worker, daemon=True).start()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
