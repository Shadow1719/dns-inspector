import os, re, json, time, queue, sqlite3, threading, hashlib, ipaddress, subprocess, gc, sys, tracemalloc, io, platform, shutil, zipfile, socket
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import quote

import requests

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
try:
    with open(os.path.join(BASE_DIR, "VERSION"), "r", encoding="utf-8") as f:
        APP_VERSION = f.read().strip()
except Exception:
    APP_VERSION = os.getenv("APP_VERSION", "dev")

OBSERVABILITY_START_MONOTONIC = time.monotonic()
OBSERVABILITY_START_AT = datetime.now(timezone.utc).isoformat()
MEMORY_DIAGNOSTICS_ENABLED = os.getenv("MEMORY_DIAGNOSTICS_ENABLED", "1").strip().lower() not in {"0","false","no","off"}
MEMORY_DIAGNOSTICS_FRAMES = max(5, min(20, int(os.getenv("MEMORY_DIAGNOSTICS_FRAMES", "10"))))
if MEMORY_DIAGNOSTICS_ENABLED and not tracemalloc.is_tracing():
    tracemalloc.start(MEMORY_DIAGNOSTICS_FRAMES)

AGH_URL = os.getenv("AGH_URL", "").rstrip("/")
AGH_USER = os.getenv("AGH_USER", "")
AGH_PASS = os.getenv("AGH_PASS", "")
POLL_SECONDS = max(5, int(os.getenv("POLL_SECONDS", "10")))
NEIGHBORS_PATH = os.getenv("NEIGHBORS_PATH", "/data/neighbors.txt")
UI_REFRESH_SECONDS = max(5, int(os.getenv("UI_REFRESH_SECONDS", "10")))
DB_PATH = os.getenv("DB_PATH", "/data/inspector.db")
TRACKERDB_PATH = os.getenv("TRACKERDB_PATH", "/data/trackerdb.sqlite")
TRACKERDB_URL = os.getenv("TRACKERDB_URL", "https://raw.githubusercontent.com/whotracksme/whotracks.me/master/whotracksme/data/assets/trackerdb.sql")
TRACKERDB_REFRESH_HOURS = int(os.getenv("TRACKERDB_REFRESH_HOURS", "24"))
TRACKERDB_DOWNLOAD_CHUNK_SIZE = max(64*1024, int(os.getenv("TRACKERDB_DOWNLOAD_CHUNK_SIZE", str(1024*1024))))
RDAP_URL = os.getenv("RDAP_URL", "https://rdap.org/domain/").rstrip("/")
MACVENDOR_URL = os.getenv("MACVENDOR_URL", "https://api.macvendors.com").rstrip("/")
MACVENDOR_CACHE_HOURS = int(os.getenv("MACVENDOR_CACHE_HOURS", "168"))
HOSTNAME_CACHE_HOURS = int(os.getenv("HOSTNAME_CACHE_HOURS", "24"))
DEVICE_IP_RETENTION_HOURS = max(1.0, float(os.getenv("DEVICE_IP_RETENTION_HOURS", "12")))
DEVICE_IP_CLEANUP_INTERVAL_MINUTES = max(5, int(os.getenv("DEVICE_IP_CLEANUP_INTERVAL_MINUTES", "30")))
IP_PING_INTERVAL_HOURS = max(1.0, float(os.getenv("IP_PING_INTERVAL_HOURS", "4")))
IP_PING_INITIAL_DELAY_SECONDS = max(10, int(os.getenv("IP_PING_INITIAL_DELAY_SECONDS", "60")))
IP_PING_TIMEOUT_SECONDS = max(1, int(os.getenv("IP_PING_TIMEOUT_SECONDS", "1")))
NETIFY_CACHE_HOURS = int(os.getenv("NETIFY_CACHE_HOURS", "4320"))
RDAP_CACHE_HOURS = int(os.getenv("RDAP_CACHE_HOURS", "720"))
DNS_RECORDS_CACHE_HOURS = int(os.getenv("DNS_RECORDS_CACHE_HOURS", "240"))
ENRICHMENT_RETRY_HOURS = max(24.0, float(os.getenv("ENRICHMENT_RETRY_HOURS", "24")))
NETIFY_URL = os.getenv("NETIFY_URL", "https://www.netify.ai/resources/hostnames/").rstrip("/") + "/"
RUNTIME_CLIENT_REFRESH_INTERVAL = max(30, int(os.getenv("RUNTIME_CLIENT_REFRESH_INTERVAL", "60")))
NEIGHBOR_RECONCILE_INTERVAL = max(30, int(os.getenv("NEIGHBOR_RECONCILE_INTERVAL", "60")))

last_runtime_clients_refresh = 0.0
last_neighbor_reconcile = 0.0
last_ingest_at = 0.0
neighbors_cache = {}
neighbors_mtime = None
enrichment_refreshing = set()
_enrich_inflight = set()
_enrichment_retry_until = {}
_enrichment_retry_loaded = set()
_enrichment_queued = set()

db_lock = threading.RLock()
neighbors_lock = threading.Lock()
enrichment_lock = threading.Lock()
_enrich_guard = threading.Lock()
_enrichment_queue_lock = threading.Lock()
_enrichment_queue = queue.Queue(maxsize=500)
DEVICE_ENRICH_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="device-enrich")
_status_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="agh-status")
_status_guard = threading.Lock()
_status_inflight = set()
_status_slots = threading.BoundedSemaphore(20)
_http_local = threading.local()
_background_started = False
_background_start_lock = threading.Lock()
_UI_REQUEST_START_KEY = "_dns_inspector_request_started"

MAC_RE = re.compile(r"^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.I)
IP_RE = re.compile(r"^[0-9a-f:.]+$")
BLOCKED_REASONS={"FilteredBlackList","FilteredSafeBrowsing","FilteredParental","FilteredBlockedService"}
ALLOWED_REASONS={"NotFilteredWhiteList","NotFilteredNotFound","Rewrite","RewriteEtcHosts","RewriteRule","FilteredSafeSearch"}
UNKNOWN_REASONS={"NotFilteredError","FilteredInvalid"}
VENDOR_LOGOS={"dell":"/static/vendor-logos/dell.svg","lg innotek":"/static/vendor-logos/lg.svg","lge":"/static/vendor-logos/lg.svg","lg":"/static/vendor-logos/lg.svg","zte":"/static/vendor-logos/zte.svg","bosch":"/static/vendor-logos/bosch.svg","roborock":"/static/vendor-logos/roborock.svg","beijing roborock technology":"/static/vendor-logos/roborock.svg","petkit":"/static/vendor-logos/petkit.svg"}
VENDOR_FAVICONS={"dell":"/static/vendor-favicons/dell.ico","lg innotek":"/static/vendor-favicons/lg.ico","lge":"/static/vendor-favicons/lg.ico","lg":"/static/vendor-favicons/lg.ico","zte":"/static/vendor-favicons/zte.ico","bosch":"/static/vendor-favicons/bosch.ico","roborock":"/static/vendor-favicons/roborock.ico","beijing roborock technology":"/static/vendor-favicons/roborock.ico","petkit":"/static/vendor-favicons/petkit.ico"}

def http_session():
    session=getattr(_http_local,"session",None)
    if session is None:
        session=requests.Session()
        _http_local.session=session
    return session

def utcnow():
    return datetime.now(timezone.utc).isoformat()

def is_mac(value): return bool(MAC_RE.match(str(value or "").strip()))
def normalize_mac(value):
    raw=str(value or "").strip().lower().replace("-",":")
    if not is_mac(raw): return ""
    return raw

def is_ip(value):
    try: ipaddress.ip_address(str(value or "").strip()); return True
    except Exception: return False

def apex_domain(domain):
    parts=[p for p in str(domain or "").strip().strip(".").split(".") if p]
    return ".".join(parts[-2:]) if len(parts)>=2 else str(domain or "").strip().strip(".")

def _html(v):
    return str(v or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"','&quot;').replace("'","&#39;")

def device_hint(name, hostname, info):
    text=" ".join(str(x or "") for x in (name,hostname,info)).lower()
    if any(x in text for x in ("iphone","ipad","android","pixel","galaxy","phone")): return "Phone / Tablet","📱","medium"
    if any(x in text for x in ("tv","television","lgwebos","roku","apple tv","chromecast","firetv")): return "TV / Streaming","📺","medium"
    if any(x in text for x in ("laptop","notebook","macbook","thinkpad")): return "Laptop","💻","medium"
    if any(x in text for x in ("desktop","pc","windows","imac")): return "Computer","🖥️","medium"
    if any(x in text for x in ("printer","print")): return "Printer","🖨️","medium"
    if any(x in text for x in ("camera","cam-","ipc")): return "Camera","📷","medium"
    if any(x in text for x in ("speaker","sonos","echo","homepod")): return "Speaker","🔊","medium"
    if any(x in text for x in ("router","gateway","switch","access point","ap-")): return "Network","🛜","medium"
    return "IoT / Unknown","📦","low"

def _local_static_exists(url):
    if not url or not url.startswith('/static/'):
        return False
    return os.path.exists(os.path.join(BASE_DIR, url.lstrip('/')))

def vendor_logo_url(vendor):
    key=str(vendor or '').strip().lower()
    return VENDOR_LOGOS.get(key) if key in VENDOR_LOGOS and _local_static_exists(VENDOR_LOGOS[key]) else ''

def query_status(reason, original_response=None):
    reason = str(reason or '')
    if reason in BLOCKED_REASONS:
        return 'Blocked'
    if reason in ALLOWED_REASONS:
        return 'Allowed'
    if reason in UNKNOWN_REASONS:
        return 'Unknown'
    return 'Unknown'
