import array
import bisect
import csv
import hashlib
import hmac
import io
import ipaddress
import json
import math
import os
import queue
import re
import socket
import signal
import subprocess
import secrets
import sys
import sqlite3
import threading
import traceback
import time
from concurrent.futures import ThreadPoolExecutor
from collections import deque
from contextlib import closing
from datetime import datetime, timezone, timedelta
from functools import wraps
from urllib.parse import quote

import requests
from flask import Flask, jsonify, render_template_string, request, send_file

from analytics_report import build_analytics_pdf
from report_scheduler import (
    ReportPathError,
    ReportScheduler,
    filename_context,
    prune_report_history,
    render_filename_template,
    resolve_report_path,
    send_report_email,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
try:
    with open(os.path.join(BASE_DIR, "VERSION"), "r", encoding="utf-8") as f:
        APP_VERSION = f.read().strip()
except Exception:
    APP_VERSION = os.getenv("APP_VERSION", "dev")


def normalize_runtime_environment(value):
    return "development" if (value or "").strip().lower() == "development" else "production"


RUNTIME_ENV = normalize_runtime_environment(os.getenv("DNS_INSPECTOR_ENV"))


def is_development_environment():
    return RUNTIME_ENV == "development"


def _environment_render_context():
    dev = is_development_environment()
    return {
        "is_dev_environment": dev,
        "favicon_path": "/static/favicon-dev.svg" if dev else "/static/favicon.svg",
        "page_title": f"DNS Inspector DEV v{APP_VERSION}" if dev else "DNS Inspector",
    }

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
TRACKERDB_DOWNLOAD_CHUNK_SIZE = max(64 * 1024, int(os.getenv("TRACKERDB_DOWNLOAD_CHUNK_SIZE", str(1024 * 1024))))
RDAP_URL = os.getenv("RDAP_URL", "https://rdap.org/domain/").rstrip("/")
MACVENDOR_URL = os.getenv("MACVENDOR_URL", "https://api.macvendors.com").rstrip("/")
MACVENDOR_CACHE_HOURS = int(os.getenv("MACVENDOR_CACHE_HOURS", "168"))
HOSTNAME_CACHE_HOURS = int(os.getenv("HOSTNAME_CACHE_HOURS", "24"))
NETIFY_CACHE_HOURS = int(os.getenv("NETIFY_CACHE_HOURS", "4320"))  # 180 days
RDAP_CACHE_HOURS = int(os.getenv("RDAP_CACHE_HOURS", "720"))  # 30 days
DNS_RECORDS_CACHE_HOURS = int(os.getenv("DNS_RECORDS_CACHE_HOURS", "240"))  # 10 days
ENRICHMENT_RETRY_HOURS = max(24.0, float(os.getenv("ENRICHMENT_RETRY_HOURS", "24")))
DEVICE_IP_RETENTION_HOURS = max(1.0, float(os.getenv("DEVICE_IP_RETENTION_HOURS", "12")))
DEVICE_IP_CLEANUP_INTERVAL_MINUTES = max(5, int(os.getenv("DEVICE_IP_CLEANUP_INTERVAL_MINUTES", "30")))
IP_PING_INTERVAL_HOURS = max(1.0, float(os.getenv("IP_PING_INTERVAL_HOURS", "4")))
IP_PING_INITIAL_DELAY_SECONDS = max(10, int(os.getenv("IP_PING_INITIAL_DELAY_SECONDS", "60")))
IP_PING_TIMEOUT_SECONDS = max(1, int(os.getenv("IP_PING_TIMEOUT_SECONDS", "1")))
NETIFY_URL = os.getenv("NETIFY_URL", "https://www.netify.ai/resources/hostnames/").rstrip("/") + "/"

ADMIN_TOKEN = os.getenv("DNS_INSPECTOR_ADMIN_TOKEN", "").strip()

app = Flask(__name__)

@app.context_processor
def _security_template_context():
    return {"admin_auth_enabled": bool(ADMIN_TOKEN)}


db_lock = threading.Lock()
session = requests.Session()
_devlog_lock = threading.Lock()
_devlog = deque(maxlen=500)

# Administrative lifecycle, mutable-label and diagnostic endpoints can be
# protected without breaking existing trusted-LAN deployments. When
# DNS_INSPECTOR_ADMIN_TOKEN is set, the browser performs an explicit token
# login and receives a short-lived, random HttpOnly/SameSite session cookie.
# The configured token is never rendered into HTML/JS, logged, or stored in
# browser storage. When the token is unset, the existing trusted-LAN behavior
# remains unchanged.
ADMIN_SESSION_COOKIE = "dns_inspector_admin"
ADMIN_SESSION_TTL_SECONDS = max(300, int(os.getenv("DNS_INSPECTOR_ADMIN_SESSION_TTL_SECONDS", "28800")))
ADMIN_SESSION_MAX = max(8, int(os.getenv("DNS_INSPECTOR_ADMIN_SESSION_MAX", "128")))
ADMIN_LOGIN_WINDOW_SECONDS = max(30, int(os.getenv("DNS_INSPECTOR_ADMIN_LOGIN_WINDOW_SECONDS", "300")))
ADMIN_LOGIN_MAX_ATTEMPTS = max(1, int(os.getenv("DNS_INSPECTOR_ADMIN_LOGIN_MAX_ATTEMPTS", "5")))
ADMIN_COOKIE_SECURE_OVERRIDE = os.getenv("DNS_INSPECTOR_ADMIN_COOKIE_SECURE", "").strip().lower() in {"1", "true", "yes", "on"}
ADMIN_TOKEN_FINGERPRINT = hashlib.sha256(ADMIN_TOKEN.encode("utf-8")).hexdigest() if ADMIN_TOKEN else ""
_admin_sessions = {}
_admin_sessions_lock = threading.Lock()
_admin_login_attempts = deque(maxlen=512)
_admin_login_lock = threading.Lock()


def _admin_cookie_secure():
    forwarded_proto = request.headers.get("X-Forwarded-Proto", "").split(",", 1)[0].strip().lower()
    return bool(request.is_secure or forwarded_proto == "https" or ADMIN_COOKIE_SECURE_OVERRIDE)


def _prune_admin_sessions(now=None):
    now = time.time() if now is None else now
    expired = [key for key, record in _admin_sessions.items() if record[1] <= now]
    for key in expired:
        _admin_sessions.pop(key, None)
    if len(_admin_sessions) <= ADMIN_SESSION_MAX:
        return
    oldest = sorted(_admin_sessions.items(), key=lambda item: item[1][0])[: len(_admin_sessions) - ADMIN_SESSION_MAX]
    for key, _ in oldest:
        _admin_sessions.pop(key, None)


def _issue_admin_session():
    raw = secrets.token_urlsafe(32)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    now = time.time()
    with _admin_sessions_lock:
        _prune_admin_sessions(now)
        _admin_sessions[digest] = (now, now + ADMIN_SESSION_TTL_SECONDS, ADMIN_TOKEN_FINGERPRINT)
    return raw


def _admin_session_valid(req):
    if not ADMIN_TOKEN:
        return True
    raw = req.cookies.get(ADMIN_SESSION_COOKIE, "")
    if not raw:
        return False
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    now = time.time()
    with _admin_sessions_lock:
        record = _admin_sessions.get(digest)
        if record is None:
            return False
        if record[1] <= now or not hmac.compare_digest(record[2], ADMIN_TOKEN_FINGERPRINT):
            _admin_sessions.pop(digest, None)
            return False
        return True


def _admin_login_rate_limited(client_id):
    now = time.monotonic()
    cutoff = now - ADMIN_LOGIN_WINDOW_SECONDS
    with _admin_login_lock:
        while _admin_login_attempts and _admin_login_attempts[0][1] <= cutoff:
            _admin_login_attempts.popleft()
        attempts = sum(1 for address, _ in _admin_login_attempts if address == client_id)
        if attempts >= ADMIN_LOGIN_MAX_ATTEMPTS:
            retry_after = max(1, int((_admin_login_attempts[0][1] + ADMIN_LOGIN_WINDOW_SECONDS) - now))
            return True, retry_after
        _admin_login_attempts.append((client_id, now))
    return False, 0


def _csrf_request_valid(req):
    if req.method in {"GET", "HEAD", "OPTIONS"}:
        return True
    # Same-origin browser fetch() sends this custom header; a cross-site HTML
    # form cannot set it, and a cross-origin fetch would require CORS before
    # the browser could send it. This is an additional CSRF defense alongside
    # the Strict SameSite session cookie.
    return hmac.compare_digest(req.headers.get("X-DNS-Inspector-Requested-With", ""), "fetch")


def _json_no_store(payload, status=200):
    resp = jsonify(payload)
    resp.status_code = status
    resp.headers["Cache-Control"] = "no-store"
    return resp


def require_admin(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not ADMIN_TOKEN:
            return view(*args, **kwargs)
        if not _admin_session_valid(request):
            return _json_no_store({"ok": False, "error": "Admin authentication required"}, 401)
        if not _csrf_request_valid(request):
            return _json_no_store({"ok": False, "error": "CSRF validation failed"}, 403)
        return view(*args, **kwargs)
    return wrapper


_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=(), usb=()",
    # script-src/style-src keep 'unsafe-inline' because the UI is a single
    # server-rendered template with inline <script>/<style> blocks and no
    # nonce plumbing; see docs/SECURITY_AUDIT_0.8.6.md for the tracked
    # follow-up to remove it. Every directive below only allow-lists hosts the
    # UI actually loads resources from (unpkg for Leaflet, the OSM/OpenTopoMap/
    # Esri tile hosts the map renderer requests) -- see static/leaflet-map.js.
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://unpkg.com; "
        "img-src 'self' data: https://server.arcgisonline.com; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    ),
}


_ADMIN_PROTECTED_PATHS = {
    "/api/system/restart",
    "/api/system/stop",
    "/api/device/label",
    "/api/debug/snapshot",
    "/api/devlog/export",
    "/api/devlog",
}


@app.after_request
def _apply_security_headers(response):
    for name, value in _SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    if ADMIN_TOKEN and request.path in _ADMIN_PROTECTED_PATHS:
        response.headers["Cache-Control"] = "private, no-store"
        response.headers["Pragma"] = "no-cache"
    return response

def log_event(level, message, **context):
    entry = {
        "at": utcnow() if "utcnow" in globals() else datetime.now(timezone.utc).isoformat(),
        "level": str(level or "INFO").upper(),
        "message": str(message),
    }
    if context:
        entry["context"] = {str(k): str(v) for k, v in context.items()}
    with _devlog_lock:
        _devlog.append(entry)
    return entry

last_ingest_at = 0.0
neighbors_lock = threading.Lock()
neighbors_cache = {}
neighbors_mtime = None
enrichment_lock = threading.Lock()
enrichment_refreshing = set()

# Background AdGuard status refreshes are deliberately bounded: an Overview
# request must never create an unbounded number of threads (one per stale
# domain on every request would do exactly that).
_status_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="agh-status")
_status_guard = threading.Lock()
_status_inflight = set()
_status_slots = threading.BoundedSemaphore(20)

# Enrichment is a bounded queue processed by a single background worker,
# never a thread-per-domain fan-out. Retry state is persisted so a missing/
# failed lookup is not retried on every UI poll.
_enrichment_queue = queue.Queue(maxsize=500)
_enrichment_queue_lock = threading.Lock()
_enrichment_queued = set()
_enrichment_retry_until = {}
_enrichment_retry_loaded = set()

MAC_RE = re.compile(r"^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.I)
IP_RE = re.compile(r"^[0-9a-f:.]+$")

# --- Offline GeoIP / observed destination map -------------------------------
GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "/data/geoip_country_ranges.csv")
GEOIP_CACHE_MAX_ENTRIES = max(256, int(os.getenv("GEOIP_CACHE_MAX_ENTRIES", "8192")))
GEOIP_MAP_CACHE_SECONDS = max(5, int(os.getenv("GEOIP_MAP_CACHE_SECONDS", "20")))
GEOIP_MAP_DOMAIN_LIMIT = max(50, int(os.getenv("GEOIP_MAP_DOMAIN_LIMIT", "1500")))
GEOIP_DESTINATION_IPS_PER_DOMAIN_LIMIT = max(4, int(os.getenv("GEOIP_DESTINATION_IPS_PER_DOMAIN_LIMIT", "32")))
GEOIP_LOAD_CHUNK_ROWS = max(1, int(os.getenv("GEOIP_LOAD_CHUNK_ROWS", "5000")))
GEOIP_LOAD_YIELD_SECONDS = max(0.0, float(os.getenv("GEOIP_LOAD_YIELD_SECONDS", "0.01")))
# Optional coordinate-capable GeoIP database. Unlike GEOIP_DB_PATH (country
# ranges only), this is never guessed or derived -- Destinations map mode and
# destination route/arc rendering stay disabled unless this is explicitly
# configured and loads successfully. See docs/GEOIP.md.
GEOIP_CITY_DB_PATH = os.getenv("GEOIP_CITY_DB_PATH", "/data/geoip_city_coordinates.csv")
# Optional second, lower-priority coordinate layer: curated known datacenter/
# cloud/hosting provider ranges (Issue #88 follow-up). Only used when a real
# IP falls inside an explicitly-sourced range; region-level coordinates are
# labeled "known_datacenter" provenance, never presented as an exact server
# location and never used to override a real city-GeoIP match. See
# docs/GEOIP.md for the CSV format and how to source/refresh it.
GEOIP_DATACENTER_DB_PATH = os.getenv("GEOIP_DATACENTER_DB_PATH", "/data/geoip_datacenter_ranges.csv")

# --- Bounded analytics history (Issue #88) -----------------------------------
# processed_queries stays bounded to 100k rows (see ingest()); this is a
# separate, much smaller, hourly-aggregated table so historical charts and
# scheduled reports keep working long after raw rows roll off.
ANALYTICS_BUCKET_SECONDS = 3600
ANALYTICS_HISTORY_RETENTION_HOURS = max(24, int(os.getenv("ANALYTICS_HISTORY_RETENTION_HOURS", str(24 * 90))))
ANALYTICS_HISTORY_MAX_CATCHUP_BUCKETS = 6  # bounds the work done in a single tick after downtime

# --- Scheduled report generation / storage / email (Issue #88) --------------
REPORTS_BASE_DIR = os.getenv("REPORTS_DIR", "/data/reports")
REPORTS_DEFAULT_RETENTION = 14
SMTP_PASSWORD_ENV_VAR = "SMTP_PASSWORD"
_CGNAT_V4_NETWORK = ipaddress.ip_network("100.64.0.0/10")
COUNTRY_CENTROIDS = {
    "US": (39.8, -98.6, "United States"), "CA": (56.1, -106.3, "Canada"), "MX": (23.6, -102.5, "Mexico"),
    "BR": (-14.2, -51.9, "Brazil"), "AR": (-38.4, -63.6, "Argentina"), "CL": (-35.7, -71.5, "Chile"),
    "CO": (4.6, -74.3, "Colombia"), "PE": (-9.2, -75.0, "Peru"), "GB": (54.0, -2.0, "United Kingdom"),
    "IE": (53.4, -8.2, "Ireland"), "FR": (46.6, 2.2, "France"), "DE": (51.2, 10.4, "Germany"),
    "NL": (52.1, 5.3, "Netherlands"), "BE": (50.8, 4.5, "Belgium"), "CH": (46.8, 8.2, "Switzerland"),
    "AT": (47.5, 14.6, "Austria"), "IT": (42.8, 12.6, "Italy"), "ES": (40.5, -3.7, "Spain"),
    "PT": (39.4, -8.2, "Portugal"), "SE": (60.1, 18.6, "Sweden"), "NO": (60.5, 8.5, "Norway"),
    "DK": (56.3, 9.5, "Denmark"), "FI": (61.9, 25.7, "Finland"), "IS": (64.9, -19.0, "Iceland"),
    "PL": (51.9, 19.1, "Poland"), "CZ": (49.8, 15.5, "Czechia"), "SK": (48.7, 19.7, "Slovakia"),
    "HU": (47.2, 19.5, "Hungary"), "RO": (45.9, 25.0, "Romania"), "BG": (42.7, 25.5, "Bulgaria"),
    "GR": (39.1, 21.8, "Greece"), "TR": (38.9, 35.2, "Turkey"), "RU": (61.5, 105.3, "Russia"),
    "UA": (48.4, 31.2, "Ukraine"), "EE": (58.6, 25.0, "Estonia"), "LV": (56.9, 24.6, "Latvia"),
    "LT": (55.2, 23.9, "Lithuania"), "CN": (35.9, 104.2, "China"), "JP": (36.2, 138.3, "Japan"),
    "KR": (35.9, 127.8, "South Korea"), "TW": (23.7, 121.0, "Taiwan"), "HK": (22.3, 114.2, "Hong Kong"),
    "SG": (1.35, 103.8, "Singapore"), "IN": (20.6, 79.0, "India"), "ID": (-0.8, 113.9, "Indonesia"),
    "MY": (4.2, 101.9, "Malaysia"), "TH": (15.9, 101.0, "Thailand"), "VN": (14.1, 108.3, "Vietnam"),
    "PH": (12.9, 121.8, "Philippines"), "AU": (-25.3, 133.8, "Australia"), "NZ": (-41.0, 174.9, "New Zealand"),
    "ZA": (-30.6, 22.9, "South Africa"), "EG": (26.8, 30.8, "Egypt"), "NG": (9.1, 8.7, "Nigeria"),
    "KE": (-0.02, 37.9, "Kenya"), "MA": (31.8, -7.1, "Morocco"), "IL": (31.0, 34.8, "Israel"),
    "AE": (23.4, 53.8, "United Arab Emirates"), "SA": (23.9, 45.1, "Saudi Arabia"), "QA": (25.4, 51.2, "Qatar"),
    "PK": (30.4, 69.3, "Pakistan"), "BD": (23.7, 90.4, "Bangladesh"), "KZ": (48.0, 66.9, "Kazakhstan"),
    "IR": (32.4, 53.7, "Iran"), "IQ": (33.2, 43.7, "Iraq"),
}

def normalize_public_ip(value):
    try:
        addr = ipaddress.ip_address(str(value).strip())
    except (ValueError, AttributeError):
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved or addr.is_unspecified:
        return None
    if isinstance(addr, ipaddress.IPv4Address) and addr in _CGNAT_V4_NETWORK:
        return None
    return str(addr)

def extract_observed_answer_ips(entry):
    """Only A/AAAA answers actually returned by AdGuard; never re-resolve domains."""
    ips = []
    for answer in entry.get("answer") or []:
        if not isinstance(answer, dict) or str(answer.get("type") or "").upper() not in {"A", "AAAA"}:
            continue
        ip = normalize_public_ip(answer.get("value"))
        if ip and ip not in ips:
            ips.append(ip)
    return ips

def _iter_csv_rows_throttled(reader):
    count = 0
    for row in reader:
        yield row
        count += 1
        if GEOIP_LOAD_CHUNK_ROWS and GEOIP_LOAD_YIELD_SECONDS and count % GEOIP_LOAD_CHUNK_ROWS == 0:
            time.sleep(GEOIP_LOAD_YIELD_SECONDS)

class _CompactRangeTableBuilder:
    def __init__(self, extra_typecodes):
        self.start = array.array("Q"); self.end = array.array("Q"); self.extra = [array.array(tc) for tc in extra_typecodes]
        self._sorted = True; self._last_start = -1
    def append(self, start, end, *extra_values):
        if start < self._last_start: self._sorted = False
        self._last_start = start; self.start.append(start); self.end.append(end)
        for column, value in zip(self.extra, extra_values): column.append(value)
    def finalize(self):
        if self._sorted or len(self.start) <= 1: return
        order = sorted(range(len(self.start)), key=self.start.__getitem__)
        self.start = array.array("Q", (self.start[i] for i in order)); self.end = array.array("Q", (self.end[i] for i in order))
        self.extra = [array.array(column.typecode, (column[i] for i in order)) for column in self.extra]

class GeoIPProvider:
    def lookup(self, ip): raise NotImplementedError
    @property
    def available(self): return False
    @property
    def range_count(self): return 0
    @property
    def path(self): return None

class NullGeoIPProvider(GeoIPProvider):
    def lookup(self, ip): return None, None

class CsvRangeGeoIPProvider(GeoIPProvider):
    """Memory-conscious local CSV range lookup using primitive arrays for IPv4."""
    def __init__(self, path):
        self._path = path; self._v4_start = array.array("Q"); self._v4_end = array.array("Q"); self._v4_country_idx = array.array("H")
        self._v6 = []; self._v6_starts = []; self._countries = []; self._country_index = {}; self._loaded = False; self._load()
    def _intern_country(self, code, name):
        idx = self._country_index.get(code)
        if idx is None:
            idx = len(self._countries); self._countries.append((code, name)); self._country_index[code] = idx
        return idx
    def _load(self):
        builder = _CompactRangeTableBuilder(("H",)); v6_rows = []
        try:
            with open(self._path, "r", encoding="utf-8", newline="") as f:
                for row in _iter_csv_rows_throttled(csv.reader(f)):
                    if not row or len(row) < 4: continue
                    start_raw, end_raw = row[0].strip(), row[1].strip(); code, name = row[2].strip().upper(), row[3].strip()
                    if start_raw.lower() in {"start_ip","start","network_start"}: continue
                    try: start_addr = ipaddress.ip_address(start_raw); end_addr = ipaddress.ip_address(end_raw)
                    except ValueError: continue
                    if start_addr.version != end_addr.version or not code: continue
                    idx = self._intern_country(code, name or code)
                    if start_addr.version == 4: builder.append(int(start_addr), int(end_addr), idx)
                    else: v6_rows.append((int(start_addr), int(end_addr), idx))
            builder.finalize(); self._v4_start, self._v4_end = builder.start, builder.end; self._v4_country_idx = builder.extra[0]
            v6_rows.sort(key=lambda row: row[0]); self._v6 = v6_rows; self._v6_starts = [row[0] for row in v6_rows]; self._loaded = bool(self._v4_start or self._v6)
        except (OSError, csv.Error): self._loaded = False
    @property
    def available(self): return self._loaded
    @property
    def range_count(self): return len(self._v4_start) + len(self._v6)
    @property
    def path(self): return self._path
    def lookup(self, ip):
        try: addr = ipaddress.ip_address(ip)
        except ValueError: return None, None
        value = int(addr)
        if addr.version == 4:
            if not self._v4_start: return None, None
            idx = bisect.bisect_right(self._v4_start, value) - 1
            if idx < 0 or not (self._v4_start[idx] <= value <= self._v4_end[idx]): return None, None
            return self._countries[self._v4_country_idx[idx]]
        if not self._v6: return None, None
        idx = bisect.bisect_right(self._v6_starts, value) - 1
        if idx < 0: return None, None
        start, end, country_idx = self._v6[idx]
        return self._countries[country_idx] if start <= value <= end else (None, None)

class CsvRangeCityGeoIPProvider(GeoIPProvider):
    """Optional coordinate-capable local CSV range lookup.

    Expected CSV columns: start_ip,end_ip,country_code,country_name,city,lat,lon
    (header row optional; extra trailing columns are ignored). This is a
    separate, optional database from GEOIP_DB_PATH (country ranges only) --
    Destinations map mode and route/arc rendering only ever activate when
    this loads real rows, never by falling back to country centroids.
    """
    def __init__(self, path):
        self._path = path
        self._v4_start = array.array("Q"); self._v4_end = array.array("Q")
        self._v4_city_idx = array.array("I"); self._v4_lat = array.array("d"); self._v4_lon = array.array("d")
        self._v6 = []; self._v6_starts = []
        self._cities = []; self._city_index = {}
        self._loaded = False; self._load()

    def _intern_city(self, code, name, city):
        key = (code, name, city)
        idx = self._city_index.get(key)
        if idx is None:
            idx = len(self._cities); self._cities.append(key); self._city_index[key] = idx
        return idx

    def _load(self):
        builder = _CompactRangeTableBuilder(("I", "d", "d")); v6_rows = []
        try:
            with open(self._path, "r", encoding="utf-8", newline="") as f:
                for row in _iter_csv_rows_throttled(csv.reader(f)):
                    if not row or len(row) < 7: continue
                    start_raw, end_raw = row[0].strip(), row[1].strip()
                    code, name, city = row[2].strip().upper(), row[3].strip(), row[4].strip()
                    if start_raw.lower() in {"start_ip", "start", "network_start"}: continue
                    try:
                        start_addr = ipaddress.ip_address(start_raw); end_addr = ipaddress.ip_address(end_raw)
                        lat = float(row[5]); lon = float(row[6])
                    except ValueError: continue
                    if start_addr.version != end_addr.version: continue
                    if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0): continue
                    idx = self._intern_city(code, name or code, city)
                    if start_addr.version == 4: builder.append(int(start_addr), int(end_addr), idx, lat, lon)
                    else: v6_rows.append((int(start_addr), int(end_addr), idx, lat, lon))
            builder.finalize()
            self._v4_start, self._v4_end = builder.start, builder.end
            self._v4_city_idx, self._v4_lat, self._v4_lon = builder.extra
            v6_rows.sort(key=lambda r: r[0]); self._v6 = v6_rows; self._v6_starts = [r[0] for r in v6_rows]
            self._loaded = bool(self._v4_start or self._v6)
        except (OSError, csv.Error): self._loaded = False

    @property
    def available(self): return self._loaded
    @property
    def range_count(self): return len(self._v4_start) + len(self._v6)
    @property
    def path(self): return self._path

    def lookup(self, ip):
        """Returns (country_code, country_name, city, lat, lon), all None on a miss."""
        miss = (None, None, None, None, None)
        try: addr = ipaddress.ip_address(ip)
        except ValueError: return miss
        value = int(addr)
        if addr.version == 4:
            if not self._v4_start: return miss
            idx = bisect.bisect_right(self._v4_start, value) - 1
            if idx < 0 or not (self._v4_start[idx] <= value <= self._v4_end[idx]): return miss
            code, name, city = self._cities[self._v4_city_idx[idx]]
            return code, name, city, self._v4_lat[idx], self._v4_lon[idx]
        if not self._v6: return miss
        idx = bisect.bisect_right(self._v6_starts, value) - 1
        if idx < 0: return miss
        start, end, city_idx, lat, lon = self._v6[idx]
        if not (start <= value <= end): return miss
        code, name, city = self._cities[city_idx]
        return code, name, city, lat, lon


class CsvRangeDatacenterGeoIPProvider(GeoIPProvider):
    """Optional curated known-datacenter/cloud/hosting provider range lookup.

    This is a *second, lower-priority* coordinate layer (Issue #88 follow-up):
    it only ever fills in a destination point when the real city/coordinate
    GeoIP database (CsvRangeCityGeoIPProvider) has no match for that IP.
    Coordinates here are provider/region-derived (e.g. a cloud region's
    published location), not a claim about the exact physical server -- the
    caller must always keep the "known_datacenter" provenance attached to
    whatever this returns.

    Expected CSV columns: start_ip,end_ip,country_code,provider,region,lat,lon
    (header row optional; extra trailing columns are ignored). Rows must come
    from an authoritative, explicit source for that IP/range/provider/region
    (e.g. a cloud provider's own published IP-range document) -- never a
    geographic guess. See docs/GEOIP.md.
    """
    def __init__(self, path):
        self._path = path
        self._v4_start = array.array("Q"); self._v4_end = array.array("Q")
        self._v4_entry_idx = array.array("I"); self._v4_lat = array.array("d"); self._v4_lon = array.array("d")
        self._v6 = []; self._v6_starts = []
        self._entries = []; self._entry_index = {}
        self._loaded = False; self._load()

    def _intern_entry(self, code, provider, region):
        key = (code, provider, region)
        idx = self._entry_index.get(key)
        if idx is None:
            idx = len(self._entries); self._entries.append(key); self._entry_index[key] = idx
        return idx

    def _load(self):
        builder = _CompactRangeTableBuilder(("I", "d", "d")); v6_rows = []
        try:
            with open(self._path, "r", encoding="utf-8", newline="") as f:
                for row in _iter_csv_rows_throttled(csv.reader(f)):
                    if not row or len(row) < 7: continue
                    start_raw, end_raw = row[0].strip(), row[1].strip()
                    code, provider, region = row[2].strip().upper(), row[3].strip(), row[4].strip()
                    if start_raw.lower() in {"start_ip", "start", "network_start"}: continue
                    if not provider: continue
                    try:
                        start_addr = ipaddress.ip_address(start_raw); end_addr = ipaddress.ip_address(end_raw)
                        lat = float(row[5]); lon = float(row[6])
                    except ValueError: continue
                    if start_addr.version != end_addr.version: continue
                    if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0): continue
                    idx = self._intern_entry(code or None, provider, region or None)
                    if start_addr.version == 4: builder.append(int(start_addr), int(end_addr), idx, lat, lon)
                    else: v6_rows.append((int(start_addr), int(end_addr), idx, lat, lon))
            builder.finalize()
            self._v4_start, self._v4_end = builder.start, builder.end
            self._v4_entry_idx, self._v4_lat, self._v4_lon = builder.extra
            v6_rows.sort(key=lambda r: r[0]); self._v6 = v6_rows; self._v6_starts = [r[0] for r in v6_rows]
            self._loaded = bool(self._v4_start or self._v6)
        except (OSError, csv.Error): self._loaded = False

    @property
    def available(self): return self._loaded
    @property
    def range_count(self): return len(self._v4_start) + len(self._v6)
    @property
    def path(self): return self._path

    def lookup(self, ip):
        """Returns (country_code, provider, region, lat, lon), all None on a miss."""
        miss = (None, None, None, None, None)
        try: addr = ipaddress.ip_address(ip)
        except ValueError: return miss
        value = int(addr)
        if addr.version == 4:
            if not self._v4_start: return miss
            idx = bisect.bisect_right(self._v4_start, value) - 1
            if idx < 0 or not (self._v4_start[idx] <= value <= self._v4_end[idx]): return miss
            code, provider, region = self._entries[self._v4_entry_idx[idx]]
            return code, provider, region, self._v4_lat[idx], self._v4_lon[idx]
        if not self._v6: return miss
        idx = bisect.bisect_right(self._v6_starts, value) - 1
        if idx < 0: return miss
        start, end, entry_idx, lat, lon = self._v6[idx]
        if not (start <= value <= end): return miss
        code, provider, region = self._entries[entry_idx]
        return code, provider, region, lat, lon


_geoip_provider = NullGeoIPProvider(); _geoip_cache = {}; _geoip_cache_order = deque(); _geoip_cache_lock = threading.Lock(); _geoip_load_lock = threading.Lock(); _geoip_load_started = False
# City/coordinate provider is None (not a NullGeoIPProvider) when unconfigured, so callers can
# distinguish "no coordinate database at all" from "database configured but empty" cleanly.
_geoip_city_provider = None; _geoip_city_cache = {}; _geoip_city_cache_order = deque(); _geoip_city_cache_lock = threading.Lock(); _geoip_city_load_lock = threading.Lock(); _geoip_city_load_started = False
# Known-datacenter provider follows the same "None means unconfigured" convention as
# the city provider, and is always subordinate to it (Issue #88 follow-up).
_geoip_datacenter_provider = None; _geoip_datacenter_cache = {}; _geoip_datacenter_cache_order = deque(); _geoip_datacenter_cache_lock = threading.Lock(); _geoip_datacenter_load_lock = threading.Lock(); _geoip_datacenter_load_started = False
_geoip_map_cache = {"at": 0.0, "data": None}; _geoip_map_cache_lock = threading.Lock()
GEOIP_DIAGNOSTIC_MESSAGES = {
    "not_configured": "No GeoIP database configured; observed destinations remain unmapped rather than guessed.",
    "load_failed": "GeoIP database is present but failed to load.",
    "no_public_destinations": "GeoIP is loaded, but no public DNS destination IPs have been observed yet.",
    "no_country_matches": "Public destination IPs exist, but none matched the configured country ranges.",
    "country_only": "Country GeoIP is working. Coordinate-level destinations are not configured in this milestone.",
}
def geoip_lookup(ip):
    with _geoip_cache_lock:
        if ip in _geoip_cache: return _geoip_cache[ip]
    code, name = _geoip_provider.lookup(ip); result = {"country_code": code, "country_name": name}
    with _geoip_cache_lock:
        if ip not in _geoip_cache:
            _geoip_cache[ip] = result; _geoip_cache_order.append(ip)
            while len(_geoip_cache_order) > GEOIP_CACHE_MAX_ENTRIES: _geoip_cache.pop(_geoip_cache_order.popleft(), None)
    return result
def _geoip_diagnostics():
    p = _geoip_provider
    return {"provider_type": type(p).__name__, "configured": bool(p.available), "db_path_basename": os.path.basename(p.path) if p.available and p.path else None, "range_count": p.range_count if p.available else 0}
def _geoip_diagnostic_state(total_observations, geolocated_observations):
    if isinstance(_geoip_provider, NullGeoIPProvider): return "not_configured"
    if not _geoip_provider.available: return "load_failed"
    if total_observations == 0: return "no_public_destinations"
    if geolocated_observations == 0: return "no_country_matches"
    return "country_only"
def _reload_geoip_provider():
    global _geoip_provider
    with _geoip_load_lock:
        path_exists = os.path.exists(GEOIP_DB_PATH); provider = CsvRangeGeoIPProvider(GEOIP_DB_PATH) if path_exists else NullGeoIPProvider()
        with _geoip_cache_lock: _geoip_provider = provider; _geoip_cache.clear(); _geoip_cache_order.clear()
    state = "loaded" if _geoip_provider.available else ("load_failed" if path_exists else "not_configured")
    log_event("INFO" if state == "loaded" else "WARNING", "GeoIP provider state changed", state=state, ranges=_geoip_provider.range_count if _geoip_provider.available else 0)
def _geoip_initial_load_worker():
    global _geoip_load_started
    if not os.path.exists(GEOIP_DB_PATH): log_event("INFO", "GeoIP database not configured", path=os.path.basename(GEOIP_DB_PATH)); return
    with _geoip_load_lock:
        if _geoip_load_started: return
        _geoip_load_started = True
    try: log_event("INFO", "GeoIP background load started", path=os.path.basename(GEOIP_DB_PATH)); _reload_geoip_provider()
    except Exception as exc: log_event("ERROR", "GeoIP background load failed", error=repr(exc))


def geoip_city_lookup(ip):
    provider = _geoip_city_provider
    if provider is None or not provider.available:
        return {"country_code": None, "country_name": None, "city": None, "lat": None, "lon": None}
    with _geoip_city_cache_lock:
        if ip in _geoip_city_cache: return _geoip_city_cache[ip]
    code, name, city, lat, lon = provider.lookup(ip)
    result = {"country_code": code, "country_name": name, "city": city, "lat": lat, "lon": lon}
    with _geoip_city_cache_lock:
        if ip not in _geoip_city_cache:
            _geoip_city_cache[ip] = result; _geoip_city_cache_order.append(ip)
            while len(_geoip_city_cache_order) > GEOIP_CACHE_MAX_ENTRIES: _geoip_city_cache.pop(_geoip_city_cache_order.popleft(), None)
    return result
def _geoip_city_diagnostics():
    p = _geoip_city_provider
    if p is None: return {"provider_type": "NoneConfigured", "configured": False, "db_path_basename": None, "range_count": 0}
    return {"provider_type": type(p).__name__, "configured": bool(p.available), "db_path_basename": os.path.basename(p.path) if p.available and p.path else None, "range_count": p.range_count if p.available else 0}
def _reload_geoip_city_provider():
    global _geoip_city_provider
    with _geoip_city_load_lock:
        path_exists = os.path.exists(GEOIP_CITY_DB_PATH)
        provider = CsvRangeCityGeoIPProvider(GEOIP_CITY_DB_PATH) if path_exists else None
        with _geoip_city_cache_lock: _geoip_city_provider = provider; _geoip_city_cache.clear(); _geoip_city_cache_order.clear()
    state = "loaded" if (provider and provider.available) else ("load_failed" if path_exists else "not_configured")
    log_event("INFO" if state == "loaded" else "WARNING", "GeoIP city provider state changed", state=state, ranges=str(provider.range_count if provider and provider.available else 0))
def _geoip_city_initial_load_worker():
    global _geoip_city_load_started
    if not os.path.exists(GEOIP_CITY_DB_PATH): log_event("INFO", "GeoIP city database not configured", path=os.path.basename(GEOIP_CITY_DB_PATH)); return
    with _geoip_city_load_lock:
        if _geoip_city_load_started: return
        _geoip_city_load_started = True
    try: log_event("INFO", "GeoIP city background load started", path=os.path.basename(GEOIP_CITY_DB_PATH)); _reload_geoip_city_provider()
    except Exception as exc: log_event("ERROR", "GeoIP city background load failed", error=repr(exc))


def geoip_datacenter_lookup(ip):
    """Second-tier, lower-priority coordinate lookup (Issue #88 follow-up).

    Callers must only use this once a real city/coordinate GeoIP lookup has
    already missed for the same IP -- see geoip_map_payload(). Returned
    coordinates are provider/region-derived, never an exact server claim.
    """
    provider = _geoip_datacenter_provider
    if provider is None or not provider.available:
        return {"country_code": None, "provider": None, "region": None, "lat": None, "lon": None}
    with _geoip_datacenter_cache_lock:
        if ip in _geoip_datacenter_cache: return _geoip_datacenter_cache[ip]
    code, provider_name, region, lat, lon = provider.lookup(ip)
    result = {"country_code": code, "provider": provider_name, "region": region, "lat": lat, "lon": lon}
    with _geoip_datacenter_cache_lock:
        if ip not in _geoip_datacenter_cache:
            _geoip_datacenter_cache[ip] = result; _geoip_datacenter_cache_order.append(ip)
            while len(_geoip_datacenter_cache_order) > GEOIP_CACHE_MAX_ENTRIES: _geoip_datacenter_cache.pop(_geoip_datacenter_cache_order.popleft(), None)
    return result
def _geoip_datacenter_diagnostics():
    p = _geoip_datacenter_provider
    if p is None: return {"provider_type": "NoneConfigured", "configured": False, "db_path_basename": None, "range_count": 0}
    return {"provider_type": type(p).__name__, "configured": bool(p.available), "db_path_basename": os.path.basename(p.path) if p.available and p.path else None, "range_count": p.range_count if p.available else 0}
def _reload_geoip_datacenter_provider():
    global _geoip_datacenter_provider
    with _geoip_datacenter_load_lock:
        path_exists = os.path.exists(GEOIP_DATACENTER_DB_PATH)
        provider = CsvRangeDatacenterGeoIPProvider(GEOIP_DATACENTER_DB_PATH) if path_exists else None
        with _geoip_datacenter_cache_lock: _geoip_datacenter_provider = provider; _geoip_datacenter_cache.clear(); _geoip_datacenter_cache_order.clear()
    state = "loaded" if (provider and provider.available) else ("load_failed" if path_exists else "not_configured")
    log_event("INFO" if state == "loaded" else "WARNING", "GeoIP datacenter provider state changed", state=state, ranges=str(provider.range_count if provider and provider.available else 0))
def _geoip_datacenter_initial_load_worker():
    global _geoip_datacenter_load_started
    if not os.path.exists(GEOIP_DATACENTER_DB_PATH): log_event("INFO", "GeoIP datacenter database not configured", path=os.path.basename(GEOIP_DATACENTER_DB_PATH)); return
    with _geoip_datacenter_load_lock:
        if _geoip_datacenter_load_started: return
        _geoip_datacenter_load_started = True
    try: log_event("INFO", "GeoIP datacenter background load started", path=os.path.basename(GEOIP_DATACENTER_DB_PATH)); _reload_geoip_datacenter_provider()
    except Exception as exc: log_event("ERROR", "GeoIP datacenter background load failed", error=repr(exc))

HTML = """
<!doctype html><html><head><meta charset="utf-8"><link rel="icon" type="image/svg+xml" href="{{favicon_path}}"><title>{{page_title}}</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<!-- Issue #69: Leaflet + OpenStreetMap is the DNS Destinations map's real
     geographic viewport (replacing the previous experimental renderer). The legacy
     SVG renderer further below in this template remains the automatic
     fallback whenever this library/tiles can't load -- see
     static/leaflet-map.js. -->
<link rel="stylesheet" href="https://unpkg.com/gridstack@10/dist/gridstack.min.css">
<script src="https://unpkg.com/gridstack@10/dist/gridstack-all.js"></script>
<!-- Analytics dashboard grid (0.8.6): GridStack.js drives real drag/resize/
     collision-reflow for the widget grid below (see the Dashboard Builder
     script near the end of this template). Pinned to the 10.x major line
     rather than an exact patch since GridStack follows semver and only
     bumps major on breaking API changes -- see #dash-customize-btn wiring. -->
<script>
/* Applied before first paint so a saved theme/density/accent never flashes
   the default look first. Kept intentionally tiny and self-contained (the
   full preferences module below re-applies the same values once loaded). */
(function(){try{var p=JSON.parse(localStorage.getItem('dnsInspectorPrefs')||'{}');var root=document.documentElement;var theme=p.theme||'bemo-dark';if(theme==='system'){theme=(window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches)?'bemo-light':'bemo-dark';}root.setAttribute('data-theme',theme);root.setAttribute('data-density',p.density||'comfortable');root.setAttribute('data-motion',p.reducedMotion?'reduced':'');var accents={teal:'#2dd4c8',blue:'#58a6ff',violet:'#a371f7',amber:'#e3b341',pink:'#ec4899',slate:'#94a3b8'};if(p.accent&&accents[p.accent])root.style.setProperty('--accent',accents[p.accent]);}catch(e){}})();
</script>
<style>
:root{color-scheme:dark;--sem-ok:#3fb950;--sem-info:#58a6ff;--sem-blocked:#f85149;--sem-warn:#d29922;--sem-crit:#da3633;--sem-live:#39c5cf;
--font-sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;--font-mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
--bg:#090c11;--surface-0:#0d1117;--surface-1:#11161d;--surface-2:#161b22;--surface-3:#1c232e;
--border:#242b35;--border-strong:#333c49;--text-primary:#e6edf3;--text-secondary:#8b949e;--text-tertiary:#5c6773;
--accent:#2dd4c8;--accent-strong:color-mix(in srgb, var(--accent) 82%, black);--accent-soft:color-mix(in srgb, var(--accent) 15%, transparent);--accent-contrast:color-mix(in srgb, var(--accent) 92%, black);
--radius-xs:6px;--radius-sm:9px;--radius-md:13px;--radius-lg:18px;--radius-pill:999px;
--space-1:4px;--space-2:8px;--space-3:12px;--space-4:16px;--space-5:20px;--space-6:28px;--space-7:36px;--space-8:48px;
--shadow-sm:0 1px 2px rgba(0,0,0,.3);--shadow-md:0 10px 26px rgba(0,0,0,.32);--shadow-lg:0 22px 52px rgba(0,0,0,.4);
--transition:150ms ease}

/* ---- Inspector BEMO themes (0.8.4) ----
   Each theme only redeclares surface/border/text/semantic tokens; the
   derived --accent-strong/--accent-soft/--accent-contrast above stay in
   effect (they resolve against whatever --accent is cascaded on <html> at
   used-value time), so a user accent override keeps working in every
   theme without repeating the color-mix() formula per theme. Semantic
   status colors (--sem-*) are re-tuned per theme for contrast but keep
   their meaning: ok=allowed, blocked=blocked, warn/crit unchanged. */
html[data-theme="bemo-light"]{color-scheme:light;
--bg:#f4f6f8;--surface-0:#ffffff;--surface-1:#ffffff;--surface-2:#f1f4f7;--surface-3:#e7ecf1;
--border:#dde3e9;--border-strong:#c3ccd4;--text-primary:#0f172a;--text-secondary:#4b5768;--text-tertiary:#6b7688;
--accent:#0e8f83;--sem-ok:#1a7f37;--sem-info:#0969da;--sem-blocked:#cf222e;--sem-warn:#9a6700;--sem-crit:#a40e26;--sem-live:#0f8b96;
--shadow-sm:0 1px 2px rgba(15,23,42,.08);--shadow-md:0 10px 26px rgba(15,23,42,.10);--shadow-lg:0 22px 52px rgba(15,23,42,.14)}
html[data-theme="bemo-aurora"]{color-scheme:dark;
--bg:#070912;--surface-0:#0b0f1c;--surface-1:#0f1426;--surface-2:#151b33;--surface-3:#1b2340;
--border:#262e4d;--border-strong:#34406b;--text-primary:#e7ecff;--text-secondary:#9aa4d1;--text-tertiary:#6b76a3;
--accent:#7c8cff;--sem-ok:#3ddc97;--sem-info:#5eb1ff;--sem-blocked:#ff6b81;--sem-warn:#ffcb66;--sem-crit:#ff4d6d;--sem-live:#8ee9ff}
html[data-theme="bemo-natural"]{color-scheme:dark;
--bg:#0e120f;--surface-0:#111611;--surface-1:#141a15;--surface-2:#1a2119;--surface-3:#212a1f;
--border:#2b342a;--border-strong:#3b4739;--text-primary:#e8efe6;--text-secondary:#a3b09e;--text-tertiary:#79876f;
--accent:#8fbf7f;--sem-ok:#7cc576;--sem-info:#7fb3a3;--sem-blocked:#e2735a;--sem-warn:#d9a441;--sem-crit:#c9503a;--sem-live:#5fae95}

/* ---- density: spacing/typography scale only, colors are never touched ---- */
html[data-density="compact"]{--space-3:9px;--space-4:12px;--space-5:16px;--space-6:20px}
html[data-density="compact"] .card{padding:14px 16px}
html[data-density="compact"] td,html[data-density="compact"] th{padding:8px 8px}
html[data-density="compact"] .toolbar,html[data-density="compact"] .recent-controls{padding:8px}
html[data-density="dense"]{--space-3:7px;--space-4:9px;--space-5:12px;--space-6:16px}
html[data-density="dense"] .card{padding:11px 13px}
html[data-density="dense"] td,html[data-density="dense"] th{padding:5px 7px;font-size:.86rem}
html[data-density="dense"] .toolbar,html[data-density="dense"] .recent-controls{padding:6px}
html[data-density="dense"] h2{font-size:.96rem}

/* ---- explicit reduced-motion preference, in addition to the OS setting ---- */
html[data-motion="reduced"] *,html[data-motion="reduced"] *::before,html[data-motion="reduced"] *::after{animation-duration:.001ms!important;animation-iteration-count:1!important;transition-duration:.001ms!important}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.001ms!important;animation-iteration-count:1!important;transition-duration:.001ms!important}}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:28px;max-width:1450px;margin-inline:auto}
h1{margin:0 0 6px;font-size:2rem;letter-spacing:-.02em}.muted,small{color:#8b949e}.live{color:#7ee787;font-weight:700}.updated-time{color:#58a6ff;font-weight:700}.updated-date{color:#8b949e}.signal{border-left:3px solid #30363d;padding:10px 12px;background:#0d1117;border-radius:8px}.signal-green{border-color:#3fb950}.signal-blue{border-color:#58a6ff}.signal-yellow{border-color:#d29922}.signal-orange{border-color:#db6d28}.signal-red{border-color:#f85149}.signal-gray{border-color:#8b949e}.signal-title{font-weight:750;margin-bottom:5px}.evidence{margin:6px 0 0;padding-left:18px;color:#c9d1d9}.evidence li{margin:3px 0}.confidence-high{color:#3fb950;font-weight:700}.confidence-medium{color:#d29922;font-weight:700}.confidence-low{color:#8b949e;font-weight:700}.dns-list{display:flex;flex-wrap:wrap;gap:6px}.dns-ip{display:inline-block;padding:4px 8px;border:1px solid #30363d;border-radius:7px;background:#161b22;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.82rem}.vendor-logo{width:20px;height:20px;object-fit:contain;vertical-align:middle;margin-right:6px;border-radius:4px}.vendor-logo-lg{width:30px;height:30px;object-fit:contain;flex:0 0 30px}.vendor-mark{display:inline-flex;align-items:center;justify-content:center;width:20px;height:20px;margin-right:6px;border-radius:5px;background:#30363d;font-size:.7rem}.vendor-mark-lg{display:inline-flex;align-items:center;justify-content:center;width:30px;height:30px;flex:0 0 30px;border-radius:8px;background:#30363d;font-size:.75rem;font-weight:800}.device-type-icon{display:inline-flex;align-items:center;justify-content:center;width:20px;height:20px;flex:0 0 20px;margin-right:6px;border-radius:5px;background:#30363d;color:#8b949e}.device-type-icon-lg{display:inline-flex;align-items:center;justify-content:center;width:30px;height:30px;flex:0 0 30px;border-radius:8px;background:#30363d;color:#8b949e}.device-type-icon svg,.device-type-icon-lg svg{width:70%;height:70%;fill:none;stroke:currentColor;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}
.toolbar{display:flex;gap:8px;align-items:center;margin:20px 0 4px}.toolbar input{flex:1;min-width:0}.toolbar button{white-space:nowrap}
.observability-strip{display:flex;align-items:center;flex-wrap:wrap;gap:8px;margin:4px 0 8px}
.observability-pill{display:inline-flex;align-items:center;gap:6px;padding:5px 9px;border:1px solid #30363d;border-radius:999px;background:#11161d;color:#c9d1d9;font-size:.78rem;font-variant-numeric:tabular-nums}
.observability-dot{width:7px;height:7px;border-radius:50%;background:#3fb950;box-shadow:0 0 0 2px rgba(63,185,80,.10)}
.debug-button{padding:5px 9px;font-size:.78rem;border-radius:999px}.devlog-entry{padding:8px 10px;border-bottom:1px solid var(--border);font-size:.78rem}.devlog-entry:last-child{border-bottom:0}.devlog-meta{color:var(--text-tertiary);font-family:var(--font-mono);margin-right:8px}.devlog-level{font-weight:800;margin-right:6px}.devlog-level-ERROR{color:var(--sem-blocked)}.devlog-level-WARNING{color:var(--sem-warn)}.devlog-level-INFO{color:var(--sem-info)}.devlog-scroll{max-height:260px;overflow:auto;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--surface-0)}
.debug-button:hover{border-color:#58a6ff}
input,button{background:#161b22;color:#e6edf3;border:1px solid #30363d;padding:10px 13px;border-radius:8px;font:inherit}button{cursor:pointer}button:hover{border-color:#58a6ff}
.card{background:#11161d;border:1px solid #30363d;border-radius:14px;padding:18px;margin-top:18px;box-shadow:0 8px 28px rgba(0,0,0,.16)}
.card h2{margin-top:0;letter-spacing:-.01em}
table{width:100%;border-collapse:collapse;table-layout:fixed}#recent-table th:nth-child(1),#recent-table td:nth-child(1){width:34%}#recent-table th:nth-child(2),#recent-table td:nth-child(2){width:10%}#recent-table th:nth-child(3),#recent-table td:nth-child(3){width:31%}#recent-table th:nth-child(4),#recent-table td:nth-child(4){width:9%}#recent-table th:nth-child(5),#recent-table td:nth-child(5){width:7%}#recent-table th:nth-child(6),#recent-table td:nth-child(6){width:9%}#recent-table th,#recent-table td{overflow:hidden;text-overflow:ellipsis;vertical-align:top}td,th{padding:11px 10px;border-bottom:1px solid #21262d;text-align:left;vertical-align:middle}th{font-size:.78rem;text-transform:uppercase;letter-spacing:.06em;color:#8b949e}.sortable{cursor:pointer;user-select:none}.sortable:hover{color:#e6edf3}.sortable::after{content:" ↕";opacity:.35}.sortable.sort-asc::after{content:" ↑";opacity:1}.sortable.sort-desc::after{content:" ↓";opacity:1}tr:last-child td{border-bottom:0}
a{color:#79c0ff;text-decoration:none}a:hover{text-decoration:underline}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.kv{padding:8px 0;border-bottom:1px solid #21262d}.kv b{display:inline-block;min-width:140px}
pre{white-space:pre-wrap;word-break:break-word;color:#ddd}.source{font-size:.88em;color:#8b949e}.error{color:#ff9b9b}
.tag{display:inline-block;padding:4px 9px;border-radius:999px;background:#30363d;margin:2px;font-size:.82rem}.green{background:#174d2a}.yellow{background:#5a4610}.orange{background:#6a3510}.red{background:#6a1717}.blue{background:#16395c}.gray{background:#30363d}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}.dot-green{background:#3fb950}.dot-blue{background:#58a6ff}.dot-yellow{background:#d29922}.dot-orange{background:#db6d28}.dot-red{background:#f85149}.dot-gray{background:#8b949e}.status-pill{display:inline-flex;align-items:center;gap:5px;padding:4px 8px;border-radius:999px;font-size:.78rem;font-weight:700}.status-allowed{background:#174d2a;color:#7ee787}.status-blocked{background:#6a1717;color:#ffb4b4}.status-mixed{background:#5a4610;color:#f2cc60}.status-unknown{background:#30363d;color:#8b949e}.severity-info{color:#3fb950;font-weight:700}.severity-low{color:#d29922;font-weight:700}.severity-medium{color:#db6d28;font-weight:700}.severity-high{color:#f85149;font-weight:700}.severity-unknown{color:#8b949e;font-weight:700}
.provenance-badge{display:inline-flex;align-items:center;padding:2px 8px;border-radius:999px;font-size:.7rem;font-weight:700;vertical-align:middle;background:#30363d;color:#8b949e}.provenance-city_geoip{background:#174d2a;color:#7ee787}.provenance-known_datacenter{background:#16395c;color:#8fc7ff}.provenance-mixed{background:#5a4610;color:#f2cc60}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.sub{font-size:.82rem;color:#8b949e}.right{float:right}
.device{display:flex;align-items:flex-start;gap:10px}.icon{font-size:1.55rem;line-height:1.2}.device-name{font-size:1rem;font-weight:700;line-height:1.25}.confidence{font-size:.78rem;color:#8b949e}.technical{font-size:.76rem;color:#6e7681;margin-top:2px}
.device-list{display:flex;flex-wrap:wrap;gap:5px}.device-chip{display:inline-flex;align-items:center;gap:5px;background:#161b22;border:1px solid #30363d;border-radius:999px;padding:4px 8px;font-size:.8rem}.device-chip .device-type-icon{margin-right:0;width:16px;height:16px;flex-basis:16px;background:transparent}
.client-chip{display:inline-block;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:4px 7px;margin:2px;font-size:.85em}
.glance-domain{font-weight:650}.recent-controls{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:0 0 14px;padding:12px;border:1px solid #30363d;border-radius:10px;background:#0d1117}.filter-group{display:flex;gap:6px;align-items:center;flex-wrap:wrap}.filter-label{font-size:.76rem;color:#8b949e;text-transform:uppercase;letter-spacing:.06em}.filter-btn{padding:7px 10px;border-radius:8px;font-size:.82rem;font-weight:700}.filter-btn.active{background:#16395c;border-color:#58a6ff;color:#e6edf3}.filter-btn.filter-allowed.active{background:#174d2a;border-color:#3fb950;color:#7ee787}.filter-btn.filter-blocked.active{background:#6a1717;border-color:#f85149;color:#ffb4b4}.filter-btn.filter-new.active{background:#5a4610;border-color:#d29922;color:#f2cc60}.filter-select{padding:7px 9px;font-size:.82rem;min-width:120px}.results-summary{display:flex;gap:12px;align-items:center;flex-wrap:wrap;color:#8b949e;font-size:.8rem;margin:8px 0 12px}.results-summary b{color:#e6edf3}.new-badge{display:inline-flex;align-items:center;gap:4px;padding:3px 7px;border-radius:999px;background:#5a4610;color:#f2cc60;border:1px solid #8f6b1c;font-size:.72rem;font-weight:800;margin-left:7px;vertical-align:middle}.new-badge-dot{width:6px;height:6px;border-radius:50%;background:#d29922}.row-new td{background:rgba(210,153,34,.035)}.new-banner{display:none;align-items:center;justify-content:space-between;gap:10px;margin:0 0 12px;padding:9px 12px;border:1px solid #8f6b1c;border-radius:9px;background:#2b2412;color:#f2cc60}.new-banner.show{display:flex}.new-banner button{padding:5px 9px;font-size:.78rem}.new-domain-items{display:inline-flex;flex-wrap:wrap;gap:6px;align-items:center}.new-domain-item{display:inline-flex;align-items:center;gap:5px}.new-domain-link{color:#f2cc60;font-weight:650}.new-domain-link:hover{color:#fff;text-decoration:underline}.pager{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-top:12px;padding-top:10px;border-top:1px solid #21262d}.pager-controls{display:flex;gap:6px;align-items:center}.pager button{padding:6px 10px;font-size:.8rem}.pager button:disabled{opacity:.45;cursor:default}.page-label{font-size:.8rem;color:#8b949e}.external-tools{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}.external-tool{display:inline-flex;align-items:center;gap:4px;padding:3px 7px;border:1px solid #30363d;border-radius:7px;background:#161b22;color:#8b949e;font-size:.74rem;text-decoration:none}.external-tool:hover{border-color:#58a6ff;color:#79c0ff;text-decoration:none}.inline-tools{display:inline-flex;gap:5px;margin-left:6px;vertical-align:middle}.inline-tool{display:inline-flex;align-items:center;justify-content:center;width:20px;height:20px;border:1px solid #30363d;border-radius:6px;background:#161b22;color:#8b949e;font-size:.72rem;text-decoration:none}.inline-tool svg,.external-tool svg{width:13px;height:13px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}.inline-tool:hover{border-color:#58a6ff;color:#79c0ff;text-decoration:none}.inline-tool{cursor:pointer}.external-tool.icon-only{width:20px;height:20px;padding:0;justify-content:center}.link-device{color:inherit;text-decoration:none}.link-device:hover{text-decoration:none}.link-device:hover .device-name{text-decoration:underline}.link-ip{font-weight:650}.device-chip{cursor:pointer}.device-chip:hover{border-color:#58a6ff}.device-label-btn{padding:3px 7px;font-size:.72rem;border-radius:7px}
.device-label-cell{width:16%;vertical-align:top}.device-ip-ping{display:inline-flex;align-items:center;gap:5px;margin-left:5px;padding:2px 0}.device-ip-ping-dot{width:8px;height:8px;border-radius:50%;display:inline-block;border:1px solid #30363d;background:#8b949e;flex:0 0 8px}.device-ip-ping-dot.online{background:#3fb950;border-color:#3fb950}.device-ip-ping-dot.offline{background:#f85149;border-color:#f85149}.device-ip-ping-dot.pending{background:#d29922;border-color:#d29922;animation:dnsInspectorPulse 1s ease-in-out infinite}@keyframes dnsInspectorPulse{50%{opacity:.35}}.device-ip-ping-btn{padding:2px 6px;font-size:.68rem;border-radius:6px}.device-ip-ping-btn:disabled{opacity:.55;cursor:default}.device-label-cell .device-label-inline{margin-top:0;display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.device-label-cell .device-label-text{font-size:.8rem}.device-table-label-col{width:16%}
.refresh-status{position:fixed;top:10px;right:16px;z-index:100;display:none;align-items:center;gap:8px;padding:7px 10px;border:1px solid #30363d;border-radius:999px;background:rgba(17,22,29,.96);box-shadow:0 6px 20px rgba(0,0,0,.25);color:#c9d1d9;font-size:.78rem}
.refresh-status.show{display:inline-flex}.refresh-spinner{width:13px;height:13px;border:2px solid #30363d;border-top-color:#58a6ff;border-radius:50%;animation:dnsInspectorSpin .75s linear infinite}@keyframes dnsInspectorSpin{to{transform:rotate(360deg)}}
.device-label-inline{display:inline-flex;align-items:center;gap:6px;margin-top:4px}.device-label-text{color:#c9d1d9;font-size:.76rem}.clickable-label{cursor:pointer}.glance-meta{display:flex;flex-wrap:wrap;gap:6px;margin-top:4px;color:#8b949e;font-size:.78rem}.glance-devices{max-width:520px}
.tabs{display:flex;gap:6px;margin:18px 0 0;padding:0 4px;position:sticky;top:0;z-index:5;background:#0d1117}
.tab-btn{border:1px solid #30363d;background:#161b22;color:#8b949e;padding:9px 14px;border-radius:9px 9px 0 0;cursor:pointer;font-weight:700}
.tab-btn:hover{border-color:#58a6ff;color:#c9d1d9}.tab-btn.active{background:#11161d;color:#e6edf3;border-bottom-color:#11161d}
.tab-panel{display:none}.tab-panel.active{display:block}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.chart-card{min-height:260px}.chart-list{display:flex;flex-direction:column;gap:9px;margin-top:10px}.bar-row{display:grid;grid-template-columns:minmax(120px,1fr) 3fr auto;gap:10px;align-items:center;font-size:.84rem}.bar-label{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.bar-track{height:12px;background:#161b22;border:1px solid #30363d;border-radius:999px;overflow:hidden}.bar-fill{height:100%;background:#58a6ff;border-radius:999px;min-width:2px}.bar-value{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#c9d1d9;min-width:70px;text-align:right}.stats-note{color:#8b949e;font-size:.8rem;margin-top:10px}
@media(max-width:900px){body{padding:16px}.grid{grid-template-columns:1fr}.toolbar{flex-wrap:wrap}.toolbar input{flex-basis:100%}td,th{padding:9px 6px}.hide-mobile{display:none}}
.dev-banner{position:sticky;top:0;z-index:1000;background:#db6d28;color:#0d1117;font-weight:800;text-align:center;padding:10px 16px;letter-spacing:.02em;border-radius:8px;margin-bottom:16px;border:2px solid #f0883e}
.dev-badge{display:inline-block;background:#db6d28;color:#0d1117;font-weight:800;font-size:.5em;padding:2px 10px;border-radius:999px;vertical-align:middle;margin-left:10px;letter-spacing:.05em}
.analytics-hero{display:grid;grid-template-columns:1.3fr 1fr;gap:14px;align-items:stretch}
.live-card{position:relative;overflow:hidden;border-color:#1f6feb55}
.live-card::before{content:'';position:absolute;inset:0;background:radial-gradient(600px 200px at 0% 0%,rgba(57,197,207,.10),transparent 60%);pointer-events:none}
.live-title{display:flex;align-items:center;gap:8px;font-weight:750;color:#c9d1d9}
.live-dot{width:9px;height:9px;border-radius:50%;background:var(--sem-live);box-shadow:0 0 0 3px rgba(57,197,207,.18);animation:dnsInspectorPulse 1.4s ease-in-out infinite}
.live-rate{font-size:2.4rem;font-weight:800;letter-spacing:-.02em;margin:8px 0 2px;font-variant-numeric:tabular-nums;position:relative}
.live-rate small{font-size:.4em;color:#8b949e;font-weight:700;margin-left:6px}
.live-sparkline-wrap{margin-top:8px;position:relative}
.history-svg{width:100%;height:120px;display:block}
.history-svg-clickable{cursor:pointer}
.history-svg-clickable:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.metric-crosshair{stroke:var(--accent);stroke-width:1.4;stroke-dasharray:3 2;opacity:.85}
.metric-selected-dot{fill:var(--accent);stroke:var(--surface-0);stroke-width:1.6}
.interval-detail{margin-top:10px;padding:12px;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--surface-2)}
.interval-detail-head{display:flex;align-items:flex-start;justify-content:space-between;gap:8px}
.interval-detail-sub{display:block;font-size:.72rem;color:var(--text-secondary);font-weight:500}
.interval-detail-close{background:transparent;border:none;color:var(--text-secondary);font-size:1.1rem;line-height:1;cursor:pointer;padding:2px 6px}
.interval-detail-close:hover{color:var(--text-primary)}
.interval-detail-stats{display:flex;gap:16px;margin:10px 0;flex-wrap:wrap}
.interval-detail-stats div{display:flex;flex-direction:column}
.interval-detail-stats b{font-size:1.1rem;font-variant-numeric:tabular-nums}
.interval-detail-stats span{font-size:.7rem;color:var(--text-secondary);text-transform:uppercase;letter-spacing:.03em}
.interval-status-row{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px}
.interval-status-chip{font-size:.7rem;padding:2px 8px;border-radius:999px;background:var(--surface-3);color:var(--text-secondary)}
.interval-status-chip.interval-status-blocked{color:var(--sem-blocked)}
.interval-status-chip.interval-status-allowed{color:var(--sem-ok)}
.interval-detail-note{font-size:.75rem;color:var(--text-secondary);margin-bottom:8px;font-style:italic}
.interval-detail-lists{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.interval-detail-lists h4{margin:0 0 4px;font-size:.75rem;color:var(--text-secondary);text-transform:uppercase;letter-spacing:.03em}
.interval-detail-lists ul{list-style:none;margin:0;padding:0;max-height:160px;overflow-y:auto}
.interval-detail-lists li{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:3px 0;font-size:.8rem;border-bottom:1px solid var(--border)}
.interval-detail-lists li.empty{color:var(--text-secondary);font-style:italic;border-bottom:none}
.interval-detail-lists a{color:var(--accent);text-decoration:none}
.interval-detail-lists a:hover{text-decoration:underline}
.interval-detail-loading,.interval-detail-error{font-size:.8rem;color:var(--text-secondary)}
.report-headline{display:flex;align-items:baseline;justify-content:space-between;margin-bottom:10px}
.report-headline h3{margin:0;font-size:1rem}
.report-kpi-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px;margin-bottom:12px}
.report-kpi{background:var(--surface-2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:9px 10px;display:flex;flex-direction:column;gap:2px}
.report-kpi-label{font-size:.68rem;text-transform:uppercase;letter-spacing:.04em;color:var(--text-secondary)}
.report-kpi-value{font-size:1.25rem;font-weight:800;font-variant-numeric:tabular-nums}
.report-kpi-sub{font-size:.7rem;color:var(--text-secondary)}
.report-observations{display:flex;flex-direction:column;gap:8px}
.report-observation{border-radius:var(--radius-sm);padding:9px 11px;background:var(--surface-2);border:1px solid var(--border);font-size:.82rem}
.report-observation b{display:block;margin-bottom:2px}
.report-observation p{margin:0;color:var(--text-secondary);font-size:.78rem;line-height:1.4}
.report-observation-warn{border-color:var(--sem-warn);background:color-mix(in srgb, var(--sem-warn) 10%, var(--surface-2))}
.report-observation-blocked{border-color:var(--sem-blocked);background:color-mix(in srgb, var(--sem-blocked) 10%, var(--surface-2))}
.report-observation-ok{border-color:var(--sem-ok);background:color-mix(in srgb, var(--sem-ok) 10%, var(--surface-2))}
.stat-tiles{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}
.stat-tile{background:#0d1117;border:1px solid #30363d;border-radius:10px;padding:12px;display:flex;flex-direction:column;justify-content:center}
.stat-tile-label{font-size:.72rem;color:#8b949e;text-transform:uppercase;letter-spacing:.05em}
.stat-tile-value{font-size:1.5rem;font-weight:800;margin-top:4px;font-variant-numeric:tabular-nums}
.stat-tile.ok .stat-tile-value{color:var(--sem-ok)}
.stat-tile.blocked .stat-tile-value{color:var(--sem-blocked)}
.stat-tile.info .stat-tile-value{color:var(--sem-info)}
.stat-tile.warn .stat-tile-value{color:var(--sem-warn)}
.analytics-range-controls{display:flex;gap:6px;align-items:center;margin:14px 0;flex-wrap:wrap}
.range-btn{padding:6px 12px;font-size:.8rem;border-radius:999px}
.range-btn.active{background:#16395c;border-color:#58a6ff;color:#e6edf3}
.range-custom-controls{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-top:8px}
.range-custom-controls[hidden]{display:none}
.range-custom-controls input[type=date]{padding:5px 8px;font-size:.8rem}
.range-custom-controls button{padding:5px 12px;font-size:.8rem;border-radius:999px}
.range-custom-error{color:var(--sem-blocked);font-size:.78rem}
.assessment-open-btn{white-space:nowrap}
.assessment-toolbar{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-bottom:16px}
.assessment-section{margin-top:14px}
.assessment-section>summary{cursor:pointer;font-weight:700;font-size:1.02rem;padding:2px 0;list-style:revert}
.assessment-section>summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.assessment-section-body{margin-top:12px}
.assessment-kv{display:grid;grid-template-columns:auto 1fr;gap:6px 14px;font-size:.86rem}
.assessment-kv b{color:var(--text-secondary);font-weight:600}
.assessment-list{list-style:none;margin:0;padding:0;display:grid;gap:6px;font-size:.86rem}
.assessment-list li{display:flex;justify-content:space-between;gap:10px;border-bottom:1px solid var(--border);padding-bottom:4px}
.assessment-note{color:var(--text-tertiary);font-size:.8rem;margin-top:8px}
.status-bar{display:flex;height:16px;border-radius:999px;overflow:hidden;border:1px solid #30363d;background:#161b22}
.status-seg{height:100%;min-width:0}
.legend-row{display:flex;flex-wrap:wrap;gap:14px;margin-top:10px;font-size:.8rem;color:#c9d1d9}
.legend-item{display:inline-flex;align-items:center;gap:6px}
.legend-dot{width:9px;height:9px;border-radius:50%;flex:0 0 9px}
.activity-row{display:flex;justify-content:space-between;align-items:center;gap:8px;padding:7px 0;border-bottom:1px solid #21262d;font-size:.85rem}
.activity-row:last-child{border-bottom:0}
.activity-row .sub{color:#8b949e;font-size:.76rem;white-space:nowrap}
.sem-dot{width:8px;height:8px;border-radius:50%;flex:0 0 8px;display:inline-block;margin-right:6px}
.sem-ok{background:var(--sem-ok)}.sem-info{background:var(--sem-info)}.sem-blocked{background:var(--sem-blocked)}.sem-warn{background:var(--sem-warn)}.sem-crit{background:var(--sem-crit)}.sem-live{background:var(--sem-live)}
@media(max-width:900px){.analytics-hero,.stat-tiles{grid-template-columns:1fr}}

/* ============================================================
   Inspector BEMO design system
   A single token-driven visual language layered over the base
   rules above. Selectors are re-declared here (not renamed) so
   every element JS/Python already emits picks up the new look.
   ============================================================ */
html{background:var(--bg)}
body{font-family:var(--font-sans);background:var(--bg);background-image:radial-gradient(1100px 480px at 12% -10%,rgba(45,212,200,.06),transparent 60%),radial-gradient(900px 420px at 100% 0%,rgba(88,166,255,.05),transparent 55%);color:var(--text-primary);max-width:1480px;padding:24px 28px 56px;line-height:1.45}
::selection{background:var(--accent-soft);color:var(--text-primary)}
h1,h2,h3{font-family:var(--font-sans);letter-spacing:-.015em;color:var(--text-primary)}
h2{font-size:1.05rem;font-weight:750}
h3{font-size:.92rem;font-weight:700;color:var(--text-secondary);text-transform:uppercase;letter-spacing:.05em;margin:0 0 10px}
.muted,small{color:var(--text-secondary)}
a{color:var(--accent);text-decoration:none;transition:color var(--transition)}
a:hover{color:#7fe9e1;text-decoration:underline}
.live{color:var(--sem-ok)}

/* focus visibility: color is never the only signal elsewhere, but focus needs to be unmistakable */
a:focus-visible,button:focus-visible,input:focus-visible,select:focus-visible,.tab-btn:focus-visible,.filter-btn:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}

input,button,select{font-family:var(--font-sans);background:var(--surface-2);color:var(--text-primary);border:1px solid var(--border);border-radius:var(--radius-sm);padding:9px 13px;font-size:.88rem;transition:border-color var(--transition),background var(--transition),color var(--transition)}
button{cursor:pointer;font-weight:650}
button:hover,select:hover{border-color:var(--border-strong)}
button:hover{border-color:var(--accent);color:var(--text-primary)}
input:focus,button:focus,select:focus{border-color:var(--accent)}
input::placeholder{color:var(--text-tertiary)}

.card{background:linear-gradient(180deg,var(--surface-1),var(--surface-0));border:1px solid var(--border);border-radius:var(--radius-lg);padding:20px 22px;margin-top:18px;box-shadow:var(--shadow-md)}
.card>h2{display:flex;align-items:center;gap:8px;margin:0 0 14px;padding-bottom:12px;border-bottom:1px solid var(--border)}

/* ---- application shell / navigation ---- */
.app-shell{display:flex;align-items:flex-start;justify-content:space-between;gap:24px;flex-wrap:wrap;padding-bottom:18px;border-bottom:1px solid var(--border);margin-bottom:4px}
.shell-brand{display:flex;align-items:center;gap:14px;min-width:0}
.brand-mark{flex:0 0 auto;width:44px;height:44px;border-radius:var(--radius-md);background:linear-gradient(155deg,var(--accent-soft),transparent 70%);border:1px solid var(--border-strong);display:flex;align-items:center;justify-content:center;color:var(--accent)}
.brand-mark svg{width:24px;height:24px;fill:none;stroke:currentColor;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}
.brand-text{min-width:0}
.brand-platform{display:block;font-size:.72rem;font-weight:750;letter-spacing:.12em;text-transform:uppercase;color:var(--accent)}
.brand-title{margin:1px 0 0;font-size:1.7rem;line-height:1.15}
.version-chip{font-size:.55em;color:var(--text-secondary);font-weight:600;margin-left:6px}
.shell-status{display:flex;flex-direction:column;align-items:flex-end;gap:6px;text-align:right}
.shell-meta{margin:0;font-size:.82rem}
@media(max-width:760px){.app-shell{flex-direction:column}.shell-status{align-items:flex-start;text-align:left}}

.dev-banner{position:sticky;top:0;z-index:1000;display:flex;align-items:center;justify-content:center;gap:9px;background:linear-gradient(90deg,#db6d28,#e2862f);color:#100a04;font-weight:800;text-align:center;padding:10px 16px;letter-spacing:.03em;border-radius:var(--radius-sm);margin-bottom:16px;border:1px solid #f0883e;box-shadow:var(--shadow-sm)}
.dev-banner svg{width:17px;height:17px;flex:0 0 17px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.dev-badge{display:inline-flex;align-items:center;background:var(--sem-warn);color:#100a04;font-weight:800;font-size:.5em;padding:2px 10px;border-radius:var(--radius-pill);vertical-align:middle;margin-left:10px;letter-spacing:.06em}

.observability-strip{gap:8px}
.observability-pill{background:var(--surface-2);border-color:var(--border);border-radius:var(--radius-pill);color:var(--text-secondary)}
.observability-dot{background:var(--sem-ok);box-shadow:0 0 0 3px rgba(63,185,80,.15)}
.debug-button{border-radius:var(--radius-pill);color:var(--text-secondary)}
.debug-button:hover{border-color:var(--accent);color:var(--text-primary)}

.toolbar{gap:10px;margin:22px 0 18px;padding:6px;background:var(--surface-1);border:1px solid var(--border);border-radius:var(--radius-md)}
.toolbar input{border:none;background:transparent;padding:9px 12px}
.toolbar input:focus{outline:none}
.toolbar button{border-radius:var(--radius-sm)}

.tabs{display:flex;gap:4px;margin:22px 0 0;padding:4px;position:sticky;top:0;z-index:5;background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-md)}
.tab-btn{display:inline-flex;align-items:center;gap:7px;border:1px solid transparent;background:transparent;color:var(--text-secondary);padding:9px 15px;border-radius:var(--radius-sm);font-weight:700;font-size:.88rem}
.tab-btn svg{width:15px;height:15px;flex:0 0 15px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.tab-btn:hover{color:var(--text-primary);background:var(--surface-2)}
.tab-btn.active{background:var(--accent-soft);color:var(--text-primary);border-color:var(--accent)}
.tab-panel.active{animation:dnsInspectorFadeIn .22s ease}
@keyframes dnsInspectorFadeIn{from{opacity:0;transform:translateY(3px)}to{opacity:1;transform:none}}

/* ---- tables ---- */
table{border-spacing:0}
th{font-family:var(--font-sans);color:var(--text-tertiary);font-weight:700;background:transparent;border-bottom:1px solid var(--border-strong)}
td,th{border-bottom:1px solid var(--border);padding:12px 10px}
tbody tr{transition:background var(--transition)}
tbody tr:hover{background:rgba(255,255,255,.02)}
.sortable::after{opacity:.3}
.sortable.sort-asc::after,.sortable.sort-desc::after{opacity:1;color:var(--accent)}

/* ---- badges / status language (color is never the only signal: text always accompanies these) ---- */
.tag{background:var(--surface-3);border:1px solid var(--border);border-radius:var(--radius-pill);color:var(--text-secondary);font-weight:650;font-size:.78rem}
.tag.green{background:rgba(63,185,80,.14);border-color:rgba(63,185,80,.35);color:#7ee787}
.tag.yellow{background:rgba(210,153,34,.14);border-color:rgba(210,153,34,.35);color:#f2cc60}
.tag.orange{background:rgba(219,109,40,.14);border-color:rgba(219,109,40,.35);color:#ffa96b}
.tag.red{background:rgba(248,81,73,.14);border-color:rgba(248,81,73,.35);color:#ffb4b4}
.tag.blue{background:rgba(88,166,255,.14);border-color:rgba(88,166,255,.35);color:#8fc7ff}
.tag.gray{background:var(--surface-3);border-color:var(--border);color:var(--text-secondary)}
.status-pill{border-radius:var(--radius-pill);font-weight:750}
.provenance-badge{border-radius:var(--radius-pill);font-weight:750}
.provenance-city_geoip{background:rgba(63,185,80,.14);color:#7ee787;border:1px solid rgba(63,185,80,.3)}
.provenance-known_datacenter{background:rgba(88,166,255,.14);color:#8fc7ff;border:1px solid rgba(88,166,255,.3)}
.provenance-mixed{background:rgba(210,153,34,.14);color:#f2cc60;border:1px solid rgba(210,153,34,.3)}
.status-allowed{background:rgba(63,185,80,.14);color:#7ee787;border:1px solid rgba(63,185,80,.3)}
.status-blocked{background:rgba(248,81,73,.14);color:#ffb4b4;border:1px solid rgba(248,81,73,.3)}
.status-mixed{background:rgba(210,153,34,.14);color:#f2cc60;border:1px solid rgba(210,153,34,.3)}
.status-unknown{background:var(--surface-3);color:var(--text-secondary);border:1px solid var(--border)}
.new-badge{background:rgba(210,153,34,.16);border:1px solid rgba(210,153,34,.4);color:#f2cc60;border-radius:var(--radius-pill)}
.new-banner{border-radius:var(--radius-md);background:rgba(210,153,34,.1);border:1px solid rgba(210,153,34,.4)}

/* ---- filters / controls toolbar ---- */
.recent-controls{background:var(--surface-1);border:1px solid var(--border);border-radius:var(--radius-md);padding:14px}
.filter-label{color:var(--text-tertiary)}
.filter-btn{border-radius:var(--radius-pill);background:var(--surface-2)}
.filter-btn.active{background:var(--accent-soft);border-color:var(--accent);color:var(--text-primary)}
.filter-btn.filter-allowed.active{background:rgba(63,185,80,.14);border-color:var(--sem-ok);color:#7ee787}
.filter-btn.filter-blocked.active{background:rgba(248,81,73,.14);border-color:var(--sem-blocked);color:#ffb4b4}
.filter-btn.filter-new.active{background:rgba(210,153,34,.14);border-color:var(--sem-warn);color:#f2cc60}
.filter-select{border-radius:var(--radius-sm)}
.results-summary{color:var(--text-tertiary)}
.pager{border-top-color:var(--border)}
.pager button{border-radius:var(--radius-sm)}

.client-chip,.device-chip{background:var(--surface-2);border-color:var(--border);border-radius:var(--radius-sm)}
.device-chip:hover{border-color:var(--accent);background:var(--surface-3)}
.external-tool,.inline-tool{background:var(--surface-2);border-color:var(--border);color:var(--text-tertiary);border-radius:var(--radius-sm)}
.external-tool:hover,.inline-tool:hover{border-color:var(--accent);color:var(--accent)}
.device-label-btn{border-radius:var(--radius-sm)}
.dns-ip{background:var(--surface-2);border-color:var(--border);border-radius:var(--radius-sm)}

/* ---- device/IP + inspect detail views ---- */
.signal{border-left-width:3px;background:var(--surface-2);border-radius:var(--radius-sm)}
.kv{border-bottom-color:var(--border)}
.vendor-mark,.vendor-mark-lg,.device-type-icon,.device-type-icon-lg{background:var(--surface-3);color:var(--text-secondary)}

/* ---- empty / loading state ---- */
.empty-state{display:flex;align-items:center;gap:8px;padding:14px 4px;color:var(--text-tertiary);font-size:.85rem}
.refresh-status{background:rgba(17,22,29,.96);border-color:var(--border);box-shadow:var(--shadow-md)}
.refresh-spinner{border-color:var(--border);border-top-color:var(--accent)}
.error{color:#ffb4b4;display:inline-flex;align-items:center;gap:6px}
.source{color:var(--text-tertiary)}
pre{color:var(--text-secondary);background:var(--surface-2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:12px}

/* ---- analytics: the live panel is a first-class component ---- */
.live-card{background:linear-gradient(165deg,rgba(45,212,200,.09),var(--surface-1) 55%);border-color:rgba(45,212,200,.35)}
.live-card::before{background:radial-gradient(620px 220px at 0% 0%,rgba(45,212,200,.16),transparent 62%)}
.live-title{color:var(--text-primary);font-size:.86rem;text-transform:uppercase;letter-spacing:.06em}
.live-dot{background:var(--sem-live);box-shadow:0 0 0 4px rgba(57,197,207,.18)}
.live-rate{color:var(--text-primary);text-shadow:0 0 24px rgba(45,212,200,.25)}
.stat-tile{background:var(--surface-0);border-color:var(--border);border-radius:var(--radius-md);transition:border-color var(--transition)}
.stat-tile:hover{border-color:var(--border-strong)}
.range-btn{border-radius:var(--radius-pill)}
.range-btn.active{background:var(--accent-soft);border-color:var(--accent);color:var(--text-primary)}
.status-bar{border-radius:var(--radius-pill);background:var(--surface-2);border-color:var(--border)}
.legend-item{color:var(--text-secondary)}
.activity-row{border-bottom-color:var(--border)}
.chart-card{background:var(--surface-1)}
.bar-track{background:var(--surface-2);border-color:var(--border)}
.bar-fill{background:var(--accent);background-image:linear-gradient(90deg,var(--accent-strong),var(--accent))}

@media(max-width:900px){.card{padding:16px}.tabs{overflow-x:auto}.tab-btn{flex:0 0 auto}}

/* ---- Settings ---- */
.settings-dialog{border:1px solid var(--border);border-radius:var(--radius-lg);padding:0;background:var(--surface-1);color:var(--text-primary);box-shadow:var(--shadow-lg);width:min(720px,92vw);max-height:min(640px,86vh)}
.settings-dialog::backdrop{background:rgba(4,6,10,.6)}
.settings-head{display:flex;align-items:center;justify-content:space-between;padding:16px 20px;border-bottom:1px solid var(--border)}
.settings-head h2{margin:0;border:none;padding:0}
.settings-close{padding:6px 9px;border-radius:var(--radius-sm)}
.settings-body{display:flex;gap:0;max-height:calc(min(640px,86vh) - 116px);overflow:hidden}
.settings-nav{display:flex;flex-direction:column;gap:2px;flex:0 0 160px;padding:12px;border-right:1px solid var(--border);overflow-y:auto}
.settings-nav-btn{display:flex;align-items:center;justify-content:flex-start;text-align:left;background:transparent;border-color:transparent;color:var(--text-secondary);border-radius:var(--radius-sm);padding:8px 10px;font-size:.85rem}
.settings-nav-btn:hover{background:var(--surface-2);color:var(--text-primary)}
.settings-nav-btn.active{background:var(--accent-soft);border-color:var(--accent);color:var(--text-primary)}
.settings-panels{flex:1;padding:18px 20px;overflow-y:auto}
.settings-section{display:none}
.settings-section.active{display:block}
.settings-section h3{margin-top:0}
.settings-row{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:10px 0;border-bottom:1px solid var(--border)}
.settings-row:last-child{border-bottom:0}
.settings-row-label{min-width:0}
.settings-row-label b{display:block;font-size:.86rem}
.settings-row-label small{color:var(--text-tertiary)}
.settings-control{display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end;align-items:center}
.settings-choice-group{display:inline-flex;gap:4px;background:var(--surface-2);border:1px solid var(--border);border-radius:var(--radius-pill);padding:3px}
.settings-choice{padding:6px 12px;border-radius:var(--radius-pill);border-color:transparent;background:transparent;color:var(--text-secondary);font-size:.8rem}
.settings-choice.active{background:var(--accent-soft);color:var(--text-primary);border-color:var(--accent)}
.settings-swatch{width:26px;height:26px;border-radius:50%;border:2px solid var(--border);padding:0;background:var(--swatch-color,var(--accent))}
.settings-swatch.active{border-color:var(--text-primary);box-shadow:0 0 0 2px var(--swatch-color,var(--accent))}
.settings-select{border-radius:var(--radius-sm)}
.settings-hint{font-size:.8rem;color:var(--text-secondary);line-height:1.5;margin:0 0 14px}
.settings-hint code{font-family:var(--font-mono)}
#reports-smtp-recipients-input{resize:vertical}
.settings-choice[href]{text-decoration:none;display:inline-flex;align-items:center}
.settings-kv{display:grid;grid-template-columns:auto 1fr;gap:6px 14px;font-size:.84rem}
.settings-kv b{color:var(--text-secondary);font-weight:600}
.settings-kv span{font-family:var(--font-mono)}
.settings-foot{display:flex;justify-content:flex-end;gap:8px;padding:12px 20px;border-top:1px solid var(--border)}
.settings-restart-block{margin-top:16px;padding-top:14px;border-top:1px solid var(--border);display:flex;flex-direction:column;gap:8px;align-items:flex-start}
#system-restart-btn,#system-stop-btn{border-color:var(--sem-crit);color:var(--sem-crit);background:transparent}
#system-restart-btn:hover,#system-stop-btn:hover{background:var(--sem-crit);color:#fff}
#system-restart-btn.confirming,#system-stop-btn.confirming{background:var(--sem-crit);color:#fff}
#system-restart-btn:disabled,#system-stop-btn:disabled{opacity:.6;cursor:wait;background:transparent;color:var(--sem-crit)}
.settings-restart-note{color:var(--text-tertiary);font-size:.78rem}
@media(max-width:640px){.settings-body{flex-direction:column;max-height:70vh}.settings-nav{flex-direction:row;flex-wrap:wrap;flex:0 0 auto;border-right:0;border-bottom:1px solid var(--border)}.settings-row{flex-direction:column;align-items:flex-start}.settings-control{justify-content:flex-start}}

/* ---- Analytics Visual 2.0 (0.8.5): same metric, three distinct presentations ---- */
.metric-visual{position:relative}
.metric-visual svg{width:100%;height:var(--metric-h,120px);display:block;transition:height var(--transition)}
.metric-visual .metric-marker-dot{r:3.6;stroke:var(--surface-0);stroke-width:1.4}
.metric-visual .metric-marker-dot title{pointer-events:none}
.metric-readout{display:flex;gap:16px;margin-top:8px;flex-wrap:wrap}
.metric-readout-item{font-size:.7rem;color:var(--text-tertiary);display:flex;flex-direction:column;gap:1px;text-transform:uppercase;letter-spacing:.04em}
.metric-readout-item b{font-size:.94rem;color:var(--text-primary);font-variant-numeric:tabular-nums;font-family:var(--font-mono);text-transform:none;letter-spacing:normal}

/* Digital: numeric-first hierarchy, hard-edged bars + line, radial ring readout */
.visual-digital .metric-grid line{stroke:var(--border);stroke-width:1;opacity:.6}
.visual-digital .metric-bars rect{fill:var(--accent-soft)}
.visual-digital .metric-line{stroke-linecap:butt;stroke-linejoin:miter}
.live-card.visual-digital .live-rate{font-family:var(--font-mono);letter-spacing:.02em}
.digital-ring{display:flex;justify-content:center;margin:2px 0 4px}
.digital-ring svg{width:84px;height:84px}
.digital-ring text{font-family:var(--font-mono);fill:var(--text-primary);font-weight:800}

/* Analog: restrained instrument-cluster gauge with real tick marks and a needle */
.live-card.visual-analog .live-rate{display:none}
.analog-gauge{display:flex;justify-content:center;margin:2px 0 6px}
.analog-gauge svg{width:196px;height:114px}
.analog-gauge .gauge-tick{stroke:var(--border-strong);stroke-width:1.4}
.analog-gauge .gauge-tick-major{stroke:var(--text-tertiary);stroke-width:2}
.analog-gauge .gauge-arc-bg{stroke:var(--border)}
.analog-gauge .gauge-needle{stroke:var(--text-primary);stroke-width:2.5;stroke-linecap:round}
.analog-gauge .gauge-hub{fill:var(--text-primary)}
.analog-gauge .gauge-value{font-family:var(--font-mono);fill:var(--text-primary);font-weight:800}
.analog-gauge .gauge-label{fill:var(--text-tertiary);letter-spacing:.06em}
.visual-analog .metric-line{stroke-linecap:round;stroke-linejoin:round}
.visual-analog .metric-grid line{stroke:var(--border);stroke-width:1;stroke-dasharray:2 3;opacity:.7}

/* Specter: oscilloscope / radar activity trace with glow, sweep and a live pulse */
.live-card.visual-specter .live-rate{text-shadow:0 0 16px var(--accent-soft),0 0 2px var(--accent)}
.live-card.visual-specter .live-title{color:var(--accent)}
.visual-specter .metric-line{filter:drop-shadow(0 0 5px var(--accent-soft))}
.visual-specter .metric-grid line{stroke:var(--accent-soft);stroke-width:1;opacity:.4}
.visual-specter .metric-pulse{fill:var(--accent);filter:drop-shadow(0 0 4px var(--accent))}
.visual-specter .metric-sweep{stroke:var(--accent);stroke-width:1;opacity:.55}
.specter-radar{display:flex;justify-content:center;margin:2px 0 4px}
.specter-radar svg{width:120px;height:120px}
.specter-radar .radar-ring{stroke:var(--accent-soft);fill:none}
.specter-radar .radar-sweep{stroke:var(--accent);filter:drop-shadow(0 0 4px var(--accent))}
.specter-radar .radar-value{fill:var(--text-primary);font-family:var(--font-mono);font-weight:800}
@keyframes dnsInspectorSweepX{from{transform:translateX(-4px)}to{transform:translateX(604px)}}
@keyframes dnsInspectorRadarSpin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}
html:not([data-motion="reduced"]) .visual-specter .metric-sweep{animation:dnsInspectorSweepX 3.4s linear infinite}
html:not([data-motion="reduced"]) .visual-specter .metric-pulse{animation:dnsInspectorPulse 1.6s ease-in-out infinite}
html:not([data-motion="reduced"]) .specter-radar .radar-sweep-group{animation:dnsInspectorRadarSpin 3.6s linear infinite;transform-origin:60px 60px}
html[data-motion="reduced"] .metric-sweep,html[data-motion="reduced"] .radar-sweep-group{display:none}

/* ---- Instrument gauges (0.8.5.1): bounded-ratio metrics, reusing the
   analog-gauge look. The needle is a fixed-length line rotated around the
   hub via `transform`, updated in place on re-render (see
   `updateGaugeNeedle()`) rather than replaced wholesale, so this transition
   actually has a previous value to animate from; `x1`/`y1`/`x2`/`y2` are not
   real CSS/animatable properties on an SVG `<line>`, unlike `transform`.
   Honors the reduced-motion preference. ---- */
.gauge-cluster{display:flex;flex-wrap:wrap;gap:18px;justify-content:center}
.gauge-face{display:flex;flex-direction:column;align-items:center;gap:4px;min-width:180px}
html:not([data-motion="reduced"]) .instrument-gauge .gauge-needle{transition:transform .5s ease}

/* ---- DNS Destinations map (Issue #33; Visual 2.0 in Issue #37/0.8.6;
   Issue #56 redesigned it into a traffic-intensity infographic). This
   follow-up replaces the single `mapStyle` preset with two independent
   preferences: `mapBasemap` (Satellite Heat / Satellite Density / Real Map
   + Pins / Dark NOC -- structural rendering: background treatment plus how
   observed activity is drawn) and `mapTheme` (Indigo + Gold / Cyan / BEMO
   Dark Accent -- color ramp/palette only). Satellite Heat/Density and Real
   Map + Pins now attempt to load a real photographic/cartographic tile
   image for their background (Issue #63; see MAP_TILE_PROVIDERS/
   mapEnsureTileLayer() below); the bundled offline dot-matrix world (see
   mapWorldDots() below, sampled from the bundled WORLD_LAND_D vector rings)
   remains the graceful fallback whenever that image hasn't loaded (or
   fails to), and is Dark NOC's permanent, intentionally-stylized
   background. Bubble/particle size and position are entirely data-driven
   and deterministic (seeded, never Math.random()); only markers at/above a
   high intensity ratio pulse, and only when motion isn't reduced. ---- */
/* Issue #69: Leaflet + OpenStreetMap real map viewport. static/leaflet-map.js
   turns #destination-map itself into Leaflet's own container (a real
   pan/zoom slippy map, not a fixed image) only once the library actually
   initializes; these rules only apply then (via the leaflet-map-host class
   it adds), so the legacy SVG fallback above -- which sizes itself through
   .destination-map-wrap/.destination-map-svg -- is completely unaffected
   when Leaflet can't load. */
#destination-map.leaflet-map-host{width:100%;min-height:320px;aspect-ratio:2/1;position:relative;border:1px solid var(--border);border-radius:var(--radius-md);background:var(--surface-1)}
.leaflet-status-banner{z-index:1000}
.leaflet-dns-marker{cursor:pointer}
.leaflet-dns-marker span{display:flex;width:100%;height:100%;align-items:center;justify-content:center;border-radius:50%;color:#0b0f14;font-size:.68rem;font-weight:700;border:1.5px solid rgba(255,255,255,.55);box-shadow:0 0 0 1px rgba(0,0,0,.25)}
.leaflet-dns-marker-selected span{outline:2px solid #fff;outline-offset:1px}
.destination-map-wrap{
  position:relative;
  --map-bg-a:var(--surface-2); --map-bg-b:var(--surface-1);
  --map-grid:var(--border); --map-grid-strong:var(--border-strong); --map-grid-opacity:.5;
  --map-border:var(--border); --map-point-glow:none; --map-particle-glow:none;
  --map-vignette:none; --map-banner-bg:var(--surface-1); --map-pulse-display:block;
  --map-dot:var(--accent); --map-dot-opacity:.4;
}
/* Basemap = structural rendering (background gradient, grid, vignette,
   pulse visibility and how activity particles/pins are drawn). */
.destination-map-wrap[data-map-basemap="satellite-heat"]{
  --map-bg-a:#241a0c; --map-bg-b:#0a0703;
  --map-grid:#3a2c18; --map-grid-strong:#54401f; --map-grid-opacity:.35;
  --map-vignette:inset 0 0 80px 16px rgba(0,0,0,.65); --map-banner-bg:rgba(10,7,3,.9); --map-pulse-display:block;
  --map-point-glow:drop-shadow(0 0 6px rgba(255,176,64,.85)) drop-shadow(0 0 14px rgba(255,120,40,.5));
  --map-particle-glow:blur(2.2px);
}
.destination-map-wrap[data-map-basemap="satellite-density"]{
  --map-bg-a:#152018; --map-bg-b:#050b08;
  --map-grid:#25382c; --map-grid-strong:#3a563f; --map-grid-opacity:.4;
  --map-vignette:inset 0 0 70px 12px rgba(0,0,0,.6); --map-banner-bg:rgba(5,11,8,.9); --map-pulse-display:block;
  --map-point-glow:none; --map-particle-glow:none;
}
.destination-map-wrap[data-map-basemap="real-pins"]{
  --map-bg-a:#e8edf3; --map-bg-b:#c3cfdd;
  --map-grid:#aebdd0; --map-grid-strong:#8ea0b8; --map-grid-opacity:.8;
  --map-vignette:none; --map-banner-bg:rgba(255,255,255,.94); --map-pulse-display:none;
  --map-point-glow:none; --map-particle-glow:none;
}
.destination-map-wrap[data-map-basemap="dark-noc"]{
  --map-bg-a:#050608; --map-bg-b:#000000;
  --map-grid:#1c2430; --map-grid-strong:#324256; --map-grid-opacity:.75;
  --map-vignette:inset 0 0 90px 18px rgba(0,0,0,.75); --map-banner-bg:rgba(0,0,0,.92); --map-pulse-display:block;
  --map-point-glow:drop-shadow(0 0 5px rgba(255,80,60,.9)) drop-shadow(0 0 10px rgba(255,40,20,.5));
  --map-particle-glow:none;
}
/* Theme = color ramp/palette only, independent of the basemap above -- see
   mapThemeColor()/MAP_THEME_STOPS in the script. This block only sets the
   muted (inactive) world-dot color; active/intensity colors are computed
   per-marker in JS and applied inline. */
.destination-map-wrap[data-map-theme="indigo-gold"]{ --map-dot:#4c3f8a; --map-dot-opacity:.5; }
.destination-map-wrap[data-map-theme="cyan"]{ --map-dot:#0f5a68; --map-dot-opacity:.55; }
.destination-map-wrap[data-map-theme="bemo-accent"]{ --map-dot:#2a4a70; --map-dot-opacity:.5; }
.destination-map-svg{position:relative;z-index:1;width:100%;height:auto;aspect-ratio:2/1;background:radial-gradient(ellipse at 50% 40%,var(--map-bg-a),var(--map-bg-b));box-shadow:var(--map-vignette);border:1px solid var(--map-border);border-radius:var(--radius-md);cursor:grab}
.destination-map-svg.map-dragging{cursor:grabbing}
/* Issue #63: once a real tile image is actually showing, let it show through
   instead of the synthetic background gradient above. */
.map-tiles-active .destination-map-svg{background:transparent}
html:not([data-motion="reduced"]) .destination-map-svg{transition:background .2s ease}
.map-world-dot{fill:var(--map-dot);opacity:var(--map-dot-opacity)}
.map-world-dot-active{opacity:.95}
.map-graticule .map-grid-line{stroke:var(--map-grid);stroke-width:1;opacity:var(--map-grid-opacity)}
.map-graticule .map-grid-equator{opacity:calc(var(--map-grid-opacity) * 1.6);stroke:var(--map-grid-strong)}
.map-status-banner{position:absolute;top:10px;left:10px;right:10px;margin:0 auto;padding:8px 12px;background:var(--map-banner-bg);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-secondary);font-size:.8rem;text-align:center;pointer-events:none;box-shadow:var(--shadow-sm,0 1px 4px rgba(0,0,0,.15))}
.map-status-banner .map-status-action{margin-top:6px;pointer-events:auto}
.map-entity{cursor:pointer}
/* Issue #63: an SVG <g> gets the browser's default focus-visible outline
   drawn as a rectangle around its whole bounding box (hit-area + spread-out
   particles + pulse ring), not around the visible marker -- this is exactly
   the "rectangular focus box around the circle/group" the issue reports.
   The group itself is never outlined; keyboard focus and click-selection
   both instead ring the real anchor circle (.map-bubble), same as
   .map-bubble-selected below, so the highlighted marker is always the
   marker the user actually sees. */
.map-entity:focus-visible{outline:none}
.map-entity:focus-visible .map-bubble{stroke:var(--accent);stroke-width:3;fill-opacity:1}
.map-hit-area{fill:transparent;pointer-events:all}
/* Issue #56: marker fill/stroke is set inline per-entity from
   mapThemeColor() (the same relative-to-max ratio that already sizes the
   marker) rather than a single flat accent -- traffic intensity is meant to
   be readable from color alone, independent of the chosen basemap/theme. */
.map-bubble{fill-opacity:.85;stroke-width:1;filter:var(--map-point-glow);transition:fill-opacity .3s ease,stroke-width .3s ease,r .3s ease}
.map-entity:hover .map-bubble,.map-bubble-selected{fill-opacity:1;stroke-width:2}
.map-bubble-selected{stroke:var(--accent)!important;stroke-width:3!important}
.map-bubble-pulse-ring{fill:none;stroke:var(--accent);stroke-width:1.5;opacity:.5;transform-box:fill-box;transform-origin:center;pointer-events:none;display:var(--map-pulse-display)}
html:not([data-motion="reduced"]) .map-bubble-pulse-ring{animation:dnsInspectorMapPulse 2.4s ease-out infinite}
html[data-motion="reduced"] .map-bubble-pulse-ring{display:none}
@media(prefers-reduced-motion:reduce){
  .map-bubble-pulse-ring{display:none!important;animation:none!important}
  .map-bubble{transition:none!important}
}
@keyframes dnsInspectorMapPulse{0%{transform:scale(1);opacity:.5}100%{transform:scale(2.4);opacity:0}}
/* Bounded, deterministic activity particles (Issue #56 follow-up): count and
   spread come from mapParticleCount()/mapParticleOffsets() in the script,
   seeded by each entity's own stable id -- never Math.random() -- so a
   country/cluster's cloud looks the same on every refresh instead of
   jittering, and grows denser/brighter with more observations rather than
   just growing one giant circle. */
.map-particle{pointer-events:none}
.map-particle-heat{filter:var(--map-particle-glow);opacity:.55}
.map-particle-density{opacity:.85}
.map-particle-noc{opacity:.9}
.map-pin{opacity:.95;pointer-events:none}
.map-cluster-count{font-size:7px;fill:var(--map-bg-b);pointer-events:none;text-anchor:middle;dominant-baseline:central}
.map-bubble-count{font-size:7px;fill:rgba(4,10,18,.85);font-weight:600;pointer-events:none;text-anchor:middle;dominant-baseline:central}
.map-controls{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:8px 0}
.map-controls .settings-select{padding:6px 8px;font-size:.78rem}
.map-routes-toggle-label{display:inline-flex;align-items:center;gap:5px;font-size:.78rem;color:var(--text-secondary);padding:5px 8px;border-radius:var(--radius-sm);background:var(--surface-2);border:1px solid var(--border);cursor:pointer;user-select:none}
.map-routes-toggle-label input{margin:0}
.map-zoom-group{display:inline-flex;gap:4px}
.map-zoom-btn{padding:5px 10px;font-size:.78rem;border-radius:var(--radius-sm);background:var(--surface-2);border:1px solid var(--border);color:var(--text-secondary);cursor:pointer}
.map-zoom-btn:hover{background:var(--surface-3)}
/* Issue #56: explicit size+color legend, kept in sync with mapIntensityColor()'s
   gradient stops so the swatches never drift from the actual marker colors. */
.map-legend{display:flex;flex-wrap:wrap;gap:20px;align-items:flex-end;margin:8px 0;padding:8px 12px;background:var(--surface-2);border:1px solid var(--border);border-radius:var(--radius-sm);font-size:.76rem;color:var(--text-secondary)}
.map-legend-group{display:flex;flex-direction:column;gap:5px;min-width:130px}
.map-legend-title{font-weight:600;color:var(--text-primary)}
.map-legend-size-scale{display:flex;align-items:flex-end;gap:7px;height:30px}
.map-legend-dot{border-radius:50%;flex-shrink:0;display:inline-block}
.map-legend-gradient{width:132px;height:10px;border-radius:6px;background:linear-gradient(90deg,hsl(152,68%,42%),hsl(84,72%,45%),hsl(40,92%,50%),hsl(2,82%,52%))}
.map-legend-caption{font-size:.72rem}
.map-detail{position:relative;margin-top:10px;padding:10px 34px 10px 12px;background:var(--surface-2);border:1px solid var(--border);border-radius:var(--radius-sm)}
.map-detail h3{margin:0 0 4px;font-size:.95rem}
.map-detail-row{margin-top:6px;font-size:.82rem}
.map-detail-close{position:absolute;top:6px;right:6px;width:24px;height:24px;background:transparent;border:none;border-radius:var(--radius-sm);color:var(--text-secondary);font-size:1rem;line-height:1;cursor:pointer}
.map-detail-close:hover{background:var(--surface-3);color:var(--text-primary)}
.chip-row{display:flex;flex-wrap:wrap;gap:6px;margin-top:4px}
.chip{background:var(--surface-3);border:1px solid var(--border);border-radius:var(--radius-pill);padding:2px 8px;font-size:.72rem}
/* Issue #63: country breakdown/ranking beside the map on desktop, below it
   on narrower widgets -- same payload as the map itself (data.countries),
   no second backend query. */
.destination-map-layout{display:grid;grid-template-columns:minmax(0,1fr) minmax(220px,280px);gap:12px;align-items:stretch;container-type:inline-size}
@media(max-width:900px){.destination-map-layout{grid-template-columns:minmax(0,1fr);align-items:start}}
@media(min-width:901px){.map-breakdown{height:max(320px,calc((100cqw - 292px)/2))}}
.map-breakdown{display:flex;flex-direction:column;min-width:0;height:clamp(320px,40cqw,520px);max-height:520px;background:var(--surface-2);border:1px solid var(--border);border-radius:var(--radius-sm);overflow:hidden}
.diagnostics-actions{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0}
.diagnostics-actions button{padding:7px 10px;font-size:.78rem;border-radius:var(--radius-sm)}
.map-breakdown-head{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:8px 10px;border-bottom:1px solid var(--border);flex:0 0 auto}
.map-breakdown-title{font-size:.78rem;font-weight:600;color:var(--text-primary)}
.map-breakdown-sort-btn{padding:3px 8px;font-size:.72rem;border-radius:var(--radius-sm);background:var(--surface-3);border:1px solid var(--border);color:var(--text-secondary);cursor:pointer}
.map-breakdown-sort-btn:hover{background:var(--surface-1)}
.map-breakdown-list{list-style:none;margin:0;padding:0;flex:1 1 auto;min-height:0;max-height:none;overflow-y:auto}
@media(max-width:900px){.map-breakdown{height:340px;max-height:340px}.map-breakdown-list{flex:1 1 auto;max-height:none}}
.map-breakdown-row{display:block;width:100%;text-align:left;padding:7px 10px;border:none;border-bottom:1px solid var(--border);background:transparent;color:var(--text-primary);cursor:pointer;font:inherit}
.map-breakdown-row:last-child{border-bottom:none}
.map-breakdown-row:hover{background:var(--surface-3)}
.map-breakdown-row:focus-visible{outline:2px solid var(--accent);outline-offset:-2px;background:var(--surface-3)}
.map-breakdown-row.map-breakdown-row-selected{background:var(--surface-3);box-shadow:inset 3px 0 0 var(--accent)}
.map-breakdown-row-top{display:flex;align-items:center;justify-content:space-between;gap:8px;font-size:.82rem;font-weight:600}
.map-breakdown-row-metric{font-variant-numeric:tabular-nums;color:var(--text-secondary);font-weight:500}
.map-breakdown-row-sub{margin-top:2px;font-size:.72rem;color:var(--text-secondary)}
.map-breakdown-empty{padding:14px 10px;font-size:.78rem;color:var(--text-secondary)}
/* Issue #63: real raster tile/imagery basemap layer, additive to and
   independent of the always-available offline dot-matrix world -- see
   mapEnsureTileLayer()/MAP_TILE_PROVIDERS in the script. Tiles sit behind
   the existing SVG overlay (.destination-map-wrap is already
   position:relative above; world dots stay hidden while a photographic/
   cartographic basemap is actually showing, see .map-tiles-active) so
   marker/particle placement is unchanged and traffic rendering always
   reads as a layer drawn over the geography, never mixed into it. */
.map-tile-layer{position:absolute;inset:0;z-index:0;overflow:hidden;border-radius:var(--radius-md);background:var(--map-bg-b)}
/* object-fit:fill deliberately stretches/distorts the single square-ish
   world tile to exactly match mapProjectMercator()'s independent x/y
   scaling onto the non-square MAP_W x MAP_H canvas -- cover/contain would
   preserve the image's own aspect ratio and silently break marker/tile
   coordinate alignment. */
.map-tile-layer img.map-tile{position:absolute;inset:0;width:100%;height:100%;object-fit:fill;opacity:0;transition:opacity .25s ease}
html[data-motion="reduced"] .map-tile-layer img.map-tile{transition:none}
.map-tile-layer img.map-tile.map-tile-loaded{opacity:1}
.map-tiles-active .map-world-dots{display:none}
.map-tile-attribution{position:absolute;right:4px;bottom:2px;font-size:.62rem;padding:1px 5px;background:rgba(0,0,0,.55);color:#e7ecf3;border-radius:3px;pointer-events:none;z-index:2}

/* ---- Dashboard Builder (0.8.6): GridStack.js-backed Analytics widget grid.
   GridStack (see the <script> includes near the top of <head>) owns the
   real x/y/w/h grid math, drag, resize, collision/reflow and persistence
   plumbing; this block only themes its generic DOM (.grid-stack /
   .grid-stack-item / .grid-stack-item-content) and the widget chrome
   (drag handle + hide/move buttons) layered on top of it. See the
   Dashboard Builder script further down this template. ---- */
.dash-toolbar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:14px 0}
.dash-toolbar .settings-select{padding:7px 10px;font-size:.8rem}
.dash-customize-btn{border-radius:var(--radius-pill)}
.dash-customize-btn.active{background:var(--accent-soft);border-color:var(--accent);color:var(--text-primary)}
.dash-hint{color:var(--text-tertiary);font-size:.78rem}
.dash-grid.grid-stack{background:transparent}
.dash-grid .grid-stack-item-content{overflow:visible;box-sizing:border-box;height:100%}
.dash-widget{container-type:inline-size;container-name:dashboard-widget;min-width:0}
.dash-widget .grid-stack-item-content{min-width:0}
.dash-widget .card{min-height:120px;min-width:0;overflow:visible;height:100%;box-sizing:border-box}
.dash-widget .analytics-hero{min-width:0}
.dash-widget .stat-tiles{min-width:0}
@container dashboard-widget (max-width: 900px){
  .dash-widget .analytics-hero{grid-template-columns:1fr}
  .dash-widget .stat-tiles{grid-template-columns:repeat(2,minmax(0,1fr))}
  .dash-widget .analytics-range-controls{gap:5px}
  .dash-widget .range-btn{padding-left:9px;padding-right:9px}
  .dash-widget .chart-grid{grid-template-columns:1fr}
  .dash-widget .gauge-cluster{gap:10px}
  .dash-widget .gauge-face{min-width:145px;flex:1 1 145px}
}
@container dashboard-widget (max-width: 620px){
  .dash-widget .stat-tiles{grid-template-columns:repeat(2,minmax(0,1fr))}
  .dash-widget .chart-grid{grid-template-columns:1fr}
  .dash-widget .chart-card{min-height:220px}
  .dash-widget .bar-row{grid-template-columns:minmax(0,1fr) auto;gap:7px}
  .dash-widget .bar-track{grid-column:1 / -1;order:3}
  .dash-widget .bar-value{min-width:56px}
  .dash-widget .analytics-range-controls{align-items:stretch}
  .dash-widget .range-btn{flex:1 1 auto}
  .dash-widget .range-custom-controls{align-items:stretch}
  .dash-widget .range-custom-controls label{flex:1 1 100%}
}
@container dashboard-widget (max-width: 460px){
  .dash-widget .stat-tiles{grid-template-columns:1fr}
  .dash-widget h2{font-size:.96rem}
  .dash-widget .stats-note{font-size:.74rem}
  .dash-widget .activity-row{align-items:flex-start;flex-wrap:wrap}
  .dash-widget .activity-row .sub{width:100%;white-space:normal}
  .dash-widget .report-kpi-row{grid-template-columns:repeat(2,minmax(0,1fr))}
}
.dash-grid.dash-customizing .grid-stack-item-content{outline:1px dashed var(--border-strong);outline-offset:-1px;border-radius:var(--radius-lg)}
.dash-grid .grid-stack-item.ui-draggable-dragging .grid-stack-item-content,.dash-grid .grid-stack-item.ui-resizable-resizing .grid-stack-item-content{opacity:.75}
.dash-widget-head{display:none;align-items:center;gap:6px;margin:0 0 12px;padding:6px 8px;background:var(--surface-2);border:1px solid var(--border);border-radius:var(--radius-sm)}
.dash-grid.dash-customizing .dash-widget-head{display:flex}
.dash-widget-head .dash-drag-handle{color:var(--text-tertiary);flex:0 0 auto;display:flex;cursor:grab;padding:2px 4px;touch-action:none}
.dash-widget-head .dash-widget-title{flex:1;font-size:.74rem;font-weight:700;color:var(--text-secondary);text-transform:uppercase;letter-spacing:.04em;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dash-widget-head button{padding:4px 8px;font-size:.72rem;border-radius:var(--radius-sm);line-height:1.2}
/* GridStack's own drag handles are only meaningful in customize mode; its
   resize handles (.ui-resizable-handle, its own class, not ours) are hidden
   the rest of the time so the grid reads as static content by default. */
.dash-grid:not(.dash-customizing) .ui-resizable-handle{display:none!important}
.dash-grid.dash-customizing .grid-stack-item{cursor:default}
.dash-hidden-tray{display:none;flex-wrap:wrap;align-items:center;gap:8px;margin:0 0 14px;padding:8px 10px;background:var(--surface-2);border:1px dashed var(--border-strong);border-radius:var(--radius-sm)}
.dash-hidden-tray.visible{display:flex}
.dash-hidden-tray-label{font-size:.76rem;color:var(--text-tertiary);font-weight:600}
.dash-hidden-tray-list{display:flex;flex-wrap:wrap;gap:6px}
.dash-hidden-tray-list button{padding:4px 10px;font-size:.76rem;border-radius:var(--radius-pill);background:var(--surface-3);border:1px solid var(--border);color:var(--text-primary);cursor:pointer}
@media(max-width:900px){.dash-grid.grid-stack{margin-left:0!important}}
</style></head><body>
{% if is_dev_environment %}<div class="dev-banner" role="alert"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3l10 18H2z"/><path d="M12 10v4"/><circle cx="12" cy="17.5" r=".1" fill="currentColor" stroke="currentColor" stroke-width="2"/></svg><span>DEVELOPMENT ENVIRONMENT — NOT PRODUCTION</span></div>{% endif %}
<header class="app-shell">
  <div class="shell-brand">
    <div class="brand-mark"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8.5"/><path d="M12 3.5v17M3.5 12h17"/><circle cx="12" cy="12" r="2.4" fill="currentColor" stroke="none"/></svg></div>
    <div class="brand-text">
      <span class="brand-platform">Inspector BEMO</span>
      <h1 class="brand-title">DNS Inspector <span class="muted version-chip">v{{version}}</span>{% if is_dev_environment %} <span class="dev-badge">DEV</span>{% endif %}</h1>
    </div>
  </div>
  <div class="shell-status">
    <div class="observability-strip" aria-label="Application runtime status">
      <span class="observability-pill"><span class="observability-dot"></span><span id="obs-uptime">Uptime —</span></span>
      <span class="observability-pill"><span id="obs-memory">RAM —</span></span>
      <button type="button" class="debug-button" id="debug-download-top-btn" title="Download a bounded diagnostic snapshot">Debug</button><button type="button" class="debug-button" id="settings-open-btn" aria-haspopup="dialog" aria-controls="settings-dialog"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 15.5a3.5 3.5 0 100-7 3.5 3.5 0 000 7z"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 11-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 11-4 0v-.09a1.65 1.65 0 00-1-1.51 1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 11-2.83-2.83l.06-.06a1.65 1.65 0 00.33-1.82 1.65 1.65 0 00-1.51-1H3a2 2 0 110-4h.09a1.65 1.65 0 001.51-1 1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 112.83-2.83l.06.06a1.65 1.65 0 001.82.33H9a1.65 1.65 0 001-1.51V3a2 2 0 114 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 112.83 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9a1.65 1.65 0 001.51 1H21a2 2 0 110 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg>Settings</button><button type="button" class="debug-button" id="devlog-open-btn" aria-label="Open DevLog">DevLog</button>
    </div>
    <p class="muted shell-meta">Watching AdGuard activity · <span class="live">● Live</span> · refresh every {{refresh_seconds}}s · updated <span id="last-update-time" class="updated-time"></span> · <span id="last-update-date" class="updated-date"></span></p>
  </div>
</header>
<dialog id="settings-dialog" class="settings-dialog" aria-label="Inspector BEMO settings">
  <div class="settings-head"><h2>Settings</h2><button type="button" class="settings-close" id="settings-close-btn" aria-label="Close settings">✕</button></div>
  <div class="settings-body">
    <nav class="settings-nav" role="tablist" aria-label="Settings sections">
            {% if admin_auth_enabled %}<button type="button" class="settings-nav-btn" data-settings-tab="security" role="tab">Security</button>{% endif %}
      <button type="button" class="settings-nav-btn active" data-settings-tab="appearance" role="tab">Appearance</button>
      <button type="button" class="settings-nav-btn" data-settings-tab="dashboard" role="tab">Dashboard</button>
      <button type="button" class="settings-nav-btn" data-settings-tab="monitoring" role="tab">Monitoring</button>
      <button type="button" class="settings-nav-btn" data-settings-tab="reports" role="tab">Reports</button>
      <button type="button" class="settings-nav-btn" data-settings-tab="diagnostics" role="tab">Diagnostics</button>
      <button type="button" class="settings-nav-btn" data-settings-tab="system" role="tab">System</button>
      <button type="button" class="settings-nav-btn" data-settings-tab="about" role="tab">About</button>
    </nav>
    <div class="settings-panels">
{% if admin_auth_enabled %}
      <section class="settings-section" data-settings-panel="security">
        <h3>Admin security</h3>
        <div class="settings-kv">
          <b>Session</b><span id="admin-auth-status">Checking…</span>
        </div>
        <div class="settings-row" style="margin-top:14px">
          <div class="settings-row-label"><b>Admin token</b><small>Creates a short-lived HttpOnly session cookie. The token is not stored in page source, localStorage or sessionStorage.</small></div>
          <div class="settings-control">
            <input class="settings-select" type="password" id="admin-token-input" autocomplete="off" placeholder="Admin token">
            <button type="button" id="admin-login-btn">Sign in</button>
            <button type="button" id="admin-logout-btn">Sign out</button>
          </div>
        </div>
      </section>
      {% endif %}
      <section class="settings-section active" data-settings-panel="appearance">
        <h3>Theme</h3>
        <div class="settings-row"><div class="settings-row-label"><b>Color theme</b><small>Applies across Overview, Devices, DNS views and Analytics</small></div>
          <div class="settings-control settings-choice-group" role="group" aria-label="Theme">
            <button type="button" class="settings-choice" data-theme-choice="bemo-dark">Dark</button>
            <button type="button" class="settings-choice" data-theme-choice="bemo-light">Light</button>
            <button type="button" class="settings-choice" data-theme-choice="bemo-aurora">Aurora</button>
            <button type="button" class="settings-choice" data-theme-choice="bemo-natural">Natural</button>
            <button type="button" class="settings-choice" data-theme-choice="system">System</button>
          </div>
        </div>
        <div class="settings-row"><div class="settings-row-label"><b>Accent color</b><small>Status colors (Allowed/Blocked/Warning/Critical) stay semantic and are never overridden</small></div>
          <div class="settings-control" id="accent-choice-group" role="group" aria-label="Accent color"></div>
        </div>
        <div class="settings-row"><div class="settings-row-label"><b>Density</b><small>Table and card spacing</small></div>
          <div class="settings-control settings-choice-group" role="group" aria-label="Density">
            <button type="button" class="settings-choice" data-density-choice="comfortable">Comfortable</button>
            <button type="button" class="settings-choice" data-density-choice="compact">Compact</button>
            <button type="button" class="settings-choice" data-density-choice="dense">Dense</button>
          </div>
        </div>
        <div class="settings-row"><div class="settings-row-label"><b>Reduce motion</b><small>Turns off pulse/spin/fade animations</small></div>
          <div class="settings-control"><input type="checkbox" id="reduced-motion-toggle"></div>
        </div>
      </section>
      <section class="settings-section" data-settings-panel="dashboard">
        <h3>Dashboard</h3>
        <div class="settings-row"><div class="settings-row-label"><b>Default view</b><small>Which section opens when you load DNS Inspector</small></div>
          <div class="settings-control"><select class="settings-select" id="default-view-select"><option value="last">Last viewed</option><option value="overview">Overview</option><option value="devices">Devices</option><option value="analytics">Analytics</option></select></div>
        </div>
        <div class="settings-row"><div class="settings-row-label"><b>Analytics visual style</b><small>Same live metrics, different presentation</small></div>
          <div class="settings-control settings-choice-group" role="group" aria-label="Analytics visual style">
            <button type="button" class="settings-choice" data-style-choice="digital">Digital</button>
            <button type="button" class="settings-choice" data-style-choice="analog">Analog</button>
            <button type="button" class="settings-choice" data-style-choice="specter">Specter</button>
          </div>
        </div>
        <div class="settings-row"><div class="settings-row-label"><b>Dashboard layout</b><small>Reorder, resize, show/hide and choose presets for the Analytics widgets, in the Analytics tab</small></div>
          <div class="settings-control"><button type="button" onclick="document.getElementById('settings-close-btn')?.click();document.querySelector('.tab-btn[data-tab=analytics]')?.click();document.getElementById('dash-customize-btn')?.click();">Customize dashboard</button></div>
        </div>
      </section>
      <section class="settings-section" data-settings-panel="monitoring">
        <h3>Monitoring</h3>
        <div class="settings-row"><div class="settings-row-label"><b>Refresh interval</b><small>How often the dashboard polls for new activity (server default: {{refresh_seconds}}s)</small></div>
          <div class="settings-control"><select class="settings-select" id="refresh-interval-select"><option value="0">Server default ({{refresh_seconds}}s)</option></select></div>
        </div>
      </section>
      <section class="settings-section" data-settings-panel="reports">
        <h3>Reports</h3>
        <p class="settings-hint">Scheduled Visibility reports reuse the exact same generator as "Export report now" &mdash; no separate code path, no fabricated data. Files are written only under a fixed base directory (<code id="reports-base-dir">/data/reports</code>) using a validated relative filename; path traversal is rejected.</p>
        <div class="settings-row"><div class="settings-row-label"><b>Export &amp; save</b><small>Reuses the live report generator, right now</small></div>
          <div class="settings-control settings-choice-group">
            <a class="settings-choice" id="reports-export-now-btn" href="/api/analytics/report.pdf">Export report now</a>
            <button type="button" class="settings-choice" id="reports-save-now-btn">Save report now</button>
            <button type="button" class="settings-choice" id="reports-test-email-btn">Send test email</button>
          </div>
        </div>
        <div class="settings-kv" id="reports-status-kv"><b>Loading…</b><span></span></div>
        <div class="settings-row"><div class="settings-row-label"><b>Scheduled reports</b><small>One bounded background worker &mdash; never overlaps, never duplicates after a restart</small></div>
          <div class="settings-control"><input type="checkbox" id="reports-enabled-toggle"> <label for="reports-enabled-toggle">Enabled</label></div>
        </div>
        <div class="settings-row"><div class="settings-row-label"><b>Interval</b><small>How often a new report is generated</small></div>
          <div class="settings-control"><select class="settings-select" id="reports-interval-select"><option value="hourly">Hourly</option><option value="daily">Daily</option><option value="weekly">Weekly</option><option value="custom">Custom</option></select>
          <input type="number" class="settings-select" id="reports-custom-interval-input" min="900" step="60" placeholder="seconds" style="width:110px;display:none"></div>
        </div>
        <div class="settings-row"><div class="settings-row-label"><b>Report window</b><small>The analysis period each scheduled report covers</small></div>
          <div class="settings-control"><select class="settings-select" id="reports-window-select"><option value="1h">Last hour</option><option value="6h">Last 6 hours</option><option value="24h">Last 24 hours</option><option value="7d">Last 7 days</option></select></div>
        </div>
        <div class="settings-row"><div class="settings-row-label"><b>Save location</b><small>Relative subfolder under the base directory above (optional)</small></div>
          <div class="settings-control"><input type="text" class="settings-select" id="reports-save-dir-input" placeholder="(base directory)"></div>
        </div>
        <div class="settings-row"><div class="settings-row-label"><b>Filename template</b><small>Placeholders: {range} {date} {time} {timestamp}</small></div>
          <div class="settings-control"><input type="text" class="settings-select" id="reports-filename-input" placeholder="dns-inspector-{range}-{timestamp}.pdf"></div>
        </div>
        <div class="settings-row"><div class="settings-row-label"><b>Retention</b><small>Oldest saved reports are deleted beyond this count</small></div>
          <div class="settings-control"><input type="number" class="settings-select" id="reports-retention-input" min="1" max="200" style="width:90px"></div>
        </div>
        <div class="settings-row"><div class="settings-row-label"><b>Email delivery</b><small>Optional SMTP delivery of each saved report</small></div>
          <div class="settings-control"><input type="checkbox" id="reports-smtp-enabled-toggle"> <label for="reports-smtp-enabled-toggle">Enabled</label></div>
        </div>
        <div class="settings-row"><div class="settings-row-label"><b>SMTP server</b><small>Host / port / security</small></div>
          <div class="settings-control">
            <input type="text" class="settings-select" id="reports-smtp-host-input" placeholder="smtp.example.com" style="width:160px">
            <input type="number" class="settings-select" id="reports-smtp-port-input" placeholder="587" style="width:80px">
            <select class="settings-select" id="reports-smtp-security-select"><option value="starttls">STARTTLS</option><option value="tls">TLS</option><option value="none">None</option></select>
          </div>
        </div>
        <div class="settings-row"><div class="settings-row-label"><b>SMTP credentials</b><small>Username here; password is read only from the <code>SMTP_PASSWORD</code> environment variable / Docker secret and is never stored in the app database or returned by the API</small></div>
          <div class="settings-control"><input type="text" class="settings-select" id="reports-smtp-username-input" placeholder="username (optional)"> <span id="reports-smtp-password-state" class="settings-restart-note"></span></div>
        </div>
        <div class="settings-row"><div class="settings-row-label"><b>Sender &amp; recipients</b><small>One recipient per line</small></div>
          <div class="settings-control">
            <input type="text" class="settings-select" id="reports-smtp-sender-input" placeholder="dns-inspector@example.com" style="width:220px">
            <textarea class="settings-select" id="reports-smtp-recipients-input" rows="2" placeholder="alerts@example.com" style="width:220px"></textarea>
          </div>
        </div>
        <div class="settings-row"><div class="settings-row-label"><b>Subject template</b><small>Placeholder: {range}</small></div>
          <div class="settings-control"><input type="text" class="settings-select" id="reports-smtp-subject-input" placeholder="DNS Inspector report - {range}"></div>
        </div>
        <div class="settings-row"><div class="settings-row-label"></div><div class="settings-control"><button type="button" id="reports-save-schedule-btn">Save schedule</button> <span id="reports-save-schedule-result" class="settings-restart-note"></span></div></div>
      </section>
      <section class="settings-section" data-settings-panel="diagnostics">
        <h3>Diagnostics</h3>
        <div class="settings-kv" id="diagnostics-kv"><b>Loading…</b><span></span></div>
        <div class="settings-row-label" style="padding-top:14px"><b>Analytics render performance</b><small>Last fetch/render timing for the Analytics poll and the destination map, split by network vs. on-page render time</small></div>
        <div class="settings-kv" id="diagnostics-perf-kv"><b>No samples yet</b><span>Open the Analytics tab first</span></div>
        <div class="settings-row-label" style="padding-top:14px"><b>DevLog</b><small>Recent bounded operational events from this process</small></div>
        <div class="diagnostics-actions"><button type="button" id="devlog-download-btn">Download DevLog</button><button type="button" id="debug-download-btn">Download Debug Snapshot</button></div>
        <div class="devlog-scroll" id="devlog-list"><div class="settings-kv"><b>Loading…</b><span></span></div></div>
        
      </section>
      <section class="settings-section" data-settings-panel="system">
        <h3>System</h3>
        <div class="settings-kv" id="system-kv"><b>Loading…</b><span></span></div>
        <div class="settings-restart-block">
          <button type="button" id="system-restart-btn">Restart DNS Inspector</button>
          <span class="settings-restart-note" id="system-restart-note">Restarts the running application/container. In-progress requests are dropped; persisted data in <code>/data</code> is unaffected.</span>
        </div>
        <div class="settings-restart-block">
          <button type="button" id="system-stop-btn">Stop Application</button>
          <span class="settings-restart-note" id="system-stop-note">Gracefully shuts down the running application/container. The web UI will be unavailable until it is started again manually; persisted data in <code>/data</code> is unaffected.</span>
        </div>
      </section>
      <section class="settings-section" data-settings-panel="about">
        <h3>About</h3>
        <div class="settings-kv">
          <b>Platform</b><span>Inspector BEMO</span>
          <b>Module</b><span>DNS Inspector</span>
          <b>Version</b><span>v{{version}}</span>
          <b>Environment</b><span>{% if is_dev_environment %}Development{% else %}Production{% endif %}</span>
          <b>Uptime</b><span id="about-uptime">—</span>
          <b>GeoIP data</b><span>IP Geolocation by <a href="https://db-ip.com" target="_blank" rel="noopener noreferrer">DB-IP</a> (DB-IP Lite, CC BY 4.0)</span>
          <b>Known datacenter data</b><span>Optional, operator-supplied curated provider/region ranges &mdash; see docs/GEOIP.md for sourcing and licensing</span>
        </div>
      </section>
    </div>
  </div>
  <div class="settings-foot"><button type="button" id="settings-reset-btn">Reset to defaults</button><button type="button" id="settings-done-btn">Done</button></div>
</dialog>
<form class="toolbar" action="/search"><input name="q" placeholder="hostname..." value="{{q}}"><button type="submit">Inspect</button><button type="button" onclick="window.location='/'">Reset</button></form>
<nav class="tabs" role="tablist" aria-label="DNS Inspector sections">
  <button class="tab-btn" data-tab="overview" role="tab"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/></svg>Overview</button>
  <button class="tab-btn" data-tab="devices" role="tab"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M9 20h6M12 16v4"/></svg>Devices</button>
  <button class="tab-btn active" data-tab="analytics" role="tab"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 19V9M11 19V5M18 19v-7"/></svg>Analytics</button>
</nav>
<script>
/* ---- Inspector BEMO preferences (0.8.4) ----
   Theme, accent, density, motion, monitoring cadence and the Analytics
   visual-style abstraction. Stored as one localStorage preference object --
   no new backend route, no change to the existing DNS data model. Declared
   in its own script block, first, so every later block (recent table,
   analytics, settings dialog) can read/call into it immediately; a function
   body is only evaluated when it *runs*, so it is safe for these functions
   to reference names (like `refreshMs`, `renderLiveHero`) that later
   blocks define, as long as nothing here calls them before those blocks
   have executed. */
const ADMIN_AUTH_ENABLED = {{ 'true' if admin_auth_enabled else 'false' }};
let adminSessionActive = false;
let adminLoginPromise = null;

function setAdminAuthStatus(text, ok){
  const el = document.getElementById('admin-auth-status');
  if (!el) return;
  el.textContent = text;
  el.dataset.state = ok ? 'ok' : 'error';
}

async function refreshAdminAuthStatus(){
  if (!ADMIN_AUTH_ENABLED) return false;
  try{
    const r = await fetch('/api/admin/status', {cache:'no-store', credentials:'same-origin'});
    const d = await r.json();
    adminSessionActive = d.authenticated === true;
    setAdminAuthStatus(adminSessionActive ? 'Authenticated' : 'Not authenticated', adminSessionActive);
    return adminSessionActive;
  }catch(e){
    adminSessionActive = false;
    setAdminAuthStatus('Status unavailable', false);
    return false;
  }
}

async function loginAdminToken(token){
  const value = String(token || '');
  if (!value) return false;
  try{
    const r = await fetch('/api/admin/login', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      credentials:'same-origin',
      cache:'no-store',
      body:JSON.stringify({token:value}),
    });
    const d = await r.json().catch(()=>({}));
    if (!r.ok || !d.ok){
      setAdminAuthStatus(r.status === 429 ? 'Too many attempts — try again later' : 'Authentication failed', false);
      return false;
    }
    adminSessionActive = true;
    setAdminAuthStatus('Authenticated', true);
    return true;
  }catch(e){
    setAdminAuthStatus('Authentication request failed', false);
    return false;
  }
}

async function ensureAdminAuth(){
  if (!ADMIN_AUTH_ENABLED || adminSessionActive) return true;
  if (adminLoginPromise) return adminLoginPromise;
  adminLoginPromise = (async()=>{
    const statusOk = await refreshAdminAuthStatus();
    if (statusOk) return true;
    const token = window.prompt('DNS Inspector admin token:');
    if (token === null || token === '') return false;
    return loginAdminToken(token);
  })().finally(()=>{ adminLoginPromise = null; });
  return adminLoginPromise;
}

async function adminFetch(url, options = {}){
  if (!ADMIN_AUTH_ENABLED) return fetch(url, options);
  const method = String(options.method || 'GET').toUpperCase();
  const headers = new Headers(options.headers || {});
  if (!['GET','HEAD','OPTIONS'].includes(method)) headers.set('X-DNS-Inspector-Requested-With', 'fetch');
  const requestOptions = Object.assign({}, options, {credentials:'same-origin', headers});
  let r = await fetch(url, requestOptions);
  if (r.status === 401){
    adminSessionActive = false;
    const authenticated = await ensureAdminAuth();
    if (!authenticated) return r;
    r = await fetch(url, requestOptions);
  }
  return r;
}

document.getElementById('admin-login-btn')?.addEventListener('click', async()=>{
  const input = document.getElementById('admin-token-input');
  const token = input?.value || '';
  if (input) input.value = '';
  const ok = await loginAdminToken(token);
  if (ok) input?.blur();
});

document.getElementById('admin-logout-btn')?.addEventListener('click', async()=>{
  try{
    const r = await fetch('/api/admin/logout', {
      method:'POST',
      headers:{'X-DNS-Inspector-Requested-With':'fetch'},
      credentials:'same-origin',
      cache:'no-store',
    });
    adminSessionActive = false;
    setAdminAuthStatus(r.ok ? 'Signed out' : 'Sign-out failed', false);
  }catch(e){
    setAdminAuthStatus('Sign-out failed', false);
  }
});

if (ADMIN_AUTH_ENABLED) refreshAdminAuthStatus();

const PREF_KEY = 'dnsInspectorPrefs';
const ACCENT_PRESETS = {teal:'#2dd4c8', blue:'#58a6ff', violet:'#a371f7', amber:'#e3b341', pink:'#ec4899', slate:'#94a3b8'};
const REFRESH_OPTIONS = [5, 10, 15, 30, 60];
const DEFAULT_PREFS = {theme:'bemo-dark', accent:'', density:'comfortable', reducedMotion:false, defaultView:'analytics', refreshSeconds:0, analyticsStyle:'digital', mapMode:'countries', mapMetric:'observations', mapBasemap:'satellite-heat', mapTheme:'bemo-accent', mapRoutes:false};
function loadPrefs(){ try{ return Object.assign({}, DEFAULT_PREFS, JSON.parse(localStorage.getItem(PREF_KEY)||'{}')); }catch(e){ return Object.assign({}, DEFAULT_PREFS); } }
function savePrefs(){ try{ localStorage.setItem(PREF_KEY, JSON.stringify(prefs)); }catch(e){} }
let prefs = loadPrefs();
function resolvedTheme(theme){ if(theme !== 'system') return theme; return (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) ? 'bemo-light' : 'bemo-dark'; }
function applyAppearance(){
  const root = document.documentElement;
  root.setAttribute('data-theme', resolvedTheme(prefs.theme));
  root.setAttribute('data-density', prefs.density || 'comfortable');
  root.setAttribute('data-motion', prefs.reducedMotion ? 'reduced' : '');
  if (prefs.accent && ACCENT_PRESETS[prefs.accent]) root.style.setProperty('--accent', ACCENT_PRESETS[prefs.accent]);
  else root.style.removeProperty('--accent');
}
applyAppearance();
function effectiveRefreshMs(){ return Math.max(5000, (Number(prefs.refreshSeconds)||{{refresh_seconds}}) * 1000); }
function applyMonitoring(){
  refreshMs = effectiveRefreshMs();
  if (document.querySelector('.tab-btn.active')?.dataset.tab === 'analytics' && typeof startAnalyticsPolling === 'function'){ stopAnalyticsPolling(); startAnalyticsPolling(); }
}
function applyAnalyticsStyle(){
  if (typeof renderLiveHero === 'function') renderLiveHero();
  if (document.getElementById('tab-analytics')?.classList.contains('active') && typeof fetchAnalyticsFull === 'function') fetchAnalyticsFull();
}

/* Reusable metric-visual abstraction: one metric, three presentation
   styles (Analog / Digital / Specter). Every caller passes the same shape
   of points ({count}) the historical/live analytics data already has --
   the underlying data semantics never change, only the rendering. */
function metricSplitRuns(xy){
  const runs = []; let cur = [];
  xy.forEach(pt => { if (pt){ cur.push(pt); } else if (cur.length){ runs.push(cur); cur = []; } });
  if (cur.length) runs.push(cur);
  return runs;
}
function metricXY(points, w, h, pad){
  const vals = points.map(p=>p.count).filter(v=>v!=null && Number.isFinite(v));
  const max = Math.max(1, ...vals);
  const n = points.length;
  const stepX = n > 1 ? (w - 2*pad) / (n - 1) : 0;
  return points.map((p, i) => (p.count == null || !Number.isFinite(p.count)) ? null : {x: pad + i*stepX, y: h - pad - (p.count/max)*(h-2*pad)});
}
function metricStraightPath(xy){ return metricSplitRuns(xy).map(run => 'M' + run.map(p => p.x.toFixed(1)+' '+p.y.toFixed(1)).join(' L')).join(' '); }
function metricSmoothRun(pts){
  if (pts.length < 3) return 'M' + pts.map(p => p.x.toFixed(1)+' '+p.y.toFixed(1)).join(' L');
  let d = `M${pts[0].x.toFixed(1)} ${pts[0].y.toFixed(1)} `;
  for (let i=1;i<pts.length-1;i++){
    const mx=(pts[i].x+pts[i+1].x)/2, my=(pts[i].y+pts[i+1].y)/2;
    d += `Q${pts[i].x.toFixed(1)} ${pts[i].y.toFixed(1)} ${mx.toFixed(1)} ${my.toFixed(1)} `;
  }
  const last = pts[pts.length-1];
  return d + `L${last.x.toFixed(1)} ${last.y.toFixed(1)}`;
}
function metricSmoothPath(xy){ return metricSplitRuns(xy).map(metricSmoothRun).join(' '); }
/* A "spike" is a bucket whose count is a real statistical outlier against the
   other buckets in the same series (mean + 2 standard deviations, with a
   floor so a handful of near-identical low counts don't all qualify). No
   severity or cause is inferred -- only that the observed count stands out. */
function metricSpikeIndices(pts){
  const vals = pts.map(p=>p.count).filter(v=>v!=null && Number.isFinite(v));
  const idx = new Set();
  if (vals.length < 6) return idx;
  const mean = vals.reduce((a,b)=>a+b,0)/vals.length;
  const variance = vals.reduce((a,b)=>a+(b-mean)*(b-mean),0)/vals.length;
  const threshold = mean + Math.max(2*Math.sqrt(variance), mean*0.75, 1);
  pts.forEach((p,i) => { if (p.count!=null && p.count > threshold) idx.add(i); });
  return idx;
}
function metricPointLabel(p){
  let when = '';
  try{ if (p.t) when = ' at ' + new Date(p.t).toLocaleString([], {month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'}); }catch(e){}
  return `Spike: ${p.count}${when}`;
}
function renderMetricVisual(elId, points, colorVar, unitLabel, opts){
  opts = opts || {};
  const el = document.getElementById(elId); if (!el) return;
  const style = prefs.analyticsStyle || 'digital';
  el.classList.add('metric-visual');
  el.classList.remove('visual-analog','visual-digital','visual-specter');
  el.classList.add('visual-'+style);
  const pts = points || [];
  if (!pts.some(p => p.count != null)){ el.innerHTML = '<div class="empty-state">No data yet.</div>'; return; }
  const w=Math.max(280, Math.round(el.clientWidth || 600)), h=120, pad=4;
  const xy = metricXY(pts, w, h, pad);
  const vals = pts.map(p=>p.count).filter(v=>v!=null);
  const peak = vals.length ? Math.max(...vals) : 0;
  const avg = vals.length ? Math.round((vals.reduce((a,b)=>a+b,0)/vals.length)*10)/10 : 0;
  let current = 0;
  for (let i=pts.length-1;i>=0;i--){ if (pts[i].count!=null){ current = pts[i].count; break; } }
  const spikes = metricSpikeIndices(pts);
  const grid = `<g class="metric-grid">${[0.25,0.5,0.75].map(f => { const y=(pad+(h-2*pad)*f).toFixed(1); return `<line x1="${pad}" x2="${w-pad}" y1="${y}" y2="${y}"/>`; }).join('')}</g>`;
  let defs='', fill='', bars='';
  const linePath = style === 'digital' ? metricStraightPath(xy) : metricSmoothPath(xy);
  if (style === 'digital'){
    const stepX = xy.length > 1 ? (w-2*pad)/(xy.length-1) : (w-2*pad);
    const barW = Math.max(1.5, stepX*0.45);
    bars = `<g class="metric-bars">${xy.map(p => p ? `<rect x="${(p.x-barW/2).toFixed(1)}" y="${p.y.toFixed(1)}" width="${barW.toFixed(1)}" height="${Math.max(0,h-pad-p.y).toFixed(1)}"/>` : '').join('')}</g>`;
  }
  if (style === 'specter'){
    const gradId = 'grad-'+elId;
    const areaPath = metricSplitRuns(xy).map(run => `${metricSmoothRun(run)} L${run[run.length-1].x.toFixed(1)} ${h-pad} L${run[0].x.toFixed(1)} ${h-pad} Z`).join(' ');
    defs = `<defs><linearGradient id="${gradId}" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="var(${colorVar})" stop-opacity=".35"/><stop offset="100%" stop-color="var(${colorVar})" stop-opacity="0"/></linearGradient></defs>`;
    fill = `<path d="${esc(areaPath)}" fill="url(#${gradId})" stroke="none"/>`;
  }
  const strokeWidth = style === 'digital' ? 2 : 2.6;
  const lastPt = [...xy].reverse().find(p => p);
  const pulse = (style === 'specter' && lastPt) ? `<circle class="metric-pulse" cx="${lastPt.x.toFixed(1)}" cy="${lastPt.y.toFixed(1)}" r="3.6"/>` : '';
  const sweep = style === 'specter' ? `<line class="metric-sweep" x1="0" x2="0" y1="${pad}" y2="${h-pad}"/>` : '';
  const markers = [...spikes].map(i => xy[i] ? `<circle class="metric-marker-dot" cx="${xy[i].x.toFixed(1)}" cy="${xy[i].y.toFixed(1)}" fill="var(${colorVar})"><title>${esc(metricPointLabel(pts[i]))}</title></circle>` : '').join('');
  const selIdx = opts.selectedIndex;
  const selection = (selIdx != null && xy[selIdx]) ? `<line class="metric-crosshair" x1="${xy[selIdx].x.toFixed(1)}" x2="${xy[selIdx].x.toFixed(1)}" y1="${pad}" y2="${h-pad}"/><circle class="metric-selected-dot" cx="${xy[selIdx].x.toFixed(1)}" cy="${xy[selIdx].y.toFixed(1)}" r="5"/>` : '';
  const readout = `<div class="metric-readout"><div class="metric-readout-item">Current<b>${esc(current)}</b></div><div class="metric-readout-item">Average<b>${esc(avg)}</b></div><div class="metric-readout-item">Peak<b>${esc(peak)}</b></div>${spikes.size ? `<div class="metric-readout-item">Spikes<b>${spikes.size}</b></div>` : ''}</div>`;
  const clickable = typeof opts.onPointClick === 'function';
  el.innerHTML = `<svg viewBox="0 0 ${w} ${h}" class="history-svg${clickable ? ' history-svg-clickable' : ''}" preserveAspectRatio="none" role="img" aria-label="${esc(unitLabel||'activity over time')}" ${clickable ? 'tabindex="0"' : ''}>${grid}${defs}${fill}${bars}<path class="metric-line" d="${esc(linePath)}" fill="none" stroke="var(${colorVar})" stroke-width="${strokeWidth}" stroke-linecap="round" stroke-linejoin="round"/>${sweep}${pulse}${markers}${selection}</svg>${readout}<div class="stats-note">${esc(unitLabel||'')}</div>`;
  if (clickable){
    const svgEl = el.querySelector('svg');
    const pickIndex = (clientX) => {
      const rect = svgEl.getBoundingClientRect();
      if (!rect.width) return null;
      const frac = Math.max(0, Math.min(1, (clientX - rect.left) / rect.width));
      return Math.max(0, Math.min(pts.length - 1, Math.round(frac * (pts.length - 1))));
    };
    svgEl.addEventListener('click', (evt) => {
      const idx = pickIndex(evt.clientX);
      if (idx != null && pts[idx] && pts[idx].count != null) opts.onPointClick(pts[idx], idx);
    });
    svgEl.addEventListener('keydown', (evt) => {
      if (evt.key !== 'Enter' && evt.key !== ' ') return;
      evt.preventDefault();
      const idx = selIdx != null ? selIdx : pts.length - 1;
      if (pts[idx] && pts[idx].count != null) opts.onPointClick(pts[idx], idx);
    });
  }
}
/* Digital: a radial "capacity" ring -- current sample against the peak
   observed in the current rolling window -- plus the numeric value at its
   center, echoing the donut/numeric-hierarchy language of the reference. */
function digitalRingSvg(pct, current){
  const r=32, c=2*Math.PI*r, p=Math.max(0,Math.min(1,pct));
  return `<div class="digital-ring"><svg viewBox="0 0 84 84" aria-hidden="true"><circle cx="42" cy="42" r="${r}" fill="none" stroke="var(--border)" stroke-width="7"/><circle cx="42" cy="42" r="${r}" fill="none" stroke="var(--sem-live)" stroke-width="7" stroke-linecap="round" stroke-dasharray="${c.toFixed(1)}" stroke-dashoffset="${(c*(1-p)).toFixed(1)}" transform="rotate(-90 42 42)"/><text x="42" y="47" text-anchor="middle" font-size="17">${esc(current)}</text></svg></div>`;
}
/* Analog: a restrained instrument-cluster gauge -- tick marks, a needle and a
   numeric center readout -- rather than a bare semicircle. */
function analogGaugeSvg(pct, current, peak){
  const cx=98, cy=98, r=78, p=Math.max(0,Math.min(1,pct));
  const angleDeg = 180 - p*180, rad = angleDeg*Math.PI/180;
  const nx=(cx+(r-16)*Math.cos(rad)).toFixed(1), ny=(cy-(r-16)*Math.sin(rad)).toFixed(1);
  let ticks = '';
  for (let i=0;i<=10;i++){
    const a = 180 - (i/10)*180, ar = a*Math.PI/180, major = i%5===0;
    const rOuter=r+2, rInner=major?r-11:r-5;
    ticks += `<line class="gauge-tick${major?' gauge-tick-major':''}" x1="${(cx+rOuter*Math.cos(ar)).toFixed(1)}" y1="${(cy-rOuter*Math.sin(ar)).toFixed(1)}" x2="${(cx+rInner*Math.cos(ar)).toFixed(1)}" y2="${(cy-rInner*Math.sin(ar)).toFixed(1)}"/>`;
  }
  return `<div class="analog-gauge"><svg viewBox="0 0 196 114" aria-hidden="true"><path class="gauge-arc-bg" d="M${cx-r} ${cy} A${r} ${r} 0 0 1 ${cx+r} ${cy}" fill="none" stroke-width="3"/>${ticks}<line class="gauge-needle" x1="${cx}" y1="${cy}" x2="${nx}" y2="${ny}"/><circle class="gauge-hub" cx="${cx}" cy="${cy}" r="5"/><text class="gauge-value" x="${cx}" y="${cy-22}" text-anchor="middle" font-size="20">${esc(current)}</text><text class="gauge-label" x="${cx}" y="${cy-6}" text-anchor="middle" font-size="9">of ${esc(peak)} peak/60s</text></svg></div>`;
}
/* Specter: a radar-style sweep -- same live count, a distinctly different,
   experimental presentation. */
function specterRadarSvg(pct, current){
  const p=Math.max(0,Math.min(1,pct));
  return `<div class="specter-radar"><svg viewBox="0 0 120 120" aria-hidden="true">${[18,34,50].map(r=>`<circle class="radar-ring" cx="60" cy="60" r="${r}"/>`).join('')}<line class="radar-ring" x1="60" y1="10" x2="60" y2="110"/><line class="radar-ring" x1="10" y1="60" x2="110" y2="60"/><g class="radar-sweep-group"><line class="radar-sweep" x1="60" y1="60" x2="60" y2="10"/></g><circle cx="60" cy="60" r="${(4+p*10).toFixed(1)}" fill="var(--accent)" opacity=".85"/><text class="radar-value" x="60" y="65" text-anchor="middle" font-size="16">${esc(current)}</text></svg></div>`;
}
/* Bounded-ratio instrument gauge (0.8.5.1): the same instrument-cluster look
   as analogGaugeSvg (ticks/needle/hub/readout), generalized to any metric
   with a real 0-100% range/scale rather than a live-count peak. Used only
   for metrics that genuinely have a meaningful bounded range -- not every
   KPI becomes a gauge. Unlike analogGaugeSvg, the needle is a fixed-length
   line rotated around the hub (`transform:rotate(...)`, a real animatable
   CSS property -- `x1`/`y1`/`x2`/`y2` are not) and `renderInstrumentGauges`
   updates that rotation on the existing element on re-render instead of
   replacing the SVG outright, so the CSS transition (see `.gauge-needle`
   transition rule) has a previous value to animate from rather than jumping;
   that transition is suppressed under `prefers-reduced-motion` / the in-app
   reduced-motion preference. */
function gaugeNeedleRotationDeg(pct){
  return (Math.max(0,Math.min(1,pct))*180-90).toFixed(2);
}
function instrumentPercentGaugeSvg(pct, valueText, rangeLabel){
  const cx=98, cy=98, r=78, p=Math.max(0,Math.min(1,pct));
  let ticks = '';
  for (let i=0;i<=10;i++){
    const a = 180 - (i/10)*180, ar = a*Math.PI/180, major = i%5===0;
    const rOuter=r+2, rInner=major?r-11:r-5;
    ticks += `<line class="gauge-tick${major?' gauge-tick-major':''}" x1="${(cx+rOuter*Math.cos(ar)).toFixed(1)}" y1="${(cy-rOuter*Math.sin(ar)).toFixed(1)}" x2="${(cx+rInner*Math.cos(ar)).toFixed(1)}" y2="${(cy-rInner*Math.sin(ar)).toFixed(1)}"/>`;
  }
  return `<div class="analog-gauge instrument-gauge"><svg viewBox="0 0 196 114" aria-hidden="true"><path class="gauge-arc-bg" d="M${cx-r} ${cy} A${r} ${r} 0 0 1 ${cx+r} ${cy}" fill="none" stroke-width="3"/>${ticks}<line class="gauge-needle" x1="${cx}" y1="${cy}" x2="${cx}" y2="${cy-(r-16)}" style="transform-origin:${cx}px ${cy}px;transform:rotate(${gaugeNeedleRotationDeg(p)}deg)"/><circle class="gauge-hub" cx="${cx}" cy="${cy}" r="5"/><text class="gauge-value" x="${cx}" y="${cy-22}" text-anchor="middle" font-size="20">${esc(valueText)}</text><text class="gauge-label" x="${cx}" y="${cy-6}" text-anchor="middle" font-size="9">${esc(rangeLabel)}</text></svg></div>`;
}
function updateGaugeNeedle(slot, pct, valueText, rangeLabel){
  const needle = slot.querySelector('.gauge-needle');
  const valueEl = slot.querySelector('.gauge-value');
  const labelEl = slot.querySelector('.gauge-label');
  if (!needle || !valueEl || !labelEl) return false;
  needle.style.transform = `rotate(${gaugeNeedleRotationDeg(pct)}deg)`;
  valueEl.textContent = valueText;
  labelEl.textContent = rangeLabel;
  return true;
}
function renderInstrumentGauges(data){
  const wrap = document.getElementById('instrument-gauges'); if (!wrap) return;
  const b = data?.status_breakdown || {};
  const blocked = Number(b.Blocked)||0, allowed = Number(b.Allowed)||0;
  const knownTotal = blocked + allowed;
  const blockedPct = knownTotal ? blocked/knownTotal : 0;
  const activeDevices = Number(data?.active_devices)||0;
  const totalDevices = Number(data?.total_devices)||0;
  const activePct = totalDevices ? Math.min(1, activeDevices/totalDevices) : 0;
  const blockedSlot = document.getElementById('gauge-blocked-ratio');
  if (blockedSlot){
    const valueText = Math.round(blockedPct*100)+'%', rangeLabel = `${blocked} of ${knownTotal} classified domains`;
    if (!knownTotal) blockedSlot.innerHTML = '<div class="empty-state">No classified domains yet.</div>';
    else if (!updateGaugeNeedle(blockedSlot, blockedPct, valueText, rangeLabel)) blockedSlot.innerHTML = instrumentPercentGaugeSvg(blockedPct, valueText, rangeLabel);
  }
  const devicesSlot = document.getElementById('gauge-active-devices');
  if (devicesSlot){
    const valueText = String(activeDevices), rangeLabel = `of ${totalDevices} known devices, last 5m`;
    if (!totalDevices) devicesSlot.innerHTML = '<div class="empty-state">No known devices yet.</div>';
    else if (!updateGaugeNeedle(devicesSlot, activePct, valueText, rangeLabel)) devicesSlot.innerHTML = instrumentPercentGaugeSvg(activePct, valueText, rangeLabel);
  }
}
</script>
<section id="tab-overview" class="tab-panel" data-panel="overview">
  <div id="inspect-root">
  {% if inspect_html %}{{ inspect_html|safe }}{% endif %}
  </div>
  <div class="card"><h2>At a glance</h2>
  <div id="new-banner" class="new-banner"><span id="new-banner-text"></span><button type="button" onclick="clearNewBanner()">Dismiss</button></div>
  <div class="recent-controls">
    <div class="filter-group"><span class="filter-label">Status</span><button class="filter-btn active" data-status-filter="">All <span id="count-all"></span></button><button class="filter-btn filter-allowed" data-status-filter="Allowed">Allowed <span id="count-allowed"></span></button><button class="filter-btn filter-blocked" data-status-filter="Blocked">Blocked <span id="count-blocked"></span></button><button class="filter-btn" data-status-filter="Mixed">Mixed <span id="count-mixed"></span></button><button class="filter-btn" data-status-filter="Unknown">Unknown <span id="count-unknown"></span></button></div>
    <div class="filter-group"><button class="filter-btn filter-new" id="new-filter" type="button">New &lt;24h <span id="count-new"></span></button></div>
    <div class="filter-group"><span class="filter-label">Classification</span><select id="classification-filter" class="filter-select"><option value="">All</option></select></div>
    <div class="filter-group"><span class="filter-label">Severity</span><select id="severity-filter" class="filter-select"><option value="">All</option></select></div>
    <div class="filter-group"><span class="filter-label">Device</span><select id="device-filter" class="filter-select"><option value="">All</option></select></div>
    <div class="filter-group"><span class="filter-label">Vendor</span><select id="vendor-filter" class="filter-select"><option value="">All</option></select></div>
    <div class="filter-group" style="margin-left:auto"><span class="filter-label">Show</span><select id="page-size" class="filter-select"><option value="10">10</option><option value="25">25</option><option value="50" selected>50</option><option value="100">100</option><option value="250">250</option><option value="500">500</option></select></div>
  </div>
  <div class="results-summary"><span id="results-summary"></span></div>
  <table id="recent-table"><thead><tr><th class="sortable" data-sort-key="domain" data-sort-type="text">Domain</th><th class="sortable" data-sort-key="activity" data-sort-type="number">Activity</th><th class="sortable" data-sort-key="devices" data-sort-type="number">Devices</th><th class="sortable" data-sort-key="status" data-sort-type="text">Status</th><th class="sortable" data-sort-key="severity" data-sort-type="text">Severity</th><th class="sortable" data-sort-key="classification" data-sort-type="text">Classification</th></tr></thead>
  <tbody id="recent-body">{{ recent_html|safe }}</tbody></table>
  <div class="pager"><div class="page-label" id="page-label"></div><div class="pager-controls"><button type="button" id="page-prev">Previous</button><button type="button" id="page-next">Next</button></div></div>
  </div>
</section>
<section id="tab-devices" class="tab-panel" data-panel="devices">
  <div class="card"><h2>Clients / Devices</h2>
  <table id="clients-table"><thead><tr><th class="sortable" data-sort-key="device" data-sort-type="text">Device</th><th class="sortable" data-sort-key="identity" data-sort-type="text">Identity</th><th class="sortable" data-sort-key="ips" data-sort-type="text">Current / recent IPs</th><th class="sortable" data-sort-key="requests" data-sort-type="number">Requests</th></tr></thead>
  <tbody id="clients-body">{{ clients_html|safe }}</tbody></table>
  <p class="source">Identity is based on AdGuard client information when available. A DHCP IP is treated as a changing observation, not as a permanent device identity. MAC/client identifiers are used as the stable key when AdGuard exposes them.</p></div>
</section>
<section id="tab-analytics" class="tab-panel active" data-panel="analytics">
  <div class="card" style="margin-bottom:14px;display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap">
    <div><h2 style="margin:0">Visibility Assessment</h2><div class="stats-note" style="margin-top:4px">Open the full 10-section assessment built from the same Analytics data.</div></div>
    <button type="button" class="assessment-open-btn" onclick="setActiveTab('assessment')">Open full assessment</button>
  </div>
  <div class="dash-toolbar">
    <button type="button" class="dash-customize-btn" id="dash-customize-btn" aria-pressed="false">Customize</button>
    <button type="button" id="analytics-export-pdf-btn" title="Export the currently selected Analytics range as a visual PDF report">Export PDF</button>
    <select class="settings-select" id="dash-preset-select" aria-label="Dashboard preset">
      <option value="default">Default layout</option>
      <option value="monitoring">Monitoring</option>
      <option value="compact">Compact</option>
      <option value="investigation">Investigation</option>
      <option value="custom">Custom</option>
    </select>
    <button type="button" id="dash-reset-btn" title="Reset to the default layout">Reset layout</button>
    <span class="dash-hint" id="dash-hint" hidden>Use the handle to drag, or resize from a corner/edge, or the arrow/hide buttons &mdash; changes save to this browser.</span>
  </div>
  <div class="dash-hidden-tray" id="dash-hidden-tray"><span class="dash-hidden-tray-label">Hidden widgets:</span><div class="dash-hidden-tray-list" id="dash-hidden-tray-list"></div></div>
  <div class="dash-grid grid-stack" id="analytics-dash-grid">
    <div class="grid-stack-item dash-widget" data-widget-id="visibility-report" data-title="Visibility report" gs-id="visibility-report" gs-w="4" gs-h="8" gs-min-h="8">
      <div class="grid-stack-item-content">
      <div class="card">
        <h2>Visibility report <span class="sub">executive overview</span></h2>
        <div class="stats-note" style="margin-top:0">A factual first-glance summary for the selected period above &mdash; every figure here is derived from the same retained data as the charts below, never invented.</div>
        <div class="analytics-hero">
          <div class="card live-card" id="live-card">
            <div class="live-title"><span class="live-dot"></span>Live activity</div>
            <div class="live-rate"><span id="live-rate-value">&mdash;</span><small>queries / 60s</small></div>
            <div id="live-gauge-slot"></div>
            <div class="live-sparkline-wrap" id="live-sparkline"></div>
            <div class="stats-note">Rolling in-browser window (up to 100 samples) &middot; a new sample every {{refresh_seconds}}s &middot; nothing extra is written to disk</div>
          </div>
          <div class="stat-tiles">
            <div class="stat-tile ok"><div class="stat-tile-label">Allowed domains</div><div class="stat-tile-value" id="tile-allowed">&mdash;</div></div>
            <div class="stat-tile blocked"><div class="stat-tile-label">Blocked domains</div><div class="stat-tile-value" id="tile-blocked">&mdash;</div></div>
            <div class="stat-tile info"><div class="stat-tile-label">Active devices</div><div class="stat-tile-value" id="tile-devices">&mdash;</div></div>
            <div class="stat-tile warn"><div class="stat-tile-label">New domains (24h)</div><div class="stat-tile-value" id="tile-new-domains">&mdash;</div></div>
          </div>
        </div>
        <div id="visibility-report"><div class="empty-state">Loading…</div></div>
      </div>
      </div>
    </div>
    <div class="grid-stack-item dash-widget" data-widget-id="query-volume" data-title="DNS activity over time" gs-id="query-volume" gs-w="4" gs-h="7" gs-min-h="7">
      <div class="grid-stack-item-content">
      <div class="card">
        <h2>DNS activity over time</h2>
        <div class="analytics-range-controls" role="group" aria-label="Historical time range">
          <button type="button" class="range-btn active" data-analytics-range="1h">1H</button>
          <button type="button" class="range-btn" data-analytics-range="6h">6H</button>
          <button type="button" class="range-btn" data-analytics-range="24h">24H</button>
          <button type="button" class="range-btn" data-analytics-range="7d">7D</button>
          <button type="button" class="range-btn" data-analytics-range="30d">30D</button>
          <button type="button" class="range-btn" data-analytics-range="90d">90D</button>
          <button type="button" class="range-btn" id="analytics-range-custom-btn" data-analytics-range="custom" aria-expanded="false" aria-controls="analytics-range-custom-controls">Custom</button>
        </div>
        <div class="range-custom-controls" id="analytics-range-custom-controls" hidden>
          <label for="analytics-custom-from">From <input type="date" id="analytics-custom-from"></label>
          <label for="analytics-custom-to">To <input type="date" id="analytics-custom-to"></label>
          <button type="button" id="analytics-custom-apply-btn">Apply</button>
          <span class="range-custom-error" id="analytics-custom-error" role="alert"></span>
        </div>
        <div id="chart-query-volume"></div>
        <div class="stats-note" style="margin-top:0">Click or tap a point (or focus it and press Enter) for the exact interval &mdash; query count, status mix, new domains/devices, and top domains/devices for that window.</div>
        <div id="chart-query-volume-detail" class="interval-detail" hidden></div>
      </div>
      </div>
    </div>
    <div class="grid-stack-item dash-widget" data-widget-id="new-domains" data-title="New domains discovered" gs-id="new-domains" gs-w="2" gs-h="5" gs-min-h="5">
      <div class="grid-stack-item-content">
      <div class="card"><h2>New domains discovered</h2><div id="chart-new-domains"></div></div>
      </div>
    </div>
    <div class="grid-stack-item dash-widget" data-widget-id="new-devices" data-title="New devices discovered" gs-id="new-devices" gs-w="2" gs-h="5" gs-min-h="5">
      <div class="grid-stack-item-content">
      <div class="card"><h2>New devices discovered</h2><div id="chart-new-devices"></div></div>
      </div>
    </div>
    <div class="grid-stack-item dash-widget" data-widget-id="status-breakdown" data-title="Status breakdown" gs-id="status-breakdown" gs-w="4" gs-h="5" gs-min-h="5">
      <div class="grid-stack-item-content">
      <div class="card">
        <h2>Status breakdown</h2>
        <div id="status-breakdown"></div>
        <div class="stats-note">All known domains, grouped by their current AdGuard filtering outcome.</div>
      </div>
      </div>
    </div>
    <div class="grid-stack-item dash-widget" data-widget-id="instrument-gauges" data-title="Instrument gauges" gs-id="instrument-gauges" gs-w="4" gs-h="5" gs-min-h="5">
      <div class="grid-stack-item-content">
      <div class="card">
        <h2>Instrument gauges</h2>
        <div id="instrument-gauges" class="gauge-cluster">
          <div class="gauge-face"><div id="gauge-blocked-ratio"></div><div class="stats-note">Blocked ratio</div></div>
          <div class="gauge-face"><div id="gauge-active-devices"></div><div class="stats-note">Active devices</div></div>
        </div>
      </div>
      </div>
    </div>
    <div class="grid-stack-item dash-widget" data-widget-id="destination-map" data-title="DNS Destinations (observed)" gs-id="destination-map" gs-w="4" gs-h="10" gs-min-h="10">
      <div class="grid-stack-item-content">
      <div class="card">
        <h2>DNS Destinations <span class="sub">(observed)</span></h2>
        <div class="stats-note" style="margin-top:0" id="destination-map-subtitle">Country-level aggregate of resolved DNS response IPs &mdash; not verified physical server locations. CDN, anycast and multi-region destinations resolve to whichever country answered.</div>
        <div class="map-controls">
          <select class="settings-select" id="map-mode-select" aria-label="Map mode">
            <option value="countries">Countries</option>
            <option value="destinations">Destinations</option>
          </select>
          <select class="settings-select" id="map-metric-select" aria-label="Map metric">
            <option value="observations">Observations</option>
            <option value="unique_ips">Unique IPs</option>
            <option value="domains">Domains</option>
          </select>
          <select class="settings-select" id="map-basemap-select" aria-label="Map basemap">
            <option value="satellite-heat">Satellite Heat</option>
            <option value="satellite-density">Satellite Density</option>
            <option value="real-pins">Real Map / Pins</option>
            <option value="dark-noc">Dark NOC / Urban</option>
          </select>
          <select class="settings-select" id="map-theme-select" aria-label="Map theme">
            <option value="indigo-gold">Indigo + Gold</option>
            <option value="cyan">Cyan</option>
            <option value="bemo-accent">BEMO / Dark Accent</option>
          </select>
          <label class="map-routes-toggle-label"><input type="checkbox" id="map-routes-toggle" aria-label="Show destination routes (visual path, not the real network route)"> Routes</label>
          <span class="map-zoom-group" role="group" aria-label="Map zoom">
            <button type="button" class="map-zoom-btn" id="map-zoom-out-btn" aria-label="Zoom out">&minus;</button>
            <button type="button" class="map-zoom-btn" id="map-zoom-in-btn" aria-label="Zoom in">+</button>
            <button type="button" class="map-zoom-btn" id="map-fit-btn" aria-label="Fit map to data">Fit</button>
            <button type="button" class="map-zoom-btn" id="map-reset-btn" aria-label="Reset map view">Reset</button>
          </span>
        </div>
        <div class="stats-note" style="margin-top:0">Click or tap a marker for details &mdash; they stay open until dismissed. Drag to pan, scroll/pinch to zoom, or use the buttons above. Tab to a marker and press Enter/Space to select it; arrow keys pan and +/- zoom when the map is focused. Basemap picks how activity is drawn (heat glow, density points, pins, or bright NOC points); theme only recolors the intensity ramp, independently of the basemap.</div>
        <div class="map-legend" id="destination-map-legend" role="note" aria-label="Map legend: marker size and color both scale with observation count">
          <div class="map-legend-group">
            <span class="map-legend-title">Marker size</span>
            <span class="map-legend-size-scale">
              <span class="map-legend-dot" style="width:8px;height:8px;background:hsl(152,68%,42%)"></span>
              <span class="map-legend-dot" style="width:17px;height:17px;background:hsl(40,92%,50%)"></span>
              <span class="map-legend-dot" style="width:28px;height:28px;background:hsl(2,82%,52%)"></span>
            </span>
            <span class="map-legend-caption">Fewer <span id="map-legend-metric-label">observations</span> &rarr; more</span>
          </div>
          <div class="map-legend-group">
            <span class="map-legend-title">Marker color</span>
            <span class="map-legend-gradient" id="map-legend-gradient"></span>
            <span class="map-legend-caption">Low intensity &rarr; high intensity</span>
          </div>
          <div class="map-legend-group">
            <span class="map-legend-title">Particles</span>
            <span class="map-legend-caption">More particles/brighter glow around a real observed location means more traffic there &mdash; they are an intensity visualization, not independent physical servers.</span>
          </div>
          <div class="map-legend-group" id="map-legend-provenance">
            <span class="map-legend-title">Destination provenance</span>
            <span class="map-legend-caption"><span class="provenance-badge provenance-city_geoip">City GeoIP</span> exact-coordinate match &middot; <span class="provenance-badge provenance-known_datacenter">Known datacenter</span> region-derived from a curated provider database, never an exact server location &middot; Country-only/unmapped destinations are never shown as a bubble here.</span>
          </div>
        </div>
        <div class="destination-map-layout">
          <div>
            <div id="destination-map"></div>
            <div id="destination-map-detail" class="map-detail" hidden></div>
          </div>
          <div class="map-breakdown">
            <div class="map-breakdown-head">
              <span class="map-breakdown-title">Countries</span>
              <button type="button" class="map-breakdown-sort-btn" id="map-breakdown-sort-btn" aria-label="Toggle country breakdown sort order">Sort: <span id="map-breakdown-sort-label">Metric</span></button>
            </div>
            <ul class="map-breakdown-list" id="map-breakdown-list" role="list" aria-label="Country breakdown"></ul>
          </div>
        </div>
        <div class="stats-note" style="margin-top:0" id="destination-map-history"></div>
        <div class="stats-note" style="margin-top:0">GeoIP data, when configured: IP Geolocation by <a href="https://db-ip.com" target="_blank" rel="noopener noreferrer">DB-IP</a> (DB-IP Lite, CC BY 4.0). Known-datacenter points, when configured, come from an operator-supplied curated provider/region database &mdash; see docs/GEOIP.md.</div>
      </div>
      </div>
    </div>
    <div class="grid-stack-item dash-widget" data-widget-id="activity-domains" data-title="Recently active domains" gs-id="activity-domains" gs-w="2" gs-h="5" gs-min-h="5">
      <div class="grid-stack-item-content">
      <div class="card"><h2>Recently active domains</h2><div id="activity-domains"></div></div>
      </div>
    </div>
    <div class="grid-stack-item dash-widget" data-widget-id="activity-devices" data-title="Recently active devices" gs-id="activity-devices" gs-w="2" gs-h="5" gs-min-h="5">
      <div class="grid-stack-item-content">
      <div class="card"><h2>Recently active devices</h2><div id="activity-devices"></div></div>
      </div>
    </div>
    <div class="grid-stack-item dash-widget" data-widget-id="top-activity" data-title="Top activity (all time)" gs-id="top-activity" gs-w="4" gs-h="8" gs-min-h="7">
      <div class="grid-stack-item-content">
      <div class="card"><h2>Top activity (all time)</h2><div class="stats-note" style="margin-top:0">Cumulative totals since the database was created.</div></div>
      <div class="chart-grid">
        <div class="card chart-card"><h2>Most requested domains</h2><div id="chart-domains" class="chart-list"></div><div class="stats-note">Based on recorded DNS requests.</div></div>
        <div class="card chart-card"><h2>Most active devices</h2><div id="chart-devices" class="chart-list"></div><div class="stats-note">Ranked by total recorded requests.</div></div>
        <div class="card chart-card"><h2>Most active vendors</h2><div id="chart-vendors" class="chart-list"></div><div class="stats-note">Aggregated from identified devices.</div></div>
        <div class="card chart-card"><h2>Most active IPs</h2><div id="chart-ips" class="chart-list"></div><div class="stats-note">Aggregated from device IP observations.</div></div>
      </div>
      </div>
    </div>
  </div>
</section>
<section id="tab-assessment" class="tab-panel" data-panel="assessment">
  <div class="card">
    <div class="assessment-toolbar" style="margin-bottom:8px">
      <button type="button" onclick="setActiveTab('analytics')">← Back to Analytics</button>
      <span class="stats-note">Detailed report</span>
    </div>
    <h2>Visibility Assessment <span class="sub">standalone 10-section report</span></h2>
    <div class="stats-note" style="margin-top:0">Every figure below is read from the same <code>/api/analytics</code>, <code>/api/analytics/map</code>, and <code>/api/reports/status</code> data the rest of the dashboard uses &mdash; nothing here is a separate or fabricated data source. Sections are collapsed by default; expand the ones you need.</div>
    <div class="assessment-toolbar">
      <span id="assessment-period-label" class="stats-note" style="margin:0">Analysis period: &mdash;</span>
      <button type="button" id="assessment-refresh-btn">Refresh assessment</button>
    </div>
    <div id="assessment-root">
      <details class="assessment-section" open>
        <summary>1. Executive summary</summary>
        <div class="assessment-section-body" id="assessment-summary" data-assessment-slot><div class="empty-state">Open this tab to load the assessment.</div></div>
      </details>
      <details class="assessment-section">
        <summary>2. Activity timeline</summary>
        <div class="assessment-section-body" id="assessment-timeline" data-assessment-slot></div>
      </details>
      <details class="assessment-section">
        <summary>3. Status &amp; classification</summary>
        <div class="assessment-section-body" id="assessment-status" data-assessment-slot></div>
      </details>
      <details class="assessment-section">
        <summary>4. Recently active domains</summary>
        <div class="assessment-section-body" id="assessment-top-domains" data-assessment-slot></div>
      </details>
      <details class="assessment-section">
        <summary>5. Recently active devices</summary>
        <div class="assessment-section-body" id="assessment-top-devices" data-assessment-slot></div>
      </details>
      <details class="assessment-section">
        <summary>6. New discoveries this period</summary>
        <div class="assessment-section-body" id="assessment-new" data-assessment-slot></div>
      </details>
      <details class="assessment-section">
        <summary>7. Destination geography</summary>
        <div class="assessment-section-body" id="assessment-geo" data-assessment-slot></div>
      </details>
      <details class="assessment-section">
        <summary>8. Destination coverage &amp; provenance</summary>
        <div class="assessment-section-body" id="assessment-coverage" data-assessment-slot></div>
      </details>
      <details class="assessment-section">
        <summary>9. Report delivery &amp; scheduling</summary>
        <div class="assessment-section-body" id="assessment-reports" data-assessment-slot></div>
      </details>
      <details class="assessment-section">
        <summary>10. Methodology &amp; limitations</summary>
        <div class="assessment-section-body">
          <ul class="assessment-list">
            <li><span>Data source</span><span>Every section reads the live DNS Inspector API (<code>/api/analytics</code>, <code>/api/analytics/map</code>, <code>/api/reports/status</code>) &mdash; the same endpoints the Analytics tab and PDF export use.</span></li>
            <li><span>Retention</span><span>Figures are bounded by the retained analytics history window; periods outside that window are not fabricated, they are reported as unavailable.</span></li>
            <li><span>Geolocation</span><span>Destination geography describes where DNS answers resolve to, aggregated at country/coordinate level from an optional GeoIP database. It is not a verified map of physical servers.</span></li>
            <li><span>Classification</span><span>Allowed/Blocked/Mixed/Unknown reflect the current AdGuard filtering outcome for each domain, not a security verdict produced by this application.</span></li>
            <li><span>No risk scoring</span><span>This assessment intentionally avoids inventing a risk score, threat rating, or root-cause explanation beyond what the underlying data supports.</span></li>
          </ul>
        </div>
      </details>
    </div>
  </div>
</section>
<script>
/* Standalone Visibility Assessment tab (Issue #88): a progressive-disclosure
   10-section view built entirely from data the Analytics tab and PDF export
   already fetch -- no new/fabricated data source. Loaded once per tab
   activation (or on demand via the Refresh button), not on a poll timer,
   since it's a point-in-time assessment rather than a live dashboard. */
function assessmentPeriodLabel(){
  if (analyticsRange === 'custom' && analyticsCustomWindow) return `Custom (${(analyticsCustomWindow.from||'').slice(0,10)} to ${(analyticsCustomWindow.to||'').slice(0,10)})`;
  const active = document.querySelector(`[data-analytics-range="${CSS.escape(analyticsRange || '1h')}"]`);
  return active ? active.textContent : (analyticsRange || '1h');
}
function assessmentEmpty(text){ return `<div class="empty-state">${esc(text)}</div>`; }
function renderAssessmentSummary(a){
  const qPoints = (a.series?.queries?.points || []).filter(p => p.count != null);
  const total = sumSeriesPoints(qPoints);
  const newDomains = sumSeriesPoints(a.series?.new_domains?.points);
  const newDevices = sumSeriesPoints(a.series?.new_devices?.points);
  const b = a.status_breakdown || {};
  const known = (Number(b.Allowed)||0) + (Number(b.Blocked)||0);
  const blockedPct = known ? Math.round((Number(b.Blocked||0) / known) * 1000) / 10 : null;
  return `<div class="assessment-kv">`
    + `<b>Period</b><span>${esc(a.series?.queries?.label || a.range)}</span>`
    + `<b>Total queries</b><span>${esc(total)}</span>`
    + `<b>New domains</b><span>${esc(newDomains)}</span>`
    + `<b>New devices</b><span>${esc(newDevices)}</span>`
    + `<b>Active devices</b><span>${esc(a.active_devices ?? '—')} of ${esc(a.total_devices ?? '—')} known</span>`
    + `<b>Blocked share</b><span>${blockedPct != null ? blockedPct + '%' : 'no classified domains yet'}</span>`
    + `</div>`;
}
function renderAssessmentTimeline(a){
  const points = a.series?.queries?.points || [];
  const known = points.filter(p => p.count != null);
  if (!known.length) return assessmentEmpty('No retained query timeline is available for this period.');
  return `<div class="assessment-kv">`
    + `<b>Buckets</b><span>${esc(points.length)} (${esc(a.series?.queries?.bucket_seconds || 0)}s each)</span>`
    + `<b>Buckets with data</b><span>${esc(known.length)}</span>`
    + `<b>Total queries</b><span>${esc(sumSeriesPoints(points))}</span>`
    + `</div><p class="assessment-note">See the "DNS activity over time" chart on the Analytics tab for the interactive, click-to-drill-down version of this timeline.</p>`;
}
function renderAssessmentStatus(a){
  const b = a.status_breakdown || {};
  const total = Number(b.All) || 0;
  if (!total) return assessmentEmpty('No classified domains yet.');
  const rows = ['Allowed','Blocked','Mixed','Unknown'].map(k => {
    const v = Number(b[k]) || 0; const pct = total ? Math.round((v/total)*1000)/10 : 0;
    return `<li><span>${esc(k)}</span><span>${esc(v)} (${pct}%)</span></li>`;
  }).join('');
  return `<ul class="assessment-list">${rows}</ul>`;
}
function assessmentDomainList(rows){
  if (!rows || !rows.length) return assessmentEmpty('No recent domain activity recorded for this period.');
  return `<ul class="assessment-list">${rows.slice(0, 12).map(r => `<li><span>${esc(r.domain)}</span><span>${esc(r.status || 'Unknown')} &middot; ${esc(r.requests)} requests</span></li>`).join('')}</ul>`;
}
function assessmentDeviceList(rows){
  if (!rows || !rows.length) return assessmentEmpty('No recent device activity recorded for this period.');
  return `<ul class="assessment-list">${rows.slice(0, 12).map(d => `<li><span>${esc(d.label || d.device_key)}</span><span>${esc(d.requests)} requests</span></li>`).join('')}</ul>`;
}
function renderAssessmentNew(a){
  const newDomains = sumSeriesPoints(a.series?.new_domains?.points);
  const newDevices = sumSeriesPoints(a.series?.new_devices?.points);
  if (!newDomains && !newDevices) return assessmentEmpty('No new domains or devices were first seen in this period.');
  return `<div class="assessment-kv"><b>New domains</b><span>${esc(newDomains)}</span><b>New devices</b><span>${esc(newDevices)}</span></div>`
    + `<p class="assessment-note">Select a bucket on the Analytics tab's timeline chart for the exact list of new domains/devices in that interval.</p>`;
}
function renderAssessmentGeo(m){
  const countries = (m?.countries || []).slice().sort((x, y) => (y.observation_count||0) - (x.observation_count||0));
  const unknown = m?.unknown || {};
  if (!countries.length) return assessmentEmpty('No geolocated destination countries yet.');
  const rows = countries.slice(0, 12).map(c => `<li><span>${esc(c.country_name || c.country_code)}</span><span>${esc(c.observation_count)} observations &middot; ${esc(c.domain_count)} domains</span></li>`).join('');
  const unknownNote = unknown.observation_count ? `<p class="assessment-note">${esc(unknown.observation_count)} observation(s) across ${esc(unknown.domain_count||0)} domain(s) could not be geolocated.</p>` : '';
  return `<ul class="assessment-list">${rows}</ul>${unknownNote}`;
}
function renderAssessmentCoverage(m){
  const cov = m?.coverage || {};
  const prov = cov.provenance || {};
  return `<div class="assessment-kv">`
    + `<b>Domains tracked</b><span>${esc(cov.total_domains ?? 0)}</span>`
    + `<b>Geolocated domains</b><span>${esc(cov.geolocated_domains ?? 0)} (${esc(cov.geolocated_pct ?? 0)}%)</span>`
    + `<b>City GeoIP (exact)</b><span>${esc(prov.city_geoip ?? 0)}</span>`
    + `<b>Known datacenter (region)</b><span>${esc(prov.known_datacenter ?? 0)}</span>`
    + `<b>Country only</b><span>${esc(prov.country_only ?? 0)}</span>`
    + `<b>Unmapped</b><span>${esc(prov.unmapped ?? 0)}</span>`
    + `</div>`;
}
function renderAssessmentReports(statusData){
  const state = statusData?.state || {};
  return `<div class="assessment-kv">`
    + `<b>Scheduler</b><span>${state.enabled ? 'Enabled' : 'Disabled'}</span>`
    + `<b>Next run</b><span>${esc(state.next_run || '—')}</span>`
    + `<b>Last run</b><span>${esc(state.last_run || 'never')}</span>`
    + `<b>Last result</b><span>${esc(state.last_result || '—')}</span>`
    + `<b>Last saved file</b><span>${esc(state.last_saved_file || '—')}</span>`
    + `<b>Last email result</b><span>${state.last_email_result ? (state.last_email_result.ok ? 'sent' : 'failed: ' + esc(state.last_email_result.error||'')) : '—'}</span>`
    + `</div><p class="assessment-note">Configure scheduling, retention and SMTP delivery from Settings &rsaquo; Reports.</p>`;
}
async function loadAssessment(){
  const label = document.getElementById('assessment-period-label');
  if (label) label.textContent = `Analysis period: ${assessmentPeriodLabel()}`;
  document.querySelectorAll('#assessment-root [data-assessment-slot]').forEach(el => { el.innerHTML = assessmentEmpty('Loading…'); });
  try{
    const [aRes, mRes, sRes] = await Promise.all([
      fetch(`/api/analytics?${analyticsRangeQueryString()}`, {cache: 'no-store'}),
      fetch('/api/analytics/map', {cache: 'no-store'}),
      fetch('/api/reports/status', {cache: 'no-store'}),
    ]);
    const a = await aRes.json();
    const m = await mRes.json();
    const s = await sRes.json();
    document.getElementById('assessment-summary').innerHTML = renderAssessmentSummary(a);
    document.getElementById('assessment-timeline').innerHTML = renderAssessmentTimeline(a);
    document.getElementById('assessment-status').innerHTML = renderAssessmentStatus(a);
    document.getElementById('assessment-top-domains').innerHTML = assessmentDomainList(a.recent_domains);
    document.getElementById('assessment-top-devices').innerHTML = assessmentDeviceList(a.recent_devices);
    document.getElementById('assessment-new').innerHTML = renderAssessmentNew(a);
    document.getElementById('assessment-geo').innerHTML = renderAssessmentGeo(m);
    document.getElementById('assessment-coverage').innerHTML = renderAssessmentCoverage(m);
    document.getElementById('assessment-reports').innerHTML = renderAssessmentReports(s);
  }catch(e){
    document.querySelectorAll('#assessment-root [data-assessment-slot]').forEach(el => { el.innerHTML = assessmentEmpty('Unable to load this section right now.'); });
  }
}
document.getElementById('assessment-refresh-btn')?.addEventListener('click', loadAssessment);
function assessmentTabChanged(name){ if (name === 'assessment') loadAssessment(); }
window.onAssessmentTabChange = assessmentTabChanged;
</script>
<script>
let refreshMs = effectiveRefreshMs();
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
function realDeviceLabel(c){ const vendor=String(c.vendor||'').trim().toLowerCase(); const identifier=String(c.device_key||c.identifier||'').trim().toLowerCase(); for(const v of [c.hostname,c.name,c.display_name]){ const t=String(v||'').trim(); if(t && t.toLowerCase()!==vendor && t.toLowerCase()!==identifier) return t; } return ''; }
function ipLink(ip){ return `<a class="client-chip mono link-ip" href="${ipHref(ip)}">${esc(ip)}</a>`; }
function magnifierSvg(){ return `<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="6.5"></circle><path d="M16 16l5 5"></path></svg>`; }
function deviceTypeSvg(type, fallback='', large=false){ const t=String(type||'').toLowerCase(); let b='<rect x=\"5\" y=\"6\" width=\"14\" height=\"14\" rx=\"3\"/><path d=\"M9 3v3M15 3v3M9 20v1M15 20v1M3 10h2M3 16h2M19 10h2M19 16h2\"/><circle cx=\"12\" cy=\"13\" r=\"2\"/>'; if(t.includes('phone')||t.includes('tablet')) b='<rect x=\"7\" y=\"3\" width=\"10\" height=\"18\" rx=\"2\"/><circle cx=\"12\" cy=\"18\" r=\"1\" fill=\"currentColor\" stroke=\"none\"/>'; else if(t.includes('computer')) b='<rect x=\"3\" y=\"4\" width=\"18\" height=\"12\" rx=\"2\"/><path d=\"M9 20h6M12 16v4\"/>'; else if(t.includes('console')) b='<rect x=\"3\" y=\"7\" width=\"18\" height=\"10\" rx=\"3\"/><path d=\"M7 12h4M9 10v4M16 10h.01M18 12h.01\"/>'; else if(t.includes('camera')) b='<path d=\"M5 8h4l2-3h2l2 3h4v10H5z\"/><circle cx=\"12\" cy=\"13\" r=\"3\"/>'; else if(t.includes('speaker')) b='<rect x=\"7\" y=\"3\" width=\"10\" height=\"18\" rx=\"2\"/><circle cx=\"12\" cy=\"9\" r=\"2\"/><circle cx=\"12\" cy=\"16\" r=\"3\"/>'; else if(t.includes('network')) b='<rect x=\"9\" y=\"3\" width=\"6\" height=\"5\" rx=\"1\"/><rect x=\"3\" y=\"16\" width=\"6\" height=\"5\" rx=\"1\"/><rect x=\"15\" y=\"16\" width=\"6\" height=\"5\" rx=\"1\"/><path d=\"M12 8v4M6 16v-2h12v2\"/>'; else if(t.includes('tv')) b='<rect x=\"3\" y=\"5\" width=\"18\" height=\"12\" rx=\"2\"/><path d=\"M9 21h6M12 17v4\"/>'; else if(t.includes('washing')||t.includes('dishwasher')||t.includes('appliance')) b='<rect x=\"5\" y=\"3\" width=\"14\" height=\"18\" rx=\"2\"/><circle cx=\"12\" cy=\"13\" r=\"4\"/><path d=\"M8 6h.01M11 6h.01M14 6h.01\"/>'; const cls=large?'device-type-icon-lg':'device-type-icon'; return `<span class=\"${cls}\"><svg viewBox=\"0 0 24 24\">${b}</svg></span>`; }
function externalButton(url,label,icon=''){ const glyph = icon === '' ? magnifierSvg() : esc(icon); return `<a class="external-tool ${label ? '' : 'icon-only'}" href="${esc(url)}" target="_blank" rel="noopener noreferrer" title="${esc(label || 'External lookup')}">${glyph}${label ? ' ' + esc(label) : ''}</a>`; }
function deviceLabelFor(c){ return String((window.deviceLabels||{})[c.device_key||c.identifier]||c.label||'').trim(); }
function deviceRow(c){
  const ips = (c.ips || []).map(ipLink).join(' ');
  const host = c.hostname && c.hostname !== (c.name || c.vendor || c.display_name || c.identifier) ? `<div class="technical mono"><a class="link-device" href="${deviceHref(c)}" title="Open device details">HOST ${esc(c.hostname)}</a></div>` : '';
  const vendor = c.vendor ? `<div class="sub">${c.vendor_logo ? `<img class="vendor-logo" src="${esc(c.vendor_logo)}" alt="" loading="lazy">` : `<span class="vendor-mark">◈</span>`}${esc(c.vendor)} ${externalButton(`https://www.google.com/search?q=${encodeURIComponent(c.vendor)}`,'Search vendor')}</div>` : '';
  const mac = c.mac ? `<div class="technical mono">${esc(c.mac)} ${externalButton(`https://maclookup.app/search/result?mac=${encodeURIComponent(c.mac)}`,'MAC lookup')}</div>` : '';
  const source = c.source ? `<div class="technical">${esc(c.source)}</div>` : '';
  const explicitLabel = deviceLabelFor(c);
  const linkedPrimary = explicitLabel || realDeviceLabel(c);
  const primary = linkedPrimary || c.vendor || c.identifier;
  const primaryHtml = linkedPrimary ? deviceLink(c, `<div class="device-name">${esc(primary)}</div>`, 'primary-device') : `<div class="device-name">${esc(primary)}</div>`;
  const visual = c.vendor_logo ? `<img class="vendor-logo-lg" src="${esc(c.vendor_logo)}" alt="" loading="lazy">` : deviceTypeSvg(c.type, c.icon, true);
  const visualHtml = linkedPrimary ? deviceLink(c, visual) : visual;
  const labelButton = `<button type="button" class="device-label-btn" data-device-key="${esc(c.device_key||c.identifier||'')}" data-device-label="${esc(explicitLabel)}">${explicitLabel?'Edit label':'Add label'}</button>`; const labelMeta = `<div class="device-label-inline"><span class="device-label-text">${explicitLabel?'Label: '+esc(explicitLabel):'No label'}</span>${labelButton}</div>`; return `<tr data-sort-device="${esc(primary)}" data-sort-identity="${esc(c.mac || '')}" data-sort-ips="${esc((c.ips || []).join(' '))}" data-sort-requests="${Number(c.requests)||0}"><td><div class="device">${visualHtml}<span>${primaryHtml}${vendor}${host}<div class="confidence">${esc(c.type)} · ${esc(c.confidence_label)}</div>${labelMeta}${source}</span></div></td><td>${ips || '—'}</td><td>${c.mac ? `<span class="mono">${esc(c.mac)}</span> ${externalButton(`https://maclookup.app/search/result?mac=${encodeURIComponent(c.mac)}`,'MAC lookup')}` : '—'}</td><td>${esc(c.requests)}</td></tr>`;
}
let recentMeta={page:1,pages:1,total:0,page_size:50,new_count:0,status_counts:{All:0,Allowed:0,Blocked:0,Unknown:0}};let recentFilters={status:'',newOnly:false,classification:'',severity:'',device:'',vendor:'',page:1,page_size:50};let knownDomains=new Set();let initialDomainSnapshot=false;
function ageText(iso){const t=new Date(iso).getTime();if(!Number.isFinite(t))return '';const m=Math.max(0,Math.floor((Date.now()-t)/60000));if(m<1)return 'now';if(m<60)return `${m}m`;const h=Math.floor(m/60);if(h<24)return `${h}h`;return `${Math.floor(h/24)}d`}
function isNewRow(r){const t=new Date(r.first_seen||'').getTime();return Number.isFinite(t)&&(Date.now()-t)<86400000}
function renderRecent(rows,force){window.__lastRecent=rows||[];if(!force&&!document.getElementById('tab-overview')?.classList.contains('active'))return;document.getElementById('recent-body').innerHTML=(rows||[]).map(r=>{const devices=(r.devices||[]).map(d=>{const label=deviceLabelFor(d);return `<a class="device-chip link-device" href="${deviceHref(d)}" title="Open device details">${d.vendor_logo?`<img class="vendor-logo" src="${esc(d.vendor_logo)}" alt="" loading="lazy">`:deviceTypeSvg(d.type,d.icon,false)}${esc(label||d.name)}</a>`;}).join('');const n=isNewRow(r);const badge=n?`<span class="new-badge" title="First seen ${esc(r.first_seen||'')}"><span class="new-badge-dot"></span>NEW · ${esc(ageText(r.first_seen))}</span>`:'';return `<tr class="${n?'row-new':''}" data-sort-domain="${esc(r.domain)}" data-sort-activity="${Number(r.requests)||0}" data-sort-devices="${Number(r.clients)||0}" data-sort-status="${esc(r.status)}" data-sort-severity="${esc(r.severity)}" data-sort-classification="${esc(r.classification)}"><td><a class="glance-domain" href="/search?q=${encodeURIComponent(r.domain)}" title="Inspect domain in DNS Inspector">${esc(r.domain)}</a>${badge}<div class="glance-meta"><span>${esc(r.requests)} requests</span><span>·</span><span>${esc(r.clients)} device${r.clients===1?'':'s'}</span></div></td><td><b>${esc(r.requests)}</b> requests</td><td class="glance-devices"><div class="device-list">${devices||'<span class="sub">No identified devices</span>'}</div></td><td><span class="status-pill status-${esc(r.status_class)}">${esc(r.status)}</span></td><td><span class="severity-${esc(r.severity_text_class)}">${esc(r.severity)}</span></td><td><span class="dot dot-${esc(r.severity_class)}"></span><span class="tag ${esc(r.badge_class)}">${esc(r.classification)}</span></td></tr>`}).join('');reapplyTableSorts()}
function setSelectOptions(id,values,selected){const e=document.getElementById(id);if(!e)return;e.innerHTML='<option value="">All</option>'+(values||[]).map(v=>{const value=typeof v==='string'?v:v.value;const label=typeof v==='string'?v:v.label;return `<option value="${esc(value)}">${esc(label)}</option>`}).join('');e.value=selected||''}
function renderRecentControls(meta,opts){recentMeta=meta||recentMeta;const c=recentMeta.status_counts||{};[['count-all','All'],['count-allowed','Allowed'],['count-blocked','Blocked'],['count-mixed','Mixed'],['count-unknown','Unknown']].forEach(([i,k])=>{const e=document.getElementById(i);if(e)e.textContent=c[k]!=null?` ${c[k]}`:''});const n=document.getElementById('count-new');if(n)n.textContent=recentMeta.new_count!=null?` ${recentMeta.new_count}`:'';document.getElementById('analytics-export-pdf-btn')?.addEventListener('click', () => {
  window.location.href = '/api/analytics/report.pdf?' + analyticsRangeQueryString();
});
document.querySelectorAll('[data-status-filter]').forEach(b=>b.classList.toggle('active',(b.dataset.statusFilter||'')===recentFilters.status));document.getElementById('new-filter')?.classList.toggle('active',recentFilters.newOnly);const sum=document.getElementById('results-summary');if(sum)sum.innerHTML=`<b>${recentMeta.total||0}</b> matching domain${(recentMeta.total||0)===1?'':'s'} · <b>${recentMeta.new_count||0}</b> new in the last 24h`;setSelectOptions('classification-filter',opts?.classifications,recentFilters.classification);setSelectOptions('severity-filter',opts?.severities,recentFilters.severity);setSelectOptions('device-filter',opts?.devices,recentFilters.device);setSelectOptions('vendor-filter',opts?.vendors,recentFilters.vendor);const ps=document.getElementById('page-size');if(ps)ps.value=String(recentFilters.page_size);const label=document.getElementById('page-label');if(label){const a=recentMeta.total?((recentMeta.page-1)*recentMeta.page_size)+1:0;const b=recentMeta.total?Math.min(recentMeta.page*recentMeta.page_size,recentMeta.total):0;label.textContent=`Showing ${a}–${b} of ${recentMeta.total||0}`}const prev=document.getElementById('page-prev'),next=document.getElementById('page-next');if(prev)prev.disabled=recentMeta.page<=1;if(next)next.disabled=recentMeta.page>=recentMeta.pages}
function showNewBanner(entries){const b=document.getElementById('new-banner'),t=document.getElementById('new-banner-text');if(!b||!t||!entries.length)return;const items=entries.slice(0,3).map(r=>{const status=r.status||'Unknown';const statusClass=r.status_class||'unknown';const href=`/search?q=${encodeURIComponent(r.domain)}`;return `<span class="new-domain-item"><a class="new-domain-link" href="${href}" title="Inspect domain in DNS Inspector">${esc(r.domain)}</a><span class="status-pill status-${esc(statusClass)}">${esc(status)}</span></span>`}).join('');t.innerHTML=`<b>${entries.length}</b> new domain${entries.length===1?'':'s'} detected · <span class="new-domain-items">${items}</span>`;b.classList.add('show')}
function clearNewBanner(){document.getElementById('new-banner')?.classList.remove('show')}
function updateNewDetection(rows){const current=rows||[];const set=new Set(current.map(r=>r.domain));if(!initialDomainSnapshot){set.forEach(d=>knownDomains.add(d));initialDomainSnapshot=true;return}const fresh=current.filter(r=>!knownDomains.has(r.domain));set.forEach(d=>knownDomains.add(d));if(fresh.length)showNewBanner(fresh)}
window.deviceLabels={};
function ensureRefreshStatus(){let el=document.getElementById('refresh-status');if(el)return el;el=document.createElement('div');el.id='refresh-status';el.className='refresh-status';el.innerHTML='<span class="refresh-spinner"></span><span>Refreshing…</span>';document.body.appendChild(el);return el}
function showRefreshStatus(){ensureRefreshStatus().classList.add('show')}
function hideRefreshStatus(){const el=document.getElementById('refresh-status');if(el)el.classList.remove('show')}
function ipPingTitle(s){if(!s)return 'Never checked';const when=new Date(Number(s.last_checked)*1000);const result=s.online?'Reachable':'Unreachable';const latency=s.latency_ms!=null?` · ${s.latency_ms} ms`:'';const err=s.error?` · ${s.error}`:'';return `${result}${latency}${err} · ${when.toLocaleString()}`}
function ipPingMarkup(ip,s){const state=s?(s.online?'online':'offline'):'pending';const label=s?(s.online?'OK':'FAIL'):'?';return `<span class="device-ip-ping" data-ping-ip="${esc(ip)}" title="${esc(ipPingTitle(s))}"><span class="device-ip-ping-dot ${state}" data-ping-dot></span><button type="button" class="device-ip-ping-btn" data-ping-button="${esc(ip)}">Ping</button></span>`}
function decorateDeviceIps(){const root=document.getElementById('clients-body');if(!root)return;root.querySelectorAll('a.link-ip').forEach(a=>{if(a.parentElement?.querySelector('.device-ip-ping'))return;const ip=(a.textContent||'').trim();if(!ip)return;const wrap=document.createElement('span');wrap.innerHTML=ipPingMarkup(ip,(window.ipPingStatuses||{})[ip]);a.insertAdjacentElement('afterend',wrap);});bindIpPingButtons();}
function applyIpPingStatuses(){document.querySelectorAll('[data-ping-ip]').forEach(wrap=>{const ip=wrap.getAttribute('data-ping-ip');const s=(window.ipPingStatuses||{})[ip];const dot=wrap.querySelector('[data-ping-dot]');const btn=wrap.querySelector('[data-ping-button]');if(!dot||!btn)return;dot.className='device-ip-ping-dot '+(s?(s.online?'online':'offline'):'pending');wrap.title=ipPingTitle(s);btn.disabled=false;btn.textContent='Ping';});}
async function loadIpPingStatuses(){try{const r=await fetch('/api/ip/ping/status',{cache:'no-store'});if(!r.ok)return;const data=await r.json();window.ipPingStatuses=data.statuses||{};decorateDeviceIps();applyIpPingStatuses();}catch(e){console.debug('IP ping status load failed',e)}}
async function pingDeviceIp(ip,button){if(!ip||!button)return;button.disabled=true;button.textContent='…';const wrap=button.closest('[data-ping-ip]');const dot=wrap?.querySelector('[data-ping-dot]');if(dot)dot.className='device-ip-ping-dot pending';try{const r=await fetch('/api/ip/ping',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})});const data=await r.json();if(!r.ok||!data.ok)throw new Error(data.error||'Ping failed');window.ipPingStatuses=window.ipPingStatuses||{};window.ipPingStatuses[ip]=data.result;applyIpPingStatuses();}catch(e){window.ipPingStatuses=window.ipPingStatuses||{};window.ipPingStatuses[ip]={online:false,error:e.message,last_checked:Date.now()/1000};applyIpPingStatuses();alert(`Ping ${ip} failed: ${e.message}`);}}
function bindIpPingButtons(){document.querySelectorAll('[data-ping-button]').forEach(b=>{if(b.dataset.bound)return;b.dataset.bound='1';b.addEventListener('click',e=>{e.preventDefault();e.stopPropagation();pingDeviceIp(b.dataset.pingButton,b)});});}
function injectIpPingControls(){decorateDeviceIps();loadIpPingStatuses();}
function placeDeviceLabelsInColumn(){const body=document.getElementById('clients-body');const table=body?.closest('table');if(!body||!table)return;table.classList.add('device-table');const head=table.tHead?.rows?.[0];if(head&&!head.querySelector('.device-label-head')){const th=document.createElement('th');th.className='device-label-head';th.textContent='Label';head.insertBefore(th,head.cells[1]||null)}body.querySelectorAll('tr').forEach(row=>{if(row.querySelector('.device-label-cell'))return;const label=row.querySelector('.device-label-inline');if(!label)return;const td=document.createElement('td');td.className='device-label-cell';td.appendChild(label);row.insertBefore(td,row.cells[1]||null)});}

async function loadDeviceLabels(){try{const r=await adminFetch('/api/device/label',{cache:'no-store'});if(!r.ok)return;const data=await r.json();window.deviceLabels=data.labels||{};}catch(e){console.debug('device labels load failed',e)}}
async function editDeviceLabel(button){const key=button?.dataset?.deviceKey||'';if(!key)return;const current=button.dataset.deviceLabel||'';const value=window.prompt('Device label',current);if(value===null)return;const label=value.trim().slice(0,80);try{const r=await adminFetch('/api/device/label',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({device_key:key,label})});const data=await r.json();if(!r.ok||!data.ok)throw new Error(data.error||'Save failed');window.deviceLabels[key]=label;renderClients(window.__lastClients||[]);renderRecent(window.__lastRecent||[]);bindDeviceLabelButtons();}catch(e){alert('Could not save device label: '+e.message)}}
function bindDeviceLabelButtons(){document.querySelectorAll('.device-label-btn').forEach(b=>{if(b.dataset.bound)return;b.dataset.bound='1';b.addEventListener('click',()=>editDeviceLabel(b));})}
function renderClients(rows,force){ window.__lastClients=rows||[]; if(!force&&!document.getElementById('tab-devices')?.classList.contains('active'))return; document.getElementById('clients-body').innerHTML = (rows||[]).map(deviceRow).join(''); bindDeviceLabelButtons(); placeDeviceLabelsInColumn(); injectIpPingControls(); reapplyTableSorts(); }
let tableSortState = {recent:{key:null,dir:1}, clients:{key:null,dir:1}};
function rowSortValue(row,key,type){ const raw=row.dataset['sort'+key.charAt(0).toUpperCase()+key.slice(1)] ?? ''; return type==='number' ? (Number(raw)||0) : String(raw).toLowerCase(); }
function applySort(table,key,dir){ const th=[...table.querySelectorAll('th.sortable')].find(x=>x.dataset.sortKey===key); if(!th)return; table.querySelectorAll('th.sortable').forEach(x=>x.classList.remove('sort-asc','sort-desc')); th.classList.add(dir===1?'sort-asc':'sort-desc'); const type=th.dataset.sortType||'text'; const body=table.tBodies[0]; [...body.rows].sort((a,b)=>{const av=rowSortValue(a,key,type),bv=rowSortValue(b,key,type); if(av<bv)return -1*dir; if(av>bv)return 1*dir; return 0;}).forEach(r=>body.appendChild(r)); }
function bindSortableTables(){ document.querySelectorAll('th.sortable').forEach(th=>{ th.onclick=()=>{ const table=th.closest('table'); const name=table.id==='recent-table'?'recent':'clients'; const key=th.dataset.sortKey; const same=tableSortState[name].key===key; tableSortState[name]={key,dir:same?-tableSortState[name].dir:1}; applySort(table,key,tableSortState[name].dir); }; }); }
function reapplyTableSorts(){ const r=document.getElementById('recent-table'),c=document.getElementById('clients-table'); if(r&&tableSortState.recent.key)applySort(r,tableSortState.recent.key,tableSortState.recent.dir); if(c&&tableSortState.clients.key)applySort(c,tableSortState.clients.key,tableSortState.clients.dir); }
function setActiveTab(name){
  const requested = name === 'assessment' ? 'assessment' : name;
  const navName = requested === 'assessment' ? 'analytics' : requested;
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === navName));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.dataset.panel === requested));
  try{ localStorage.setItem('dnsInspectorTab', requested === 'assessment' ? 'analytics' : requested); }catch(e){}
  // The background /api/state poll skips re-rendering a tab's table while
  // it isn't visible (see renderRecent/renderClients); catch it up here
  // from the cached last-fetched rows instead of re-fetching.
  if (name === 'overview' && Array.isArray(window.__lastRecent)) renderRecent(window.__lastRecent, true);
  if (name === 'devices' && Array.isArray(window.__lastClients)) renderClients(window.__lastClients, true);
  if (typeof window.onAnalyticsTabChange === 'function') window.onAnalyticsTabChange(name);
  if (typeof window.onAssessmentTabChange === 'function') window.onAssessmentTabChange(name);
}
function chartBars(elId, items){
  const el=document.getElementById(elId); if(!el) return;
  if(!items || !items.length){ el.innerHTML='<div class="empty-state">No data yet.</div>'; return; }
  const max=Math.max(...items.map(x=>Number(x.value)||0),1);
  el.innerHTML=items.map(x=>{
    const pct=Math.max(2, Math.round(((Number(x.value)||0)/max)*100));
    const label=esc(x.label);
    const left=x.href ? `<a class="bar-label" href="${esc(x.href)}">${label}</a>` : `<span class="bar-label">${label}</span>`;
    return `<div class="bar-row">${left}<div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div><span class="bar-value">${esc(x.value)}</span></div>`;
  }).join('');
}
function renderStats(stats){
  if(!stats) return;
  chartBars('chart-domains', stats.domains);
  chartBars('chart-devices', stats.devices);
  chartBars('chart-vendors', stats.vendors);
  chartBars('chart-ips', stats.ips);
}
document.querySelectorAll('.tab-btn').forEach(b => b.addEventListener('click', () => setActiveTab(b.dataset.tab)));
// Navigation uses native anchors; no global click interception so IP/device links behave normally.
bindSortableTables();
const hasInspectContent = !!document.getElementById('inspect-root')?.textContent.trim();
try{
  if(currentQuery || hasInspectContent){ setActiveTab('overview'); }
  else if(prefs.defaultView && prefs.defaultView !== 'last' && ['overview','devices','analytics'].includes(prefs.defaultView)){ setActiveTab(prefs.defaultView); }
  else{
    const landing = (prefs.defaultView && prefs.defaultView !== 'last' && ['overview','devices','analytics'].includes(prefs.defaultView)) ? prefs.defaultView : 'analytics';
    setActiveTab(landing);
  }
}catch(e){}
renderStats({{ stats|tojson }});
function buildStateUrl(){const p=new URLSearchParams();if(currentQuery)p.set('q',currentQuery);if(recentFilters.status)p.set('status',recentFilters.status);if(recentFilters.newOnly)p.set('new','1');if(recentFilters.classification)p.set('classification',recentFilters.classification);if(recentFilters.severity)p.set('severity',recentFilters.severity);if(recentFilters.device)p.set('device',recentFilters.device);if(recentFilters.vendor)p.set('vendor',recentFilters.vendor);p.set('page',String(recentFilters.page));p.set('page_size',String(recentFilters.page_size));return '/api/state?'+p.toString()}
function applyRecentFilterChanges(){recentFilters.page=1;requestRefresh()}
let refreshTimer=null;
let refreshInFlight=false;
let refreshPending=false;
function scheduleRefresh(delay=refreshMs){
  if(refreshTimer) clearTimeout(refreshTimer);
  refreshTimer=setTimeout(()=>{ refreshTimer=null; refresh(); }, Math.max(250, delay));
}
function requestRefresh(){
  if(refreshTimer){ clearTimeout(refreshTimer); refreshTimer=null; }
  if(refreshInFlight){ refreshPending=true; return; }
  refresh();
}
async function refresh(force=false){
  showRefreshStatus();
  if(refreshInFlight){ refreshPending=true; return; }
  refreshInFlight=true;
  try{const r=await fetch(buildStateUrl(),{cache:'no-store'});if(!r.ok)return;const data=await r.json();renderRecent(data.recent);updateNewDetection(data.recent);renderRecentControls(data.recent_meta,data.filter_options);if(initialDomainSnapshot&&data.recent_meta?.new_domains?.length)showNewBanner(data.recent_meta.new_domains);renderClients(data.clients);renderStats(data.stats);renderObservability(data.observability);if(data.live)pushLiveSample(data.live.queries_in_window,data.live.window_seconds);if(data.inspect_html!==null)document.getElementById('inspect-root').innerHTML=data.inspect_html;const stamp=formatUpdated(data.updated);document.getElementById('last-update-time').textContent=stamp.time;document.getElementById('last-update-date').textContent=stamp.date}catch(e){console.debug('refresh failed',e)}finally{hideRefreshStatus();refreshInFlight=false;if(refreshPending){refreshPending=false;scheduleRefresh(0)}else{scheduleRefresh(refreshMs)}}}
document.querySelectorAll('[data-status-filter]').forEach(b=>b.addEventListener('click',()=>{recentFilters.status=b.dataset.statusFilter||'';applyRecentFilterChanges()}));document.getElementById('new-filter')?.addEventListener('click',()=>{recentFilters.newOnly=!recentFilters.newOnly;applyRecentFilterChanges()});for(const [id,key] of [['classification-filter','classification'],['severity-filter','severity'],['device-filter','device'],['vendor-filter','vendor']])document.getElementById(id)?.addEventListener('change',e=>{recentFilters[key]=e.target.value;applyRecentFilterChanges()});document.getElementById('page-size')?.addEventListener('change',e=>{recentFilters.page_size=Number(e.target.value)||50;applyRecentFilterChanges()});document.getElementById('page-prev')?.addEventListener('click',()=>{if(recentFilters.page>1){recentFilters.page--;requestRefresh()}});document.getElementById('page-next')?.addEventListener('click',()=>{if(recentFilters.page<recentMeta.pages){recentFilters.page++;requestRefresh()}});
const initialStamp=formatUpdated({{ updated|tojson }});document.getElementById('last-update-time').textContent=initialStamp.time;document.getElementById('last-update-date').textContent=initialStamp.date;loadDeviceLabels().then(()=>{renderClients(window.__lastClients||[]);renderRecent(window.__lastRecent||[]);bindDeviceLabelButtons();placeDeviceLabelsInColumn();});requestRefresh();
</script>
<script>
function observabilityDuration(seconds){let s=Math.max(0,Math.floor(Number(seconds)||0));const d=Math.floor(s/86400);s%=86400;const h=Math.floor(s/3600);s%=3600;const m=Math.floor(s/60);s%=60;if(d)return `${d}d ${h}h ${m}m`;if(h)return `${h}h ${m}m ${s}s`;if(m)return `${m}m ${s}s`;return `${s}s`}
function observabilityRam(value){const mb=Number(value);return Number.isFinite(mb)?`${mb.toFixed(mb>=100?0:1)} MB`:'—'}
function renderObservability(d){if(!d)return;const u=document.getElementById('obs-uptime');const m=document.getElementById('obs-memory');if(u)u.textContent=`Uptime ${observabilityDuration(d.uptime_seconds)}`;if(m)m.textContent=`RAM ${observabilityRam(d.ram_mb)}`}
</script>
<script>
// The live queries-per-window sample rides the existing /api/state refresh
// loop in the first <script> block (see pushLiveSample below) rather than a
// second high-frequency timer. Only the historical/status view below gets
// its own timer, and it ticks at the same cadence as that existing loop and
// only while the Analytics tab is actually visible.
const ANALYTICS_LIVE_MAX_SAMPLES = 100;
let analyticsLiveSamples = [];
let analyticsRange = '1h';
let analyticsCustomWindow = null; // {from, to} ISO dates -- only set while analyticsRange === 'custom'
function analyticsRangeQueryString(){
  if (analyticsRange === 'custom' && analyticsCustomWindow && analyticsCustomWindow.from && analyticsCustomWindow.to){
    return `range=custom&from=${encodeURIComponent(analyticsCustomWindow.from)}&to=${encodeURIComponent(analyticsCustomWindow.to)}`;
  }
  return `range=${encodeURIComponent(analyticsRange || '1h')}`;
}
let analyticsFullTimer = null;
/* Issue #61: performance/render-storm fixes. `/api/analytics/map` runs
   heavier server-side GeoIP aggregation than `/api/analytics`, so it gets
   its own bounded timer (mapRefreshMs()) instead of being fetched on every
   analytics poll tick. Every poll path below also gets an AbortController
   (cancels its own previous in-flight request) plus a monotonic sequence
   number, so a slow response can never overwrite state a newer request
   already replaced, and an in-flight guard so a slow interval tick can't
   pile up overlapping requests. */
let mapRefreshTimer = null;
let analyticsFetchController = null;
let mapFetchController = null;
let analyticsFetchSeq = 0;
let mapFetchSeq = 0;
let mapFetchInFlight = false;
let mapLastFingerprint = null;
const MAP_MIN_REFRESH_MS = 20000;
function mapRefreshMs(){ return Math.max(MAP_MIN_REFRESH_MS, refreshMs * 3); }
/* Lightweight client-side perf trace (Issue #61): records HTTP-fetch time
   separately from render time for the last few analytics/map cycles so a
   slow interaction can be attributed to network vs. main-thread rendering
   without needing a browser profiler. Read via window.__dnsInspectorPerf or
   Settings > Diagnostics. Never itself triggers a network request. */
window.__dnsInspectorPerf = { analytics: [], map: [] };
function perfNow(){ return (window.performance && typeof window.performance.now === 'function') ? window.performance.now() : Date.now(); }
function recordPerf(kind, fetchStartedAt, renderStartedAt, renderEndedAt){
  const bucket = window.__dnsInspectorPerf[kind] || (window.__dnsInspectorPerf[kind] = []);
  bucket.push({
    fetchMs: Math.round(renderStartedAt - fetchStartedAt),
    renderMs: Math.round(renderEndedAt - renderStartedAt),
    totalMs: Math.round(renderEndedAt - fetchStartedAt),
    at: Date.now(),
  });
  if (bucket.length > 20) bucket.shift();
}

const STATUS_COLOR_VAR = {Allowed:'--sem-ok', Blocked:'--sem-blocked', Mixed:'--sem-warn', Unknown:'--sem-info'};
function renderStatusBreakdown(breakdown){
  const el = document.getElementById('status-breakdown'); if (!el) return;
  const b = breakdown || {};
  const total = Math.max(1, Number(b.All)||0);
  const keys = ['Allowed','Blocked','Mixed','Unknown'];
  const bar = keys.map(k => { const v = Number(b[k])||0; const pct = (v/total*100).toFixed(2); return v ? `<div class="status-seg" style="width:${pct}%;background:var(${STATUS_COLOR_VAR[k]})" title="${esc(k)}: ${esc(v)}"></div>` : ''; }).join('');
  const legend = keys.map(k => `<span class="legend-item"><span class="legend-dot" style="background:var(${STATUS_COLOR_VAR[k]})"></span>${esc(k)} <b>${esc(Number(b[k])||0)}</b></span>`).join('');
  el.innerHTML = `<div class="status-bar">${bar}</div><div class="legend-row">${legend}</div>`;
}
function statusSemClass(status){
  if (status === 'Blocked') return 'sem-blocked';
  if (status === 'Allowed') return 'sem-ok';
  if (status === 'Mixed') return 'sem-warn';
  return 'sem-info';
}
function renderRecentActivity(domains, devices){
  const dEl = document.getElementById('activity-domains');
  if (dEl){
    const rows = domains || [];
    dEl.innerHTML = rows.length ? rows.map(r => `<div class="activity-row"><span><span class="sem-dot ${statusSemClass(r.status)}"></span><a href="/search?q=${encodeURIComponent(r.domain)}">${esc(r.domain)}</a></span><span class="sub">${esc(r.status)} &middot; ${esc(ageText(r.last_seen))} ago</span></div>`).join('') : '<div class="empty-state">No recent activity yet.</div>';
  }
  const vEl = document.getElementById('activity-devices');
  if (vEl){
    const rows = devices || [];
    vEl.innerHTML = rows.length ? rows.map(d => `<div class="activity-row"><span><span class="sem-dot sem-live"></span><a href="/device?key=${encodeURIComponent(d.device_key)}">${esc(d.label)}</a></span><span class="sub">${esc(ageText(d.last_seen))} ago &middot; ${esc(d.requests)} total</span></div>`).join('') : '<div class="empty-state">No recent activity yet.</div>';
  }
}
function renderLiveHero(windowSeconds){
  const rateEl = document.getElementById('live-rate-value');
  const latest = analyticsLiveSamples[analyticsLiveSamples.length - 1];
  if (rateEl) rateEl.textContent = latest ? latest.count : '—';
  renderMetricVisual('live-sparkline', analyticsLiveSamples, '--sem-live', `Queries in the last ${windowSeconds||60}s`);
  const card = document.getElementById('live-card');
  if (card){ card.classList.remove('visual-analog','visual-digital','visual-specter'); card.classList.add('visual-'+(prefs.analyticsStyle||'digital')); }
  const gaugeSlot = document.getElementById('live-gauge-slot');
  if (gaugeSlot){
    const vals = analyticsLiveSamples.map(s=>s.count).filter(v=>v!=null);
    const peak = Math.max(1, ...vals);
    const current = latest ? latest.count : 0;
    const pct = Math.max(0, Math.min(1, current / peak));
    const style = prefs.analyticsStyle || 'digital';
    if (style === 'analog') gaugeSlot.innerHTML = analogGaugeSvg(pct, current, peak);
    else if (style === 'specter') gaugeSlot.innerHTML = specterRadarSvg(pct, current);
    else gaugeSlot.innerHTML = digitalRingSvg(pct, current);
  }
}
function pushLiveSample(n, windowSeconds){
  analyticsLiveSamples.push({count: Number(n)||0});
  if (analyticsLiveSamples.length > ANALYTICS_LIVE_MAX_SAMPLES) analyticsLiveSamples.shift();
  renderLiveHero(windowSeconds);
}
/* Interactive click-to-investigate on the "DNS activity over time" chart
   (Issue #88 #2): the selected bucket stays highlighted across polling
   refreshes (matched by exact timestamp, not index, since the underlying
   points array shifts every refresh), and the popover shows only real data
   returned by /api/analytics/interval -- no invented root cause. */
let selectedIntervalBucket = null; // {range, t}
function renderIntervalDetail(detail){
  const el = document.getElementById('chart-query-volume-detail'); if (!el) return;
  if (detail === null){ el.hidden = true; el.innerHTML = ''; return; }
  el.hidden = false;
  if (detail === 'loading'){ el.innerHTML = '<div class="interval-detail-loading">Loading interval detail&hellip;</div>'; return; }
  if (!detail || !detail.ok){
    el.innerHTML = `<div class="interval-detail-error">${esc((detail && detail.error) || 'Unable to load interval detail.')}</div>`;
    return;
  }
  let when = detail.bucket_start;
  try{ when = new Date(detail.bucket_start).toLocaleString([], {month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'}); }catch(e){}
  const granularityLabel = detail.granularity === 'exact' ? 'Exact interval' : detail.granularity === 'hourly_aggregate' ? 'Reconstructed from bounded hourly history' : 'No retained data';
  const ratioText = detail.vs_average_ratio != null ? `${detail.vs_average_ratio}&times; average` : '&mdash;';
  const newDomainsCount = Array.isArray(detail.new_domains) ? detail.new_domains.length : (detail.new_domains_count || 0);
  const statusEntries = Object.entries(detail.status || {}).filter(([,v]) => v);
  const statusRow = statusEntries.length
    ? statusEntries.map(([k,v]) => `<span class="interval-status-chip interval-status-${esc(k.toLowerCase())}">${esc(k)}: ${esc(v)}</span>`).join('')
    : '<span class="interval-status-chip">No status breakdown for this interval</span>';
  const domainItem = (d) => `<li><a href="/search?q=${encodeURIComponent(d.domain)}">${esc(d.domain)}</a><span>${esc(d.count)}</span></li>`;
  const deviceItem = (d) => `<li><a href="/device?key=${encodeURIComponent(d.device_key)}">${esc(d.label)}</a><span>${esc(d.count)}</span></li>`;
  const topDomains = (detail.top_domains||[]).length ? detail.top_domains.map(domainItem).join('') : '<li class="empty">No domain-level detail retained for this interval.</li>';
  const topDevices = (detail.top_devices||[]).length ? detail.top_devices.map(deviceItem).join('') : '<li class="empty">No device-level detail retained for this interval.</li>';
  el.innerHTML = `
    <div class="interval-detail-head">
      <div><strong>${esc(when)}</strong><span class="interval-detail-sub">${esc(granularityLabel)}</span></div>
      <button type="button" class="interval-detail-close" aria-label="Close interval detail">&times;</button>
    </div>
    <div class="interval-detail-stats">
      <div><b>${esc(detail.query_count ?? 0)}</b><span>Queries</span></div>
      <div><b>${ratioText}</b><span>vs period avg</span></div>
      <div><b>${esc(newDomainsCount)}</b><span>New domains</span></div>
    </div>
    <div class="interval-status-row">${statusRow}</div>
    ${detail.note ? `<div class="interval-detail-note">${esc(detail.note)}</div>` : ''}
    <div class="interval-detail-lists">
      <div><h4>Top domains</h4><ul>${topDomains}</ul></div>
      <div><h4>Top devices</h4><ul>${topDevices}</ul></div>
    </div>`;
  el.querySelector('.interval-detail-close')?.addEventListener('click', () => {
    selectedIntervalBucket = null;
    renderIntervalDetail(null);
    if (window.__lastAnalyticsPayload) renderQueryVolumeChart(window.__lastAnalyticsPayload);
  });
}
function selectIntervalBucket(point, rangeKey){
  selectedIntervalBucket = {range: rangeKey, t: point.t};
  if (window.__lastAnalyticsPayload) renderQueryVolumeChart(window.__lastAnalyticsPayload);
  renderIntervalDetail('loading');
  fetch(`/api/analytics/interval?${analyticsRangeQueryString()}&bucket_start=${encodeURIComponent(point.t)}`, {cache:'no-store'})
    .then(r => r.json())
    .then(detail => { if (selectedIntervalBucket && selectedIntervalBucket.t === point.t) renderIntervalDetail(detail); })
    .catch(() => renderIntervalDetail({ok:false, error:'Interval request failed.'}));
}
function sumSeriesPoints(points){ return (points||[]).reduce((a,p) => a + (Number(p.count)||0), 0); }
/* Executive-overview "Visibility report" card (Issue #88 #1/#9): every figure
   here is derived from the exact same analytics payload the charts below
   render from -- no separate fetch, no invented findings, no risk verdicts. */
function renderVisibilityReport(data){
  const el = document.getElementById('visibility-report'); if (!el) return;
  const qPoints = (data.series?.queries?.points || []).filter(p => p.count != null);
  const total = sumSeriesPoints(qPoints);
  const avg = qPoints.length ? total / qPoints.length : 0;
  let peak = null;
  qPoints.forEach(p => { if (!peak || p.count > peak.count) peak = p; });
  const peakRatio = (peak && avg) ? peak.count / avg : 0;
  const newDomains = sumSeriesPoints(data.series?.new_domains?.points);
  const newDevices = sumSeriesPoints(data.series?.new_devices?.points);
  const blocked = Number(data.status_breakdown?.Blocked || 0), allowed = Number(data.status_breakdown?.Allowed || 0);
  const knownTotal = blocked + allowed;
  const blockedPct = knownTotal ? Math.round((blocked / knownTotal) * 1000) / 10 : null;
  const rangeLabel = data.series?.queries?.label || data.range;

  const kpis = [
    ['Queries', mapCompactNumber(total), rangeLabel],
    ['Peak interval', peak ? mapCompactNumber(peak.count) : '—', peak ? (peakRatio >= 2 ? `${peakRatio.toFixed(1)}× average` : 'within normal range') : 'no data yet'],
    ['New domains', mapCompactNumber(newDomains), 'this period'],
    ['New devices', mapCompactNumber(newDevices), 'this period'],
    ['Active devices', `${data.active_devices ?? '—'} / ${data.total_devices ?? '—'}`, 'last 5 minutes'],
    ['Blocked share', blockedPct != null ? blockedPct + '%' : '—', 'current classification'],
  ];
  const kpiHtml = kpis.map(([label, value, sub]) => `<div class="report-kpi"><span class="report-kpi-label">${esc(label)}</span><span class="report-kpi-value">${esc(value)}</span><span class="report-kpi-sub">${esc(sub)}</span></div>`).join('');

  const observations = [];
  if (peak && peakRatio >= 2){
    let when = peak.t; try{ when = new Date(peak.t).toLocaleString([], {month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'}); }catch(e){}
    observations.push({tone:'warn', title:`Traffic peaked at ${mapCompactNumber(peak.count)} queries`, body:`About ${peakRatio.toFixed(1)}× the period average, in the interval starting ${esc(when)}. Select it for the exact breakdown.`, clickable:true});
  }
  if (knownTotal){
    if (blockedPct >= 20) observations.push({tone:'blocked', title:`${blockedPct}% of classified domains are currently Blocked`, body:'Reflects the current AdGuard classification state, not a period-specific count.'});
    else observations.push({tone:'ok', title:`${blockedPct}% of classified domains are currently Blocked`, body:'Classification mix is predominantly Allowed/Mixed for the tracked domain set.'});
  }
  if (newDomains > 0) observations.push({tone:'info', title:`${newDomains} new domain${newDomains === 1 ? '' : 's'} observed this period`, body:'First-seen domains within the selected time range.'});
  const obsHtml = observations.length
    ? observations.map((o, i) => `<div class="report-observation report-observation-${esc(o.tone)}"${o.clickable ? ' role="button" tabindex="0" data-report-obs="' + i + '"' : ''}><b>${esc(o.title)}</b><p>${o.body}</p></div>`).join('')
    : '<div class="report-observation">No notable observations for this period yet.</div>';

  el.innerHTML = `
    <div class="report-headline"><div><h3>${esc(rangeLabel)}</h3><span class="stats-note" style="margin:0">Updated ${esc(new Date(data.updated).toLocaleTimeString())}</span></div></div>
    <div class="report-kpi-row">${kpiHtml}</div>
    <div class="report-observations">${obsHtml}</div>`;
  if (peak && peakRatio >= 2){
    el.querySelector('[data-report-obs]')?.addEventListener('click', () => selectIntervalBucket(peak, data.range));
    el.querySelector('[data-report-obs]')?.addEventListener('keydown', (evt) => { if (evt.key === 'Enter' || evt.key === ' '){ evt.preventDefault(); selectIntervalBucket(peak, data.range); } });
  }
}
function renderQueryVolumeChart(data){
  const points = data.series?.queries?.points || [];
  let selectedIndex = null;
  if (selectedIntervalBucket && selectedIntervalBucket.range === data.range){
    const idx = points.findIndex(p => p.t === selectedIntervalBucket.t);
    if (idx !== -1) selectedIndex = idx;
  }
  renderMetricVisual('chart-query-volume', points, '--sem-info', 'DNS queries', {
    selectedIndex,
    onPointClick: (point) => selectIntervalBucket(point, data.range),
  });
}
async function fetchAnalyticsFull(){
  const seq = ++analyticsFetchSeq;
  if (analyticsFetchController) analyticsFetchController.abort();
  const controller = new AbortController();
  analyticsFetchController = controller;
  const fetchStartedAt = perfNow();
  try{
    const r = await fetch(`/api/analytics?${analyticsRangeQueryString()}`, {cache:'no-store', signal: controller.signal});
    if (seq !== analyticsFetchSeq) return; // superseded by a newer request while this one was in flight
    if (!r.ok){
      if (analyticsRange === 'custom'){
        const errEl = document.getElementById('analytics-custom-error');
        try{ const body = await r.json(); if (errEl) errEl.textContent = body.error || 'Unable to load that custom range.'; }catch(e){ if (errEl) errEl.textContent = 'Unable to load that custom range.'; }
      }
      return;
    }
    const data = await r.json();
    if (seq !== analyticsFetchSeq) return; // superseded while awaiting the response body
    const renderStartedAt = perfNow();
    window.__lastAnalyticsPayload = data;
    renderVisibilityReport(data);
    renderQueryVolumeChart(data);
    renderMetricVisual('chart-new-domains', data.series?.new_domains?.points, '--sem-ok', 'New domains');
    renderMetricVisual('chart-new-devices', data.series?.new_devices?.points, '--sem-ok', 'New devices');
    renderStatusBreakdown(data.status_breakdown);
    renderRecentActivity(data.recent_domains, data.recent_devices);
    renderInstrumentGauges(data);
    const tAllowed=document.getElementById('tile-allowed'); if(tAllowed) tAllowed.textContent = data.status_breakdown?.Allowed ?? '—';
    const tBlocked=document.getElementById('tile-blocked'); if(tBlocked) tBlocked.textContent = data.status_breakdown?.Blocked ?? '—';
    const tDevices=document.getElementById('tile-devices'); if(tDevices) tDevices.textContent = data.active_devices ?? '—';
    const tNewDomains=document.getElementById('tile-new-domains'); if(tNewDomains) tNewDomains.textContent = data.new_domains_24h ?? '—';
    document.querySelectorAll('[data-analytics-range]').forEach(b => b.classList.toggle('active', b.dataset.analyticsRange === analyticsRange));
    recordPerf('analytics', fetchStartedAt, renderStartedAt, perfNow());
    // /api/analytics/map is intentionally NOT fetched here -- see
    // startAnalyticsPolling()/mapRefreshMs(): it runs heavier server-side
    // GeoIP aggregation and gets its own bounded-cadence timer so it can
    // never turn every analytics poll into a map-rebuild storm.
  }catch(e){ if (e?.name !== 'AbortError') console.debug('analytics refresh failed', e); }
}
/* DNS Destinations map (0.8.5.1; Visual 2.0 in Issue #37/0.8.6): aggregated
   GeoIP data from its own endpoint/cache (see `/api/analytics/map`) so it
   can be recomputed on a different, server-bounded cadence than the rest of
   the Analytics payload. Two modes share the same bundled offline basemap:
   Countries (country-level bubbles -- works with only a country GeoIP
   database) and Destinations (real per-IP coordinates from an optional
   city/coordinate GeoIP database, grid-clustered client-side so nearby
   points stay readable and separate again on zoom -- never an invented
   coordinate for a country-only address). Map appearance and the bubble/
   cluster sizing metric are `dnsInspectorPrefs` preferences, independent of
   the application theme/Analytics visual style. */
const MAP_W = 720, MAP_H = 360;
/* Issue #56 follow-up: two independent selectors replace the old single
   `mapStyle` preset (BEMO Dark/Aurora/White/Minimal). MAP_BASEMAPS is the
   structural rendering (background treatment plus how observed activity is
   drawn: heat glow, scattered density particles, a pin glyph, or bright
   NOC-grid points); MAP_THEMES only recolors the intensity ramp/palette on
   top of whichever basemap is active -- see mapEntityMarkup()/
   mapThemeColor() below for how they combine. */
const MAP_BASEMAPS = ['satellite-heat', 'satellite-density', 'real-pins', 'dark-noc'];
const MAP_THEMES = ['indigo-gold', 'cyan', 'bemo-accent'];
const MAP_METRICS = ['observations', 'unique_ips', 'domains'];
let mapSelectedCountry = null;
let mapSelectedDestinationKey = null;
let mapZoom = 1;
let mapViewCenter = { cx: MAP_W / 2, cy: MAP_H / 2 };
let mapLastPayload = null;
function mapActiveBasemap(){ return MAP_BASEMAPS.includes(prefs.mapBasemap) ? prefs.mapBasemap : 'satellite-heat'; }
function mapActiveTheme(){ return MAP_THEMES.includes(prefs.mapTheme) ? prefs.mapTheme : 'bemo-accent'; }
/* Issue #63: real raster tile basemap, additive to the always-available
   offline dot-matrix world below. A single zoom-0 tile already covers the
   *entire* Mercator-clipped world in one image, so this never requests a
   tile set bigger than one image per basemap and needs no per-tile
   pan/zoom math; it loads asynchronously like any other <img>, is cached
   by the browser the same way, and the widget keeps rendering the existing
   offline dot-matrix (unchanged, in its own equirectangular projection)
   until/unless that image actually finishes loading. Dark NOC intentionally
   keeps its stylized treatment rather than a satellite/street photo (the
   issue explicitly allows this). These are the same class of no-API-key
   default providers commonly used for this purpose (OpenStreetMap standard
   tiles, Esri World Imagery); see docs/MAP_BASEMAP.md for their documented
   attribution/usage-policy requirements -- this session's sandbox had no
   outbound network access to re-verify those live, the same limitation
   recorded against several other 0.8.5.x GeoIP-provider hand-offs in
   docs/CURRENT_STATE.md, so an operator should confirm both URLs still
   resolve and still match their current policy before relying on this in
   production. Both are overridable by editing MAP_TILE_PROVIDERS. */
const MAP_TILE_PROVIDERS = {
  'satellite-heat': {
    url: 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/0/0/0',
    attribution: 'Tiles &copy; Esri &mdash; Source: Esri, Maxar, Earthstar Geographics, and the GIS User Community',
  },
  'satellite-density': {
    url: 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/0/0/0',
    attribution: 'Tiles &copy; Esri &mdash; Source: Esri, Maxar, Earthstar Geographics, and the GIS User Community',
  },
  'real-pins': {
    url: 'https://tile.openstreetmap.org/0/0/0.png',
    attribution: '&copy; OpenStreetMap contributors',
  },
};
function mapTileProviderFor(basemap){ return MAP_TILE_PROVIDERS[basemap] || null; }
/* idle: nothing attempted yet for this basemap; loading: an <img> request is
   in flight; ready: it loaded, Mercator projection + tiles are active;
   failed: it didn't load, offline dot-matrix stays active. Persists across
   re-renders (module-level) even though the DOM node carrying it is torn
   down and recreated every render, same as every other map render state. */
let mapTileState = { basemap: null, status: 'idle' };
function mapUsesMercatorProjection(){
  const basemap = mapActiveBasemap();
  return !!(mapTileProviderFor(basemap) && mapTileState.basemap === basemap && mapTileState.status === 'ready');
}
/* Standard Web Mercator "global pixel at zoom 0, normalized to 0..1" --
   the same formula every slippy-map tile library uses -- scaled onto our
   existing MAP_W x MAP_H canvas so it lines up with a real zoom-0 tile
   image stretched to fill that same canvas (see mapEnsureTileLayer()). */
function mapProjectMercator(lat, lon){
  const clampedLat = Math.max(-85.05112878, Math.min(85.05112878, lat));
  const latRad = clampedLat * Math.PI / 180;
  const px = (lon + 180) / 360;
  const py = (1 - Math.log(Math.tan(Math.PI / 4 + latRad / 2)) / Math.PI) / 2;
  return { x: px * MAP_W, y: py * MAP_H };
}
/* The offline dot-matrix silhouette (WORLD_LAND_D/mapWorldDots() below) was
   hand-authored directly in this equirectangular pixel space, not derived
   from real lat/lon -- so it only stays aligned with real observed
   coordinates while this plain equirectangular projection is what's
   actually on screen. Real tile imagery uses true Web Mercator instead
   (mapProjectMercator above); the two are never shown at once (see
   .map-tiles-active hiding .map-world-dots), so each stays internally
   consistent with whichever background is actually active. */
function mapProject(lat, lon){
  if (mapUsesMercatorProjection()) return mapProjectMercator(lat, lon);
  return { x: (lon + 180) / 360 * MAP_W, y: (90 - lat) / 180 * MAP_H };
}
/* Creates/refreshes the tile <img> for the active basemap (a no-op when the
   basemap has no configured provider, e.g. Dark NOC) and toggles
   .map-tiles-active on the wrapper. Called by mapFinishRender() after every
   render, since the whole wrap (and any previous tile <img>) is replaced by
   `el.innerHTML = mapBaseSvg(...)` like the rest of this widget -- the
   browser's own HTTP cache (not this code) is what keeps a re-requested,
   already-loaded tile URL cheap across those re-renders. Loading is always
   asynchronous and never blocks bubble/particle rendering above it; the
   *first* successful load for a given basemap re-renders once (via
   renderDestinationMap) so markers can move from the equirectangular
   fallback projection to the real Mercator one -- every render after that
   already uses Mercator from the start, so no further extra re-render
   happens. A failed load simply leaves the existing offline dot-matrix
   showing; it never throws or blocks the rest of the widget. */
function mapEnsureTileLayer(wrapEl){
  const basemap = mapActiveBasemap();
  const provider = mapTileProviderFor(basemap);
  wrapEl.classList.toggle('map-tiles-active', mapUsesMercatorProjection());
  if (!provider) return;
  const layer = document.createElement('div');
  layer.className = 'map-tile-layer';
  const img = document.createElement('img');
  img.className = 'map-tile';
  img.alt = '';
  img.decoding = 'async';
  const alreadyReady = mapTileState.basemap === basemap && mapTileState.status === 'ready';
  if (alreadyReady) img.classList.add('map-tile-loaded');
  img.addEventListener('load', () => {
    img.classList.add('map-tile-loaded');
    const wasReady = mapTileState.basemap === basemap && mapTileState.status === 'ready';
    mapTileState = { basemap, status: 'ready' };
    if (!wasReady && mapLastPayload) renderDestinationMap(mapLastPayload);
  });
  img.addEventListener('error', () => {
    if (mapTileState.basemap === basemap && mapTileState.status === 'ready') return;
    mapTileState = { basemap, status: 'failed' };
  });
  img.src = provider.url;
  layer.appendChild(img);
  wrapEl.insertBefore(layer, wrapEl.firstChild);
  // A sibling of both the tile layer and the <svg> (not a child of the tile
  // layer's own stacking context) so its z-index reliably places it above
  // both regardless of which one is currently on top.
  const attribution = document.createElement('div');
  attribution.className = 'map-tile-attribution';
  attribution.innerHTML = provider.attribution;
  wrapEl.appendChild(attribution);
}
/* Bundled/offline-safe world-landmass silhouette (Issue #33): a simplified,
   hand-authored equirectangular outline of the seven continents plus a few
   large islands, in the same 720x360 projection as mapProject()/the
   graticule below, so the background renders without any GeoIP database,
   network access or external map provider. It is intentionally stylized --
   not survey-accurate coastline data -- purely so the widget always shows a
   recognizable world map rather than an empty card. */
/* 0.8.5.4 (Issue #39): the original hand-authored rings below were mostly
   long, dead-straight segments (a real offender: a perfectly horizontal
   100px-long edge across the top of Eurasia), which read as an obviously
   low-poly flat silhouette rather than a coastline. Each ring's longest,
   flattest edges got one or two extra vertices with a small inward/outward
   nudge -- still hand-authored/stylized, not survey-accurate data, but no
   longer dominated by a handful of giant straight lines. Vertex order and
   overall silhouette/bounding shape are unchanged, so bubble/cluster
   placement relative to each landmass is unaffected. */
const WORLD_LAND_D = [
  'M24,50 L50,60 L80,40 L118,32 L160,36 L210,40 L240,70 L254,84 L226,90 L212,100 L200,130 L180,122 L166,128 L184,138 L200,162 L192,160 L150,136 L130,124 L116,106 L112,88 L100,72 L90,64 L57,61 Z',
  'M270,14 L295,12 L320,16 L320,40 L270,60 L250,40 Z',
  'M206,156 L236,160 L258,170 L290,190 L284,206 L280,220 L274,226 L264,236 L246,250 L230,270 L224,290 L216,270 L218,250 L218,230 L204,211 L198,192 L200,180 L206,166 Z',
  'M348,110 L380,106 L402,116 L424,118 L431,137 L446,156 L462,156 L462,176 L442,184 L438,194 L430,220 L424,238 L396,248 L384,216 L386,198 L378,184 L366,172 L350,170 L326,150 L340,116 Z',
  'M446,204 L460,212 L454,230 L448,220 Z',
  'M342,94 L350,82 L370,78 L382,70 L410,38 L440,44 L480,36 L510,32 L540,34 L570,33 L610,35 L640,34 L670,35 L700,44 L716,52 L680,60 L640,90 L620,96 L602,118 L576,138 L576,158 L560,166 L568,178 L556,150 L544,136 L520,154 L514,164 L506,150 L500,138 L482,130 L472,130 L464,150 L446,156 L430,116 L432,108 L414,106 L398,100 L386,90 L378,92 Z',
  'M344,74 L362,74 L354,62 L348,64 L340,70 Z',
  'M620,90 L644,90 L640,110 L624,114 L620,100 Z',
  'M550,170 L572,186 L590,196 L580,192 L560,176 Z',
  'M578,172 L598,172 L594,188 L576,184 Z',
  'M586,224 L600,212 L620,204 L634,204 L642,202 L646,202 L650,214 L666,236 L660,254 L640,256 L632,250 L622,244 L590,248 L586,232 Z',
  'M706,256 L716,256 L708,272 L696,270 Z',
  'M0,360 L0,344 L60,338 L150,346 L260,336 L380,344 L500,334 L620,344 L720,338 L720,360 Z'
].join(' ');
/* Issue #56 follow-up: the world is now rendered as a dense dot-matrix
   sampled from WORLD_LAND_D's own vector rings, instead of one flat filled
   silhouette (the low-poly look the issue asked to replace). Every ring is
   a simple closed outline with no holes, so a plain ray-cast point-in-ring
   test unioned across rings is enough -- no new geometry, no bundled
   raster asset, no network access. The sample grid runs once per page load
   and is memoized (WORLD_DOT_CACHE). */
function mapLandRings(){
  return WORLD_LAND_D.split('Z').map(seg => seg.trim()).filter(Boolean).map(seg => {
    const nums = (seg.match(/-?\\d+(?:\\.\\d+)?/g) || []).map(Number);
    const pts = [];
    for (let i = 0; i + 1 < nums.length; i += 2) pts.push([nums[i], nums[i + 1]]);
    return pts;
  });
}
function mapPointInRing(x, y, ring){
  let inside = false;
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++){
    const xi = ring[i][0], yi = ring[i][1], xj = ring[j][0], yj = ring[j][1];
    if (((yi > y) !== (yj > y)) && (x < (xj - xi) * (y - yi) / (yj - yi) + xi)) inside = !inside;
  }
  return inside;
}
let WORLD_DOT_CACHE = null;
function mapWorldDots(){
  if (WORLD_DOT_CACHE) return WORLD_DOT_CACHE;
  const rings = mapLandRings();
  const step = 6.2;
  const dots = [];
  for (let y = step / 2; y < MAP_H; y += step){
    for (let x = step / 2; x < MAP_W; x += step){
      for (let r = 0; r < rings.length; r++){
        if (mapPointInRing(x, y, rings[r])){ dots.push({ x: +x.toFixed(1), y: +y.toFixed(1) }); break; }
      }
    }
  }
  WORLD_DOT_CACHE = dots;
  return dots;
}
/* "The data is the map": observed activity recolors/brightens the real
   world dots that fall within a ratio-scaled radius of each entity's own
   real coordinate, instead of only drawing a separate overlay on top of an
   inert background. `entities` is a small array of already-projected
   {x, y, ratio} points -- never a fabricated location. */
function mapActiveDotRatios(entities){
  const active = new Map();
  if (!entities || !entities.length) return active;
  const dots = mapWorldDots();
  entities.forEach(en => {
    const influence = 6 + en.ratio * 16;
    const inf2 = influence * influence;
    for (let i = 0; i < dots.length; i++){
      const dx = dots[i].x - en.x, dy = dots[i].y - en.y;
      if (dx * dx + dy * dy <= inf2){
        const prev = active.get(i) || 0;
        if (en.ratio > prev) active.set(i, en.ratio);
      }
    }
  });
  return active;
}
function mapLandmassSvg(entities){
  const dots = mapWorldDots();
  const active = mapActiveDotRatios(entities);
  const theme = mapActiveTheme();
  let out = '';
  for (let i = 0; i < dots.length; i++){
    const d = dots[i];
    const ratio = active.get(i);
    if (ratio == null){ out += `<circle class="map-world-dot" cx="${d.x}" cy="${d.y}" r="1"/>`; continue; }
    out += `<circle class="map-world-dot map-world-dot-active" cx="${d.x}" cy="${d.y}" r="${(1.2 + ratio * 1.4).toFixed(1)}" style="fill:${mapThemeColor(ratio, theme)}"/>`;
  }
  return `<g class="map-world-dots">${out}</g>`;
}
function mapBaseLayers(entities){ return `${mapLandmassSvg(entities)}${mapGraticule()}`; }
function mapStatusBanner(text, actionHtml){
  if (!text) return '';
  return `<div class="map-status-banner" role="status" aria-live="polite">${text}${actionHtml ? `<div class="map-status-action">${actionHtml}</div>` : ''}</div>`;
}
function mapViewBoxAttr(){
  const vw = MAP_W / mapZoom, vh = MAP_H / mapZoom;
  const vx = Math.min(Math.max(mapViewCenter.cx - vw / 2, 0), MAP_W - vw);
  const vy = Math.min(Math.max(mapViewCenter.cy - vh / 2, 0), MAP_H - vh);
  return `${vx.toFixed(1)} ${vy.toFixed(1)} ${vw.toFixed(1)} ${vh.toFixed(1)}`;
}
function mapBaseSvg(label, inner, entities){
  const basemap = mapActiveBasemap();
  const theme = mapActiveTheme();
  return `<div class="destination-map-wrap" data-map-basemap="${esc(basemap)}" data-map-theme="${esc(theme)}"><svg viewBox="${mapViewBoxAttr()}" class="destination-map-svg" role="img" aria-label="${esc(label)}" tabindex="0" style="touch-action:none">${mapBaseLayers(entities)}${inner || ''}</svg></div>`;
}
function mapGraticule(){
  let lines = '';
  for (let lon=-180; lon<=180; lon+=30){ const x=((lon+180)/360*MAP_W).toFixed(1); lines += `<line class="map-grid-line" x1="${x}" y1="0" x2="${x}" y2="${MAP_H}"/>`; }
  for (let lat=-90; lat<=90; lat+=30){ const y=((90-lat)/180*MAP_H).toFixed(1); lines += `<line class="map-grid-line" x1="0" y1="${y}" x2="${MAP_W}" y2="${y}"/>`; }
  const eqY = (MAP_H/2).toFixed(1);
  return `<g class="map-graticule">${lines}<line class="map-grid-line map-grid-equator" x1="0" y1="${eqY}" x2="${MAP_W}" y2="${eqY}"/></g>`;
}
/* Bubble/cluster sizing metric (Issue #37): one of Observations (default),
   Unique IPs or Domains -- the same selected metric drives both Countries
   mode bubbles and Destinations mode clusters, via each entity's own
   already-aggregated field, never a client-recomputed guess. */
function mapMetricValue(entity){
  const metric = MAP_METRICS.includes(prefs.mapMetric) ? prefs.mapMetric : 'observations';
  if (metric === 'unique_ips') return entity.unique_ip_count ?? 0;
  if (metric === 'domains') return entity.domain_count ?? 0;
  return entity.observation_count ?? 0;
}
function mapMetricLabel(){
  const metric = MAP_METRICS.includes(prefs.mapMetric) ? prefs.mapMetric : 'observations';
  if (metric === 'unique_ips') return 'unique IPs';
  if (metric === 'domains') return 'domains';
  return 'observations';
}
/* Issue #56: shared green -> lime/yellow -> orange -> red traffic-intensity
   scale. `ratio` is always the same value/max-in-view fraction that already
   drives bubble/cluster radius, so a marker's size and color are always two
   views of one underlying intensity rather than independently chosen. The
   gradient stops here are duplicated (as literal HSL values) by the
   `.map-legend-gradient` CSS background and the legend's three sample dots,
   so the legend can never visually drift from what a marker actually renders. */
const MAP_INTENSITY_STOPS = [
  {t: 0, h: 152, s: 68, l: 42},
  {t: 0.35, h: 84, s: 72, l: 45},
  {t: 0.65, h: 40, s: 92, l: 50},
  {t: 1, h: 2, s: 82, l: 52},
];
/* Issue #56 follow-up: `mapTheme` remaps the same low->high intensity
   ordering onto a different palette while keeping MAP_INTENSITY_STOPS (the
   default "BEMO / Dark Accent" theme, and the literal stops the CSS legend
   gradient is built from) unchanged in meaning. */
const MAP_THEME_STOPS = {
  'bemo-accent': MAP_INTENSITY_STOPS,
  'indigo-gold': [
    {t: 0, h: 248, s: 42, l: 34},
    {t: 0.4, h: 235, s: 55, l: 46},
    {t: 0.7, h: 46, s: 70, l: 55},
    {t: 1, h: 45, s: 96, l: 62},
  ],
  'cyan': [
    {t: 0, h: 199, s: 40, l: 26},
    {t: 0.4, h: 192, s: 60, l: 40},
    {t: 0.7, h: 186, s: 85, l: 52},
    {t: 1, h: 178, s: 95, l: 66},
  ],
};
function mapInterpolateStops(ratio, stops){
  const t = Math.max(0, Math.min(1, Number(ratio) || 0));
  let a = stops[0], b = stops[stops.length - 1];
  for (let i = 0; i < stops.length - 1; i++){
    if (t >= stops[i].t && t <= stops[i + 1].t){ a = stops[i]; b = stops[i + 1]; break; }
  }
  const span = (b.t - a.t) || 1;
  const f = (t - a.t) / span;
  const h = a.h + (b.h - a.h) * f, s = a.s + (b.s - a.s) * f, l = a.l + (b.l - a.l) * f;
  return `hsl(${h.toFixed(0)},${s.toFixed(0)}%,${l.toFixed(0)}%)`;
}
function mapIntensityColor(ratio){
  return mapInterpolateStops(ratio, MAP_INTENSITY_STOPS);
}
function mapThemeColor(ratio, theme){
  return mapInterpolateStops(ratio, MAP_THEME_STOPS[theme] || MAP_INTENSITY_STOPS);
}
function mapCompactNumber(n){
  n = Number(n) || 0;
  if (n >= 1000000) return (n / 1000000).toFixed(1).replace(/\\.0$/, '') + 'M';
  if (n >= 1000) return (n / 1000).toFixed(1).replace(/\\.0$/, '') + 'k';
  return String(n);
}
/* Deterministic, seeded particle placement (Issue #56 follow-up): particle
   offsets derive from each entity's own stable id (country code or
   destination-cluster grid key) via a tiny FNV-1a hash + mulberry32 PRNG --
   never Math.random() -- so the same entity's "cloud" renders in the same
   relative spots on every refresh instead of jumping around. Particles are
   a bounded intensity visualization anchored on the entity's one real
   coordinate; they never represent a fabricated location. */
function mapSeedFromString(s){
  let h = 2166136261;
  for (let i = 0; i < s.length; i++){ h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return h >>> 0;
}
function mapMulberry32(seed){
  let a = seed >>> 0;
  return function(){
    a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function mapParticleCap(basemap){
  if (basemap === 'real-pins') return 1;
  if (basemap === 'satellite-heat') return 5;
  return 14; // satellite-density, dark-noc
}
function mapParticleCount(ratio, cap){
  if (cap <= 1) return cap;
  const n = 1 + Math.round(Math.pow(Math.max(0, Math.min(1, ratio)), 0.55) * (cap - 1));
  return Math.max(1, Math.min(cap, n));
}
function mapParticleOffsets(id, count, spread){
  const rnd = mapMulberry32(mapSeedFromString(String(id)));
  const pts = [];
  for (let i = 0; i < count; i++){
    const angle = rnd() * Math.PI * 2;
    const dist = Math.sqrt(rnd()) * spread;
    pts.push({ dx: Math.cos(angle) * dist, dy: Math.sin(angle) * dist });
  }
  return pts;
}
/* One shared renderer for both Countries-mode bubbles and Destinations-mode
   clusters: an invisible hit-area (a small marker's real click/tap target
   should not depend on its visual size), the basemap-appropriate activity
   particles/pin (all colored via mapThemeColor()), the existing anchor
   circle (unchanged sqrt-scaled sizing), an optional pulse ring and an
   optional compact count label. Everything lives inside one focusable
   <g data-...> wrapper so clicking/tapping/keyboard-activating any particle
   in a dense cluster resolves to the same real entity as the anchor. */
function mapEntityMarkup(opts){
  const { id, attr, x, y, ratio, color, r, selected, ariaSelected, label, countLabel } = opts;
  const basemap = mapActiveBasemap();
  const cap = mapParticleCap(basemap);
  const count = mapParticleCount(ratio, cap);
  const spread = 3 + ratio * (basemap === 'satellite-heat' ? 9 : 13);
  const offsets = (basemap === 'real-pins') ? [] : mapParticleOffsets(id, count, spread);
  let particles = '';
  if (basemap === 'satellite-heat'){
    particles = offsets.map(o => `<circle class="map-particle map-particle-heat" cx="${(x + o.dx).toFixed(1)}" cy="${(y + o.dy).toFixed(1)}" r="${(4 + ratio * 8).toFixed(1)}" style="fill:${color}"/>`).join('');
  } else if (basemap === 'dark-noc'){
    particles = offsets.map(o => `<rect class="map-particle map-particle-noc" x="${(x + o.dx - 1.1).toFixed(1)}" y="${(y + o.dy - 1.1).toFixed(1)}" width="2.2" height="2.2" style="fill:${color}"/>`).join('');
  } else if (basemap === 'satellite-density'){
    particles = offsets.map(o => `<circle class="map-particle map-particle-density" cx="${(x + o.dx).toFixed(1)}" cy="${(y + o.dy).toFixed(1)}" r="1.5" style="fill:${color}"/>`).join('');
  }
  const pin = basemap === 'real-pins'
    ? `<path class="map-pin" d="M${x.toFixed(1)},${(y - Number(r) - 6).toFixed(1)} c-4,0 -6,3 -6,6 c0,4 6,10 6,10 c0,0 6,-6 6,-10 c0,-3 -2,-6 -6,-6 Z" style="fill:${color};stroke:${color}"/>`
    : '';
  const pulse = ratio >= 0.72
    ? `<circle class="map-bubble-pulse-ring" style="stroke:${color}" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${r}"/>`
    : '';
  const hit = `<circle class="map-hit-area" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${Math.max(Number(r) + 4, 10)}"/>`;
  const anchor = `<circle class="map-bubble${selected}" style="fill:${color};stroke:${color}" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${r}"/>`;
  return `<g class="map-entity" ${attr}="${esc(id)}" tabindex="0" role="button" aria-pressed="${ariaSelected}" aria-label="${esc(label)}">${hit}${pulse}${particles}${pin}${anchor}${countLabel || ''}<title>${label}</title></g>`;
}
/* Destination coordinate provenance (Issue #88 known-datacenter follow-up):
   the map/report/PDF must all label *how* a destination point was placed
   rather than presenting every bubble as equally precise. */
function provenanceLabel(entity){
  if (!entity || !entity.provenance) return null;
  if (entity.provenance === 'city_geoip') return 'City GeoIP';
  if (entity.provenance === 'known_datacenter') return 'Known datacenter' + (entity.provider ? ` (${entity.provider}${entity.region ? ' · ' + entity.region : ''})` : '');
  if (entity.provenance === 'mixed') return 'Mixed provenance';
  return null;
}
function renderMapDetail(entity, kind){
  const el = document.getElementById('destination-map-detail'); if (!el) return;
  if (!entity){ el.hidden = true; el.innerHTML = ''; return; }
  el.hidden = false;
  const closeBtn = '<button type="button" class="map-detail-close" id="map-detail-close-btn" aria-label="Close details">&times;</button>';
  if (kind === 'destination'){
    const domains = (entity.sample_domains||[]).map(d => `<span class="chip">${esc(d)}</span>`).join('') || '<span class="sub">No sampled domains</span>';
    const ipCount = entity.unique_ip_count || 1;
    const where = entity.city ? `${entity.city}, ${entity.country_name || entity.country_code || 'unknown location'}` : (entity.country_name || entity.country_code || 'Unknown location');
    const provLabel = provenanceLabel(entity);
    const provBadge = provLabel ? `<span class="provenance-badge provenance-${esc(entity.provenance)}">${esc(provLabel)}</span>` : '';
    el.innerHTML = closeBtn + `<h3>${esc(where)} <span class="sub">${esc(ipCount)} IP${ipCount===1?'':'s'}</span> ${provBadge}</h3>`
      + `<div class="stats-note">${esc(entity.observation_count)} observed destination observation${entity.observation_count===1?'':'s'} &middot; ${esc(entity.domain_count)} domain${entity.domain_count===1?'':'s'} &middot; approximate coordinates from observed DNS destinations, not a verified physical location${entity.provenance === 'known_datacenter' ? ' &middot; region-derived from a curated known-datacenter range, not an exact server location' : ''}</div>`
      + `<div class="map-detail-row"><b>Domains</b><div class="chip-row">${domains}</div></div>`;
  } else {
    const domains = (entity.sample_domains||[]).map(d => `<span class="chip">${esc(d)}</span>`).join('') || '<span class="sub">No sampled domains</span>';
    const devices = (entity.sample_devices||[]).map(d => `<span class="chip">${esc(d)}</span>`).join('') || '<span class="sub">No associated devices</span>';
    el.innerHTML = closeBtn + `<h3>${esc(entity.country_name)} <span class="sub">${esc(entity.country_code)}</span></h3>`
      + `<div class="stats-note">${esc(entity.observation_count)} destination observation${entity.observation_count===1?'':'s'} &middot; ${esc(entity.domain_count)} domain${entity.domain_count===1?'':'s'} &middot; ${esc(entity.device_count)} device${entity.device_count===1?'':'s'}</div>`
      + `<div class="map-detail-row"><b>Domains</b><div class="chip-row">${domains}</div></div>`
      + `<div class="map-detail-row"><b>Devices</b><div class="chip-row">${devices}</div></div>`;
  }
  document.getElementById('map-detail-close-btn')?.addEventListener('click', () => {
    mapSelectedCountry = null; mapSelectedDestinationKey = null;
    renderMapDetail(null);
    if (mapLastPayload) renderDestinationMap(mapLastPayload);
  });
}
/* Issue #63: one shared selection path for a country, used by both a map
   marker click/keydown and a country-breakdown row click/keydown, so the
   two never diverge. The detail card is rendered *before* the (more
   expensive) full map re-render -- the technical guidance in the issue is
   to avoid a click flow that risks losing/invalidating detail state behind
   a full re-render, so "show the real detail immediately" always happens
   first and does not depend on that re-render succeeding. */
function mapSelectCountry(code, opts){
  opts = opts || {};
  const data = mapLastPayload;
  if (!data) return;
  const countries = data.countries || [];
  const entity = countries.find(c => c.country_code === code);
  if (!entity) return;
  const toggle = opts.toggle !== false;
  mapSelectedCountry = (toggle && mapSelectedCountry === code) ? null : code;
  mapSelectedDestinationKey = null;
  if (mapSelectedCountry && prefs.mapMode !== 'countries'){
    prefs.mapMode = 'countries';
    savePrefs();
    syncMapControls();
  }
  if (mapSelectedCountry && opts.centerZoom && entity.centroid){
    const [lat, lon] = entity.centroid;
    const proj = mapProject(lat, lon);
    mapZoom = Math.max(mapZoom, 3);
    mapViewCenter = { cx: proj.x, cy: proj.y };
    mapClampCenter();
  }
  renderMapDetail(mapSelectedCountry ? entity : null, 'country');
  renderDestinationMap(data);
}
/* Issue #63: real country breakdown/ranking, driven by the unbounded
   `data.countries` list already returned by /api/analytics/map (every
   geolocated country, not only the bounded subset with a plotted map
   bubble/centroid) -- no second backend query, no invented metrics. */
let mapBreakdownSortMode = 'metric';
function renderMapBreakdownHistory(data){
  const el = document.getElementById('destination-map-history'); if (!el) return;
  const h = data?.history;
  const prov = data?.coverage?.provenance;
  const provParts = [];
  if (prov){
    if (prov.city_geoip) provParts.push(`${esc(prov.city_geoip)} City GeoIP`);
    if (prov.known_datacenter) provParts.push(`${esc(prov.known_datacenter)} Known datacenter`);
    if (prov.country_only) provParts.push(`${esc(prov.country_only)} Country only`);
    if (prov.unmapped) provParts.push(`${esc(prov.unmapped)} Unmapped`);
  }
  const provText = provParts.length ? ` Destination observations by provenance: ${provParts.join(' &middot; ')}.` : '';
  if (!h || !h.tracked_domains_all_time){ el.innerHTML = provText.trim(); return; }
  let since = '';
  if (h.tracking_since){
    const d = new Date(h.tracking_since);
    if (!isNaN(d.getTime())) since = ` since ${d.toLocaleDateString()}`;
  }
  el.innerHTML = `Tracking ${esc(h.tracked_domains_all_time)} domain${h.tracked_domains_all_time===1?'':'s'} with observed destinations all-time${since} -- this history is stored in SQLite and persists across restarts.${provText}`;
}
function renderMapBreakdown(data){
  const list = document.getElementById('map-breakdown-list'); if (!list) return;
  const sortLabel = document.getElementById('map-breakdown-sort-label');
  if (sortLabel) sortLabel.textContent = mapBreakdownSortMode === 'name' ? 'Name' : 'Metric';
  const countries = (data?.countries || []).slice();
  if (!countries.length){
    list.innerHTML = '<li class="map-breakdown-empty">No geolocated countries yet.</li>';
    return;
  }
  if (mapBreakdownSortMode === 'name') countries.sort((a, b) => String(a.country_name||'').localeCompare(String(b.country_name||'')));
  else countries.sort((a, b) => mapMetricValue(b) - mapMetricValue(a));
  const totalObservations = countries.reduce((s, c) => s + (c.observation_count || 0), 0);
  list.innerHTML = countries.map(c => {
    const selected = mapSelectedCountry === c.country_code;
    const share = totalObservations ? Math.round((c.observation_count / totalObservations) * 1000) / 10 : 0;
    const deviceBit = (c.device_count != null) ? ` &middot; ${esc(c.device_count)} device${c.device_count===1?'':'s'}` : '';
    return `<li><button type="button" class="map-breakdown-row${selected ? ' map-breakdown-row-selected' : ''}" data-breakdown-country="${esc(c.country_code)}" aria-pressed="${selected}">`
      + `<span class="map-breakdown-row-top"><span>${esc(c.country_name)}</span><span class="map-breakdown-row-metric">${mapCompactNumber(mapMetricValue(c))}</span></span>`
      + `<span class="map-breakdown-row-sub">${esc(c.observation_count)} obs &middot; ${esc(c.unique_ip_count)} IP${c.unique_ip_count===1?'':'s'} &middot; ${esc(c.domain_count)} domain${c.domain_count===1?'':'s'}${deviceBit} &middot; ${share}% of geolocated</span>`
      + `</button></li>`;
  }).join('');
  list.querySelectorAll('[data-breakdown-country]').forEach(btn => {
    btn.addEventListener('click', () => mapSelectCountry(btn.getAttribute('data-breakdown-country'), { toggle: false, centerZoom: true }));
  });
  bindMapBreakdownKeyboardNav(list);
}
/* Roving-tabindex arrow-key navigation (Issue #88 accessibility pass): the
   country list is a real button-per-row list already reachable via Tab, but
   without this every row was a separate Tab stop. Up/Down/Home/End now move
   focus one row at a time -- Enter/Space activation is native <button>
   behavior and needs no extra code. */
function bindMapBreakdownKeyboardNav(list){
  const items = Array.from(list.querySelectorAll('[data-breakdown-country]'));
  items.forEach((btn, i) => { btn.tabIndex = i === 0 ? 0 : -1; });
  if (list.dataset.keynavBound) return;
  list.dataset.keynavBound = '1';
  list.addEventListener('keydown', (e) => {
    if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(e.key)) return;
    const currentItems = Array.from(list.querySelectorAll('[data-breakdown-country]'));
    const idx = currentItems.indexOf(document.activeElement);
    if (idx === -1) return;
    let nextIdx = idx;
    if (e.key === 'ArrowDown') nextIdx = Math.min(idx + 1, currentItems.length - 1);
    else if (e.key === 'ArrowUp') nextIdx = Math.max(idx - 1, 0);
    else if (e.key === 'Home') nextIdx = 0;
    else if (e.key === 'End') nextIdx = currentItems.length - 1;
    e.preventDefault();
    currentItems.forEach((el, i) => { el.tabIndex = i === nextIdx ? 0 : -1; });
    currentItems[nextIdx].focus();
  });
}
document.getElementById('map-breakdown-sort-btn')?.addEventListener('click', () => {
  mapBreakdownSortMode = mapBreakdownSortMode === 'name' ? 'metric' : 'name';
  if (mapLastPayload) renderMapBreakdown(mapLastPayload);
});
/* Bounded client-side grid clustering (Issue #37): nearby real destination
   coordinates merge into one cluster bubble whose observation/domain counts
   are the real sum of its members -- no observation is lost, just visually
   grouped. The grid cell shrinks as `mapZoom` increases, so zooming into a
   cluster reveals smaller clusters/individual points instead of one giant
   blob; this is a bounded analytics-widget heuristic, not a general
   quad-tree/supercluster implementation. */
function clusterDestinationPoints(points, zoom){
  const cell = Math.max(3, 26 / zoom);
  const cells = new Map();
  points.forEach(p => {
    if (p.lat == null || p.lon == null) return;
    const {x, y} = mapProject(p.lat, p.lon);
    const key = Math.floor(x / cell) + ':' + Math.floor(y / cell);
    let bucket = cells.get(key);
    if (!bucket){ bucket = { key, sumX: 0, sumY: 0, points: [], observation_count: 0, domain_count: 0 }; cells.set(key, bucket); }
    bucket.points.push(p);
    bucket.sumX += x; bucket.sumY += y;
    bucket.observation_count += (p.observation_count || 0);
    bucket.domain_count += (p.domain_count || 0);
  });
  return Array.from(cells.values()).map(b => {
    const provenanceSet = new Set(b.points.map(p => p.provenance).filter(Boolean));
    const singlePoint = b.points.length === 1 ? b.points[0] : null;
    return {
      key: b.key,
      x: b.sumX / b.points.length,
      y: b.sumY / b.points.length,
      points: b.points,
      unique_ip_count: b.points.length,
      observation_count: b.observation_count,
      domain_count: b.domain_count,
      country_code: b.points[0].country_code,
      country_name: b.points[0].country_name,
      city: singlePoint ? singlePoint.city : null,
      provenance: provenanceSet.size === 1 ? Array.from(provenanceSet)[0] : (provenanceSet.size > 1 ? 'mixed' : null),
      provider: singlePoint ? singlePoint.provider : null,
      region: singlePoint ? singlePoint.region : null,
      sample_domains: Array.from(new Set(b.points.flatMap(p => p.sample_domains || []))).slice(0, 5),
    };
  });
}
function renderCountriesMode(data){
  const el = document.getElementById('destination-map'); if (!el) return;
  const cov = data?.coverage || {};
  const unknownDomains = data?.unknown?.domain_count || 0;
  const allCountries = data?.countries || [];
  if (!allCountries.length){
    // Two honestly distinct reasons this can be empty (Issue #39 diagnostics):
    // either nothing has been observed yet, or observed public IPs exist but
    // matched no range in the loaded database.
    const banner = data?.diagnostics?.state === 'no_country_matches'
      ? mapStatusBanner('Observed public destination IPs exist, but none matched a range in the loaded GeoIP database. Double-check the database covers the address families you expect (IPv4/IPv6) and is current.')
      : mapStatusBanner('No geolocated destinations yet. This fills in as domains are queried and their actual DNS answers get matched against the configured GeoIP database.');
    el.innerHTML = mapBaseSvg('World map; no geolocated destinations yet', banner);
    mapFinishRender(el);
    renderMapDetail(null);
    return;
  }
  // Only geolocated countries with a plotted-bubble centroid (COUNTRY_CENTROIDS
  // is a bounded subset, see docs/GEOIP.md) can appear on the map itself; a
  // country missing one is still real data, so it must stay visible in the
  // coverage line below rather than silently vanishing.
  const countries = allCountries.filter(c => c.centroid);
  const unplottedCount = allCountries.length - countries.length;
  const plottedNote = unplottedCount
    ? `${esc(countries.length)} of ${esc(allCountries.length)} geolocated countries plotted (${esc(unplottedCount)} lack bubble coordinates but are counted below)`
    : `${esc(countries.length)} countr${countries.length===1?'y':'ies'} plotted`;
  const coverageNote = `<div class="stats-note">${esc(cov.geolocated_pct ?? 0)}% of observed destinations geolocated &middot; ${plottedNote} &middot; ${esc(unknownDomains)} domain${unknownDomains===1?'':'s'} unmapped</div>`;
  if (!countries.length){
    el.innerHTML = mapBaseSvg(
      'World map; geolocated countries have no plotted coordinates yet',
      mapStatusBanner(`${esc(allCountries.length)} countr${allCountries.length===1?'y':'ies'} geolocated, but none have map bubble coordinates configured yet -- see the country list below.`)
    ) + coverageNote;
    mapFinishRender(el);
    renderMapDetail(null);
    return;
  }
  const maxVal = Math.max(1, ...countries.map(c => mapMetricValue(c)));
  const theme = mapActiveTheme();
  /* Issue #56: size and color are both driven by the same relative-to-max
     `ratio` -- size via sqrt (so one dominant country can't visually swallow
     the map) and color via mapThemeColor() (low=few -> high=many, per the
     selected theme). A ratio at/above 0.72 also gets the existing pulse
     ring (previously only the single top country did), so "large + hot"
     markers read as genuinely high activity rather than a decorative
     one-off. Issue #56 follow-up: the same {x, y, ratio} feeds both the
     entity marker below and the active-world-dot recoloring in mapBaseSvg(). */
  const entitiesForDots = countries.map(c => {
    const [lat, lon] = c.centroid; const {x, y} = mapProject(lat, lon);
    return { x, y, ratio: mapMetricValue(c) / maxVal };
  });
  const bubbles = countries.map(c => {
    const [lat, lon] = c.centroid;
    const {x, y} = mapProject(lat, lon);
    const ratio = mapMetricValue(c) / maxVal;
    const color = mapThemeColor(ratio, theme);
    const r = (4 + Math.sqrt(ratio) * 18).toFixed(1);
    const selected = mapSelectedCountry === c.country_code ? ' map-bubble-selected' : '';
    const label = `${c.country_name}: ${esc(c.observation_count)} destination observations, ${esc(c.domain_count)} domains`;
    const countLabel = Number(r) >= 9
      ? `<text class="map-bubble-count" x="${x.toFixed(1)}" y="${y.toFixed(1)}">${mapCompactNumber(mapMetricValue(c))}</text>`
      : '';
    return mapEntityMarkup({ id: c.country_code, attr: 'data-country', x, y, ratio, color, r, selected, ariaSelected: mapSelectedCountry === c.country_code, label, countLabel });
  }).join('');
  el.innerHTML = mapBaseSvg('Observed DNS destinations by country', bubbles, entitiesForDots) + coverageNote;
  mapFinishRender(el);
  // Issue #63: bubble clicks/keydown reuse the exact same mapSelectCountry()
  // path a country-breakdown row uses, so the two selection paths can never
  // diverge in behavior.
  el.querySelectorAll('[data-country]').forEach(node => {
    node.addEventListener('click', () => {
      if (mapWasDragging) return;
      mapSelectCountry(node.getAttribute('data-country'));
    });
    node.addEventListener('keydown', (e) => {
      if (e.key !== 'Enter' && e.key !== ' ' && e.key !== 'Spacebar') return;
      e.preventDefault();
      mapSelectCountry(node.getAttribute('data-country'));
    });
  });
}
function renderDestinationsMode(data, capabilities){
  const el = document.getElementById('destination-map'); if (!el) return;
  if (!capabilities.coordinates && !capabilities.datacenter){
    el.innerHTML = mapBaseSvg(
      'World map; coordinate-level destination data unavailable',
      mapStatusBanner(
        'Coordinate-level destination data is unavailable &mdash; only a country GeoIP database is configured. Configure a city/coordinate-capable GeoIP database, or a curated known-datacenter database, to enable Destinations mode, or switch to Countries. See docs/GEOIP.md.',
        '<button type="button" class="map-zoom-btn" id="map-switch-countries-btn">Switch to Countries</button>'
      )
    );
    mapFinishRender(el);
    renderMapDetail(null);
    const switchBtn = document.getElementById('map-switch-countries-btn');
    if (switchBtn) switchBtn.addEventListener('click', () => {
      prefs.mapMode = 'countries'; savePrefs(); syncMapControls();
      if (mapLastPayload) renderDestinationMap(mapLastPayload);
    });
    return;
  }
  const points = (data?.destinations || []).filter(p => p.lat != null && p.lon != null);
  if (!points.length){
    el.innerHTML = mapBaseSvg(
      'World map; no geolocated destination coordinates yet',
      mapStatusBanner('No geolocated destination coordinates yet. This fills in as domains are queried and their actual DNS answers get matched against the configured city/coordinate or known-datacenter GeoIP database.')
    );
    mapFinishRender(el);
    renderMapDetail(null);
    return;
  }
  const clusters = clusterDestinationPoints(points, mapZoom);
  const maxVal = Math.max(1, ...clusters.map(c => mapMetricValue(c)));
  const theme = mapActiveTheme();
  const cov = data?.coverage || {};
  const coverageNote = `<div class="stats-note">${esc(cov.geolocated_pct ?? 0)}% of observed destinations geolocated &middot; ${esc(clusters.length)} cluster${clusters.length===1?'':'s'} &middot; ${esc(points.length)} destination point${points.length===1?'':'s'} plotted (bounded)</div>`;
  const entitiesForDots = clusters.map(c => ({ x: c.x, y: c.y, ratio: mapMetricValue(c) / maxVal }));
  const bubbles = clusters.map(c => {
    const ratio = mapMetricValue(c) / maxVal;
    const color = mapThemeColor(ratio, theme);
    const r = (4 + Math.sqrt(ratio) * 15).toFixed(1);
    const selected = mapSelectedDestinationKey === c.key ? ' map-bubble-selected' : '';
    const provLabel = provenanceLabel(c);
    const label = (c.unique_ip_count > 1
      ? `${esc(c.unique_ip_count)} destinations: ${esc(c.observation_count)} observations, ${esc(c.domain_count)} domains`
      : `${esc(c.city || c.country_name || c.country_code || 'Unknown')}: ${esc(c.observation_count)} observations, ${esc(c.domain_count)} domains`) + (provLabel ? ` — ${esc(provLabel)}` : '');
    const countLabel = c.unique_ip_count > 1
      ? `<text class="map-cluster-count" x="${c.x.toFixed(1)}" y="${c.y.toFixed(1)}">${c.unique_ip_count > 99 ? '99+' : c.unique_ip_count}</text>`
      : (Number(r) >= 9 ? `<text class="map-bubble-count" x="${c.x.toFixed(1)}" y="${c.y.toFixed(1)}">${mapCompactNumber(mapMetricValue(c))}</text>` : '');
    return mapEntityMarkup({ id: c.key, attr: 'data-cluster', x: c.x, y: c.y, ratio, color, r, selected, ariaSelected: mapSelectedDestinationKey === c.key, label, countLabel });
  }).join('');
  el.innerHTML = mapBaseSvg('Observed DNS destinations by coordinate, clustered', bubbles, entitiesForDots) + coverageNote;
  mapFinishRender(el);
  const activateCluster = (key) => {
    const cluster = clusters.find(c => c.key === key);
    if (!cluster) return;
    if (cluster.unique_ip_count > 1 && mapZoom < 8){
      mapZoom = Math.min(8, mapZoom * 2);
      mapViewCenter = { cx: cluster.x, cy: cluster.y };
      if (mapLastPayload) renderDestinationMap(mapLastPayload);
      return;
    }
    mapSelectedDestinationKey = (mapSelectedDestinationKey === key) ? null : key;
    // Issue #63: show the real detail immediately, before the (more
    // expensive) full bubble re-render, so the click path never risks
    // losing/invalidating the detail state behind that re-render.
    renderMapDetail(mapSelectedDestinationKey ? cluster : null, 'destination');
    renderDestinationsMode(data, capabilities);
  };
  el.querySelectorAll('[data-cluster]').forEach(node => {
    node.addEventListener('click', () => {
      if (mapWasDragging) return;
      activateCluster(node.getAttribute('data-cluster'));
    });
    node.addEventListener('keydown', (e) => {
      if (e.key !== 'Enter' && e.key !== ' ' && e.key !== 'Spacebar') return;
      e.preventDefault();
      activateCluster(node.getAttribute('data-cluster'));
    });
  });
}
function renderDestinationMap(data){
  const el = document.getElementById('destination-map'); if (!el) return;
  mapLastPayload = data;
  const provider = data?.provider || {};
  const capabilities = data?.capabilities || {};
  const subtitleEl = document.getElementById('destination-map-subtitle');
  const mode = prefs.mapMode === 'destinations' ? 'destinations' : 'countries';
  if (subtitleEl){
    subtitleEl.textContent = mode === 'destinations'
      ? 'Real observed DNS destination IPs plotted by coordinate and clustered when nearby — City GeoIP points are exact-coordinate matches; Known datacenter points are region-derived from a curated provider database, not a verified physical server location.'
      : 'Country-level aggregate of resolved DNS response IPs — not verified physical server locations. CDN, anycast and multi-region destinations resolve to whichever country answered.';
  }
  const legendMetricEl = document.getElementById('map-legend-metric-label');
  if (legendMetricEl) legendMetricEl.textContent = mapMetricLabel();
  // Issue #63: breakdown/history render from the exact same payload as the
  // map itself, regardless of mode/diagnostic state below.
  renderMapBreakdown(data);
  renderMapBreakdownHistory(data);
  const diagState = data?.diagnostics?.state;
  if (diagState === 'load_failed'){
    el.innerHTML = mapBaseSvg(
      'World map; GeoIP database failed to load',
      mapStatusBanner('GEOIP_DB_PATH is set, but the configured database failed to load. Check that the file exists at that path inside the container and is readable, then restart. See docs/GEOIP.md.')
    );
    mapFinishRender(el);
    renderMapDetail(null);
    return;
  }
  if (!provider.configured && !capabilities.coordinates && !capabilities.datacenter){
    el.innerHTML = mapBaseSvg(
      'World map; GeoIP not configured, destinations unmapped',
      mapStatusBanner('No GeoIP database configured &mdash; destinations are reported as unmapped rather than guessed. See docs/GEOIP.md to enable the map.')
    );
    mapFinishRender(el);
    renderMapDetail(null);
    return;
  }
  if (mode === 'destinations'){
    renderDestinationsMode(data, capabilities);
    return;
  }
  renderCountriesMode(data);
}
/* Real map navigation (Issue #39 / 0.8.5.4): pointer drag to pan, wheel/pinch
   to zoom toward the cursor, arrow keys to pan and +/-/0 to zoom/reset when
   the map has focus. Pointer Events unify mouse/touch/pen, so this is also
   the touch implementation -- `touch-action:none` on the svg (see
   mapBaseSvg()) stops the browser from scrolling the page during a drag.
   Every render call replaces the map's innerHTML (see mapFinishRender()
   below), so listeners are attached fresh each time rather than assumed to
   survive a re-render. */
let mapWasDragging = false;
let mapDragState = null;
function mapClampZoom(z){ return Math.min(8, Math.max(1, z)); }
function mapClampCenter(){
  const vw = MAP_W / mapZoom, vh = MAP_H / mapZoom;
  mapViewCenter = {
    cx: Math.min(Math.max(mapViewCenter.cx, vw / 2), MAP_W - vw / 2),
    cy: Math.min(Math.max(mapViewCenter.cy, vh / 2), MAP_H - vh / 2),
  };
}
/* Zooms toward a client-space point (cursor or pinch midpoint) instead of the
   viewport center, the same feel MapLibre/most real map widgets use. */
function mapApplyZoomAt(newZoom, clientX, clientY, svgEl){
  newZoom = mapClampZoom(newZoom);
  if (newZoom === mapZoom) return;
  const rect = svgEl.getBoundingClientRect();
  const fx = rect.width ? (clientX - rect.left) / rect.width : 0.5;
  const fy = rect.height ? (clientY - rect.top) / rect.height : 0.5;
  const oldVw = MAP_W / mapZoom, oldVh = MAP_H / mapZoom;
  const oldVx = Math.min(Math.max(mapViewCenter.cx - oldVw / 2, 0), MAP_W - oldVw);
  const oldVy = Math.min(Math.max(mapViewCenter.cy - oldVh / 2, 0), MAP_H - oldVh);
  const worldX = oldVx + fx * oldVw, worldY = oldVy + fy * oldVh;
  mapZoom = newZoom;
  mapViewCenter = { cx: worldX, cy: worldY };
  mapClampCenter();
}
function mapBoundingBoxOf(points){
  if (!points.length) return null;
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  points.forEach(p => {
    const {x, y} = mapProject(p.lat, p.lon);
    minX = Math.min(minX, x); maxX = Math.max(maxX, x);
    minY = Math.min(minY, y); maxY = Math.max(maxY, y);
  });
  return {minX, minY, maxX, maxY};
}
/* Optional fit-to-data (Issue #39 item 9): only runs on explicit "Fit" click,
   never automatically on refresh, so the viewport doesn't jump around while
   an operator is looking at it. */
function mapFitToData(){
  if (!mapLastPayload) return;
  const mode = prefs.mapMode === 'destinations' ? 'destinations' : 'countries';
  const points = mode === 'destinations'
    ? (mapLastPayload.destinations || []).filter(p => p.lat != null && p.lon != null)
    : (mapLastPayload.countries || []).filter(c => c.centroid).map(c => ({lat: c.centroid[0], lon: c.centroid[1]}));
  const box = mapBoundingBoxOf(points);
  if (!box) return;
  const padX = Math.max(24, (box.maxX - box.minX) * 0.3);
  const padY = Math.max(24, (box.maxY - box.minY) * 0.3);
  const w = Math.min(MAP_W, Math.max(20, (box.maxX - box.minX) + padX * 2));
  const h = Math.min(MAP_H, Math.max(20, (box.maxY - box.minY) + padY * 2));
  mapZoom = mapClampZoom(Math.min(MAP_W / w, MAP_H / h));
  mapViewCenter = { cx: (box.minX + box.maxX) / 2, cy: (box.minY + box.maxY) / 2 };
  mapClampCenter();
  renderDestinationMap(mapLastPayload);
}
/* Attaches pan/zoom/keyboard handlers to a freshly-rendered map svg. Called
   by mapFinishRender() after every `el.innerHTML = mapBaseSvg(...)`. */
function mapAttachInteraction(el){
  const svgEl = el.querySelector('svg.destination-map-svg');
  if (!svgEl) return;
  svgEl.addEventListener('pointerdown', (e) => {
    if (e.pointerType === 'mouse' && e.button !== 0) return;
    mapDragState = { pointerId: e.pointerId, startX: e.clientX, startY: e.clientY, startCenter: {...mapViewCenter}, moved: false };
    try { svgEl.setPointerCapture(e.pointerId); } catch (err) { /* not fatal */ }
    svgEl.classList.add('map-dragging');
  });
  svgEl.addEventListener('pointermove', (e) => {
    if (!mapDragState || mapDragState.pointerId !== e.pointerId) return;
    const rect = svgEl.getBoundingClientRect();
    if (!rect.width || !rect.height) return;
    const vw = MAP_W / mapZoom, vh = MAP_H / mapZoom;
    const dx = (e.clientX - mapDragState.startX) * (vw / rect.width);
    const dy = (e.clientY - mapDragState.startY) * (vh / rect.height);
    if (Math.abs(e.clientX - mapDragState.startX) > 3 || Math.abs(e.clientY - mapDragState.startY) > 3) mapDragState.moved = true;
    mapViewCenter = { cx: mapDragState.startCenter.cx - dx, cy: mapDragState.startCenter.cy - dy };
    mapClampCenter();
    svgEl.setAttribute('viewBox', mapViewBoxAttr());
  });
  const endDrag = (e) => {
    if (!mapDragState || mapDragState.pointerId !== e.pointerId) return;
    mapWasDragging = mapDragState.moved;
    mapDragState = null;
    svgEl.classList.remove('map-dragging');
    // A drag-release over a bubble/cluster also fires a native `click`;
    // clear the flag on the next tick so that click sees it but the
    // following interaction doesn't.
    setTimeout(() => { mapWasDragging = false; }, 0);
  };
  svgEl.addEventListener('pointerup', endDrag);
  svgEl.addEventListener('pointercancel', endDrag);
  svgEl.addEventListener('wheel', (e) => {
    e.preventDefault();
    mapApplyZoomAt(mapZoom * Math.exp(-e.deltaY * 0.0015), e.clientX, e.clientY, svgEl);
    svgEl.setAttribute('viewBox', mapViewBoxAttr());
  }, { passive: false });
  svgEl.addEventListener('keydown', (e) => {
    const rect = svgEl.getBoundingClientRect();
    const cx = rect.left + rect.width / 2, cy = rect.top + rect.height / 2;
    const panStep = (MAP_W / mapZoom) * 0.08;
    if (e.key === 'ArrowLeft') mapViewCenter.cx -= panStep;
    else if (e.key === 'ArrowRight') mapViewCenter.cx += panStep;
    else if (e.key === 'ArrowUp') mapViewCenter.cy -= panStep;
    else if (e.key === 'ArrowDown') mapViewCenter.cy += panStep;
    else if (e.key === '+' || e.key === '=') { mapApplyZoomAt(mapZoom * 1.4, cx, cy, svgEl); }
    else if (e.key === '-' || e.key === '_') { mapApplyZoomAt(mapZoom / 1.4, cx, cy, svgEl); }
    else if (e.key === '0') { mapZoom = 1; mapViewCenter = { cx: MAP_W / 2, cy: MAP_H / 2 }; }
    else return;
    e.preventDefault();
    mapClampCenter();
    svgEl.setAttribute('viewBox', mapViewBoxAttr());
  });
}
/* The legend's color-ramp swatch is a static CSS gradient for the default
   "BEMO / Dark Accent" theme (see .map-legend-gradient); for the other two
   themes it's overridden inline here from the exact same MAP_THEME_STOPS a
   marker's color comes from, so the legend can never visually drift from
   what markers actually render. */
function mapSyncLegendGradient(){
  const el = document.getElementById('map-legend-gradient'); if (!el) return;
  const theme = mapActiveTheme();
  if (theme === 'bemo-accent'){ el.style.background = ''; return; }
  const stops = MAP_THEME_STOPS[theme] || MAP_INTENSITY_STOPS;
  const css = stops.map(s => `hsl(${s.h},${s.s}%,${s.l}%)`).join(',');
  el.style.background = `linear-gradient(90deg,${css})`;
}
function mapFinishRender(el){
  mapAttachInteraction(el);
  mapSyncLegendGradient();
  const wrap = el.querySelector('.destination-map-wrap');
  if (wrap) mapEnsureTileLayer(wrap);
}
function syncMapControls(){
  const modeSel = document.getElementById('map-mode-select');
  const metricSel = document.getElementById('map-metric-select');
  const basemapSel = document.getElementById('map-basemap-select');
  const themeSel = document.getElementById('map-theme-select');
  const routesToggle = document.getElementById('map-routes-toggle');
  if (modeSel) modeSel.value = prefs.mapMode || 'countries';
  if (metricSel) metricSel.value = prefs.mapMetric || 'observations';
  if (basemapSel) basemapSel.value = mapActiveBasemap();
  if (themeSel) themeSel.value = mapActiveTheme();
  if (routesToggle) routesToggle.checked = !!prefs.mapRoutes;
  mapSyncLegendGradient();
}
syncMapControls();
document.getElementById('map-mode-select')?.addEventListener('change', (e) => {
  prefs.mapMode = e.target.value === 'destinations' ? 'destinations' : 'countries';
  savePrefs();
  mapSelectedCountry = null; mapSelectedDestinationKey = null;
  if (mapLastPayload) renderDestinationMap(mapLastPayload);
});
document.getElementById('map-metric-select')?.addEventListener('change', (e) => {
  prefs.mapMetric = MAP_METRICS.includes(e.target.value) ? e.target.value : 'observations';
  savePrefs();
  if (mapLastPayload) renderDestinationMap(mapLastPayload);
});
document.getElementById('map-basemap-select')?.addEventListener('change', (e) => {
  prefs.mapBasemap = MAP_BASEMAPS.includes(e.target.value) ? e.target.value : 'satellite-heat';
  savePrefs();
  mapSyncLegendGradient();
  if (mapLastPayload) renderDestinationMap(mapLastPayload);
});
document.getElementById('map-theme-select')?.addEventListener('change', (e) => {
  prefs.mapTheme = MAP_THEMES.includes(e.target.value) ? e.target.value : 'bemo-accent';
  savePrefs();
  mapSyncLegendGradient();
  if (mapLastPayload) renderDestinationMap(mapLastPayload);
});
document.getElementById('map-routes-toggle')?.addEventListener('change', (e) => {
  prefs.mapRoutes = !!e.target.checked;
  savePrefs();
  if (mapLastPayload) renderDestinationMap(mapLastPayload);
});
document.getElementById('map-zoom-in-btn')?.addEventListener('click', () => {
  mapZoom = Math.min(8, mapZoom * 2);
  if (mapLastPayload) renderDestinationMap(mapLastPayload);
});
document.getElementById('map-zoom-out-btn')?.addEventListener('click', () => {
  mapZoom = Math.max(1, mapZoom / 2);
  if (mapZoom === 1) mapViewCenter = { cx: MAP_W / 2, cy: MAP_H / 2 };
  if (mapLastPayload) renderDestinationMap(mapLastPayload);
});
document.getElementById('map-reset-btn')?.addEventListener('click', () => {
  mapZoom = 1; mapViewCenter = { cx: MAP_W / 2, cy: MAP_H / 2 };
  mapSelectedCountry = null; mapSelectedDestinationKey = null;
  renderMapDetail(null);
  if (mapLastPayload) renderDestinationMap(mapLastPayload);
});
document.getElementById('map-fit-btn')?.addEventListener('click', mapFitToData);
function mapPayloadFingerprint(data){
  try{
    return JSON.stringify({
      provider: data?.provider, capabilities: data?.capabilities,
      diagnostics: data?.diagnostics, coverage: data?.coverage,
      countries: data?.countries, destinations: data?.destinations, unknown: data?.unknown,
    });
  }catch(e){ return null; }
}
async function fetchDestinationMap(){
  if (mapFetchInFlight) return;
  mapFetchInFlight = true;
  const seq = ++mapFetchSeq;
  if (mapFetchController) mapFetchController.abort();
  const controller = new AbortController();
  mapFetchController = controller;
  const fetchStartedAt = perfNow();
  try{
    const r = await fetch('/api/analytics/map', {cache:'no-store', signal: controller.signal});
    if (seq !== mapFetchSeq) return; // superseded by a newer request while this one was in flight
    if (!r.ok) return;
    const data = await r.json();
    if (seq !== mapFetchSeq) return; // superseded while awaiting the response body
    const fingerprint = mapPayloadFingerprint(data);
    if (fingerprint !== null && fingerprint === mapLastFingerprint && mapLastPayload){
      mapLastPayload = data; // keep the freshest payload for interaction-triggered re-renders (zoom/pan/Fit)
      recordPerf('map', fetchStartedAt, perfNow(), perfNow());
      return;
    }
    mapLastFingerprint = fingerprint;
    const renderStartedAt = perfNow();
    renderDestinationMap(data);
    recordPerf('map', fetchStartedAt, renderStartedAt, perfNow());
  }catch(e){ if (e?.name !== 'AbortError') console.debug('destination map refresh failed', e); }
  finally{ mapFetchInFlight = false; }
}
function startAnalyticsPolling(){
  if (analyticsFullTimer) return;
  renderLiveHero();
  fetchAnalyticsFull();
  fetchDestinationMap();
  analyticsFullTimer = setInterval(fetchAnalyticsFull, refreshMs);
  mapRefreshTimer = setInterval(fetchDestinationMap, mapRefreshMs());
}
function stopAnalyticsPolling(){
  if (analyticsFullTimer){ clearInterval(analyticsFullTimer); analyticsFullTimer = null; }
  if (mapRefreshTimer){ clearInterval(mapRefreshTimer); mapRefreshTimer = null; }
  if (analyticsFetchController){ analyticsFetchController.abort(); analyticsFetchController = null; }
  if (mapFetchController){ mapFetchController.abort(); mapFetchController = null; }
}
function hideCustomRangeControls(){
  const panel = document.getElementById('analytics-range-custom-controls');
  if (panel) panel.hidden = true;
  document.getElementById('analytics-range-custom-btn')?.setAttribute('aria-expanded', 'false');
}
document.querySelectorAll('[data-analytics-range]').forEach(b => b.addEventListener('click', () => {
  const key = b.dataset.analyticsRange;
  if (key === 'custom'){
    const panel = document.getElementById('analytics-range-custom-controls');
    const wasOpen = !!(panel && !panel.hidden);
    if (panel) panel.hidden = wasOpen;
    b.setAttribute('aria-expanded', String(!wasOpen));
    if (!wasOpen) document.getElementById('analytics-custom-from')?.focus();
    return;
  }
  analyticsRange = key;
  analyticsCustomWindow = null;
  hideCustomRangeControls();
  document.querySelectorAll('[data-analytics-range]').forEach(x => x.classList.toggle('active', x === b));
  selectedIntervalBucket = null; renderIntervalDetail(null);
  fetchAnalyticsFull();
}));
document.getElementById('analytics-custom-apply-btn')?.addEventListener('click', () => {
  const errEl = document.getElementById('analytics-custom-error');
  if (errEl) errEl.textContent = '';
  const fromVal = document.getElementById('analytics-custom-from')?.value;
  const toVal = document.getElementById('analytics-custom-to')?.value;
  if (!fromVal || !toVal){ if (errEl) errEl.textContent = 'Choose both a from and to date.'; return; }
  const fromIso = new Date(fromVal + 'T00:00:00Z').toISOString();
  const toIso = new Date(toVal + 'T23:59:59Z').toISOString();
  if (new Date(toIso) <= new Date(fromIso)){ if (errEl) errEl.textContent = 'The "to" date must be after the "from" date.'; return; }
  analyticsRange = 'custom';
  analyticsCustomWindow = {from: fromIso, to: toIso};
  document.querySelectorAll('[data-analytics-range]').forEach(x => x.classList.toggle('active', x.dataset.analyticsRange === 'custom'));
  selectedIntervalBucket = null; renderIntervalDetail(null);
  fetchAnalyticsFull();
});
function analyticsTabChanged(name){
  if (name === 'analytics') startAnalyticsPolling(); else stopAnalyticsPolling();
}
window.onAnalyticsTabChange = analyticsTabChanged;
analyticsTabChanged(document.querySelector('.tab-btn.active')?.dataset.tab || 'overview');
</script>
<script>
/* ---- Dashboard Builder (0.8.6): GridStack.js-backed Analytics widget grid ----
   GridStack owns real drag, resize, collision/reflow and grid math; this
   module wires it to the page (widget chrome, presets, hide/show, a
   keyboard-operable move-earlier/move-later fallback) and persists the
   resulting x/y/w/h per widget per-browser. This only moves/resizes/hides
   the widgets already in the page -- no widget's underlying data or route
   changes. `float:true` is used deliberately (no auto vertical gravity) so
   every geometry write this module makes is exact and reproducible instead
   of being second-guessed by GridStack's own compaction. */
(function(){
  if (typeof GridStack === 'undefined') return; // CDN unavailable: widgets still render, just without drag/resize/presets.
  const gridEl = document.getElementById('analytics-dash-grid');
  if (!gridEl) return;
  const WIDGET_IDS = Array.from(gridEl.querySelectorAll('.dash-widget')).map(w => w.dataset.widgetId);
  const LAYOUT_KEY = 'dnsInspectorDashboardLayoutV2';
  const COLUMNS = 4;
  const clone = (obj) => JSON.parse(JSON.stringify(obj));
  function widgetEl(id){ return gridEl.querySelector(`[data-widget-id="${id}"]`); }

  function widgetHeadHtml(title){
    return `<div class="dash-widget-head"><span class="dash-drag-handle" title="Drag to reposition">⠿</span><span class="dash-widget-title">${esc(title)}</span><button type="button" data-dash-action="move-up" title="Move earlier" aria-label="Move ${esc(title)} earlier">&uarr;</button><button type="button" data-dash-action="move-down" title="Move later" aria-label="Move ${esc(title)} later">&darr;</button><button type="button" data-dash-action="hide" title="Hide widget" aria-label="Hide ${esc(title)}">&times;</button></div>`;
  }
  WIDGET_IDS.forEach(id => {
    const el = widgetEl(id);
    const content = el && el.querySelector('.grid-stack-item-content');
    if (content) content.insertAdjacentHTML('afterbegin', widgetHeadHtml(el.dataset.title || id));
  });

  // gs-w/gs-h come from the server-rendered markup; gs-x/gs-y are
  // intentionally absent so GridStack auto-packs the shipped DOM order on
  // init, in reading order, the same way the old CSS `grid-auto-flow:dense`
  // did -- that auto-packed result becomes DEFAULT_LAYOUT below. Interactive
  // resize uses preventCollision so neighboring widgets stay put.
  const grid = GridStack.init({
    column: COLUMNS,
    cellHeight: 60,
    margin: 10,
    float: true,
    animate: false,
    preventCollision: true,
    staticGrid: true,
    handle: '.dash-drag-handle',
    resizable: { handles: 'e, se, s' },
    oneColumnSize: 900,
  }, gridEl);

  const DEFAULT_LAYOUT = { preset: 'default', hidden: [], widgets: grid.save(false).map(n => ({id: n.id, x: n.x, y: n.y, w: n.w, h: n.h})) };

  function baseWH(id){
    const n = DEFAULT_LAYOUT.widgets.find(w => w.id === id);
    return n ? {w: n.w, h: n.h} : {w: 4, h: 4};
  }

  /* Simple skyline/shelf packer -- given widgets in a desired reading order
     with a target column span, lays them out left-to-right/top-to-bottom
     with no gaps, mirroring the old dense CSS-grid packing but producing
     real x/y coordinates for GridStack. */
  function packLayout(items){
    const colY = new Array(COLUMNS).fill(0);
    return items.map(it => {
      const w = Math.max(1, Math.min(COLUMNS, it.w));
      let bestX = 0, bestY = Infinity;
      for (let x = 0; x <= COLUMNS - w; x++){
        let y = 0;
        for (let c = x; c < x + w; c++) y = Math.max(y, colY[c]);
        if (y < bestY){ bestY = y; bestX = x; }
      }
      for (let c = bestX; c < bestX + w; c++) colY[c] = bestY + it.h;
      return { id: it.id, x: bestX, y: bestY, w, h: it.h };
    });
  }

  function presetLayout(name){
    const COMPACT_H = 3, TALL_BONUS = 3;
    let order, hidden = [];
    if (name === 'monitoring'){
      order = [
        ['visibility-report', null, 'tall'], ['status-breakdown', null, null],
        ['instrument-gauges', null, null], ['destination-map', null, null],
        ['query-volume', null, null], ['new-domains', null, null], ['new-devices', null, null],
        ['activity-domains', null, 'compact'], ['activity-devices', null, 'compact'],
      ];
      hidden = ['top-activity'];
    } else if (name === 'compact'){
      order = DEFAULT_LAYOUT.widgets.filter(w => w.id !== 'top-activity').map(w => [w.id, null, 'compact']);
      hidden = ['top-activity'];
    } else if (name === 'investigation'){
      order = [
        ['query-volume', null, null], ['status-breakdown', null, null],
        ['instrument-gauges', null, null], ['destination-map', null, null],
        ['top-activity', null, 'tall'], ['activity-domains', null, 'tall'], ['activity-devices', null, 'tall'],
        ['new-domains', null, null], ['new-devices', null, null], ['visibility-report', 2, 'compact'],
      ];
    } else {
      return clone(DEFAULT_LAYOUT);
    }
    hidden = hidden.filter(id => WIDGET_IDS.includes(id));
    const items = order
      .filter(([id]) => WIDGET_IDS.includes(id) && !hidden.includes(id))
      .map(([id, wOverride, hMode]) => {
        const base = baseWH(id);
        const w = wOverride || base.w;
        const h = hMode === 'compact' ? COMPACT_H : (hMode === 'tall' ? base.h + TALL_BONUS : base.h);
        return { id, w, h };
      });
    return { preset: name, hidden, widgets: packLayout(items) };
  }

  function loadLayout(){
    try{
      const raw = JSON.parse(localStorage.getItem(LAYOUT_KEY) || 'null');
      if (!raw || !Array.isArray(raw.widgets)) return clone(DEFAULT_LAYOUT);
      const knownIds = new Set(WIDGET_IDS);
      const widgets = raw.widgets.filter(w => w && knownIds.has(w.id) && [w.x, w.y, w.w, w.h].every(Number.isFinite));
      const hidden = Array.isArray(raw.hidden) ? raw.hidden.filter(id => knownIds.has(id)) : [];
      const known = new Set([...widgets.map(w => w.id), ...hidden]);
      // A widget shipped after this layout was saved is in neither list --
      // surface it at its shipped default position instead of dropping it.
      DEFAULT_LAYOUT.widgets.forEach(dw => { if (!known.has(dw.id)) widgets.push(clone(dw)); });
      return { preset: raw.preset || 'custom', widgets, hidden };
    }catch(e){ return clone(DEFAULT_LAYOUT); }
  }
  function saveLayout(){
    try{ localStorage.setItem(LAYOUT_KEY, JSON.stringify({preset: layout.preset, widgets: layout.widgets, hidden: layout.hidden})); }catch(e){}
  }

  let layout = loadLayout();
  let customizing = false;
  let applyingProgrammatically = false;

  function syncLayoutFromGrid(){
    layout.widgets = grid.save(false).map(n => ({id: n.id, x: n.x, y: n.y, w: n.w, h: n.h}));
  }

  function applyGeometry(state){
    applyingProgrammatically = true;
    try{
      WIDGET_IDS.forEach(id => {
        const el = widgetEl(id);
        if (!el || !state.hidden.includes(id)) return;
        if (el.gridstackNode) grid.removeWidget(el, false);
        el.style.display = 'none';
      });
      state.widgets.forEach(w => {
        const el = widgetEl(w.id);
        if (!el) return;
        el.style.display = '';
        if (el.gridstackNode) grid.update(el, {x: w.x, y: w.y, w: w.w, h: w.h});
        else grid.addWidget(el, {x: w.x, y: w.y, w: w.w, h: w.h, id: w.id});
      });
    } finally { applyingProgrammatically = false; }
  }

  function refreshChrome(){
    const presetSelect = document.getElementById('dash-preset-select');
    if (presetSelect) presetSelect.value = layout.preset || 'custom';
    WIDGET_IDS.forEach(id => {
      const el = widgetEl(id);
      if (!el) return;
      const isHidden = layout.hidden.includes(id);
      const hideBtn = el.querySelector('[data-dash-action="hide"]');
      if (hideBtn){
        hideBtn.innerHTML = isHidden ? '&#43;' : '&times;';
        hideBtn.title = isHidden ? 'Show widget' : 'Hide widget';
        hideBtn.setAttribute('aria-label', (isHidden ? 'Show ' : 'Hide ') + (el.dataset.title || id));
      }
    });
    const tray = document.getElementById('dash-hidden-tray');
    const trayList = document.getElementById('dash-hidden-tray-list');
    if (tray && trayList){
      trayList.innerHTML = layout.hidden.map(id => {
        const el = widgetEl(id);
        const title = el ? (el.dataset.title || id) : id;
        return `<button type="button" data-dash-show="${id}">${esc(title)} +</button>`;
      }).join('');
      tray.classList.toggle('visible', customizing && layout.hidden.length > 0);
    }
    if (document.getElementById('tab-analytics')?.classList.contains('active') && typeof fetchAnalyticsFull === 'function') fetchAnalyticsFull();
    if (typeof renderLiveHero === 'function') renderLiveHero();
  }

  function markCustom(){
    layout.preset = 'custom';
    syncLayoutFromGrid();
    saveLayout();
    refreshChrome();
  }

  function hideWidgetById(id){
    const el = widgetEl(id);
    applyingProgrammatically = true;
    try{
      if (el && el.gridstackNode) grid.removeWidget(el, false);
      if (el) el.style.display = 'none';
    } finally { applyingProgrammatically = false; }
    if (!layout.hidden.includes(id)) layout.hidden.push(id);
    markCustom();
  }
  function unhideWidget(id){
    const el = widgetEl(id);
    if (!el) return;
    applyingProgrammatically = true;
    try{
      el.style.display = '';
      if (!el.gridstackNode){
        const last = layout.widgets.find(w => w.id === id) || DEFAULT_LAYOUT.widgets.find(w => w.id === id) || {w: 4, h: 4};
        grid.addWidget(el, {x: 0, y: (grid.getRow ? grid.getRow() : 0), w: last.w, h: last.h, id});
      }
    } finally { applyingProgrammatically = false; }
    layout.hidden = layout.hidden.filter(h => h !== id);
    markCustom();
  }

  // Keyboard/touch-accessible reordering, independent of pointer drag: swaps
  // this widget's grid position with its visual neighbour (reading order is
  // y then x, i.e. top-to-bottom then left-to-right).
  function visibleOrderedIds(){
    return WIDGET_IDS
      .filter(id => !layout.hidden.includes(id))
      .map(id => { const el = widgetEl(id); return el && el.gridstackNode ? {id, node: el.gridstackNode} : null; })
      .filter(Boolean)
      .sort((a, b) => a.node.y - b.node.y || a.node.x - b.node.x)
      .map(x => x.id);
  }
  function moveWidget(id, dir){
    const order = visibleOrderedIds();
    const idx = order.indexOf(id);
    const otherIdx = idx + dir;
    if (idx === -1 || otherIdx < 0 || otherIdx >= order.length) return;
    const elA = widgetEl(id), elB = widgetEl(order[otherIdx]);
    if (!elA || !elB || !elA.gridstackNode || !elB.gridstackNode) return;
    const a = elA.gridstackNode, b = elB.gridstackNode;
    const posA = {x: a.x, y: a.y, w: a.w, h: a.h}, posB = {x: b.x, y: b.y, w: b.w, h: b.h};
    applyingProgrammatically = true;
    try{ grid.update(elA, posB); grid.update(elB, posA); } finally { applyingProgrammatically = false; }
    markCustom();
  }

  gridEl.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-dash-action]'); if (!btn) return;
    const widget = btn.closest('.dash-widget'); if (!widget) return;
    const id = widget.dataset.widgetId;
    const action = btn.dataset.dashAction;
    if (action === 'hide') hideWidgetById(id);
    else if (action === 'move-up') moveWidget(id, -1);
    else if (action === 'move-down') moveWidget(id, 1);
  });
  document.getElementById('dash-hidden-tray')?.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-dash-show]'); if (!btn) return;
    unhideWidget(btn.dataset.dashShow);
  });

  // A resize is collision-safe: preventCollision keeps neighboring
  // widgets in their existing cells instead of allowing GridStack to push
  // the entire dashboard downward. Responsive renderers below use the
  // current widget/container dimensions and cached data to adapt in-place.

  // GridStack already reports each live resize step. Use that signal rather
  // than observing the widget box itself: observing the box with ResizeObserver
  // can form a layout/render feedback loop and freeze the browser tab.
  let responsiveRefreshPending = false;

  function scheduleResponsiveAnalyticsRefresh(){
    if (responsiveRefreshPending) return;
    responsiveRefreshPending = true;
    requestAnimationFrame(() => {
      responsiveRefreshPending = false;
      const payload = window.__lastAnalyticsPayload;
      if (!payload) return;
      renderVisibilityReport(payload);
      renderQueryVolumeChart(payload);
      renderMetricVisual('chart-new-domains', payload.series?.new_domains?.points, '--sem-ok', 'New domains');
      renderMetricVisual('chart-new-devices', payload.series?.new_devices?.points, '--sem-ok', 'New devices');
      renderStatusBreakdown(payload.status_breakdown);
      renderRecentActivity(payload.recent_domains, payload.recent_devices);
      renderInstrumentGauges(payload);
      if (typeof window.dnsInspectorResizeMap === 'function') window.dnsInspectorResizeMap();
    });
  }

  grid.on('resize', () => scheduleResponsiveAnalyticsRefresh());

  // GridStack's own 'change' event captures final pointer-driven drag/resize
  // geometry; the guard skips this module's own programmatic writes so
  // switching a preset doesn't immediately relabel itself 'custom'.
  grid.on('change', () => {
    if (applyingProgrammatically) return;
    layout.preset = 'custom';
    syncLayoutFromGrid();
    saveLayout();
    refreshChrome();
  });

  const customizeBtn = document.getElementById('dash-customize-btn');
  const hint = document.getElementById('dash-hint');
  customizeBtn?.addEventListener('click', () => {
    customizing = !customizing;
    grid.setStatic(!customizing);
    gridEl.classList.toggle('dash-customizing', customizing);
    customizeBtn.classList.toggle('active', customizing);
    customizeBtn.setAttribute('aria-pressed', String(customizing));
    customizeBtn.textContent = customizing ? 'Done customizing' : 'Customize';
    if (hint) hint.hidden = !customizing;
    refreshChrome();
  });

  document.getElementById('dash-preset-select')?.addEventListener('change', (e) => {
    const name = e.target.value;
    if (name === 'custom') return;
    layout = presetLayout(name);
    applyGeometry(layout);
    saveLayout();
    refreshChrome();
  });

  document.getElementById('dash-reset-btn')?.addEventListener('click', () => {
    layout = clone(DEFAULT_LAYOUT);
    applyGeometry(layout);
    saveLayout();
    refreshChrome();
  });

  applyGeometry(layout);
  refreshChrome();
})();
</script>
<script>
/* ---- Settings dialog wiring ----
   Preferences state, theming and the Analytics visual-style abstraction
   all live earlier so they're ready before first paint / first Analytics
   render; this block only wires up the dialog UI and persists choices. */
(function(){
  const dialog = document.getElementById('settings-dialog');
  const openBtn = document.getElementById('settings-open-btn');
  const closeBtn = document.getElementById('settings-close-btn');
  const doneBtn = document.getElementById('settings-done-btn');
  const resetBtn = document.getElementById('settings-reset-btn');
  if (!dialog || !openBtn) return;

  async function refreshDevLogPanel(){
    const el = document.getElementById('devlog-list'); if (!el) return;
    try{
      const r = await adminFetch('/api/devlog', {cache:'no-store'});
      const d = await r.json();
      const rows = d.entries || [];
      el.innerHTML = rows.length ? rows.slice(-100).reverse().map(x => {
        const ctx = x.context ? ' · ' + esc(JSON.stringify(x.context)) : '';
        return '<div class="devlog-entry"><span class="devlog-meta">' + esc(x.at) + '</span><span class="devlog-level devlog-level-' + esc(x.level) + '">' + esc(x.level) + '</span><span>' + esc(x.message) + esc(ctx) + '</span></div>';
      }).join('') : '<div class="settings-kv"><b>No events yet</b><span>Operational events will appear here.</span></div>';
    }catch(e){
      el.innerHTML = '<div class="settings-kv"><b>DevLog unavailable</b><span>—</span></div>';
    }
  }

  async function downloadBoundedArtifact(url){
    try{
      const r = await fetch(url, {cache:'no-store'});
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const blob = await r.blob();
      const disposition = r.headers.get('Content-Disposition') || '';
      const match = disposition.match(/filename="?([^";]+)"?/i);
      const filename = match ? match[1] : (url.includes('debug') ? 'dns-inspector-debug.json' : 'dns-inspector-devlog.txt');
      const href = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = href; a.download = filename; document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(href), 1000);
    }catch(e){
      console.error('diagnostic download failed', e);
      alert('Diagnostic download failed. Check the DNS Inspector server logs.');
    }
  }
  document.getElementById('devlog-download-btn')?.addEventListener('click', () => downloadBoundedArtifact('/api/devlog/export'));
  document.getElementById('debug-download-btn')?.addEventListener('click', () => downloadBoundedArtifact('/api/debug/snapshot'));
  document.getElementById('debug-download-top-btn')?.addEventListener('click', () => downloadBoundedArtifact('/api/debug/snapshot'));

  function openDialog(){
    if (typeof dialog.showModal === 'function') dialog.showModal(); else dialog.setAttribute('open','');
    refreshDiagnosticsPanel();
    refreshDevLogPanel();
    refreshSystemPanel();
    refreshAboutUptime();
    refreshReportsPanel();
  }
  function closeDialog(){ if (typeof dialog.close === 'function') dialog.close(); else dialog.removeAttribute('open'); }
  openBtn.addEventListener('click', openDialog);
  closeBtn?.addEventListener('click', closeDialog);
  doneBtn?.addEventListener('click', closeDialog);
  dialog.addEventListener('click', (e) => { if (e.target === dialog) closeDialog(); });

  dialog.querySelectorAll('.settings-nav-btn').forEach(btn => btn.addEventListener('click', () => {
    dialog.querySelectorAll('.settings-nav-btn').forEach(b => b.classList.toggle('active', b === btn));
    dialog.querySelectorAll('.settings-section').forEach(s => s.classList.toggle('active', s.dataset.settingsPanel === btn.dataset.settingsTab));
  }));

  const accentGroup = document.getElementById('accent-choice-group');
  Object.keys(ACCENT_PRESETS).forEach(key => {
    const b = document.createElement('button');
    b.type = 'button'; b.className = 'settings-swatch'; b.dataset.accentChoice = key;
    b.style.setProperty('--swatch-color', ACCENT_PRESETS[key]);
    const label = key.charAt(0).toUpperCase() + key.slice(1);
    b.title = label; b.setAttribute('aria-label', 'Accent: ' + label);
    accentGroup.appendChild(b);
  });

  const refreshSelect = document.getElementById('refresh-interval-select');
  REFRESH_OPTIONS.forEach(s => { const o = document.createElement('option'); o.value = String(s); o.textContent = s + 's'; refreshSelect.appendChild(o); });

  function syncControls(){
    dialog.querySelectorAll('[data-theme-choice]').forEach(b => b.classList.toggle('active', b.dataset.themeChoice === prefs.theme));
    dialog.querySelectorAll('[data-accent-choice]').forEach(b => b.classList.toggle('active', b.dataset.accentChoice === prefs.accent));
    dialog.querySelectorAll('[data-density-choice]').forEach(b => b.classList.toggle('active', b.dataset.densityChoice === (prefs.density||'comfortable')));
    dialog.querySelectorAll('[data-style-choice]').forEach(b => b.classList.toggle('active', b.dataset.styleChoice === (prefs.analyticsStyle||'digital')));
    const rm = document.getElementById('reduced-motion-toggle'); if (rm) rm.checked = !!prefs.reducedMotion;
    const dv = document.getElementById('default-view-select'); if (dv) dv.value = prefs.defaultView || 'last';
    if (refreshSelect) refreshSelect.value = String(prefs.refreshSeconds || 0);
  }

  function update(partial){ Object.assign(prefs, partial); savePrefs(); syncControls(); }

  dialog.querySelectorAll('[data-theme-choice]').forEach(b => b.addEventListener('click', () => { update({theme: b.dataset.themeChoice}); applyAppearance(); }));
  dialog.querySelectorAll('[data-accent-choice]').forEach(b => b.addEventListener('click', () => { update({accent: b.dataset.accentChoice}); applyAppearance(); }));
  dialog.querySelectorAll('[data-density-choice]').forEach(b => b.addEventListener('click', () => { update({density: b.dataset.densityChoice}); applyAppearance(); }));
  dialog.querySelectorAll('[data-style-choice]').forEach(b => b.addEventListener('click', () => { update({analyticsStyle: b.dataset.styleChoice}); applyAnalyticsStyle(); }));
  document.getElementById('reduced-motion-toggle')?.addEventListener('change', (e) => { update({reducedMotion: e.target.checked}); applyAppearance(); });
  document.getElementById('default-view-select')?.addEventListener('change', (e) => { update({defaultView: e.target.value}); });
  refreshSelect?.addEventListener('change', (e) => { update({refreshSeconds: Number(e.target.value)||0}); applyMonitoring(); });

  resetBtn?.addEventListener('click', () => {
    prefs = Object.assign({}, DEFAULT_PREFS);
    savePrefs();
    syncControls();
    applyAppearance(); applyMonitoring(); applyAnalyticsStyle();
  });

  function kvRows(entries){ return entries.map(([k,v]) => `<b>${esc(k)}</b><span>${esc(v)}</span>`).join(''); }

  async function refreshDiagnosticsPanel(){
    const el = document.getElementById('diagnostics-kv'); if (!el) return;
    try{
      const r = await fetch('/api/observability', {cache:'no-store'});
      const d = await r.json();
      const rows = [['Uptime', d.uptime_human || '—'], ['Memory (RSS)', d.ram_mb != null ? d.ram_mb + ' MB' : '—'], ['Process ID', d.pid ?? '—'], ['Threads', d.thread_count ?? '—'], ['Database size', d.db_size_bytes != null ? (Math.round(d.db_size_bytes/1024/1024*10)/10) + ' MB' : '—']];
      const counts = d.db_counts || {};
      ['domains','devices','processed_queries','analytics_buckets'].forEach(t => { if (counts[t] != null) rows.push(['Rows: ' + t, counts[t]]); });
      const sched = d.report_scheduler || {};
      rows.push(['Report scheduler', sched.enabled ? 'Enabled' : 'Disabled']);
      if (sched.next_run) rows.push(['Next scheduled report', sched.next_run]);
      if (sched.last_run) rows.push(['Last report run', `${sched.last_run} (${sched.last_result || 'unknown'})`]);
      el.innerHTML = kvRows(rows);
    }catch(e){ el.innerHTML = '<b>Diagnostics unavailable</b><span>—</span>'; }
    renderClientPerfPanel();
  }

  async function refreshReportsPanel(){
    const kv = document.getElementById('reports-status-kv');
    try{
      const [cfgRes, statusRes] = await Promise.all([
        fetch('/api/reports/schedule', {cache:'no-store'}),
        fetch('/api/reports/status', {cache:'no-store'}),
      ]);
      const cfgData = await cfgRes.json();
      const statusData = await statusRes.json();
      const cfg = cfgData.config || {};
      const state = statusData.state || {};
      const baseDirEl = document.getElementById('reports-base-dir'); if (baseDirEl) baseDirEl.textContent = statusData.base_dir || '/data/reports';
      const setVal = (id, val) => { const el = document.getElementById(id); if (el) el.value = val; };
      const setChecked = (id, val) => { const el = document.getElementById(id); if (el) el.checked = !!val; };
      setChecked('reports-enabled-toggle', cfg.enabled);
      setVal('reports-interval-select', cfg.interval || 'daily');
      setVal('reports-custom-interval-input', cfg.custom_interval_seconds || 86400);
      const customInput = document.getElementById('reports-custom-interval-input'); if (customInput) customInput.style.display = cfg.interval === 'custom' ? '' : 'none';
      setVal('reports-window-select', cfg.window || '24h');
      setVal('reports-save-dir-input', cfg.save_dir || '');
      setVal('reports-filename-input', cfg.filename_template || '');
      setVal('reports-retention-input', cfg.retention_count || 14);
      setChecked('reports-smtp-enabled-toggle', cfg.smtp_enabled);
      setVal('reports-smtp-host-input', cfg.smtp_host || '');
      setVal('reports-smtp-port-input', cfg.smtp_port || 587);
      setVal('reports-smtp-security-select', cfg.smtp_security || 'starttls');
      setVal('reports-smtp-username-input', cfg.smtp_username || '');
      const pwEl = document.getElementById('reports-smtp-password-state'); if (pwEl) pwEl.textContent = cfg.smtp_password_set ? 'SMTP_PASSWORD is set' : 'SMTP_PASSWORD is not set (test/live sends will fail if auth is required)';
      setVal('reports-smtp-sender-input', cfg.smtp_sender || '');
      setVal('reports-smtp-recipients-input', (cfg.smtp_recipients || []).join('\n'));
      setVal('reports-smtp-subject-input', cfg.smtp_subject_template || '');
      if (kv) kv.innerHTML = kvRows([
        ['Scheduler', state.enabled ? 'Enabled' : 'Disabled'],
        ['Next run', state.next_run || '—'],
        ['Last run', state.last_run || 'never'],
        ['Last result', state.last_result || '—'],
        ['Last saved file', state.last_saved_file || '—'],
        ['Last email result', state.last_email_result ? (state.last_email_result.ok ? 'sent' : 'failed: ' + (state.last_email_result.error||'')) : '—'],
      ]);
    }catch(e){ if (kv) kv.innerHTML = '<b>Reports status unavailable</b><span>—</span>'; }
  }
  document.getElementById('reports-interval-select')?.addEventListener('change', (e) => {
    const customInput = document.getElementById('reports-custom-interval-input'); if (customInput) customInput.style.display = e.target.value === 'custom' ? '' : 'none';
  });
  document.getElementById('reports-save-schedule-btn')?.addEventListener('click', async () => {
    const resultEl = document.getElementById('reports-save-schedule-result');
    const recipients = (document.getElementById('reports-smtp-recipients-input')?.value || '').split('\n').map(s => s.trim()).filter(Boolean);
    const payload = {
      enabled: !!document.getElementById('reports-enabled-toggle')?.checked,
      interval: document.getElementById('reports-interval-select')?.value,
      custom_interval_seconds: Number(document.getElementById('reports-custom-interval-input')?.value) || 86400,
      window: document.getElementById('reports-window-select')?.value,
      save_dir: (document.getElementById('reports-save-dir-input')?.value || '').trim(),
      filename_template: (document.getElementById('reports-filename-input')?.value || '').trim() || 'dns-inspector-{range}-{timestamp}.pdf',
      retention_count: Number(document.getElementById('reports-retention-input')?.value) || 14,
      smtp_enabled: !!document.getElementById('reports-smtp-enabled-toggle')?.checked,
      smtp_host: (document.getElementById('reports-smtp-host-input')?.value || '').trim(),
      smtp_port: Number(document.getElementById('reports-smtp-port-input')?.value) || 587,
      smtp_security: document.getElementById('reports-smtp-security-select')?.value,
      smtp_username: (document.getElementById('reports-smtp-username-input')?.value || '').trim(),
      smtp_sender: (document.getElementById('reports-smtp-sender-input')?.value || '').trim(),
      smtp_recipients: recipients,
      smtp_subject_template: (document.getElementById('reports-smtp-subject-input')?.value || '').trim(),
    };
    if (resultEl) resultEl.textContent = 'Saving…';
    try{
      const r = await fetch('/api/reports/schedule', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
      const d = await r.json();
      if (resultEl) resultEl.textContent = d.ok ? 'Saved.' : ('Error: ' + (d.error || 'unknown'));
      refreshReportsPanel();
    }catch(e){ if (resultEl) resultEl.textContent = 'Save failed.'; }
  });
  document.getElementById('reports-save-now-btn')?.addEventListener('click', async (e) => {
    const btn = e.currentTarget; btn.disabled = true;
    try{
      const r = await fetch('/api/reports/save-now', {method:'POST'});
      const d = await r.json();
      alert(d.ok ? `Report saved: ${d.saved_file || ''}` : `Save failed: ${d.error || 'unknown error'}`);
    }catch(e){ alert('Save failed.'); }
    finally{ btn.disabled = false; refreshReportsPanel(); }
  });
  document.getElementById('reports-test-email-btn')?.addEventListener('click', async (e) => {
    const btn = e.currentTarget; btn.disabled = true;
    try{
      const r = await fetch('/api/reports/test-email', {method:'POST', headers:{'Content-Type':'application/json'}, body: '{}'});
      const d = await r.json();
      alert(d.ok ? `Test email sent to ${d.recipient_count || 0} recipient(s).` : `Test email failed: ${d.error || 'unknown error'}`);
    }catch(e){ alert('Test email failed.'); }
    finally{ btn.disabled = false; }
  });

  /* Issue #61: surfaces the client-side perf trace recorded by
     recordPerf()/fetchAnalyticsFull()/fetchDestinationMap() so an operator
     can tell a slow HTTP round-trip apart from slow in-browser rendering
     without opening devtools. Purely reads window.__dnsInspectorPerf --
     never triggers a request of its own. */
  function renderClientPerfPanel(){
    const el = document.getElementById('diagnostics-perf-kv'); if (!el) return;
    const perf = window.__dnsInspectorPerf || {analytics:[], map:[]};
    const summarize = (label, samples) => {
      if (!samples.length) return [label + ' (no samples yet)', '—'];
      const last = samples[samples.length - 1];
      const avg = (key) => Math.round(samples.reduce((s,x) => s + x[key], 0) / samples.length);
      return [label + ' (last / avg of ' + samples.length + ')', `fetch ${last.fetchMs}ms / ${avg('fetchMs')}ms &middot; render ${last.renderMs}ms / ${avg('renderMs')}ms`];
    };
    const rows = [summarize('Analytics poll', perf.analytics || []), summarize('Destination map', perf.map || [])];
    el.innerHTML = rows.map(([k,v]) => `<b>${esc(k)}</b><span>${v}</span>`).join('');
  }

  async function refreshSystemPanel(){
    const el = document.getElementById('system-kv'); if (!el) return;
    try{
      const r = await fetch('/health', {cache:'no-store'});
      const d = await r.json();
      el.innerHTML = kvRows([
        ['Environment', d.environment || '—'],
        ['AdGuard source', d.adguard ? 'Configured' : 'Not configured'],
        ['Poll interval', (d.poll_seconds ?? '—') + 's'],
        ['UI refresh (server default)', (d.ui_refresh_seconds ?? '—') + 's'],
        ['Version', d.version || '—'],
      ]);
    }catch(e){ el.innerHTML = '<b>System info unavailable</b><span>—</span>'; }
  }

  async function refreshAboutUptime(){
    const el = document.getElementById('about-uptime'); if (!el) return;
    try{ const r = await fetch('/api/observability', {cache:'no-store'}); const d = await r.json(); el.textContent = d.uptime_human || '—'; }catch(e){ el.textContent = '—'; }
  }

  /* ---- Restart control (Issue #43) ----
     Two-step in-panel confirm (no native confirm() dialog, matching the
     rest of this custom Settings UI) -> POST /api/system/restart with an
     explicit confirm flag -> disable the button immediately so a second
     click can't queue a duplicate request (the backend independently
     rejects a concurrent one with 409 either way) -> poll /health until the
     restarted process answers again, then reload. */
  (function wireRestartControl(){
    const btn = document.getElementById('system-restart-btn');
    const note = document.getElementById('system-restart-note');
    if (!btn) return;
    const originalLabel = btn.textContent;
    const originalNote = note ? note.textContent : '';
    let confirmTimer = null;
    let awaitingConfirm = false;

    function resetButton(){
      awaitingConfirm = false;
      confirmTimer = null;
      btn.classList.remove('confirming');
      btn.textContent = originalLabel;
      if (note) note.textContent = originalNote;
    }

    async function waitForServerAndReload(){
      for (let attempt = 0; attempt < 60; attempt++){
        await new Promise(r => setTimeout(r, 1000));
        try{
          const r = await fetch('/health', {cache:'no-store'});
          if (r.ok){ window.location.reload(); return; }
        }catch(e){ /* still restarting -- keep polling */ }
      }
      window.location.reload();
    }

    async function triggerRestart(){
      btn.disabled = true;
      btn.classList.remove('confirming');
      btn.textContent = 'Restarting…';
      if (note) note.textContent = 'Restarting DNS Inspector — this page will reload automatically once it is back.';
      try{
        const r = await adminFetch('/api/system/restart', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({confirm: true}),
        });
        if (r.status === 409){
          if (note) note.textContent = 'A restart is already in progress — waiting for it to finish.';
          await waitForServerAndReload();
          return;
        }
        if (!r.ok){
          if (note) note.textContent = 'Restart request failed. Check the server logs.';
          btn.disabled = false;
          btn.textContent = originalLabel;
          return;
        }
      }catch(e){
        // The connection can legitimately drop mid-restart once the process
        // image is replaced -- that is expected, not a failure.
      }
      await waitForServerAndReload();
    }

    btn.addEventListener('click', () => {
      if (btn.disabled) return;
      if (!awaitingConfirm){
        awaitingConfirm = true;
        btn.classList.add('confirming');
        btn.textContent = 'Click again to confirm restart';
        if (note) note.textContent = 'This restarts the running application/container. Click again within 5 seconds to confirm.';
        confirmTimer = setTimeout(resetButton, 5000);
        return;
      }
      clearTimeout(confirmTimer);
      awaitingConfirm = false;
      triggerRestart();
    });
  })();

  /* ---- Stop control (Issue #78) ----
     Same two-step in-panel confirm pattern as the Restart control above, but
     Stop performs a graceful shutdown (a self-delivered SIGTERM, not a hard
     kill -- see `_perform_self_stop()`/`POST /api/system/stop`) and the
     process does not come back on its own, so unlike Restart there is no
     waitForServerAndReload() poll loop here: once the request is accepted,
     the control just reports that the application has stopped and the web
     UI will stay unavailable until the container/application is started
     again. */
  (function wireStopControl(){
    const btn = document.getElementById('system-stop-btn');
    const note = document.getElementById('system-stop-note');
    if (!btn) return;
    const originalLabel = btn.textContent;
    const originalNote = note ? note.textContent : '';
    let confirmTimer = null;
    let awaitingConfirm = false;

    function resetButton(){
      awaitingConfirm = false;
      confirmTimer = null;
      btn.classList.remove('confirming');
      btn.textContent = originalLabel;
      if (note) note.textContent = originalNote;
    }

    async function triggerStop(){
      btn.disabled = true;
      btn.classList.remove('confirming');
      btn.textContent = 'Stopping…';
      if (note) note.textContent = 'Stopping DNS Inspector…';
      try{
        const r = await adminFetch('/api/system/stop', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({confirm: true}),
        });
        if (r.status === 409){
          if (note) note.textContent = 'A restart or stop is already in progress.';
          btn.disabled = false;
          btn.textContent = originalLabel;
          return;
        }
        if (!r.ok){
          if (note) note.textContent = 'Stop request failed. Check the server logs.';
          btn.disabled = false;
          btn.textContent = originalLabel;
          return;
        }
      }catch(e){
        // The connection can legitimately drop once the process actually
        // receives the signal and exits -- that is expected, not a failure.
      }
      btn.textContent = 'Stopped';
      if (note) note.textContent = 'DNS Inspector has been stopped. The web UI will stay unavailable until the container/application is started again.';
    }

    btn.addEventListener('click', () => {
      if (btn.disabled) return;
      if (!awaitingConfirm){
        awaitingConfirm = true;
        btn.classList.add('confirming');
        btn.textContent = 'Click again to confirm stop';
        if (note) note.textContent = 'This gracefully shuts down the running application/container. The web UI will be unavailable until it is started again. Click again within 5 seconds to confirm.';
        confirmTimer = setTimeout(resetButton, 5000);
        return;
      }
      clearTimeout(confirmTimer);
      awaitingConfirm = false;
      triggerStop();
    });
  })();

  document.getElementById('devlog-open-btn')?.addEventListener('click', () => {
    openBtn?.click();
    setTimeout(() => document.querySelector('[data-settings-tab="diagnostics"]')?.click(), 0);
  });

  syncControls();
})();
</script><script src="/static/leaflet-map.js"></script>
</body>

</html>
"""


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def add_column_if_missing(c, table, column, ddl):
    cols = {row[1] for row in c.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in cols:
        c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


# --- Generic persisted settings (Issue #88: report scheduling, map origin) --
def _get_setting_raw(c, key, default=None):
    row = c.execute("SELECT value FROM app_settings WHERE key=?", (key,)).fetchone()
    if not row: return default
    try: return json.loads(row[0])
    except (TypeError, ValueError): return default


def _set_setting_raw(c, key, value):
    c.execute("INSERT INTO app_settings(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at", (key, json.dumps(value), utcnow()))


def get_setting(key, default=None):
    with closing(sqlite3.connect(DB_PATH)) as c:
        return _get_setting_raw(c, key, default)


def set_setting(key, value):
    with db_lock, closing(sqlite3.connect(DB_PATH)) as c:
        _set_setting_raw(c, key, value); c.commit()


def init_db():
    with closing(sqlite3.connect(DB_PATH)) as c:
        c.execute("""CREATE TABLE IF NOT EXISTS domains(
            domain TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT,
            requests INTEGER NOT NULL DEFAULT 0, clients_json TEXT NOT NULL DEFAULT '{}',
            classification TEXT NOT NULL DEFAULT 'Unknown', company TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '', blocked_requests INTEGER NOT NULL DEFAULT 0, allowed_requests INTEGER NOT NULL DEFAULT 0, unknown_requests INTEGER NOT NULL DEFAULT 0, last_status TEXT NOT NULL DEFAULT 'Unknown', last_reason TEXT NOT NULL DEFAULT '')""")
        c.execute("""CREATE TABLE IF NOT EXISTS rdap_cache(
            domain TEXT PRIMARY KEY, fetched_at TEXT NOT NULL, json TEXT NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS mac_vendor_cache(
            mac TEXT PRIMARY KEY, fetched_at TEXT NOT NULL, vendor TEXT NOT NULL DEFAULT '')""")
        c.execute("""CREATE TABLE IF NOT EXISTS hostname_cache(
            ip TEXT PRIMARY KEY, fetched_at TEXT NOT NULL, hostname TEXT NOT NULL DEFAULT '')""")
        c.execute("""CREATE TABLE IF NOT EXISTS netify_cache(
            domain TEXT PRIMARY KEY, fetched_at TEXT NOT NULL, json TEXT NOT NULL DEFAULT '{}')""")
        c.execute("""CREATE TABLE IF NOT EXISTS netify_ip_cache(
            ip TEXT PRIMARY KEY, fetched_at TEXT NOT NULL, json TEXT NOT NULL DEFAULT '{}')""")
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
            confidence TEXT NOT NULL DEFAULT 'low', source TEXT NOT NULL DEFAULT '', first_seen TEXT NOT NULL DEFAULT '', last_seen TEXT NOT NULL,
            request_count INTEGER NOT NULL DEFAULT 0, info_json TEXT NOT NULL DEFAULT '{}')""")
        add_column_if_missing(c, "devices", "vendor", "TEXT NOT NULL DEFAULT ''")
        add_column_if_missing(c, "devices", "first_seen", "TEXT NOT NULL DEFAULT ''" )
        add_column_if_missing(c, "domains", "blocked_requests", "INTEGER NOT NULL DEFAULT 0")
        add_column_if_missing(c, "domains", "allowed_requests", "INTEGER NOT NULL DEFAULT 0")
        add_column_if_missing(c, "domains", "unknown_requests", "INTEGER NOT NULL DEFAULT 0")
        add_column_if_missing(c, "domains", "last_status", "TEXT NOT NULL DEFAULT 'Unknown'")
        add_column_if_missing(c, "domains", "last_reason", "TEXT NOT NULL DEFAULT ''")
        c.execute("UPDATE devices SET first_seen=COALESCE(NULLIF(first_seen,''), last_seen) WHERE first_seen=''")
        c.execute("""CREATE TABLE IF NOT EXISTS device_ips(
            device_key TEXT NOT NULL, ip TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
            requests INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(device_key,ip))""")
        c.execute("""CREATE TABLE IF NOT EXISTS domain_destination_ips(
            domain TEXT NOT NULL, ip TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
            observations INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(domain,ip))""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_domain_destination_ip_last_seen ON domain_destination_ips(last_seen)")
        c.execute("""CREATE TABLE IF NOT EXISTS processed_queries(
            fingerprint TEXT PRIMARY KEY, seen_at TEXT NOT NULL, status_counted INTEGER NOT NULL DEFAULT 0)""")
        add_column_if_missing(c, "processed_queries", "status_counted", "INTEGER NOT NULL DEFAULT 0")
        # Issue #88: enrich the existing bounded processed_queries rows (no new
        # rows added) with domain/device/status so exact-interval drill-down can
        # be computed for real from the still-retained rolling window.
        add_column_if_missing(c, "processed_queries", "domain", "TEXT NOT NULL DEFAULT ''")
        add_column_if_missing(c, "processed_queries", "device_key", "TEXT NOT NULL DEFAULT ''")
        add_column_if_missing(c, "processed_queries", "status", "TEXT NOT NULL DEFAULT ''")
        add_column_if_missing(c, "domains", "current_status", "TEXT NOT NULL DEFAULT 'Unknown'")
        add_column_if_missing(c, "domains", "current_reason", "TEXT NOT NULL DEFAULT ''")
        c.execute("""CREATE TABLE IF NOT EXISTS adguard_status_cache(
            domain TEXT PRIMARY KEY, fetched_at TEXT NOT NULL, status TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '')""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_processed_seen ON processed_queries(seen_at)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_device_ips_last_seen ON device_ips(last_seen)")
        c.execute("""CREATE TABLE IF NOT EXISTS ip_ping_status(
            ip TEXT PRIMARY KEY,
            last_checked REAL NOT NULL,
            online INTEGER NOT NULL,
            latency_ms REAL,
            error TEXT NOT NULL DEFAULT '')""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_ip_ping_status_last_checked ON ip_ping_status(last_checked)")
        c.execute("""CREATE TABLE IF NOT EXISTS enrichment_attempts(
            domain TEXT PRIMARY KEY,
            attempted_at REAL NOT NULL,
            next_attempt_at REAL NOT NULL)""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_enrichment_attempt_next ON enrichment_attempts(next_attempt_at)")
        # Issue #88: bounded hourly-aggregated analytics history, independent of
        # (and much smaller than) the 100k-row processed_queries cap, so charts,
        # interval drill-down and scheduled reports keep working for long
        # retained windows without retaining every raw query indefinitely.
        c.execute("""CREATE TABLE IF NOT EXISTS analytics_buckets(
            bucket_start TEXT PRIMARY KEY, bucket_seconds INTEGER NOT NULL,
            query_count INTEGER NOT NULL DEFAULT 0, unique_domains INTEGER NOT NULL DEFAULT 0, unique_devices INTEGER NOT NULL DEFAULT 0,
            allowed INTEGER NOT NULL DEFAULT 0, blocked INTEGER NOT NULL DEFAULT 0, unknown INTEGER NOT NULL DEFAULT 0,
            new_domains INTEGER NOT NULL DEFAULT 0, new_devices INTEGER NOT NULL DEFAULT 0,
            top_domains_json TEXT NOT NULL DEFAULT '[]', top_devices_json TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL)""")
        # Small generic key/value store for settings that need to persist and
        # survive a restart (report scheduling config, map origin, ...) but do
        # not warrant their own narrow table.
        c.execute("""CREATE TABLE IF NOT EXISTS app_settings(
            key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)""")
        c.commit()


def _sqlite_unistr(value):
    """Compatibility implementation for SQLite < 3.50's unistr() function."""
    if value is None:
        return None
    text = str(value)
    out = []
    i = 0
    while i < len(text):
        if text[i] != "\\":
            out.append(text[i])
            i += 1
            continue
        if i + 1 >= len(text):
            out.append("\\")
            i += 1
            continue
        nxt = text[i + 1]
        if nxt == "\\":
            out.append("\\")
            i += 2
            continue
        digits = None
        step = 0
        if nxt in "uU":
            width = 4 if nxt == "u" else 8
            digits = text[i + 2:i + 2 + width]
            step = 2 + width
        elif nxt == "+":
            digits = text[i + 2:i + 2 + 6]
            step = 2 + 6
        else:
            digits = text[i + 1:i + 5]
            step = 4
        expected_len = 4 if nxt not in "uU+" else (6 if nxt == "+" else 4)
        if digits and len(digits) == expected_len and all(ch in "0123456789abcdefABCDEF" for ch in digits):
            try:
                codepoint = int(digits, 16)
                if 0 <= codepoint <= 0x10FFFF:
                    out.append(chr(codepoint))
                    i += step
                    continue
            except (ValueError, OverflowError):
                pass
        out.append("\\")
        i += 1
    return "".join(out)


def _open_trackerdb(path):
    c = sqlite3.connect(path)
    if sqlite3.sqlite_version_info < (3, 50, 0):
        c.create_function("unistr", 1, _sqlite_unistr)
    return c


def trackerdb_ready():
    if not os.path.exists(TRACKERDB_PATH):
        return False
    try:
        with closing(_open_trackerdb(TRACKERDB_PATH)) as c:
            c.execute("SELECT 1 FROM tracker_domains LIMIT 1").fetchone()
        return True
    except Exception:
        return False


def trackerdb_refresh_needed():
    return (not trackerdb_ready()) or (time.time() - os.path.getmtime(TRACKERDB_PATH) > TRACKERDB_REFRESH_HOURS * 3600)


def _execute_sql_file(conn, path):
    """Execute a SQLite .dump incrementally while preserving explicit transactions.
    
    sqlite3.Connection.executescript() implicitly commits any active transaction
    before running the supplied script. That is incompatible with SQLite dumps
    containing BEGIN TRANSACTION / ... / COMMIT because feeding the dump one
    complete statement at a time through executescript() commits the transaction
    after every statement and makes the final COMMIT fail with:
    "cannot commit - no transaction is active".
    
    Execute each complete statement with connection.execute() instead. This
    keeps the dump streaming/bounded in Python memory and preserves the dump's
    own transaction boundaries.
    """
    statement = []
    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        for raw_line in f:
            statement.append(raw_line)
            candidate = "".join(statement)
            if sqlite3.complete_statement(candidate):
                sql = candidate.strip()
                if sql:
                    conn.execute(sql)
                statement.clear()
    trailing = "".join(statement).strip()
    if trailing:
        conn.execute(trailing)


def refresh_trackerdb(force=False):
    if not force and not trackerdb_refresh_needed():
        return
    tmp, newdb = TRACKERDB_PATH + ".download", TRACKERDB_PATH + ".new"
    try:
        print("Downloading TrackerDB snapshot...", flush=True)
        log_event("INFO", "TrackerDB snapshot download started")
        with requests.get(TRACKERDB_URL, timeout=60, stream=True) as r:
            r.raise_for_status()
            with open(tmp, "wb") as f:
                for chunk in r.iter_content(chunk_size=TRACKERDB_DOWNLOAD_CHUNK_SIZE):
                    if chunk:
                        f.write(chunk)
        if os.path.exists(newdb):
            os.remove(newdb)
        with closing(_open_trackerdb(newdb)) as c:
            _execute_sql_file(c, tmp)
            c.execute("PRAGMA journal_mode=DELETE")
        os.replace(newdb, TRACKERDB_PATH)
        try:
            os.remove(tmp)
        except FileNotFoundError:
            pass
        print("TrackerDB ready.", flush=True)
        log_event("INFO", "TrackerDB ready")
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


def adguard_current_status(domain):
    """Read-only current filtering decision from AdGuard Home."""
    domain = str(domain or "").strip().rstrip(".").lower()
    if not domain:
        return "Unknown", ""
    try:
        data = agh_get("/control/filtering/check_host", params={"name": domain})
        reason = str(data.get("reason") or "")
        return query_status(reason), reason
    except Exception as e:
        print(f"AdGuard status check failed for {domain}: {e!r}", flush=True)
        return "Unknown", ""


def cached_adguard_status(domain, max_age_seconds=300):
    domain = str(domain or "").strip().rstrip(".").lower()
    now = datetime.now(timezone.utc)
    with closing(sqlite3.connect(DB_PATH)) as c:
        row = c.execute("SELECT fetched_at,status,reason FROM adguard_status_cache WHERE domain=?", (domain,)).fetchone()
    if row:
        try:
            fetched = datetime.fromisoformat(row[0])
            if fetched.tzinfo is None:
                fetched = fetched.replace(tzinfo=timezone.utc)
            if (now - fetched).total_seconds() < max_age_seconds:
                return row[1], row[2], False
        except Exception:
            pass
    return "Unknown", "", True


def refresh_adguard_status(domain):
    domain = str(domain or "").strip().rstrip(".").lower()
    if not domain:
        return
    status, reason = adguard_current_status(domain)
    if status == "Unknown" and not reason:
        return
    now = utcnow()
    with db_lock, closing(sqlite3.connect(DB_PATH)) as c:
        c.execute("INSERT OR REPLACE INTO adguard_status_cache(domain,fetched_at,status,reason) VALUES(?,?,?,?)", (domain, now, status, reason))
        c.execute("UPDATE domains SET current_status=?, current_reason=? WHERE domain=?", (status, reason, domain))
        c.commit()


def _schedule_adguard_status(domain):
    """Queue at most one bounded AdGuard status refresh per domain.

    Overview requests must never create an unbounded number of threads.
    """
    domain = str(domain or "").strip().rstrip(".").lower()
    if not domain:
        return False
    if not _status_slots.acquire(blocking=False):
        return False
    with _status_guard:
        if domain in _status_inflight:
            _status_slots.release()
            return False
        _status_inflight.add(domain)

    def run():
        try:
            refresh_adguard_status(domain)
        except Exception as e:
            print(f"AdGuard status refresh error for {domain}: {e!r}", flush=True)
        finally:
            with _status_guard:
                _status_inflight.discard(domain)
            _status_slots.release()

    try:
        _status_executor.submit(run)
        return True
    except Exception:
        with _status_guard:
            _status_inflight.discard(domain)
        _status_slots.release()
        return False


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


def hostname_for_ip(ip, allow_network=True):
    if not is_ip(ip):
        return ""
    try:
        with closing(sqlite3.connect(DB_PATH)) as c:
            row = c.execute("SELECT fetched_at,hostname FROM hostname_cache WHERE ip=?", (ip,)).fetchone()
        if row:
            age = datetime.now(timezone.utc) - datetime.fromisoformat(row[0])
            if age.total_seconds() < HOSTNAME_CACHE_HOURS * 3600:
                return row[1]
    except Exception:
        pass
    hostname = ""
    if not allow_network:
        return ""
    try:
        hostname = socket.gethostbyaddr(ip)[0].rstrip(".")
        # Ignore an IP echo or empty result; those are not useful hostnames.
        if hostname == ip:
            hostname = ""
    except Exception:
        hostname = ""
    try:
        with closing(sqlite3.connect(DB_PATH)) as c:
            c.execute("INSERT OR REPLACE INTO hostname_cache(ip,fetched_at,hostname) VALUES(?,?,?)", (ip, utcnow(), hostname))
            c.commit()
    except Exception:
        pass
    return hostname


def mac_vendor_lookup(mac, allow_network=True):
    mac = normalize_mac(mac)
    if not mac:
        return ""
    try:
        with closing(sqlite3.connect(DB_PATH)) as c:
            row = c.execute("SELECT fetched_at,vendor FROM mac_vendor_cache WHERE mac=?", (mac,)).fetchone()
        if row:
            age = datetime.now(timezone.utc) - datetime.fromisoformat(row[0])
            if age.total_seconds() < MACVENDOR_CACHE_HOURS * 3600:
                return row[1]
    except Exception:
        pass
    vendor = ""
    if not allow_network:
        return ""
    try:
        r = requests.get(f"{MACVENDOR_URL}/{quote(mac, safe='')}", timeout=8)
        if r.status_code == 200:
            vendor = r.text.strip()
    except Exception as e:
        print("MAC vendor lookup error:", repr(e), flush=True)
    try:
        with closing(sqlite3.connect(DB_PATH)) as c:
            c.execute("INSERT OR REPLACE INTO mac_vendor_cache(mac,fetched_at,vendor) VALUES(?,?,?)", (mac, utcnow(), vendor))
            c.commit()
    except Exception:
        pass
    return vendor


_enrich_guard = threading.Lock()
_enrich_inflight = set()

def _schedule_device_network_enrichment(device_key, ips, mac, hostname_hint=""):
    key = str(device_key or "")
    if not key:
        return
    with _enrich_guard:
        if key in _enrich_inflight:
            return
        _enrich_inflight.add(key)

    def run():
        try:
            hostname = str(hostname_hint or "").strip()
            if not hostname:
                for ip in ips or []:
                    hostname = hostname_for_ip(ip, allow_network=True)
                    if hostname:
                        break
            vendor = mac_vendor_lookup(mac, allow_network=True) if mac else ""
            with db_lock, closing(sqlite3.connect(DB_PATH)) as c:
                row = c.execute("SELECT hostname,mac,vendor FROM devices WHERE device_key=?", (key,)).fetchone()
                if row:
                    final_hostname = row[0] or hostname
                    final_mac = mac or row[1]
                    final_vendor = vendor or row[2]
                    c.execute("UPDATE devices SET hostname=?, mac=?, vendor=? WHERE device_key=?", (final_hostname, final_mac, final_vendor, key))
                    c.commit()
        except Exception as e:
            print("device enrichment error:", repr(e), flush=True)
        finally:
            with _enrich_guard:
                _enrich_inflight.discard(key)

    threading.Thread(target=run, daemon=True, name="device-enrich").start()

def enrich_device_network_identity(c, device_key, ips, mac, hostname_hint=""):
    # Critical-path enrichment is cache-only. Network lookups are deferred to a
    # background worker so an ingest/reconcile transaction never blocks the UI.
    hostname = str(hostname_hint or "").strip()
    if not hostname:
        for ip in ips or []:
            hostname = hostname_for_ip(ip, allow_network=False)
            if hostname:
                break
    vendor = mac_vendor_lookup(mac, allow_network=False) if mac else ""
    row = c.execute("SELECT hostname,mac,vendor FROM devices WHERE device_key=?", (device_key,)).fetchone()
    if not row:
        _schedule_device_network_enrichment(device_key, ips, mac, hostname)
        return hostname, vendor
    final_hostname = row[0] or hostname
    final_mac = mac or row[1]
    final_vendor = vendor or row[2]
    c.execute("UPDATE devices SET hostname=?, mac=?, vendor=? WHERE device_key=?", (final_hostname, final_mac, final_vendor, device_key))
    if not final_hostname or (mac and not final_vendor):
        _schedule_device_network_enrichment(device_key, ips, mac, final_hostname)
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


BLOCKED_REASONS = {
    "FilteredBlackList",
    "FilteredSafeBrowsing",
    "FilteredParental",
    "FilteredBlockedService",
}
ALLOWED_REASONS = {
    "NotFilteredWhiteList",
    "NotFilteredNotFound",
    "Rewrite",
    "RewriteEtcHosts",
    "RewriteRule",
    "FilteredSafeSearch",
}
UNKNOWN_REASONS = {
    "NotFilteredError",
    "FilteredInvalid",
}

def query_status(reason, original_response=None):
    reason = str(reason or "")
    if reason in BLOCKED_REASONS:
        return "Blocked"
    if reason in ALLOWED_REASONS:
        return "Allowed"
    if reason in UNKNOWN_REASONS:
        return "Unknown"
    # Do not infer "allowed" merely because an answer exists.  AdGuard's
    # reason is the authoritative signal for query-log status.
    return "Unknown"


def status_summary(blocked, allowed, unknown):
    if blocked and allowed:
        return "Mixed", "mixed"
    if blocked:
        return "Blocked", "blocked"
    if allowed:
        return "Allowed", "allowed"
    return "Unknown", "unknown"


def severity_for_classification(classification):
    mapping = {
        "Known service": ("Info", "info"),
        "Known ownership": ("Info", "info"),
        "Telemetry / tracking": ("Low", "low"),
        "Advertising": ("Medium", "medium"),
        "Suspicious": ("High", "high"),
    }
    return mapping.get(classification, ("Unknown", "unknown"))


def upsert_device(c, device_key, name, hostname, mac, ips, source, info, now, increment=True):
    row = c.execute("SELECT request_count FROM devices WHERE device_key=?", (device_key,)).fetchone()
    dtype, icon, confidence = device_hint(name, hostname, info)
    if row:
        if increment:
            c.execute("""UPDATE devices SET name=?, hostname=?, mac=?, device_type=?, icon=?, confidence=?, source=?, first_seen=CASE WHEN first_seen='' THEN ? ELSE first_seen END, last_seen=?, request_count=request_count+1, info_json=? WHERE device_key=?""",
                      (name, hostname, mac, dtype, icon, confidence, source, now, now, json.dumps(info), device_key))
        else:
            c.execute("""UPDATE devices SET name=?, hostname=?, mac=?, device_type=?, icon=?, confidence=?, source=?, first_seen=CASE WHEN first_seen='' THEN ? ELSE first_seen END, last_seen=?, info_json=? WHERE device_key=?""",
                      (name, hostname, mac, dtype, icon, confidence, source, now, now, json.dumps(info), device_key))
    else:
        c.execute("""INSERT INTO devices(device_key,name,hostname,mac,device_type,icon,confidence,source,first_seen,last_seen,request_count,info_json)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                  (device_key, name, hostname, mac, dtype, icon, confidence, source, now, now, 1, json.dumps(info)))
    for ip in ips:
        row2 = c.execute("SELECT requests FROM device_ips WHERE device_key=? AND ip=?", (device_key, ip)).fetchone()
        if row2:
            c.execute("UPDATE device_ips SET last_seen=?, requests=requests+1 WHERE device_key=? AND ip=?", (now, device_key, ip))
        else:
            c.execute("INSERT INTO device_ips(device_key,ip,first_seen,last_seen,requests) VALUES(?,?,?,?,1)", (device_key, ip, now, now))


def _record_domain_destination_ips(c, domain, ips, now):
    if not ips:
        return
    existing_count = None
    for ip in ips:
        updated = c.execute("UPDATE domain_destination_ips SET last_seen=?, observations=observations+1 WHERE domain=? AND ip=?", (now, domain, ip)).rowcount
        if updated:
            continue
        if existing_count is None:
            existing_count = c.execute("SELECT COUNT(*) FROM domain_destination_ips WHERE domain=?", (domain,)).fetchone()[0]
        if existing_count >= GEOIP_DESTINATION_IPS_PER_DOMAIN_LIMIT:
            continue
        c.execute("INSERT INTO domain_destination_ips(domain,ip,first_seen,last_seen,observations) VALUES(?,?,?,?,1)", (domain, ip, now, now))
        existing_count += 1

def ingest(force=False):
    global last_ingest_at
    now_ts = time.time()
    if not force and now_ts - last_ingest_at < max(2, min(POLL_SECONDS, 5)):
        return
    try:
        data = fetch_querylog()
        entries = data.get("data") or []
        now = utcnow()
        with db_lock, closing(sqlite3.connect(DB_PATH)) as c:
            new_count = 0
            status_backfilled = 0
            new_domains_for_enrichment = []
            for e in entries:
                fp = query_fingerprint(e)
                existing = c.execute("SELECT status_counted FROM processed_queries WHERE fingerprint=?", (fp,)).fetchone()
                domain = ((e.get("question") or {}).get("name") or "").rstrip(".").lower()
                observed_destination_ips = extract_observed_answer_ips(e)

                # A previous Inspector version already counted this request but
                # did not persist AdGuard's status. Backfill the status counters
                # when the same query is still present in the rolling Query Log.
                if existing:
                    if int(existing[0] or 0) == 0 and domain:
                        qstatus = query_status(e.get("reason"), e.get("answer"))
                        row = c.execute("SELECT blocked_requests,allowed_requests,unknown_requests FROM domains WHERE domain=?", (domain,)).fetchone()
                        if row:
                            blocked, allowed, unknown = int(row[0] or 0), int(row[1] or 0), int(row[2] or 0)
                            if qstatus == "Blocked": blocked += 1
                            elif qstatus == "Allowed": allowed += 1
                            else: unknown += 1
                            c.execute("UPDATE domains SET blocked_requests=?, allowed_requests=?, unknown_requests=?, last_status=?, last_reason=?, current_status=?, current_reason=? WHERE domain=?", (blocked, allowed, unknown, qstatus, str(e.get("reason") or ""), qstatus, str(e.get("reason") or ""), domain))
                            status_backfilled += 1
                        c.execute("UPDATE processed_queries SET status_counted=1 WHERE fingerprint=?", (fp,))
                    elif existing and int(existing[0] or 0) == 0:
                        c.execute("UPDATE processed_queries SET status_counted=1 WHERE fingerprint=?", (fp,))
                    continue

                ident, cname, source, info, device_key, mac, ips, hostname = client_info_from_entry(e)
                if not domain:
                    c.execute("INSERT OR IGNORE INTO processed_queries(fingerprint,seen_at,status_counted,domain,device_key,status) VALUES(?,?,1,?,?,?)", (fp, now, "", "", ""))
                    continue
                qstatus = query_status(e.get("reason"), e.get("answer"))
                _record_domain_destination_ips(c, domain, observed_destination_ips, now)
                row = c.execute("SELECT clients_json,blocked_requests,allowed_requests,unknown_requests FROM domains WHERE domain=?", (domain,)).fetchone()
                clients = json.loads(row[0]) if row else {}
                clients[device_key] = clients.get(device_key, 0) + 1
                if row:
                    blocked, allowed, unknown = int(row[1] or 0), int(row[2] or 0), int(row[3] or 0)
                    if qstatus == "Blocked": blocked += 1
                    elif qstatus == "Allowed": allowed += 1
                    else: unknown += 1
                    c.execute("UPDATE domains SET last_seen=?, requests=requests+1, clients_json=?, blocked_requests=?, allowed_requests=?, unknown_requests=?, last_status=?, last_reason=?, current_status=?, current_reason=? WHERE domain=?", (now, json.dumps(clients), blocked, allowed, unknown, qstatus, str(e.get("reason") or ""), qstatus, str(e.get("reason") or ""), domain))
                else:
                    blocked = 1 if qstatus == "Blocked" else 0
                    allowed = 1 if qstatus == "Allowed" else 0
                    unknown = 1 if qstatus == "Unknown" else 0
                    c.execute("INSERT INTO domains(domain,first_seen,last_seen,requests,clients_json,blocked_requests,allowed_requests,unknown_requests,last_status,last_reason,current_status,current_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (domain, now, now, 1, json.dumps(clients), blocked, allowed, unknown, qstatus, str(e.get("reason") or ""), qstatus, str(e.get("reason") or "")))
                    new_domains_for_enrichment.append(domain)
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
                c.execute("INSERT OR IGNORE INTO processed_queries(fingerprint,seen_at,status_counted,domain,device_key,status) VALUES(?,?,1,?,?,?)", (fp, now, domain, device_key, qstatus))
                new_count += 1
            # Keep the dedupe table bounded while retaining enough history for repeated 500-entry query-log snapshots.
            c.execute("DELETE FROM processed_queries WHERE rowid IN (SELECT rowid FROM processed_queries ORDER BY seen_at DESC LIMIT -1 OFFSET 100000)")
            c.commit()
        for new_domain in dict.fromkeys(new_domains_for_enrichment):
            _queue_domain_enrichment(new_domain)
        refresh_runtime_clients()
        reconcile_neighbors()
        last_ingest_at = time.time()
        if new_count or status_backfilled:
            print(f"Ingested {new_count} new DNS queries; backfilled {status_backfilled} query statuses.", flush=True)
            log_event("INFO", "DNS ingest cycle", new_queries=new_count, status_backfilled=status_backfilled)
    except Exception as e:
        print("ingest error:", repr(e), flush=True)


def _prune_stale_device_ips():
    """Drop device/IP associations older than DEVICE_IP_RETENTION_HOURS.

    A recycled LAN address can later belong to a completely different
    device, so IP associations must not be kept indefinitely. `last_seen` is
    stored as an ISO-8601 UTC string (see `utcnow()`), so the cutoff must be
    formatted the same way rather than compared as a raw Unix timestamp --
    SQLite's TEXT-affinity comparison would otherwise never match.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=DEVICE_IP_RETENTION_HOURS)).isoformat()
    try:
        with db_lock, closing(sqlite3.connect(DB_PATH)) as c:
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
        time.sleep(DEVICE_IP_CLEANUP_INTERVAL_MINUTES * 60)
        _prune_stale_device_ips()


def _validate_ping_ip(value):
    value = str(value or "").strip()
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError("Invalid IP address")
    if addr.is_loopback or addr.is_multicast or addr.is_unspecified or not addr.is_private:
        raise ValueError("Only private LAN IP addresses can be pinged")
    return value


def _run_ip_ping(ip):
    ip = _validate_ping_ip(ip)
    started = time.monotonic()
    online = False
    latency_ms = None
    error = ""
    try:
        proc = subprocess.run(
            ["ping", "-c", "1", "-W", str(IP_PING_TIMEOUT_SECONDS), ip],
            capture_output=True,
            text=True,
            timeout=IP_PING_TIMEOUT_SECONDS + 2,
            check=False,
        )
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        online = proc.returncode == 0
        if online:
            match = re.search(r"time[=<]([0-9.]+)\s*ms", output)
            latency_ms = float(match.group(1)) if match else round((time.monotonic() - started) * 1000.0, 1)
        else:
            error = "No reply"
    except FileNotFoundError:
        error = "ping command unavailable"
    except subprocess.TimeoutExpired:
        error = "Timeout"
    except Exception as e:
        error = str(e)[:200]

    checked = time.time()
    with db_lock, closing(sqlite3.connect(DB_PATH)) as c:
        c.execute(
            "INSERT OR REPLACE INTO ip_ping_status(ip,last_checked,online,latency_ms,error) VALUES(?,?,?,?,?)",
            (ip, checked, 1 if online else 0, latency_ms, error),
        )
        c.commit()
    return {"ip": ip, "online": online, "latency_ms": latency_ms, "error": error, "last_checked": checked}


def _ping_active_ips():
    cutoff = time.time() - DEVICE_IP_RETENTION_HOURS * 3600.0
    with closing(sqlite3.connect(DB_PATH)) as c:
        ips = [row[0] for row in c.execute(
            "SELECT DISTINCT ip FROM device_ips WHERE last_seen>=? AND ip IS NOT NULL AND TRIM(ip)<>''",
            (cutoff,),
        ).fetchall()]
    for ip in ips:
        try:
            _run_ip_ping(ip)
        except Exception as e:
            print(f"IP ping error for {ip}: {e!r}", flush=True)
    if ips:
        log_event("INFO", "IP reachability sweep completed", checked=len(ips))


def _ip_ping_worker():
    time.sleep(IP_PING_INITIAL_DELAY_SECONDS)
    while True:
        try:
            _ping_active_ips()
        except Exception as e:
            print("IP reachability sweep error:", repr(e), flush=True)
        time.sleep(IP_PING_INTERVAL_HOURS * 3600.0)


@app.route("/api/ip/ping/status", methods=["GET"])
def api_ip_ping_status():
    try:
        with closing(sqlite3.connect(DB_PATH)) as c:
            rows = c.execute("SELECT ip,last_checked,online,latency_ms,error FROM ip_ping_status").fetchall()
        return jsonify({
            "ok": True,
            "statuses": {
                row[0]: {
                    "last_checked": row[1],
                    "online": bool(row[2]),
                    "latency_ms": row[3],
                    "error": row[4] or "",
                }
                for row in rows
            },
        })
    except Exception as e:
        print("IP ping status error:", repr(e), flush=True)
        return jsonify({"ok": False, "statuses": {}}), 500


MANUAL_PING_MIN_INTERVAL_SECONDS = max(1.0, float(os.getenv("MANUAL_PING_MIN_INTERVAL_SECONDS", "3")))
MANUAL_PING_MAX_PER_MINUTE = max(1, int(os.getenv("MANUAL_PING_MAX_PER_MINUTE", "20")))
_manual_ping_lock = threading.Lock()
_manual_ping_last_by_ip = {}
_manual_ping_recent = deque()


def _check_manual_ping_rate_limit(ip):
    """Bound user-triggered LAN pings: a per-target cooldown (stop a single
    button mash from re-spawning `ping` back-to-back for the same host) plus a
    server-wide per-minute cap (stop a caller from sweeping many LAN
    addresses quickly, effectively using this endpoint as a network scanner).
    """
    now = time.monotonic()
    with _manual_ping_lock:
        last = _manual_ping_last_by_ip.get(ip)
        if last is not None and (now - last) < MANUAL_PING_MIN_INTERVAL_SECONDS:
            wait = MANUAL_PING_MIN_INTERVAL_SECONDS - (now - last)
            return False, f"Ping {ip} again in {wait:.1f}s"
        while _manual_ping_recent and (now - _manual_ping_recent[0]) > 60.0:
            _manual_ping_recent.popleft()
        if len(_manual_ping_recent) >= MANUAL_PING_MAX_PER_MINUTE:
            return False, "Too many manual pings; try again shortly"
        _manual_ping_last_by_ip[ip] = now
        _manual_ping_recent.append(now)
        return True, ""


@app.route("/api/ip/ping", methods=["POST"])
def api_ip_ping():
    try:
        data = request.get_json(silent=True) or {}
        ip = _validate_ping_ip(data.get("ip"))
        allowed, reason = _check_manual_ping_rate_limit(ip)
        if not allowed:
            return jsonify({"ok": False, "error": reason}), 429
        return jsonify({"ok": True, "result": _run_ip_ping(ip)})
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:
        print("manual IP ping error:", repr(e), flush=True)
        return jsonify({"ok": False, "error": "Ping failed"}), 500



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
    with db_lock, closing(sqlite3.connect(DB_PATH)) as c:
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
    with db_lock, closing(sqlite3.connect(DB_PATH)) as c:
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
        with closing(sqlite3.connect(TRACKERDB_PATH)) as c:
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


def _netify_page_value(text, heading, stop_headings=()):
    """Extract the first useful value following a Netify section heading."""
    if not text:
        return ""
    stops = "|".join(re.escape(x) for x in stop_headings) if stop_headings else r"$^"
    # The public Netify pages currently render section headings as plain text after
    # HTML stripping. Keep this deliberately permissive because their markup changes.
    pattern = rf"\b{re.escape(heading)}\b\s+(.{{2,220}}?)(?=\s+(?:{stops})\b|$)"
    m = re.search(pattern, text, re.I)
    if not m:
        return ""
    value = re.sub(r"\s+", " ", m.group(1)).strip(" .,:;-|")
    return value


def _netify_extract_stack(text):
    """Parse platform/network/ASN labels from a Netify public page."""
    result = {}
    headings = ("Associated Platform", "Associated Network", "Associated IPs", "Routing Info",
                "IP Info", "Platform", "Network", "ASN Route", "Location", "Category", "Organization")
    platform = _netify_page_value(text, "Associated Platform", headings[1:])
    network = _netify_page_value(text, "Associated Network", headings[2:])
    if platform:
        result["platform"] = platform.split(" - ", 1)[0].strip()
    if network:
        result["network"] = network.split(" - ", 1)[0].strip()
    m = re.search(r"\bASN\s+(AS\d+)\b", text, re.I)
    if m:
        result["asn"] = m.group(1).upper()
    # IP pages expose "ASN Label" as well as the ASN tag.
    if not result.get("asn"):
        m = re.search(r"\bASN\s+Label\s+([^|]+?)(?=\s+ASN Route\b|\s+Category\b|\s+Organization\b|$)", text, re.I)
        if m:
            result["asn_label"] = m.group(1).strip(" .,:;-|")
    return result


def netify_ip_lookup(ip, force=False):
    """Best-effort enrichment from Netify's public IP pages, cached locally."""
    ip = str(ip or "").strip()
    if not ip:
        return {}
    try:
        with closing(sqlite3.connect(DB_PATH)) as c:
            row = c.execute("SELECT fetched_at,json FROM netify_ip_cache WHERE ip=?", (ip,)).fetchone()
        if row:
            age = datetime.now(timezone.utc) - datetime.fromisoformat(row[0])
            if (not force) or age.total_seconds() < NETIFY_CACHE_HOURS * 3600:
                return json.loads(row[1])
    except Exception:
        pass
    result = {}
    try:
        url = f"https://www.netify.ai/resources/ips/{quote(ip, safe='.:')}"
        r = session.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0 DNS-Inspector/" + APP_VERSION})
        if r.ok:
            text = _strip_html_text(r.text)
            result.update(_netify_extract_stack(text))
            m = re.search(r"\b(?:Location|Country)\s+[^|]+?[-–]\s*provided by", text, re.I)
            if m:
                result["location"] = m.group(0).strip()
            result["source_url"] = url
    except Exception as e:
        print("Netify IP lookup error:", repr(e), flush=True)
    try:
        with closing(sqlite3.connect(DB_PATH)) as c:
            c.execute("INSERT OR REPLACE INTO netify_ip_cache(ip,fetched_at,json) VALUES(?,?,?)", (ip, utcnow(), json.dumps(result)))
            c.commit()
    except Exception:
        pass
    return result


def netify_lookup(domain, force=False):
    """Best-effort enrichment from Netify's public hostname pages.
    Netify's paid Hostname API requires a key, so the Inspector uses the public
    hostname/application pages as secondary evidence and caches the result.
    """
    domain = str(domain or '').strip('.').lower()
    if not domain:
        return {}
    try:
        with closing(sqlite3.connect(DB_PATH)) as c:
            row = c.execute("SELECT fetched_at,json FROM netify_cache WHERE domain=?", (domain,)).fetchone()
        if row:
            age = datetime.now(timezone.utc) - datetime.fromisoformat(row[0])
            if (not force) or age.total_seconds() < NETIFY_CACHE_HOURS * 3600:
                return json.loads(row[1])
    except Exception:
        pass
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

            # Netify public hostname pages use explicit "Associated ..." sections.
            # Parse those before the older label:value fallback.
            result.update({k: v for k, v in _netify_extract_stack(text).items() if v and not result.get(k)})
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

            for pat in (r"is associated with (?:the )?(.+?) application", r"associated with (?:the )?(.+?) application"):
                m = re.search(pat, text, re.I)
                if m:
                    app_name = m.group(1).strip(" .,:;-")
                    if app_name:
                        result["application"] = app_name
                        break

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

            if result.get("application") and not result.get("website_url"):
                slug = re.sub(r"[^a-z0-9]+", "-", result["application"].lower()).strip("-")
                if slug:
                    try:
                        ar = session.get(f"https://www.netify.ai/resources/applications/{quote(slug, safe='-')}", timeout=10,
                                         headers={"User-Agent": "Mozilla/5.0 DNS-Inspector/" + APP_VERSION})
                        if ar.ok:
                            at = _strip_html_text(ar.text)
                            pm = re.search(r"Primary Domains\s+(.{0,1000})", at, re.I)
                            if pm:
                                domains = re.findall(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", pm.group(1).lower())
                                if domains:
                                    result["website_url"] = "https://" + domains[0]
                    except Exception:
                        pass

            app = result.get("application", "")
            if not result.get("company_name") and app:
                for marker, owner in (("LG Smart TV", "LG Electronics"), ("LG TV", "LG Electronics"),
                                      ("LG", "LG Electronics"), ("Samsung", "Samsung Electronics"),
                                      ("Bosch", "Bosch"), ("Roborock", "Roborock"), ("PETKIT", "PETKIT")):
                    if marker.lower() in app.lower():
                        result["company_name"] = owner
                        break

            # If the hostname page does not expose platform/network/ASN directly,
            # use its associated IPs. We only promote a value when the evidence is
            # consistent across the IPs we inspect, avoiding misleading mixed results.
            ips = result.get("ips") or []
            if ips and (not result.get("platform") or not result.get("network") or not result.get("asn")):
                ip_results = [netify_ip_lookup(ip) for ip in ips[:8]]
                for key in ("platform", "network", "asn"):
                    if result.get(key):
                        continue
                    vals = [str(x.get(key) or "").strip() for x in ip_results if str(x.get(key) or "").strip()]
                    if vals:
                        counts = {v: vals.count(v) for v in set(vals)}
                        best = max(counts, key=counts.get)
                        # Require a majority of observed IPs to agree.
                        if counts[best] >= max(1, len(vals) // 2 + 1):
                            result[key] = best
                if not result.get("platform"):
                    vals = [str(x.get("platform") or "").strip() for x in ip_results if x.get("platform")]
                    if vals and len(set(vals)) == 1:
                        result["platform"] = vals[0]
                if not result.get("network"):
                    vals = [str(x.get("network") or "").strip() for x in ip_results if x.get("network")]
                    if vals and len(set(vals)) == 1:
                        result["network"] = vals[0]

            if result:
                result["source_url"] = url
                break
    except Exception as e:
        print("Netify lookup error:", repr(e), flush=True)

    try:
        with closing(sqlite3.connect(DB_PATH)) as c:
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
            with closing(sqlite3.connect(DB_PATH)) as c:
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
            with closing(sqlite3.connect(DB_PATH)) as c:
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
        with closing(sqlite3.connect(DB_PATH)) as c:
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
        with closing(sqlite3.connect(DB_PATH)) as c:
            c.execute("INSERT OR REPLACE INTO dns_records_cache(domain,fetched_at,json) VALUES(?,?,?)", (domain, utcnow(), json.dumps(records)))
            c.commit()
    except Exception:
        pass
    return records


def _cache_needs_refresh(table, domain, max_age_hours):
    """Return True when a cache row is missing or older than its TTL."""
    try:
        with closing(sqlite3.connect(DB_PATH)) as c:
            row = c.execute(f"SELECT fetched_at FROM {table} WHERE domain=?", (domain,)).fetchone()
        if not row:
            return True
        age = datetime.now(timezone.utc) - datetime.fromisoformat(row[0])
        return age.total_seconds() >= max_age_hours * 3600
    except Exception:
        return True


def _enrichment_retry_allowed(domain, now_ts=None):
    """Return True unless this domain's enrichment was attempted too recently.

    A missing/failed lookup must not be retried on every ~10s UI poll, so the
    next-allowed-attempt timestamp is persisted in SQLite and mirrored here.
    """
    now_ts = time.time() if now_ts is None else now_ts
    until = _enrichment_retry_until.get(domain)
    if until is not None:
        return until <= now_ts
    if domain in _enrichment_retry_loaded:
        return True
    try:
        with closing(sqlite3.connect(DB_PATH)) as c:
            row = c.execute("SELECT next_attempt_at FROM enrichment_attempts WHERE domain=?", (domain,)).fetchone()
        until = float(row[0]) if row else 0.0
        if row:
            _enrichment_retry_until[domain] = until
    except Exception:
        until = 0.0
    _enrichment_retry_loaded.add(domain)
    return until <= now_ts


def _mark_enrichment_attempt(domain, now_ts=None):
    now_ts = time.time() if now_ts is None else now_ts
    next_ts = now_ts + ENRICHMENT_RETRY_HOURS * 3600.0
    _enrichment_retry_until[domain] = next_ts
    try:
        with closing(sqlite3.connect(DB_PATH)) as c:
            c.execute(
                "INSERT OR REPLACE INTO enrichment_attempts(domain,attempted_at,next_attempt_at) VALUES(?,?,?)",
                (domain, now_ts, next_ts),
            )
            c.commit()
    except Exception as e:
        print('enrichment retry-state error:', repr(e), flush=True)
    return next_ts


def _queue_domain_enrichment(domain):
    """Queue at most one bounded enrichment refresh per domain.

    Enrichment never runs on the request path and never spawns one thread
    per domain; a single background worker drains this bounded queue.
    """
    domain = str(domain or '').strip('.').lower()
    if not domain:
        return False
    with _enrichment_queue_lock:
        if domain in _enrichment_queued or domain in enrichment_refreshing:
            return False
        if not _enrichment_retry_allowed(domain):
            return False
        try:
            _enrichment_queue.put_nowait(domain)
        except queue.Full:
            return False
        _enrichment_queued.add(domain)
        _mark_enrichment_attempt(domain)
    return True


def _enrichment_worker():
    while True:
        domain = _enrichment_queue.get()
        with _enrichment_queue_lock:
            _enrichment_queued.discard(domain)
        with enrichment_lock:
            enrichment_refreshing.add(domain)
        try:
            # Re-check every source at execution time; fresh data is never touched.
            if _cache_needs_refresh("netify_cache", domain, NETIFY_CACHE_HOURS):
                netify_lookup(domain, force=True)
            if _cache_needs_refresh("rdap_cache", apex_domain(domain), RDAP_CACHE_HOURS):
                rdap_lookup(domain, force=True)
            if _cache_needs_refresh("dns_records_cache", domain, DNS_RECORDS_CACHE_HOURS):
                dns_records_lookup(domain, force=True)
        except Exception as e:
            print('enrichment worker error:', repr(e), flush=True)
        finally:
            with enrichment_lock:
                enrichment_refreshing.discard(domain)
            _enrichment_queue.task_done()
            time.sleep(max(0.0, float(os.getenv('ENRICHMENT_DELAY_SECONDS', '1.0'))))


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

def inline_external_button(url, title, icon=""):
    # All external actions use the same magnifier + visible label. The icon
    # argument is retained for compatibility but intentionally ignored so the
    # UI stays uniform everywhere.
    glyph = "<svg viewBox='0 0 24 24' aria-hidden='true'><circle cx='11' cy='11' r='6.5'></circle><path d='M16 16l5 5'></path></svg>"
    return f"<a class='external-tool' href='{_html(url)}' title='{_html(title)}' aria-label='{_html(title)}' target='_blank' rel='noopener noreferrer'>{glyph} {_html(title)}</a>"


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



def real_device_label(c):
    vendor = str(c.get('vendor') or '').strip().casefold()
    identifier = str(c.get('identifier') or c.get('device_key') or '').strip().casefold()
    for value in (c.get('hostname'), c.get('name'), c.get('display_name')):
        text = str(value or '').strip()
        if not text:
            continue
        folded = text.casefold()
        if folded in {vendor, identifier}:
            continue
        return text
    return ''

def inspect_html(result):
    if not result:
        return ""
    client_rows = []
    for c in result["client_details"]:
        key = quote(c.get("device_key", ""), safe="")
        linked_name = real_device_label(c)
        name_value = linked_name or c.get("vendor") or c.get("device_key") or "Unknown"
        name = _html(name_value)
        name_html = f"<a class='link-device' href='/device?key={key}'><div class='device-name'>{name}</div></a>" if linked_name else f"<div class='device-name'>{name}</div>"
        logo = vendor_visual(c.get("vendor"), c.get("vendor_logo"), True, c.get("icon", "◈"), c.get("type", ""))
        vendor_tools = inline_external_button(vendor_lookup_url(c.get('vendor')), "Vendor lookup", "") if c.get('vendor') else ""
        vendor = f"<div class='sub'>{vendor_visual(c.get('vendor'), c.get('vendor_logo'))}{_html(c['vendor'])}{vendor_tools}</div>" if c.get("vendor") else ""
        host = f"<div class='sub mono'><a class='link-device' href='/device?key={key}'>HOST {_html(c['hostname'])}</a></div>" if c.get("hostname") and c.get("hostname") != c.get("display_name") else ""
        mac = _html(c.get("mac") or "—")
        mac_tools = inline_external_button(mac_lookup_url(c.get("mac")), "MAC vendor lookup", "") if c.get("mac") else ""
        ips = ''.join(f"<a class='client-chip mono link-ip' href='/ip?addr={quote(ip, safe='')}' title='Open IP details'>{_html(ip)}</a>" for ip in c.get("ips", [])) or '—'
        visual_html = f"<a class='link-device' href='/device?key={key}' title='Open device details'>{logo}</a>" if linked_name else logo
        client_rows.append(f"<tr><td><div class='device'>{visual_html}<span>{name_html}{vendor}{host}<div class='confidence'>{_html(c.get('type'))} · {_html(c.get('confidence_label'))}</div></span></div></td><td>{ips}</td><td><span class='mono'>{mac}</span> {mac_tools}</td><td>{c['requests']}</td></tr>")
    clients_html = ''.join(client_rows)
    e = result["explanation"]
    evidence_html = "".join(f"<li>{_html(x)}</li>" for x in e["evidence"])
    dns_html = "".join(f"<a class='dns-ip link-ip' href='/ip?addr={quote(ip, safe='')}' title='Open IP details'>{_html(ip)}</a>" for ip in result['dns']) or "<span class='sub'>No A/AAAA result</span>"
    return f"""
<div class='card'><h2>{_html(result['domain'])}</h2>
<div><span class='status-pill status-{result['status_class']}'>{_html(result['status'])}</span><span class='tag'>{_html(result['severity'])}</span><span class='tag {result['badge_class']}'>{_html(result['classification'])}</span>
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


def classify(tracker, rdap, netify=None):
    """Classify using multiple cached evidence sources without over-claiming."""
    netify = netify or {}
    cat = (tracker.get("category") or "").lower()
    app_name = (netify.get("application") or "").strip()
    company = (netify.get("company_name") or "").strip()
    if cat == "advertising":
        return "Advertising", "orange", "orange"
    if cat in {"site_analytics", "social_media", "extensions"}:
        return "Telemetry / tracking", "yellow", "yellow"
    if cat:
        return "Known service", "green", "green"
    if app_name or company:
        return "Known service", "green", "green"
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

VENDOR_FAVICONS = {
    "dell": "/static/vendor-favicons/dell.ico",
    "lg innotek": "/static/vendor-favicons/lg.ico",
    "lge": "/static/vendor-favicons/lg.ico",
    "lg": "/static/vendor-favicons/lg.ico",
    "zte": "/static/vendor-favicons/zte.ico",
    "bosch": "/static/vendor-favicons/bosch.ico",
    "roborock": "/static/vendor-favicons/roborock.ico",
    "beijing roborock technology": "/static/vendor-favicons/roborock.ico",
    "petkit": "/static/vendor-favicons/petkit.ico",
}

def _local_static_exists(url):
    if not url:
        return False
    return os.path.exists(os.path.join(BASE_DIR, url.lstrip("/")))

def device_type_visual(device_type="", icon="📦", large=False):
    """Render a local, dependency-free SVG for devices without a vendor mark.
    This replaces platform-dependent emoji/"stock" glyphs with consistent UI icons.
    """
    t = str(device_type or "").lower()
    size = 30 if large else 20
    cls = "device-type-icon-lg" if large else "device-type-icon"
    # Simple outline glyphs; all are intentionally monochrome and CSS-driven.
    if "phone" in t or "tablet" in t:
        body = '<rect x="7" y="3" width="10" height="18" rx="2"/><circle cx="12" cy="18" r="1" fill="currentColor" stroke="none"/>'
    elif "computer" in t:
        body = '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M9 20h6M12 16v4"/>'
    elif "console" in t:
        body = '<rect x="3" y="7" width="18" height="10" rx="3"/><path d="M7 12h4M9 10v4M16 10h.01M18 12h.01"/>'
    elif "camera" in t:
        body = '<path d="M5 8h4l2-3h2l2 3h4v10H5z"/><circle cx="12" cy="13" r="3"/>'
    elif "speaker" in t:
        body = '<rect x="7" y="3" width="10" height="18" rx="2"/><circle cx="12" cy="9" r="2"/><circle cx="12" cy="16" r="3"/>'
    elif "network" in t:
        body = '<rect x="9" y="3" width="6" height="5" rx="1"/><rect x="3" y="16" width="6" height="5" rx="1"/><rect x="15" y="16" width="6" height="5" rx="1"/><path d="M12 8v4M6 16v-2h12v2"/>'
    elif "washing" in t or "dishwasher" in t or "appliance" in t:
        body = '<rect x="5" y="3" width="14" height="18" rx="2"/><circle cx="12" cy="13" r="4"/><path d="M8 6h.01M11 6h.01M14 6h.01"/>'
    elif "vacuum" in t:
        body = '<circle cx="12" cy="14" r="6"/><path d="M8 9l-2-4h4M12 8v3"/>'
    elif "tv" in t:
        body = '<rect x="3" y="5" width="18" height="12" rx="2"/><path d="M9 21h6M12 17v4"/>'
    else:
        # Generic connected IoT/device icon instead of the system emoji box.
        body = '<rect x="5" y="6" width="14" height="14" rx="3"/><path d="M9 3v3M15 3v3M9 20v1M15 20v1M3 10h2M3 16h2M19 10h2M19 16h2"/><circle cx="12" cy="13" r="2"/>'
    return f'<span class="{cls}" aria-hidden="true"><svg viewBox="0 0 24 24">{body}</svg></span>'


def vendor_logo_url(vendor):
    """Prefer an official vendor favicon bundled at build time.

    If a vendor blocks favicon fetching during CI, fall back to the bundled
    vendor mark so a known vendor never collapses to the generic gray device
    icon. The fallback is local and never fetched by the browser.
    """
    text = str(vendor or "").lower()
    for key, url in VENDOR_FAVICONS.items():
        if key in text and _local_static_exists(url):
            return url
    for key, url in VENDOR_LOGOS.items():
        if key in text and _local_static_exists(url):
            return url
    return ""


def vendor_visual(vendor, logo_url="", large=False, fallback="◈", device_type=""):
    cls = "vendor-logo-lg" if large else "vendor-logo"
    if logo_url:
        return f"<img class=\"{cls}\" src=\"{_html(logo_url)}\" alt=\"\" loading=\"lazy\">"
    return device_type_visual(device_type, fallback, large=large)


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
    elif netify and (netify.get("application") or netify.get("company_name")): summary, tone, confidence = "Known service identified by Netify.", "green", "Medium"
    elif rdap.get("org"): summary, tone, confidence = "Known infrastructure with ownership data.", "blue", "Medium"
    else: summary, tone, confidence = "Purpose is not established from available signals.", "gray", "Low"
    return {"summary": summary, "tone": tone, "confidence": confidence, "evidence": evidence or ["No strong identifying signals are available yet"]}


def _resolve_search_domain(query):
    """Resolve a search query to the single most relevant observed domain.

    Order: exact domain match, then partial domain match, then device
    identity fields (name/hostname/mac/vendor) and recent IPs -- the device
    match is scored by how much of that device's own traffic falls under
    each candidate domain, so a single search box can find a device's
    activity without a separate device search.
    """
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


def inspect_domain(domain):
    domain = _resolve_search_domain(domain)
    if not domain:
        return None
    with closing(sqlite3.connect(DB_PATH)) as c:
        row = c.execute("SELECT domain,first_seen,last_seen,requests,clients_json,blocked_requests,allowed_requests,unknown_requests,last_status,last_reason,current_status,current_reason FROM domains WHERE domain=?", (domain,)).fetchone()
        if not row:
            return None
        blocked_requests, allowed_requests, unknown_requests, last_status, last_reason, current_status, current_reason = row[5], row[6], row[7], row[8], row[9], row[10], row[11]
        tracker = tracker_lookup(domain)
        # Slow external enrichment is read from local cache only. Missing or
        # expired data is refreshed asynchronously below.
        rdap = rdap_lookup(domain)
        netify = netify_lookup(domain)
        dns_records = dns_records_lookup(domain)
        classification, badge, severity = classify(tracker, rdap, netify)
        clients_map = canonicalize_client_map(json.loads(row[4] or "{}"))
        client_details = [client_display(c, key, count) for key, count in sorted(clients_map.items(), key=lambda kv: kv[1], reverse=True)]

    needs_refresh = (
        _cache_needs_refresh("netify_cache", domain, NETIFY_CACHE_HOURS)
        or _cache_needs_refresh("rdap_cache", apex_domain(domain), RDAP_CACHE_HOURS)
        or _cache_needs_refresh("dns_records_cache", domain, DNS_RECORDS_CACHE_HOURS)
    )
    if needs_refresh:
        _queue_domain_enrichment(domain)

    dns = resolve_dns(domain, dns_records)
    return {
        "domain": row[0], "first_seen": row[1], "last_seen": row[2], "requests": row[3], "clients": clients_map,
        "classification": classification, "badge_class": badge, "severity_class": severity, "tracker": tracker,
        "status": (current_status if current_status and current_status != "Unknown" else status_summary(int(blocked_requests or 0), int(allowed_requests or 0), int(unknown_requests or 0))[0]), "status_class": ((current_status if current_status and current_status != "Unknown" else status_summary(int(blocked_requests or 0), int(allowed_requests or 0), int(unknown_requests or 0))[0]).lower()),
        "severity": severity_for_classification(classification)[0], "severity_text_class": severity_for_classification(classification)[1],
        "status_counts": {"blocked": int(blocked_requests or 0), "allowed": int(allowed_requests or 0), "unknown": int(unknown_requests or 0)}, "last_status": last_status, "last_reason": last_reason, "current_status": current_status, "current_reason": current_reason,
        "company": {"name": tracker.get("company_name") or rdap.get("org") or netify.get("company_name") or netify.get("application") or "", "description": tracker.get("description", "") or netify.get("description", ""), "website_url": tracker.get("company_website", "") or tracker.get("website_url", "") or netify.get("website_url", ""), "country": tracker.get("country", "") or rdap.get("country", "") or netify.get("country", "")},
        "rdap": rdap, "netify": netify, "dns": dns, "dns_records": dns_records, "client_details": client_details,
        "explanation": build_explanation(domain, tracker, rdap, client_details, netify),
    }

def _parse_ui_timestamp(value):
    if not value:
        return None
    try:
        text=str(value).strip()
        if text.endswith("Z"):
            text=text[:-1]+"+00:00"
        dt=datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt=dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _is_new_domain(first_seen):
    dt=_parse_ui_timestamp(first_seen)
    return bool(dt and (datetime.now(timezone.utc)-dt).total_seconds()<86400)


def get_filter_options():
    # Reuse the exact same friendly-label logic as the Devices view instead of
    # duplicating a simplified SQL COALESCE rule, so the Overview device
    # dropdown never disagrees with how a device is actually labelled.
    with closing(sqlite3.connect(DB_PATH)) as c:
        vendors=[r[0] for r in c.execute("SELECT DISTINCT vendor FROM devices WHERE TRIM(vendor)<>'' ORDER BY vendor COLLATE NOCASE").fetchall()]
        rows=c.execute("SELECT device_key,name,hostname,vendor FROM devices ORDER BY request_count DESC, device_key COLLATE NOCASE").fetchall()
        devices=[]
        for device_key,name,hostname,vendor in rows:
            label=real_device_label({"device_key":device_key,"identifier":device_key,"name":name,"hostname":hostname,"display_name":hostname or name or vendor or device_key,"vendor":vendor})
            label=label or str(vendor or '').strip() or device_key
            devices.append({"value":device_key,"label":label})
    return {"classifications":["Known service","Telemetry / Tracking","Advertising","Suspicious","Unknown"],"severities":["Info","Low","Medium","High","Unknown"],"vendors":vendors,"devices":devices}


def _status_from_counts(blocked, allowed):
    blocked = int(blocked or 0)
    allowed = int(allowed or 0)
    if blocked and allowed:
        return "Mixed", "mixed"
    if blocked:
        return "Blocked", "blocked"
    if allowed:
        return "Allowed", "allowed"
    return "Unknown", "unknown"


def get_recent(page=1,page_size=50,status_filter="",new_only=False,classification_filter="",severity_filter="",device_filter="",vendor_filter=""):
    page=max(1,int(page or 1)); page_size=max(10,min(500,int(page_size or 50)))
    order_sql="first_seen DESC" if new_only else "requests DESC"
    now_dt=datetime.now(timezone.utc)
    cutoff=(now_dt-timedelta(hours=24)).isoformat()

    # Status and NEW are persisted in the domains table, so do not scan
    # thousands of domains and run TrackerDB/RDAP/Netify lookups just to
    # answer a simple Overview filter. This is the main latency/memory fix
    # for the Allowed/Blocked/Mixed/NEW filters.
    simple_filter = not (classification_filter or severity_filter or device_filter or vendor_filter)
    where=[]
    params=[]
    if new_only:
        where.append("first_seen>=?")
        params.append(cutoff)
    if status_filter:
        if status_filter == "Allowed":
            where.append("blocked_requests=0 AND allowed_requests>0")
        elif status_filter == "Blocked":
            where.append("blocked_requests>0 AND allowed_requests=0")
        elif status_filter == "Mixed":
            where.append("blocked_requests>0 AND allowed_requests>0")
        elif status_filter == "Unknown":
            where.append("blocked_requests=0 AND allowed_requests=0")
    sql_where = (" WHERE " + " AND ".join(where)) if where else ""

    with closing(sqlite3.connect(DB_PATH)) as c:
        status_rows = c.execute("SELECT SUM(CASE WHEN blocked_requests=0 AND allowed_requests=0 THEN 1 ELSE 0 END), SUM(CASE WHEN blocked_requests=0 AND allowed_requests>0 THEN 1 ELSE 0 END), SUM(CASE WHEN blocked_requests>0 AND allowed_requests=0 THEN 1 ELSE 0 END), SUM(CASE WHEN blocked_requests>0 AND allowed_requests>0 THEN 1 ELSE 0 END) FROM domains").fetchone()
        status_counts={
            "All": int(c.execute("SELECT COUNT(*) FROM domains").fetchone()[0] or 0),
            "Unknown": int(status_rows[0] or 0),
            "Allowed": int(status_rows[1] or 0),
            "Blocked": int(status_rows[2] or 0),
            "Mixed": int(status_rows[3] or 0),
        }

        if simple_filter:
            total=int(c.execute("SELECT COUNT(*) FROM domains" + sql_where, tuple(params)).fetchone()[0] or 0)
            pages=max(1,(total+page_size-1)//page_size)
            page=min(page,pages)
            offset=(page-1)*page_size
            rows=c.execute(f"SELECT domain,requests,clients_json,first_seen,blocked_requests,allowed_requests,unknown_requests,last_status,current_status,current_reason FROM domains{sql_where} ORDER BY {order_sql} LIMIT ? OFFSET ?", tuple(params)+(page_size,offset)).fetchall()
        else:
            # Complex filters still need enrichment, but status/NEW constraints
            # are pushed into SQL first so unrelated domains are never scanned.
            scan_limit=max(500,min(3000,page*page_size+500))
            rows=c.execute(f"SELECT domain,requests,clients_json,first_seen,blocked_requests,allowed_requests,unknown_requests,last_status,current_status,current_reason FROM domains{sql_where} ORDER BY {order_sql} LIMIT ?", tuple(params)+(scan_limit,)).fetchall()

        matched=[]
        for domain,requests_count,clients_json,first_seen,blocked_requests,allowed_requests,unknown_requests,last_status,current_status,current_reason in rows:
            try:
                clients=canonicalize_client_map(json.loads(clients_json or "{}"))
            except Exception:
                clients={}
            devices=[]; row_vendors=set(); row_keys=set()
            for key,count in sorted(clients.items(),key=lambda kv:kv[1],reverse=True)[:6]:
                d=client_display(c,key,count); dkey=d.get("device_key",key); row_keys.add(dkey)
                vendor=d.get("vendor","")
                if vendor: row_vendors.add(vendor)
                devices.append({"device_key":dkey,"identifier":d.get("identifier",key),"name":d.get("hostname") or d.get("name") or vendor or d.get("display_name") or key,"icon":d.get("icon","📦"),"type":d.get("type","IoT / Unknown"),"vendor_logo":d.get("vendor_logo",""),"vendor":vendor})

            # Enrichment is needed for the classification/severity columns, but
            # it is only performed for rows that can actually appear here.
            t=tracker_lookup(domain); rd=rdap_lookup(domain); n=netify_lookup(domain)
            cls,badge,severity=classify(t,rd,n)
            status,status_class=_status_from_counts(blocked_requests,allowed_requests)
            if status_filter and status!=status_filter: continue
            is_new=_is_new_domain(first_seen)
            if new_only and not is_new: continue
            sev,sev_class=severity_for_classification(cls)
            if classification_filter and cls!=classification_filter: continue
            if severity_filter and sev!=severity_filter: continue
            if device_filter and device_filter not in row_keys: continue
            if vendor_filter and vendor_filter not in row_vendors: continue

            # Only queue a stale-status refresh when the row is actually relevant.
            try:
                cached_status,cached_reason,stale=cached_adguard_status(domain)
                if cached_status!="Unknown":
                    status,status_class=cached_status,cached_status.lower()
                if stale:
                    _schedule_adguard_status(domain)
            except Exception:
                cached_reason=""

            matched.append({"domain":domain,"requests":int(requests_count),"clients":len(clients),"devices":devices,"classification":cls,"badge_class":badge,"severity_class":severity,"severity":sev,"severity_text_class":sev_class,"status":status,"status_class":status_class,"last_status":last_status,"current_reason":cached_reason or current_reason,"first_seen":first_seen,"is_new":is_new})

        if simple_filter:
            # SQL already selected the exact page; keep the pagination metadata exact.
            page_rows=matched
        else:
            total=len(matched)
            pages=max(1,(total+page_size-1)//page_size)
            page=min(page,pages)
            start_i=(page-1)*page_size
            page_rows=matched[start_i:start_i+page_size]

        exact_new=int(c.execute("SELECT COUNT(*) FROM domains WHERE first_seen>=?",(cutoff,)).fetchone()[0] or 0)
        fresh_cutoff=(now_dt-timedelta(seconds=max(30,UI_REFRESH_SECONDS*2))).isoformat()
        fresh_domains=[r[0] for r in c.execute("SELECT domain FROM domains WHERE first_seen>=? ORDER BY first_seen DESC LIMIT 10",(fresh_cutoff,)).fetchall()]

    if simple_filter:
        total=int(total)
        pages=max(1,(total+page_size-1)//page_size)
    else:
        total=len(matched)
        pages=max(1,(total+page_size-1)//page_size)
    return {"rows":page_rows,"meta":{"page":page,"pages":pages,"total":total,"page_size":page_size,"new_count":exact_new,"new_domains":fresh_domains,"status_counts":status_counts}}

def get_clients():
    with closing(sqlite3.connect(DB_PATH)) as c:
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
    with closing(sqlite3.connect(DB_PATH)) as c:
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
    with closing(sqlite3.connect(DB_PATH)) as c:
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
    domains = "".join(f"<tr><td><a href='/search?q={quote(x['domain'], safe='')}' title='Inspect domain in DNS Inspector'>{_html(x['domain'])}</a></td><td>{x['requests']}</td><td class='mono'>{_html(x['last_seen'])}</td></tr>" for x in d['domains']) or "<tr><td colspan='3' class='sub'>No domain activity recorded.</td></tr>"
    device_tools = []
    search_url = device_search_url(primary, d.get('hostname'), d.get('vendor'))
    if search_url: device_tools.append(inline_external_button(search_url, 'Search device'))
    if d.get('mac'): device_tools.append(inline_external_button(mac_lookup_url(d['mac']), 'MAC lookup'))
    return f"""<div class='card'><p><a href='/'>&larr; Back to dashboard</a></p><div class='device' style='margin-bottom:14px'><span>{logo}</span><span><h2 style='margin:0'>{_html(primary)}</h2><div class='sub'>{_html(d.get('vendor') or 'Unknown vendor')}</div><div class='confidence'>{_html(d.get('type'))} · {_html(d.get('confidence'))}</div></span></div><div class='external-tools'>{''.join(device_tools)}</div><div class='grid'><div><div class='kv'><b>MAC:</b> <span class='mono'>{_html(d.get('mac') or '—')}</span></div><div class='kv'><b>Hostname:</b> <span class='mono'>{_html(d.get('hostname') or '—')}</span></div><div class='kv'><b>Source:</b> {_html(d.get('source') or '—')}</div></div><div><div class='kv'><b>First seen:</b> {_html(d.get('first_seen') or '—')}</div><div class='kv'><b>Last seen:</b> {_html(d.get('last_seen') or '—')}</div><div class='kv'><b>Total queries:</b> {_html(d.get('request_count'))}</div></div></div><h3>IP history</h3><div class='dns-list'>{ips}</div><h3>Top DNS activity</h3><table><thead><tr><th>Domain</th><th>Queries</th><th>Last seen</th></tr></thead><tbody>{domains}</tbody></table></div>"""


def detail_html_ip(d):
    device_rows = []
    for x in d['devices']:
        href = quote(x['device_key'], safe='')
        linked_primary = real_device_label(x)
        primary = linked_primary or x.get('vendor') or x['device_key']
        label = f"<a class='link-device' href='/device?key={href}'>{_html(primary)}</a>" if linked_primary else _html(primary)
        visual = vendor_visual(x.get('vendor'), x.get('vendor_logo'), False, x.get('icon','◈'), x.get('type', ''))
        device_rows.append(f"<tr><td>{visual}{label}</td><td class='mono'>{_html(x.get('mac') or '—')} {inline_external_button(mac_lookup_url(x.get('mac')), 'MAC vendor lookup', '') if x.get('mac') else ''}</td><td>{x['requests']}</td></tr>")
    devices = ''.join(device_rows) or "<tr><td colspan='3' class='sub'>No known device mapping.</td></tr>"
    domains = "".join(f"<tr><td><a href='/search?q={quote(x['domain'], safe='')}' title='Inspect domain in DNS Inspector'>{_html(x['domain'])}</a></td><td>{x['requests']}</td><td class='mono'>{_html(x['last_seen'])}</td></tr>" for x in d['domains']) or "<tr><td colspan='3' class='sub'>No DNS activity recorded.</td></tr>"
    return f"""<div class='card'><p><a href='/'>&larr; Back to dashboard</a></p><h2 class='mono'>{_html(d['ip'])}</h2><p class='muted'>IP observation · {len(d['devices'])} known device(s)</p><h3>Known devices</h3><table><thead><tr><th>Device</th><th>MAC</th><th>Queries</th></tr></thead><tbody>{devices}</tbody></table><h3>Domains contacted</h3><table><thead><tr><th>Domain</th><th>Queries</th><th>Last seen</th></tr></thead><tbody>{domains}</tbody></table></div>"""

def recent_html(recent):
    rows = []
    for r in recent:
        rows.append(
            f"<tr data-sort-domain='{_html(r['domain'])}' data-sort-activity='{int(r['requests'])}' data-sort-devices='{int(r['clients'])}' data-sort-status='{_html(r['status'])}' data-sort-severity='{_html(r['severity'])}' data-sort-classification='{_html(r['classification'])}'>"
            f"<td><a class='glance-domain' href='/search?q={quote(r['domain'], safe='')}' title='Inspect domain in DNS Inspector'>{_html(r['domain'])}</a><div class='glance-meta'><span>{int(r['requests'])} requests</span><span>·</span><span>{int(r['clients'])} device{'s' if int(r['clients']) != 1 else ''}</span></div></td>"
            f"<td><b>{int(r['requests'])}</b> requests</td><td class='glance-devices'><div class='device-list'>"
            + ''.join(f"<a class='device-chip link-device' href='/device?key={quote(d.get('identifier') or d.get('device_key') or '', safe='')}'>{vendor_visual(d.get('vendor',''), d.get('vendor_logo',''), False, d.get('icon','📦'), d.get('type',''))}{_html(d.get('name') or d.get('identifier') or '')}</a>" for d in r.get('devices', []))
            + ("<span class='sub'>No identified devices</span>" if not r.get('devices') else "")
            + f"</div></td><td><span class='status-pill status-{r['status_class']}'>{_html(r['status'])}</span></td><td><span class='severity-{r['severity_text_class']}'>{_html(r['severity'])}</span></td><td><span class='dot dot-{r['severity_class']}'></span><span class='tag {r['badge_class']}'>{_html(r['classification'])}</span></td></tr>"
        )
    return ''.join(rows)



def clients_html(clients):
    rows = []
    for c in clients:
        key = c.get('identifier','')
        href = quote(key, safe='')
        linked_primary = real_device_label(c)
        primary = linked_primary or c.get('vendor') or key
        primary_html = f"<a class='link-device' href='/device?key={href}' title='Open device details'><div class='device-name'>{_html(primary)}</div></a>" if linked_primary else f"<div class='device-name'>{_html(primary)}</div>"
        secondary = []
        if c.get('vendor') and c.get('vendor') != primary: secondary.append(f"<div class='sub'>{_html(c['vendor'])}{inline_external_button(vendor_lookup_url(c.get('vendor')), 'Vendor lookup', '')}</div>")
        if c.get('hostname') and c.get('hostname') != primary: secondary.append(f"<div class='technical mono'><a class='link-device' href='/device?key={href}' title='Open device details'>HOST {_html(c['hostname'])}</a></div>")
        visual = vendor_visual(c.get('vendor'), c.get('vendor_logo'), True, c.get('icon','◈'), c.get('type',''))
        ips = ''.join(f"<a class='client-chip mono link-ip' href='/ip?addr={quote(ip, safe='')}' title='Open IP details'>{_html(ip)}</a>" for ip in c.get('ips', [])) or '—'
        mac = _html(c.get('mac') or '—')
        mac_tools = inline_external_button(mac_lookup_url(c.get('mac')), 'MAC vendor lookup', '') if c.get('mac') else ''
        visual_html = f"<a class='link-device' href='/device?key={href}'>{visual}</a>" if linked_primary else visual
        rows.append(f"<tr><td><div class='device'>{visual_html}<span>{primary_html}{''.join(secondary)}<div class='confidence'>{_html(c['type'])} · {_html(c['confidence_label'])}</div></span></div></td><td>{ips}</td><td><span class='mono'>{mac}</span> {mac_tools}</td><td>{c['requests']}</td></tr>")
    return ''.join(rows)


# --- Analytics: bounded reads from existing persisted history ----------------
ANALYTICS_RANGE_OPTIONS = ["1h", "6h", "24h", "7d", "30d", "90d"]
ANALYTICS_LIVE_WINDOW_SECONDS = 60
ANALYTICS_ACTIVE_DEVICE_WINDOW_SECONDS = 300
_ANALYTICS_RANGES = {"1h": (3600, 60, 60, "Last hour"), "6h": (21600, 300, 72, "Last 6 hours"), "24h": (86400, 900, 96, "Last 24 hours"), "7d": (604800, 7200, 84, "Last 7 days")}
# 30d/90d are backed by the bounded analytics_buckets aggregation table
# (hourly rows rolled up into coarser display buckets) rather than raw
# processed_queries, since that table is not guaranteed to retain 30-90 days
# of history at higher query volumes.
_ANALYTICS_BUCKET_RANGES = {"30d": (30 * 86400, 21600, 120, "Last 30 days"), "90d": (90 * 86400, 86400, 90, "Last 90 days")}

def _parse_iso(value):
    try: dt = datetime.fromisoformat(value)
    except (TypeError, ValueError): return None
    if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
    return dt

def _analytics_range(range_key): return _ANALYTICS_RANGES.get(range_key, _ANALYTICS_RANGES["1h"])

def _bucket_timestamps_window(timestamps, start, bucket_seconds, bucket_count):
    buckets = [0] * bucket_count; window_seconds = bucket_seconds * bucket_count
    for raw in timestamps:
        dt = _parse_iso(raw)
        if dt is None: continue
        offset = (dt - start).total_seconds()
        if 0 <= offset < window_seconds:
            idx = int(offset // bucket_seconds)
            if 0 <= idx < bucket_count: buckets[idx] += 1
    return [{"t": (start + timedelta(seconds=i * bucket_seconds)).isoformat(), "count": buckets[i]} for i in range(bucket_count)]

def _bucket_timestamps(timestamps, range_seconds, bucket_seconds, bucket_count, now_dt):
    start = now_dt - timedelta(seconds=range_seconds)
    return _bucket_timestamps_window(timestamps, start, bucket_seconds, bucket_count)

def _history_bucket_series_window(value_col, start, bucket_seconds, bucket_count):
    """Bucketed rollup from the bounded analytics_buckets aggregation table
    for an arbitrary [start, start + bucket_seconds*bucket_count) window."""
    with closing(sqlite3.connect(DB_PATH)) as c:
        min_bucket_start = c.execute("SELECT MIN(bucket_start) FROM analytics_buckets").fetchone()[0]
        rows = c.execute(f"SELECT bucket_start,{value_col} FROM analytics_buckets WHERE bucket_start>=? ORDER BY bucket_start ASC", (start.isoformat(),)).fetchall()
    buckets = [0] * bucket_count; window_seconds = bucket_seconds * bucket_count
    for bucket_start, value in rows:
        dt = _parse_iso(bucket_start)
        if dt is None: continue
        offset = (dt - start).total_seconds()
        if 0 <= offset < window_seconds:
            idx = int(offset // bucket_seconds)
            if 0 <= idx < bucket_count: buckets[idx] += int(value or 0)
    points = [{"t": (start + timedelta(seconds=i * bucket_seconds)).isoformat(), "count": buckets[i]} for i in range(bucket_count)]
    min_dt = _parse_iso(min_bucket_start)
    for point in points:
        bucket_end = _parse_iso(point["t"]) + timedelta(seconds=bucket_seconds)
        if min_dt is None or bucket_end <= min_dt: point["count"] = None
    return points

def _history_bucket_series(value_col, range_key):
    """Range series for 30d/90d, rolled up from the bounded analytics_buckets
    aggregation table instead of raw processed_queries/domains/devices."""
    range_seconds, rollup_seconds, bucket_count, label = _ANALYTICS_BUCKET_RANGES[range_key]
    now_dt = datetime.now(timezone.utc); start = now_dt - timedelta(seconds=range_seconds)
    points = _history_bucket_series_window(value_col, start, rollup_seconds, bucket_count)
    return {"range": range_key, "label": label, "bucket_seconds": rollup_seconds, "points": points}

def get_query_volume_series(range_key):
    if range_key in _ANALYTICS_BUCKET_RANGES: return _history_bucket_series("query_count", range_key)
    range_seconds, bucket_seconds, bucket_count, label = _analytics_range(range_key); now_dt = datetime.now(timezone.utc); start = now_dt - timedelta(seconds=range_seconds)
    with closing(sqlite3.connect(DB_PATH)) as c:
        min_seen_at = c.execute("SELECT MIN(seen_at) FROM processed_queries").fetchone()[0]
        rows = c.execute("SELECT seen_at FROM processed_queries WHERE seen_at>=? ORDER BY seen_at ASC", (start.isoformat(),)).fetchall()
    points = _bucket_timestamps([r[0] for r in rows], range_seconds, bucket_seconds, bucket_count, now_dt); min_dt = _parse_iso(min_seen_at)
    for point in points:
        bucket_end = _parse_iso(point["t"]) + timedelta(seconds=bucket_seconds)
        if min_dt is None or bucket_end <= min_dt: point["count"] = None
    return {"range": range_key, "label": label, "bucket_seconds": bucket_seconds, "points": points}

def _first_seen_series(table, range_key):
    if table not in ("domains", "devices"): raise ValueError("unsupported table for first-seen series")
    if range_key in _ANALYTICS_BUCKET_RANGES: return _history_bucket_series("new_domains" if table == "domains" else "new_devices", range_key)
    range_seconds, bucket_seconds, bucket_count, label = _analytics_range(range_key); now_dt = datetime.now(timezone.utc); start = now_dt - timedelta(seconds=range_seconds)
    with closing(sqlite3.connect(DB_PATH)) as c: rows = c.execute(f"SELECT first_seen FROM {table} WHERE first_seen>=? AND first_seen<>''", (start.isoformat(),)).fetchall()
    return {"range": range_key, "label": label, "bucket_seconds": bucket_seconds, "points": _bucket_timestamps([r[0] for r in rows], range_seconds, bucket_seconds, bucket_count, now_dt)}

def get_new_domains_series(range_key): return _first_seen_series("domains", range_key)
def get_new_devices_series(range_key): return _first_seen_series("devices", range_key)


# --- Custom From/To analytics window (Issue #88) -----------------------------
# A user-chosen [from, to) window rather than one of the fixed presets above.
# Bounded the same way the presets are: clamped to "now" and to the retained
# analytics-history floor, and tiered into a bucket size so the point count
# stays reasonable regardless of how wide a span is requested. Spans that fit
# within the same window the "7d" preset uses read the still-retained raw
# processed_queries/domains/devices tables (exact); wider spans fall back to
# the bounded hourly analytics_buckets aggregation, exactly like 30d/90d.
CUSTOM_ANALYTICS_RAW_SPAN_SECONDS = 7 * 86400
CUSTOM_ANALYTICS_MAX_SPAN_SECONDS = 90 * 86400
CUSTOM_ANALYTICS_MAX_BUCKETS = 180
_CUSTOM_ANALYTICS_BUCKET_TIERS = (
    (2 * 3600, 60), (24 * 3600, 900), (7 * 86400, 7200), (30 * 86400, 21600), (90 * 86400, 86400),
)


def _custom_analytics_bucket_seconds(span_seconds):
    for max_span, bucket_seconds in _CUSTOM_ANALYTICS_BUCKET_TIERS:
        if span_seconds <= max_span:
            return bucket_seconds
    return _CUSTOM_ANALYTICS_BUCKET_TIERS[-1][1]


def parse_custom_analytics_window(from_raw, to_raw):
    """Validate and bound a custom analytics window. Returns (window, error) --
    window is a dict of {start, end, bucket_seconds, bucket_count, use_raw,
    label}, error is a user-facing string on failure. Never fabricates a
    window outside what's actually requested/retained."""
    start = _parse_iso((from_raw or "").strip())
    end = _parse_iso((to_raw or "").strip())
    if start is None or end is None:
        return None, "from and to must be ISO-8601 timestamps"
    if end <= start:
        return None, "to must be after from"
    now_dt = datetime.now(timezone.utc)
    retention_floor = now_dt - timedelta(hours=ANALYTICS_HISTORY_RETENTION_HOURS)
    if end > now_dt: end = now_dt
    if start < retention_floor: start = retention_floor
    if end <= start:
        return None, "requested window is outside the retained analytics history"
    if (end - start).total_seconds() > CUSTOM_ANALYTICS_MAX_SPAN_SECONDS:
        start = end - timedelta(seconds=CUSTOM_ANALYTICS_MAX_SPAN_SECONDS)
    span_seconds = (end - start).total_seconds()
    bucket_seconds = _custom_analytics_bucket_seconds(span_seconds)
    bucket_count = max(1, min(CUSTOM_ANALYTICS_MAX_BUCKETS, math.ceil(span_seconds / bucket_seconds)))
    label = f"Custom ({start.date().isoformat()} to {end.date().isoformat()})"
    return {
        "start": start, "end": end, "bucket_seconds": bucket_seconds, "bucket_count": bucket_count,
        "use_raw": span_seconds <= CUSTOM_ANALYTICS_RAW_SPAN_SECONDS, "label": label,
    }, None


def get_custom_query_volume_series(window):
    start, end, bucket_seconds, bucket_count = window["start"], window["end"], window["bucket_seconds"], window["bucket_count"]
    if window["use_raw"]:
        with closing(sqlite3.connect(DB_PATH)) as c:
            min_seen_at = c.execute("SELECT MIN(seen_at) FROM processed_queries").fetchone()[0]
            rows = c.execute("SELECT seen_at FROM processed_queries WHERE seen_at>=? AND seen_at<?", (start.isoformat(), end.isoformat())).fetchall()
        points = _bucket_timestamps_window([r[0] for r in rows], start, bucket_seconds, bucket_count)
        min_dt = _parse_iso(min_seen_at)
        for point in points:
            bucket_end = _parse_iso(point["t"]) + timedelta(seconds=bucket_seconds)
            if min_dt is None or bucket_end <= min_dt: point["count"] = None
    else:
        points = _history_bucket_series_window("query_count", start, bucket_seconds, bucket_count)
    return {"range": "custom", "label": window["label"], "bucket_seconds": bucket_seconds, "points": points, "window": {"from": start.isoformat(), "to": end.isoformat()}}


def _custom_first_seen_series(table, window):
    if table not in ("domains", "devices"): raise ValueError("unsupported table for first-seen series")
    start, end, bucket_seconds, bucket_count = window["start"], window["end"], window["bucket_seconds"], window["bucket_count"]
    if window["use_raw"]:
        with closing(sqlite3.connect(DB_PATH)) as c:
            rows = c.execute(f"SELECT first_seen FROM {table} WHERE first_seen>=? AND first_seen<? AND first_seen<>''", (start.isoformat(), end.isoformat())).fetchall()
        points = _bucket_timestamps_window([r[0] for r in rows], start, bucket_seconds, bucket_count)
    else:
        value_col = "new_domains" if table == "domains" else "new_devices"
        points = _history_bucket_series_window(value_col, start, bucket_seconds, bucket_count)
    return {"range": "custom", "label": window["label"], "bucket_seconds": bucket_seconds, "points": points, "window": {"from": start.isoformat(), "to": end.isoformat()}}


def get_custom_new_domains_series(window): return _custom_first_seen_series("domains", window)
def get_custom_new_devices_series(window): return _custom_first_seen_series("devices", window)

def get_status_breakdown():
    with closing(sqlite3.connect(DB_PATH)) as c:
        row = c.execute("SELECT SUM(CASE WHEN blocked_requests=0 AND allowed_requests=0 THEN 1 ELSE 0 END), SUM(CASE WHEN blocked_requests=0 AND allowed_requests>0 THEN 1 ELSE 0 END), SUM(CASE WHEN blocked_requests>0 AND allowed_requests=0 THEN 1 ELSE 0 END), SUM(CASE WHEN blocked_requests>0 AND allowed_requests>0 THEN 1 ELSE 0 END), COUNT(*) FROM domains").fetchone()
    unknown, allowed, blocked, mixed, total = (int(v or 0) for v in row); return {"Unknown": unknown, "Allowed": allowed, "Blocked": blocked, "Mixed": mixed, "All": total}

def get_recent_activity(limit=12):
    with closing(sqlite3.connect(DB_PATH)) as c:
        domain_rows = c.execute("SELECT domain,last_seen,current_status,requests FROM domains ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall(); device_rows = c.execute("SELECT device_key,COALESCE(NULLIF(hostname,''),NULLIF(name,''),NULLIF(vendor,''),device_key),last_seen,request_count FROM devices ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall()
    return {"domains": [{"domain": d, "last_seen": ls, "status": st or "Unknown", "requests": int(r or 0)} for d, ls, st, r in domain_rows], "devices": [{"device_key": k, "label": label, "last_seen": ls, "requests": int(r or 0)} for k, label, ls, r in device_rows]}

def _active_devices_count(window_seconds=ANALYTICS_ACTIVE_DEVICE_WINDOW_SECONDS):
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    with closing(sqlite3.connect(DB_PATH)) as c: return int(c.execute("SELECT COUNT(*) FROM devices WHERE last_seen>=?", (cutoff,)).fetchone()[0] or 0)

def _total_devices_count():
    with closing(sqlite3.connect(DB_PATH)) as c: return int(c.execute("SELECT COUNT(*) FROM devices").fetchone()[0] or 0)

def _analytics_live_snapshot(window_seconds=ANALYTICS_LIVE_WINDOW_SECONDS):
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    with closing(sqlite3.connect(DB_PATH)) as c: count = int(c.execute("SELECT COUNT(*) FROM processed_queries WHERE seen_at>=?", (cutoff,)).fetchone()[0] or 0)
    return {"updated": utcnow(), "window_seconds": window_seconds, "queries_in_window": count}

def analytics_payload(range_key="1h", custom_window=None):
    if range_key == "custom" and custom_window:
        series = {"queries": get_custom_query_volume_series(custom_window), "new_domains": get_custom_new_domains_series(custom_window), "new_devices": get_custom_new_devices_series(custom_window)}
    else:
        if range_key not in ANALYTICS_RANGE_OPTIONS: range_key = "1h"
        series = {"queries": get_query_volume_series(range_key), "new_domains": get_new_domains_series(range_key), "new_devices": get_new_devices_series(range_key)}
    cutoff_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    with closing(sqlite3.connect(DB_PATH)) as c: new_domains_24h = int(c.execute("SELECT COUNT(*) FROM domains WHERE first_seen>=?", (cutoff_24h,)).fetchone()[0] or 0)
    activity = get_recent_activity()
    payload = {"updated": utcnow(), "range": range_key, "range_options": ANALYTICS_RANGE_OPTIONS,
            "series": series,
            "status_breakdown": get_status_breakdown(), "recent_domains": activity["domains"], "recent_devices": activity["devices"], "active_devices": _active_devices_count(), "total_devices": _total_devices_count(), "new_domains_24h": new_domains_24h, "live": _analytics_live_snapshot()}
    if range_key == "custom" and custom_window:
        payload["custom_window"] = {"from": custom_window["start"].isoformat(), "to": custom_window["end"].isoformat(), "label": custom_window["label"]}
    return payload


# --- Bounded hourly analytics history + exact-interval drill-down (#88) -----
def _bucket_floor(dt):
    return dt.replace(minute=0, second=0, microsecond=0)


def _aggregate_analytics_bucket(c, bucket_start_dt):
    """Close out one hourly bucket from the still-retained processed_queries
    window and upsert its summary into analytics_buckets. Idempotent: safe to
    re-run for the same bucket_start (e.g. after a restart)."""
    bucket_end_dt = bucket_start_dt + timedelta(seconds=ANALYTICS_BUCKET_SECONDS)
    start_iso, end_iso = bucket_start_dt.isoformat(), bucket_end_dt.isoformat()
    rows = c.execute("SELECT domain,device_key,status FROM processed_queries WHERE seen_at>=? AND seen_at<?", (start_iso, end_iso)).fetchall()
    domain_counts, device_counts = {}, {}
    allowed = blocked = unknown = 0
    for domain, device_key, status in rows:
        if domain: domain_counts[domain] = domain_counts.get(domain, 0) + 1
        if device_key: device_counts[device_key] = device_counts.get(device_key, 0) + 1
        if status == "Blocked": blocked += 1
        elif status == "Allowed": allowed += 1
        elif status: unknown += 1
    new_domains = c.execute("SELECT COUNT(*) FROM domains WHERE first_seen>=? AND first_seen<?", (start_iso, end_iso)).fetchone()[0]
    new_devices = c.execute("SELECT COUNT(*) FROM devices WHERE first_seen>=? AND first_seen<?", (start_iso, end_iso)).fetchone()[0]
    top_domains = sorted(domain_counts.items(), key=lambda kv: -kv[1])[:8]
    top_devices = sorted(device_counts.items(), key=lambda kv: -kv[1])[:8]
    c.execute(
        """INSERT INTO analytics_buckets(bucket_start,bucket_seconds,query_count,unique_domains,unique_devices,allowed,blocked,unknown,new_domains,new_devices,top_domains_json,top_devices_json,created_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(bucket_start) DO UPDATE SET query_count=excluded.query_count, unique_domains=excluded.unique_domains, unique_devices=excluded.unique_devices,
             allowed=excluded.allowed, blocked=excluded.blocked, unknown=excluded.unknown, new_domains=excluded.new_domains, new_devices=excluded.new_devices,
             top_domains_json=excluded.top_domains_json, top_devices_json=excluded.top_devices_json""",
        (start_iso, ANALYTICS_BUCKET_SECONDS, len(rows), len(domain_counts), len(device_counts), allowed, blocked, unknown,
         int(new_domains or 0), int(new_devices or 0), json.dumps(top_domains), json.dumps(top_devices), utcnow()),
    )


def analytics_history_tick():
    """Close out any fully-elapsed hourly buckets since the last tick (bounded
    catch-up after downtime) and prune retained history beyond the configured
    retention window. Cheap on the common case: at most one new bucket per
    real hour boundary."""
    now_dt = datetime.now(timezone.utc)
    current_bucket = _bucket_floor(now_dt)
    with db_lock, closing(sqlite3.connect(DB_PATH)) as c:
        last_closed_raw = _get_setting_raw(c, "analytics_last_closed_bucket")
        last_closed_dt = _parse_iso(last_closed_raw) if last_closed_raw else None
        retention_floor = current_bucket - timedelta(hours=ANALYTICS_HISTORY_RETENTION_HOURS)
        if last_closed_dt is None:
            earliest_raw = c.execute("SELECT MIN(seen_at) FROM processed_queries").fetchone()[0]
            earliest_dt = _parse_iso(earliest_raw)
            # Never fabricate history for time before any data was tracked --
            # start exactly one bucket before the (hour-aligned) oldest
            # retained raw row, or the retention floor, whichever is more
            # recent, so every bucket this loop closes stays hour-aligned.
            start_from = _bucket_floor(earliest_dt) if earliest_dt else current_bucket
            last_closed_dt = max(retention_floor, start_from - timedelta(seconds=ANALYTICS_BUCKET_SECONDS))
        cursor = max(last_closed_dt, retention_floor) + timedelta(seconds=ANALYTICS_BUCKET_SECONDS)
        closed = 0
        while cursor < current_bucket and closed < ANALYTICS_HISTORY_MAX_CATCHUP_BUCKETS:
            _aggregate_analytics_bucket(c, cursor)
            last_closed_dt = cursor
            cursor += timedelta(seconds=ANALYTICS_BUCKET_SECONDS)
            closed += 1
        if closed:
            _set_setting_raw(c, "analytics_last_closed_bucket", last_closed_dt.isoformat())
        c.execute("DELETE FROM analytics_buckets WHERE bucket_start<?", (retention_floor.isoformat(),))
        c.commit()
    return closed


def _interval_detail_core(range_key, bucket_dt, bucket_seconds, period_average):
    """Exact-interval drill-down for a clicked chart bucket. Uses real
    per-query attribution while the interval is still inside the retained
    processed_queries window (granularity "exact"), falls back to the bounded
    hourly analytics_buckets summary once it has rolled off ("hourly_aggregate"),
    and is explicit -- never fabricated -- when neither has any data ("none")."""
    bucket_end_dt = bucket_dt + timedelta(seconds=bucket_seconds)
    start_iso, end_iso = bucket_dt.isoformat(), bucket_end_dt.isoformat()

    with closing(sqlite3.connect(DB_PATH)) as c:
        min_seen_at = c.execute("SELECT MIN(seen_at) FROM processed_queries").fetchone()[0]
        min_seen_dt = _parse_iso(min_seen_at)
        device_labels = {row[0]: row[1] for row in c.execute("SELECT device_key,COALESCE(NULLIF(hostname,''),NULLIF(name,''),NULLIF(vendor,''),device_key) FROM devices").fetchall()}

        # "Exact" is available whenever any part of the currently retained raw
        # window could fall inside this bucket -- not just when the bucket
        # starts at/after the oldest retained row, since row-count-based
        # eviction never aligns exactly to bucket boundaries.
        if min_seen_dt is None or bucket_end_dt > min_seen_dt:
            rows = c.execute("SELECT domain,device_key,status FROM processed_queries WHERE seen_at>=? AND seen_at<?", (start_iso, end_iso)).fetchall()
            new_domain_rows = c.execute("SELECT domain FROM domains WHERE first_seen>=? AND first_seen<? ORDER BY first_seen ASC LIMIT 25", (start_iso, end_iso)).fetchall()
            new_device_rows = c.execute("SELECT device_key FROM devices WHERE first_seen>=? AND first_seen<? ORDER BY first_seen ASC LIMIT 25", (start_iso, end_iso)).fetchall()
            domain_counts, device_counts = {}, {}
            allowed = blocked = unknown = 0
            for domain, device_key, status in rows:
                if domain: domain_counts[domain] = domain_counts.get(domain, 0) + 1
                if device_key: device_counts[device_key] = device_counts.get(device_key, 0) + 1
                if status == "Blocked": blocked += 1
                elif status == "Allowed": allowed += 1
                elif status: unknown += 1
            top_domains = sorted(domain_counts.items(), key=lambda kv: -kv[1])[:10]
            top_devices = sorted(device_counts.items(), key=lambda kv: -kv[1])[:10]
            query_count = len(rows)
            return {
                "ok": True, "range": range_key, "bucket_start": start_iso, "bucket_end": end_iso, "granularity": "exact",
                "query_count": query_count, "period_average": period_average,
                "vs_average_ratio": round(query_count / period_average, 2) if period_average else None,
                "unique_domains": len(domain_counts), "unique_devices": len(device_counts),
                "status": {"Allowed": allowed, "Blocked": blocked, "Unknown": unknown},
                "new_domains": [d for (d,) in new_domain_rows], "new_devices": [device_labels.get(k, k) for (k,) in new_device_rows],
                "top_domains": [{"domain": d, "count": n} for d, n in top_domains],
                "top_devices": [{"device_key": k, "label": device_labels.get(k, k), "count": n} for k, n in top_devices],
            }

        agg_rows = c.execute(
            "SELECT query_count,allowed,blocked,unknown,new_domains,new_devices,top_domains_json,top_devices_json FROM analytics_buckets WHERE bucket_start>=? AND bucket_start<? ORDER BY bucket_start ASC",
            (start_iso, end_iso),
        ).fetchall()
        if not agg_rows:
            return {
                "ok": True, "range": range_key, "bucket_start": start_iso, "bucket_end": end_iso, "granularity": "none",
                "query_count": 0, "period_average": period_average, "status": {}, "top_domains": [], "top_devices": [],
                "note": "No retained data is available for this interval.",
            }
        merged_domains, merged_devices = {}, {}
        query_count = new_domains_count = new_devices_count = allowed = blocked = unknown = 0
        for qc, a, b, u, nd, nv, tdj, tvj in agg_rows:
            query_count += int(qc or 0); allowed += int(a or 0); blocked += int(b or 0); unknown += int(u or 0)
            new_domains_count += int(nd or 0); new_devices_count += int(nv or 0)
            for d, n in json.loads(tdj or "[]"): merged_domains[d] = merged_domains.get(d, 0) + n
            for k, n in json.loads(tvj or "[]"): merged_devices[k] = merged_devices.get(k, 0) + n
        top_domains = sorted(merged_domains.items(), key=lambda kv: -kv[1])[:10]
        top_devices = sorted(merged_devices.items(), key=lambda kv: -kv[1])[:10]
        return {
            "ok": True, "range": range_key, "bucket_start": start_iso, "bucket_end": end_iso, "granularity": "hourly_aggregate",
            "query_count": query_count, "period_average": period_average,
            "vs_average_ratio": round(query_count / period_average, 2) if period_average else None,
            "unique_domains": None, "unique_devices": None,
            "status": {"Allowed": allowed, "Blocked": blocked, "Unknown": unknown},
            "new_domains_count": new_domains_count, "new_devices_count": new_devices_count,
            "top_domains": [{"domain": d, "count": n} for d, n in top_domains],
            "top_devices": [{"device_key": k, "label": device_labels.get(k, k), "count": n} for k, n in top_devices],
            "note": "This interval is outside the retained raw query log; figures are reconstructed from the bounded hourly analytics history, so unique counts and top lists reflect what was recorded when each hour closed, not every individual query.",
        }


def analytics_interval_detail(range_key, bucket_dt):
    if range_key in _ANALYTICS_BUCKET_RANGES:
        _, bucket_seconds, _, _ = _ANALYTICS_BUCKET_RANGES[range_key]
    else:
        _, bucket_seconds, _, _ = _analytics_range(range_key)
    try:
        series = get_query_volume_series(range_key)
        vals = [p["count"] for p in series["points"] if p.get("count") is not None]
        period_average = round(sum(vals) / len(vals), 1) if vals else None
    except Exception:
        period_average = None
    return _interval_detail_core(range_key, bucket_dt, bucket_seconds, period_average)


def analytics_interval_detail_custom(window, bucket_dt):
    bucket_seconds = window["bucket_seconds"]
    try:
        series = get_custom_query_volume_series(window)
        vals = [p["count"] for p in series["points"] if p.get("count") is not None]
        period_average = round(sum(vals) / len(vals), 1) if vals else None
    except Exception:
        period_average = None
    return _interval_detail_core("custom", bucket_dt, bucket_seconds, period_average)


def get_stats(limit=10):
    with closing(sqlite3.connect(DB_PATH)) as c:
        top_domains = c.execute("SELECT domain,requests FROM domains ORDER BY requests DESC LIMIT ?", (limit,)).fetchall()
        top_devices = c.execute("SELECT device_key,COALESCE(NULLIF(hostname,''),NULLIF(name,''),NULLIF(vendor,''),device_key),request_count FROM devices ORDER BY request_count DESC LIMIT ?", (limit,)).fetchall()
        top_vendors = c.execute("SELECT vendor,SUM(request_count) AS total FROM devices WHERE TRIM(vendor)<>'' GROUP BY vendor ORDER BY total DESC LIMIT ?", (limit,)).fetchall()
        top_ips = c.execute("SELECT ip,SUM(requests) AS total FROM device_ips GROUP BY ip ORDER BY total DESC LIMIT ?", (limit,)).fetchall()
    return {
        "domains": [{"label": d, "value": int(v), "href": "/search?q=" + quote(d, safe="")} for d, v in top_domains],
        "devices": [{"label": label, "value": int(v), "href": "/device?key=" + quote(key, safe="")} for key, label, v in top_devices],
        "vendors": [{"label": v, "value": int(total), "href": ""} for v, total in top_vendors],
        "ips": [{"label": ip, "value": int(total), "href": "/ip?addr=" + quote(ip, safe="")} for ip, total in top_ips],
    }


def state_payload(q="",status_filter="",new_only=False,classification_filter="",severity_filter="",device_filter="",vendor_filter="",page=1,page_size=50):
    result=inspect_domain(q) if q else None
    recent=get_recent(page=page,page_size=page_size,status_filter=status_filter,new_only=new_only,classification_filter=classification_filter,severity_filter=severity_filter,device_filter=device_filter,vendor_filter=vendor_filter)
    return {"updated":utcnow(),"recent":recent["rows"],"recent_meta":recent["meta"],"filter_options":get_filter_options(),"clients":get_clients(),"stats":get_stats(),"observability":_observability_payload(),"inspect_html":inspect_html(result) if result else None}

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
    with db_lock, closing(sqlite3.connect(DB_PATH)) as c:
        # Merge per-device records first. This preserves the historical IP list.
        for ip, mac in neighbors.items():
            old_key = "ip:" + ip
            new_key = "mac:" + mac
            if old_key == new_key:
                continue
            old = c.execute("SELECT name,hostname,mac,device_type,icon,confidence,source,first_seen,last_seen,request_count,info_json FROM devices WHERE device_key=?", (old_key,)).fetchone()
            if not old:
                continue
            new = c.execute("SELECT request_count FROM devices WHERE device_key=?", (new_key,)).fetchone()
            if new:
                c.execute("""UPDATE devices SET name=COALESCE(NULLIF(name,''),?), hostname=COALESCE(NULLIF(hostname,''),?), mac=?,
                            device_type=CASE WHEN device_type='IoT / Unknown' THEN ? ELSE device_type END,
                            icon=CASE WHEN icon='📦' THEN ? ELSE icon END,
                            confidence=CASE WHEN confidence='low' THEN ? ELSE confidence END,
                            first_seen=CASE WHEN first_seen='' OR first_seen > ? THEN ? ELSE first_seen END,
                            last_seen=CASE WHEN last_seen < ? THEN ? ELSE last_seen END,
                            request_count=request_count+?, info_json=CASE WHEN info_json='{}' THEN ? ELSE info_json END
                            WHERE device_key=?""",
                           (old[0], old[1], mac, old[3], old[4], old[5], old[7], old[7], old[8], old[8], old[9], old[10], new_key))
            else:
                c.execute("""INSERT INTO devices(device_key,name,hostname,mac,device_type,icon,confidence,source,first_seen,last_seen,request_count,info_json)
                             VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                          (new_key, old[0], old[1], mac, old[3], old[4], old[5], old[6], old[7], old[8], old[9], old[10]))
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
    threading.Thread(target=refresh_trackerdb, daemon=True, name="trackerdb-refresh").start()
    while True:
        started = time.time()
        ingest()
        try:
            analytics_history_tick()
        except Exception as exc:
            print("analytics history tick error:", repr(exc), flush=True)
        elapsed = time.time() - started
        time.sleep(max(1, POLL_SECONDS - elapsed))


def generate_analytics_report_pdf(range_key, custom_window=None):
    """Single source of truth for PDF generation -- used by the manual
    download route, the "Save report now" action, and the scheduler, so
    scheduled and on-demand reports can never diverge (Issue #88 #15)."""
    if range_key == "custom" and custom_window:
        analytics = analytics_payload("custom", custom_window)
    else:
        if range_key not in ANALYTICS_RANGE_OPTIONS:
            range_key = "1h"
        analytics = analytics_payload(range_key)
    report_buffer = build_analytics_pdf(
        analytics=analytics,
        stats=get_stats(limit=8),
        breakdown=get_status_breakdown(),
        map_data=geoip_map_payload(),
        version=APP_VERSION,
        environment=RUNTIME_ENV,
        range_key=range_key,
        custom_window=custom_window,
    )
    label = ((analytics.get("series") or {}).get("queries") or {}).get("label", range_key)
    meta = {"range_key": range_key, "label": label, "generated_at": utcnow()}
    if custom_window:
        meta["custom_from"] = custom_window["start"].isoformat()
        meta["custom_to"] = custom_window["end"].isoformat()
        meta["filename_range"] = f"custom-{custom_window['start'].strftime('%Y%m%d')}-{custom_window['end'].strftime('%Y%m%d')}"
    else:
        meta["filename_range"] = range_key
    return report_buffer.getvalue(), meta


@app.route("/api/analytics/report.pdf")
def api_analytics_report_pdf():
    range_key = request.args.get("range", "1h").strip() or "1h"
    custom_window = None
    if range_key == "custom":
        custom_window, err = parse_custom_analytics_window(request.args.get("from", ""), request.args.get("to", ""))
        if err:
            return jsonify({"ok": False, "error": err}), 400
    try:
        pdf_bytes, meta = generate_analytics_report_pdf(range_key, custom_window)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"dns-inspector-analytics-{meta['filename_range']}-{stamp}.pdf",
        )
    except Exception as e:
        print("analytics PDF export error:", repr(e), flush=True)
        traceback.print_exc()
        return jsonify({"ok": False, "error": "Analytics PDF generation failed"}), 500


@app.route("/api/analytics")
def api_analytics():
    range_key = request.args.get("range", "1h").strip() or "1h"
    if range_key == "custom":
        custom_window, err = parse_custom_analytics_window(request.args.get("from", ""), request.args.get("to", ""))
        if err:
            return jsonify({"ok": False, "error": err}), 400
        try: return jsonify(analytics_payload("custom", custom_window))
        except Exception as e:
            print("analytics error:", repr(e), flush=True)
            empty = {"range": "custom", "label": "", "bucket_seconds": 0, "points": []}
            return jsonify({"updated": utcnow(), "range": "custom", "range_options": ANALYTICS_RANGE_OPTIONS, "series": {"queries": empty, "new_domains": empty, "new_devices": empty}, "status_breakdown": {}, "recent_domains": [], "recent_devices": [], "active_devices": 0, "total_devices": 0, "new_domains_24h": 0, "live": {"updated": utcnow(), "window_seconds": ANALYTICS_LIVE_WINDOW_SECONDS, "queries_in_window": 0}, "error": str(e)}), 200
    try: return jsonify(analytics_payload(range_key))
    except Exception as e:
        print("analytics error:", repr(e), flush=True)
        empty = {"range": range_key, "label": "", "bucket_seconds": 0, "points": []}
        return jsonify({"updated": utcnow(), "range": range_key, "range_options": ANALYTICS_RANGE_OPTIONS, "series": {"queries": empty, "new_domains": empty, "new_devices": empty}, "status_breakdown": {}, "recent_domains": [], "recent_devices": [], "active_devices": 0, "total_devices": 0, "new_domains_24h": 0, "live": {"updated": utcnow(), "window_seconds": ANALYTICS_LIVE_WINDOW_SECONDS, "queries_in_window": 0}, "error": str(e)}), 200


@app.route("/api/analytics/interval")
def api_analytics_interval():
    range_key = request.args.get("range", "1h").strip() or "1h"
    bucket_dt = _parse_iso(request.args.get("bucket_start", "").strip())
    if bucket_dt is None:
        return jsonify({"ok": False, "error": "bucket_start must be an ISO-8601 timestamp"}), 400
    if range_key == "custom":
        custom_window, err = parse_custom_analytics_window(request.args.get("from", ""), request.args.get("to", ""))
        if err:
            return jsonify({"ok": False, "error": err}), 400
        try:
            return jsonify(analytics_interval_detail_custom(custom_window, bucket_dt))
        except Exception as e:
            print("analytics interval error:", repr(e), flush=True)
            return jsonify({"ok": False, "error": "Unable to compute interval detail"}), 200
    if range_key not in ANALYTICS_RANGE_OPTIONS:
        return jsonify({"ok": False, "error": "unsupported range"}), 400
    try:
        return jsonify(analytics_interval_detail(range_key, bucket_dt))
    except Exception as e:
        print("analytics interval error:", repr(e), flush=True)
        return jsonify({"ok": False, "error": "Unable to compute interval detail"}), 200


# --- Scheduled report generation / storage / email (Issue #88) --------------
DEFAULT_REPORT_SCHEDULE = {
    "enabled": False, "interval": "daily", "custom_interval_seconds": 86400,
    "window": "24h", "save_dir": "", "filename_template": "dns-inspector-{range}-{timestamp}.pdf",
    "retention_count": REPORTS_DEFAULT_RETENTION,
    "smtp_enabled": False, "smtp_host": "", "smtp_port": 587, "smtp_security": "starttls",
    "smtp_username": "", "smtp_sender": "", "smtp_recipients": [], "smtp_subject_template": "DNS Inspector report - {range}",
    "history": [], "last_run_ts": None, "last_result": None, "last_error": None, "last_saved_file": None, "last_email_result": None,
}
EDITABLE_REPORT_SCHEDULE_FIELDS = {
    "enabled", "interval", "custom_interval_seconds", "window", "save_dir", "filename_template", "retention_count",
    "smtp_enabled", "smtp_host", "smtp_port", "smtp_security", "smtp_username", "smtp_sender", "smtp_recipients", "smtp_subject_template",
}
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def get_report_schedule_config():
    stored = get_setting("report_schedule") or {}
    config = dict(DEFAULT_REPORT_SCHEDULE); config.update(stored)
    config["_smtp_password"] = os.environ.get(SMTP_PASSWORD_ENV_VAR, "")
    return config


def public_report_schedule_config(config=None):
    """API-safe view of the schedule config -- the SMTP password is never
    stored in this dict in the first place, only ever read from the
    environment, so there is nothing to accidentally leak here."""
    config = dict(config if config is not None else get_report_schedule_config())
    config.pop("_smtp_password", None)
    config["smtp_password_set"] = bool(os.environ.get(SMTP_PASSWORD_ENV_VAR, ""))
    return config


def _persist_report_schedule(update):
    with db_lock, closing(sqlite3.connect(DB_PATH)) as c:
        stored = _get_setting_raw(c, "report_schedule") or {}
        merged = dict(DEFAULT_REPORT_SCHEDULE); merged.update(stored); merged.update(update)
        _set_setting_raw(c, "report_schedule", merged); c.commit()
        return merged


def update_report_schedule_config(patch):
    errors = []
    filtered = {}
    for key, value in (patch or {}).items():
        if key not in EDITABLE_REPORT_SCHEDULE_FIELDS:
            continue
        if key == "interval" and value not in ("hourly", "daily", "weekly", "custom"):
            errors.append("interval must be one of hourly, daily, weekly, custom"); continue
        if key == "window" and value not in ANALYTICS_RANGE_OPTIONS:
            errors.append("window must be a supported analytics range"); continue
        if key == "smtp_security" and value not in ("none", "starttls", "tls"):
            errors.append("smtp_security must be none, starttls, or tls"); continue
        if key == "retention_count":
            try: value = max(1, min(MAX_RETENTION_COUNT, int(value)))
            except (TypeError, ValueError): errors.append("retention_count must be an integer"); continue
        if key == "custom_interval_seconds":
            try: value = max(900, int(value))
            except (TypeError, ValueError): errors.append("custom_interval_seconds must be an integer"); continue
        if key == "smtp_port":
            try: value = int(value)
            except (TypeError, ValueError): errors.append("smtp_port must be an integer"); continue
        if key == "smtp_recipients":
            if not isinstance(value, list):
                errors.append("smtp_recipients must be a list of email addresses"); continue
            value = [str(v).strip() for v in value if str(v or "").strip()]
            bad = [v for v in value if not _EMAIL_RE.match(v)]
            if bad:
                errors.append(f"smtp_recipients contains invalid address(es): {', '.join(bad[:3])}"); continue
        if key in ("save_dir", "filename_template"):
            value = str(value or "")
        filtered[key] = value
    if errors:
        raise ValueError("; ".join(errors))
    # Validate the resulting save location is actually safe before persisting
    # it, so a bad save_dir/filename_template surfaces immediately in the API
    # response instead of silently failing every scheduled run.
    probe = dict(DEFAULT_REPORT_SCHEDULE); probe.update(get_report_schedule_config()); probe.update(filtered)
    try:
        _report_relative_path(probe, "24h")
    except ReportPathError as exc:
        raise ValueError(str(exc))
    return _persist_report_schedule(filtered)


def _report_relative_path(config, range_key):
    save_dir = (config.get("save_dir") or "").strip().strip("/")
    filename = render_filename_template(config.get("filename_template"), filename_context(range_key))
    relative = f"{save_dir}/{filename}" if save_dir else filename
    resolve_report_path(REPORTS_BASE_DIR, relative)  # raises ReportPathError if unsafe
    return relative, filename


def _scheduler_generate_report(window_key):
    pdf_bytes, meta = generate_analytics_report_pdf(window_key)
    return pdf_bytes, meta


def _scheduler_save_report(pdf_bytes, config, meta):
    relative, filename = _report_relative_path(config, meta["range_key"])
    full_path = resolve_report_path(REPORTS_BASE_DIR, relative)
    tmp_path = full_path + ".tmp"
    with open(tmp_path, "wb") as f:
        f.write(pdf_bytes)
    os.replace(tmp_path, full_path)
    stored = get_setting("report_schedule") or {}
    history = list(stored.get("history") or [])
    history.append({"path": full_path, "filename": filename, "range_key": meta["range_key"], "generated_at": meta["generated_at"]})
    history = prune_report_history(REPORTS_BASE_DIR, history, config.get("retention_count") or REPORTS_DEFAULT_RETENTION)
    meta["filename"] = filename
    _persist_report_schedule({"history": history})
    return full_path


def _scheduler_log(level, message, **ctx):
    log_event(level, message, **ctx)


MAX_RETENTION_COUNT = 200
_report_scheduler = ReportScheduler(
    config_provider=get_report_schedule_config,
    persist_run=_persist_report_schedule,
    generate_report=_scheduler_generate_report,
    save_report=_scheduler_save_report,
    logger=_scheduler_log,
)


@app.route("/api/reports/schedule", methods=["GET", "POST"])
def api_reports_schedule():
    if request.method == "GET":
        return jsonify({"ok": True, "config": public_report_schedule_config(), "state": _report_scheduler.state()})
    data = request.get_json(silent=True) or {}
    try:
        merged = update_report_schedule_config(data)
        return jsonify({"ok": True, "config": public_report_schedule_config(merged)})
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.route("/api/reports/status")
def api_reports_status():
    return jsonify({"ok": True, "state": _report_scheduler.state(), "base_dir": REPORTS_BASE_DIR})


@app.route("/api/reports/save-now", methods=["POST"])
def api_reports_save_now():
    config = get_report_schedule_config()
    result = _report_scheduler.run_now(config=config, reason="manual")
    status = 200 if result.get("ok") else 409
    return jsonify(result), status


@app.route("/api/reports/test-email", methods=["POST"])
def api_reports_test_email():
    data = request.get_json(silent=True) or {}
    config = get_report_schedule_config()
    recipients = data.get("recipients") if isinstance(data.get("recipients"), list) else config.get("smtp_recipients") or []
    recipients = [str(r).strip() for r in recipients if str(r or "").strip()]
    bad = [r for r in recipients if not _EMAIL_RE.match(r)]
    if bad:
        return jsonify({"ok": False, "error": f"Invalid recipient address(es): {', '.join(bad[:3])}"}), 400
    result = send_report_email(
        host=config.get("smtp_host"), port=config.get("smtp_port"), security=config.get("smtp_security"),
        username=config.get("smtp_username"), password=config.get("_smtp_password"), sender=config.get("smtp_sender"),
        recipients=recipients, subject="DNS Inspector - test email",
        body="This is a test email from the DNS Inspector scheduled report worker. If you received this, SMTP delivery is configured correctly.",
    )
    log_event("INFO" if result.get("ok") else "WARNING", "report test email", ok=str(result.get("ok")), recipient_count=str(result.get("recipient_count", 0)))
    return jsonify(result), (200 if result.get("ok") else 502)


@app.route("/api/reports/history")
def api_reports_history():
    stored = get_setting("report_schedule") or {}
    history = list(stored.get("history") or [])
    return jsonify({"ok": True, "history": [
        {"filename": h.get("filename"), "range_key": h.get("range_key"), "generated_at": h.get("generated_at")}
        for h in reversed(history)
    ]})


@app.route("/api/settings/map-origin", methods=["GET", "POST"])
def api_settings_map_origin():
    """A visualization-only origin point for destination route arcs. Never
    derived/guessed -- the operator must explicitly set real coordinates
    (e.g. their own network's approximate location) or leave it unset, in
    which case no arcs are drawn (Issue #88 #5/#6)."""
    if request.method == "GET":
        return jsonify({"ok": True, "origin": get_setting("map_origin")})
    data = request.get_json(silent=True) or {}
    if data.get("clear"):
        set_setting("map_origin", None)
        return jsonify({"ok": True, "origin": None})
    try:
        lat = float(data.get("lat")); lon = float(data.get("lon"))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "lat/lon must be numbers"}), 400
    if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
        return jsonify({"ok": False, "error": "lat/lon out of range"}), 400
    label = str(data.get("label") or "").strip()[:80]
    origin = {"lat": lat, "lon": lon, "label": label}
    set_setting("map_origin", origin)
    return jsonify({"ok": True, "origin": origin})

@app.post("/api/admin/login")
def api_admin_login():
    if not ADMIN_TOKEN:
        return _json_no_store({"ok": False, "enabled": False, "error": "Admin authentication is not enabled"}, 404)

    limited, retry_after = _admin_login_rate_limited(request.remote_addr or "unknown")
    if limited:
        resp = _json_no_store({"ok": False, "error": "Too many login attempts"}, 429)
        resp.headers["Retry-After"] = str(retry_after)
        return resp

    data = request.get_json(silent=True) or {}
    supplied = data.get("token")
    if not isinstance(supplied, str) or not hmac.compare_digest(supplied, ADMIN_TOKEN):
        return _json_no_store({"ok": False, "error": "Invalid admin token"}, 401)

    raw = _issue_admin_session()
    resp = _json_no_store({"ok": True, "authenticated": True, "expires_in": ADMIN_SESSION_TTL_SECONDS})
    resp.set_cookie(
        ADMIN_SESSION_COOKIE,
        raw,
        max_age=ADMIN_SESSION_TTL_SECONDS,
        httponly=True,
        secure=_admin_cookie_secure(),
        samesite="Strict",
        path="/",
    )
    return resp


@app.get("/api/admin/status")
def api_admin_status():
    authenticated = _admin_session_valid(request) if ADMIN_TOKEN else False
    return _json_no_store({"ok": True, "enabled": bool(ADMIN_TOKEN), "authenticated": authenticated})


@app.post("/api/admin/logout")
def api_admin_logout():
    raw = request.cookies.get(ADMIN_SESSION_COOKIE, "")
    if raw:
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        with _admin_sessions_lock:
            _admin_sessions.pop(digest, None)
    resp = _json_no_store({"ok": True, "authenticated": False})
    resp.delete_cookie(ADMIN_SESSION_COOKIE, path="/")
    return resp


@app.route("/api/device/label", methods=["GET", "POST"])
@require_admin
def api_device_label():
    try:
        with db_lock, closing(sqlite3.connect(DB_PATH)) as c:
            c.execute("CREATE TABLE IF NOT EXISTS device_labels(device_key TEXT PRIMARY KEY, label TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL)")
            if request.method == "GET":
                rows = c.execute("SELECT device_key,label FROM device_labels WHERE TRIM(label)<>''").fetchall(); return jsonify({"ok": True, "labels": {k: v for k, v in rows}})
            data = request.get_json(silent=True) or {}; device_key = str(data.get("device_key") or "").strip(); label = str(data.get("label") or "").strip()[:80]
            if not device_key: return jsonify({"ok": False, "error": "device_key is required"}), 400
            c.execute("INSERT OR REPLACE INTO device_labels(device_key,label,updated_at) VALUES(?,?,?)", (device_key, label, utcnow())); c.commit()
            return jsonify({"ok": True, "device_key": device_key, "label": label})
    except Exception as e:
        print("device label error:", repr(e), flush=True); return jsonify({"ok": False, "error": "Unable to save device label"}), 500

OBSERVABILITY_START_MONOTONIC = time.monotonic(); OBSERVABILITY_START_AT = datetime.now(timezone.utc).isoformat()
def _format_duration(seconds):
    s=max(0,int(seconds)); d,s=divmod(s,86400); h,s=divmod(s,3600); m,s=divmod(s,60)
    if d:return f"{d}d {h}h {m}m"
    if h:return f"{h}h {m}m {s}s"
    if m:return f"{m}m {s}s"
    return f"{s}s"
def _observability_rss_mb():
    try:
        with open("/proc/self/status","r",encoding="utf-8") as f:
            for line in f:
                if line.startswith("VmRSS:"): return round(int(line.split()[1])/1024.0,1)
    except Exception:return None
    return None
def _observability_payload():
    try: db_size=os.path.getsize(DB_PATH)
    except OSError: db_size=None
    counts={}
    try:
        with closing(sqlite3.connect(DB_PATH)) as c:
            for table in ("domains","devices","processed_queries","analytics_buckets"):
                try: counts[table]=int(c.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] or 0)
                except sqlite3.Error: counts[table]=None
    except Exception: pass
    uptime=max(0.0,time.monotonic()-OBSERVABILITY_START_MONOTONIC)
    return {"version":APP_VERSION,"environment":RUNTIME_ENV,"started_at":OBSERVABILITY_START_AT,"uptime_seconds":round(uptime,1),"uptime_human":_format_duration(uptime),"ram_mb":_observability_rss_mb(),"pid":os.getpid(),"thread_count":threading.active_count(),"db_size_bytes":db_size,"db_counts":counts,"report_scheduler":_report_scheduler.state()}
@app.route("/api/observability")
def api_observability():
    try:return jsonify(_observability_payload())
    except Exception as e:
        print("observability endpoint error:",repr(e),flush=True); return jsonify({"version":APP_VERSION,"environment":RUNTIME_ENV,"uptime_seconds":0,"ram_mb":None}),200

_lifecycle_lock=threading.Lock(); _restart_in_progress=False; _stop_in_progress=False; RESTART_DELAY_SECONDS=max(0.1,float(os.getenv("RESTART_DELAY_SECONDS","0.75"))); STOP_DELAY_SECONDS=max(0.1,float(os.getenv("STOP_DELAY_SECONDS","0.75")))
def _perform_self_restart():
    global _restart_in_progress; time.sleep(RESTART_DELAY_SECONDS)
    try:os.execv(sys.executable,[sys.executable]+sys.argv)
    except OSError as e:
        print(f"Self-restart failed: {e!r}",flush=True)
        with _lifecycle_lock:_restart_in_progress=False
@app.route("/api/system/restart",methods=["POST"])
@require_admin
def api_system_restart():
    global _restart_in_progress; payload=request.get_json(silent=True) or {}
    if payload.get("confirm") is not True:return jsonify({"ok":False,"error":'restart requires {"confirm": true}'}),400
    with _lifecycle_lock:
        if _restart_in_progress:return jsonify({"ok":False,"error":"a restart is already in progress"}),409
        if _stop_in_progress:return jsonify({"ok":False,"error":"a stop is already in progress"}),409
        _restart_in_progress=True
    threading.Thread(target=_perform_self_restart,daemon=True,name="self-restart").start(); return jsonify({"ok":True,"status":"restarting"}),202
def _perform_self_stop():
    global _stop_in_progress; time.sleep(STOP_DELAY_SECONDS)
    try:os.kill(os.getpid(),signal.SIGTERM)
    except OSError as e:
        print(f"Self-stop failed: {e!r}",flush=True)
        with _lifecycle_lock:_stop_in_progress=False
@app.route("/api/system/stop",methods=["POST"])
@require_admin
def api_system_stop():
    global _stop_in_progress; payload=request.get_json(silent=True) or {}
    if payload.get("confirm") is not True:return jsonify({"ok":False,"error":'stop requires {"confirm": true}'}),400
    with _lifecycle_lock:
        if _stop_in_progress:return jsonify({"ok":False,"error":"a stop is already in progress"}),409
        if _restart_in_progress:return jsonify({"ok":False,"error":"a restart is already in progress"}),409
        _stop_in_progress=True
    threading.Thread(target=_perform_self_stop,daemon=True,name="self-stop").start(); return jsonify({"ok":True,"status":"stopping"}),202

def _debug_snapshot_payload():
    """Small, bounded diagnostic snapshot; intentionally excludes deep proc/GC/tracemalloc collectors."""
    with _devlog_lock:
        events = list(_devlog)[-200:]
    with _geoip_cache_lock:
        geoip_cache_entries = len(_geoip_cache)
    with _geoip_map_cache_lock:
        map_cache_at = _geoip_map_cache.get("at", 0.0)
        map_cache_ready = _geoip_map_cache.get("data") is not None
    observability = _observability_payload()
    return {
        "generated_at": utcnow(),
        "application": {"version": APP_VERSION, "environment": RUNTIME_ENV, "pid": os.getpid()},
        "observability": observability,
        "geoip": {
            "provider": _geoip_diagnostics(),
            "cache_entries": geoip_cache_entries,
            "map_cache_ready": map_cache_ready,
            "map_cache_age_seconds": round(max(0.0, time.time() - map_cache_at), 1) if map_cache_at else None,
        },
        "runtime": {
            "poll_seconds": POLL_SECONDS,
            "ui_refresh_seconds": UI_REFRESH_SECONDS,
            "active_threads": [{"name": t.name, "daemon": bool(t.daemon), "alive": bool(t.is_alive())} for t in threading.enumerate()],
            "devlog_entries_exported": len(events),
        },
        "devlog": events,
    }


@app.route("/api/devlog/export")
@require_admin
def api_devlog_export():
    with _devlog_lock:
        events = list(_devlog)[-500:]
    lines = []
    for entry in events:
        context = json.dumps(entry.get("context", {}), ensure_ascii=False, sort_keys=True) if entry.get("context") else ""
        suffix = " · " + context if context else ""
        lines.append(f"{entry.get('at','')}	{entry.get('level','INFO')}	{entry.get('message','')}{suffix}")
    payload = ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")
    return send_file(io.BytesIO(payload), mimetype="text/plain; charset=utf-8", as_attachment=True, download_name=f"dns-inspector-devlog-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.txt")


@app.route("/api/debug/snapshot")
@require_admin
def api_debug_snapshot():
    payload = json.dumps(_debug_snapshot_payload(), ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
    return send_file(io.BytesIO(payload), mimetype="application/json", as_attachment=True, download_name=f"dns-inspector-debug-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.json")


@app.route("/api/devlog")
@require_admin
def api_devlog():
    level_filter = request.args.get("level", "").strip().upper()
    query = request.args.get("q", "").strip().lower()
    with _devlog_lock:
        rows = list(_devlog)
    if level_filter:
        rows = [row for row in rows if row["level"] == level_filter]
    if query:
        rows = [row for row in rows if query in json.dumps(row, ensure_ascii=False).lower()]
    return jsonify({"updated": utcnow(), "entries": rows[-200:]})


def geoip_map_payload():
    now = time.time()
    with _geoip_map_cache_lock:
        if _geoip_map_cache["data"] is not None and now - _geoip_map_cache["at"] < GEOIP_MAP_CACHE_SECONDS:
            return _geoip_map_cache["data"]
    with closing(sqlite3.connect(DB_PATH)) as c:
        domain_rows = c.execute("SELECT domain,clients_json FROM domains WHERE requests>0 ORDER BY last_seen DESC LIMIT ?", (GEOIP_MAP_DOMAIN_LIMIT,)).fetchall()
        destination_rows = c.execute(
            "SELECT di.domain,di.ip,di.observations FROM domain_destination_ips di "
            "JOIN (SELECT domain FROM domains WHERE requests>0 ORDER BY last_seen DESC LIMIT ?) lim ON lim.domain=di.domain",
            (GEOIP_MAP_DOMAIN_LIMIT,),
        ).fetchall()
        device_labels = {row[0]: row[1] for row in c.execute("SELECT device_key,COALESCE(NULLIF(hostname,''),NULLIF(name,''),NULLIF(vendor,''),device_key) FROM devices").fetchall()}
        history_row = c.execute("SELECT COUNT(DISTINCT domain),MIN(first_seen) FROM domain_destination_ips").fetchone()
    by_domain = {}
    for domain, ip, observations in destination_rows:
        by_domain.setdefault(domain, []).append((ip, int(observations or 0)))
    countries = {}
    destination_points = {}
    city_provider_ready = _geoip_city_provider is not None and _geoip_city_provider.available
    datacenter_provider_ready = _geoip_datacenter_provider is not None and _geoip_datacenter_provider.available
    total_observations = geolocated_observations = 0
    # Per-provenance observation counts for the coordinate hierarchy (Issue
    # #88 follow-up): city_geoip and known_datacenter are real map points;
    # country_only/unmapped never place a Destinations bubble, but are still
    # counted so the map/report/PDF can say honestly how much coverage each
    # tier actually has.
    provenance_counts = {"city_geoip": 0, "known_datacenter": 0, "country_only": 0, "unmapped": 0}
    total_domains = len(domain_rows); geolocated_domains = unknown_domains = unknown_observations = 0
    for domain, clients_json in domain_rows:
        try: clients = json.loads(clients_json or "{}")
        except (TypeError, ValueError): clients = {}
        domain_geolocated = False; unmatched = 0
        for ip, observations in by_domain.get(domain, []):
            total_observations += observations
            result = geoip_lookup(ip); code, name = result["country_code"], result["country_name"]
            # Destination coordinate hierarchy (Issue #88 #5/#6 + known-
            # datacenter follow-up): a real city/coordinate GeoIP match wins
            # first; only when that misses does an explicitly-sourced known
            # datacenter/provider range fill in a region-derived point;
            # otherwise the IP is country-only (counted for the Countries
            # aggregate, never a Destinations bubble) or fully unmapped.
            # Neither tier is gated on whether the separate country-range
            # provider also happened to match this IP.
            point_provenance = None
            if city_provider_ready:
                city_result = geoip_city_lookup(ip)
                if city_result["lat"] is not None and city_result["lon"] is not None:
                    point_key = ("city", round(city_result["lat"], 3), round(city_result["lon"], 3))
                    dbucket = destination_points.setdefault(point_key, {
                        "lat": city_result["lat"], "lon": city_result["lon"],
                        "country_code": city_result["country_code"] or code, "country_name": city_result["country_name"] or name,
                        "city": city_result["city"], "provider": None, "region": None, "provenance": "city_geoip",
                        "observation_count": 0, "domain_keys": set(), "ip_keys": set(),
                    })
                    dbucket["observation_count"] += observations; dbucket["domain_keys"].add(domain); dbucket["ip_keys"].add(ip)
                    point_provenance = "city_geoip"
            if point_provenance is None and datacenter_provider_ready:
                dc_result = geoip_datacenter_lookup(ip)
                if dc_result["lat"] is not None and dc_result["lon"] is not None:
                    point_key = ("dc", round(dc_result["lat"], 3), round(dc_result["lon"], 3), dc_result["provider"], dc_result["region"])
                    dbucket = destination_points.setdefault(point_key, {
                        "lat": dc_result["lat"], "lon": dc_result["lon"],
                        "country_code": dc_result["country_code"] or code, "country_name": name,
                        "city": None, "provider": dc_result["provider"], "region": dc_result["region"], "provenance": "known_datacenter",
                        "observation_count": 0, "domain_keys": set(), "ip_keys": set(),
                    })
                    dbucket["observation_count"] += observations; dbucket["domain_keys"].add(domain); dbucket["ip_keys"].add(ip)
                    point_provenance = "known_datacenter"
            if point_provenance is None:
                point_provenance = "country_only" if code else "unmapped"
            provenance_counts[point_provenance] += observations
            if not code:
                unmatched += observations
                continue
            domain_geolocated = True; geolocated_observations += observations
            bucket = countries.setdefault(code, {"country_name": name or code, "domain_keys": set(), "observation_count": 0, "sample_domains": {}, "device_keys": set(), "ip_keys": set()})
            bucket["observation_count"] += observations; bucket["domain_keys"].add(domain); bucket["sample_domains"][domain] = bucket["sample_domains"].get(domain, 0) + observations
            bucket["device_keys"].update(clients.keys()); bucket["ip_keys"].add(ip)
        if domain_geolocated: geolocated_domains += 1
        else:
            unknown_domains += 1; unknown_observations += unmatched
    destination_list = [
        {
            "lat": b["lat"], "lon": b["lon"], "country_code": b["country_code"], "country_name": b["country_name"], "city": b["city"],
            "provider": b["provider"], "region": b["region"], "provenance": b["provenance"],
            "observation_count": b["observation_count"], "domain_count": len(b["domain_keys"]), "unique_ip_count": len(b["ip_keys"]),
            "sample_domains": list(b["domain_keys"])[:5],
        }
        for b in destination_points.values()
    ]
    destination_list.sort(key=lambda d: -d["observation_count"])
    country_list = []
    for code, bucket in countries.items():
        top_domains = sorted(bucket["sample_domains"].items(), key=lambda kv: -kv[1])[:5]
        centroid = COUNTRY_CENTROIDS.get(code)
        country_list.append({
            "country_code": code, "country_name": bucket["country_name"], "domain_count": len(bucket["domain_keys"]),
            "observation_count": bucket["observation_count"], "unique_ip_count": len(bucket["ip_keys"]),
            "sample_domains": [d for d, _ in top_domains],
            "sample_devices": [device_labels.get(k, k) for k in list(bucket["device_keys"])[:5]],
            "centroid": list(centroid[:2]) if centroid else None,
        })
    country_list.sort(key=lambda row: -row["observation_count"])
    diagnostic_state = _geoip_diagnostic_state(total_observations, geolocated_observations)
    payload = {
        "updated": utcnow(),
        "provider": {"configured": bool(_geoip_provider.available), "db_path_basename": os.path.basename(_geoip_provider.path) if _geoip_provider.available and _geoip_provider.path else None, "range_count": _geoip_provider.range_count if _geoip_provider.available else 0},
        "countries": country_list, "destinations": destination_list,
        "unknown": {"domain_count": unknown_domains, "observation_count": unknown_observations},
        "coverage": {"total_domains": total_domains, "geolocated_domains": geolocated_domains, "total_observations": total_observations, "geolocated_observations": geolocated_observations, "geolocated_pct": round(100.0 * geolocated_observations / total_observations, 1) if total_observations else 0.0, "provenance": provenance_counts},
        "capabilities": {"country": bool(_geoip_provider.available), "coordinates": city_provider_ready, "datacenter": datacenter_provider_ready, "heatmap": False},
        "history": {"tracked_domains_all_time": int(history_row[0] or 0), "tracking_since": history_row[1] if history_row and history_row[1] else None},
        "diagnostics": {"state": diagnostic_state, "message": GEOIP_DIAGNOSTIC_MESSAGES[diagnostic_state], "country": _geoip_diagnostics(), "city": _geoip_city_diagnostics(), "datacenter": _geoip_datacenter_diagnostics()},
        # Visualization-only origin for destination route/arc rendering. Real
        # coordinates only ever come from an explicit operator setting --
        # never derived/guessed (Issue #88 #5).
        "origin": get_setting("map_origin"),
    }
    with _geoip_map_cache_lock:
        _geoip_map_cache["data"] = payload; _geoip_map_cache["at"] = now
    return payload


@app.route("/api/analytics/map")
def api_analytics_map():
    try:
        return jsonify(geoip_map_payload())
    except Exception as exc:
        log_event("ERROR", "Destination map payload failed", error=repr(exc))
        return jsonify({"updated": utcnow(), "provider": {"configured": False, "range_count": 0}, "countries": [], "destinations": [], "unknown": {"domain_count": 0, "observation_count": 0}, "coverage": {"total_domains": 0, "geolocated_domains": 0, "total_observations": 0, "geolocated_observations": 0, "geolocated_pct": 0.0, "provenance": {"city_geoip": 0, "known_datacenter": 0, "country_only": 0, "unmapped": 0}}, "capabilities": {"country": False, "coordinates": False, "datacenter": False, "heatmap": False}, "history": {"tracked_domains_all_time": 0, "tracking_since": None}, "diagnostics": {"state": "load_failed", "message": "Destination map backend error."}}), 200


@app.route("/")
def index():
    q=request.args.get("q","").strip()
    status_filter=request.args.get("status","").strip()
    new_only=request.args.get("new","0")=="1"
    classification_filter=request.args.get("classification","").strip()
    severity_filter=request.args.get("severity","").strip()
    device_filter=request.args.get("device","").strip()
    vendor_filter=request.args.get("vendor","").strip()
    page=int(request.args.get("page","1") or 1)
    page_size=int(request.args.get("page_size","50") or 50)
    result=inspect_domain(q) if q else None
    recent=get_recent(page=page,page_size=page_size,status_filter=status_filter,new_only=new_only,classification_filter=classification_filter,severity_filter=severity_filter,device_filter=device_filter,vendor_filter=vendor_filter)
    clients=get_clients()
    return render_template_string(HTML,q=q,result=result,inspect_html=inspect_html(result) if result else "",recent_html=recent_html(recent["rows"]),clients_html=clients_html(clients),version=APP_VERSION,refresh_seconds=UI_REFRESH_SECONDS,refresh_seconds_ms=UI_REFRESH_SECONDS*1000,updated=utcnow(),stats=get_stats(),error=None, **_environment_render_context())


@app.route("/search")
def search():
    return index()


@app.route("/api/state")
def api_state():
    try:
        return jsonify(state_payload(q=request.args.get("q","").strip(),status_filter=request.args.get("status","").strip(),new_only=request.args.get("new","0")=="1",classification_filter=request.args.get("classification","").strip(),severity_filter=request.args.get("severity","").strip(),device_filter=request.args.get("device","").strip(),vendor_filter=request.args.get("vendor","").strip(),page=int(request.args.get("page","1") or 1),page_size=int(request.args.get("page_size","50") or 50)))
    except Exception as e:
        print("state error:",repr(e),flush=True)
        return jsonify({"updated":utcnow(),"recent":[],"recent_meta":{"page":1,"pages":1,"total":0,"page_size":50,"new_count":0,"new_domains":[],"status_counts":{}},"filter_options":get_filter_options(),"clients":get_clients(),"stats":get_stats(),"inspect_html":None,"error":str(e)}),200


@app.route("/device")
def device_view():
    key = request.args.get("key", "").strip()
    d = device_detail(key)
    if not d:
        return render_template_string(HTML, q="", result=None, inspect_html=f"<div class='card'><h2>Device not found</h2><p class='error'>No device exists for this identity.</p><p><a href='/'>Back to dashboard</a></p></div>", recent_html=recent_html(get_recent()["rows"]), clients_html=clients_html(get_clients()), version=APP_VERSION, refresh_seconds=UI_REFRESH_SECONDS, refresh_seconds_ms=UI_REFRESH_SECONDS * 1000, updated=utcnow(), stats=get_stats(), error=None), 404
    return render_template_string(HTML, q="", result=None, inspect_html=detail_html_device(d), recent_html=recent_html(get_recent()["rows"]), clients_html=clients_html(get_clients()), version=APP_VERSION, refresh_seconds=UI_REFRESH_SECONDS, refresh_seconds_ms=UI_REFRESH_SECONDS * 1000, updated=utcnow(), stats=get_stats(), error=None)


@app.route("/ip")
def ip_view():
    addr = request.args.get("addr", "").strip()
    d = ip_detail(addr)
    if not d:
        return render_template_string(HTML, q="", result=None, inspect_html=f"<div class='card'><h2>IP not found</h2><p class='error'>No valid IP observation exists for this address.</p><p><a href='/'>Back to dashboard</a></p></div>", recent_html=recent_html(get_recent()["rows"]), clients_html=clients_html(get_clients()), version=APP_VERSION, refresh_seconds=UI_REFRESH_SECONDS, refresh_seconds_ms=UI_REFRESH_SECONDS * 1000, updated=utcnow(), stats=get_stats(), error=None), 404
    return render_template_string(HTML, q="", result=None, inspect_html=detail_html_ip(d), recent_html=recent_html(get_recent()["rows"]), clients_html=clients_html(get_clients()), version=APP_VERSION, refresh_seconds=UI_REFRESH_SECONDS, refresh_seconds_ms=UI_REFRESH_SECONDS * 1000, updated=utcnow(), stats=get_stats(), error=None)


@app.route("/health")
def health():
    return jsonify({"ok": True, "version": APP_VERSION, "environment": RUNTIME_ENV})


if __name__ == "__main__":
    init_db()
    _prune_stale_device_ips()
    threading.Thread(target=worker, daemon=True).start()
    threading.Thread(target=_enrichment_worker, daemon=True, name="enrichment-queue").start()
    threading.Thread(target=_device_ip_cleanup_worker, daemon=True, name="device-ip-cleanup").start()
    threading.Thread(target=_ip_ping_worker, daemon=True, name="ip-ping").start()
    threading.Thread(target=_geoip_initial_load_worker, daemon=True, name="geoip-loader").start()
    threading.Thread(target=_geoip_city_initial_load_worker, daemon=True, name="geoip-city-loader").start()
    threading.Thread(target=_geoip_datacenter_initial_load_worker, daemon=True, name="geoip-datacenter-loader").start()
    _report_scheduler.start()
    signal.signal(signal.SIGTERM, lambda *_: (_report_scheduler.shutdown(), sys.exit(0)))
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))