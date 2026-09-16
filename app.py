# === SQLITE CLOSE PATCH 0.7.13-HF2.3 ===
import hashlib
import ipaddress
import json
import os
import re
import queue
import socket
import sqlite3
import subprocess
import threading
import time
import gc
import sys
import tracemalloc
import io
import platform
import shutil
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from urllib.parse import quote

import requests
from flask import Flask, jsonify, render_template_string, request, send_file

from pathlib import Path
from contextlib import closing

from bemo_core.health import HealthLevel, InspectorHealth
from bemo_core.registry import get_registry
import inspectors.dns as dns_inspector
from inspectors.dns import (
    ALLOWED_REASONS,
    BLOCKED_REASONS,
    UNKNOWN_REASONS,
    _status_from_counts,
    query_status,
    severity_for_classification,
    status_summary,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
try:
    with open(os.path.join(BASE_DIR, "VERSION"), "r", encoding="utf-8") as f:
        APP_VERSION = f.read().strip()
except Exception:
    APP_VERSION = os.getenv("APP_VERSION", "dev")

dns_inspector.register(APP_VERSION)


def normalize_runtime_environment(value):
    """Normalize DNS_INSPECTOR_ENV, defaulting to production when unset/unknown."""
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
        "platform_name": "Inspector BEMO",
        "registered_inspectors": [info.to_dict() for info in get_registry().list()],
    }


OBSERVABILITY_START_MONOTONIC = time.monotonic()
OBSERVABILITY_START_AT = datetime.now(timezone.utc).isoformat()

MEMORY_DIAGNOSTICS_ENABLED = os.getenv("MEMORY_DIAGNOSTICS_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}
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
DEVICE_IP_RETENTION_HOURS = max(1.0, float(os.getenv("DEVICE_IP_RETENTION_HOURS", "12")))
DEVICE_IP_CLEANUP_INTERVAL_MINUTES = max(5, int(os.getenv("DEVICE_IP_CLEANUP_INTERVAL_MINUTES", "30")))
IP_PING_INTERVAL_HOURS = max(1.0, float(os.getenv("IP_PING_INTERVAL_HOURS", "4")))
IP_PING_INITIAL_DELAY_SECONDS = max(10, int(os.getenv("IP_PING_INITIAL_DELAY_SECONDS", "60")))
IP_PING_TIMEOUT_SECONDS = max(1, int(os.getenv("IP_PING_TIMEOUT_SECONDS", "1")))
NETIFY_CACHE_HOURS = int(os.getenv("NETIFY_CACHE_HOURS", "4320"))  # 180 days
RDAP_CACHE_HOURS = int(os.getenv("RDAP_CACHE_HOURS", "720"))  # 30 days
DNS_RECORDS_CACHE_HOURS = int(os.getenv("DNS_RECORDS_CACHE_HOURS", "240"))  # 10 days
ENRICHMENT_RETRY_HOURS = max(24.0, float(os.getenv("ENRICHMENT_RETRY_HOURS", "24")))
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

# Background AdGuard status refreshes are deliberately bounded.
_status_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="agh-status")
_status_guard = threading.Lock()
_status_inflight = set()
_status_slots = threading.BoundedSemaphore(20)

MAC_RE = re.compile(r"^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.I)
IP_RE = re.compile(r"^[0-9a-f:.]+$")

HTML = """
<!doctype html><html><head><meta charset="utf-8"><link rel="icon" type="image/svg+xml" href="{{favicon_path}}"><title>{{page_title}}</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:28px;max-width:1450px;margin-inline:auto}
h1{margin:0 0 6px;font-size:2rem;letter-spacing:-.02em}.muted,small{color:#8b949e}.live{color:#7ee787;font-weight:700}.updated-time{color:#58a6ff;font-weight:700}.updated-date{color:#8b949e}.signal{border-left:3px solid #30363d;padding:10px 12px;background:#0d1117;border-radius:8px}.signal-green{border-color:#3fb950}.signal-blue{border-color:#58a6ff}.signal-yellow{border-color:#d29922}.signal-orange{border-color:#db6d28}.signal-red{border-color:#f85149}.signal-gray{border-color:#8b949e}.signal-title{font-weight:750;margin-bottom:5px}.evidence{margin:6px 0 0;padding-left:18px;color:#c9d1d9}.evidence li{margin:3px 0}.confidence-high{color:#3fb950;font-weight:700}.confidence-medium{color:#d29922;font-weight:700}.confidence-low{color:#8b949e;font-weight:700}.dns-list{display:flex;flex-wrap:wrap;gap:6px}.dns-ip{display:inline-block;padding:4px 8px;border:1px solid #30363d;border-radius:7px;background:#161b22;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.82rem}.vendor-logo{width:20px;height:20px;object-fit:contain;vertical-align:middle;margin-right:6px;border-radius:4px}.vendor-logo-lg{width:30px;height:30px;object-fit:contain;flex:0 0 30px}.vendor-mark{display:inline-flex;align-items:center;justify-content:center;width:20px;height:20px;margin-right:6px;border-radius:5px;background:#30363d;font-size:.7rem}.vendor-mark-lg{display:inline-flex;align-items:center;justify-content:center;width:30px;height:30px;flex:0 0 30px;border-radius:8px;background:#30363d;font-size:.75rem;font-weight:800}.device-type-icon{display:inline-flex;align-items:center;justify-content:center;width:20px;height:20px;flex:0 0 20px;margin-right:6px;border-radius:5px;background:#30363d;color:#8b949e}.device-type-icon-lg{display:inline-flex;align-items:center;justify-content:center;width:30px;height:30px;flex:0 0 30px;border-radius:8px;background:#30363d;color:#8b949e}.device-type-icon svg,.device-type-icon-lg svg{width:70%;height:70%;fill:none;stroke:currentColor;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}
.toolbar{display:flex;gap:8px;align-items:center;margin:20px 0 4px}.toolbar input{flex:1;min-width:0}.toolbar button{white-space:nowrap}
.observability-strip{display:flex;align-items:center;flex-wrap:wrap;gap:8px;margin:4px 0 8px}
.observability-pill{display:inline-flex;align-items:center;gap:6px;padding:5px 9px;border:1px solid #30363d;border-radius:999px;background:#11161d;color:#c9d1d9;font-size:.78rem;font-variant-numeric:tabular-nums}
.observability-dot{width:7px;height:7px;border-radius:50%;background:#3fb950;box-shadow:0 0 0 2px rgba(63,185,80,.10)}
.debug-button{padding:5px 9px;font-size:.78rem;border-radius:999px}
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
.bemo-shell-nav{display:flex;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:6px}
.bemo-brand{font-weight:800;letter-spacing:.02em;color:#8b949e;font-size:.82rem;text-transform:uppercase}
.bemo-inspector-pill{display:inline-flex;align-items:center;padding:4px 10px;border-radius:999px;border:1px solid #30363d;background:#161b22;color:#8b949e;font-size:.78rem;font-weight:700}
.bemo-inspector-pill.active{border-color:#58a6ff;color:#e6edf3;background:#11161d}
.bemo-more-inspectors{color:#6e7681;font-size:.78rem}
</style></head><body>
{% if is_dev_environment %}<div class="dev-banner" role="alert">⚠️ DEVELOPMENT ENVIRONMENT — NOT PRODUCTION</div>{% endif %}
<nav class="bemo-shell-nav" aria-label="Inspector BEMO navigation">
  <span class="bemo-brand">{{platform_name}}</span>
  {% for inspector in registered_inspectors %}<span class="bemo-inspector-pill active">{{inspector.name}}</span>{% endfor %}
  <span class="bemo-more-inspectors">System · Storage · Services — planned</span>
</nav>
<h1>DNS Inspector <span class="muted" style="font-size:.55em">v{{version}}</span>{% if is_dev_environment %} <span class="dev-badge">DEV</span>{% endif %}</h1>
<div class="observability-strip" aria-label="Application runtime status">
  <span class="observability-pill"><span class="observability-dot"></span><span id="obs-uptime">Uptime —</span></span>
  <span class="observability-pill"><span id="obs-memory">RAM —</span></span>
  <button type="button" class="debug-button" onclick="window.location='/debug/bundle'">Generate Debug Bundle</button>
</div>
<p class="muted">Watching AdGuard activity · <span class="live">● Live</span> · refresh every {{refresh_seconds}}s · updated <span id="last-update-time" class="updated-time"></span> · <span id="last-update-date" class="updated-date"></span></p>
<form class="toolbar" action="/search"><input name="q" placeholder="hostname..." value="{{q}}"><button type="submit">Inspect</button><button type="button" onclick="window.location='/'">Reset</button></form>
<div class="tabs" role="tablist" aria-label="DNS Inspector sections">
  <button class="tab-btn active" data-tab="overview" role="tab">Overview</button>
  <button class="tab-btn" data-tab="devices" role="tab">Devices</button>
  <button class="tab-btn" data-tab="analytics" role="tab">Analytics</button>
</div>
<section id="tab-overview" class="tab-panel active" data-panel="overview">
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
<section id="tab-analytics" class="tab-panel" data-panel="analytics">
  <div class="chart-grid">
    <div class="card chart-card"><h2>Most requested domains</h2><div id="chart-domains" class="chart-list"></div><div class="stats-note">Based on recorded DNS requests.</div></div>
    <div class="card chart-card"><h2>Most active devices</h2><div id="chart-devices" class="chart-list"></div><div class="stats-note">Ranked by total recorded requests.</div></div>
    <div class="card chart-card"><h2>Most active vendors</h2><div id="chart-vendors" class="chart-list"></div><div class="stats-note">Aggregated from identified devices.</div></div>
    <div class="card chart-card"><h2>Most active IPs</h2><div id="chart-ips" class="chart-list"></div><div class="stats-note">Aggregated from device IP observations.</div></div>
  </div>
</section>
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
function renderRecent(rows){window.__lastRecent=rows||[];document.getElementById('recent-body').innerHTML=(rows||[]).map(r=>{const devices=(r.devices||[]).map(d=>{const label=deviceLabelFor(d);return `<a class="device-chip link-device" href="${deviceHref(d)}" title="Open device details">${d.vendor_logo?`<img class="vendor-logo" src="${esc(d.vendor_logo)}" alt="" loading="lazy">`:deviceTypeSvg(d.type,d.icon,false)}${esc(label||d.name)}</a>`;}).join('');const n=isNewRow(r);const badge=n?`<span class="new-badge" title="First seen ${esc(r.first_seen||'')}"><span class="new-badge-dot"></span>NEW · ${esc(ageText(r.first_seen))}</span>`:'';return `<tr class="${n?'row-new':''}" data-sort-domain="${esc(r.domain)}" data-sort-activity="${Number(r.requests)||0}" data-sort-devices="${Number(r.clients)||0}" data-sort-status="${esc(r.status)}" data-sort-severity="${esc(r.severity)}" data-sort-classification="${esc(r.classification)}"><td><a class="glance-domain" href="/search?q=${encodeURIComponent(r.domain)}" title="Inspect domain in DNS Inspector">${esc(r.domain)}</a>${badge}<div class="glance-meta"><span>${esc(r.requests)} requests</span><span>·</span><span>${esc(r.clients)} device${r.clients===1?'':'s'}</span></div></td><td><b>${esc(r.requests)}</b> requests</td><td class="glance-devices"><div class="device-list">${devices||'<span class="sub">No identified devices</span>'}</div></td><td><span class="status-pill status-${esc(r.status_class)}">${esc(r.status)}</span></td><td><span class="severity-${esc(r.severity_text_class)}">${esc(r.severity)}</span></td><td><span class="dot dot-${esc(r.severity_class)}"></span><span class="tag ${esc(r.badge_class)}">${esc(r.classification)}</span></td></tr>`}).join('');reapplyTableSorts()}
function setSelectOptions(id,values,selected){const e=document.getElementById(id);if(!e)return;e.innerHTML='<option value="">All</option>'+(values||[]).map(v=>{const value=typeof v==='string'?v:v.value;const label=typeof v==='string'?v:v.label;return `<option value="${esc(value)}">${esc(label)}</option>`}).join('');e.value=selected||''}
function renderRecentControls(meta,opts){recentMeta=meta||recentMeta;const c=recentMeta.status_counts||{};[['count-all','All'],['count-allowed','Allowed'],['count-blocked','Blocked'],['count-mixed','Mixed'],['count-unknown','Unknown']].forEach(([i,k])=>{const e=document.getElementById(i);if(e)e.textContent=c[k]!=null?` ${c[k]}`:''});const n=document.getElementById('count-new');if(n)n.textContent=recentMeta.new_count!=null?` ${recentMeta.new_count}`:'';document.querySelectorAll('[data-status-filter]').forEach(b=>b.classList.toggle('active',(b.dataset.statusFilter||'')===recentFilters.status));document.getElementById('new-filter')?.classList.toggle('active',recentFilters.newOnly);const sum=document.getElementById('results-summary');if(sum)sum.innerHTML=`<b>${recentMeta.total||0}</b> matching domain${(recentMeta.total||0)===1?'':'s'} · <b>${recentMeta.new_count||0}</b> new in the last 24h`;setSelectOptions('classification-filter',opts?.classifications,recentFilters.classification);setSelectOptions('severity-filter',opts?.severities,recentFilters.severity);setSelectOptions('device-filter',opts?.devices,recentFilters.device);setSelectOptions('vendor-filter',opts?.vendors,recentFilters.vendor);const ps=document.getElementById('page-size');if(ps)ps.value=String(recentFilters.page_size);const label=document.getElementById('page-label');if(label){const a=recentMeta.total?((recentMeta.page-1)*recentMeta.page_size)+1:0;const b=recentMeta.total?Math.min(recentMeta.page*recentMeta.page_size,recentMeta.total):0;label.textContent=`Showing ${a}–${b} of ${recentMeta.total||0}`}const prev=document.getElementById('page-prev'),next=document.getElementById('page-next');if(prev)prev.disabled=recentMeta.page<=1;if(next)next.disabled=recentMeta.page>=recentMeta.pages}
function showNewBanner(entries){const b=document.getElementById('new-banner'),t=document.getElementById('new-banner-text');if(!b||!t||!entries.length)return;const items=entries.slice(0,3).map(r=>{const status=r.status||'Unknown';const statusClass=r.status_class||'unknown';const href=`/search?q=${encodeURIComponent(r.domain)}`;return `<span class="new-domain-item"><a class="new-domain-link" href="${href}" title="Inspect domain in DNS Inspector">${esc(r.domain)}</a><span class="status-pill status-${esc(statusClass)}">${esc(status)}</span></span>`}).join('');t.innerHTML=`<b>${entries.length}</b> new domain${entries.length===1?'':'s'} detected · <span class="new-domain-items">${items}</span>`;b.classList.add('show')}
function clearNewBanner(){document.getElementById('new-banner')?.classList.remove('show')}
function updateNewDetection(rows){const current=rows||[];const set=new Set(current.map(r=>r.domain));if(!initialDomainSnapshot){set.forEach(d=>knownDomains.add(d));initialDomainSnapshot=true;return}const fresh=current.filter(r=>!knownDomains.has(r.domain));set.forEach(d=>knownDomains.add(d));if(fresh.length)showNewBanner(fresh)}
window.deviceLabels={};
function ensureRefreshStatus(){let el=document.getElementById('refresh-status');if(el)return el;el=document.createElement('div');el.id='refresh-status';el.className='refresh-status';el.innerHTML='<span class="refresh-spinner"></span><span>Se încarcă lista…</span>';document.body.appendChild(el);return el}
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

async function loadDeviceLabels(){try{const r=await fetch('/api/device/label',{cache:'no-store'});if(!r.ok)return;const data=await r.json();window.deviceLabels=data.labels||{};}catch(e){console.debug('device labels load failed',e)}}
async function editDeviceLabel(button){const key=button?.dataset?.deviceKey||'';if(!key)return;const current=button.dataset.deviceLabel||'';const value=window.prompt('Device label',current);if(value===null)return;const label=value.trim().slice(0,80);try{const r=await fetch('/api/device/label',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({device_key:key,label})});const data=await r.json();if(!r.ok||!data.ok)throw new Error(data.error||'Save failed');window.deviceLabels[key]=label;renderClients(window.__lastClients||[]);renderRecent(window.__lastRecent||[]);bindDeviceLabelButtons();}catch(e){alert('Could not save device label: '+e.message)}}
function bindDeviceLabelButtons(){document.querySelectorAll('.device-label-btn').forEach(b=>{if(b.dataset.bound)return;b.dataset.bound='1';b.addEventListener('click',()=>editDeviceLabel(b));})}
function renderClients(rows){ window.__lastClients=rows||[]; document.getElementById('clients-body').innerHTML = rows.map(deviceRow).join(''); bindDeviceLabelButtons(); placeDeviceLabelsInColumn(); injectIpPingControls(); reapplyTableSorts(); }
let tableSortState = {recent:{key:null,dir:1}, clients:{key:null,dir:1}};
function rowSortValue(row,key,type){ const raw=row.dataset['sort'+key.charAt(0).toUpperCase()+key.slice(1)] ?? ''; return type==='number' ? (Number(raw)||0) : String(raw).toLowerCase(); }
function applySort(table,key,dir){ const th=[...table.querySelectorAll('th.sortable')].find(x=>x.dataset.sortKey===key); if(!th)return; table.querySelectorAll('th.sortable').forEach(x=>x.classList.remove('sort-asc','sort-desc')); th.classList.add(dir===1?'sort-asc':'sort-desc'); const type=th.dataset.sortType||'text'; const body=table.tBodies[0]; [...body.rows].sort((a,b)=>{const av=rowSortValue(a,key,type),bv=rowSortValue(b,key,type); if(av<bv)return -1*dir; if(av>bv)return 1*dir; return 0;}).forEach(r=>body.appendChild(r)); }
function bindSortableTables(){ document.querySelectorAll('th.sortable').forEach(th=>{ th.onclick=()=>{ const table=th.closest('table'); const name=table.id==='recent-table'?'recent':'clients'; const key=th.dataset.sortKey; const same=tableSortState[name].key===key; tableSortState[name]={key,dir:same?-tableSortState[name].dir:1}; applySort(table,key,tableSortState[name].dir); }; }); }
function reapplyTableSorts(){ const r=document.getElementById('recent-table'),c=document.getElementById('clients-table'); if(r&&tableSortState.recent.key)applySort(r,tableSortState.recent.key,tableSortState.recent.dir); if(c&&tableSortState.clients.key)applySort(c,tableSortState.clients.key,tableSortState.clients.dir); }
function setActiveTab(name){
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.dataset.panel === name));
  try{ localStorage.setItem('dnsInspectorTab', name); }catch(e){}
}
function chartBars(elId, items){
  const el=document.getElementById(elId); if(!el) return;
  if(!items || !items.length){ el.innerHTML='<div class="sub">No data yet.</div>'; return; }
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
  const saved=localStorage.getItem('dnsInspectorTab');
  if(!currentQuery && !hasInspectContent && saved && ['overview','devices','analytics'].includes(saved)) setActiveTab(saved);
  else if(currentQuery || hasInspectContent) setActiveTab('overview');
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
  try{const r=await fetch(buildStateUrl(),{cache:'no-store'});if(!r.ok)return;const data=await r.json();renderRecent(data.recent);updateNewDetection(data.recent);renderRecentControls(data.recent_meta,data.filter_options);if(initialDomainSnapshot&&data.recent_meta?.new_domains?.length)showNewBanner(data.recent_meta.new_domains);renderClients(data.clients);renderStats(data.stats);renderObservability(data.observability);if(data.inspect_html!==null)document.getElementById('inspect-root').innerHTML=data.inspect_html;const stamp=formatUpdated(data.updated);document.getElementById('last-update-time').textContent=stamp.time;document.getElementById('last-update-date').textContent=stamp.date}catch(e){console.debug('refresh failed',e)}finally{hideRefreshStatus();refreshInFlight=false;if(refreshPending){refreshPending=false;scheduleRefresh(0)}else{scheduleRefresh(refreshMs)}}}
document.querySelectorAll('[data-status-filter]').forEach(b=>b.addEventListener('click',()=>{recentFilters.status=b.dataset.statusFilter||'';applyRecentFilterChanges()}));document.getElementById('new-filter')?.addEventListener('click',()=>{recentFilters.newOnly=!recentFilters.newOnly;applyRecentFilterChanges()});for(const [id,key] of [['classification-filter','classification'],['severity-filter','severity'],['device-filter','device'],['vendor-filter','vendor']])document.getElementById(id)?.addEventListener('change',e=>{recentFilters[key]=e.target.value;applyRecentFilterChanges()});document.getElementById('page-size')?.addEventListener('change',e=>{recentFilters.page_size=Number(e.target.value)||50;applyRecentFilterChanges()});document.getElementById('page-prev')?.addEventListener('click',()=>{if(recentFilters.page>1){recentFilters.page--;requestRefresh()}});document.getElementById('page-next')?.addEventListener('click',()=>{if(recentFilters.page<recentMeta.pages){recentFilters.page++;requestRefresh()}});
const initialStamp=formatUpdated({{ updated|tojson }});document.getElementById('last-update-time').textContent=initialStamp.time;document.getElementById('last-update-date').textContent=initialStamp.date;loadDeviceLabels().then(()=>{renderClients(window.__lastClients||[]);renderRecent(window.__lastRecent||[]);bindDeviceLabelButtons();placeDeviceLabelsInColumn();});requestRefresh();
</script>
<script>
function observabilityDuration(seconds){let s=Math.max(0,Math.floor(Number(seconds)||0));const d=Math.floor(s/86400);s%=86400;const h=Math.floor(s/3600);s%=3600;const m=Math.floor(s/60);s%=60;if(d)return `${d}d ${h}h ${m}m`;if(h)return `${h}h ${m}m ${s}s`;if(m)return `${m}m ${s}s`;return `${s}s`}
function observabilityRam(value){const mb=Number(value);return Number.isFinite(mb)?`${mb.toFixed(mb>=100?0:1)} MB`:'—'}
function renderObservability(d){if(!d)return;const u=document.getElementById('obs-uptime');const m=document.getElementById('obs-memory');if(u)u.textContent=`Uptime ${observabilityDuration(d.uptime_seconds)}`;if(m)m.textContent=`RAM ${observabilityRam(d.ram_mb)}`}
</script></body></html>
"""


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def add_column_if_missing(c, table, column, ddl):
    cols = {row[1] for row in c.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in cols:
        c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


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
        c.execute("""CREATE TABLE IF NOT EXISTS processed_queries(
            fingerprint TEXT PRIMARY KEY, seen_at TEXT NOT NULL, status_counted INTEGER NOT NULL DEFAULT 0)""")
        add_column_if_missing(c, "processed_queries", "status_counted", "INTEGER NOT NULL DEFAULT 0")
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
        with _open_trackerdb(TRACKERDB_PATH) as c:
            c.execute("SELECT 1 FROM tracker_domains LIMIT 1").fetchone()
        return True
    except Exception:
        return False


def trackerdb_refresh_needed():
    return (not trackerdb_ready()) or (time.time() - os.path.getmtime(TRACKERDB_PATH) > TRACKERDB_REFRESH_HOURS * 3600)


def _execute_sql_file(conn, path):
    """Execute a SQL dump incrementally to avoid holding the full snapshot in RAM."""
    statement = []
    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        for raw_line in f:
            statement.append(raw_line)
            candidate = "".join(statement)
            if sqlite3.complete_statement(candidate):
                conn.executescript(candidate)
                statement.clear()
    if statement and "".join(statement).strip():
        conn.executescript("".join(statement))


def refresh_trackerdb(force=False):
    if not force and not trackerdb_refresh_needed():
        return
    tmp, newdb = TRACKERDB_PATH + ".download", TRACKERDB_PATH + ".new"
    try:
        print("Downloading TrackerDB snapshot...", flush=True)
        with requests.get(TRACKERDB_URL, timeout=60, stream=True) as r:
            r.raise_for_status()
            with open(tmp, "wb") as f:
                for chunk in r.iter_content(chunk_size=TRACKERDB_DOWNLOAD_CHUNK_SIZE):
                    if chunk:
                        f.write(chunk)
        if os.path.exists(newdb):
            os.remove(newdb)
        with _open_trackerdb(newdb) as c:
            _execute_sql_file(c, tmp)
            c.execute("PRAGMA journal_mode=DELETE")
        os.replace(newdb, TRACKERDB_PATH)
        try:
            os.remove(tmp)
        except FileNotFoundError:
            pass
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
    """Queue at most one AdGuard status refresh per domain.

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
                    c.execute("INSERT OR IGNORE INTO processed_queries(fingerprint,seen_at,status_counted) VALUES(?,?,1)", (fp, now))
                    continue
                qstatus = query_status(e.get("reason"), e.get("answer"))
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
                c.execute("INSERT OR IGNORE INTO processed_queries(fingerprint,seen_at,status_counted) VALUES(?,?,1)", (fp, now))
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
    except Exception as e:
        print("ingest error:", repr(e), flush=True)


def _validate_ping_ip(value):
    value = str(value or '').strip()
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError('Invalid IP address')
    if addr.is_loopback or addr.is_multicast or not addr.is_private:
        raise ValueError('Only private LAN IP addresses can be pinged')
    return value


def _run_ip_ping(ip):
    ip = _validate_ping_ip(ip)
    started = time.monotonic()
    online = False
    latency_ms = None
    error = ''
    try:
        proc = subprocess.run(
            ['ping', '-c', '1', '-W', str(IP_PING_TIMEOUT_SECONDS), ip],
            capture_output=True,
            text=True,
            timeout=IP_PING_TIMEOUT_SECONDS + 2,
            check=False,
        )
        output = (proc.stdout or '') + '\n' + (proc.stderr or '')
        online = proc.returncode == 0
        if online:
            match = re.search(r'time[=<]([0-9.]+)\s*ms', output)
            latency_ms = float(match.group(1)) if match else round((time.monotonic() - started) * 1000.0, 1)
        else:
            error = 'No reply'
    except FileNotFoundError:
        error = 'ping command unavailable'
    except subprocess.TimeoutExpired:
        error = 'Timeout'
    except Exception as e:
        error = str(e)[:200]

    checked = time.time()
    with db_lock, closing(sqlite3.connect(DB_PATH)) as c:
        c.execute(
            'INSERT OR REPLACE INTO ip_ping_status(ip,last_checked,online,latency_ms,error) VALUES(?,?,?,?,?)',
            (ip, checked, 1 if online else 0, latency_ms, error),
        )
        c.commit()
    return {'ip': ip, 'online': online, 'latency_ms': latency_ms, 'error': error, 'last_checked': checked}


def _ping_active_ips():
    cutoff = time.time() - DEVICE_IP_RETENTION_HOURS * 3600.0
    try:
        with db_lock, closing(sqlite3.connect(DB_PATH)) as c:
            ips = [row[0] for row in c.execute(
                'SELECT DISTINCT ip FROM device_ips WHERE last_seen >= ? AND ip IS NOT NULL AND TRIM(ip) <> ""',
                (cutoff,),
            ).fetchall()]
        for ip in ips:
            try:
                _run_ip_ping(ip)
            except Exception as e:
                print(f'IP ping error for {ip}: {e!r}', flush=True)
        if ips:
            print(f'IP reachability sweep checked {len(ips)} active addresses', flush=True)
    except Exception as e:
        print('IP reachability sweep error:', repr(e), flush=True)


def _ip_ping_worker():
    time.sleep(IP_PING_INITIAL_DELAY_SECONDS)
    while True:
        _ping_active_ips()
        time.sleep(IP_PING_INTERVAL_HOURS * 3600.0)


@app.route('/api/ip/ping/status', methods=['GET'])
def api_ip_ping_status():
    try:
        with db_lock, closing(sqlite3.connect(DB_PATH)) as c:
            rows = c.execute('SELECT ip,last_checked,online,latency_ms,error FROM ip_ping_status').fetchall()
        return jsonify({
            'ok': True,
            'statuses': {
                row[0]: {
                    'last_checked': row[1],
                    'online': bool(row[2]),
                    'latency_ms': row[3],
                    'error': row[4] or '',
                }
                for row in rows
            },
        })
    except Exception as e:
        print('IP ping status error:', repr(e), flush=True)
        return jsonify({'ok': False, 'statuses': {}}), 500


@app.route('/api/ip/ping', methods=['POST'])
def api_ip_ping():
    try:
        data = request.get_json(silent=True) or {}
        ip = _validate_ping_ip(data.get('ip'))
        return jsonify({'ok': True, 'result': _run_ip_ping(ip)})
    except ValueError as e:
        return jsonify({'ok': False, 'error': str(e)}), 400
    except Exception as e:
        print('manual IP ping error:', repr(e), flush=True)
        return jsonify({'ok': False, 'error': 'Ping failed'}), 500


def _prune_stale_device_ips():
    cutoff = time.time() - DEVICE_IP_RETENTION_HOURS * 3600.0
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
        _prune_stale_device_ips()
        time.sleep(DEVICE_IP_CLEANUP_INTERVAL_MINUTES * 60)


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


_enrichment_queue = queue.Queue(maxsize=500)
_enrichment_queue_lock = threading.Lock()
_enrichment_queued = set()
_enrichment_retry_until = {}
_enrichment_retry_loaded = set()

def _enrichment_retry_allowed(domain, now_ts=None):
    now_ts = time.time() if now_ts is None else now_ts
    until = _enrichment_retry_until.get(domain)
    if until is not None:
        return until <= now_ts
    if domain in _enrichment_retry_loaded:
        return True
    try:
        with closing(sqlite3.connect(DB_PATH)) as c:
            row = c.execute("SELECT next_attempt_at FROM enrichment_attempts WHERE domain=?", (domain,)).fetchone()
        if row:
            until = float(row[0] or 0)
            _enrichment_retry_until[domain] = until
        else:
            until = 0.0
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
        next_ts = _mark_enrichment_attempt(domain)
    print(f"Enrichment queued: {domain}; next retry after {datetime.fromtimestamp(next_ts, timezone.utc).isoformat()}", flush=True)
    return True

def _enrichment_needs_refresh(table, domain, ttl_hours):
    return _cache_needs_refresh(table, domain, ttl_hours)

def _enrichment_worker():
    while True:
        domain = _enrichment_queue.get()
        with _enrichment_queue_lock:
            _enrichment_queued.discard(domain)
        with enrichment_lock:
            enrichment_refreshing.add(domain)
        try:
            # Re-check every source at execution time. Fresh data is never touched.
            if _enrichment_needs_refresh('netify_cache', domain, NETIFY_CACHE_HOURS):
                netify_lookup(domain, force=True)
            if _enrichment_needs_refresh('rdap_cache', apex_domain(domain), RDAP_CACHE_HOURS):
                rdap_lookup(domain, force=True)
            if _enrichment_needs_refresh('dns_records_cache', domain, DNS_RECORDS_CACHE_HOURS):
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
    return f"https://maclookup.app/search/result?mac={quote(mac, safe=':')}" if mac else ''


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
    with closing(sqlite3.connect(DB_PATH)) as c:
        vendors=[r[0] for r in c.execute("SELECT DISTINCT vendor FROM devices WHERE TRIM(vendor)<>'' ORDER BY vendor COLLATE NOCASE").fetchall()]
        rows=c.execute("SELECT device_key,name,hostname,vendor FROM devices ORDER BY request_count DESC, device_key COLLATE NOCASE").fetchall()
        devices=[]
        for device_key,name,hostname,vendor in rows:
            label=real_device_label({"device_key":device_key,"identifier":device_key,"name":name,"hostname":hostname,"display_name":hostname or name or vendor or device_key,"vendor":vendor})
            label=label or str(vendor or '').strip() or device_key
            devices.append({"value":device_key,"label":label})
    return {"classifications":["Known service","Telemetry / Tracking","Advertising","Suspicious","Unknown"],"severities":["Info","Low","Medium","High","Unknown"],"vendors":vendors,"devices":devices}


def get_recent(page=1,page_size=50,status_filter="",new_only=False,classification_filter="",severity_filter="",device_filter="",vendor_filter=""):
    page=max(1,int(page or 1)); page_size=max(10,min(500,int(page_size or 50)))
    order_sql="first_seen DESC" if new_only else "requests DESC"
    now_dt=datetime.now(timezone.utc)
    cutoff=(now_dt-timedelta(hours=24)).isoformat()

    # Status and NEW are persisted in the domains table, so do not scan thousands
    # of domains and run TrackerDB/RDAP/Netify lookups just to answer a simple
    # Overview filter. This is the main latency fix for Allowed/Blocked/Mixed/NEW.
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
            rows=c.execute(f"SELECT domain,requests,clients_json,first_seen,blocked_requests,allowed_requests,unknown_requests,last_status,current_status,current_reason FROM domains{sql_where} ORDER BY {order_sql} LIMIT ? OFFSET ?", tuple(params)+ (page_size,offset)).fetchall()
        else:
            # Complex filters still need enrichment, but status/NEW constraints are
            # pushed into SQL first so we do not scan unrelated domains.
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

            # Enrichment is needed for the classification/severity columns, but it
            # is performed only for rows that can actually appear on this page.
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

            # Only queue stale status refreshes when the row is actually relevant.
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
            # SQL already selected the exact page. Keep the pagination metadata exact.
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
    uptime = _observability_uptime_seconds()
    return {"updated":utcnow(),"recent":recent["rows"],"recent_meta":recent["meta"],"filter_options":get_filter_options(),"clients":get_clients(),"stats":get_stats(),"inspect_html":inspect_html(result) if result else None,"observability":{"uptime_seconds":round(uptime,1),"uptime_human":_observability_uptime_human(uptime),"ram_mb":_observability_rss_mb()}}

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
        elapsed = time.time() - started
        time.sleep(max(1, POLL_SECONDS - elapsed))


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
    return render_template_string(HTML,q=q,result=result,inspect_html=inspect_html(result) if result else "",recent_html=recent_html(recent["rows"]),clients_html=clients_html(clients),version=APP_VERSION,refresh_seconds=UI_REFRESH_SECONDS,refresh_seconds_ms=UI_REFRESH_SECONDS*1000,updated=utcnow(),stats=get_stats(),error=None,**_environment_render_context())


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


@app.route("/api/device/label", methods=["GET", "POST"])
def api_device_label():
    try:
        with db_lock, closing(sqlite3.connect(DB_PATH)) as c:
            c.execute("CREATE TABLE IF NOT EXISTS device_labels(device_key TEXT PRIMARY KEY, label TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL)")
            if request.method == "GET":
                rows = c.execute("SELECT device_key,label FROM device_labels WHERE TRIM(label)<>''").fetchall()
                return jsonify({"ok": True, "labels": {k: v for k, v in rows}})
            data = request.get_json(silent=True) or {}
            device_key = str(data.get("device_key") or "").strip()
            label = str(data.get("label") or "").strip()[:80]
            if not device_key:
                return jsonify({"ok": False, "error": "device_key is required"}), 400
            c.execute("INSERT OR REPLACE INTO device_labels(device_key,label,updated_at) VALUES(?,?,?)", (device_key, label, utcnow()))
            c.commit()
            return jsonify({"ok": True, "device_key": device_key, "label": label})
    except Exception as e:
        print("device label error:", repr(e), flush=True)
        return jsonify({"ok": False, "error": "Unable to save device label"}), 500


@app.route("/device")
def device_view():
    key = request.args.get("key", "").strip()
    d = device_detail(key)
    if not d:
        return render_template_string(HTML, q="", result=None, inspect_html=f"<div class='card'><h2>Device not found</h2><p class='error'>No device exists for this identity.</p><p><a href='/'>Back to dashboard</a></p></div>", recent_html=recent_html(get_recent()["rows"]), clients_html=clients_html(get_clients()), version=APP_VERSION, refresh_seconds=UI_REFRESH_SECONDS, refresh_seconds_ms=UI_REFRESH_SECONDS * 1000, updated=utcnow(), stats=get_stats(), error=None, **_environment_render_context()), 404
    return render_template_string(HTML, q="", result=None, inspect_html=detail_html_device(d), recent_html=recent_html(get_recent()["rows"]), clients_html=clients_html(get_clients()), version=APP_VERSION, refresh_seconds=UI_REFRESH_SECONDS, refresh_seconds_ms=UI_REFRESH_SECONDS * 1000, updated=utcnow(), stats=get_stats(), error=None, **_environment_render_context())


@app.route("/ip")
def ip_view():
    addr = request.args.get("addr", "").strip()
    d = ip_detail(addr)
    if not d:
        return render_template_string(HTML, q="", result=None, inspect_html=f"<div class='card'><h2>IP not found</h2><p class='error'>No valid IP observation exists for this address.</p><p><a href='/'>Back to dashboard</a></p></div>", recent_html=recent_html(get_recent()["rows"]), clients_html=clients_html(get_clients()), version=APP_VERSION, refresh_seconds=UI_REFRESH_SECONDS, refresh_seconds_ms=UI_REFRESH_SECONDS * 1000, updated=utcnow(), stats=get_stats(), error=None, **_environment_render_context()), 404
    return render_template_string(HTML, q="", result=None, inspect_html=detail_html_ip(d), recent_html=recent_html(get_recent()["rows"]), clients_html=clients_html(get_clients()), version=APP_VERSION, refresh_seconds=UI_REFRESH_SECONDS, refresh_seconds_ms=UI_REFRESH_SECONDS * 1000, updated=utcnow(), stats=get_stats(), error=None, **_environment_render_context())


@app.route("/health")
def health():
    return jsonify({"ok": True, "version": APP_VERSION, "adguard": AGH_URL, "trackerdb": trackerdb_ready(), "poll_seconds": POLL_SECONDS, "ui_refresh_seconds": UI_REFRESH_SECONDS, "environment": RUNTIME_ENV})


@app.route("/api/inspectors")
def api_inspectors():
    """BEMO Core inspector registry, as the shell navigation consumes it."""
    status_counts = get_recent(page=1, page_size=10)["meta"]["status_counts"]
    dns_health = dns_inspector.health(
        blocked=status_counts.get("Blocked", 0),
        allowed=status_counts.get("Allowed", 0),
        unknown=status_counts.get("Unknown", 0),
    )
    inspectors = []
    for info in get_registry().list():
        payload = info.to_dict()
        payload["health"] = dns_health.to_dict() if info.slug == dns_inspector.SLUG else InspectorHealth(HealthLevel.UNKNOWN).to_dict()
        inspectors.append(payload)
    return jsonify({"platform_name": "Inspector BEMO", "inspectors": inspectors})


# === DEEP DEBUG BUNDLE PATCH 0.7.13-HF2 ===
# === DEEP DEBUG BUNDLE FIX PATCH 0.7.13-HF2.2 ===

def _deep_debug_read_text(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            return f.read()
    except Exception as e:
        return f'ERROR: {type(e).__name__}: {e}'


def _deep_debug_parse_kb_lines(text):
    out = {}
    for line in text.splitlines():
        if ':' not in line:
            continue
        key, rest = line.split(':', 1)
        parts = rest.strip().split()
        if not parts:
            continue
        value = parts[0]
        try:
            out[key] = int(value) * (1024 if len(parts) > 1 and parts[1].lower() == 'kb' else 1)
        except ValueError:
            out[key] = rest.strip()
    return out


def _deep_debug_proc_status():
    raw = _deep_debug_read_text('/proc/self/status')
    wanted = {
        'VmSize', 'VmPeak', 'VmRSS', 'VmHWM', 'RssAnon', 'RssFile', 'RssShmem',
        'VmData', 'VmStk', 'VmExe', 'VmLib', 'VmSwap', 'HugetlbPages'
    }
    parsed = _deep_debug_parse_kb_lines(raw)
    return {k: parsed.get(k) for k in sorted(wanted)}


def _deep_debug_smaps_rollup():
    path = '/proc/self/smaps_rollup'
    if not Path(path).exists():
        return {'available': False}
    parsed = _deep_debug_parse_kb_lines(_deep_debug_read_text(path))
    wanted = [
        'Rss', 'Pss', 'Pss_Anon', 'Pss_File', 'Pss_Shmem',
        'Private_Clean', 'Private_Dirty', 'Shared_Clean', 'Shared_Dirty',
        'Anonymous', 'AnonHugePages', 'Swap', 'SwapPss'
    ]
    return {'available': True, **{k: parsed.get(k) for k in wanted}}


def _deep_debug_top_mappings(limit=25):
    path = '/proc/self/smaps'
    if not Path(path).exists():
        return {'available': False, 'mappings': []}
    header_re = re.compile(r'^([0-9a-f]+-[0-9a-f]+)\s+\S+\s+\S+\s+\S+\s+\S+(?:\s+(.*))?$')
    rows = []
    current = None
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                m = header_re.match(line.rstrip('\n'))
                if m:
                    if current:
                        rows.append(current)
                    current = {
                        'address': m.group(1),
                        'path': (m.group(2) or '').strip() or '[anonymous]',
                        'rss': 0,
                        'pss': 0,
                        'private_dirty': 0,
                        'anonymous': 0,
                    }
                    continue
                if current is None or ':' not in line:
                    continue
                key, rest = line.split(':', 1)
                value = rest.strip().split()
                if not value:
                    continue
                try:
                    kb = int(value[0]) * 1024
                except ValueError:
                    continue
                if key == 'Rss':
                    current['rss'] = kb
                elif key == 'Pss':
                    current['pss'] = kb
                elif key == 'Private_Dirty':
                    current['private_dirty'] = kb
                elif key == 'Anonymous':
                    current['anonymous'] = kb
            if current:
                rows.append(current)
    except Exception as e:
        return {'available': True, 'error': f'{type(e).__name__}: {e}', 'mappings': []}
    rows.sort(key=lambda x: x['rss'], reverse=True)
    return {'available': True, 'mappings': rows[:max(1, int(limit))]}


def _deep_debug_cgroup_memory():
    candidates = [
        '/sys/fs/cgroup/memory.current',
        '/sys/fs/cgroup/memory.max',
    ]
    values = {}
    for path in candidates:
        if Path(path).exists():
            raw = _deep_debug_read_text(path).strip()
            key = Path(path).name
            try:
                values[key] = int(raw) if raw != 'max' else raw
            except ValueError:
                values[key] = raw
    for name in ('memory.stat', 'memory.events'):
        path = f'/sys/fs/cgroup/{name}'
        if Path(path).exists():
            parsed = {}
            for line in _deep_debug_read_text(path).splitlines():
                parts = line.split()
                if len(parts) == 2:
                    try:
                        parsed[parts[0]] = int(parts[1])
                    except ValueError:
                        parsed[parts[0]] = parts[1]
            values[name] = parsed
    return values


def _deep_debug_mallinfo2():
    try:
        import ctypes
        import ctypes.util
        libc_path = ctypes.util.find_library('c') or 'libc.so.6'
        libc = ctypes.CDLL(libc_path)
        if not hasattr(libc, 'mallinfo2'):
            return {'available': False, 'reason': 'mallinfo2 not exported by libc'}

        class MallInfo2(ctypes.Structure):
            _fields_ = [
                ('arena', ctypes.c_size_t),
                ('ordblks', ctypes.c_size_t),
                ('smblks', ctypes.c_size_t),
                ('hblks', ctypes.c_size_t),
                ('hblkhd', ctypes.c_size_t),
                ('usmblks', ctypes.c_size_t),
                ('fsmblks', ctypes.c_size_t),
                ('uordblks', ctypes.c_size_t),
                ('fordblks', ctypes.c_size_t),
                ('keepcost', ctypes.c_size_t),
            ]

        libc.mallinfo2.restype = MallInfo2
        info = libc.mallinfo2()
        return {'available': True, **{name: int(getattr(info, name)) for name, _ in MallInfo2._fields_}}
    except Exception as e:
        return {'available': False, 'error': f'{type(e).__name__}: {e}'}


def _deep_debug_threads():
    root = Path('/proc/self/task')
    rows = []
    try:
        for child in root.iterdir():
            tid = child.name
            comm_path = child / 'comm'
            stat_path = child / 'status'
            comm = _deep_debug_read_text(comm_path).strip()
            status = _deep_debug_read_text(stat_path)
            state = None
            voluntary = None
            nonvoluntary = None
            for line in status.splitlines():
                if line.startswith('State:'):
                    state = line.split(':', 1)[1].strip()
                elif line.startswith('voluntary_ctxt_switches:'):
                    voluntary = line.split(':', 1)[1].strip()
                elif line.startswith('nonvoluntary_ctxt_switches:'):
                    nonvoluntary = line.split(':', 1)[1].strip()
            rows.append({
                'tid': tid,
                'name': comm,
                'state': state,
                'voluntary_ctxt_switches': voluntary,
                'nonvoluntary_ctxt_switches': nonvoluntary,
            })
    except Exception as e:
        return {'error': f'{type(e).__name__}: {e}', 'threads': []}
    rows.sort(key=lambda x: int(x['tid']) if x['tid'].isdigit() else 0)
    return {'count': len(rows), 'threads': rows}


def _deep_debug_fds():
    root = Path('/proc/self/fd')
    rows = []
    counts = {}
    try:
        for child in sorted(root.iterdir(), key=lambda p: p.name):
            try:
                target = os.readlink(child)
            except Exception as e:
                target = f'<unreadable: {type(e).__name__}>'
            if target.startswith('socket:['):
                kind = 'socket'
            elif target.startswith('pipe:['):
                kind = 'pipe'
            elif target.startswith('anon_inode:'):
                kind = 'anon_inode'
            elif target.startswith('/'):
                kind = 'file'
            else:
                kind = 'other'
            counts[kind] = counts.get(kind, 0) + 1
            rows.append({'fd': child.name, 'kind': kind, 'target': target})
    except Exception as e:
        return {'error': f'{type(e).__name__}: {e}', 'counts': counts, 'entries': rows}
    return {'count': len(rows), 'counts': counts, 'entries': rows[:200]}


def _deep_debug_sqlite():
    result = {}
    try:
        with db_lock, closing(sqlite3.connect(DB_PATH)) as c:
            for pragma in (
                'journal_mode', 'journal_size_limit', 'page_count', 'page_size',
                'freelist_count', 'cache_size', 'cache_spill', 'temp_store',
                'mmap_size', 'synchronous', 'locking_mode'
            ):
                try:
                    row = c.execute(f'PRAGMA {pragma}').fetchone()
                    result[pragma] = row[0] if row else None
                except Exception as e:
                    result[pragma] = f'{type(e).__name__}: {e}'
    except Exception as e:
        result['error'] = f'{type(e).__name__}: {e}'
    return result


def _deep_debug_http_pools():
    out = []
    try:
        adapters = getattr(session, 'adapters', {})
        for prefix, adapter in adapters.items():
            row = {'prefix': prefix, 'adapter_type': type(adapter).__name__}
            poolmanager = getattr(adapter, 'poolmanager', None)
            if poolmanager is not None:
                row['poolmanager_type'] = type(poolmanager).__name__
                pools = getattr(poolmanager, 'pools', None)
                try:
                    row['pool_count'] = len(pools) if pools is not None else None
                except Exception:
                    row['pool_count'] = None
                row['num_pools'] = getattr(poolmanager, 'num_pools', None)
                row['maxsize'] = getattr(poolmanager, 'connection_pool_kw', {}).get('maxsize') if hasattr(poolmanager, 'connection_pool_kw') else None
            out.append(row)
    except Exception as e:
        return {'error': f'{type(e).__name__}: {e}', 'adapters': []}
    return {'adapters': out}


def _deep_debug_python_objects():
    try:
        import gc
        from collections import Counter

        counts = Counter()
        object_count = 0
        for obj in gc.get_objects():
            object_count += 1
            try:
                typ = type(obj)
                module = getattr(typ, '__module__', None) or '<unknown>'
                qualname = getattr(typ, '__qualname__', None) or getattr(typ, '__name__', None) or repr(typ)
                counts[f'{module}.{qualname}'] += 1
            except Exception:
                counts['<unclassifiable>'] += 1

        top = [
            {'type': name, 'count': count}
            for name, count in counts.most_common(50)
        ]
        return {'gc_object_count': object_count, 'top_types': top}
    except Exception as e:
        return {'error': f'{type(e).__name__}: {e}'}


def _deep_debug_tracemalloc():
    try:
        import tracemalloc
        if not tracemalloc.is_tracing():
            return {'available': False, 'reason': 'tracemalloc not active'}
        current, peak = tracemalloc.get_traced_memory()
        snap = tracemalloc.take_snapshot()
        stats = snap.statistics('traceback')[:40]
        top = []
        for stat in stats:
            top.append({
                'size_bytes': stat.size,
                'count': stat.count,
                'traceback': [str(frame) for frame in stat.traceback.format()],
            })
        return {'available': True, 'current_bytes': current, 'peak_bytes': peak, 'top_tracebacks': top}
    except Exception as e:
        return {'available': False, 'error': f'{type(e).__name__}: {e}'}


def _deep_debug_limits():
    try:
        import resource
        names = {
            'RLIMIT_AS': getattr(resource, 'RLIMIT_AS', None),
            'RLIMIT_DATA': getattr(resource, 'RLIMIT_DATA', None),
            'RLIMIT_STACK': getattr(resource, 'RLIMIT_STACK', None),
        }
        out = {}
        for name, ident in names.items():
            if ident is None:
                continue
            soft, hard = resource.getrlimit(ident)
            out[name] = {'soft': soft, 'hard': hard}
        return out
    except Exception as e:
        return {'error': f'{type(e).__name__}: {e}'}


# === DEBUG BUNDLE RESILIENCE PATCH 0.7.13-HF2.1 ===

def _deep_debug_safe_call(name, fn):
    try:
        return {'ok': True, 'data': fn()}
    except BaseException as e:
        import traceback
        return {
            'ok': False,
            'error': f'{type(e).__name__}: {e}',
            'traceback': traceback.format_exc(),
        }


def _deep_debug_memory_snapshot_safe():
    collectors = [
        ('proc_status', _deep_debug_proc_status),
        ('smaps_rollup', _deep_debug_smaps_rollup),
        ('top_memory_mappings', _deep_debug_top_mappings),
        ('cgroup_memory', _deep_debug_cgroup_memory),
        ('glibc_mallinfo2', _deep_debug_mallinfo2),
        ('threads', _deep_debug_threads),
        ('file_descriptors', _deep_debug_fds),
        ('sqlite', _deep_debug_sqlite),
        ('http_pools', _deep_debug_http_pools),
        ('python_object_types', _deep_debug_python_objects),
        ('tracemalloc', _deep_debug_tracemalloc),
        ('resource_limits', _deep_debug_limits),
    ]
    return {name: _deep_debug_safe_call(name, fn) for name, fn in collectors}


def _deep_debug_memory_snapshot():
    return {
        'proc_status_bytes': _deep_debug_proc_status(),
        'smaps_rollup_bytes': _deep_debug_smaps_rollup(),
        'top_memory_mappings': _deep_debug_top_mappings(),
        'cgroup_memory': _deep_debug_cgroup_memory(),
        'glibc_mallinfo2': _deep_debug_mallinfo2(),
        'threads': _deep_debug_threads(),
        'file_descriptors': _deep_debug_fds(),
        'sqlite': _deep_debug_sqlite(),
        'http_pools': _deep_debug_http_pools(),
        'python_object_types': _deep_debug_python_objects(),
        'tracemalloc': _deep_debug_tracemalloc(),
        'resource_limits': _deep_debug_limits(),
    }



def _observability_uptime_seconds():
    return max(0.0, time.monotonic() - OBSERVABILITY_START_MONOTONIC)


def _observability_uptime_human(seconds):
    total = max(0, int(seconds))
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    if minutes or hours or days:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")
    return " ".join(parts)


def _observability_rss_mb():
    try:
        with open('/proc/self/status', 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                if line.startswith('VmRSS:'):
                    return round(float(line.split()[1]) / 1024.0, 1)
    except Exception:
        pass
    try:
        import resource
        return round(float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) / 1024.0, 1)
    except Exception:
        return None


def _observability_db_counts():
    tables = [
        'domains','devices','device_ips','device_labels','processed_queries',
        'adguard_status_cache','enrichment_attempts','ip_ping_status',
        'rdap_cache','netify_cache','dns_records_cache','mac_vendor_cache',
        'hostname_cache','client_cache'
    ]
    counts = {}
    try:
        with db_lock, closing(sqlite3.connect(DB_PATH)) as c:
            for table in tables:
                try:
                    counts[table] = int(c.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0])
                except Exception:
                    counts[table] = None
    except Exception as e:
        counts['_error'] = str(e)
    return counts


def _observability_payload():
    uptime = _observability_uptime_seconds()
    try:
        db_size = os.path.getsize(DB_PATH)
    except OSError:
        db_size = None
    return {
        'version': APP_VERSION,
        'environment': RUNTIME_ENV,
        'started_at': OBSERVABILITY_START_AT,
        'uptime_seconds': round(uptime, 1),
        'uptime_human': _observability_uptime_human(uptime),
        'ram_mb': _observability_rss_mb(),
        'pid': os.getpid(),
        'thread_count': threading.active_count(),
        'python': platform.python_version(),
        'platform': platform.platform(),
        'db_size_bytes': db_size,
        'db_counts': _observability_db_counts(),
    }


def _memory_diagnostics_container_summary(value):
    """Return cheap, shallow diagnostics for long-lived module globals."""
    try:
        size = sys.getsizeof(value)
    except Exception:
        size = None
    info = {'type': type(value).__name__, 'size_bytes': size}
    try:
        if isinstance(value, dict):
            info['length'] = len(value)
        elif isinstance(value, (list, tuple, set, frozenset)):
            info['length'] = len(value)
        elif hasattr(value, 'qsize') and callable(value.qsize):
            info['length'] = int(value.qsize())
        elif hasattr(value, '__len__'):
            info['length'] = len(value)
    except Exception:
        pass
    return info


def _memory_diagnostics():
    if not MEMORY_DIAGNOSTICS_ENABLED or not tracemalloc.is_tracing():
        return {'enabled': False}

    current, peak = tracemalloc.get_traced_memory()
    result = {
        'enabled': True,
        'tracemalloc_current_mb': round(current / (1024 * 1024), 2),
        'tracemalloc_peak_mb': round(peak / (1024 * 1024), 2),
        'gc_counts': list(gc.get_count()),
        'gc_stats': gc.get_stats(),
    }

    try:
        objects = gc.get_objects()
        result['gc_object_count'] = len(objects)
    except Exception:
        result['gc_object_count'] = None

    # Capture only a compact top-of-process allocation view. The snapshot is
    # immediately discarded, so diagnostics do not build a historical leak log.
    try:
        snapshot = tracemalloc.take_snapshot()
        snapshot = snapshot.filter_traces((
            tracemalloc.Filter(False, '<frozen importlib._bootstrap>'),
            tracemalloc.Filter(False, '<unknown>'),
        ))
        stats = snapshot.statistics('lineno')[:25]
        top = []
        for stat in stats:
            frame = stat.traceback[0]
            top.append({
                'file': frame.filename,
                'line': frame.lineno,
                'size_mb': round(stat.size / (1024 * 1024), 3),
                'count': stat.count,
                'text': frame.name if hasattr(frame, 'name') else '',
            })
        result['top_allocations'] = top
    except Exception as e:
        result['top_allocations_error'] = str(e)

    # Surface suspiciously long-lived module-level containers without walking
    # their contents. This is intentionally shallow and only runs on demand.
    try:
        module_globals = {}
        for name, value in globals().items():
            if name.startswith('_'):
                continue
            if isinstance(value, (dict, list, tuple, set, frozenset)) or hasattr(value, 'qsize'):
                try:
                    info = _memory_diagnostics_container_summary(value)
                    length = info.get('length')
                    size = info.get('size_bytes')
                    # Ignore tiny/static containers unless they are surprisingly large.
                    if (isinstance(length, int) and length >= 10) or (isinstance(size, int) and size >= 65536):
                        module_globals[name] = info
                except Exception:
                    continue
        result['large_globals'] = dict(sorted(module_globals.items(), key=lambda item: (item[1].get('size_bytes') or 0), reverse=True)[:50])
    except Exception as e:
        result['large_globals_error'] = str(e)

    try:
        result['fd_count'] = len(os.listdir('/proc/self/fd'))
    except Exception:
        result['fd_count'] = None

    return result


# Extend the 0.7.12 observability payload without changing its existing API.
_original_observability_payload = _observability_payload

def _observability_payload():
    payload = _original_observability_payload()
    payload['memory_diagnostics'] = _memory_diagnostics()
    return payload


@app.route('/api/observability')
def api_observability():
    try:
        return jsonify(_observability_payload())
    except Exception as e:
        print('observability endpoint error:', repr(e), flush=True)
        return jsonify({
            'version': APP_VERSION,
            'environment': RUNTIME_ENV,
            'uptime_seconds': _observability_uptime_seconds(),
            'ram_mb': None,
        }), 200


def _observability_safe_config():
    names = [
        'POLL_SECONDS','UI_REFRESH_SECONDS','TRACKERDB_REFRESH_HOURS',
        'TRACKERDB_DOWNLOAD_CHUNK_SIZE','MACVENDOR_CACHE_HOURS',
        'HOSTNAME_CACHE_HOURS','NETIFY_CACHE_HOURS','RDAP_CACHE_HOURS',
        'DNS_RECORDS_CACHE_HOURS','ENRICHMENT_RETRY_HOURS',
        'ENRICHMENT_DELAY_SECONDS','DEVICE_IP_RETENTION_HOURS',
        'DEVICE_IP_CLEANUP_INTERVAL_MINUTES','IP_PING_INTERVAL_HOURS',
        'IP_PING_INITIAL_DELAY_SECONDS','IP_PING_TIMEOUT_SECONDS'
    ]
    safe = {name: globals().get(name) for name in names}
    safe['adguard_configured'] = bool(AGH_URL)
    safe['adguard_username_configured'] = bool(AGH_USER)
    safe['adguard_password_configured'] = bool(AGH_PASS)
    return safe


@app.route('/debug/bundle')
def debug_bundle():
    try:
        runtime = _observability_payload()
        deep_memory = _deep_debug_memory_snapshot_safe()
        bundle = io.BytesIO()
        with zipfile.ZipFile(bundle, 'w', compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr(
                'manifest.txt',
                f'DNS Inspector {APP_VERSION}\nGenerated: {datetime.now(timezone.utc).isoformat()}\nPurpose: safe deep memory diagnostic snapshot\nPatch: 0.7.13-hotfix.2.1\n'
            )
            z.writestr('runtime.json', json.dumps(runtime, indent=2, ensure_ascii=False, sort_keys=True, default=str))
            z.writestr('memory-deep.json', json.dumps(deep_memory, indent=2, ensure_ascii=False, sort_keys=True, default=str))
            z.writestr('config-safe.json', json.dumps(_observability_safe_config(), indent=2, ensure_ascii=False, sort_keys=True, default=str))
            z.writestr(
                'logs-note.txt',
                'DNS Inspector does not persist historical stdout/stderr logs. Retrieve container/application logs from Docker or TrueNAS when a historical log stream is needed.\n'
            )
            try:
                usage = shutil.disk_usage(os.path.dirname(DB_PATH) or '/')
                z.writestr(
                    'storage.json',
                    json.dumps({
                        'data_path': os.path.dirname(DB_PATH) or '/',
                        'total_bytes': usage.total,
                        'used_bytes': usage.used,
                        'free_bytes': usage.free,
                    }, indent=2)
                )
            except Exception as e:
                z.writestr('storage.json', json.dumps({'error': str(e)}, indent=2))
        bundle.seek(0)
        filename = f'dns-inspector-debug-{APP_VERSION}-{datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")}.zip'
        return send_file(bundle, mimetype='application/zip', as_attachment=True, download_name=filename)
    except Exception as e:
        print('debug bundle error:', repr(e), flush=True)
        return jsonify({'ok': False, 'error': 'Could not generate debug bundle'}), 500


# === APPLICATION ENTRY POINT (0.8.0) ===
# Startup used to live inline under `if __name__ == "__main__"`, which meant the
# only way to exercise it was to launch the real server. The steps below are the
# same steps, in the same order, as 0.7.14 -- they are now named so that tests and
# future module boundaries have something explicit to call.

#: Long-lived background threads, in the order 0.7.14 started them.
BACKGROUND_WORKERS = (
    ("agh-ingest", worker),
    ("enrichment-queue", _enrichment_worker),
    ("device-ip-cleanup", _device_ip_cleanup_worker),
    ("ip-ping", _ip_ping_worker),
)


def start_background_workers():
    """Start every long-lived background thread and return the started threads."""
    threads = []
    for name, target in BACKGROUND_WORKERS:
        thread = threading.Thread(target=target, daemon=True, name=name)
        thread.start()
        threads.append(thread)
    return threads


def serve():
    """Run the built-in Flask server. Blocks until the process is stopped."""
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))


def main():
    """The single startup path for DNS Inspector."""
    init_db()
    _prune_stale_device_ips()
    start_background_workers()
    serve()


if __name__ == "__main__":
    main()
