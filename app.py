import array
import bisect
import csv
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
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from urllib.parse import quote

import requests
from flask import Flask, jsonify, render_template_string, request, send_file

from pathlib import Path
from contextlib import closing
from scripts import geoip_updater
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
try:
    with open(os.path.join(BASE_DIR, "VERSION"), "r", encoding="utf-8") as f:
        APP_VERSION = f.read().strip()
except Exception:
    APP_VERSION = os.getenv("APP_VERSION", "dev")


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

# GeoIP is always a local/offline lookup against an operator-supplied CIDR
# database (see docs/GEOIP.md) -- never a per-query network request. The path
# is configurable so a deployment can point at its own converted database;
# when no file exists there, the destination map honestly reports 0% geolocated
# instead of inventing locations (see `NullGeoIPProvider`).
#
# 0.8.5.4 (Issue #39): this default used to be `BASE_DIR/data/...`
# (`/app/data/...` inside the container), while every other persistent path
# (`DB_PATH`, `NEIGHBORS_PATH`, `TRACKERDB_PATH` above) defaults under `/data`
# -- the same directory the Dockerfile creates and the README's documented
# `-v /path/to/data:/data` single-volume setup mounts. `/app/data` is never
# created by the image and isn't part of that documented volume, so an
# operator who followed the README and dropped the converted CSV into their
# mounted `/data` never had it picked up. The default now matches every other
# path so the documented single-volume setup actually populates the map.
GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "/data/geoip_country_ranges.csv")
GEOIP_CACHE_MAX_ENTRIES = max(256, int(os.getenv("GEOIP_CACHE_MAX_ENTRIES", "8192")))
GEOIP_MAP_CACHE_SECONDS = max(5, int(os.getenv("GEOIP_MAP_CACHE_SECONDS", "30")))
GEOIP_MAP_DOMAIN_LIMIT = max(50, int(os.getenv("GEOIP_MAP_DOMAIN_LIMIT", "1500")))
# Upper bound on distinct observed destination IPs retained per domain (see
# `domain_destination_ips` / `_record_domain_destination_ips()`) -- keeps a
# single high-rotation multi-CDN domain from growing the table unboundedly.
GEOIP_DESTINATION_IPS_PER_DOMAIN_LIMIT = max(4, int(os.getenv("GEOIP_DESTINATION_IPS_PER_DOMAIN_LIMIT", "32")))

# Optional coordinate/city-level GeoIP provider (Issue #37 / 0.8.6). Entirely
# separate from and additive to the country provider above -- when unset (the
# default), Destinations mode honestly reports coordinate data as unavailable
# instead of inventing a city/IP location from a country centroid. See
# docs/GEOIP.md for the supported schema (DB-IP City Lite, converted) and its
# CC BY 4.0 attribution requirement. Default corrected to `/data` in 0.8.5.4
# for the same reason as `GEOIP_DB_PATH` above.
GEOIP_CITY_DB_PATH = os.getenv("GEOIP_CITY_DB_PATH", "/data/geoip_city_ranges.csv")
GEOIP_CITY_CACHE_MAX_ENTRIES = max(256, int(os.getenv("GEOIP_CITY_CACHE_MAX_ENTRIES", "8192")))
# Upper bound on individual coordinate points returned to the browser per map
# payload -- a rendering/payload-size bound only; country aggregation and the
# `coverage` figures above are computed over every observed destination
# regardless of this cap (see geoip_map_payload()).
GEOIP_MAP_DESTINATION_POINTS_LIMIT = max(50, int(os.getenv("GEOIP_MAP_DESTINATION_POINTS_LIMIT", "600")))

# Issue #50 / 0.8.5.10: the CSV parse phase inside `CsvRangeGeoIPProvider`/
# `CsvCityGeoIPProvider` (below) is the actual CPU/disk-heavy step in both the
# deferred initial load (`_geoip_initial_load_worker()`) and a completed
# auto-update's in-process reload (`_reload_geoip_providers()`) -- a real
# DB-IP City Lite export is several million rows. Parsing it in one unbroken
# loop can peg a CPU core for the whole load, which is noticeable on a modest
# host even off the request path. Bandwidth is deliberately not throttled
# here (the download itself is a separate, already-isolated subprocess step,
# see GEOIP_AUTO_UPDATE_WATCHDOG_SECONDS above); instead `_iter_csv_rows_throttled()`
# below sleeps briefly after every bounded chunk of parsed rows so the rest
# of the process gets scheduled in between chunks.
GEOIP_LOAD_CHUNK_ROWS = max(1, int(os.getenv("GEOIP_LOAD_CHUNK_ROWS", "5000")))
GEOIP_LOAD_YIELD_SECONDS = max(0.0, float(os.getenv("GEOIP_LOAD_YIELD_SECONDS", "0.01")))

# Automatic DB-IP Lite updates (Issue #42 / 0.8.5.5): a background worker
# checks for a newer monthly DB-IP Country/City Lite release on this cadence
# and, if found, downloads/validates/converts it via `scripts/geoip_updater.py`
# (which reuses the same converters `docs/GEOIP.md`'s manual setup already
# used) and atomically replaces the file(s) above -- see `geoip_auto_update_worker()`
# and `_reload_geoip_providers()`. `GEOIP_UPDATE_*` env vars are read once,
# together, by `geoip_updater.build_config_from_env()` so the CLI and this
# background worker can never drift out of sync with each other.
GEOIP_AUTO_UPDATE = geoip_updater.is_auto_update_enabled()
_GEOIP_UPDATE_CONFIG = geoip_updater.build_config_from_env()
# Issue #44 / 0.8.5.7: the previous 0.8.5.5/0.8.5.6 worker woke up every
# GEOIP_AUTO_UPDATE_POLL_SECONDS *and ran its first check/update pass
# immediately at thread startup* -- on a fresh deployment with no state
# file, that meant a multi-hundred-megabyte DB-IP Lite Country/City Lite
# download and Python CSV conversion could start competing with the
# application for network/CPU/disk before it ever finished becoming
# healthy. The worker now never runs a pass at startup: it only wakes at
# this daily local-time window (`geoip_updater.next_scheduled_run()`), and
# `_is_check_due()`/GEOIP_UPDATE_INTERVAL_DAYS still independently decides
# whether that wake actually turns into a real network check per target.
GEOIP_AUTO_UPDATE_HOUR = max(0, min(23, int(os.getenv("GEOIP_AUTO_UPDATE_HOUR", "3"))))
GEOIP_AUTO_UPDATE_MINUTE = max(0, min(59, int(os.getenv("GEOIP_AUTO_UPDATE_MINUTE", "0"))))
GEOIP_AUTO_UPDATE_TIMEZONE_NAME = os.getenv("GEOIP_AUTO_UPDATE_TIMEZONE", "UTC")
# Issue #43: a real-world run was observed with `in_progress=true` and both
# targets' `last_checked_at=null` for several minutes with no success/error.
# `geoip_updater.run_update()` now persists state incrementally per target
# (see its own change log), but this is a second, independent safety net in
# `_run_geoip_update_pass()` -- `run_update()` is bounded by its own
# per-request connect/read timeouts, yet nothing previously bounded the
# *whole* check/download/convert pass, so a run stuck on something those
# per-request timeouts don't cover (e.g. a hung DNS resolution, an
# unexpectedly slow decompress/convert of a huge file) could hold
# `_geoip_update_in_progress` at `true` indefinitely. Issue #44 / 0.8.5.7
# additionally moved the actual check/update pass into a *subprocess*
# (`_geoip_updater_cli_command()`), so once this many seconds elapse the
# parent now actually terminates the hung child (`_terminate_geoip_subprocess()`)
# instead of merely abandoning an in-process daemon thread it had no way to
# stop -- either way, an explicit timeout error is recorded and the flag is
# cleared so the *next* scheduled window can retry.
GEOIP_AUTO_UPDATE_WATCHDOG_SECONDS = max(60, int(os.getenv("GEOIP_AUTO_UPDATE_WATCHDOG_SECONDS", "1800")))

app = Flask(__name__)
db_lock = threading.Lock()
session = requests.Session()
last_ingest_at = 0.0
neighbors_lock = threading.Lock()
neighbors_cache = {}
neighbors_mtime = None
enrichment_lock = threading.Lock()
enrichment_refreshing = set()

# In-memory only (deliberately not persisted to the updater state file, so a
# crash mid-update can never leave a stuck "in progress" flag on disk) --
# `/api/observability` reports this alongside the durable per-target state
# `geoip_updater.load_state()` tracks (last check, current release, last
# success/error). See `geoip_auto_update_worker()`.
_geoip_update_lock = threading.Lock()
_geoip_update_in_progress = False
# In-memory only, set by `geoip_auto_update_worker()` each time it computes
# the next daily window -- lets `/api/observability` distinguish "scheduled,
# waiting for its window" from "in_progress" (Issue #44).
_geoip_next_scheduled_run_at = None

# Background AdGuard status refreshes are deliberately bounded.
_status_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="agh-status")
_status_guard = threading.Lock()
_status_inflight = set()
_status_slots = threading.BoundedSemaphore(20)

MAC_RE = re.compile(r"^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.I)
IP_RE = re.compile(r"^[0-9a-f:.]+$")

HTML = """
<!doctype html><html><head><meta charset="utf-8"><link rel="icon" type="image/svg+xml" href="{{favicon_path}}"><title>{{page_title}}</title>
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
.analytics-hero{display:grid;grid-template-columns:1.3fr 1fr;gap:14px;align-items:stretch}
.live-card{position:relative;overflow:hidden;border-color:#1f6feb55}
.live-card::before{content:'';position:absolute;inset:0;background:radial-gradient(600px 200px at 0% 0%,rgba(57,197,207,.10),transparent 60%);pointer-events:none}
.live-title{display:flex;align-items:center;gap:8px;font-weight:750;color:#c9d1d9}
.live-dot{width:9px;height:9px;border-radius:50%;background:var(--sem-live);box-shadow:0 0 0 3px rgba(57,197,207,.18);animation:dnsInspectorPulse 1.4s ease-in-out infinite}
.live-rate{font-size:2.4rem;font-weight:800;letter-spacing:-.02em;margin:8px 0 2px;font-variant-numeric:tabular-nums;position:relative}
.live-rate small{font-size:.4em;color:#8b949e;font-weight:700;margin-left:6px}
.live-sparkline-wrap{margin-top:8px;position:relative}
.history-svg{width:100%;height:120px;display:block}
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
.settings-kv{display:grid;grid-template-columns:auto 1fr;gap:6px 14px;font-size:.84rem}
.settings-kv b{color:var(--text-secondary);font-weight:600}
.settings-kv span{font-family:var(--font-mono)}
.settings-foot{display:flex;justify-content:flex-end;gap:8px;padding:12px 20px;border-top:1px solid var(--border)}
.settings-restart-block{margin-top:16px;padding-top:14px;border-top:1px solid var(--border);display:flex;flex-direction:column;gap:8px;align-items:flex-start}
#system-restart-btn{border-color:var(--sem-crit);color:var(--sem-crit);background:transparent}
#system-restart-btn:hover{background:var(--sem-crit);color:#fff}
#system-restart-btn.confirming{background:var(--sem-crit);color:#fff}
#system-restart-btn:disabled{opacity:.6;cursor:wait;background:transparent;color:var(--sem-crit)}
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
   Dark Accent -- color ramp/palette only). Every combination renders the
   same offline dot-matrix world (see mapWorldDots() below, sampled from the
   bundled WORLD_LAND_D vector rings) instead of one flat filled silhouette
   -- there is no bundled satellite/street raster asset, so "Satellite"/
   "Real Map" are stylistic approximations rather than literal imagery,
   which keeps the map fully offline/self-contained. Bubble/particle size
   and position are entirely data-driven and deterministic (seeded, never
   Math.random()); only markers at/above a high intensity ratio pulse, and
   only when motion isn't reduced. ---- */
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
.destination-map-svg{width:100%;height:auto;aspect-ratio:2/1;background:radial-gradient(ellipse at 50% 40%,var(--map-bg-a),var(--map-bg-b));box-shadow:var(--map-vignette);border:1px solid var(--map-border);border-radius:var(--radius-md);cursor:grab}
.destination-map-svg.map-dragging{cursor:grabbing}
html:not([data-motion="reduced"]) .destination-map-svg{transition:background .2s ease}
.map-world-dot{fill:var(--map-dot);opacity:var(--map-dot-opacity)}
.map-world-dot-active{opacity:.95}
.map-graticule .map-grid-line{stroke:var(--map-grid);stroke-width:1;opacity:var(--map-grid-opacity)}
.map-graticule .map-grid-equator{opacity:calc(var(--map-grid-opacity) * 1.6);stroke:var(--map-grid-strong)}
.map-status-banner{position:absolute;top:10px;left:10px;right:10px;margin:0 auto;padding:8px 12px;background:var(--map-banner-bg);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-secondary);font-size:.8rem;text-align:center;pointer-events:none;box-shadow:var(--shadow-sm,0 1px 4px rgba(0,0,0,.15))}
.map-status-banner .map-status-action{margin-top:6px;pointer-events:auto}
.map-entity{cursor:pointer}
.map-entity:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.map-hit-area{fill:transparent;pointer-events:all}
/* Issue #56: marker fill/stroke is set inline per-entity from
   mapThemeColor() (the same relative-to-max ratio that already sizes the
   marker) rather than a single flat accent -- traffic intensity is meant to
   be readable from color alone, independent of the chosen basemap/theme. */
.map-bubble{fill-opacity:.85;stroke-width:1;filter:var(--map-point-glow);transition:fill-opacity .3s ease,stroke-width .3s ease,r .3s ease}
.map-entity:hover .map-bubble,.map-bubble-selected{fill-opacity:1;stroke-width:2}
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

/* ---- Dashboard Builder (0.8.5): customizable Analytics widget grid ---- */
.dash-toolbar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:14px 0}
.dash-toolbar .settings-select{padding:7px 10px;font-size:.8rem}
.dash-customize-btn{border-radius:var(--radius-pill)}
.dash-customize-btn.active{background:var(--accent-soft);border-color:var(--accent);color:var(--text-primary)}
.dash-hint{color:var(--text-tertiary);font-size:.78rem}
.dash-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;align-items:start;grid-auto-flow:dense}
.dash-widget{grid-column:span 4;min-width:0;min-height:0}
.dash-widget .card{min-height:120px}
.dash-widget[data-w="1"]{grid-column:span 1}
.dash-widget[data-w="2"]{grid-column:span 2}
.dash-widget[data-w="3"]{grid-column:span 3}
.dash-widget[data-w="4"]{grid-column:span 4}
.dash-widget[data-hidden="1"]{display:none}
.dash-grid.dash-customizing .dash-widget[data-hidden="1"]{display:block;opacity:.5}
.dash-grid.dash-customizing .dash-widget{outline:1px dashed var(--border-strong);outline-offset:3px;border-radius:var(--radius-lg)}
.dash-grid.dash-customizing .dash-widget[data-dragging="1"]{opacity:.4}
.dash-widget-head{display:none;align-items:center;gap:6px;margin:0 0 12px;padding:6px 8px;background:var(--surface-2);border:1px solid var(--border);border-radius:var(--radius-sm)}
.dash-grid.dash-customizing .dash-widget-head{display:flex}
.dash-widget-head .dash-drag-handle{color:var(--text-tertiary);flex:0 0 auto;display:flex;cursor:grab;padding:2px 4px}
.dash-widget-head .dash-widget-title{flex:1;font-size:.74rem;font-weight:700;color:var(--text-secondary);text-transform:uppercase;letter-spacing:.04em;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dash-widget-head button{padding:4px 8px;font-size:.72rem;border-radius:var(--radius-sm);line-height:1.2}
.dash-widget[data-h="compact"] .metric-visual{--metric-h:78px}
.dash-widget[data-h="tall"] .metric-visual{--metric-h:196px}
.dash-widget[data-h="compact"] .dash-scroll,.dash-widget[data-h="compact"] .chart-list{max-height:120px;overflow:auto}
.dash-widget[data-h="tall"] .dash-scroll,.dash-widget[data-h="tall"] .chart-list{max-height:440px;overflow:auto}
/* 0.8.5.6: a real 4-column layout grid (1-4 column span per widget) instead
   of a binary half/full choice; `grid-auto-flow:dense` back-fills gaps left
   by mixed-width widgets instead of leaving holes. Two intermediate
   breakpoints keep the same span *proportions* readable as the viewport
   narrows, rather than only collapsing straight to one column. */
@media(max-width:1300px){
  .dash-grid{grid-template-columns:repeat(2,minmax(0,1fr))}
  .dash-widget[data-w="1"],.dash-widget[data-w="2"]{grid-column:span 1}
  .dash-widget[data-w="3"],.dash-widget[data-w="4"]{grid-column:span 2}
}
@media(max-width:900px){.dash-grid{grid-template-columns:1fr}.dash-widget{grid-column:1/-1!important}}
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
      <button type="button" class="debug-button" id="settings-open-btn" aria-haspopup="dialog" aria-controls="settings-dialog"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 15.5a3.5 3.5 0 100-7 3.5 3.5 0 000 7z"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 11-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 11-4 0v-.09a1.65 1.65 0 00-1-1.51 1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 11-2.83-2.83l.06-.06a1.65 1.65 0 00.33-1.82 1.65 1.65 0 00-1.51-1H3a2 2 0 110-4h.09a1.65 1.65 0 001.51-1 1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 112.83-2.83l.06.06a1.65 1.65 0 001.82.33H9a1.65 1.65 0 001-1.51V3a2 2 0 114 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 112.83 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9a1.65 1.65 0 001.51 1H21a2 2 0 110 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg>Settings</button>
      <button type="button" class="debug-button" onclick="window.location='/debug/bundle'">Generate Debug Bundle</button>
    </div>
    <p class="muted shell-meta">Watching AdGuard activity · <span class="live">● Live</span> · refresh every {{refresh_seconds}}s · updated <span id="last-update-time" class="updated-time"></span> · <span id="last-update-date" class="updated-date"></span></p>
  </div>
</header>
<dialog id="settings-dialog" class="settings-dialog" aria-label="Inspector BEMO settings">
  <div class="settings-head"><h2>Settings</h2><button type="button" class="settings-close" id="settings-close-btn" aria-label="Close settings">✕</button></div>
  <div class="settings-body">
    <nav class="settings-nav" role="tablist" aria-label="Settings sections">
      <button type="button" class="settings-nav-btn active" data-settings-tab="appearance" role="tab">Appearance</button>
      <button type="button" class="settings-nav-btn" data-settings-tab="dashboard" role="tab">Dashboard</button>
      <button type="button" class="settings-nav-btn" data-settings-tab="monitoring" role="tab">Monitoring</button>
      <button type="button" class="settings-nav-btn" data-settings-tab="diagnostics" role="tab">Diagnostics</button>
      <button type="button" class="settings-nav-btn" data-settings-tab="system" role="tab">System</button>
      <button type="button" class="settings-nav-btn" data-settings-tab="about" role="tab">About</button>
    </nav>
    <div class="settings-panels">
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
      <section class="settings-section" data-settings-panel="diagnostics">
        <h3>Diagnostics</h3>
        <div class="settings-kv" id="diagnostics-kv"><b>Loading…</b><span></span></div>
        <div class="settings-row" style="border-bottom:0;padding-top:14px"><div class="settings-row-label"><b>Debug bundle</b><small>A safe diagnostic snapshot for troubleshooting</small></div>
          <div class="settings-control"><button type="button" onclick="window.location='/debug/bundle'">Generate Debug Bundle</button></div>
        </div>
      </section>
      <section class="settings-section" data-settings-panel="system">
        <h3>System</h3>
        <div class="settings-kv" id="system-kv"><b>Loading…</b><span></span></div>
        <div class="settings-restart-block">
          <button type="button" id="system-restart-btn">Restart DNS Inspector</button>
          <span class="settings-restart-note" id="system-restart-note">Restarts the running application/container. In-progress requests are dropped; persisted data in <code>/data</code> is unaffected.</span>
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
        </div>
      </section>
    </div>
  </div>
  <div class="settings-foot"><button type="button" id="settings-reset-btn">Reset to defaults</button><button type="button" id="settings-done-btn">Done</button></div>
</dialog>
<form class="toolbar" action="/search"><input name="q" placeholder="hostname..." value="{{q}}"><button type="submit">Inspect</button><button type="button" onclick="window.location='/'">Reset</button></form>
<nav class="tabs" role="tablist" aria-label="DNS Inspector sections">
  <button class="tab-btn active" data-tab="overview" role="tab"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/></svg>Overview</button>
  <button class="tab-btn" data-tab="devices" role="tab"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M9 20h6M12 16v4"/></svg>Devices</button>
  <button class="tab-btn" data-tab="analytics" role="tab"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 19V9M11 19V5M18 19v-7"/></svg>Analytics</button>
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
const PREF_KEY = 'dnsInspectorPrefs';
const ACCENT_PRESETS = {teal:'#2dd4c8', blue:'#58a6ff', violet:'#a371f7', amber:'#e3b341', pink:'#ec4899', slate:'#94a3b8'};
const REFRESH_OPTIONS = [5, 10, 15, 30, 60];
const DEFAULT_PREFS = {theme:'bemo-dark', accent:'', density:'comfortable', reducedMotion:false, defaultView:'last', refreshSeconds:0, analyticsStyle:'digital', mapMode:'countries', mapMetric:'observations', mapBasemap:'satellite-heat', mapTheme:'bemo-accent'};
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
function renderMetricVisual(elId, points, colorVar, unitLabel){
  const el = document.getElementById(elId); if (!el) return;
  const style = prefs.analyticsStyle || 'digital';
  el.classList.add('metric-visual');
  el.classList.remove('visual-analog','visual-digital','visual-specter');
  el.classList.add('visual-'+style);
  const pts = points || [];
  if (!pts.some(p => p.count != null)){ el.innerHTML = '<div class="empty-state">No data yet.</div>'; return; }
  const w=600, h=120, pad=4;
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
  const readout = `<div class="metric-readout"><div class="metric-readout-item">Current<b>${esc(current)}</b></div><div class="metric-readout-item">Average<b>${esc(avg)}</b></div><div class="metric-readout-item">Peak<b>${esc(peak)}</b></div>${spikes.size ? `<div class="metric-readout-item">Spikes<b>${spikes.size}</b></div>` : ''}</div>`;
  el.innerHTML = `<svg viewBox="0 0 ${w} ${h}" class="history-svg" preserveAspectRatio="none" role="img" aria-label="${esc(unitLabel||'activity over time')}">${grid}${defs}${fill}${bars}<path class="metric-line" d="${esc(linePath)}" fill="none" stroke="var(${colorVar})" stroke-width="${strokeWidth}" stroke-linecap="round" stroke-linejoin="round"/>${sweep}${pulse}${markers}</svg>${readout}<div class="stats-note">${esc(unitLabel||'')}</div>`;
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
  <div class="dash-toolbar">
    <button type="button" class="dash-customize-btn" id="dash-customize-btn" aria-pressed="false">Customize</button>
    <select class="settings-select" id="dash-preset-select" aria-label="Dashboard preset">
      <option value="default">Default layout</option>
      <option value="monitoring">Monitoring</option>
      <option value="compact">Compact</option>
      <option value="investigation">Investigation</option>
      <option value="custom">Custom</option>
    </select>
    <button type="button" id="dash-reset-btn" title="Reset to the default layout">Reset layout</button>
    <span class="dash-hint" id="dash-hint" hidden>Use the handle to drag, or the arrow/size/hide buttons &mdash; changes save to this browser.</span>
  </div>
  <div class="dash-grid" id="analytics-dash-grid">
    <div class="dash-widget" data-widget-id="live-overview" data-title="Live activity" data-w="4" data-h="normal">
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
    </div>
    <div class="dash-widget" data-widget-id="query-volume" data-title="DNS activity over time" data-w="4" data-h="normal">
      <div class="card">
        <h2>DNS activity over time</h2>
        <div class="analytics-range-controls" role="group" aria-label="Historical time range">
          <button type="button" class="range-btn active" data-analytics-range="1h">1H</button>
          <button type="button" class="range-btn" data-analytics-range="6h">6H</button>
          <button type="button" class="range-btn" data-analytics-range="24h">24H</button>
          <button type="button" class="range-btn" data-analytics-range="7d">7D</button>
        </div>
        <div id="chart-query-volume"></div>
      </div>
    </div>
    <div class="dash-widget" data-widget-id="new-domains" data-title="New domains discovered" data-w="2" data-h="normal">
      <div class="card"><h2>New domains discovered</h2><div id="chart-new-domains"></div></div>
    </div>
    <div class="dash-widget" data-widget-id="new-devices" data-title="New devices discovered" data-w="2" data-h="normal">
      <div class="card"><h2>New devices discovered</h2><div id="chart-new-devices"></div></div>
    </div>
    <div class="dash-widget" data-widget-id="status-breakdown" data-title="Status breakdown" data-w="4" data-h="normal">
      <div class="card">
        <h2>Status breakdown</h2>
        <div id="status-breakdown" class="dash-scroll"></div>
        <div class="stats-note">All known domains, grouped by their current AdGuard filtering outcome.</div>
      </div>
    </div>
    <div class="dash-widget" data-widget-id="instrument-gauges" data-title="Instrument gauges" data-w="4" data-h="normal">
      <div class="card">
        <h2>Instrument gauges</h2>
        <div id="instrument-gauges" class="gauge-cluster">
          <div class="gauge-face"><div id="gauge-blocked-ratio"></div><div class="stats-note">Blocked ratio</div></div>
          <div class="gauge-face"><div id="gauge-active-devices"></div><div class="stats-note">Active devices</div></div>
        </div>
      </div>
    </div>
    <div class="dash-widget" data-widget-id="destination-map" data-title="DNS Destinations (observed)" data-w="4" data-h="normal">
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
        </div>
        <div id="destination-map"></div>
        <div id="destination-map-detail" class="map-detail" hidden></div>
        <div class="stats-note" style="margin-top:0">GeoIP data, when configured: IP Geolocation by <a href="https://db-ip.com" target="_blank" rel="noopener noreferrer">DB-IP</a> (DB-IP Lite, CC BY 4.0).</div>
      </div>
    </div>
    <div class="dash-widget" data-widget-id="activity-domains" data-title="Recently active domains" data-w="2" data-h="normal">
      <div class="card"><h2>Recently active domains</h2><div id="activity-domains" class="dash-scroll"></div></div>
    </div>
    <div class="dash-widget" data-widget-id="activity-devices" data-title="Recently active devices" data-w="2" data-h="normal">
      <div class="card"><h2>Recently active devices</h2><div id="activity-devices" class="dash-scroll"></div></div>
    </div>
    <div class="dash-widget" data-widget-id="top-activity" data-title="Top activity (all time)" data-w="4" data-h="normal">
      <div class="card"><h2>Top activity (all time)</h2><div class="stats-note" style="margin-top:0">Cumulative totals since the database was created.</div></div>
      <div class="chart-grid">
        <div class="card chart-card"><h2>Most requested domains</h2><div id="chart-domains" class="chart-list"></div><div class="stats-note">Based on recorded DNS requests.</div></div>
        <div class="card chart-card"><h2>Most active devices</h2><div id="chart-devices" class="chart-list"></div><div class="stats-note">Ranked by total recorded requests.</div></div>
        <div class="card chart-card"><h2>Most active vendors</h2><div id="chart-vendors" class="chart-list"></div><div class="stats-note">Aggregated from identified devices.</div></div>
        <div class="card chart-card"><h2>Most active IPs</h2><div id="chart-ips" class="chart-list"></div><div class="stats-note">Aggregated from device IP observations.</div></div>
      </div>
    </div>
  </div>
</section>
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
function renderRecentControls(meta,opts){recentMeta=meta||recentMeta;const c=recentMeta.status_counts||{};[['count-all','All'],['count-allowed','Allowed'],['count-blocked','Blocked'],['count-mixed','Mixed'],['count-unknown','Unknown']].forEach(([i,k])=>{const e=document.getElementById(i);if(e)e.textContent=c[k]!=null?` ${c[k]}`:''});const n=document.getElementById('count-new');if(n)n.textContent=recentMeta.new_count!=null?` ${recentMeta.new_count}`:'';document.querySelectorAll('[data-status-filter]').forEach(b=>b.classList.toggle('active',(b.dataset.statusFilter||'')===recentFilters.status));document.getElementById('new-filter')?.classList.toggle('active',recentFilters.newOnly);const sum=document.getElementById('results-summary');if(sum)sum.innerHTML=`<b>${recentMeta.total||0}</b> matching domain${(recentMeta.total||0)===1?'':'s'} · <b>${recentMeta.new_count||0}</b> new in the last 24h`;setSelectOptions('classification-filter',opts?.classifications,recentFilters.classification);setSelectOptions('severity-filter',opts?.severities,recentFilters.severity);setSelectOptions('device-filter',opts?.devices,recentFilters.device);setSelectOptions('vendor-filter',opts?.vendors,recentFilters.vendor);const ps=document.getElementById('page-size');if(ps)ps.value=String(recentFilters.page_size);const label=document.getElementById('page-label');if(label){const a=recentMeta.total?((recentMeta.page-1)*recentMeta.page_size)+1:0;const b=recentMeta.total?Math.min(recentMeta.page*recentMeta.page_size,recentMeta.total):0;label.textContent=`Showing ${a}–${b} of ${recentMeta.total||0}`}const prev=document.getElementById('page-prev'),next=document.getElementById('page-next');if(prev)prev.disabled=recentMeta.page<=1;if(next)next.disabled=recentMeta.page>=recentMeta.pages}
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

async function loadDeviceLabels(){try{const r=await fetch('/api/device/label',{cache:'no-store'});if(!r.ok)return;const data=await r.json();window.deviceLabels=data.labels||{};}catch(e){console.debug('device labels load failed',e)}}
async function editDeviceLabel(button){const key=button?.dataset?.deviceKey||'';if(!key)return;const current=button.dataset.deviceLabel||'';const value=window.prompt('Device label',current);if(value===null)return;const label=value.trim().slice(0,80);try{const r=await fetch('/api/device/label',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({device_key:key,label})});const data=await r.json();if(!r.ok||!data.ok)throw new Error(data.error||'Save failed');window.deviceLabels[key]=label;renderClients(window.__lastClients||[]);renderRecent(window.__lastRecent||[]);bindDeviceLabelButtons();}catch(e){alert('Could not save device label: '+e.message)}}
function bindDeviceLabelButtons(){document.querySelectorAll('.device-label-btn').forEach(b=>{if(b.dataset.bound)return;b.dataset.bound='1';b.addEventListener('click',()=>editDeviceLabel(b));})}
function renderClients(rows,force){ window.__lastClients=rows||[]; if(!force&&!document.getElementById('tab-devices')?.classList.contains('active'))return; document.getElementById('clients-body').innerHTML = (rows||[]).map(deviceRow).join(''); bindDeviceLabelButtons(); placeDeviceLabelsInColumn(); injectIpPingControls(); reapplyTableSorts(); }
let tableSortState = {recent:{key:null,dir:1}, clients:{key:null,dir:1}};
function rowSortValue(row,key,type){ const raw=row.dataset['sort'+key.charAt(0).toUpperCase()+key.slice(1)] ?? ''; return type==='number' ? (Number(raw)||0) : String(raw).toLowerCase(); }
function applySort(table,key,dir){ const th=[...table.querySelectorAll('th.sortable')].find(x=>x.dataset.sortKey===key); if(!th)return; table.querySelectorAll('th.sortable').forEach(x=>x.classList.remove('sort-asc','sort-desc')); th.classList.add(dir===1?'sort-asc':'sort-desc'); const type=th.dataset.sortType||'text'; const body=table.tBodies[0]; [...body.rows].sort((a,b)=>{const av=rowSortValue(a,key,type),bv=rowSortValue(b,key,type); if(av<bv)return -1*dir; if(av>bv)return 1*dir; return 0;}).forEach(r=>body.appendChild(r)); }
function bindSortableTables(){ document.querySelectorAll('th.sortable').forEach(th=>{ th.onclick=()=>{ const table=th.closest('table'); const name=table.id==='recent-table'?'recent':'clients'; const key=th.dataset.sortKey; const same=tableSortState[name].key===key; tableSortState[name]={key,dir:same?-tableSortState[name].dir:1}; applySort(table,key,tableSortState[name].dir); }; }); }
function reapplyTableSorts(){ const r=document.getElementById('recent-table'),c=document.getElementById('clients-table'); if(r&&tableSortState.recent.key)applySort(r,tableSortState.recent.key,tableSortState.recent.dir); if(c&&tableSortState.clients.key)applySort(c,tableSortState.clients.key,tableSortState.clients.dir); }
function setActiveTab(name){
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.dataset.panel === name));
  try{ localStorage.setItem('dnsInspectorTab', name); }catch(e){}
  // The background /api/state poll skips re-rendering a tab's table while
  // it isn't visible (see renderRecent/renderClients); catch it up here
  // from the cached last-fetched rows instead of re-fetching.
  if (name === 'overview' && Array.isArray(window.__lastRecent)) renderRecent(window.__lastRecent, true);
  if (name === 'devices' && Array.isArray(window.__lastClients)) renderClients(window.__lastClients, true);
  if (typeof window.onAnalyticsTabChange === 'function') window.onAnalyticsTabChange(name);
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
    const saved=localStorage.getItem('dnsInspectorTab');
    if(saved && ['overview','devices','analytics'].includes(saved)) setActiveTab(saved);
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
let analyticsFullTimer = null;

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
async function fetchAnalyticsFull(){
  try{
    const r = await fetch(`/api/analytics?range=${encodeURIComponent(analyticsRange)}`, {cache:'no-store'});
    if (!r.ok) return;
    const data = await r.json();
    renderMetricVisual('chart-query-volume', data.series?.queries?.points, '--sem-info', 'DNS queries');
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
    fetchDestinationMap();
  }catch(e){ console.debug('analytics refresh failed', e); }
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
function mapProject(lat, lon){ return { x: (lon+180)/360*MAP_W, y: (90-lat)/180*MAP_H }; }
function mapActiveBasemap(){ return MAP_BASEMAPS.includes(prefs.mapBasemap) ? prefs.mapBasemap : 'satellite-heat'; }
function mapActiveTheme(){ return MAP_THEMES.includes(prefs.mapTheme) ? prefs.mapTheme : 'bemo-accent'; }
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
    const nums = (seg.match(/-?\d+(?:\.\d+)?/g) || []).map(Number);
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
  return `<div class="map-status-banner">${text}${actionHtml ? `<div class="map-status-action">${actionHtml}</div>` : ''}</div>`;
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
  if (n >= 1000) return (n / 1000).toFixed(1).replace(/\.0$/, '') + 'k';
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
function renderMapDetail(entity, kind){
  const el = document.getElementById('destination-map-detail'); if (!el) return;
  if (!entity){ el.hidden = true; el.innerHTML = ''; return; }
  el.hidden = false;
  const closeBtn = '<button type="button" class="map-detail-close" id="map-detail-close-btn" aria-label="Close details">&times;</button>';
  if (kind === 'destination'){
    const domains = (entity.sample_domains||[]).map(d => `<span class="chip">${esc(d)}</span>`).join('') || '<span class="sub">No sampled domains</span>';
    const ipCount = entity.unique_ip_count || 1;
    const where = entity.city ? `${entity.city}, ${entity.country_name || entity.country_code || 'unknown location'}` : (entity.country_name || entity.country_code || 'Unknown location');
    el.innerHTML = closeBtn + `<h3>${esc(where)} <span class="sub">${esc(ipCount)} IP${ipCount===1?'':'s'}</span></h3>`
      + `<div class="stats-note">${esc(entity.observation_count)} observed destination observation${entity.observation_count===1?'':'s'} &middot; ${esc(entity.domain_count)} domain${entity.domain_count===1?'':'s'} &middot; approximate coordinates from observed DNS destinations, not a verified physical location</div>`
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
  return Array.from(cells.values()).map(b => ({
    key: b.key,
    x: b.sumX / b.points.length,
    y: b.sumY / b.points.length,
    points: b.points,
    unique_ip_count: b.points.length,
    observation_count: b.observation_count,
    domain_count: b.domain_count,
    country_code: b.points[0].country_code,
    country_name: b.points[0].country_name,
    city: b.points.length === 1 ? b.points[0].city : null,
    sample_domains: Array.from(new Set(b.points.flatMap(p => p.sample_domains || []))).slice(0, 5),
  }));
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
  const activateCountry = (code) => {
    mapSelectedCountry = (mapSelectedCountry === code) ? null : code;
    renderCountriesMode(data);
    renderMapDetail(mapSelectedCountry ? countries.find(c => c.country_code === mapSelectedCountry) : null, 'country');
  };
  el.querySelectorAll('[data-country]').forEach(node => {
    node.addEventListener('click', () => {
      if (mapWasDragging) return;
      activateCountry(node.getAttribute('data-country'));
    });
    node.addEventListener('keydown', (e) => {
      if (e.key !== 'Enter' && e.key !== ' ' && e.key !== 'Spacebar') return;
      e.preventDefault();
      activateCountry(node.getAttribute('data-country'));
    });
  });
}
function renderDestinationsMode(data, capabilities){
  const el = document.getElementById('destination-map'); if (!el) return;
  if (!capabilities.coordinates){
    el.innerHTML = mapBaseSvg(
      'World map; coordinate-level destination data unavailable',
      mapStatusBanner(
        'Coordinate-level destination data is unavailable &mdash; only a country GeoIP database is configured. Configure a city/coordinate-capable GeoIP database to enable Destinations mode, or switch to Countries. See docs/GEOIP.md.',
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
      mapStatusBanner('No geolocated destination coordinates yet. This fills in as domains are queried and their actual DNS answers get matched against the configured city/coordinate GeoIP database.')
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
    const label = c.unique_ip_count > 1
      ? `${esc(c.unique_ip_count)} destinations: ${esc(c.observation_count)} observations, ${esc(c.domain_count)} domains`
      : `${esc(c.city || c.country_name || c.country_code || 'Unknown')}: ${esc(c.observation_count)} observations, ${esc(c.domain_count)} domains`;
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
    renderDestinationsMode(data, capabilities);
    renderMapDetail(mapSelectedDestinationKey ? cluster : null, 'destination');
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
      ? 'Real observed DNS destination IPs plotted by coordinate and clustered when nearby — not verified physical server locations.'
      : 'Country-level aggregate of resolved DNS response IPs — not verified physical server locations. CDN, anycast and multi-region destinations resolve to whichever country answered.';
  }
  const legendMetricEl = document.getElementById('map-legend-metric-label');
  if (legendMetricEl) legendMetricEl.textContent = mapMetricLabel();
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
  if (!provider.configured && !capabilities.coordinates){
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
}
function syncMapControls(){
  const modeSel = document.getElementById('map-mode-select');
  const metricSel = document.getElementById('map-metric-select');
  const basemapSel = document.getElementById('map-basemap-select');
  const themeSel = document.getElementById('map-theme-select');
  if (modeSel) modeSel.value = prefs.mapMode || 'countries';
  if (metricSel) metricSel.value = prefs.mapMetric || 'observations';
  if (basemapSel) basemapSel.value = mapActiveBasemap();
  if (themeSel) themeSel.value = mapActiveTheme();
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
async function fetchDestinationMap(){
  try{
    const r = await fetch('/api/analytics/map', {cache:'no-store'});
    if (!r.ok) return;
    renderDestinationMap(await r.json());
  }catch(e){ console.debug('destination map refresh failed', e); }
}
function startAnalyticsPolling(){
  if (analyticsFullTimer) return;
  renderLiveHero();
  fetchAnalyticsFull();
  analyticsFullTimer = setInterval(fetchAnalyticsFull, refreshMs);
}
function stopAnalyticsPolling(){
  if (analyticsFullTimer){ clearInterval(analyticsFullTimer); analyticsFullTimer = null; }
}
document.querySelectorAll('[data-analytics-range]').forEach(b => b.addEventListener('click', () => {
  analyticsRange = b.dataset.analyticsRange;
  document.querySelectorAll('[data-analytics-range]').forEach(x => x.classList.toggle('active', x === b));
  fetchAnalyticsFull();
}));
function analyticsTabChanged(name){
  if (name === 'analytics') startAnalyticsPolling(); else stopAnalyticsPolling();
}
window.onAnalyticsTabChange = analyticsTabChanged;
analyticsTabChanged(document.querySelector('.tab-btn.active')?.dataset.tab || 'overview');
</script>
<script>
/* ---- Dashboard Builder (0.8.5) ----
   Customize mode for the Analytics widget grid: drag/move, bounded resize
   (half/full width x compact/normal/tall height), show/hide and named
   presets, persisted per-browser. This only reorders/resizes/hides the
   widgets already in the page -- no widget's underlying data or route
   changes. Drag-and-drop via the handle is a pointer/mouse enhancement;
   the move-up/move-down buttons are the touch- and keyboard-accessible
   path, since HTML5 drag-and-drop is unreliable on touch devices. */
(function(){
  const grid = document.getElementById('analytics-dash-grid');
  if (!grid) return;
  const WIDGET_IDS = Array.from(grid.querySelectorAll('.dash-widget')).map(w => w.dataset.widgetId);
  const LAYOUT_KEY = 'dnsInspectorDashboardLayout';
  const WIDTH_STEPS = ['1','2','3','4'];

  /* 0.8.5.6: the grid moved from a binary half/full width to a real 1-4
     column span. A browser that already persisted a pre-0.8.5.6
     `dnsInspectorDashboardLayout` (or a preset built before this change) can
     still hand back the old 'full'/'half' strings -- normalize those to the
     equivalent span instead of treating them as an invalid/unknown width. */
  function normalizeWidth(w){
    if (w === 'full') return '4';
    if (w === 'half') return '2';
    return WIDTH_STEPS.includes(String(w)) ? String(w) : '4';
  }

  function defaultLayout(){
    const widgets = {};
    WIDGET_IDS.forEach(id => {
      const el = grid.querySelector(`[data-widget-id="${id}"]`);
      widgets[id] = { w: normalizeWidth(el.dataset.w), h: el.dataset.h || 'normal', hidden: false };
    });
    return { preset: 'default', order: WIDGET_IDS.slice(), widgets };
  }
  const DEFAULT_LAYOUT = defaultLayout();
  const clone = (obj) => JSON.parse(JSON.stringify(obj));

  /* A widget introduced by a later release (e.g. the 0.8.5.1 GeoIP map) is
     absent from any `order` saved by an older build, and from any preset's
     own hard-coded reorder list. Naively appending such ids to the very end
     of `order` buries a newly-shipped widget below everything a user's
     browser already persisted -- functionally invisible without scrolling
     past what used to be the bottom of the page. Placing it right next to
     its default neighbour keeps existing customization intact while still
     surfacing the new widget close to where a fresh layout would show it. */
  function insertWidgetsAtDefaultPosition(order, defaultOrder){
    order = order.slice();
    defaultOrder.forEach((id, defaultIdx) => {
      if (order.includes(id)) return;
      let insertAt = -1;
      for (let i = defaultIdx - 1; i >= 0 && insertAt === -1; i--){
        const idx = order.indexOf(defaultOrder[i]);
        if (idx !== -1) insertAt = idx + 1;
      }
      if (insertAt === -1){
        for (let i = defaultIdx + 1; i < defaultOrder.length && insertAt === -1; i++){
          const idx = order.indexOf(defaultOrder[i]);
          if (idx !== -1) insertAt = idx;
        }
      }
      order.splice(insertAt === -1 ? order.length : insertAt, 0, id);
    });
    return order;
  }

  function presetLayout(name){
    const base = clone(DEFAULT_LAYOUT);
    base.preset = name;
    const set = (id, patch) => { if (base.widgets[id]) Object.assign(base.widgets[id], patch); };
    if (name === 'monitoring'){
      base.order = ['live-overview','status-breakdown','query-volume','new-domains','new-devices','activity-domains','activity-devices','top-activity'];
      set('live-overview', {h:'tall'});
      set('activity-domains', {h:'compact'});
      set('activity-devices', {h:'compact'});
      set('top-activity', {hidden:true});
    } else if (name === 'compact'){
      WIDGET_IDS.forEach(id => set(id, {h:'compact'}));
      set('top-activity', {hidden:true});
    } else if (name === 'investigation'){
      base.order = ['query-volume','status-breakdown','top-activity','activity-domains','activity-devices','new-domains','new-devices','live-overview'];
      set('top-activity', {h:'tall'});
      set('activity-domains', {h:'tall'});
      set('activity-devices', {h:'tall'});
      set('live-overview', {w:'2', h:'compact'});
    }
    base.order = insertWidgetsAtDefaultPosition(base.order, DEFAULT_LAYOUT.order);
    return base;
  }

  function loadLayout(){
    try{
      const raw = JSON.parse(localStorage.getItem(LAYOUT_KEY) || 'null');
      if (!raw || !raw.widgets || !raw.order) return clone(DEFAULT_LAYOUT);
      const widgets = {};
      WIDGET_IDS.forEach(id => {
        const merged = Object.assign({w:'4',h:'normal',hidden:false}, raw.widgets[id] || {});
        merged.w = normalizeWidth(merged.w);
        widgets[id] = merged;
      });
      const order = insertWidgetsAtDefaultPosition(raw.order.filter(id => WIDGET_IDS.includes(id)), DEFAULT_LAYOUT.order);
      return { preset: raw.preset || 'custom', order, widgets };
    }catch(e){ return clone(DEFAULT_LAYOUT); }
  }
  function saveLayout(){ try{ localStorage.setItem(LAYOUT_KEY, JSON.stringify(layout)); }catch(e){} }

  let layout = loadLayout();
  let customizing = false;

  function widgetHeadHtml(title){
    return `<div class="dash-widget-head"><span class="dash-drag-handle" draggable="true" title="Drag to reorder">⠿</span><span class="dash-widget-title">${esc(title)}</span><button type="button" data-dash-action="move-up" title="Move up" aria-label="Move ${esc(title)} up">&uarr;</button><button type="button" data-dash-action="move-down" title="Move down" aria-label="Move ${esc(title)} down">&darr;</button><button type="button" class="dash-width-btn" data-dash-action="width" aria-label="Change ${esc(title)} width">&hArr;</button><button type="button" data-dash-action="height" title="Toggle height (compact/normal/tall)">&vArr;</button><button type="button" data-dash-action="hide" title="Hide widget" aria-label="Hide ${esc(title)}">&times;</button></div>`;
  }
  WIDGET_IDS.forEach(id => {
    const el = grid.querySelector(`[data-widget-id="${id}"]`);
    el.insertAdjacentHTML('afterbegin', widgetHeadHtml(el.dataset.title || id));
  });

  function applyLayout(){
    layout.order.forEach((id, i) => {
      const el = grid.querySelector(`[data-widget-id="${id}"]`);
      if (!el) return;
      el.style.order = String(i);
      const w = layout.widgets[id] || {w:'4',h:'normal',hidden:false};
      el.dataset.w = normalizeWidth(w.w);
      el.dataset.h = w.h || 'normal';
      el.dataset.hidden = w.hidden ? '1' : '0';
      const hideBtn = el.querySelector('[data-dash-action="hide"]');
      if (hideBtn){ hideBtn.innerHTML = w.hidden ? '&#43;' : '&times;'; hideBtn.title = w.hidden ? 'Show widget' : 'Hide widget'; }
      const widthBtn = el.querySelector('[data-dash-action="width"]');
      if (widthBtn) widthBtn.title = `Width: ${el.dataset.w}/4 columns (click to widen/narrow)`;
    });
    const presetSelect = document.getElementById('dash-preset-select');
    if (presetSelect) presetSelect.value = layout.preset || 'custom';
    if (document.getElementById('tab-analytics')?.classList.contains('active') && typeof fetchAnalyticsFull === 'function') fetchAnalyticsFull();
    if (typeof renderLiveHero === 'function') renderLiveHero();
  }

  function markCustom(){ layout.preset = 'custom'; saveLayout(); applyLayout(); }

  grid.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-dash-action]'); if (!btn) return;
    const widget = btn.closest('.dash-widget'); const id = widget.dataset.widgetId;
    const action = btn.dataset.dashAction;
    const idx = layout.order.indexOf(id);
    const cur = layout.widgets[id];
    if (action === 'move-up' && idx > 0){ [layout.order[idx-1], layout.order[idx]] = [layout.order[idx], layout.order[idx-1]]; }
    else if (action === 'move-down' && idx < layout.order.length-1){ [layout.order[idx+1], layout.order[idx]] = [layout.order[idx], layout.order[idx+1]]; }
    else if (action === 'width'){ cur.w = WIDTH_STEPS[(WIDTH_STEPS.indexOf(normalizeWidth(cur.w)) + 1) % WIDTH_STEPS.length]; }
    else if (action === 'height'){ cur.h = cur.h === 'compact' ? 'normal' : (cur.h === 'normal' ? 'tall' : 'compact'); }
    else if (action === 'hide'){ cur.hidden = !cur.hidden; }
    markCustom();
  });

  let dragId = null;
  grid.addEventListener('dragstart', (e) => {
    const handle = e.target.closest('.dash-drag-handle'); if (!handle || !customizing) return;
    const widget = handle.closest('.dash-widget'); dragId = widget.dataset.widgetId;
    widget.dataset.dragging = '1';
    if (e.dataTransfer) e.dataTransfer.effectAllowed = 'move';
  });
  grid.addEventListener('dragend', (e) => {
    const widget = e.target.closest('.dash-widget'); if (widget) widget.removeAttribute('data-dragging');
    dragId = null;
  });
  grid.addEventListener('dragover', (e) => { if (dragId) e.preventDefault(); });
  grid.addEventListener('drop', (e) => {
    if (!dragId) return;
    e.preventDefault();
    const target = e.target.closest('.dash-widget');
    if (!target || target.dataset.widgetId === dragId) return;
    const from = layout.order.indexOf(dragId), to = layout.order.indexOf(target.dataset.widgetId);
    if (from === -1 || to === -1) return;
    layout.order.splice(from, 1);
    layout.order.splice(to, 0, dragId);
    markCustom();
  });

  const customizeBtn = document.getElementById('dash-customize-btn');
  const hint = document.getElementById('dash-hint');
  customizeBtn?.addEventListener('click', () => {
    customizing = !customizing;
    grid.classList.toggle('dash-customizing', customizing);
    customizeBtn.classList.toggle('active', customizing);
    customizeBtn.setAttribute('aria-pressed', String(customizing));
    customizeBtn.textContent = customizing ? 'Done customizing' : 'Customize';
    if (hint) hint.hidden = !customizing;
  });

  document.getElementById('dash-preset-select')?.addEventListener('change', (e) => {
    const name = e.target.value;
    if (name === 'custom') return;
    layout = presetLayout(name);
    saveLayout();
    applyLayout();
  });

  document.getElementById('dash-reset-btn')?.addEventListener('click', () => {
    layout = clone(DEFAULT_LAYOUT);
    saveLayout();
    applyLayout();
  });

  applyLayout();
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

  function openDialog(){
    if (typeof dialog.showModal === 'function') dialog.showModal(); else dialog.setAttribute('open','');
    refreshDiagnosticsPanel();
    refreshSystemPanel();
    refreshAboutUptime();
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
      ['domains','devices','processed_queries'].forEach(t => { if (counts[t] != null) rows.push(['Rows: ' + t, counts[t]]); });
      el.innerHTML = kvRows(rows);
    }catch(e){ el.innerHTML = '<b>Diagnostics unavailable</b><span>—</span>'; }
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
        const r = await fetch('/api/system/restart', {
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

  syncControls();
})();
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
        c.execute("CREATE INDEX IF NOT EXISTS idx_domains_last_seen ON domains(last_seen)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_domains_first_seen ON domains(first_seen)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_devices_first_seen ON devices(first_seen)")
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
        # Observed DNS destination IPs (0.8.5.1): the actual A/AAAA answer(s)
        # AdGuard returned for a query, captured at ingestion time from the
        # query log entry itself -- distinct from `dns_records_cache`, which
        # is an independently DNS-over-HTTPS-resolved snapshot and is not
        # necessarily the IP the original query actually received. Bounded to
        # `GEOIP_DESTINATION_IPS_PER_DOMAIN_LIMIT` distinct IPs per domain.
        c.execute("""CREATE TABLE IF NOT EXISTS domain_destination_ips(
            domain TEXT NOT NULL, ip TEXT NOT NULL, first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL, observations INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(domain, ip))""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_domain_destination_ips_domain ON domain_destination_ips(domain)")
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


_CGNAT_V4_NETWORK = ipaddress.ip_network("100.64.0.0/10")  # RFC 6598 shared/CGNAT space


def normalize_public_ip(value):
    """Return a normalized public IP string, or None for private, loopback,
    link-local, multicast, reserved, unspecified or CGNAT addresses.

    Used to keep the GeoIP destination map honest: only addresses that could
    plausibly identify a real external destination are ever geolocated.
    """
    try:
        addr = ipaddress.ip_address(str(value).strip())
    except (ValueError, AttributeError):
        return None
    if isinstance(addr, ipaddress.IPv6Address):
        mapped = addr.ipv4_mapped
        if mapped is not None:
            addr = mapped
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved or addr.is_unspecified:
        return None
    if isinstance(addr, ipaddress.IPv4Address) and addr in _CGNAT_V4_NETWORK:
        return None
    return str(addr)


def extract_observed_answer_ips(entry):
    """Return normalized public A/AAAA IPs actually present in this AdGuard
    query log entry's `answer` section -- the real destination(s) that query
    received, not an independently re-resolved snapshot. AdGuard's querylog
    API returns `answer` as a list of `{"type": "A"|"AAAA"|..., "value": ...}`
    records; unrelated record types (CNAME, TXT, ...) are ignored."""
    ips = []
    for ans in entry.get("answer") or []:
        if not isinstance(ans, dict):
            continue
        if str(ans.get("type") or "").upper() not in ("A", "AAAA"):
            continue
        normalized = normalize_public_ip(ans.get("value"))
        if normalized and normalized not in ips:
            ips.append(normalized)
    return ips


def _record_domain_destination_ips(c, domain, ips, now):
    """Upsert observed destination IPs for `domain`, bounded to
    `GEOIP_DESTINATION_IPS_PER_DOMAIN_LIMIT` distinct IPs. Each IP's own
    `observations` counter -- not the domain's overall request count -- is
    what the destination map aggregates by, so a domain with several
    concurrently-valid answers (CDN/anycast) does not have its whole query
    volume attributed to whichever IP happened to be looked up first."""
    if not ips:
        return
    existing_count = None
    for ip in ips:
        updated = c.execute(
            "UPDATE domain_destination_ips SET last_seen=?, observations=observations+1 WHERE domain=? AND ip=?",
            (now, domain, ip),
        ).rowcount
        if updated:
            continue
        if existing_count is None:
            existing_count = c.execute(
                "SELECT COUNT(*) FROM domain_destination_ips WHERE domain=?", (domain,)
            ).fetchone()[0]
        if existing_count >= GEOIP_DESTINATION_IPS_PER_DOMAIN_LIMIT:
            continue
        c.execute(
            "INSERT INTO domain_destination_ips(domain,ip,first_seen,last_seen,observations) VALUES(?,?,?,?,1)",
            (domain, ip, now, now),
        )
        existing_count += 1


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
                _record_domain_destination_ips(c, domain, extract_observed_answer_ips(e), now)
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


# ---- GeoIP / DNS Destinations map (0.8.5.1) --------------------------------
# Data flow: DNS query -> AdGuard's own answer for that query, captured at
# ingestion time (`domain_destination_ips`, populated by
# `_record_domain_destination_ips`/`extract_observed_answer_ips` -- the real
# A/AAAA answer(s) the query received, not an independently re-resolved
# snapshot) -> public IP filter (`normalize_public_ip`) -> local/offline
# GeoIP lookup -> country aggregate. No step here makes a network request;
# GeoIP lookups are a local table scan against an operator-supplied CSV
# database (see docs/GEOIP.md). The map represents *observed DNS
# destinations*, not verified physical server locations -- CDN/anycast/
# multi-region destinations legitimately resolve to whichever country their
# answering edge node's IP is allocated to. Each destination IP is weighted
# by how many times it was actually observed in an answer, not by the
# domain's total query count, so a multi-CDN domain is not misattributed
# entirely to whichever IP happened to be checked first.

# Approximate country centroids used only to place a bubble on the map grid.
# Deliberately a bounded, commonly-hosting-relevant subset (not all ISO
# 3166-1 codes): a country a GeoIP database resolves but that is missing here
# still counts toward the aggregate totals/legend, it just has no plotted
# bubble. Coordinates are approximate (degrees lat, lon) and not intended to
# imply precision beyond "roughly where this country is".
COUNTRY_CENTROIDS = {
    "US": (39.8, -98.6, "United States"), "CA": (56.1, -106.3, "Canada"),
    "MX": (23.6, -102.5, "Mexico"), "BR": (-14.2, -51.9, "Brazil"),
    "AR": (-38.4, -63.6, "Argentina"), "CL": (-35.7, -71.5, "Chile"),
    "CO": (4.6, -74.3, "Colombia"), "PE": (-9.2, -75.0, "Peru"),
    "GB": (54.0, -2.0, "United Kingdom"), "IE": (53.4, -8.2, "Ireland"),
    "FR": (46.6, 2.2, "France"), "DE": (51.2, 10.4, "Germany"),
    "NL": (52.1, 5.3, "Netherlands"), "BE": (50.8, 4.5, "Belgium"),
    "LU": (49.8, 6.1, "Luxembourg"), "CH": (46.8, 8.2, "Switzerland"),
    "AT": (47.5, 14.6, "Austria"), "IT": (42.8, 12.6, "Italy"),
    "ES": (40.5, -3.7, "Spain"), "PT": (39.4, -8.2, "Portugal"),
    "SE": (60.1, 18.6, "Sweden"), "NO": (60.5, 8.5, "Norway"),
    "DK": (56.3, 9.5, "Denmark"), "FI": (61.9, 25.7, "Finland"),
    "IS": (64.9, -19.0, "Iceland"), "PL": (51.9, 19.1, "Poland"),
    "CZ": (49.8, 15.5, "Czechia"), "SK": (48.7, 19.7, "Slovakia"),
    "HU": (47.2, 19.5, "Hungary"), "RO": (45.9, 25.0, "Romania"),
    "BG": (42.7, 25.5, "Bulgaria"), "GR": (39.1, 21.8, "Greece"),
    "TR": (38.9, 35.2, "Turkey"), "RU": (61.5, 105.3, "Russia"),
    "UA": (48.4, 31.2, "Ukraine"), "EE": (58.6, 25.0, "Estonia"),
    "LV": (56.9, 24.6, "Latvia"), "LT": (55.2, 23.9, "Lithuania"),
    "CN": (35.9, 104.2, "China"), "JP": (36.2, 138.3, "Japan"),
    "KR": (35.9, 127.8, "South Korea"), "TW": (23.7, 121.0, "Taiwan"),
    "HK": (22.3, 114.2, "Hong Kong"), "SG": (1.35, 103.8, "Singapore"),
    "IN": (20.6, 79.0, "India"), "ID": (-0.8, 113.9, "Indonesia"),
    "MY": (4.2, 101.9, "Malaysia"), "TH": (15.9, 101.0, "Thailand"),
    "VN": (14.1, 108.3, "Vietnam"), "PH": (12.9, 121.8, "Philippines"),
    "AU": (-25.3, 133.8, "Australia"), "NZ": (-41.0, 174.9, "New Zealand"),
    "ZA": (-30.6, 22.9, "South Africa"), "EG": (26.8, 30.8, "Egypt"),
    "NG": (9.1, 8.7, "Nigeria"), "KE": (-0.02, 37.9, "Kenya"),
    "MA": (31.8, -7.1, "Morocco"), "IL": (31.0, 34.8, "Israel"),
    "AE": (23.4, 53.8, "United Arab Emirates"), "SA": (23.9, 45.1, "Saudi Arabia"),
    "QA": (25.4, 51.2, "Qatar"), "PK": (30.4, 69.3, "Pakistan"),
    "BD": (23.7, 90.4, "Bangladesh"), "KZ": (48.0, 66.9, "Kazakhstan"),
    "IR": (32.4, 53.7, "Iran"), "IQ": (33.2, 43.7, "Iraq"),
}


def _iter_csv_rows_throttled(reader, chunk_rows=None, yield_seconds=None):
    """Yield rows from a `csv.reader` in bounded chunks, sleeping briefly
    between chunks (Issue #50 / 0.8.5.10) so parsing a multi-million-row
    GeoIP database doesn't monopolize CPU/disk for the whole load. Row order
    and content are unchanged -- this only inserts idle gaps into an
    otherwise tight loop. `chunk_rows`/`yield_seconds` default to the
    `GEOIP_LOAD_CHUNK_ROWS`/`GEOIP_LOAD_YIELD_SECONDS` module config (env-
    overridable) but are accepted as arguments so tests can exercise the
    chunk boundary without waiting on real sleeps."""
    chunk_rows = GEOIP_LOAD_CHUNK_ROWS if chunk_rows is None else chunk_rows
    yield_seconds = GEOIP_LOAD_YIELD_SECONDS if yield_seconds is None else yield_seconds
    count = 0
    for row in reader:
        yield row
        count += 1
        if chunk_rows and yield_seconds and count % chunk_rows == 0:
            time.sleep(yield_seconds)


class _CompactRangeTableBuilder:
    """Streams IPv4 start/end/extra-column rows directly into `array.array`
    columns of primitives while a GeoIP CSV is parsed, instead of buffering a
    Python list of millions of row tuples first and only compacting it
    afterwards (Issue #52 -- the previous `v4_rows`/`self._v4` staging lists
    were the primary suspect behind multi-GB peak RSS while loading a real
    multi-million-row DB-IP City Lite export).

    A real DB-IP Lite export is already sorted by start IP, so the common
    case is a single append-only pass with no extra buffering at all:
    `append()` tracks whether input stayed non-decreasing by start, and
    `finalize()` is a no-op when it did. If the input was *not* sorted,
    `finalize()` reorders the already-compact primitive columns via one
    index-permutation pass -- still bounded by primitive int/float memory,
    never a list of Python tuples/strings.
    """

    def __init__(self, extra_typecodes):
        self.start = array.array('Q')
        self.end = array.array('Q')
        self.extra = [array.array(tc) for tc in extra_typecodes]
        self._sorted = True
        self._last_start = -1

    def append(self, start, end, *extra_values):
        if start < self._last_start:
            self._sorted = False
        self._last_start = start
        self.start.append(start)
        self.end.append(end)
        for col, value in zip(self.extra, extra_values):
            col.append(value)

    def finalize(self):
        """Must be called once, after every row has been appended."""
        if self._sorted or len(self.start) <= 1:
            return
        order = sorted(range(len(self.start)), key=self.start.__getitem__)
        self.start = array.array('Q', (self.start[i] for i in order))
        self.end = array.array('Q', (self.end[i] for i in order))
        self.extra = [array.array(col.typecode, (col[i] for i in order)) for col in self.extra]


class GeoIPProvider:
    """Abstraction over a local/offline IP -> country lookup source, so the
    backing database can be swapped later without touching call sites."""

    def lookup(self, ip):
        """Return (country_code, country_name); (None, None) when unmapped."""
        raise NotImplementedError

    @property
    def available(self):
        return False

    @property
    def range_count(self):
        """Number of loaded IP ranges, when the provider has a concept of one."""
        return 0

    @property
    def path(self):
        """Configured backing file path, when the provider has one."""
        return None


class NullGeoIPProvider(GeoIPProvider):
    """No database configured: every address is honestly reported unmapped
    rather than a location being invented."""

    def lookup(self, ip):
        return None, None

    @property
    def available(self):
        return False


class CsvRangeGeoIPProvider(GeoIPProvider):
    """Loads `start_ip,end_ip,country_code,country_name` rows (one optional
    header row) into sorted per-address-family range tables and answers
    lookups with a binary search. See docs/GEOIP.md for the schema and how to
    build this file from a licensed offline GeoIP database.

    IPv4 ranges (the overwhelming majority of rows, even in a country-level
    database) are streamed directly into parallel fixed-width `array.array`
    columns via `_CompactRangeTableBuilder` -- 8-byte integer start/end keys
    plus a small integer index into an interned country-code/name table --
    rather than a Python list of millions of `(start, end, code, name)`
    tuples (Issue #52). IPv6 ranges are far fewer in a real export, so they
    stay a plain sorted list of tuples referencing the same interned table.
    """

    def __init__(self, path):
        self._path = path
        self._v4_start = array.array('Q')
        self._v4_end = array.array('Q')
        self._v4_country_idx = array.array('H')
        self._v6 = []  # sorted [(start_int, end_int, country_idx), ...]
        self._v6_starts = []
        self._countries = []  # [(country_code, country_name), ...], interned
        self._country_index = {}
        self._loaded = False
        self._load()

    def _intern_country(self, code, name):
        idx = self._country_index.get(code)
        if idx is None:
            idx = len(self._countries)
            self._countries.append((code, name))
            self._country_index[code] = idx
        return idx

    def _load(self):
        v4_builder = _CompactRangeTableBuilder(('H',))
        v6_rows = []
        try:
            with open(self._path, "r", encoding="utf-8", newline="") as f:
                for row in _iter_csv_rows_throttled(csv.reader(f)):
                    if not row or len(row) < 4:
                        continue
                    start_raw, end_raw, code, name = row[0].strip(), row[1].strip(), row[2].strip().upper(), row[3].strip()
                    if start_raw.lower() in ("start_ip", "start", "network_start"):
                        continue  # header row
                    try:
                        start_addr = ipaddress.ip_address(start_raw)
                        end_addr = ipaddress.ip_address(end_raw)
                    except ValueError:
                        continue
                    if start_addr.version != end_addr.version or not code:
                        continue
                    country_idx = self._intern_country(code, name or code)
                    if start_addr.version == 4:
                        v4_builder.append(int(start_addr), int(end_addr), country_idx)
                    else:
                        v6_rows.append((int(start_addr), int(end_addr), country_idx))
            v4_builder.finalize()
            self._v4_start = v4_builder.start
            self._v4_end = v4_builder.end
            self._v4_country_idx = v4_builder.extra[0]
            v6_rows.sort(key=lambda r: r[0])
            self._v6 = v6_rows
            self._v6_starts = [r[0] for r in v6_rows]
            self._loaded = bool(len(self._v4_start) or self._v6)
        except (OSError, csv.Error):
            self._loaded = False

    @property
    def available(self):
        return self._loaded

    @property
    def range_count(self):
        return len(self._v4_start) + len(self._v6)

    @property
    def path(self):
        return self._path

    def lookup(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None, None
        value = int(addr)
        if addr.version == 4:
            starts = self._v4_start
            if not starts:
                return None, None
            idx = bisect.bisect_right(starts, value) - 1
            if idx < 0 or not (starts[idx] <= value <= self._v4_end[idx]):
                return None, None
            return self._countries[self._v4_country_idx[idx]]
        if not self._v6:
            return None, None
        idx = bisect.bisect_right(self._v6_starts, value) - 1
        if idx < 0:
            return None, None
        start, end, country_idx = self._v6[idx]
        if start <= value <= end:
            return self._countries[country_idx]
        return None, None


class CityGeoIPProvider:
    """Abstraction over an optional local/offline IP -> city/coordinate lookup
    source (Issue #37 / 0.8.6). Entirely additive to and independent of
    `GeoIPProvider` above (the country-only lookup, which keeps working on
    its own regardless of whether a city database is configured)."""

    def lookup_city(self, ip):
        """Return a dict with country_code/country_name/city/lat/lon, or
        `None` when the address is unmapped. Must never invent a location --
        an address outside every loaded range returns `None`, not a country
        centroid standing in for a real coordinate."""
        raise NotImplementedError

    @property
    def available(self):
        return False

    @property
    def range_count(self):
        return 0

    @property
    def path(self):
        return None


class NullCityGeoIPProvider(CityGeoIPProvider):
    """No city-level database configured: Destinations mode must say
    coordinate data is unavailable rather than falling back to a country
    centroid pretending to be a city/IP location."""

    def lookup_city(self, ip):
        return None

    @property
    def available(self):
        return False


class CsvCityGeoIPProvider(CityGeoIPProvider):
    """Loads `start_ip,end_ip,country_code,country_name,city,latitude,longitude`
    rows (see docs/GEOIP.md -- the shape `scripts/convert_dbip_city_lite.py`
    produces from a DB-IP City Lite export) into a bounded, indexed runtime
    representation instead of a plain Python list of millions of per-row
    tuples/strings:

    - IPv4 ranges (the overwhelming majority of rows in a real city-level
      database, potentially several million) are stored as parallel
      fixed-width `array.array` columns -- 8-byte integer start/end keys,
      4-byte float lat/lon -- plus small integer indices into interned
      country/city string tables, so the (much smaller) set of distinct
      country/city names is only ever stored once each, not once per range
      row.
    - IPv6 ranges are far fewer in a real city export, so they stay a plain
      sorted list of tuples -- splitting a 128-bit range key across two
      64-bit array slots isn't worth the complexity at that row count.

    Lookup is a binary search (`bisect`) against a precomputed start-key
    sequence, the same approach `CsvRangeGeoIPProvider` uses for country
    ranges.
    """

    _HEADER_FIRST_COLUMNS = ("start_ip", "start", "network_start", "ip_start")

    def __init__(self, path):
        self._path = path
        self._v4_start = array.array('Q')
        self._v4_end = array.array('Q')
        self._v4_lat = array.array('f')
        self._v4_lon = array.array('f')
        self._v4_country_idx = array.array('H')
        self._v4_city_idx = array.array('I')
        self._v6 = []  # sorted [(start_int, end_int, country_code, country_name, city, lat, lon), ...]
        self._v6_starts = []
        self._countries = []  # [(country_code, country_name), ...], interned
        self._cities = []  # [city_name, ...], interned
        self._country_index = {}
        self._city_index = {}
        self._loaded = False
        self._load()

    def _intern_country(self, code, name):
        idx = self._country_index.get(code)
        if idx is None:
            idx = len(self._countries)
            self._countries.append((code, name))
            self._country_index[code] = idx
        return idx

    def _intern_city(self, city):
        idx = self._city_index.get(city)
        if idx is None:
            idx = len(self._cities)
            self._cities.append(city)
            self._city_index[city] = idx
        return idx

    def _load(self):
        # Streamed directly into compact `array.array` columns via
        # `_CompactRangeTableBuilder` (Issue #52) instead of buffering a
        # `v4_rows` list of millions of Python tuples before sorting it --
        # that temporary list was the primary suspect behind multi-GB peak
        # RSS while loading a real multi-million-row DB-IP City Lite export.
        v4_builder = _CompactRangeTableBuilder(('H', 'I', 'f', 'f'))
        try:
            with open(self._path, "r", encoding="utf-8", newline="") as f:
                for row in _iter_csv_rows_throttled(csv.reader(f)):
                    if not row or len(row) < 7:
                        continue
                    start_raw, end_raw = row[0].strip(), row[1].strip()
                    if start_raw.lower() in self._HEADER_FIRST_COLUMNS:
                        continue  # header row
                    code = row[2].strip().upper()
                    name = row[3].strip()
                    city = row[4].strip()
                    if not code:
                        continue
                    try:
                        start_addr = ipaddress.ip_address(start_raw)
                        end_addr = ipaddress.ip_address(end_raw)
                        lat = float(row[5])
                        lon = float(row[6])
                    except ValueError:
                        continue
                    if start_addr.version != end_addr.version:
                        continue
                    if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
                        continue
                    country_idx = self._intern_country(code, name or code)
                    city_idx = self._intern_city(city)
                    if start_addr.version == 4:
                        v4_builder.append(int(start_addr), int(end_addr), country_idx, city_idx, lat, lon)
                    else:
                        self._v6.append((int(start_addr), int(end_addr), code, name or code, city, lat, lon))
            v4_builder.finalize()
            self._v4_start = v4_builder.start
            self._v4_end = v4_builder.end
            self._v4_country_idx = v4_builder.extra[0]
            self._v4_city_idx = v4_builder.extra[1]
            self._v4_lat = v4_builder.extra[2]
            self._v4_lon = v4_builder.extra[3]
            self._v6.sort(key=lambda r: r[0])
            self._v6_starts = [r[0] for r in self._v6]
            self._loaded = bool(len(self._v4_start) or self._v6)
        except (OSError, csv.Error):
            self._loaded = False

    @property
    def available(self):
        return self._loaded

    @property
    def range_count(self):
        return len(self._v4_start) + len(self._v6)

    @property
    def path(self):
        return self._path

    def lookup_city(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        value = int(addr)
        if addr.version == 4:
            starts = self._v4_start
            if not starts:
                return None
            idx = bisect.bisect_right(starts, value) - 1
            if idx < 0 or not (starts[idx] <= value <= self._v4_end[idx]):
                return None
            code, name = self._countries[self._v4_country_idx[idx]]
            city = self._cities[self._v4_city_idx[idx]]
            return {
                "country_code": code, "country_name": name, "city": city or None,
                "lat": self._v4_lat[idx], "lon": self._v4_lon[idx],
            }
        if not self._v6:
            return None
        idx = bisect.bisect_right(self._v6_starts, value) - 1
        if idx < 0:
            return None
        start, end, code, name, city, lat, lon = self._v6[idx]
        if not (start <= value <= end):
            return None
        return {"country_code": code, "country_name": name, "city": city or None, "lat": lat, "lon": lon}


_geoip_provider = NullGeoIPProvider()
_geoip_cache = {}
_geoip_cache_order = deque()
_geoip_cache_lock = threading.Lock()

_geoip_city_provider = NullCityGeoIPProvider()
_geoip_city_cache = {}
_geoip_city_cache_order = deque()
_geoip_city_cache_lock = threading.Lock()

# GeoIP databases can contain millions of rows. They must never be parsed
# synchronously during module import: doing so blocks PID 1 from reaching the
# Flask server and makes a healthy container appear to hang at startup.
# Providers start as explicit Null providers and are replaced by the first
# background load once the application has started serving requests.
#
# Issue #51: a fixed clock delay before this load only ever proved that some
# amount of wall-clock time had passed, not that the HTTP server had actually
# managed to accept and answer a request -- real TrueNAS evidence showed the
# container reporting RUNNING with the socket bound while `/health` itself
# stayed unanswered for several more seconds once the deferred load started.
# `_first_response_ready` is set exactly once, by `_mark_first_response_ready()`
# (an `after_request` hook that fires for every response, success or error),
# the first time the HTTP service actually finishes serving something.
# `GEOIP_INITIAL_LOAD_DELAY_SECONDS` becomes a safety ceiling on that wait --
# still the same env var and default as before, but now only the fallback for
# an environment where nothing ever requests anything (e.g. no health
# checker configured at all), not the thing that gates every startup.
_first_response_ready = threading.Event()
_first_response_monotonic = None
GEOIP_INITIAL_LOAD_DELAY_SECONDS = max(
    0.0, float(os.getenv("GEOIP_INITIAL_LOAD_DELAY_SECONDS", "1"))
)

#: One-shot state for the deferred initial GeoIP load, surfaced via
#: `/api/observability` (`_startup_readiness_diagnostics()`) so "the process
#: is running" and "the HTTP service is ready" stay distinguishable there
#: too, not just internally to the wait gate above.
_geoip_initial_load_state_lock = threading.Lock()
_geoip_initial_load_state = {"started_at": None, "completed_at": None, "error": None}


@app.after_request
def _mark_first_response_ready(response):
    """Flip `_first_response_ready` the first time any response is actually
    sent -- proof the HTTP service can serve a request, not just that the
    process/socket exists. Cheap (an `Event` that's already set short-circuits
    immediately) so this stays negligible on every later request."""
    global _first_response_monotonic
    if not _first_response_ready.is_set():
        _first_response_monotonic = time.monotonic()
        _first_response_ready.set()
    return response


def _geoip_initial_load_worker():
    """Load persistent GeoIP databases after the web server startup path.

    The database files can be very large, especially DB-IP City Lite. Keeping
    construction off module import means PID 1 can bind the HTTP server and
    report healthy status immediately; the map remains temporarily unmapped
    until this one-time background load completes.

    Issue #51: this now waits for genuine proof of HTTP reachability
    (`_first_response_ready`) instead of guessing a fixed delay is enough --
    `GEOIP_INITIAL_LOAD_DELAY_SECONDS` bounds how long it will wait for that
    proof before proceeding anyway, so a deployment that never receives a
    single request still eventually gets a populated map.
    """
    served = _first_response_ready.wait(timeout=GEOIP_INITIAL_LOAD_DELAY_SECONDS)
    if not served:
        print(
            "GeoIP initial load: no HTTP response observed within "
            f"{GEOIP_INITIAL_LOAD_DELAY_SECONDS:.1f}s; proceeding without "
            "further delay.",
            flush=True,
        )

    country_present = os.path.exists(GEOIP_DB_PATH)
    city_present = os.path.exists(GEOIP_CITY_DB_PATH)
    if not country_present and not city_present:
        print("GeoIP initial load: no local databases found; keeping Null providers.", flush=True)
        return

    started = time.monotonic()
    with _geoip_initial_load_state_lock:
        _geoip_initial_load_state["started_at"] = started
    print(
        "GeoIP initial load: starting deferred background load "
        f"(country={country_present}, city={city_present})",
        flush=True,
    )
    try:
        _reload_geoip_providers()
        elapsed = time.monotonic() - started
        print(
            f"GeoIP initial load: complete in {elapsed:.1f}s",
            flush=True,
        )
        with _geoip_initial_load_state_lock:
            _geoip_initial_load_state["completed_at"] = time.monotonic()
    except Exception as e:
        print(
            f"GeoIP initial load error: keeping Null providers for now: {e!r}",
            flush=True,
        )
        with _geoip_initial_load_state_lock:
            _geoip_initial_load_state["completed_at"] = time.monotonic()
            _geoip_initial_load_state["error"] = repr(e)


def _startup_readiness_diagnostics():
    """Issue #51: makes "the process/container is running" and "the HTTP
    service has actually served a request" two distinguishable, observable
    facts instead of conflating them. `/health` deliberately stays a plain,
    fast, unconditional 200 -- this lives in `/api/observability` instead so
    nothing here can make `/health` itself slower or gate on GeoIP."""
    first_response_seconds = None
    if _first_response_ready.is_set() and _first_response_monotonic is not None:
        first_response_seconds = round(max(0.0, _first_response_monotonic - OBSERVABILITY_START_MONOTONIC), 3)
    with _geoip_initial_load_state_lock:
        state = dict(_geoip_initial_load_state)
    started_at = state["started_at"]
    completed_at = state["completed_at"]
    geoip_initial_load_seconds_after_start = (
        round(max(0.0, started_at - OBSERVABILITY_START_MONOTONIC), 3) if started_at is not None else None
    )
    geoip_initial_load_duration_seconds = (
        round(max(0.0, completed_at - started_at), 3)
        if started_at is not None and completed_at is not None
        else None
    )
    return {
        "http_ready": _first_response_ready.is_set(),
        "first_response_seconds_after_start": first_response_seconds,
        "geoip_initial_load_started": started_at is not None,
        "geoip_initial_load_complete": completed_at is not None,
        "geoip_initial_load_seconds_after_start": geoip_initial_load_seconds_after_start,
        "geoip_initial_load_duration_seconds": geoip_initial_load_duration_seconds,
        "geoip_initial_load_error": state["error"],
    }


def _geoip_diagnostics():
    """A small operator-facing snapshot of GeoIP provider state -- used by
    `/api/observability` and the one-time startup log line (see
    `_log_geoip_status`). Deliberately excludes the full configured path so a
    debug bundle/observability payload doesn't leak filesystem layout."""
    provider = _geoip_provider
    configured = bool(provider.available)
    path = provider.path
    return {
        "provider_type": type(provider).__name__,
        "configured": configured,
        "db_path_basename": os.path.basename(path) if configured and path else None,
        "range_count": provider.range_count if configured else 0,
    }


def _geoip_city_diagnostics():
    """Same shape as `_geoip_diagnostics()`, for the optional coordinate/city
    provider -- kept as a separate snapshot since a deployment can have
    either, both, or neither of the country and city databases configured."""
    provider = _geoip_city_provider
    configured = bool(provider.available)
    path = provider.path
    return {
        "provider_type": type(provider).__name__,
        "configured": configured,
        "db_path_basename": os.path.basename(path) if configured and path else None,
        "range_count": provider.range_count if configured else 0,
    }


def _log_geoip_status():
    """Log GeoIP provider state once at startup -- never per-query."""
    diag = _geoip_diagnostics()
    if diag["configured"]:
        print(
            f"GeoIP: {diag['provider_type']} loaded {diag['range_count']} ranges "
            f"from {diag['db_path_basename']}",
            flush=True,
        )
    else:
        print(
            "GeoIP: no database configured (NullGeoIPProvider) -- the destination "
            "map will honestly report 0% geolocated until GEOIP_DB_PATH points at "
            "a loaded CSV database. See docs/GEOIP.md.",
            flush=True,
        )
    city_diag = _geoip_city_diagnostics()
    if city_diag["configured"]:
        print(
            f"GeoIP city: {city_diag['provider_type']} loaded {city_diag['range_count']} "
            f"ranges from {city_diag['db_path_basename']} -- Destinations mode available",
            flush=True,
        )
    else:
        print(
            "GeoIP city: no coordinate/city database configured -- Destinations mode "
            "will report coordinate-level data as unavailable until GEOIP_CITY_DB_PATH "
            "points at a loaded CSV database. See docs/GEOIP.md.",
            flush=True,
        )


def _trim_allocator_memory():
    """Best-effort secondary mitigation only (Issue #52's required direction
    explicitly rules this out as *the* fix): after a GeoIP provider swap, the
    old provider's `array.array` columns/interned string tables are garbage,
    but glibc's allocator does not always return freed heap memory to the OS
    on its own, which can leave process RSS sitting at a high watermark even
    once the compact-storage redesign above has already cut the actual live
    footprint. `gc.collect()` clears any reference cycles immediately instead
    of waiting for a generational sweep; `malloc_trim(0)` (Linux glibc only)
    then asks the allocator to release freed arenas back to the OS. Both are
    no-ops if there is nothing to reclaim, and any failure (non-glibc libc,
    non-Linux platform) is silently ignored -- this must never raise."""
    gc.collect()
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6")
        libc.malloc_trim(0)
    except Exception:
        pass


def _reload_geoip_providers():
    """Reconstruct the country/city GeoIP providers from whatever is on disk
    right now and swap them in, so a completed auto-update (or a manually
    replaced file) takes effect without restarting the process. Also clears
    the per-IP lookup caches, since they may hold answers resolved against
    the previous database. Safe to call at any time -- the previous provider
    instances simply become unreferenced once every in-flight lookup that
    already grabbed them returns.

    The two providers are constructed and swapped in one at a time (not both
    built up-front) so the old provider plus a second full provider are never
    both required to be memory-resident for longer than necessary; each
    provider's own `_load()` (see `CsvRangeGeoIPProvider`/`CsvCityGeoIPProvider`)
    already streams its CSV into compact storage without ever staging the
    whole database as Python row objects (Issue #52)."""
    global _geoip_provider, _geoip_city_provider
    new_country = CsvRangeGeoIPProvider(GEOIP_DB_PATH) if os.path.exists(GEOIP_DB_PATH) else NullGeoIPProvider()
    with _geoip_cache_lock:
        _geoip_provider = new_country
        _geoip_cache.clear()
        _geoip_cache_order.clear()
    del new_country
    new_city = CsvCityGeoIPProvider(GEOIP_CITY_DB_PATH) if os.path.exists(GEOIP_CITY_DB_PATH) else NullCityGeoIPProvider()
    with _geoip_city_cache_lock:
        _geoip_city_provider = new_city
        _geoip_city_cache.clear()
        _geoip_city_cache_order.clear()
    del new_city
    _trim_allocator_memory()
    _log_geoip_status()


def _geoip_update_diagnostics():
    """Operator-facing snapshot of the automatic updater's state, used by
    `/api/observability` -- the durable, per-target facts (last check,
    current release, last success/error) come straight from
    `geoip_updater.load_state()`; `in_progress`/`next_scheduled_run_at` are
    in-memory-only, set by `_run_geoip_update_pass()`/`geoip_auto_update_worker()`.
    `status` (Issue #44) gives a single at-a-glance value distinguishing
    "disabled", "scheduled" (waiting for its next window) and "in_progress"
    -- `in_progress` itself is guaranteed to clear again (see
    `_run_geoip_update_pass()`'s `finally`), so it can never be stuck at
    `true` forever."""
    state = geoip_updater.load_state(_GEOIP_UPDATE_CONFIG.state_path)
    targets = {}
    for target in ("country", "city"):
        entry = dict(state[target])
        entry["next_check_at"] = geoip_updater.next_check_iso(entry.get("last_checked_ok_at"), _GEOIP_UPDATE_CONFIG.interval_days)
        targets[target] = entry
    status = "in_progress" if _geoip_update_in_progress else ("scheduled" if GEOIP_AUTO_UPDATE else "disabled")
    return {
        "auto_update_enabled": GEOIP_AUTO_UPDATE,
        "interval_days": _GEOIP_UPDATE_CONFIG.interval_days,
        "schedule": {
            "hour": GEOIP_AUTO_UPDATE_HOUR,
            "minute": GEOIP_AUTO_UPDATE_MINUTE,
            "timezone": GEOIP_AUTO_UPDATE_TIMEZONE_NAME,
        },
        "status": status,
        "in_progress": _geoip_update_in_progress,
        "next_scheduled_run_at": _geoip_next_scheduled_run_at,
        **targets,
    }


def _geoip_updater_cli_command():
    """The subprocess command `_run_geoip_update_pass()` runs for one
    check/update pass (Issue #44). Isolating the heavy download/convert work
    in a child process means a multi-hundred-thousand-row City Lite
    conversion can never contend with Flask's own request-handling threads
    for the GIL, and -- unlike the previous same-process daemon thread
    (0.8.5.5/0.8.5.6), which the watchdog could time out but never actually
    stop -- a child that hangs past the watchdog timeout can be terminated
    outright (`_terminate_geoip_subprocess()`). This runs the exact same CLI
    entry point (`scripts/geoip_updater.py`) the manual one-shot workflow
    already uses, so it reads the identical `GEOIP_*`/`GEOIP_UPDATE_*`
    environment variables (inherited automatically -- this is a plain
    subprocess, not a shell) via `geoip_updater.build_config_from_env()`;
    there is no second, drifting configuration path."""
    return [sys.executable, os.path.join(BASE_DIR, "scripts", "geoip_updater.py")]


def _terminate_geoip_subprocess(proc):
    """Best-effort clean shutdown of a hung updater child: SIGTERM, then
    SIGKILL if it hasn't exited after a short grace period. Always reaps the
    process (via `communicate()`) afterwards so it never becomes a zombie."""
    try:
        proc.terminate()
        proc.communicate(timeout=10)
        return
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        return
    try:
        proc.kill()
        proc.communicate(timeout=5)
    except Exception:
        pass


def _run_geoip_update_pass(command=None, timeout=None):
    """Run exactly one watchdog-guarded check/update pass and update
    `_geoip_update_in_progress` accordingly. Split out from
    `geoip_auto_update_worker()`'s scheduling loop so a single pass is
    directly callable from tests (Issue #43) without looping or sleeping.

    Issue #44: the actual check/download/convert work now runs in a
    subprocess (`_geoip_updater_cli_command()`) rather than an in-process
    daemon thread, so `GEOIP_AUTO_UPDATE_WATCHDOG_SECONDS` is enforced via
    `Popen.communicate(timeout=...)` and a hung child is actually killed
    (`_terminate_geoip_subprocess()`) -- the parent Flask process can never
    be starved by a stuck decompress/convert, and no leaked thread
    accumulates inside it across repeated timeouts. `command`/`timeout` are
    overridable so tests can exercise a deliberately hanging or failing
    child without a real network-backed run.
    """
    global _geoip_update_in_progress
    command = list(command) if command is not None else _geoip_updater_cli_command()
    if timeout is None:
        timeout = GEOIP_AUTO_UPDATE_WATCHDOG_SECONDS
    with _geoip_update_lock:
        _geoip_update_in_progress = True
    print("GeoIP auto-update: starting scheduled check/update pass", flush=True)
    before_state = geoip_updater.load_state(_GEOIP_UPDATE_CONFIG.state_path)
    try:
        try:
            proc = subprocess.Popen(
                command, cwd=BASE_DIR, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
        except OSError as e:
            print(f"GeoIP auto-update error: failed to launch updater subprocess: {e}", flush=True)
            return
        try:
            stdout, _ = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            print(
                f"GeoIP auto-update error: child pid={proc.pid} exceeded "
                f"GEOIP_AUTO_UPDATE_WATCHDOG_SECONDS={timeout}s -- terminating it so the "
                f"parent stays healthy; will retry at the next scheduled window", flush=True,
            )
            _terminate_geoip_subprocess(proc)
            geoip_updater.mark_stuck_checks_as_timed_out(_GEOIP_UPDATE_CONFIG.state_path)
            return
        for line in (stdout or "").splitlines():
            print(f"GeoIP auto-update: {line}", flush=True)
        if proc.returncode != 0:
            print(f"GeoIP auto-update: child exited with status {proc.returncode}", flush=True)
        print("GeoIP auto-update: scheduled check/update pass complete", flush=True)
        after_state = geoip_updater.load_state(_GEOIP_UPDATE_CONFIG.state_path)
        if any(
            after_state[t].get("current_release") != before_state[t].get("current_release")
            for t in ("country", "city")
        ):
            _reload_geoip_providers()
    finally:
        with _geoip_update_lock:
            _geoip_update_in_progress = False


def _geoip_sleep(seconds):
    """Thin wrapper around `time.sleep` so tests can intercept the
    scheduler's wait for the next window without a real multi-hour sleep."""
    time.sleep(seconds)


def geoip_auto_update_worker():
    """Background worker (Issue #42/0.8.5.5; rescheduled in Issue #44/0.8.5.7):
    sleeps until the next configured daily maintenance window
    (`GEOIP_AUTO_UPDATE_HOUR`:`GEOIP_AUTO_UPDATE_MINUTE` in
    `GEOIP_AUTO_UPDATE_TIMEZONE`, default 03:00 UTC) and only then runs a
    single watchdog-guarded check/update pass (`_run_geoip_update_pass()`).
    It deliberately never runs a pass at thread startup -- a missing state
    file must not mean "download now" -- so a fresh deployment's first-ever
    DB-IP Lite Country/City Lite download (hundreds of megabytes, ~7.75M
    City Lite rows) never competes with the application becoming healthy.

    A real network check against DB-IP still only happens once
    `GEOIP_UPDATE_INTERVAL_DAYS` (default 30) has elapsed since a target's
    last non-error check (`geoip_updater._is_check_due()`); this schedule
    only controls *when* that cheap, local, no-network gate gets
    re-evaluated -- once a day, not hourly, and with no network polling at
    all in between.
    """
    global _geoip_next_scheduled_run_at
    if not GEOIP_AUTO_UPDATE:
        print("GeoIP auto-update: disabled (GEOIP_AUTO_UPDATE=false). Enable it or run scripts/geoip_updater.py manually. See docs/GEOIP.md.", flush=True)
        return
    tz, tz_warning = geoip_updater.resolve_auto_update_timezone(GEOIP_AUTO_UPDATE_TIMEZONE_NAME)
    if tz_warning:
        print(f"GeoIP auto-update: {tz_warning}", flush=True)
    print(
        f"GeoIP auto-update: scheduled for {GEOIP_AUTO_UPDATE_HOUR:02d}:{GEOIP_AUTO_UPDATE_MINUTE:02d} "
        f"{GEOIP_AUTO_UPDATE_TIMEZONE_NAME} daily -- a real DB-IP check only happens per target once "
        f"GEOIP_UPDATE_INTERVAL_DAYS={_GEOIP_UPDATE_CONFIG.interval_days} have elapsed since its last "
        f"non-error check.", flush=True,
    )
    while True:
        now = datetime.now(tz)
        next_run = geoip_updater.next_scheduled_run(now, GEOIP_AUTO_UPDATE_HOUR, GEOIP_AUTO_UPDATE_MINUTE)
        sleep_seconds = max(0.0, (next_run - now).total_seconds())
        with _geoip_update_lock:
            _geoip_next_scheduled_run_at = next_run.isoformat()
        print(
            f"GeoIP auto-update: next scheduled window at {next_run.isoformat()} "
            f"(sleeping ~{sleep_seconds:.0f}s)", flush=True,
        )
        _geoip_sleep(sleep_seconds)
        _run_geoip_update_pass()


# GeoIP diagnostic state machine (Issue #39 / 0.8.5.4): a single map-payload
# diagnostic must let an operator tell "nothing is configured" apart from
# "it's configured but broken" apart from "it's working but there's nothing to
# show yet" without grepping container logs. `geoip_map_payload()` computes
# the state from data it already has (provider identity/availability plus the
# same observation/coverage counters it aggregates) rather than adding a
# second code path; the UI picks one of these six banners instead of the old
# single configured/not-configured boolean.
GEOIP_DIAGNOSTIC_MESSAGES = {
    "not_configured": (
        "No GeoIP database configured — destinations are reported as "
        "unmapped rather than guessed. See docs/GEOIP.md to enable the map."
    ),
    "load_failed": (
        "GEOIP_DB_PATH is set, but the configured database failed to load. "
        "Check that the file exists at that path inside the container and is "
        "readable, then restart. See docs/GEOIP.md."
    ),
    "no_public_destinations": (
        "GeoIP database loaded, but no observed public destination IPs have "
        "been recorded yet. This fills in as domains are queried."
    ),
    "no_country_matches": (
        "Observed public destination IPs exist, but none matched a range in "
        "the loaded GeoIP database. Double-check the database covers the "
        "address families you expect (IPv4/IPv6) and is current."
    ),
    "country_only": (
        "Country-level geolocation is working. Configure a city/coordinate "
        "database (GEOIP_CITY_DB_PATH) to enable Destinations mode. See "
        "docs/GEOIP.md."
    ),
    "partial_coordinate_coverage": (
        "Country-level geolocation is working, but the configured city/"
        "coordinate database does not yet cover the observed destination "
        "IPs."
    ),
    "full_coverage": (
        "GeoIP is fully configured: country and coordinate-level destination "
        "data are both available."
    ),
}


def _geoip_diagnostic_state(total_observations, geolocated_observations, city_capable, destination_point_count):
    """Return one of `GEOIP_DIAGNOSTIC_MESSAGES`' keys for the current
    provider/observation state. Never makes a network request or a second
    database read -- every input is already computed by the caller."""
    if not _geoip_provider.available:
        # `_geoip_provider` is a `NullGeoIPProvider` only when `GEOIP_DB_PATH`
        # didn't exist at startup (see its construction below); any other
        # unavailable provider means a configured path failed to parse.
        return "not_configured" if isinstance(_geoip_provider, NullGeoIPProvider) else "load_failed"
    if total_observations == 0:
        return "no_public_destinations"
    if geolocated_observations == 0:
        return "no_country_matches"
    if not city_capable:
        return "country_only"
    if destination_point_count == 0:
        return "partial_coordinate_coverage"
    return "full_coverage"


def geoip_lookup(ip):
    """Cached local GeoIP lookup for a single already-normalized public IP.
    Bounded FIFO cache -- this is a CPU-only local lookup (never a network
    request), but the cache still keeps repeated map aggregation cheap."""
    with _geoip_cache_lock:
        cached = _geoip_cache.get(ip)
        if cached is not None:
            return cached
    code, name = _geoip_provider.lookup(ip)
    result = {"country_code": code, "country_name": name}
    with _geoip_cache_lock:
        if ip not in _geoip_cache:
            _geoip_cache[ip] = result
            _geoip_cache_order.append(ip)
            while len(_geoip_cache_order) > GEOIP_CACHE_MAX_ENTRIES:
                _geoip_cache.pop(_geoip_cache_order.popleft(), None)
    return result


def geoip_city_lookup(ip):
    """Cached local city/coordinate GeoIP lookup for a single already-
    normalized public IP. Returns `None` when unmapped or when no city
    database is configured -- callers must not substitute a country centroid
    for a missing result. Cache entries store `None` results too (a `None`
    lookup is still worth remembering), so presence is checked with `in`
    rather than truthiness."""
    with _geoip_city_cache_lock:
        if ip in _geoip_city_cache:
            return _geoip_city_cache[ip]
    result = _geoip_city_provider.lookup_city(ip)
    with _geoip_city_cache_lock:
        if ip not in _geoip_city_cache:
            _geoip_city_cache[ip] = result
            _geoip_city_cache_order.append(ip)
            while len(_geoip_city_cache_order) > GEOIP_CITY_CACHE_MAX_ENTRIES:
                _geoip_city_cache.pop(_geoip_city_cache_order.popleft(), None)
    return result


_geoip_map_cache = {"at": 0.0, "data": None}
_geoip_map_cache_lock = threading.Lock()


def geoip_map_payload():
    """Aggregate observed DNS destinations by GeoIP country.

    Reuses `domains.clients_json` and `domain_destination_ips` -- the real
    A/AAAA answers AdGuard returned for each query, captured at ingestion
    time (see `_record_domain_destination_ips`) -- so the map represents
    actually-observed destinations, not an independently re-resolved
    snapshot. Each destination IP contributes its own observation count to
    its country, rather than a domain's whole query volume being attributed
    to a single arbitrarily-chosen IP; a multi-A/AAAA/CDN domain can
    therefore appear in more than one country. No synchronous resolution and
    no new per-query network work is added to ingestion. Bounded by
    `GEOIP_MAP_DOMAIN_LIMIT` and short-TTL cached by `GEOIP_MAP_CACHE_SECONDS`
    so repeated polling stays cheap.
    """
    now = time.time()
    with _geoip_map_cache_lock:
        cached = _geoip_map_cache["data"]
        if cached is not None and now - _geoip_map_cache["at"] < GEOIP_MAP_CACHE_SECONDS:
            return cached

    with closing(sqlite3.connect(DB_PATH)) as c:
        domain_rows = c.execute(
            "SELECT domain, clients_json FROM domains "
            "WHERE requests > 0 ORDER BY last_seen DESC LIMIT ?",
            (GEOIP_MAP_DOMAIN_LIMIT,),
        ).fetchall()
        destination_rows = c.execute(
            "SELECT di.domain, di.ip, di.observations FROM domain_destination_ips di "
            "JOIN (SELECT domain FROM domains WHERE requests > 0 ORDER BY last_seen DESC LIMIT ?) lim "
            "ON lim.domain = di.domain",
            (GEOIP_MAP_DOMAIN_LIMIT,),
        ).fetchall()
        device_labels = {
            row[0]: row[1]
            for row in c.execute(
                "SELECT device_key, COALESCE(NULLIF(hostname,''), NULLIF(name,''), NULLIF(vendor,''), device_key) FROM devices"
            ).fetchall()
        }

    destinations_by_domain = {}
    for domain, ip, observations in destination_rows:
        destinations_by_domain.setdefault(domain, []).append((ip, int(observations or 0)))

    countries = {}
    # Coordinate destination points (Issue #37 / 0.8.6), keyed by observed IP
    # so a domain answering the same destination IP as another domain still
    # produces one point with a combined observation/domain count, rather
    # than one point per (domain, ip) pair. Only populated when a city/
    # coordinate provider is actually configured -- see `capabilities` below;
    # a country-only deployment never reaches `geoip_city_lookup()` at all,
    # so Destinations mode has nothing invented to show.
    destination_points = {}
    city_capable = bool(_geoip_city_provider.available)
    unknown_domains = unknown_observations = 0
    geolocated_domains = geolocated_observations = 0
    total_domains = len(domain_rows)
    total_observations = 0

    for domain, clients_json in domain_rows:
        try:
            clients = json.loads(clients_json or "{}")
        except (TypeError, ValueError):
            clients = {}
        destinations = destinations_by_domain.get(domain, [])
        domain_geolocated = False
        domain_unmatched_observations = 0
        for ip, observations in destinations:
            total_observations += observations
            result = geoip_lookup(ip)
            code, name = result["country_code"], result["country_name"]
            if not code:
                domain_unmatched_observations += observations
            else:
                domain_geolocated = True
                geolocated_observations += observations
                bucket = countries.setdefault(code, {
                    "country_name": name or code,
                    "domain_keys": set(), "observation_count": 0,
                    "sample_domains": {}, "device_keys": set(), "ip_keys": set(),
                })
                bucket["observation_count"] += observations
                bucket["domain_keys"].add(domain)
                bucket["sample_domains"][domain] = bucket["sample_domains"].get(domain, 0) + observations
                bucket["device_keys"].update(clients.keys())
                bucket["ip_keys"].add(ip)
            if city_capable:
                city_result = geoip_city_lookup(ip)
                if city_result:
                    point = destination_points.setdefault(ip, {
                        "country_code": city_result["country_code"],
                        "country_name": city_result["country_name"],
                        "city": city_result["city"],
                        "lat": city_result["lat"], "lon": city_result["lon"],
                        "observation_count": 0, "domain_keys": set(), "sample_domains": {},
                    })
                    point["observation_count"] += observations
                    point["domain_keys"].add(domain)
                    point["sample_domains"][domain] = point["sample_domains"].get(domain, 0) + observations
        if domain_geolocated:
            geolocated_domains += 1
        else:
            unknown_domains += 1
            unknown_observations += domain_unmatched_observations

    country_list = []
    for code, bucket in countries.items():
        top_domains = sorted(bucket["sample_domains"].items(), key=lambda kv: -kv[1])[:5]
        country_list.append({
            "country_code": code,
            "country_name": bucket["country_name"],
            "domain_count": len(bucket["domain_keys"]),
            "observation_count": bucket["observation_count"],
            "device_count": len(bucket["device_keys"]),
            "unique_ip_count": len(bucket["ip_keys"]),
            "sample_domains": [d for d, _ in top_domains],
            "sample_devices": [device_labels.get(k, k) for k in list(bucket["device_keys"])[:5]],
            "centroid": COUNTRY_CENTROIDS.get(code),
        })
    country_list.sort(key=lambda c: -c["observation_count"])

    # Bounded to GEOIP_MAP_DESTINATION_POINTS_LIMIT for payload/render size --
    # a rendering cap only; `coverage` above is computed over every observed
    # destination regardless of how many individual points are returned here,
    # so capping this list never distorts the honestly-reported percentages.
    destination_list = []
    for ip, point in destination_points.items():
        top_domains = sorted(point["sample_domains"].items(), key=lambda kv: -kv[1])[:5]
        destination_list.append({
            "ip": ip,
            "country_code": point["country_code"],
            "country_name": point["country_name"],
            "city": point["city"],
            "lat": point["lat"],
            "lon": point["lon"],
            "observation_count": point["observation_count"],
            "domain_count": len(point["domain_keys"]),
            "sample_domains": [d for d, _ in top_domains],
        })
    destination_list.sort(key=lambda d: -d["observation_count"])
    destination_list = destination_list[:GEOIP_MAP_DESTINATION_POINTS_LIMIT]

    diagnostic_state = _geoip_diagnostic_state(
        total_observations, geolocated_observations, city_capable, len(destination_list),
    )

    payload = {
        "updated": utcnow(),
        # 0.8.5.4: no longer leaks the full configured `GEOIP_DB_PATH` -- only
        # the basename, same as `_geoip_diagnostics()` already does for
        # `/api/observability` (see docs/GEOIP.md).
        "provider": {
            "configured": _geoip_provider.available,
            "db_path_basename": os.path.basename(_geoip_provider.path) if _geoip_provider.available and _geoip_provider.path else None,
            "range_count": _geoip_provider.range_count if _geoip_provider.available else 0,
        },
        "countries": country_list,
        "destinations": destination_list,
        "unknown": {"domain_count": unknown_domains, "observation_count": unknown_observations},
        "coverage": {
            "total_domains": total_domains, "geolocated_domains": geolocated_domains,
            "total_observations": total_observations, "geolocated_observations": geolocated_observations,
            "geolocated_pct": round((geolocated_observations / total_observations) * 100, 1) if total_observations else 0.0,
        },
        "capabilities": {
            "country": bool(_geoip_provider.available),
            "coordinates": city_capable,
            "heatmap": False,
        },
        # Six-state diagnostic (Issue #39): lets the UI distinguish "not
        # configured" from "configured but broken" from "working but nothing
        # to show yet" without container log access.
        "diagnostics": {
            "state": diagnostic_state,
            "message": GEOIP_DIAGNOSTIC_MESSAGES[diagnostic_state],
            "country": _geoip_diagnostics(),
            "city": _geoip_city_diagnostics(),
        },
    }
    with _geoip_map_cache_lock:
        _geoip_map_cache["data"] = payload
        _geoip_map_cache["at"] = now
    return payload


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
    domains = "".join(f"<tr><td><a href='/search?q={quote(x['domain'], safe='')}' title='Inspect domain in DNS Inspector'>{_html(x['domain'])}</a></td><td>{x['requests']}</td><td class='mono'>{_html(x['last_seen'])}</td></tr>" for x in d['domains']) or "<tr><td colspan='3' class='empty-state'>No domain activity recorded.</td></tr>"
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
    devices = ''.join(device_rows) or "<tr><td colspan='3' class='empty-state'>No known device mapping.</td></tr>"
    domains = "".join(f"<tr><td><a href='/search?q={quote(x['domain'], safe='')}' title='Inspect domain in DNS Inspector'>{_html(x['domain'])}</a></td><td>{x['requests']}</td><td class='mono'>{_html(x['last_seen'])}</td></tr>" for x in d['domains']) or "<tr><td colspan='3' class='empty-state'>No DNS activity recorded.</td></tr>"
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


# --- Analytics: live activity and historical trends ---------------------
#
# These read from data the ingestion pipeline already persists (query
# fingerprints with timestamps in `processed_queries`, `first_seen`/
# `last_seen` on `domains` and `devices`). No new sampling pipeline or
# time-series storage is introduced; history is only as deep as what is
# already retained (`processed_queries` is capped at 100k rows, see
# `ingest()`), and buckets older than the oldest retained row are reported
# as `None` rather than a fabricated zero.

ANALYTICS_RANGE_OPTIONS = ["1h", "6h", "24h", "7d"]
ANALYTICS_LIVE_WINDOW_SECONDS = 60
ANALYTICS_ACTIVE_DEVICE_WINDOW_SECONDS = 300

_ANALYTICS_RANGES = {
    "1h": (3600, 60, 60, "Last hour"),
    "6h": (21600, 300, 72, "Last 6 hours"),
    "24h": (86400, 900, 96, "Last 24 hours"),
    "7d": (604800, 7200, 84, "Last 7 days"),
}


def _analytics_range(range_key):
    return _ANALYTICS_RANGES.get(range_key, _ANALYTICS_RANGES["1h"])


def _parse_iso(value):
    try:
        dt = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _bucket_timestamps(timestamps, range_seconds, bucket_seconds, bucket_count, now_dt):
    buckets = [0] * bucket_count
    start = now_dt - timedelta(seconds=range_seconds)
    for raw in timestamps:
        dt = _parse_iso(raw)
        if dt is None:
            continue
        offset = (dt - start).total_seconds()
        if offset < 0:
            continue
        idx = int(offset // bucket_seconds)
        if 0 <= idx < bucket_count:
            buckets[idx] += 1
    return [{"t": (start + timedelta(seconds=i * bucket_seconds)).isoformat(), "count": buckets[i]} for i in range(bucket_count)]


def get_query_volume_series(range_key):
    range_seconds, bucket_seconds, bucket_count, label = _analytics_range(range_key)
    now_dt = datetime.now(timezone.utc)
    start = now_dt - timedelta(seconds=range_seconds)
    with closing(sqlite3.connect(DB_PATH)) as c:
        min_seen_at = c.execute("SELECT MIN(seen_at) FROM processed_queries").fetchone()[0]
        rows = c.execute("SELECT seen_at FROM processed_queries WHERE seen_at>=? ORDER BY seen_at ASC", (start.isoformat(),)).fetchall()
    points = _bucket_timestamps([r[0] for r in rows], range_seconds, bucket_seconds, bucket_count, now_dt)
    min_dt = _parse_iso(min_seen_at)
    for point in points:
        bucket_end = _parse_iso(point["t"]) + timedelta(seconds=bucket_seconds)
        if min_dt is None or bucket_end <= min_dt:
            point["count"] = None
    return {"range": range_key, "label": label, "bucket_seconds": bucket_seconds, "points": points}


def _first_seen_series(table, range_key):
    if table not in ("domains", "devices"):
        raise ValueError("unsupported table for first-seen series")
    range_seconds, bucket_seconds, bucket_count, label = _analytics_range(range_key)
    now_dt = datetime.now(timezone.utc)
    start = now_dt - timedelta(seconds=range_seconds)
    with closing(sqlite3.connect(DB_PATH)) as c:
        rows = c.execute(f"SELECT first_seen FROM {table} WHERE first_seen>=? AND first_seen<>''", (start.isoformat(),)).fetchall()
    points = _bucket_timestamps([r[0] for r in rows], range_seconds, bucket_seconds, bucket_count, now_dt)
    return {"range": range_key, "label": label, "bucket_seconds": bucket_seconds, "points": points}


def get_new_domains_series(range_key):
    return _first_seen_series("domains", range_key)


def get_new_devices_series(range_key):
    return _first_seen_series("devices", range_key)


def get_status_breakdown():
    with closing(sqlite3.connect(DB_PATH)) as c:
        row = c.execute("SELECT SUM(CASE WHEN blocked_requests=0 AND allowed_requests=0 THEN 1 ELSE 0 END), SUM(CASE WHEN blocked_requests=0 AND allowed_requests>0 THEN 1 ELSE 0 END), SUM(CASE WHEN blocked_requests>0 AND allowed_requests=0 THEN 1 ELSE 0 END), SUM(CASE WHEN blocked_requests>0 AND allowed_requests>0 THEN 1 ELSE 0 END), COUNT(*) FROM domains").fetchone()
    unknown, allowed, blocked, mixed, total = (int(v or 0) for v in row)
    return {"Unknown": unknown, "Allowed": allowed, "Blocked": blocked, "Mixed": mixed, "All": total}


def get_recent_activity(limit=12):
    with closing(sqlite3.connect(DB_PATH)) as c:
        domain_rows = c.execute("SELECT domain,last_seen,current_status,requests FROM domains ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall()
        device_rows = c.execute("SELECT device_key,COALESCE(NULLIF(hostname,''),NULLIF(name,''),NULLIF(vendor,''),device_key),last_seen,request_count FROM devices ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall()
    domains = [{"domain": d, "last_seen": ls, "status": st or "Unknown", "requests": int(r or 0)} for d, ls, st, r in domain_rows]
    devices = [{"device_key": k, "label": label, "last_seen": ls, "requests": int(r or 0)} for k, label, ls, r in device_rows]
    return {"domains": domains, "devices": devices}


def _analytics_live_snapshot(window_seconds=ANALYTICS_LIVE_WINDOW_SECONDS):
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    with closing(sqlite3.connect(DB_PATH)) as c:
        count = int(c.execute("SELECT COUNT(*) FROM processed_queries WHERE seen_at>=?", (cutoff,)).fetchone()[0] or 0)
    return {"updated": utcnow(), "window_seconds": window_seconds, "queries_in_window": count}


def _active_devices_count(window_seconds=ANALYTICS_ACTIVE_DEVICE_WINDOW_SECONDS):
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    with closing(sqlite3.connect(DB_PATH)) as c:
        return int(c.execute("SELECT COUNT(*) FROM devices WHERE last_seen>=?", (cutoff,)).fetchone()[0] or 0)


def _total_devices_count():
    """Every known device, regardless of recency. This is the denominator for
    the "active devices" gauge's min/max range -- `active_devices` alone has
    no scale of its own."""
    with closing(sqlite3.connect(DB_PATH)) as c:
        return int(c.execute("SELECT COUNT(*) FROM devices").fetchone()[0] or 0)


def analytics_payload(range_key="1h"):
    if range_key not in ANALYTICS_RANGE_OPTIONS:
        range_key = "1h"
    cutoff_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    with closing(sqlite3.connect(DB_PATH)) as c:
        new_domains_24h = int(c.execute("SELECT COUNT(*) FROM domains WHERE first_seen>=?", (cutoff_24h,)).fetchone()[0] or 0)
    activity = get_recent_activity()
    return {
        "updated": utcnow(),
        "range": range_key,
        "range_options": ANALYTICS_RANGE_OPTIONS,
        "series": {
            "queries": get_query_volume_series(range_key),
            "new_domains": get_new_domains_series(range_key),
            "new_devices": get_new_devices_series(range_key),
        },
        "status_breakdown": get_status_breakdown(),
        "recent_domains": activity["domains"],
        "recent_devices": activity["devices"],
        "active_devices": _active_devices_count(),
        "total_devices": _total_devices_count(),
        "new_domains_24h": new_domains_24h,
        "live": _analytics_live_snapshot(),
    }


def state_payload(q="",status_filter="",new_only=False,classification_filter="",severity_filter="",device_filter="",vendor_filter="",page=1,page_size=50):
    result=inspect_domain(q) if q else None
    recent=get_recent(page=page,page_size=page_size,status_filter=status_filter,new_only=new_only,classification_filter=classification_filter,severity_filter=severity_filter,device_filter=device_filter,vendor_filter=vendor_filter)
    uptime = _observability_uptime_seconds()
    return {"updated":utcnow(),"recent":recent["rows"],"recent_meta":recent["meta"],"filter_options":get_filter_options(),"clients":get_clients(),"stats":get_stats(),"inspect_html":inspect_html(result) if result else None,"observability":{"uptime_seconds":round(uptime,1),"uptime_human":_observability_uptime_human(uptime),"ram_mb":_observability_rss_mb()},"live":_analytics_live_snapshot()}

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
        return jsonify({"updated":utcnow(),"recent":[],"recent_meta":{"page":1,"pages":1,"total":0,"page_size":50,"new_count":0,"new_domains":[],"status_counts":{}},"filter_options":get_filter_options(),"clients":get_clients(),"stats":get_stats(),"inspect_html":None,"live":{"updated":utcnow(),"window_seconds":ANALYTICS_LIVE_WINDOW_SECONDS,"queries_in_window":0},"error":str(e)}),200


# `/api/analytics` covers historical trends and the status/activity breakdown.
# The live queries-per-window counter deliberately rides the existing
# `/api/state` refresh loop above (see `state_payload`) instead of a second
# polling loop, per the "Analytics Live Activity" note in ROADMAP.md.
@app.route("/api/analytics")
def api_analytics():
    range_key = request.args.get("range", "1h").strip() or "1h"
    try:
        return jsonify(analytics_payload(range_key))
    except Exception as e:
        print("analytics error:", repr(e), flush=True)
        empty_series = {"range": range_key, "label": "", "bucket_seconds": 0, "points": []}
        return jsonify({"updated": utcnow(), "range": range_key, "range_options": ANALYTICS_RANGE_OPTIONS,
                         "series": {"queries": empty_series, "new_domains": empty_series, "new_devices": empty_series},
                         "status_breakdown": {}, "recent_domains": [], "recent_devices": [],
                         "active_devices": 0, "total_devices": 0, "new_domains_24h": 0,
                         "live": {"updated": utcnow(), "window_seconds": ANALYTICS_LIVE_WINDOW_SECONDS, "queries_in_window": 0},
                         "error": str(e)}), 200


# `/api/analytics/map` is deliberately separate from `/api/analytics`: it
# aggregates over every active domain (bounded by `GEOIP_MAP_DOMAIN_LIMIT`)
# rather than a fixed recent-activity slice, and carries its own short-TTL
# cache (`GEOIP_MAP_CACHE_SECONDS`) so the Analytics poll loop can call it on
# the same cadence without recomputing the aggregate on every request.
@app.route("/api/analytics/map")
def api_analytics_map():
    try:
        return jsonify(geoip_map_payload())
    except Exception as e:
        print("geoip map error:", repr(e), flush=True)
        return jsonify({
            "updated": utcnow(),
            "provider": {"configured": False, "db_path_basename": None, "range_count": 0},
            "countries": [],
            "destinations": [],
            "unknown": {"domain_count": 0, "observation_count": 0},
            "coverage": {"total_domains": 0, "geolocated_domains": 0, "total_observations": 0, "geolocated_observations": 0, "geolocated_pct": 0.0},
            "capabilities": {"country": False, "coordinates": False, "heatmap": False},
            "diagnostics": {"state": "load_failed", "message": GEOIP_DIAGNOSTIC_MESSAGES["load_failed"], "country": None, "city": None},
            "error": str(e),
        }), 200


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
        'hostname_cache','client_cache','domain_destination_ips'
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
        'geoip': _geoip_diagnostics(),
        'geoip_city': _geoip_city_diagnostics(),
        'geoip_update': _geoip_update_diagnostics(),
        'startup': _startup_readiness_diagnostics(),
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


# === Restart control (Issue #43) ===
# The container runs `app.py` directly as PID 1 with no supervisor/entrypoint
# script (see the Dockerfile's `CMD ["python", "/app/app.py"]`) and Flask's
# built-in dev server, not a process manager -- a real restart therefore
# cannot rely on an orchestrator's restart policy (that requires the
# deployer to have configured one, and the container would otherwise stay
# fully down until they notice) and must not be faked by only restarting a
# background worker thread. `os.execv` replaces this process's image in
# place: the PID and the container never actually stop, `main()` runs again
# from scratch exactly as it would on a fresh container start (re-opens the
# SQLite database, restarts every `BACKGROUND_WORKERS` thread, rebinds the
# listening socket), and `/data` -- a bind-mounted volume the process itself
# never touches -- is completely unaffected.
RESTART_DELAY_SECONDS = max(0.1, float(os.getenv("RESTART_DELAY_SECONDS", "0.75")))
_restart_lock = threading.Lock()
_restart_in_progress = False


def _perform_self_restart():
    """Runs in its own daemon thread, started only after `api_system_restart`
    has already built its HTTP response. The short delay gives the
    single-threaded dev server time to flush that response over the socket
    before this replaces the process image -- without it, the client could
    see the connection drop before ever learning the restart was accepted."""
    global _restart_in_progress
    time.sleep(RESTART_DELAY_SECONDS)
    try:
        os.execv(sys.executable, [sys.executable] + sys.argv)
    except OSError as e:
        print(f"Self-restart failed: {e!r}", flush=True)
        with _restart_lock:
            _restart_in_progress = False


@app.route('/api/system/restart', methods=['POST'])
def api_system_restart():
    """Restart control backing the Settings > System panel's Restart button.
    Requires an explicit `{"confirm": true}` JSON body -- an accidental or
    blind POST (a health checker, a replayed request) can never trigger a
    real restart -- and rejects a second request while one is already in
    flight instead of queuing or double-executing it."""
    global _restart_in_progress
    payload = request.get_json(silent=True) or {}
    if payload.get('confirm') is not True:
        return jsonify({'ok': False, 'error': 'restart requires {"confirm": true} in the request body'}), 400
    with _restart_lock:
        if _restart_in_progress:
            return jsonify({'ok': False, 'error': 'a restart is already in progress'}), 409
        _restart_in_progress = True
    threading.Thread(target=_perform_self_restart, daemon=True, name='self-restart').start()
    return jsonify({'ok': True, 'status': 'restarting'}), 202


# === APPLICATION ENTRY POINT (0.8.0) ===
# Startup used to live inline under `if __name__ == "__main__"`, which meant the
# only way to exercise it was to launch the real server. The steps below are the
# same steps, in the same order, as 0.7.14 -- they are now named so that tests and
# future module boundaries have something explicit to call.

#: Long-lived background threads, in the order 0.7.14 started them.
#
# `_geoip_initial_load_worker()` is deliberately NOT one of these (Issue #50
# / 0.8.5.10, CI run 35317057142): every entry here is a long-lived loop that
# runs for the life of the process, while the initial GeoIP load is a
# one-shot task that does its work once and returns. Declaring it alongside
# the long-lived workers made `test_background_workers_are_declared`/
# `test_start_background_workers_starts_daemon_threads` (which assert the
# fixed five-worker contract) fail, and conflated two different lifecycles
# that deserve to stay explicit. It is started separately, directly from
# `main()`, below.
BACKGROUND_WORKERS = (
    ("agh-ingest", worker),
    ("enrichment-queue", _enrichment_worker),
    ("device-ip-cleanup", _device_ip_cleanup_worker),
    ("ip-ping", _ip_ping_worker),
    ("geoip-auto-update", geoip_auto_update_worker),
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
    """Run the built-in Flask server. Blocks until the process is stopped.

    Issue #51: `threaded=True` lets the server accept and answer a request
    (e.g. `/health`, or a normal UI request) that lands while another is
    still being handled, instead of Flask's single-threaded default forcing
    every request to wait its turn behind whichever one is currently in
    flight -- real reachability, not just a bound listening socket.
    """
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")), threaded=True)


def main():
    """The single startup path for DNS Inspector."""
    init_db()
    if os.path.exists(GEOIP_DB_PATH) or os.path.exists(GEOIP_CITY_DB_PATH):
        print(
            "GeoIP: database detected; deferring initial load to a one-shot "
            "background thread so the HTTP server can start immediately.",
            flush=True,
        )
        # One-shot, not a long-lived BACKGROUND_WORKERS entry -- see the
        # comment above BACKGROUND_WORKERS for why.
        threading.Thread(
            target=_geoip_initial_load_worker, daemon=True, name="geoip-initial-load",
        ).start()
    else:
        _log_geoip_status()
    _prune_stale_device_ips()
    start_background_workers()
    serve()


if __name__ == "__main__":
    main()
