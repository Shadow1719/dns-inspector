from pathlib import Path

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

MARKER = '# === OBSERVABILITY PATCH 0.7.12 ==='
if MARKER in text:
    print('DNS Inspector observability patch already applied')
    raise SystemExit(0)

# Build-time patch only: runtime observability stays read-only and lightweight.
# No persistent log file is created; the debug bundle records safe snapshots and
# explicitly points to Docker/TrueNAS logs for historical stdout/stderr.
text = text.replace(
    'import time\n',
    'import time\nimport io\nimport platform\nimport shutil\nimport zipfile\n',
    1,
)
text = text.replace(
    'from flask import Flask, jsonify, render_template_string, request\n',
    'from flask import Flask, jsonify, render_template_string, request, send_file\n',
    1,
)

# Process-local start time: uptime belongs to the DNS application process.
anchor = '    APP_VERSION = os.getenv("APP_VERSION", "dev")\n\nAGH_URL = os.getenv("AGH_URL", "").rstrip("/")\n'
insert = '    APP_VERSION = os.getenv("APP_VERSION", "dev")\n\nOBSERVABILITY_START_MONOTONIC = time.monotonic()\nOBSERVABILITY_START_AT = datetime.now(timezone.utc).isoformat()\n\nAGH_URL = os.getenv("AGH_URL", "").rstrip("/")\n'
if anchor not in text:
    raise SystemExit('observability patch failed: version/config anchor not found')
text = text.replace(anchor, insert, 1)

# Small header styles; intentionally no charting dependency and no persistent metrics.
style_marker = '.toolbar{display:flex;gap:8px;align-items:center;margin:20px 0 4px}.toolbar input{flex:1;min-width:0}.toolbar button{white-space:nowrap}\n'
style_extra = '''.toolbar{display:flex;gap:8px;align-items:center;margin:20px 0 4px}.toolbar input{flex:1;min-width:0}.toolbar button{white-space:nowrap}
.observability-strip{display:flex;align-items:center;flex-wrap:wrap;gap:8px;margin:4px 0 8px}
.observability-pill{display:inline-flex;align-items:center;gap:6px;padding:5px 9px;border:1px solid #30363d;border-radius:999px;background:#11161d;color:#c9d1d9;font-size:.78rem;font-variant-numeric:tabular-nums}
.observability-dot{width:7px;height:7px;border-radius:50%;background:#3fb950;box-shadow:0 0 0 2px rgba(63,185,80,.10)}
.debug-button{padding:5px 9px;font-size:.78rem;border-radius:999px}
.debug-button:hover{border-color:#58a6ff}
'''
if style_marker not in text:
    raise SystemExit('observability patch failed: toolbar style marker not found')
text = text.replace(style_marker, style_extra, 1)

# Header: lightweight live runtime facts + one-click snapshot bundle.
header_old = '<h1>DNS Inspector <span class="muted" style="font-size:.55em">v{{version}}</span></h1>\n<p class="muted">Watching AdGuard activity · <span class="live">● Live</span> · refresh every {{refresh_seconds}}s · updated <span id="last-update-time" class="updated-time"></span> · <span id="last-update-date" class="updated-date"></span></p>\n'
header_new = '''<h1>DNS Inspector <span class="muted" style="font-size:.55em">v{{version}}</span></h1>
<div class="observability-strip" aria-label="Application runtime status">
  <span class="observability-pill"><span class="observability-dot"></span><span id="obs-uptime">Uptime —</span></span>
  <span class="observability-pill"><span id="obs-memory">RAM —</span></span>
  <button type="button" class="debug-button" onclick="window.location='/debug/bundle'">Generate Debug Bundle</button>
</div>
<p class="muted">Watching AdGuard activity · <span class="live">● Live</span> · refresh every {{refresh_seconds}}s · updated <span id="last-update-time" class="updated-time"></span> · <span id="last-update-date" class="updated-date"></span></p>
'''
if header_old not in text:
    raise SystemExit('observability patch failed: header marker not found')
text = text.replace(header_old, header_new, 1)

# Runtime JS: one tiny JSON request every 5 seconds, independent of the main state refresh.
js_marker = "const initialStamp=formatUpdated({{ updated|tojson }});document.getElementById('last-update-time').textContent=initialStamp.time;document.getElementById('last-update-date').textContent=initialStamp.date;setTimeout(()=>refresh(true),refreshMs);"
js_extra = '''function observabilityDuration(seconds){let s=Math.max(0,Math.floor(Number(seconds)||0));const d=Math.floor(s/86400);s%=86400;const h=Math.floor(s/3600);s%=3600;const m=Math.floor(s/60);s%=60;if(d)return `${d}d ${h}h ${m}m`;if(h)return `${h}h ${m}m ${s}s`;if(m)return `${m}m ${s}s`;return `${s}s`}
function observabilityRam(value){const mb=Number(value);return Number.isFinite(mb)?`${mb.toFixed(mb>=100?0:1)} MB`:'—'}
async function updateObservability(){try{const r=await fetch('/api/observability',{cache:'no-store'});if(!r.ok)return;const d=await r.json();document.getElementById('obs-uptime').textContent=`Uptime ${observabilityDuration(d.uptime_seconds)}`;document.getElementById('obs-memory').textContent=`RAM ${observabilityRam(d.ram_mb)}`}catch(e){console.debug('observability refresh failed',e)}}
updateObservability();setInterval(updateObservability,5000);
'''
if js_marker not in text:
    raise SystemExit('observability patch failed: final JS marker not found')
text = text.replace(js_marker, js_extra + js_marker, 1)

# Server-side helpers and routes. Counts are intentionally metadata-only; row contents never leave the bundle.
route_marker = 'if __name__ == "__main__":\n'
route_block = r'''def _observability_uptime_seconds():
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
                    kb = float(line.split()[1])
                    return round(kb / 1024.0, 1)
    except Exception:
        pass
    try:
        import resource
        return round(float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) / 1024.0, 1)
    except Exception:
        return None


def _observability_db_counts():
    tables = [
        'domains', 'devices', 'device_ips', 'device_labels', 'processed_queries',
        'adguard_status_cache', 'enrichment_attempts', 'ip_ping_status',
        'rdap_cache', 'netify_cache', 'dns_records_cache', 'mac_vendor_cache',
        'hostname_cache', 'client_cache',
    ]
    counts = {}
    try:
        with db_lock, sqlite3.connect(DB_PATH) as c:
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
    db_size = None
    try:
        db_size = os.path.getsize(DB_PATH)
    except OSError:
        pass
    return {
        'version': APP_VERSION,
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


@app.route('/api/observability')
def api_observability():
    try:
        return jsonify(_observability_payload())
    except Exception as e:
        print('observability endpoint error:', repr(e), flush=True)
        return jsonify({'version': APP_VERSION, 'uptime_seconds': _observability_uptime_seconds(), 'ram_mb': None}), 200


def _observability_safe_config():
    names = [
        'POLL_SECONDS', 'UI_REFRESH_SECONDS', 'TRACKERDB_REFRESH_HOURS',
        'TRACKERDB_DOWNLOAD_CHUNK_SIZE', 'MACVENDOR_CACHE_HOURS',
        'HOSTNAME_CACHE_HOURS', 'NETIFY_CACHE_HOURS', 'RDAP_CACHE_HOURS',
        'DNS_RECORDS_CACHE_HOURS', 'ENRICHMENT_RETRY_HOURS',
        'ENRICHMENT_DELAY_SECONDS', 'DEVICE_IP_RETENTION_HOURS',
        'DEVICE_IP_CLEANUP_INTERVAL_MINUTES', 'IP_PING_INTERVAL_HOURS',
        'IP_PING_INITIAL_DELAY_SECONDS', 'IP_PING_TIMEOUT_SECONDS',
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
        bundle = io.BytesIO()
        with zipfile.ZipFile(bundle, 'w', compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr('manifest.txt', f'DNS Inspector {APP_VERSION}\nGenerated: {utcnow()}\nPurpose: safe diagnostic snapshot\n')
            z.writestr('runtime.json', json.dumps(runtime, indent=2, ensure_ascii=False, sort_keys=True))
            z.writestr('config-safe.json', json.dumps(_observability_safe_config(), indent=2, ensure_ascii=False, sort_keys=True, default=str))
            z.writestr('logs-note.txt', 'DNS Inspector does not persist historical stdout/stderr logs. Retrieve container/application logs from Docker or TrueNAS when a historical log stream is needed.\n')
            try:
                usage = shutil.disk_usage(os.path.dirname(DB_PATH) or '/')
                z.writestr('storage.json', json.dumps({
                    'data_path': os.path.dirname(DB_PATH) or '/',
                    'total_bytes': usage.total,
                    'used_bytes': usage.used,
                    'free_bytes': usage.free,
                }, indent=2))
            except Exception as e:
                z.writestr('storage.json', json.dumps({'error': str(e)}, indent=2))
        bundle.seek(0)
        filename = f'dns-inspector-debug-{APP_VERSION}-{datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")}.zip'
        return send_file(bundle, mimetype='application/zip', as_attachment=True, download_name=filename)
    except Exception as e:
        print('debug bundle error:', repr(e), flush=True)
        return jsonify({'ok': False, 'error': 'Could not generate debug bundle'}), 500


'''
if route_marker not in text:
    raise SystemExit('observability patch failed: main marker not found')
text = text.replace(route_marker, route_block + route_marker, 1)

# Basic syntax validation before the patched source is written into the image.
compile(text, str(APP), 'exec')
APP.write_text(text, encoding='utf-8')
print('DNS Inspector 0.7.12 observability patch applied')
