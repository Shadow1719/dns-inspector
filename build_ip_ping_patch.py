from pathlib import Path

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

# Periodic/manual LAN reachability checks for recently active IP associations.
# Keep the target strictly to private/link-local addresses so the endpoint cannot
# be abused as a general-purpose network probe.
text = text.replace(
    'import socket\nimport sqlite3\n',
    'import socket\nimport sqlite3\nimport subprocess\n',
    1,
)

marker = 'DEVICE_IP_CLEANUP_INTERVAL_MINUTES = max(5, int(os.getenv("DEVICE_IP_CLEANUP_INTERVAL_MINUTES", "30")))\n'
insert = marker + 'IP_PING_INTERVAL_HOURS = max(1.0, float(os.getenv("IP_PING_INTERVAL_HOURS", "4")))\nIP_PING_INITIAL_DELAY_SECONDS = max(10, int(os.getenv("IP_PING_INITIAL_DELAY_SECONDS", "60")))\nIP_PING_TIMEOUT_SECONDS = max(1, int(os.getenv("IP_PING_TIMEOUT_SECONDS", "1")))\n'
if 'IP_PING_INTERVAL_HOURS = ' not in text:
    if marker not in text:
        raise SystemExit('IP ping patch failed: IP retention settings marker not found')
    text = text.replace(marker, insert, 1)

# Persist the most recent reachability result for each IP.
marker = '        c.execute("CREATE INDEX IF NOT EXISTS idx_device_ips_last_seen ON device_ips(last_seen)")\n'
insert = '''        c.execute("""CREATE TABLE IF NOT EXISTS ip_ping_status(
            ip TEXT PRIMARY KEY,
            last_checked REAL NOT NULL,
            online INTEGER NOT NULL,
            latency_ms REAL,
            error TEXT NOT NULL DEFAULT '')""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_ip_ping_status_last_checked ON ip_ping_status(last_checked)")
'''
if 'CREATE TABLE IF NOT EXISTS ip_ping_status' not in text:
    if marker not in text:
        raise SystemExit('IP ping patch failed: init_db marker not found')
    text = text.replace(marker, marker + insert, 1)

# Ping implementation + API endpoints.
marker = 'def _prune_stale_device_ips():\n'
block = '''def _validate_ping_ip(value):
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
        output = (proc.stdout or '') + '\\n' + (proc.stderr or '')
        online = proc.returncode == 0
        if online:
            match = re.search(r'time[=<]([0-9.]+)\\s*ms', output)
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
    with db_lock, sqlite3.connect(DB_PATH) as c:
        c.execute(
            'INSERT OR REPLACE INTO ip_ping_status(ip,last_checked,online,latency_ms,error) VALUES(?,?,?,?,?)',
            (ip, checked, 1 if online else 0, latency_ms, error),
        )
        c.commit()
    return {'ip': ip, 'online': online, 'latency_ms': latency_ms, 'error': error, 'last_checked': checked}


def _ping_active_ips():
    cutoff = time.time() - DEVICE_IP_RETENTION_HOURS * 3600.0
    try:
        with db_lock, sqlite3.connect(DB_PATH) as c:
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
        with db_lock, sqlite3.connect(DB_PATH) as c:
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


'''
if 'def _run_ip_ping(ip):' not in text:
    if marker not in text:
        raise SystemExit('IP ping patch failed: cleanup function marker not found')
    text = text.replace(marker, block + marker, 1)

# UI styling for per-IP reachability markers and manual Ping controls.
css_marker = '.device-label-cell{width:16%;vertical-align:top}'
css_extra = '''.device-ip-ping{display:inline-flex;align-items:center;gap:5px;margin-left:5px;padding:2px 0}.device-ip-ping-dot{width:8px;height:8px;border-radius:50%;display:inline-block;border:1px solid #30363d;background:#8b949e;flex:0 0 8px}.device-ip-ping-dot.online{background:#3fb950;border-color:#3fb950}.device-ip-ping-dot.offline{background:#f85149;border-color:#f85149}.device-ip-ping-dot.pending{background:#d29922;border-color:#d29922;animation:dnsInspectorPulse 1s ease-in-out infinite}@keyframes dnsInspectorPulse{50%{opacity:.35}}.device-ip-ping-btn{padding:2px 6px;font-size:.68rem;border-radius:6px}.device-ip-ping-btn:disabled{opacity:.55;cursor:default}'''
if 'device-ip-ping' not in text:
    if css_marker not in text:
        raise SystemExit('IP ping patch failed: UI CSS marker not found')
    text = text.replace(css_marker, css_marker + css_extra, 1)

# Add the IP ping controls around every currently displayed IP link.
marker = 'function placeDeviceLabelsInColumn(){'
helper_marker = '''function ipPingTitle(s){if(!s)return 'Never checked';const when=new Date(Number(s.last_checked)*1000);const result=s.online?'Reachable':'Unreachable';const latency=s.latency_ms!=null?` · ${s.latency_ms} ms`:'';const err=s.error?` · ${s.error}`:'';return `${result}${latency}${err} · ${when.toLocaleString()}`}
function ipPingMarkup(ip,s){const state=s?(s.online?'online':'offline'):'pending';const label=s?(s.online?'OK':'FAIL'):'?';return `<span class="device-ip-ping" data-ping-ip="${esc(ip)}" title="${esc(ipPingTitle(s))}"><span class="device-ip-ping-dot ${state}" data-ping-dot></span><button type="button" class="device-ip-ping-btn" data-ping-button="${esc(ip)}">Ping</button></span>`}
function decorateDeviceIps(){const root=document.getElementById('clients-body');if(!root)return;root.querySelectorAll('a.link-ip').forEach(a=>{if(a.parentElement?.querySelector('.device-ip-ping'))return;const ip=(a.textContent||'').trim();if(!ip)return;const wrap=document.createElement('span');wrap.innerHTML=ipPingMarkup(ip,(window.ipPingStatuses||{})[ip]);a.insertAdjacentElement('afterend',wrap);});bindIpPingButtons();}
function applyIpPingStatuses(){document.querySelectorAll('[data-ping-ip]').forEach(wrap=>{const ip=wrap.getAttribute('data-ping-ip');const s=(window.ipPingStatuses||{})[ip];const dot=wrap.querySelector('[data-ping-dot]');const btn=wrap.querySelector('[data-ping-button]');if(!dot||!btn)return;dot.className='device-ip-ping-dot '+(s?(s.online?'online':'offline'):'pending');wrap.title=ipPingTitle(s);btn.disabled=false;btn.textContent='Ping';});}
async function loadIpPingStatuses(){try{const r=await fetch('/api/ip/ping/status',{cache:'no-store'});if(!r.ok)return;const data=await r.json();window.ipPingStatuses=data.statuses||{};decorateDeviceIps();applyIpPingStatuses();}catch(e){console.debug('IP ping status load failed',e)}}
async function pingDeviceIp(ip,button){if(!ip||!button)return;button.disabled=true;button.textContent='…';const wrap=button.closest('[data-ping-ip]');const dot=wrap?.querySelector('[data-ping-dot]');if(dot)dot.className='device-ip-ping-dot pending';try{const r=await fetch('/api/ip/ping',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})});const data=await r.json();if(!r.ok||!data.ok)throw new Error(data.error||'Ping failed');window.ipPingStatuses=window.ipPingStatuses||{};window.ipPingStatuses[ip]=data.result;applyIpPingStatuses();}catch(e){window.ipPingStatuses=window.ipPingStatuses||{};window.ipPingStatuses[ip]={online:false,error:e.message,last_checked:Date.now()/1000};applyIpPingStatuses();alert(`Ping ${ip} failed: ${e.message}`);}}
function bindIpPingButtons(){document.querySelectorAll('[data-ping-button]').forEach(b=>{if(b.dataset.bound)return;b.dataset.bound='1';b.addEventListener('click',e=>{e.preventDefault();e.stopPropagation();pingDeviceIp(b.dataset.pingButton,b)});});}
function injectIpPingControls(){decorateDeviceIps();loadIpPingStatuses();}
'''
if 'function ipPingTitle' not in text:
    if marker not in text:
        raise SystemExit('IP ping patch failed: device-label placement marker not found')
    text = text.replace(marker, helper_marker + marker, 1)

# Re-run after every Devices render so IPs from new pages/refreshes get controls.
old_render = "function renderClients(rows){ window.__lastClients=rows||[]; document.getElementById('clients-body').innerHTML = rows.map(deviceRow).join(''); bindDeviceLabelButtons(); placeDeviceLabelsInColumn(); reapplyTableSorts(); }"
new_render = "function renderClients(rows){ window.__lastClients=rows||[]; document.getElementById('clients-body').innerHTML = rows.map(deviceRow).join(''); bindDeviceLabelButtons(); placeDeviceLabelsInColumn(); injectIpPingControls(); reapplyTableSorts(); }"
if old_render not in text:
    raise SystemExit('IP ping patch failed: renderClients marker not found')
text = text.replace(old_render, new_render, 1)

# Add the reachability worker to application startup.
old_main = '''if __name__ == "__main__":
    init_db()
    _prune_stale_device_ips()
    threading.Thread(target=worker, daemon=True).start()
    threading.Thread(target=_enrichment_worker, daemon=True, name="enrichment-queue").start()
    threading.Thread(target=_device_ip_cleanup_worker, daemon=True, name="device-ip-cleanup").start()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
'''
new_main = '''if __name__ == "__main__":
    init_db()
    _prune_stale_device_ips()
    threading.Thread(target=worker, daemon=True).start()
    threading.Thread(target=_enrichment_worker, daemon=True, name="enrichment-queue").start()
    threading.Thread(target=_device_ip_cleanup_worker, daemon=True, name="device-ip-cleanup").start()
    threading.Thread(target=_ip_ping_worker, daemon=True, name="ip-ping").start()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
'''
if old_main not in text:
    raise SystemExit('IP ping patch failed: startup marker not found')
text = text.replace(old_main, new_main, 1)

APP.write_text(text, encoding='utf-8')
print('DNS Inspector IP reachability patch applied: 4h background ping + per-IP manual Ping controls')
