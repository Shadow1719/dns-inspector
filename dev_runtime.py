import ipaddress
import re
import sqlite3
import subprocess
import threading
import time
import os

from flask import jsonify, request

from app import app, db_lock, DB_PATH

DEVICE_IP_RETENTION_HOURS = max(1.0, float(os.environ.get('DEVICE_IP_RETENTION_HOURS','12')))
IP_PING_INTERVAL_HOURS = max(1.0, float(os.environ.get('IP_PING_INTERVAL_HOURS','4')))
IP_PING_INITIAL_DELAY_SECONDS = max(10, int(os.environ.get('IP_PING_INITIAL_DELAY_SECONDS','60')))
IP_PING_TIMEOUT_SECONDS = max(1, int(os.environ.get('IP_PING_TIMEOUT_SECONDS','1')))

DEV_CSS = """
.dev-build-banner{position:sticky;top:0;z-index:1000;margin:0 0 12px;padding:9px 14px;border:2px solid #f0883e;border-radius:10px;background:#3b1f0f;color:#ffb86b;font-weight:900;letter-spacing:.06em;text-align:center;text-transform:uppercase;box-shadow:0 6px 20px rgba(0,0,0,.25)}
.device-runtime-status{display:inline-flex;align-items:center;gap:5px;padding:4px 8px;border-radius:999px;font-size:.78rem;font-weight:700}
.device-runtime-status.online{background:#174d2a;color:#7ee787}.device-runtime-status.offline{background:#6a1717;color:#ffb4b4}.device-runtime-status.unknown{background:#30363d;color:#8b949e}
.device-runtime-ping{padding:2px 6px!important;font-size:.68rem!important;border-radius:6px!important;margin-left:5px}
.device-runtime-ping:disabled{opacity:.55;cursor:default}
"""

DEV_JS = r"""
(function(){
  const pingState = window.__dnsInspectorPingStatuses = window.__dnsInspectorPingStatuses || {};
  function statusForRow(row){
    const links=Array.prototype.slice.call(row.querySelectorAll('a.link-ip'));
    const states=links.map(function(a){return pingState[(a.textContent||'').trim()];}).filter(Boolean);
    const anyOnline=states.some(function(s){return !!s.online;});
    const allOffline=states.length===links.length&&states.length>0&&states.every(function(s){return !s.online;});
    return anyOnline?'Online':(allOffline?'Offline':'Unknown');
  }
  function decorate(){
    const table=document.getElementById('clients-table'),body=document.getElementById('clients-body');if(!table||!body)return;
    const head=table.tHead&&table.tHead.rows[0];
    if(head&&!head.querySelector('[data-runtime-status-head]')){const th=document.createElement('th');th.textContent='Status';th.setAttribute('data-runtime-status-head','1');head.insertBefore(th,head.lastElementChild);}
    Array.prototype.slice.call(body.rows).forEach(function(row){
      if(!row.querySelector('[data-runtime-status-cell]')){const cell=document.createElement('td');cell.setAttribute('data-runtime-status-cell','1');cell.innerHTML='<span class="device-runtime-status unknown">Unknown</span>';row.insertBefore(cell,row.lastElementChild);}
      Array.prototype.slice.call(row.querySelectorAll('a.link-ip')).forEach(function(a){const holder=a.parentNode;if(holder&&holder.querySelector&&holder.querySelector('[data-runtime-ping]'))return;const ip=(a.textContent||'').trim();if(!ip)return;const btn=document.createElement('button');btn.type='button';btn.className='device-runtime-ping';btn.setAttribute('data-runtime-ping',ip);btn.textContent='Ping';a.insertAdjacentElement('afterend',btn);});
    });
    updateStatusCells();bindButtons();
  }
  function updateStatusCells(){const body=document.getElementById('clients-body');if(!body)return;Array.prototype.slice.call(body.rows).forEach(function(row){const pill=row.querySelector('[data-runtime-status-cell] .device-runtime-status');if(!pill)return;const s=statusForRow(row);pill.className='device-runtime-status '+s.toLowerCase();pill.textContent=s;});}
  function bindButtons(){Array.prototype.slice.call(document.querySelectorAll('[data-runtime-ping]')).forEach(function(btn){if(btn.getAttribute('data-bound')==='1')return;btn.setAttribute('data-bound','1');btn.addEventListener('click',function(ev){ev.preventDefault();ev.stopPropagation();const ip=btn.getAttribute('data-runtime-ping');btn.disabled=true;btn.textContent='…';fetch('/api/ip/ping',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:ip})}).then(function(r){return r.json().then(function(d){if(!r.ok||!d.ok)throw new Error(d.error||'Ping failed');return d;});}).then(function(d){pingState[ip]=d.result;updateStatusCells();btn.disabled=false;btn.textContent='Ping';}).catch(function(e){pingState[ip]={online:false,error:e.message,last_checked:Date.now()/1000};updateStatusCells();btn.disabled=false;btn.textContent='Ping';});});});}
  function loadStatuses(){fetch('/api/ip/ping/status',{cache:'no-store'}).then(function(r){if(!r.ok)throw new Error('ping status '+r.status);return r.json();}).then(function(d){Object.assign(pingState,d.statuses||{});decorate();}).catch(function(){decorate();});}
  function start(){loadStatuses();const body=document.getElementById('clients-body');if(body)new MutationObserver(function(){decorate();}).observe(body,{childList:true,subtree:true});decorate();}
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',start,{once:true});else start();
})();
"""


def _ensure_schema():
    with db_lock, sqlite3.connect(DB_PATH, timeout=30.0) as c:
        c.execute('PRAGMA busy_timeout=30000')
        c.execute('''CREATE TABLE IF NOT EXISTS ip_ping_status(ip TEXT PRIMARY KEY,last_checked REAL NOT NULL,online INTEGER NOT NULL,latency_ms REAL,error TEXT NOT NULL DEFAULT '')''')
        c.execute('CREATE INDEX IF NOT EXISTS idx_ip_ping_status_last_checked ON ip_ping_status(last_checked)')
        c.commit()


def _validate_ip(value):
    value=str(value or '').strip()
    try: addr=ipaddress.ip_address(value)
    except ValueError: raise ValueError('Invalid IP address')
    if addr.is_loopback or addr.is_multicast or not addr.is_private: raise ValueError('Only private LAN IP addresses can be pinged')
    return value


def _run_ping(ip):
    ip=_validate_ip(ip);started=time.monotonic();online=False;latency_ms=None;error=''
    try:
        proc=subprocess.run(['ping','-c','1','-W',str(IP_PING_TIMEOUT_SECONDS),ip],capture_output=True,text=True,timeout=IP_PING_TIMEOUT_SECONDS+2,check=False)
        output=(proc.stdout or '')+'\n'+(proc.stderr or '');online=proc.returncode==0
        if online:
            m=re.search(r'time[=<]([0-9.]+)\s*ms',output);latency_ms=float(m.group(1)) if m else round((time.monotonic()-started)*1000.0,1)
        else:error='No reply'
    except FileNotFoundError:error='ping command unavailable'
    except subprocess.TimeoutExpired:error='Timeout'
    except Exception as e:error=str(e)[:200]
    checked=time.time()
    with db_lock, sqlite3.connect(DB_PATH,timeout=30.0) as c:
        c.execute('PRAGMA busy_timeout=30000')
        c.execute('INSERT OR REPLACE INTO ip_ping_status(ip,last_checked,online,latency_ms,error) VALUES(?,?,?,?,?)',(ip,checked,1 if online else 0,latency_ms,error));c.commit()
    return {'ip':ip,'online':online,'latency_ms':latency_ms,'error':error,'last_checked':checked}


@app.route('/api/ip/ping/status', methods=['GET'])
def dev_ip_ping_status():
    try:
        _ensure_schema()
        with sqlite3.connect(DB_PATH,timeout=30.0) as c: rows=c.execute('SELECT ip,last_checked,online,latency_ms,error FROM ip_ping_status').fetchall()
        return jsonify({'ok':True,'statuses':{r[0]:{'last_checked':r[1],'online':bool(r[2]),'latency_ms':r[3],'error':r[4] or ''} for r in rows}})
    except Exception as e:
        print('IP ping status error:',repr(e),flush=True);return jsonify({'ok':False,'statuses':{}}),500


@app.route('/api/ip/ping', methods=['POST'])
def dev_ip_ping():
    try:
        data=request.get_json(silent=True) or {};return jsonify({'ok':True,'result':_run_ping(data.get('ip'))})
    except ValueError as e:return jsonify({'ok':False,'error':str(e)}),400
    except Exception as e:
        print('manual IP ping error:',repr(e),flush=True);return jsonify({'ok':False,'error':'Ping failed'}),500


def _datetime_cutoff(ts):
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts,timezone.utc).isoformat()


def _background_ping_sweep():
    time.sleep(IP_PING_INITIAL_DELAY_SECONDS)
    while True:
        try:
            _ensure_schema();cutoff=_datetime_cutoff(time.time()-DEVICE_IP_RETENTION_HOURS*3600.0)
            with sqlite3.connect(DB_PATH,timeout=30.0) as c:
                c.execute('PRAGMA busy_timeout=30000');ips=[r[0] for r in c.execute('SELECT DISTINCT ip FROM device_ips WHERE last_seen>=? AND ip IS NOT NULL AND TRIM(ip)<>""',(cutoff,)).fetchall()]
            for ip in ips:
                try:_run_ping(ip)
                except Exception as e:print(f'IP ping error for {ip}: {e!r}',flush=True)
        except Exception as e:print('IP reachability sweep error:',repr(e),flush=True)
        time.sleep(IP_PING_INTERVAL_HOURS*3600.0)


def _inject_response(response):
    if 'text/html' not in (response.headers.get('Content-Type') or '').lower(): return response
    try:
        body=response.get_data(as_text=True)
        body=body.replace('/static/favicon.svg','/static/favicon-dev.svg',1)
        if 'class="dev-build-banner"' not in body: body=body.replace('<body>','<body><div class="dev-build-banner">DEVELOPMENT BUILD &middot; DNS Inspector 0.8 &middot; NOT PRODUCTION</div>',1)
        if DEV_CSS not in body: body=body.replace('</style>',DEV_CSS+'</style>',1)
        if DEV_JS not in body: body=body.replace('</body>','<script>'+DEV_JS+'</script></body>',1)
        response.set_data(body);return response
    except Exception:return response


@app.after_request
def dev_ui_restore(response): return _inject_response(response)


_ensure_schema()
try:
    if not getattr(app,'_dev_restore_worker_started',False):
        import app as _legacy_app
        if hasattr(_legacy_app,'worker'): threading.Thread(target=_legacy_app.worker,daemon=True,name='ingest-worker').start()
        threading.Thread(target=_background_ping_sweep,daemon=True,name='ip-ping').start()
        app._dev_restore_worker_started=True
except Exception as e: print('dev runtime background startup error:',repr(e),flush=True)
