from pathlib import Path

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

MARKER = '# === DEV 0.8 STABILITY PATCH V1 ==='
if MARKER in text:
    print('DEV 0.8 stability patch already applied')
    raise SystemExit(0)

# ---------------------------------------------------------------------------
# 1) Analytics fallback: render useful values server-side as well as through
#    the rescue JS. This prevents a JS regression from leaving all four cards
#    empty when get_stats() already has valid data.
# ---------------------------------------------------------------------------
analytics_replacements = {
    '<div id="chart-domains" class="chart-list"></div>': '''<div id="chart-domains" class="chart-list">
{% set maxv = (stats.domains|map(attribute='value')|max if stats.domains else 1) %}
{% for item in stats.domains %}<div class="bar-row"><a class="bar-label" href="{{ item.href }}">{{ item.label }}</a><div class="bar-track"><div class="bar-fill" style="width:{{ ((item.value / maxv) * 100)|round(0)|int }}%"></div></div><span class="bar-value">{{ item.value }}</span></div>{% else %}<div class="sub">No data yet.</div>{% endfor %}
</div>''',
    '<div id="chart-devices" class="chart-list"></div>': '''<div id="chart-devices" class="chart-list">
{% set maxv = (stats.devices|map(attribute='value')|max if stats.devices else 1) %}
{% for item in stats.devices %}<div class="bar-row"><a class="bar-label" href="{{ item.href }}">{{ item.label }}</a><div class="bar-track"><div class="bar-fill" style="width:{{ ((item.value / maxv) * 100)|round(0)|int }}%"></div></div><span class="bar-value">{{ item.value }}</span></div>{% else %}<div class="sub">No data yet.</div>{% endfor %}
</div>''',
    '<div id="chart-vendors" class="chart-list"></div>': '''<div id="chart-vendors" class="chart-list">
{% set maxv = (stats.vendors|map(attribute='value')|max if stats.vendors else 1) %}
{% for item in stats.vendors %}<div class="bar-row"><span class="bar-label">{{ item.label }}</span><div class="bar-track"><div class="bar-fill" style="width:{{ ((item.value / maxv) * 100)|round(0)|int }}%"></div></div><span class="bar-value">{{ item.value }}</span></div>{% else %}<div class="sub">No data yet.</div>{% endfor %}
</div>''',
    '<div id="chart-ips" class="chart-list"></div>': '''<div id="chart-ips" class="chart-list">
{% set maxv = (stats.ips|map(attribute='value')|max if stats.ips else 1) %}
{% for item in stats.ips %}<div class="bar-row"><a class="bar-label" href="{{ item.href }}">{{ item.label }}</a><div class="bar-track"><div class="bar-fill" style="width:{{ ((item.value / maxv) * 100)|round(0)|int }}%"></div></div><span class="bar-value">{{ item.value }}</span></div>{% else %}<div class="sub">No data yet.</div>{% endfor %}
</div>''',
}
for old, new in analytics_replacements.items():
    if old not in text:
        raise SystemExit(f'stability patch: analytics marker not found: {old[:50]}')
    text = text.replace(old, new, 1)

# ---------------------------------------------------------------------------
# 2) Lightweight IP/device detail views. The old detail routes rebuilt the
#    entire dashboard (including enrichment-heavy recent rows) before showing
#    the requested detail card. That made an IP click needlessly expensive.
#    Keep the same visual shell, but let /api/state hydrate the dashboard later.
# ---------------------------------------------------------------------------
anchor = '@app.route("/device")\ndef device_view():\n'
if anchor not in text:
    raise SystemExit('stability patch: device route marker not found')

replacement = '''@app.route("/device")\ndef device_view():\n    key = request.args.get("key", "").strip()\n    d = device_detail(key)\n    empty_stats = {"domains": [], "devices": [], "vendors": [], "ips": []}\n    if not d:\n        body = "<div class='card'><h2>Device not found</h2><p class='error'>No device exists for this identity.</p><p><a href='/'>Back to dashboard</a></p></div>"\n        return render_template_string(HTML, q="", result=None, inspect_html=body, recent_html="", clients_html="", version=APP_VERSION, refresh_seconds=UI_REFRESH_SECONDS, refresh_seconds_ms=UI_REFRESH_SECONDS * 1000, updated=utcnow(), filter_options=get_filter_options(), stats=empty_stats, error=None), 404\n    return render_template_string(HTML, q="", result=None, inspect_html=detail_html_device(d), recent_html="", clients_html="", version=APP_VERSION, refresh_seconds=UI_REFRESH_SECONDS, refresh_seconds_ms=UI_REFRESH_SECONDS * 1000, updated=utcnow(), filter_options=get_filter_options(), stats=empty_stats, error=None)\n\n\n@app.route("/ip")\ndef ip_view():\n    addr = request.args.get("addr", "").strip()\n    d = ip_detail(addr)\n    empty_stats = {"domains": [], "devices": [], "vendors": [], "ips": []}\n    if not d:\n        body = "<div class='card'><h2>IP not found</h2><p class='error'>No valid IP observation exists for this address.</p><p><a href='/'>Back to dashboard</a></p></div>"\n        return render_template_string(HTML, q="", result=None, inspect_html=body, recent_html="", clients_html="", version=APP_VERSION, refresh_seconds=UI_REFRESH_SECONDS, refresh_seconds_ms=UI_REFRESH_SECONDS * 1000, updated=utcnow(), filter_options=get_filter_options(), stats=empty_stats, error=None), 404\n    return render_template_string(HTML, q="", result=None, inspect_html=detail_html_ip(d), recent_html="", clients_html="", version=APP_VERSION, refresh_seconds=UI_REFRESH_SECONDS, refresh_seconds_ms=UI_REFRESH_SECONDS * 1000, updated=utcnow(), filter_options=get_filter_options(), stats=empty_stats, error=None)\n\n\n'''
text = text.replace(anchor, replacement, 1)

# ---------------------------------------------------------------------------
# 3) Safe observability endpoint: memory diagnostics still remain available to
#    the debug bundle, but the 5-second UI poll must not run a tracemalloc
#    snapshot/statistics pass on every request. The debug snapshot can remain
#    deep; the live endpoint should stay cheap and non-failing.
# ---------------------------------------------------------------------------
obs_anchor = 'if __name__ == "__main__":\n'
obs_block = '''def _api_observability_live():\n    try:\n        # _original_observability_payload is created by the memory-diagnostics\n        # patch specifically so the deep wrapper can add tracemalloc data.\n        payload_fn = globals().get('_original_observability_payload', globals().get('_observability_payload'))\n        payload = payload_fn() if callable(payload_fn) else {}\n        return jsonify(payload)\n    except Exception as e:\n        print('live observability error:', repr(e), flush=True)\n        return jsonify({\n            'version': APP_VERSION,\n            'uptime_seconds': max(0.0, time.monotonic() - OBSERVABILITY_START_MONOTONIC),\n            'ram_mb': None,\n        }), 200\n\ntry:\n    app.view_functions['api_observability'] = _api_observability_live\nexcept Exception:\n    pass\n\n'''
if 'def _api_observability_live()' not in text:
    if obs_anchor not in text:
        raise SystemExit('stability patch: main marker not found')
    text = text.replace(obs_anchor, obs_block + obs_anchor, 1)

# ---------------------------------------------------------------------------
# 4) Independent, deliberately small UI bridge for Analytics + device Status /
#    Ping. This avoids the much more complicated rescue script and re-runs after
#    dashboard DOM replacement via one MutationObserver.
# ---------------------------------------------------------------------------
bridge = r'''<script>
/* DNS Inspector 0.8 stability bridge v1 */
(function(){
  function esc(v){return String(v==null?'':v).replace(/[&<>\"']/g,function(c){return ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'})[c]});}
  function updateStamp(iso){
    try{var d=new Date(iso);if(isNaN(d.getTime()))return;var t=document.getElementById('last-update-time'),day=document.getElementById('last-update-date');if(t)t.textContent=d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false});if(day)day.textContent=d.toLocaleDateString([], {year:'numeric',month:'short',day:'numeric'});}catch(e){}
  }
  function drawBars(id,items){
    var root=document.getElementById(id);if(!root)return;if(!Array.isArray(items)||!items.length)return;
    var max=1,i,x,v,pct,html='';for(i=0;i<items.length;i++){x=items[i]||{};v=Number(x.value)||0;if(v>max)max=v;pct=Math.max(2,Math.round((v/max)*100));html+='<div class="bar-row">'+(x.href?'<a class="bar-label" href="'+esc(x.href)+'">'+esc(x.label)+'</a>':'<span class="bar-label">'+esc(x.label)+'</span>')+'<div class="bar-track"><div class="bar-fill" style="width:'+pct+'%"></div></div><span class="bar-value">'+esc(v)+'</span></div>';}root.innerHTML=html;
  }
  function loadAnalytics(){
    fetch('/api/dev/analytics',{cache:'no-store'}).then(function(r){if(!r.ok)throw new Error('analytics '+r.status);return r.json();}).then(function(d){if(!d||d.ok===false)return;updateStamp(d.updated);drawBars('chart-domains',d.stats&&d.stats.domains);drawBars('chart-devices',d.stats&&d.stats.devices);drawBars('chart-vendors',d.stats&&d.stats.vendors);drawBars('chart-ips',d.stats&&d.stats.ips);}).catch(function(e){console.debug('stability analytics failed',e);});
  }
  window.__dnsInspectorPingStatuses=window.__dnsInspectorPingStatuses||{};
  function statusForRow(row){
    var links=Array.prototype.slice.call(row.querySelectorAll('a.link-ip')),states=links.map(function(a){return window.__dnsInspectorPingStatuses[(a.textContent||'').trim()];}).filter(Boolean),online=states.some(function(s){return !!s.online;}),offline=states.length===links.length&&states.length>0&&states.every(function(s){return !s.online;});return online?'Online':offline?'Offline':'Unknown';
  }
  function decorateDevices(){
    var table=document.getElementById('clients-table'),body=document.getElementById('clients-body');if(!table||!body)return;
    var head=table.tHead&&table.tHead.rows[0];
    if(head&&!head.querySelector('[data-stability-status-head]')){var th=document.createElement('th');th.textContent='Status';th.setAttribute('data-stability-status-head','1');head.insertBefore(th,head.lastElementChild);}
    Array.prototype.slice.call(body.rows).forEach(function(row){
      if(!row.querySelector('[data-stability-status-cell]')){var cell=document.createElement('td');cell.setAttribute('data-stability-status-cell','1');cell.innerHTML='<span class="status-pill status-unknown">Unknown</span>';row.insertBefore(cell,row.lastElementChild);}
      Array.prototype.slice.call(row.querySelectorAll('a.link-ip')).forEach(function(a){var holder=a.parentNode;if(holder&&holder.querySelector&&holder.querySelector('[data-stability-ping]'))return;var ip=(a.textContent||'').trim();if(!ip)return;var span=document.createElement('span');span.setAttribute('data-stability-ping',ip);span.style.cssText='display:inline-flex;align-items:center;gap:4px;margin-left:4px';span.innerHTML='<button type="button" style="padding:2px 6px;font-size:.68rem;border-radius:6px" data-stability-ping-btn="'+esc(ip)+'">Ping</button>';a.insertAdjacentElement('afterend',span);});
    });
    updateDeviceStatusCells();bindPingButtons();
  }
  function updateDeviceStatusCells(){var body=document.getElementById('clients-body');if(!body)return;Array.prototype.slice.call(body.rows).forEach(function(row){var cell=row.querySelector('[data-stability-status-cell] .status-pill');if(!cell)return;var s=statusForRow(row);cell.className='status-pill '+(s==='Online'?'status-allowed':s==='Offline'?'status-blocked':'status-unknown');cell.textContent=s;});}
  function bindPingButtons(){Array.prototype.slice.call(document.querySelectorAll('[data-stability-ping-btn]')).forEach(function(btn){if(btn.getAttribute('data-bound')==='1')return;btn.setAttribute('data-bound','1');btn.addEventListener('click',function(ev){ev.preventDefault();ev.stopPropagation();var ip=btn.getAttribute('data-stability-ping-btn');btn.disabled=true;btn.textContent='…';fetch('/api/ip/ping',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:ip})}).then(function(r){return r.json().then(function(d){if(!r.ok||!d.ok)throw new Error(d.error||'Ping failed');return d;});}).then(function(d){window.__dnsInspectorPingStatuses[ip]=d.result;updateDeviceStatusCells();btn.textContent='Ping';btn.disabled=false;}).catch(function(e){window.__dnsInspectorPingStatuses[ip]={online:false,error:e.message,last_checked:Date.now()/1000};updateDeviceStatusCells();btn.textContent='Ping';btn.disabled=false;});});});}
  function loadPingStatuses(){fetch('/api/ip/ping/status',{cache:'no-store'}).then(function(r){if(!r.ok)throw new Error('ping status '+r.status);return r.json();}).then(function(d){window.__dnsInspectorPingStatuses=d.statuses||{};decorateDevices();}).catch(function(e){console.debug('stability ping status failed',e);decorateDevices();});}
  function start(){loadAnalytics();loadPingStatuses();var body=document.getElementById('clients-body'),root=document.getElementById('inspect-root');if(body)new MutationObserver(function(){decorateDevices();}).observe(body,{childList:true,subtree:true});if(root)new MutationObserver(function(){}).observe(root,{childList:true,subtree:true});setInterval(loadAnalytics,10000);}
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',start,{once:true});else start();
})();
</script>'''
body_marker = '</body></html>'
if 'DNS Inspector 0.8 stability bridge v1' not in text:
    if body_marker not in text:
        raise SystemExit('stability patch: body marker not found')
    text = text.replace(body_marker, bridge + '\n' + body_marker, 1)

text = MARKER + '\n' + text
compile(text, str(APP), 'exec')
APP.write_text(text, encoding='utf-8')
print('DEV 0.8 stability patch v1 applied')
