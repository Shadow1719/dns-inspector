from pathlib import Path

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

MARKER = '# === OBSERVABILITY UI HOTFIX 0.7.13-HF2.4 ==='
if MARKER in text:
    print('DNS Inspector observability UI hotfix already applied')
    raise SystemExit(0)

# The original observability strip used a separate 5-second /api/observability
# poll. The main /api/state endpoint is already working on the dashboard and is
# already refreshed on the existing UI cadence, so use it as the single source
# for the lightweight uptime/RAM header values. This removes a second polling
# loop and makes the indicators follow the same request path as the live UI.

state_marker = 'def state_payload(q="",status_filter="",new_only=False,classification_filter="",severity_filter="",device_filter="",vendor_filter="",page=1,page_size=50):\n    result=inspect_domain(q) if q else None\n    recent=get_recent(page=page,page_size=page_size,status_filter=status_filter,new_only=new_only,classification_filter=classification_filter,severity_filter=severity_filter,device_filter=device_filter,vendor_filter=vendor_filter)\n    return {"updated":utcnow(),"recent":recent["rows"],"recent_meta":recent["meta"],"filter_options":get_filter_options(),"clients":get_clients(),"stats":get_stats(),"inspect_html":inspect_html(result) if result else None}\n'
state_replacement = '''def state_payload(q="",status_filter="",new_only=False,classification_filter="",severity_filter="",device_filter="",vendor_filter="",page=1,page_size=50):
    result=inspect_domain(q) if q else None
    recent=get_recent(page=page,page_size=page_size,status_filter=status_filter,new_only=new_only,classification_filter=classification_filter,severity_filter=severity_filter,device_filter=device_filter,vendor_filter=vendor_filter)
    uptime = _observability_uptime_seconds()
    return {"updated":utcnow(),"recent":recent["rows"],"recent_meta":recent["meta"],"filter_options":get_filter_options(),"clients":get_clients(),"stats":get_stats(),"inspect_html":inspect_html(result) if result else None,"observability":{"uptime_seconds":round(uptime,1),"uptime_human":_observability_uptime_human(uptime),"ram_mb":_observability_rss_mb()}}\n'''
if state_marker not in text:
    raise SystemExit('observability UI hotfix failed: state_payload marker not found')
text = text.replace(state_marker, state_replacement, 1)

# Replace the standalone observability fetch loop with a pure renderer. The
# existing /api/state refresh loop becomes the only browser polling loop.
old_js = '''<script>
function observabilityDuration(seconds){let s=Math.max(0,Math.floor(Number(seconds)||0));const d=Math.floor(s/86400);s%=86400;const h=Math.floor(s/3600);s%=3600;const m=Math.floor(s/60);s%=60;if(d)return `${d}d ${h}h ${m}m`;if(h)return `${h}h ${m}m ${s}s`;if(m)return `${m}m ${s}s`;return `${s}s`}
function observabilityRam(value){const mb=Number(value);return Number.isFinite(mb)?`${mb.toFixed(mb>=100?0:1)} MB`:'—'}
async function updateObservability(){try{const r=await fetch('/api/observability',{cache:'no-store'});if(!r.ok)return;const d=await r.json();const u=document.getElementById('obs-uptime');const m=document.getElementById('obs-memory');if(u)u.textContent=`Uptime ${observabilityDuration(d.uptime_seconds)}`;if(m)m.textContent=`RAM ${observabilityRam(d.ram_mb)}`}catch(e){console.debug('observability refresh failed',e)}}
updateObservability();setInterval(updateObservability,5000);
</script>'''
new_js = '''<script>
function observabilityDuration(seconds){let s=Math.max(0,Math.floor(Number(seconds)||0));const d=Math.floor(s/86400);s%=86400;const h=Math.floor(s/3600);s%=3600;const m=Math.floor(s/60);s%=60;if(d)return `${d}d ${h}h ${m}m`;if(h)return `${h}h ${m}m ${s}s`;if(m)return `${m}m ${s}s`;return `${s}s`}
function observabilityRam(value){const mb=Number(value);return Number.isFinite(mb)?`${mb.toFixed(mb>=100?0:1)} MB`:'—'}
function renderObservability(d){if(!d)return;const u=document.getElementById('obs-uptime');const m=document.getElementById('obs-memory');if(u)u.textContent=`Uptime ${observabilityDuration(d.uptime_seconds)}`;if(m)m.textContent=`RAM ${observabilityRam(d.ram_mb)}`}
</script>'''
if old_js not in text:
    raise SystemExit('observability UI hotfix failed: standalone observability JS marker not found')
text = text.replace(old_js, new_js, 1)

# Feed observability values through the already-active state refresh.
refresh_marker = "renderStats(data.stats);if(data.inspect_html!==null)document.getElementById('inspect-root').innerHTML=data.inspect_html;const stamp=formatUpdated(data.updated);"
refresh_replacement = "renderStats(data.stats);renderObservability(data.observability);if(data.inspect_html!==null)document.getElementById('inspect-root').innerHTML=data.inspect_html;const stamp=formatUpdated(data.updated);"
if refresh_marker not in text:
    raise SystemExit('observability UI hotfix failed: refresh hook marker not found')
text = text.replace(refresh_marker, refresh_replacement, 1)

# Populate the header immediately instead of waiting one full UI interval.
initial_refresh = 'const initialStamp=formatUpdated({{ updated|tojson }});document.getElementById(\'last-update-time\').textContent=initialStamp.time;document.getElementById(\'last-update-date\').textContent=initialStamp.date;setTimeout(()=>refresh(true),refreshMs);'
initial_replacement = 'const initialStamp=formatUpdated({{ updated|tojson }});document.getElementById(\'last-update-time\').textContent=initialStamp.time;document.getElementById(\'last-update-date\').textContent=initialStamp.date;refresh(true);'
if initial_refresh not in text:
    raise SystemExit('observability UI hotfix failed: initial refresh marker not found')
text = text.replace(initial_refresh, initial_replacement, 1)

compile(text, str(APP), 'exec')
APP.write_text(text, encoding='utf-8')
print('DNS Inspector 0.7.13-hotfix.2.4 observability UI hotfix applied')
