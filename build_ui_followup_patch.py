from pathlib import Path

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

# Put manual device labels in their own dedicated Devices-table column.
# The existing label patch keeps the label UI inside the first cell; move that
# already-rendered element into a separate cell after each render so the layout
# stays stable without touching device identity/reconciliation logic.
css_marker = '.device-label-btn{padding:3px 7px;font-size:.72rem;border-radius:7px}'
css_extra = '''.device-label-btn{padding:3px 7px;font-size:.72rem;border-radius:7px}
.device-label-cell{width:16%;vertical-align:top}.device-label-cell .device-label-inline{margin-top:0;display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.device-label-cell .device-label-text{font-size:.8rem}.device-table-label-col{width:16%}
.refresh-status{position:fixed;top:10px;right:16px;z-index:100;display:none;align-items:center;gap:8px;padding:7px 10px;border:1px solid #30363d;border-radius:999px;background:rgba(17,22,29,.96);box-shadow:0 6px 20px rgba(0,0,0,.25);color:#c9d1d9;font-size:.78rem}
.refresh-status.show{display:inline-flex}.refresh-spinner{width:13px;height:13px;border:2px solid #30363d;border-top-color:#58a6ff;border-radius:50%;animation:dnsInspectorSpin .75s linear infinite}@keyframes dnsInspectorSpin{to{transform:rotate(360deg)}}
'''
if css_marker in text and 'refresh-status' not in text:
    text = text.replace(css_marker, css_extra, 1)

# Loading indicator helpers. It is shown while /api/state is being refreshed,
# including the immediate refresh performed on page load.
marker = 'window.deviceLabels={};'
helpers = '''window.deviceLabels={};
function ensureRefreshStatus(){let el=document.getElementById('refresh-status');if(el)return el;el=document.createElement('div');el.id='refresh-status';el.className='refresh-status';el.innerHTML='<span class="refresh-spinner"></span><span>Se încarcă lista…</span>';document.body.appendChild(el);return el}
function showRefreshStatus(){ensureRefreshStatus().classList.add('show')}
function hideRefreshStatus(){const el=document.getElementById('refresh-status');if(el)el.classList.remove('show')}
function placeDeviceLabelsInColumn(){const body=document.getElementById('clients-body');const table=body?.closest('table');if(!body||!table)return;table.classList.add('device-table');const head=table.tHead?.rows?.[0];if(head&&!head.querySelector('.device-label-head')){const th=document.createElement('th');th.className='device-label-head';th.textContent='Label';head.insertBefore(th,head.cells[1]||null)}body.querySelectorAll('tr').forEach(row=>{if(row.querySelector('.device-label-cell'))return;const label=row.querySelector('.device-label-inline');if(!label)return;const td=document.createElement('td');td.className='device-label-cell';td.appendChild(label);row.insertBefore(td,row.cells[1]||null)});}
'''
if marker not in text:
    raise SystemExit('UI follow-up patch failed: device label marker not found')
text = text.replace(marker, helpers, 1)

old_render = "function renderClients(rows){ window.__lastClients=rows||[]; document.getElementById('clients-body').innerHTML = rows.map(deviceRow).join(''); bindDeviceLabelButtons(); reapplyTableSorts(); }"
new_render = "function renderClients(rows){ window.__lastClients=rows||[]; document.getElementById('clients-body').innerHTML = rows.map(deviceRow).join(''); bindDeviceLabelButtons(); placeDeviceLabelsInColumn(); reapplyTableSorts(); }"
if old_render not in text:
    raise SystemExit('UI follow-up patch failed: renderClients marker not found')
text = text.replace(old_render, new_render, 1)

# Keep the dedicated label column after the label-fetch re-render as well.
text = text.replace(
    "loadDeviceLabels().then(()=>{renderClients(window.__lastClients||[]);renderRecent(window.__lastRecent||[]);bindDeviceLabelButtons();});scheduleRefresh(refreshMs);",
    "loadDeviceLabels().then(()=>{renderClients(window.__lastClients||[]);renderRecent(window.__lastRecent||[]);bindDeviceLabelButtons();placeDeviceLabelsInColumn();});requestRefresh();",
    1,
)

# Show immediate feedback during every API refresh instead of leaving the page
# looking frozen while the 5-10 second database/state request completes.
old_refresh = "async function refresh(force=false){\n  if(refreshInFlight){ refreshPending=true; return; }"
new_refresh = "async function refresh(force=false){\n  showRefreshStatus();\n  if(refreshInFlight){ refreshPending=true; return; }"
if old_refresh not in text:
    raise SystemExit('UI follow-up patch failed: refresh opening marker not found')
text = text.replace(old_refresh, new_refresh, 1)

old_finally = "finally{refreshInFlight=false;if(refreshPending){refreshPending=false;scheduleRefresh(0)}else{scheduleRefresh(refreshMs)}}}"
new_finally = "finally{hideRefreshStatus();refreshInFlight=false;if(refreshPending){refreshPending=false;scheduleRefresh(0)}else{scheduleRefresh(refreshMs)}}}"
if old_finally not in text:
    raise SystemExit('UI follow-up patch failed: refresh finally marker not found')
text = text.replace(old_finally, new_finally, 1)

APP.write_text(text, encoding='utf-8')
print('DNS Inspector UI follow-up patch applied: dedicated label column + refresh indicator')
