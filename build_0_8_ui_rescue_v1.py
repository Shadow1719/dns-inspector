from pathlib import Path

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

MARKER = '/* DNS Inspector 0.8 UI rescue v1 */'
if MARKER in text:
    print('DEV 0.8 UI rescue already applied')
    raise SystemExit(0)

# Dedicated lightweight endpoint for analytics + dashboard timestamp.
route = r'''

# === DEV 0.8 UI rescue: independent dashboard data endpoint ===
@app.route('/api/dev/analytics')
def api_dev_analytics():
    try:
        return jsonify({'ok': True, 'updated': utcnow(), 'stats': get_stats()})
    except Exception as e:
        print('dev analytics error:', repr(e), flush=True)
        return jsonify({'ok': False, 'updated': utcnow(), 'stats': {'domains': [], 'devices': [], 'vendors': [], 'ips': []}, 'error': str(e)}), 200
'''
anchor = '\n@app.route("/device")\n'
if 'def api_dev_analytics()' not in text:
    if anchor not in text:
        raise SystemExit('UI rescue: detail route anchor not found')
    text = text.replace(anchor, route + anchor, 1)

css = r'''

/* DNS Inspector 0.8 UI rescue v1 */
.ui-rescue-status{display:inline-flex;align-items:center;gap:6px;font-size:.76rem;font-weight:750;padding:3px 7px;border-radius:999px;border:1px solid #30363d;background:#161b22}.ui-rescue-dot{width:8px;height:8px;border-radius:50%;display:inline-block;background:#8b949e}.ui-rescue-online .ui-rescue-dot{background:#3fb950}.ui-rescue-offline .ui-rescue-dot{background:#f85149}.ui-rescue-unknown .ui-rescue-dot{background:#d29922}.ui-rescue-ping{padding:3px 7px;font-size:.68rem;border-radius:6px;margin-left:5px}.ui-rescue-ping:disabled{opacity:.55;cursor:default}.ui-rescue-adg{border-left:4px solid #8b949e;border-radius:10px;background:#0d1117;padding:12px 13px;margin-top:2px}.ui-rescue-adg.red{border-color:#f85149}.ui-rescue-adg.yellow{border-color:#d29922}.ui-rescue-adg.orange{border-color:#db6d28}.ui-rescue-adg.blue{border-color:#58a6ff}.ui-rescue-adg.gray{border-color:#8b949e}.ui-rescue-adg-head{display:flex;align-items:center;justify-content:space-between;gap:8px}.ui-rescue-adg-main{display:flex;flex-wrap:wrap;align-items:center;gap:8px}.ui-rescue-adg-label{font-weight:800;font-size:1.02rem}.ui-rescue-adg-conf{font-size:.78rem;color:#8b949e}.ui-rescue-adg-summary{margin-top:6px;font-weight:700}.ui-rescue-adg-explanation{margin-top:3px;color:#c9d1d9}.ui-rescue-adg-evidence{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-top:9px}.ui-rescue-adg-chip{padding:4px 8px;border-radius:999px;border:1px solid #30363d;background:#161b22;color:#e6edf3;font-size:.76rem;font-weight:700}.ui-rescue-adg-chip.red{background:#3b1114;border-color:#6e1c24;color:#ffb4b4}.ui-rescue-adg-chip.yellow{background:#3a2d0b;border-color:#8f6b1c;color:#f2cc60}.ui-rescue-adg-chip.orange{background:#3a1d0b;border-color:#8b4a1c;color:#ffb86b}.ui-rescue-adg-chip.blue{background:#102b45;border-color:#24557e;color:#9ed0ff}.ui-rescue-adg-tech{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px;margin-top:9px}.ui-rescue-adg-tech>div{padding:7px 9px;border:1px solid #21262d;border-radius:8px;background:#11161d}.ui-rescue-adg-tech span{display:block;color:#8b949e;font-size:.68rem;text-transform:uppercase;letter-spacing:.05em;margin-bottom:3px}.ui-rescue-adg-tech b{display:block;font-size:.78rem;overflow-wrap:anywhere}@media(max-width:900px){.ui-rescue-adg-tech{grid-template-columns:1fr}}
'''
if MARKER not in text:
    if '</style>' not in text:
        raise SystemExit('UI rescue: style marker not found')
    text = text.replace('</style>', css + '</style>', 1)

script = r'''<script>
/* DNS Inspector 0.8 UI rescue v1 */
(function(){
  const esc = v => String(v ?? '').replace(/[&<>\"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}[c]));
  const adgTone = v => { const x=String(v||'').toLowerCase(); if(x.includes('threat')) return 'red'; if(x.includes('advertising')||x.includes('tracking')) return 'yellow'; if(x.includes('gambling')||x.includes('dns security')) return 'orange'; if(x.includes('allowed')||x.includes('custom')) return 'blue'; return 'gray'; };
  const fmtUpdated = iso => { const d=new Date(iso); if(Number.isNaN(d.getTime())) return; const t=document.getElementById('last-update-time'), day=document.getElementById('last-update-date'); if(t)t.textContent=d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}); if(day)day.textContent=d.toLocaleDateString([], {year:'numeric',month:'short',day:'numeric'}); };

  function renderBars(id, items){
    const el=document.getElementById(id); if(!el)return;
    if(!Array.isArray(items)||!items.length){el.innerHTML='<div class="sub">No data yet.</div>';return;}
    const max=Math.max(...items.map(x=>Number(x.value)||0),1);
    el.innerHTML=items.map(x=>{ const v=Number(x.value)||0; const pct=Math.max(2,Math.round(v/max*100)); const label=esc(x.label); const left=x.href?`<a class="bar-label" href="${esc(x.href)}">${label}</a>`:`<span class="bar-label">${label}</span>`; return `<div class="bar-row">${left}<div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div><span class="bar-value">${esc(v)}</span></div>`; }).join('');
  }
  function renderAnalytics(stats){ if(!stats)return; renderBars('chart-domains',stats.domains); renderBars('chart-devices',stats.devices); renderBars('chart-vendors',stats.vendors); renderBars('chart-ips',stats.ips); }
  async function loadAnalytics(){ try{ const r=await fetch('/api/dev/analytics',{cache:'no-store'}); const d=await r.json(); if(d.ok!==false){fmtUpdated(d.updated);renderAnalytics(d.stats);} }catch(e){console.debug('UI rescue analytics failed',e);} }

  let pingStatuses={};
  function pingLabel(s){ if(!s)return 'Unknown'; return s.online ? 'Online' : 'Offline'; }
  function pingClass(s){ return s ? (s.online?'ui-rescue-online':'ui-rescue-offline') : 'ui-rescue-unknown'; }
  function ipButton(ip,s){ return `<span class="ui-rescue-ip" data-ui-rescue-ip="${esc(ip)}"><span class="ui-rescue-status ${pingClass(s)}"><span class="ui-rescue-dot"></span><span class="ui-rescue-status-label">${pingLabel(s)}</span></span><button type="button" class="ui-rescue-ping" data-ui-rescue-ping="${esc(ip)}">Ping</button></span>`; }
  function decorateDeviceTable(){
    const table=document.getElementById('clients-table'); const body=document.getElementById('clients-body'); if(!table||!body)return;
    const head=table.tHead?.rows?.[0];
    if(head && !head.querySelector('[data-ui-rescue-status-head]')){ const th=document.createElement('th'); th.textContent='Status'; th.dataset.uiRescueStatusHead='1'; head.insertBefore(th, head.lastElementChild); }
    body.querySelectorAll('tr').forEach(row=>{
      if(row.querySelector('[data-ui-rescue-device-status]')) return;
      const ipLinks=Array.from(row.querySelectorAll('a.link-ip'));
      const ips=ipLinks.map(a=>(a.textContent||'').trim()).filter(Boolean);
      const overall=ips.map(ip=>pingStatuses[ip]).filter(Boolean);
      const anyOnline=overall.some(s=>s.online); const allOffline=overall.length===ips.length && overall.length>0 && overall.every(s=>!s.online);
      const label=anyOnline?'Online':(allOffline?'Offline':'Unknown');
      const statusCell=document.createElement('td'); statusCell.dataset.uiRescueDeviceStatus='1';
      statusCell.innerHTML=`<span class="ui-rescue-status ${anyOnline?'ui-rescue-online':allOffline?'ui-rescue-offline':'ui-rescue-unknown'}"><span class="ui-rescue-dot"></span><span>${label}</span></span>`;
      if(row.cells.length) row.insertBefore(statusCell,row.lastElementChild); else row.appendChild(statusCell);
      ipLinks.forEach(a=>{ const ip=(a.textContent||'').trim(); if(!ip||a.parentElement?.querySelector(`[data-ui-rescue-ip="${CSS.escape(ip)}"]`))return; const wrap=document.createElement('span'); wrap.innerHTML=ipButton(ip,pingStatuses[ip]); a.insertAdjacentElement('afterend',wrap.firstElementChild); });
    });
    bindPingButtons();
  }
  function updateDeviceTable(){
    document.querySelectorAll('[data-ui-rescue-ip]').forEach(w=>{ const ip=w.dataset.uiRescueIp; const s=pingStatuses[ip]; const st=w.querySelector('.ui-rescue-status'); const label=w.querySelector('.ui-rescue-status-label'); const btn=w.querySelector('button'); if(st){st.className='ui-rescue-status '+pingClass(s); if(label)label.textContent=pingLabel(s);} if(btn)btn.disabled=false; });
    document.querySelectorAll('#clients-body tr').forEach(row=>{ const ipLinks=Array.from(row.querySelectorAll('a.link-ip')); const states=ipLinks.map(a=>pingStatuses[(a.textContent||'').trim()]).filter(Boolean); const any=states.some(s=>s.online); const all=states.length===ipLinks.length && states.length>0 && states.every(s=>!s.online); const cell=row.querySelector('[data-ui-rescue-device-status] .ui-rescue-status'); const text=cell?.querySelector('span:last-child'); if(cell){cell.className='ui-rescue-status '+(any?'ui-rescue-online':all?'ui-rescue-offline':'ui-rescue-unknown'); if(text)text.textContent=any?'Online':all?'Offline':'Unknown';}});
  }
  function bindPingButtons(){document.querySelectorAll('[data-ui-rescue-ping]').forEach(btn=>{if(btn.dataset.bound)return;btn.dataset.bound='1';btn.addEventListener('click',async e=>{e.preventDefault();e.stopPropagation();const ip=btn.dataset.uiRescuePing;btn.disabled=true;btn.textContent='…';try{const r=await fetch('/api/ip/ping',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})});const d=await r.json();if(!d.ok)throw new Error(d.error||'Ping failed');pingStatuses[ip]=d.result;updateDeviceTable();}catch(err){pingStatuses[ip]={online:false,error:err.message,last_checked:Date.now()/1000};updateDeviceTable();}finally{btn.disabled=false;btn.textContent='Ping';}});});}
  async function loadPingStatuses(){try{const r=await fetch('/api/ip/ping/status',{cache:'no-store'});const d=await r.json();pingStatuses=d.statuses||{};decorateDeviceTable();updateDeviceTable();}catch(e){console.debug('UI rescue ping status failed',e);decorateDeviceTable();}}

  async function loadAdguardIntoTarget(){
    const root=document.getElementById('inspect-root'); if(!root)return;
    const headings=Array.from(root.querySelectorAll('h1,h2,h3,h4,div,strong,span'));
    const targetHeading=headings.find(el=>(el.textContent||'').replace(/\s+/g,' ').trim()==='Why is this here?');
    if(!targetHeading)return;
    const target=targetHeading.nextElementSibling || targetHeading.parentElement?.querySelector('.signal');
    if(!target)return;
    if(target.dataset.uiRescueAdg==='1') return;
    const sourceCard=Array.from(root.querySelectorAll('.adguard-why-card')).find(Boolean);
    if(sourceCard) sourceCard.style.display='none';
    const q=document.querySelector('input[name="q"]')?.value?.trim(); if(!q)return;
    target.dataset.uiRescueAdg='1';
    target.className='';
    target.innerHTML=`<div class="ui-rescue-adg gray"><div class="ui-rescue-adg-head"><div class="ui-rescue-adg-main"><span class="ui-rescue-adg-label">Checking AdGuard decision…</span></div><button type="button" class="ui-rescue-adg-refresh">Refresh</button></div><div class="ui-rescue-adg-body sub">Loading…</div></div>`;
    const card=target.firstElementChild; const body=card.querySelector('.ui-rescue-adg-body'); const refresh=card.querySelector('.ui-rescue-adg-refresh');
    const load=async()=>{body.textContent='Checking the current AdGuard decision…';try{const r=await fetch('/api/adguard/explain?domain='+encodeURIComponent(q),{cache:'no-store'});const d=await r.json();const tone=adgTone(d.verdict);card.className='ui-rescue-adg '+tone;const tech=d.technical||{};const evidence=(d.evidence||[]);card.innerHTML=`<div class="ui-rescue-adg-head"><div class="ui-rescue-adg-main"><span class="ui-rescue-adg-label">${esc(d.verdict||'Unknown')}</span><span class="ui-rescue-adg-conf">Confidence: ${esc(d.confidence||'Low')}</span><span class="status-pill status-${esc((d.status||'Unknown').toLowerCase())}">${esc(d.status||'Unknown')}</span></div><button type="button" class="ui-rescue-adg-refresh">Refresh</button></div><div class="ui-rescue-adg-summary">${esc(d.summary||'')}</div><div class="ui-rescue-adg-explanation">${esc(d.explanation||'')}</div>${evidence.length?`<div class="ui-rescue-adg-evidence"><span class="sub">Evidence:</span>${evidence.map(e=>`<button type="button" class="ui-rescue-adg-chip ${adgTone(e.label)}" title="${esc(e.source||'AdGuard')}">${esc(e.label)}</button>`).join('')}</div>`:''}<div class="ui-rescue-adg-tech"><div><span>Reason</span><b class="mono">${esc(tech.reason||'—')}</b></div><div><span>Matched rule</span><b class="mono">${esc(tech.rule||'—')}</b></div><div><span>Filter list ID</span><b class="mono">${esc(tech.filter_list_id||'—')}</b></div><div><span>Source</span><b>${esc(evidence[0]?.source||'AdGuard')}</b></div></div>`; const next=card.querySelector('.ui-rescue-adg-refresh'); next.addEventListener('click',load); card.querySelectorAll('.ui-rescue-adg-chip').forEach((b,i)=>b.addEventListener('click',()=>{const e=evidence[i];alert((e.label||'Evidence')+'\n\nSource: '+(e.source||'AdGuard')+'\nRule: '+(e.rule||'—')+(e.filter_id?'\nFilter list ID: '+e.filter_id:''));}));}catch(e){body.innerHTML='<span class="error">Could not explain the AdGuard decision right now.</span>';}};
    refresh.addEventListener('click',load); load();
  }
  function rescueInspect(){try{loadAdguardIntoTarget();}catch(e){console.debug('UI rescue AdGuard failed',e);}}

  async function start(){
    loadAnalytics();
    loadPingStatuses();
    rescueInspect();
    setInterval(loadAnalytics,5000);
    const root=document.getElementById('inspect-root'); if(root){const mo=new MutationObserver(()=>{rescueInspect();});mo.observe(root,{childList:true,subtree:true});}
    const clients=document.getElementById('clients-body'); if(clients){const mo2=new MutationObserver(()=>{decorateDeviceTable();updateDeviceTable();});mo2.observe(clients,{childList:true,subtree:true});}
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',start,{once:true}); else start();
})();
</script>'''
anchor='</body></html>'
text=text.replace(anchor,script+'\n'+anchor,1)

compile(text,str(APP),'exec')
APP.write_text(text,encoding='utf-8')
print('DEV 0.8 UI rescue v1 applied')
