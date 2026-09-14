from pathlib import Path

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

MARKER = '/* DNS Inspector 0.8 observability independent refresh */'
if MARKER in text:
    print('DEV AdGuard explanation v6 observability bridge already applied')
    raise SystemExit(0)

script = '''<script>
/* DNS Inspector 0.8 observability independent refresh */
(function(){
  function formatUptime(seconds){
    let s=Math.max(0,Math.floor(Number(seconds)||0));
    const d=Math.floor(s/86400); s%=86400;
    const h=Math.floor(s/3600); s%=3600;
    const m=Math.floor(s/60); s%=60;
    if(d) return d+'d '+h+'h '+m+'m';
    if(h) return h+'h '+m+'m '+s+'s';
    if(m) return m+'m '+s+'s';
    return s+'s';
  }
  function formatRam(value){
    const mb=Number(value);
    return Number.isFinite(mb) ? (mb >= 100 ? mb.toFixed(0) : mb.toFixed(1))+' MB' : '—';
  }
  async function updateRuntimeIndicators(){
    try{
      const r=await fetch('/api/observability',{cache:'no-store'});
      if(!r.ok) return;
      const d=await r.json();
      const u=document.getElementById('obs-uptime');
      const m=document.getElementById('obs-memory');
      if(u) u.textContent='Uptime '+formatUptime(d.uptime_seconds);
      if(m) m.textContent='RAM '+formatRam(d.ram_mb);
    }catch(e){
      console.debug('runtime indicators refresh failed',e);
    }
  }

  function removeTechnicalDetails(root){
    const scope=root || document;
    scope.querySelectorAll('details.adg-details').forEach(function(el){ el.remove(); });
  }

  updateRuntimeIndicators();
  window.setInterval(updateRuntimeIndicators,5000);

  // The AdGuard explanation is re-inserted into #inspect-root during live
  // state refreshes. Remove the legacy technical accordion after every insert.
  removeTechnicalDetails(document);
  const inspectRoot=document.getElementById('inspect-root');
  if(inspectRoot){
    const observer=new MutationObserver(function(){ removeTechnicalDetails(inspectRoot); });
    observer.observe(inspectRoot,{childList:true,subtree:true});
  }
})();
</script>'''

anchor='</body></html>'
if anchor not in text:
    raise SystemExit('AdGuard explain v6: closing body marker not found')
text=text.replace(anchor, script+'\n'+anchor, 1)

compile(text, str(APP), 'exec')
APP.write_text(text, encoding='utf-8')
print('DEV AdGuard explanation v6 observability bridge applied; legacy technical-details accordion removed at runtime')
