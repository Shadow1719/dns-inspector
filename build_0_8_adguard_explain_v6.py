from pathlib import Path
import re

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

# Keep the lightweight runtime indicators independent from the main dashboard
# refresh chain. This protects Uptime/RAM even if the main JS is busy replacing
# inspect HTML or a later UI patch changes its scheduling.
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
  updateRuntimeIndicators();
  window.setInterval(updateRuntimeIndicators,5000);
})();
</script>'''

anchor='</body></html>'
if anchor not in text:
    raise SystemExit('AdGuard explain v6: closing body marker not found')
text=text.replace(anchor, script+'\n'+anchor, 1)

# The product UI should explain the AdGuard decision directly in the card;
# do not leave a secondary technical accordion ("Show more"/"Technical details")
# in the live explanation panel.
# v3 creates the accordion inside a JavaScript string, so remove that generated
# block after v5 has finished wiring the live refresh script.
text, removed_details = re.subn(
    r"\n\s*const details='<details class=\"adg-details\">.*?</details>';",
    "",
    text,
    count=1,
    flags=re.S,
)
if removed_details != 1:
    raise SystemExit(f'AdGuard explain v6: expected technical-details block once, found {removed_details}')

text, removed_concat = re.subn(r"\+details(?=</div>';)" , "", text, count=1)
if removed_concat != 1:
    raise SystemExit(f'AdGuard explain v6: expected details concat once, found {removed_concat}')

compile(text, str(APP), 'exec')
APP.write_text(text, encoding='utf-8')
print('DEV AdGuard explanation v6 observability bridge applied; technical details accordion removed')
