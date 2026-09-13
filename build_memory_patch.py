from pathlib import Path
import re

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

# Long-lived enrichment: cache aggressively and move slow work off the request path.
text = text.replace('import os\nimport re\n', 'import os\nimport re\nimport queue\n', 1)
text = text.replace(
    'NETIFY_CACHE_HOURS = int(os.getenv("NETIFY_CACHE_HOURS", "360"))\n',
    'NETIFY_CACHE_HOURS = int(os.getenv("NETIFY_CACHE_HOURS", "4320"))  # 180 days\n',
    1,
)
text = text.replace(
    'RDAP_CACHE_HOURS = int(os.getenv("RDAP_CACHE_HOURS", "720"))\n',
    'RDAP_CACHE_HOURS = int(os.getenv("RDAP_CACHE_HOURS", "720"))  # 30 days\n',
    1,
)
text = text.replace(
    'DNS_RECORDS_CACHE_HOURS = int(os.getenv("DNS_RECORDS_CACHE_HOURS", "168"))\n',
    'DNS_RECORDS_CACHE_HOURS = int(os.getenv("DNS_RECORDS_CACHE_HOURS", "240"))  # 10 days\n',
    1,
)

# Replace the old one-thread-per-domain enrichment scheduler.
start = text.index('def refresh_domain_enrichment(domain):')
end = text.index('def resolve_dns(domain, records=None):', start)
new_enrichment = '''_enrichment_queue = queue.Queue(maxsize=500)
_enrichment_queue_lock = threading.Lock()
_enrichment_queued = set()

def _queue_domain_enrichment(domain):
    domain = str(domain or '').strip('.').lower()
    if not domain:
        return False
    with _enrichment_queue_lock:
        if domain in _enrichment_queued or domain in enrichment_refreshing:
            return False
        try:
            _enrichment_queue.put_nowait(domain)
        except queue.Full:
            return False
        _enrichment_queued.add(domain)
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


'''
text = text[:start] + new_enrichment + text[end:]

# Inspection only queues missing/expired metadata; it never performs the refresh itself.
old_inspect = '''    needs_refresh = (
        _cache_needs_refresh("netify_cache", domain, NETIFY_CACHE_HOURS)
        or _cache_needs_refresh("rdap_cache", apex_domain(domain), RDAP_CACHE_HOURS)
        or _cache_needs_refresh("dns_records_cache", domain, DNS_RECORDS_CACHE_HOURS)
    )
    if needs_refresh:
        refresh_domain_enrichment(domain)

'''
new_inspect = '''    needs_refresh = (
        _cache_needs_refresh("netify_cache", domain, NETIFY_CACHE_HOURS)
        or _cache_needs_refresh("rdap_cache", apex_domain(domain), RDAP_CACHE_HOURS)
        or _cache_needs_refresh("dns_records_cache", domain, DNS_RECORDS_CACHE_HOURS)
    )
    if needs_refresh:
        _queue_domain_enrichment(domain)

'''
if old_inspect not in text:
    raise SystemExit('memory patch failed: inspect refresh block not found')
text = text.replace(old_inspect, new_inspect, 1)

# Replace the browser polling loop with one cancellable timer and an in-flight guard.
old_js = '''async function refresh(force=false){try{const r=await fetch(buildStateUrl(),{cache:'no-store'});if(!r.ok)return;const data=await r.json();renderRecent(data.recent);updateNewDetection(data.recent);renderRecentControls(data.recent_meta,data.filter_options);if(initialDomainSnapshot&&data.recent_meta?.new_domains?.length)showNewBanner(data.recent_meta.new_domains);renderClients(data.clients);renderStats(data.stats);if(data.inspect_html!==null)document.getElementById('inspect-root').innerHTML=data.inspect_html;const stamp=formatUpdated(data.updated);document.getElementById('last-update-time').textContent=stamp.time;document.getElementById('last-update-date').textContent=stamp.date}catch(e){console.debug('refresh failed',e)}finally{setTimeout(refresh,refreshMs)}}
document.querySelectorAll('[data-status-filter]').forEach(b=>b.addEventListener('click',()=>{recentFilters.status=b.dataset.statusFilter||'';applyRecentFilterChanges()}));document.getElementById('new-filter')?.addEventListener('click',()=>{recentFilters.newOnly=!recentFilters.newOnly;applyRecentFilterChanges()});for(const [id,key] of [['classification-filter','classification'],['severity-filter','severity'],['device-filter','device'],['vendor-filter','vendor']])document.getElementById(id)?.addEventListener('change',e=>{recentFilters[key]=e.target.value;applyRecentFilterChanges()});document.getElementById('page-size')?.addEventListener('change',e=>{recentFilters.page_size=Number(e.target.value)||50;applyRecentFilterChanges()});document.getElementById('page-prev')?.addEventListener('click',()=>{if(recentFilters.page>1){recentFilters.page--;refresh(true)}});document.getElementById('page-next')?.addEventListener('click',()=>{if(recentFilters.page<recentMeta.pages){recentFilters.page++;refresh(true)}});
'''
new_js = '''let refreshTimer=null;
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
  if(refreshInFlight){ refreshPending=true; return; }
  refreshInFlight=true;
  try{const r=await fetch(buildStateUrl(),{cache:'no-store'});if(!r.ok)return;const data=await r.json();renderRecent(data.recent);updateNewDetection(data.recent);renderRecentControls(data.recent_meta,data.filter_options);if(initialDomainSnapshot&&data.recent_meta?.new_domains?.length)showNewBanner(data.recent_meta.new_domains);renderClients(data.clients);renderStats(data.stats);if(data.inspect_html!==null)document.getElementById('inspect-root').innerHTML=data.inspect_html;const stamp=formatUpdated(data.updated);document.getElementById('last-update-time').textContent=stamp.time;document.getElementById('last-update-date').textContent=stamp.date}catch(e){console.debug('refresh failed',e)}finally{refreshInFlight=false;if(refreshPending){refreshPending=false;scheduleRefresh(0)}else{scheduleRefresh(refreshMs)}}}
document.querySelectorAll('[data-status-filter]').forEach(b=>b.addEventListener('click',()=>{recentFilters.status=b.dataset.statusFilter||'';applyRecentFilterChanges()}));document.getElementById('new-filter')?.addEventListener('click',()=>{recentFilters.newOnly=!recentFilters.newOnly;applyRecentFilterChanges()});for(const [id,key] of [['classification-filter','classification'],['severity-filter','severity'],['device-filter','device'],['vendor-filter','vendor']])document.getElementById(id)?.addEventListener('change',e=>{recentFilters[key]=e.target.value;applyRecentFilterChanges()});document.getElementById('page-size')?.addEventListener('change',e=>{recentFilters.page_size=Number(e.target.value)||50;applyRecentFilterChanges()});document.getElementById('page-prev')?.addEventListener('click',()=>{if(recentFilters.page>1){recentFilters.page--;requestRefresh()}});document.getElementById('page-next')?.addEventListener('click',()=>{if(recentFilters.page<recentMeta.pages){recentFilters.page++;requestRefresh()}});
'''
if old_js not in text:
    raise SystemExit('memory patch failed: JS refresh block not found')
text = text.replace(old_js, new_js, 1)
text = text.replace(
    'function applyRecentFilterChanges(){recentFilters.page=1;refresh(true)}',
    'function applyRecentFilterChanges(){recentFilters.page=1;requestRefresh()}',
    1,
)
text = text.replace(
    "const initialStamp=formatUpdated({{ updated|tojson }});document.getElementById('last-update-time').textContent=initialStamp.time;document.getElementById('last-update-date').textContent=initialStamp.date;setTimeout(()=>refresh(true),refreshMs);",
    "const initialStamp=formatUpdated({{ updated|tojson }});document.getElementById('last-update-time').textContent=initialStamp.time;document.getElementById('last-update-date').textContent=initialStamp.date;scheduleRefresh(refreshMs);",
    1,
)

# Start exactly one enrichment worker alongside the ingest worker.
old_main = '''if __name__ == "__main__":
    init_db()
    threading.Thread(target=worker, daemon=True).start()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
'''
new_main = '''if __name__ == "__main__":
    init_db()
    threading.Thread(target=worker, daemon=True).start()
    threading.Thread(target=_enrichment_worker, daemon=True, name="enrichment-queue").start()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
'''
if old_main not in text:
    raise SystemExit('memory patch failed: main block not found')
text = text.replace(old_main, new_main, 1)

APP.write_text(text, encoding='utf-8')
print('DNS Inspector 0.7.8 memory/enrichment patch applied')
