from pathlib import Path

APP = Path("/app/app.py")
text = APP.read_text(encoding="utf-8")

# Long-lived enrichment is cached aggressively. UI polling must never turn into
# repeated external lookups or a growing collection of enrichment threads.
text = text.replace(
    'import os\nimport re\n',
    'import os\nimport re\nimport queue\n',
    1,
)
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

old_refresh = '''def refresh_domain_enrichment(domain):\n    """Refresh slow external enrichment in the background, never in the request path."""\n    domain = str(domain or '').strip('.').lower()\n    if not domain:\n        return\n    with enrichment_lock:\n        if domain in enrichment_refreshing:\n            return\n        enrichment_refreshing.add(domain)\n\n    def run():\n        try:\n            netify_lookup(domain, force=True)\n            rdap_lookup(domain, force=True)\n            dns_records_lookup(domain, force=True)\n        except Exception as e:\n            print("enrichment refresh error:", repr(e), flush=True)\n        finally:\n            with enrichment_lock:\n                enrichment_refreshing.discard(domain)\n\n    threading.Thread(target=run, daemon=True, name=f"enrich:{domain}").start()\n\n\n'''
new_refresh = '''# Enrichment is deliberately serialized. New domains can arrive in bursts,\n# but enrichment is non-critical and must never compete with UI polling or ingest.\n_enrichment_queue = queue.Queue(maxsize=500)\n_enrichment_queue_lock = threading.Lock()\n_enrichment_queued = set()\n\ndef _queue_domain_enrichment(domain):\n    domain = str(domain or '').strip('.').lower()\n    if not domain:\n        return False\n    with _enrichment_queue_lock:\n        if domain in _enrichment_queued or domain in enrichment_refreshing:\n            return False\n        try:\n            _enrichment_queue.put_nowait(domain)\n        except queue.Full:\n            return False\n        _enrichment_queued.add(domain)\n    return True\n\ndef _enrichment_needs_refresh(table, domain, ttl_hours):\n    return _cache_needs_refresh(table, domain, ttl_hours)\n\ndef _enrichment_worker():\n    while True:\n        domain = _enrichment_queue.get()\n        with _enrichment_queue_lock:\n            _enrichment_queued.discard(domain)\n        with enrichment_lock:\n            enrichment_refreshing.add(domain)\n        try:\n            # Re-check every source at execution time. Existing, fresh data is\n            # never touched, and one failed source never erases another source.\n            if _enrichment_needs_refresh("netify_cache", domain, NETIFY_CACHE_HOURS):\n                netify_lookup(domain, force=True)\n            if _enrichment_needs_refresh("rdap_cache", apex_domain(domain), RDAP_CACHE_HOURS):\n                rdap_lookup(domain, force=True)\n            if _enrichment_needs_refresh("dns_records_cache", domain, DNS_RECORDS_CACHE_HOURS):\n                dns_records_lookup(domain, force=True)\n        except Exception as e:\n            print("enrichment worker error:", repr(e), flush=True)\n        finally:\n            with enrichment_lock:\n                enrichment_refreshing.discard(domain)\n            enrichment_queue_done = _enrichment_queue.task_done()\n            # Keep enrichment deliberately gentle for upstreams and the local DB.\n            time.sleep(max(0.0, float(os.getenv("ENRICHMENT_DELAY_SECONDS", "1.0"))))\n\n'''
if old_refresh not in text:
    raise SystemExit("memory patch failed: refresh_domain_enrichment block not found")
text = text.replace(old_refresh, new_refresh, 1)

old_inspect = '''    needs_refresh = (\n        _cache_needs_refresh("netify_cache", domain, NETIFY_CACHE_HOURS)\n        or _cache_needs_refresh("rdap_cache", apex_domain(domain), RDAP_CACHE_HOURS)\n        or _cache_needs_refresh("dns_records_cache", domain, DNS_RECORDS_CACHE_HOURS)\n    )\n    if needs_refresh:\n        refresh_domain_enrichment(domain)\n\n'''
new_inspect = '''    needs_refresh = (\n        _cache_needs_refresh("netify_cache", domain, NETIFY_CACHE_HOURS)\n        or _cache_needs_refresh("rdap_cache", apex_domain(domain), RDAP_CACHE_HOURS)\n        or _cache_needs_refresh("dns_records_cache", domain, DNS_RECORDS_CACHE_HOURS)\n    )\n    if needs_refresh:\n        _queue_domain_enrichment(domain)\n\n'''
if old_inspect not in text:
    raise SystemExit("memory patch failed: inspect refresh block not found")
text = text.replace(old_inspect, new_inspect, 1)

# Replace the self-rescheduling browser polling loop with one cancellable timer.\nold_js = '''async function refresh(force=false){try{const r=await fetch(buildStateUrl(),{cache:'no-store'});if(!r.ok)return;const data=await r.json();renderRecent(data.recent);updateNewDetection(data.recent);renderRecentControls(data.recent_meta,data.filter_options);if(initialDomainSnapshot&&data.recent_meta?.new_domains?.length)showNewBanner(data.recent_meta.new_domains);renderClients(data.clients);renderStats(data.stats);if(data.inspect_html!==null)document.getElementById('inspect-root').innerHTML=data.inspect_html;const stamp=formatUpdated(data.updated);document.getElementById('last-update-time').textContent=stamp.time;document.getElementById('last-update-date').textContent=stamp.date}catch(e){console.debug('refresh failed',e)}finally{setTimeout(refresh,refreshMs)}}\ndocument.querySelectorAll('[data-status-filter]').forEach(b=>b.addEventListener('click',()=>{recentFilters.status=b.dataset.statusFilter||'';applyRecentFilterChanges()}));document.getElementById('new-filter')?.addEventListener('click',()=>{recentFilters.newOnly=!recentFilters.newOnly;applyRecentFilterChanges()});for(const [id,key] of [['classification-filter','classification'],['severity-filter','severity'],['device-filter','device'],['vendor-filter','vendor']])document.getElementById(id)?.addEventListener('change',e=>{recentFilters[key]=e.target.value;applyRecentFilterChanges()});document.getElementById('page-size')?.addEventListener('change',e=>{recentFilters.page_size=Number(e.target.value)||50;applyRecentFilterChanges()});document.getElementById('page-prev')?.addEventListener('click',()=>{if(recentFilters.page>1){recentFilters.page--;refresh(true)}});document.getElementById('page-next')?.addEventListener('click',()=>{if(recentFilters.page<recentMeta.pages){recentFilters.page++;refresh(true)}});\n'''
new_js = '''let refreshTimer=null;\nlet refreshInFlight=false;\nlet refreshPending=false;\nfunction scheduleRefresh(delay=refreshMs){\n  if(refreshTimer) clearTimeout(refreshTimer);\n  refreshTimer=setTimeout(()=>{ refreshTimer=null; refresh(); }, Math.max(250, delay));\n}\nfunction requestRefresh(){\n  if(refreshTimer) { clearTimeout(refreshTimer); refreshTimer=null; }\n  if(refreshInFlight){ refreshPending=true; return; }\n  refresh();\n}\nasync function refresh(force=false){\n  if(refreshInFlight){ refreshPending=true; return; }\n  refreshInFlight=true;\n  try{const r=await fetch(buildStateUrl(),{cache:'no-store'});if(!r.ok)return;const data=await r.json();renderRecent(data.recent);updateNewDetection(data.recent);renderRecentControls(data.recent_meta,data.filter_options);if(initialDomainSnapshot&&data.recent_meta?.new_domains?.length)showNewBanner(data.recent_meta.new_domains);renderClients(data.clients);renderStats(data.stats);if(data.inspect_html!==null)document.getElementById('inspect-root').innerHTML=data.inspect_html;const stamp=formatUpdated(data.updated);document.getElementById('last-update-time').textContent=stamp.time;document.getElementById('last-update-date').textContent=stamp.date}catch(e){console.debug('refresh failed',e)}finally{refreshInFlight=false;if(refreshPending){refreshPending=false;scheduleRefresh(0)}else{scheduleRefresh(refreshMs)}}}\ndocument.querySelectorAll('[data-status-filter]').forEach(b=>b.addEventListener('click',()=>{recentFilters.status=b.dataset.statusFilter||'';applyRecentFilterChanges()}));document.getElementById('new-filter')?.addEventListener('click',()=>{recentFilters.newOnly=!recentFilters.newOnly;applyRecentFilterChanges()});for(const [id,key] of [['classification-filter','classification'],['severity-filter','severity'],['device-filter','device'],['vendor-filter','vendor']])document.getElementById(id)?.addEventListener('change',e=>{recentFilters[key]=e.target.value;applyRecentFilterChanges()});document.getElementById('page-size')?.addEventListener('change',e=>{recentFilters.page_size=Number(e.target.value)||50;applyRecentFilterChanges()});document.getElementById('page-prev')?.addEventListener('click',()=>{if(recentFilters.page>1){recentFilters.page--;requestRefresh()}});document.getElementById('page-next')?.addEventListener('click',()=>{if(recentFilters.page<recentMeta.pages){recentFilters.page++;requestRefresh()}});\n'''
if old_js not in text:
    raise SystemExit("memory patch failed: JS refresh block not found")
text = text.replace(old_js, new_js, 1)
text = text.replace('function applyRecentFilterChanges(){recentFilters.page=1;refresh(true)}', 'function applyRecentFilterChanges(){recentFilters.page=1;requestRefresh()}', 1)
text = text.replace('const initialStamp=formatUpdated({{ updated|tojson }});document.getElementById(\'last-update-time\').textContent=initialStamp.time;document.getElementById(\'last-update-date\').textContent=initialStamp.date;setTimeout(()=>refresh(true),refreshMs);', 'const initialStamp=formatUpdated({{ updated|tojson }});document.getElementById(\'last-update-time\').textContent=initialStamp.time;document.getElementById(\'last-update-date\').textContent=initialStamp.date;scheduleRefresh(refreshMs);', 1)

# Start exactly one enrichment worker alongside the existing ingest worker.
old_main = '''if __name__ == "__main__":\n    init_db()\n    threading.Thread(target=worker, daemon=True).start()\n    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))\n'''
new_main = '''if __name__ == "__main__":\n    init_db()\n    threading.Thread(target=worker, daemon=True).start()\n    threading.Thread(target=_enrichment_worker, daemon=True, name="enrichment-queue").start()\n    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))\n'''
if old_main not in text:
    raise SystemExit("memory patch failed: main block not found")
text = text.replace(old_main, new_main, 1)

APP.write_text(text, encoding="utf-8")
print("DNS Inspector 0.7.8 memory/enrichment patch applied")
