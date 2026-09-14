from pathlib import Path

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

MARKER = '/* DNS Inspector 0.8 usable controls v2 */'
if MARKER in text:
    print('DEV 0.8 usable controls patch already applied')
    raise SystemExit(0)

# Keep the server-side option spelling identical to the classifier.
text = text.replace('"Telemetry / Tracking"', '"Telemetry / tracking"', 1)

# Render filter options in the initial page instead of waiting for a live-state
# refresh. This keeps the controls useful even when /api/state is slow or fails.
replacements = {
    '<select id="classification-filter" class="filter-select"><option value="">All</option></select>':
        '<select id="classification-filter" class="filter-select"><option value="">All</option>{% for value in filter_options.classifications %}<option value="{{ value }}">{{ value }}</option>{% endfor %}</select>',
    '<select id="severity-filter" class="filter-select"><option value="">All</option></select>':
        '<select id="severity-filter" class="filter-select"><option value="">All</option>{% for value in filter_options.severities %}<option value="{{ value }}">{{ value }}</option>{% endfor %}</select>',
    '<select id="device-filter" class="filter-select"><option value="">All</option></select>':
        '<select id="device-filter" class="filter-select"><option value="">All</option>{% for option in filter_options.devices %}<option value="{{ option.value }}">{{ option.label }}</option>{% endfor %}</select>',
    '<select id="vendor-filter" class="filter-select"><option value="">All</option></select>':
        '<select id="vendor-filter" class="filter-select"><option value="">All</option>{% for value in filter_options.vendors %}<option value="{{ value }}">{{ value }}</option>{% endfor %}</select>',
}
for old, new in replacements.items():
    if old not in text:
        raise SystemExit(f'usable controls patch: filter marker not found: {old[:60]}')
    text = text.replace(old, new, 1)

# Every full-page template render needs the initial option catalog.
text = text.replace(
    'stats=get_stats(),error=None)',
    'filter_options=get_filter_options(),stats=get_stats(),error=None)',
)

script = r'''<script>
/* DNS Inspector 0.8 usable controls v2 */
(function(){
  function activateTab(name){
    if(!name) return;
    document.querySelectorAll('.tab-btn').forEach(function(b){
      b.classList.toggle('active', b.dataset.tab === name);
      b.setAttribute('aria-selected', b.dataset.tab === name ? 'true' : 'false');
    });
    document.querySelectorAll('.tab-panel').forEach(function(p){
      p.classList.toggle('active', p.dataset.panel === name);
    });
    try{ localStorage.setItem('dnsInspectorTab', name); }catch(e){}
  }

  function setQueryParam(name, value){
    const url = new URL(window.location.href);
    if(value === '' || value === null || value === undefined || value === false){
      url.searchParams.delete(name);
    }else{
      url.searchParams.set(name, String(value));
    }
    url.searchParams.delete('page');
    window.location.assign(url.toString());
  }

  function syncControlsFromUrl(){
    const p = new URLSearchParams(window.location.search);
    const status = p.get('status') || '';
    document.querySelectorAll('[data-status-filter]').forEach(function(b){
      b.classList.toggle('active', (b.dataset.statusFilter || '') === status);
    });
    const nf = document.getElementById('new-filter');
    if(nf) nf.classList.toggle('active', p.get('new') === '1');
    [['classification-filter','classification'],['severity-filter','severity'],['device-filter','device'],['vendor-filter','vendor'],['page-size','page_size']].forEach(function(pair){
      const el=document.getElementById(pair[0]);
      if(el && p.has(pair[1])) el.value=p.get(pair[1]);
    });
    let tab='overview';
    try{
      const saved=localStorage.getItem('dnsInspectorTab');
      if(saved && ['overview','devices','analytics'].includes(saved)) tab=saved;
    }catch(e){}
    const hasInspect=!!document.getElementById('inspect-root')?.textContent.trim();
    const q=p.get('q') || '';
    if(q || hasInspect) tab='overview';
    activateTab(tab);
  }

  function sortTable(table, key, direction){
    if(!table || !table.tBodies.length) return;
    var headers = Array.from(table.querySelectorAll('th.sortable'));
    var header = headers.find(function(h){ return h.dataset.sortKey === key; });
    if(!header) return;
    var type = header.dataset.sortType || 'text';
    headers.forEach(function(h){ h.classList.remove('sort-asc','sort-desc'); h.setAttribute('aria-sort','none'); });
    header.classList.add(direction === 1 ? 'sort-asc' : 'sort-desc');
    header.setAttribute('aria-sort', direction === 1 ? 'ascending' : 'descending');
    var body = table.tBodies[0];
    Array.from(body.rows).sort(function(a,b){
      var av = a.dataset['sort' + key.charAt(0).toUpperCase() + key.slice(1)] || '';
      var bv = b.dataset['sort' + key.charAt(0).toUpperCase() + key.slice(1)] || '';
      if(type === 'number') { av = Number(av) || 0; bv = Number(bv) || 0; }
      else { av = String(av).toLowerCase(); bv = String(bv).toLowerCase(); }
      if(av < bv) return -1 * direction;
      if(av > bv) return 1 * direction;
      return 0;
    }).forEach(function(row){ body.appendChild(row); });
  }

  var sortState = {};

  document.addEventListener('click', function(ev){
    var tab=ev.target.closest && ev.target.closest('.tab-btn');
    if(tab){
      ev.preventDefault();
      ev.stopImmediatePropagation();
      activateTab(tab.dataset.tab || 'overview');
      return;
    }

    var status=ev.target.closest && ev.target.closest('[data-status-filter]');
    if(status){
      ev.preventDefault();
      ev.stopImmediatePropagation();
      setQueryParam('status', status.dataset.statusFilter || '');
      return;
    }

    var nf=ev.target.closest && ev.target.closest('#new-filter');
    if(nf){
      ev.preventDefault();
      ev.stopImmediatePropagation();
      var active=nf.classList.contains('active');
      setQueryParam('new', active ? '' : '1');
      return;
    }

    var header=ev.target.closest && ev.target.closest('th.sortable');
    if(header){
      ev.preventDefault();
      ev.stopImmediatePropagation();
      var table=header.closest('table');
      var name=table ? table.id : '';
      var key=header.dataset.sortKey || '';
      if(!table || !key) return;
      var previous=sortState[name];
      var direction=(previous && previous.key === key) ? -previous.direction : 1;
      sortState[name]={key:key,direction:direction};
      sortTable(table,key,direction);
      return;
    }

    var prev=ev.target.closest && ev.target.closest('#page-prev');
    if(prev){
      ev.preventDefault();
      ev.stopImmediatePropagation();
      var urlPrev=new URL(window.location.href);
      var pagePrev=Math.max(1, Number(urlPrev.searchParams.get('page') || '1') - 1);
      urlPrev.searchParams.set('page', String(pagePrev));
      window.location.assign(urlPrev.toString());
      return;
    }

    var next=ev.target.closest && ev.target.closest('#page-next');
    if(next){
      ev.preventDefault();
      ev.stopImmediatePropagation();
      var urlNext=new URL(window.location.href);
      var pageNext=Math.max(1, Number(urlNext.searchParams.get('page') || '1') + 1);
      urlNext.searchParams.set('page', String(pageNext));
    }
  }, true);

  document.addEventListener('change', function(ev){
    var target=ev.target;
    if(!target || !['classification-filter','severity-filter','device-filter','vendor-filter','page-size'].includes(target.id)) return;
    ev.preventDefault();
    ev.stopImmediatePropagation();
    var mapping={
      'classification-filter':'classification',
      'severity-filter':'severity',
      'device-filter':'device',
      'vendor-filter':'vendor',
      'page-size':'page_size'
    };
    setQueryParam(mapping[target.id], target.value || '');
  }, true);

  syncControlsFromUrl();
})();
</script>'''

anchor='</body></html>'
if anchor not in text:
    raise SystemExit('usable controls patch: closing body marker not found')
text=text.replace(anchor, script+'\n'+anchor, 1)

compile(text, str(APP), 'exec')
APP.write_text(text, encoding='utf-8')
print('DEV 0.8 usable controls + table sorting patch applied')
