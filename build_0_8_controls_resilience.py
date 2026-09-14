from pathlib import Path

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

MARKER = '/* DNS Inspector 0.8 resilient controls bridge */'
if MARKER in text:
    print('DEV 0.8 controls resilience patch already applied')
    raise SystemExit(0)

script = r'''<script>
/* DNS Inspector 0.8 resilient controls bridge */
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

  document.addEventListener('click', function(ev){
    const tab=ev.target.closest && ev.target.closest('.tab-btn');
    if(tab){
      ev.preventDefault();
      ev.stopImmediatePropagation();
      activateTab(tab.dataset.tab || 'overview');
      return;
    }

    const status=ev.target.closest && ev.target.closest('[data-status-filter]');
    if(status){
      ev.preventDefault();
      ev.stopImmediatePropagation();
      setQueryParam('status', status.dataset.statusFilter || '');
      return;
    }

    const nf=ev.target.closest && ev.target.closest('#new-filter');
    if(nf){
      ev.preventDefault();
      ev.stopImmediatePropagation();
      const active=nf.classList.contains('active');
      setQueryParam('new', active ? '' : '1');
      return;
    }

    const prev=ev.target.closest && ev.target.closest('#page-prev');
    if(prev){
      ev.preventDefault();
      ev.stopImmediatePropagation();
      const url=new URL(window.location.href);
      const page=Math.max(1, Number(url.searchParams.get('page') || '1') - 1);
      url.searchParams.set('page', String(page));
      window.location.assign(url.toString());
      return;
    }

    const next=ev.target.closest && ev.target.closest('#page-next');
    if(next){
      ev.preventDefault();
      ev.stopImmediatePropagation();
      const url=new URL(window.location.href);
      const page=Math.max(1, Number(url.searchParams.get('page') || '1') + 1);
      url.searchParams.set('page', String(page));
      window.location.assign(url.toString());
    }
  }, true);

  document.addEventListener('change', function(ev){
    const target=ev.target;
    if(!target || !['classification-filter','severity-filter','device-filter','vendor-filter','page-size'].includes(target.id)) return;
    ev.preventDefault();
    ev.stopImmediatePropagation();
    const mapping={
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

anchor = '</body></html>'
if anchor not in text:
    raise SystemExit('controls resilience patch: closing body marker not found')
text = text.replace(anchor, script + '\n' + anchor, 1)

compile(text, str(APP), 'exec')
APP.write_text(text, encoding='utf-8')
print('DEV 0.8 controls resilience patch applied')
