from pathlib import Path

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

MARKER = '/* DNS Inspector 0.8 AdGuard layout V2 */'
if MARKER in text:
    print('DEV 0.8 AdGuard layout V2 already applied')
    raise SystemExit(0)

script = r'''<script>
/* DNS Inspector 0.8 AdGuard layout V2 */
(function(){
  function exactText(el){ return (el.textContent || '').replace(/\s+/g,' ').trim(); }

  function relocateAdGuardExplanation(){
    const all = Array.from(document.querySelectorAll('h1,h2,h3,h4,div,strong,span'));
    const title = all.find(function(el){ return exactText(el) === 'Why did AdGuard allow or block this?'; });
    const targetHeading = all.find(function(el){ return exactText(el) === 'Why is this here?'; });
    if(!title || !targetHeading) return false;

    const source = title.closest('.adguard-why-card') || title.closest('.card') || title.parentElement;
    if(!source) return false;

    // Move the real live nodes. The AdGuard explanation script attaches its
    // event handler and async renderer to these nodes, so cloning innerHTML
    // would leave the visible copy permanently stuck at "Checking...".
    const body = source.querySelector('.adguard-why-body');
    const refresh = source.querySelector('.adg-refresh');
    if(!body) return false;

    // The current domain card's right column is the sibling after the heading.
    let target = targetHeading.nextElementSibling;
    if(!target){
      target = targetHeading.parentElement;
    }
    if(!target) return false;

    // Already relocated: don't rebuild it.
    if(body.parentElement && body.parentElement.classList.contains('adguard-relocated')){
      return true;
    }

    const wrapper = document.createElement('div');
    wrapper.className = 'adguard-relocated';

    if(refresh){
      const actions = document.createElement('div');
      actions.className = 'adguard-relocated-actions';
      actions.appendChild(refresh);
      wrapper.appendChild(actions);
    }
    wrapper.appendChild(body);

    target.innerHTML = '';
    target.appendChild(wrapper);
    source.style.display = 'none';
    return true;
  }

  function run(){
    try{ relocateAdGuardExplanation(); }catch(e){ console.debug('AdGuard layout relocation failed', e); }
  }

  function observe(){
    const root = document.getElementById('inspect-root');
    if(!root || root.dataset.adgRelocateObserved === '1') return;
    root.dataset.adgRelocateObserved = '1';
    const observer = new MutationObserver(function(){ window.setTimeout(run, 0); });
    observer.observe(root, {childList:true, subtree:true});
  }

  if(document.readyState === 'loading'){
    document.addEventListener('DOMContentLoaded', function(){ run(); observe(); }, {once:true});
  }else{
    run();
    observe();
  }
})();
</script>'''

anchor = '</body></html>'
if anchor not in text:
    raise SystemExit('AdGuard layout V2: closing body marker not found')
text = text.replace(anchor, script + '\n' + anchor, 1)

css = r'''
.adguard-relocated{margin-top:0}.adguard-relocated-actions{display:flex;justify-content:flex-end;margin:0 0 8px}.adguard-relocated .adguard-why-body{margin-top:0}.adguard-relocated .adg-refresh{padding:6px 10px;font-size:.78rem}
'''
if '</style>' in text:
    text = text.replace('</style>', css + '</style>', 1)

compile(text, str(APP), 'exec')
APP.write_text(text, encoding='utf-8')
print('DEV AdGuard layout V2 applied with live-node relocation')
