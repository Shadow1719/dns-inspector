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
    const title = all.find(function(el){
      return exactText(el) === 'Why did AdGuard allow or block this?';
    });
    const targetHeading = all.find(function(el){
      return exactText(el) === 'Why is this here?';
    });
    if(!title || !targetHeading) return false;

    const source = title.closest('.card') || title.parentElement;
    if(!source) return false;

    // The purpose/explanation heading is already in the right-hand column.
    // Replace only the box immediately below that heading, preserving the heading itself.
    let target = targetHeading.nextElementSibling;
    if(!target){
      target = targetHeading.parentElement && targetHeading.parentElement.querySelector('.signal, .purpose, .why, .box');
    }
    if(!target) return false;

    const fragment = document.createElement('div');
    fragment.className = 'adguard-relocated';
    fragment.innerHTML = source.innerHTML;

    // Remove the duplicate top-level AdGuard heading from the moved content.
    Array.from(fragment.querySelectorAll('h1,h2,h3,h4,div,strong,span')).forEach(function(el){
      if(exactText(el) === 'Why did AdGuard allow or block this?'){
        const container = el.closest('h1,h2,h3,h4') || el;
        if(container && container.parentElement) container.parentElement.removeChild(container);
      }
    });

    target.innerHTML = '';
    target.appendChild(fragment);
    source.style.display = 'none';
    return true;
  }

  function run(){
    try{ relocateAdGuardExplanation(); }catch(e){}
  }

  if(document.readyState === 'loading'){
    document.addEventListener('DOMContentLoaded', run, {once:true});
  }else{
    run();
  }
})();
</script>'''

anchor = '</body></html>'
if anchor not in text:
    raise SystemExit('AdGuard layout V2: closing body marker not found')
text = text.replace(anchor, script + '\n' + anchor, 1)

css = r'''
.adguard-relocated{margin-top:0}.adguard-relocated .adguard-inline{margin-top:0}.adguard-relocated .adguard-inline-title{font-size:1.02rem}.adguard-relocated .adg-inline-tech{margin-top:9px}
'''
if '</style>' in text:
    text = text.replace('</style>', css + '</style>', 1)

compile(text, str(APP), 'exec')
APP.write_text(text, encoding='utf-8')
print('DEV AdGuard layout V2 applied')
