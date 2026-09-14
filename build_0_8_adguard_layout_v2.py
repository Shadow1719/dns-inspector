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
  function relocateAdGuardExplanation(){
    const headings = Array.from(document.querySelectorAll('h1,h2,h3,h4,div,strong,span'));
    const title = headings.find(function(el){
      return (el.textContent || '').trim() === 'Why did AdGuard allow or block this?';
    });
    if(!title) return false;

    // The AdGuard explanation is rendered as its own card near the top of the inspect view.
    // Move its inner content into the existing right-hand "Why is this here?" column.
    let source = title.closest('.card');
    if(!source) source = title.parentElement;

    const targetHeading = headings.find(function(el){
      return (el.textContent || '').trim() === 'Why is this here?';
    });
    if(!targetHeading) return false;

    let target = targetHeading.parentElement;
    if(target && target.classList && target.classList.contains('card')){
      target = target.querySelector(':scope > div:last-child') || target;
    }
    if(!target) return false;

    const fragment = document.createElement('div');
    fragment.className = 'adguard-relocated';
    fragment.innerHTML = source.innerHTML;

    // Keep the domain's own right-hand purpose block structure, but replace its contents.
    // Remove the duplicate top-level title from the moved copy.
    const movedTitle = Array.from(fragment.querySelectorAll('h1,h2,h3,h4,div,strong,span')).find(function(el){
      return (el.textContent || '').trim() === 'Why did AdGuard allow or block this?';
    });
    if(movedTitle){
      const titleContainer = movedTitle.closest('h1,h2,h3,h4') || movedTitle;
      if(titleContainer && titleContainer.parentElement){
        titleContainer.parentElement.removeChild(titleContainer);
      }
    }

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
.adguard-relocated{margin-top:0}.adguard-relocated .adguard-inline{margin-top:0}.adguard-relocated .adguard-inline-title{font-size:1.05rem}.adguard-relocated .adg-inline-tech{margin-top:9px}
'''
if '</style>' in text:
    text = text.replace('</style>', css + '</style>', 1)

compile(text, str(APP), 'exec')
APP.write_text(text, encoding='utf-8')
print('DEV AdGuard layout V2 applied')
