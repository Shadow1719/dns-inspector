from pathlib import Path

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

OLD = "document.getElementById('inspect-root').innerHTML=data.inspect_html;"
NEW = """const inspectRoot=document.getElementById('inspect-root');
inspectRoot.innerHTML=data.inspect_html;
// HTML inserted via innerHTML does not execute its <script> tags. Re-run the
// small inline scripts returned by inspect_html so the DEV AdGuard explanation
// card initializes again after every live refresh.
inspectRoot.querySelectorAll('script').forEach(oldScript=>{
  const script=document.createElement('script');
  for(const attr of oldScript.attributes) script.setAttribute(attr.name,attr.value);
  script.textContent=oldScript.textContent;
  oldScript.replaceWith(script);
});"""

if OLD not in text:
    raise SystemExit('AdGuard explain v5: live refresh marker not found')

text = text.replace(OLD, NEW, 1)
APP.write_text(text, encoding='utf-8')
print('DEV AdGuard explanation v5 patch applied')
