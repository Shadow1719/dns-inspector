from pathlib import Path
import os
import re

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

MARKER = '# === DEV 0.8 DEV14 POLISH PATCH ==='
if MARKER in text:
    print('DEV14 polish patch already applied')
    raise SystemExit(0)

if 'NEW_DOMAIN_WINDOW_HOURS' not in text:
    m = re.search(r'(?m)^UI_REFRESH_SECONDS\s*=.*$', text)
    if not m:
        raise SystemExit('DEV14: UI_REFRESH_SECONDS anchor not found')
    text = text[:m.end()] + '\nNEW_DOMAIN_WINDOW_HOURS = max(1.0, float(os.getenv("NEW_DOMAIN_WINDOW_HOURS", "2")))' + text[m.end():]

if 'def age_text_for_iso(value):' not in text:
    anchor = 'def utcnow():\n'
    if anchor not in text:
        raise SystemExit('DEV14: utcnow anchor not found')
    helper = '''def age_text_for_iso(value):
    try:
        dt = datetime.fromisoformat(str(value))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        minutes = max(0, int((datetime.now(timezone.utc) - dt).total_seconds() // 60))
        if minutes < 1:
            return "now"
        if minutes < 60:
            return f"{minutes}m"
        hours = minutes // 60
        if hours < 24:
            return f"{hours}h"
        return f"{hours // 24}d"
    except Exception:
        return ""


'''
    text = text.replace(anchor, helper + anchor, 1)

fresh_re = re.compile(
    r'(?m)^[ \t]*fresh_cutoff\s*=\s*\(now_dt\s*-\s*timedelta\(seconds\s*=\s*max\(30,\s*UI_REFRESH_SECONDS\s*\*\s*2\)\)\)\.isoformat\(\)[ \t]*$\n'
    r'^[ \t]*fresh_domains\s*=\s*\[[^\n]*?fetchall\(\)\][ \t]*$',
    re.S,
)
new_recent = '''        fresh_cutoff = (now_dt - timedelta(hours=NEW_DOMAIN_WINDOW_HOURS)).isoformat()
        fresh_window_count = int(c.execute(
            "SELECT COUNT(*) FROM domains WHERE first_seen>=?", (fresh_cutoff,)
        ).fetchone()[0])
        fresh_rows = c.execute(
            "SELECT domain,first_seen,blocked_requests,allowed_requests,unknown_requests,current_status "
            "FROM domains WHERE first_seen>=? ORDER BY first_seen DESC LIMIT 10",
            (fresh_cutoff,),
        ).fetchall()
        fresh_domains = []
        for domain, first_seen, blocked, allowed, unknown, current_status in fresh_rows:
            status = current_status if current_status and current_status != "Unknown" else status_summary(
                int(blocked or 0), int(allowed or 0), int(unknown or 0)
            )[0]
            fresh_domains.append({
                "domain": domain,
                "status": status,
                "status_class": str(status).lower(),
                "first_seen": first_seen,
                "age": age_text_for_iso(first_seen),
            })
'''
recent_match = fresh_re.search(text)
if not recent_match:
    raise SystemExit('DEV14: get_recent new-domain block not found')
text = text[:recent_match.start()] + new_recent + text[recent_match.end():]

old_meta = '            "new_count": exact_new,\n            "new_domains": fresh_domains,\n'
new_meta = '            "new_count": exact_new,\n            "new_window_count": fresh_window_count,\n            "new_domains": fresh_domains,\n'
if old_meta not in text:
    raise SystemExit('DEV14: recent meta marker not found')
text = text.replace(old_meta, new_meta, 1)

show_re = re.compile(r'function showNewBanner\(entries\)\{.*?\n\}\nfunction clearNewBanner\(\)', re.S)
match = show_re.search(text)
if not match:
    raise SystemExit('DEV14: showNewBanner/clearNewBanner block not found')
new_show = r'''let lastNewBannerSignature='';
let dismissedNewBannerSignature='';
try{dismissedNewBannerSignature=localStorage.getItem('dnsInspectorDismissedNewBanner')||''}catch(e){}
function showNewBanner(entries,totalCount=null){
  const b=document.getElementById('new-banner'),t=document.getElementById('new-banner-text');
  if(!b||!t||!entries.length)return;
  const normalized=entries.map(r=>typeof r==='string'?{domain:r,status:'Unknown',status_class:'unknown',first_seen:''}:r);
  const count=Number.isFinite(Number(totalCount))?Number(totalCount):normalized.length;
  const signature=normalized.map(r=>`${r.domain}:${r.first_seen||''}`).join('|')+':'+count;
  if(signature===dismissedNewBannerSignature)return;
  if(signature===lastNewBannerSignature&&b.classList.contains('show'))return;
  lastNewBannerSignature=signature;
  const items=normalized.slice(0,3).map(r=>{
    const status=r.status||'Unknown';
    const statusClass=r.status_class||'unknown';
    const age=r.first_seen?ageText(r.first_seen):(r.age||'');
    const ageHtml=age?`<span class="sub">${esc(age)} ago</span>`:'';
    const href=`/search?q=${encodeURIComponent(r.domain)}`;
    return `<span class="new-domain-item"><a class="new-domain-link" href="${href}" title="Inspect domain in DNS Inspector">${esc(r.domain)}</a>${ageHtml}<span class="status-pill status-${esc(statusClass)}">${esc(status)}</span></span>`;
  }).join('');
  const suffix=count>3?`<span class="sub">+${count-3} more</span>`:'';
  t.innerHTML=`<b>${count}</b> new domain${count===1?'':'s'} detected in the last ${esc({{ new_domain_window_label|tojson }})} · <span class="new-domain-items">${items}${suffix}</span>`;
  b.classList.add('show');
}
function clearNewBanner(){
  const b=document.getElementById('new-banner');
  if(!b||!lastNewBannerSignature)return;
  b.classList.remove('show');
  dismissedNewBannerSignature=lastNewBannerSignature;
  try{localStorage.setItem('dnsInspectorDismissedNewBanner',dismissedNewBannerSignature)}catch(e){}
}'''
text = text[:match.start()] + new_show + text[match.end():]

text = text.replace(
    'if(initialDomainSnapshot&&data.recent_meta?.new_domains?.length)showNewBanner(data.recent_meta.new_domains);',
    'if(initialDomainSnapshot&&data.recent_meta?.new_domains?.length)showNewBanner(data.recent_meta.new_domains,data.recent_meta.new_window_count);',
    1,
)

if 'const initialNewDomains=' not in text:
    anchor = 'const initialStamp=formatUpdated({{ updated|tojson }});'
    if anchor not in text:
        raise SystemExit('DEV14: initial stamp anchor not found')
    inject = '''const initialNewDomains={{ recent_meta.new_domains|tojson }};
if(initialNewDomains.length) showNewBanner(initialNewDomains, {{ recent_meta.new_window_count|tojson }});
'''
    text = text.replace(anchor, inject + anchor, 1)

text = MARKER + '\n' + text
compile(text, str(APP), 'exec')
APP.write_text(text, encoding='utf-8')
print('DEV14 polish patch applied')
