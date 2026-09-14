from pathlib import Path
import re

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

MARKER = '/* DNS Inspector 0.8 AdGuard UI polish v1 */'
if MARKER in text:
    print('DEV 0.8 AdGuard UI polish already applied')
    raise SystemExit(0)

# Expose the filter list URL alongside its name. AdGuard filtering/status normally
# carries the canonical source URL, so the UI can link directly to the list rather
# than maintaining a fragile hand-written catalog of GitHub URLs.
helper = r'''

def _adg_filter_url_map(status):
    out = {}
    if not isinstance(status, dict):
        return out
    for key in ('filters', 'whitelist_filters', 'filter_lists'):
        rows = status.get(key)
        if not isinstance(rows, list):
            continue
        for item in rows:
            if not isinstance(item, dict):
                continue
            fid = item.get('id') or item.get('filter_id')
            url = str(item.get('url') or item.get('source_url') or '').strip()
            if fid is not None and url:
                out[str(fid)] = url
    return out
'''

if 'def _adg_filter_url_map(status):' not in text:
    marker = '\ndef _adg_user_rules(status):\n'
    if marker not in text:
        raise SystemExit('AdGuard UI polish: user-rules marker not found')
    text = text.replace(marker, helper + marker, 1)

# Add URL lookup to the explanation evidence objects.
if 'furlmap = _adg_filter_url_map(filter_status)' not in text:
    marker = '    fmap = _adg_filter_map(filter_status)\n'
    if marker not in text:
        raise SystemExit('AdGuard UI polish: filter-map marker not found')
    text = text.replace(marker, marker + '    furlmap = _adg_filter_url_map(filter_status)\n', 1)

old = "evidence.append({'kind': kind, 'label': label, 'tone': tone, 'source': source or 'AdGuard rule', 'rule': rule, 'filter_id': fid})"
new = "evidence.append({'kind': kind, 'label': label, 'tone': tone, 'source': source or 'AdGuard rule', 'source_url': furlmap.get(fid, ''), 'rule': rule, 'filter_id': fid})"
if old in text:
    text = text.replace(old, new, 1)

old_custom = "evidence.append({'kind': kind, 'label': label, 'tone': tone, 'source': 'Your custom AdGuard rules', 'rule': line, 'filter_id': ''})"
new_custom = "evidence.append({'kind': kind, 'label': label, 'tone': tone, 'source': 'Your custom AdGuard rules', 'source_url': '', 'rule': line, 'filter_id': ''})"
if old_custom in text:
    text = text.replace(old_custom, new_custom, 1)

# Replace the popup-based UI with an always-visible compact grid and inline evidence.
start = text.find('def _adguard_explain_card(domain):')
end = text.find("\n\n@app.route('/api/adguard/explain')", start)
if start < 0 or end < 0:
    raise SystemExit('AdGuard UI polish: explain-card function bounds not found')

replacement = r'''def _adguard_explain_card(domain):
    encoded = quote(str(domain or ''), safe='')
    return f'''<div class='card adguard-why-card'>
<div class='adguard-why-head'><h2>Why did AdGuard allow or block this?</h2><button type='button' class='adg-refresh'>Refresh</button></div>
<div class='adguard-why-body'><div class='sub'>Checking the current AdGuard decision…</div></div>
</div>
<script>
(function(){{
  const root=document.currentScript.previousElementSibling;
  if(!root) return;
  const body=root.querySelector('.adguard-why-body');
  const domain=decodeURIComponent('{encoded}');
  const esc=(v)=>String(v??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  const tone=(v)=>{{const x=String(v||'').toLowerCase(); if(x.includes('threat')) return 'red'; if(x.includes('advertising')||x.includes('tracking')) return 'yellow'; if(x.includes('custom')||x.includes('allowed')) return 'blue'; if(x.includes('gambling')||x.includes('dns security')) return 'orange'; return 'gray';}};
  const sourceHtml=(e)=>{{
    const label=esc(e.source||'AdGuard');
    return e.source_url ? `<a href="${esc(e.source_url)}" target="_blank" rel="noopener noreferrer" class="adg-source-link">${label}</a>` : label;
  }};
  function render(d){{
    const evidence=Array.isArray(d.evidence)?d.evidence:[];
    const t=d.technical||{{}};
    const toneClass=tone(d.verdict);
    const primary=evidence[0]||{{}};
    const chips=evidence.map((e,i)=>`<button type="button" class="adg-keyword adg-${tone(e.label)}" data-i="${i}">${esc(e.label)}</button>`).join('');
    const detail=evidence.length?`<div class="adg-evidence-detail" id="adg-evidence-detail"><div class="adg-evidence-detail-title">Evidence details</div><div class="adg-evidence-detail-grid"><div><span>Source</span><b id="adg-evidence-source">${sourceHtml(primary)}</b></div><div><span>Rule</span><b id="adg-evidence-rule" class="mono">${esc(primary.rule||'—')}</b></div><div><span>Filter list ID</span><b id="adg-evidence-id" class="mono">${esc(primary.filter_id||'—')}</b></div></div></div>`:'';
    const source=primary.source_url ? `<a href="${esc(primary.source_url)}" target="_blank" rel="noopener noreferrer" class="adg-source-link">${esc(primary.source||'AdGuard')}</a>` : esc(primary.source||'AdGuard');
    body.innerHTML=`<div class="adg-verdict adg-${toneClass}">
      <div class="adg-verdict-main"><span class="adg-verdict-label">${esc(d.verdict||'Unknown')}</span><span class="adg-confidence">Confidence: ${esc(d.confidence||'Low')}</span><span class="status-pill status-${esc((d.status||'Unknown').toLowerCase())}">${esc(d.status||'Unknown')}</span></div>
      <div class="adg-summary">${esc(d.summary||'')}</div>
      <div class="adg-explanation">${esc(d.explanation||'')}</div>
      ${chips?`<div class="adg-evidence-row"><span class="sub">Evidence:</span>${chips}</div>`:''}
      <div class="adg-tech-grid">
        <div><span>Reason</span><b class="mono">${esc(t.reason||'—')}</b></div>
        <div><span>Matched rule</span><b class="mono">${esc(t.rule||'—')}</b></div>
        <div><span>Filter list ID</span><b class="mono">${esc(t.filter_list_id||'—')}</b></div>
        <div><span>Source</span><b>${source}</b></div>
      </div>
      ${detail}
    </div>`;
    body.querySelectorAll('.adg-keyword').forEach(btn=>btn.addEventListener('click',()=>{{
      const e=evidence[Number(btn.dataset.i)];
      if(!e) return;
      const rootDetail=body.querySelector('#adg-evidence-detail');
      if(!rootDetail) return;
      rootDetail.classList.add('visible');
      const src=rootDetail.querySelector('#adg-evidence-source');
      const rule=rootDetail.querySelector('#adg-evidence-rule');
      const fid=rootDetail.querySelector('#adg-evidence-id');
      if(src) src.innerHTML=e.source_url ? `<a href="${esc(e.source_url)}" target="_blank" rel="noopener noreferrer" class="adg-source-link">${esc(e.source||'AdGuard')}</a>` : esc(e.source||'AdGuard');
      if(rule) rule.textContent=e.rule||'—';
      if(fid) fid.textContent=e.filter_id||'—';
    }}));
  }}
  async function load(){{
    body.innerHTML='<div class="sub">Checking the current AdGuard decision…</div>';
    try{{
      const r=await fetch('/api/adguard/explain?domain='+encodeURIComponent(domain),{{cache:'no-store'}});
      const d=await r.json();
      render(d);
    }}catch(err){{body.innerHTML='<div class="error">Could not explain the AdGuard decision right now.</div>';}}
  }}
  root.querySelector('.adg-refresh')?.addEventListener('click',load);
  load();
}})();
</script>'''

text = text[:start] + replacement + text[end:]

# Compact inline layout, no <details>, no popup.
css = r'''
/* DNS Inspector 0.8 AdGuard UI polish v1 */
.adg-source-link{color:#79c0ff;text-decoration:none}.adg-source-link:hover{text-decoration:underline;color:#a5d6ff}.adg-evidence-detail{display:none;margin-top:8px;padding:8px 10px;border:1px solid #21262d;border-radius:8px;background:#11161d}.adg-evidence-detail.visible{display:block}.adg-evidence-detail-title{font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;color:#8b949e;margin-bottom:6px}.adg-evidence-detail-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:7px}.adg-evidence-detail-grid>div{min-width:0}.adg-evidence-detail-grid span{display:block;color:#8b949e;font-size:.66rem;text-transform:uppercase;letter-spacing:.04em;margin-bottom:2px}.adg-evidence-detail-grid b{display:block;font-size:.76rem;overflow-wrap:anywhere}.adg-tech-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px;margin-top:9px}.adg-tech-grid>div{padding:7px 9px;border:1px solid #21262d;border-radius:8px;background:#11161d}.adg-tech-grid span{display:block;color:#8b949e;font-size:.66rem;text-transform:uppercase;letter-spacing:.05em;margin-bottom:2px}.adg-tech-grid b{display:block;font-size:.76rem;overflow-wrap:anywhere}.adg-verdict{border-left:4px solid #30363d;border-radius:10px;background:#0d1117;padding:12px 13px}.adg-verdict.red{border-color:#f85149}.adg-verdict.yellow{border-color:#d29922}.adg-verdict.orange{border-color:#db6d28}.adg-verdict.blue{border-color:#58a6ff}.adg-verdict.gray{border-color:#8b949e}.adg-verdict-main{display:flex;flex-wrap:wrap;gap:8px;align-items:center}.adg-verdict-label{font-size:1.02rem;font-weight:800}.adg-confidence{font-size:.76rem;color:#8b949e}.adg-summary{margin-top:6px;font-weight:700}.adg-explanation{margin-top:3px;color:#c9d1d9}.adg-evidence-row{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-top:8px}.adg-keyword{padding:4px 8px;border-radius:999px;border:1px solid #30363d;background:#161b22;color:#e6edf3;font-size:.75rem;font-weight:700;cursor:pointer}.adg-keyword:hover{border-color:#58a6ff}.adg-keyword.adg-red{background:#3b1114;border-color:#6e1c24;color:#ffb4b4}.adg-keyword.adg-yellow{background:#3a2d0b;border-color:#8f6b1c;color:#f2cc60}.adg-keyword.adg-orange{background:#3a1d0b;border-color:#8b4a1c;color:#ffb86b}.adg-keyword.adg-blue{background:#102b45;border-color:#24557e;color:#9ed0ff}@media(max-width:900px){.adg-tech-grid,.adg-evidence-detail-grid{grid-template-columns:1fr}}
'''
text = text.replace('</style>', css + '</style>', 1)

compile(text, str(APP), 'exec')
APP.write_text(text, encoding='utf-8')
print('DEV 0.8 AdGuard UI polish v1 applied')
