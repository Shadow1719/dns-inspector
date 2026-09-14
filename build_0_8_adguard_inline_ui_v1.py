from pathlib import Path

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

MARKER = '# === DEV 0.8 ADGUARD INLINE UI V1 ==='
if MARKER in text:
    print('DEV AdGuard inline UI patch already applied')
    raise SystemExit(0)

HELPER = r'''

# === DEV 0.8 ADGUARD INLINE UI V1 ===
def _adguard_explain_inline(domain):
    """Render the live AdGuard decision directly inside the domain card."""
    data = _adguard_explain(domain)
    verdict = str(data.get('verdict') or 'Unknown')
    confidence = str(data.get('confidence') or 'Low')
    status = str(data.get('status') or 'Unknown')
    summary = str(data.get('summary') or '')
    explanation = str(data.get('explanation') or '')
    evidence = data.get('evidence') or []
    technical = data.get('technical') or {}
    tone = 'gray'
    low = verdict.lower()
    if 'threat' in low:
        tone = 'red'
    elif 'advertising' in low or 'tracking' in low:
        tone = 'yellow'
    elif 'gambling' in low or 'dns security' in low:
        tone = 'orange'
    elif 'allowed' in low or 'custom policy' in low:
        tone = 'blue'

    evidence_html = ''
    for item in evidence:
        label = _html(item.get('label') or 'Evidence')
        source = _html(item.get('source') or 'AdGuard')
        evidence_html += f"<span class='adg-inline-evidence adg-{_html(item.get('tone') or tone)}' title='Source: {source}'>{label}</span>"

    source_names = []
    for item in evidence:
        source = str(item.get('source') or '').strip()
        if source and source not in source_names:
            source_names.append(source)
    source_text = ', '.join(source_names[:4])
    if len(source_names) > 4:
        source_text += f" +{len(source_names)-4} more"

    return f"""
<div class='adguard-inline'>
  <div class='adguard-inline-title'>AdGuard decision</div>
  <div class='adg-inline-verdict adg-{tone}'>
    <div class='adg-inline-main'>
      <span class='adg-inline-label'>{_html(verdict)}</span>
      <span class='adg-inline-confidence'>Confidence: {_html(confidence)}</span>
      <span class='status-pill status-{_html(status.lower())}'>{_html(status)}</span>
    </div>
    <div class='adg-inline-summary'>{_html(summary)}</div>
    <div class='adg-inline-explanation'>{_html(explanation)}</div>
    {f"<div class='adg-inline-evidence-row'><span class='sub'>Evidence:</span>{evidence_html}</div>" if evidence_html else ''}
    <div class='adg-inline-tech'>
      <div><span>Source</span><b>{_html(source_text or 'AdGuard rule')}</b></div>
      <div><span>Reason</span><b class='mono'>{_html(technical.get('reason') or '—')}</b></div>
      <div><span>Matched rule</span><b class='mono'>{_html(technical.get('rule') or '—')}</b></div>
      <div><span>Filter list ID</span><b class='mono'>{_html(technical.get('filter_list_id') or '—')}</b></div>
    </div>
  </div>
</div>
"""

if "def inspect_html(result):" not in text:
    raise SystemExit('AdGuard inline UI patch: inspect_html marker not found')
text = text.replace('def inspect_html(result):', HELPER + '\n\ndef inspect_html(result):', 1)

old_return = "    return _adguard_explain_card(result['domain']) + f\"\"\"\n<div class='card'><h2>{_html(result['domain'])}</h2>"
new_return = "    return f\"\"\"\n<div class='card'><h2>{_html(result['domain'])}</h2>"
if old_return not in text:
    raise SystemExit('AdGuard inline UI patch: separate explanation card marker not found')
text = text.replace(old_return, new_return, 1)

old_why = """<div><h3>Why is this here?</h3>\n<div class='signal signal-{e['tone']}'><div class='signal-title'>{_html(e['summary'])}</div><ul class='evidence'>{evidence_html}</ul><div>Confidence: <span class='confidence-{e['confidence'].lower()}'>{_html(e['confidence'])}</span></div></div></div></div>"""
new_why = """<div>{_adguard_explain_inline(result['domain'])}</div></div>"""
if old_why not in text:
    raise SystemExit('AdGuard inline UI patch: domain explanation column marker not found')
text = text.replace(old_why, new_why, 1)

css = r'''
.adguard-inline{margin-top:2px}.adguard-inline-title{font-size:1.17rem;font-weight:750;margin-bottom:8px}.adg-inline-verdict{border-left:4px solid #30363d;border-radius:10px;background:#0d1117;padding:12px 13px}.adg-inline-verdict.red{border-color:#f85149}.adg-inline-verdict.yellow{border-color:#d29922}.adg-inline-verdict.orange{border-color:#db6d28}.adg-inline-verdict.blue{border-color:#58a6ff}.adg-inline-verdict.gray{border-color:#8b949e}.adg-inline-main{display:flex;align-items:center;flex-wrap:wrap;gap:8px}.adg-inline-label{font-size:1.05rem;font-weight:800}.adg-inline-confidence{font-size:.78rem;color:#8b949e}.adg-inline-summary{margin-top:7px;font-weight:700}.adg-inline-explanation{margin-top:3px;color:#c9d1d9}.adg-inline-evidence-row{display:flex;align-items:center;flex-wrap:wrap;gap:6px;margin-top:10px}.adg-inline-evidence{display:inline-flex;align-items:center;padding:4px 8px;border-radius:999px;border:1px solid #30363d;background:#161b22;font-size:.76rem;font-weight:700}.adg-inline-evidence.adg-red{background:#3b1114;border-color:#6e1c24;color:#ffb4b4}.adg-inline-evidence.adg-yellow{background:#3a2d0b;border-color:#8f6b1c;color:#f2cc60}.adg-inline-evidence.adg-orange{background:#3a1d0b;border-color:#8b4a1c;color:#ffb86b}.adg-inline-evidence.adg-blue{background:#102b45;border-color:#24557e;color:#9ed0ff}.adg-inline-evidence.adg-gray{background:#161b22;color:#c9d1d9}.adg-inline-tech{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px;margin-top:10px}.adg-inline-tech>div{padding:7px 9px;border:1px solid #21262d;border-radius:8px;background:#11161d;min-width:0}.adg-inline-tech span{display:block;color:#8b949e;font-size:.68rem;text-transform:uppercase;letter-spacing:.05em;margin-bottom:3px}.adg-inline-tech b{display:block;overflow-wrap:anywhere;font-size:.78rem}
@media(max-width:900px){.adg-inline-tech{grid-template-columns:1fr}}
'''
if '</style>' not in text:
    raise SystemExit('AdGuard inline UI patch: style marker not found')
text = text.replace('</style>', css + '</style>', 1)

compile(text, str(APP), 'exec')
APP.write_text(text, encoding='utf-8')
print('DEV AdGuard inline UI patch applied')
