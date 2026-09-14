from pathlib import Path

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

HELPERS = r"""

# --- DEV 0.8: human-readable AdGuard rule explanations ---
def _adg_kind(source, rule=''):
    s = f'{source} {rule}'.lower()
    if rule.strip().startswith('@@'):
        return 'policy', 'Custom policy', 'blue'
    if any(x in s for x in ('threat intelligence', 'malware', 'phishing', 'urlhaus', 'badware', 'malicious', 'shadowwhisperer')):
        return 'threat', 'Threat', 'red'
    if 'gambling' in s:
        return 'gambling', 'Gambling', 'orange'
    if 'rebind' in s or 'dyndns' in s:
        return 'dns-security', 'DNS security', 'orange'
    if any(x in s for x in ('tracker', 'tracking', 'telemetry', 'privacy', 'analytics', 'adguard dns', 'oisd', 'normal blocklist', 'advertising', 'ads')):
        return 'tracking', 'Advertising / tracking', 'yellow'
    return 'filter', 'Filtering', 'gray'


def _adg_rules(payload):
    if not isinstance(payload, dict):
        return []
    for key in ('rules', 'rule', 'matched_rules', 'matched_rule'):
        raw = payload.get(key)
        if raw is None:
            continue
        if isinstance(raw, (str, dict)):
            raw = [raw]
        if not isinstance(raw, list):
            continue
        out = []
        for item in raw:
            if isinstance(item, str):
                out.append({'rule': item})
            elif isinstance(item, dict):
                out.append(dict(item))
        if out:
            return out
    return []


def _adg_rule(item):
    if isinstance(item, str):
        return item.strip()
    if not isinstance(item, dict):
        return ''
    for key in ('rule', 'text', 'matched_rule', 'original_rule'):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ''


def _adg_id(item):
    if not isinstance(item, dict):
        return ''
    for key in ('filter_list_id', 'filter_id', 'id'):
        value = item.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ''


def _adg_filter_map(status):
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
            name = str(item.get('name') or item.get('title') or '').strip()
            if fid is not None and name:
                out[str(fid)] = name
    return out


def _adg_user_rules(status):
    if not isinstance(status, dict):
        return []
    raw = status.get('user_rules')
    if isinstance(raw, str):
        return [x.strip() for x in raw.splitlines() if x.strip()]
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if isinstance(x, str) and str(x).strip()]
    return []


def _adg_query_rules(domain):
    try:
        payload = agh_get('/control/querylog', params={'limit': 100, 'search': domain})
    except Exception:
        return []
    rows = payload.get('data') if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        return []
    found = []
    for entry in rows:
        if not isinstance(entry, dict):
            continue
        question = entry.get('question') or {}
        qname = str(question.get('name') or entry.get('name') or '').strip().rstrip('.').lower()
        if qname and qname != domain:
            continue
        found.extend(_adg_rules(entry))
    return found


def _adguard_explain(domain):
    domain = str(domain or '').strip().rstrip('.').lower()
    if not domain:
        return {'domain': '', 'status': 'Unknown', 'verdict': 'Unknown', 'confidence': 'Low', 'summary': '', 'explanation': '', 'evidence': [], 'technical': {}}
    try:
        check = agh_get('/control/filtering/check_host', params={'name': domain})
    except Exception as exc:
        check = {'_error': str(exc)}
    status, reason = adguard_current_status(domain)
    try:
        filter_status = agh_get('/control/filtering/status')
    except Exception:
        filter_status = {}

    fmap = _adg_filter_map(filter_status)
    user_rules = _adg_user_rules(filter_status)
    items = _adg_rules(check) or _adg_query_rules(domain)
    evidence = []
    seen = set()
    for item in items:
        rule = _adg_rule(item)
        fid = _adg_id(item)
        source = fmap.get(fid, '')
        if not source and rule in user_rules:
            source = 'Your custom AdGuard rules'
        if not source and not rule:
            continue
        kind, label, tone = _adg_kind(source, rule)
        key = (kind, source, rule)
        if key in seen:
            continue
        seen.add(key)
        evidence.append({'kind': kind, 'label': label, 'tone': tone, 'source': source or 'AdGuard rule', 'rule': rule, 'filter_id': fid})

    if not evidence and user_rules:
        for line in user_rules:
            low = line.lower()
            if any(x in low for x in (f'||{domain}'.lower(), f'|{domain}'.lower(), f'{domain}^'.lower())):
                kind, label, tone = _adg_kind('Your custom AdGuard rules', line)
                evidence.append({'kind': kind, 'label': label, 'tone': tone, 'source': 'Your custom AdGuard rules', 'rule': line, 'filter_id': ''})

    kinds = {x['kind'] for x in evidence}
    threat_sources = {x['source'] for x in evidence if x['kind'] == 'threat' and x['source']}
    if 'threat' in kinds:
        verdict, confidence = 'Threat', ('High' if len(threat_sources) >= 2 else 'Medium')
        summary = 'This domain matched a security-focused intelligence source.'
        explanation = 'AdGuard found evidence associated with a security threat source.'
    elif 'policy' in kinds:
        verdict, confidence = 'Custom policy', 'High'
        summary = 'This request is controlled by your own AdGuard policy.'
        explanation = 'This decision comes from a rule you configured in AdGuard Home.'
    elif 'gambling' in kinds:
        verdict, confidence = 'Gambling', 'High'
        summary = 'This request matched a gambling-focused filter.'
        explanation = 'The domain matched a category-specific gambling filter.'
    elif 'dns-security' in kinds:
        verdict, confidence = 'DNS security', 'Medium'
        summary = 'This domain was highlighted by a DNS security policy.'
        explanation = 'The domain matched a DNS security-oriented filter.'
    elif 'tracking' in kinds:
        verdict, confidence = 'Advertising / tracking', 'High'
        summary = 'This request is associated with advertising, telemetry, or tracking activity.'
        explanation = 'The domain matched a privacy-oriented advertising or tracking filter.'
    elif status == 'Blocked':
        verdict, confidence = 'Blocked by AdGuard', 'High'
        summary = 'AdGuard is blocking this request.'
        explanation = 'AdGuard is currently blocking this domain, but the matched rule source was not exposed by the available response.'
    elif status == 'Allowed':
        verdict, confidence = 'Allowed', 'High'
        summary = 'AdGuard currently allows this request.'
        explanation = 'No blocking rule is currently being reported for this domain.'
    else:
        verdict, confidence = 'Unknown', 'Low'
        summary = 'No clear AdGuard decision is available yet.'
        explanation = 'The current AdGuard decision could not be explained from the available API data.'

    return {'domain': domain, 'status': status, 'verdict': verdict, 'confidence': confidence, 'summary': summary, 'explanation': explanation,
            'evidence': evidence,
            'technical': {'reason': reason, 'rule': evidence[0]['rule'] if evidence else '', 'filter_list_id': evidence[0]['filter_id'] if evidence else ''}}


def _adguard_explain_card(domain):
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
  async function load(){{
    body.innerHTML='<div class="sub">Checking the current AdGuard decision…</div>';
    try{{
      const r=await fetch('/api/adguard/explain?domain='+encodeURIComponent(domain),{{cache:'no-store'}});
      const d=await r.json();
      const evidence=Array.isArray(d.evidence)?d.evidence:[];
      const buttons=evidence.map((e,i)=>'<button type="button" class="adg-keyword adg-'+tone(e.label)+'" data-i="'+i+'">'+esc(e.label)+'</button>').join('');
      const t=d.technical||{{}};
      const details='<details class="adg-details"><summary>Technical details</summary><div class="adg-tech-grid"><div><b>AdGuard decision</b><div>'+esc(d.status||'Unknown')+'</div></div><div><b>Reason</b><div class="mono">'+esc(t.reason||'—')+'</div></div><div><b>Matched rule</b><div class="mono">'+esc(t.rule||'—')+'</div></div><div><b>Filter list ID</b><div class="mono">'+esc(t.filter_list_id||'—')+'</div></div></div></details>';
      body.innerHTML='<div class="adg-verdict adg-'+tone(d.verdict)+'"><div class="adg-verdict-main"><span class="adg-verdict-label">'+esc(d.verdict||'Unknown')+'</span><span class="adg-confidence">Confidence: '+esc(d.confidence||'Low')+'</span></div><div class="adg-summary">'+esc(d.summary||'')+'</div><div class="adg-explanation">'+esc(d.explanation||'')+'</div>'+(buttons?'<div class="adg-evidence-row"><span class="sub">Evidence:</span>'+buttons+'</div>':'')+details+'</div>';
      body.querySelectorAll('[data-i]').forEach(btn=>btn.addEventListener('click',()=>{{const e=evidence[Number(btn.dataset.i)]; if(!e) return; alert((e.label||'Evidence')+'\\n\\nSource: '+(e.source||'AdGuard')+'\\nRule: '+(e.rule||'—')+(e.filter_id?'\\nFilter list ID: '+e.filter_id:''));}}));
    }}catch(err){{body.innerHTML='<div class="error">Could not explain the AdGuard decision right now.</div>';}}
  }}
  root.querySelector('.adg-refresh')?.addEventListener('click',load);
  load();
}})();
</script>'''


@app.route('/api/adguard/explain')
def api_adguard_explain():
    return jsonify(_adguard_explain(request.args.get('domain', '').strip()))
"""

if 'def inspect_html(result):' not in text:
    raise SystemExit('AdGuard explain v3: inspect_html marker not found')
text = text.replace('def inspect_html(result):', HELPERS + '\n\ndef inspect_html(result):', 1)

old_return = "    return f\"\"\"\n<div class='card'><h2>{_html(result['domain'])}</h2>"
new_return = "    return _adguard_explain_card(result['domain']) + f\"\"\"\n<div class='card'><h2>{_html(result['domain'])}</h2>"
if old_return not in text:
    raise SystemExit('AdGuard explain v3: inspect_html return marker not found')
text = text.replace(old_return, new_return, 1)

css = r'''
.adguard-why-head{display:flex;align-items:center;justify-content:space-between;gap:12px}.adguard-why-head h2{margin:0}.adg-refresh{padding:6px 10px;font-size:.78rem}.adg-verdict{border-left:4px solid #30363d;border-radius:10px;background:#0d1117;padding:13px 14px}.adg-verdict.red{border-color:#f85149}.adg-verdict.yellow{border-color:#d29922}.adg-verdict.orange{border-color:#db6d28}.adg-verdict.blue{border-color:#58a6ff}.adg-verdict.gray{border-color:#8b949e}.adg-verdict-main{display:flex;flex-wrap:wrap;gap:10px;align-items:center}.adg-verdict-label{font-size:1.05rem;font-weight:800}.adg-confidence{font-size:.78rem;color:#8b949e}.adg-summary{margin-top:7px;font-weight:700}.adg-explanation{margin-top:4px;color:#c9d1d9}.adg-evidence-row{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-top:11px}.adg-keyword{padding:4px 8px;border-radius:999px;border:1px solid #30363d;background:#161b22;color:#e6edf3;font-size:.78rem;font-weight:700;cursor:pointer}.adg-keyword:hover{border-color:#58a6ff}.adg-keyword.adg-red{background:#3b1114;border-color:#6e1c24;color:#ffb4b4}.adg-keyword.adg-yellow{background:#3a2d0b;border-color:#8f6b1c;color:#f2cc60}.adg-keyword.adg-orange{background:#3a1d0b;border-color:#8b4a1c;color:#ffb86b}.adg-keyword.adg-blue{background:#102b45;border-color:#24557e;color:#9ed0ff}.adg-details{margin-top:11px}.adg-details summary{cursor:pointer;color:#8b949e;font-size:.8rem}.adg-tech-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin-top:8px}.adg-tech-grid>div{padding:8px;border:1px solid #21262d;border-radius:8px;background:#11161d}.adg-tech-grid b{display:block;color:#8b949e;font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px}
'''
if '</style>' not in text:
    raise SystemExit('AdGuard explain v3: style marker not found')
text = text.replace('</style>', css + '</style>', 1)

APP.write_text(text, encoding='utf-8')
print('DEV AdGuard explanation v3 patch applied')
