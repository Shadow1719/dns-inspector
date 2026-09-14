from pathlib import Path

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

MARKER = '# === DEV 0.8 ADGUARD LIST TEST V1 ==='
if MARKER in text:
    print('DEV AdGuard list test patch already applied')
    raise SystemExit(0)

block = r'''

# === DEV 0.8 ADGUARD LIST TEST V1 ===
def _adguard_list_test(domain):
    domain = str(domain or '').strip().rstrip('.').lower()
    if not domain:
        return {'ok': False, 'error': 'Missing domain'}
    result = {
        'ok': True,
        'domain': domain,
        'adguard': {},
        'filters': [],
        'matched': [],
    }
    try:
        status = agh_get('/control/filtering/status')
        result['adguard']['status_endpoint'] = 'ok'
    except Exception as exc:
        return {'ok': False, 'domain': domain, 'error': f'filtering/status failed: {exc}'}

    raw_filters = status.get('filters') if isinstance(status, dict) else []
    if not isinstance(raw_filters, list):
        raw_filters = []
    filter_map = {}
    for item in raw_filters:
        if not isinstance(item, dict):
            continue
        fid = item.get('id', item.get('filter_id'))
        row = {
            'id': str(fid) if fid is not None else '',
            'name': str(item.get('name') or item.get('title') or '').strip(),
            'enabled': bool(item.get('enabled', True)),
            'rules_count': item.get('rules_count', item.get('rulesCount')),
            'url': str(item.get('url') or '').strip(),
            'last_updated': item.get('last_updated', item.get('lastUpdated')),
        }
        if row['id']:
            filter_map[row['id']] = row['name'] or row['id']
        result['filters'].append(row)

    try:
        check = agh_get('/control/filtering/check_host', params={'name': domain})
        result['adguard']['check_host'] = 'ok'
    except Exception as exc:
        result['ok'] = False
        result['adguard']['check_host'] = 'error'
        result['error'] = f'filtering/check_host failed: {exc}'
        return result

    result['check_host'] = check
    rules = _adg_rules(check)
    for item in rules:
        rule = _adg_rule(item)
        fid = _adg_id(item)
        result['matched'].append({
            'rule': rule,
            'filter_id': fid,
            'filter_name': filter_map.get(fid, ''),
        })

    return result


@app.route('/api/adguard/list-test')
def api_adguard_list_test():
    return jsonify(_adguard_list_test(request.args.get('domain', '').strip()))
'''

anchor = "\ndef _adguard_explain(domain):\n"
if anchor not in text:
    raise SystemExit('AdGuard list test patch: insertion anchor not found')
text = text.replace(anchor, block + anchor, 1)

compile(text, str(APP), 'exec')
APP.write_text(text, encoding='utf-8')
print('DEV AdGuard list test patch applied')
