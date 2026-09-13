import re
from pathlib import Path

APP = Path("/app/app.py")
text = APP.read_text(encoding="utf-8")

css_marker = '.glance-devices{max-width:520px}'
css_patch = '''.glance-devices{max-width:520px}
.lookup-row{display:grid;grid-template-columns:minmax(0,1fr) 118px;gap:8px;align-items:start;min-width:0}
.lookup-value{min-width:0;overflow-wrap:anywhere}
.lookup-action{width:118px;display:flex;justify-content:flex-start}
.lookup-action .external-tool{width:118px;justify-content:flex-start;margin:0;white-space:nowrap}'''
if css_marker not in text:
    raise SystemExit("UI patch failed: CSS marker not found")
text = text.replace(css_marker, css_patch, 1)

vendor_re = re.compile(r'^  const vendor = c\.vendor \? .*? : \'\';$', re.M)
vendor_new = '''  const vendor = c.vendor ? `<div class="lookup-row"><div class="lookup-value sub">${c.vendor_logo ? `<img class="vendor-logo" src="${esc(c.vendor_logo)}" alt="" loading="lazy">` : `<span class="vendor-mark">◈</span>`}${esc(c.vendor)}</div><div class="lookup-action">${externalButton(`https://www.google.com/search?q=${encodeURIComponent(c.vendor)}`,'Search vendor')}</div></div>` : '';'''
text, n = vendor_re.subn(vendor_new, text, count=1)
if n != 1:
    raise SystemExit("UI patch failed: vendor row not found")

return_re = re.compile(r'^  return `'<r data-sort-device=.*$', re.M)
return_new = '''  return `<tr data-sort-device="${esc(primary)}" data-sort-identity="${esc(c.mac || '')}" data-sort-ips="${esc((c.ips || []).join(' '))}" data-sort-requests="${Number(c.requests)||0}"><td><div class="device">${visualHtml}<span>${primaryHtml}${vendor}${host}<div class="confidence">${esc(c.type)} · ${esc(c.confidence_label)}</div>${source}</span></div></td><td>${ips || '—'}</td><td>${c.mac ? `<div class="lookup-row"><span class="lookup-value mono">${esc(c.mac)}</span><span class="lookup-action">${externalButton(`https://macvendors.com/${encodeURIComponent(c.mac)}`,'MAC lookup')}</span></div>` : '—'}</td><td>${esc(c.requests)}</td></tr>`;'''
text, n = return_re.subn(return_new, text, count=1)
if n != 1:
    raise SystemExit("UI patch failed: device row return not found")

APP.write_text(text, encoding="utf-8")
print("DNS Inspector UI alignment patch applied")
