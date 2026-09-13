from pathlib import Path

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

# Browser-safe MAC lookup URL. macvendors.com/<mac> is its API endpoint, which
# can return 404 when opened as a normal webpage. MACLookup has a browser route.
text = text.replace(
    'return f"https://macvendors.com/{quote(mac, safe=\':\') }" if mac else \'\'',
    'return f"https://maclookup.app/search/result?mac={quote(mac, safe=\':\')}" if mac else \'\'',
    1,
)
text = text.replace(
    'https://macvendors.com/${encodeURIComponent(c.mac)}',
    'https://maclookup.app/search/result?mac=${encodeURIComponent(c.mac)}',
)

# Persistent labels live in a separate table so the existing devices table and
# its identity/reconciliation logic remain untouched. The DB is already on /data.
label_endpoint = '''@app.route("/api/device/label", methods=["GET", "POST"])
def api_device_label():
    try:
        with db_lock, sqlite3.connect(DB_PATH) as c:
            c.execute("CREATE TABLE IF NOT EXISTS device_labels(device_key TEXT PRIMARY KEY, label TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL)")
            if request.method == "GET":
                rows = c.execute("SELECT device_key,label FROM device_labels WHERE TRIM(label)<>''").fetchall()
                return jsonify({"ok": True, "labels": {k: v for k, v in rows}})
            data = request.get_json(silent=True) or {}
            device_key = str(data.get("device_key") or "").strip()
            label = str(data.get("label") or "").strip()[:80]
            if not device_key:
                return jsonify({"ok": False, "error": "device_key is required"}), 400
            c.execute("INSERT OR REPLACE INTO device_labels(device_key,label,updated_at) VALUES(?,?,?)", (device_key, label, utcnow()))
            c.commit()
            return jsonify({"ok": True, "device_key": device_key, "label": label})
    except Exception as e:
        print("device label error:", repr(e), flush=True)
        return jsonify({"ok": False, "error": "Unable to save device label"}), 500


'''
marker = '@app.route("/device")\ndef device_view():'
if marker not in text:
    raise SystemExit('device label v2 patch failed: device route marker not found')
text = text.replace(marker, label_endpoint + marker, 1)

# Add compact device-label controls to the Devices tab.
needle = 'function deviceRow(c){\n'
if needle not in text:
    raise SystemExit('device label v2 patch failed: deviceRow marker not found')
text = text.replace(needle, "function deviceLabelFor(c){ return String((window.deviceLabels||{})[c.device_key||c.identifier]||c.label||'').trim(); }\nfunction deviceRow(c){\n", 1)

old = '  const linkedPrimary = realDeviceLabel(c);\n  const primary = linkedPrimary || c.vendor || c.identifier;'
new = '  const explicitLabel = deviceLabelFor(c);\n  const linkedPrimary = explicitLabel || realDeviceLabel(c);\n  const primary = linkedPrimary || c.vendor || c.identifier;'
if old not in text:
    raise SystemExit('device label v2 patch failed: device primary block not found')
text = text.replace(old, new, 1)

old = '  return `<tr data-sort-device="${esc(primary)}" data-sort-identity="${esc(c.mac || \'\')}" data-sort-ips="${esc((c.ips || []).join(\' \'))}" data-sort-requests="${Number(c.requests)||0}"><td><div class="device">${visualHtml}<span>${primaryHtml}${vendor}${host}<div class="confidence">${esc(c.type)} · ${esc(c.confidence_label)}</div>${source}</span></div></td><td>${ips || \'—\'}</td><td>${c.mac ? `<span class="mono">${esc(c.mac)}</span> ${externalButton(`https://maclookup.app/search/result?mac=${encodeURIComponent(c.mac)}`,\'MAC lookup\')}` : \'—\'}</td><td>${esc(c.requests)}</td></tr>`;'
new = '  const labelButton = `<button type="button" class="device-label-btn" data-device-key="${esc(c.device_key||c.identifier||\'\')}" data-device-label="${esc(explicitLabel)}">${explicitLabel?\'Edit label\':\'Add label\'}</button>`; const labelMeta = `<div class="device-label-inline"><span class="device-label-text">${explicitLabel?\'Label: \'+esc(explicitLabel):\'No label\'}</span>${labelButton}</div>`; return `<tr data-sort-device="${esc(primary)}" data-sort-identity="${esc(c.mac || \'\')}" data-sort-ips="${esc((c.ips || []).join(\' \'))}" data-sort-requests="${Number(c.requests)||0}"><td><div class="device">${visualHtml}<span>${primaryHtml}${vendor}${host}<div class="confidence">${esc(c.type)} · ${esc(c.confidence_label)}</div>${labelMeta}${source}</span></div></td><td>${ips || \'—\'}</td><td>${c.mac ? `<span class="mono">${esc(c.mac)}</span> ${externalButton(`https://maclookup.app/search/result?mac=${encodeURIComponent(c.mac)}`,\'MAC lookup\')}` : \'—\'}</td><td>${esc(c.requests)}</td></tr>`;'
if old not in text:
    raise SystemExit('device label v2 patch failed: deviceRow return not found')
text = text.replace(old, new, 1)

# Apply labels to Overview device chips too.
old = 'const devices=(r.devices||[]).map(d=>`<a class="device-chip link-device" href="${deviceHref(d)}" title="Open device details">${d.vendor_logo?`<img class="vendor-logo" src="${esc(d.vendor_logo)}" alt="" loading="lazy">`:deviceTypeSvg(d.type,d.icon,false)}${esc(d.name)}</a>`).join(\'\');'
new = 'const devices=(r.devices||[]).map(d=>{const label=deviceLabelFor(d);return `<a class="device-chip link-device" href="${deviceHref(d)}" title="Open device details">${d.vendor_logo?`<img class="vendor-logo" src="${esc(d.vendor_logo)}" alt="" loading="lazy">`:deviceTypeSvg(d.type,d.icon,false)}${esc(label||d.name)}</a>`;}).join(\'\');'
if old not in text:
    raise SystemExit('device label v2 patch failed: Overview device chips not found')
text = text.replace(old, new, 1)

# Small UI controls + client-side label fetch/save.
css_marker = '.clickable-label{cursor:pointer}'
css_insert = '.device-label-btn{padding:3px 7px;font-size:.72rem;border-radius:7px}.device-label-inline{display:inline-flex;align-items:center;gap:6px;margin-top:4px}.device-label-text{color:#c9d1d9;font-size:.76rem}.clickable-label{cursor:pointer}'
if css_marker not in text:
    raise SystemExit('device label v2 patch failed: CSS marker not found')
text = text.replace(css_marker, css_insert, 1)

marker = "function renderClients(rows){ document.getElementById('clients-body').innerHTML = rows.map(deviceRow).join(''); reapplyTableSorts(); }"
insert = "window.deviceLabels={};\nasync function loadDeviceLabels(){try{const r=await fetch('/api/device/label',{cache:'no-store'});if(!r.ok)return;const data=await r.json();window.deviceLabels=data.labels||{};}catch(e){console.debug('device labels load failed',e)}}\nasync function editDeviceLabel(button){const key=button?.dataset?.deviceKey||'';if(!key)return;const current=button.dataset.deviceLabel||'';const value=window.prompt('Device label',current);if(value===null)return;const label=value.trim().slice(0,80);try{const r=await fetch('/api/device/label',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({device_key:key,label})});const data=await r.json();if(!r.ok||!data.ok)throw new Error(data.error||'Save failed');window.deviceLabels[key]=label;renderClients(window.__lastClients||[]);renderRecent(window.__lastRecent||[]);bindDeviceLabelButtons();}catch(e){alert('Could not save device label: '+e.message)}}\nfunction bindDeviceLabelButtons(){document.querySelectorAll('.device-label-btn').forEach(b=>{if(b.dataset.bound)return;b.dataset.bound='1';b.addEventListener('click',()=>editDeviceLabel(b));})}\n"
if marker not in text:
    raise SystemExit('device label v2 patch failed: renderClients marker not found')
text = text.replace(marker, insert + marker, 1)

old = "function renderClients(rows){ document.getElementById('clients-body').innerHTML = rows.map(deviceRow).join(''); reapplyTableSorts(); }"
new = "function renderClients(rows){ window.__lastClients=rows||[]; document.getElementById('clients-body').innerHTML = rows.map(deviceRow).join(''); bindDeviceLabelButtons(); reapplyTableSorts(); }"
text = text.replace(old, new, 1)

# Keep last recent rows so a label save can re-render without an extra API request.
old = 'function renderRecent(rows){document.getElementById(\'recent-body\').innerHTML=(rows||[]).map(r=>'
new = 'function renderRecent(rows){window.__lastRecent=rows||[];document.getElementById(\'recent-body\').innerHTML=(rows||[]).map(r=>'
if old not in text:
    raise SystemExit('device label v2 patch failed: renderRecent marker not found')
text = text.replace(old, new, 1)

# Load labels once before the regular polling loop starts.
old = "const initialStamp=formatUpdated({{ updated|tojson }});document.getElementById('last-update-time').textContent=initialStamp.time;document.getElementById('last-update-date').textContent=initialStamp.date;scheduleRefresh(refreshMs);"
new = "const initialStamp=formatUpdated({{ updated|tojson }});document.getElementById('last-update-time').textContent=initialStamp.time;document.getElementById('last-update-date').textContent=initialStamp.date;loadDeviceLabels().then(()=>{renderClients(window.__lastClients||[]);renderRecent(window.__lastRecent||[]);bindDeviceLabelButtons();});scheduleRefresh(refreshMs);"
if old not in text:
    raise SystemExit('device label v2 patch failed: initial refresh hook not found')
text = text.replace(old, new, 1)

APP.write_text(text, encoding='utf-8')
print('DNS Inspector v2 device labels + MAC lookup patch applied')
