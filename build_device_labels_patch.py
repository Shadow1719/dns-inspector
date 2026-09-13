from pathlib import Path

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

# Persistent human-friendly device labels. Labels are attached to the stable
# device identity (normally MAC) and are never overwritten by automatic enrichment.
text = text.replace(
    '        add_column_if_missing(c, "devices", "vendor", "TEXT NOT NULL DEFAULT \'\'")\n',
    '        add_column_if_missing(c, "devices", "vendor", "TEXT NOT NULL DEFAULT \'\'")\n        add_column_if_missing(c, "devices", "label", "TEXT NOT NULL DEFAULT \'\'")\n',
    1,
)

# Preserve labels when legacy IP-keyed devices are reconciled into MAC-keyed devices.
old = 'old = c.execute("SELECT name,hostname,mac,device_type,icon,confidence,source,first_seen,last_seen,request_count,info_json FROM devices WHERE device_key=?", (old_key,)).fetchone()'
new = 'old = c.execute("SELECT name,hostname,mac,device_type,icon,confidence,source,first_seen,last_seen,request_count,info_json,label FROM devices WHERE device_key=?", (old_key,)).fetchone()'
if old not in text:
    raise SystemExit('device label patch failed: legacy device SELECT not found')
text = text.replace(old, new, 1)

old = '''UPDATE devices SET name=COALESCE(NULLIF(name,''),?), hostname=COALESCE(NULLIF(hostname,''),?), mac=?,
                            device_type=CASE WHEN device_type='IoT / Unknown' THEN ? ELSE device_type END,
                            icon=CASE WHEN icon='📦' THEN ? ELSE icon END,
                            confidence=CASE WHEN confidence='low' THEN ? ELSE confidence END,
                            first_seen=CASE WHEN first_seen='' OR first_seen > ? THEN ? ELSE first_seen END,
                            last_seen=CASE WHEN last_seen < ? THEN ? ELSE last_seen END,
                            request_count=request_count+?, info_json=CASE WHEN info_json='{}' THEN ? ELSE info_json END
                            WHERE device_key=?'''
new = '''UPDATE devices SET name=COALESCE(NULLIF(name,''),?), hostname=COALESCE(NULLIF(hostname,''),?), mac=?,
                            device_type=CASE WHEN device_type='IoT / Unknown' THEN ? ELSE device_type END,
                            icon=CASE WHEN icon='📦' THEN ? ELSE icon END,
                            confidence=CASE WHEN confidence='low' THEN ? ELSE confidence END,
                            first_seen=CASE WHEN first_seen='' OR first_seen > ? THEN ? ELSE first_seen END,
                            last_seen=CASE WHEN last_seen < ? THEN ? ELSE last_seen END,
                            request_count=request_count+?, info_json=CASE WHEN info_json='{}' THEN ? ELSE info_json END,
                            label=CASE WHEN label='' THEN ? ELSE label END
                            WHERE device_key=?'''
if old not in text:
    raise SystemExit('device label patch failed: legacy device UPDATE not found')
text = text.replace(old, new, 1)

old = '(old[0], old[1], mac, old[3], old[4], old[5], old[7], old[7], old[8], old[8], old[9], old[10], new_key))'
new = '(old[0], old[1], mac, old[3], old[4], old[5], old[7], old[7], old[8], old[8], old[9], old[10], old[11], new_key))'
if old not in text:
    raise SystemExit('device label patch failed: legacy device UPDATE args not found')
text = text.replace(old, new, 1)

old = '''INSERT INTO devices(device_key,name,hostname,mac,device_type,icon,confidence,source,first_seen,last_seen,request_count,info_json)
                             VALUES(?,?,?,?,?,?,?,?,?,?,?,?)'''
new = '''INSERT INTO devices(device_key,name,hostname,mac,device_type,icon,confidence,source,first_seen,last_seen,request_count,info_json,label)
                             VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)'''
if old not in text:
    raise SystemExit('device label patch failed: legacy device INSERT not found')
text = text.replace(old, new, 1)
old = '(new_key, old[0], old[1], mac, old[3], old[4], old[5], old[6], old[7], old[8], old[9], old[10]))'
new = '(new_key, old[0], old[1], mac, old[3], old[4], old[5], old[6], old[7], old[8], old[9], old[10], old[11]))'
if old not in text:
    raise SystemExit('device label patch failed: legacy device INSERT args not found')
text = text.replace(old, new, 1)

# Include the label in all device payloads used by the UI.
old = 'row = c.execute("SELECT device_key,name,hostname,mac,vendor,device_type,icon,confidence,source,request_count FROM devices WHERE device_key=?", (device_key,)).fetchone()'
new = 'row = c.execute("SELECT device_key,name,hostname,mac,vendor,device_type,icon,confidence,source,request_count,label FROM devices WHERE device_key=?", (device_key,)).fetchone()'
if old not in text:
    raise SystemExit('device label patch failed: client_display SELECT not found')
text = text.replace(old, new, 1)

old = '        _, name, hostname, mac, vendor, dtype, icon, confidence, source, total = row'
new = '        _, name, hostname, mac, vendor, dtype, icon, confidence, source, total, label = row'
if old not in text:
    raise SystemExit('device label patch failed: client_display unpack not found')
text = text.replace(old, new, 1)

old = '"device_key": device_key, "identifier": device_key, "display_name": hostname or name or vendor or display, "name": name, "hostname": hostname, "mac": mac, "vendor": vendor, "vendor_logo": vendor_logo_url(vendor), "type": dtype, "icon": icon, "confidence_label": confidence, "source": source, "requests": count, "ips": ips, "total_requests": total'
new = '"device_key": device_key, "identifier": device_key, "display_name": label or hostname or name or vendor or display, "label": label, "name": name, "hostname": hostname, "mac": mac, "vendor": vendor, "vendor_logo": vendor_logo_url(vendor), "type": dtype, "icon": icon, "confidence_label": confidence, "source": source, "requests": count, "ips": ips, "total_requests": total'
if old not in text:
    raise SystemExit('device label patch failed: client_display payload not found')
text = text.replace(old, new, 1)

old = '"device_key": device_key, "identifier": device_key, "display_name": device_key, "name": "", "hostname": "", "mac": "", "vendor": "", "type": "IoT / Unknown", "icon": "📦", "confidence_label": "low", "source": "historical", "requests": count, "ips": [], "total_requests": count}'
new = '"device_key": device_key, "identifier": device_key, "display_name": device_key, "label": "", "name": "", "hostname": "", "mac": "", "vendor": "", "type": "IoT / Unknown", "icon": "📦", "confidence_label": "low", "source": "historical", "requests": count, "ips": [], "total_requests": count}'
if old not in text:
    raise SystemExit('device label patch failed: client_display fallback not found')
text = text.replace(old, new, 1)

# Devices tab query + payload.
old = 'rows = c.execute("SELECT device_key,name,hostname,mac,vendor,device_type,icon,confidence,source,request_count FROM devices ORDER BY request_count DESC").fetchall()'
new = 'rows = c.execute("SELECT device_key,name,hostname,mac,vendor,device_type,icon,confidence,source,request_count,label FROM devices ORDER BY request_count DESC").fetchall()'
if old not in text:
    raise SystemExit('device label patch failed: get_clients SELECT not found')
text = text.replace(old, new, 1)
old = 'for device_key, name, hostname, mac, vendor, dtype, icon, confidence, source, count in rows:'
new = 'for device_key, name, hostname, mac, vendor, dtype, icon, confidence, source, count, label in rows:'
if old not in text:
    raise SystemExit('device label patch failed: get_clients unpack not found')
text = text.replace(old, new, 1)
old = 'out.append({"identifier": device_key, "name": name, "display_name": hostname or name or vendor or device_key, "hostname": hostname, "mac": mac, "vendor": vendor, "vendor_logo": vendor_logo_url(vendor), "type": dtype, "icon": icon, "confidence_label": confidence, "source": source, "requests": count, "ips": ips})'
new = 'out.append({"identifier": device_key, "device_key": device_key, "label": label, "name": name, "display_name": label or hostname or name or vendor or device_key, "hostname": hostname, "mac": mac, "vendor": vendor, "vendor_logo": vendor_logo_url(vendor), "type": dtype, "icon": icon, "confidence_label": confidence, "source": source, "requests": count, "ips": ips})'
if old not in text:
    raise SystemExit('device label patch failed: get_clients payload not found')
text = text.replace(old, new, 1)

# Device detail data includes label.
old = 'row = c.execute("SELECT device_key,name,hostname,mac,vendor,device_type,icon,confidence,source,first_seen,last_seen,request_count FROM devices WHERE device_key=?", (device_key,)).fetchone()'
new = 'row = c.execute("SELECT device_key,name,hostname,mac,vendor,device_type,icon,confidence,source,first_seen,last_seen,request_count,label FROM devices WHERE device_key=?", (device_key,)).fetchone()'
if old not in text:
    raise SystemExit('device label patch failed: device_detail SELECT not found')
text = text.replace(old, new, 1)
old = 'd = {"device_key": row[0], "name": row[1], "hostname": row[2], "mac": row[3], "vendor": row[4], "type": row[5], "icon": row[6], "confidence": row[7], "source": row[8], "first_seen": row[9], "last_seen": row[10], "request_count": row[11], "vendor_logo": vendor_logo_url(row[4])}'
new = 'd = {"device_key": row[0], "name": row[1], "hostname": row[2], "mac": row[3], "vendor": row[4], "type": row[5], "icon": row[6], "confidence": row[7], "source": row[8], "first_seen": row[9], "last_seen": row[10], "request_count": row[11], "label": row[12], "vendor_logo": vendor_logo_url(row[4])}'
if old not in text:
    raise SystemExit('device label patch failed: device_detail payload not found')
text = text.replace(old, new, 1)

# Server-side device label preference in generated detail pages.
old = 'primary = d.get("hostname") or d.get("name") or d.get("vendor") or d.get("device_key")'
new = 'primary = d.get("label") or d.get("hostname") or d.get("name") or d.get("vendor") or d.get("device_key")'
if old not in text:
    raise SystemExit('device label patch failed: detail primary not found')
text = text.replace(old, new, 1)

# Add a persistent label field/button to device detail header.
old = '<div class="confidence">{_html(d.get(\'type\'))} · {_html(d.get(\'confidence\'))}</div></span></div>'
new = '<div class="confidence">{_html(d.get(\'type\'))} · {_html(d.get(\'confidence\'))}</div><div class="device-label-detail"><span class="sub">Label: {_html(d.get(\'label\') or \'—\')}</span> <button type="button" class="device-label-btn" data-device-key="{_html(d.get(\'device_key\'))}" data-device-label="{_html(d.get(\'label\') or \'\')}">{\'Edit label\' if d.get(\'label\') else \'Add label\'}</button></div></span></div>'
if old not in text:
    raise SystemExit('device label patch failed: detail HTML hook not found')
text = text.replace(old, new, 1)

# A human label should win over inferred hostname/vendor in server-generated device labels.
old = 'for value in (c.get(\'hostname\'), c.get(\'name\'), c.get(\'display_name\')):'
new = 'for value in (c.get(\'label\'), c.get(\'hostname\'), c.get(\'name\'), c.get(\'display_name\')):'
if old not in text:
    raise SystemExit('device label patch failed: real_device_label loop not found')
text = text.replace(old, new, 1)

# Browser UI: styles and label editing helper.
marker = '.clickable-label{cursor:pointer}.glance-meta{display:flex;flex-wrap:wrap;gap:6px;margin-top:4px;color:#8b949e;font-size:.78rem}.glance-devices{max-width:520px}'
insert = '.clickable-label{cursor:pointer}.device-label-btn{padding:3px 7px;font-size:.72rem;border-radius:7px}.device-label-detail{margin-top:4px}.device-label-inline{display:inline-flex;align-items:center;gap:6px;margin-top:4px}.device-label-text{color:#c9d1d9;font-size:.76rem}.glance-meta{display:flex;flex-wrap:wrap;gap:6px;margin-top:4px;color:#8b949e;font-size:.78rem}.glance-devices{max-width:520px}'
if marker not in text:
    raise SystemExit('device label patch failed: CSS marker not found')
text = text.replace(marker, insert, 1)

# Fix external MAC lookup: macvendors.com/.... is the API, not a public lookup page.
# Use the working public MAC lookup site for browser navigation.
old = 'https://macvendors.com/${encodeURIComponent(c.mac)}'
new = 'https://maclookup.app/search'
# Keep the actual MAC in a data attribute and add a query to the public search URL when possible.
# The site can still accept pasted MACs; the important part is removing the 404 API-path link.
text = text.replace(old, new)

# Browser realDeviceLabel: user label always wins.
old = 'function realDeviceLabel(c){ const vendor=String(c.vendor||\'\').trim().toLowerCase(); const identifier=String(c.device_key||c.identifier||\'\').trim().toLowerCase(); for(const v of [c.hostname,c.name,c.display_name]){ const t=String(v||\'\').trim(); if(t && t.toLowerCase()!==vendor && t.toLowerCase()!==identifier) return t; } return \'\'; }'
new = 'function realDeviceLabel(c){ const explicit=String(c.label||\'\').trim(); if(explicit) return explicit; const vendor=String(c.vendor||\'\').trim().toLowerCase(); const identifier=String(c.device_key||c.identifier||\'\').trim().toLowerCase(); for(const v of [c.hostname,c.name,c.display_name]){ const t=String(v||\'\').trim(); if(t && t.toLowerCase()!==vendor && t.toLowerCase()!==identifier) return t; } return \'\'; }'
if old not in text:
    raise SystemExit('device label patch failed: JS realDeviceLabel not found')
text = text.replace(old, new, 1)

# Device row gets a small Add/Edit label control.
old = 'return `<tr data-sort-device="${esc(primary)}" data-sort-identity="${esc(c.mac || \'\')}" data-sort-ips="${esc((c.ips || []).join(\' \'))}" data-sort-requests="${Number(c.requests)||0}"><td><div class="device">${visualHtml}<span>${primaryHtml}${vendor}${host}<div class="confidence">${esc(c.type)} · ${esc(c.confidence_label)}</div>${source}</span></div></td><td>${ips || \'—\'}</td><td>${c.mac ? `<span class="mono">${esc(c.mac)}</span> ${externalButton(`https://macvendors.com/${encodeURIComponent(c.mac)}`,\'MAC lookup\')}` : \'—\'}</td><td>${esc(c.requests)}</td></tr>`;'
new = 'const labelText=String(c.label||\'\').trim(); const labelButton=`<button type="button" class="device-label-btn" data-device-key="${esc(c.device_key||c.identifier||\'\')}" data-device-label="${esc(labelText)}">${labelText?\'Edit label\':\'Add label\'}</button>`; return `<tr data-sort-device="${esc(primary)}" data-sort-identity="${esc(c.mac || \'\')}" data-sort-ips="${esc((c.ips || []).join(\' \'))}" data-sort-requests="${Number(c.requests)||0}"><td><div class="device">${visualHtml}<span>${primaryHtml}${vendor}${host}<div class="confidence">${esc(c.type)} · ${esc(c.confidence_label)}</div><div class="device-label-inline"><span class="device-label-text">${labelText?\'Label: \'+esc(labelText):\'No label\'}</span>${labelButton}</div>${source}</span></div></td><td>${ips || \'—\'}</td><td>${c.mac ? `<span class="mono">${esc(c.mac)}</span> ${externalButton(`https://maclookup.app/search`,\'MAC lookup\')}` : \'—\'}</td><td>${esc(c.requests)}</td></tr>`;'
if old not in text:
    raise SystemExit('device label patch failed: JS deviceRow return not found')
text = text.replace(old, new, 1)

# Overview device chips use the label when present.
old = '${esc(d.name)}'
new = '${esc(d.label || d.name)}'
text = text.replace(old, new, 1)

# Label editing function + event binding before sortable tables.
marker = "function renderClients(rows){ document.getElementById('clients-body').innerHTML = rows.map(deviceRow).join(''); reapplyTableSorts(); }"
insert = marker + "\nasync function editDeviceLabel(button){ const key=button?.dataset?.deviceKey||''; if(!key)return; const current=button.dataset.deviceLabel||''; const value=window.prompt('Device label',current); if(value===null)return; const label=value.trim().slice(0,80); try{ const r=await fetch('/api/device/label',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({device_key:key,label})}); const data=await r.json(); if(!r.ok||!data.ok)throw new Error(data.error||'Save failed'); requestRefresh(); }catch(e){ alert('Could not save device label: '+e.message); } }\nfunction bindDeviceLabelButtons(){ document.querySelectorAll('.device-label-btn').forEach(b=>{ if(b.dataset.bound)return; b.dataset.bound='1'; b.addEventListener('click',()=>editDeviceLabel(b)); }); }"
if marker not in text:
    raise SystemExit('device label patch failed: renderClients marker not found')
text = text.replace(marker, insert, 1)

# Ensure dynamically rendered buttons get their handler.
old = "function renderClients(rows){ document.getElementById('clients-body').innerHTML = rows.map(deviceRow).join(''); reapplyTableSorts(); }\nlet tableSortState"
new = "function renderClients(rows){ document.getElementById('clients-body').innerHTML = rows.map(deviceRow).join(''); bindDeviceLabelButtons(); reapplyTableSorts(); }\nlet tableSortState"
if old not in text:
    raise SystemExit('device label patch failed: renderClients binding hook not found')
text = text.replace(old, new, 1)

# API endpoint for persistent labels.
marker = '@app.route("/device")\ndef device_view():'
insert = '''@app.route("/api/device/label", methods=["POST"])
def api_device_label():
    try:
        data = request.get_json(silent=True) or {}
        device_key = str(data.get("device_key") or "").strip()
        label = str(data.get("label") or "").strip()[:80]
        if not device_key:
            return jsonify({"ok": False, "error": "device_key is required"}), 400
        with db_lock, sqlite3.connect(DB_PATH) as c:
            exists = c.execute("SELECT 1 FROM devices WHERE device_key=?", (device_key,)).fetchone()
            if not exists:
                return jsonify({"ok": False, "error": "Device not found"}), 404
            c.execute("UPDATE devices SET label=? WHERE device_key=?", (label, device_key))
            c.commit()
        return jsonify({"ok": True, "device_key": device_key, "label": label})
    except Exception as e:
        print("device label error:", repr(e), flush=True)
        return jsonify({"ok": False, "error": "Unable to save device label"}), 500


@app.route("/device")
def device_view():'''
if marker not in text:
    raise SystemExit('device label patch failed: device route marker not found')
text = text.replace(marker, insert, 1)

APP.write_text(text, encoding='utf-8')
print('DNS Inspector device labels + MAC lookup patch applied')
