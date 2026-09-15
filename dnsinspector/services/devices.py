from dnsinspector.core.runtime import *
from contextlib import closing
from datetime import datetime, timezone, timedelta
import os, json, time, threading, queue, sqlite3, re, hashlib, socket, subprocess, shutil, zipfile, io, platform, gc, sys
import requests
from dnsinspector.services import adguard as _adguard
from dnsinspector.db import *

def is_mac(value):
    return bool(value and MAC_RE.match(str(value).strip()))

def normalize_mac(value):
    if not is_mac(value): return ''
    return str(value).strip().lower().replace('-', ':')

def load_neighbors(force=False):
    global neighbors_cache, neighbors_mtime
    try: mtime = os.path.getmtime(NEIGHBORS_PATH)
    except OSError: return {}
    with neighbors_lock:
        if not force and neighbors_mtime == mtime: return dict(neighbors_cache)
        parsed = {}
        try:
            with open(NEIGHBORS_PATH, 'r', encoding='utf-8') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 3 and is_ip(parts[0]) and parts[1] == 'lladdr' and is_mac(parts[2]): parsed[str(parts[0]).strip()] = normalize_mac(parts[2])
        except Exception as e:
            print('neighbors load error:', repr(e), flush=True); return dict(neighbors_cache)
        neighbors_cache, neighbors_mtime = parsed, mtime
        return dict(neighbors_cache)

def neighbor_mac_for_ips(ips):
    neighbors = load_neighbors()
    for ip in ips:
        mac = neighbors.get(str(ip).strip())
        if mac: return mac
    return ''

def hostname_for_ip(ip, allow_network=True):
    if not is_ip(ip): return ''
    try:
        with closing(db_connect(DB_PATH)) as c: row = c.execute('SELECT fetched_at,hostname FROM hostname_cache WHERE ip=?', (ip,)).fetchone()
        if row:
            age = datetime.now(timezone.utc) - datetime.fromisoformat(row[0])
            if age.total_seconds() < HOSTNAME_CACHE_HOURS * 3600: return row[1]
    except Exception: pass
    if not allow_network: return ''
    try:
        hostname = socket.gethostbyaddr(ip)[0].rstrip('.')
        if hostname == ip: hostname = ''
    except Exception: hostname = ''
    try:
        with db_lock, closing(db_connect(DB_PATH)) as c:
            c.execute('INSERT OR REPLACE INTO hostname_cache(ip,fetched_at,hostname) VALUES(?,?,?)', (ip, utcnow(), hostname)); c.commit()
    except Exception: pass
    return hostname

def mac_vendor_lookup(mac, allow_network=True):
    mac = normalize_mac(mac)
    if not mac: return ''
    try:
        with closing(db_connect(DB_PATH)) as c: row = c.execute('SELECT fetched_at,vendor FROM mac_vendor_cache WHERE mac=?', (mac,)).fetchone()
        if row:
            age = datetime.now(timezone.utc) - datetime.fromisoformat(row[0])
            if age.total_seconds() < MACVENDOR_CACHE_HOURS * 3600: return row[1]
    except Exception: pass
    if not allow_network: return ''
    vendor = ''
    try:
        r = http_session().get(f"{MACVENDOR_URL}/{quote(mac, safe='')}", timeout=8)
        if r.status_code == 200: vendor = r.text.strip()
    except Exception as e: print('MAC vendor lookup error:', repr(e), flush=True)
    try:
        with db_lock, closing(db_connect(DB_PATH)) as c:
            c.execute('INSERT OR REPLACE INTO mac_vendor_cache(mac,fetched_at,vendor) VALUES(?,?,?)', (mac, utcnow(), vendor)); c.commit()
    except Exception: pass
    return vendor

def _schedule_device_network_enrichment(device_key, ips, mac, hostname_hint=''):
    key = str(device_key or '')
    if not key: return
    with _enrich_guard:
        if key in _enrich_inflight: return
        _enrich_inflight.add(key)
    def run():
        try:
            hostname = str(hostname_hint or '').strip()
            if not hostname:
                for ip in ips or []:
                    hostname = hostname_for_ip(ip, allow_network=True)
                    if hostname: break
            vendor = mac_vendor_lookup(mac, allow_network=True) if mac else ''
            with db_lock, closing(db_connect(DB_PATH)) as c:
                row = c.execute('SELECT hostname,mac,vendor FROM devices WHERE device_key=?', (key,)).fetchone()
                if row:
                    final_hostname, final_mac, final_vendor = row[0] or hostname, mac or row[1], vendor or row[2]
                    if (final_hostname, final_mac, final_vendor) != (row[0], row[1], row[2]):
                        c.execute('UPDATE devices SET hostname=?, mac=?, vendor=? WHERE device_key=?', (final_hostname, final_mac, final_vendor, key)); c.commit()
        except Exception as e: print('device enrichment error:', repr(e), flush=True)
        finally:
            with _enrich_guard: _enrich_inflight.discard(key)
    DEVICE_ENRICH_EXECUTOR.submit(run)

def enrich_device_network_identity(c, device_key, ips, mac, hostname_hint=''):
    hostname = str(hostname_hint or '').strip()
    if not hostname:
        for ip in ips or []:
            hostname = hostname_for_ip(ip, allow_network=False)
            if hostname: break
    vendor = mac_vendor_lookup(mac, allow_network=False) if mac else ''
    row = c.execute('SELECT hostname,mac,vendor FROM devices WHERE device_key=?', (device_key,)).fetchone()
    if not row:
        _schedule_device_network_enrichment(device_key, ips, mac, hostname); return (hostname, vendor)
    final_hostname, final_mac, final_vendor = row[0] or hostname, mac or row[1], vendor or row[2]
    c.execute('UPDATE devices SET hostname=?, mac=?, vendor=? WHERE device_key=?', (final_hostname, final_mac, final_vendor, device_key))
    if not final_hostname or (mac and not final_vendor): _schedule_device_network_enrichment(device_key, ips, mac, final_hostname)
    return (final_hostname, final_vendor)

def is_ip(value):
    try: ipaddress.ip_address(str(value).strip()); return True
    except Exception: return False

def extract_identity(info, identifier, client_id=None):
    info = info or {}; ids = info.get('ids') or info.get('id') or []
    if isinstance(ids, str): ids = [ids]
    values = list(ids) if isinstance(ids, list) else []
    for key in ('identifier','client_id','mac','address','ip','ip_addr'):
        if info.get(key): values.append(info.get(key))
    values.append(identifier)
    if client_id: values.append(client_id)
    extra_ips = []
    for key in ('ip_addrs','ips','addresses','ip_addresses'):
        raw = info.get(key) or []
        if isinstance(raw, str): raw = [raw]
        if isinstance(raw, list): extra_ips.extend(raw)
    mac = next((normalize_mac(v) for v in values if is_mac(v)), '')
    ips = []
    for v in values + extra_ips:
        if is_ip(v):
            s = str(v).strip()
            if s not in ips: ips.append(s)
    name = str(info.get('name') or '').strip(); hostname = str(info.get('hostname') or info.get('host') or info.get('name') or '').strip(); client_identifier = str(client_id or info.get('client_id') or identifier or '').strip()
    if not mac: mac = neighbor_mac_for_ips(ips)
    if mac: device_key = 'mac:' + mac
    elif client_identifier and not is_ip(client_identifier): device_key = 'client:' + client_identifier.lower()
    elif name or hostname: device_key = 'name:' + re.sub('[^a-z0-9]+','-',(name or hostname).lower()).strip('-')
    elif ips: device_key = 'ip:' + ips[0]
    else: device_key = 'unknown:' + str(identifier)
    return (device_key, mac, ips, name, hostname)

def client_info_from_entry(entry):
    ident = entry.get('client') or entry.get('client_id') or 'unknown'; info = entry.get('client_info') or {}; client_id = entry.get('client_id') or ''; name = (info.get('name') or '').strip(); source = 'AdGuard client_info' if name else 'querylog'; device_key, mac, ips, name, hostname = extract_identity(info, ident, client_id)
    if is_ip(ident) and ident not in ips: ips.insert(0, ident)
    return (str(ident), name, source, info, device_key, mac, ips, hostname)

def upsert_device(c, device_key, name, hostname, mac, ips, source, info, now, increment=True):
    row = c.execute('SELECT request_count FROM devices WHERE device_key=?', (device_key,)).fetchone(); dtype, icon, confidence = device_hint(name, hostname, info)
    if row:
        if increment: c.execute("UPDATE devices SET name=?, hostname=?, mac=?, device_type=?, icon=?, confidence=?, source=?, first_seen=CASE WHEN first_seen='' THEN ? ELSE first_seen END, last_seen=?, request_count=request_count+1, info_json=? WHERE device_key=?", (name,hostname,mac,dtype,icon,confidence,source,now,now,json.dumps(info),device_key))
        else: c.execute("UPDATE devices SET name=?, hostname=?, mac=?, device_type=?, icon=?, confidence=?, source=?, first_seen=CASE WHEN first_seen='' THEN ? ELSE first_seen END, last_seen=?, info_json=? WHERE device_key=?", (name,hostname,mac,dtype,icon,confidence,source,now,now,json.dumps(info),device_key))
    else: c.execute('INSERT INTO devices(device_key,name,hostname,mac,device_type,icon,confidence,source,first_seen,last_seen,request_count,info_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)', (device_key,name,hostname,mac,dtype,icon,confidence,source,now,now,1,json.dumps(info)))
    for ip in ips:
        row2 = c.execute('SELECT requests FROM device_ips WHERE device_key=? AND ip=?', (device_key,ip)).fetchone()
        if row2: c.execute('UPDATE device_ips SET last_seen=?, requests=requests+1 WHERE device_key=? AND ip=?', (now,device_key,ip))
        else: c.execute('INSERT INTO device_ips(device_key,ip,first_seen,last_seen,requests) VALUES(?,?,?,?,1)', (device_key,ip,now,now))

def _validate_ping_ip(value):
    value=str(value or '').strip()
    try: addr=ipaddress.ip_address(value)
    except ValueError: raise ValueError('Invalid IP address')
    if addr.is_loopback or addr.is_multicast or not addr.is_private: raise ValueError('Only private LAN IP addresses can be pinged')
    return value

def _run_ip_ping(ip):
    ip=_validate_ping_ip(ip); started=time.monotonic(); online=False; latency_ms=None; error=''
    try:
        proc=subprocess.run(['ping','-c','1','-W',str(IP_PING_TIMEOUT_SECONDS),ip],capture_output=True,text=True,timeout=IP_PING_TIMEOUT_SECONDS+2,check=False); output=(proc.stdout or '')+'\n'+(proc.stderr or ''); online=proc.returncode==0
        if online:
            match=re.search('time[=<]([0-9.]+)\\s*ms',output); latency_ms=float(match.group(1)) if match else round((time.monotonic()-started)*1000.0,1)
        else: error='No reply'
    except FileNotFoundError: error='ping command unavailable'
    except subprocess.TimeoutExpired: error='Timeout'
    except Exception as e: error=str(e)[:200]
    checked=time.time()
    with db_lock, closing(db_connect(DB_PATH)) as c:
        c.execute('INSERT OR REPLACE INTO ip_ping_status(ip,last_checked,online,latency_ms,error) VALUES(?,?,?,?,?)',(ip,checked,1 if online else 0,latency_ms,error)); c.commit()
    return {'ip':ip,'online':online,'latency_ms':latency_ms,'error':error,'last_checked':checked}

def _ping_active_ips():
    cutoff=time.time()-DEVICE_IP_RETENTION_HOURS*3600.0
    try:
        with db_lock, closing(db_connect(DB_PATH)) as c: ips=[r[0] for r in c.execute('SELECT DISTINCT ip FROM device_ips WHERE last_seen >= ? AND ip IS NOT NULL AND TRIM(ip) <> ""',(cutoff,)).fetchall()]
        for ip in ips:
            try: _run_ip_ping(ip)
            except Exception as e: print(f'IP ping error for {ip}: {e!r}',flush=True)
        if ips: print(f'IP reachability sweep checked {len(ips)} active addresses',flush=True)
    except Exception as e: print('IP reachability sweep error:',repr(e),flush=True)

def _ip_ping_worker():
    time.sleep(IP_PING_INITIAL_DELAY_SECONDS)
    while True: _ping_active_ips(); time.sleep(IP_PING_INTERVAL_HOURS*3600.0)

def api_ip_ping_status():
    try:
        with db_lock, closing(db_connect(DB_PATH)) as c: rows=c.execute('SELECT ip,last_checked,online,latency_ms,error FROM ip_ping_status').fetchall()
        return jsonify({'ok':True,'statuses':{r[0]:{'last_checked':r[1],'online':bool(r[2]),'latency_ms':r[3],'error':r[4] or ''} for r in rows}})
    except Exception as e:
        print('IP ping status error:',repr(e),flush=True); return (jsonify({'ok':False,'statuses':{}}),500)

def api_ip_ping():
    try:
        data=request.get_json(silent=True) or {}; ip=_validate_ping_ip(data.get('ip')); return jsonify({'ok':True,'result':_run_ip_ping(ip)})
    except ValueError as e: return (jsonify({'ok':False,'error':str(e)}),400)
    except Exception as e:
        print('manual IP ping error:',repr(e),flush=True); return (jsonify({'ok':False,'error':'Ping failed'}),500)

def _prune_stale_device_ips():
    cutoff=time.time()-DEVICE_IP_RETENTION_HOURS*3600.0
    try:
        with db_lock, closing(db_connect(DB_PATH)) as c:
            removed=int(c.execute('DELETE FROM device_ips WHERE last_seen < ?',(cutoff,)).rowcount or 0); c.commit()
        if removed: print(f'Pruned {removed} stale device IP associations older than {DEVICE_IP_RETENTION_HOURS:g}h',flush=True)
        return removed
    except Exception as e: print('device IP cleanup error:',repr(e),flush=True); return 0

def _device_ip_cleanup_worker():
    while True: _prune_stale_device_ips(); time.sleep(DEVICE_IP_CLEANUP_INTERVAL_MINUTES*60)

def refresh_runtime_clients():
    data=_adguard.fetch_clients(); auto={str(x.get('ip')):x for x in data.get('auto_clients') or [] if x.get('ip')}; manual={str(ident):x for x in data.get('clients') or [] for ident in (x.get('ids') or [])};
    if not auto and not manual: return
    now=utcnow()
    with db_lock, closing(db_connect(DB_PATH)) as c:
        rows=c.execute('SELECT identifier,device_key FROM client_cache').fetchall()
        for ident,current_device_key in rows:
            x=manual.get(ident) or auto.get(ident)
            if not x: continue
            name=(x.get('name') or '').strip(); source='AdGuard configured client' if ident in manual else x.get('source') or 'AdGuard runtime client'; info=dict(x); device_key,mac,ips,cname,hostname=extract_identity(info,ident,x.get('client_id') or x.get('id')); c.execute('UPDATE client_cache SET name=?, source=?, info_json=?, device_key=?, mac=?, hostname=? WHERE identifier=?',(name or cname,source,json.dumps(info),device_key or current_device_key,mac,hostname,ident))
            if device_key:
                device_ips_now=ips or ([ident] if is_ip(ident) else []); upsert_device(c,device_key,name or cname,hostname,mac,device_ips_now,source,info,now,increment=False); enrich_device_network_identity(c,device_key,device_ips_now,mac,hostname)
        c.commit()

def migrate_legacy_domain_clients():
    with db_lock, closing(db_connect(DB_PATH)) as c:
        aliases={ident:dkey for ident,dkey in c.execute("SELECT identifier,device_key FROM client_cache WHERE device_key<>''").fetchall()}
        if not aliases: return
        for domain,raw in c.execute('SELECT domain,clients_json FROM domains').fetchall():
            try: clients=json.loads(raw or '{}')
            except Exception: clients={}
            migrated={}; changed=False
            for key,count in clients.items():
                dkey=aliases.get(key,key); changed=changed or dkey!=key; migrated[dkey]=migrated.get(dkey,0)+count
            if changed: c.execute('UPDATE domains SET clients_json=? WHERE domain=?',(json.dumps(migrated),domain))
        c.commit()

def canonicalize_client_map(clients):
    neighbors=load_neighbors(); merged={}
    for key,count in clients.items():
        new_key=key
        if str(key).startswith('ip:'):
            mac=neighbors.get(str(key)[3:])
            if mac: new_key='mac:'+mac
        merged[new_key]=merged.get(new_key,0)+count
    return merged

def device_ip_list(c,device_key):
    return [r[0] for r in c.execute('SELECT ip,last_seen FROM device_ips WHERE device_key=? ORDER BY last_seen DESC LIMIT 6',(device_key,)).fetchall()]

def domains_for_device(c,device_key,limit=25):
    rows=c.execute('SELECT domain,requests,clients_json,last_seen FROM domains ORDER BY requests DESC').fetchall(); out=[]
    for domain,requests_count,clients_json,last_seen in rows:
        try: clients=json.loads(clients_json or '{}')
        except Exception: clients={}
        if device_key in clients:
            out.append({'domain':domain,'requests':int(clients.get(device_key,0)),'last_seen':last_seen})
            if len(out)>=limit: break
    return out

def device_detail(device_key):
    if not device_key: return None
    with closing(db_connect(DB_PATH)) as c:
        row=c.execute('SELECT device_key,name,hostname,mac,vendor,device_type,icon,confidence,source,first_seen,last_seen,request_count FROM devices WHERE device_key=?',(device_key,)).fetchone()
        if not row: return None
        d={'device_key':row[0],'name':row[1],'hostname':row[2],'mac':row[3],'vendor':row[4],'type':row[5],'icon':row[6],'confidence':row[7],'source':row[8],'first_seen':row[9],'last_seen':row[10],'request_count':row[11],'vendor_logo':vendor_logo_url(row[4])}
        d['ips']=[{'ip':r[0],'first_seen':r[1],'last_seen':r[2],'requests':r[3]} for r in c.execute('SELECT ip,first_seen,last_seen,requests FROM device_ips WHERE device_key=? ORDER BY last_seen DESC',(device_key,)).fetchall()]; d['domains']=domains_for_device(c,device_key)
    return d

def ip_detail(ip):
    if not is_ip(ip): return None
    with closing(db_connect(DB_PATH)) as c:
        rows=c.execute('SELECT d.device_key,d.name,d.hostname,d.mac,d.vendor,d.device_type,d.icon,d.confidence,d.source,di.first_seen,di.last_seen,di.requests FROM device_ips di JOIN devices d ON d.device_key=di.device_key WHERE di.ip=? ORDER BY di.last_seen DESC',(ip,)).fetchall(); devices=[]; device_keys=set()
        for r in rows: device_keys.add(r[0]); devices.append({'device_key':r[0],'name':r[1],'hostname':r[2],'mac':r[3],'vendor':r[4],'type':r[5],'icon':r[6],'confidence':r[7],'source':r[8],'first_seen':r[9],'last_seen':r[10],'requests':r[11],'vendor_logo':vendor_logo_url(r[4])})
        domains=[]
        for domain,requests_count,clients_json,last_seen in c.execute('SELECT domain,requests,clients_json,last_seen FROM domains ORDER BY requests DESC').fetchall():
            try: clients=json.loads(clients_json or '{}')
            except Exception: clients={}
            count=sum(int(clients.get(k,0)) for k in device_keys)
            if count:
                domains.append({'domain':domain,'requests':count,'last_seen':last_seen})
                if len(domains)>=50: break
    return {'ip':ip,'devices':devices,'domains':domains}

def client_display(c,device_key,count):
    row=c.execute('SELECT device_key,name,hostname,mac,vendor,device_type,icon,confidence,source,request_count FROM devices WHERE device_key=?',(device_key,)).fetchone()
    if row:
        _,name,hostname,mac,vendor,dtype,icon,confidence,source,total=row; ips=device_ip_list(c,device_key); display=hostname or name or vendor or device_key
        return {'device_key':device_key,'identifier':device_key,'display_name':hostname or name or vendor or display,'name':name,'hostname':hostname,'mac':mac,'vendor':vendor,'vendor_logo':vendor_logo_url(vendor),'type':dtype,'icon':icon,'confidence_label':confidence,'source':source,'requests':count,'ips':ips,'total_requests':total}
    return {'device_key':device_key,'identifier':device_key,'display_name':device_key,'name':'','hostname':'','mac':'','vendor':'','type':'IoT / Unknown','icon':'📦','confidence_label':'low','source':'historical','requests':count,'ips':[],'total_requests':count}

def device_hint(name,hostname,info):
    text=' '.join([str(name or ''),str(hostname or ''),json.dumps(info or {})]).lower()
    if any(x in text for x in ('webos','smart tv','smart-tv','oled','qn ed','lgtv','television')): return ('TV','📺','high')
    if any(x in text for x in ('aircon','air conditioner','air-conditioner','lg ac','climat')): return ('AC','❄️','high')
    if any(x in text for x in ('dryer','tumble')): return ('Dryer','🧺','medium')
    if any(x in text for x in ('washer','washing machine')): return ('Washing machine','🧺','medium')
    if any(x in text for x in ('iphone','ipad','android','pixel','galaxy')): return ('Phone / Tablet','📱','medium')
    if any(x in text for x in ('macbook','laptop','windows','desktop','pc')): return ('Computer','💻','medium')
    if any(x in text for x in ('playstation','xbox','switch')): return ('Console','🎮','medium')
    if any(x in text for x in ('camera','cam-','ipc')): return ('Camera','📷','medium')
    if any(x in text for x in ('speaker','sonos','echo','homepod')): return ('Speaker','🔊','medium')
    if any(x in text for x in ('router','gateway','switch','access point','ap-')): return ('Network','🛜','medium')
    return ('IoT / Unknown','📦','low')

def reconcile_neighbors():
    neighbors=load_neighbors()
    if not neighbors: return 0
    changed=0; now=utcnow()
    with db_lock, closing(db_connect(DB_PATH)) as c:
        for ip,mac in neighbors.items():
            old_key='ip:'+ip; new_key='mac:'+mac
            if old_key==new_key: continue
            old=c.execute('SELECT name,hostname,mac,device_type,icon,confidence,source,first_seen,last_seen,request_count,info_json FROM devices WHERE device_key=?',(old_key,)).fetchone()
            if not old: continue
            new=c.execute('SELECT request_count FROM devices WHERE device_key=?',(new_key,)).fetchone()
            if new:
                c.execute("UPDATE devices SET name=COALESCE(NULLIF(name,''),?), hostname=COALESCE(NULLIF(hostname,''),?), mac=?, device_type=CASE WHEN device_type='IoT / Unknown' THEN ? ELSE device_type END, icon=CASE WHEN icon='📦' THEN ? ELSE icon END, confidence=CASE WHEN confidence='low' THEN ? ELSE confidence END, first_seen=CASE WHEN first_seen='' OR first_seen > ? THEN ? ELSE first_seen END, last_seen=CASE WHEN last_seen < ? THEN ? ELSE last_seen END, request_count=request_count+?, info_json=CASE WHEN info_json='{}' THEN ? ELSE info_json END WHERE device_key=?",(old[0],old[1],mac,old[3],old[4],old[5],old[7],old[7],old[8],old[8],old[9],old[10],new_key))
            else:
                c.execute('INSERT INTO devices(device_key,name,hostname,mac,device_type,icon,confidence,source,first_seen,last_seen,request_count,info_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(new_key,old[0],old[1],mac,old[3],old[4],old[5],old[6],old[7],old[8],old[9],old[10]))
            old_ips=c.execute('SELECT ip,last_seen FROM device_ips WHERE device_key=?',(old_key,)).fetchall()
            for old_ip,old_ip_seen in old_ips:
                existing=c.execute('SELECT last_seen FROM device_ips WHERE device_key=? AND ip=?',(new_key,old_ip)).fetchone()
                if existing:
                    keep_seen=existing[0] if (existing[0] or '') >= (old_ip_seen or '') else old_ip_seen; c.execute('UPDATE device_ips SET last_seen=? WHERE device_key=? AND ip=?',(keep_seen,new_key,old_ip)); c.execute('DELETE FROM device_ips WHERE device_key=? AND ip=?',(old_key,old_ip))
                else: c.execute('UPDATE device_ips SET device_key=? WHERE device_key=? AND ip=?',(new_key,old_key,old_ip))
            c.execute('DELETE FROM devices WHERE device_key=?',(old_key,)); changed+=1
        for domain,raw in c.execute('SELECT domain,clients_json FROM domains').fetchall():
            try: clients=json.loads(raw or '{}')
            except Exception: clients={}
            migrated={}; did_change=False
            for key,count in clients.items():
                if key.startswith('ip:'):
                    mac=neighbors.get(key[3:]); new_key='mac:'+mac if mac else key
                else: new_key=key
                did_change=did_change or new_key!=key; migrated[new_key]=migrated.get(new_key,0)+count
            if did_change: c.execute('UPDATE domains SET clients_json=? WHERE domain=?',(json.dumps(migrated),domain))
        for dkey,dmac,dhost in c.execute('SELECT device_key,mac,hostname FROM devices').fetchall():
            ips=[r[0] for r in c.execute('SELECT ip FROM device_ips WHERE device_key=? ORDER BY last_seen DESC LIMIT 6',(dkey,)).fetchall()]
            enrich_device_network_identity(c,dkey,ips,dmac,dhost)
        c.commit()
    if changed: print(f'Reconciled {changed} legacy IP device(s) using neighbors.txt.',flush=True)
    return changed
