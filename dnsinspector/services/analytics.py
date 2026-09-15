from dnsinspector.core.runtime import *
from contextlib import closing
from datetime import datetime, timezone, timedelta
import os, json, time, threading, queue, sqlite3, re, hashlib, socket, subprocess, shutil, zipfile, io, platform, gc, sys
import requests
from dnsinspector.services import adguard as _adguard
from dnsinspector.db import *
from dnsinspector.services import devices as _devices
from dnsinspector.services import domains as _domains
from dnsinspector.services import observability as _observability

def _parse_ui_timestamp(value):
    if not value: return None
    try:
        text=str(value).strip(); text=text[:-1]+'+00:00' if text.endswith('Z') else text; dt=datetime.fromisoformat(text); return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
    except Exception: return None

def _is_new_domain(first_seen):
    dt=_parse_ui_timestamp(first_seen); return bool(dt and (datetime.now(timezone.utc)-dt).total_seconds()<86400)

def get_filter_options():
    with closing(db_connect(DB_PATH)) as c:
        vendors=[r[0] for r in c.execute("SELECT DISTINCT vendor FROM devices WHERE TRIM(vendor)<>'' ORDER BY vendor COLLATE NOCASE").fetchall()]
        devices=[{'value':k,'label':lbl} for k,lbl in c.execute("SELECT device_key,COALESCE(NULLIF(hostname,''),NULLIF(name,''),NULLIF(vendor,''),device_key) AS lbl FROM devices ORDER BY lbl COLLATE NOCASE").fetchall()]
    return {'classifications':['Known service','Telemetry / tracking','Advertising','Suspicious','Unknown'],'severities':['Info','Low','Medium','High','Unknown'],'vendors':vendors,'devices':devices}

def _recent_cached_json_map(c,table,domains=None):
    try:
        if domains:
            placeholders=','.join('?' for _ in domains); rows=c.execute(f'SELECT domain,json FROM {table} WHERE domain IN ({placeholders})',tuple(domains)).fetchall()
        else: rows=c.execute(f'SELECT domain,json FROM {table} LIMIT 5000').fetchall()
        out={}
        for domain,raw in rows:
            try: out[str(domain)]=json.loads(raw or '{}')
            except Exception: out[str(domain)]={}
        return out
    except Exception: return {}

def _recent_device_cache(c):
    rows=c.execute('SELECT device_key,name,hostname,mac,vendor,device_type,icon,confidence,source,request_count FROM devices').fetchall()
    return {r[0]:{'device_key':r[0],'identifier':r[0],'display_name':r[2] or r[1] or r[4] or r[0],'name':r[1],'hostname':r[2],'mac':r[3],'vendor':r[4],'vendor_logo':vendor_logo_url(r[4]),'type':r[5],'icon':r[6],'confidence_label':r[7],'source':r[8],'total_requests':int(r[9] or 0)} for r in rows}

def _recent_client_display(device_cache,device_key,count):
    base=device_cache.get(device_key)
    if base: out=dict(base); out['requests']=int(count or 0); return out
    return {'device_key':device_key,'identifier':device_key,'display_name':device_key,'name':'','hostname':'','mac':'','vendor':'','vendor_logo':'','type':'IoT / Unknown','icon':'📦','confidence_label':'low','source':'historical','requests':int(count or 0),'ips':[],'total_requests':int(count or 0)}

def _recent_cache_fresh(fetched_at,max_age_seconds):
    try:
        fetched=datetime.fromisoformat(str(fetched_at)); fetched=fetched.replace(tzinfo=timezone.utc) if fetched.tzinfo is None else fetched; return (datetime.now(timezone.utc)-fetched).total_seconds()<max_age_seconds
    except Exception: return False

def get_recent(page=1,page_size=50,status_filter='',new_only=False,classification_filter='',severity_filter='',device_filter='',vendor_filter=''):
    page=max(1,int(page or 1)); page_size=max(10,min(500,int(page_size or 50))); order_sql='first_seen DESC' if new_only else 'requests DESC'; scan_limit=max(500,min(3000,page*page_size+500))
    with db_connect(DB_PATH) as c:
        raw_rows=c.execute(f'SELECT domain,requests,clients_json,first_seen,blocked_requests,allowed_requests,unknown_requests,last_status,current_status,current_reason,classification FROM domains ORDER BY {order_sql} LIMIT ?', (scan_limit,)).fetchall(); page_domains=[r[0] for r in raw_rows]; device_cache=_recent_device_cache(c)
        try:
            placeholders=','.join('?' for _ in page_domains) or "''"; agh_rows=c.execute(f'SELECT domain,fetched_at,status,reason FROM adguard_status_cache WHERE domain IN ({placeholders})',tuple(page_domains)).fetchall(); agh_cache={r[0]:{'fetched_at':r[1],'status':r[2],'reason':r[3]} for r in agh_rows}
        except Exception: agh_cache={}
        netify_cache=_recent_cached_json_map(c,'netify_cache',page_domains); rdap_cache=_recent_cached_json_map(c,'rdap_cache',page_domains); prelim=[]; status_counts={'All':0,'Allowed':0,'Blocked':0,'Mixed':0,'Unknown':0}; stale_domains=[]
        for domain,requests_count,clients_json,first_seen,blocked_requests,allowed_requests,unknown_requests,last_status,current_status,current_reason,stored_classification in raw_rows:
            try: clients=_devices.canonicalize_client_map(json.loads(clients_json or '{}'))
            except Exception: clients={}
            devices=[]; row_vendors=set(); row_keys=set()
            for key,count in sorted(clients.items(),key=lambda kv:kv[1],reverse=True)[:6]:
                d=_recent_client_display(device_cache,key,count); dkey=d.get('device_key',key); row_keys.add(dkey); vendor=d.get('vendor','');
                if vendor: row_vendors.add(vendor)
                devices.append({'device_key':dkey,'identifier':d.get('identifier',key),'name':d.get('hostname') or d.get('name') or vendor or d.get('display_name') or key,'icon':d.get('icon','📦'),'type':d.get('type','IoT / Unknown'),'vendor_logo':d.get('vendor_logo',''),'vendor':vendor})
            agh=agh_cache.get(domain)
            if agh and _recent_cache_fresh(agh.get('fetched_at'),300): status=agh.get('status') or 'Unknown'; reason=agh.get('reason') or ''
            elif current_status and current_status!='Unknown': status=current_status; reason=current_reason or ''
            else:
                status,_=_domains.status_summary(int(blocked_requests or 0),int(allowed_requests or 0),int(unknown_requests or 0)); reason=current_reason or ''
                if agh: stale_domains.append(domain)
            status_counts[status if status in status_counts else 'Unknown']+=1
            if status_filter and status!=status_filter: continue
            is_new=_is_new_domain(first_seen)
            if new_only and not is_new: continue
            if device_filter and device_filter not in row_keys: continue
            if vendor_filter and vendor_filter not in row_vendors: continue
            prelim.append({'domain':domain,'requests':int(requests_count or 0),'clients':len(clients),'devices':devices,'stored_classification':stored_classification or 'Unknown','status':status,'status_class':str(status).lower(),'current_reason':reason,'first_seen':first_seen,'is_new':is_new,'netify':netify_cache.get(domain,{}),'rdap':rdap_cache.get(domain,{})})
        total_prelim=len(prelim); needs_intel_filter=bool(classification_filter or severity_filter); candidates=prelim if needs_intel_filter else prelim[max(0,(page-1)*page_size):min(total_prelim,max(0,(page-1)*page_size)+page_size)]; matched=[]
        for item in candidates:
            domain=item['domain']; tracker=tracker_lookup(domain) if trackerdb_ready() else {}; cls,badge,severity_class=_domains.classify(tracker,item.get('rdap') or {},item.get('netify') or {}); sev,sev_class=_domains.severity_for_classification(cls)
            if cls=='Unknown' and item.get('stored_classification') not in (None,'','Unknown'): cls=item['stored_classification']; badge='green' if cls=='Known service' else 'gray'; severity_class=badge; sev,sev_class=_domains.severity_for_classification(cls)
            if classification_filter and cls!=classification_filter: continue
            if severity_filter and sev!=severity_filter: continue
            if domain in stale_domains and len(matched)<page_size*2: _adguard._schedule_adguard_status(domain)
            matched.append({'domain':domain,'requests':item['requests'],'clients':item['clients'],'devices':item['devices'],'classification':cls,'badge_class':badge,'severity_class':severity_class,'severity':sev,'severity_text_class':sev_class,'status':item['status'],'status_class':item['status_class'],'last_status':item['status'],'current_reason':item['current_reason'],'first_seen':item['first_seen'],'is_new':item['is_new']})
        if needs_intel_filter:
            total=len(matched); pages=max(1,(total+page_size-1)//page_size); page=min(page,pages); page_rows=matched[(page-1)*page_size:(page-1)*page_size+page_size]
        else:
            total=total_prelim; pages=max(1,(total+page_size-1)//page_size); page=min(page,pages); page_rows=matched
    with db_connect(DB_PATH) as c:
        now_dt=datetime.now(timezone.utc); exact_new=int(c.execute('SELECT COUNT(*) FROM domains WHERE first_seen>=?',((now_dt-timedelta(hours=24)).isoformat(),)).fetchone()[0]); fresh_cutoff=(now_dt-timedelta(seconds=max(30,UI_REFRESH_SECONDS*2))).isoformat(); fresh_domains=[r[0] for r in c.execute('SELECT domain FROM domains WHERE first_seen>=? ORDER BY first_seen DESC LIMIT 10',(fresh_cutoff,)).fetchall()]
    return {'rows':page_rows,'meta':{'page':page,'pages':pages,'total':total,'page_size':page_size,'new_count':exact_new,'new_domains':fresh_domains,'status_counts':status_counts}}

def get_clients():
    with closing(db_connect(DB_PATH)) as c:
        rows=c.execute('SELECT device_key,name,hostname,mac,vendor,device_type,icon,confidence,source,request_count FROM devices ORDER BY request_count DESC').fetchall(); ips_by_device={}
        for dkey,ip,first_seen,last_seen,requests_count in c.execute('SELECT device_key,ip,first_seen,last_seen,requests FROM device_ips ORDER BY last_seen DESC').fetchall(): ips_by_device.setdefault(dkey,[]).append({'ip':ip,'first_seen':first_seen,'last_seen':last_seen,'requests':requests_count})
        return [{'identifier':dk,'name':name,'display_name':hostname or name or vendor or dk,'hostname':hostname,'mac':mac,'vendor':vendor,'vendor_logo':vendor_logo_url(vendor),'type':dtype,'icon':icon,'confidence_label':confidence,'source':source,'requests':count,'ips':ips_by_device.get(dk,[])} for dk,name,hostname,mac,vendor,dtype,icon,confidence,source,count in rows]

def get_stats(limit=10):
    with closing(db_connect(DB_PATH)) as c:
        top_domains=c.execute('SELECT domain,requests FROM domains ORDER BY requests DESC LIMIT ?',(limit,)).fetchall(); top_devices=c.execute("SELECT device_key,COALESCE(NULLIF(hostname,''),NULLIF(name,''),NULLIF(vendor,''),device_key),request_count FROM devices ORDER BY request_count DESC LIMIT ?",(limit,)).fetchall(); top_vendors=c.execute("SELECT vendor,SUM(request_count) AS total FROM devices WHERE TRIM(vendor)<>'' GROUP BY vendor ORDER BY total DESC LIMIT ?",(limit,)).fetchall(); top_ips=c.execute('SELECT ip,SUM(requests) AS total FROM device_ips GROUP BY ip ORDER BY total DESC LIMIT ?',(limit,)).fetchall()
    return {'domains':[{'label':d,'value':int(v),'href':'/search?q='+quote(d,safe='')} for d,v in top_domains],'devices':[{'label':label,'value':int(v),'href':'/device?key='+quote(key,safe='')} for key,label,v in top_devices],'vendors':[{'label':v,'value':int(total),'href':''} for v,total in top_vendors],'ips':[{'label':ip,'value':int(total),'href':'/ip?addr='+quote(ip,safe='')} for ip,total in top_ips]}

def state_payload(q='',status_filter='',new_only=False,classification_filter='',severity_filter='',device_filter='',vendor_filter='',page=1,page_size=50):
    result=_domains.inspect_domain(q) if q else None; recent=get_recent(page=page,page_size=page_size,status_filter=status_filter,new_only=new_only,classification_filter=classification_filter,severity_filter=severity_filter,device_filter=device_filter,vendor_filter=vendor_filter); uptime=_observability._observability_uptime_seconds()
    return {'updated':utcnow(),'recent':recent['rows'],'recent_meta':recent['meta'],'filter_options':get_filter_options(),'clients':get_clients(),'stats':get_stats(),'inspect_html':_ui.inspect_html(result) if result else None,'observability':{'uptime_seconds':round(uptime,1),'uptime_human':_observability._observability_uptime_human(uptime),'ram_mb':_observability._observability_rss_mb()}}
