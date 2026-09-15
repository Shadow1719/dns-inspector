from dnsinspector.core.runtime import *
from contextlib import closing
from datetime import datetime, timezone, timedelta
import os, json, time, threading, queue, sqlite3, re, hashlib, socket, subprocess, shutil, zipfile, io, platform, gc, sys
import requests
from dnsinspector.db import *
from dnsinspector.services import devices as _devices
from dnsinspector.services import enrichment as _enrichment


def status_summary(blocked, allowed, unknown):
    if blocked and allowed:
        return ('Mixed', 'mixed')
    if blocked:
        return ('Blocked', 'blocked')
    if allowed:
        return ('Allowed', 'allowed')
    return ('Unknown', 'unknown')

def severity_for_classification(classification):
    mapping = {'Known service': ('Info', 'info'), 'Known ownership': ('Info', 'info'), 'Telemetry / tracking': ('Low', 'low'), 'Advertising': ('Medium', 'medium'), 'Suspicious': ('High', 'high')}
    return mapping.get(classification, ('Unknown', 'unknown'))

def classify(tracker, rdap, netify=None):
    netify = netify or {}
    cat = (tracker.get('category') or '').lower()
    app_name = (netify.get('application') or '').strip()
    company = (netify.get('company_name') or '').strip()
    if cat == 'advertising': return ('Advertising', 'orange', 'orange')
    if cat in {'site_analytics', 'social_media', 'extensions'}: return ('Telemetry / tracking', 'yellow', 'yellow')
    if cat: return ('Known service', 'green', 'green')
    if app_name or company: return ('Known service', 'green', 'green')
    if rdap.get('org'): return ('Known ownership', 'blue', 'blue')
    return ('Unknown', 'gray', 'gray')

def build_explanation(domain, tracker, rdap, client_details, netify=None):
    cat = (tracker.get('category') or '').lower()
    vendors = sorted({c.get('vendor', '') for c in client_details if c.get('vendor')})
    hostnames = sorted({c.get('hostname', '') for c in client_details if c.get('hostname')})
    evidence = []
    if client_details: evidence.append(f'{len(client_details)} local device(s) contacted this domain')
    if vendors: evidence.append('Vendor signals: ' + ', '.join(vendors[:3]))
    if hostnames: evidence.append('Known hostnames: ' + ', '.join(hostnames[:3]))
    if tracker.get('matched_domain'): evidence.append(f"TrackerDB match: {tracker.get('matched_domain')}")
    if rdap.get('org'): evidence.append(f"RDAP ownership: {rdap.get('org')}")
    if netify and netify.get('application'): evidence.append(f"Netify application: {netify.get('application')}")
    if netify and netify.get('company_name'): evidence.append(f"Netify company: {netify.get('company_name')}")
    if cat == 'advertising': summary, tone, confidence = ('Likely advertising / ad delivery.', 'orange', 'High')
    elif cat in {'site_analytics', 'social_media', 'extensions'}: summary, tone, confidence = ('Likely telemetry or tracking.', 'yellow', 'High')
    elif cat: summary, tone, confidence = ('Known third-party service.', 'green', 'Medium')
    elif netify and (netify.get('application') or netify.get('company_name')): summary, tone, confidence = ('Known service identified by Netify.', 'green', 'Medium')
    elif rdap.get('org'): summary, tone, confidence = ('Known infrastructure with ownership data.', 'blue', 'Medium')
    else: summary, tone, confidence = ('Purpose is not established from available signals.', 'gray', 'Low')
    return {'summary': summary, 'tone': tone, 'confidence': confidence, 'evidence': evidence or ['No strong identifying signals are available yet']}

def inspect_domain(domain):
    domain = domain.lower().rstrip('.')
    with closing(db_connect(DB_PATH)) as c:
        row = c.execute('SELECT domain,first_seen,last_seen,requests,clients_json,blocked_requests,allowed_requests,unknown_requests,last_status,last_reason,current_status,current_reason FROM domains WHERE domain=?', (domain,)).fetchone()
        if not row: return None
        blocked_requests, allowed_requests, unknown_requests, last_status, last_reason, current_status, current_reason = (row[5], row[6], row[7], row[8], row[9], row[10], row[11])
        tracker = tracker_lookup(domain)
        rdap = _enrichment.rdap_lookup(domain)
        netify = _enrichment.netify_lookup(domain)
        dns_records = _enrichment.dns_records_lookup(domain)
        classification, badge, severity = classify(tracker, rdap, netify)
        clients_map = _devices.canonicalize_client_map(json.loads(row[4] or '{}'))
        client_details = [_devices.client_display(c, key, count) for key, count in sorted(clients_map.items(), key=lambda kv: kv[1], reverse=True)]
    needs_refresh = _enrichment._cache_needs_refresh('netify_cache', domain, NETIFY_CACHE_HOURS) or _enrichment._cache_needs_refresh('rdap_cache', _enrichment.apex_domain(domain), RDAP_CACHE_HOURS) or _enrichment._cache_needs_refresh('dns_records_cache', domain, DNS_RECORDS_CACHE_HOURS)
    if needs_refresh: _enrichment._queue_domain_enrichment(domain)
    dns = _enrichment.resolve_dns(domain, dns_records)
    status = current_status if current_status and current_status != 'Unknown' else status_summary(int(blocked_requests or 0), int(allowed_requests or 0), int(unknown_requests or 0))[0]
    return {'domain': row[0], 'first_seen': row[1], 'last_seen': row[2], 'requests': row[3], 'clients': clients_map, 'classification': classification, 'badge_class': badge, 'severity_class': severity, 'tracker': tracker, 'status': status, 'status_class': status.lower(), 'severity': severity_for_classification(classification)[0], 'severity_text_class': severity_for_classification(classification)[1], 'status_counts': {'blocked': int(blocked_requests or 0), 'allowed': int(allowed_requests or 0), 'unknown': int(unknown_requests or 0)}, 'last_status': last_status, 'last_reason': last_reason, 'current_status': current_status, 'current_reason': current_reason, 'company': {'name': tracker.get('company_name') or rdap.get('org') or netify.get('company_name') or netify.get('application') or '', 'description': tracker.get('description', '') or netify.get('description', ''), 'website_url': tracker.get('company_website', '') or tracker.get('website_url', '') or netify.get('website_url', ''), 'country': tracker.get('country', '') or rdap.get('country', '') or netify.get('country', '')}, 'rdap': rdap, 'netify': netify, 'dns': dns, 'dns_records': dns_records, 'client_details': client_details, 'explanation': build_explanation(domain, tracker, rdap, client_details, netify)}
