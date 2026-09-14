from pathlib import Path

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

MARKER = '# === DEV 0.8 PERFORMANCE PATCH V3 ==='
if MARKER in text:
    print('DEV 0.8 performance patch v3 already applied')
    raise SystemExit(0)

start_marker = 'def get_recent(page=1,page_size=50,status_filter="",new_only=False,classification_filter="",severity_filter="",device_filter="",vendor_filter=""):\n'
end_marker = '\ndef get_clients():\n'
start = text.find(start_marker)
end = text.find(end_marker, start + len(start_marker))
if start < 0 or end < 0:
    raise SystemExit('performance v3: get_recent boundaries not found')

replacement = r'''def _recent_cached_json_map(c, table):
    """Load a small enrichment cache once instead of opening SQLite per domain."""
    try:
        rows = c.execute(f"SELECT domain,json FROM {table}").fetchall()
        out = {}
        for domain, raw in rows:
            try:
                out[str(domain)] = json.loads(raw or "{}")
            except Exception:
                out[str(domain)] = {}
        return out
    except Exception:
        return {}


def _recent_device_cache(c):
    rows = c.execute(
        "SELECT device_key,name,hostname,mac,vendor,device_type,icon,confidence,source,request_count FROM devices"
    ).fetchall()
    return {
        row[0]: {
            "device_key": row[0],
            "identifier": row[0],
            "display_name": row[2] or row[1] or row[4] or row[0],
            "name": row[1],
            "hostname": row[2],
            "mac": row[3],
            "vendor": row[4],
            "vendor_logo": vendor_logo_url(row[4]),
            "type": row[5],
            "icon": row[6],
            "confidence_label": row[7],
            "source": row[8],
            "total_requests": int(row[9] or 0),
        }
        for row in rows
    }


def _recent_client_display(device_cache, device_key, count):
    base = device_cache.get(device_key)
    if base:
        out = dict(base)
        out["requests"] = int(count or 0)
        return out
    return {
        "device_key": device_key,
        "identifier": device_key,
        "display_name": device_key,
        "name": "",
        "hostname": "",
        "mac": "",
        "vendor": "",
        "vendor_logo": "",
        "type": "IoT / Unknown",
        "icon": "📦",
        "confidence_label": "low",
        "source": "historical",
        "requests": int(count or 0),
        "ips": [],
        "total_requests": int(count or 0),
    }


def _recent_cache_fresh(fetched_at, max_age_seconds):
    try:
        fetched = datetime.fromisoformat(str(fetched_at))
        if fetched.tzinfo is None:
            fetched = fetched.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - fetched).total_seconds() < max_age_seconds
    except Exception:
        return False


def get_recent(page=1,page_size=50,status_filter="",new_only=False,classification_filter="",severity_filter="",device_filter="",vendor_filter=""):
    """Build the dashboard list without doing network enrichment in the request path.

    The previous implementation called tracker/RDAP/Netify for every scanned domain,
    and Netify could perform live HTTP requests for uncached domains. With thousands of
    domains that made GET / and /api/state compete with ingestion and could freeze the UI.
    """
    page = max(1, int(page or 1))
    page_size = max(10, min(500, int(page_size or 50)))
    order_sql = "first_seen DESC" if new_only else "requests DESC"
    scan_limit = max(500, min(3000, page * page_size + 500))

    with sqlite3.connect(DB_PATH) as c:
        raw_rows = c.execute(
            f"SELECT domain,requests,clients_json,first_seen,blocked_requests,allowed_requests,unknown_requests,"
            f"last_status,current_status,current_reason,classification "
            f"FROM domains ORDER BY {order_sql} LIMIT ?",
            (scan_limit,),
        ).fetchall()

        device_cache = _recent_device_cache(c)

        try:
            agh_rows = c.execute(
                "SELECT domain,fetched_at,status,reason FROM adguard_status_cache"
            ).fetchall()
            agh_cache = {r[0]: {"fetched_at": r[1], "status": r[2], "reason": r[3]} for r in agh_rows}
        except Exception:
            agh_cache = {}

        # These are cache-only. They never trigger network traffic from the dashboard.
        netify_cache = _recent_cached_json_map(c, "netify_cache")
        rdap_cache = _recent_cached_json_map(c, "rdap_cache")

        prelim = []
        status_counts = {"All": 0, "Allowed": 0, "Blocked": 0, "Mixed": 0, "Unknown": 0}
        stale_domains = []

        for (domain, requests_count, clients_json, first_seen, blocked_requests,
             allowed_requests, unknown_requests, last_status, current_status,
             current_reason, stored_classification) in raw_rows:
            try:
                clients = canonicalize_client_map(json.loads(clients_json or "{}"))
            except Exception:
                clients = {}

            devices = []
            row_vendors = set()
            row_keys = set()
            for key, count in sorted(clients.items(), key=lambda kv: kv[1], reverse=True)[:6]:
                d = _recent_client_display(device_cache, key, count)
                dkey = d.get("device_key", key)
                row_keys.add(dkey)
                vendor = d.get("vendor", "")
                if vendor:
                    row_vendors.add(vendor)
                # IPs are intentionally omitted here; the dashboard only needs identity.
                devices.append({
                    "device_key": dkey,
                    "identifier": d.get("identifier", key),
                    "name": d.get("hostname") or d.get("name") or vendor or d.get("display_name") or key,
                    "icon": d.get("icon", "📦"),
                    "type": d.get("type", "IoT / Unknown"),
                    "vendor_logo": d.get("vendor_logo", ""),
                    "vendor": vendor,
                })

            agh = agh_cache.get(domain)
            if agh and _recent_cache_fresh(agh.get("fetched_at"), 300):
                status = agh.get("status") or "Unknown"
                reason = agh.get("reason") or ""
            elif current_status and current_status != "Unknown":
                status = current_status
                reason = current_reason or ""
            else:
                status, _ = status_summary(
                    int(blocked_requests or 0),
                    int(allowed_requests or 0),
                    int(unknown_requests or 0),
                )
                reason = current_reason or ""
                if agh:
                    stale_domains.append(domain)

            status_counts[status if status in status_counts else "Unknown"] += 1
            if status_filter and status != status_filter:
                continue

            is_new = _is_new_domain(first_seen)
            if new_only and not is_new:
                continue
            if device_filter and device_filter not in row_keys:
                continue
            if vendor_filter and vendor_filter not in row_vendors:
                continue

            prelim.append({
                "domain": domain,
                "requests": int(requests_count or 0),
                "clients": len(clients),
                "devices": devices,
                "stored_classification": stored_classification or "Unknown",
                "status": status,
                "status_class": str(status).lower(),
                "current_reason": reason,
                "first_seen": first_seen,
                "is_new": is_new,
                "netify": netify_cache.get(domain, {}),
                "rdap": rdap_cache.get(domain, {}),
            })

        total_prelim = len(prelim)

        # Keep the common dashboard path cheap: classify only the rows actually needed
        # for the requested page. Classification/severity filters still scan candidates,
        # but without any network requests.
        needs_intel_filter = bool(classification_filter or severity_filter)
        if needs_intel_filter:
            candidates = prelim
        else:
            start_i = max(0, (page - 1) * page_size)
            end_i = min(total_prelim, start_i + page_size)
            candidates = prelim[start_i:end_i]

        matched = []
        for item in candidates:
            domain = item["domain"]
            tracker = {}
            if needs_intel_filter or len(matched) < page_size:
                try:
                    tracker = tracker_lookup(domain)
                except Exception:
                    tracker = {}

            # Classify from TrackerDB plus cached RDAP/Netify only.
            cached_rdap = item.get("rdap") or {}
            cached_netify = item.get("netify") or {}
            cls, badge, _ = classify(tracker, cached_rdap, cached_netify)
            sev, sev_class = severity_for_classification(cls)

            # Preserve an already-persisted classification only when the live cached
            # evidence has no stronger signal. This avoids unexpectedly downgrading
            # domains while old rows are waiting for re-enrichment.
            if cls == "Unknown" and item.get("stored_classification") not in (None, "", "Unknown"):
                cls = item["stored_classification"]
                badge = "green" if cls == "Known service" else "gray"
                sev, sev_class = severity_for_classification(cls)

            if classification_filter and cls != classification_filter:
                continue
            if severity_filter and sev != severity_filter:
                continue

            if len(stale_domains) < page_size * 2 and domain in stale_domains:
                threading.Thread(
                    target=refresh_adguard_status,
                    args=(domain,),
                    daemon=True,
                    name=f"agh-status:{domain}",
                ).start()

            matched.append({
                "domain": domain,
                "requests": item["requests"],
                "clients": item["clients"],
                "devices": item["devices"],
                "classification": cls,
                "badge_class": badge,
                "severity_class": severity_for_classification(cls)[0],
                "severity": sev,
                "severity_text_class": sev_class,
                "status": item["status"],
                "status_class": item["status_class"],
                "last_status": item["status"],
                "current_reason": item["current_reason"],
                "first_seen": item["first_seen"],
                "is_new": item["is_new"],
            })

        if needs_intel_filter:
            total = len(matched)
            pages = max(1, (total + page_size - 1) // page_size)
            page = min(page, pages)
            start_i = (page - 1) * page_size
            page_rows = matched[start_i:start_i + page_size]
        else:
            total = total_prelim
            pages = max(1, (total + page_size - 1) // page_size)
            page = min(page, pages)
            # candidates already represent this page.
            page_rows = matched

    with sqlite3.connect(DB_PATH) as c:
        now_dt = datetime.now(timezone.utc)
        cutoff = (now_dt - timedelta(hours=24)).isoformat()
        exact_new = int(c.execute(
            "SELECT COUNT(*) FROM domains WHERE first_seen>=?", (cutoff,)
        ).fetchone()[0])
        fresh_cutoff = (now_dt - timedelta(seconds=max(30, UI_REFRESH_SECONDS * 2))).isoformat()
        fresh_domains = [r[0] for r in c.execute(
            "SELECT domain FROM domains WHERE first_seen>=? ORDER BY first_seen DESC LIMIT 10", (fresh_cutoff,)
        ).fetchall()]

    return {
        "rows": page_rows,
        "meta": {
            "page": page,
            "pages": pages,
            "total": total,
            "page_size": page_size,
            "new_count": exact_new,
            "new_domains": fresh_domains,
            "status_counts": status_counts,
        },
    }
'''

text = text[:start] + replacement + text[end:]

# Add a slow-request diagnostic without changing request behavior.
marker = 'if __name__ == "__main__":\n'
perf_block = '''_UI_REQUEST_START_KEY = "_dns_inspector_request_started"\n\n@app.before_request\ndef _ui_request_timer_start():\n    request.environ[_UI_REQUEST_START_KEY] = time.perf_counter()\n\n@app.after_request\ndef _ui_request_timer_end(response):\n    started = request.environ.get(_UI_REQUEST_START_KEY)\n    if started is not None:\n        elapsed = time.perf_counter() - started\n        if elapsed >= 3.0:\n            print(f"Slow HTTP {request.method} {request.path}: {elapsed:.2f}s status={response.status_code}", flush=True)\n    return response\n\n'''
if '_UI_REQUEST_START_KEY' not in text:
    if marker not in text:
        raise SystemExit('performance v3: main marker not found')
    text = text.replace(marker, perf_block + marker, 1)

text = MARKER + '\n' + text
compile(text, str(APP), 'exec')
APP.write_text(text, encoding='utf-8')
print('DEV 0.8 performance patch v3 applied')
