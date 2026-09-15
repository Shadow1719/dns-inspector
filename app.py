import os
import threading
from flask import jsonify, request, send_file
import dnsinspector.legacy_app as legacy
from dnsinspector.core import runtime as core
from dnsinspector.db import core as db
from dnsinspector.services import analytics, devices, domains, ingest
from dnsinspector.services import ui as ui_service

# Centralize the legacy application's SQLite access on the new DB layer.
legacy.db_lock = core.db_lock
legacy.db_connect = db.db_connect
legacy.init_db = db.init_db
legacy.APP_VERSION = core.APP_VERSION
legacy.DB_PATH = core.DB_PATH
legacy.utcnow = core.utcnow

# Replace high-traffic backend operations with the new modules while keeping
# legacy Flask routes/templates as the compatibility shell for this migration.
for name, fn in {
    'get_recent': analytics.get_recent,
    'get_clients': analytics.get_clients,
    'get_filter_options': analytics.get_filter_options,
    'get_stats': analytics.get_stats,
    'state_payload': analytics.state_payload,
    'inspect_domain': domains.inspect_domain,
    'device_detail': devices.device_detail,
    'ip_detail': devices.ip_detail,
    'worker': ingest.worker,
}.items():
    setattr(legacy, name, fn)

# Development-only UI marker and development favicon are kept deliberately on
# the dev branch; the production build uses its normal favicon.
@legacy.app.after_request
def _dev_ui(response):
    if response.content_type and response.content_type.startswith('text/html'):
        try:
            body = response.get_data(as_text=True)
            if 'DEVELOPMENT BUILD · DNS Inspector' not in body:
                marker = '<div class="dev-build-banner" style="position:fixed;left:0;right:0;top:0;z-index:99999;padding:6px 12px;background:#7f1d1d;color:#fff;font:700 12px/1.2 system-ui;text-align:center;letter-spacing:.04em">DEVELOPMENT BUILD · DNS Inspector 0.8 · NOT PRODUCTION</div>'
                body = body.replace('<body', marker + '<body', 1)
                body = body.replace('/static/favicon.svg', '/static/favicon-dev.svg')
                response.set_data(body)
        except Exception:
            pass
    return response

@legacy.app.get('/api/ip/ping/status')
def _dev_ping_status():
    return devices.api_ip_ping_status()

@legacy.app.post('/api/ip/ping')
def _dev_ping():
    return devices.api_ip_ping()

app = legacy.app

_started = False
if os.getenv('DISABLE_BACKGROUND_SERVICES', '').strip().lower() not in {'1','true','yes','on'}:
    with core._background_start_lock:
        if not core._background_started:
            db.init_db()
            threading.Thread(target=ingest.worker, daemon=True, name='dns-inspector-worker').start()
            core._background_started = True

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', '8080')))
