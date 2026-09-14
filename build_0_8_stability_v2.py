from pathlib import Path
import re

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

MARKER = '# === DEV 0.8 STABILITY PATCH V2 ==='
if MARKER in text:
    print('DEV 0.8 stability patch v2 already applied')
    raise SystemExit(0)

# The previous stability patch replaced /device with a new /ip route but left
# the original /ip route below it. Flask rejects duplicate endpoint names at
# import time. Replace the entire detail-route section atomically so there is
# exactly one /device and one /ip view.
start = text.find('@app.route("/device")')
end = text.find('@app.route("/health")')
if start < 0 or end < 0 or end <= start:
    raise SystemExit('stability v2: detail route section not found')

routes = '''@app.route("/device")\ndef device_view():\n    key = request.args.get("key", "").strip()\n    d = device_detail(key)\n    empty_stats = {"domains": [], "devices": [], "vendors": [], "ips": []}\n    if not d:\n        body = "<div class='card'><h2>Device not found</h2><p class='error'>No device exists for this identity.</p><p><a href='/'>Back to dashboard</a></p></div>"\n        return render_template_string(HTML, q="", result=None, inspect_html=body, recent_html="", clients_html="", version=APP_VERSION, refresh_seconds=UI_REFRESH_SECONDS, refresh_seconds_ms=UI_REFRESH_SECONDS * 1000, updated=utcnow(), filter_options=get_filter_options(), stats=empty_stats, error=None), 404\n    return render_template_string(HTML, q="", result=None, inspect_html=detail_html_device(d), recent_html="", clients_html="", version=APP_VERSION, refresh_seconds=UI_REFRESH_SECONDS, refresh_seconds_ms=UI_REFRESH_SECONDS * 1000, updated=utcnow(), filter_options=get_filter_options(), stats=empty_stats, error=None)\n\n\n@app.route("/ip")\ndef ip_view():\n    addr = request.args.get("addr", "").strip()\n    d = ip_detail(addr)\n    empty_stats = {"domains": [], "devices": [], "vendors": [], "ips": []}\n    if not d:\n        body = "<div class='card'><h2>IP not found</h2><p class='error'>No valid IP observation exists for this address.</p><p><a href='/'>Back to dashboard</a></p></div>"\n        return render_template_string(HTML, q="", result=None, inspect_html=body, recent_html="", clients_html="", version=APP_VERSION, refresh_seconds=UI_REFRESH_SECONDS, refresh_seconds_ms=UI_REFRESH_SECONDS * 1000, updated=utcnow(), filter_options=get_filter_options(), stats=empty_stats, error=None), 404\n    return render_template_string(HTML, q="", result=None, inspect_html=detail_html_ip(d), recent_html="", clients_html="", version=APP_VERSION, refresh_seconds=UI_REFRESH_SECONDS, refresh_seconds_ms=UI_REFRESH_SECONDS * 1000, updated=utcnow(), filter_options=get_filter_options(), stats=empty_stats, error=None)\n\n\n'''
text = text[:start] + routes + text[end:]

# Add the correct filter option catalog to the main dashboard render as well.
text = text.replace(
    'updated=utcnow(),stats=get_stats(),error=None)',
    'updated=utcnow(),filter_options=get_filter_options(),stats=get_stats(),error=None)',
    1,
)

# Lightweight live observability route override. Keep it separate from the deep
# tracemalloc diagnostics used by debug bundles.
obs_marker = 'def _api_observability_live():'
if obs_marker not in text:
    obs_block = '''def _api_observability_live():\n    try:\n        payload_fn = globals().get('_original_observability_payload', globals().get('_observability_payload'))\n        payload = payload_fn() if callable(payload_fn) else {}\n        return jsonify(payload)\n    except Exception as e:\n        print('live observability error:', repr(e), flush=True)\n        return jsonify({\n            'version': APP_VERSION,\n            'uptime_seconds': max(0.0, time.monotonic() - OBSERVABILITY_START_MONOTONIC),\n            'ram_mb': None,\n        }), 200\n\ntry:\n    app.view_functions['api_observability'] = _api_observability_live\nexcept Exception:\n    pass\n\n'''
    marker = 'if __name__ == "__main__":\n'
    if marker not in text:
        raise SystemExit('stability v2: main marker not found')
    text = text.replace(marker, obs_block + marker, 1)

text = MARKER + '\n' + text
compile(text, str(APP), 'exec')
APP.write_text(text, encoding='utf-8')
print('DEV 0.8 stability patch v2 applied')
