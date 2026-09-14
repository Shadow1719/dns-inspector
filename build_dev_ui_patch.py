from pathlib import Path

APP = Path("/app/app.py")
text = APP.read_text(encoding="utf-8")

old_head = '<link rel="icon" type="image/svg+xml" href="/static/favicon.svg"><title>DNS Inspector</title>'
new_head = '<link rel="icon" type="image/svg+xml" href="/static/favicon-dev.svg"><title>DNS Inspector DEV</title>'
if old_head not in text:
    raise SystemExit("DEV UI patch: expected page head marker not found")
text = text.replace(old_head, new_head, 1)

old_style = ':root{color-scheme:dark}\n'
new_style = ':root{color-scheme:dark}\n.dev-build-banner{position:sticky;top:0;z-index:1000;margin:0 0 12px;padding:9px 14px;border:2px solid #f0883e;border-radius:10px;background:#3b1f0f;color:#ffb86b;font-weight:900;letter-spacing:.06em;text-align:center;text-transform:uppercase;box-shadow:0 6px 20px rgba(0,0,0,.25)}\n'
if old_style not in text:
    raise SystemExit("DEV UI patch: expected root style marker not found")
text = text.replace(old_style, new_style, 1)

if '<body>' not in text:
    raise SystemExit("DEV UI patch: expected body marker not found")
text = text.replace('<body>', '<body><div class="dev-build-banner">DEVELOPMENT BUILD &middot; DNS Inspector 0.8 &middot; NOT PRODUCTION</div>', 1)

APP.write_text(text, encoding="utf-8")
print("DEV UI patch applied")
