from pathlib import Path

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

MARKER = '# === DEV 0.8 STABILITY PATCH V3 ==='
if MARKER in text:
    print('DEV 0.8 stability patch v3 already applied')
    raise SystemExit(0)

# Stability v1 installed a MutationObserver on #clients-body while decorateDevices()
# itself mutates that subtree (status cell/classes, ping controls). That creates a
# self-triggering observer -> DOM mutation -> observer cycle which can peg the
# browser renderer and make other tabs appear frozen. Do not observe our own DOM.
bad = "if(body)new MutationObserver(function(){decorateDevices();}).observe(body,{childList:true,subtree:true});"
if bad not in text:
    raise SystemExit('stability v3: MutationObserver loop marker not found')

replacement = "if(body){}"
text = text.replace(bad, replacement, 1)

# Re-apply device decoration periodically after /api/state replaces the dashboard
# body. Keep this bounded and timer-driven instead of DOM-observer-driven.
old = "setInterval(loadAnalytics,10000);"
if old not in text:
    raise SystemExit('stability v3: analytics interval marker not found')
text = text.replace(
    old,
    "setInterval(function(){loadAnalytics();loadPingStatuses();decorateDevices();},10000);",
    1,
)

text = MARKER + '\n' + text
compile(text, str(APP), 'exec')
APP.write_text(text, encoding='utf-8')
print('DEV 0.8 stability patch v3 applied')
