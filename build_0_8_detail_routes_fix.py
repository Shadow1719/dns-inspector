from pathlib import Path
import re

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

MARKER = '# === DEV 0.8 DETAIL ROUTES FILTER CONTEXT FIX ==='
if MARKER in text:
    print('DEV 0.8 detail routes fix already applied')
    raise SystemExit(0)

old = 'stats=get_stats(),error=None)'
new = 'stats=get_stats(),filter_options=get_filter_options(),error=None)'
count = text.count(old)
if count < 3:
    raise SystemExit(f'Detail routes fix: expected at least 3 template calls, found {count}')
text = text.replace(old, new)

text = MARKER + '\n' + text
compile(text, str(APP), 'exec')
APP.write_text(text, encoding='utf-8')
print(f'DEV 0.8 detail routes filter context fix applied to {count} template calls')
