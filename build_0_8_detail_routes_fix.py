from pathlib import Path

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

MARKER = '# === DEV 0.8 DETAIL ROUTES FILTER CONTEXT FIX ==='
if MARKER in text:
    print('DEV 0.8 detail routes fix already applied')
    raise SystemExit(0)

old = 'stats=get_stats(),error=None)'
new = 'stats=get_stats(),filter_options=get_filter_options(),error=None)'
count = text.count(old)
if count == 0:
    print('Detail routes fix: no matching template calls found; leaving source unchanged')
else:
    text = text.replace(old, new)

text = MARKER + '\n' + text
compile(text, str(APP), 'exec')
APP.write_text(text, encoding='utf-8')
print(f'DEV 0.8 detail routes filter context fix applied to {count} template calls')
