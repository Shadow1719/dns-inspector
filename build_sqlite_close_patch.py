from pathlib import Path
import re

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

MARKER = '# === SQLITE CLOSE PATCH 0.7.13-HF2.3 ==='
if MARKER in text:
    print('DNS Inspector SQLite close patch already applied')
    raise SystemExit(0)

# sqlite3.Connection.__enter__ does not close the connection on __exit__.
# The app uses several `with sqlite3.connect(...) as c:` blocks, which can
# therefore leave one native SQLite file descriptor/connection behind per
# request. Convert those DB_PATH context managers to explicit closing().
if 'from contextlib import closing' not in text:
    lines = text.splitlines()
    insert_at = 0
    while insert_at < len(lines) and (lines[insert_at].startswith('from ') or lines[insert_at].startswith('import ') or not lines[insert_at].strip()):
        insert_at += 1
    lines.insert(insert_at, 'from contextlib import closing')
    text = '\n'.join(lines) + ('\n' if text.endswith('\n') else '')

replacements = [
    ('with sqlite3.connect(DB_PATH) as c:', 'with closing(sqlite3.connect(DB_PATH)) as c:'),
    ('with db_lock, sqlite3.connect(DB_PATH) as c:', 'with db_lock, closing(sqlite3.connect(DB_PATH)) as c:'),
]
counts = {}
for old, new in replacements:
    count = text.count(old)
    if count:
        text = text.replace(old, new)
    counts[old] = count

# Also catch single-line connection context managers using a different local
# variable, while leaving TrackerDB/temporary-database connections untouched.
pattern = re.compile(r'with sqlite3\.connect\(DB_PATH\) as (\w+):')
text, extra = pattern.subn(lambda m: f'with closing(sqlite3.connect(DB_PATH)) as {m.group(1)}:', text)
counts['generic_db_path'] = extra

if sum(counts.values()) == 0:
    raise SystemExit('SQLite close patch failed: no DB_PATH sqlite context manager found')

text = text.replace(
    'from contextlib import closing\n# === SQLITE CLOSE PATCH 0.7.13-HF2.3 ===',
    'from contextlib import closing\n' + MARKER,
    1,
)
if MARKER not in text:
    text = MARKER + '\n' + text

compile(text, str(APP), 'exec')
APP.write_text(text, encoding='utf-8')
print(f'DNS Inspector SQLite close patch 0.7.13-hotfix.2.3 applied: {counts}')
