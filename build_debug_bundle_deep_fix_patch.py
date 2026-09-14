from pathlib import Path
import re

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

MARKER = '# === DEEP DEBUG BUNDLE FIX PATCH 0.7.13-HF2.2 ==='
if MARKER in text:
    print('DNS Inspector deep debug collector fix already applied')
    raise SystemExit(0)

# The HF2 helpers use Path inside the generated app. The build script's own
# import does not inject that symbol into app.py, so add it explicitly.
if 'from pathlib import Path' not in text:
    lines = text.splitlines()
    insert_at = 0
    while insert_at < len(lines) and (lines[insert_at].startswith('from ') or lines[insert_at].startswith('import ') or not lines[insert_at].strip()):
        insert_at += 1
    lines.insert(insert_at, 'from pathlib import Path')
    text = '\n'.join(lines) + ('\n' if text.endswith('\n') else '')

# Replace the fragile GC object-type collector with a defensive implementation.
pattern = re.compile(
    r"def _deep_debug_python_objects\(\):\n.*?\n\ndef _deep_debug_tracemalloc\(\):",
    re.DOTALL,
)
match = pattern.search(text)
if not match:
    raise SystemExit('deep debug fix failed: python object collector anchor not found')

replacement = '''def _deep_debug_python_objects():\n    try:\n        import gc\n        from collections import Counter\n\n        counts = Counter()\n        object_count = 0\n        for obj in gc.get_objects():\n            object_count += 1\n            try:\n                typ = type(obj)\n                module = getattr(typ, '__module__', None) or '<unknown>'\n                qualname = getattr(typ, '__qualname__', None) or getattr(typ, '__name__', None) or repr(typ)\n                counts[f'{module}.{qualname}'] += 1\n            except Exception:\n                counts['<unclassifiable>'] += 1\n\n        top = [\n            {'type': name, 'count': count}\n            for name, count in counts.most_common(50)\n        ]\n        return {'gc_object_count': object_count, 'top_types': top}\n    except Exception as e:\n        return {'error': f'{type(e).__name__}: {e}'}\n\n\ndef _deep_debug_tracemalloc():'''
text = text[:match.start()] + replacement + text[match.end():]

# Keep the generated bundle metadata aligned with the actual hotfix.
text = text.replace('Patch: 0.7.13-hotfix.2\\n', 'Patch: 0.7.13-hotfix.2.2\\n')
text = text.replace("Patch: 0.7.13-hotfix.2\\n'", "Patch: 0.7.13-hotfix.2.2\\n'")

# Add a tiny marker so this patch is idempotent if the build is repeated.
anchor = '# === DEEP DEBUG BUNDLE PATCH 0.7.13-HF2 ==='
if anchor in text:
    text = text.replace(anchor, anchor + '\n' + MARKER, 1)
else:
    text = MARKER + '\n' + text

compile(text, str(APP), 'exec')
APP.write_text(text, encoding='utf-8')
print('DNS Inspector deep debug collector fix patch 0.7.13-hotfix.2.2 applied')
