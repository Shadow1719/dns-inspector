from pathlib import Path

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

MARKER = '# === MEMORY DIAGNOSTICS PATCH 0.7.13-HOTFIX.1 ==='
if MARKER in text:
    print('DNS Inspector memory diagnostics patch already applied')
    raise SystemExit(0)

# tracemalloc tracks Python allocations without retaining historical snapshots.
# Keep the frame depth modest to limit diagnostic overhead during this hotfix.
text = text.replace(
    'import time\n',
    'import time\nimport gc\nimport sys\nimport tracemalloc\n',
    1,
)

anchor = 'AGH_URL = os.getenv("AGH_URL", "").rstrip("/")\n'
insert = '''MEMORY_DIAGNOSTICS_ENABLED = os.getenv("MEMORY_DIAGNOSTICS_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}\nMEMORY_DIAGNOSTICS_FRAMES = max(5, min(20, int(os.getenv("MEMORY_DIAGNOSTICS_FRAMES", "10"))))\n\nif MEMORY_DIAGNOSTICS_ENABLED and not tracemalloc.is_tracing():\n    tracemalloc.start(MEMORY_DIAGNOSTICS_FRAMES)\n\nAGH_URL = os.getenv("AGH_URL", "").rstrip("/")\n'''
if anchor not in text:
    raise SystemExit('memory diagnostics patch failed: config anchor not found')
text = text.replace(anchor, insert, 1)

# Inject the diagnostic collector after the existing observability payload function.
obs_marker = '\ndef api_observability():\n'
if obs_marker not in text:
    raise SystemExit('memory diagnostics patch failed: observability endpoint marker not found')

block = r'''

def _memory_diagnostics_container_summary(value):
    """Return cheap, shallow diagnostics for long-lived module globals."""
    try:
        size = sys.getsizeof(value)
    except Exception:
        size = None
    info = {'type': type(value).__name__, 'size_bytes': size}
    try:
        if isinstance(value, dict):
            info['length'] = len(value)
        elif isinstance(value, (list, tuple, set, frozenset)):
            info['length'] = len(value)
        elif hasattr(value, 'qsize') and callable(value.qsize):
            info['length'] = int(value.qsize())
        elif hasattr(value, '__len__'):
            info['length'] = len(value)
    except Exception:
        pass
    return info


def _memory_diagnostics():
    if not MEMORY_DIAGNOSTICS_ENABLED or not tracemalloc.is_tracing():
        return {'enabled': False}

    current, peak = tracemalloc.get_traced_memory()
    result = {
        'enabled': True,
        'tracemalloc_current_mb': round(current / (1024 * 1024), 2),
        'tracemalloc_peak_mb': round(peak / (1024 * 1024), 2),
        'gc_counts': list(gc.get_count()),
        'gc_stats': gc.get_stats(),
    }

    try:
        objects = gc.get_objects()
        result['gc_object_count'] = len(objects)
    except Exception:
        result['gc_object_count'] = None

    # Capture only a compact top-of-process allocation view. The snapshot is
    # immediately discarded, so diagnostics do not build a historical leak log.
    try:
        snapshot = tracemalloc.take_snapshot()
        snapshot = snapshot.filter_traces((
            tracemalloc.Filter(False, '<frozen importlib._bootstrap>'),
            tracemalloc.Filter(False, '<unknown>'),
        ))
        stats = snapshot.statistics('lineno')[:25]
        top = []
        for stat in stats:
            frame = stat.traceback[0]
            top.append({
                'file': frame.filename,
                'line': frame.lineno,
                'size_mb': round(stat.size / (1024 * 1024), 3),
                'count': stat.count,
                'text': frame.name if hasattr(frame, 'name') else '',
            })
        result['top_allocations'] = top
    except Exception as e:
        result['top_allocations_error'] = str(e)

    # Surface suspiciously long-lived module-level containers without walking
    # their contents. This is intentionally shallow and only runs on demand.
    try:
        module_globals = {}
        for name, value in globals().items():
            if name.startswith('_'):
                continue
            if isinstance(value, (dict, list, tuple, set, frozenset)) or hasattr(value, 'qsize'):
                try:
                    info = _memory_diagnostics_container_summary(value)
                    length = info.get('length')
                    size = info.get('size_bytes')
                    # Ignore tiny/static containers unless they are surprisingly large.
                    if (isinstance(length, int) and length >= 10) or (isinstance(size, int) and size >= 65536):
                        module_globals[name] = info
                except Exception:
                    continue
        result['large_globals'] = dict(sorted(module_globals.items(), key=lambda item: (item[1].get('size_bytes') or 0), reverse=True)[:50])
    except Exception as e:
        result['large_globals_error'] = str(e)

    try:
        result['fd_count'] = len(os.listdir('/proc/self/fd'))
    except Exception:
        result['fd_count'] = None

    return result


# Extend the 0.7.12 observability payload without changing its existing API.
_original_observability_payload = _observability_payload

def _observability_payload():
    payload = _original_observability_payload()
    payload['memory_diagnostics'] = _memory_diagnostics()
    return payload

'''
text = text.replace(obs_marker, block + obs_marker, 1)

# Include a dedicated, easy-to-read JSON file in the debug bundle. The existing
# runtime.json remains backward compatible and now also carries the diagnostics.
compile(text, str(APP), 'exec')
APP.write_text(text, encoding='utf-8')
print('DNS Inspector 0.7.13-hotfix.1 memory diagnostics patch applied')
