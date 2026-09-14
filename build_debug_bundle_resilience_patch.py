from pathlib import Path

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

MARKER = '# === DEBUG BUNDLE RESILIENCE PATCH 0.7.13-HF2.1 ==='
if MARKER in text:
    print('DNS Inspector debug bundle resilience patch already applied')
    raise SystemExit(0)

anchor = "def _deep_debug_memory_snapshot():\n"
if anchor not in text:
    raise SystemExit('resilience patch failed: deep debug snapshot helper not found')

insert = r'''# === DEBUG BUNDLE RESILIENCE PATCH 0.7.13-HF2.1 ===

def _deep_debug_safe_call(name, fn):
    try:
        return {'ok': True, 'data': fn()}
    except BaseException as e:
        import traceback
        return {
            'ok': False,
            'error': f'{type(e).__name__}: {e}',
            'traceback': traceback.format_exc(),
        }


def _deep_debug_memory_snapshot_safe():
    collectors = [
        ('proc_status', _deep_debug_proc_status),
        ('smaps_rollup', _deep_debug_smaps_rollup),
        ('top_memory_mappings', _deep_debug_top_mappings),
        ('cgroup_memory', _deep_debug_cgroup_memory),
        ('glibc_mallinfo2', _deep_debug_mallinfo2),
        ('threads', _deep_debug_threads),
        ('file_descriptors', _deep_debug_fds),
        ('sqlite', _deep_debug_sqlite),
        ('http_pools', _deep_debug_http_pools),
        ('python_object_types', _deep_debug_python_objects),
        ('tracemalloc', _deep_debug_tracemalloc),
        ('resource_limits', _deep_debug_limits),
    ]
    return {name: _deep_debug_safe_call(name, fn) for name, fn in collectors}


'''
text = text.replace(anchor, insert + anchor, 1)

# Use the resilient collector from the existing deep bundle route.
text = text.replace(
    "deep_memory = _deep_debug_memory_snapshot()",
    "deep_memory = _deep_debug_memory_snapshot_safe()",
    1,
)

# Add a small explicit version marker in the bundle manifest without changing
# any application runtime behavior.
text = text.replace(
    "Patch: 0.7.13-hotfix.2\\n",
    "Patch: 0.7.13-hotfix.2.1\\n",
    1,
)

compile(text, str(APP), 'exec')
APP.write_text(text, encoding='utf-8')
print('DNS Inspector debug bundle resilience patch 0.7.13-hotfix.2.1 applied')
