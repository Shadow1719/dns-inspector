from pathlib import Path
import re

APP = Path('/app/app.py')
text = APP.read_text(encoding='utf-8')

MARKER = '# === DEEP DEBUG BUNDLE PATCH 0.7.13-HF2 ==='
if MARKER in text:
    print('DNS Inspector deep debug bundle patch already applied')
    raise SystemExit(0)

# Only add helpers consumed by /debug/bundle. Do not alter ingest, enrichment,
# polling, caches, worker scheduling, or ordinary runtime behavior.
helper_marker = 'def _observability_uptime_seconds():'
if helper_marker not in text:
    raise SystemExit('deep debug patch failed: observability helper anchor not found')

helpers = r'''# === DEEP DEBUG BUNDLE PATCH 0.7.13-HF2 ===

def _deep_debug_read_text(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            return f.read()
    except Exception as e:
        return f'ERROR: {type(e).__name__}: {e}'


def _deep_debug_parse_kb_lines(text):
    out = {}
    for line in text.splitlines():
        if ':' not in line:
            continue
        key, rest = line.split(':', 1)
        parts = rest.strip().split()
        if not parts:
            continue
        value = parts[0]
        try:
            out[key] = int(value) * (1024 if len(parts) > 1 and parts[1].lower() == 'kb' else 1)
        except ValueError:
            out[key] = rest.strip()
    return out


def _deep_debug_proc_status():
    raw = _deep_debug_read_text('/proc/self/status')
    wanted = {
        'VmSize', 'VmPeak', 'VmRSS', 'VmHWM', 'RssAnon', 'RssFile', 'RssShmem',
        'VmData', 'VmStk', 'VmExe', 'VmLib', 'VmSwap', 'HugetlbPages'
    }
    parsed = _deep_debug_parse_kb_lines(raw)
    return {k: parsed.get(k) for k in sorted(wanted)}


def _deep_debug_smaps_rollup():
    path = '/proc/self/smaps_rollup'
    if not Path(path).exists():
        return {'available': False}
    parsed = _deep_debug_parse_kb_lines(_deep_debug_read_text(path))
    wanted = [
        'Rss', 'Pss', 'Pss_Anon', 'Pss_File', 'Pss_Shmem',
        'Private_Clean', 'Private_Dirty', 'Shared_Clean', 'Shared_Dirty',
        'Anonymous', 'AnonHugePages', 'Swap', 'SwapPss'
    ]
    return {'available': True, **{k: parsed.get(k) for k in wanted}}


def _deep_debug_top_mappings(limit=25):
    path = '/proc/self/smaps'
    if not Path(path).exists():
        return {'available': False, 'mappings': []}
    header_re = re.compile(r'^([0-9a-f]+-[0-9a-f]+)\s+\S+\s+\S+\s+\S+\s+\S+(?:\s+(.*))?$')
    rows = []
    current = None
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                m = header_re.match(line.rstrip('\n'))
                if m:
                    if current:
                        rows.append(current)
                    current = {
                        'address': m.group(1),
                        'path': (m.group(2) or '').strip() or '[anonymous]',
                        'rss': 0,
                        'pss': 0,
                        'private_dirty': 0,
                        'anonymous': 0,
                    }
                    continue
                if current is None or ':' not in line:
                    continue
                key, rest = line.split(':', 1)
                value = rest.strip().split()
                if not value:
                    continue
                try:
                    kb = int(value[0]) * 1024
                except ValueError:
                    continue
                if key == 'Rss':
                    current['rss'] = kb
                elif key == 'Pss':
                    current['pss'] = kb
                elif key == 'Private_Dirty':
                    current['private_dirty'] = kb
                elif key == 'Anonymous':
                    current['anonymous'] = kb
            if current:
                rows.append(current)
    except Exception as e:
        return {'available': True, 'error': f'{type(e).__name__}: {e}', 'mappings': []}
    rows.sort(key=lambda x: x['rss'], reverse=True)
    return {'available': True, 'mappings': rows[:max(1, int(limit))]}


def _deep_debug_cgroup_memory():
    candidates = [
        '/sys/fs/cgroup/memory.current',
        '/sys/fs/cgroup/memory.max',
    ]
    values = {}
    for path in candidates:
        if Path(path).exists():
            raw = _deep_debug_read_text(path).strip()
            key = Path(path).name
            try:
                values[key] = int(raw) if raw != 'max' else raw
            except ValueError:
                values[key] = raw
    for name in ('memory.stat', 'memory.events'):
        path = f'/sys/fs/cgroup/{name}'
        if Path(path).exists():
            parsed = {}
            for line in _deep_debug_read_text(path).splitlines():
                parts = line.split()
                if len(parts) == 2:
                    try:
                        parsed[parts[0]] = int(parts[1])
                    except ValueError:
                        parsed[parts[0]] = parts[1]
            values[name] = parsed
    return values


def _deep_debug_mallinfo2():
    try:
        import ctypes
        import ctypes.util
        libc_path = ctypes.util.find_library('c') or 'libc.so.6'
        libc = ctypes.CDLL(libc_path)
        if not hasattr(libc, 'mallinfo2'):
            return {'available': False, 'reason': 'mallinfo2 not exported by libc'}

        class MallInfo2(ctypes.Structure):
            _fields_ = [
                ('arena', ctypes.c_size_t),
                ('ordblks', ctypes.c_size_t),
                ('smblks', ctypes.c_size_t),
                ('hblks', ctypes.c_size_t),
                ('hblkhd', ctypes.c_size_t),
                ('usmblks', ctypes.c_size_t),
                ('fsmblks', ctypes.c_size_t),
                ('uordblks', ctypes.c_size_t),
                ('fordblks', ctypes.c_size_t),
                ('keepcost', ctypes.c_size_t),
            ]

        libc.mallinfo2.restype = MallInfo2
        info = libc.mallinfo2()
        return {'available': True, **{name: int(getattr(info, name)) for name, _ in MallInfo2._fields_}}
    except Exception as e:
        return {'available': False, 'error': f'{type(e).__name__}: {e}'}


def _deep_debug_threads():
    root = Path('/proc/self/task')
    rows = []
    try:
        for child in root.iterdir():
            tid = child.name
            comm_path = child / 'comm'
            stat_path = child / 'status'
            comm = _deep_debug_read_text(comm_path).strip()
            status = _deep_debug_read_text(stat_path)
            state = None
            voluntary = None
            nonvoluntary = None
            for line in status.splitlines():
                if line.startswith('State:'):
                    state = line.split(':', 1)[1].strip()
                elif line.startswith('voluntary_ctxt_switches:'):
                    voluntary = line.split(':', 1)[1].strip()
                elif line.startswith('nonvoluntary_ctxt_switches:'):
                    nonvoluntary = line.split(':', 1)[1].strip()
            rows.append({
                'tid': tid,
                'name': comm,
                'state': state,
                'voluntary_ctxt_switches': voluntary,
                'nonvoluntary_ctxt_switches': nonvoluntary,
            })
    except Exception as e:
        return {'error': f'{type(e).__name__}: {e}', 'threads': []}
    rows.sort(key=lambda x: int(x['tid']) if x['tid'].isdigit() else 0)
    return {'count': len(rows), 'threads': rows}


def _deep_debug_fds():
    root = Path('/proc/self/fd')
    rows = []
    counts = {}
    try:
        for child in sorted(root.iterdir(), key=lambda p: p.name):
            try:
                target = os.readlink(child)
            except Exception as e:
                target = f'<unreadable: {type(e).__name__}>'
            if target.startswith('socket:['):
                kind = 'socket'
            elif target.startswith('pipe:['):
                kind = 'pipe'
            elif target.startswith('anon_inode:'):
                kind = 'anon_inode'
            elif target.startswith('/'):
                kind = 'file'
            else:
                kind = 'other'
            counts[kind] = counts.get(kind, 0) + 1
            rows.append({'fd': child.name, 'kind': kind, 'target': target})
    except Exception as e:
        return {'error': f'{type(e).__name__}: {e}', 'counts': counts, 'entries': rows}
    return {'count': len(rows), 'counts': counts, 'entries': rows[:200]}


def _deep_debug_sqlite():
    result = {}
    try:
        with db_lock, sqlite3.connect(DB_PATH) as c:
            for pragma in (
                'journal_mode', 'journal_size_limit', 'page_count', 'page_size',
                'freelist_count', 'cache_size', 'cache_spill', 'temp_store',
                'mmap_size', 'synchronous', 'locking_mode'
            ):
                try:
                    row = c.execute(f'PRAGMA {pragma}').fetchone()
                    result[pragma] = row[0] if row else None
                except Exception as e:
                    result[pragma] = f'{type(e).__name__}: {e}'
    except Exception as e:
        result['error'] = f'{type(e).__name__}: {e}'
    return result


def _deep_debug_http_pools():
    out = []
    try:
        adapters = getattr(session, 'adapters', {})
        for prefix, adapter in adapters.items():
            row = {'prefix': prefix, 'adapter_type': type(adapter).__name__}
            poolmanager = getattr(adapter, 'poolmanager', None)
            if poolmanager is not None:
                row['poolmanager_type'] = type(poolmanager).__name__
                pools = getattr(poolmanager, 'pools', None)
                try:
                    row['pool_count'] = len(pools) if pools is not None else None
                except Exception:
                    row['pool_count'] = None
                row['num_pools'] = getattr(poolmanager, 'num_pools', None)
                row['maxsize'] = getattr(poolmanager, 'connection_pool_kw', {}).get('maxsize') if hasattr(poolmanager, 'connection_pool_kw') else None
            out.append(row)
    except Exception as e:
        return {'error': f'{type(e).__name__}: {e}', 'adapters': []}
    return {'adapters': out}


def _deep_debug_python_objects():
    try:
        import gc
        from collections import Counter
        objects = gc.get_objects()
        counts = Counter(type(obj).__module__ + '.' + type(obj).__qualname__ for obj in objects)
        top = [{'type': name, 'count': count} for name, count in counts.most_common(50)]
        return {'gc_object_count': len(objects), 'top_types': top}
    except Exception as e:
        return {'error': f'{type(e).__name__}: {e}'}


def _deep_debug_tracemalloc():
    try:
        import tracemalloc
        if not tracemalloc.is_tracing():
            return {'available': False, 'reason': 'tracemalloc not active'}
        current, peak = tracemalloc.get_traced_memory()
        snap = tracemalloc.take_snapshot()
        stats = snap.statistics('traceback')[:40]
        top = []
        for stat in stats:
            top.append({
                'size_bytes': stat.size,
                'count': stat.count,
                'traceback': [str(frame) for frame in stat.traceback.format()],
            })
        return {'available': True, 'current_bytes': current, 'peak_bytes': peak, 'top_tracebacks': top}
    except Exception as e:
        return {'available': False, 'error': f'{type(e).__name__}: {e}'}


def _deep_debug_limits():
    try:
        import resource
        names = {
            'RLIMIT_AS': getattr(resource, 'RLIMIT_AS', None),
            'RLIMIT_DATA': getattr(resource, 'RLIMIT_DATA', None),
            'RLIMIT_STACK': getattr(resource, 'RLIMIT_STACK', None),
        }
        out = {}
        for name, ident in names.items():
            if ident is None:
                continue
            soft, hard = resource.getrlimit(ident)
            out[name] = {'soft': soft, 'hard': hard}
        return out
    except Exception as e:
        return {'error': f'{type(e).__name__}: {e}'}


def _deep_debug_memory_snapshot():
    return {
        'proc_status_bytes': _deep_debug_proc_status(),
        'smaps_rollup_bytes': _deep_debug_smaps_rollup(),
        'top_memory_mappings': _deep_debug_top_mappings(),
        'cgroup_memory': _deep_debug_cgroup_memory(),
        'glibc_mallinfo2': _deep_debug_mallinfo2(),
        'threads': _deep_debug_threads(),
        'file_descriptors': _deep_debug_fds(),
        'sqlite': _deep_debug_sqlite(),
        'http_pools': _deep_debug_http_pools(),
        'python_object_types': _deep_debug_python_objects(),
        'tracemalloc': _deep_debug_tracemalloc(),
        'resource_limits': _deep_debug_limits(),
    }


'''
text = text.replace(helper_marker, helpers + '\n' + helper_marker, 1)

# Replace only the body of the existing debug bundle route so the additional
# data is generated on-demand when the user clicks Generate Debug Bundle.
start = text.find("@app.route('/debug/bundle')")
if start < 0:
    raise SystemExit('deep debug patch failed: debug bundle route not found')
end = text.find('\n\nif __name__ == "__main__":', start)
if end < 0:
    raise SystemExit('deep debug patch failed: main marker not found after debug bundle')

new_route = r'''@app.route('/debug/bundle')
def debug_bundle():
    try:
        runtime = _observability_payload()
        deep_memory = _deep_debug_memory_snapshot()
        bundle = io.BytesIO()
        with zipfile.ZipFile(bundle, 'w', compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr(
                'manifest.txt',
                f'DNS Inspector {APP_VERSION}\nGenerated: {datetime.now(timezone.utc).isoformat()}\nPurpose: safe deep memory diagnostic snapshot\nPatch: 0.7.13-hotfix.2\n'
            )
            z.writestr('runtime.json', json.dumps(runtime, indent=2, ensure_ascii=False, sort_keys=True, default=str))
            z.writestr('memory-deep.json', json.dumps(deep_memory, indent=2, ensure_ascii=False, sort_keys=True, default=str))
            z.writestr('config-safe.json', json.dumps(_observability_safe_config(), indent=2, ensure_ascii=False, sort_keys=True, default=str))
            z.writestr(
                'logs-note.txt',
                'DNS Inspector does not persist historical stdout/stderr logs. Retrieve container/application logs from Docker or TrueNAS when a historical log stream is needed.\n'
            )
            try:
                usage = shutil.disk_usage(os.path.dirname(DB_PATH) or '/')
                z.writestr(
                    'storage.json',
                    json.dumps({
                        'data_path': os.path.dirname(DB_PATH) or '/',
                        'total_bytes': usage.total,
                        'used_bytes': usage.used,
                        'free_bytes': usage.free,
                    }, indent=2)
                )
            except Exception as e:
                z.writestr('storage.json', json.dumps({'error': str(e)}, indent=2))
        bundle.seek(0)
        filename = f'dns-inspector-debug-{APP_VERSION}-{datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")}.zip'
        return send_file(bundle, mimetype='application/zip', as_attachment=True, download_name=filename)
    except Exception as e:
        print('debug bundle error:', repr(e), flush=True)
        return jsonify({'ok': False, 'error': 'Could not generate debug bundle'}), 500
'''
text = text[:start] + new_route + text[end:]

compile(text, str(APP), 'exec')
APP.write_text(text, encoding='utf-8')
print('DNS Inspector deep debug bundle patch 0.7.13-hotfix.2 applied')
