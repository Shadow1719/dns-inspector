from pathlib import Path

APP = Path("/app/app.py")
text = APP.read_text(encoding="utf-8")

text = text.replace(
    '_status_inflight = set()\n',
    '_status_inflight = set()\n_status_slots = threading.BoundedSemaphore(20)\n',
    1,
)
old = '''    with _status_guard:\n        if domain in _status_inflight:\n            return False\n        _status_inflight.add(domain)\n'''
new = '''    if not _status_slots.acquire(blocking=False):\n        return False\n    with _status_guard:\n        if domain in _status_inflight:\n            _status_slots.release()\n            return False\n        _status_inflight.add(domain)\n'''
if old not in text:
    raise SystemExit("hardcap patch failed: scheduler guard not found")
text = text.replace(old, new, 1)
text = text.replace(
    '''        finally:\n            with _status_guard:\n                _status_inflight.discard(domain)\n''',
    '''        finally:\n            with _status_guard:\n                _status_inflight.discard(domain)\n            _status_slots.release()\n''',
    1,
)
text = text.replace(
    '''    except Exception:\n        with _status_guard:\n            _status_inflight.discard(domain)\n        return False\n''',
    '''    except Exception:\n        with _status_guard:\n            _status_inflight.discard(domain)\n        _status_slots.release()\n        return False\n''',
    1,
)
text = text.replace(
    '            sev,sev_class=severity_for_classification(cls) if False else (None,None)\n            cls,badge,severity=classify(t,rd,n)\n',
    '            cls,badge,severity=classify(t,rd,n)\n',
    1,
)
APP.write_text(text, encoding="utf-8")
print("DNS Inspector hard-cap cleanup applied")
