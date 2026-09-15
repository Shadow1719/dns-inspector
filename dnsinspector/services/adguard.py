import threading
from concurrent.futures import ThreadPoolExecutor

import dnsinspector.legacy_app as legacy

agh_login = legacy.agh_login
agh_get = legacy.agh_get
fetch_querylog = legacy.fetch_querylog
adguard_current_status = legacy.adguard_current_status
cached_adguard_status = legacy.cached_adguard_status
refresh_adguard_status = legacy.refresh_adguard_status
fetch_clients = legacy.fetch_clients
_adguard_list_test = legacy._adguard_list_test
_adguard_explain = legacy._adguard_explain
_adguard_explain_card = legacy._adguard_explain_card

# AdGuard status refresh is owned by this service module.  The legacy module
# exposes the actual refresh operation but not the scheduling contract used by
# Analytics, so keep the concurrency guard here instead of reaching into
# legacy private globals.
_status_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="agh-status")
_status_guard = threading.Lock()
_status_inflight = set()
_status_slots = threading.BoundedSemaphore(20)


def _schedule_adguard_status(domain):
    """Schedule one bounded background refresh for a domain.

    This function deliberately does not depend on a private scheduler inside
    legacy_app.  Analytics can therefore use the AdGuard service contract
    without coupling itself to the legacy implementation details.
    """
    domain = str(domain or '').strip().rstrip('.').lower()
    if not domain:
        return False
    if not _status_slots.acquire(blocking=False):
        return False
    with _status_guard:
        if domain in _status_inflight:
            _status_slots.release()
            return False
        _status_inflight.add(domain)

    def run():
        try:
            refresh_adguard_status(domain)
        except Exception as exc:
            print(f'AdGuard status refresh error for {domain}: {exc!r}', flush=True)
        finally:
            with _status_guard:
                _status_inflight.discard(domain)
            _status_slots.release()

    try:
        _status_executor.submit(run)
        return True
    except Exception:
        with _status_guard:
            _status_inflight.discard(domain)
        _status_slots.release()
        return False
