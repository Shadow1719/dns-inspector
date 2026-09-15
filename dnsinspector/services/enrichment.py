import threading
from concurrent.futures import ThreadPoolExecutor

import dnsinspector.legacy_app as legacy

netify_ip_lookup = legacy.netify_ip_lookup
netify_lookup = legacy.netify_lookup
rdap_lookup = legacy.rdap_lookup
dns_records_lookup = legacy.dns_records_lookup
resolve_dns = legacy.resolve_dns
_cache_needs_refresh = legacy._cache_needs_refresh

# Domain enrichment scheduling is owned by this service module.  Do not depend
# on the legacy application's private queue/worker globals here: those helpers
# are not part of legacy_app's compatibility contract and may disappear while
# the migration continues.
_enrichment_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="domain-enrich")
_enrichment_guard = threading.Lock()
_enrichment_inflight = set()
_enrichment_slots = threading.BoundedSemaphore(20)


def _queue_domain_enrichment(domain):
    """Schedule bounded background enrichment for one domain.

    The request path only schedules work. Network I/O happens in the bounded
    executor and is deduplicated per domain so repeated dashboard refreshes
    cannot create an unbounded thread/task backlog.
    """
    domain = str(domain or '').strip().rstrip('.').lower()
    if not domain:
        return False

    if not _enrichment_slots.acquire(blocking=False):
        return False

    with _enrichment_guard:
        if domain in _enrichment_inflight:
            _enrichment_slots.release()
            return False
        _enrichment_inflight.add(domain)

    def run():
        try:
            # These operations already maintain their own local caches. They are
            # deliberately executed outside the Flask request path.
            netify_lookup(domain, force=True)
            rdap_lookup(domain, force=True)
            dns_records_lookup(domain, force=True)
        except Exception as exc:
            print(f"domain enrichment error for {domain}: {exc!r}", flush=True)
        finally:
            with _enrichment_guard:
                _enrichment_inflight.discard(domain)
            _enrichment_slots.release()

    try:
        _enrichment_executor.submit(run)
        return True
    except Exception:
        with _enrichment_guard:
            _enrichment_inflight.discard(domain)
        _enrichment_slots.release()
        return False


def _enrichment_worker():
    """Compatibility entry point retained during the legacy migration.

    The scheduler is executor-backed now, so there is no dedicated blocking
    queue consumer thread to start. Calls are intentionally harmless.
    """
    return None
