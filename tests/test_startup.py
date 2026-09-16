"""The startup path: one named entry point, one set of background workers."""

import threading

# Routes 0.7.14 served. 0.8.0 must not lose or rename any of them.
EXPECTED_ROUTES = {
    "/",
    "/api/device/label",
    "/api/ip/ping",
    "/api/ip/ping/status",
    "/api/observability",
    "/api/state",
    "/debug/bundle",
    "/device",
    "/health",
    "/ip",
    "/search",
}


def test_entry_point_functions_exist(app_module):
    for name in ("main", "serve", "start_background_workers", "init_db"):
        assert callable(getattr(app_module, name)), f"{name} is not callable"


def test_background_workers_are_declared(app_module):
    """Every long-lived thread is declared in one place rather than inline."""
    declared = dict(app_module.BACKGROUND_WORKERS)
    assert set(declared) == {
        "agh-ingest", "enrichment-queue", "device-ip-cleanup", "ip-ping",
    }
    for name, target in declared.items():
        assert callable(target), f"worker {name} has no callable target"


def test_start_background_workers_starts_daemon_threads(app_module, monkeypatch):
    """Workers start as daemons so the process can always exit.

    The real worker bodies are replaced: this test verifies the *starting*
    behaviour, not AdGuard ingestion.
    """
    stopped = threading.Event()

    def noop():
        stopped.wait(timeout=5)

    monkeypatch.setattr(
        app_module,
        "BACKGROUND_WORKERS",
        tuple((name, noop) for name, _ in app_module.BACKGROUND_WORKERS),
    )

    threads = app_module.start_background_workers()
    try:
        assert len(threads) == 4
        assert all(t.daemon for t in threads)
        assert all(t.is_alive() for t in threads)
        assert {t.name for t in threads} == {
            "agh-ingest", "enrichment-queue", "device-ip-cleanup", "ip-ping",
        }
    finally:
        stopped.set()
        for thread in threads:
            thread.join(timeout=5)


def test_all_routes_are_registered(app_module):
    rules = {rule.rule for rule in app_module.app.url_map.iter_rules()}
    missing = EXPECTED_ROUTES - rules
    assert not missing, f"routes lost since 0.7.14: {sorted(missing)}"


def test_static_files_are_served(app_module):
    rules = {rule.rule for rule in app_module.app.url_map.iter_rules()}
    assert "/static/<path:filename>" in rules


def test_observability_route_binds_to_the_right_endpoint(app_module):
    """Regression test for D-1: a stray blank line bound this route to a helper."""
    endpoints = {
        rule.rule: rule.endpoint for rule in app_module.app.url_map.iter_rules()
    }
    assert endpoints["/api/observability"] == "api_observability"
