from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_dev_server_runs_threaded():
    """Regression test for Issue #100: app.run() was started without
    threaded=True, so Werkzeug's dev server (what Dockerfile actually runs
    in production: `CMD ["python","/app/app.py"]`) served exactly one HTTP
    request at a time. A single slow request -- report PDF generation, an
    SMTP send in api_reports_save_now, a subprocess-backed /api/ip/ping --
    would then queue up every other concurrent browser request (dashboard
    polling, Analytics fetches) behind it, which looks like a frozen/hung
    tab even though each request eventually returns 200. Every background
    worker already started above (DNS ingest, enrichment, GeoIP loaders, the
    report scheduler) runs as its own thread against the same per-call
    sqlite3 connections + db_lock, so the HTTP layer being single-threaded
    was the only thing forcing that serialization."""
    lines = (REPO_ROOT / "app.py").read_text().splitlines()
    run_lines = [line for line in lines if "app.run(" in line]
    assert len(run_lines) == 1, "expected a single app.run(...) call in app.py"
    assert "threaded=True" in run_lines[0]
