import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import report_scheduler as rs


def test_resolve_report_path_accepts_safe_relative_names(tmp_path):
    full = rs.resolve_report_path(str(tmp_path), "dns-inspector-24h-20260101-000000.pdf")
    assert full.startswith(str(tmp_path))
    assert full.endswith("dns-inspector-24h-20260101-000000.pdf")


def test_resolve_report_path_accepts_a_safe_subdirectory(tmp_path):
    full = rs.resolve_report_path(str(tmp_path), "daily/report.pdf")
    assert full == str((tmp_path / "daily" / "report.pdf"))


@pytest.mark.parametrize(
    "bad_name",
    [
        "../escape.pdf",
        "../../etc/passwd",
        "/etc/passwd",
        "sub/../../escape.pdf",
        "..",
        "",
        "weird name; rm -rf.pdf",
        "sub\x00dir/report.pdf",
    ],
)
def test_resolve_report_path_rejects_traversal_and_unsafe_names(tmp_path, bad_name):
    with pytest.raises(rs.ReportPathError):
        rs.resolve_report_path(str(tmp_path), bad_name)


def test_resolve_report_path_never_escapes_base_even_with_symlink(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    base = tmp_path / "base"
    base.mkdir()
    link = base / "escape"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported in this environment")
    with pytest.raises(rs.ReportPathError):
        rs.resolve_report_path(str(base), "escape/report.pdf")


def test_render_filename_template_substitutes_known_placeholders():
    name = rs.render_filename_template("dns-inspector-{range}-{timestamp}.pdf", {"range": "24h", "timestamp": "20260101-000000", "date": "20260101", "time": "000000"})
    assert name == "dns-inspector-24h-20260101-000000.pdf"


def test_render_filename_template_falls_back_safely_on_bad_template():
    name = rs.render_filename_template("{not_a_real_field}.pdf", {"range": "24h", "timestamp": "20260101-000000", "date": "20260101", "time": "000000"})
    assert name == "dns-inspector-report-20260101-000000.pdf"


def test_render_filename_template_always_ends_in_pdf():
    name = rs.render_filename_template("report-{range}", {"range": "24h", "timestamp": "x", "date": "x", "time": "x"})
    assert name.endswith(".pdf")


def test_prune_report_history_deletes_oldest_files_beyond_retention(tmp_path):
    history = []
    for i in range(5):
        p = tmp_path / f"report-{i}.pdf"
        p.write_bytes(b"%PDF-1.4 fake")
        history.append({"path": str(p)})
    kept = rs.prune_report_history(str(tmp_path), history, retention_count=2)
    assert len(kept) == 2
    assert kept == history[-2:]
    for entry in history[:-2]:
        assert not Path(entry["path"]).exists()
    for entry in history[-2:]:
        assert Path(entry["path"]).exists()


def test_prune_report_history_never_deletes_outside_base_dir(tmp_path):
    outside_file = tmp_path / "outside.pdf"
    outside_file.write_bytes(b"%PDF-1.4 fake")
    base = tmp_path / "base"
    base.mkdir()
    history = [{"path": str(outside_file)}] + [
        {"path": str(base / f"r{i}.pdf")} for i in range(3)
    ]
    for entry in history[1:]:
        Path(entry["path"]).write_bytes(b"%PDF-1.4 fake")
    kept = rs.prune_report_history(str(base), history, retention_count=1)
    assert outside_file.exists()  # never touched even though it was pruned from the list
    assert len(kept) == 1


def test_send_report_email_reports_not_configured_without_raising():
    result = rs.send_report_email(
        host="", port=587, security="starttls", username="", password="",
        sender="", recipients=[], subject="x", body="y",
    )
    assert result["ok"] is False
    assert "error" in result


def test_send_report_email_never_leaks_password_on_failure():
    result = rs.send_report_email(
        host="127.0.0.1", port=1,  # nothing listens here -- guaranteed connection failure
        security="none", username="user", password="super-secret-password",
        sender="a@example.com", recipients=["b@example.com"], subject="x", body="y",
        timeout=1,
    )
    assert result["ok"] is False
    assert "super-secret-password" not in str(result)


class _FakeClock:
    def __init__(self, start=1000.0):
        self.t = start

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


def _make_scheduler(**overrides):
    calls = {"generate": 0, "save": 0, "persist": []}

    def generate_report(window_key):
        calls["generate"] += 1
        return b"%PDF-1.4 fake", {"range_key": window_key, "label": window_key, "generated_at": "now"}

    def save_report(pdf_bytes, config, meta):
        calls["save"] += 1
        return "/tmp/fake-report.pdf"

    def persist_run(update):
        calls["persist"].append(update)

    kwargs = dict(
        config_provider=lambda: {"enabled": True, "interval": "hourly", "window": "24h"},
        persist_run=persist_run,
        generate_report=generate_report,
        save_report=save_report,
        tick_seconds=rs.MIN_TICK_SECONDS,
        clock=_FakeClock(),
    )
    kwargs.update(overrides)
    scheduler = rs.ReportScheduler(**kwargs)
    return scheduler, calls


def test_compute_due_at_runs_immediately_when_never_run_before():
    due = rs.ReportScheduler.compute_due_at({"interval": "daily"}, now=500.0)
    assert due == 500.0


def test_compute_due_at_respects_interval_and_last_run():
    due = rs.ReportScheduler.compute_due_at({"interval": "hourly", "last_run_ts": 1000.0}, now=1500.0)
    assert due == 1000.0 + rs.INTERVAL_SECONDS["hourly"]


def test_compute_due_at_custom_interval_has_a_floor():
    due = rs.ReportScheduler.compute_due_at({"interval": "custom", "custom_interval_seconds": 1, "last_run_ts": 0.0}, now=10.0)
    assert due == rs.MIN_CUSTOM_INTERVAL_SECONDS


def test_run_now_reuses_the_same_generator_and_persists_state():
    scheduler, calls = _make_scheduler()
    result = scheduler.run_now(reason="manual")
    assert result["ok"] is True
    assert calls["generate"] == 1
    assert calls["save"] == 1
    assert calls["persist"][-1]["last_result"] == "success"
    state = scheduler.state()
    assert state["last_result"] == "success"
    assert state["running"] is False


def test_run_now_never_overlaps_and_releases_the_lock_for_the_next_call():
    scheduler, calls = _make_scheduler()
    first = scheduler.run_now(reason="manual")
    assert first["ok"] is True
    # The lock must be released after a completed run -- a second call must
    # succeed too, not report "already in progress" forever.
    second = scheduler.run_now(reason="manual")
    assert second["ok"] is True
    assert calls["generate"] == 2


def test_run_now_reports_conflict_when_a_run_is_genuinely_in_progress():
    scheduler, calls = _make_scheduler()
    assert scheduler._run_lock.acquire(blocking=False)  # simulate a run already in flight
    try:
        result = scheduler.run_now(reason="manual")
        assert result["ok"] is False
        assert calls["generate"] == 0
    finally:
        scheduler._run_lock.release()


def test_run_now_survives_generation_failure_without_crashing():
    def failing_generate(window_key):
        raise RuntimeError("boom")

    scheduler, calls = _make_scheduler(generate_report=failing_generate)
    result = scheduler.run_now(reason="manual")
    assert result["ok"] is False
    assert calls["save"] == 0
    assert scheduler.state()["last_result"] == "error"


def test_run_now_save_failure_still_reports_cleanly():
    def failing_save(pdf_bytes, config, meta):
        raise OSError("disk full")

    scheduler, calls = _make_scheduler(save_report=failing_save)
    result = scheduler.run_now(reason="manual")
    assert result["ok"] is False
    assert scheduler.state()["last_result"] == "error"


def test_email_failure_does_not_prevent_local_save():
    def save_report(pdf_bytes, config, meta):
        return "/tmp/saved.pdf"

    scheduler, calls = _make_scheduler(
        save_report=save_report,
        config_provider=lambda: {
            "enabled": True, "interval": "hourly", "window": "24h", "smtp_enabled": True,
            "smtp_host": "", "smtp_port": 587, "smtp_security": "starttls",
            "smtp_sender": "", "smtp_recipients": [],
        },
    )
    result = scheduler.run_now(reason="manual")
    assert result["ok"] is True
    assert result["saved_file"] == "/tmp/saved.pdf"
    assert result["email"]["ok"] is False  # SMTP not configured, but the run itself still succeeded


def test_shutdown_stops_the_background_thread_cleanly():
    scheduler, calls = _make_scheduler()
    scheduler.start()
    assert scheduler._thread is not None
    scheduler.shutdown(timeout=5)
    assert not scheduler._thread.is_alive()


def test_start_is_idempotent():
    scheduler, calls = _make_scheduler()
    scheduler.start()
    first_thread = scheduler._thread
    scheduler.start()  # should not spawn a second thread while the first is alive
    assert scheduler._thread is first_thread
    scheduler.shutdown(timeout=5)
