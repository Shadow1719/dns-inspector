"""Bounded scheduler + safe local storage + optional SMTP delivery for
scheduled Analytics/Visibility reports (Issue #88).

Design constraints this module exists to satisfy:
  - exactly one background worker thread, never a timer-per-report
  - explicit lifecycle: start / next-due / execute / success-failure / shutdown
  - no overlapping report generation jobs (a run in progress is never
    duplicated by the next tick)
  - no duplicate jobs after a process restart -- "next due" is computed from
    a persisted last-run timestamp, not from process start time
  - report storage never accepts an unsanitized path: a configurable base
    directory plus a validated relative filename only
  - bounded local report history (oldest files pruned once retention_count
    is exceeded)
  - a failed email never breaks local report generation/save, and credentials
    are never included in the state this module exposes
"""

from __future__ import annotations

import os
import re
import smtplib
import threading
import time
from datetime import datetime, timezone
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

INTERVAL_SECONDS = {"hourly": 3600, "daily": 86400, "weekly": 604800}
WINDOW_SECONDS = {"1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800}
MIN_CUSTOM_INTERVAL_SECONDS = 900  # a "custom" cadence can never busy-loop faster than 15m
MIN_TICK_SECONDS = 15
DEFAULT_RETENTION = 14
MAX_RETENTION = 200

_FILENAME_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")


class ReportPathError(ValueError):
    """Raised when a report path/filename cannot be safely resolved."""


def resolve_report_path(base_dir, relative_name):
    """Resolve `relative_name` under `base_dir`, rejecting anything that
    would place the resolved file outside of it.

    Never trusts the caller's path directly: rejects absolute paths, drive
    letters, NUL bytes, empty segments, and `..` traversal segments before
    ever touching the filesystem, then re-validates the fully resolved path
    is still inside `base_dir` (catching symlink tricks too).
    """
    if not relative_name or not isinstance(relative_name, str):
        raise ReportPathError("filename is required")
    if "\x00" in relative_name:
        raise ReportPathError("filename contains invalid characters")
    candidate = relative_name.replace("\\", "/")
    if candidate.startswith("/") or ":" in candidate:
        raise ReportPathError("filename must be a relative path")
    parts = [p for p in candidate.split("/") if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        raise ReportPathError("filename must not contain path traversal segments")
    for part in parts:
        if not _FILENAME_SEGMENT_RE.match(part):
            raise ReportPathError(f"filename segment {part!r} contains unsupported characters")
    try:
        os.makedirs(base_dir, exist_ok=True)
    except OSError as exc:
        raise ReportPathError(f"report base directory {base_dir!r} is not usable: {exc}")
    base_real = os.path.realpath(base_dir)
    full = os.path.realpath(os.path.join(base_real, *parts))
    if full != base_real and not full.startswith(base_real + os.sep):
        raise ReportPathError("resolved path escapes the configured report directory")
    return full


def render_filename_template(template, context):
    """Render a user-provided filename template against a fixed, safe set of
    placeholders. Unknown placeholders and format errors fall back to a safe
    default rather than raising into the scheduler loop."""
    try:
        name = (template or "").format(**context)
    except Exception:
        name = "dns-inspector-report-{timestamp}.pdf"
        name = name.format(**context)
    if not name.lower().endswith(".pdf"):
        name += ".pdf"
    return name


def filename_context(range_key, now=None):
    now = now or datetime.now(timezone.utc)
    return {
        "range": range_key,
        "date": now.strftime("%Y%m%d"),
        "time": now.strftime("%H%M%S"),
        "timestamp": now.strftime("%Y%m%d-%H%M%S"),
    }


def send_report_email(*, host, port, security, username, password, sender, recipients,
                       subject, body, attachment_bytes=None, attachment_filename=None, timeout=15):
    """Send (or test-send) an email. Returns a dict describing only safe,
    non-secret delivery metadata -- never the password, and never the raw
    SMTP exception text (which some servers echo the AUTH payload into)."""
    recipients = [r.strip() for r in (recipients or []) if r and r.strip()]
    if not host or not port or not sender or not recipients:
        return {"ok": False, "error": "SMTP is not fully configured", "recipient_count": len(recipients)}
    msg = MIMEMultipart()
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject or "DNS Inspector report"
    msg.attach(MIMEText(body or "", "plain"))
    if attachment_bytes is not None:
        part = MIMEApplication(attachment_bytes, Name=attachment_filename or "report.pdf")
        part["Content-Disposition"] = f'attachment; filename="{attachment_filename or "report.pdf"}"'
        msg.attach(part)
    try:
        if security == "tls":
            server = smtplib.SMTP_SSL(host, int(port), timeout=timeout)
        else:
            server = smtplib.SMTP(host, int(port), timeout=timeout)
        with server:
            if security == "starttls":
                server.starttls()
            if username and password:
                server.login(username, password)
            server.sendmail(sender, recipients, msg.as_string())
        return {"ok": True, "recipient_count": len(recipients), "at": datetime.now(timezone.utc).isoformat()}
    except Exception as exc:
        return {"ok": False, "error": type(exc).__name__, "recipient_count": len(recipients), "at": datetime.now(timezone.utc).isoformat()}


class ReportScheduler:
    """One bounded background worker. All state mutation happens on the
    worker thread except `run_now`, which callers (API handlers) may invoke
    directly -- both paths share `_run_lock` so a manual "export now" click
    and a due scheduled run can never overlap."""

    def __init__(self, *, config_provider, persist_run, generate_report, save_report,
                 tick_seconds=30, clock=time.time, logger=None):
        self._config_provider = config_provider
        self._persist_run = persist_run
        self._generate_report = generate_report
        self._save_report = save_report
        self._tick_seconds = max(MIN_TICK_SECONDS, tick_seconds)
        self._clock = clock
        self._logger = logger or (lambda level, message, **ctx: None)
        self._stop_event = threading.Event()
        self._thread = None
        self._run_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._state = {
            "enabled": False,
            "next_run": None,
            "last_run": None,
            "last_result": None,
            "last_error": None,
            "last_duration_seconds": None,
            "last_saved_file": None,
            "last_email_result": None,
            "running": False,
        }

    def state(self):
        with self._state_lock:
            return dict(self._state)

    def _set_state(self, **updates):
        with self._state_lock:
            self._state.update(updates)

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, name="report-scheduler", daemon=True)
        self._thread.start()

    def shutdown(self, timeout=5):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout)

    def _loop(self):
        while not self._stop_event.is_set():
            try:
                self._tick()
            except Exception as exc:
                self._logger("ERROR", "report scheduler tick failed", error=repr(exc))
            self._stop_event.wait(self._tick_seconds)

    @staticmethod
    def compute_due_at(config, now):
        interval_key = config.get("interval") or "daily"
        if interval_key == "custom":
            interval_seconds = max(MIN_CUSTOM_INTERVAL_SECONDS, int(config.get("custom_interval_seconds") or INTERVAL_SECONDS["daily"]))
        else:
            interval_seconds = INTERVAL_SECONDS.get(interval_key, INTERVAL_SECONDS["daily"])
        last_run_ts = config.get("last_run_ts")
        if last_run_ts is None:
            return now  # never run before -- due at the next tick, not retroactively "overdue" forever
        return float(last_run_ts) + interval_seconds

    def _tick(self):
        config = self._config_provider() or {}
        enabled = bool(config.get("enabled"))
        self._set_state(enabled=enabled)
        if not enabled:
            self._set_state(next_run=None)
            return
        now = self._clock()
        due_at = self.compute_due_at(config, now)
        self._set_state(next_run=_iso(due_at))
        if now < due_at:
            return
        self.run_now(config=config, reason="scheduled")

    def run_now(self, config=None, reason="manual"):
        if not self._run_lock.acquire(blocking=False):
            self._logger("INFO", "report scheduler run skipped: already running", reason=reason)
            return {"ok": False, "error": "A report run is already in progress"}
        started = self._clock()
        self._set_state(running=True)
        try:
            config = config if config is not None else (self._config_provider() or {})
            result = self._execute(config, reason)
            return result
        finally:
            duration = self._clock() - started
            self._set_state(running=False, last_run=_iso(started), last_duration_seconds=round(duration, 3))
            self._run_lock.release()

    def _execute(self, config, reason):
        window_key = config.get("window") or "24h"
        try:
            pdf_bytes, meta = self._generate_report(window_key)
        except Exception as exc:
            self._set_state(last_result="error", last_error=f"generation failed: {exc}")
            self._logger("ERROR", "scheduled report generation failed", error=repr(exc))
            self._persist_run({"last_run_ts": self._clock(), "last_result": "error", "last_error": str(exc)})
            return {"ok": False, "error": "report generation failed"}

        try:
            saved_path = self._save_report(pdf_bytes, config, meta)
        except Exception as exc:
            self._set_state(last_result="error", last_error=f"save failed: {exc}")
            self._logger("ERROR", "scheduled report save failed", error=repr(exc))
            self._persist_run({"last_run_ts": self._clock(), "last_result": "error", "last_error": str(exc)})
            return {"ok": False, "error": "report save failed"}

        email_result = None
        if config.get("smtp_enabled"):
            email_result = self._send_email(config, pdf_bytes, meta)

        self._set_state(last_result="success", last_error=None, last_saved_file=saved_path, last_email_result=email_result)
        self._logger("INFO", "scheduled report generated", reason=reason, saved_file=os.path.basename(saved_path))
        self._persist_run({
            "last_run_ts": self._clock(),
            "last_result": "success",
            "last_error": None,
            "last_saved_file": saved_path,
            "last_email_result": email_result,
        })
        return {"ok": True, "saved_file": saved_path, "email": email_result}

    def _send_email(self, config, pdf_bytes, meta):
        filename = os.path.basename(meta.get("filename") or "dns-inspector-report.pdf")
        subject = (config.get("smtp_subject_template") or "DNS Inspector report - {range}").format(range=meta.get("range_key", ""))
        body = (
            f"Attached: the DNS Inspector visibility report for {meta.get('label', meta.get('range_key', ''))}.\n"
            "This is an automated delivery from the scheduled report worker."
        )
        result = send_report_email(
            host=config.get("smtp_host"),
            port=config.get("smtp_port"),
            security=config.get("smtp_security"),
            username=config.get("smtp_username"),
            password=config.get("_smtp_password"),
            sender=config.get("smtp_sender"),
            recipients=config.get("smtp_recipients") or [],
            subject=subject,
            body=body,
            attachment_bytes=pdf_bytes,
            attachment_filename=filename,
        )
        # A failed send is logged as safe metadata only and never raised --
        # the local save above has already completed by this point.
        self._logger(
            "INFO" if result.get("ok") else "WARNING",
            "scheduled report email delivery",
            ok=str(result.get("ok")),
            recipient_count=str(result.get("recipient_count", 0)),
        )
        return result


def _iso(epoch_seconds):
    try:
        return datetime.fromtimestamp(float(epoch_seconds), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return None


def prune_report_history(base_dir, history, retention_count):
    """Keep only the newest `retention_count` entries of a saved-report
    history list (each a dict with a "path" key), deleting the pruned files
    from disk. Returns the retained history list, oldest-file-safe: never
    deletes a file outside base_dir even if the history list was tampered
    with, and tolerates already-missing files."""
    retention_count = max(1, min(MAX_RETENTION, int(retention_count or DEFAULT_RETENTION)))
    if len(history) <= retention_count:
        return history
    base_real = os.path.realpath(base_dir)
    keep = history[-retention_count:]
    drop = history[:-retention_count]
    for entry in drop:
        path = entry.get("path") or ""
        real = os.path.realpath(path)
        if real == base_real or not real.startswith(base_real + os.sep):
            continue
        try:
            os.remove(real)
        except OSError:
            pass
    return keep
