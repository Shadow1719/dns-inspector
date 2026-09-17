"""`scripts/geoip_updater.py` -- automatic DB-IP Lite updates (Issue #42 / 0.8.5.5).

Standalone tests (no `app.py`/Flask import, matching `test_verify_geoip_script.py`'s
approach): a small fake `requests.Session` stand-in routes HEAD/GET calls to
canned responses so nothing here ever touches the real network, matching the
project's hermetic test philosophy (see `tests/conftest.py`).
"""

import gzip
import hashlib
import io
import json
import os
import time
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest
import requests

from scripts import geoip_updater as gu

# Raw (unconverted) DB-IP export rows -- the shape the updater actually
# downloads and feeds through the existing converters.
COUNTRY_ROWS_RAW = "203.0.113.0,203.0.113.255,US\n198.51.100.0,198.51.100.255,DE\n"
CITY_ROWS_RAW = (
    "203.0.113.0,203.0.113.255,NA,US,VA,Ashburn,39.04,-77.49\n"
    "198.51.100.0,198.51.100.255,EU,DE,BE,Berlin,52.52,13.405\n"
)


def _gzip_bytes(text):
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as f:
        f.write(text.encode("utf-8"))
    return buf.getvalue()


class FakeResponse:
    def __init__(self, status_code=200, body=b"", text=""):
        self.status_code = status_code
        self._body = body
        self.text = text

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def iter_content(self, chunk_size=1024):
        yield self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


class FakeSession:
    """Stand-in for `requests.Session`: routes `.head()`/`.get()` to
    caller-supplied `{url: FakeResponse}` maps instead of the network. An
    unregistered URL behaves like a real 404."""

    def __init__(self, head_responses=None, get_responses=None):
        self.head_responses = head_responses or {}
        self.get_responses = get_responses or {}
        self.head_calls = []
        self.get_calls = []

    def head(self, url, timeout=None, allow_redirects=True):
        self.head_calls.append(url)
        return self.head_responses.get(url, FakeResponse(404))

    def get(self, url, timeout=None, stream=False):
        self.get_calls.append(url)
        return self.get_responses.get(url, FakeResponse(404))


def _session_for(url_status):
    """A `FakeSession` where every url in `url_status` answers the same way
    whether probed via HEAD or fetched via GET."""
    head = {u: FakeResponse(s) for u, s in url_status.items()}
    get = {u: FakeResponse(s) for u, s in url_status.items()}
    return FakeSession(head_responses=head, get_responses=get)


# --- release discovery --------------------------------------------------------


def test_candidate_releases_are_newest_first_and_bounded():
    releases = list(gu.candidate_releases(today=date(2026, 9, 15), lookback_months=2))
    assert releases == [(2026, 9), (2026, 8), (2026, 7)]


def test_candidate_releases_rolls_over_a_year_boundary():
    releases = list(gu.candidate_releases(today=date(2026, 1, 15), lookback_months=1))
    assert releases == [(2026, 1), (2025, 12)]


def test_find_latest_release_returns_current_month_when_available():
    template = "https://example.test/dbip-country-lite-{year:04d}-{month:02d}.csv.gz"
    url = template.format(year=2026, month=9)
    session = _session_for({url: 200})
    config = gu.UpdaterConfig(lookback_months=2)
    release, found_url = gu.find_latest_release(template, session, config, today=date(2026, 9, 15))
    assert (release, found_url) == ("2026-09", url)


def test_find_latest_release_falls_back_to_a_prior_month():
    template = "https://example.test/dbip-country-lite-{year:04d}-{month:02d}.csv.gz"
    prev_url = template.format(year=2026, month=8)
    session = _session_for({prev_url: 200})
    config = gu.UpdaterConfig(lookback_months=2)
    release, url = gu.find_latest_release(template, session, config, today=date(2026, 9, 3))
    assert release == "2026-08"
    assert url == prev_url


def test_find_latest_release_returns_none_when_nothing_resolves():
    template = "https://example.test/missing-{year:04d}-{month:02d}.csv.gz"
    session = _session_for({})
    config = gu.UpdaterConfig(lookback_months=1)
    release, url = gu.find_latest_release(template, session, config, today=date(2026, 9, 15))
    assert release is None
    assert url is None


def test_probe_falls_back_to_get_when_head_is_not_allowed():
    url = "https://example.test/dbip-country-lite-2026-09.csv.gz"
    session = FakeSession(head_responses={url: FakeResponse(405)}, get_responses={url: FakeResponse(200)})
    config = gu.UpdaterConfig()
    assert gu._probe_url_exists(session, url, config) is True


# --- download / validate / convert -------------------------------------------


def test_download_and_convert_replaces_the_database_atomically(tmp_path):
    dest = tmp_path / "geoip_country_ranges.csv"
    dest.write_text("stale,data\n")
    url = "https://example.test/dbip-country-lite-2026-09.csv.gz"
    session = FakeSession(get_responses={url: FakeResponse(200, body=_gzip_bytes(COUNTRY_ROWS_RAW))})
    config = gu.UpdaterConfig(min_country_ranges=1)

    rows = gu.download_and_convert(session, url, gu.convert_country_rows, str(dest), 1, config)

    assert rows == 2
    content = dest.read_text()
    assert "United States" in content and "Germany" in content
    # only the destination file remains -- temp download/convert files are cleaned up
    assert list(tmp_path.iterdir()) == [dest]


def test_download_and_convert_sweeps_a_stale_temp_file_from_a_prior_killed_pass(tmp_path):
    """Issue #44: the background worker now runs this as a subprocess it can
    SIGKILL on a watchdog timeout, which skips this function's own `finally`
    cleanup entirely -- so a `.geoip-download-*`/`.geoip-convert-*` temp file
    from a killed pass can be left behind. The *next* real pass must sweep
    anything old enough to safely assume it's abandoned, without touching a
    temp file that could still be genuinely in flight."""
    dest = tmp_path / "geoip_country_ranges.csv"
    dest.write_text("stale,data\n")
    stale = tmp_path / ".geoip-download-leftover.csv.gz"
    stale.write_text("leftover")
    old = time.time() - gu._STALE_TEMP_MAX_AGE_SECONDS - 60
    os.utime(stale, (old, old))
    fresh = tmp_path / ".geoip-convert-inflight.csv"
    fresh.write_text("still being written")

    url = "https://example.test/dbip-country-lite-2026-09.csv.gz"
    session = FakeSession(get_responses={url: FakeResponse(200, body=_gzip_bytes(COUNTRY_ROWS_RAW))})
    config = gu.UpdaterConfig(min_country_ranges=1)

    gu.download_and_convert(session, url, gu.convert_country_rows, str(dest), 1, config)

    assert not stale.exists(), "a temp file older than the staleness window must be swept"
    assert fresh.exists(), "a temp file within the staleness window must be left alone"


def test_download_and_convert_leaves_existing_database_untouched_on_http_error(tmp_path):
    dest = tmp_path / "geoip_country_ranges.csv"
    dest.write_text("existing,good,data\n")
    url = "https://example.test/dbip-country-lite-2026-09.csv.gz"
    session = FakeSession(get_responses={url: FakeResponse(500)})
    config = gu.UpdaterConfig()

    with pytest.raises(requests.HTTPError):
        gu.download_and_convert(session, url, gu.convert_country_rows, str(dest), 1, config)

    assert dest.read_text() == "existing,good,data\n"
    assert list(tmp_path.iterdir()) == [dest]


def test_download_and_convert_leaves_existing_database_untouched_below_min_rows(tmp_path):
    dest = tmp_path / "geoip_country_ranges.csv"
    dest.write_text("existing,good,data\n")
    url = "https://example.test/dbip-country-lite-2026-09.csv.gz"
    session = FakeSession(get_responses={url: FakeResponse(200, body=_gzip_bytes(COUNTRY_ROWS_RAW))})
    config = gu.UpdaterConfig(min_country_ranges=100)

    with pytest.raises(gu.GeoIPUpdateError, match="below the safety floor"):
        gu.download_and_convert(session, url, gu.convert_country_rows, str(dest), 100, config)

    assert dest.read_text() == "existing,good,data\n"


def test_download_and_convert_rejects_a_non_gzip_payload(tmp_path):
    dest = tmp_path / "geoip_country_ranges.csv"
    dest.write_text("existing\n")
    url = "https://example.test/dbip-country-lite-2026-09.csv.gz"
    session = FakeSession(get_responses={url: FakeResponse(200, body=b"not actually gzip")})
    config = gu.UpdaterConfig()

    with pytest.raises(gu.GeoIPUpdateError, match="not gzip-compressed"):
        gu.download_and_convert(session, url, gu.convert_country_rows, str(dest), 1, config)

    assert dest.read_text() == "existing\n"


def test_download_and_convert_dry_run_never_touches_the_destination(tmp_path):
    dest = tmp_path / "geoip_country_ranges.csv"
    dest.write_text("existing\n")
    url = "https://example.test/dbip-country-lite-2026-09.csv.gz"
    session = FakeSession(get_responses={url: FakeResponse(200, body=_gzip_bytes(COUNTRY_ROWS_RAW))})
    config = gu.UpdaterConfig(min_country_ranges=1)

    rows = gu.download_and_convert(session, url, gu.convert_country_rows, str(dest), 1, config, replace=False)

    assert rows == 2
    assert dest.read_text() == "existing\n"


def test_download_and_convert_verifies_a_matching_checksum(tmp_path):
    dest = tmp_path / "geoip_country_ranges.csv"
    url = "https://example.test/dbip-country-lite-2026-09.csv.gz"
    checksum_url = url + ".sha256"
    gz_bytes = _gzip_bytes(COUNTRY_ROWS_RAW)
    digest = hashlib.sha256(gz_bytes).hexdigest()
    session = FakeSession(get_responses={
        url: FakeResponse(200, body=gz_bytes),
        checksum_url: FakeResponse(200, text=f"{digest}  dbip-country-lite-2026-09.csv.gz"),
    })
    config = gu.UpdaterConfig(min_country_ranges=1)

    rows = gu.download_and_convert(session, url, gu.convert_country_rows, str(dest), 1, config, checksum_url=checksum_url)

    assert rows == 2


def test_download_and_convert_fails_closed_on_a_checksum_mismatch(tmp_path):
    dest = tmp_path / "geoip_country_ranges.csv"
    dest.write_text("existing\n")
    url = "https://example.test/dbip-country-lite-2026-09.csv.gz"
    checksum_url = url + ".sha256"
    session = FakeSession(get_responses={
        url: FakeResponse(200, body=_gzip_bytes(COUNTRY_ROWS_RAW)),
        checksum_url: FakeResponse(200, text="0" * 64),
    })
    config = gu.UpdaterConfig(min_country_ranges=1)

    with pytest.raises(gu.GeoIPUpdateError, match="checksum mismatch"):
        gu.download_and_convert(session, url, gu.convert_country_rows, str(dest), 1, config, checksum_url=checksum_url)

    assert dest.read_text() == "existing\n"


def test_city_converter_is_reused_unchanged(tmp_path):
    """The updater must reuse `convert_dbip_city_lite.convert`, not a
    duplicated implementation."""
    dest = tmp_path / "geoip_city_ranges.csv"
    url = "https://example.test/dbip-city-lite-2026-09.csv.gz"
    session = FakeSession(get_responses={url: FakeResponse(200, body=_gzip_bytes(CITY_ROWS_RAW))})
    config = gu.UpdaterConfig(min_city_ranges=1)

    rows = gu.download_and_convert(session, url, gu.convert_city_rows, str(dest), 1, config)

    assert rows == 2
    assert "Ashburn" in dest.read_text()


# --- persistent state ----------------------------------------------------------


def test_load_state_returns_the_default_shape_when_missing(tmp_path):
    state = gu.load_state(str(tmp_path / "missing.json"))
    assert state == gu.default_state()


def test_load_state_tolerates_corrupt_json(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("{not valid json")
    assert gu.load_state(str(path)) == gu.default_state()


def test_save_and_load_state_round_trip(tmp_path):
    path = tmp_path / "sub" / "state.json"
    state = gu.default_state()
    state["country"]["current_release"] = "2026-09"
    gu.save_state(str(path), state)
    loaded = gu.load_state(str(path))
    assert loaded["country"]["current_release"] == "2026-09"
    assert loaded["city"]["current_release"] is None


def test_load_state_drops_unknown_fields(tmp_path):
    path = tmp_path / "state.json"
    path.write_text(json.dumps({"country": {"current_release": "2026-01", "bogus": "x"}, "city": {}}))
    state = gu.load_state(str(path))
    assert state["country"]["current_release"] == "2026-01"
    assert "bogus" not in state["country"]


def test_next_check_iso_adds_the_interval():
    last = "2026-09-01T00:00:00+00:00"
    next_check = gu.next_check_iso(last, 30)
    assert datetime.fromisoformat(next_check) - datetime.fromisoformat(last) == timedelta(days=30)


def test_next_check_iso_is_none_without_a_prior_check():
    assert gu.next_check_iso(None, 30) is None


# --- orchestration (run_update) -------------------------------------------------


def test_run_update_is_a_noop_when_already_current(tmp_path):
    template = "https://example.test/dbip-country-lite-{year:04d}-{month:02d}.csv.gz"
    url = template.format(year=2026, month=9)
    dest = tmp_path / "country.csv"
    dest.write_text("existing,current,release\n")
    state_path = tmp_path / "state.json"
    state = gu.default_state()
    state["country"]["current_release"] = "2026-09"
    gu.save_state(str(state_path), state)
    session = _session_for({url: 200})
    config = gu.UpdaterConfig(
        country_db_path=str(dest), country_url_template=template,
        state_path=str(state_path), lookback_months=0,
    )

    results = gu.run_update(config, country_only=True, session=session, today=date(2026, 9, 15))

    assert results == [{"target": "country", "action": "skipped_up_to_date", "release": "2026-09"}]
    assert dest.read_text() == "existing,current,release\n"
    assert session.get_calls == []


def test_run_update_skips_a_check_that_is_not_due_yet(tmp_path):
    dest = tmp_path / "country.csv"
    state_path = tmp_path / "state.json"
    state = gu.default_state()
    state["country"]["current_release"] = "2026-08"
    state["country"]["last_checked_at"] = gu._now_iso()
    state["country"]["last_checked_ok_at"] = gu._now_iso()
    gu.save_state(str(state_path), state)
    session = _session_for({})  # any call would be a bug -- nothing is registered
    config = gu.UpdaterConfig(country_db_path=str(dest), state_path=str(state_path), interval_days=30)

    results = gu.run_update(config, country_only=True, session=session)

    assert results == [{"target": "country", "action": "skipped_not_due", "release": "2026-08"}]
    assert session.head_calls == [] and session.get_calls == []


def test_run_update_retries_a_failed_check_at_the_next_window_not_after_the_full_interval(tmp_path):
    """Issue #44 requirement: a failed check (bad URL template, transient
    network error, no release published yet) must not lock the target out
    of retrying for a full `interval_days` just because `last_checked_at`
    changed. Only a *successful* (or confirmed-up-to-date) check should
    reset the 30-day cadence -- `_is_check_due` gates on `last_checked_ok_at`
    specifically so a same-day retry after a failure is still due."""
    dest = tmp_path / "country.csv"
    state_path = tmp_path / "state.json"
    state = gu.default_state()
    # A check ran recently (last_checked_at) but it failed -- last_checked_ok_at
    # was never set, so the 30-day gate must not consider this "recently OK".
    state["country"]["last_checked_at"] = gu._now_iso()
    state["country"]["last_error"] = "no DB-IP Lite release found at the configured URL template for the probed months"
    state["country"]["last_error_at"] = gu._now_iso()
    gu.save_state(str(state_path), state)
    config = gu.UpdaterConfig(country_db_path=str(dest), state_path=str(state_path), interval_days=30)

    assert gu._is_check_due(state["country"], config.interval_days, force=False) is True


def test_is_check_due_respects_the_interval_after_a_successful_check():
    target_state = {"last_checked_ok_at": gu._now_iso(), "last_checked_at": gu._now_iso()}
    assert gu._is_check_due(target_state, interval_days=30, force=False) is False


def test_is_check_due_respects_the_interval_after_confirming_up_to_date(tmp_path):
    """`skipped_up_to_date` is not an error -- it must also reset the 30-day
    cadence, the same as a real `updated` outcome, so a target that is
    genuinely current doesn't get re-probed every day for a month."""
    template = "https://example.test/dbip-country-lite-{year:04d}-{month:02d}.csv.gz"
    url = template.format(year=2026, month=9)
    dest = tmp_path / "country.csv"
    dest.write_text("existing,current,release\n")
    state_path = tmp_path / "state.json"
    state = gu.default_state()
    state["country"]["current_release"] = "2026-09"
    gu.save_state(str(state_path), state)
    session = _session_for({url: 200})
    config = gu.UpdaterConfig(
        country_db_path=str(dest), country_url_template=template,
        state_path=str(state_path), lookback_months=0,
    )

    results = gu.run_update(config, country_only=True, session=session, today=date(2026, 9, 15))
    assert results == [{"target": "country", "action": "skipped_up_to_date", "release": "2026-09"}]

    saved = gu.load_state(str(state_path))
    assert saved["country"]["last_checked_ok_at"] is not None
    assert gu._is_check_due(saved["country"], interval_days=30, force=False) is False


def test_is_check_due_forced_check_ignores_a_recent_successful_check():
    target_state = {"last_checked_ok_at": gu._now_iso()}
    assert gu._is_check_due(target_state, interval_days=30, force=True) is True


def test_is_check_due_is_true_with_no_prior_state():
    assert gu._is_check_due({}, interval_days=30, force=False) is True


def test_run_update_failure_preserves_the_existing_database_and_records_the_error(tmp_path):
    template = "https://example.test/dbip-country-lite-{year:04d}-{month:02d}.csv.gz"
    url = template.format(year=2026, month=9)
    dest = tmp_path / "country.csv"
    dest.write_text("existing,good,data\n")
    state_path = tmp_path / "state.json"
    session = FakeSession(head_responses={url: FakeResponse(200)}, get_responses={url: FakeResponse(500)})
    config = gu.UpdaterConfig(
        country_db_path=str(dest), country_url_template=template,
        state_path=str(state_path), lookback_months=0,
    )

    results = gu.run_update(config, country_only=True, session=session, today=date(2026, 9, 15))

    assert results[0]["action"] == "failed"
    assert dest.read_text() == "existing,good,data\n"
    state = gu.load_state(str(state_path))
    assert state["country"]["last_error"]
    assert state["country"]["current_release"] is None
    # Issue #44: a failed check must not be mistaken for a "recently OK"
    # check, or `_is_check_due` would silently wait out the full interval
    # again before ever retrying.
    assert state["country"]["last_checked_ok_at"] is None
    assert gu._is_check_due(state["country"], interval_days=30, force=False) is True


def test_run_update_updates_the_database_and_persists_state_on_success(tmp_path):
    template = "https://example.test/dbip-country-lite-{year:04d}-{month:02d}.csv.gz"
    url = template.format(year=2026, month=9)
    dest = tmp_path / "country.csv"
    dest.write_text("stale\n")
    state_path = tmp_path / "state.json"
    session = FakeSession(
        head_responses={url: FakeResponse(200)},
        get_responses={url: FakeResponse(200, body=_gzip_bytes(COUNTRY_ROWS_RAW))},
    )
    config = gu.UpdaterConfig(
        country_db_path=str(dest), country_url_template=template,
        state_path=str(state_path), lookback_months=0, min_country_ranges=1,
    )

    results = gu.run_update(config, country_only=True, session=session, today=date(2026, 9, 15))

    assert results[0]["action"] == "updated"
    assert "United States" in dest.read_text()
    state = gu.load_state(str(state_path))
    assert state["country"]["current_release"] == "2026-09"
    assert state["country"]["last_success_at"]
    assert state["country"]["last_checked_ok_at"]


def test_run_update_dry_run_ignores_the_due_and_up_to_date_gates_but_persists_nothing(tmp_path):
    template = "https://example.test/dbip-country-lite-{year:04d}-{month:02d}.csv.gz"
    url = template.format(year=2026, month=9)
    dest = tmp_path / "country.csv"
    dest.write_text("stale\n")
    state_path = tmp_path / "state.json"
    state = gu.default_state()
    state["country"]["current_release"] = "2026-09"  # already current
    state["country"]["last_checked_at"] = gu._now_iso()  # just checked
    gu.save_state(str(state_path), state)
    session = FakeSession(
        head_responses={url: FakeResponse(200)},
        get_responses={url: FakeResponse(200, body=_gzip_bytes(COUNTRY_ROWS_RAW))},
    )
    config = gu.UpdaterConfig(
        country_db_path=str(dest), country_url_template=template,
        state_path=str(state_path), lookback_months=0, min_country_ranges=1,
    )

    results = gu.run_update(config, country_only=True, dry_run=True, session=session, today=date(2026, 9, 15))

    assert results[0]["action"] == "dry_run_ok"
    assert results[0]["rows"] == 2
    assert dest.read_text() == "stale\n"  # never replaced
    reloaded = gu.load_state(str(state_path))
    assert reloaded == state  # state file untouched by the dry run


def test_run_update_rejects_conflicting_only_flags(tmp_path):
    config = gu.UpdaterConfig(state_path=str(tmp_path / "state.json"))
    with pytest.raises(ValueError):
        gu.run_update(config, country_only=True, city_only=True)


def test_run_update_persists_state_after_each_target_not_only_at_the_end(tmp_path, monkeypatch):
    """Issue #43 regression: a real deployment showed `in_progress=true` with
    *both* targets' `last_checked_at=null` for several minutes. The previous
    implementation only called `save_state()` once, after every target had
    already been processed -- so a slow/stuck later target (city) hid the
    fact that an earlier target (country) had already finished. Simulate
    city blowing up mid-check and confirm country's result was already
    durably persisted to disk before that happened, not lost with it.
    """
    template = "https://example.test/dbip-country-lite-{year:04d}-{month:02d}.csv.gz"
    url = template.format(year=2026, month=9)
    dest = tmp_path / "country.csv"
    dest.write_text("stale\n")
    state_path = tmp_path / "state.json"
    session = FakeSession(
        head_responses={url: FakeResponse(200)},
        get_responses={url: FakeResponse(200, body=_gzip_bytes(COUNTRY_ROWS_RAW))},
    )
    config = gu.UpdaterConfig(
        country_db_path=str(dest), country_url_template=template,
        state_path=str(state_path), lookback_months=0, min_country_ranges=1,
    )

    real_update_one = gu._update_one

    def flaky_update_one(target, *args, **kwargs):
        if target == "city":
            raise RuntimeError("simulated hang/crash mid-check")
        return real_update_one(target, *args, **kwargs)

    monkeypatch.setattr(gu, "_update_one", flaky_update_one)

    with pytest.raises(RuntimeError):
        gu.run_update(config, session=session, today=date(2026, 9, 15))

    saved = gu.load_state(str(state_path))
    assert saved["country"]["last_checked_at"] is not None
    assert saved["country"]["last_error"] is None
    assert saved["country"]["current_release"] == "2026-09"


def test_mark_stuck_checks_as_timed_out_records_an_error_for_an_unsettled_check(tmp_path):
    state_path = tmp_path / "state.json"
    state = gu.default_state()
    state["country"]["last_checked_at"] = gu._now_iso()
    gu.save_state(str(state_path), state)

    gu.mark_stuck_checks_as_timed_out(str(state_path))

    saved = gu.load_state(str(state_path))
    assert saved["country"]["last_error"]
    assert saved["country"]["last_error_at"] is not None
    # city was never checked this pass -- nothing to mark for it.
    assert saved["city"]["last_checked_at"] is None
    assert saved["city"]["last_error"] is None


def test_mark_stuck_checks_as_timed_out_leaves_a_settled_check_untouched(tmp_path):
    state_path = tmp_path / "state.json"
    state = gu.default_state()
    checked = gu._now_iso()
    state["country"]["last_checked_at"] = checked
    state["country"]["last_success_at"] = checked
    state["country"]["current_release"] = "2026-09"
    gu.save_state(str(state_path), state)

    gu.mark_stuck_checks_as_timed_out(str(state_path))

    saved = gu.load_state(str(state_path))
    assert saved["country"]["last_error"] is None
    assert saved["country"]["current_release"] == "2026-09"


# --- disabled mode ---------------------------------------------------------------


def test_is_auto_update_enabled_defaults_to_true(monkeypatch):
    monkeypatch.delenv("GEOIP_AUTO_UPDATE", raising=False)
    assert gu.is_auto_update_enabled() is True


@pytest.mark.parametrize("value", ["false", "0", "no", "off", "False"])
def test_is_auto_update_enabled_respects_disabling_values(monkeypatch, value):
    monkeypatch.setenv("GEOIP_AUTO_UPDATE", value)
    assert gu.is_auto_update_enabled() is False


# --- manual CLI invocation ---------------------------------------------------------


def test_main_status_reports_state_without_any_network_call(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("GEOIP_UPDATE_STATE_PATH", str(tmp_path / "state.json"))
    code = gu.main(["--status"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["country"]["current_release"] is None
    assert payload["city"]["current_release"] is None
    assert "interval_days" in payload


def test_main_rejects_conflicting_only_flags():
    with pytest.raises(SystemExit):
        gu.main(["--country-only", "--city-only"])


def test_main_forwards_flags_to_run_update(monkeypatch, capsys):
    captured = {}

    def fake_run_update(config, dry_run=False, force=False, country_only=False, city_only=False, **kwargs):
        captured.update(dry_run=dry_run, force=force, country_only=country_only, city_only=city_only)
        return [{"target": "country", "action": "dry_run_ok", "release": "2026-09", "rows": 5}]

    monkeypatch.setattr(gu, "run_update", fake_run_update)
    code = gu.main(["--dry-run", "--country-only"])

    assert code == 0
    assert captured == {"dry_run": True, "force": False, "country_only": True, "city_only": False}
    assert "dry_run_ok" in capsys.readouterr().out


def test_main_returns_nonzero_when_a_target_fails(monkeypatch):
    monkeypatch.setattr(
        gu, "run_update",
        lambda *a, **k: [{"target": "country", "action": "failed", "release": "2026-09", "error": "boom"}],
    )
    assert gu.main([]) == 1


# --- scheduling (Issue #44) -----------------------------------------------------


def test_next_scheduled_run_stays_today_when_the_window_has_not_passed():
    now = datetime(2026, 9, 17, 1, 0, 0, tzinfo=timezone.utc)
    run = gu.next_scheduled_run(now, hour=3, minute=0)
    assert run == datetime(2026, 9, 17, 3, 0, 0, tzinfo=timezone.utc)


def test_next_scheduled_run_rolls_to_tomorrow_when_the_window_already_passed():
    now = datetime(2026, 9, 17, 3, 0, 1, tzinfo=timezone.utc)
    run = gu.next_scheduled_run(now, hour=3, minute=0)
    assert run == datetime(2026, 9, 18, 3, 0, 0, tzinfo=timezone.utc)


def test_next_scheduled_run_at_the_exact_window_rolls_to_tomorrow():
    """Calling this again immediately after a pass started at exactly the
    scheduled second must not return the same instant a second time --
    otherwise the worker's loop would spin, re-running a pass every
    iteration instead of waiting a full day."""
    now = datetime(2026, 9, 17, 3, 0, 0, tzinfo=timezone.utc)
    run = gu.next_scheduled_run(now, hour=3, minute=0)
    assert run == datetime(2026, 9, 18, 3, 0, 0, tzinfo=timezone.utc)


def test_next_scheduled_run_handles_a_midnight_window():
    now = datetime(2026, 9, 17, 23, 59, 0, tzinfo=timezone.utc)
    run = gu.next_scheduled_run(now, hour=0, minute=0)
    assert run == datetime(2026, 9, 18, 0, 0, 0, tzinfo=timezone.utc)


def test_next_scheduled_run_across_a_dst_spring_forward_transition():
    """Europe/Bucharest springs forward (23h day) on the last Sunday of
    March (2026-03-29). `next_scheduled_run` must still land on the correct
    wall-clock 10:00 the next day, and the actual elapsed real time between
    the two instants must reflect the DST jump (23h, not 24h) -- proving the
    zoneinfo-aware arithmetic here isn't silently doing fixed-offset math.
    (A scheduled hour of 10 is used, not 3, specifically to stay clear of
    the 03:00-04:00 gap the transition itself creates that day.)"""
    tz = ZoneInfo("Europe/Bucharest")
    now = datetime(2026, 3, 28, 10, 0, 1, tzinfo=tz)  # just after today's window
    run = gu.next_scheduled_run(now, hour=10, minute=0)
    assert (run.year, run.month, run.day, run.hour, run.minute) == (2026, 3, 29, 10, 0)
    elapsed = run.astimezone(timezone.utc) - now.astimezone(timezone.utc)
    assert elapsed == timedelta(hours=22, minutes=59, seconds=59)


def test_next_scheduled_run_across_a_dst_fall_back_transition():
    """Bucharest falls back (25h day) on the last Sunday of October
    (2026-10-25); the elapsed real time crossing it should be ~25h, not 24h."""
    tz = ZoneInfo("Europe/Bucharest")
    now = datetime(2026, 10, 24, 10, 0, 1, tzinfo=tz)
    run = gu.next_scheduled_run(now, hour=10, minute=0)
    assert (run.year, run.month, run.day, run.hour, run.minute) == (2026, 10, 25, 10, 0)
    elapsed = run.astimezone(timezone.utc) - now.astimezone(timezone.utc)
    assert elapsed == timedelta(hours=24, minutes=59, seconds=59)


def test_resolve_auto_update_timezone_defaults_to_utc_for_an_empty_name():
    tz, warning = gu.resolve_auto_update_timezone("")
    assert tz is timezone.utc
    assert warning is None


def test_resolve_auto_update_timezone_resolves_a_real_iana_zone():
    tz, warning = gu.resolve_auto_update_timezone("Europe/Bucharest")
    assert warning is None
    assert isinstance(tz, ZoneInfo)
    assert str(tz) == "Europe/Bucharest"


def test_resolve_auto_update_timezone_falls_back_to_utc_on_an_unknown_name():
    tz, warning = gu.resolve_auto_update_timezone("Not/ARealZone")
    assert tz is timezone.utc
    assert warning is not None
    assert "Not/ARealZone" in warning


def test_build_config_from_env_reads_the_schedule_env_vars(monkeypatch):
    monkeypatch.setenv("GEOIP_AUTO_UPDATE_HOUR", "4")
    monkeypatch.setenv("GEOIP_AUTO_UPDATE_MINUTE", "30")
    monkeypatch.setenv("GEOIP_AUTO_UPDATE_TIMEZONE", "Europe/Bucharest")
    config = gu.build_config_from_env()
    assert config.auto_update_hour == 4
    assert config.auto_update_minute == 30
    assert config.auto_update_timezone == "Europe/Bucharest"


def test_build_config_from_env_defaults_the_schedule_to_3am_utc(monkeypatch):
    monkeypatch.delenv("GEOIP_AUTO_UPDATE_HOUR", raising=False)
    monkeypatch.delenv("GEOIP_AUTO_UPDATE_MINUTE", raising=False)
    monkeypatch.delenv("GEOIP_AUTO_UPDATE_TIMEZONE", raising=False)
    config = gu.build_config_from_env()
    assert config.auto_update_hour == 3
    assert config.auto_update_minute == 0
    assert config.auto_update_timezone == "UTC"


def test_build_config_from_env_clamps_an_out_of_range_hour(monkeypatch):
    monkeypatch.setenv("GEOIP_AUTO_UPDATE_HOUR", "99")
    config = gu.build_config_from_env()
    assert config.auto_update_hour == 23
