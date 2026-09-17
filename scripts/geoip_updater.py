#!/usr/bin/env python3
"""Automatic DB-IP Lite GeoIP database updater (Issue #42 / 0.8.5.5).

DNS Inspector's destination map (`docs/GEOIP.md`) previously required an
operator to manually download a DB-IP Lite export every month, run
`scripts/convert_dbip_country_lite.py` / `convert_dbip_city_lite.py` by hand,
and restart the container. This module makes that set-and-forget: it checks
DB-IP Lite for a newer monthly release on a configurable cadence, downloads
and validates it, converts it with the *same* existing converters (no
duplicated conversion logic), and atomically replaces the active database
only once the replacement is fully validated -- a failed or incomplete
check/download/conversion always leaves the previously working database
completely untouched.

This module has no dependency on `app.py` (no Flask) so it can run
standalone as a CLI (`python scripts/geoip_updater.py --help`) for a manual
one-shot update or a CI/troubleshooting dry run, and is imported by `app.py`
for the background auto-update worker.

## On the DB-IP Lite download URL

DB-IP Lite (https://db-ip.com/db/lite.php) publishes a new Country Lite and
City Lite CSV export near the start of each month, CC BY 4.0 licensed. The
default URL templates below follow DB-IP's long-standing, widely-mirrored
Lite distribution convention:

    https://download.db-ip.com/free/dbip-country-lite-<year>-<month>.csv.gz
    https://download.db-ip.com/free/dbip-city-lite-<year>-<month>.csv.gz

This implementation could not reach the network from its build environment
to re-fetch https://db-ip.com/db/download/ip-to-country-lite /
ip-to-city-lite and confirm the exact current pattern live -- both templates
are therefore fully overridable via `GEOIP_UPDATE_COUNTRY_URL_TEMPLATE` /
`GEOIP_UPDATE_CITY_URL_TEMPLATE` (see `docs/GEOIP.md`), and an operator
should confirm the pattern still matches DB-IP's current download page
before relying on unattended updates. If DB-IP has changed the pattern, a
mismatch is treated the same as "no release published this month" (see
`find_latest_release`) -- it never corrupts, blocks use of, or silently
replaces the existing database with garbage.

Attribution: DB-IP Lite is CC BY 4.0 -- see docs/GEOIP.md and the About panel
in the UI for the required attribution/link back to https://db-ip.com.
"""

import argparse
import csv
import gzip
import hashlib
import json
import os
import sys
import tempfile
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone

import requests

try:
    from scripts.convert_dbip_country_lite import convert as convert_country_rows
    from scripts.convert_dbip_city_lite import convert as convert_city_rows
except ImportError:  # running as a standalone script, not as part of the `scripts` package
    from convert_dbip_country_lite import convert as convert_country_rows
    from convert_dbip_city_lite import convert as convert_city_rows

DEFAULT_COUNTRY_URL_TEMPLATE = "https://download.db-ip.com/free/dbip-country-lite-{year:04d}-{month:02d}.csv.gz"
DEFAULT_CITY_URL_TEMPLATE = "https://download.db-ip.com/free/dbip-city-lite-{year:04d}-{month:02d}.csv.gz"
DEFAULT_STATE_PATH = "/data/geoip_update_state.json"

_STATE_TARGETS = ("country", "city")
_STATE_FIELDS = ("current_release", "last_checked_at", "last_success_at", "last_error", "last_error_at")


class GeoIPUpdateError(Exception):
    """A download/validate/convert step failed. Callers must leave the
    active database untouched when this is raised."""


@dataclass
class UpdaterConfig:
    country_db_path: str = "/data/geoip_country_ranges.csv"
    city_db_path: str = "/data/geoip_city_ranges.csv"
    state_path: str = DEFAULT_STATE_PATH
    country_url_template: str = DEFAULT_COUNTRY_URL_TEMPLATE
    city_url_template: str = DEFAULT_CITY_URL_TEMPLATE
    # Optional sidecar checksum URL templates. Left empty by default: DB-IP's
    # free Lite tier is not confirmed to publish a per-file checksum, and
    # inventing one would be worse than being explicit that it's unverified
    # (see `_expected_checksum` -- structural/row-count validation still
    # applies regardless). Set these if a checksum source is available for
    # your mirror/deployment.
    country_checksum_url_template: str = ""
    city_checksum_url_template: str = ""
    interval_days: int = 30
    lookback_months: int = 2
    min_country_ranges: int = 10000
    min_city_ranges: int = 100000
    connect_timeout: int = 10
    read_timeout: int = 300
    chunk_size: int = 1024 * 1024


def _int_env(name, default):
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def build_config_from_env():
    """The single place `GEOIP_UPDATE_*` / `GEOIP_DB_PATH` / `GEOIP_CITY_DB_PATH`
    env vars are read into an `UpdaterConfig` -- used identically by the CLI
    and by `app.py`'s background worker so the two never drift."""
    return UpdaterConfig(
        country_db_path=os.getenv("GEOIP_DB_PATH", "/data/geoip_country_ranges.csv"),
        city_db_path=os.getenv("GEOIP_CITY_DB_PATH", "/data/geoip_city_ranges.csv"),
        state_path=os.getenv("GEOIP_UPDATE_STATE_PATH", DEFAULT_STATE_PATH),
        country_url_template=os.getenv("GEOIP_UPDATE_COUNTRY_URL_TEMPLATE", DEFAULT_COUNTRY_URL_TEMPLATE),
        city_url_template=os.getenv("GEOIP_UPDATE_CITY_URL_TEMPLATE", DEFAULT_CITY_URL_TEMPLATE),
        country_checksum_url_template=os.getenv("GEOIP_UPDATE_COUNTRY_CHECKSUM_URL_TEMPLATE", ""),
        city_checksum_url_template=os.getenv("GEOIP_UPDATE_CITY_CHECKSUM_URL_TEMPLATE", ""),
        interval_days=max(1, _int_env("GEOIP_UPDATE_INTERVAL_DAYS", 30)),
        lookback_months=max(0, _int_env("GEOIP_UPDATE_LOOKBACK_MONTHS", 2)),
        min_country_ranges=max(1, _int_env("GEOIP_UPDATE_MIN_COUNTRY_RANGES", 10000)),
        min_city_ranges=max(1, _int_env("GEOIP_UPDATE_MIN_CITY_RANGES", 100000)),
        connect_timeout=max(1, _int_env("GEOIP_UPDATE_CONNECT_TIMEOUT_SECONDS", 10)),
        read_timeout=max(1, _int_env("GEOIP_UPDATE_READ_TIMEOUT_SECONDS", 300)),
        chunk_size=max(64 * 1024, _int_env("GEOIP_UPDATE_CHUNK_SIZE", 1024 * 1024)),
    )


def is_auto_update_enabled():
    return os.getenv("GEOIP_AUTO_UPDATE", "true").strip().lower() not in {"0", "false", "no", "off"}


# --- release discovery --------------------------------------------------------


def candidate_releases(today=None, lookback_months=2):
    """Yield (year, month) tuples, newest first, for the current month and up
    to `lookback_months` prior months -- DB-IP occasionally publishes a few
    days into the month, so a bounded look-back avoids treating a late
    release as "no update available" for the rest of the month."""
    today = today or date.today()
    y, m = today.year, today.month
    for _ in range(lookback_months + 1):
        yield (y, m)
        m -= 1
        if m == 0:
            y, m = y - 1, 12


def _probe_url_exists(session, url, config):
    """True if `url` resolves to a real object, without downloading its body.
    Tries HEAD first; falls back to a streamed GET (closed immediately after
    the status line) if the server doesn't support HEAD."""
    timeout = (config.connect_timeout, config.read_timeout)
    try:
        resp = session.head(url, timeout=timeout, allow_redirects=True)
        if resp.status_code == 200:
            return True
        if resp.status_code not in (405, 501):
            return False
    except requests.RequestException:
        return False
    try:
        with session.get(url, timeout=timeout, stream=True) as resp:
            return resp.status_code == 200
    except requests.RequestException:
        return False


def find_latest_release(url_template, session, config, today=None):
    """Return `(release_key, url)` for the newest DB-IP Lite release this
    template resolves to (release_key like "2026-09"), newest month first.
    `(None, None)` if none of the probed months resolve -- callers must treat
    that as "no update available right now", never as an error."""
    for year, month in candidate_releases(today=today, lookback_months=config.lookback_months):
        url = url_template.format(year=year, month=month)
        if _probe_url_exists(session, url, config):
            return f"{year:04d}-{month:02d}", url
    return None, None


# --- download / validate / convert -------------------------------------------


def _expected_checksum(session, checksum_url, config):
    """Fetch and parse a sidecar checksum, tolerating either a bare hex
    digest or `sha256sum`-style `"<digest>  <filename>"` output. Returns
    `None` (verification skipped, not failed) if no checksum URL is
    configured, the fetch fails, or the response doesn't look like a SHA-256
    digest -- checksum verification is a bonus on top of, never a
    replacement for, the structural/row-count validation below."""
    if not checksum_url:
        return None
    try:
        resp = session.get(checksum_url, timeout=(config.connect_timeout, config.read_timeout))
        if resp.status_code != 200:
            return None
        text = resp.text.strip()
    except requests.RequestException:
        return None
    if not text:
        return None
    token = text.split()[0].lower()
    if len(token) == 64 and all(c in "0123456789abcdef" for c in token):
        return token
    return None


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _download_gz(session, url, tmp_path, config):
    with session.get(url, timeout=(config.connect_timeout, config.read_timeout), stream=True) as resp:
        resp.raise_for_status()
        with open(tmp_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=config.chunk_size):
                if chunk:
                    f.write(chunk)


def _convert_gz_csv(gz_path, convert_rows_fn, out_path):
    """Stream-decompress the downloaded `.csv.gz` and run it through the same
    row converter `scripts/convert_dbip_country_lite.py` /
    `convert_dbip_city_lite.py` already use for a manual conversion, writing
    the result to `out_path`. Returns the number of rows written."""
    count = 0
    with gzip.open(gz_path, "rt", encoding="utf-8", newline="") as in_file:
        with open(out_path, "w", encoding="utf-8", newline="") as out_file:
            writer = csv.writer(out_file)
            for row in convert_rows_fn(csv.reader(in_file)):
                writer.writerow(row)
                count += 1
    return count


def download_and_convert(session, url, convert_rows_fn, dest_path, min_rows, config, checksum_url=None, replace=True):
    """Download, verify and convert a DB-IP Lite CSV export, replacing
    `dest_path` atomically only once every validation step has passed.
    `dest_path` is left completely untouched if anything below fails --
    downloads and the intermediate conversion always happen in temp files
    next to it, and the final `os.replace()` is the only step that touches
    the real path (atomic on the same filesystem, matching the
    `refresh_trackerdb()` pattern already used for TrackerDB updates).

    When `replace` is False (dry-run/verify mode), every step still runs for
    real against the network, but the converted file is discarded instead of
    replacing `dest_path` -- suitable for CI/troubleshooting checks that must
    not mutate the active database.

    Returns the number of converted rows. Raises `GeoIPUpdateError` (or lets
    a `requests`/`OSError` propagate) on any failure.
    """
    workdir = os.path.dirname(os.path.abspath(dest_path)) or "."
    os.makedirs(workdir, exist_ok=True)
    fd_gz, tmp_gz = tempfile.mkstemp(prefix=".geoip-download-", suffix=".csv.gz", dir=workdir)
    os.close(fd_gz)
    fd_csv, tmp_csv = tempfile.mkstemp(prefix=".geoip-convert-", suffix=".csv", dir=workdir)
    os.close(fd_csv)
    try:
        _download_gz(session, url, tmp_gz, config)
        with open(tmp_gz, "rb") as f:
            magic = f.read(2)
        if magic != b"\x1f\x8b":
            raise GeoIPUpdateError(f"downloaded file from {url} is not gzip-compressed")
        if checksum_url:
            expected = _expected_checksum(session, checksum_url, config)
            if expected:
                actual = _sha256_file(tmp_gz)
                if actual.lower() != expected.lower():
                    raise GeoIPUpdateError(f"checksum mismatch for {url}: expected {expected}, got {actual}")
        rows = _convert_gz_csv(tmp_gz, convert_rows_fn, tmp_csv)
        if rows < min_rows:
            raise GeoIPUpdateError(
                f"converted only {rows} range(s) from {url}, below the safety floor of "
                f"{min_rows} -- refusing to replace the active database"
            )
        if replace:
            os.replace(tmp_csv, dest_path)
        return rows
    finally:
        for p in (tmp_gz, tmp_csv):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except OSError:
                pass


# --- persistent updater state -------------------------------------------------


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def default_state():
    return {target: {field: None for field in _STATE_FIELDS} for target in _STATE_TARGETS}


def load_state(path):
    """Tolerant of a missing/corrupt/partial state file -- always returns the
    full expected shape so callers never need to guard against missing keys."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return default_state()
    state = default_state()
    for target in _STATE_TARGETS:
        raw = data.get(target)
        if isinstance(raw, dict):
            state[target].update({k: v for k, v in raw.items() if k in state[target]})
    return state


def save_state(path, state):
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".geoip-update-state-", suffix=".json", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, sort_keys=True)
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def next_check_iso(last_checked_at, interval_days):
    if not last_checked_at:
        return None
    try:
        dt = datetime.fromisoformat(last_checked_at)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (dt + timedelta(days=interval_days)).isoformat()


def _seconds_since(iso_ts):
    if not iso_ts:
        return None
    try:
        dt = datetime.fromisoformat(iso_ts)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).total_seconds()


def _is_check_due(target_state, interval_days, force):
    if force:
        return True
    elapsed = _seconds_since(target_state.get("last_checked_at"))
    return elapsed is None or elapsed >= interval_days * 86400


# --- orchestration -------------------------------------------------------------

_TARGET_SPECS = {
    "country": {
        "convert": convert_country_rows,
        "min_rows_field": "min_country_ranges",
        "db_path_field": "country_db_path",
        "url_template_field": "country_url_template",
        "checksum_template_field": "country_checksum_url_template",
    },
    "city": {
        "convert": convert_city_rows,
        "min_rows_field": "min_city_ranges",
        "db_path_field": "city_db_path",
        "url_template_field": "city_url_template",
        "checksum_template_field": "city_checksum_url_template",
    },
}


def _update_one(target, config, state, session, dry_run, force, logger, today=None):
    spec = _TARGET_SPECS[target]
    target_state = state[target]
    now = _now_iso()
    # A dry run is a verification tool (CI/troubleshooting): it must always
    # actually exercise the download/validate/convert pipeline for the
    # caller to learn anything, regardless of whether a real update happens
    # to be due right now -- so it bypasses the due/already-current gates the
    # same way `force` does, while `download_and_convert(..., replace=False)`
    # below still guarantees it never touches the active database or
    # persisted state (see `run_update`).
    effective_force = force or dry_run

    if not _is_check_due(target_state, config.interval_days, effective_force):
        return {"target": target, "action": "skipped_not_due", "release": target_state.get("current_release")}

    target_state["last_checked_at"] = now
    url_template = getattr(config, spec["url_template_field"])
    release, url = find_latest_release(url_template, session, config, today=today)
    if release is None:
        target_state["last_error"] = "no DB-IP Lite release found at the configured URL template for the probed months"
        target_state["last_error_at"] = now
        logger(f"GeoIP updater [{target}]: {target_state['last_error']}")
        return {"target": target, "action": "no_release_found", "release": target_state.get("current_release")}

    if not effective_force and release == target_state.get("current_release"):
        target_state["last_error"] = None
        return {"target": target, "action": "skipped_up_to_date", "release": release}

    year, month = (int(p) for p in release.split("-"))
    checksum_template = getattr(config, spec["checksum_template_field"])
    checksum_url = checksum_template.format(year=year, month=month) if checksum_template else None
    dest_path = getattr(config, spec["db_path_field"])
    min_rows = getattr(config, spec["min_rows_field"])

    try:
        rows = download_and_convert(
            session, url, spec["convert"], dest_path, min_rows, config,
            checksum_url=checksum_url, replace=not dry_run,
        )
    except (GeoIPUpdateError, requests.RequestException, OSError) as e:
        target_state["last_error"] = str(e)
        target_state["last_error_at"] = now
        logger(f"GeoIP updater [{target}]: update failed: {e}")
        return {"target": target, "action": "failed", "release": release, "error": str(e)}

    target_state["last_error"] = None
    if dry_run:
        logger(f"GeoIP updater [{target}]: dry run OK -- release {release}, {rows} rows, database left unchanged")
        return {"target": target, "action": "dry_run_ok", "release": release, "rows": rows}

    target_state["current_release"] = release
    target_state["last_success_at"] = now
    logger(f"GeoIP updater [{target}]: updated to release {release} ({rows} rows)")
    return {"target": target, "action": "updated", "release": release, "rows": rows}


def run_update(config, dry_run=False, force=False, country_only=False, city_only=False, session=None, logger=print, today=None):
    """Run one check/update pass for the country and/or city database.

    Safe to call on any cadence: each target independently no-ops
    (`skipped_not_due`) unless `config.interval_days` has elapsed since its
    last check (or `force=True`), and no-ops again (`skipped_up_to_date`) if
    the newest available release is already the one in use. Returns a list
    of per-target result dicts (`target`, `action`, `release`, and
    `rows`/`error` where applicable). `today` overrides "the current date"
    used for release discovery -- exposed for deterministic tests, not
    normally passed by callers.
    """
    if country_only and city_only:
        raise ValueError("country_only and city_only are mutually exclusive")
    session = session or requests.Session()
    state = load_state(config.state_path)
    targets = [t for t in _STATE_TARGETS if not (t == "country" and city_only) and not (t == "city" and country_only)]

    results = [_update_one(target, config, state, session, dry_run, force, logger, today=today) for target in targets]

    if not dry_run:
        save_state(config.state_path, state)
    return results


# --- CLI -----------------------------------------------------------------------


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "Manual one-shot DB-IP Lite GeoIP updater for DNS Inspector. Checks "
            "whether a newer DB-IP Country/City Lite release is available and, "
            "if so, downloads, validates and atomically replaces the configured "
            "database file(s). Safe to run repeatedly: no-ops when already "
            "current unless --force is given, and never touches the active "
            "database on a validation failure. Reads the same GEOIP_* / "
            "GEOIP_UPDATE_* environment variables app.py's background updater "
            "uses -- see docs/GEOIP.md."
        ),
    )
    parser.add_argument("--dry-run", action="store_true", help="Check/download/validate/convert for real, but never replace the active database or persist updater state.")
    parser.add_argument("--force", action="store_true", help="Re-check and re-download even if the current release is already up to date.")
    parser.add_argument("--country-only", action="store_true", help="Only update the country database.")
    parser.add_argument("--city-only", action="store_true", help="Only update the city/coordinate database.")
    parser.add_argument("--status", action="store_true", help="Print current updater state and exit without checking or downloading anything.")
    args = parser.parse_args(argv)

    if args.country_only and args.city_only:
        parser.error("--country-only and --city-only are mutually exclusive")

    config = build_config_from_env()

    if args.status:
        state = load_state(config.state_path)
        report = {"auto_update_enabled": is_auto_update_enabled(), "interval_days": config.interval_days}
        for target in _STATE_TARGETS:
            entry = dict(state[target])
            entry["next_check_at"] = next_check_iso(entry.get("last_checked_at"), config.interval_days)
            report[target] = entry
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0

    results = run_update(
        config, dry_run=args.dry_run, force=args.force,
        country_only=args.country_only, city_only=args.city_only,
    )
    failed = False
    for r in results:
        line = f"{r['target']}: {r['action']}"
        if r.get("release"):
            line += f" (release {r['release']})"
        if r.get("rows") is not None:
            line += f", {r['rows']} rows"
        if r.get("error"):
            line += f" -- {r['error']}"
            failed = True
        print(line)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
