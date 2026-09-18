"""Analytics/map polling responsiveness fixes (Issue #61).

Real DEV debug evidence showed `/api/analytics/map` being fetched on every
single `/api/analytics` poll tick (itself polled continuously), with no
in-flight guard and no stale-response protection -- a render-storm that made
clicks/selector changes feel like they waited 5-10 seconds. Same
rendered-markup-source testing approach as the existing map frontend test
modules (test_map_visual2_frontend.py etc.) since there is no headless-
browser harness: these pin the presence and shape of the fix in the page's
inline `<script>`, not actual browser timing.
"""

import re


def test_destination_map_is_no_longer_fetched_from_inside_fetchAnalyticsFull(client):
    """The old code called fetchDestinationMap() unconditionally at the end
    of every fetchAnalyticsFull() tick -- that call must be gone; the map is
    driven by its own timer instead (see startAnalyticsPolling() below)."""
    body = client.get("/").data.decode("utf-8")
    match = re.search(r"async function fetchAnalyticsFull\(\)\{(.*?)\n\}\n", body, re.S)
    assert match, "fetchAnalyticsFull() not found in rendered page"
    assert "fetchDestinationMap()" not in match.group(1)


def test_map_has_its_own_bounded_refresh_cadence_separate_from_analytics(client):
    body = client.get("/").data.decode("utf-8")
    assert "function mapRefreshMs(){" in body
    assert "const MAP_MIN_REFRESH_MS = 20000;" in body
    assert "mapRefreshTimer = setInterval(fetchDestinationMap, mapRefreshMs());" in body
    # And it must be a genuinely different timer/interval from the analytics one.
    assert "analyticsFullTimer = setInterval(fetchAnalyticsFull, refreshMs);" in body


def test_both_poll_functions_use_abortcontroller_and_a_stale_response_guard(client):
    body = client.get("/").data.decode("utf-8")
    for fn_name in ("fetchAnalyticsFull", "fetchDestinationMap"):
        match = re.search(rf"async function {fn_name}\(\)\{{(.*?)\n\}}\n", body, re.S)
        assert match, f"{fn_name}() not found in rendered page"
        fn_body = match.group(1)
        assert "new AbortController()" in fn_body
        assert "signal: controller.signal" in fn_body
        assert "AbortError" in fn_body


def test_map_fetch_has_an_in_flight_guard_so_a_slow_tick_cannot_pile_up(client):
    body = client.get("/").data.decode("utf-8")
    assert "let mapFetchInFlight = false;" in body
    match = re.search(r"async function fetchDestinationMap\(\)\{(.*?)\n\}\n", body, re.S)
    assert match
    assert "if (mapFetchInFlight) return;" in match.group(1)


def test_map_skips_rebuilding_the_svg_when_polled_data_is_unchanged(client):
    """mapPayloadFingerprint() must gate the render call in fetchDestinationMap()
    so an unchanged aggregation doesn't force a full SVG rebuild every poll."""
    body = client.get("/").data.decode("utf-8")
    assert "function mapPayloadFingerprint(data){" in body
    match = re.search(r"async function fetchDestinationMap\(\)\{(.*?)\n\}\n", body, re.S)
    assert match
    fn_body = match.group(1)
    assert "fingerprint === mapLastFingerprint" in fn_body
    assert "renderDestinationMap(data);" in fn_body


def test_client_side_perf_trace_records_fetch_and_render_time_separately(client):
    """Diagnostics instrumentation so a slow interaction can be attributed to
    HTTP vs. main-thread rendering without a browser profiler."""
    body = client.get("/").data.decode("utf-8")
    assert "window.__dnsInspectorPerf" in body
    assert "function recordPerf(kind, fetchStartedAt, renderStartedAt, renderEndedAt){" in body
    assert "recordPerf('analytics'," in body
    assert "recordPerf('map'," in body
    assert 'id="diagnostics-perf-kv"' in body
    assert "function renderClientPerfPanel(){" in body


def test_stop_analytics_polling_clears_both_timers_and_aborts_in_flight_requests(client):
    body = client.get("/").data.decode("utf-8")
    match = re.search(r"function stopAnalyticsPolling\(\)\{(.*?)\n\}\n", body, re.S)
    assert match, "stopAnalyticsPolling() not found in rendered page"
    fn_body = match.group(1)
    assert "clearInterval(analyticsFullTimer)" in fn_body
    assert "clearInterval(mapRefreshTimer)" in fn_body
    assert "analyticsFetchController.abort()" in fn_body
    assert "mapFetchController.abort()" in fn_body
