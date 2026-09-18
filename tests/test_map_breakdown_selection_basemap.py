"""DNS Destinations map follow-up (Issue #63): country breakdown/ranking,
marker click/selection fixes, and a real tile basemap layer.

These pin the rendered `app.py` template the same way
tests/test_geoip_destinations_map.py and tests/test_map_basemap_theme_visual4.py
already do for this widget (no headless-browser harness in this repository),
plus real backend assertions for the additive `history` field. Existing map
payload/semantics tests in those files are unchanged by this issue and are
not duplicated here.
"""

import json
import re
import sqlite3
import uuid
from contextlib import closing


def _unique(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _insert_domain(db_path, domain, now, requests=1, clients=None):
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO domains"
            "(domain,first_seen,last_seen,requests,clients_json,blocked_requests,"
            "allowed_requests,unknown_requests,last_status,current_status)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            (domain, now, now, requests, json.dumps(clients or {}), 0, requests, 0, "Allowed", "Allowed"),
        )
        conn.commit()


def _add_destination_ip(db_path, domain, first_seen, ip, observations=1, last_seen=None):
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO domain_destination_ips(domain,ip,first_seen,last_seen,observations) "
            "VALUES(?,?,?,?,?)",
            (domain, ip, first_seen, last_seen or first_seen, observations),
        )
        conn.commit()


def _reset_map_cache(app_module):
    app_module._geoip_map_cache["data"] = None
    app_module._geoip_map_cache["at"] = 0.0


# --- persistence: `history` is additive and real, not a second store -------


def test_analytics_map_payload_gains_additive_history_field(app_module, initialised_db):
    """Existing fields/shape must be untouched (Issue #63 explicitly keeps
    `/api/analytics/map`'s existing semantics); `history` is additive."""
    _reset_map_cache(app_module)
    payload = app_module.geoip_map_payload()
    assert set(payload) >= {
        "updated", "provider", "countries", "destinations", "unknown",
        "coverage", "capabilities", "diagnostics", "history",
    }
    assert set(payload["history"]) == {"tracked_domains_all_time", "tracking_since"}
    assert isinstance(payload["history"]["tracked_domains_all_time"], int)


def test_history_reflects_the_whole_persistent_table_not_the_bounded_map_window(
    app_module, initialised_db, monkeypatch,
):
    """`history.tracked_domains_all_time` must count every domain that ever
    got a destination IP recorded, not just the GEOIP_MAP_DOMAIN_LIMIT-bounded
    window the rest of the payload uses -- proven here by comparing against
    an independent full-table COUNT while GEOIP_MAP_DOMAIN_LIMIT is set to 1
    (so the existing bounded `coverage.total_domains` field really is capped,
    while `history` is not). This is the real evidence that the map's
    underlying observation history is cumulative, not capped to a small
    recent window, without inventing a second storage layer."""
    domain = _unique("history-domain")
    now = app_module.utcnow()
    _insert_domain(initialised_db, domain, now, requests=1)
    _add_destination_ip(initialised_db, domain, now, "203.0.113.77", observations=1)

    monkeypatch.setattr(app_module, "GEOIP_MAP_DOMAIN_LIMIT", 1)
    _reset_map_cache(app_module)
    payload = app_module.geoip_map_payload()

    with closing(sqlite3.connect(initialised_db)) as conn:
        expected = conn.execute("SELECT COUNT(DISTINCT domain) FROM domain_destination_ips").fetchone()[0]
    assert payload["history"]["tracked_domains_all_time"] == expected
    assert payload["history"]["tracking_since"] is not None
    assert payload["coverage"]["total_domains"] <= 1  # the bounded window really is bounded here


def test_api_analytics_map_route_exposes_history(client):
    response = client.get("/api/analytics/map")
    payload = json.loads(response.data)
    assert "history" in payload
    assert "tracked_domains_all_time" in payload["history"]


# --- country breakdown/ranking ----------------------------------------------


def test_breakdown_panel_and_layout_are_registered_in_the_dashboard_grid(client):
    body = client.get("/").data.decode("utf-8")
    assert 'class="destination-map-layout"' in body
    assert 'id="map-breakdown-list"' in body
    assert 'id="map-breakdown-sort-btn"' in body
    assert 'id="destination-map-history"' in body


def test_breakdown_render_functions_exist(client):
    body = client.get("/").data.decode("utf-8")
    for fn in ("renderMapBreakdown", "renderMapBreakdownHistory", "mapSelectCountry"):
        assert f"function {fn}(" in body


def test_breakdown_rows_are_native_buttons_for_keyboard_activation(client):
    """A plain <button> gets Enter/Space activation from the browser itself
    -- no custom keydown handler needed, unlike the SVG marker case."""
    body = client.get("/").data.decode("utf-8")
    assert 'class="map-breakdown-row' in body
    assert "data-breakdown-country" in body
    assert "<button type=\"button\" class=\"map-breakdown-row" in body


def test_breakdown_uses_only_real_payload_fields_no_invented_metrics(client):
    body = client.get("/").data.decode("utf-8")
    match = re.search(r"function renderMapBreakdown\(data\)\{(.*?)\n\}", body, re.S)
    assert match, "renderMapBreakdown() not found"
    src = match.group(1)
    for field in ("observation_count", "unique_ip_count", "domain_count", "device_count", "country_name", "country_code"):
        assert field in src


def test_breakdown_row_click_reuses_the_exact_same_selection_path_as_a_marker(client):
    """Issue #63 requires a breakdown row and a map marker to use the same
    selection path -- both must call mapSelectCountry()."""
    body = client.get("/").data.decode("utf-8")
    assert "mapSelectCountry(btn.getAttribute('data-breakdown-country')" in body
    assert "mapSelectCountry(node.getAttribute('data-country'))" in body


def test_breakdown_sort_toggle_supports_metric_and_name(client):
    body = client.get("/").data.decode("utf-8")
    assert "mapBreakdownSortMode" in body
    assert "localeCompare" in body


# --- marker click/selection/detail fix --------------------------------------


def test_map_entity_focus_no_longer_draws_a_rectangular_outline(client):
    """Regression guard for the exact bug reported in Issue #63: an SVG <g>
    draws its default focus-visible outline as a rectangle around its whole
    bounding box (hit-area + spread particles), not around the visible
    marker. The group itself must not be outlined any more."""
    body = client.get("/").data.decode("utf-8")
    assert ".map-entity:focus-visible{outline:none}" in body
    assert ".map-entity:focus-visible{outline:2px solid" not in body


def test_map_entity_focus_and_selection_ring_the_real_marker_instead(client):
    body = client.get("/").data.decode("utf-8")
    assert ".map-entity:focus-visible .map-bubble{" in body
    assert ".map-bubble-selected{" in body


def test_map_select_country_shows_detail_before_the_full_rerender(client):
    """Technical guidance in Issue #63: avoid a click flow that renders the
    entire map and only then risks losing/invalidating the detail state --
    renderMapDetail() must be called before renderDestinationMap()/the mode
    re-render, not after."""
    body = client.get("/").data.decode("utf-8")
    match = re.search(r"function mapSelectCountry\(code, opts\)\{(.*?)\n\}", body, re.S)
    assert match, "mapSelectCountry() not found"
    src = match.group(1)
    detail_idx = src.index("renderMapDetail(")
    rerender_idx = src.index("renderDestinationMap(data)")
    assert detail_idx < rerender_idx


def test_destination_cluster_selection_also_shows_detail_before_rerender(client):
    body = client.get("/").data.decode("utf-8")
    match = re.search(r"const activateCluster = \(key\) => \{(.*?)\n  \};", body, re.S)
    assert match, "activateCluster() not found"
    src = match.group(1)
    detail_idx = src.index("renderMapDetail(")
    rerender_idx = src.index("renderDestinationsMode(data, capabilities);")
    assert detail_idx < rerender_idx


def test_map_marker_keyboard_activation_uses_the_same_handler_as_click(client):
    body = client.get("/").data.decode("utf-8")
    assert "e.key !== 'Enter' && e.key !== ' ' && e.key !== 'Spacebar'" in body
    assert "mapSelectCountry(node.getAttribute('data-country'));" in body


def test_stale_map_fetch_responses_cannot_overwrite_a_newer_one(client):
    """A monotonic request token guards against an out-of-order/late
    response from the 5-10s poll cycle overwriting the map with stale data;
    click/keyboard selection must not depend on this fetch at all."""
    body = client.get("/").data.decode("utf-8")
    assert "let mapFetchSeq = 0;" in body
    assert "if (seq !== mapFetchSeq) return;" in body


# --- real tile basemap layer -------------------------------------------------


def test_tile_provider_config_and_helpers_exist(client):
    body = client.get("/").data.decode("utf-8")
    assert "const MAP_TILE_PROVIDERS = {" in body
    for fn in ("mapTileProviderFor", "mapUsesMercatorProjection", "mapProjectMercator", "mapEnsureTileLayer"):
        assert f"function {fn}(" in body


def test_satellite_and_real_pins_basemaps_have_a_tile_provider(client):
    body = client.get("/").data.decode("utf-8")
    match = re.search(r"const MAP_TILE_PROVIDERS = \{(.*?)\n\};", body, re.S)
    assert match, "MAP_TILE_PROVIDERS not found"
    src = match.group(1)
    assert "'satellite-heat':" in src
    assert "'satellite-density':" in src
    assert "'real-pins':" in src


def test_dark_noc_intentionally_has_no_tile_provider(client):
    """The issue explicitly allows Dark NOC/Urban to keep its stylized
    treatment rather than a satellite/street photo."""
    body = client.get("/").data.decode("utf-8")
    match = re.search(r"const MAP_TILE_PROVIDERS = \{(.*?)\n\};", body, re.S)
    assert match, "MAP_TILE_PROVIDERS not found"
    src = match.group(1)
    assert "'dark-noc':" not in src


def test_tile_layer_is_additive_and_separate_from_the_traffic_overlay(client):
    """Traffic rendering (particles/bubbles/pins) must remain a separate
    layer drawn over the background image, not mixed into it."""
    body = client.get("/").data.decode("utf-8")
    assert ".map-tile-layer{" in body
    assert ".map-tiles-active .map-world-dots{display:none}" in body
    # The entity/marker renderer is untouched by the tile layer addition.
    assert "function mapEntityMarkup(opts){" in body


def test_tile_image_has_an_attribution_control(client):
    body = client.get("/").data.decode("utf-8")
    assert ".map-tile-attribution{" in body
    assert "OpenStreetMap contributors" in body
    assert "Esri" in body


def test_tile_loading_never_blocks_and_falls_back_on_error(client):
    body = client.get("/").data.decode("utf-8")
    assert "img.addEventListener('load'" in body
    assert "img.addEventListener('error'" in body
    assert "mapTileState = { basemap, status: 'failed' };" in body


def test_tile_reduced_motion_disables_fade_transition(client):
    body = client.get("/").data.decode("utf-8")
    assert 'html[data-motion="reduced"] .map-tile-layer img.map-tile{transition:none}' in body


def test_offline_dot_matrix_fallback_is_unchanged_and_still_present(client):
    """The offline dot-matrix world (Issue #33/#56) remains the graceful
    fallback -- it must not have been removed by the new tile layer."""
    body = client.get("/").data.decode("utf-8")
    assert "function mapWorldDots(){" in body
    assert "const WORLD_LAND_D = [" in body
