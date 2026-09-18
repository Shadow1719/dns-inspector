"""DNS Destinations map infographic redesign (Issue #56 / 0.8.5.x).

Same rendered-markup-source testing approach as test_map_visual2_frontend.py
and test_map_navigation_visual21.py -- there is no headless-browser harness,
so these pin the presence and shape of the new size/color-intensity encoding,
the explicit legend, click/tap + keyboard marker activation and the dismissible
detail card, plus regression guards that the existing map API semantics, pan/
zoom/Fit/Reset controls, mode/metric/style selectors and DB-IP attribution
footer are all still present and unchanged.
"""

import re


# --- size + color traffic-intensity encoding --------------------------------


def test_intensity_color_function_exists_and_spans_green_to_red(client):
    body = client.get("/").data.decode("utf-8")
    assert "function mapIntensityColor(ratio){" in body
    match = re.search(r"const MAP_INTENSITY_STOPS = \[(.*?)\];", body, re.S)
    assert match, "MAP_INTENSITY_STOPS not found in rendered page"
    stops = match.group(1)
    # low = green (hue ~150), highest = red (hue ~0-10) -- lime/yellow and
    # orange must appear as intermediate stops between them.
    hues = [int(h) for h in re.findall(r"h:\s*(-?\d+)", stops)]
    assert len(hues) >= 4
    assert hues[0] >= 140  # green
    assert hues[-1] <= 15  # red
    assert any(30 <= h <= 100 for h in hues[1:-1])  # lime/yellow/orange midpoint


def test_country_and_cluster_markers_use_the_same_ratio_for_size_and_color(client):
    """Size (sqrt-scaled radius) and color (mapThemeColor) must both be
    derived from the same value/max-in-view ratio, not two independent
    computations that could disagree."""
    body = client.get("/").data.decode("utf-8")
    assert "const ratio = mapMetricValue(c) / maxVal;" in body
    assert "const color = mapThemeColor(ratio, theme);" in body
    assert "Math.sqrt(ratio) * 18" in body  # countries
    assert "Math.sqrt(ratio) * 15" in body  # destination clusters


def test_markers_render_with_inline_intensity_fill_and_stroke(client):
    body = client.get("/").data.decode("utf-8")
    assert 'style="fill:${color};stroke:${color}"' in body


def test_large_high_intensity_countries_get_a_numeric_count_label(client):
    """Numeric labels on big markers make the encoded volume readable without
    a table -- one of the issue's explicit infographic asks."""
    body = client.get("/").data.decode("utf-8")
    assert "function mapCompactNumber(n){" in body
    assert 'class="map-bubble-count"' in body
    assert ".map-bubble-count{" in body


def test_high_ratio_markers_pulse_not_only_the_single_top_country(client):
    """Previously only the single top country ever pulsed; now any marker at
    or above a high-intensity ratio does, so "large + red" reads as active
    everywhere it applies, not just for one hard-coded entry."""
    body = client.get("/").data.decode("utf-8")
    assert "const pulse = ratio >= 0.72" in body
    assert "topCode" not in body


# --- explicit size/color legend ----------------------------------------------


def test_map_legend_is_present_and_explains_both_encodings(client):
    body = client.get("/").data.decode("utf-8")
    assert 'id="destination-map-legend"' in body
    assert "Marker size" in body
    assert "Marker color" in body
    assert 'id="map-legend-metric-label"' in body
    assert ".map-legend-gradient{" in body


def test_legend_gradient_uses_the_same_color_stops_as_mapIntensityColor(client):
    """The legend must never visually drift from what a marker actually
    renders -- both are literal copies of the same HSL stops."""
    body = client.get("/").data.decode("utf-8")
    assert "hsl(152,68%,42%)" in body
    assert "hsl(2,82%,52%)" in body


def test_legend_metric_label_is_synced_from_the_current_map_metric_preference(client):
    body = client.get("/").data.decode("utf-8")
    assert "function mapMetricLabel(){" in body
    assert "document.getElementById('map-legend-metric-label')" in body


# --- click/tap primary interaction, not delayed hover ------------------------


def test_markers_are_keyboard_focusable_with_a_button_role(client):
    body = client.get("/").data.decode("utf-8")
    assert 'tabindex="0" role="button"' in body
    assert "aria-pressed=" in body


def test_markers_wire_both_click_and_enter_space_keydown_activation(client):
    """Click/tap is primary; Enter/Space must trigger the identical action,
    not a separate/weaker code path, per the issue's keyboard-access
    requirement."""
    body = client.get("/").data.decode("utf-8")
    assert "const activateCountry = (code) => {" in body
    assert "const activateCluster = (key) => {" in body
    assert body.count("if (e.key !== 'Enter' && e.key !== ' ' && e.key !== 'Spacebar') return;") == 2


def test_detail_card_persists_until_dismissed_via_a_close_control(client):
    body = client.get("/").data.decode("utf-8")
    assert 'id="map-detail-close-btn"' in body
    assert ".map-detail-close{" in body
    assert "aria-label=\"Close details\"" in body


def test_widget_copy_directs_users_to_click_tap_rather_than_hover(client):
    body = client.get("/").data.decode("utf-8")
    assert "Click or tap a marker for details" in body
    assert "stay open until dismissed" in body


# --- regression: existing map semantics/controls are unchanged --------------


def test_existing_mode_metric_basemap_theme_and_zoom_controls_still_present(client):
    body = client.get("/").data.decode("utf-8")
    for widget_id in (
        "map-mode-select", "map-metric-select", "map-basemap-select", "map-theme-select",
        "map-zoom-in-btn", "map-zoom-out-btn", "map-fit-btn", "map-reset-btn",
    ):
        assert f'id="{widget_id}"' in body


def test_pan_zoom_keyboard_navigation_functions_are_unchanged(client):
    body = client.get("/").data.decode("utf-8")
    for fn in (
        "mapAttachInteraction", "mapFinishRender", "mapApplyZoomAt",
        "mapClampZoom", "mapClampCenter", "mapBoundingBoxOf", "mapFitToData",
    ):
        assert f"function {fn}(" in body
    assert 'tabindex="0" style="touch-action:none"' in body


def test_reduced_motion_still_suppresses_the_pulse_ring(client):
    body = client.get("/").data.decode("utf-8")
    assert 'html[data-motion="reduced"] .map-bubble-pulse-ring{display:none}' in body
    assert "@media(prefers-reduced-motion:reduce)" in body


def test_bundled_offline_world_landmass_is_unchanged(client):
    """The vector source geometry (WORLD_LAND_D) is unchanged; the follow-up
    redesign only changed how it's rendered (a sampled dot-matrix world,
    mapWorldDots(), instead of one flat filled silhouette)."""
    body = client.get("/").data.decode("utf-8")
    assert "const WORLD_LAND_D" in body
    assert "function mapWorldDots(){" in body
    assert 'class="map-world-dot"' in body


def test_db_ip_attribution_footer_is_preserved(client):
    body = client.get("/").data.decode("utf-8")
    assert "IP Geolocation by" in body
    assert 'href="https://db-ip.com"' in body
    assert "DB-IP Lite, CC BY 4.0" in body


def test_destinations_mode_still_explains_unavailable_coordinate_data_honestly(client):
    body = client.get("/").data.decode("utf-8")
    assert "Coordinate-level destination data is unavailable" in body
    assert "Switch to Countries" in body


def test_clustering_still_sums_rather_than_drops_merged_observations(client):
    body = client.get("/").data.decode("utf-8")
    assert "bucket.observation_count += (p.observation_count || 0)" in body
    assert "bucket.domain_count += (p.domain_count || 0)" in body


def test_map_api_endpoint_and_widget_ids_are_unchanged(client):
    """This is a visual/interaction redesign only -- /api/analytics/map and
    the Dashboard Builder widget/content ids must not move."""
    response = client.get("/api/analytics/map")
    assert response.status_code == 200
    payload = response.get_json()
    for field in ("provider", "coverage", "countries", "unknown", "capabilities"):
        assert field in payload
    body = client.get("/").data.decode("utf-8")
    assert 'data-widget-id="destination-map"' in body
    assert 'id="destination-map"' in body
    assert 'id="destination-map-detail"' in body


def test_no_geoip_configured_state_still_renders_the_map_honestly(client):
    body = client.get("/").data.decode("utf-8")
    assert "No GeoIP database configured" in body
    assert "Server Locations" not in body
