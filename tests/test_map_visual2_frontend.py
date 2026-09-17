"""Destination Map Visual 2.0 rendered-markup checks (Issue #37 / 0.8.6).

The Inspector's UI has no headless-browser test harness (see the existing
pattern in test_geoip_destinations_map.py) -- these tests assert against the
rendered page's HTML/inline-JS source, the same style already used for the
0.8.5.1/0.8.5.2 map and the Dashboard Builder. They pin: the new mode/
metric/style controls exist and are wired to the shared `dnsInspectorPrefs`
mechanism, the four map styles are genuinely independent of the app theme,
clustering/zoom/reset exist, and the honest-semantics/empty-state copy from
earlier releases is preserved.
"""

import re


def test_default_prefs_include_map_mode_metric_and_style(client):
    body = client.get("/").data.decode("utf-8")
    match = re.search(r"const DEFAULT_PREFS = \{(.*?)\};", body)
    assert match, "DEFAULT_PREFS not found in rendered page"
    defaults = match.group(1)
    assert "mapMode:'countries'" in defaults
    assert "mapMetric:'observations'" in defaults
    assert "mapStyle:'bemo-dark'" in defaults


def test_map_style_preference_is_independent_of_the_application_theme_preference(client):
    """`theme` (application) and `mapStyle` (map) must be two distinct
    `dnsInspectorPrefs` keys, each settable without touching the other --
    not derived from `html[data-theme]`."""
    body = client.get("/").data.decode("utf-8")
    assert "mapStyle:" in body
    assert "theme:'bemo-dark'" in body
    assert "data-map-style" in body


def test_widget_exposes_mode_metric_style_and_zoom_controls(client):
    body = client.get("/").data.decode("utf-8")
    assert 'id="map-mode-select"' in body
    assert 'id="map-metric-select"' in body
    assert 'id="map-style-select"' in body
    assert 'id="map-zoom-in-btn"' in body
    assert 'id="map-zoom-out-btn"' in body
    assert 'id="map-reset-btn"' in body
    assert '<option value="countries">Countries</option>' in body
    assert '<option value="destinations">Destinations</option>' in body
    assert '<option value="bemo-dark">BEMO Dark</option>' in body
    assert '<option value="aurora">Aurora</option>' in body
    assert '<option value="white">White</option>' in body
    assert '<option value="minimal">Minimal</option>' in body


def test_all_four_map_styles_have_a_dedicated_css_rule(client):
    body = client.get("/").data.decode("utf-8")
    for style in ("bemo-dark", "aurora", "white", "minimal"):
        assert f'.destination-map-wrap[data-map-style="{style}"]{{' in body


def test_map_render_functions_for_visual_2_exist(client):
    body = client.get("/").data.decode("utf-8")
    for fn in (
        "renderCountriesMode", "renderDestinationsMode", "clusterDestinationPoints",
        "mapMetricValue", "mapViewBoxAttr", "syncMapControls",
    ):
        assert f"function {fn}(" in body


def test_destinations_mode_explains_unavailable_coordinate_data_rather_than_faking_it(client):
    body = client.get("/").data.decode("utf-8")
    assert "Coordinate-level destination data is unavailable" in body
    assert "Switch to Countries" in body


def test_clustering_never_drops_observations_when_merging_points(client):
    """clusterDestinationPoints() must sum (not overwrite) observation_count
    and domain_count across merged points -- pinning the aggregation shape
    so a future edit can't silently start discarding merged data."""
    body = client.get("/").data.decode("utf-8")
    assert "bucket.observation_count += (p.observation_count || 0)" in body
    assert "bucket.domain_count += (p.domain_count || 0)" in body


def test_zoom_and_reset_controls_are_wired_to_map_state(client):
    body = client.get("/").data.decode("utf-8")
    assert "mapZoom = Math.min(8, mapZoom * 2)" in body
    assert "mapZoom = Math.max(1, mapZoom / 2)" in body
    assert "map-reset-btn" in body


# --- regression: existing honest-semantics/empty-state copy is preserved ----


def test_no_geoip_configured_banner_copy_is_preserved(client):
    body = client.get("/").data.decode("utf-8")
    assert "No GeoIP database configured" in body
    assert "observed" in body.lower()
    assert "Server Locations" not in body


def test_countries_mode_plotted_vs_total_copy_is_preserved(client):
    body = client.get("/").data.decode("utf-8")
    assert "geolocated countries plotted" in body


def test_countries_mode_still_renders_the_bundled_background_behind_bubbles(client):
    """Regression guard: Countries mode's non-empty render path must still
    produce the exact `mapBaseSvg(...)` call this behaviour has always used,
    even after the Visual 2.0 mode/style/metric rework."""
    body = client.get("/").data.decode("utf-8")
    assert "mapBaseSvg('Observed DNS destinations by country', bubbles)" in body


def test_reduced_motion_still_suppresses_the_map_pulse_ring(client):
    body = client.get("/").data.decode("utf-8")
    assert 'html[data-motion="reduced"] .map-bubble-pulse-ring{display:none}' in body


def test_world_landmass_asset_is_still_bundled_and_offline_safe(client):
    body = client.get("/").data.decode("utf-8")
    assert "const WORLD_LAND_D" in body
    assert 'class="map-landmass"' in body


def test_destination_map_widget_ids_are_unchanged(client):
    """Dashboard Builder layout persistence (Issue #31) keys widgets by
    `data-widget-id` -- Visual 2.0 must not rename the widget or its content
    container ids, or every saved layout would lose this widget's position."""
    body = client.get("/").data.decode("utf-8")
    assert 'data-widget-id="destination-map"' in body
    assert 'id="destination-map"' in body
    assert 'id="destination-map-detail"' in body
