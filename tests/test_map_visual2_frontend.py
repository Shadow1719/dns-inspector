"""Destination Map Visual 2.0 rendered-markup checks (Issue #37 / 0.8.6);
Basemap/Theme split (Issue #61).

The Inspector's UI has no headless-browser test harness (see the existing
pattern in test_geoip_destinations_map.py) -- these tests assert against the
rendered page's HTML/inline-JS source, the same style already used for the
0.8.5.1/0.8.5.2 map and the Dashboard Builder. They pin: the mode/metric/
basemap/theme controls exist and are wired to the shared `dnsInspectorPrefs`
mechanism, the four basemaps and three themes are genuinely independent
axes (and independent of the app theme), clustering/zoom/reset exist, and
the honest-semantics/empty-state copy from earlier releases is preserved.
"""

import re


def test_default_prefs_include_map_mode_metric_basemap_and_theme(client):
    body = client.get("/").data.decode("utf-8")
    match = re.search(r"const DEFAULT_PREFS = \{(.*?)\};", body)
    assert match, "DEFAULT_PREFS not found in rendered page"
    defaults = match.group(1)
    assert "mapMode:'countries'" in defaults
    assert "mapMetric:'observations'" in defaults
    assert "mapBasemap:'dark-noc'" in defaults
    assert "mapTheme:'bemo-dark-accent'" in defaults


def test_map_basemap_and_theme_preferences_are_independent_of_each_other_and_of_the_application_theme(client):
    """`theme` (application), `mapBasemap` (background/rendering strategy)
    and `mapTheme` (map palette) must be three distinct `dnsInspectorPrefs`
    keys, each settable without touching the others -- not derived from
    `html[data-theme]`."""
    body = client.get("/").data.decode("utf-8")
    assert "mapBasemap:" in body
    assert "mapTheme:" in body
    assert "theme:'bemo-dark'" in body
    assert "data-map-basemap" in body
    assert "data-map-theme" in body


def test_old_map_style_preference_migrates_to_a_basemap_default(client):
    """A browser with an older `dnsInspectorPrefs.mapStyle` saved (pre-Issue
    #61) must not silently lose its choice -- loadPrefs() maps it to the
    closest new `mapBasemap` value the first time prefs are loaded."""
    body = client.get("/").data.decode("utf-8")
    assert "MAP_STYLE_TO_BASEMAP_MIGRATION" in body
    assert "'bemo-dark':'dark-noc'" in body


def test_widget_exposes_mode_metric_basemap_theme_and_zoom_controls(client):
    body = client.get("/").data.decode("utf-8")
    assert 'id="map-mode-select"' in body
    assert 'id="map-metric-select"' in body
    assert 'id="map-basemap-select"' in body
    assert 'id="map-theme-select"' in body
    assert 'id="map-zoom-in-btn"' in body
    assert 'id="map-zoom-out-btn"' in body
    assert 'id="map-reset-btn"' in body
    assert '<option value="countries">Countries</option>' in body
    assert '<option value="destinations">Destinations</option>' in body
    assert '<option value="dark-noc">Dark NOC / Urban</option>' in body
    assert '<option value="satellite-heat">Satellite Heat</option>' in body
    assert '<option value="satellite-density">Satellite Density</option>' in body
    assert '<option value="real-pins">Real Map / Pins</option>' in body
    assert '<option value="bemo-dark-accent">BEMO Dark Accent</option>' in body
    assert '<option value="indigo-gold">Indigo + Gold</option>' in body
    assert '<option value="cyan">Cyan</option>' in body


def test_all_four_basemaps_have_a_dedicated_css_rule(client):
    body = client.get("/").data.decode("utf-8")
    for basemap in ("dark-noc", "satellite-heat", "satellite-density", "real-pins"):
        assert f'.destination-map-wrap[data-map-basemap="{basemap}"]{{' in body


def test_all_three_themes_have_a_dedicated_css_rule(client):
    body = client.get("/").data.decode("utf-8")
    for theme in ("bemo-dark-accent", "indigo-gold", "cyan"):
        assert f'.destination-map-wrap[data-map-theme="{theme}"]{{' in body


def test_basemap_marker_builder_branches_on_basemap_not_theme(client):
    """mapEntityMarkerSvg() -- the one shared marker builder for both
    Countries bubbles and Destinations clusters -- must branch its rendering
    *strategy* on the selected Basemap (real pins / heat glow / particle
    field / classic pulse bubble), not merely recolor one shape."""
    body = client.get("/").data.decode("utf-8")
    assert "function mapEntityMarkerSvg(" in body
    for marker_case in ("'real-pins'", "'satellite-heat'", "'satellite-density'"):
        assert f"basemap === {marker_case}" in body
    assert "map-density-particle" in body
    assert "map-heat-glow" in body
    assert "map-pin" in body


def test_satellite_density_particles_are_deterministically_seeded(client):
    """Particle jitter must be seeded from the entity's own stable key, not
    Math.random()/Date.now(), so refreshes never make the map visually jump
    for unchanged data."""
    body = client.get("/").data.decode("utf-8")
    assert "function seededRandomFor(" in body
    assert "function mulberry32(" in body


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
