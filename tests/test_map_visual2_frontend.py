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
    """0.8.5.4 (Issue #39): zoom is continuous (pointer drag pan, wheel/pinch
    zoom, keyboard) rather than the old fixed power-of-two steps -- both the
    +/- buttons and every other zoom entry point funnel through the shared
    `mapZoomAt()` helper so they all respect the same clamp/anchor logic."""
    body = client.get("/").data.decode("utf-8")
    assert "function mapZoomAt(factor, anchor){" in body
    assert "mapZoomAt(1.6, mapViewCenter)" in body
    assert "mapZoomAt(1 / 1.6, mapViewCenter)" in body
    assert "map-reset-btn" in body
    assert "map-fit-btn" in body


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


# --- Visual 2.1 (Issue #39): real pan/zoom navigation ------------------------


def test_pointer_drag_pan_functions_exist(client):
    body = client.get("/").data.decode("utf-8")
    for fn in ("mapOnPointerDown", "mapOnPointerMove", "mapOnPointerUp", "initMapInteraction"):
        assert f"function {fn}(" in body


def test_wheel_and_keyboard_navigation_functions_exist(client):
    body = client.get("/").data.decode("utf-8")
    assert "function mapOnWheel(" in body
    assert "function mapOnKeydown(" in body
    assert "addEventListener('wheel', mapOnWheel, { passive: false })" in body


def test_fit_to_data_control_exists_and_is_wired(client):
    body = client.get("/").data.decode("utf-8")
    assert 'id="map-fit-btn"' in body
    assert "function mapFitToData(){" in body
    assert "document.getElementById('map-fit-btn')?.addEventListener('click', mapFitToData)" in body


def test_map_svg_is_keyboard_focusable_and_describes_its_controls(client):
    body = client.get("/").data.decode("utf-8")
    assert 'tabindex="0"' in body
    assert "Drag to pan" in body


def test_map_uses_touch_action_none_so_the_browser_does_not_intercept_pan_gestures(client):
    body = client.get("/").data.decode("utf-8")
    assert "touch-action:none" in body


def test_drag_does_not_trigger_a_spurious_bubble_click(client):
    """A pan that ends on top of a bubble/cluster must not also toggle that
    element's own click-to-select handler -- see the capture-phase guard in
    `initMapInteraction()`."""
    body = client.get("/").data.decode("utf-8")
    assert "mapLastDragMoved" in body
    assert "e.stopPropagation(); e.preventDefault(); mapLastDragMoved = false;" in body


def test_zoom_is_continuous_and_clamped_not_fixed_power_of_two_steps(client):
    body = client.get("/").data.decode("utf-8")
    assert "const MAP_ZOOM_MIN = 1, MAP_ZOOM_MAX = 16;" in body
    assert "function mapClampZoom(z){" in body
    assert "function mapClampCenter(cx, cy){" in body


# --- Visual 2.1 (Issue #39): genuinely distinct map style presets ------------


def test_each_map_style_varies_more_than_just_the_accent_color(client):
    """Each style must vary background treatment, coastline glow, graticule
    dash pattern and banner colors -- not only the point/accent color -- or
    switching styles just re-tints the same flat map."""
    body = client.get("/").data.decode("utf-8")
    style_blocks = {}
    for style in ("bemo-dark", "aurora", "white", "minimal"):
        match = re.search(
            r'\.destination-map-wrap\[data-map-style="%s"\]\{([^}]*)\}' % re.escape(style), body,
        )
        assert match, f"no CSS rule found for style {style}"
        style_blocks[style] = match.group(1)
    # Every style must define its own ocean/background treatment, coastline
    # glow and graticule dash pattern, not just reuse the default.
    for style, block in style_blocks.items():
        assert "--map-bg:" in block, style
        assert "--map-land-glow:" in block, style
        assert "--map-grid-dash:" in block, style
        assert "--map-banner-bg:" in block, style
    # And those values must actually differ across styles, not merely be
    # re-declared identically.
    backgrounds = {style: block.split("--map-bg:")[1].split(";")[0] for style, block in style_blocks.items()}
    assert len(set(backgrounds.values())) == 4
    banners = {style: block.split("--map-banner-bg:")[1].split(";")[0] for style, block in style_blocks.items()}
    assert len(set(banners.values())) == 4


def test_bemo_dark_and_aurora_have_distinct_grid_treatments(client):
    body = client.get("/").data.decode("utf-8")
    assert "--map-grid-dash:1,4" in body  # aurora's atmospheric dashed graticule
    assert '.destination-map-wrap[data-map-style="minimal"]{' in body


def test_map_ocean_backgrounds_are_gradients_not_flat_fills(client):
    """Depth/contrast requirement: the ocean/background treatment should read
    as gradient depth, not a single flat fill color, for the non-minimal
    styles."""
    body = client.get("/").data.decode("utf-8")
    for style in ("bemo-dark", "aurora", "white"):
        match = re.search(
            r'\.destination-map-wrap\[data-map-style="%s"\]\{([^}]*)\}' % re.escape(style), body,
        )
        assert "radial-gradient(" in match.group(1), style


def test_map_svg_renders_a_vignette_box_shadow_for_depth(client):
    body = client.get("/").data.decode("utf-8")
    assert "box-shadow:var(--map-vignette)" in body
    assert "--map-vignette:" in body


def test_status_banner_uses_map_style_colors_not_app_theme_surface_colors(client):
    """The empty-state banner must vary per map style (Issue #39 item 3),
    independent of the application theme -- it must not fall back to the
    generic `--surface-1`/`--border`/`--text-secondary` app-theme tokens."""
    body = client.get("/").data.decode("utf-8")
    assert ".map-status-banner{position:absolute" in body
    assert "background:var(--map-banner-bg)" in body
    assert "border:1px solid var(--map-banner-border)" in body
    assert "color:var(--map-banner-color)" in body
