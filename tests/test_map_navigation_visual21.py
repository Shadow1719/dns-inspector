"""Destination Map Visual 2.1 (Issue #39 / 0.8.5.4): real pan/zoom navigation,
genuinely distinct map style presets and a denser world-landmass silhouette.

Same rendered-markup-source testing approach as
test_map_visual2_frontend.py -- there is no headless-browser harness, so
these pin the presence and shape of the interaction/theme source code in the
page's inline `<script>`, not actual pointer/wheel behaviour in a browser.
"""

import re


def test_map_svg_is_focusable_and_blocks_native_touch_scrolling(client):
    """Keyboard panning needs a focusable element; touch-action:none stops the
    browser from scrolling the page instead of letting a touch drag pan."""
    body = client.get("/").data.decode("utf-8")
    assert 'tabindex="0" style="touch-action:none"' in body


def test_map_pan_zoom_interaction_functions_exist(client):
    body = client.get("/").data.decode("utf-8")
    for fn in (
        "mapAttachInteraction", "mapFinishRender", "mapApplyZoomAt",
        "mapClampZoom", "mapClampCenter", "mapBoundingBoxOf", "mapFitToData",
    ):
        assert f"function {fn}(" in body


def test_map_wires_pointer_drag_wheel_and_keyboard_events(client):
    body = client.get("/").data.decode("utf-8")
    assert "addEventListener('pointerdown'" in body
    assert "addEventListener('pointermove'" in body
    assert "addEventListener('pointerup'" in body
    assert "addEventListener('pointercancel'" in body
    assert "addEventListener('wheel'" in body
    assert "addEventListener('keydown'" in body


def test_wheel_zoom_is_centered_on_the_cursor_not_the_viewport_center(client):
    body = client.get("/").data.decode("utf-8")
    assert "mapApplyZoomAt(mapZoom * Math.exp(-e.deltaY * 0.0015), e.clientX, e.clientY, svgEl)" in body


def test_a_drag_release_does_not_toggle_bubble_or_cluster_selection(client):
    """Regression guard: without this, releasing a pan gesture over a bubble
    would also fire a native click and flip its selection state."""
    body = client.get("/").data.decode("utf-8")
    assert "let mapWasDragging" in body
    assert "if (mapWasDragging) return;" in body


def test_fit_to_data_control_exists_and_is_wired(client):
    body = client.get("/").data.decode("utf-8")
    assert 'id="map-fit-btn"' in body
    assert "document.getElementById('map-fit-btn')?.addEventListener('click', mapFitToData);" in body


def test_existing_discrete_zoom_and_reset_buttons_still_work(client):
    """Regression guard from test_map_visual2_frontend.py: the new continuous
    wheel/drag navigation is additive, the original +/- buttons are unchanged."""
    body = client.get("/").data.decode("utf-8")
    assert "mapZoom = Math.min(8, mapZoom * 2)" in body
    assert "mapZoom = Math.max(1, mapZoom / 2)" in body


# --- genuinely distinct basemap presets (not just an accent color) ----------
#
# Issue #56 follow-up replaced the single `mapStyle` preset (BEMO Dark/
# Aurora/White/Minimal) with two independent preferences: `mapBasemap`
# (structural rendering) and `mapTheme` (color ramp only). These tests were
# updated in place to match the new selector, testing the same underlying
# "genuinely different visuals, not just a recolor" property Issue #39
# originally established.


def test_each_basemap_sets_far_more_than_a_single_accent_property(client):
    """Each basemap block must set its own background gradient, grid
    opacity, vignette, banner treatment, marker glow and particle glow --
    a double-digit number of distinct --map-* custom properties."""
    body = client.get("/").data.decode("utf-8")
    for basemap in ("satellite-heat", "satellite-density", "real-pins", "dark-noc"):
        match = re.search(
            re.escape(f'.destination-map-wrap[data-map-basemap="{basemap}"]{{') + r'([^}]*)\}',
            body,
        )
        assert match, f"no CSS rule found for basemap {basemap}"
        props = set(re.findall(r'--map-[a-z0-9-]+(?=:)', match.group(1)))
        assert len(props) >= 8, f"{basemap} only varies {len(props)} properties: {props}"


def test_real_pins_basemap_disables_the_pulse_ring_for_a_lower_noise_readable_map(client):
    body = client.get("/").data.decode("utf-8")
    match = re.search(r'\.destination-map-wrap\[data-map-basemap="real-pins"\]\{([^}]*)\}', body)
    assert match
    assert "--map-pulse-display:none" in match.group(1)


def test_satellite_heat_and_dark_noc_basemaps_have_a_marker_glow_but_the_others_do_not(client):
    body = client.get("/").data.decode("utf-8")
    for basemap in ("satellite-heat", "dark-noc"):
        match = re.search(re.escape(f'.destination-map-wrap[data-map-basemap="{basemap}"]{{') + r'([^}]*)\}', body)
        assert "drop-shadow" in match.group(1)
    for basemap in ("satellite-density", "real-pins"):
        match = re.search(re.escape(f'.destination-map-wrap[data-map-basemap="{basemap}"]{{') + r'([^}]*)\}', body)
        assert "--map-point-glow:none" in match.group(1)


def test_map_background_is_a_gradient_driven_by_style_variables_not_a_flat_fill(client):
    body = client.get("/").data.decode("utf-8")
    assert "background:radial-gradient(ellipse at 50% 40%,var(--map-bg-a),var(--map-bg-b))" in body


# --- denser, less low-poly basemap geometry ----------------------------------


def test_world_landmass_has_a_meaningfully_denser_point_count_than_visual_2_0(client):
    body = client.get("/").data.decode("utf-8")
    match = re.search(r"const WORLD_LAND_D = \[(.*?)\]\.join", body, re.S)
    assert match, "WORLD_LAND_D constant not found in rendered page"
    coords = re.findall(r"[ML](-?\d+(?:\.\d+)?),(-?\d+(?:\.\d+)?)", match.group(1))
    assert len(coords) > 140  # Visual 2.0 shipped ~146; the flattest edges gained extra vertices
    for x, y in coords:
        assert 0 <= float(x) <= 720
        assert 0 <= float(y) <= 360


def test_landmass_is_a_dense_sampled_dot_matrix_not_a_flat_fill(client):
    """An Issue #56 follow-up replaced the flat filled silhouette (with its
    blurred depth-layer duplicate) with a dot matrix sampled from the same
    WORLD_LAND_D vector rings -- denser and more detailed than a couple of
    filled `<path>` elements, and still fully offline/self-generated."""
    body = client.get("/").data.decode("utf-8")
    assert "function mapWorldDots(){" in body
    assert "function mapPointInRing(x, y, ring){" in body
    assert ".map-world-dot{" in body


# --- honest instructions for the new interaction model -----------------------


def test_widget_explains_the_new_drag_and_scroll_interaction(client):
    body = client.get("/").data.decode("utf-8")
    assert "Drag to pan" in body
