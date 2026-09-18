"""DNS Destinations map basemap/theme split and deterministic density
rendering (Issue #56 follow-up, 0.8.5.x).

Same rendered-markup-source testing approach as test_map_visual2_frontend.py
and test_map_infographic_visual3.py -- there is no headless-browser harness,
so these pin: the two independent `mapBasemap`/`mapTheme` selectors and their
CSS, the offline dot-matrix world (mapWorldDots()) recoloring in place rather
than a separate overlay, deterministic (seeded, never Math.random()) bounded
particle placement/count that scales with observed volume, click/keyboard
activation resolving any particle in a cluster to the real underlying entity,
the "not independent physical servers" disclosure, and that
`/api/analytics/map`'s existing fields are unchanged (no invented metric).
"""

import re


# --- two independent selectors, not seven arbitrary styles -------------------


def test_basemap_and_theme_are_two_distinct_constant_lists(client):
    body = client.get("/").data.decode("utf-8")
    match = re.search(r"const MAP_BASEMAPS = \[(.*?)\];", body)
    assert match, "MAP_BASEMAPS not found in rendered page"
    basemaps = re.findall(r"'([a-z-]+)'", match.group(1))
    assert basemaps == ["satellite-heat", "satellite-density", "real-pins", "dark-noc"]
    match = re.search(r"const MAP_THEMES = \[(.*?)\];", body)
    assert match, "MAP_THEMES not found in rendered page"
    themes = re.findall(r"'([a-z-]+)'", match.group(1))
    assert themes == ["indigo-gold", "cyan", "bemo-accent"]


def test_basemap_and_theme_attributes_are_both_set_on_every_render_path(client):
    """Even the empty/unconfigured-GeoIP render paths go through mapBaseSvg(),
    so both attributes must always be present, not only once real data
    exists."""
    body = client.get("/").data.decode("utf-8")
    assert 'data-map-basemap="${esc(basemap)}"' in body
    assert 'data-map-theme="${esc(theme)}"' in body
    assert "No GeoIP database configured" in body


def test_theme_color_stops_preserve_low_to_high_ordering_per_theme(client):
    body = client.get("/").data.decode("utf-8")
    match = re.search(r"const MAP_THEME_STOPS = \{(.*?)\n\};", body, re.S)
    assert match, "MAP_THEME_STOPS not found in rendered page"
    block = match.group(1)
    for theme in ("indigo-gold", "cyan"):
        theme_match = re.search(re.escape(f"'{theme}': [") + r"(.*?)\]", block, re.S)
        assert theme_match, f"no stops found for theme {theme}"
        lightness = [int(l) for l in re.findall(r"l:\s*(\d+)", theme_match.group(1))]
        assert len(lightness) >= 4
        assert lightness[0] < lightness[-1]  # low intensity is dimmer than high


# --- deterministic, bounded particle density -----------------------------


def test_particle_placement_is_seeded_not_math_random(client):
    body = client.get("/").data.decode("utf-8")
    assert "function mapSeedFromString(s){" in body
    assert "function mapMulberry32(seed){" in body
    assert "function mapParticleOffsets(id, count, spread){" in body
    assert "mapMulberry32(mapSeedFromString(String(id)))" in body
    assert "Math.random" not in body


def test_particle_count_scales_with_intensity_ratio_and_is_bounded_per_basemap(client):
    body = client.get("/").data.decode("utf-8")
    assert "function mapParticleCount(ratio, cap){" in body
    assert "function mapParticleCap(basemap){" in body
    # real-pins never scatters (a single pin glyph instead); heat is capped
    # lower (a few large glowing blobs); density/NOC allow the most points.
    assert "if (basemap === 'real-pins') return 1;" in body
    assert "if (basemap === 'satellite-heat') return 5;" in body
    assert "return 14; // satellite-density, dark-noc" in body


def test_basemap_determines_how_activity_particles_are_drawn(client):
    body = client.get("/").data.decode("utf-8")
    assert "class=\"map-particle map-particle-heat\"" in body
    assert "class=\"map-particle map-particle-density\"" in body
    assert "class=\"map-particle map-particle-noc\"" in body
    assert 'class="map-pin"' in body
    for rule in (".map-particle-heat{", ".map-particle-density{", ".map-particle-noc{", ".map-pin{"):
        assert rule in body


# --- "the data is the map": real dots recolor, not a flat overlay -----------


def test_observed_activity_recolors_the_worlds_own_dots_in_place(client):
    body = client.get("/").data.decode("utf-8")
    assert "function mapActiveDotRatios(entities){" in body
    assert "map-world-dot-active" in body
    assert "mapThemeColor(ratio, theme)" in body


def test_active_dot_radius_and_color_both_scale_with_the_entitys_own_ratio(client):
    body = client.get("/").data.decode("utf-8")
    assert "r=\"${(1.2 + ratio * 1.4).toFixed(1)}\"" in body


def test_entities_feeding_the_dot_overlay_reuse_the_same_projected_coordinates(client):
    """The dot-overlay entities are the exact same {x, y, ratio} the markers
    themselves are drawn from -- never a second, possibly-diverging
    computation or a fabricated coordinate."""
    body = client.get("/").data.decode("utf-8")
    assert "const entitiesForDots = countries.map(c => {" in body
    assert "const entitiesForDots = clusters.map(c => ({ x: c.x, y: c.y, ratio: mapMetricValue(c) / maxVal }));" in body


# --- click/tap/keyboard on any particle resolves to the real entity ---------


def test_interactive_attributes_live_on_the_wrapping_group_not_individual_particles(client):
    """A dense particle cloud must resolve to the one real underlying
    country/destination entity when clicked/tapped/keyboard-activated
    anywhere in it -- achieved by putting `data-country`/`data-cluster`,
    `tabindex`, `role` and `aria-pressed` on the shared wrapper `<g>`."""
    body = client.get("/").data.decode("utf-8")
    assert 'function mapEntityMarkup(opts){' in body
    assert '<g class="map-entity" ${attr}="${esc(id)}" tabindex="0" role="button"' in body
    assert 'class="map-hit-area"' in body
    assert '.map-hit-area{fill:transparent;pointer-events:all}' in body


def test_countries_and_destinations_modes_both_use_the_shared_entity_renderer(client):
    body = client.get("/").data.decode("utf-8")
    assert "return mapEntityMarkup({ id: c.country_code, attr: 'data-country'" in body
    assert "return mapEntityMarkup({ id: c.key, attr: 'data-cluster'" in body


# --- no fabricated locations / not independent physical servers ------------


def test_legend_discloses_particles_are_an_intensity_visualization_not_real_servers(client):
    body = client.get("/").data.decode("utf-8")
    assert "not independent physical servers" in body


# --- legend/controls explain both selectors ---------------------------------


def test_widget_copy_explains_basemap_vs_theme_distinction(client):
    body = client.get("/").data.decode("utf-8")
    assert "Basemap picks how activity is drawn" in body
    assert "theme only recolors the intensity ramp" in body


def test_legend_gradient_is_kept_in_sync_with_the_selected_theme(client):
    body = client.get("/").data.decode("utf-8")
    assert "function mapSyncLegendGradient(){" in body
    assert "mapSyncLegendGradient();" in body
    assert 'id="map-legend-gradient"' in body


# --- regression: existing map API/semantics are unchanged -------------------


def test_map_api_payload_shape_is_unchanged_no_invented_metric(client):
    response = client.get("/api/analytics/map")
    assert response.status_code == 200
    payload = response.get_json()
    for field in ("provider", "coverage", "countries", "unknown", "capabilities"):
        assert field in payload


def test_reduced_motion_still_suppresses_pulse_and_marker_transitions(client):
    body = client.get("/").data.decode("utf-8")
    assert 'html[data-motion="reduced"] .map-bubble-pulse-ring{display:none}' in body
    assert "@media(prefers-reduced-motion:reduce){" in body
    assert ".map-bubble{transition:none!important}" in body
