"""Regression/source checks for the Leaflet + OpenStreetMap DNS Destinations
map renderer (Issue #69), which supersedes and replaces the amCharts
experiment as the default map renderer. See docs/LEAFLET_MAP.md."""

from pathlib import Path

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


def test_leaflet_library_and_renderer_are_always_loaded(client):
    body = client.get("/").data.decode("utf-8")
    assert 'href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"' in body
    assert 'src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"' in body
    assert 'src="/static/leaflet-map.js"' in body


def test_amcharts_experiment_is_fully_removed(client):
    body = client.get("/").data.decode("utf-8")
    assert "amcharts" not in body.lower()
    app_source = Path(__file__).resolve().parent.parent.joinpath("app.py").read_text(encoding="utf-8")
    assert "AMCHARTS_MAP_ENABLED" not in app_source
    assert not (STATIC_DIR / "amcharts-map-poc.js").exists()
    assert not (Path(__file__).resolve().parent.parent / "docs" / "AMCHARTS_MAP_POC.md").exists()


def test_leaflet_renderer_source_uses_osm_tiles_and_keeps_fallback_contract():
    source = (STATIC_DIR / "leaflet-map.js").read_text(encoding="utf-8")
    # Leaflet owns the tile layer, using real OpenStreetMap slippy tiles with
    # visible attribution -- not an iframe to openstreetmap.org.
    assert "tile.openstreetmap.org/{z}/{x}/{y}.png" in source
    assert "OpenStreetMap" in source
    assert "<iframe" not in source
    assert "L.tileLayer(" in source
    # Only ever replaces the renderer entry point fetchDestinationMap() calls
    # into; never redefines the fetch owner itself (Issue #61 protections).
    assert "window.renderDestinationMap = update;" in source
    assert "window.fetchDestinationMap" not in source
    assert "new AbortController" not in source
    # Graceful, source-verifiable fallback to the legacy SVG renderer.
    assert "if (!window.L)" in source
    assert "keeping legacy SVG map" in source


def test_leaflet_renderer_reuses_shared_selection_and_breakdown_sync():
    source = (STATIC_DIR / "leaflet-map.js").read_text(encoding="utf-8")
    # Country selection must stay synchronized with the country breakdown
    # panel (Issue #63) by calling the exact same shared functions, rather
    # than re-implementing an independent selection/detail path.
    assert "mapSelectCountry(c.country_code)" in source
    assert "renderMapDetail(" in source
    assert "renderMapBreakdown(data)" in source
    assert "renderMapBreakdownHistory(data)" in source


def test_leaflet_renderer_supports_both_modes_and_future_layer_structure():
    source = (STATIC_DIR / "leaflet-map.js").read_text(encoding="utf-8")
    assert "function renderCountries(" in source
    assert "function renderDestinations(" in source
    assert "state.layers = {" in source
    assert "countries: L.layerGroup()" in source
    assert "destinations: L.layerGroup()" in source


def test_leaflet_renderer_keeps_reduced_motion_support():
    source = (STATIC_DIR / "leaflet-map.js").read_text(encoding="utf-8")
    assert "reducedMotion()" in source
    assert "zoomAnimation: !reducedMotion()" in source

def test_country_breakdown_is_height_constrained_for_scroll():
    app_source = (Path(__file__).resolve().parent.parent / "app.py").read_text(encoding="utf-8")
    # The desktop grid needs a definite breakdown height; otherwise an
    # unbounded country list grows the whole row instead of making the list
    # itself scroll. The formula mirrors the Leaflet map's 2:1 aspect ratio
    # after reserving the 280px breakdown column and 12px gap.
    assert "container-type:inline-size" in app_source
    assert "height:max(320px,calc((100cqw - 292px)/2))" in app_source
    assert "overflow-y:auto" in app_source


# ---- Issue #72: country list UX, basemap layer control, DTC pins ----


def test_selected_marker_has_high_contrast_double_ring_style():
    app_source = (Path(__file__).resolve().parent.parent / "app.py").read_text(encoding="utf-8")
    # The previous single 2px white outline was reported as too subtle
    # against a busy tile background; a white-then-dark double ring (plus a
    # soft shadow) is legible against both light and dark basemap imagery,
    # unlike a single flat color which can vanish against a similar
    # background.
    assert ".leaflet-dns-marker-selected span{outline:none;box-shadow:0 0 0 3px #fff,0 0 0 6px #0b0f14" in app_source
    assert ".leaflet-dns-marker-selected{z-index:1000!important}" in app_source
    source = (STATIC_DIR / "leaflet-map.js").read_text(encoding="utf-8")
    # Selected markers are also drawn above unselected neighbours via a real
    # Leaflet zIndexOffset, not CSS z-index alone (CSS z-index doesn't apply
    # to sibling Leaflet marker panes the same way).
    assert "zIndexOffset: selected ? 1000 : 0" in source


def test_double_click_breakdown_row_focuses_leaflet_map_without_breaking_click():
    app_source = (Path(__file__).resolve().parent.parent / "app.py").read_text(encoding="utf-8")
    # Single click keeps its existing Issue #63 selection/detail behavior...
    assert "btn.addEventListener('click', () => mapSelectCountry(btn.getAttribute('data-breakdown-country'), { toggle: false, centerZoom: true }));" in app_source
    # ...and double-click additionally focuses the real Leaflet viewport,
    # guarded so it's a no-op if Leaflet never initialized.
    assert "btn.addEventListener('dblclick', () => {" in app_source
    assert "window.leafletFocusCountryOnMap" in app_source
    source = (STATIC_DIR / "leaflet-map.js").read_text(encoding="utf-8")
    assert "window.leafletFocusCountryOnMap = function (code) {" in source
    assert "state.map.setView([lat, lon], Math.max(state.map.getZoom(), 5)" in source


def test_leaflet_layer_control_has_osm_and_tracestrack_basemaps():
    source = (STATIC_DIR / "leaflet-map.js").read_text(encoding="utf-8")
    # A real Leaflet layer control (L.control.layers), not a custom <select>,
    # so more basemaps can be registered later without new UI plumbing.
    assert "L.control.layers(baseLayers, overlayLayers" in source
    assert '"OpenStreetMap Standard": { url: OSM_TILE_URL' in source
    assert '"Tracestrack Topo":' in source
    assert "tile.tracestrack.com/topo__/{z}/{x}/{y}.png?key={key}" in source
    assert "tracestrack.com" in source  # attribution link
    # The API key is read from a client-side-only pref, not hard-coded or
    # guessed, and updates the already-created layer in place.
    assert "tracestrackApiKey" in source
    assert "window.mapUpdateTracestrackKey = function (key) {" in source

    app_source = (Path(__file__).resolve().parent.parent / "app.py").read_text(encoding="utf-8")
    assert 'id="map-tracestrack-key-input"' in app_source
    assert "tracestrackApiKey:''" in app_source
    assert "window.mapUpdateTracestrackKey" in app_source


def test_dtc_pins_layer_is_additive_off_by_default_and_cites_sources():
    source = (STATIC_DIR / "leaflet-map.js").read_text(encoding="utf-8")
    assert "const DTC_LOCATIONS = [" in source
    # Off by default: the dtc layer group is created but never .addTo(map)
    # directly (only the layer control can add it, via its checkbox).
    assert "dtc: L.layerGroup()," in source
    assert "L.layerGroup().addTo(map)" in source  # countries only
    assert '"Data Centers (beta)": state.layers.dtc' in source
    # Every seed entry must cite a real source URL, not an invented one.
    for entry_id in ["aws-us-east-1", "aws-eu-west-1", "gcp-us-central1", "azure-eastus", "cloudflare-ams"]:
        assert entry_id in source
    assert source.count("source:") == 5
    assert "no outbound network access to re-verify these entries live" in source
    # The DTC/countries/destinations datasets are visually distinguishable.
    app_source = (Path(__file__).resolve().parent.parent / "app.py").read_text(encoding="utf-8")
    assert ".leaflet-dtc-marker span{" in app_source
