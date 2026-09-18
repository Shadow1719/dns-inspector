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
