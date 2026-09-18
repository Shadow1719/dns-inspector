"""Regression/source checks for the opt-in amCharts map experiment."""

def test_amcharts_map_experiment_can_be_enabled(app_module, client, monkeypatch):
    monkeypatch.setattr(app_module, "AMCHARTS_MAP_ENABLED", True)
    body = client.get("/").data.decode("utf-8")
    assert 'src="https://cdn.amcharts.com/lib/version/5.20.6/index.js"' in body
    assert 'src="https://cdn.amcharts.com/lib/version/5.20.6/map.js"' in body
    assert 'src="https://cdn.amcharts.com/lib/5/geodata/worldLow.js"' in body
    assert 'src="/static/amcharts-map-poc.js"' in body

def test_amcharts_renderer_does_not_replace_fetchDestinationMap_source():
    from pathlib import Path
    source = (Path(__file__).resolve().parent.parent / "static" / "amcharts-map-poc.js").read_text(encoding="utf-8")
    assert "window.renderDestinationMap = update;" in source
    assert "window.fetchDestinationMap =" not in source
    assert "ClusteredPointSeries" in source
