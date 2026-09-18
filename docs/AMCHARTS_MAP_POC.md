# amCharts map experiment

This is an isolated 0.8.5.14 experiment and is not merged into dev.

Enable with AMCHARTS_MAP_ENABLED=1. The default remains the existing SVG renderer.

This experiment tests amCharts 5 MapChart with MapPolygonSeries for countries and ClusteredPointSeries for observed destination IPs. It keeps the existing /api/analytics/map payload and the existing polling owner. The key test is that map geometry, grid, markers, pan and zoom all transform together.

The photographic satellite tile layer is deliberately not part of this first experiment. Once the vector behavior is confirmed, a raster/tile layer can be synchronized against the same chart viewport instead of being a fixed CSS background.

The amCharts main package is pinned to 5.20.6 for the experiment; worldLow geodata is loaded from the amCharts CDN. The free build keeps amCharts branding.