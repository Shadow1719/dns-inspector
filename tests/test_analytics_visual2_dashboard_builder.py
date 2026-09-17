"""Analytics Visual 2.0 + Dashboard Builder + runtime cleanup (Issue #23):
structural regression checks.

Like `test_ui_design_system.py` and `test_settings_and_themes.py`, these
assert markup/hooks exist without pinning exact CSS values or asserting on
client-side JS behaviour (there is no JS runtime in the test suite). The
underlying `/api/analytics` and `/api/state` payload shapes are unchanged by
this release -- see `tests/test_analytics.py` for those -- so this file only
covers the new front-end presentation/customization hooks and the parts of
the runtime cleanup that are visible from the rendered page.
"""


DASH_WIDGET_IDS = (
    "live-overview", "query-volume", "new-domains", "new-devices",
    "status-breakdown", "activity-domains", "activity-devices", "top-activity",
)


def test_analytics_visual_functions_are_distinct_per_style(client):
    """0.8.4 had one `liveGaugeSvg` shared between styles; 0.8.5 replaces it
    with a distinct renderer per visual style so Digital/Analog/Specter are
    genuinely different presentations, not palette variants of one gauge.
    """
    body = client.get("/").data.decode("utf-8")
    for fn in ("digitalRingSvg", "analogGaugeSvg", "specterRadarSvg", "renderMetricVisual"):
        assert f"function {fn}(" in body
    assert "function liveGaugeSvg(" not in body


def test_metric_spike_detection_is_a_real_statistical_outlier_check(client):
    """Timeline/event markers (Issue #23) must be derived from the real
    bucket counts already fetched, not an invented severity/incident model.
    """
    body = client.get("/").data.decode("utf-8")
    assert "function metricSpikeIndices(" in body
    assert "function metricPointLabel(" in body
    assert "metric-marker-dot" in body


def test_metric_readout_shows_current_average_and_peak(client):
    body = client.get("/").data.decode("utf-8")
    assert "metric-readout" in body


def test_dashboard_builder_grid_wraps_every_analytics_widget(client):
    body = client.get("/").data.decode("utf-8")
    assert 'id="analytics-dash-grid"' in body
    for widget_id in DASH_WIDGET_IDS:
        assert f'data-widget-id="{widget_id}"' in body


def test_dashboard_builder_controls_exist(client):
    body = client.get("/").data.decode("utf-8")
    assert 'id="dash-customize-btn"' in body
    assert 'id="dash-reset-btn"' in body
    assert 'id="dash-preset-select"' in body
    for preset in ("default", "monitoring", "compact", "investigation", "custom"):
        assert f'<option value="{preset}"' in body


def test_dashboard_layout_persists_client_side_only(client):
    """Matches the 0.8.x constraint already covered for `dnsInspectorPrefs`
    in test_settings_and_themes.py: no database migration for this either.
    """
    body = client.get("/").data.decode("utf-8")
    assert "dnsInspectorDashboardLayout" in body
    assert "localStorage" in body


def test_settings_dashboard_panel_links_to_the_customize_mode(client):
    body = client.get("/").data.decode("utf-8")
    assert "dash-customize-btn" in body
    assert 'data-settings-panel="dashboard"' in body


def test_overview_and_devices_tables_skip_rendering_while_hidden(client):
    """Runtime cleanup (Issue #23): the background /api/state poll used to
    rebuild the Overview/Devices table innerHTML on every tick regardless of
    which tab was visible. `renderRecent`/`renderClients` now take a `force`
    flag and only do that work when their own tab is active (or explicitly
    forced from cache on tab switch).
    """
    body = client.get("/").data.decode("utf-8")
    assert "function renderRecent(rows,force)" in body
    assert "function renderClients(rows,force)" in body
    assert "tab-overview" in body and "tab-devices" in body


def test_retired_patch_chain_markers_are_gone(client):
    """docs/CURRENT_STATE.md already documents the generated Docker patch
    chain as retired; these were leftover comment labels from it with no
    functional role.
    """
    body = client.get("/").data.decode("utf-8")
    assert "SQLITE CLOSE PATCH" not in body
    assert "DEEP DEBUG BUNDLE PATCH" not in body


def test_dead_pre_dashboard_builder_css_was_removed(client):
    """`.analytics-timeline-grid` / `.activity-feed-grid` / `.live-gauge`
    were fully superseded by the `.dash-grid`/`.dash-widget` structure and
    the new gauge renderers; keeping them would just be dead weight.
    """
    body = client.get("/").data.decode("utf-8")
    assert ".analytics-timeline-grid" not in body
    assert ".activity-feed-grid" not in body
    assert ".live-gauge{" not in body
    assert ".live-gauge svg" not in body


def test_new_widgets_are_reconciled_into_saved_layouts_at_their_default_position(client):
    """Issue #31: a widget shipped in a later release (e.g. the 0.8.5.1
    `destination-map`/`instrument-gauges` widgets) is absent from any
    `dnsInspectorDashboardLayout` an older build already persisted, and from
    every named preset's own hard-coded reorder list. Blindly appending such
    ids to the very end of `order` buried them below everything a returning
    user's browser already had saved -- on a long dashboard that reads as
    "the widget is gone", not "the widget moved", and required the operator
    to manually clear localStorage to see it. `loadLayout()` and
    `presetLayout()` must reconcile missing ids next to their default
    neighbour instead of pushing them past the end of a pre-existing order.
    """
    body = client.get("/").data.decode("utf-8")
    assert "function insertWidgetsAtDefaultPosition(order, defaultOrder){" in body
    # Both the saved-layout merge and every named preset must run their
    # widget ids through the reconciliation helper rather than trusting a
    # stale/hard-coded order verbatim.
    assert (
        "const order = insertWidgetsAtDefaultPosition("
        "raw.order.filter(id => WIDGET_IDS.includes(id)), DEFAULT_LAYOUT.order);"
    ) in body
    assert "base.order = insertWidgetsAtDefaultPosition(base.order, DEFAULT_LAYOUT.order);" in body
    # The old blind-append merge (`if (!order.includes(id)) order.push(id)`)
    # is the exact bug this regresses -- it must not come back.
    assert "if (!order.includes(id)) order.push(id)" not in body


def test_device_detail_reuses_the_dashboard_builder_free_shell(app_module, client):
    """Regression guard matching the equivalent checks in
    test_ui_design_system.py / test_settings_and_themes.py: the device/IP
    detail views share the one `HTML` template shell, not a divergent copy.
    """
    response = client.get("/device?key=does-not-exist")
    assert response.status_code == 404
    body = response.data.decode("utf-8")
    assert 'class="app-shell"' in body
    assert 'id="settings-dialog"' in body
