import sys


def _fresh_app(monkeypatch, tmp_path, env=None):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "inspector.db"))
    monkeypatch.setenv("TRACKERDB_PATH", str(tmp_path / "trackerdb.sqlite"))
    monkeypatch.setenv("AGH_URL", "")
    monkeypatch.setenv("NEIGHBORS_PATH", str(tmp_path / "neighbors.txt"))
    if env is None:
        monkeypatch.delenv("DNS_INSPECTOR_ENV", raising=False)
    else:
        monkeypatch.setenv("DNS_INSPECTOR_ENV", env)
    sys.modules.pop("app", None)
    import app
    return app


def test_environment_defaults_to_production_and_selects_prod_assets(monkeypatch, tmp_path):
    app = _fresh_app(monkeypatch, tmp_path)
    assert app.RUNTIME_ENV == "production"
    ctx = app._environment_render_context()
    assert ctx["is_dev_environment"] is False
    assert ctx["favicon_path"] == "/static/favicon.svg"
    assert ctx["page_title"] == "DNS Inspector"


def test_environment_development_selects_dev_assets(monkeypatch, tmp_path):
    app = _fresh_app(monkeypatch, tmp_path, "development")
    assert app.RUNTIME_ENV == "development"
    ctx = app._environment_render_context()
    assert ctx["is_dev_environment"] is True
    assert ctx["favicon_path"] == "/static/favicon-dev.svg"
    assert ctx["page_title"] == f"DNS Inspector DEV v{app.APP_VERSION}"


def test_root_route_renders_dashboard_html_not_analytics_json(monkeypatch, tmp_path):
    app = _fresh_app(monkeypatch, tmp_path, "development")
    app.init_db()
    client = app.app.test_client()

    response = client.get("/")
    assert response.status_code == 200
    assert response.content_type.startswith("text/html")
    body = response.get_data(as_text=True)
    assert "DNS Inspector" in body
    assert "DEVELOPMENT ENVIRONMENT" in body
    assert "/static/favicon-dev.svg" in body


def test_health_and_analytics_payload_expose_clean_runtime_state(monkeypatch, tmp_path):
    app = _fresh_app(monkeypatch, tmp_path, "development")
    app.init_db()
    client = app.app.test_client()

    health = client.get("/health").get_json()
    assert health["environment"] == "development"
    assert health["version"] == app.APP_VERSION

    analytics = client.get("/api/analytics?range=1h").get_json()
    assert analytics["range"] == "1h"
    assert len(analytics["series"]["queries"]["points"]) == 60
    assert len(analytics["series"]["new_domains"]["points"]) == 60
    assert len(analytics["series"]["new_devices"]["points"]) == 60
    assert analytics["status_breakdown"]["All"] == 0
    assert analytics["live"]["queries_in_window"] == 0


def test_device_labels_are_persistent_and_bounded(monkeypatch, tmp_path):
    app = _fresh_app(monkeypatch, tmp_path, "development")
    app.init_db()
    client = app.app.test_client()
    assert client.post("/api/device/label", json={"device_key": "mac:aa:bb", "label": "Living Room TV"}).status_code == 200
    data = client.get("/api/device/label").get_json()
    assert data["labels"] == {"mac:aa:bb": "Living Room TV"}
    assert client.post("/api/device/label", json={"device_key": "mac:aa:bb", "label": "x" * 200}).get_json()["label"] == "x" * 80


def test_first_analytics_widget_is_live_visibility_report_not_a_dead_widget(monkeypatch, tmp_path):
    """Issue #88 follow-up: the deployed dashboard's first "Live activity"
    widget was a separate, easy-to-miss widget from the new Visibility
    report card. Rather than shipping two adjacent widgets where one can
    look inert, the live rate/gauge/sparkline and stat tiles are merged
    into the single "Visibility report" widget so there is exactly one
    first-glance widget and it is always populated with real data."""
    app = _fresh_app(monkeypatch, tmp_path, "development")
    body = app.HTML
    assert 'data-widget-id="live-overview"' not in body
    assert body.count('data-widget-id="visibility-report"') == 1
    # The live hero (rate/gauge/sparkline) and stat tiles now live inside
    # the Visibility report widget, not a separate dead widget.
    visibility_start = body.index('data-widget-id="visibility-report"')
    query_volume_start = body.index('data-widget-id="query-volume"')
    visibility_widget_html = body[visibility_start:query_volume_start]
    for marker in ("live-rate-value", "live-gauge-slot", "live-sparkline", "tile-allowed", "tile-blocked", "tile-devices", "tile-new-domains", 'id="visibility-report"'):
        assert marker in visibility_widget_html, f"{marker} missing from the merged Visibility report widget"


def test_dns_activity_chart_is_wired_for_click_to_investigate(monkeypatch, tmp_path):
    """Issue #88 follow-up: interval drill-down must be reachable from the
    actual "DNS activity over time" chart in the UI, not just the backend
    /api/analytics/interval endpoint."""
    app = _fresh_app(monkeypatch, tmp_path, "development")
    body = app.HTML
    assert 'id="chart-query-volume-detail"' in body
    assert "function selectIntervalBucket(" in body
    assert "function renderIntervalDetail(" in body
    assert "onPointClick: (point) => selectIntervalBucket(point, data.range)" in body
    assert "/api/analytics/interval?range=" in body


def test_analytics_pdf_export_is_a_real_pdf(monkeypatch, tmp_path):
    app = _fresh_app(monkeypatch, tmp_path, "development")
    app.init_db()
    client = app.app.test_client()

    response = client.get("/api/analytics/report.pdf?range=1h")
    assert response.status_code == 200
    assert response.mimetype == "application/pdf"
    assert response.data.startswith(b"%PDF-")
    assert "attachment;" in response.headers.get("Content-Disposition", "")
    assert len(response.data) > 2000


def test_analytics_pdf_export_handles_known_datacenter_provenance(monkeypatch, tmp_path):
    """Issue #88 known-datacenter follow-up: the PDF generator must not choke
    when destination coverage includes known-datacenter (region-derived, not
    city-GeoIP) points -- it reuses geoip_map_payload()'s coverage.provenance
    breakdown, so this exercises that new code path end-to-end."""
    import json
    from contextlib import closing

    app = _fresh_app(monkeypatch, tmp_path, "development")
    app.init_db()
    dc_csv = tmp_path / "geoip_datacenter.csv"
    dc_csv.write_text(
        "start_ip,end_ip,country_code,provider,region,lat,lon\n"
        "34.64.0.0,34.127.255.255,US,Google Cloud,us-central1,41.2619,-95.8608\n",
        encoding="utf-8",
    )
    app._geoip_datacenter_provider = app.CsvRangeDatacenterGeoIPProvider(str(dc_csv))
    app._geoip_map_cache["data"] = None

    now = app.utcnow()
    with closing(app.sqlite3.connect(app.DB_PATH)) as c:
        c.execute(
            "INSERT INTO domains(domain,first_seen,last_seen,requests,clients_json,blocked_requests,allowed_requests,unknown_requests,last_status,last_reason,current_status,current_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            ("cloud.example.com", now, now, 3, json.dumps({"mac:aa": 3}), 0, 3, 0, "Allowed", "", "Allowed", ""),
        )
        c.execute(
            "INSERT INTO domain_destination_ips(domain,ip,first_seen,last_seen,observations) VALUES(?,?,?,?,?)",
            ("cloud.example.com", "34.65.1.1", now, now, 3),
        )
        c.commit()

    map_payload = app.geoip_map_payload()
    assert map_payload["destinations"][0]["provenance"] == "known_datacenter"
    assert map_payload["coverage"]["provenance"]["known_datacenter"] == 3

    client = app.app.test_client()
    response = client.get("/api/analytics/report.pdf?range=1h")
    assert response.status_code == 200
    assert response.data.startswith(b"%PDF-")
    assert len(response.data) > 2000


def test_analytics_tab_has_custom_range_controls(monkeypatch, tmp_path):
    """Issue #88 item 1: a custom From/To period control must exist in the
    UI, not just the backend -- and it must be wired to the same
    /api/analytics(.pdf)/interval endpoints as the preset range buttons."""
    app = _fresh_app(monkeypatch, tmp_path, "development")
    body = app.HTML
    assert 'data-analytics-range="custom"' in body
    assert 'id="analytics-custom-from"' in body
    assert 'id="analytics-custom-to"' in body
    assert 'id="analytics-custom-apply-btn"' in body
    assert "function analyticsRangeQueryString(" in body
    assert "range=custom" in body
    # The export button and interval drill-down must use the same custom
    # from/to, not silently fall back to a preset when a custom window is active.
    assert "analyticsRangeQueryString()" in body


def test_assessment_tab_exists_with_ten_sections_and_reuses_existing_data(monkeypatch, tmp_path):
    """Issue #88 item 2: a standalone Assessment tab with 10 progressive-
    disclosure sections, built only from data the Analytics tab/PDF export
    already expose -- no new/fabricated data source."""
    app = _fresh_app(monkeypatch, tmp_path, "development")
    body = app.HTML
    assert 'data-tab="assessment"' in body
    assert 'id="tab-assessment"' in body
    assert body.count('class="assessment-section"') == 10
    assessment_start = body.index('id="tab-assessment"')
    assessment_end = body.index("</section>", assessment_start)
    assessment_html = body[assessment_start:assessment_end]
    # progressive disclosure: native <details>/<summary>, fully keyboard operable without extra JS
    assert assessment_html.count("<details") == 10
    assert assessment_html.count("<summary>") == 10
    for slot in (
        "assessment-summary", "assessment-timeline", "assessment-status", "assessment-top-domains",
        "assessment-top-devices", "assessment-new", "assessment-geo", "assessment-coverage", "assessment-reports",
    ):
        assert f'id="{slot}"' in assessment_html
    # No fabricated data source -- only the existing analytics/map/reports endpoints.
    assert "fetch(`/api/analytics?" in body
    assert "fetch('/api/analytics/map'" in body
    assert "fetch('/api/reports/status'" in body


def test_country_breakdown_list_has_roving_keyboard_navigation(monkeypatch, tmp_path):
    """Issue #88 item 3: the country breakdown list must support arrow-key
    roving-tabindex navigation, not just sequential Tab-through-buttons."""
    app = _fresh_app(monkeypatch, tmp_path, "development")
    body = app.HTML
    assert "function bindMapBreakdownKeyboardNav(" in body
    assert "ArrowDown" in body and "ArrowUp" in body
    assert "'Home'" in body and "'End'" in body


_DASH_WIDGET_IDS = (
    "visibility-report", "query-volume", "new-domains", "new-devices",
    "status-breakdown", "instrument-gauges", "destination-map",
    "activity-domains", "activity-devices", "top-activity",
)


def test_analytics_dashboard_is_a_real_gridstack_grid(monkeypatch, tmp_path):
    """The Analytics widget grid must be backed by GridStack.js (draggable,
    resizable, collision-aware, snap-to-cell), not the old CSS-grid
    order/width/height-name system it replaces."""
    app = _fresh_app(monkeypatch, tmp_path, "development")
    body = app.HTML
    assert "unpkg.com/gridstack" in body
    assert "gridstack.min.css" in body
    assert "gridstack-all.js" in body
    assert 'class="dash-grid grid-stack" id="analytics-dash-grid"' in body
    for widget_id in _DASH_WIDGET_IDS:
        assert f'data-widget-id="{widget_id}"' in body
        assert f'gs-id="{widget_id}"' in body
        assert body.count(f'data-widget-id="{widget_id}"') == 1
    # Every grid-stack-item must declare an explicit column/row span for
    # GridStack to auto-pack on init -- a missing gs-w/gs-h is a silent 1x1.
    assert body.count('class="grid-stack-item dash-widget"') == len(_DASH_WIDGET_IDS)
    assert body.count("gs-w=") == len(_DASH_WIDGET_IDS)
    assert body.count("gs-h=") == len(_DASH_WIDGET_IDS)
    # The old per-widget order/width/height-name CSS-grid system must be
    # fully retired, not left dangling alongside the new one.
    for legacy_marker in ("dash-resize-handle", "WIDTH_STEPS", "normalizeWidth", "--dash-widget-height"):
        assert legacy_marker not in body


def test_analytics_dashboard_layout_is_persisted_and_restorable(monkeypatch, tmp_path):
    """Issue #88 follow-up (GridStack): drag/resize/hide changes must persist
    per-browser (x/y/w/h, not just an order list) and be restored after a
    refresh, including a real reflow/collision path and a keyboard-operable
    fallback for users who cannot drag with a pointer."""
    app = _fresh_app(monkeypatch, tmp_path, "development")
    body = app.HTML
    assert "GridStack.init(" in body
    assert "dnsInspectorDashboardLayout" in body
    assert "function applyGeometry(" in body
    assert "function packLayout(" in body
    assert "function presetLayout(" in body
    assert "grid.on('change'" in body
    assert "grid.setStatic(" in body
    assert "localStorage.setItem(LAYOUT_KEY" in body
    assert "localStorage.getItem(LAYOUT_KEY" in body
    # Hide/show must be real grid membership changes (removeWidget/addWidget),
    # not a display:none-only trick that would leave a gap behind.
    assert "grid.removeWidget(" in body
    assert "grid.addWidget(" in body
    assert 'id="dash-hidden-tray"' in body
    # Keyboard/touch-accessible reordering must survive alongside pointer drag.
    assert "function moveWidget(" in body
    assert 'data-dash-action="move-up"' in body
    assert 'data-dash-action="move-down"' in body
