"""Settings, themes and Analytics visual styles (Issue #22): structural
regression checks.

Like `test_ui_design_system.py`, these assert markup/hooks exist without
pinning exact CSS values or asserting on client-side JS behaviour (there is
no JS runtime in the test suite) -- theme/accent/density/refresh-interval/
analytics-style preferences are applied entirely client-side via
localStorage, so what we can and should verify from the Flask test client is
that every preference has a real, wired-up control in the rendered page.
"""


def test_settings_open_button_exists_in_shell(client):
    body = client.get("/").data.decode("utf-8")
    assert 'id="settings-open-btn"' in body
    assert 'aria-controls="settings-dialog"' in body


def test_settings_dialog_exposes_all_documented_sections(client):
    body = client.get("/").data.decode("utf-8")
    assert 'id="settings-dialog"' in body
    for section in ("appearance", "dashboard", "monitoring", "diagnostics", "system", "about"):
        assert f'data-settings-tab="{section}"' in body
        assert f'data-settings-panel="{section}"' in body


def test_theme_choices_cover_dark_light_aurora_natural_and_system(client):
    body = client.get("/").data.decode("utf-8")
    # Selectable choices in the Settings dialog.
    for theme in ("bemo-dark", "bemo-light", "bemo-aurora", "bemo-natural", "system"):
        assert f'data-theme-choice="{theme}"' in body
    # Actual CSS token overrides backing three of the four named themes
    # (bemo-dark is the :root default and has no override block).
    for theme in ("bemo-light", "bemo-aurora", "bemo-natural"):
        assert f'html[data-theme="{theme}"]' in body


def test_accent_and_density_preference_controls_exist(client):
    body = client.get("/").data.decode("utf-8")
    assert 'id="accent-choice-group"' in body
    for density in ("comfortable", "compact", "dense"):
        assert f'data-density-choice="{density}"' in body
    assert 'id="reduced-motion-toggle"' in body


def test_monitoring_refresh_interval_control_exists(client):
    body = client.get("/").data.decode("utf-8")
    assert 'id="refresh-interval-select"' in body
    assert 'id="default-view-select"' in body


def test_analytics_visual_style_choices_are_analog_digital_specter(client):
    """The Analytics visual-style abstraction (Issue #22): same live metric,
    selectable presentation. `renderMetricVisual` is the single function
    every chart (live sparkline + the three historical timelines) renders
    through, keyed off this same preference.
    """
    body = client.get("/").data.decode("utf-8")
    for style in ("digital", "analog", "specter"):
        assert f'data-style-choice="{style}"' in body
    assert "renderMetricVisual" in body
    assert "analyticsStyle" in body


def test_diagnostics_and_system_panels_reuse_existing_observability_and_health_routes(client):
    """Diagnostics/System must not invent a new data pipeline -- they read
    the existing `/api/observability` and `/health` routes client-side.
    """
    body = client.get("/").data.decode("utf-8")
    assert "/api/observability" in body
    assert "fetch('/health'" in body


def test_about_panel_shows_existing_identity_context(client):
    body = client.get("/").data.decode("utf-8")
    assert 'data-settings-panel="about"' in body
    assert "Inspector BEMO" in body
    assert 'id="about-uptime"' in body


def test_preferences_are_stored_client_side_only(client):
    """0.8.x constraint: no database migration for UI preferences."""
    body = client.get("/").data.decode("utf-8")
    assert "dnsInspectorPrefs" in body
    assert "localStorage" in body


def test_device_detail_reuses_the_same_settings_dialog(app_module, client):
    """Regression guard matching `test_device_detail_reuses_the_same_design_language`
    in test_ui_design_system.py: Settings must be part of the one shared
    shell, not bolted onto the dashboard route only.
    """
    response = client.get("/device?key=does-not-exist")
    assert response.status_code == 404
    body = response.data.decode("utf-8")
    assert 'id="settings-dialog"' in body
