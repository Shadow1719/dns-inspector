"""Inspector BEMO UI overhaul (Issue #20): structural regression checks.

These assert the shared shell/navigation and design-system hooks are present
without pinning exact CSS values, so the suite stays useful as the visual
design keeps evolving. Behavioural/DEV-banner contracts are already covered
by `tests/test_environment.py`; this file only covers what that one doesn't.
"""


def test_dashboard_has_a_unified_app_shell(client):
    body = client.get("/").data.decode("utf-8")
    assert 'class="app-shell"' in body
    assert "Inspector BEMO" in body
    assert 'class="brand-title"' in body


def test_dashboard_nav_exposes_all_three_sections(client):
    body = client.get("/").data.decode("utf-8")
    for tab in ("overview", "devices", "analytics"):
        assert f'data-tab="{tab}"' in body
    # Tabs are a real <nav> now, not a bare <div>, for assistive tech.
    assert '<nav class="tabs"' in body


def test_design_tokens_are_defined_once_and_reused(client):
    """Semantic status variables must keep their exact names: the Analytics
    JS (`STATUS_COLOR_VAR`, `statusSemClass`) references them as raw CSS
    variable names, not through any Python/Jinja value.
    """
    body = client.get("/").data.decode("utf-8")
    for token in (
        "--sem-ok", "--sem-info", "--sem-blocked", "--sem-warn",
        "--sem-crit", "--sem-live", "--accent", "--surface-1", "--radius-md",
    ):
        assert token in body


def test_empty_state_class_exists_for_loading_and_no_data_messages(client):
    body = client.get("/").data.decode("utf-8")
    assert ".empty-state" in body


def test_device_detail_reuses_the_same_design_language(app_module, client):
    """Regression guard: device/IP detail views render through the same
    `HTML` template as the dashboard, so they must not silently diverge from
    the shared shell (Issue #20 requires one coherent product, not
    independently styled screens).
    """
    response = client.get("/device?key=does-not-exist")
    assert response.status_code == 404
    body = response.data.decode("utf-8")
    assert 'class="app-shell"' in body
    assert 'class="card"' in body
