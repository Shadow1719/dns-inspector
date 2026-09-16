"""DNS Inspector Home landing (0.8.5.2 UI polish).

The existing Analytics dashboard becomes the first tab and the default
landing view, presented as "Home" in the nav bar; the internal `analytics`
identifiers (`data-tab`, panel id, `/api/analytics*` routes) are unchanged --
this is a visible-label/default-tab change only, not a rename of the
Analytics feature. Like the other UI structural tests, these only assert on
the rendered markup -- there is no JS runtime in this suite.
"""

import re


def test_home_is_the_first_nav_tab_and_labelled_home(client):
    body = client.get("/").data.decode("utf-8")
    nav = re.search(r'<nav class="tabs".*?</nav>', body, re.S).group(0)
    tabs = re.findall(r'data-tab="(\w+)"', nav)
    assert tabs == ["analytics", "overview", "devices"], tabs
    assert re.search(r'data-tab="analytics"[^>]*>.*?Home</button>', nav, re.S)
    assert "Analytics</button>" not in nav


def test_home_tab_is_the_default_active_view(client):
    body = client.get("/").data.decode("utf-8")
    assert '<button class="tab-btn active" data-tab="analytics"' in body
    assert '<section id="tab-analytics" class="tab-panel active"' in body
    # Overview/Devices are no longer default-active in the server-rendered markup.
    assert '<button class="tab-btn active" data-tab="overview"' not in body
    assert '<section id="tab-overview" class="tab-panel active"' not in body


def test_analytics_tab_identifiers_are_unchanged(client):
    """Only the visible label moved; internal wiring stays `analytics`."""
    body = client.get("/").data.decode("utf-8")
    assert 'id="tab-analytics"' in body
    assert 'data-panel="analytics"' in body
    assert "/api/analytics" in body


def test_default_view_setting_still_offers_home_and_other_sections(client):
    body = client.get("/").data.decode("utf-8")
    assert 'id="default-view-select"' in body
    assert '<option value="analytics">Home</option>' in body
    for value in ("overview", "devices"):
        assert f'<option value="{value}">' in body


def test_search_and_default_view_bootstrap_logic_is_unchanged(client):
    """A search/inspect result must still land on Overview, and an explicit
    "Default view" preference (including the Home/analytics option) must
    still be honoured -- only the tie-breaker for a first-ever visit with
    nothing saved moved from Overview to Home.
    """
    body = client.get("/").data.decode("utf-8")
    assert "if(currentQuery || hasInspectContent){ setActiveTab('overview'); }" in body
    assert "['overview','devices','analytics'].includes(prefs.defaultView)" in body
