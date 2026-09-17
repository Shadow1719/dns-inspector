"""Dashboard widget grid layout fix (Issue #43).

The 0.8.5 Dashboard Builder only offered a binary width (`half`/`full` of a
2-column grid) and behaved more like picking between a couple of presets than
a real layout system. This replaces the binary width with a genuine 1-4
column span per widget on a real 4-column grid, with `grid-auto-flow:dense`
to back-fill gaps and two responsive breakpoints so the span *proportions*
stay meaningful as the viewport narrows.

Like `test_analytics_visual2_dashboard_builder.py`, these assert
markup/CSS/JS hooks exist without pinning exact pixel values or asserting on
client-side runtime behaviour (there is no JS runtime in this test suite).
"""

DASH_WIDGET_IDS = (
    "live-overview", "query-volume", "new-domains", "new-devices",
    "status-breakdown", "instrument-gauges", "destination-map",
    "activity-domains", "activity-devices", "top-activity",
)


def test_dash_grid_is_a_real_four_column_span_system(client):
    body = client.get("/").data.decode("utf-8")
    assert ".dash-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr))" in body
    assert "grid-auto-flow:dense" in body
    for span in ("1", "2", "3", "4"):
        assert f'.dash-widget[data-w="{span}"]{{grid-column:span {span}}}' in body


def test_dash_grid_no_longer_uses_the_binary_half_full_width(client):
    body = client.get("/").data.decode("utf-8")
    assert 'data-w="full"' not in body
    assert 'data-w="half"' not in body
    assert '.dash-widget[data-w="half"]' not in body


def test_widgets_carry_a_numeric_column_span(client):
    body = client.get("/").data.decode("utf-8")
    for widget_id in DASH_WIDGET_IDS:
        assert f'data-widget-id="{widget_id}"' in body
    # Full-bleed widgets (span 4) and paired half-width widgets (span 2) --
    # same visual sizing as before the migration, just expressed as spans.
    assert 'data-widget-id="live-overview" data-title="Live activity" data-w="4"' in body
    assert 'data-widget-id="new-domains" data-title="New domains discovered" data-w="2"' in body


def test_dash_grid_has_two_responsive_breakpoints(client):
    body = client.get("/").data.decode("utf-8")
    assert "@media(max-width:1300px){" in body
    assert "@media(max-width:900px){.dash-grid{grid-template-columns:1fr}" in body


def test_width_control_cycles_through_all_four_spans_not_a_binary_toggle(client):
    body = client.get("/").data.decode("utf-8")
    assert "const WIDTH_STEPS = ['1','2','3','4'];" in body
    assert (
        "cur.w = WIDTH_STEPS[(WIDTH_STEPS.indexOf(normalizeWidth(cur.w)) + 1) % WIDTH_STEPS.length];"
    ) in body
    # The old binary toggle must not come back.
    assert "cur.w = cur.w === 'full' ? 'half' : 'full';" not in body


def test_normalize_width_migrates_pre_existing_saved_layouts(client):
    """A browser that already has an older `dnsInspectorDashboardLayout`
    persisted (or a preset built before this change) can still hand back the
    old 'full'/'half' strings -- `normalizeWidth()` must map those to their
    equivalent span instead of silently defaulting every previously-full
    widget in the customer's saved layout to a size they never chose."""
    body = client.get("/").data.decode("utf-8")
    assert "function normalizeWidth(w){" in body
    assert "if (w === 'full') return '4';" in body
    assert "if (w === 'half') return '2';" in body


def test_dashboard_builder_grid_still_wraps_every_analytics_widget(client):
    """Regression guard: the width-system migration must not drop or rename
    any existing widget id (no data/functionality removed)."""
    body = client.get("/").data.decode("utf-8")
    assert 'id="analytics-dash-grid"' in body
    for widget_id in DASH_WIDGET_IDS:
        assert f'data-widget-id="{widget_id}"' in body
