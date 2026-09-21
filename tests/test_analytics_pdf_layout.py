"""Regression tests for the Analytics PDF "Most queried domains" / "Most
active devices" bar-list layout.

These guard against labels being drawn underneath/behind the horizontal bar
graphics: the label for a row must always have enough vertical room to sit
fully above that row's bar before the bar is drawn.
"""

import pytest
from reportlab.lib.units import mm
from reportlab.pdfbase.pdfmetrics import stringWidth

from analytics_report import _bar_list_layout, _ellipsize, build_analytics_pdf


LABEL_SIZE, LABEL_GAP, BAR_H, ROW_GAP = 7.2, 3, 5, 4
MIN_ROW_H = LABEL_SIZE + LABEL_GAP + BAR_H + ROW_GAP


@pytest.mark.parametrize("height_mm", [20, 37, 50, 64, 80, 120])
@pytest.mark.parametrize("row_count", [0, 1, 3, 7, 8, 20])
def test_bar_list_layout_never_lets_a_row_overlap(height_mm, row_count):
    shown, row_h = _bar_list_layout(height_mm * mm, row_count)
    assert shown <= row_count
    if shown:
        # row_h is the pitch between rows; it must be at least enough to fit
        # the label line, the label->bar clearance, the bar itself, and the
        # gap before the next row, or the label baseline lands inside (or
        # below) the bar drawn underneath it.
        assert row_h >= MIN_ROW_H - 1e-6
    else:
        assert row_count == 0 or height_mm == 20


def test_bar_list_layout_fits_all_seven_rows_at_the_real_panel_height():
    # This is the exact height build_analytics_pdf uses for the domains/
    # devices panels. It must comfortably fit the up-to-7 rows the report
    # actually displays.
    shown, row_h = _bar_list_layout(64 * mm, 8)
    assert shown == 7
    assert row_h >= MIN_ROW_H


def test_bar_list_layout_shows_fewer_rows_instead_of_overlapping():
    # The panel height that originally shipped (37mm) cannot safely fit 7
    # rows; the fix must show fewer rows rather than stack a label on top of
    # the bar below it.
    shown, row_h = _bar_list_layout(37 * mm, 7)
    assert 0 < shown < 7
    assert row_h >= MIN_ROW_H


def test_ellipsize_leaves_short_text_untouched():
    text = "example.com"
    assert _ellipsize(text, "Helvetica", 7.2, 500) == text


def test_ellipsize_truncates_long_text_to_fit():
    long_domain = "a-very-long-subdomain-label-for-regression-testing." * 3 + "example.com"
    max_width = 80
    result = _ellipsize(long_domain, "Helvetica", 7.2, max_width)
    assert result != long_domain
    assert result.endswith("…")
    assert stringWidth(result, "Helvetica", 7.2) <= max_width


def test_ellipsize_degenerates_to_bare_ellipsis_when_width_too_small():
    assert _ellipsize("example.com", "Helvetica", 8, 0.5) == "…"


def _sample_report_inputs():
    long_domain = "this-is-an-unusually-long-subdomain-label-used-for-regression-testing.example-corp-internal.com"
    long_device = "Living-Room-Really-Long-Smart-Speaker-Device-Name-For-Layout-Testing"
    analytics = {
        "series": {
            "queries": {
                "points": [{"t": f"2026-01-01T{h:02d}:00:00Z", "count": 100 + h * 7} for h in range(24)]
            }
        }
    }
    stats = {
        "domains": [{"label": f"{long_domain}-{i}", "value": 1000 - i * 10, "href": "#"} for i in range(8)],
        "devices": [{"label": f"{long_device}-{i}", "value": 500 - i * 5, "href": "#"} for i in range(8)],
    }
    breakdown = {"Allowed": 800, "Blocked": 150, "Mixed": 40, "Unknown": 10}
    map_data = {"countries": [{"country_name": "United States", "country_code": "US", "observation_count": 500}]}
    return analytics, stats, breakdown, map_data


def test_build_analytics_pdf_with_long_labels_is_valid_and_bounded():
    analytics, stats, breakdown, map_data = _sample_report_inputs()
    buf = build_analytics_pdf(
        analytics=analytics,
        stats=stats,
        breakdown=breakdown,
        map_data=map_data,
        version="0.8.6-dev.5",
        environment="dev",
        range_key="24h",
    )
    data = buf.read()
    assert data.startswith(b"%PDF")
    # Deterministic, memory-bounded output rather than an unbounded/runaway document.
    assert 1_000 < len(data) < 2_000_000


def test_build_analytics_pdf_handles_empty_top_lists():
    analytics, _, breakdown, map_data = _sample_report_inputs()
    buf = build_analytics_pdf(
        analytics=analytics,
        stats={"domains": [], "devices": []},
        breakdown=breakdown,
        map_data=map_data,
        version="0.8.6-dev.5",
        environment="dev",
        range_key="1h",
    )
    data = buf.read()
    assert data.startswith(b"%PDF")
