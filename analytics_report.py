from __future__ import annotations

import math
from datetime import datetime, timezone
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph


PAGE_W, PAGE_H = A4
MARGIN = 16 * mm

NAVY = HexColor("#101827")
NAVY_2 = HexColor("#172033")
INK = HexColor("#152033")
MUTED = HexColor("#667085")
GRID = HexColor("#E7ECF3")
BLUE = HexColor("#3B82F6")
CYAN = HexColor("#06B6D4")
TEAL = HexColor("#14B8A6")
GREEN = HexColor("#16A34A")
AMBER = HexColor("#D97706")
RED = HexColor("#DC2626")
PURPLE = HexColor("#7C3AED")
WHITE = colors.white
PALE_BLUE = HexColor("#EFF6FF")
PALE_GREEN = HexColor("#ECFDF3")
PALE_AMBER = HexColor("#FFF7ED")
PALE_RED = HexColor("#FEF2F2")
PALE_PURPLE = HexColor("#F5F3FF")


def _fmt_num(value):
    try:
        n = float(value)
    except (TypeError, ValueError):
        return "0"
    if abs(n) >= 1_000_000:
        return f"{n/1_000_000:.1f}M".replace(".0M", "M")
    if abs(n) >= 1_000:
        return f"{n/1_000:.1f}k".replace(".0k", "k")
    return f"{int(n):,}"


def _fmt_pct(value):
    try:
        return f"{float(value):.1f}%"
    except (TypeError, ValueError):
        return "0.0%"


def _ellipsize(text, font_name, font_size, max_width):
    """Truncate text with a trailing ellipsis so it never exceeds max_width at the given font."""
    text = text or ""
    if stringWidth(text, font_name, font_size) <= max_width:
        return text
    ellipsis = "…"
    lo, hi = 0, len(text)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if stringWidth(text[:mid] + ellipsis, font_name, font_size) <= max_width:
            lo = mid
        else:
            hi = mid - 1
    return (text[:lo] + ellipsis) if lo > 0 else ellipsis


def _fmt_dt(value):
    try:
        text = str(value)
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        return dt.astimezone().strftime("%b %d, %Y · %H:%M")
    except Exception:
        return str(value)


def _series_points(analytics):
    return [p for p in (analytics.get("series", {}).get("queries", {}).get("points") or []) if p.get("count") is not None]


def _stats(analytics):
    pts = _series_points(analytics)
    values = [float(p.get("count") or 0) for p in pts]
    total = int(sum(values))
    avg = (sum(values) / len(values)) if values else 0.0
    peak = max(values) if values else 0.0
    peak_pt = max(pts, key=lambda p: float(p.get("count") or 0), default={})
    return {
        "points": pts,
        "total": total,
        "avg": avg,
        "peak": int(peak),
        "peak_at": peak_pt.get("t"),
        "peak_ratio": (peak / avg) if avg else 0.0,
    }


def _draw_round_rect(c, x, y, w, h, fill, stroke=None, radius=8):
    c.setFillColor(fill)
    c.setStrokeColor(stroke or fill)
    c.roundRect(x, y, w, h, radius, fill=1, stroke=1 if stroke else 0)


def _draw_kpi(c, x, y, w, h, label, value, accent, sub=""):
    _draw_round_rect(c, x, y, w, h, WHITE, GRID, 10)
    c.setFillColor(accent)
    c.roundRect(x, y + h - 5, w, 5, 3, fill=1, stroke=0)
    c.setFont("Helvetica-Bold", 8)
    c.setFillColor(MUTED)
    c.drawString(x + 11, y + h - 20, label.upper())
    c.setFont("Helvetica-Bold", 19)
    c.setFillColor(INK)
    c.drawString(x + 11, y + h - 43, str(value))
    if sub:
        c.setFont("Helvetica", 7.5)
        c.setFillColor(MUTED)
        c.drawString(x + 11, y + 12, sub)


def _draw_section_title(c, x, y, title, subtitle=None):
    c.setFont("Helvetica-Bold", 14)
    c.setFillColor(INK)
    c.drawString(x, y, title)
    if subtitle:
        c.setFont("Helvetica", 8)
        c.setFillColor(MUTED)
        c.drawString(x, y - 13, subtitle)


def _draw_line_chart(c, x, y, w, h, points, accent=BLUE):
    _draw_round_rect(c, x, y, w, h, WHITE, GRID, 10)
    if not points:
        c.setFont("Helvetica", 9)
        c.setFillColor(MUTED)
        c.drawCentredString(x + w / 2, y + h / 2, "No retained query timeline is available for this period.")
        return

    values = [float(p.get("count") or 0) for p in points]
    vmax = max(values) if values else 1
    chart_x, chart_y = x + 38, y + 30
    chart_w, chart_h = w - 54, h - 58

    for i in range(4):
        gy = chart_y + chart_h * (i / 3)
        c.setStrokeColor(GRID)
        c.setLineWidth(0.6)
        c.line(chart_x, gy, chart_x + chart_w, gy)

    c.setFont("Helvetica", 6.5)
    c.setFillColor(MUTED)
    for i, frac in enumerate((0.0, 0.5, 1.0)):
        val = vmax * frac
        c.drawRightString(chart_x - 6, chart_y + chart_h * frac - 2, _fmt_num(val))

    if len(points) == 1:
        xs = [chart_x + chart_w / 2]
    else:
        step = chart_w / (len(points) - 1)
        xs = [chart_x + i * step for i in range(len(points))]

    coords = []
    for x0, p in zip(xs, points):
        v = float(p.get("count") or 0)
        y0 = chart_y + (v / max(vmax, 1)) * chart_h
        coords.append((x0, y0))

    c.setStrokeColor(HexColor("#DDEBFF"))
    c.setLineWidth(6)
    path = c.beginPath()
    path.moveTo(*coords[0])
    for x0, y0 in coords[1:]:
        path.lineTo(x0, y0)
    c.drawPath(path, stroke=1, fill=0)

    c.setStrokeColor(accent)
    c.setLineWidth(2.3)
    path = c.beginPath()
    path.moveTo(*coords[0])
    for x0, y0 in coords[1:]:
        path.lineTo(x0, y0)
    c.drawPath(path, stroke=1, fill=0)

    peak_idx = max(range(len(values)), key=lambda i: values[i])
    px, py = coords[peak_idx]
    c.setFillColor(RED if values[peak_idx] >= (sum(values) / max(len(values), 1)) * 2 else accent)
    c.circle(px, py, 3.7, fill=1, stroke=0)
    if points[peak_idx].get("t"):
        c.setFont("Helvetica-Bold", 7)
        c.setFillColor(INK)
        c.drawString(min(px + 7, x + w - 110), min(py + 7, y + h - 15), f"Peak {_fmt_num(values[peak_idx])}")
        c.setFont("Helvetica", 6.5)
        c.setFillColor(MUTED)
        c.drawString(min(px + 7, x + w - 110), min(py - 3, y + 6), _fmt_dt(points[peak_idx]["t"]))

    c.setFont("Helvetica", 6.5)
    c.setFillColor(MUTED)
    label_points = [points[0], points[len(points)//2], points[-1]]
    label_xs = [chart_x, chart_x + chart_w / 2, chart_x + chart_w]
    for xp, p in zip(label_xs, label_points):
        c.drawCentredString(xp, y + 12, _fmt_dt(p.get("t", ""))[:16])


def _draw_donut(c, x, y, w, h, breakdown):
    _draw_round_rect(c, x, y, w, h, WHITE, GRID, 10)
    total = sum(float(breakdown.get(k) or 0) for k in ("Allowed", "Blocked", "Mixed", "Unknown"))
    cx, cy = x + 72, y + h / 2
    radius = 43
    mapping = [
        ("Allowed", GREEN),
        ("Blocked", RED),
        ("Mixed", AMBER),
        ("Unknown", HexColor("#98A2B3")),
    ]
    if total <= 0:
        c.setStrokeColor(GRID)
        c.setLineWidth(14)
        c.circle(cx, cy, radius, fill=0, stroke=1)
    else:
        start = 90
        for key, color in mapping:
            val = float(breakdown.get(key) or 0)
            sweep = 360 * val / total
            c.setFillColor(color)
            c.setStrokeColor(WHITE)
            c.setLineWidth(1)
            c.wedge(cx - radius, cy - radius, cx + radius, cy + radius, start, sweep, fill=1, stroke=1)
            start -= sweep
    c.setFillColor(WHITE)
    c.circle(cx, cy, 27, fill=1, stroke=0)
    c.setFillColor(INK)
    c.setFont("Helvetica-Bold", 12)
    c.drawCentredString(cx, cy + 2, _fmt_num(total))
    c.setFont("Helvetica", 7)
    c.setFillColor(MUTED)
    c.drawCentredString(cx, cy - 9, "classified")

    c.setFont("Helvetica-Bold", 8.5)
    c.setFillColor(INK)
    c.drawString(x + 135, y + h - 24, "Status mix")
    ly = y + h - 44
    for key, color in mapping:
        val = float(breakdown.get(key) or 0)
        pct = (val / total * 100) if total else 0
        c.setFillColor(color)
        c.roundRect(x + 135, ly - 2, 7, 7, 2, fill=1, stroke=0)
        c.setFillColor(INK)
        c.setFont("Helvetica", 8)
        c.drawString(x + 148, ly, key)
        c.setFillColor(MUTED)
        c.drawRightString(x + w - 12, ly, f"{_fmt_num(val)} · {pct:.1f}%")
        ly -= 17


def _bar_list_layout(h, row_count, *, top_pad=36, bottom_pad=10, label_size=7.2, label_gap=3, bar_h=5, row_gap=4):
    """Compute how many rows of a bar list fit in height h without the label
    ever overlapping the bar below it, and the pitch (row_h) between rows.

    Returns (shown_rows, row_h). row_h is only meaningful when shown_rows > 0.
    """
    available = max(h - top_pad - bottom_pad, 0)
    min_row_h = label_size + label_gap + bar_h + row_gap
    max_rows = int(available // min_row_h)
    shown = min(row_count, max_rows) if row_count and max_rows > 0 else 0
    row_h = (available / shown) if shown else 0
    return shown, row_h


def _draw_bar_list(c, x, y, w, h, title, rows, color):
    _draw_round_rect(c, x, y, w, h, WHITE, GRID, 10)
    c.setFont("Helvetica-Bold", 9)
    c.setFillColor(INK)
    c.drawString(x + 12, y + h - 20, title)

    if not rows:
        c.setFont("Helvetica", 8)
        c.setFillColor(MUTED)
        c.drawString(x + 12, y + h - 40, "No data available")
        return

    top_pad, bottom_pad = 36, 10
    label_size, label_gap, bar_h, row_gap = 7.2, 3, 5, 4
    shown, row_h = _bar_list_layout(
        h, len(rows), top_pad=top_pad, bottom_pad=bottom_pad,
        label_size=label_size, label_gap=label_gap, bar_h=bar_h, row_gap=row_gap,
    )
    if not shown:
        c.setFont("Helvetica", 8)
        c.setFillColor(MUTED)
        c.drawString(x + 12, y + h - 40, "Not enough space to display items")
        return
    rows = rows[:shown]

    max_v = max(float(r.get("value") or 0) for r in rows) or 1
    value_col_w = 34
    bar_w = w - 24 - value_col_w
    label_max_w = w - 24
    rows_top = y + h - top_pad

    for i, row in enumerate(rows):
        row_top = rows_top - i * row_h
        label = _ellipsize(str(row.get("label") or ""), "Helvetica", label_size, label_max_w)
        value = float(row.get("value") or 0)

        # Label sits on its own line at the top of the row; the bar is drawn
        # entirely below the label's baseline (plus a clearance gap), so the
        # bar can never be drawn underneath/behind the text.
        c.setFillColor(INK)
        c.setFont("Helvetica", label_size)
        c.drawString(x + 12, row_top - label_size, label)

        bar_y = row_top - label_size - label_gap - bar_h
        c.setFillColor(HexColor("#EFF3F8"))
        c.roundRect(x + 12, bar_y, bar_w, bar_h, 2.5, fill=1, stroke=0)
        c.setFillColor(color)
        c.roundRect(x + 12, bar_y, max(bar_w * (value / max_v), 0), bar_h, 2.5, fill=1, stroke=0)

        c.setFillColor(MUTED)
        c.setFont("Helvetica-Bold", 7.2)
        c.drawRightString(x + w - 12, bar_y + 0.8, _fmt_num(value))


def _draw_insight(c, x, y, w, h, label, title, body, accent, bg):
    _draw_round_rect(c, x, y, w, h, bg, bg, 10)
    c.setFillColor(accent)
    c.circle(x + 15, y + h - 15, 4, fill=1, stroke=0)
    c.setFillColor(MUTED)
    c.setFont("Helvetica-Bold", 7)
    c.drawString(x + 27, y + h - 18, label.upper())
    c.setFillColor(INK)
    c.setFont("Helvetica-Bold", 9.5)
    c.drawString(x + 12, y + h - 36, title[:56])
    style = ParagraphStyle("insight", fontName="Helvetica", fontSize=7.4, leading=10, textColor=MUTED)
    p = Paragraph(body, style)
    p.wrapOn(c, w - 24, h - 52)
    p.drawOn(c, x + 12, y + 10)


TOTAL_REPORT_PAGES = 4


def _draw_page_footer(c, page_num, window_label, generated_iso, dark=False):
    line_color = HexColor("#334155") if dark else GRID
    text_color = HexColor("#94A3B8") if dark else MUTED
    c.setStrokeColor(line_color)
    c.setLineWidth(0.6)
    c.line(MARGIN, 9 * mm, PAGE_W - MARGIN, 9 * mm)
    c.setFont("Helvetica", 7)
    c.setFillColor(text_color)
    c.drawString(MARGIN, 4.5 * mm, f"DNS Inspector · Inspector BEMO visibility report · analysis window: {window_label}")
    c.drawCentredString(PAGE_W / 2, 4.5 * mm, f"Generated {_fmt_dt(generated_iso)}")
    c.drawRightString(PAGE_W - MARGIN, 4.5 * mm, f"Page {page_num} of {TOTAL_REPORT_PAGES}")


_RANGE_LABELS = {"1h": "Last hour", "6h": "Last 6 hours", "24h": "Last 24 hours", "7d": "Last 7 days", "30d": "Last 30 days", "90d": "Last 90 days"}


def build_analytics_pdf(*, analytics, stats, breakdown, map_data, version, environment, range_key, window=None):
    window = window or {}
    window_label = window.get("label") or _RANGE_LABELS.get(range_key, range_key)
    coverage = window.get("coverage") or {}
    coverage_note = coverage.get("note")

    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    c.setTitle(f"DNS Inspector Analytics — {window_label}")
    c.setAuthor("DNS Inspector / Inspector BEMO")
    generated_iso = datetime.now(timezone.utc).isoformat()

    s = _stats(analytics)
    total = s["total"]
    avg = s["avg"]
    peak = s["peak"]
    peak_ratio = s["peak_ratio"]
    status_total = sum(float(breakdown.get(k) or 0) for k in ("Allowed", "Blocked", "Mixed", "Unknown"))
    blocked = float(breakdown.get("Blocked") or 0)
    blocked_pct = (blocked / status_total * 100) if status_total else 0
    countries = (map_data or {}).get("countries") or []

    # Page 1 — executive overview
    c.setFillColor(NAVY)
    c.rect(0, PAGE_H - 74 * mm, PAGE_W, 74 * mm, fill=1, stroke=0)
    c.setFillColor(TEAL)
    c.roundRect(MARGIN, PAGE_H - 22 * mm, 22 * mm, 6 * mm, 3 * mm, fill=1, stroke=0)
    c.setFillColor(WHITE)
    c.setFont("Helvetica-Bold", 9)
    c.drawCentredString(MARGIN + 11 * mm, PAGE_H - 19.4 * mm, "DNS")
    c.setFont("Helvetica-Bold", 24)
    c.drawString(MARGIN, PAGE_H - 42 * mm, "Visibility report")
    c.setFont("Helvetica", 9.5)
    c.setFillColor(HexColor("#CBD5E1"))
    c.drawString(MARGIN, PAGE_H - 50 * mm, "A visual summary of observed DNS activity — designed for quick understanding, not data overload.")
    c.setFont("Helvetica-Bold", 8.5)
    c.setFillColor(WHITE)
    c.drawRightString(PAGE_W - MARGIN, PAGE_H - 18 * mm, f"DNS Inspector v{version}")
    c.setFont("Helvetica", 8)
    c.setFillColor(HexColor("#CBD5E1"))
    c.drawRightString(PAGE_W - MARGIN, PAGE_H - 30 * mm, f"{environment.upper()} · {window_label.upper()}")

    c.setFillColor(INK)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(MARGIN, PAGE_H - 92 * mm, "Period overview")
    c.setFont("Helvetica", 8)
    c.setFillColor(MUTED)
    c.drawString(MARGIN, PAGE_H - 99 * mm, "The timeline below is based on the retained processed-query history available to DNS Inspector.")
    if window.get("start") and window.get("end"):
        c.drawString(MARGIN, PAGE_H - 104 * mm, f"Report window: {_fmt_dt(window['start'])} → {_fmt_dt(window['end'])}")

    card_y = PAGE_H - 139 * mm
    gap = 8 * mm
    card_w = (PAGE_W - 2 * MARGIN - 3 * gap) / 4
    _draw_kpi(c, MARGIN, card_y, card_w, 31 * mm, "Queries in period", _fmt_num(total), BLUE, "bucketed from retained history")
    _draw_kpi(c, MARGIN + card_w + gap, card_y, card_w, 31 * mm, "Average / bucket", _fmt_num(avg), CYAN, "smoothed activity baseline")
    _draw_kpi(c, MARGIN + 2 * (card_w + gap), card_y, card_w, 31 * mm, "Peak bucket", _fmt_num(peak), RED if peak_ratio >= 2 else AMBER, f"{peak_ratio:.1f}× period average" if avg else "")
    _draw_kpi(c, MARGIN + 3 * (card_w + gap), card_y, card_w, 31 * mm, "Blocked share", _fmt_pct(blocked_pct), RED if blocked_pct >= 20 else AMBER, "current classification mix")

    chart_y = 79 * mm
    _draw_line_chart(c, MARGIN, chart_y, PAGE_W - 2 * MARGIN, 75 * mm, s["points"])

    _draw_page_footer(c, 1, window_label, generated_iso)
    c.showPage()

    # Page 2 — what stands out
    #
    # Layout is computed top-down from fixed anchors so nothing can overlap
    # regardless of whether the optional coverage banner is present:
    #   section title/subtitle -> [coverage banner, if present] -> cards
    #   -> donut (fixed position) -> "Visibility snapshot" heading -> bar lists -> footer
    # The donut/heading/bar-list cluster near the bottom of the page never
    # moves; only the banner+cards block above it grows or shrinks.
    _draw_section_title(c, MARGIN, PAGE_H - 22 * mm, "What stands out", "Interpretation cards — concise, evidence-based, and intentionally free of invented root causes.")

    card_h = 44 * mm
    card_top = PAGE_H - 33 * mm  # safely below the section subtitle in every case
    if coverage_note:
        banner_h = 18 * mm
        banner_y = card_top - banner_h
        _draw_round_rect(c, MARGIN, banner_y, PAGE_W - 2 * MARGIN, banner_h, PALE_AMBER, PALE_AMBER, 8)
        c.setFillColor(AMBER)
        c.circle(MARGIN + 12, banner_y + banner_h - 8, 3, fill=1, stroke=0)
        c.setFont("Helvetica-Bold", 7.5)
        c.setFillColor(INK)
        c.drawString(MARGIN + 22, banner_y + banner_h - 10.5, "COVERAGE NOTE — REQUESTED PERIOD EXCEEDS RETAINED HISTORY")
        note_style = ParagraphStyle("coverage", fontName="Helvetica", fontSize=7.6, leading=10, textColor=INK)
        note_p = Paragraph(coverage_note, note_style)
        note_p.wrapOn(c, PAGE_W - 2 * MARGIN - 24, banner_h - 12)
        note_p.drawOn(c, MARGIN + 12, banner_y + 4)
        card_top = banner_y - 8 * mm

    cards_y = card_top - card_h
    card_gap = 6 * mm
    card_w2 = (PAGE_W - 2 * MARGIN - 2 * card_gap) / 3
    if peak:
        peak_title = f"Traffic peaked at {_fmt_num(peak)}"
        peak_body = f"The highest observed bucket is {_fmt_num(peak)} queries, about {peak_ratio:.1f}× the period average. This is a traffic anomaly worth inspecting at the exact timestamp."
    else:
        peak_title = "No retained peak to compare"
        peak_body = "There is not enough retained query history for a meaningful peak comparison in this period."
    _draw_insight(c, MARGIN, cards_y, card_w2, card_h, "Activity", peak_title, peak_body, RED if peak_ratio >= 2 else BLUE, PALE_RED if peak_ratio >= 2 else PALE_BLUE)

    if blocked_pct >= 20:
        status_title = f"{_fmt_pct(blocked_pct)} currently classified blocked"
        status_body = "Blocked traffic is a visible part of the current status mix. The report treats this as an observed state, not a security verdict."
        status_accent, status_bg = RED, PALE_RED
    else:
        status_title = f"{_fmt_pct(blocked_pct)} currently classified blocked"
        status_body = "The current classification mix is predominantly allowed or mixed. Use the status panel to identify domains that behave differently."
        status_accent, status_bg = GREEN, PALE_GREEN
    _draw_insight(c, MARGIN + card_w2 + card_gap, cards_y, card_w2, card_h, "Status", status_title, status_body, status_accent, status_bg)

    country_count = len(countries)
    country_title = f"{country_count} geolocated countries"
    country_body = "Observed public destination IPs are aggregated at country level. Country geography describes where DNS answers resolve, not verified server locations."
    _draw_insight(c, MARGIN + 2 * (card_w2 + card_gap), cards_y, card_w2, card_h, "Destinations", country_title, country_body, PURPLE, PALE_PURPLE)

    _draw_donut(c, MARGIN, 103 * mm, PAGE_W - 2 * MARGIN, 68 * mm, breakdown)

    c.setFont("Helvetica-Bold", 12)
    c.setFillColor(INK)
    c.drawString(MARGIN, 90 * mm, "Visibility snapshot")
    c.setFont("Helvetica", 8)
    c.setFillColor(MUTED)
    c.drawString(MARGIN, 84 * mm, "Top items currently tracked by DNS Inspector — useful context for the period, not a fabricated period-only count.")

    top_domains = (stats or {}).get("domains") or []
    top_devices = (stats or {}).get("devices") or []
    _draw_bar_list(c, MARGIN, 16 * mm, (PAGE_W - 2 * MARGIN - 6 * mm) / 2, 64 * mm, "Most queried domains", top_domains, BLUE)
    _draw_bar_list(c, MARGIN + (PAGE_W - 2 * MARGIN) / 2 + 3 * mm, 16 * mm, (PAGE_W - 2 * MARGIN - 6 * mm) / 2, 64 * mm, "Most active devices", top_devices, TEAL)

    _draw_page_footer(c, 2, window_label, generated_iso)
    c.showPage()

    # Page 3 — destinations and context
    _draw_section_title(c, MARGIN, PAGE_H - 22 * mm, "Destination context", "Country-level aggregation from observed public A/AAAA answers.")
    _draw_round_rect(c, MARGIN, 151 * mm, PAGE_W - 2 * MARGIN, 105 * mm, WHITE, GRID, 10)

    c.setFont("Helvetica-Bold", 11)
    c.setFillColor(INK)
    c.drawString(MARGIN + 12, 244 * mm, "Observed destination countries")
    max_obs = max([float(x.get("observation_count") or 0) for x in countries[:10]] or [1])
    row_y = 232 * mm
    for country in countries[:10]:
        name = str(country.get("country_name") or country.get("country_code") or "Unknown")
        obs = float(country.get("observation_count") or 0)
        c.setFont("Helvetica", 8)
        c.setFillColor(INK)
        c.drawString(MARGIN + 12, row_y, name[:30])
        c.setFillColor(HexColor("#EDF2F7"))
        c.roundRect(MARGIN + 82, row_y - 2, 82 * mm, 6, 3, fill=1, stroke=0)
        c.setFillColor(PURPLE)
        c.roundRect(MARGIN + 82, row_y - 2, 82 * mm * (obs / max_obs), 6, 3, fill=1, stroke=0)
        c.setFillColor(MUTED)
        c.drawRightString(PAGE_W - MARGIN - 12, row_y, _fmt_num(obs))
        row_y -= 17
        if row_y < 159 * mm:
            break

    c.setFont("Helvetica-Bold", 10)
    c.setFillColor(INK)
    c.drawString(MARGIN, 137 * mm, "How to read this")
    style = ParagraphStyle("note", fontName="Helvetica", fontSize=8.2, leading=11.5, textColor=MUTED)
    # Known-datacenter follow-up (Issue #88): the destination coordinate
    # hierarchy (exact city GeoIP > curated known-datacenter region > country
    # only > unmapped) must stay visible in the PDF, not just on the map.
    provenance = ((map_data or {}).get("coverage") or {}).get("provenance") or {}
    city_n = int(provenance.get("city_geoip") or 0)
    dc_n = int(provenance.get("known_datacenter") or 0)
    provenance_note = ""
    if city_n or dc_n:
        provenance_note = (
            f" Includes {_fmt_num(city_n)} City GeoIP (exact coordinate) and {_fmt_num(dc_n)} Known datacenter "
            "(region-derived, not exact) matched observations."
        )
    note = Paragraph(
        "The destination section intentionally avoids implying exact physical infrastructure. "
        "A country bubble is an aggregation of observed answer IPs that matched the configured country database. "
        "This is useful for traffic distribution, but it should not be interpreted as a map of individual servers."
        + provenance_note,
        style,
    )
    note.wrapOn(c, PAGE_W - 2 * MARGIN, 30 * mm)
    note.drawOn(c, MARGIN, 112 * mm)

    # Investigation prompt card. A static PDF cannot itself be clicked, so this
    # is deliberately a plain note rather than a pseudo-button -- interactive
    # drill-down lives in the DNS Inspector UI, not here. Every text element
    # is its own row with a fixed, generous gap to the next, so nothing can
    # overlap regardless of exact font metrics.
    card_x = MARGIN + 14
    card_w = PAGE_W - 2 * MARGIN - 28
    _draw_round_rect(c, MARGIN, 28 * mm, PAGE_W - 2 * MARGIN, 69 * mm, NAVY, NAVY, 12)

    c.setFont("Helvetica-Bold", 13)
    c.setFillColor(WHITE)
    c.drawString(card_x, 82 * mm, "Investigation prompt")

    sentence_style = ParagraphStyle("invest_sentence", fontName="Helvetica", fontSize=8.5, leading=11.5, textColor=HexColor("#CBD5E1"))
    sentence = Paragraph(
        "Traffic peaks and status changes are easiest to explain from the exact interval that produced them, not from this static summary.",
        sentence_style,
    )
    sentence.wrapOn(c, card_w, 20 * mm)
    sentence.drawOn(c, card_x, 62 * mm)

    c.setFillColor(TEAL)
    c.circle(card_x + 2.5, 52.5 * mm, 2.5, fill=1, stroke=0)
    c.setFillColor(WHITE)
    c.setFont("Helvetica-Bold", 8.5)
    c.drawString(card_x + 11, 50.5 * mm, "Investigate this interval in DNS Inspector")

    followup_style = ParagraphStyle("invest_followup", fontName="Helvetica", fontSize=7.6, leading=10.5, textColor=HexColor("#94A3B8"))
    followup = Paragraph(
        "Open the Analytics tab and select a bucket on the activity timeline to see exact query counts, new domains, devices and status changes for that interval.",
        followup_style,
    )
    followup.wrapOn(c, card_w, 22 * mm)
    followup.drawOn(c, card_x, 34 * mm)

    _draw_page_footer(c, 3, window_label, generated_iso)
    c.showPage()

    c.setFillColor(NAVY)
    c.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
    c.setFillColor(WHITE)
    c.setFont("Helvetica-Bold", 22)
    c.drawString(MARGIN, PAGE_H - 42 * mm, "Read the report in context")
    c.setFont("Helvetica", 9)
    c.setFillColor(HexColor("#CBD5E1"))
    c.drawString(MARGIN, PAGE_H - 51 * mm, "The PDF is intentionally visual. Detailed evidence remains in the live DNS Inspector dashboard.")

    bullets = [
        ("Activity", "Start with the timeline. Large departures from the local baseline are the best candidates for drill-down."),
        ("Status", "Blocked / allowed percentages describe the current classification state and should be read alongside the domains that drive them."),
        ("Destinations", "Country aggregation provides context for observed public answers; it is not a physical server map."),
        ("Next step", "Use the interactive dashboard interval selection for the exact bucket, then inspect the affected domains and devices."),
    ]
    yy = PAGE_H - 80 * mm
    for label, body in bullets:
        c.setFillColor(TEAL)
        c.circle(MARGIN + 3, yy + 3, 3, fill=1, stroke=0)
        c.setFillColor(WHITE)
        c.setFont("Helvetica-Bold", 9.5)
        c.drawString(MARGIN + 14, yy, label)
        c.setFillColor(HexColor("#CBD5E1"))
        p = Paragraph(body, ParagraphStyle("bp", fontName="Helvetica", fontSize=8, leading=11, textColor=HexColor("#CBD5E1")))
        p.wrapOn(c, PAGE_W - MARGIN - (MARGIN + 14), 23 * mm)
        p.drawOn(c, MARGIN + 14, yy - 18)
        yy -= 34 * mm

    _draw_page_footer(c, 4, window_label, generated_iso, dark=True)
    c.save()
    buf.seek(0)
    return buf
