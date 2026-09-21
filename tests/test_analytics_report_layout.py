from io import BytesIO

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas

import analytics_report


def _boxes_overlap(a, b):
    ax0, ay0, ax1, ay1 = a
    bx0, by0, bx1, by1 = b
    return not (ax1 <= bx0 or bx1 <= ax0 or ay1 <= by0 or by1 <= ay0)


def _draw_callout():
    page_w, page_h = A4
    margin = 16 * mm
    c = canvas.Canvas(BytesIO(), pagesize=A4)
    card_x, card_y, card_w, card_h = margin, 28 * mm, page_w - 2 * margin, 69 * mm
    boxes = analytics_report._draw_investigation_callout(c, card_x, card_y, card_w, card_h)
    return card_x, card_y, card_w, card_h, boxes


def test_investigation_callout_blocks_stay_inside_the_card():
    card_x, card_y, card_w, card_h, boxes = _draw_callout()
    assert set(boxes) == {"heading", "sentence", "pill", "followup"}
    for name, (x0, y0, x1, y1) in boxes.items():
        assert x0 >= card_x, name
        assert x1 <= card_x + card_w, name
        assert y0 >= card_y, f"{name} spills below the card bottom"
        assert y1 <= card_y + card_h, f"{name} spills above the card top"


def test_investigation_callout_blocks_never_overlap():
    _, _, _, _, boxes = _draw_callout()
    names = list(boxes)
    for i, a_name in enumerate(names):
        for b_name in names[i + 1:]:
            assert not _boxes_overlap(boxes[a_name], boxes[b_name]), f"{a_name} overlaps {b_name}"


def test_investigation_callout_blocks_stack_top_to_bottom_in_order():
    _, _, _, _, boxes = _draw_callout()
    heading, sentence, pill, followup = (boxes["heading"], boxes["sentence"], boxes["pill"], boxes["followup"])
    # Each block's bottom sits above the next block's top: heading -> sentence -> pill -> followup.
    assert heading[1] >= sentence[3]
    assert sentence[1] >= pill[3]
    assert pill[1] >= followup[3]


def test_investigation_callout_followup_spans_full_content_width_not_squeezed_beside_pill():
    _, _, card_w, _, boxes = _draw_callout()
    pad_x = 14 * mm
    content_w = card_w - 2 * pad_x
    followup_x0, _, followup_x1, _ = boxes["followup"]
    assert followup_x1 - followup_x0 == content_w
