"""Regression test: the state-transition-timeline SVG must not use
hard-coded dark or light text colours on unspecified fills — that
was the "black text on dark background, unreadable in dark mode"
bug. Title text, lane labels, and legend labels should all inherit
``currentColor``; segment value labels are the exception and use a
black+white-outline halo (paint-order stroke fill) so they read on
every STATE_COLORS fill.
"""

from __future__ import annotations

import re

from dnssec_tracker.models import Event, Key
from dnssec_tracker.render.timeline_svg import render_state_timeline


def _state_change_event(tag: int, field: str, new: str, ts: str) -> Event:
    return Event(
        ts=ts,
        source="state",
        event_type="state_changed",
        summary=f"{field} -> {new}",
        zone="example.com",
        key_tag=tag,
        key_role="KSK",
        detail={"field": field, "old": "hidden", "new": new},
    )


def _key(tag: int) -> Key:
    return Key(
        zone="example.com", key_tag=tag, role="KSK",
        algorithm=13, key_id=f"k{tag}",
        first_seen="2026-01-01T00:00:00Z",
    )


def test_title_text_is_currentColor():
    """The bold time-range title at the top of the SVG used to have
    no ``fill`` attribute, defaulting to browser-default black and
    becoming invisible in dark mode. It must explicitly use
    ``currentColor`` so the theme-aware <body> foreground drives it."""
    events = [
        _state_change_event(111, "GoalState", "omnipresent", "2026-04-01T00:00:00Z"),
        _state_change_event(111, "DNSKEYState", "omnipresent", "2026-04-10T00:00:00Z"),
    ]
    svg = render_state_timeline(events, [_key(111)])
    # The first <text> element in the SVG is the bold title. It must
    # carry fill="currentColor".
    first_text = re.search(r"<text\b[^>]*>", svg).group(0)
    assert 'fill="currentColor"' in first_text


def test_lane_labels_are_currentColor():
    """The row labels on the left edge ("KSK 111 · GoalState", etc.)
    used to have no fill attribute either."""
    events = [
        _state_change_event(111, "GoalState", "omnipresent", "2026-04-01T00:00:00Z"),
        _state_change_event(111, "GoalState", "hidden", "2026-04-15T00:00:00Z"),
    ]
    svg = render_state_timeline(events, [_key(111)])
    # Extract every <text> that contains a bullet "·" — those are
    # the row labels. All of them must carry currentColor.
    labels = re.findall(r'<text\b[^>]*>[^<]*·[^<]*</text>', svg)
    assert labels, "expected at least one lane label"
    for lbl in labels:
        assert 'fill="currentColor"' in lbl, f"lane label lost currentColor: {lbl!r}"


def test_legend_labels_are_currentColor():
    """The legend at the bottom (hidden / rumoured / omnipresent /
    unretentive / N/A) labels used to have no fill and would vanish
    against a dark page."""
    events = [
        _state_change_event(111, "GoalState", "omnipresent", "2026-04-01T00:00:00Z"),
        _state_change_event(111, "GoalState", "rumoured", "2026-04-10T00:00:00Z"),
    ]
    svg = render_state_timeline(events, [_key(111)])
    # The known state names that appear in the legend. Because the
    # same state name can also appear as an in-segment label (with
    # the halo style) we grab every matching <text> and require at
    # least one of them to carry currentColor — that's the legend
    # entry, positioned after all segment labels.
    for name in ("hidden", "rumoured", "omnipresent", "unretentive"):
        matches = re.findall(
            r'<text\b[^>]*>' + re.escape(name) + r'</text>',
            svg,
        )
        assert matches, f"legend label {name!r} not emitted"
        assert any('fill="currentColor"' in m for m in matches), (
            f"legend label {name!r} is not rendered with currentColor "
            f"in any occurrence: {matches}"
        )


def test_segment_labels_carry_halo():
    """Labels painted over coloured segments are an exception — they
    use paint-order stroke-fill with a white outline behind black
    text so they read on every STATE_COLORS fill in both themes."""
    events = [
        _state_change_event(111, "GoalState", "omnipresent", "2026-04-01T00:00:00Z"),
        _state_change_event(111, "GoalState", "hidden", "2026-04-15T00:00:00Z"),
    ]
    svg = render_state_timeline(events, [_key(111)])
    # The value labels ("omnipresent" / "hidden") rendered on wide
    # segments must carry the paint-order halo.
    seg_labels = re.findall(
        r'<text\b[^>]*paint-order="stroke fill"[^>]*>[^<]+</text>',
        svg,
    )
    assert seg_labels, "expected at least one segment-label with halo"


def test_lane_background_uses_palette_variable():
    """Lane backgrounds used to be a hardcoded light-grey
    (#f5f5f7) that sat oddly on the dark theme. They should use
    var(--surface-alt) so the chrome matches whichever palette is
    active."""
    events = [
        _state_change_event(111, "GoalState", "omnipresent", "2026-04-01T00:00:00Z"),
        _state_change_event(111, "GoalState", "rumoured", "2026-04-10T00:00:00Z"),
    ]
    svg = render_state_timeline(events, [_key(111)])
    assert "var(--surface-alt)" in svg
    assert "#f5f5f7" not in svg, "hard-coded lane background snuck back in"
