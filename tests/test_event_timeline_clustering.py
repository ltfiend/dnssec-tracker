"""Clustering behaviour of the event-timeline SVG renderer.

Events whose pixel x-coordinates land within ``cluster_px`` of each
other collapse into a single cluster circle. This keeps a mass state
transition (KRRSIGState + DNSKEYState + DSState + GoalState ticking in
the same rndc poll) legible instead of stacking a dozen overlapping
dots. Singletons must still render identically to the pre-clustering
baseline.
"""

from __future__ import annotations

import math
import re

from dnssec_tracker.models import Event
from dnssec_tracker.render.event_timeline import render_event_timeline


_DATA_CIRCLE_RE = re.compile(
    r'<circle cx="([0-9.]+)" cy="([0-9.]+)" r="([0-9.]+)" '
    r'fill="[^"]+" stroke="currentColor"'
)


def _circles(svg: str) -> list[tuple[float, float, float]]:
    """Return every data-circle in the SVG as (cx, cy, r) tuples.

    The legend at the bottom of the SVG uses its own short ``<circle
    cx=".." cy=".." r="4" fill=".." />`` form without the
    ``stroke="currentColor"`` attribute, so this filter targets the
    data-circles only.
    """

    return [
        (float(cx), float(cy), float(r))
        for cx, cy, r in _DATA_CIRCLE_RE.findall(svg)
    ]


def _mk(ts: str, source: str, et: str = "state_changed",
        summary: str = "", key_role: str | None = None) -> Event:
    return Event(
        ts=ts,
        source=source,
        event_type=et,
        summary=summary or f"{et} at {ts}",
        zone="example.com",
        key_role=key_role,
    )


# ---- Cluster vs. singleton --------------------------------------------


def test_many_events_at_same_ts_collapse_into_one_circle():
    """Four fields ticking in the same rndc poll → one circle, not four."""

    ts = "2026-04-10T12:00:00Z"
    events = [
        _mk(ts, "state", "state_changed", summary="GoalState hidden -> omnipresent"),
        _mk(ts, "state", "state_changed", summary="DNSKEYState rumoured -> omnipresent"),
        _mk(ts, "state", "state_changed", summary="KRRSIGState rumoured -> omnipresent"),
        _mk(ts, "state", "state_changed", summary="DSState rumoured -> omnipresent"),
    ]
    # Give the chart a wide window so same-ts events absolutely
    # project to the same x.
    svg = render_event_timeline(
        events, from_ts="2026-04-10T00:00:00Z", to_ts="2026-04-10T23:59:59Z"
    )

    circles = _circles(svg)
    assert len(circles) == 1, f"expected one cluster circle, got {len(circles)}"

    # Tooltip (the <title> child) must list every member.
    title_match = re.search(r"<title>(.*?)</title>", svg, re.DOTALL)
    assert title_match is not None
    title_text = title_match.group(1)
    assert "GoalState" in title_text
    assert "DNSKEYState" in title_text
    assert "KRRSIGState" in title_text
    assert "DSState" in title_text


def test_events_spread_wide_do_not_cluster():
    """Four events a day apart each → four separate circles."""

    events = [
        _mk("2026-04-01T00:00:00Z", "state", summary="day 1"),
        _mk("2026-04-08T00:00:00Z", "state", summary="day 8"),
        _mk("2026-04-15T00:00:00Z", "state", summary="day 15"),
        _mk("2026-04-22T00:00:00Z", "state", summary="day 22"),
    ]
    svg = render_event_timeline(
        events, from_ts="2026-04-01T00:00:00Z", to_ts="2026-04-30T00:00:00Z"
    )
    circles = _circles(svg)
    assert len(circles) == 4


# ---- Count badge -----------------------------------------------------


def test_cluster_count_badge_present_for_multi_member():
    ts = "2026-04-10T12:00:00Z"
    events = [_mk(ts, "state", summary=f"ev {i}") for i in range(5)]
    svg = render_event_timeline(
        events, from_ts="2026-04-10T00:00:00Z", to_ts="2026-04-10T23:59:59Z"
    )
    # A text element with the count, rendered inside the cluster circle.
    assert re.search(r"<text [^>]*>5</text>", svg), (
        "cluster count badge for count=5 missing"
    )


def test_singleton_has_no_count_badge():
    svg = render_event_timeline([
        _mk("2026-04-10T12:00:00Z", "state", summary="solo"),
    ])
    # The only <text> elements should be the axis-title, tick labels,
    # and the legend — none of them should be the bare digit "1".
    # Grep for a <text ...>1</text> and assert it's absent.
    assert not re.search(r"<text [^>]*>1</text>", svg)


# ---- Radius scaling --------------------------------------------------


def test_cluster_radius_scales_with_sqrt_of_count():
    """A 9-member cluster should be ~3x the base radius (sqrt(9))."""

    ts = "2026-04-10T12:00:00Z"
    events = [_mk(ts, "state", summary=f"ev {i}") for i in range(9)]
    svg = render_event_timeline(
        events, from_ts="2026-04-10T00:00:00Z", to_ts="2026-04-10T23:59:59Z"
    )
    circles = _circles(svg)
    assert len(circles) == 1
    _, _, radius = circles[0]
    base = 4.5
    expected = base * math.sqrt(9)  # ~13.5, but capped at 12
    # Either hits the cap or is close to 3x base — both are fine.
    assert radius <= 12.001
    assert radius >= base * 2.5, (
        f"radius {radius} should be ~3x base {base}, got only {radius / base:.2f}x"
    )


# ---- Cluster colour --------------------------------------------------


def test_uniform_source_cluster_uses_source_colour():
    ts = "2026-04-10T12:00:00Z"
    events = [_mk(ts, "state", summary=f"ev {i}") for i in range(3)]
    svg = render_event_timeline(
        events, from_ts="2026-04-10T00:00:00Z", to_ts="2026-04-10T23:59:59Z"
    )
    # Data circle (the one with count text 3 inside) is filled with
    # var(--state), not var(--muted).
    data_circle = re.search(
        r'<circle cx="[0-9.]+" cy="[0-9.]+" r="[0-9.]+" '
        r'fill="([^"]+)" stroke="currentColor"',
        svg,
    )
    assert data_circle is not None
    assert data_circle.group(1) == "var(--state)"


def test_mixed_source_cluster_uses_muted_colour():
    ts = "2026-04-10T12:00:00Z"
    events = [
        _mk(ts, "state", summary="ev 1"),
        _mk(ts, "dns",   summary="ev 2"),
        _mk(ts, "rndc",  summary="ev 3"),
    ]
    svg = render_event_timeline(
        events, from_ts="2026-04-10T00:00:00Z", to_ts="2026-04-10T23:59:59Z"
    )
    data_circle = re.search(
        r'<circle cx="[0-9.]+" cy="[0-9.]+" r="[0-9.]+" '
        r'fill="([^"]+)" stroke="currentColor"',
        svg,
    )
    assert data_circle is not None
    assert data_circle.group(1) == "var(--muted)"


# ---- Singleton still behaves like the legacy renderer ---------------


def test_singleton_inline_label_preserved_for_major_type():
    """A solo state_changed with field+new detail still gets its
    inline label. The label is truncated to ~22 chars so angled
    labels don't project too far vertically — the tooltip carries
    the full detail. Key identity (role+tag) and the field name
    must survive the truncation."""

    svg = render_event_timeline([
        Event(
            ts="2026-04-10T12:00:00Z",
            source="state",
            event_type="state_changed",
            summary="goal",
            zone="example.com",
            key_tag=12345,
            key_role="KSK",
            detail={"field": "GoalState", "new": "omnipresent"},
        )
    ])
    # Key identity preserved in the inline label.
    assert "KSK12345" in svg
    # Field name preserved (the 22-char cap may drop the trailing
    # value; the full "GoalState=omnipresent" would only survive
    # if the caller put it into the event summary, which isn't the
    # case here).
    assert "GoalState" in svg
    # Labels are now rotated so the transform attribute is present.
    assert 'class="evt-label"' in svg
    assert "rotate(" in svg


# ---- Angled labels + themed hover tooltip ----------------------------


def test_singleton_labels_are_rotated_to_prevent_horizontal_overlap():
    """Two events moderately close in time used to overwrite each
    other's inline labels — both labels landed on the same y-line
    and drew on top. The fix rotates labels by ±30° so they fan
    away from the axis. Assert the rotation transform is emitted
    on the label text element."""
    svg = render_event_timeline([
        Event(
            ts="2026-04-10T12:00:00Z",
            source="state",
            event_type="state_changed",
            summary="one",
            zone="example.com", key_tag=11111, key_role="KSK",
            detail={"field": "GoalState", "new": "omnipresent"},
        ),
        Event(
            ts="2026-04-10T14:00:00Z",
            source="state",
            event_type="state_changed",
            summary="two",
            zone="example.com", key_tag=22222, key_role="KSK",
            detail={"field": "DNSKEYState", "new": "omnipresent"},
        ),
    ])
    # Both labels are angled — the rotation transform carries
    # either -30 or 30 (above-axis vs below-axis clusters) and
    # happens at the label's own pivot point.
    import re
    angles = re.findall(
        r'<text class="evt-label"[^>]*transform="rotate\((-?\d+)\s',
        svg,
    )
    assert len(angles) == 2
    # Valid angle values for the fan-out layout.
    for a in angles:
        assert a in ("-30", "30")


def test_every_cluster_has_a_themed_hover_tip():
    """Each event cluster is wrapped in ``<g class="evt-cluster">``
    and carries a nested ``<g class="evt-tip">`` with the larger
    CSS-controlled tooltip. CSS in app.css makes the tip invisible
    by default; the parent :hover selector reveals it."""
    svg = render_event_timeline([
        Event(
            ts="2026-04-10T12:00:00Z", source="state",
            event_type="state_changed", summary="x",
            zone="example.com", key_tag=1, key_role="KSK",
            detail={"field": "GoalState", "new": "omnipresent"},
        ),
        Event(
            ts="2026-04-15T12:00:00Z", source="dns",
            event_type="dns_ds_appeared_at_parent", summary="y",
            zone="example.com", key_tag=1,
        ),
    ])
    assert svg.count('<g class="evt-cluster">') == 2
    # Each cluster has its own hover-tip group.
    assert svg.count('class="evt-tip"') == 2
    # And a themed background rect.
    assert svg.count('class="evt-tip-bg"') == 2
    # Tip lines use the larger font-size class.
    assert svg.count('class="evt-tip-line"') >= 2
    # The fallback <title> stays too (PDF export path).
    assert svg.count("<title>") == 2


def test_hover_tip_flips_left_when_dot_is_near_chart_right_edge():
    """Tooltip default is to the upper-right of the dot; when a
    dot is near the chart's right edge, the tip should flip to the
    left so it doesn't overflow the SVG."""
    # Put an event right at the end of the window.
    svg = render_event_timeline(
        [
            Event(
                ts="2026-04-01T00:00:00Z", source="state",
                event_type="state_changed", summary="start",
                zone="example.com", key_tag=1, key_role="KSK",
                detail={"field": "GoalState", "new": "omnipresent"},
            ),
            Event(
                ts="2026-04-30T23:59:00Z", source="state",
                event_type="state_changed", summary="end",
                zone="example.com", key_tag=1, key_role="KSK",
                detail={"field": "GoalState", "new": "hidden"},
            ),
        ],
        from_ts="2026-04-01T00:00:00Z",
        to_ts="2026-04-30T23:59:59Z",
    )
    import re
    tip_xs = [
        float(m.group(1))
        for m in re.finditer(
            r'<g class="evt-tip"[^>]*transform="translate\(([-\d.]+),',
            svg,
        )
    ]
    assert len(tip_xs) == 2
    # The second (right-edge) dot's tip x must be clearly to the
    # left of the first one — the flip kicked in. The dot is at
    # x ≈ 880 (within ~40 px of the right edge at 920); the tip
    # must sit left of that, not overflowing past 920.
    assert tip_xs[1] < 880
