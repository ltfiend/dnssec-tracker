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
    ``KSK12345 GoalState=omnipresent`` inline label — the pre-
    clustering baseline for sparse streams."""

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
    assert "KSK12345" in svg
    assert "GoalState=omnipresent" in svg
