"""Per-lane clustering behaviour.

In the swim-lane timeline, clustering is scoped to a single lane —
events from different sources can't merge into one cluster because
they live on different horizontal lanes by construction. Within a
lane, events whose pixel x-coordinates are within ``cluster_px`` of
each other still collapse to a single circle (the mass-transition
legibility fix for KRRSIG + DNSKEY + DSState + GoalState all
ticking in the same rndc poll).

Inline per-event text labels are deliberately absent — detail
belongs in the tooltip, not floating text on the chart. The lane
label on the left identifies the category.
"""

from __future__ import annotations

import math
import re

from dnssec_tracker.models import Event
from dnssec_tracker.render.event_timeline import render_event_timeline


# Matches the primary event-cluster <circle>, which always carries
# ``stroke="currentColor"`` to separate it from the small
# milestone-cap circles (which have no stroke).
_CLUSTER_CIRCLE_RE = re.compile(
    r'<circle cx="([0-9.]+)" cy="([0-9.]+)" r="([0-9.]+)" '
    r'fill="([^"]+)"[^/]*?stroke="currentColor"'
)


def _circles(svg: str) -> list[tuple[float, float, float, str]]:
    """Return every cluster circle as ``(cx, cy, r, fill)``."""
    return [
        (float(cx), float(cy), float(r), fill)
        for cx, cy, r, fill in _CLUSTER_CIRCLE_RE.findall(svg)
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


# ---- Cluster vs. singleton -------------------------------------------


def test_many_events_at_same_ts_in_same_lane_collapse_into_one_circle():
    """Four state-file fields ticking in the same rndc poll —
    same source, same timestamp — collapse into a single cluster
    circle in the state lane."""

    ts = "2026-04-10T12:00:00Z"
    events = [
        _mk(ts, "state", "state_changed", summary="GoalState hidden -> omnipresent"),
        _mk(ts, "state", "state_changed", summary="DNSKEYState rumoured -> omnipresent"),
        _mk(ts, "state", "state_changed", summary="KRRSIGState rumoured -> omnipresent"),
        _mk(ts, "state", "state_changed", summary="DSState rumoured -> omnipresent"),
    ]
    svg = render_event_timeline(
        events, from_ts="2026-04-10T00:00:00Z", to_ts="2026-04-10T23:59:59Z"
    )
    circles = _circles(svg)
    assert len(circles) == 1

    # The cluster's data-tip carries every member.
    tip_match = re.search(r'data-tip="([^"]+)"', svg)
    assert tip_match is not None
    tip = tip_match.group(1)
    assert "GoalState" in tip
    assert "DNSKEYState" in tip
    assert "KRRSIGState" in tip
    assert "DSState" in tip


def test_events_spread_wide_do_not_cluster():
    """Four events a week apart each → four separate circles in
    their lane."""
    events = [
        _mk("2026-04-01T00:00:00Z", "state", summary="day 1"),
        _mk("2026-04-08T00:00:00Z", "state", summary="day 8"),
        _mk("2026-04-15T00:00:00Z", "state", summary="day 15"),
        _mk("2026-04-22T00:00:00Z", "state", summary="day 22"),
    ]
    svg = render_event_timeline(
        events, from_ts="2026-04-01T00:00:00Z", to_ts="2026-04-30T00:00:00Z"
    )
    assert len(_circles(svg)) == 4


def test_events_across_sources_land_in_separate_lanes_not_one_cluster():
    """With swim lanes, events from different sources at the same
    timestamp cannot share a cluster — each source has its own
    horizontal lane. Four separate circles with different y
    coordinates (one per lane)."""
    ts = "2026-04-10T12:00:00Z"
    events = [
        _mk(ts, "state", summary="s"),
        _mk(ts, "rndc",  summary="r"),
        _mk(ts, "dns",   summary="d"),
        _mk(ts, "syslog", summary="y"),
    ]
    svg = render_event_timeline(
        events, from_ts="2026-04-10T00:00:00Z", to_ts="2026-04-10T23:59:59Z"
    )
    circles = _circles(svg)
    assert len(circles) == 4
    # Each circle sits at a different cy (one per lane).
    ys = sorted({cy for _, cy, _, _ in circles})
    assert len(ys) == 4


# ---- Count badge -----------------------------------------------------


def test_cluster_count_badge_present_for_multi_member():
    ts = "2026-04-10T12:00:00Z"
    events = [_mk(ts, "state", summary=f"ev {i}") for i in range(5)]
    svg = render_event_timeline(
        events, from_ts="2026-04-10T00:00:00Z", to_ts="2026-04-10T23:59:59Z"
    )
    # The <text class="evt-count-badge">5</text> sits inside the
    # cluster circle.
    assert re.search(
        r'<text class="evt-count-badge"[^>]*>5</text>', svg,
    ), "cluster count badge for count=5 missing"


def test_singleton_has_no_count_badge():
    svg = render_event_timeline([
        _mk("2026-04-10T12:00:00Z", "state", summary="solo"),
    ])
    # No count badge rendered for count==1.
    assert 'class="evt-count-badge"' not in svg


# ---- Radius scaling --------------------------------------------------


def test_cluster_radius_scales_with_sqrt_of_count():
    """A 9-member cluster should be ~3x the base radius, capped
    at the max_radius constant in the renderer."""

    ts = "2026-04-10T12:00:00Z"
    events = [_mk(ts, "state", summary=f"ev {i}") for i in range(9)]
    svg = render_event_timeline(
        events, from_ts="2026-04-10T00:00:00Z", to_ts="2026-04-10T23:59:59Z"
    )
    circles = _circles(svg)
    assert len(circles) == 1
    _, _, radius, _ = circles[0]
    # The renderer uses base_radius=5.0, max_radius=11.0 — so
    # sqrt(9)*5 = 15 gets capped at 11. Assert that clusters
    # genuinely grow (2x+ the base is a lower bound).
    assert radius <= 11.001
    assert radius >= 5.0 * 2.0, (
        f"cluster radius {radius} did not scale with cluster size"
    )


# ---- Cluster colour --------------------------------------------------


def test_uniform_source_cluster_uses_source_colour():
    """A cluster in the state lane is filled with the state
    colour variable — lanes are single-source by construction."""
    ts = "2026-04-10T12:00:00Z"
    events = [_mk(ts, "state", summary=f"ev {i}") for i in range(3)]
    svg = render_event_timeline(
        events, from_ts="2026-04-10T00:00:00Z", to_ts="2026-04-10T23:59:59Z"
    )
    circles = _circles(svg)
    assert len(circles) == 1
    _, _, _, fill = circles[0]
    assert fill == "var(--state)"


# Note: the pre-lane-redesign test_mixed_source_cluster_uses_muted_colour
# was deleted. With swim lanes, mixed-source clusters cannot exist —
# events from different sources live on different lanes.


# ---- Singleton rendering --------------------------------------------


def test_singleton_has_no_inline_text_label():
    """The swim-lane redesign removed all per-event inline labels.
    A solo state_changed renders as a bare circle (plus milestone
    flag if applicable); detail goes in the tooltip."""

    svg = render_event_timeline([
        Event(
            ts="2026-04-10T12:00:00Z",
            source="state",
            event_type="state_changed",
            summary="KSK GoalState -> omnipresent",
            zone="example.com",
            key_tag=12345,
            key_role="KSK",
            detail={"field": "GoalState", "new": "omnipresent"},
        )
    ])
    # No free-standing text label carrying the detail — the
    # data-tip attribute has it, but no floating <text>.
    # Scan every non-chrome <text>: title strip, lane label, tick
    # labels, count badges. None should contain the summary.
    free_text_nodes = re.findall(r'<text[^>]*>([^<]+)</text>', svg)
    for t in free_text_nodes:
        assert "KSK GoalState" not in t
        assert "GoalState -> omnipresent" not in t
    # The detail lives in the data-tip attribute.
    assert 'data-tip="' in svg


def test_every_cluster_wraps_in_evt_cluster_group():
    """Each cluster is wrapped in a ``<g class="evt-cluster">`` so
    the page-level tooltip JS can attach listeners cleanly."""
    svg = render_event_timeline([
        _mk("2026-04-10T12:00:00Z", "state", summary="a"),
        _mk("2026-04-10T14:00:00Z", "rndc", summary="b"),
    ])
    assert svg.count('<g class="evt-cluster"') == 2
