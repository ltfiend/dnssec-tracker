"""Baseline render tests for the swim-lane event timeline.

The timeline's structure: one horizontal swim lane per source
present in the event list, ordered canonically
(state / key / rndc / dns / syslog / named). Each lane carries
its own dots; per-event inline labels are gone — detail lives in
the hover tooltip (``data-tip`` attribute on each cluster).
"""

from dnssec_tracker.models import Event
from dnssec_tracker.render.event_timeline import render_event_timeline


def _events():
    return [
        Event(ts="2026-04-01T08:00:00Z", source="state",
              event_type="state_changed", summary="GoalState -> omnipresent",
              zone="example.com", key_tag=12345, key_role="KSK",
              detail={"field": "GoalState", "new": "omnipresent"}),
        Event(ts="2026-04-05T12:00:00Z", source="rndc",
              event_type="rndc_state_changed", summary="dnskey rumoured -> omnipresent",
              zone="example.com", key_tag=12345, key_role="KSK",
              detail={"field": "dnskey", "new": "omnipresent"}),
        Event(ts="2026-04-10T00:00:00Z", source="dns",
              event_type="dns_ds_appeared_at_parent",
              summary="DS added at parent for example.com",
              zone="example.com"),
        Event(ts="2026-04-10T00:01:00Z", source="syslog",
              event_type="iodyn_rndc_reload",
              summary="bind_reload:RNDC reload",
              zone="example.com"),
    ]


def test_render_event_timeline_returns_svg():
    svg = render_event_timeline(_events())
    assert svg.startswith("<svg")
    assert "event-timeline" in svg
    assert "</svg>" in svg


def test_timeline_has_one_lane_per_source():
    """Four distinct sources in the event list → four lane labels
    rendered on the left edge."""
    svg = render_event_timeline(_events())
    import re
    labels = re.findall(
        r'<text class="evt-lane-label"[^>]*>([^<]+)</text>', svg,
    )
    # Canonical order: state, rndc, dns, syslog (key / named absent).
    assert labels == ["state", "rndc", "dns", "syslog"]


def test_timeline_includes_event_circles_and_data_tip_tooltips():
    svg = render_event_timeline(_events())
    # One cluster per source (each source lands in its own lane).
    # Plus potential milestone-flag cap circles for the
    # milestone types — we only require at least 4 event circles.
    assert svg.count("<circle") >= 4
    # data-tip attribute on each cluster carries the event detail.
    assert "GoalState" in svg
    assert "rndc_state_changed" in svg
    assert "DS added at parent" in svg


def test_no_inline_text_labels_for_singletons():
    """The whole point of the swim-lane redesign: no inline text
    clutter on individual events. Detail is in the tooltip; the
    lane label on the left identifies the category."""
    svg = render_event_timeline(_events())
    # The event summary text must NOT appear as standalone SVG
    # text (it only appears inside the data-tip attribute, not
    # as a floating <text> label on the chart).
    import re
    free_text = re.findall(
        r'<text[^>]*>([^<]+)</text>', svg,
    )
    # The only free <text> allowed: the title strip (timestamp
    # range), the lane labels, the axis tick labels, and cluster
    # count badges. None should contain an event summary like
    # "GoalState -> omnipresent".
    for t in free_text:
        assert "GoalState -> omnipresent" not in t
        assert "RNDC reload" not in t


def test_empty_events_returns_placeholder_svg():
    svg = render_event_timeline([])
    assert "<svg" in svg
    assert "No events" in svg
