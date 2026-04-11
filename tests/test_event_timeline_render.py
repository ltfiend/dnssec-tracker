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


def test_timeline_includes_event_markers_and_tooltips():
    svg = render_event_timeline(_events())
    # At least one <circle> for each event.
    assert svg.count("<circle") >= 4
    # Tooltips (<title>) carry the event summary text.
    assert "GoalState" in svg
    assert "rndc_state_changed" in svg
    assert "DS added at parent" in svg


def test_timeline_labels_include_role_and_field_for_state_changes():
    svg = render_event_timeline(_events())
    # KSK12345 + GoalState=omnipresent should appear as an inline label.
    assert "KSK12345" in svg


def test_empty_events_returns_placeholder_svg():
    svg = render_event_timeline([])
    assert "<svg" in svg
    assert "No events" in svg
