from datetime import date

from dnssec_tracker.models import Event
from dnssec_tracker.render.calendar import render_calendar


def _make_events() -> list[Event]:
    return [
        Event(ts="2026-04-03T09:00:00Z", source="state",
              event_type="state_changed", summary="GoalState -> omnipresent",
              zone="example.com", key_tag=12345, key_role="KSK"),
        Event(ts="2026-04-03T09:30:00Z", source="rndc",
              event_type="rndc_state_changed", summary="dnskey -> omnipresent",
              zone="example.com", key_tag=12345, key_role="KSK"),
        Event(ts="2026-04-05T12:00:00Z", source="syslog",
              event_type="iodyn_settime", summary="modifying KSK Publish",
              zone="example.com", key_role="KSK"),
        Event(ts="2026-05-10T00:00:00Z", source="dns",
              event_type="dns_ds_appeared_at_parent",
              summary="DS added at parent for example.com",
              zone="example.com"),
    ]


def test_calendar_covers_every_month_in_window():
    html = render_calendar(_make_events(),
                           from_ts="2026-04-01T00:00:00Z",
                           to_ts="2026-05-31T23:59:59Z")
    assert "April 2026" in html
    assert "May 2026" in html


def test_calendar_marks_days_with_events():
    html = render_calendar(_make_events(),
                           from_ts="2026-04-01T00:00:00Z",
                           to_ts="2026-05-31T23:59:59Z")
    # A day with events should pick up has-events and a density class.
    assert "has-events" in html
    assert "count-" in html
    # And should emit source dots for both state and rndc on April 3.
    assert "src-state" in html
    assert "src-rndc" in html
    assert "src-syslog" in html
    assert "src-dns" in html


def test_calendar_legend_renders():
    html = render_calendar([],
                           from_ts="2026-04-01T00:00:00Z",
                           to_ts="2026-04-30T00:00:00Z")
    assert 'class="cal-legend"' in html
    assert "April 2026" in html


def test_calendar_multiple_events_become_higher_density(tmp_path):
    events = [
        Event(ts="2026-04-15T%02d:00:00Z" % h, source="state",
              event_type="state_changed", summary=f"change {h}",
              zone="example.com", key_tag=1, key_role="KSK",
              detail={"field": "DNSKEYState", "new": "omnipresent"})
        for h in range(7)  # 7 events on one day -> "count-l"
    ]
    html = render_calendar(events,
                           from_ts="2026-04-01T00:00:00Z",
                           to_ts="2026-04-30T00:00:00Z",
                           today=date(2026, 4, 15))
    assert "count-l" in html
    # Today marker should be applied.
    assert "cal-today" in html
