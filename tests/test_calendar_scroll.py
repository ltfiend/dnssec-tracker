"""Tests for the three-month centred calendar + scroll navigation.

Covers:
* ``render_calendar(center=...)`` renders exactly three months
  (previous, centre, next) regardless of where events or scheduled
  dates actually fall.
* The scroll-navigation helper on the route parses
  ``cal_center=YYYY-MM`` and computes prev/next triples correctly,
  including year boundaries.
* The zone page pulls a large enough event set that old-month
  calendar cells still get source dots (regression for the "no dots
  on old months" bug).
* The nav links on the zone page carry ``cal_center=`` and preserve
  the current filter state.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dnssec_tracker.app import create_app
from dnssec_tracker.config import Config
from dnssec_tracker.models import Event, Key, Zone
from dnssec_tracker.render.calendar import render_calendar
from dnssec_tracker.web.routes import _calendar_scroll


# ---- render_calendar(center=...) ------------------------------------


def test_center_pins_window_to_three_months():
    """Events span February through September, but ``center=May`` must
    render exactly April / May / June — no more, no less."""
    events = [
        Event(ts=f"2026-{m:02d}-15T00:00:00Z", source="state",
              event_type="state_changed", summary=f"m{m}",
              zone="example.com", key_tag=1, key_role="KSK",
              detail={"field": "GoalState", "new": "omnipresent"})
        for m in range(2, 10)
    ]
    html = render_calendar(events, center=date(2026, 5, 15))
    assert "April 2026" in html
    assert "May 2026" in html
    assert "June 2026" in html
    assert "February 2026" not in html
    assert "July 2026" not in html
    assert "March 2026" not in html
    assert "September 2026" not in html


def test_center_at_year_boundary_december():
    """center=December 2026 should render Nov 2026 / Dec 2026 / Jan 2027."""
    html = render_calendar([], center=date(2026, 12, 10))
    assert "November 2026" in html
    assert "December 2026" in html
    assert "January 2027" in html


def test_center_at_year_boundary_january():
    """center=January 2026 should render Dec 2025 / Jan 2026 / Feb 2026."""
    html = render_calendar([], center=date(2026, 1, 5))
    assert "December 2025" in html
    assert "January 2026" in html
    assert "February 2026" in html


def test_center_with_events_in_all_three_months_shows_dots():
    """Regression for the reported bug: if events DO fall on old
    calendar months in the pinned window, their source dots must
    render (previously old months showed cells without dots because
    the event query was limited to the most-recent 100 rows)."""
    events = [
        Event(ts="2026-04-15T00:00:00Z", source="state",
              event_type="state_changed", summary="april event",
              zone="example.com", key_tag=1, key_role="KSK",
              detail={"field": "GoalState", "new": "omnipresent"}),
        Event(ts="2026-05-20T00:00:00Z", source="rndc",
              event_type="rndc_state_changed", summary="may event",
              zone="example.com", key_tag=1, key_role="KSK"),
        Event(ts="2026-06-10T00:00:00Z", source="dns",
              event_type="dns_ds_appeared_at_parent", summary="june event",
              zone="example.com", key_tag=1),
    ]
    html = render_calendar(events, center=date(2026, 5, 15))
    # Each source's dot class should appear at least once in the
    # rendered markup — April shows src-state, May src-rndc, June src-dns.
    assert 'class="cal-dot src-state"' in html
    assert 'class="cal-dot src-rndc"' in html
    assert 'class="cal-dot src-dns"' in html
    # And has-events class should land on at least three cells.
    assert html.count("has-events") >= 3


def test_no_center_keeps_auto_window_for_backward_compat():
    """When center is None (the report-export path), the original
    event-bracketing auto-window still applies so the report keeps
    showing the full history in one shot."""
    events = [
        Event(ts="2025-01-15T00:00:00Z", source="state",
              event_type="state_changed", summary="way old",
              zone="example.com", key_tag=1, key_role="KSK"),
        Event(ts="2026-05-10T00:00:00Z", source="state",
              event_type="state_changed", summary="recent",
              zone="example.com", key_tag=1, key_role="KSK"),
    ]
    html = render_calendar(events)  # no center
    # Auto-window brackets the events, so January 2025 + May 2026
    # both appear (plus the months in between).
    assert "January 2025" in html
    assert "May 2026" in html


# ---- _calendar_scroll helper ----------------------------------------


def test_calendar_scroll_parses_valid_input():
    center, prev, nxt = _calendar_scroll("2026-05")
    assert center == date(2026, 5, 1)
    assert prev == date(2026, 4, 1)
    assert nxt == date(2026, 6, 1)


def test_calendar_scroll_handles_year_rollover_forward():
    center, prev, nxt = _calendar_scroll("2026-12")
    assert center == date(2026, 12, 1)
    assert prev == date(2026, 11, 1)
    assert nxt == date(2027, 1, 1)


def test_calendar_scroll_handles_year_rollover_backward():
    center, prev, nxt = _calendar_scroll("2026-01")
    assert center == date(2026, 1, 1)
    assert prev == date(2025, 12, 1)
    assert nxt == date(2026, 2, 1)


def test_calendar_scroll_defaults_to_current_month_when_missing():
    center, prev, nxt = _calendar_scroll(None)
    today = date.today().replace(day=1)
    assert center == today


def test_calendar_scroll_ignores_garbage_and_falls_back():
    center, _, _ = _calendar_scroll("not-a-month")
    assert center == date.today().replace(day=1)
    center, _, _ = _calendar_scroll("2026-13")  # invalid month
    assert center == date.today().replace(day=1)


# ---- end-to-end: zone page ------------------------------------------


def _make_app(tmp_path: Path):
    cfg = Config(
        key_dir=tmp_path,
        syslog_path=None,
        named_log_path=None,
        db_path=tmp_path / "events.db",
    )
    for k in cfg.enabled_collectors:
        cfg.enabled_collectors[k] = False
    app = create_app(cfg)
    return app, app.state.db, cfg


def test_zone_page_renders_three_months_by_default(tmp_path):
    app, db, _cfg = _make_app(tmp_path)
    db.upsert_zone(Zone(name="example.com", key_dir=str(tmp_path)))
    with TestClient(app) as client:
        r = client.get("/zones/example.com")
    assert r.status_code == 200
    body = r.text
    # Nav bar + prev/later buttons are present.
    assert 'class="cal-nav"' in body
    assert "earlier" in body
    assert "later" in body
    # cal-nav-current carries the center YYYY-MM string.
    assert 'class="cal-nav-current"' in body


def test_zone_nav_preserves_filter_state_in_prev_next_links(tmp_path):
    app, db, _cfg = _make_app(tmp_path)
    db.upsert_zone(Zone(name="example.com", key_dir=str(tmp_path)))
    with TestClient(app) as client:
        r = client.get(
            "/zones/example.com",
            params={"role": "KSK", "hide_types": "rrsig,soa"},
        )
    assert r.status_code == 200
    body = r.text
    # The prev/next links must carry role=KSK and hide_types= along
    # with cal_center so the user doesn't lose their filter selection
    # when they scroll the calendar.
    assert "role=KSK" in body
    assert "hide_types=rrsig,soa" in body


def test_zone_page_accepts_cal_center_param_and_shows_that_window(tmp_path):
    app, db, _cfg = _make_app(tmp_path)
    db.upsert_zone(Zone(name="example.com", key_dir=str(tmp_path)))
    # Seed an event in the chosen window so there's *something* to dot.
    db.insert_event(Event(
        ts="2025-05-15T00:00:00Z", source="state",
        event_type="state_changed", summary="historical",
        zone="example.com", key_tag=1, key_role="KSK",
        detail={"field": "GoalState", "new": "omnipresent"},
    ))
    with TestClient(app) as client:
        r = client.get("/zones/example.com", params={"cal_center": "2025-05"})
    assert r.status_code == 200
    body = r.text
    # The centred window: April / May / June 2025.
    assert "April 2025" in body
    assert "May 2025" in body
    assert "June 2025" in body
    # The seeded event's source dot must appear — this is the
    # regression for the "no dots on old dates" bug (the event is
    # dated May 2025 which would previously have been outside the
    # most-recent-100 slice).
    assert 'class="cal-dot src-state"' in body


def test_zone_page_with_many_old_events_shows_dots_in_old_calendar(tmp_path):
    """Heavier regression: seed >100 recent events plus one very old
    event, ask for a calendar centred on the old date, and assert
    its dot renders. Previously the query was limited to
    events_per_page (100) so the old event got lost."""
    app, db, cfg = _make_app(tmp_path)
    db.upsert_zone(Zone(name="example.com", key_dir=str(tmp_path)))
    # The one event we care about — way back.
    db.insert_event(Event(
        ts="2024-06-15T00:00:00Z", source="state",
        event_type="state_changed", summary="ancient",
        zone="example.com", key_tag=42, key_role="KSK",
        detail={"field": "GoalState", "new": "omnipresent"},
    ))
    # A pile of recent events to push the old one off the first page.
    for i in range(150):
        db.insert_event(Event(
            ts=f"2026-04-{(i % 28) + 1:02d}T00:00:00Z",
            source="rndc",
            event_type="rndc_state_changed",
            summary=f"recent {i}",
            zone="example.com", key_tag=42, key_role="KSK",
            detail={"field": "dnskey", "new": "omnipresent"},
        ))
    # events_per_page default is 100 — far less than the 151 events.
    assert cfg.events_per_page < 151
    with TestClient(app) as client:
        r = client.get(
            "/zones/example.com", params={"cal_center": "2024-06"},
        )
    body = r.text
    assert "June 2024" in body
    # The old event's dot must survive. If events_per_page is still
    # the query limit, the ancient event never makes it into the
    # calendar's by_day map and the dot is missing — this assertion
    # enforces the fix.
    assert 'class="cal-dot src-state"' in body
