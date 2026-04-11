from pathlib import Path

from dnssec_tracker.config import Config
from dnssec_tracker.db import Database
from dnssec_tracker.models import Event, Key, Zone, now_iso
from dnssec_tracker.render.html_export import render_report_html
from dnssec_tracker.render.timeline_svg import (
    render_rndc_timeline,
    render_state_timeline,
)


def _seeded_db(tmp_path: Path) -> tuple[Database, Config]:
    db = Database(tmp_path / "events.db")
    cfg = Config(
        key_dir=Path("/tmp"),
        syslog_path=None,
        named_log_path=None,
        db_path=tmp_path / "events.db",
    )
    db.upsert_zone(Zone(name="example.com", key_dir="/keys"))
    db.upsert_key(Key(zone="example.com", key_tag=12345, role="KSK", algorithm=13))
    db.upsert_key(Key(zone="example.com", key_tag=67890, role="ZSK", algorithm=13))

    base_detail = lambda old, new: {"field": "GoalState", "old": old, "new": new}
    db.insert_event(Event(
        ts="2026-04-10T00:00:00Z",
        source="state",
        event_type="state_changed",
        summary="KSK goal hidden -> omnipresent",
        zone="example.com",
        key_tag=12345,
        key_role="KSK",
        detail=base_detail("hidden", "omnipresent"),
    ))
    db.insert_event(Event(
        ts="2026-04-10T01:00:00Z",
        source="state",
        event_type="state_changed",
        summary="KSK DNSKEYState rumoured -> omnipresent",
        zone="example.com",
        key_tag=12345,
        key_role="KSK",
        detail={"field": "DNSKEYState", "old": "rumoured", "new": "omnipresent"},
    ))
    db.insert_event(Event(
        ts="2026-04-10T02:00:00Z",
        source="rndc",
        event_type="rndc_state_changed",
        summary="KSK ds hidden -> rumoured",
        zone="example.com",
        key_tag=12345,
        key_role="KSK",
        detail={"field": "ds", "old": "hidden", "new": "rumoured"},
    ))
    db.insert_event(Event(
        ts="2026-04-10T03:00:00Z",
        source="syslog",
        event_type="iodyn_key_created",
        summary="Key.create:Creating example.com KSK key ...",
        zone="example.com",
        detail={"tag": "Key.create"},
    ))
    return db, cfg


def test_state_timeline_svg_contains_lane(tmp_path):
    db, cfg = _seeded_db(tmp_path)
    events = db.query_events(zone="example.com")
    keys = db.list_keys("example.com")
    svg = render_state_timeline(events, keys)
    assert "<svg" in svg
    assert "GoalState" in svg
    assert "DNSKEYState" in svg


def test_rndc_timeline_maps_fields(tmp_path):
    db, cfg = _seeded_db(tmp_path)
    events = db.query_events(zone="example.com")
    keys = db.list_keys("example.com")
    svg = render_rndc_timeline(events, keys)
    assert "<svg" in svg
    assert "DSState" in svg  # "ds" should be mapped to DSState


def test_render_report_html(tmp_path):
    db, cfg = _seeded_db(tmp_path)
    html = render_report_html(db, cfg, "example.com")
    assert "<html" in html
    assert "example.com" in html
    assert "Key inventory" in html
    assert "Chronological event log" in html
    assert "rndc" in html.lower()
    # counts section
    assert "on-disk state transition" in html
    assert "rndc-reported state change" in html or "rndc-reported" in html
    # new renderers must be included in the report
    assert "Calendar view" in html
    assert "cal-month" in html
    # split timelines
    assert "DNS event timeline" in html
    assert "File event timeline" in html
    assert "event-timeline" in html
    # per-key breakdown
    assert "Per-key breakdown" in html
    assert "K*.key file timings" in html
