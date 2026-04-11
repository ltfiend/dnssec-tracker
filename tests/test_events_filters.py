"""Regex filters + calendar date range on the /events page.

Tests the regex-aware query path on the DB layer, the date
normalisation helper on the route layer, and the end-to-end page
rendering via the real FastAPI app + TestClient.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dnssec_tracker.app import create_app
from dnssec_tracker.config import Config
from dnssec_tracker.db import Database
from dnssec_tracker.models import Event
from dnssec_tracker.web.routes import _expand_date


# ---- _expand_date --------------------------------------------------


def test_expand_date_from_turns_to_start_of_day():
    assert _expand_date("2026-04-10", end=False) == "2026-04-10T00:00:00Z"


def test_expand_date_to_turns_to_end_of_day():
    assert _expand_date("2026-04-10", end=True) == "2026-04-10T23:59:59Z"


def test_expand_date_passes_full_iso_through_unchanged():
    raw = "2026-04-10T12:34:56Z"
    assert _expand_date(raw, end=False) == raw
    assert _expand_date(raw, end=True) == raw


def test_expand_date_handles_empty_and_none():
    assert _expand_date(None, end=False) is None
    assert _expand_date("", end=True) == ""


# ---- DB regex query ------------------------------------------------


def _seed_db(tmp_path: Path) -> Database:
    db = Database(tmp_path / "events.db")
    rows = [
        # (ts, source, event_type, zone)
        ("2026-04-10T00:00:00Z", "state",  "state_changed",    "example.com"),
        ("2026-04-10T01:00:00Z", "rndc",   "rndc_state_changed", "example.com"),
        ("2026-04-10T02:00:00Z", "dns",    "dns_ds_appeared_at_parent", "fus3d.net"),
        ("2026-04-10T03:00:00Z", "dns",    "dns_dnskey_appeared_at_zone", "fus3d.net"),
        ("2026-04-10T04:00:00Z", "syslog", "iodyn_key_created",  "foo.internal"),
        ("2026-04-11T05:00:00Z", "named",  "named_dnskey_active","example.org"),
    ]
    for ts, src, et, zone in rows:
        db.insert_event(Event(
            ts=ts, source=src, event_type=et, summary=f"{et} on {zone}",
            zone=zone,
        ))
    return db


def test_zone_filter_accepts_regex_alternation(tmp_path):
    db = _seed_db(tmp_path)
    got = db.query_events(zone="example\\.(com|org)")
    zones = sorted({e.zone for e in got})
    assert zones == ["example.com", "example.org"]


def test_zone_filter_anchored_regex(tmp_path):
    db = _seed_db(tmp_path)
    # Anchored regex: only zones that start with "fus3d".
    got = db.query_events(zone="^fus3d\\.")
    assert {e.zone for e in got} == {"fus3d.net"}


def test_zone_filter_plain_substring_still_works(tmp_path):
    db = _seed_db(tmp_path)
    got = db.query_events(zone="example")   # no regex metachars
    assert {e.zone for e in got} == {"example.com", "example.org"}


def test_event_type_regex_matches_family(tmp_path):
    db = _seed_db(tmp_path)
    # All dns_ds_* events
    got = db.query_events(event_type="^dns_ds_")
    assert [e.event_type for e in got] == ["dns_ds_appeared_at_parent"]


def test_source_regex_covers_channel(tmp_path):
    db = _seed_db(tmp_path)
    # DNS "channel" (dns + rndc) via alternation
    got = db.query_events(source="^(dns|rndc)$")
    sources = sorted({e.source for e in got})
    assert sources == ["dns", "rndc"]


def test_invalid_regex_matches_nothing_rather_than_erroring(tmp_path):
    db = _seed_db(tmp_path)
    got = db.query_events(zone="example.com(")  # unbalanced paren
    assert got == [], "invalid regex should produce no rows, not raise"


def test_combined_regex_and_date_range(tmp_path):
    db = _seed_db(tmp_path)
    got = db.query_events(
        source="^(dns|rndc)$",
        from_ts="2026-04-10T00:00:00Z",
        to_ts="2026-04-10T23:59:59Z",
    )
    # Should match 3 events on 2026-04-10 where source is dns or rndc
    assert len(got) == 3
    assert {e.source for e in got} == {"dns", "rndc"}


# ---- events page end-to-end ----------------------------------------


@pytest.fixture
def seeded_client(tmp_path):
    cfg = Config(
        key_dir=tmp_path,
        syslog_path=None,
        named_log_path=None,
        db_path=tmp_path / "events.db",
    )
    for k in cfg.enabled_collectors:
        cfg.enabled_collectors[k] = False
    app = create_app(cfg)
    _seed_db_into(app.state.db)
    return TestClient(app)


def _seed_db_into(db: Database) -> None:
    rows = [
        ("2026-04-10T00:00:00Z", "state",  "state_changed",  "example.com"),
        ("2026-04-10T02:00:00Z", "dns",    "dns_ds_appeared_at_parent", "fus3d.net"),
        ("2026-04-10T03:00:00Z", "dns",    "dns_dnskey_appeared_at_zone", "fus3d.net"),
        ("2026-04-11T05:00:00Z", "named",  "named_dnskey_active","example.org"),
    ]
    for ts, src, et, zone in rows:
        db.insert_event(Event(
            ts=ts, source=src, event_type=et, summary=f"{et} on {zone}",
            zone=zone,
        ))


def test_events_page_uses_html5_date_inputs(seeded_client):
    r = seeded_client.get("/events")
    assert r.status_code == 200
    html = r.text
    # Both from/to should render as <input type="date" ...>
    assert html.count('type="date"') == 2
    # And the filter note calls out regex support.
    assert "regex" in html.lower()


def test_events_page_zone_regex_filter(seeded_client):
    r = seeded_client.get("/events", params={"zone": "^fus3d\\."})
    assert r.status_code == 200
    html = r.text
    # Only fus3d.net events should be in the table body; example.*
    # should not.
    assert "fus3d.net" in html
    assert "dns_ds_appeared_at_parent" in html
    # Other zones must be absent from the event rows. Filter inputs
    # preserve the user's zone= text, which starts with "fus3d" too,
    # so we grep for the ones that wouldn't be anywhere else.
    assert "example.org" not in html
    assert "named_dnskey_active" not in html


def test_events_page_date_range_filters_to_single_day(seeded_client):
    r = seeded_client.get(
        "/events",
        params={"from": "2026-04-10", "to": "2026-04-10"},
    )
    assert r.status_code == 200
    html = r.text
    # 2026-04-10 events: 3 rows from the seed
    assert "state_changed" in html
    assert "dns_ds_appeared_at_parent" in html
    assert "dns_dnskey_appeared_at_zone" in html
    # 2026-04-11 event must be filtered out
    assert "named_dnskey_active" not in html


def test_events_page_source_alternation_filter(seeded_client):
    r = seeded_client.get("/events", params={"source": "^(dns|named)$"})
    assert r.status_code == 200
    html = r.text
    # state_changed (source=state) should NOT be shown; dns_* and
    # named_* should be.
    assert "dns_ds_appeared_at_parent" in html
    assert "named_dnskey_active" in html
    assert "state_changed" not in html


def test_events_page_preserves_date_values_in_inputs(seeded_client):
    r = seeded_client.get(
        "/events",
        params={"from": "2026-04-10", "to": "2026-04-11"},
    )
    html = r.text
    # The input value attribute should carry back just the YYYY-MM-DD
    # so the browser's date picker shows the selected date.
    assert 'value="2026-04-10"' in html
    assert 'value="2026-04-11"' in html
