"""End-to-end test for the per-key page.

Ensures that for a KSK we render: current timing snapshots, the DS
events (tied by key tag from the DS rdata at emit time), the split
DNS / file timelines, the calendar, and the timing-change subsection.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dnssec_tracker.app import create_app
from dnssec_tracker.collectors.dns_probe import DnsProbeCollector
from dnssec_tracker.config import Config
from dnssec_tracker.models import Event, Key, Zone, now_iso


DNSKEY_KSK_TXT = (
    "257 3 13 oJMRESz5E4gYzS35AJulupX0kDyQjM+9GsGZu6XW7A7m"
    "f2HxS/zV0SCNvyx8rDSb8CAW0Q9D2JVv9ZQvkLIc9g=="
)
KSK_TAG = 19463
DS_TXT = f"{KSK_TAG} 13 2 9e6c7a4d64e0a8b5bdfd1ed4bb6f3e9b21d9d9a0d9c2e3d4a5b6c7d8e9f0a1b2"


@pytest.fixture
def seeded_client(tmp_path):
    cfg = Config(
        key_dir=tmp_path,
        syslog_path=None,
        named_log_path=None,
        db_path=tmp_path / "events.db",
    )
    # disable live collectors — we seed data directly
    for k in cfg.enabled_collectors:
        cfg.enabled_collectors[k] = False
    app = create_app(cfg)
    db = app.state.db

    db.upsert_zone(Zone(name="example.com", key_dir=str(tmp_path)))
    db.upsert_key(
        Key(
            zone="example.com",
            key_tag=KSK_TAG,
            role="KSK",
            algorithm=13,
            key_id=f"Kexample.com.+013+{KSK_TAG:05d}",
        )
    )

    scope = f"example.com#{KSK_TAG}#KSK"
    db.set_snapshot(
        "key_file",
        scope,
        {
            "timings": {
                "Created": "20260401000000",
                "Publish":  "20260401000000",
                "Activate": "20260407000000",
            }
        },
    )
    db.set_snapshot(
        "state_file",
        scope,
        {
            "fields": {
                "Algorithm": "13",
                "KSK": "yes",
                "ZSK": "no",
                "GoalState": "omnipresent",
                "DNSKEYState": "omnipresent",
                "KRRSIGState": "omnipresent",
                "DSState": "rumoured",
                "Generated": "20260401000000",
                "Published": "20260401000000",
                "Active": "20260407000000",
                "DSChange": "20260410000000",
            }
        },
    )

    # DS event for the KSK — emitted via the real emit path so the
    # key_tag column is populated from the DS rdata.
    col = DnsProbeCollector(cfg, db)
    col._emit_diff(
        "example.com", "dns",
        previous={"DS": []}, current={"DS": [DS_TXT]}, parent=True,
    )

    # Timing change events — simulate iodyn-dnssec shifting Publish
    # forward via dnssec-settime, and BIND moving the DNSKEYChange
    # timestamp after the state machine ticks.
    db.insert_event(Event(
        ts=now_iso(), source="key",
        event_type="key_timing_changed",
        summary="example.com KSK tag=19463 Publish: 20260401000000 -> 20260402000000",
        zone="example.com", key_tag=KSK_TAG, key_role="KSK",
        detail={"field": "Publish", "old": "20260401000000", "new": "20260402000000"},
    ))
    db.insert_event(Event(
        ts=now_iso(), source="state",
        event_type="state_timing_changed",
        summary="example.com KSK tag=19463 DNSKEYChange: (unset) -> 20260402000000",
        zone="example.com", key_tag=KSK_TAG, key_role="KSK",
        detail={"field": "DNSKEYChange", "old": None, "new": "20260402000000"},
    ))

    # And a rndc-observed state change so the DNS timeline has content.
    db.insert_event(Event(
        ts=now_iso(), source="rndc",
        event_type="rndc_state_changed",
        summary="example.com KSK tag=19463 ds hidden -> rumoured",
        zone="example.com", key_tag=KSK_TAG, key_role="KSK",
        detail={"field": "ds", "old": "hidden", "new": "rumoured"},
    ))

    client = TestClient(app)
    yield client, db


def test_key_page_lists_current_key_file_timings(seeded_client):
    client, _ = seeded_client
    r = client.get(f"/zones/example.com/keys/{KSK_TAG}")
    assert r.status_code == 200
    body = r.text
    # Timing table headings
    assert "K*.key file timings" in body
    assert "K*.state file — state machine" in body
    assert "K*.state file — timestamps" in body
    # Values formatted from YYYYMMDDHHMMSS via the bind_ts filter
    assert "2026-04-01 00:00:00 UTC" in body   # Created / Published
    assert "2026-04-07 00:00:00 UTC" in body   # Activate / Active


def test_key_page_shows_state_machine_values(seeded_client):
    client, _ = seeded_client
    body = client.get(f"/zones/example.com/keys/{KSK_TAG}").text
    assert "GoalState" in body and "omnipresent" in body
    assert "DSState" in body and "rumoured" in body


def test_key_page_shows_ds_event_for_ksk(seeded_client):
    client, _ = seeded_client
    body = client.get(f"/zones/example.com/keys/{KSK_TAG}").text
    # DS event from dns_probe is surfaced on the KSK page
    assert "DS (key tag 19463) appeared at parent" in body
    assert "dns_ds_appeared_at_parent" in body


def test_key_page_shows_timing_change_subsection(seeded_client):
    client, _ = seeded_client
    body = client.get(f"/zones/example.com/keys/{KSK_TAG}").text
    assert "Timing changes observed" in body
    # The old/new values should be formatted via bind_ts
    assert "2026-04-01 00:00:00 UTC" in body
    assert "2026-04-02 00:00:00 UTC" in body


def test_key_page_has_calendar_and_both_timelines(seeded_client):
    client, _ = seeded_client
    body = client.get(f"/zones/example.com/keys/{KSK_TAG}").text
    assert "Calendar view" in body
    assert "cal-month" in body
    assert "DNS event timeline" in body
    assert "File event timeline" in body
    # Two separate event-timeline SVGs in the page
    assert body.count('class="event-timeline"') == 2


def test_zone_page_has_two_split_timelines(seeded_client):
    client, _ = seeded_client
    body = client.get("/zones/example.com").text
    assert "DNS event timeline" in body
    assert "File event timeline" in body
    assert body.count('class="event-timeline"') == 2
