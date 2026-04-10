from pathlib import Path

from dnssec_tracker.db import Database
from dnssec_tracker.models import Event, Key, Zone, now_iso


def make_db(tmp_path: Path) -> Database:
    return Database(tmp_path / "events.db")


def test_insert_and_query_roundtrip(tmp_path):
    db = make_db(tmp_path)
    db.upsert_zone(Zone(name="example.com", key_dir="/keys"))
    db.upsert_key(
        Key(zone="example.com", key_tag=12345, role="KSK", algorithm=13, key_id="Kexample.com.+013+12345")
    )
    for i in range(3):
        db.insert_event(
            Event(
                ts=now_iso(),
                source="state",
                event_type="state_changed",
                summary=f"transition {i}",
                zone="example.com",
                key_tag=12345,
                key_role="KSK",
                detail={"field": "GoalState", "old": "hidden", "new": "omnipresent"},
            )
        )
    events = db.query_events(zone="example.com")
    assert len(events) == 3
    assert all(e.zone == "example.com" for e in events)
    assert events[0].detail["field"] == "GoalState"


def test_filter_by_event_type(tmp_path):
    db = make_db(tmp_path)
    db.insert_event(Event(ts=now_iso(), source="dns", event_type="dns_dnskey_appeared_at_zone", summary="a"))
    db.insert_event(Event(ts=now_iso(), source="state", event_type="state_changed", summary="b"))
    assert len(db.query_events(event_type="state_changed")) == 1


def test_snapshots_round_trip(tmp_path):
    db = make_db(tmp_path)
    db.set_snapshot("state_file", "example.com#12345#KSK", {"fields": {"GoalState": "omnipresent"}})
    snap = db.get_snapshot("state_file", "example.com#12345#KSK")
    assert snap["fields"]["GoalState"] == "omnipresent"


def test_zones_and_keys_lists(tmp_path):
    db = make_db(tmp_path)
    db.upsert_zone(Zone(name="a.com", key_dir="/k"))
    db.upsert_zone(Zone(name="b.com", key_dir="/k"))
    db.upsert_key(Key(zone="a.com", key_tag=1, role="KSK", algorithm=13))
    db.upsert_key(Key(zone="a.com", key_tag=2, role="ZSK", algorithm=13))
    zones = db.list_zones()
    assert [z.name for z in zones] == ["a.com", "b.com"]
    keys = db.list_keys("a.com")
    assert {k.key_tag for k in keys} == {1, 2}
