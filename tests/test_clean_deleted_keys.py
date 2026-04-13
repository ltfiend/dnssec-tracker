"""Clean deleted keys: when a K*.state file disappears from disk
between polls, the tracker must emit ONE summary event
(``state_key_file_deleted``), delete the collector snapshots for
that key (both state_file and key_file), and drop the row from
the ``keys`` table so forward-looking views stop rendering the
key. Historical events stay in place — they carry their own
zone/tag/role metadata and the event log remains a full record.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dnssec_tracker.collectors.key_file import KeyFileCollector
from dnssec_tracker.collectors.state_file import StateFileCollector
from dnssec_tracker.config import Config
from dnssec_tracker.db import Database


def _cfg(tmp_path: Path) -> Config:
    return Config(
        key_dir=tmp_path,
        syslog_path=None,
        named_log_path=None,
        db_path=tmp_path / "events.db",
    )


def _seed_ksk(tmp_path: Path, zone: str = "example.com", tag: int = 12345) -> Path:
    """Drop a realistic K*.state + K*.key pair in a per-zone subdir
    so the default non-recursive walk picks them up."""
    zone_dir = tmp_path / zone
    zone_dir.mkdir()
    state_path = zone_dir / f"K{zone}.+013+{tag:05d}.state"
    state_path.write_text(
        "Algorithm: 13\nKSK: yes\nZSK: no\n"
        "Generated: 20260301000000\n"
        "Published: 20260301000000\n"
        "Active: 20260307000000\n"
        "GoalState: omnipresent\n"
        "DNSKEYState: omnipresent\n"
        "DSState: omnipresent\n"
    )
    key_path = zone_dir / f"K{zone}.+013+{tag:05d}.key"
    key_path.write_text(
        f"; This is a key-signing key, keyid {tag}, for {zone}.\n"
        "; Created: 20260301000000 (Sun Mar  1 00:00:00 2026)\n"
        "; Publish: 20260301000000 (Sun Mar  1 00:00:00 2026)\n"
        "; Activate: 20260307000000 (Sat Mar  7 00:00:00 2026)\n"
        f"{zone}. 86400 IN DNSKEY 257 3 13 fakepubkey\n"
    )
    return state_path


@pytest.mark.asyncio
async def test_vanished_state_file_emits_single_summary_event(tmp_path):
    state_path = _seed_ksk(tmp_path)
    cfg = _cfg(tmp_path)
    db = Database(cfg.db_path)
    col = StateFileCollector(cfg, db)

    # First pass — key is observed and snapshotted.
    await col.sample()
    assert db.get_snapshot("state_file", "example.com#12345#KSK")
    assert [k.key_tag for k in db.list_keys("example.com")] == [12345]

    # Operator removes the .state file (and its .key friend).
    state_path.unlink()
    (state_path.parent / state_path.name.replace(".state", ".key")).unlink()

    # Second pass — must detect the vanishment.
    await col.sample()

    # Exactly one state_key_file_deleted event for the vanished key.
    deletions = db.query_events(event_type="state_key_file_deleted", limit=50)
    assert len(deletions) == 1
    ev = deletions[0]
    assert ev.zone == "example.com"
    assert ev.key_tag == 12345
    assert ev.key_role == "KSK"
    assert "no longer present on disk" in ev.summary
    # detail carries the last-observed state so the historical
    # record is intact.
    assert ev.detail.get("last_fields", {}).get("GoalState") == "omnipresent"

    # No per-field "(unset)" spam — the whole point of collapsing.
    unset_events = [
        e for e in db.query_events(zone="example.com", limit=500)
        if e.event_type in ("state_changed", "state_timing_changed")
        and "(unset)" in e.summary
    ]
    assert unset_events == []


@pytest.mark.asyncio
async def test_vanished_key_snapshots_and_row_are_cleared(tmp_path):
    """After the summary event fires, the collector drops:
    * the state_file snapshot for that scope
    * the key_file snapshot for that scope
    * the keys-table row
    so forward-looking views (rollover, per-key page) stop
    rendering the key."""

    state_path = _seed_ksk(tmp_path)
    cfg = _cfg(tmp_path)
    db = Database(cfg.db_path)

    state_col = StateFileCollector(cfg, db)
    key_col = KeyFileCollector(cfg, db)

    # Seed both collectors' snapshots from the live files.
    await state_col.sample()
    await key_col.sample()
    assert db.get_snapshot("state_file", "example.com#12345#KSK")
    assert db.get_snapshot("key_file", "example.com#12345#KSK")
    assert db.list_keys("example.com")

    # Remove the files — simulate operator cleanup.
    state_path.unlink()
    (state_path.parent / state_path.name.replace(".state", ".key")).unlink()

    # state_file pass: detects vanishment, cleans up.
    await state_col.sample()

    # All three stores are clean for this key.
    assert db.get_snapshot("state_file", "example.com#12345#KSK") == {}
    assert db.get_snapshot("key_file", "example.com#12345#KSK") == {}
    assert db.list_keys("example.com") == []


@pytest.mark.asyncio
async def test_historical_events_survive_the_cleanup(tmp_path):
    """When the cleanup fires we delete snapshots and the keys row,
    but events from earlier observations MUST still be queryable —
    the event log is the historical record."""

    state_path = _seed_ksk(tmp_path)
    cfg = _cfg(tmp_path)
    db = Database(cfg.db_path)
    col = StateFileCollector(cfg, db)
    await col.sample()

    # Baseline: first-sighting event was emitted.
    baseline = db.query_events(
        zone="example.com", event_type="state_key_observed",
    )
    assert len(baseline) == 1

    # Remove the file, re-sample (cleanup fires).
    state_path.unlink()
    (state_path.parent / state_path.name.replace(".state", ".key")).unlink()
    await col.sample()

    # The first-sighting event is still queryable — history isn't
    # wiped alongside the cleanup.
    preserved = db.query_events(
        zone="example.com", event_type="state_key_observed",
    )
    assert len(preserved) == 1
    assert preserved[0].key_tag == 12345


@pytest.mark.asyncio
async def test_no_vanish_event_on_first_scan(tmp_path):
    """First poll of a fresh install — nothing has been snapshotted
    previously, so there can't be any vanished keys. The collector
    must not emit phantom deletions just because the snapshot
    store started empty."""

    _seed_ksk(tmp_path)
    cfg = _cfg(tmp_path)
    db = Database(cfg.db_path)
    col = StateFileCollector(cfg, db)
    await col.sample()

    assert db.query_events(event_type="state_key_file_deleted", limit=50) == []


@pytest.mark.asyncio
async def test_key_still_present_between_polls_no_false_deletion(tmp_path):
    """Sanity: two polls with the file unchanged should not trigger
    a deletion event."""
    _seed_ksk(tmp_path)
    cfg = _cfg(tmp_path)
    db = Database(cfg.db_path)
    col = StateFileCollector(cfg, db)
    await col.sample()
    await col.sample()
    assert db.query_events(event_type="state_key_file_deleted", limit=50) == []


@pytest.mark.asyncio
async def test_multiple_vanished_keys_each_get_their_own_summary(tmp_path):
    """Two keys vanishing at once — each gets its own single
    summary event (no mega-event collapsing both together)."""
    _seed_ksk(tmp_path, tag=11111)
    _seed_ksk(tmp_path, zone="another.example", tag=22222)
    cfg = _cfg(tmp_path)
    db = Database(cfg.db_path)
    col = StateFileCollector(cfg, db)
    await col.sample()

    # Remove everything for both zones.
    for z in ("example.com", "another.example"):
        zone_dir = tmp_path / z
        for p in zone_dir.iterdir():
            p.unlink()
        zone_dir.rmdir()

    await col.sample()

    deletions = db.query_events(event_type="state_key_file_deleted", limit=50)
    tags = sorted(e.key_tag for e in deletions)
    assert tags == [11111, 22222]
