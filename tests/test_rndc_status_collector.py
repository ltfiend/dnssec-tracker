"""Tests for the rndc_status collector's event emission — especially
the "key deleted" collapse: when a key disappears from BIND's rndc
output between polls, emit *one* ``rndc_key_deleted`` event instead
of ~9 ``rndc_state_changed`` events with ``new=None`` (one per
field).
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from dnssec_tracker.collectors.rndc_status import RndcStatusCollector
from dnssec_tracker.config import Config
from dnssec_tracker.db import Database
from dnssec_tracker.models import Key, Zone


def _cfg(tmp_path: Path) -> Config:
    cfg = Config(
        key_dir=tmp_path,
        syslog_path=None,
        named_log_path=None,
        db_path=tmp_path / "events.db",
    )
    cfg.rndc_bin = "/usr/sbin/rndc"
    cfg.rndc_server = "127.0.0.1:953"
    cfg.rndc_interval = 300
    return cfg


def _rndc_output_two_keys() -> str:
    return (
        "dnssec-policy: default\n"
        "current time:  Sat Apr 12 12:00:00 2026\n"
        "\n"
        "key: 11111 (ECDSAP256SHA256), KSK\n"
        "  published:      yes - since Sun Apr  1 00:00:00 2026\n"
        "  key signing:    yes - since Sun Apr  1 00:00:00 2026\n"
        "\n"
        "  - goal:           omnipresent\n"
        "  - dnskey:         omnipresent\n"
        "  - ds:             omnipresent\n"
        "  - zone rrsig:     N/A\n"
        "  - key rrsig:      omnipresent\n"
        "\n"
        "key: 22222 (ECDSAP256SHA256), ZSK\n"
        "  published:      yes - since Sun Apr  1 00:00:00 2026\n"
        "  zone signing:   yes - since Sun Apr  1 00:00:00 2026\n"
        "\n"
        "  - goal:           omnipresent\n"
        "  - dnskey:         omnipresent\n"
        "  - ds:             N/A\n"
        "  - zone rrsig:     omnipresent\n"
        "  - key rrsig:      N/A\n"
    )


def _rndc_output_ksk_deleted_zsk_remains() -> str:
    return (
        "dnssec-policy: default\n"
        "current time:  Sat Apr 12 12:05:00 2026\n"
        "\n"
        "key: 22222 (ECDSAP256SHA256), ZSK\n"
        "  published:      yes - since Sun Apr  1 00:00:00 2026\n"
        "  zone signing:   yes - since Sun Apr  1 00:00:00 2026\n"
        "\n"
        "  - goal:           omnipresent\n"
        "  - dnskey:         omnipresent\n"
        "  - ds:             N/A\n"
        "  - zone rrsig:     omnipresent\n"
        "  - key rrsig:      N/A\n"
    )


async def _seed_collector_with(tmp_path: Path, outputs: list[str]) -> tuple:
    """Build a collector + DB with a zone and the two keys, then run
    sample() once per output in sequence, mocking _run_rndc to return
    the pre-cooked strings.

    Returns ``(collector, db)`` so the caller can assert against the
    event log.
    """
    cfg = _cfg(tmp_path)
    db = Database(cfg.db_path)
    db.upsert_zone(Zone(name="example.com", key_dir=str(tmp_path)))
    db.upsert_key(Key(
        zone="example.com", key_tag=11111, role="KSK",
        algorithm=13, key_id="Kexample.com.+013+11111",
    ))
    db.upsert_key(Key(
        zone="example.com", key_tag=22222, role="ZSK",
        algorithm=13, key_id="Kexample.com.+013+22222",
    ))

    col = RndcStatusCollector(cfg, db)
    # Bypass the binary-exists check by shimming both code paths.
    with patch("dnssec_tracker.collectors.rndc_status.shutil.which",
               return_value=cfg.rndc_bin):
        outputs_iter = iter(outputs)

        async def fake_run(zone):
            return next(outputs_iter)

        with patch.object(col, "_run_rndc", new=fake_run):
            for _ in outputs:
                await col.sample()
    return col, db


@pytest.mark.asyncio
async def test_vanished_key_collapses_to_single_rndc_key_deleted(tmp_path):
    """First sample sees two keys, second sample sees only the ZSK
    — the KSK has been deleted. The collector must emit exactly one
    ``rndc_key_deleted`` event for the KSK and zero
    ``rndc_state_changed`` events for it."""

    _col, db = await _seed_collector_with(
        tmp_path,
        [
            _rndc_output_two_keys(),
            _rndc_output_ksk_deleted_zsk_remains(),
        ],
    )

    deleted = db.query_events(event_type="rndc_key_deleted", limit=1000)
    assert len(deleted) == 1
    ev = deleted[0]
    assert ev.key_tag == 11111
    assert ev.key_role == "KSK"
    assert "no longer reported" in ev.summary
    assert "key deleted" in ev.summary
    # detail.last_state preserves the previous observation so the
    # forensic trail doesn't vanish with the key.
    assert ev.detail.get("last_state"), "last_state must be preserved"
    assert ev.detail["last_state"].get("goal") == "omnipresent"
    assert ev.detail["last_state"].get("dnskey") == "omnipresent"

    # No rndc_state_changed events for the vanished KSK — the
    # collapse is the whole point.
    ksk_transitions = [
        e for e in db.query_events(event_type="rndc_state_changed", limit=1000)
        if e.key_tag == 11111
    ]
    assert ksk_transitions == [], (
        f"vanished KSK must NOT emit per-field state-change events, "
        f"got {len(ksk_transitions)}: "
        f"{[e.summary for e in ksk_transitions]}"
    )


@pytest.mark.asyncio
async def test_live_keys_still_get_per_field_state_changed(tmp_path):
    """The collapse logic only applies to vanished keys. Real
    transitions on keys that are still live must still emit
    ``rndc_state_changed`` events one per field."""

    first = _rndc_output_two_keys()
    # Same output but flip the ZSK's ds from N/A to rumoured — one
    # field change, one event expected, on a key that did NOT vanish.
    second = first.replace(
        "  - ds:             N/A\n"
        "  - zone rrsig:     omnipresent",
        "  - ds:             rumoured\n"
        "  - zone rrsig:     omnipresent",
    )

    _col, db = await _seed_collector_with(tmp_path, [first, second])

    zsk_changes = [
        e for e in db.query_events(event_type="rndc_state_changed", limit=1000)
        if e.key_tag == 22222
    ]
    assert len(zsk_changes) == 1
    assert zsk_changes[0].detail["field"] == "ds"
    assert zsk_changes[0].detail["new"] == "rumoured"


@pytest.mark.asyncio
async def test_first_observation_does_not_fire_key_deleted(tmp_path):
    """First rndc poll seeds the snapshot — it must emit the
    ``rndc_first_observation`` summary event and nothing else. No
    phantom ``rndc_key_deleted`` just because prev_snap was empty."""

    _col, db = await _seed_collector_with(
        tmp_path, [_rndc_output_two_keys()]
    )

    deleted = db.query_events(event_type="rndc_key_deleted", limit=1000)
    assert deleted == []

    first_obs = db.query_events(event_type="rndc_first_observation", limit=1000)
    assert len(first_obs) == 1


@pytest.mark.asyncio
async def test_vanished_key_carries_role_from_keys_table(tmp_path):
    """Because the rndc output no longer contains the vanished key,
    the collector can't read the role from the parsed status. It
    must fall back to the keys table, which still has the row from
    earlier observation."""

    _col, db = await _seed_collector_with(
        tmp_path,
        [
            _rndc_output_two_keys(),
            _rndc_output_ksk_deleted_zsk_remains(),
        ],
    )

    deleted = db.query_events(event_type="rndc_key_deleted", limit=1000)
    assert len(deleted) == 1
    # The role is the classic forensic piece — "which KSK died?".
    assert deleted[0].key_role == "KSK"


@pytest.mark.asyncio
async def test_multiple_vanished_keys_emit_one_event_each(tmp_path):
    """If a whole rollover retires and removes both keys in one go,
    we get one rndc_key_deleted per tag — not one mega-event."""

    empty_output = (
        "dnssec-policy: default\n"
        "current time:  Sat Apr 12 12:10:00 2026\n"
    )

    _col, db = await _seed_collector_with(
        tmp_path, [_rndc_output_two_keys(), empty_output]
    )

    deleted = db.query_events(event_type="rndc_key_deleted", limit=1000)
    tags = sorted(e.key_tag for e in deleted)
    assert tags == [11111, 22222]
    # No per-field noise either.
    assert db.query_events(event_type="rndc_state_changed", limit=1000) == []
