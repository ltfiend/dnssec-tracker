"""Unit tests for the overdue-key classifier.

The detection is pure and snapshot-driven — no event replay, no DB —
so these tests hand-build fake snapshots and assert the four possible
OverdueState outcomes.
"""

from __future__ import annotations

from datetime import datetime, timezone

from dnssec_tracker.models import Key
from dnssec_tracker.render.overdue import (
    OverdueState,
    assess_all,
    assess_overdue,
)


# ---- fixtures ---------------------------------------------------------

# Real ECDSA P-256 DNSKEY with known tag 19463 (see test_dns_probe_events).
_DNSKEY_PUB = (
    "oJMRESz5E4gYzS35AJulupX0kDyQjM+9GsGZu6XW7A7m"
    "f2HxS/zV0SCNvyx8rDSb8CAW0Q9D2JVv9ZQvkLIc9g=="
)
DNSKEY_KSK = f"257 3 13 {_DNSKEY_PUB}"
DNSKEY_KSK_TAG = 19463
DS_KSK = f"{DNSKEY_KSK_TAG} 13 2 9e6c7a4d64e0a8b5bdfd1ed4bb6f3e9b"


def _ksk(tag: int = DNSKEY_KSK_TAG, algo: int = 13) -> Key:
    return Key(
        zone="example.com",
        key_tag=tag,
        role="KSK",
        algorithm=algo,
        key_id=f"Kexample.com.+{algo:03d}+{tag:05d}",
        first_seen="2026-01-01T00:00:00Z",
    )


def _snap(
    generated: str = "0",
    removed: str = "0",
    created: str = "0",
    delete: str = "0",
) -> dict:
    return {
        "fields": {
            "Generated": generated,
            "Removed": removed,
            "GoalState": "omnipresent",
        },
        "timings": {
            "Created": created,
            "Delete": delete,
        },
    }


_NOW = datetime(2026, 7, 1, 12, 0, 0, tzinfo=timezone.utc)


# ---- core classification ---------------------------------------------


def test_not_past_delete_returns_none():
    """Delete scheduled in the future → state NONE, nothing lingering."""
    k = _ksk()
    snap = _snap(delete="20261001000000")  # October 2026, still future
    a = assess_overdue(k, snap, {"DNSKEY": [DNSKEY_KSK]}, {"DS": [DS_KSK]}, _NOW)
    assert a.state == OverdueState.NONE
    assert a.is_overdue is False
    assert a.delete_at is not None


def test_past_delete_clean_returns_none():
    """Delete in the past, but DNSKEY gone from zone and DS gone from
    parent — clean deletion, no warning."""
    k = _ksk()
    snap = _snap(delete="20260301000000")  # March 2026, before _NOW
    a = assess_overdue(
        k, snap,
        zone_dns_snapshot={"DNSKEY": []},
        parent_dns_snapshot={"DS": []},
        now=_NOW,
    )
    assert a.state == OverdueState.NONE
    assert a.is_overdue is False


def test_dnskey_lingering_past_delete():
    """DNSKEY still in zone after scheduled Delete → DNSKEY_LINGERING."""
    k = _ksk()
    snap = _snap(delete="20260301000000")
    a = assess_overdue(
        k, snap,
        zone_dns_snapshot={"DNSKEY": [DNSKEY_KSK]},   # still there!
        parent_dns_snapshot={"DS": []},
        now=_NOW,
    )
    assert a.state == OverdueState.DNSKEY_LINGERING
    assert a.observed_in_zone is True
    assert a.observed_at_parent is False
    assert "past scheduled Delete" in a.summary()
    assert "DNSKEY at zone" in a.summary()


def test_ds_lingering_past_delete():
    """DS still at parent after scheduled Delete → DS_LINGERING.
    This is the dangerous case: resolvers still trust the chain."""
    k = _ksk()
    snap = _snap(delete="20260301000000")
    a = assess_overdue(
        k, snap,
        zone_dns_snapshot={"DNSKEY": []},
        parent_dns_snapshot={"DS": [DS_KSK]},         # still at parent!
        now=_NOW,
    )
    assert a.state == OverdueState.DS_LINGERING
    assert a.observed_in_zone is False
    assert a.observed_at_parent is True
    assert "DS at parent" in a.summary()


def test_both_lingering_past_delete():
    """Both DNSKEY and DS lingering → BOTH_LINGERING, loudest warning."""
    k = _ksk()
    snap = _snap(delete="20260301000000")
    a = assess_overdue(
        k, snap,
        zone_dns_snapshot={"DNSKEY": [DNSKEY_KSK]},
        parent_dns_snapshot={"DS": [DS_KSK]},
        now=_NOW,
    )
    assert a.state == OverdueState.BOTH_LINGERING
    assert a.observed_in_zone is True
    assert a.observed_at_parent is True
    assert "DNSKEY at zone AND DS at parent" in a.summary()


# ---- edge cases -------------------------------------------------------


def test_no_delete_time_anywhere_returns_none():
    """No scheduled Delete AND no Removed → there's no deadline to
    measure against, so state is NONE regardless of what's observed."""
    k = _ksk()
    snap = _snap(generated="20260101000000")  # only Generated set
    a = assess_overdue(
        k, snap,
        zone_dns_snapshot={"DNSKEY": [DNSKEY_KSK]},
        parent_dns_snapshot={"DS": [DS_KSK]},
        now=_NOW,
    )
    assert a.state == OverdueState.NONE
    assert a.delete_at is None


def test_removed_fallback_when_key_file_delete_absent():
    """Scheduled Delete absent but state file's Removed is set in the
    past → classifier still uses Removed as the deadline."""
    k = _ksk()
    snap = _snap(removed="20260301000000")  # BIND says it was removed
    a = assess_overdue(
        k, snap,
        zone_dns_snapshot={"DNSKEY": [DNSKEY_KSK]},   # but it's still there
        parent_dns_snapshot={"DS": []},
        now=_NOW,
    )
    assert a.state == OverdueState.DNSKEY_LINGERING


def test_zsk_lingering_in_zone():
    """A ZSK can only ever be DNSKEY_LINGERING — ZSKs have no DS at
    parent. This ensures the classifier doesn't require a KSK/CSK role."""
    k = Key(
        zone="example.com", key_tag=DNSKEY_KSK_TAG,
        role="ZSK", algorithm=13, key_id="k",
        first_seen="2026-01-01T00:00:00Z",
    )
    snap = _snap(delete="20260301000000")
    # Use a ZSK-format DNSKEY (flags=256) that still resolves to the
    # same key tag as our fixture — for this assertion we just need
    # the tag to match, not the role.
    zsk_record = f"256 3 13 {_DNSKEY_PUB}"
    a = assess_overdue(
        k, snap,
        zone_dns_snapshot={"DNSKEY": [zsk_record]},
        parent_dns_snapshot={"DS": []},   # ZSKs don't have DS
        now=_NOW,
    )
    # The ZSK flag shifts the computed tag to 19462, not 19463 —
    # so the snapshot's published key doesn't match this key's tag,
    # and classification is NONE (not lingering).
    # This is correct: we'd need the ZSK's own DNSKEY (with tag 19462)
    # in the zone snapshot to trip the alarm. Let's prove that:
    k_zsk = Key(
        zone="example.com", key_tag=19462,
        role="ZSK", algorithm=13, key_id="k",
        first_seen="2026-01-01T00:00:00Z",
    )
    a = assess_overdue(
        k_zsk, snap,
        zone_dns_snapshot={"DNSKEY": [zsk_record]},
        parent_dns_snapshot={"DS": []},
        now=_NOW,
    )
    assert a.state == OverdueState.DNSKEY_LINGERING
    assert a.observed_at_parent is False


def test_snapshot_missing_does_not_crash():
    """A key with no snapshot (brand-new, never observed by state_file
    or key_file yet) falls through cleanly to NONE."""
    k = _ksk()
    a = assess_overdue(k, None, None, None, _NOW)
    assert a.state == OverdueState.NONE
    assert a.delete_at is None


def test_zone_dns_snapshot_missing_does_not_crash():
    """If the dns_probe hasn't run yet (no zone/parent snapshots) but
    the key has a scheduled Delete in the past — we can't observe
    anything, so nothing is lingering from our POV → NONE."""
    k = _ksk()
    snap = _snap(delete="20260301000000")
    a = assess_overdue(k, snap, None, None, _NOW)
    assert a.state == OverdueState.NONE


# ---- batch API --------------------------------------------------------


def test_assess_all_batches_per_key():
    """``assess_all`` loops over a list of keys and returns an
    assessment for each, looking up the right snapshot per key."""
    k1 = _ksk(tag=DNSKEY_KSK_TAG, algo=13)
    k2 = _ksk(tag=11111, algo=13)
    snapshots = {
        "example.com#19463#KSK": _snap(delete="20260301000000"),
        "example.com#11111#KSK": _snap(delete="20261001000000"),   # future
    }
    zone_dns = {"DNSKEY": [DNSKEY_KSK]}     # only tag 19463 observed
    parent_dns = {"DS": []}

    results = assess_all([k1, k2], snapshots, zone_dns, parent_dns, _NOW)
    by_tag = {a.key.key_tag: a for a in results}

    assert by_tag[DNSKEY_KSK_TAG].state == OverdueState.DNSKEY_LINGERING
    assert by_tag[11111].state == OverdueState.NONE
