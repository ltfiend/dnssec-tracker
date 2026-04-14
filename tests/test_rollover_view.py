"""Unit tests for the rollover-view SVG renderer.

These tests intentionally poke at the rendered SVG as a string rather
than parsing the XML — the renderer emits a hand-written flat string
for WeasyPrint compatibility and the other render-test modules
(``test_event_timeline_render``, ``test_calendar_render``) use the
same substring-grep style, so this matches the repo's idioms.
"""

from __future__ import annotations

from datetime import datetime, timezone

from dnssec_tracker.models import Event, Key
from dnssec_tracker.render.rollover_view import (
    _phase_segments_for_key,
    render_rollover_view,
)


def _ksk(tag: int, algo: int = 13, zone: str = "example.com") -> Key:
    return Key(
        zone=zone,
        key_tag=tag,
        role="KSK",
        algorithm=algo,
        key_id=f"K{zone}.+{algo:03d}+{tag:05d}",
        first_seen="2026-03-01T00:00:00Z",
    )


def _snap(
    generated: str = "0",
    published: str = "0",
    active: str = "0",
    retired: str = "0",
    removed: str = "0",
) -> dict:
    return {
        "fields": {
            "Generated": generated,
            "Published": published,
            "Active": active,
            "Retired": retired,
            "Removed": removed,
            "GoalState": "omnipresent",
        },
        "path": "/tmp/fake.state",
    }


# --------------------------------------------------------------------------
# 1. KSK rollover scenario
# --------------------------------------------------------------------------

def test_ksk_rollover_scenario():
    """Two alg-13 KSKs: one retired, one active, with DS appear /
    disappear events for each crossing at the parent. Everything the
    user needs to visually follow the rollover must be in the SVG."""

    old_key = _ksk(11111)
    new_key = _ksk(22222)

    snapshots = {
        "example.com#11111#KSK": _snap(
            generated="20260101000000",
            published="20260103000000",
            active="20260105000000",
            retired="20260320000000",
            removed="0",
        ),
        "example.com#22222#KSK": _snap(
            generated="20260301000000",
            published="20260305000000",
            active="20260315000000",
            retired="0",
            removed="0",
        ),
    }

    events = [
        Event(
            ts="2026-01-05T00:00:00Z",
            source="dns",
            event_type="dns_ds_appeared_at_parent",
            summary="DS 11111 appeared at parent",
            zone="example.com",
            key_tag=11111,
        ),
        Event(
            ts="2026-03-20T00:00:00Z",
            source="dns",
            event_type="dns_ds_disappeared_at_parent",
            summary="DS 11111 withdrawn at parent",
            zone="example.com",
            key_tag=11111,
        ),
        Event(
            ts="2026-03-10T00:00:00Z",
            source="dns",
            event_type="dns_ds_appeared_at_parent",
            summary="DS 22222 appeared at parent",
            zone="example.com",
            key_tag=22222,
        ),
    ]

    svg = render_rollover_view(
        events,
        [old_key, new_key],
        snapshots,
        from_ts="2025-12-15T00:00:00Z",
        to_ts="2026-04-30T00:00:00Z",
        today=datetime(2026, 4, 10, tzinfo=timezone.utc),
    )

    assert svg.startswith("<svg"), svg[:200]
    assert svg.rstrip().endswith("</svg>"), svg[-200:]

    # Both tags appear on the left as row labels.
    assert "tag 11111" in svg
    assert "tag 22222" in svg

    # Algorithm group header.
    assert "alg 13" in svg

    # Phase tooltips / class markers. The old "retired" phase was
    # renamed to "inactive" to reflect BIND's Inactive→Delete
    # semantic ("not signing, awaiting removal").
    assert "phase-active" in svg
    assert "phase-inactive" in svg

    # DS overlay — both keys have DS events so two live stripes are emitted.
    assert svg.count('data-ds="live"') >= 2
    # And the empty-track is rendered once per KSK row.
    assert svg.count('data-ds="track"') == 2

    # Tooltip copy includes the phase names so mouseover is useful.
    assert "active" in svg
    assert "inactive" in svg or "to be deleted" in svg


# --------------------------------------------------------------------------
# 2. Algorithm rollover scenario
# --------------------------------------------------------------------------

def test_algorithm_rollover_highlight():
    """Two KSKs, alg 13 and alg 15, with overlapping active phases."""

    k13 = _ksk(11111, algo=13)
    k15 = _ksk(22222, algo=15)

    snapshots = {
        "example.com#11111#KSK": _snap(
            generated="20260101000000",
            published="20260103000000",
            active="20260105000000",
            retired="20260401000000",
            removed="0",
        ),
        "example.com#22222#KSK": _snap(
            generated="20260301000000",
            published="20260305000000",
            active="20260315000000",
            retired="0",
            removed="0",
        ),
    }

    svg = render_rollover_view(
        [],
        [k13, k15],
        snapshots,
        from_ts="2026-01-01T00:00:00Z",
        to_ts="2026-05-01T00:00:00Z",
        today=datetime(2026, 4, 10, tzinfo=timezone.utc),
    )

    # Both algorithm groups are labelled.
    assert "alg 13" in svg
    assert "alg 15" in svg

    # Both bars present.
    assert "tag 11111" in svg
    assert "tag 22222" in svg

    # The cross-algorithm overlap highlight is emitted.
    assert 'class="algo-rollover"' in svg


# --------------------------------------------------------------------------
# 3. Empty scenarios
# --------------------------------------------------------------------------

def test_empty_inputs_returns_placeholder_svg():
    svg = render_rollover_view([], [], {})
    assert "<svg" in svg
    assert "</svg>" in svg
    assert "No keys observed" in svg


def test_key_whose_delete_preceded_window_renders_as_past_deletion_date():
    """A key whose entire scheduled lifecycle fell before the reported
    window now renders as ``removed`` spanning the window
    — the user needs to see that the key is overdue for removal even
    if the actual Delete timestamp is old. Previously this rendered a
    "No key activity" placeholder, which hid the problem.
    """
    k = _ksk(11111)
    snap = _snap(
        generated="20200101000000",
        published="20200103000000",
        active="20200105000000",
        retired="20200201000000",
        removed="20200301000000",
    )

    svg = render_rollover_view(
        [],
        [k],
        {"example.com#11111#KSK": snap},
        from_ts="2026-01-01T00:00:00Z",
        to_ts="2026-02-01T00:00:00Z",
        today=datetime(2026, 4, 10, tzinfo=timezone.utc),
    )
    assert "<svg" in svg
    assert "</svg>" in svg
    # No placeholder — the removed segment fills the window.
    assert "No key activity" not in svg
    assert "phase-removed" in svg


# --------------------------------------------------------------------------
# 4. Snapshot-only key
# --------------------------------------------------------------------------

def test_snapshot_only_key_renders_without_events():
    k = _ksk(33333)
    snap = _snap(
        generated="20260301000000",
        published="20260305000000",
        active="20260310000000",
        retired="0",
        removed="0",
    )

    svg = render_rollover_view(
        [],
        [k],
        {"example.com#33333#KSK": snap},
        from_ts="2026-02-15T00:00:00Z",
        to_ts="2026-04-15T00:00:00Z",
        today=datetime(2026, 4, 10, tzinfo=timezone.utc),
    )
    assert svg.startswith("<svg")
    assert "tag 33333" in svg
    # Pre-publication + published + active — three phases should be drawn.
    assert "phase-pre-published" in svg
    assert "phase-published" in svg
    assert "phase-active" in svg


# --------------------------------------------------------------------------
# 5. _phase_segments_for_key unit test
# --------------------------------------------------------------------------

def test_phase_segments_for_canonical_ksk_snapshot():
    """Published + Active set, Retired/Removed still ``0`` — the key is
    alive and actively signing. The helper should produce exactly the
    three expected phases: pre-published, published, active-to-window-
    end."""
    k = _ksk(44444)
    snap = _snap(
        generated="20260301000000",
        published="20260305000000",
        active="20260310000000",
        retired="0",
        removed="0",
    )
    window_start = datetime(2026, 2, 1, tzinfo=timezone.utc)
    window_end = datetime(2026, 4, 15, tzinfo=timezone.utc)

    segs = _phase_segments_for_key(k, snap, [], window_start, window_end)

    assert len(segs) == 3

    (s0, e0, p0), (s1, e1, p1), (s2, e2, p2) = segs
    assert p0 == "pre-published"
    assert p1 == "published"
    assert p2 == "active"

    assert s0 == datetime(2026, 3, 1, tzinfo=timezone.utc)
    assert e0 == datetime(2026, 3, 5, tzinfo=timezone.utc)
    assert s1 == datetime(2026, 3, 5, tzinfo=timezone.utc)
    assert e1 == datetime(2026, 3, 10, tzinfo=timezone.utc)
    assert s2 == datetime(2026, 3, 10, tzinfo=timezone.utc)
    assert e2 == window_end


def test_phase_segments_for_fully_retired_key():
    """All five boundary timestamps set — full lifecycle in the
    window. The ``removed`` phase now *renders* (it used
    to be a silent terminal marker), so a key whose Delete has
    passed shows a muted bar out to the window edge — the operator
    can see "this key is past its scheduled removal".
    """
    k = _ksk(55555)
    snap = _snap(
        generated="20260301000000",
        published="20260305000000",
        active="20260310000000",
        retired="20260320000000",
        removed="20260325000000",
    )
    window_start = datetime(2026, 2, 1, tzinfo=timezone.utc)
    window_end = datetime(2026, 4, 15, tzinfo=timezone.utc)

    segs = _phase_segments_for_key(k, snap, [], window_start, window_end)
    phases = [p for _, _, p in segs]
    assert phases == [
        "pre-published",
        "published",
        "active",
        "inactive",
        "removed",
    ]
    # inactive runs Inactive -> Delete
    to_be_deleted = segs[-2]
    assert to_be_deleted[0] == datetime(2026, 3, 20, tzinfo=timezone.utc)
    assert to_be_deleted[1] == datetime(2026, 3, 25, tzinfo=timezone.utc)
    # removed extends from Delete to the window edge
    past = segs[-1]
    assert past[0] == datetime(2026, 3, 25, tzinfo=timezone.utc)
    assert past[1] == window_end


# --------------------------------------------------------------------------
# 6. Today marker
# --------------------------------------------------------------------------

def test_today_marker_drawn_inside_window():
    k = _ksk(66666)
    snap = _snap(
        generated="20260301000000",
        published="20260305000000",
        active="20260310000000",
        retired="0",
        removed="0",
    )

    svg = render_rollover_view(
        [],
        [k],
        {"example.com#66666#KSK": snap},
        from_ts="2026-03-01T00:00:00Z",
        to_ts="2026-05-01T00:00:00Z",
        today=datetime(2026, 4, 15, tzinfo=timezone.utc),
    )

    # The marker line exists and the "now" label is rendered.
    assert 'class="now-marker"' in svg
    assert ">now<" in svg


def test_reversed_window_is_swapped_silently():
    """``to_ts < from_ts`` shouldn't crash — the renderer swaps them."""
    k = _ksk(77777)
    snap = _snap(
        generated="20260301000000",
        published="20260305000000",
        active="20260310000000",
        retired="0",
        removed="0",
    )
    svg = render_rollover_view(
        [],
        [k],
        {"example.com#77777#KSK": snap},
        from_ts="2026-05-01T00:00:00Z",
        to_ts="2026-02-01T00:00:00Z",
        today=datetime(2026, 4, 15, tzinfo=timezone.utc),
    )
    assert svg.startswith("<svg")
    assert "tag 77777" in svg


def test_ksk_and_zsk_not_considered_an_algorithm_rollover():
    """A KSK and a ZSK with different algorithms should NOT trigger
    the cross-algorithm highlight — that's normal operation, not a
    rollover."""
    ksk = _ksk(11111, algo=13)
    zsk = Key(
        zone="example.com",
        key_tag=22222,
        role="ZSK",
        algorithm=15,
        key_id="Kexample.com.+015+22222",
        first_seen="2026-01-01T00:00:00Z",
    )

    snapshots = {
        "example.com#11111#KSK": _snap(
            generated="20260101000000",
            published="20260103000000",
            active="20260105000000",
            retired="0",
            removed="0",
        ),
        "example.com#22222#ZSK": _snap(
            generated="20260101000000",
            published="20260103000000",
            active="20260105000000",
            retired="0",
            removed="0",
        ),
    }

    svg = render_rollover_view(
        [],
        [ksk, zsk],
        snapshots,
        from_ts="2026-01-01T00:00:00Z",
        to_ts="2026-05-01T00:00:00Z",
        today=datetime(2026, 4, 10, tzinfo=timezone.utc),
    )
    assert 'class="algo-rollover"' not in svg
    assert "alg 13" in svg
    assert "alg 15" in svg


# --------------------------------------------------------------------------
# 11. Key-file scheduled timings fall back when state-file is unset.
#
# Regression test for the bug where a key whose state_file has every
# field zeroed except `Generated` but whose K*.key header has the full
# scheduled lifecycle would render as an unbounded `pre-published`
# bar — even when the scheduled Delete was in the past.
# --------------------------------------------------------------------------

def _snap_with_timings(
    generated: str = "0",
    published: str = "0",
    active: str = "0",
    retired: str = "0",
    removed: str = "0",
    *,
    created: str = "0",
    publish: str = "0",
    activate: str = "0",
    inactive: str = "0",
    delete: str = "0",
) -> dict:
    return {
        "fields": {
            "Generated": generated,
            "Published": published,
            "Active": active,
            "Retired": retired,
            "Removed": removed,
            "GoalState": "omnipresent",
        },
        "timings": {
            "Created": created,
            "Publish": publish,
            "Activate": activate,
            "Inactive": inactive,
            "Delete": delete,
        },
    }


def test_phase_segments_fall_back_to_key_file_scheduled_timings():
    """State file has only Generated set — Published/Active/Retired/
    Removed are all ``0`` — but the K*.key header has the full scheduled
    lifecycle. The helper must use the scheduled key-file values so
    every phase boundary is present.
    """
    k = _ksk(66666)
    snap = _snap_with_timings(
        # state file only knows when the key was generated…
        generated="20260228000000",
        # …everything else on the state-file side is still zero.
        # The key file carries the full scheduled lifecycle:
        created="20260228000000",
        publish="20260301000000",
        activate="20260307000000",
        inactive="20260601000000",
        delete="20260608000000",
    )
    window_start = datetime(2026, 2, 1, tzinfo=timezone.utc)
    window_end = datetime(2026, 7, 15, tzinfo=timezone.utc)

    segs = _phase_segments_for_key(k, snap, [], window_start, window_end)
    phases = [p for _, _, p in segs]
    assert phases == [
        "pre-published",
        "published",
        "active",
        "inactive",
        "removed",
    ]


def test_post_delete_key_renders_as_past_deletion_date_not_pre_publication():
    """The specific user-reported bug: a key whose scheduled Delete is
    in the past was rendering as a long ``pre-published`` bar because
    the state file hadn't caught up. With key-file fallback the final
    phase is ``removed`` extending to window_end.
    """
    k = _ksk(77777)
    # state file only knows Generated; everything else is still 0.
    # key file's schedule has Delete well in the past relative to the
    # render window's end.
    snap = _snap_with_timings(
        generated="20250101000000",
        created="20250101000000",
        publish="20250101000000",
        activate="20250107000000",
        inactive="20250601000000",
        delete="20250608000000",
    )
    window_start = datetime(2025, 1, 1, tzinfo=timezone.utc)
    window_end = datetime(2026, 1, 1, tzinfo=timezone.utc)

    segs = _phase_segments_for_key(k, snap, [], window_start, window_end)
    phases = [p for _, _, p in segs]
    # Crucially, the LAST phase must be removed, NOT
    # pre-published (which was the bug).
    assert phases[-1] == "removed"
    # And that phase must extend from the scheduled Delete to window_end.
    last = segs[-1]
    assert last[0] == datetime(2025, 6, 8, tzinfo=timezone.utc)
    assert last[1] == window_end


def test_state_file_overrides_key_file_when_both_set():
    """If both snapshots have a value for the same boundary, state_file
    wins — it records what actually happened, not what was scheduled.
    """
    k = _ksk(88888)
    # state_file says Active fired on 2026-03-15
    # key_file schedule said it was planned for 2026-03-10
    # The rendered "active" phase should begin on 2026-03-15 (actual).
    snap = {
        "fields": {
            "Generated": "20260301000000",
            "Published": "20260302000000",
            "Active":    "20260315000000",   # actual
            "Retired":   "0",
            "Removed":   "0",
            "GoalState": "omnipresent",
        },
        "timings": {
            "Created":  "20260301000000",
            "Publish":  "20260302000000",
            "Activate": "20260310000000",    # scheduled earlier — ignored
            "Inactive": "0",
            "Delete":   "0",
        },
    }
    window_start = datetime(2026, 2, 1, tzinfo=timezone.utc)
    window_end = datetime(2026, 4, 15, tzinfo=timezone.utc)
    segs = _phase_segments_for_key(k, snap, [], window_start, window_end)

    # Find the "active" segment — its start must match the state_file
    # value (15th), not the key_file scheduled value (10th).
    active = [s for s in segs if s[2] == "active"]
    assert len(active) == 1
    assert active[0][0] == datetime(2026, 3, 15, tzinfo=timezone.utc)


# --------------------------------------------------------------------------
# Event-driven boundary refinement — user-reported bug:
# "bars don't capture when a KSK appears in a zone or when it goes
# published -> active as separate events with different bars".
#
# Root cause: BIND often writes Generated/Published/Active at the same
# instant during rollover setup; the state-file then has all three
# boundaries at one point, and the segment builder drops zero-width
# phases so only 'active' survived. Fix: when boundaries collapse,
# fall through to observed events (dns_dnskey_appeared_at_zone,
# KRRSIG → omnipresent, etc.) to split the phases apart.
# --------------------------------------------------------------------------

def test_collapsed_state_timestamps_split_via_observed_events():
    """gen == pub == act in state file, but DNSKEY-in-zone and
    KRRSIG-omnipresent events happened on distinct days. The
    renderer must split the phases apart using the event evidence
    so pre-published / published / active are each their own bar.
    """
    k = _ksk(12345)
    snap = _snap(
        generated="20260301000000",
        published="20260301000000",
        active="20260301000000",
    )
    events = [
        Event(ts="2026-03-04T00:00:00Z", source="dns",
              event_type="dns_dnskey_appeared_at_zone",
              summary="DNSKEY at zone",
              zone="example.com", key_tag=12345),
        Event(ts="2026-03-08T00:00:00Z", source="state",
              event_type="state_changed",
              summary="KRRSIG -> omnipresent",
              zone="example.com", key_tag=12345, key_role="KSK",
              detail={"field": "KRRSIGState", "new": "omnipresent"}),
    ]
    segs = _phase_segments_for_key(
        k, snap, events,
        datetime(2026, 2, 20, tzinfo=timezone.utc),
        datetime(2026, 4, 20, tzinfo=timezone.utc),
    )
    phases = [p for _, _, p in segs]
    assert phases == ["pre-published", "published", "active"]
    # Each phase has real duration — pre-pub gen->dns-appeared,
    # published dns-appeared->KRRSIG-omni, active to window_end.
    assert segs[0][0] == datetime(2026, 3, 1, tzinfo=timezone.utc)
    assert segs[0][1] == datetime(2026, 3, 4, tzinfo=timezone.utc)
    assert segs[1][0] == datetime(2026, 3, 4, tzinfo=timezone.utc)
    assert segs[1][1] == datetime(2026, 3, 8, tzinfo=timezone.utc)
    assert segs[2][0] == datetime(2026, 3, 8, tzinfo=timezone.utc)


def test_rndc_dnskey_rumoured_also_refines_published_boundary():
    """If there's no dns_dnskey_appeared_at_zone observation (maybe
    the DNS probe was disabled), rndc's own view of dnskey going
    omnipresent serves as the next-best evidence of publication."""
    k = _ksk(22222)
    snap = _snap(
        generated="20260301000000",
        published="20260301000000",
        active="20260301000000",
    )
    events = [
        Event(ts="2026-03-05T00:00:00Z", source="rndc",
              event_type="rndc_state_changed",
              summary="dnskey -> omnipresent",
              zone="example.com", key_tag=22222, key_role="KSK",
              detail={"field": "dnskey", "new": "omnipresent"}),
    ]
    segs = _phase_segments_for_key(
        k, snap, events,
        datetime(2026, 2, 20, tzinfo=timezone.utc),
        datetime(2026, 4, 20, tzinfo=timezone.utc),
    )
    phases = [p for _, _, p in segs]
    # With only a publication signal (rndc dnskey -> omnipresent)
    # and no separate RRSIG-signing signal, the ``published`` and
    # ``active`` boundaries stay coincident — so we get
    # pre-published followed by active. The important regression
    # guard is ``pre-published`` existing at all: before the fix,
    # the whole chart was a single ``active`` bar with no visible
    # pre-pub segment.
    assert phases[0] == "pre-published"
    # pre-pub ends at the observed rndc publication moment.
    assert segs[0][1] == datetime(2026, 3, 5, tzinfo=timezone.utc)


def test_zsk_uses_zrrsig_to_refine_active_boundary():
    """ZSKs sign the zone (not DNSKEY), so the refinement looks at
    ZRRSIG becoming omnipresent, not KRRSIG."""
    k = Key(zone="example.com", key_tag=67890, role="ZSK",
            algorithm=13, key_id="Kexample.com.+013+67890",
            first_seen="2026-03-01T00:00:00Z")
    snap = _snap(
        generated="20260301000000",
        published="20260301000000",
        active="20260301000000",
    )
    events = [
        Event(ts="2026-03-02T00:00:00Z", source="dns",
              event_type="dns_dnskey_appeared_at_zone",
              summary="DNSKEY at zone",
              zone="example.com", key_tag=67890),
        Event(ts="2026-03-10T00:00:00Z", source="state",
              event_type="state_changed",
              summary="ZRRSIG -> omnipresent",
              zone="example.com", key_tag=67890, key_role="ZSK",
              detail={"field": "ZRRSIGState", "new": "omnipresent"}),
        # KRRSIG events should NOT influence a ZSK — if we see one
        # here, it'd be wrong to use it. Put one earlier than the
        # ZRRSIG so the test would fail if the renderer picked the
        # wrong field.
        Event(ts="2026-03-05T00:00:00Z", source="state",
              event_type="state_changed",
              summary="KRRSIG -> omnipresent (irrelevant for ZSK)",
              zone="example.com", key_tag=67890, key_role="ZSK",
              detail={"field": "KRRSIGState", "new": "omnipresent"}),
    ]
    segs = _phase_segments_for_key(
        k, snap, events,
        datetime(2026, 2, 20, tzinfo=timezone.utc),
        datetime(2026, 4, 20, tzinfo=timezone.utc),
    )
    phases = [p for _, _, p in segs]
    assert phases == ["pre-published", "published", "active"]
    # active boundary must come from the ZRRSIG event (03-10),
    # not the earlier KRRSIG (03-05).
    assert segs[2][0] == datetime(2026, 3, 10, tzinfo=timezone.utc)


def test_refinement_does_not_override_genuinely_distinct_state_timestamps():
    """If the state file already has gen != pub != act, the
    refinement path is skipped — state-file truth wins, we don't
    manufacture different boundaries."""
    k = _ksk(33333)
    snap = _snap(
        generated="20260301000000",
        published="20260305000000",
        active="20260310000000",
    )
    # Even if we have events that COULD refine, they're ignored
    # when state-file boundaries are already distinct.
    events = [
        Event(ts="2026-03-15T00:00:00Z", source="dns",
              event_type="dns_dnskey_appeared_at_zone",
              summary="later observation",
              zone="example.com", key_tag=33333),
    ]
    segs = _phase_segments_for_key(
        k, snap, events,
        datetime(2026, 2, 20, tzinfo=timezone.utc),
        datetime(2026, 4, 20, tzinfo=timezone.utc),
    )
    # The original state-file dates must win — no silent rewriting.
    assert segs[1][0] == datetime(2026, 3, 5, tzinfo=timezone.utc)
    assert segs[2][0] == datetime(2026, 3, 10, tzinfo=timezone.utc)


def test_collapsed_with_no_events_still_degrades_gracefully():
    """If the state file collapses everything to one instant AND
    no events are available, we fall back to a single ``active``
    segment — no worse than before, and no crash."""
    k = _ksk(44444)
    snap = _snap(
        generated="20260301000000",
        published="20260301000000",
        active="20260301000000",
    )
    segs = _phase_segments_for_key(
        k, snap, [],
        datetime(2026, 2, 20, tzinfo=timezone.utc),
        datetime(2026, 4, 20, tzinfo=timezone.utc),
    )
    phases = [p for _, _, p in segs]
    # Matches the pre-fix behaviour — with zero event evidence there's
    # simply nothing to split on.
    assert phases == ["active"]


# --------------------------------------------------------------------------
# Minimum visible bar width — user-reported followup:
# "I'm still seeing only one color bar other than the DS one and it
# takes up the whole timeframe."
#
# On a year-wide chart a 2-day pre-published phase projects to ~3
# pixels — technically drawn but visually invisible next to the
# months-long active band. Enforce a 6-px floor for every positive-
# duration segment so every phase transition stays legible.
# --------------------------------------------------------------------------

import re as _re


def test_short_phases_get_minimum_visible_width_on_long_chart():
    """A realistic long-lived KSK: pre-pub 2 days, published 7 days,
    active >1 year. On the default ~680-px chart, pre-pub projects
    to ~3 pixels raw. The renderer must pad it up to at least 6 px
    so the user can actually see the bar."""
    k = _ksk(12345)
    snapshots = {
        "example.com#12345#KSK": {"fields": {
            "Generated": "20250101000000",
            "Published": "20250103000000",
            "Active":    "20250110000000",
            "Retired": "0", "Removed": "0",
            "GoalState": "omnipresent",
        }},
    }
    svg = render_rollover_view(
        [], [k], snapshots,
        from_ts="2025-01-01T00:00:00Z",
        to_ts="2026-04-14T00:00:00Z",
        today=datetime(2026, 4, 14, tzinfo=timezone.utc),
    )
    widths = {
        m.group(1): float(m.group(2))
        for m in _re.finditer(
            r'<rect class="phase phase-([\w-]+)"[^>]*?\bwidth="([\d.]+)"',
            svg,
        )
    }
    assert "pre-published" in widths
    assert "published" in widths
    assert "active" in widths
    # Every positive-duration phase must be visually detectable.
    assert widths["pre-published"] >= 6.0, (
        f"pre-published bar only {widths['pre-published']}px — "
        f"this is the 'can't see the phase change' regression"
    )
    assert widths["published"] >= 6.0
    # Active still dominates but the earlier phases stole a few
    # pixels. Confirm it's still clearly the biggest.
    assert widths["active"] > 10 * widths["pre-published"]


def test_minimum_width_does_not_push_bars_past_chart_right_edge():
    """If every narrow segment got padded and then pushed later
    segments forward, the final one could fall off the right edge.
    The renderer must cap the last bar so the overall chart still
    respects the window bound."""
    k = _ksk(77777)
    snapshots = {
        "example.com#77777#KSK": {"fields": {
            "Generated": "20260401000000",
            "Published": "20260402000000",
            "Active":    "20260403000000",
            "Retired":   "20260404000000",
            "Removed":   "20260405000000",
            "GoalState": "omnipresent",
        }},
    }
    # Narrow window so every phase collides with the min-width floor.
    svg = render_rollover_view(
        [], [k], snapshots,
        from_ts="2026-04-01T00:00:00Z",
        to_ts="2026-04-06T00:00:00Z",
        today=datetime(2026, 4, 6, tzinfo=timezone.utc),
    )
    # Chart width is 900 - margin_left(200) - margin_right(20) = 680,
    # right edge is at x=880. Every phase rect must end <= 880.
    for m in _re.finditer(
        r'<rect class="phase phase-[\w-]+"[^>]*?\bx="([\d.]+)"'
        r'[^>]*?\bwidth="([\d.]+)"',
        svg,
    ):
        x = float(m.group(1))
        w = float(m.group(2))
        assert x + w <= 881.0, (
            f"phase rect runs off the right edge: x={x} w={w} → "
            f"right={x + w}"
        )


# --------------------------------------------------------------------------
# DS overlap striping — when two KSKs simultaneously have DS at
# the parent (i.e. a double-DS rollover), each KSK's DS stripe
# renders the overlap portion with a blue/white diagonal pattern
# plus an "overlap" tooltip with the exact intersection window.
# --------------------------------------------------------------------------

from dnssec_tracker.render.rollover_view import (
    _ds_overlap_intervals,
    _split_ds_segment_by_overlap,
)


def test_ds_overlap_intervals_finds_simultaneous_ranges():
    """Given two KSKs' DS ranges that overlap in the middle, the
    sweep-line finds exactly the intersection window."""
    per_key = {
        ("z.example", 11111, "KSK"): [
            (datetime(2026, 1, 10, tzinfo=timezone.utc),
             datetime(2026, 3, 15, tzinfo=timezone.utc)),
        ],
        ("z.example", 22222, "KSK"): [
            (datetime(2026, 3, 1, tzinfo=timezone.utc),
             datetime(2026, 5, 20, tzinfo=timezone.utc)),
        ],
    }
    overlaps = _ds_overlap_intervals(per_key)
    assert overlaps == [
        (datetime(2026, 3, 1, tzinfo=timezone.utc),
         datetime(2026, 3, 15, tzinfo=timezone.utc)),
    ]


def test_ds_overlap_intervals_empty_when_ranges_dont_intersect():
    """Consecutive but non-overlapping DS ranges produce no
    overlap intervals (covering the demo scenario's shape where
    one KSK's DS cleanly hands off to the next)."""
    per_key = {
        ("z.example", 11111, "KSK"): [
            (datetime(2026, 1, 10, tzinfo=timezone.utc),
             datetime(2026, 3, 1, tzinfo=timezone.utc)),
        ],
        ("z.example", 22222, "KSK"): [
            # Starts exactly when the other ends.
            (datetime(2026, 3, 1, tzinfo=timezone.utc),
             datetime(2026, 5, 20, tzinfo=timezone.utc)),
        ],
    }
    assert _ds_overlap_intervals(per_key) == []


def test_split_ds_segment_by_overlap_carves_three_chunks():
    """A single DS range that contains an overlap in the middle
    should split into three sub-intervals: solid, overlap, solid."""
    a = datetime(2026, 1, 10, tzinfo=timezone.utc)
    b = datetime(2026, 5, 15, tzinfo=timezone.utc)
    overlaps = [
        (datetime(2026, 3, 1, tzinfo=timezone.utc),
         datetime(2026, 3, 15, tzinfo=timezone.utc)),
    ]
    out = _split_ds_segment_by_overlap(a, b, overlaps)
    # Three sub-intervals: solid up to 03-01, overlap 03-01..03-15,
    # solid 03-15..05-15.
    assert len(out) == 3
    (s0, e0, o0), (s1, e1, o1), (s2, e2, o2) = out
    assert (s0, e0, o0) == (a, overlaps[0][0], False)
    assert (s1, e1, o1) == (overlaps[0][0], overlaps[0][1], True)
    assert (s2, e2, o2) == (overlaps[0][1], b, False)


def test_rendered_svg_includes_overlap_pattern_and_tooltip():
    """End-to-end: two overlapping KSKs render with the diagonal
    pattern fill and an overlap-specific tooltip on both KSK rows."""
    k1 = Key(zone="z.example", key_tag=11111, role="KSK", algorithm=13,
             key_id="Kz.example.+013+11111",
             first_seen="2026-01-01T00:00:00Z")
    k2 = Key(zone="z.example", key_tag=22222, role="KSK", algorithm=13,
             key_id="Kz.example.+013+22222",
             first_seen="2026-02-01T00:00:00Z")
    events = [
        Event(ts="2026-01-10T00:00:00Z", source="dns",
              event_type="dns_ds_appeared_at_parent", summary="",
              zone="z.example", key_tag=11111),
        Event(ts="2026-03-15T00:00:00Z", source="dns",
              event_type="dns_ds_disappeared_at_parent", summary="",
              zone="z.example", key_tag=11111),
        Event(ts="2026-03-01T00:00:00Z", source="dns",
              event_type="dns_ds_appeared_at_parent", summary="",
              zone="z.example", key_tag=22222),
        Event(ts="2026-05-20T00:00:00Z", source="dns",
              event_type="dns_ds_disappeared_at_parent", summary="",
              zone="z.example", key_tag=22222),
    ]
    snap = {"fields": {"Generated": "20260101000000",
                       "GoalState": "omnipresent"}}
    svg = render_rollover_view(
        events, [k1, k2],
        {"z.example#11111#KSK": snap, "z.example#22222#KSK": snap},
        from_ts="2026-01-01T00:00:00Z", to_ts="2026-06-01T00:00:00Z",
        today=datetime(2026, 6, 1, tzinfo=timezone.utc),
    )
    # The defs block with the pattern is emitted once.
    assert '<pattern id="ds-overlap-stripes"' in svg
    # Two overlap rects (one per KSK row) use the pattern fill.
    assert svg.count('url(#ds-overlap-stripes)') == 2
    # Overlap tooltips name the exact intersection window.
    assert svg.count(
        "DS overlap with another KSK 2026-03-01 00:00 "
        "\u2192 2026-03-15 00:00 UTC"
    ) == 2
    # Non-overlapping portions still render as data-ds="live".
    assert svg.count('data-ds="live"') == 2
    assert svg.count('data-ds="overlap"') == 2


def test_non_overlapping_ds_ranges_produce_no_pattern_rects():
    """Demo scenario shape — sequential non-overlapping DS ranges
    — must NOT emit any overlap rects. Regression guard so the
    feature doesn't accidentally fire on clean rollovers."""
    k1 = Key(zone="z.example", key_tag=11111, role="KSK", algorithm=13,
             key_id="Kz.example.+013+11111",
             first_seen="2026-01-01T00:00:00Z")
    k2 = Key(zone="z.example", key_tag=22222, role="KSK", algorithm=13,
             key_id="Kz.example.+013+22222",
             first_seen="2026-03-01T00:00:00Z")
    events = [
        Event(ts="2026-01-10T00:00:00Z", source="dns",
              event_type="dns_ds_appeared_at_parent", summary="",
              zone="z.example", key_tag=11111),
        Event(ts="2026-03-01T00:00:00Z", source="dns",
              event_type="dns_ds_disappeared_at_parent", summary="",
              zone="z.example", key_tag=11111),
        Event(ts="2026-03-01T00:00:00Z", source="dns",
              event_type="dns_ds_appeared_at_parent", summary="",
              zone="z.example", key_tag=22222),
    ]
    snap = {"fields": {"Generated": "20260101000000",
                       "GoalState": "omnipresent"}}
    svg = render_rollover_view(
        events, [k1, k2],
        {"z.example#11111#KSK": snap, "z.example#22222#KSK": snap},
        from_ts="2026-01-01T00:00:00Z", to_ts="2026-05-01T00:00:00Z",
        today=datetime(2026, 5, 1, tzinfo=timezone.utc),
    )
    assert 'data-ds="overlap"' not in svg
    # Solid live DS stripes still render normally.
    assert svg.count('data-ds="live"') >= 2
