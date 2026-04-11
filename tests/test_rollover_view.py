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

    # Phase tooltips / class markers.
    assert "phase-active" in svg
    assert "phase-retired" in svg

    # DS overlay — both keys have DS events so two live stripes are emitted.
    assert svg.count('data-ds="live"') >= 2
    # And the empty-track is rendered once per KSK row.
    assert svg.count('data-ds="track"') == 2

    # Tooltip copy includes the phase names so mouseover is useful.
    assert "active" in svg
    assert "retired" in svg


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


def test_window_with_no_activity_returns_placeholder():
    """A key exists but its segments all fall outside the window."""
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
    assert "No key activity" in svg


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
    assert "phase-pre-publication" in svg
    assert "phase-published" in svg
    assert "phase-active" in svg


# --------------------------------------------------------------------------
# 5. _phase_segments_for_key unit test
# --------------------------------------------------------------------------

def test_phase_segments_for_canonical_ksk_snapshot():
    """Published + Active set, Retired/Removed still ``0`` — the key is
    alive and actively signing. The helper should produce exactly the
    three expected phases: pre-publication, published, active-to-window-
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
    assert p0 == "pre-publication"
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
    window. The ``removed`` boundary is a terminal marker so there
    should be exactly four segments."""
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
    assert phases == ["pre-publication", "published", "active", "retired"]
    # Retired segment runs Retired -> Removed, and nothing is emitted
    # past Removed so the bar truly stops there.
    assert segs[-1][0] == datetime(2026, 3, 20, tzinfo=timezone.utc)
    assert segs[-1][1] == datetime(2026, 3, 25, tzinfo=timezone.utc)


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
