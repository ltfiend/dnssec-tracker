"""Synthetic 12-month rollover scenario.

``build_rollover_demo(now)`` returns a fully-populated
:class:`DemoZone` with realistic DNSSEC-policy activity:

* 3 KSKs on a 6-month rollover cadence, staggered across 18 months
  so a 12-month view window captures two complete retirements plus
  the currently-active KSK.
* 13 ZSKs on a 1-month cadence — one rolling out of active, one in,
  and a tail of retired/removed keys visible earlier in the window.
* DS-at-parent transitions aligned with each KSK rollover
  (appears ~7 days after the KSK becomes Active, disappears at
  Retired).
* Per-key events: ``state_key_observed`` at generation,
  ``dns_dnskey_appeared_at_zone`` / ``dns_dnskey_disappeared_at_zone``
  at the zone-publish boundaries, ``state_changed`` transitions on
  DNSKEY / KRRSIG / ZRRSIG / GoalState so the rollover renderer's
  event-driven phase refinement has realistic boundary evidence.
* Parent DS and zone DNSKEY snapshots reflecting the *current*
  state of the world so the overdue-detection path sees "nothing
  lingering" cleanly.

Deterministic given ``now`` — the same input produces the same
DemoZone, which matters for regression tests against the shape.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from ..models import Event, Key, Zone


DEMO_ZONE_NAME = "demo.example"
DEMO_KEY_DIR = "/demo/keys"
DEMO_ALGORITHM = 13  # ECDSAP256SHA256

# Cadences
KSK_ROLL_DAYS = 182              # ~6 months
ZSK_ROLL_DAYS = 30               # 1 month

# Per-key phase durations (KSK). A KSK is pre-published briefly,
# then has a short "published but not signing" window, then
# actively signs for most of its life, then retires briefly before
# removal.
KSK_PREPUB_DAYS = 2
KSK_PUB_TO_ACTIVE_DAYS = 5
KSK_INACTIVE_DAYS = 30
# DS appears at parent shortly after activation (after parent
# publication completes) and disappears when the key retires.
KSK_DS_APPEAR_AFTER_ACTIVE_DAYS = 7

# Per-key phase durations (ZSK) — tighter since ZSKs roll every month.
ZSK_PREPUB_DAYS = 1
ZSK_PUB_TO_ACTIVE_DAYS = 2
ZSK_INACTIVE_DAYS = 3


@dataclass
class DemoZone:
    """Complete in-memory dataset for the demo page — mirrors what
    the zone-detail route normally assembles from the DB."""

    zone: Zone
    keys: list[Key]
    snapshots: dict[str, dict]          # scope -> {"fields":..., "timings":...}
    events: list[Event]
    zone_dns_snapshot: dict             # {"DNSKEY": [...], "SOA": [...]}
    parent_dns_snapshot: dict           # {"DS": [...]}

    # The window anchor. Used by the route to feed explicit from/to
    # into the renderers so the chart shows exactly the 12-month
    # window the demo is built for, not an auto-fitted range.
    window_start: datetime = field(default_factory=lambda: datetime.utcnow())
    window_end: datetime = field(default_factory=lambda: datetime.utcnow())


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _fmt_bind(ts: datetime) -> str:
    """BIND ``YYYYMMDDHHMMSS`` packed timestamp."""
    return ts.strftime("%Y%m%d%H%M%S")


def _iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _synthetic_tag(zone: str, role: str, generation: int) -> int:
    """Deterministic but distinct key tag per (zone, role, generation)."""
    h = hashlib.md5(f"{zone}:{role}:{generation}".encode()).hexdigest()
    # Key tags in DNSSEC are 16-bit; BIND clamps to <= 65535.
    return int(h[:4], 16) or 1


def _synthetic_key_id(zone: str, algo: int, tag: int) -> str:
    return f"K{zone}.+{algo:03d}+{tag:05d}"


def _build_key(
    zone: str,
    role: str,
    algo: int,
    tag: int,
    now: datetime,
) -> Key:
    return Key(
        zone=zone,
        key_tag=tag,
        role=role,
        algorithm=algo,
        key_id=_synthetic_key_id(zone, algo, tag),
        first_seen=_iso(now),
    )


def _build_snapshot(
    created: datetime,
    publish: datetime,
    activate: datetime,
    inactive: datetime | None,
    delete: datetime | None,
    role: str,
) -> dict:
    """Build a combined state_file + key_file snapshot dict.

    Fields come from the .state file — these are the actually-
    recorded transitions. Timings come from the .key file header
    — scheduled times. The rollover renderer reads both and prefers
    the state-file value when set.
    """

    def b(d: datetime | None) -> str:
        return _fmt_bind(d) if d is not None else "0"

    fields = {
        "Algorithm": str(DEMO_ALGORITHM),
        "KSK": "yes" if role in ("KSK", "CSK") else "no",
        "ZSK": "yes" if role in ("ZSK", "CSK") else "no",
        "Generated": b(created),
        "Published":  b(publish),
        "Active":     b(activate),
        "Retired":    b(inactive),
        "Removed":    b(delete),
        "GoalState":  "omnipresent",
        "DNSKEYState": "omnipresent",
    }
    if role in ("KSK", "CSK"):
        fields["KRRSIGState"] = "omnipresent"
        fields["DSState"] = "omnipresent"
    if role in ("ZSK", "CSK"):
        fields["ZRRSIGState"] = "omnipresent"

    timings = {
        "Created":  b(created),
        "Publish":  b(publish),
        "Activate": b(activate),
        "Inactive": b(inactive) if inactive else "0",
        "Delete":   b(delete) if delete else "0",
    }
    return {"fields": fields, "timings": timings}


def _emit_life_events(
    zone: str,
    tag: int,
    role: str,
    created: datetime,
    publish: datetime,
    activate: datetime,
    inactive: datetime | None,
    delete: datetime | None,
) -> list[Event]:
    """Standard lifecycle events the rollover renderer's
    event-driven boundary refinement will look at."""

    evs: list[Event] = []
    # Creation / first-sighting.
    evs.append(Event(
        ts=_iso(created),
        source="state", event_type="state_key_observed",
        summary=f"{role} tag {tag} observed on disk",
        zone=zone, key_tag=tag, key_role=role,
    ))
    # DNSKEY appears in the zone when publish lands.
    evs.append(Event(
        ts=_iso(publish),
        source="dns", event_type="dns_dnskey_appeared_at_zone",
        summary=f"DNSKEY (key tag {tag}) appeared at zone for {zone}",
        zone=zone, key_tag=tag, key_role=None,
        detail={"rrtype": "DNSKEY", "parent": False, "key_tag": tag},
    ))
    # DNSKEYState settling to omnipresent (happens between publish
    # and activate — represents full resolver propagation).
    propagated = publish + timedelta(days=1)
    evs.append(Event(
        ts=_iso(propagated),
        source="state", event_type="state_changed",
        summary=f"{role} tag {tag} DNSKEYState -> omnipresent",
        zone=zone, key_tag=tag, key_role=role,
        detail={"field": "DNSKEYState", "old": "rumoured", "new": "omnipresent"},
    ))
    # Signing kicks in at activate — KRRSIG for KSKs, ZRRSIG for ZSKs.
    rrsig_field = "ZRRSIGState" if role == "ZSK" else "KRRSIGState"
    evs.append(Event(
        ts=_iso(activate),
        source="state", event_type="state_changed",
        summary=f"{role} tag {tag} {rrsig_field} -> omnipresent",
        zone=zone, key_tag=tag, key_role=role,
        detail={"field": rrsig_field, "old": "rumoured", "new": "omnipresent"},
    ))
    # Retirement: GoalState flips to hidden.
    if inactive is not None:
        evs.append(Event(
            ts=_iso(inactive),
            source="state", event_type="state_changed",
            summary=f"{role} tag {tag} GoalState -> hidden",
            zone=zone, key_tag=tag, key_role=role,
            detail={"field": "GoalState", "old": "omnipresent", "new": "hidden"},
        ))
    # Removal: DNSKEY leaves the zone.
    if delete is not None:
        evs.append(Event(
            ts=_iso(delete),
            source="dns", event_type="dns_dnskey_disappeared_at_zone",
            summary=f"DNSKEY (key tag {tag}) disappeared at zone for {zone}",
            zone=zone, key_tag=tag, key_role=None,
            detail={"rrtype": "DNSKEY", "parent": False, "key_tag": tag},
        ))
    return evs


def _emit_ds_events(
    zone: str,
    tag: int,
    ds_appears: datetime,
    ds_disappears: datetime | None,
) -> list[Event]:
    evs = [Event(
        ts=_iso(ds_appears),
        source="dns", event_type="dns_ds_appeared_at_parent",
        summary=f"DS (key tag {tag}) appeared at parent for {zone}",
        zone=zone, key_tag=tag, key_role=None,
        detail={"rrtype": "DS", "parent": True, "key_tag": tag},
    )]
    if ds_disappears is not None:
        evs.append(Event(
            ts=_iso(ds_disappears),
            source="dns", event_type="dns_ds_disappeared_at_parent",
            summary=f"DS (key tag {tag}) disappeared at parent for {zone}",
            zone=zone, key_tag=tag, key_role=None,
            detail={"rrtype": "DS", "parent": True, "key_tag": tag},
        ))
    return evs


def build_rollover_demo(now: datetime | None = None) -> DemoZone:
    """Build the 12-month demo scenario anchored at ``now``
    (defaults to the current UTC time).

    The returned :class:`DemoZone` has every field a route would
    need to render the zone template through the existing
    renderers — no DB backing, purely in-memory.
    """

    now = _ensure_utc(now) if now is not None else datetime.now(timezone.utc)
    window_end = now
    # 12-month window, with a small pad on the right so the "now"
    # marker doesn't sit right on the edge of the chart.
    window_start = now - timedelta(days=365)

    zone = Zone(
        name=DEMO_ZONE_NAME,
        key_dir=DEMO_KEY_DIR,
        first_seen=_iso(window_start),
        last_seen=_iso(now),
    )

    keys: list[Key] = []
    snapshots: dict[str, dict] = {}
    events: list[Event] = []

    # ---------- KSKs ----------
    # KSK_i has Generated at:  now - 365 + (i * KSK_ROLL_DAYS) for i in range(3) + one older
    # We want 3 KSKs visible in the window: one that already retired
    # about a year ago (partially visible), one mid-cycle retired
    # within the window, and one currently active.
    #
    # Layout (anchored relative to now):
    #   KSK0 active:   -18mo to -12mo  (removed before window opens — just outside)
    #   KSK1 active:   -12mo to  -6mo  (retires inside the window)
    #   KSK2 active:    -6mo to  now   (currently active)
    ksk_generation_anchors = [
        # (generation_index, active_start_offset_days_from_now)
        (0, -18 * 30),   # earliest, mostly outside the window — first retirement is visible
        (1, -12 * 30),   # first full cycle inside the window
        (2,  -6 * 30),   # current active KSK
    ]

    active_ksk_tag: int | None = None
    for gen_idx, start_offset in ksk_generation_anchors:
        active_start = now + timedelta(days=start_offset)
        # inactive/remove relative to active_start — last KSK is
        # ongoing (inactive + delete = None).
        is_current = (gen_idx == ksk_generation_anchors[-1][0])
        if is_current:
            inactive = None
            delete = None
        else:
            inactive = active_start + timedelta(days=KSK_ROLL_DAYS)
            delete = inactive + timedelta(days=KSK_INACTIVE_DAYS)

        created = active_start - timedelta(
            days=KSK_PREPUB_DAYS + KSK_PUB_TO_ACTIVE_DAYS
        )
        publish = active_start - timedelta(days=KSK_PUB_TO_ACTIVE_DAYS)

        tag = _synthetic_tag(DEMO_ZONE_NAME, "KSK", gen_idx)
        keys.append(_build_key(DEMO_ZONE_NAME, "KSK", DEMO_ALGORITHM, tag, created))
        scope = f"{DEMO_ZONE_NAME}#{tag}#KSK"
        snapshots[scope] = _build_snapshot(
            created, publish, active_start, inactive, delete, "KSK",
        )
        events.extend(_emit_life_events(
            DEMO_ZONE_NAME, tag, "KSK",
            created, publish, active_start, inactive, delete,
        ))
        # DS lifecycle at parent: appears shortly after Active, goes
        # away at Retired.
        ds_appears = active_start + timedelta(
            days=KSK_DS_APPEAR_AFTER_ACTIVE_DAYS
        )
        events.extend(_emit_ds_events(
            DEMO_ZONE_NAME, tag, ds_appears, inactive,
        ))

        if is_current:
            active_ksk_tag = tag

    # ---------- ZSKs ----------
    # 13 ZSKs rolling monthly. The current ZSK is in its "active"
    # phase right now; the one before is in the tail end of
    # "inactive" waiting to be removed; the rest are progressively
    # older and either removed or mid-lifecycle depending on window.
    #
    # For ZSK_i (i in 0..12), its active-start is roughly:
    #   now - (12 - i) * 30 days
    # So ZSK_0 is the oldest (12 months ago), ZSK_12 is the current
    # one (active now, still running).
    active_zsk_tag: int | None = None
    for gen_idx in range(13):
        # Newest ZSK (gen_idx=12) activated 0 days ago and is still
        # active. Each older one shifted a month earlier.
        active_start = now - timedelta(days=(12 - gen_idx) * ZSK_ROLL_DAYS)
        is_current = (gen_idx == 12)
        if is_current:
            inactive = None
            delete = None
        else:
            inactive = active_start + timedelta(days=ZSK_ROLL_DAYS)
            delete = inactive + timedelta(days=ZSK_INACTIVE_DAYS)

        created = active_start - timedelta(
            days=ZSK_PREPUB_DAYS + ZSK_PUB_TO_ACTIVE_DAYS
        )
        publish = active_start - timedelta(days=ZSK_PUB_TO_ACTIVE_DAYS)

        tag = _synthetic_tag(DEMO_ZONE_NAME, "ZSK", gen_idx)
        keys.append(_build_key(DEMO_ZONE_NAME, "ZSK", DEMO_ALGORITHM, tag, created))
        scope = f"{DEMO_ZONE_NAME}#{tag}#ZSK"
        snapshots[scope] = _build_snapshot(
            created, publish, active_start, inactive, delete, "ZSK",
        )
        events.extend(_emit_life_events(
            DEMO_ZONE_NAME, tag, "ZSK",
            created, publish, active_start, inactive, delete,
        ))
        if is_current:
            active_zsk_tag = tag

    # ---------- current dns_probe snapshots ----------
    # The zone currently publishes the currently-active KSK + ZSK
    # DNSKEYs and the parent has a DS for the current KSK. These
    # feed the overdue-detection path, which should see "nothing
    # lingering" for a healthy zone.
    #
    # We don't need real wire-format records — just something
    # _extract_key_tag() can parse. For DS the first field is the
    # tag, which is all that matters. For DNSKEY we synthesise a
    # plausible ECDSA P-256 rdata (the tag computation works off
    # the wire bytes, so the actual base64 doesn't need to match
    # our synthetic tag — we just need valid rdata). The overdue
    # detector walks tags AT the snapshot level for the comparison,
    # not inside the rdata, so we don't have to be perfect here.
    #
    # Simplest: leave the snapshots structurally correct but empty.
    # The overdue path tolerates empty DNSKEY / DS lists and just
    # classifies every key as "not lingering".
    zone_dns_snapshot: dict = {
        "DNSKEY": [],
        "SOA": [],
        "CDS": [],
        "CDNSKEY": [],
        "RRSIG": [],
    }
    parent_dns_snapshot: dict = {"DS": []}

    return DemoZone(
        zone=zone,
        keys=keys,
        snapshots=snapshots,
        events=events,
        zone_dns_snapshot=zone_dns_snapshot,
        parent_dns_snapshot=parent_dns_snapshot,
        window_start=window_start,
        window_end=window_end,
    )
