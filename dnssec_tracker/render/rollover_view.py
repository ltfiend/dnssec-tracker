"""Chronological "rollover story" SVG visualisation.

DNSviz shows a *snapshot* of the chain of trust; this renderer shows
the *time axis*. At any vertical slice of the chart, the set of bars
intersecting that slice is exactly the keys that were operational at
that moment, subdivided into the phase each one was in. Together with
the DS-at-parent overlay stripe above every KSK bar, the user should
be able to follow an entire rollover pass — "new KSK pre-published,
then published, then DS went live at the parent, then old KSK retired,
then old KSK removed" — by sweeping their eye left-to-right across
the chart.

Pure Python + inline SVG, no JS, no new dependencies. Output is safe
for WeasyPrint (PDF export path) and for both the dark-theme live UI
and the always-light ``body.report`` stylesheet — colours go through
``var(--accent|state|muted|border|surface|fg)`` and the only hard-
coded hex is a pair of mid-grey phase fills that read on either
palette.

The public entry point is :func:`render_rollover_view`; the phase-
segment helper :func:`_phase_segments_for_key` is private but
deliberately exposed at module scope for direct unit testing — it is
where all of the "what phase is this key in between t0 and t1"
reasoning lives and it is worth the dedicated coverage.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from html import escape

from ..models import Event, Key


# ----- phase colours ------------------------------------------------------
#
# Greys are hard-coded on purpose: they read on both the dark live UI
# and the forced-light report body. Everything else goes through the
# CSS custom properties the rest of the app uses so theme changes
# propagate for free.
PHASE_FILL = {
    "pre-published": "#c8c8c8",
    "published": "var(--rndc)",          # warm amber-ish in both palettes
    "active": "var(--state)",            # the "doing its job" green
    "inactive": "var(--named)",     # orange — not signing, scheduled for delete
    "removed": "#8b5a5a",     # muted dusty red — key should be gone
}

PHASE_DESCRIPTION = {
    "pre-published": "generated but not yet in the DNSKEY RRset",
    "published": "DNSKEY visible but not yet signing",
    "active": "signing DNSKEY / zone data",
    "inactive": "not signing, published for resolver caches, awaiting delete",
    "removed": "past scheduled delete time — should no longer be in the zone",
}

PHASE_LABEL = {
    "pre-published": "pre-published",
    "published": "published",
    "active": "active",
    "inactive": "inactive",
    "removed": "removed",
}

# Event types that the DS-at-parent overlay cares about.
DS_APPEAR = "dns_ds_appeared_at_parent"
DS_DISAPPEAR = "dns_ds_disappeared_at_parent"


# ----- timestamp parsing --------------------------------------------------


def _parse_ts(ts: str | None) -> datetime | None:
    """Parse an ISO-8601 event timestamp. ``None`` on failure."""
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _parse_bind_ts(value: str | None) -> datetime | None:
    """Parse a BIND ``YYYYMMDDHHMMSS`` timestamp, ``"0"`` ``-> None``."""
    if value is None:
        return None
    s = str(value).strip()
    if not s or s == "0":
        return None
    if len(s) != 14 or not s.isdigit():
        return None
    try:
        return datetime(
            int(s[0:4]), int(s[4:6]), int(s[6:8]),
            int(s[8:10]), int(s[10:12]), int(s[12:14]),
            tzinfo=timezone.utc,
        )
    except ValueError:
        return None


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _fmt_tick(t: datetime, span_sec: float) -> str:
    """Same granularity ladder as ``event_timeline._fmt_tick``."""
    if span_sec <= 2 * 3600:
        return t.strftime("%H:%M")
    if span_sec <= 2 * 86400:
        return t.strftime("%m-%d %H:%M")
    if span_sec <= 60 * 86400:
        return t.strftime("%Y-%m-%d")
    return t.strftime("%Y-%m")


# ----- phase derivation ---------------------------------------------------


def _phase_segments_for_key(
    key: Key,
    snapshot: dict | None,
    events: list[Event],
    window_start: datetime,
    window_end: datetime,
) -> list[tuple[datetime, datetime, str]]:
    """Return ``[(start, end, phase_name), ...]`` for one key.

    Phase boundaries are drawn from the BIND ``.state`` timestamps
    (``Generated``, ``Published``, ``Active``, ``Retired``,
    ``Removed``) when the snapshot has them; otherwise fall back to
    event-derived approximations. The segment list is clamped to
    ``[window_start, window_end]`` so a key that lived entirely
    outside the window produces an empty list and is omitted from the
    chart.
    """

    fields: dict[str, str] = {}
    timings: dict[str, str] = {}
    if snapshot:
        if isinstance(snapshot.get("fields"), dict):
            fields = snapshot["fields"]
        # The wiring layer folds the K*.key file's scheduled timings
        # (Created / Publish / Activate / Inactive / Delete / SyncPublish)
        # into the same snapshot dict under "timings". The state-file
        # values take precedence — they record what actually happened —
        # but the key-file values fill in *scheduled* boundaries so a
        # key that hasn't yet crossed, say, its Active time still shows
        # the correct upcoming phase break instead of collapsing into
        # an endless "pre-published" segment.
        if isinstance(snapshot.get("timings"), dict):
            timings = snapshot["timings"]

    # Prefer state-file actuals; fall back to key-file scheduled times.
    # ``_parse_bind_ts`` returns None for "0" and missing values, which
    # is what lets ``a or b`` cleanly pick the first non-unset source.
    gen = (
        _parse_bind_ts(fields.get("Generated"))
        or _parse_bind_ts(timings.get("Created"))
    )
    pub = (
        _parse_bind_ts(fields.get("Published"))
        or _parse_bind_ts(timings.get("Publish"))
    )
    act = (
        _parse_bind_ts(fields.get("Active"))
        or _parse_bind_ts(timings.get("Activate"))
    )
    ret = (
        _parse_bind_ts(fields.get("Retired"))
        or _parse_bind_ts(timings.get("Inactive"))
    )
    rem = (
        _parse_bind_ts(fields.get("Removed"))
        or _parse_bind_ts(timings.get("Delete"))
    )

    # Fall back to events when the snapshot is missing.
    key_events = [
        e for e in events
        if e.zone == key.zone and e.key_tag == key.key_tag
    ]
    key_events.sort(key=lambda e: e.ts)

    if gen is None:
        # Walk events for anything that looks like creation.
        for e in key_events:
            if e.event_type in ("key_file_observed", "state_key_observed", "iodyn_key_created"):
                gen = _parse_ts(e.ts)
                break
        if gen is None and key_events:
            gen = _parse_ts(key_events[0].ts)
        if gen is None:
            # Fall back to first_seen on the Key object.
            gen = _parse_ts(key.first_seen)

    if pub is None:
        for e in key_events:
            if e.event_type == "dns_dnskey_appeared_at_zone":
                pub = _parse_ts(e.ts)
                break
        if pub is None:
            for e in key_events:
                if (
                    e.event_type == "state_changed"
                    and (e.detail or {}).get("field") == "DNSKEYState"
                    and "omnipresent" in str((e.detail or {}).get("new", "")).lower()
                ):
                    pub = _parse_ts(e.ts)
                    break

    if act is None:
        for e in key_events:
            if (
                e.event_type == "state_changed"
                and (e.detail or {}).get("field") == "GoalState"
                and "omnipresent" in str((e.detail or {}).get("new", "")).lower()
            ):
                act = _parse_ts(e.ts)
                break

    if ret is None:
        for e in key_events:
            if (
                e.event_type == "state_changed"
                and (e.detail or {}).get("field") == "GoalState"
                and "hidden" in str((e.detail or {}).get("new", "")).lower()
            ):
                ret = _parse_ts(e.ts)
                break

    if rem is None:
        for e in key_events:
            if e.event_type == "dns_dnskey_disappeared_at_zone":
                rem = _parse_ts(e.ts)
                break

    if gen is None:
        # Truly nothing to go on — pretend the key has existed for the
        # entire window. Better than silently dropping it.
        gen = window_start

    # Observation-based refinement. BIND often writes ``Generated``,
    # ``Published``, and ``Active`` onto the same instant (the moment
    # the key is loaded, during a pre-published rollover setup) —
    # the raw state-file timestamps then collapse gen/pub/act into a
    # single point and the earlier phases become zero-width, which
    # the segment builder drops. The user's observation was: "bars
    # don't capture when a KSK appears in a zone or when it goes
    # published -> active as separate bars".
    #
    # Fix: when a later boundary isn't strictly after the previous
    # one, look in the event stream for evidence of the actual
    # transition moment and use THAT to split the phases apart. Only
    # rewrite when the event time is strictly *later* than the
    # preceding boundary — we don't invent earlier boundaries, only
    # push later ones further out so the intermediate phase has real
    # duration on the chart.
    def _first_event_ts_after(
        after: datetime, predicates: list
    ) -> datetime | None:
        for e in key_events:
            for pred in predicates:
                if pred(e):
                    ts = _parse_ts(e.ts)
                    if ts is not None and _ensure_utc(ts) > after:
                        return _ensure_utc(ts)
                    break
        return None

    def _is_state_change_to_omnipresent(field_names: tuple[str, ...]):
        def check(e: Event) -> bool:
            if e.event_type != "state_changed":
                return False
            d = e.detail or {}
            return (
                d.get("field") in field_names
                and "omnipresent" in str(d.get("new", "")).lower()
            )
        return check

    def _is_rndc_change_to_omnipresent(field_names: tuple[str, ...]):
        def check(e: Event) -> bool:
            if e.event_type != "rndc_state_changed":
                return False
            d = e.detail or {}
            return (
                d.get("field") in field_names
                and "omnipresent" in str(d.get("new", "")).lower()
            )
        return check

    # pub got collapsed onto gen — try to find the *observed*
    # publication moment (DNSKEY actually visible in the zone, or
    # BIND's DNSKEYState transitioning to rumoured / omnipresent).
    if pub is not None and gen is not None and _ensure_utc(pub) <= _ensure_utc(gen):
        refined = _first_event_ts_after(
            _ensure_utc(gen),
            [
                lambda e: e.event_type == "dns_dnskey_appeared_at_zone",
                _is_state_change_to_omnipresent(("DNSKEYState",)),
                _is_rndc_change_to_omnipresent(("dnskey",)),
            ],
        )
        if refined is not None:
            pub = refined

    # act got collapsed onto pub — look for KRRSIG / ZRRSIG going
    # live (the key is actually signing). Use the KSK/ZSK role to
    # pick the right RRSIG field.
    if act is not None and pub is not None and _ensure_utc(act) <= _ensure_utc(pub):
        rrsig_fields_state: tuple[str, ...]
        rrsig_fields_rndc: tuple[str, ...]
        if key.role == "ZSK":
            rrsig_fields_state = ("ZRRSIGState",)
            rrsig_fields_rndc = ("zone_rrsig",)
        else:
            # KSK, CSK, or unknown — KRRSIG covers DNSKEY RRset.
            rrsig_fields_state = ("KRRSIGState",)
            rrsig_fields_rndc = ("key_rrsig",)
        refined = _first_event_ts_after(
            _ensure_utc(pub),
            [
                _is_state_change_to_omnipresent(rrsig_fields_state),
                _is_rndc_change_to_omnipresent(rrsig_fields_rndc),
            ],
        )
        if refined is not None:
            act = refined

    # ret got collapsed onto act — look for the first state change
    # signalling retirement (GoalState going hidden, or any RRSIG
    # field leaving omnipresent).
    if ret is not None and act is not None and _ensure_utc(ret) <= _ensure_utc(act):
        def _is_goal_hidden(e: Event) -> bool:
            if e.event_type != "state_changed":
                return False
            d = e.detail or {}
            return (
                d.get("field") == "GoalState"
                and "hidden" in str(d.get("new", "")).lower()
            )

        refined = _first_event_ts_after(
            _ensure_utc(act), [_is_goal_hidden]
        )
        if refined is not None:
            ret = refined

    # rem got collapsed onto ret — look for the DNSKEY leaving the
    # zone (observation side, via DNS probe).
    if rem is not None and ret is not None and _ensure_utc(rem) <= _ensure_utc(ret):
        refined = _first_event_ts_after(
            _ensure_utc(ret),
            [lambda e: e.event_type == "dns_dnskey_disappeared_at_zone"],
        )
        if refined is not None:
            rem = refined

    # Enforce monotonicity — downstream maths assumes t_i <= t_{i+1}.
    # Any out-of-order timestamp clamps forward to the previous one.
    boundaries: list[tuple[str, datetime | None]] = [
        ("pre-published", gen),
        ("published", pub),
        ("active", act),
        ("inactive", ret),        # Inactive -> Delete
        ("removed", rem),   # past Delete, renders (no longer terminal)
    ]

    # Forward-fill: if "published" is missing but "active" exists, the
    # "pre-published" phase runs straight to "active" and "published"
    # is skipped.
    cleaned: list[tuple[str, datetime]] = []
    last = None
    for name, t in boundaries:
        if t is None:
            continue
        t = _ensure_utc(t)
        if last is not None and t < last:
            t = last
        cleaned.append((name, t))
        last = t

    if not cleaned:
        return []

    # Append a synthetic terminal boundary at window_end so the last
    # phase has somewhere to end. If "removed" is set, that IS the
    # terminal boundary and the bar stops there.
    segments: list[tuple[datetime, datetime, str]] = []
    for i, (name, t0) in enumerate(cleaned):
        if i + 1 < len(cleaned):
            t1 = cleaned[i + 1][1]
        else:
            # Last boundary extends to window_end. This includes
            # ``removed``: a key whose scheduled Delete has
            # passed keeps rendering as that phase all the way to the
            # chart's right edge so the operator can *see* that the
            # key is overdue for removal — previously that segment was
            # silently dropped and the bar just ended, which made
            # post-Delete keys look like they never existed.
            t1 = window_end
        if t1 <= t0:
            continue
        segments.append((t0, t1, name))

    # Clamp to window.
    clamped: list[tuple[datetime, datetime, str]] = []
    for t0, t1, name in segments:
        if t1 <= window_start or t0 >= window_end:
            continue
        a = max(t0, window_start)
        b = min(t1, window_end)
        if b > a:
            clamped.append((a, b, name))

    return clamped


# ----- DS overlay ---------------------------------------------------------


def _ds_overlay_segments(
    key: Key,
    events: list[Event],
    window_start: datetime,
    window_end: datetime,
) -> list[tuple[datetime, datetime]]:
    """Walk DS appear / disappear events for one key and return the
    ``[(from, to), ...]`` ranges during which the DS was observed at
    the parent.
    """
    if key.role == "ZSK":
        return []

    ds_events = sorted(
        (
            e for e in events
            if e.zone == key.zone
            and e.key_tag == key.key_tag
            and e.event_type in (DS_APPEAR, DS_DISAPPEAR)
        ),
        key=lambda e: e.ts,
    )
    if not ds_events:
        return []

    ranges: list[tuple[datetime, datetime]] = []
    current_start: datetime | None = None
    for e in ds_events:
        t = _parse_ts(e.ts)
        if t is None:
            continue
        if e.event_type == DS_APPEAR and current_start is None:
            current_start = t
        elif e.event_type == DS_DISAPPEAR and current_start is not None:
            ranges.append((current_start, t))
            current_start = None
    if current_start is not None:
        ranges.append((current_start, window_end))

    # Clamp to window.
    clamped: list[tuple[datetime, datetime]] = []
    for a, b in ranges:
        if b <= window_start or a >= window_end:
            continue
        clamped.append((max(a, window_start), min(b, window_end)))
    return clamped


def _ds_overlap_intervals(
    per_key_ds: dict,
) -> list[tuple[datetime, datetime]]:
    """Given every KSK's DS live-ranges, return the time intervals
    during which *two or more* keys simultaneously have DS at the
    parent. Used to shade the DS stripes so rollover overlaps are
    visually obvious.

    Sweep-line over appearance/disappearance events: increment on
    range start, decrement on end, mark the span whenever depth
    hits 2+.
    """
    events: list[tuple[datetime, int]] = []
    for ranges in per_key_ds.values():
        for a, b in ranges:
            events.append((a, +1))
            events.append((b, -1))
    # Sort by time; -1 before +1 at the same instant so adjacent
    # (but not overlapping) ranges don't register as an overlap.
    events.sort(key=lambda t: (t[0], t[1]))

    depth = 0
    overlap_start: datetime | None = None
    out: list[tuple[datetime, datetime]] = []
    for t, delta in events:
        prev = depth
        depth += delta
        if depth >= 2 and prev < 2:
            overlap_start = t
        elif depth < 2 and prev >= 2 and overlap_start is not None:
            if t > overlap_start:
                out.append((overlap_start, t))
            overlap_start = None
    return out


def _split_ds_segment_by_overlap(
    a: datetime,
    b: datetime,
    overlaps: list[tuple[datetime, datetime]],
) -> list[tuple[datetime, datetime, bool]]:
    """Chop a single DS live range ``[a, b)`` into sub-intervals
    tagged with ``is_overlap``. Non-overlapping chunks render as
    solid blue; overlapping chunks render as the stripe pattern.
    """
    # Overlaps intersecting this segment, clipped to its bounds.
    clipped = sorted(
        (max(a, s), min(b, e))
        for s, e in overlaps
        if s < b and e > a
    )
    out: list[tuple[datetime, datetime, bool]] = []
    cursor = a
    for s, e in clipped:
        if s > cursor:
            out.append((cursor, s, False))
        out.append((s, e, True))
        cursor = e
    if cursor < b:
        out.append((cursor, b, False))
    return out


# ----- empty / placeholder SVG -------------------------------------------


def _empty(message: str) -> str:
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 60" '
        'font-family="sans-serif" font-size="12" class="rollover-view">'
        f'<text x="10" y="30" fill="currentColor" fill-opacity="0.6">{escape(message)}</text>'
        "</svg>"
    )


# ----- main entry point ---------------------------------------------------


# Role ordering: KSK first (chain-of-trust anchor), then CSK (combined,
# functionally the trust anchor too), then ZSK. This puts the "does the
# parent know about us" bars up the top where the DS overlay stripe
# lives.
_ROLE_ORDER = {"KSK": 0, "CSK": 1, "ZSK": 2}


def render_rollover_view(
    events: list[Event],
    keys: list[Key],
    snapshots: dict[str, dict],
    *,
    from_ts: str | None = None,
    to_ts: str | None = None,
    today: datetime | None = None,
    overdue_by_tag: dict[int, "OverdueState"] | None = None,
) -> str:
    """Render the rollover-story SVG fragment.

    See the module docstring for the visual model. The ``snapshots``
    dict is keyed by ``f"{zone}#{tag}#{role}"`` and each value is the
    parsed BIND ``.state`` snapshot (``{"fields": {...}, "path": ...}``);
    the parent session fetches these from the DB and passes them in so
    this module stays I/O-free.
    """

    # ----- resolve the time window ---------------------------------------
    t_start = _parse_ts(from_ts)
    t_end = _parse_ts(to_ts)
    if today is None:
        today_dt = datetime.now(timezone.utc)
    else:
        today_dt = _ensure_utc(today)

    # Collect every timestamp we know about so we can auto-fit the
    # window when the caller didn't pin it.
    candidate_ts: list[datetime] = []
    for e in events:
        t = _parse_ts(e.ts)
        if t is not None:
            candidate_ts.append(t)
    for k in keys:
        snap = snapshots.get(f"{k.zone}#{k.key_tag}#{k.role}") or {}
        fields = snap.get("fields", {}) if isinstance(snap, dict) else {}
        for field_name in ("Generated", "Published", "Active", "Retired", "Removed"):
            t = _parse_bind_ts(fields.get(field_name))
            if t is not None:
                candidate_ts.append(t)
        t = _parse_ts(k.first_seen)
        if t is not None:
            candidate_ts.append(t)

    if t_start is None:
        t_start = min(candidate_ts) if candidate_ts else today_dt - timedelta(days=30)
    if t_end is None:
        t_end = today_dt if today_dt > t_start else (
            max(candidate_ts) if candidate_ts else t_start + timedelta(days=30)
        )

    if t_end < t_start:
        t_start, t_end = t_end, t_start
    if t_end <= t_start:
        t_end = t_start + timedelta(hours=1)

    # Nothing to draw? Early out.
    if not keys:
        return _empty("No keys observed in this window.")

    # ----- build rows -----------------------------------------------------
    # Group keys by (role, algorithm). Within a group, keys stack
    # vertically sorted by first timestamp so visual order matches
    # "which key was published first".
    groups: dict[tuple[str, int], list[Key]] = {}
    for k in keys:
        groups.setdefault((k.role or "UNKNOWN", k.algorithm), []).append(k)

    # Order groups: role (KSK, CSK, ZSK), then algorithm.
    ordered_groups: list[tuple[tuple[str, int], list[Key]]] = sorted(
        groups.items(),
        key=lambda item: (_ROLE_ORDER.get(item[0][0], 9), item[0][1]),
    )

    # Precompute phase segments for each key so we can (a) decide
    # whether any key has content in the window, and (b) spot algorithm-
    # rollover overlaps without re-walking the snapshot.
    per_key_segments: dict[tuple[str, int, str], list[tuple[datetime, datetime, str]]] = {}
    per_key_ds: dict[tuple[str, int, str], list[tuple[datetime, datetime]]] = {}
    for (role, algo), gkeys in ordered_groups:
        gkeys.sort(key=lambda k: (_parse_ts(k.first_seen) or t_start))
        for k in gkeys:
            snap = snapshots.get(f"{k.zone}#{k.key_tag}#{k.role}")
            segs = _phase_segments_for_key(k, snap, events, t_start, t_end)
            per_key_segments[(k.zone, k.key_tag, k.role)] = segs
            per_key_ds[(k.zone, k.key_tag, k.role)] = _ds_overlay_segments(
                k, events, t_start, t_end,
            )

    # Time intervals where two or more KSKs simultaneously had DS
    # records at the parent — the DS-stripe overlap regions. Used
    # below to render those portions of each KSK's DS stripe with a
    # blue/white diagonal pattern plus a specific "overlap
    # <start>→<end>" tooltip, so double-DS rollover states are
    # visually distinct from single-DS active states.
    ds_overlap_spans = _ds_overlap_intervals(per_key_ds)

    # Any segments at all?
    if not any(per_key_segments.values()):
        return _empty("No key activity in the selected window.")

    # ----- layout constants ----------------------------------------------
    margin_left = 200
    margin_right = 20
    margin_top = 40
    margin_bot = 40
    width = 900
    chart_w = width - margin_left - margin_right

    row_h = 28
    row_gap = 8
    group_header_h = 18
    ds_stripe_h = 6
    ds_stripe_gap = 2

    # Compute dynamic y positions.
    y = margin_top + 10
    group_y_ranges: list[tuple[tuple[str, int], int, int]] = []  # (key, y0, y1)
    row_positions: dict[tuple[str, int, str], dict] = {}

    for gi, ((role, algo), gkeys) in enumerate(ordered_groups):
        group_y0 = y
        if gi > 0:
            y += group_header_h  # header separator
        else:
            y += group_header_h
        group_label_y = y - 4
        for k in gkeys:
            # Each KSK / CSK row also carries a DS overlay stripe above
            # it. The stripe is cosmetic — the bar is what determines
            # the "operational at this time" question — so it sits in
            # a reserved strip *above* the bar, not on top of it.
            with_ds = k.role in ("KSK", "CSK")
            top_pad = (ds_stripe_h + ds_stripe_gap) if with_ds else 0
            bar_y = y + top_pad
            row_positions[(k.zone, k.key_tag, k.role)] = {
                "row_top": y,
                "bar_y": bar_y,
                "bar_h": row_h,
                "with_ds": with_ds,
            }
            y += top_pad + row_h + row_gap
        group_y_ranges.append(((role, algo), group_y0, y, group_label_y))
        # extra gap between groups
        y += 4

    total_height = y + margin_bot
    span_sec = (t_end - t_start).total_seconds() or 1.0

    def x_for(dt: datetime) -> float:
        return margin_left + ((dt - t_start).total_seconds() / span_sec) * chart_w

    # ----- start SVG ------------------------------------------------------
    parts: list[str] = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {total_height}" '
        f'font-family="sans-serif" font-size="11" class="rollover-view">'
    )
    # A diagonal blue/white pattern used for DS-overlap regions —
    # when two KSKs simultaneously have DS at the parent during a
    # rollover, the overlap portion of each KSK's DS stripe renders
    # as stripes so the operator can see the two live DS records
    # coexist. patternTransform rotates the stripes 45 degrees;
    # userSpaceOnUse lets the pattern tile consistently across
    # different-sized rects.
    parts.append(
        '<defs>'
        '<pattern id="ds-overlap-stripes" patternUnits="userSpaceOnUse" '
        'width="8" height="8" patternTransform="rotate(45)">'
        '<rect width="8" height="8" fill="var(--accent)"/>'
        '<rect x="0" y="0" width="4" height="8" fill="#ffffff" fill-opacity="0.65"/>'
        '</pattern>'
        '</defs>'
    )

    # Date-range label — right-aligned at the top of the chart area,
    # small and muted so it sits alongside the axis ticks without
    # overlapping the group headers or tick labels. The section <h3>
    # in the template already says "Rollover view" so we don't
    # duplicate that as a bold title inside the SVG.
    parts.append(
        f'<text x="{width - margin_right}" y="14" text-anchor="end" '
        f'font-size="10" fill="currentColor" fill-opacity="0.55">'
        f'{escape(t_start.strftime("%Y-%m-%d %H:%M"))} &#x2192; '
        f'{escape(t_end.strftime("%Y-%m-%d %H:%M"))} UTC</text>'
    )

    # ----- algorithm-rollover highlight ----------------------------------
    # If two KSK / CSK groups overlap in "active" phase, shade the
    # intersection so the user sees "these algorithms were both live
    # simultaneously". Intentionally done behind the bars.
    def _active_ranges_for_group(gkeys: list[Key]) -> list[tuple[datetime, datetime]]:
        out: list[tuple[datetime, datetime]] = []
        for k in gkeys:
            for t0, t1, name in per_key_segments.get((k.zone, k.key_tag, k.role), []):
                if name == "active":
                    out.append((t0, t1))
        return out

    trust_groups = [
        (key_tuple, gkeys) for (key_tuple, gkeys) in ordered_groups
        if key_tuple[0] in ("KSK", "CSK", "ZSK")
    ]

    # Compare every pair of groups with different algorithms; if any of
    # their active ranges overlap, mark the intersection. This catches
    # both same-role cross-algorithm rollovers (KSK alg 13 -> alg 15)
    # and ZSK cross-algorithm rollovers.
    overlap_shapes: list[tuple[float, float, float, float]] = []
    for i in range(len(trust_groups)):
        for j in range(i + 1, len(trust_groups)):
            (role_i, alg_i), gi_keys = trust_groups[i]
            (role_j, alg_j), gj_keys = trust_groups[j]
            if alg_i == alg_j:
                continue
            # Only consider rollovers within the same role — a KSK and
            # a ZSK being simultaneously active is the normal case, not
            # a rollover.
            if role_i != role_j:
                continue
            ri = _active_ranges_for_group(gi_keys)
            rj = _active_ranges_for_group(gj_keys)
            for a0, a1 in ri:
                for b0, b1 in rj:
                    lo = max(a0, b0)
                    hi = min(a1, b1)
                    if hi > lo:
                        # Figure out the vertical extent spanning both
                        # groups' rows so the highlight visually links
                        # them.
                        rows_involved = [
                            row_positions[(k.zone, k.key_tag, k.role)]
                            for k in (gi_keys + gj_keys)
                            if (k.zone, k.key_tag, k.role) in row_positions
                        ]
                        if not rows_involved:
                            continue
                        y0 = min(r["bar_y"] for r in rows_involved) - 4
                        y1 = max(r["bar_y"] + r["bar_h"] for r in rows_involved) + 4
                        x0 = x_for(lo)
                        x1 = x_for(hi)
                        overlap_shapes.append((x0, y0, x1 - x0, y1 - y0))

    for x0, y0, w, h in overlap_shapes:
        parts.append(
            f'<rect class="algo-rollover" x="{x0:.1f}" y="{y0:.1f}" '
            f'width="{max(w, 1):.1f}" height="{h:.1f}" '
            f'fill="var(--accent)" fill-opacity="0.12" '
            f'stroke="var(--accent)" stroke-opacity="0.4" stroke-width="0.6" '
            f'stroke-dasharray="3 2">'
            f'<title>Algorithm rollover overlap</title></rect>'
        )

    # ----- axis ticks -----------------------------------------------------
    axis_y = margin_top - 6
    parts.append(
        f'<line x1="{margin_left}" y1="{axis_y}" x2="{margin_left + chart_w}" y2="{axis_y}" '
        f'stroke="currentColor" stroke-opacity="0.3" stroke-width="1"/>'
    )
    n_ticks = 8
    for i in range(n_ticks + 1):
        t = t_start + timedelta(seconds=span_sec * i / n_ticks)
        x = x_for(t)
        parts.append(
            f'<line x1="{x:.1f}" y1="{axis_y - 4}" x2="{x:.1f}" y2="{axis_y}" '
            f'stroke="currentColor" stroke-opacity="0.4"/>'
        )
        label = _fmt_tick(t, span_sec)
        parts.append(
            f'<text x="{x:.1f}" y="{axis_y - 8}" text-anchor="middle" '
            f'fill="currentColor" fill-opacity="0.7">{escape(label)}</text>'
        )

    # Faint vertical gridlines down the chart body.
    chart_top = margin_top
    chart_bot = total_height - margin_bot
    for i in range(n_ticks + 1):
        t = t_start + timedelta(seconds=span_sec * i / n_ticks)
        x = x_for(t)
        parts.append(
            f'<line x1="{x:.1f}" y1="{chart_top}" x2="{x:.1f}" y2="{chart_bot}" '
            f'stroke="currentColor" stroke-opacity="0.08"/>'
        )

    # ----- group separators + labels --------------------------------------
    for (role, algo), y0, y1, label_y in group_y_ranges:
        parts.append(
            f'<text x="{margin_left - 8}" y="{label_y}" text-anchor="end" '
            f'font-weight="600" fill="currentColor" fill-opacity="0.8">'
            f'{escape(role)} &middot; alg {algo}</text>'
        )
        parts.append(
            f'<line x1="{margin_left}" y1="{y0 + 8}" x2="{margin_left + chart_w}" y2="{y0 + 8}" '
            f'stroke="currentColor" stroke-opacity="0.12"/>'
        )

    # ----- per-key rows ---------------------------------------------------
    for (role, algo), gkeys in ordered_groups:
        for k in gkeys:
            pos = row_positions[(k.zone, k.key_tag, k.role)]
            bar_y = pos["bar_y"]
            bar_h = pos["bar_h"]
            row_top = pos["row_top"]

            # Per-key label on the left: the tag. The (role, alg) is
            # already in the group header above so we don't repeat it.
            parts.append(
                f'<text x="{margin_left - 8}" y="{bar_y + bar_h / 2 + 3:.1f}" '
                f'text-anchor="end" fill="currentColor" fill-opacity="0.85">'
                f'tag {int(k.key_tag)}</text>'
            )

            # Background track for the bar, so a key with no segments in
            # the window still visually occupies its row.
            parts.append(
                f'<rect x="{margin_left}" y="{bar_y}" width="{chart_w}" height="{bar_h}" '
                f'fill="var(--surface)" stroke="var(--border)" stroke-width="0.5" '
                f'fill-opacity="0.4"/>'
            )

            # Lookup overdue state for this key tag (if any). Only
            # "removed" segments get the lingering
            # treatment — earlier phases render as normal even if the
            # key will eventually end up overdue.
            overdue_state = None
            if overdue_by_tag is not None:
                overdue_state = overdue_by_tag.get(k.key_tag)

            segs = per_key_segments[(k.zone, k.key_tag, k.role)]

            # Minimum visible width for a phase segment. On a wide
            # chart (a year or more), a pre-published phase of a
            # few days projects to only 1-2 pixels and disappears
            # visually next to the months-long active bar — the user
            # reported seeing "one color bar for the whole
            # timeframe". Enforcing a small floor (6 px) and
            # shifting subsequent segments forward keeps every
            # transition visible without distorting the longest
            # phases meaningfully. The final segment is capped at
            # the chart's right edge so the overall timeline still
            # respects ``window_end``.
            min_phase_w = 6.0
            chart_right = margin_left + chart_w
            laid_out: list[tuple[float, float, str]] = []
            prev_x1: float | None = None
            for t0, t1, name in segs:
                x0_raw = x_for(t0)
                x1_raw = x_for(t1)
                x0 = x0_raw if prev_x1 is None else max(x0_raw, prev_x1)
                # Only pad positive-duration segments — zero-duration
                # phases stay zero so the time-axis maths upstream
                # still decide what's real.
                if x1_raw > x0_raw:
                    x1 = max(x1_raw, x0 + min_phase_w)
                else:
                    x1 = x1_raw
                # Clamp to the chart right edge; squeezing mostly
                # comes out of the longest (usually active) segment.
                x1 = min(x1, chart_right)
                x0 = min(x0, x1)
                laid_out.append((x0, x1, name))
                prev_x1 = x1

            # Iterate both the original (t0, t1) timestamps and the
            # laid-out (x0, x1) pixel bounds in lockstep — the rect
            # uses the visible-width-enforced pixels, the tooltip
            # text uses the true timestamps.
            for (t0, t1, name), (x0, x1, _n) in zip(segs, laid_out):
                w = max(1.0, x1 - x0)

                is_lingering = (
                    name == "removed"
                    and overdue_state is not None
                    and overdue_state.value != "none"
                )

                if is_lingering:
                    # Alarming bright red for keys that are past
                    # scheduled Delete but still visibly present at
                    # the zone or the parent. Higher opacity and a
                    # bold stroke so this reads from across the room.
                    fill = "#c43030"
                    extra_attrs = (
                        ' class="phase phase-removed phase-lingering"'
                        f' data-phase="removed"'
                        f' data-lingering="{overdue_state.value}"'
                    )
                    fill_opacity = "0.92"
                    stroke = "#7a1010"
                    stroke_width = "1.2"
                    phase_label = "OVERDUE: still published"
                    tip_tail = (
                        f"\nLINGERING: {overdue_state.value.replace('_', ' ')} "
                        f"— key should have been removed by "
                        f"{t0.strftime('%Y-%m-%d %H:%M')}"
                    )
                else:
                    fill = PHASE_FILL.get(name, "#c8c8c8")
                    extra_attrs = (
                        f' class="phase phase-{name}" data-phase="{name}"'
                    )
                    fill_opacity = "0.85"
                    stroke = "currentColor"
                    stroke_width = "0.4"
                    phase_label = PHASE_LABEL.get(name, name)
                    tip_tail = ""

                tip = (
                    f"{k.role} tag {k.key_tag} alg {k.algorithm} \u2014 {name}\n"
                    f"{PHASE_DESCRIPTION.get(name, '')}\n"
                    f"{t0.strftime('%Y-%m-%d %H:%M')} \u2192 "
                    f"{t1.strftime('%Y-%m-%d %H:%M')} UTC"
                    + tip_tail
                )
                parts.append(
                    f'<rect{extra_attrs} '
                    f'x="{x0:.1f}" y="{bar_y}" width="{w:.1f}" height="{bar_h}" '
                    f'fill="{fill}" fill-opacity="{fill_opacity}" '
                    f'stroke="{stroke}" stroke-opacity="0.9" '
                    f'stroke-width="{stroke_width}">'
                    f'<title>{escape(tip)}</title></rect>'
                )
                # Short inline label if the segment is wide enough.
                if w > 44:
                    weight_attr = ' font-weight="700"' if is_lingering else ""
                    label_fill = "#ffeaea" if is_lingering else "currentColor"
                    parts.append(
                        f'<text x="{x0 + 4:.1f}" y="{bar_y + bar_h - 8:.1f}" '
                        f'fill="{label_fill}" fill-opacity="0.95" font-size="9"'
                        f'{weight_attr}>{escape(phase_label)}</text>'
                    )

            # DS overlay stripe for KSK / CSK rows. The stripe always
            # occupies the strip above the bar even when no DS has
            # ever been observed — the empty strip is a readable
            # "the parent has not yet seen this KSK" signal.
            if pos["with_ds"]:
                stripe_y = bar_y - ds_stripe_gap - ds_stripe_h
                parts.append(
                    f'<rect class="ds-overlay-bg" data-ds="track" '
                    f'x="{margin_left}" y="{stripe_y}" width="{chart_w}" '
                    f'height="{ds_stripe_h}" fill="var(--muted)" fill-opacity="0.2" '
                    f'stroke="var(--border)" stroke-width="0.3"/>'
                )
                for a, b in per_key_ds[(k.zone, k.key_tag, k.role)]:
                    # Split each live DS range into sub-intervals:
                    # solid blue where only this KSK's DS is at the
                    # parent, and blue/white diagonal stripes where a
                    # second KSK's DS is *also* at the parent at the
                    # same time — the visible double-DS rollover
                    # overlap window.
                    for sa, sb, is_overlap in _split_ds_segment_by_overlap(
                        a, b, ds_overlap_spans,
                    ):
                        x0 = x_for(sa)
                        x1 = x_for(sb)
                        w = max(1.0, x1 - x0)
                        if is_overlap:
                            fill = "url(#ds-overlap-stripes)"
                            data_ds = "overlap"
                            tip = (
                                f"DS overlap with another KSK "
                                f"{sa.strftime('%Y-%m-%d %H:%M')} "
                                f"\u2192 {sb.strftime('%Y-%m-%d %H:%M')} UTC"
                            )
                        else:
                            fill = "var(--accent)"
                            data_ds = "live"
                            tip = (
                                f"DS observed at parent "
                                f"{a.strftime('%Y-%m-%d %H:%M')} "
                                f"\u2192 {b.strftime('%Y-%m-%d %H:%M')} UTC"
                            )
                        parts.append(
                            f'<rect class="ds-overlay" data-ds="{data_ds}" '
                            f'x="{x0:.1f}" y="{stripe_y}" width="{w:.1f}" '
                            f'height="{ds_stripe_h}" fill="{fill}" fill-opacity="0.85">'
                            f'<title>{escape(tip)}</title></rect>'
                        )
                # Tiny "DS" marker label at the left edge of the stripe.
                parts.append(
                    f'<text x="{margin_left - 8}" y="{stripe_y + ds_stripe_h:.1f}" '
                    f'text-anchor="end" font-size="8" '
                    f'fill="currentColor" fill-opacity="0.6">DS</text>'
                )

    # ----- today marker ---------------------------------------------------
    marker_dt = t_end if to_ts else today_dt
    if t_start <= marker_dt <= t_end:
        x = x_for(marker_dt)
        parts.append(
            f'<line class="now-marker" x1="{x:.1f}" y1="{chart_top}" '
            f'x2="{x:.1f}" y2="{chart_bot}" '
            f'stroke="var(--accent)" stroke-width="1.2" stroke-dasharray="4 3" '
            f'stroke-opacity="0.85"/>'
        )
        parts.append(
            f'<text x="{x:.1f}" y="{chart_top - 2:.1f}" text-anchor="middle" '
            f'fill="var(--accent)" font-size="10" font-weight="600">now</text>'
        )

    # ----- legend ---------------------------------------------------------
    legend_y = total_height - 14
    lx = margin_left
    legend_order = [
        "pre-published",
        "published",
        "active",
        "inactive",
        "removed",
    ]
    for name in legend_order:
        fill = PHASE_FILL[name]
        parts.append(
            f'<rect x="{lx}" y="{legend_y - 9}" width="12" height="10" '
            f'fill="{fill}" fill-opacity="0.85" '
            f'stroke="currentColor" stroke-opacity="0.4" stroke-width="0.3"/>'
        )
        label = PHASE_LABEL.get(name, name)
        parts.append(
            f'<text x="{lx + 16}" y="{legend_y}" fill="currentColor" fill-opacity="0.8">'
            f'{escape(label)}</text>'
        )
        lx += 130

    parts.append("</svg>")
    return "".join(parts)
