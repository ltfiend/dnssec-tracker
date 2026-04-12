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
    "pre-publication": "#c8c8c8",
    "published": "var(--rndc)",      # warm amber-ish in both palettes
    "active": "var(--state)",        # the "doing its job" green
    "retired": "var(--named)",       # muted orange
    "removed": "#9a9a9a",
}

PHASE_DESCRIPTION = {
    "pre-publication": "generated but not yet in the DNSKEY RRset",
    "published": "DNSKEY visible but not yet signing",
    "active": "signing DNSKEY / zone data",
    "retired": "not signing but still published for resolver caches",
    "removed": "fully gone from the zone",
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
    if snapshot and isinstance(snapshot.get("fields"), dict):
        fields = snapshot["fields"]

    gen = _parse_bind_ts(fields.get("Generated"))
    pub = _parse_bind_ts(fields.get("Published"))
    act = _parse_bind_ts(fields.get("Active"))
    ret = _parse_bind_ts(fields.get("Retired"))
    rem = _parse_bind_ts(fields.get("Removed"))

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

    # Enforce monotonicity — downstream maths assumes t_i <= t_{i+1}.
    # Any out-of-order timestamp clamps forward to the previous one.
    boundaries: list[tuple[str, datetime | None]] = [
        ("pre-publication", gen),
        ("published", pub),
        ("active", act),
        ("retired", ret),
        ("removed", rem),
    ]

    # Forward-fill: if "published" is missing but "active" exists, the
    # "pre-publication" phase runs straight to "active" and "published"
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
            # Last boundary:
            #   * "removed" is a terminal marker — no segment past it.
            #   * any other phase extends to window_end.
            if name == "removed":
                continue
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

            segs = per_key_segments[(k.zone, k.key_tag, k.role)]
            for t0, t1, name in segs:
                x0 = x_for(t0)
                x1 = x_for(t1)
                w = max(1.0, x1 - x0)
                fill = PHASE_FILL.get(name, "#c8c8c8")
                tip = (
                    f"{k.role} tag {k.key_tag} alg {k.algorithm} \u2014 {name}\n"
                    f"{PHASE_DESCRIPTION.get(name, '')}\n"
                    f"{t0.strftime('%Y-%m-%d %H:%M')} \u2192 {t1.strftime('%Y-%m-%d %H:%M')} UTC"
                )
                parts.append(
                    f'<rect class="phase phase-{name}" data-phase="{name}" '
                    f'x="{x0:.1f}" y="{bar_y}" width="{w:.1f}" height="{bar_h}" '
                    f'fill="{fill}" fill-opacity="0.85" '
                    f'stroke="currentColor" stroke-opacity="0.35" stroke-width="0.4">'
                    f'<title>{escape(tip)}</title></rect>'
                )
                # Short inline label if the segment is wide enough.
                if w > 44:
                    parts.append(
                        f'<text x="{x0 + 4:.1f}" y="{bar_y + bar_h - 8:.1f}" '
                        f'fill="currentColor" fill-opacity="0.9" font-size="9">'
                        f'{escape(name)}</text>'
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
                    x0 = x_for(a)
                    x1 = x_for(b)
                    w = max(1.0, x1 - x0)
                    parts.append(
                        f'<rect class="ds-overlay" data-ds="live" '
                        f'x="{x0:.1f}" y="{stripe_y}" width="{w:.1f}" '
                        f'height="{ds_stripe_h}" fill="var(--accent)" fill-opacity="0.85">'
                        f'<title>DS observed at parent {a.strftime("%Y-%m-%d %H:%M")} '
                        f'\u2192 {b.strftime("%Y-%m-%d %H:%M")} UTC</title></rect>'
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
    legend_order = ["pre-publication", "published", "active", "retired", "removed"]
    for name in legend_order:
        fill = PHASE_FILL[name]
        parts.append(
            f'<rect x="{lx}" y="{legend_y - 9}" width="12" height="10" '
            f'fill="{fill}" fill-opacity="0.85" '
            f'stroke="currentColor" stroke-opacity="0.4" stroke-width="0.3"/>'
        )
        parts.append(
            f'<text x="{lx + 16}" y="{legend_y}" fill="currentColor" fill-opacity="0.8">'
            f'{escape(name)}</text>'
        )
        lx += 110

    parts.append("</svg>")
    return "".join(parts)
