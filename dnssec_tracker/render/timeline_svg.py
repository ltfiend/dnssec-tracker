"""Server-rendered state-machine timeline as inline SVG.

One swim lane per (key, state field). Each lane is a horizontal bar
divided into coloured segments for every value the field held during
the window. This is intentionally done in pure Python so the output
works inside WeasyPrint (no JS) *and* in the live web UI.
"""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape

from ..models import Event, Key


STATE_COLORS = {
    "hidden": "#c8c8c8",
    "rumoured": "#f0c14b",
    "omnipresent": "#3e885b",
    "unretentive": "#b94a4a",
    "N/A": "#eeeeee",
}

STATE_FIELDS = ("GoalState", "DNSKEYState", "KRRSIGState", "ZRRSIGState", "DSState")


def _parse_ts(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


def _colour_for(value: str) -> str:
    v = (value or "").strip().lower()
    for k, c in STATE_COLORS.items():
        if k in v:
            return c
    return "#b0c4de"


def render_state_timeline(events: list[Event], keys: list[Key]) -> str:
    """Render a timeline SVG for the given events + keys.

    Events are expected to be in any order; this function sorts them.
    Only ``state_changed`` events (from the ``state`` source) are used
    for the lanes.
    """

    if not events or not keys:
        return ""

    state_events = [
        e for e in events
        if e.source == "state" and e.event_type == "state_changed" and e.detail.get("field") in STATE_FIELDS
    ]
    if not state_events:
        return _empty_svg("No state transitions recorded in this window.")

    state_events.sort(key=lambda e: e.ts)
    t_start = _parse_ts(state_events[0].ts)
    t_end = _parse_ts(state_events[-1].ts)
    if t_end <= t_start:
        t_end = t_start.replace(minute=t_start.minute + 1)

    span = (t_end - t_start).total_seconds() or 1.0

    # Build lanes: one per (key, field) combo that actually has events.
    lanes: dict[tuple[int, str, str], list[tuple[float, float, str]]] = {}

    per_key_field: dict[tuple[int, str, str], list[Event]] = {}
    for e in state_events:
        if e.key_tag is None:
            continue
        key = (e.key_tag, e.key_role or "", e.detail.get("field", ""))
        per_key_field.setdefault(key, []).append(e)

    for lane_key, lane_events in per_key_field.items():
        segs: list[tuple[float, float, str]] = []
        for i, ev in enumerate(lane_events):
            t0 = (_parse_ts(ev.ts) - t_start).total_seconds() / span
            t1 = 1.0
            if i + 1 < len(lane_events):
                t1 = (_parse_ts(lane_events[i + 1].ts) - t_start).total_seconds() / span
            segs.append((t0, t1, ev.detail.get("new", "")))
        lanes[lane_key] = segs

    # Layout constants
    margin_left = 200
    margin_top = 30
    lane_h = 22
    lane_gap = 6
    content_w = 700
    width = margin_left + content_w + 20
    height = margin_top + (lane_h + lane_gap) * len(lanes) + 40

    parts: list[str] = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'font-family="sans-serif" font-size="11">'
    )
    parts.append(
        f'<text x="{margin_left}" y="18" font-weight="600">'
        f'{escape(t_start.isoformat())} &#x2192; {escape(t_end.isoformat())}</text>'
    )

    y = margin_top
    for (tag, role, field_name), segs in sorted(lanes.items()):
        label = f"{role} {tag} · {field_name}"
        parts.append(
            f'<text x="{margin_left - 8}" y="{y + lane_h - 6}" text-anchor="end">{escape(label)}</text>'
        )
        parts.append(
            f'<rect x="{margin_left}" y="{y}" width="{content_w}" height="{lane_h}" '
            f'fill="#f5f5f7" stroke="#dcdde3"/>'
        )
        for t0, t1, value in segs:
            seg_x = margin_left + t0 * content_w
            seg_w = max(1.0, (t1 - t0) * content_w)
            colour = _colour_for(value)
            parts.append(
                f'<rect x="{seg_x:.1f}" y="{y}" width="{seg_w:.1f}" height="{lane_h}" '
                f'fill="{colour}" stroke="#555" stroke-width="0.3"><title>{escape(value)}</title></rect>'
            )
            if seg_w > 40:
                parts.append(
                    f'<text x="{seg_x + 4:.1f}" y="{y + lane_h - 6}" fill="#222">{escape(value)}</text>'
                )
        y += lane_h + lane_gap

    # Legend
    legend_y = y + 12
    lx = margin_left
    for name, colour in STATE_COLORS.items():
        parts.append(
            f'<rect x="{lx}" y="{legend_y}" width="14" height="10" fill="{colour}" stroke="#555"/>'
        )
        parts.append(f'<text x="{lx + 18}" y="{legend_y + 9}">{escape(name)}</text>')
        lx += 120

    parts.append("</svg>")
    return "".join(parts)


def render_rndc_timeline(events: list[Event], keys: list[Key]) -> str:
    """Same lane layout but sourced from ``rndc`` events."""
    rndc_events = [
        e for e in events
        if e.source == "rndc" and e.event_type == "rndc_state_changed"
    ]
    if not rndc_events:
        return _empty_svg("No rndc state transitions recorded in this window.")

    # Reuse the state-timeline renderer by relabelling event fields.
    shimmed: list[Event] = []
    for e in rndc_events:
        shim = Event(
            id=e.id,
            ts=e.ts,
            source="state",
            zone=e.zone,
            key_tag=e.key_tag,
            key_role=e.key_role,
            event_type="state_changed",
            summary=e.summary,
            detail={
                "field": {
                    "goal": "GoalState",
                    "dnskey": "DNSKEYState",
                    "ds": "DSState",
                    "zone_rrsig": "ZRRSIGState",
                    "key_rrsig": "KRRSIGState",
                }.get(e.detail.get("field", ""), e.detail.get("field", "")),
                "new": e.detail.get("new", ""),
            },
        )
        shimmed.append(shim)
    return render_state_timeline(shimmed, keys)


def _empty_svg(message: str) -> str:
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 60" '
        'font-family="sans-serif" font-size="12">'
        f'<text x="10" y="30" fill="#6a707b">{escape(message)}</text>'
        "</svg>"
    )
