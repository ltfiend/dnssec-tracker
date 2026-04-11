"""Chronological event-timeline chart (SVG).

A single horizontal axis covering the window, with every event drawn
as a coloured dot at its timestamp. Dots are de-overlapped by stacking
them vertically when timestamps collide within the minimum pixel
resolution. A handful of the most significant events are labelled
inline; the rest stay discoverable via the ``<title>`` tooltip.

Pure Python, no JS — safe for WeasyPrint and the live UI.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from html import escape

from ..models import Event


SOURCE_COLOR_VAR = {
    "state": "var(--state)",
    "key": "var(--key)",
    "syslog": "var(--syslog)",
    "dns": "var(--dns)",
    "named": "var(--named)",
    "rndc": "var(--rndc)",
}

# Event types that deserve an inline label (the "major milestones")
LABEL_WORTHY_TYPES = {
    "state_changed",
    "rndc_state_changed",
    "state_key_observed",
    "iodyn_key_created",
    "iodyn_ds_action",
    "iodyn_rndc_reload",
    "named_dnskey_published",
    "named_dnskey_active",
    "named_dnskey_retired",
    "dns_ds_appeared_at_parent",
    "dns_ds_disappeared_at_parent",
    "dns_dnskey_appeared_at_zone",
}


def _parse_ts(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


def render_event_timeline(
    events: list[Event],
    from_ts: str | None = None,
    to_ts: str | None = None,
) -> str:
    """Return an inline SVG fragment for the event timeline."""

    if not events:
        return _empty("No events in the reported window.")

    evs = sorted(events, key=lambda e: e.ts)

    t_start = _parse_ts(from_ts) if from_ts else _parse_ts(evs[0].ts)
    t_end = _parse_ts(to_ts) if to_ts else _parse_ts(evs[-1].ts)
    if t_end <= t_start:
        t_end = t_start + timedelta(minutes=1)
    span_sec = (t_end - t_start).total_seconds()

    # Layout
    margin_left = 60
    margin_right = 40
    margin_top = 40
    margin_bot = 70
    width = 920
    axis_y = 180
    chart_w = width - margin_left - margin_right
    chart_h = 260
    height = chart_h + margin_top + margin_bot

    def x_for(ts: datetime) -> float:
        return margin_left + ((ts - t_start).total_seconds() / span_sec) * chart_w

    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'font-family="sans-serif" font-size="11" class="event-timeline">'
    ]

    # Title
    parts.append(
        f'<text x="{margin_left}" y="20" font-weight="600" fill="currentColor">'
        f'{escape(t_start.isoformat())} &#x2192; {escape(t_end.isoformat())}</text>'
    )

    # Axis line
    parts.append(
        f'<line x1="{margin_left}" y1="{axis_y}" x2="{margin_left + chart_w}" y2="{axis_y}" '
        f'stroke="currentColor" stroke-opacity="0.4" stroke-width="1.5"/>'
    )

    # Axis ticks — pick ~8 evenly spaced timestamps
    n_ticks = 8
    for i in range(n_ticks + 1):
        t = t_start + timedelta(seconds=span_sec * i / n_ticks)
        x = x_for(t)
        parts.append(
            f'<line x1="{x:.1f}" y1="{axis_y - 5}" x2="{x:.1f}" y2="{axis_y + 5}" '
            f'stroke="currentColor" stroke-opacity="0.5"/>'
        )
        label = _fmt_tick(t, span_sec)
        parts.append(
            f'<text x="{x:.1f}" y="{axis_y + 20}" text-anchor="middle" '
            f'fill="currentColor" fill-opacity="0.7">{escape(label)}</text>'
        )

    # Place events. Collision detection: if a dot would land within
    # ``min_gap`` pixels of another dot at the same Y, stack vertically.
    min_gap = 10.0
    dot_radius = 4.5

    # Track placed (x, y) per "band" to de-overlap.
    placed: list[tuple[float, float]] = []

    for e in evs:
        t = _parse_ts(e.ts)
        if t < t_start or t > t_end:
            continue
        x = x_for(t)
        # Find the lowest y offset that doesn't collide.
        y = axis_y
        offset = 0
        step = 12
        while True:
            # Alternate above/below the axis
            candidate = axis_y + (offset // 2 + 1) * step * (-1 if offset % 2 == 0 else 1)
            if offset == 0:
                candidate = axis_y - step  # first stack always above
            if not any(abs(px - x) < min_gap and abs(py - candidate) < step - 1 for px, py in placed):
                y = candidate
                break
            offset += 1
            if offset > 40:  # pathological cluster — stop stacking
                y = candidate
                break

        placed.append((x, y))
        colour = SOURCE_COLOR_VAR.get(e.source, "var(--muted)")
        tip = f"{e.ts} [{e.source}] {e.event_type}\n{e.summary}"
        # Stem line from axis to dot
        parts.append(
            f'<line x1="{x:.1f}" y1="{axis_y}" x2="{x:.1f}" y2="{y:.1f}" '
            f'stroke="{colour}" stroke-opacity="0.6" stroke-width="1"/>'
        )
        parts.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{dot_radius}" '
            f'fill="{colour}" stroke="currentColor" stroke-opacity="0.3" stroke-width="0.6">'
            f'<title>{escape(tip)}</title></circle>'
        )
        if e.event_type in LABEL_WORTHY_TYPES:
            label = _short_label(e)
            # anchor flips based on whether the dot is above or below the axis
            above = y < axis_y
            label_y = y - 8 if above else y + 16
            parts.append(
                f'<text x="{x:.1f}" y="{label_y:.1f}" text-anchor="middle" '
                f'fill="currentColor" fill-opacity="0.85" font-size="9.5">'
                f'{escape(label)}</text>'
            )

    # Legend — only show sources that actually appear in this slice
    # of events so the split DNS / File timelines don't carry
    # irrelevant legend entries.
    present_sources = {e.source for e in evs}
    legend_y = height - 20
    lx = margin_left
    for src, colour in SOURCE_COLOR_VAR.items():
        if src not in present_sources:
            continue
        parts.append(
            f'<circle cx="{lx + 4}" cy="{legend_y - 3}" r="4" fill="{colour}"/>'
        )
        parts.append(
            f'<text x="{lx + 12}" y="{legend_y}" fill="currentColor" fill-opacity="0.75">'
            f'{escape(src)}</text>'
        )
        lx += 95

    parts.append("</svg>")
    return "".join(parts)


def _fmt_tick(t: datetime, span_sec: float) -> str:
    # Pick granularity based on the window width.
    if span_sec <= 2 * 3600:
        return t.strftime("%H:%M")
    if span_sec <= 2 * 86400:
        return t.strftime("%m-%d %H:%M")
    if span_sec <= 60 * 86400:
        return t.strftime("%Y-%m-%d")
    return t.strftime("%Y-%m")


def _short_label(e: Event) -> str:
    """Compress an event summary to fit inline on the timeline."""
    bits: list[str] = []
    if e.key_role and e.key_tag:
        bits.append(f"{e.key_role}{e.key_tag}")
    field = e.detail.get("field") if e.detail else None
    new = e.detail.get("new") if e.detail else None
    if field and new:
        bits.append(f"{field}={new}")
    elif e.event_type.startswith("iodyn_"):
        bits.append(e.event_type[len("iodyn_"):])
    elif e.event_type.startswith("named_"):
        bits.append(e.event_type[len("named_"):])
    elif e.event_type.startswith("dns_"):
        bits.append(e.event_type[len("dns_"):])
    else:
        bits.append(e.event_type)
    label = " ".join(bits)
    if len(label) > 30:
        label = label[:27] + "..."
    return label


def _empty(message: str) -> str:
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 60" '
        'font-family="sans-serif" font-size="12">'
        f'<text x="10" y="30" fill="currentColor" fill-opacity="0.6">{escape(message)}</text>'
        "</svg>"
    )
