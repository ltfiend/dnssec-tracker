"""Chronological event-timeline chart (SVG).

A single horizontal axis covering the window, with every event drawn
as a coloured dot at its timestamp. Events whose pixel x-coordinates
land within ``cluster_px`` of each other collapse into a single
cluster circle — during a mass state transition (KRRSIGState +
DNSKEYState + DSState + GoalState all ticking in the same rndc poll)
this keeps the chart legible instead of stacking a dozen overlapping
dots. Sparse streams are unaffected: a singleton cluster renders
identically to a plain dot, with the same colour and inline label for
the major event types.

Clustering is layout-aware — it happens *after* timestamps are
projected onto the pixel axis — so "two events 200 ms apart on a
30-day-wide chart" collapse the same way "two events at the exact
same second on a one-hour chart" do, because both are visually
indistinguishable anyway.

Pure Python, no JS — safe for WeasyPrint and the live UI. Cluster
tooltips are plain SVG ``<title>`` children so WeasyPrint renders
them into the PDF export untouched.
"""

from __future__ import annotations

import math
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
    *,
    cluster_px: float = 6.0,
) -> str:
    """Return an inline SVG fragment for the event timeline.

    ``cluster_px`` is the pixel distance within which two events
    collapse into a single cluster circle. Default ~6 px — a bit
    wider than the singleton dot radius so mass-transition bursts
    merge cleanly without swallowing events that are actually
    spatially distinct.
    """

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

    # ---- Clustering --------------------------------------------------
    # Project every in-window event to an (x, event) pair, then walk
    # the sorted list grouping anything whose x is within cluster_px
    # of the current cluster's centroid. This is layout-aware: two
    # events 200 ms apart on a 30-day-wide chart collapse because they
    # project to the same pixel column, not because their timestamps
    # are equal.
    min_gap = 10.0
    base_radius = 4.5
    max_radius = 12.0

    projected: list[tuple[float, Event]] = []
    for e in evs:
        t = _parse_ts(e.ts)
        if t < t_start or t > t_end:
            continue
        projected.append((x_for(t), e))

    clusters: list[dict] = []
    for x, e in projected:
        if clusters and (x - clusters[-1]["x_last"]) <= cluster_px:
            c = clusters[-1]
            c["members"].append(e)
            c["x_sum"] += x
            c["x_last"] = x
            c["x"] = c["x_sum"] / len(c["members"])
        else:
            clusters.append({
                "x": x,
                "x_sum": x,
                "x_last": x,
                "members": [e],
            })

    # ---- Stacking ----------------------------------------------------
    # Clusters still de-overlap vertically against each other with the
    # alternating-bands logic the singleton renderer used. Only the
    # unit of layout changed (cluster instead of event).
    placed: list[tuple[float, float]] = []

    for c in clusters:
        x = c["x"]
        members = c["members"]
        count = len(members)

        y = axis_y
        offset = 0
        step = 12
        while True:
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

        # Radius scales with sqrt(count) so a 4-member cluster is
        # twice the area of a singleton, a 9-member one three times,
        # etc. Capped at max_radius so a 40-event burst doesn't eat
        # half the chart.
        radius = min(base_radius * math.sqrt(count), max_radius)

        # Colour: uniform-source cluster reuses the source's variable,
        # mixed-source clusters get the neutral --muted fill.
        sources = {m.source for m in members}
        if len(sources) == 1:
            colour = SOURCE_COLOR_VAR.get(next(iter(sources)), "var(--muted)")
        else:
            colour = "var(--muted)"

        # Tooltip: one line per member, "<HH:MM:SS> [src] type: summary".
        # For singleton clusters we keep the legacy "<ts> [src] type\n<summary>"
        # shape so the existing round-trip test keeps matching.
        if count == 1:
            m = members[0]
            tip = f"{m.ts} [{m.source}] {m.event_type}\n{m.summary}"
        else:
            tip = "\n".join(
                f"{_hhmmss(m.ts)} [{m.source}] {m.event_type}: {m.summary}"
                for m in members
            )

        # Stem line from axis to circle
        parts.append(
            f'<line x1="{x:.1f}" y1="{axis_y}" x2="{x:.1f}" y2="{y:.1f}" '
            f'stroke="{colour}" stroke-opacity="0.6" stroke-width="1"/>'
        )
        parts.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{radius:.2f}" '
            f'fill="{colour}" stroke="currentColor" stroke-opacity="0.3" stroke-width="0.6">'
            f'<title>{escape(tip)}</title></circle>'
        )

        if count > 1:
            # Count badge centred in the circle. currentColor with
            # reduced opacity reads on any palette (dark theme + the
            # light report stylesheet), no hard-coded colour needed.
            # dy of 0.33em approximates optical centring.
            parts.append(
                f'<text x="{x:.1f}" y="{y:.1f}" dy="0.33em" '
                f'text-anchor="middle" font-size="9" font-weight="600" '
                f'fill="currentColor" fill-opacity="0.85" '
                f'pointer-events="none">{count}</text>'
            )
        elif members[0].event_type in LABEL_WORTHY_TYPES:
            # Singletons get the same inline label they always did —
            # this branch is the "zero visual regression for sparse
            # streams" guarantee.
            label = _short_label(members[0])
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


def _hhmmss(ts: str) -> str:
    """Extract ``HH:MM:SS`` from an ISO timestamp for cluster tooltips.

    Falls back to the raw string if the shape is unexpected, so a
    badly-formed ``ts`` never crashes the renderer.
    """

    try:
        t = _parse_ts(ts)
        return t.strftime("%H:%M:%S")
    except Exception:  # noqa: BLE001
        return ts


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
