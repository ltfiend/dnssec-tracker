"""Chronological event-timeline chart — horizontal swim lanes per
source.

Layout: one dedicated horizontal lane per source present in the
given event list, each plotted at its own y position. A shared
time axis runs along the bottom. Events in a lane cluster when
their pixel x-coordinates land within ``cluster_px`` of each other
so mass-transition bursts (a KSK rollover ticking a half-dozen
state fields in the same rndc poll) stay legible.

Per-event inline labels are gone: the lane's left-edge label
already identifies the category, and per-event detail lives in a
hover tooltip. Each cluster ``<g class="evt-cluster">`` carries
a ``data-tip`` attribute with pre-escaped HTML that the page-level
JavaScript tooltip hook in ``layout.html`` injects into a themed
floating ``<div>``. We deliberately do *not* emit an SVG
``<title>`` child: browsers render it as a second, small native
tooltip that overlaps the styled one.

Milestone events (key creation, DS transitions at the parent,
operator-issued checkds commands, file deletion) gain a small
vertical flag above their dot — visual emphasis without text.

Pure Python, no external dependencies. Safe for WeasyPrint.
"""

from __future__ import annotations

import math
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from html import escape

from ..models import Event


# Colour per source. Matches the dots used elsewhere (calendar,
# event-log row tints) so the visual vocabulary is consistent.
SOURCE_COLOR_VAR = {
    "state": "var(--state)",
    "key": "var(--key)",
    "syslog": "var(--syslog)",
    "dns": "var(--dns)",
    "named": "var(--named)",
    "rndc": "var(--rndc)",
}

# Canonical lane order, top to bottom. File-side sources grouped
# first, then BIND's own views, then free-form textual sources.
# Absent sources are skipped — lanes with zero events are not
# rendered so vertical space grows only with real signal.
SOURCE_ORDER = ["state", "key", "rndc", "dns", "syslog", "named"]

# Operationally-interesting events that get a small vertical flag
# above their dot. Chosen to highlight transitions an operator
# would care about at a glance without adding text to the chart.
MILESTONE_TYPES = {
    "state_key_observed",
    "state_key_file_deleted",
    "iodyn_key_created",
    "iodyn_ds_action",
    "iodyn_rndc_reload",
    "named_manual_checkds",
    "named_dnskey_published",
    "named_dnskey_active",
    "named_dnskey_retired",
    "dns_ds_appeared_at_parent",
    "dns_ds_disappeared_at_parent",
    "dns_dnskey_appeared_at_zone",
    "dns_dnskey_disappeared_at_zone",
}


def _parse_ts(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


def _hhmmss(ts: str) -> str:
    """Extract ``HH:MM:SS`` from an ISO timestamp for compact
    tooltip lines."""
    try:
        return _parse_ts(ts).strftime("%H:%M:%S")
    except Exception:  # noqa: BLE001
        return ts


def _yyyymmdd_hhmmss(ts: str) -> str:
    try:
        return _parse_ts(ts).strftime("%Y-%m-%d %H:%M:%S")
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


def _empty(message: str) -> str:
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 60" '
        'font-family="sans-serif" font-size="12" class="event-timeline">'
        f'<text x="10" y="30" fill="currentColor" fill-opacity="0.6">'
        f'{escape(message)}</text>'
        "</svg>"
    )


def _build_data_tip(members: list[Event]) -> str:
    """Build the pre-escaped HTML for the JS floating tooltip.

    The live-UI JS reads this string off the cluster <g>'s
    ``data-tip`` attribute and injects it via ``innerHTML``, so
    every field value is HTML-escaped here. Line structure per
    member: a bold timestamp + source/type header line, then the
    event summary below. Members separated by an <hr>.
    """

    lines: list[str] = []
    for i, m in enumerate(members):
        if i > 0:
            lines.append("<hr>")
        lines.append(
            f"<strong>{escape(_yyyymmdd_hhmmss(m.ts))}</strong> "
            f"[{escape(m.source)}] {escape(m.event_type)}"
        )
        if m.summary:
            lines.append(escape(m.summary))
    return "<br>".join(lines)


def _cluster_members(
    lane_events: list[Event],
    x_for,
    t_start: datetime,
    t_end: datetime,
    cluster_px: float,
) -> list[dict]:
    """Project every event to its pixel column and group adjacent
    events whose columns are within ``cluster_px`` into a single
    cluster dict. Returns ``[{"x": cx, "members": [Event, ...]}]``.
    """

    projected: list[tuple[float, Event]] = []
    for e in lane_events:
        t = _parse_ts(e.ts)
        if t < t_start or t > t_end:
            continue
        projected.append((x_for(t), e))
    projected.sort(key=lambda pair: pair[0])

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
    return clusters


def render_event_timeline(
    events: list[Event],
    from_ts: str | None = None,
    to_ts: str | None = None,
    *,
    cluster_px: float = 6.0,
) -> str:
    """Return an inline SVG fragment for the event timeline.

    One horizontal swim lane per event source actually present in
    ``events``. Lanes are drawn in the canonical order defined by
    :data:`SOURCE_ORDER`; empty sources are omitted.
    """

    if not events:
        return _empty("No events in the reported window.")

    evs = sorted(events, key=lambda e: e.ts)
    t_start = _parse_ts(from_ts) if from_ts else _parse_ts(evs[0].ts)
    t_end = _parse_ts(to_ts) if to_ts else _parse_ts(evs[-1].ts)
    if t_end <= t_start:
        t_end = t_start + timedelta(minutes=1)
    span_sec = (t_end - t_start).total_seconds()

    # Group events by source, filtered to the window.
    by_source: dict[str, list[Event]] = defaultdict(list)
    for e in evs:
        t = _parse_ts(e.ts)
        if t < t_start or t > t_end:
            continue
        by_source[e.source].append(e)
    # Lanes to draw: those in the canonical order that actually
    # have events. Anything unrecognised in the source field goes
    # at the end under a generic lane so we never silently drop
    # data.
    active_lanes: list[str] = [s for s in SOURCE_ORDER if by_source.get(s)]
    leftover = sorted(s for s in by_source if s not in SOURCE_ORDER)
    active_lanes.extend(leftover)

    if not active_lanes:
        return _empty("No events in the reported window.")

    # Layout.
    width = 920
    margin_left = 80     # lane-label column
    margin_right = 20
    margin_top = 40      # title strip
    margin_bot = 44      # axis + tick labels + padding
    lane_h = 32
    chart_w = width - margin_left - margin_right
    total_height = margin_top + len(active_lanes) * lane_h + margin_bot

    def x_for(t: datetime) -> float:
        return margin_left + (
            (t - t_start).total_seconds() / span_sec
        ) * chart_w

    parts: list[str] = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {width} {total_height}" '
        f'font-family="sans-serif" font-size="11" class="event-timeline">'
    )

    # Title strip: time-range label at the top-right, out of the way
    # of the lane labels on the left.
    parts.append(
        f'<text class="evt-title" x="{margin_left}" y="22" '
        f'font-weight="600" fill="currentColor">'
        f'{escape(t_start.strftime("%Y-%m-%d %H:%M"))} &#x2192; '
        f'{escape(t_end.strftime("%Y-%m-%d %H:%M"))} UTC</text>'
    )

    # Lane chrome: label on the left, faint top gridline per lane.
    for i, source in enumerate(active_lanes):
        lane_top = margin_top + i * lane_h
        lane_mid = lane_top + lane_h / 2
        # Lane label.
        parts.append(
            f'<text class="evt-lane-label" '
            f'x="{margin_left - 8}" y="{lane_mid:.1f}" '
            f'text-anchor="end" dominant-baseline="middle" '
            f'fill="currentColor" fill-opacity="0.7">'
            f'{escape(source)}</text>'
        )
        # Faint horizontal rule between lanes.
        parts.append(
            f'<line class="evt-lane-line" '
            f'x1="{margin_left}" y1="{lane_top:.1f}" '
            f'x2="{margin_left + chart_w}" y2="{lane_top:.1f}" '
            f'stroke="currentColor" stroke-opacity="0.08" stroke-width="1"/>'
        )
    # Bottom border of the last lane (also where the axis sits).
    axis_y = margin_top + len(active_lanes) * lane_h
    parts.append(
        f'<line class="evt-lane-line" '
        f'x1="{margin_left}" y1="{axis_y:.1f}" '
        f'x2="{margin_left + chart_w}" y2="{axis_y:.1f}" '
        f'stroke="currentColor" stroke-opacity="0.3" stroke-width="1"/>'
    )

    # X-axis ticks + labels along the bottom.
    n_ticks = 8
    for i in range(n_ticks + 1):
        t = t_start + timedelta(seconds=span_sec * i / n_ticks)
        x = x_for(t)
        parts.append(
            f'<line x1="{x:.1f}" y1="{axis_y:.1f}" '
            f'x2="{x:.1f}" y2="{axis_y + 4:.1f}" '
            f'stroke="currentColor" stroke-opacity="0.5"/>'
        )
        label = _fmt_tick(t, span_sec)
        parts.append(
            f'<text x="{x:.1f}" y="{axis_y + 18:.1f}" text-anchor="middle" '
            f'fill="currentColor" fill-opacity="0.7">{escape(label)}</text>'
        )

    # Dot sizing.
    base_radius = 5.0
    max_radius = 11.0

    # Render each lane's clusters.
    for i, source in enumerate(active_lanes):
        lane_top = margin_top + i * lane_h
        lane_mid = lane_top + lane_h / 2
        colour = SOURCE_COLOR_VAR.get(source, "var(--muted)")

        clusters = _cluster_members(
            by_source[source], x_for, t_start, t_end, cluster_px,
        )
        for c in clusters:
            x = c["x"]
            members = c["members"]
            count = len(members)
            radius = min(base_radius * math.sqrt(count), max_radius)

            has_milestone = any(
                m.event_type in MILESTONE_TYPES for m in members
            )

            tip_html = _build_data_tip(members)

            parts.append(
                f'<g class="evt-cluster" data-source="{escape(source)}" '
                f'data-tip="{escape(tip_html, quote=True)}">'
            )
            # Milestone flag: a short vertical tick above the dot
            # into the lane's upper half, plus a tiny filled
            # triangle tip. Drawn before the circle so the circle
            # sits on top of the flag at the dot position.
            if has_milestone:
                flag_top = lane_top + 2
                parts.append(
                    f'<line class="evt-milestone-flag" '
                    f'x1="{x:.1f}" y1="{flag_top:.1f}" '
                    f'x2="{x:.1f}" y2="{lane_mid:.1f}" '
                    f'stroke="{colour}" stroke-width="1.2" '
                    f'stroke-opacity="0.85"/>'
                )
                parts.append(
                    f'<circle class="evt-milestone-cap" '
                    f'cx="{x:.1f}" cy="{flag_top:.1f}" r="2" '
                    f'fill="{colour}" fill-opacity="0.9"/>'
                )
            parts.append(
                f'<circle cx="{x:.1f}" cy="{lane_mid:.1f}" r="{radius:.2f}" '
                f'fill="{colour}" fill-opacity="0.88" '
                f'stroke="currentColor" stroke-opacity="0.35" stroke-width="0.6"/>'
            )
            if count > 1:
                parts.append(
                    f'<text class="evt-count-badge" '
                    f'x="{x:.1f}" y="{lane_mid:.1f}" dy="0.33em" '
                    f'text-anchor="middle" font-size="9" font-weight="600" '
                    f'fill="currentColor" fill-opacity="0.92" '
                    f'pointer-events="none">{count}</text>'
                )
            parts.append('</g>')

    parts.append("</svg>")
    return "".join(parts)
