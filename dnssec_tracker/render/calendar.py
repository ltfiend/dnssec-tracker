"""Monthly calendar renderer.

Given a list of events and a time window, produce one HTML table per
month covering the window. Each day cell is colour-coded by the set of
event sources seen that day (state / rndc / dns / syslog / named /
key). A ``title`` attribute carries a short summary of the events for
hover inspection in the live UI.

Pure Python, no JS, no external libraries. Works in WeasyPrint so the
PDF report can render the exact same calendars.
"""

from __future__ import annotations

import calendar
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from html import escape
from typing import Iterable

from ..models import Event


SOURCE_ORDER = ("state", "rndc", "dns", "key", "syslog", "named")
# Human-readable labels for tooltip grouping.
SOURCE_LABEL = {
    "state": "on-disk state",
    "rndc": "rndc dnssec -status",
    "dns": "DNS probe",
    "key": "K*.key timing",
    "syslog": "iodyn / syslog",
    "named": "named.log",
}


def _parse_ts(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


def _iter_months(first: date, last: date) -> Iterable[tuple[int, int]]:
    y, m = first.year, first.month
    while (y, m) <= (last.year, last.month):
        yield y, m
        m += 1
        if m == 13:
            m = 1
            y += 1


def _window(events: list[Event], from_ts: str | None, to_ts: str | None) -> tuple[date, date]:
    """Resolve the calendar window.

    Explicit ``from``/``to`` take precedence; otherwise we bracket the
    events themselves. An empty window degrades gracefully to the
    current month.
    """

    if from_ts:
        start = _parse_ts(from_ts).date()
    elif events:
        start = min(_parse_ts(e.ts).date() for e in events)
    else:
        start = date.today().replace(day=1)

    if to_ts:
        end = _parse_ts(to_ts).date()
    elif events:
        end = max(_parse_ts(e.ts).date() for e in events)
    else:
        end = date.today()

    if end < start:
        end = start
    return start, end


def render_calendar(
    events: list[Event],
    from_ts: str | None = None,
    to_ts: str | None = None,
    *,
    today: date | None = None,
) -> str:
    """Return an HTML fragment of monthly calendar tables.

    Cells are classified by:

    * ``has-events`` — any event present
    * ``src-<source>`` for every source that fired on the date
    * ``count-<bucket>`` (1, 2-5, 6-20, 20+) for density shading

    The report's inlined stylesheet styles every combination.
    """

    start, end = _window(events, from_ts, to_ts)
    today = today or date.today()

    by_day: dict[date, list[Event]] = defaultdict(list)
    for e in events:
        d = _parse_ts(e.ts).date()
        if start <= d <= end:
            by_day[d].append(e)

    parts: list[str] = ['<div class="calendar-view">']
    parts.append(_legend())

    for year, month in _iter_months(start, end):
        parts.append(_render_month(year, month, by_day, start, end, today))

    parts.append("</div>")
    return "".join(parts)


def _legend() -> str:
    items = []
    for src in SOURCE_ORDER:
        items.append(
            f'<span class="cal-legend-item"><span class="cal-dot src-{src}"></span>'
            f'{escape(SOURCE_LABEL[src])}</span>'
        )
    items.append(
        '<span class="cal-legend-item"><span class="cal-dot cal-today-dot"></span>today</span>'
    )
    return '<div class="cal-legend">' + "".join(items) + "</div>"


def _render_month(
    year: int,
    month: int,
    by_day: dict[date, list[Event]],
    window_start: date,
    window_end: date,
    today: date,
) -> str:
    cal = calendar.Calendar(firstweekday=0)  # Monday = 0
    weeks = cal.monthdatescalendar(year, month)
    month_name = calendar.month_name[month]

    rows: list[str] = []
    for week in weeks:
        cells: list[str] = []
        for d in week:
            in_month = d.month == month
            in_window = window_start <= d <= window_end
            day_events = by_day.get(d, []) if in_window else []

            classes = ["cal-cell"]
            if not in_month:
                classes.append("cal-out")
            if in_window:
                classes.append("cal-in")
            if d == today:
                classes.append("cal-today")
            if day_events:
                classes.append("has-events")
                classes.append(_density_class(len(day_events)))

            sources_present = {e.source for e in day_events}
            dots = "".join(
                f'<span class="cal-dot src-{src}"></span>'
                for src in SOURCE_ORDER
                if src in sources_present
            )

            title = _tooltip(d, day_events)
            cells.append(
                f'<td class="{" ".join(classes)}" title="{escape(title)}">'
                f'<span class="cal-day">{d.day}</span>'
                f'<span class="cal-dots">{dots}</span>'
                f"</td>"
            )
        rows.append("<tr>" + "".join(cells) + "</tr>")

    header_days = "".join(
        f"<th>{calendar.day_abbr[i]}</th>" for i in range(7)
    )

    return (
        '<table class="cal-month">'
        f'<caption>{month_name} {year}</caption>'
        f"<thead><tr>{header_days}</tr></thead>"
        f'<tbody>{"".join(rows)}</tbody>'
        "</table>"
    )


def _density_class(count: int) -> str:
    if count >= 20:
        return "count-xl"
    if count >= 6:
        return "count-l"
    if count >= 2:
        return "count-m"
    return "count-s"


def _tooltip(d: date, events: list[Event]) -> str:
    if not events:
        return d.isoformat()
    lines: list[str] = [d.isoformat(), f"{len(events)} event(s)"]
    counts: dict[str, int] = defaultdict(int)
    for e in events:
        counts[e.source] += 1
    for src in SOURCE_ORDER:
        if src in counts:
            lines.append(f"  {SOURCE_LABEL[src]}: {counts[src]}")
    # Up to 5 sample summaries
    sample = events[:5]
    lines.append("")
    for e in sample:
        lines.append(f"- {e.summary[:90]}")
    if len(events) > 5:
        lines.append(f"... and {len(events) - 5} more")
    return "\n".join(lines)
