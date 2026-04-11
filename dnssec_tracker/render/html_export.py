"""Standalone HTML report export.

Renders the shared ``report.html`` Jinja template with all CSS and SVG
inlined so the resulting document is self-contained and survives being
emailed, archived, or served as a static file.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..config import Config
from ..db import Database
from ..models import Event, now_iso
from .calendar import render_calendar
from .event_timeline import render_event_timeline
from .timeline_svg import render_rndc_timeline, render_state_timeline


def _env() -> Environment:
    tmpl_dir = Path(__file__).parent.parent / "web" / "templates"
    return Environment(
        loader=FileSystemLoader(str(tmpl_dir)),
        autoescape=select_autoescape(["html"]),
    )


def _load_css() -> str:
    css_path = Path(__file__).parent.parent / "web" / "static" / "app.css"
    try:
        return css_path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _group_events_by_day(events: list[Event]) -> list[tuple[str, list[Event]]]:
    buckets: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        day = e.ts[:10] if len(e.ts) >= 10 else e.ts
        buckets[day].append(e)
    return [(day, sorted(buckets[day], key=lambda x: x.ts)) for day in sorted(buckets)]


def _build_report_context(
    db: Database,
    config: Config,
    zone: str,
    from_ts: str | None,
    to_ts: str | None,
) -> dict:
    z = db.get_zone(zone)
    if z is None:
        raise ValueError(f"unknown zone: {zone}")

    keys = db.list_keys(zone)
    events = list(
        reversed(
            db.query_events(
                zone=zone, from_ts=from_ts, to_ts=to_ts, limit=100_000
            )
        )
    )

    counts = {
        "state_changed": sum(1 for e in events if e.event_type == "state_changed"),
        "rndc_state_changed": sum(1 for e in events if e.event_type == "rndc_state_changed"),
        "dns_events": sum(1 for e in events if e.source == "dns"),
        "iodyn_events": sum(1 for e in events if e.source == "syslog" and e.event_type.startswith("iodyn_")),
    }

    timeline_svg = render_state_timeline(events, keys)
    rndc_svg = render_rndc_timeline(events, keys)
    calendar_html = render_calendar(events, from_ts, to_ts)
    event_timeline_svg = render_event_timeline(events, from_ts, to_ts)

    dns_observations = [e for e in events if e.source == "dns"]

    state_snapshots: dict[str, str] = {}
    for k in keys:
        snap = db.get_snapshot("state_file", f"{zone}#{k.key_tag}#{k.role}")
        if snap:
            fields = snap.get("fields", {})
            rendered = "\n".join(f"{k}: {v}" for k, v in sorted(fields.items()))
            state_snapshots[f"{k.role} tag={k.key_tag}"] = rendered

    summary_bits = []
    if counts["state_changed"]:
        summary_bits.append(f"{counts['state_changed']} on-disk state transition(s)")
    if counts["rndc_state_changed"]:
        summary_bits.append(f"{counts['rndc_state_changed']} rndc-reported state change(s)")
    if counts["iodyn_events"]:
        summary_bits.append(f"{counts['iodyn_events']} iodyn-dnssec action(s)")
    if counts["dns_events"]:
        summary_bits.append(f"{counts['dns_events']} DNS observation(s)")
    executive_summary = (
        "During the reported window " + ", ".join(summary_bits) + "."
        if summary_bits
        else "No significant activity was recorded during the reported window."
    )

    return {
        "zone": z,
        "keys": keys,
        "events": events,
        "events_by_day": _group_events_by_day(events),
        "counts": counts,
        "timeline_svg": timeline_svg,
        "rndc_svg": rndc_svg,
        "calendar_html": calendar_html,
        "event_timeline_svg": event_timeline_svg,
        "dns_observations": dns_observations,
        "state_snapshots": state_snapshots,
        "window_start": from_ts,
        "window_end": to_ts,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "policy_snapshot": "",  # filled in later if we can read named.conf
        "executive_summary": executive_summary,
        "css": _load_css(),
    }


def render_report_html(
    db: Database,
    config: Config,
    zone: str,
    from_ts: str | None = None,
    to_ts: str | None = None,
) -> str:
    ctx = _build_report_context(db, config, zone, from_ts, to_ts)
    env = _env()
    tmpl = env.get_template("report.html")
    return tmpl.render(**ctx)
