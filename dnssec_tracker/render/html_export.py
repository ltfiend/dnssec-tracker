"""Standalone HTML report export.

Renders the shared ``report.html`` Jinja template with all CSS and SVG
inlined so the resulting document is self-contained and survives being
emailed, archived, or served as a static file.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from ..config import Config
from ..db import Database
from ..models import Event, now_iso
from .calendar import render_calendar
from .channels import dns_channel, file_channel
from .event_timeline import render_event_timeline
from .filtering import FilterSet, filter_events
from .templating import create_env
from .timeline_svg import render_rndc_timeline, render_state_timeline


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
    filterset: FilterSet | None = None,
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
    # Apply the FilterSet *before* computing any counts, calendars,
    # timelines, or per-key blocks so every downstream section of the
    # report reflects the same filtered view.
    events = filter_events(events, filterset)

    counts = {
        "state_changed": sum(1 for e in events if e.event_type == "state_changed"),
        "rndc_state_changed": sum(1 for e in events if e.event_type == "rndc_state_changed"),
        "dns_events": sum(1 for e in events if e.source == "dns"),
        "iodyn_events": sum(1 for e in events if e.source == "syslog" and e.event_type.startswith("iodyn_")),
    }

    timeline_svg = render_state_timeline(events, keys)
    rndc_svg = render_rndc_timeline(events, keys)
    calendar_html = render_calendar(events, from_ts, to_ts)
    dns_timeline_svg = render_event_timeline(
        dns_channel(events), from_ts, to_ts
    )
    file_timeline_svg = render_event_timeline(
        file_channel(events), from_ts, to_ts
    )

    # Per-key current timing snapshots (Created/Publish/Activate/…
    # from K*.key plus the state-machine and timestamp fields from
    # K*.state) pulled live from the collector snapshots so the report
    # captures the exact values at render time. Events for each key
    # are also grouped so the report can show the per-key timeline
    # alongside the zone-wide one. The FilterSet is applied inside
    # _build_per_key_blocks as well so each key's section reflects
    # the same filter the zone-level sections do.
    per_key_blocks = _build_per_key_blocks(db, keys, events, filterset)

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
        "dns_timeline_svg": dns_timeline_svg,
        "file_timeline_svg": file_timeline_svg,
        "per_key_blocks": per_key_blocks,
        "dns_observations": dns_observations,
        "state_snapshots": state_snapshots,
        "window_start": from_ts,
        "window_end": to_ts,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "policy_snapshot": "",  # filled in later if we can read named.conf
        "executive_summary": executive_summary,
        "css": _load_css(),
        "filterset": filterset,
    }


def _build_per_key_blocks(
    db: Database,
    keys,
    events: list[Event],
    filterset: FilterSet | None = None,
) -> list[dict]:
    """For each key, gather its current timing snapshots and the
    events filtered down to that key (matched by ``key_tag``).

    If a ``filterset`` is supplied it's applied on top of the key_tag
    match so every per-key block reflects the same filter as the
    zone-wide sections above it. Note: when the report-wide events
    list is already filtered (as it is in the normal call path from
    :func:`_build_report_context`) re-applying the FilterSet here is
    a cheap no-op, but it stays cheap and means direct callers of
    ``_build_per_key_blocks`` don't need to remember to pre-filter.
    """

    blocks: list[dict] = []
    for k in keys:
        scope = f"{k.zone}#{k.key_tag}#{k.role}"
        key_file_snap = db.get_snapshot("key_file", scope) or {}
        state_file_snap = db.get_snapshot("state_file", scope) or {}

        state_fields_all = state_file_snap.get("fields", {}) or {}
        # Split the .state fields into state-machine names vs timestamps
        # so the report shows two focused tables rather than one big
        # mess.
        from ..parsers.bind_state import STATE_FIELDS, TIMESTAMP_FIELDS

        state_machine = {
            k_: state_fields_all.get(k_) for k_ in STATE_FIELDS if k_ in state_fields_all
        }
        state_timestamps = {
            k_: state_fields_all.get(k_) for k_ in TIMESTAMP_FIELDS if k_ in state_fields_all
        }

        key_events = filter_events(
            [e for e in events if e.key_tag == k.key_tag], filterset
        )
        # Only timing-change events (for the "changes observed"
        # subsection in the template).
        timing_changes = [
            e for e in key_events
            if e.event_type in ("key_timing_changed", "state_timing_changed")
        ]

        blocks.append(
            {
                "key": k,
                "key_file_timings": key_file_snap.get("timings", {}) or {},
                "state_machine": state_machine,
                "state_timestamps": state_timestamps,
                "events": key_events,
                "timing_changes": timing_changes,
                "dns_timeline_svg": render_event_timeline(dns_channel(key_events)),
                "file_timeline_svg": render_event_timeline(file_channel(key_events)),
                "calendar_html": render_calendar(key_events),
            }
        )
    return blocks


def render_report_html(
    db: Database,
    config: Config,
    zone: str,
    from_ts: str | None = None,
    to_ts: str | None = None,
    *,
    filterset: FilterSet | None = None,
) -> str:
    ctx = _build_report_context(
        db, config, zone, from_ts, to_ts, filterset=filterset
    )
    env = create_env()
    tmpl = env.get_template("report.html")
    return tmpl.render(**ctx)
