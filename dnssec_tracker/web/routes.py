"""FastAPI routes: dashboard, zone views, event log, exports."""

from __future__ import annotations

import asyncio
import json
import re
import time

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from ..config import Config
from ..demo import build_rollover_demo
from ..db import Database
from ..parsers.bind_state import STATE_FIELDS, TIMESTAMP_FIELDS
from ..render.calendar import render_calendar
from ..render.channels import dns_channel, file_channel
from ..render.event_timeline import render_event_timeline
from ..render.filtering import FilterSet, filter_events
from ..render.html_export import render_report_html
from ..render.overdue import assess_all
from ..render.pdf_export import render_report_pdf
from ..render.rollover_view import render_rollover_view
from ..render.templating import create_env
from ..render.timeline_svg import render_state_timeline


_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# Timings from the K*.key header we want to surface as scheduled
# markers on the calendar. Created is a historical timestamp (when the
# key was generated), so it's excluded — the calendar's scheduled
# overlay is specifically for *upcoming* transitions.
_SCHEDULED_KEY_TIMINGS = (
    "Publish", "Activate", "Inactive", "Delete", "SyncPublish", "SyncDelete",
)


_CAL_CENTER_RE = re.compile(r"^(\d{4})-(\d{2})$")


def _calendar_scroll(raw: str | None):
    """Parse a ``cal_center=YYYY-MM`` query param into a
    ``(center_date, prev_center, next_center)`` triple. Invalid or
    missing input falls back to the current month — the default
    3-month window is previous / this / next relative to today.
    """
    from datetime import date as _date

    today = _date.today()
    center = today.replace(day=1)
    if raw:
        m = _CAL_CENTER_RE.match(raw.strip())
        if m:
            try:
                center = _date(int(m.group(1)), int(m.group(2)), 1)
            except ValueError:
                pass
    # prev / next relative to center
    if center.month == 1:
        prev = _date(center.year - 1, 12, 1)
    else:
        prev = _date(center.year, center.month - 1, 1)
    if center.month == 12:
        nxt = _date(center.year + 1, 1, 1)
    else:
        nxt = _date(center.year, center.month + 1, 1)
    return center, prev, nxt


def _scheduled_dates_for_keys(db: Database, keys) -> dict:
    """Walk every key's ``key_file`` snapshot and return a
    ``{date: [description, ...]}`` mapping suitable for
    ``render_calendar(..., scheduled_dates=...)``.
    """
    from collections import defaultdict
    from datetime import datetime as _dt

    def _parse(ts):
        if not ts or ts == "0":
            return None
        s = str(ts).strip()
        if len(s) != 14 or not s.isdigit():
            return None
        try:
            return _dt(
                int(s[0:4]), int(s[4:6]), int(s[6:8]),
                int(s[8:10]), int(s[10:12]), int(s[12:14]),
            )
        except ValueError:
            return None

    out = defaultdict(list)
    for k in keys:
        scope = f"{k.zone}#{k.key_tag}#{k.role}"
        snap = db.get_snapshot("key_file", scope) or {}
        timings = snap.get("timings", {}) or {}
        for field in _SCHEDULED_KEY_TIMINGS:
            dt = _parse(timings.get(field))
            if dt is None:
                continue
            out[dt.date()].append(f"{k.role} tag {k.key_tag}: {field}")
    return dict(out)


def _expand_date(value: str | None, *, end: bool) -> str | None:
    """Turn a ``YYYY-MM-DD`` from the HTML5 date picker into a full
    ISO-8601 UTC timestamp that the SQLite ``ts`` column (also ISO) can
    range-compare against.

    * ``end=False`` stretches to the start of the day (``T00:00:00Z``)
    * ``end=True`` stretches to the last second of the day (``T23:59:59Z``)

    Values that don't match the date shape are passed through
    unchanged so existing ISO timestamps keep working.
    """

    if not value:
        return value
    if _DATE_RE.match(value):
        return f"{value}T23:59:59Z" if end else f"{value}T00:00:00Z"
    return value


def build_router(db: Database, config: Config) -> APIRouter:
    router = APIRouter()
    env = create_env()

    def render(name: str, **ctx) -> HTMLResponse:
        tmpl = env.get_template(name)
        return HTMLResponse(tmpl.render(**ctx))

    @router.get("/", response_class=HTMLResponse)
    def dashboard(request: Request) -> HTMLResponse:
        zones = db.list_zones()
        recent = db.query_events(limit=20)
        return render("dashboard.html", zones=zones, recent=recent)

    @router.get("/zones/{zone}", response_class=HTMLResponse)
    def zone_detail(
        zone: str,
        hide_types: str | None = None,
        hide_types_preset: str | None = None,
        hide_sources: str | None = None,
        role: str | None = None,
        cal_center: str | None = None,
    ) -> HTMLResponse:
        z = db.get_zone(zone)
        if z is None:
            raise HTTPException(404, f"zone {zone} not found")
        keys = db.list_keys(zone)
        # The DNSKEY-focus checkbox and the free-form text box share
        # the same logical dimension. If the preset is ticked, it
        # wins; otherwise fall back to whatever the user typed.
        hide_types = hide_types_preset or hide_types
        fs = FilterSet.from_query(hide_types, hide_sources, role)
        # Pull a broad event set so the visualisations (calendar,
        # timelines, rollover) have the full history to work with.
        # The event table below the page uses ``events_per_page``
        # to decide how many rows to show but the vis pipeline is
        # not bounded by that — using the paginated slice was the
        # "no dots on old calendar months" bug.
        all_events = filter_events(
            db.query_events(zone=zone, limit=10_000), fs
        )
        events = all_events[: config.events_per_page]
        timeline_svg = render_state_timeline(all_events, keys)
        # Split the chronological event chart into two channels:
        # DNS (dns_probe + rndc_status) and File (state_file + key_file).
        dns_timeline_svg = render_event_timeline(dns_channel(all_events))
        file_timeline_svg = render_event_timeline(file_channel(all_events))
        scheduled = _scheduled_dates_for_keys(db, keys)
        center_date, prev_center, next_center = _calendar_scroll(cal_center)
        calendar_html = render_calendar(
            all_events, scheduled_dates=scheduled, center=center_date,
        )
        # Rollover view — fetch both the state_file snapshot (actual
        # transitions that have already happened) and the key_file
        # snapshot (scheduled Created/Publish/Activate/Inactive/Delete
        # times iodyn wrote into the K*.key header). The renderer
        # prefers state_file values when set and falls back to the
        # scheduled key_file values so a key whose Delete time has
        # already passed renders as "removed" instead of
        # collapsing into an unbounded "pre-published".
        snapshots = {}
        for k in keys:
            scope = f"{k.zone}#{k.key_tag}#{k.role}"
            state_snap = db.get_snapshot("state_file", scope) or {}
            key_snap = db.get_snapshot("key_file", scope) or {}
            snapshots[scope] = {
                "fields": state_snap.get("fields", {}) or {},
                "timings": key_snap.get("timings", {}) or {},
            }
        # Assess keys whose scheduled Delete has passed but whose
        # DNSKEY is still at the zone or whose DS is still at the
        # parent. The last observed dns_probe snapshots give us the
        # current state of the world; the per-key snapshots carry the
        # scheduled Delete time. Overdue keys trigger both a red
        # warning banner at the top of the page and a high-contrast
        # fill on the rollover view's removed segment.
        zone_dns_snap = db.get_snapshot("dns_probe", f"zone:{z.name}") or {}
        parent_dns_snap = db.get_snapshot("dns_probe", f"parent:{z.name}") or {}
        overdue_assessments = assess_all(
            keys, snapshots, zone_dns_snap, parent_dns_snap,
        )
        overdue_by_tag = {
            a.key.key_tag: a.state for a in overdue_assessments if a.is_overdue
        }
        rollover_svg = render_rollover_view(
            all_events, keys, snapshots, overdue_by_tag=overdue_by_tag,
        )
        return render(
            "zone.html",
            zone=z,
            keys=keys,
            events=events,
            timeline_svg=timeline_svg,
            calendar_html=calendar_html,
            calendar_prev=prev_center.strftime("%Y-%m"),
            calendar_next=next_center.strftime("%Y-%m"),
            calendar_center=center_date.strftime("%Y-%m"),
            dns_timeline_svg=dns_timeline_svg,
            file_timeline_svg=file_timeline_svg,
            rollover_svg=rollover_svg,
            overdue_assessments=[a for a in overdue_assessments if a.is_overdue],
            filterset=fs,
            hide_types=hide_types or "",
            hide_sources=hide_sources or "",
            role=fs.role,
        )

    @router.get("/zones/{zone}/keys/{tag}", response_class=HTMLResponse)
    def key_detail(
        zone: str,
        tag: int,
        hide_types: str | None = None,
        hide_types_preset: str | None = None,
        hide_sources: str | None = None,
        role: str | None = None,
        cal_center: str | None = None,
    ) -> HTMLResponse:
        keys = [k for k in db.list_keys(zone) if k.key_tag == tag]
        if not keys:
            raise HTTPException(404, f"key {tag} not found in {zone}")
        # Preset checkbox wins over the text box if both are sent.
        hide_types = hide_types_preset or hide_types

        # Pull live timing snapshots for every (role) instance of this
        # tag. Each collector stores them keyed by
        # "zone#tag#role" so we query directly.
        key_blocks = []
        for k in keys:
            scope = f"{k.zone}#{k.key_tag}#{k.role}"
            key_file_snap = db.get_snapshot("key_file", scope) or {}
            state_file_snap = db.get_snapshot("state_file", scope) or {}
            state_fields = state_file_snap.get("fields", {}) or {}
            key_blocks.append(
                {
                    "key": k,
                    "key_file_timings": key_file_snap.get("timings", {}) or {},
                    "state_machine": {
                        f: state_fields[f] for f in STATE_FIELDS if f in state_fields
                    },
                    "state_timestamps": {
                        f: state_fields[f] for f in TIMESTAMP_FIELDS if f in state_fields
                    },
                }
            )

        # Events for this key. DS events land in here naturally because
        # _extract_key_tag pulls the tag from DS rdata at emit time,
        # so KSKs see the "DS (key tag N) appeared at parent" story
        # without any special plumbing. The key_tag match happens
        # *before* the FilterSet so role=KSK (default for a KSK page)
        # still keeps the DS events, which are emitted with
        # key_role=None.
        events = [
            e for e in db.query_events(zone=zone, limit=2000)
            if e.key_tag == tag
        ]
        fs = FilterSet.from_query(hide_types, hide_sources, role)
        events = filter_events(events, fs)
        timing_change_events = [
            e for e in events
            if e.event_type in ("key_timing_changed", "state_timing_changed")
        ]

        scheduled = _scheduled_dates_for_keys(db, keys)
        center_date, prev_center, next_center = _calendar_scroll(cal_center)
        calendar_html = render_calendar(
            events, scheduled_dates=scheduled, center=center_date,
        )
        dns_timeline_svg = render_event_timeline(dns_channel(events))
        file_timeline_svg = render_event_timeline(file_channel(events))
        # Rollover view scoped to just this key tag. Combine state_file
        # (actual transitions) and key_file (scheduled timings) for the
        # same reason as zone_detail — the scheduled times from the
        # K*.key file fill in phase boundaries the state file hasn't
        # caught up to yet.
        snapshots = {}
        for k in keys:
            scope = f"{k.zone}#{k.key_tag}#{k.role}"
            state_snap = db.get_snapshot("state_file", scope) or {}
            key_snap = db.get_snapshot("key_file", scope) or {}
            snapshots[scope] = {
                "fields": state_snap.get("fields", {}) or {},
                "timings": key_snap.get("timings", {}) or {},
            }
        zone_dns_snap = db.get_snapshot("dns_probe", f"zone:{zone}") or {}
        parent_dns_snap = db.get_snapshot("dns_probe", f"parent:{zone}") or {}
        overdue_assessments = assess_all(
            keys, snapshots, zone_dns_snap, parent_dns_snap,
        )
        overdue_by_tag = {
            a.key.key_tag: a.state for a in overdue_assessments if a.is_overdue
        }
        rollover_svg = render_rollover_view(
            events, keys, snapshots, overdue_by_tag=overdue_by_tag,
        )

        return render(
            "key.html",
            zone=zone,
            tag=tag,
            key_blocks=key_blocks,
            events=events,
            timing_change_events=timing_change_events,
            calendar_html=calendar_html,
            calendar_prev=prev_center.strftime("%Y-%m"),
            calendar_next=next_center.strftime("%Y-%m"),
            calendar_center=center_date.strftime("%Y-%m"),
            dns_timeline_svg=dns_timeline_svg,
            file_timeline_svg=file_timeline_svg,
            rollover_svg=rollover_svg,
            overdue_assessments=[a for a in overdue_assessments if a.is_overdue],
            filterset=fs,
            hide_types=hide_types or "",
            hide_sources=hide_sources or "",
            role=fs.role,
        )

    # ---- Demo ------------------------------------------------------
    #
    # A synthetic 12-month zone with 3 KSK rollovers and 13 ZSK
    # rollovers, rendered through the same zone template so the
    # rollover / calendar / timeline chrome can be evaluated against
    # a realistic dataset. No DB writes, ephemeral per-request. See
    # :mod:`dnssec_tracker.demo.scenarios`.

    @router.get("/demo", response_class=HTMLResponse)
    def demo_zone(
        cal_center: str | None = None,
    ) -> HTMLResponse:
        d = build_rollover_demo()
        keys = d.keys
        events = d.events

        # Calendar scroll (same helper zone_detail uses).
        scheduled = {}  # demo has no human-set K*.key scheduled dates
        center_date, prev_center, next_center = _calendar_scroll(cal_center)
        calendar_html = render_calendar(
            events, scheduled_dates=scheduled, center=center_date,
        )

        # Visualisations — explicit window so the chart matches the
        # 12-month scenario the demo is built for, not the auto-fitted
        # range.
        from_ts = d.window_start.isoformat().replace("+00:00", "Z")
        to_ts = d.window_end.isoformat().replace("+00:00", "Z")
        timeline_svg = render_state_timeline(events, keys)
        dns_timeline_svg = render_event_timeline(
            dns_channel(events), from_ts, to_ts,
        )
        file_timeline_svg = render_event_timeline(
            file_channel(events), from_ts, to_ts,
        )
        # Overdue assessment — the demo is intentionally healthy so
        # this should come back empty, but we run the path to make
        # sure the demo exercises it end-to-end.
        overdue_assessments = assess_all(
            keys, d.snapshots, d.zone_dns_snapshot, d.parent_dns_snapshot,
            now=d.window_end,
        )
        overdue_active = [a for a in overdue_assessments if a.is_overdue]
        overdue_by_tag = {a.key.key_tag: a.state for a in overdue_active}
        rollover_svg = render_rollover_view(
            events, keys, d.snapshots,
            from_ts=from_ts, to_ts=to_ts,
            today=d.window_end,
            overdue_by_tag=overdue_by_tag,
        )

        # Fake a FilterSet with defaults so the shared template's
        # filter form echoes back neutral values.
        fs = FilterSet.from_query(None, None, None)

        return render(
            "zone.html",
            zone=d.zone,
            keys=keys,
            events=events,
            timeline_svg=timeline_svg,
            calendar_html=calendar_html,
            calendar_prev=prev_center.strftime("%Y-%m"),
            calendar_next=next_center.strftime("%Y-%m"),
            calendar_center=center_date.strftime("%Y-%m"),
            dns_timeline_svg=dns_timeline_svg,
            file_timeline_svg=file_timeline_svg,
            rollover_svg=rollover_svg,
            overdue_assessments=overdue_active,
            filterset=fs,
            hide_types="",
            hide_sources="",
            role="all",
            demo=True,
        )

    @router.get("/events", response_class=HTMLResponse)
    def events_page(
        zone: str | None = None,
        from_ts: str | None = Query(None, alias="from"),
        to_ts: str | None = Query(None, alias="to"),
        event_type: str | None = None,
        source: str | None = None,
        page: int = 1,
    ) -> HTMLResponse:
        page = max(page, 1)
        offset = (page - 1) * config.events_per_page
        events = db.query_events(
            zone=zone,
            # HTML5 <input type="date"> sends YYYY-MM-DD; widen those
            # to full-day UTC bounds so "from 2026-04-10" really means
            # "from 00:00:00 UTC" and "to 2026-04-11" means "up to
            # 23:59:59 UTC".
            from_ts=_expand_date(from_ts, end=False),
            to_ts=_expand_date(to_ts, end=True),
            event_type=event_type,
            source=source,
            limit=config.events_per_page,
            offset=offset,
        )
        return render(
            "events.html",
            events=events,
            zone=zone,
            page=page,
            from_ts=from_ts,
            to_ts=to_ts,
            event_type=event_type,
            source=source,
        )

    # ---- JSON API ---------------------------------------------------

    @router.get("/api/zones")
    def api_zones() -> JSONResponse:
        return JSONResponse([z.__dict__ for z in db.list_zones()])

    @router.get("/api/zones/{zone}/keys")
    def api_keys(zone: str) -> JSONResponse:
        return JSONResponse([k.__dict__ for k in db.list_keys(zone)])

    @router.get("/api/zones/{zone}/snapshot")
    def api_snapshot(zone: str) -> JSONResponse:
        keys = db.list_keys(zone)
        out = []
        for k in keys:
            row = k.__dict__.copy()
            try:
                row["state"] = json.loads(k.last_state_json or "{}")
            except json.JSONDecodeError:
                row["state"] = {}
            out.append(row)
        return JSONResponse({"zone": zone, "keys": out})

    @router.get("/api/events")
    def api_events(
        zone: str | None = None,
        from_ts: str | None = Query(None, alias="from"),
        to_ts: str | None = Query(None, alias="to"),
        event_type: str | None = None,
        source: str | None = None,
        limit: int = 500,
        offset: int = 0,
    ) -> JSONResponse:
        events = db.query_events(
            zone=zone,
            from_ts=from_ts,
            to_ts=to_ts,
            event_type=event_type,
            source=source,
            limit=limit,
            offset=offset,
        )
        return JSONResponse([e.to_dict() for e in events])

    # ---- Force refresh ---------------------------------------------

    @router.post("/api/refresh")
    async def api_refresh(request: Request) -> JSONResponse:
        """Trigger an immediate sample pass on every collector.

        Called by ``dnssec-tracker --refresh`` (and therefore by
        ``docker exec dnssec-tracker dnssec-tracker --refresh``) so you
        don't have to wait out the next poll tick to see fresh data.
        Streaming collectors (syslog / named_log tails) are always
        up-to-date within a second, so their entries will report
        ``ok`` but with essentially zero elapsed time.
        """

        collectors = getattr(request.app.state, "collectors", []) or []
        results: dict = {}
        for c in collectors:
            start = time.monotonic()
            try:
                await c.force_sample()
                results[c.name] = {
                    "ok": True,
                    "ms": round((time.monotonic() - start) * 1000, 1),
                }
            except Exception as e:  # noqa: BLE001
                results[c.name] = {"ok": False, "error": f"{type(e).__name__}: {e}"}
        return JSONResponse({"refreshed": results})

    # ---- Clean deleted keys ----------------------------------------

    @router.post("/api/clean-deleted-keys")
    async def api_clean_deleted_keys(request: Request) -> JSONResponse:
        """Scan the key directory and purge stored data for any key
        whose ``K*.state`` file is no longer on disk.

        This is a **manual** action — the state_file collector does
        NOT run cleanup as part of its 30-second polling loop,
        because a file momentarily missing during a BIND reload or
        iodyn-dnssec settime race shouldn't wipe a key's snapshot
        as a side effect. An operator triggers cleanup when they
        intentionally delete keys.

        For each vanished key, one ``state_key_file_deleted`` event
        is emitted (state change: removed) and the state_file +
        key_file snapshots plus the ``keys``-table row are dropped.
        Events stay in place — the event log is an append-only
        historical record.

        Called by ``dnssec-tracker --clean-deleted-keys`` (and
        therefore by
        ``docker exec dnssec-tracker dnssec-tracker --clean-deleted-keys``).
        """

        from ..cleanup import clean_deleted_keys

        report = clean_deleted_keys(
            request.app.state.db,
            request.app.state.config,
        )
        return JSONResponse(report.to_dict())

    # ---- Reports ----------------------------------------------------

    @router.get("/zones/{zone}/report.html")
    def report_html(
        zone: str,
        from_ts: str | None = Query(None, alias="from"),
        to_ts: str | None = Query(None, alias="to"),
        hide_types: str | None = None,
        hide_sources: str | None = None,
        role: str | None = None,
    ) -> Response:
        fs = FilterSet.from_query(hide_types, hide_sources, role)
        html = render_report_html(db, config, zone, from_ts, to_ts, filterset=fs)
        return Response(content=html, media_type="text/html")

    @router.get("/zones/{zone}/report.pdf")
    def report_pdf(
        zone: str,
        from_ts: str | None = Query(None, alias="from"),
        to_ts: str | None = Query(None, alias="to"),
        hide_types: str | None = None,
        hide_sources: str | None = None,
        role: str | None = None,
    ) -> Response:
        fs = FilterSet.from_query(hide_types, hide_sources, role)
        pdf = render_report_pdf(db, config, zone, from_ts, to_ts, filterset=fs)
        return Response(content=pdf, media_type="application/pdf")

    return router
