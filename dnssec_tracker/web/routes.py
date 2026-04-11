"""FastAPI routes: dashboard, zone views, event log, exports."""

from __future__ import annotations

import asyncio
import json
import re
import time

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from ..config import Config
from ..db import Database
from ..parsers.bind_state import STATE_FIELDS, TIMESTAMP_FIELDS
from ..render.calendar import render_calendar
from ..render.channels import dns_channel, file_channel
from ..render.event_timeline import render_event_timeline
from ..render.filtering import FilterSet, filter_events
from ..render.html_export import render_report_html
from ..render.pdf_export import render_report_pdf
from ..render.templating import create_env
from ..render.timeline_svg import render_state_timeline


_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


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
        events = filter_events(
            db.query_events(zone=zone, limit=config.events_per_page), fs
        )
        timeline_svg = render_state_timeline(events, keys)
        # Split the chronological event chart into two channels:
        # DNS (dns_probe + rndc_status) and File (state_file + key_file).
        dns_timeline_svg = render_event_timeline(dns_channel(events))
        file_timeline_svg = render_event_timeline(file_channel(events))
        calendar_html = render_calendar(events)
        return render(
            "zone.html",
            zone=z,
            keys=keys,
            events=events,
            timeline_svg=timeline_svg,
            calendar_html=calendar_html,
            dns_timeline_svg=dns_timeline_svg,
            file_timeline_svg=file_timeline_svg,
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

        calendar_html = render_calendar(events)
        dns_timeline_svg = render_event_timeline(dns_channel(events))
        file_timeline_svg = render_event_timeline(file_channel(events))

        return render(
            "key.html",
            zone=zone,
            tag=tag,
            key_blocks=key_blocks,
            events=events,
            timing_change_events=timing_change_events,
            calendar_html=calendar_html,
            dns_timeline_svg=dns_timeline_svg,
            file_timeline_svg=file_timeline_svg,
            filterset=fs,
            hide_types=hide_types or "",
            hide_sources=hide_sources or "",
            role=fs.role,
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
