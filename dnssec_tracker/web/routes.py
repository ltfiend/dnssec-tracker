"""FastAPI routes: dashboard, zone views, event log, exports."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..config import Config
from ..db import Database
from ..render.html_export import render_report_html
from ..render.pdf_export import render_report_pdf
from ..render.timeline_svg import render_state_timeline


def _jinja_env() -> Environment:
    tmpl_dir = Path(__file__).parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(tmpl_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    env.filters["fromjson"] = lambda s: json.loads(s or "{}")
    return env


def build_router(db: Database, config: Config) -> APIRouter:
    router = APIRouter()
    env = _jinja_env()

    def render(name: str, **ctx) -> HTMLResponse:
        tmpl = env.get_template(name)
        return HTMLResponse(tmpl.render(**ctx))

    @router.get("/", response_class=HTMLResponse)
    def dashboard(request: Request) -> HTMLResponse:
        zones = db.list_zones()
        recent = db.query_events(limit=20)
        return render("dashboard.html", zones=zones, recent=recent)

    @router.get("/zones/{zone}", response_class=HTMLResponse)
    def zone_detail(zone: str) -> HTMLResponse:
        z = db.get_zone(zone)
        if z is None:
            raise HTTPException(404, f"zone {zone} not found")
        keys = db.list_keys(zone)
        events = db.query_events(zone=zone, limit=config.events_per_page)
        timeline_svg = render_state_timeline(events, keys)
        return render(
            "zone.html",
            zone=z,
            keys=keys,
            events=events,
            timeline_svg=timeline_svg,
        )

    @router.get("/zones/{zone}/keys/{tag}", response_class=HTMLResponse)
    def key_detail(zone: str, tag: int) -> HTMLResponse:
        keys = [k for k in db.list_keys(zone) if k.key_tag == tag]
        if not keys:
            raise HTTPException(404, f"key {tag} not found in {zone}")
        events = [
            e for e in db.query_events(zone=zone, limit=1000) if e.key_tag == tag
        ]
        return render("key.html", zone=zone, keys=keys, events=events)

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
            from_ts=from_ts,
            to_ts=to_ts,
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

    # ---- Reports ----------------------------------------------------

    @router.get("/zones/{zone}/report.html")
    def report_html(
        zone: str,
        from_ts: str | None = Query(None, alias="from"),
        to_ts: str | None = Query(None, alias="to"),
    ) -> Response:
        html = render_report_html(db, config, zone, from_ts, to_ts)
        return Response(content=html, media_type="text/html")

    @router.get("/zones/{zone}/report.pdf")
    def report_pdf(
        zone: str,
        from_ts: str | None = Query(None, alias="from"),
        to_ts: str | None = Query(None, alias="to"),
    ) -> Response:
        pdf = render_report_pdf(db, config, zone, from_ts, to_ts)
        return Response(content=pdf, media_type="application/pdf")

    return router
