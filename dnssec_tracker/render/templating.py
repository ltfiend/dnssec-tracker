"""Shared Jinja environment and small display helpers.

Both :mod:`dnssec_tracker.web.routes` (live UI) and
:mod:`dnssec_tracker.render.html_export` (report export) load templates
from ``dnssec_tracker/web/templates``; this module gives them a single
pre-configured environment so custom filters stay in sync.
"""

from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape


def format_bind_ts(value: str | None) -> str:
    """Render a ``YYYYMMDDHHMMSS`` BIND timestamp as ``YYYY-MM-DD HH:MM:SS UTC``.

    BIND's ``K*.key`` / ``K*.state`` files write timing fields in the
    packed ``YYYYMMDDHHMMSS`` form (or ``0`` for "unset"). This helper
    keeps strings unchanged if they don't match the format so it's safe
    to apply to arbitrary values.
    """

    if value is None:
        return "—"
    s = str(value).strip()
    if not s or s == "0":
        return "—"
    if len(s) == 14 and s.isdigit():
        return f"{s[0:4]}-{s[4:6]}-{s[6:8]} {s[8:10]}:{s[10:12]}:{s[12:14]} UTC"
    return s


def create_env() -> Environment:
    tmpl_dir = Path(__file__).parent.parent / "web" / "templates"
    env = Environment(
        loader=FileSystemLoader(str(tmpl_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    env.filters["fromjson"] = lambda s: json.loads(s or "{}")
    env.filters["bind_ts"] = format_bind_ts
    return env
