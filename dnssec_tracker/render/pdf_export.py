"""PDF report export via WeasyPrint.

Shares the ``report.html`` template with :mod:`html_export` so the two
outputs stay in sync. WeasyPrint runs no JavaScript, so every chart in
the report template is server-rendered SVG.
"""

from __future__ import annotations

from ..config import Config
from ..db import Database
from .html_export import render_report_html


def render_report_pdf(
    db: Database,
    config: Config,
    zone: str,
    from_ts: str | None = None,
    to_ts: str | None = None,
) -> bytes:
    # Import lazily so the rest of the codebase (and its unit tests)
    # don't require WeasyPrint's native dependencies to be installed.
    from weasyprint import HTML  # type: ignore

    html = render_report_html(db, config, zone, from_ts, to_ts)
    return HTML(string=html).write_pdf() or b""
