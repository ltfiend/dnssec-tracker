"""FastAPI application wiring."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from .collectors.base import Collector
from .collectors.dns_probe import DnsProbeCollector
from .collectors.key_file import KeyFileCollector
from .collectors.named_log import NamedLogCollector
from .collectors.rndc_status import RndcStatusCollector
from .collectors.state_file import StateFileCollector
from .collectors.syslog_tail import SyslogTailCollector
from .config import Config
from .db import Database
from .web.routes import build_router


log = logging.getLogger("dnssec_tracker.app")


COLLECTOR_CLASSES: dict[str, type[Collector]] = {
    "state_file": StateFileCollector,
    "key_file": KeyFileCollector,
    "syslog": SyslogTailCollector,
    "named_log": NamedLogCollector,
    "dns_probe": DnsProbeCollector,
    "rndc_status": RndcStatusCollector,
}


def create_app(config: Config) -> FastAPI:
    db = Database(config.db_path)

    collectors: list[Collector] = []
    tasks: list[asyncio.Task] = []

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        for name, cls in COLLECTOR_CLASSES.items():
            if not config.enabled_collectors.get(name, False):
                log.info("collector %s disabled", name)
                continue
            try:
                collector = cls(config, db)
            except Exception:  # noqa: BLE001
                log.exception("failed to construct collector %s", name)
                continue
            collectors.append(collector)
            tasks.append(asyncio.create_task(collector.run(), name=f"collector:{name}"))
        try:
            yield
        finally:
            for c in collectors:
                c.stop()
            for t in tasks:
                try:
                    await asyncio.wait_for(t, timeout=5)
                except (asyncio.TimeoutError, Exception):  # noqa: BLE001
                    t.cancel()
            db.close()

    app = FastAPI(title="dnssec-tracker", lifespan=lifespan)
    app.state.db = db
    app.state.config = config
    # Expose the live collector list so POST /api/refresh can iterate
    # the same instances the lifespan manager started. The list itself
    # is populated when lifespan() runs on startup.
    app.state.collectors = collectors
    app.include_router(build_router(db, config))

    static_dir = Path(__file__).parent / "web" / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    return app
