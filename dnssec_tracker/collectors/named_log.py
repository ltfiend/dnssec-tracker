"""Collector that tails BIND's own log file for dnssec-category lines."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from ..models import Event
from ..parsers.named_log import parse_named_line
from .base import Collector

log = logging.getLogger("dnssec_tracker.collector.named_log")


class NamedLogCollector(Collector):
    name = "named_log"

    async def run(self) -> None:
        path = self.config.named_log_path
        if path is None:
            log.info("named_log path not configured, collector disabled")
            return
        log.info("named_log collector tailing %s", path)
        await self._tail(path)

    async def _tail(self, path: Path) -> None:
        offset = 0
        current_inode: int | None = None

        while not self._stopping.is_set():
            try:
                st = path.stat()
            except FileNotFoundError:
                await asyncio.sleep(2)
                continue

            if current_inode is None:
                current_inode = st.st_ino
                offset = st.st_size
            elif st.st_ino != current_inode or st.st_size < offset:
                current_inode = st.st_ino
                offset = 0

            if st.st_size > offset:
                try:
                    with path.open("r", encoding="utf-8", errors="replace") as f:
                        f.seek(offset)
                        chunk = f.read()
                        offset = f.tell()
                except OSError:
                    await asyncio.sleep(2)
                    continue
                for line in chunk.splitlines():
                    self._handle(line)

            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                pass

    def _handle(self, line: str) -> None:
        ev = parse_named_line(line)
        if ev is None:
            return
        self.db.insert_event(
            Event(
                ts=ev.ts.isoformat().replace("+00:00", "Z"),
                source="named",
                event_type=ev.event_type,
                summary=ev.message,
                zone=ev.zone,
                detail=ev.detail,
            )
        )
