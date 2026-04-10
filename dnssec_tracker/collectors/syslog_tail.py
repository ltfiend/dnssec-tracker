"""Collector that tails ``/var/log/syslog`` for iodyn-dnssec and named."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from ..models import Event, now_iso
from ..parsers.iodyn_syslog import (
    is_iodyn,
    is_named,
    parse_iodyn_message,
    parse_syslog_line,
)
from .base import Collector

log = logging.getLogger("dnssec_tracker.collector.syslog")


class SyslogTailCollector(Collector):
    name = "syslog"

    async def run(self) -> None:
        path = self.config.syslog_path
        if path is None:
            log.info("syslog path not configured, collector disabled")
            return
        log.info("syslog collector tailing %s", path)
        try:
            await self._tail(path)
        except asyncio.CancelledError:  # pragma: no cover
            raise
        except Exception:  # noqa: BLE001
            log.exception("syslog collector crashed")

    async def _tail(self, path: Path) -> None:
        # Simple polling tail. Handles rotation by re-opening if the inode
        # changes or the file shrinks.
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
                offset = st.st_size  # start from end — don't replay history
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
        parsed = parse_syslog_line(line)
        if parsed is None:
            return

        if is_iodyn(parsed):
            iodyn = parse_iodyn_message(parsed.ts, parsed.message)
            if iodyn is None:
                return
            self.db.insert_event(
                Event(
                    ts=parsed.ts.isoformat().replace("+00:00", "Z"),
                    source="syslog",
                    event_type=iodyn.event_type,
                    summary=iodyn.summary,
                    zone=iodyn.zone,
                    key_role=iodyn.role,
                    detail=iodyn.detail or {},
                )
            )
            return

        if is_named(parsed) and "dnssec" in parsed.message.lower():
            # Very small shortcut for syslog-delivered named lines. The
            # dedicated named_log collector handles the full log file.
            self.db.insert_event(
                Event(
                    ts=parsed.ts.isoformat().replace("+00:00", "Z"),
                    source="syslog",
                    event_type="named_syslog_line",
                    summary=parsed.message,
                    detail={"raw": parsed.message},
                )
            )
