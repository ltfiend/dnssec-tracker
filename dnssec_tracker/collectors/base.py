"""Collector base class."""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod

from ..config import Config
from ..db import Database


log = logging.getLogger("dnssec_tracker.collector")


class Collector(ABC):
    """Polling or streaming observer.

    Subclasses implement :meth:`sample` (one pass over the data source)
    and set ``interval`` to the polling cadence in seconds. Collectors
    that stream indefinitely (e.g. tailing a file) should override
    :meth:`run` directly instead.
    """

    name: str = "base"
    interval: float = 60.0

    def __init__(self, config: Config, db: Database):
        self.config = config
        self.db = db
        self._stopping = asyncio.Event()
        # Serialises scheduled and forced (out-of-band) sampling so a
        # manual ``--refresh`` never overlaps a polling pass in-flight.
        self._sample_lock = asyncio.Lock()

    async def sample(self) -> None:  # pragma: no cover - override
        raise NotImplementedError

    async def run(self) -> None:
        """Default run loop: call :meth:`sample` every ``interval``."""
        log.info("collector %s starting (interval=%ss)", self.name, self.interval)
        while not self._stopping.is_set():
            try:
                async with self._sample_lock:
                    await self.sample()
            except Exception:  # noqa: BLE001
                log.exception("collector %s sample failed", self.name)
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=self.interval)
            except asyncio.TimeoutError:
                pass
        log.info("collector %s stopped", self.name)

    async def force_sample(self) -> None:
        """Run a single sample pass immediately, out-of-band.

        Called by the ``POST /api/refresh`` endpoint (and therefore by
        ``dnssec-tracker --refresh``) so you don't have to wait for the
        next poll tick to see fresh data. Collectors that stream
        indefinitely (syslog / named_log tails) are always up-to-date
        within a second — their default behaviour here is a no-op.
        """

        async with self._sample_lock:
            try:
                await self.sample()
            except NotImplementedError:
                # Streaming collector — nothing meaningful to force.
                pass

    def stop(self) -> None:
        self._stopping.set()
