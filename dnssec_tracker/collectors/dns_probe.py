"""Collector that queries DNS directly to observe what the zone (and its
parent) publishes.

Runs two loops per zone at independent cadences:

* ``query_interval`` (default 60 s) queries the local resolver for the
  zone's own DNSKEY, SOA, CDS, and CDNSKEY records.
* ``parent_interval`` (default 300 s) queries a parent authoritative
  server for the DS record.

On each pass it diffs the observed RRset against the previous snapshot
and emits events for DNSKEY/RRSIG/CDS/CDNSKEY/DS appearance and
disappearance.
"""

from __future__ import annotations

import asyncio
import logging

import dns.asyncresolver
import dns.exception
import dns.rdatatype

from ..models import Event, now_iso
from .base import Collector

log = logging.getLogger("dnssec_tracker.collector.dns_probe")


class DnsProbeCollector(Collector):
    name = "dns_probe"

    def __init__(self, config, db):
        super().__init__(config, db)
        host, _, port = config.local_resolver.partition(":")
        self._resolver = dns.asyncresolver.Resolver(configure=False)
        self._resolver.nameservers = [host or "127.0.0.1"]
        self._resolver.port = int(port) if port else 53
        self._resolver.lifetime = config.query_timeout
        self._last_parent_ts = 0.0

    async def run(self) -> None:
        loop = asyncio.get_event_loop()
        log.info("dns_probe starting (query=%ss parent=%ss)",
                 self.config.query_interval, self.config.parent_interval)

        while not self._stopping.is_set():
            try:
                await self._pass(loop.time())
            except Exception:  # noqa: BLE001
                log.exception("dns_probe pass failed")
            try:
                await asyncio.wait_for(
                    self._stopping.wait(), timeout=self.config.query_interval
                )
            except asyncio.TimeoutError:
                pass

    async def _pass(self, now_mono: float) -> None:
        zones = self.db.list_zones()
        if not zones:
            return

        for zone in zones:
            await self._probe_zone(zone.name)

        if now_mono - self._last_parent_ts >= self.config.parent_interval:
            for zone in zones:
                await self._probe_parent(zone.name)
            self._last_parent_ts = now_mono

    async def _probe_zone(self, zone: str) -> None:
        snapshot: dict[str, list[str]] = {}
        for rrtype in ("DNSKEY", "SOA", "CDS", "CDNSKEY"):
            snapshot[rrtype] = await self._query_rrset(zone, rrtype)
        # RRSIG is pulled in only when querying with DO bit; we
        # approximate by asking for the RRSIG cover of DNSKEY via a
        # generic RRSIG query (works against authoritative servers).
        snapshot["RRSIG_DNSKEY"] = await self._query_rrset(zone, "RRSIG")

        prev = self.db.get_snapshot(self.name, f"zone:{zone}")
        self._emit_diff(zone, "dns", prev, snapshot, parent=False)
        self.db.set_snapshot(self.name, f"zone:{zone}", snapshot)

    async def _probe_parent(self, zone: str) -> None:
        # For DS queries we ask the configured local resolver — a
        # recursive resolver will chase the delegation to the parent,
        # which is good enough for long-window observation.
        rrs = await self._query_rrset(zone, "DS")
        snapshot = {"DS": rrs}
        prev = self.db.get_snapshot(self.name, f"parent:{zone}")
        self._emit_diff(zone, "dns", prev, snapshot, parent=True)
        self.db.set_snapshot(self.name, f"parent:{zone}", snapshot)

    async def _query_rrset(self, name: str, rrtype: str) -> list[str]:
        try:
            ans = await self._resolver.resolve(name, rrtype, raise_on_no_answer=False)
        except (dns.exception.DNSException, OSError):
            return []
        if ans.rrset is None:
            return []
        return sorted(str(r) for r in ans.rrset)

    def _emit_diff(
        self,
        zone: str,
        source: str,
        previous: dict,
        current: dict[str, list[str]],
        *,
        parent: bool,
    ) -> None:
        prev = previous or {}
        for rrtype, rrs in current.items():
            old = prev.get(rrtype, [])
            if old == rrs:
                continue
            added = sorted(set(rrs) - set(old))
            removed = sorted(set(old) - set(rrs))
            if added:
                self.db.insert_event(
                    Event(
                        ts=now_iso(),
                        source=source,
                        event_type=_observe_event(rrtype, parent, added=True),
                        summary=f"{rrtype} added at {'parent' if parent else 'zone'} for {zone}: {len(added)} record(s)",
                        zone=zone,
                        detail={"added": added, "parent": parent, "rrtype": rrtype},
                    )
                )
            if removed:
                self.db.insert_event(
                    Event(
                        ts=now_iso(),
                        source=source,
                        event_type=_observe_event(rrtype, parent, added=False),
                        summary=f"{rrtype} removed at {'parent' if parent else 'zone'} for {zone}: {len(removed)} record(s)",
                        zone=zone,
                        detail={"removed": removed, "parent": parent, "rrtype": rrtype},
                    )
                )


def _observe_event(rrtype: str, parent: bool, *, added: bool) -> str:
    direction = "appeared" if added else "disappeared"
    loc = "parent" if parent else "zone"
    return f"dns_{rrtype.lower()}_{direction}_at_{loc}"
