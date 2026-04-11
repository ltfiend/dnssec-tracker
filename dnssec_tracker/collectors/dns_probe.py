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
import time

import dns.asyncresolver
import dns.dnssec
import dns.exception
import dns.flags
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype

from ..models import Event, now_iso
from .base import Collector

log = logging.getLogger("dnssec_tracker.collector.dns_probe")
query_log = logging.getLogger("dnssec_tracker.query.dns")


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
                async with self._sample_lock:
                    await self._pass(loop.time())
            except Exception:  # noqa: BLE001
                log.exception("dns_probe pass failed")
            try:
                await asyncio.wait_for(
                    self._stopping.wait(), timeout=self.config.query_interval
                )
            except asyncio.TimeoutError:
                pass

    async def _pass(self, now_mono: float, *, force: bool = False) -> None:
        zones = self.db.list_zones()
        if not zones:
            return

        for zone in zones:
            await self._probe_zone(zone.name)

        if force or now_mono - self._last_parent_ts >= self.config.parent_interval:
            for zone in zones:
                await self._probe_parent(zone.name)
            self._last_parent_ts = now_mono

    async def force_sample(self) -> None:
        """Run both the zone probe and the parent DS probe immediately,
        ignoring the parent-interval gate so every DNS observable is
        refreshed on demand.
        """
        async with self._sample_lock:
            loop = asyncio.get_event_loop()
            await self._pass(loop.time(), force=True)

    async def _probe_zone(self, zone: str) -> None:
        snapshot: dict[str, list[str]] = {}
        for rrtype in ("DNSKEY", "SOA", "CDS", "CDNSKEY"):
            snapshot[rrtype] = await self._query_rrset(zone, rrtype, role="zone")
        # RRSIG is pulled in only when querying with DO bit; we
        # approximate by asking for the RRSIG cover of DNSKEY via a
        # generic RRSIG query (works against authoritative servers).
        snapshot["RRSIG"] = await self._query_rrset(zone, "RRSIG", role="zone")

        prev = self.db.get_snapshot(self.name, f"zone:{zone}")
        self._emit_diff(zone, "dns", prev, snapshot, parent=False)
        self.db.set_snapshot(self.name, f"zone:{zone}", snapshot)

    async def _probe_parent(self, zone: str) -> None:
        # For DS queries we ask the configured local resolver — a
        # recursive resolver will chase the delegation to the parent,
        # which is good enough for long-window observation. The query
        # log marks this as role=parent so it's easy to tell apart
        # from zone-side DNS traffic.
        rrs = await self._query_rrset(zone, "DS", role="parent")
        snapshot = {"DS": rrs}
        prev = self.db.get_snapshot(self.name, f"parent:{zone}")
        self._emit_diff(zone, "dns", prev, snapshot, parent=True)
        self.db.set_snapshot(self.name, f"parent:{zone}", snapshot)

    async def _query_rrset(
        self, name: str, rrtype: str, *, role: str = "zone"
    ) -> list[str]:
        """Send one DNS query and return the sorted rdata text list.

        Every query emits a structured INFO-level log line on both
        send and receive, so operators can see exactly what went out
        and what came back. The fields are::

            server=<ip>:<port> protocol=<UDP|TCP> role=<zone|parent>
            name=<qname> type=<qtype> timeout=<seconds>
            rcode=<NOERROR|...> answers=<n> elapsed_ms=<float>

        Individual answer records are logged at DEBUG level so you
        can dump them with ``--log-level DEBUG`` if you need the
        wire-form payload for offline analysis, without flooding
        INFO under normal operation.
        """

        server = (
            self._resolver.nameservers[0]
            if self._resolver.nameservers
            else "?"
        )
        port = self._resolver.port or 53
        # dnspython's asyncresolver uses UDP by default with automatic
        # TCP fallback on a truncated response; we note the nominal
        # protocol here and upgrade the log line to "UDP+TCP" below if
        # the response we received has the TC bit set, which means a
        # TCP retry happened.
        protocol = "UDP"
        timeout = float(self._resolver.lifetime or 0.0)

        query_log.info(
            "send: server=%s:%s protocol=%s role=%s name=%s type=%s timeout=%.1fs",
            server, port, protocol, role, name, rrtype, timeout,
        )

        start = time.monotonic()
        try:
            ans = await self._resolver.resolve(
                name, rrtype, raise_on_no_answer=False
            )
        except (dns.exception.DNSException, OSError) as exc:
            elapsed_ms = (time.monotonic() - start) * 1000
            query_log.warning(
                "recv: server=%s:%s role=%s name=%s type=%s FAILED %s=%s elapsed_ms=%.1f",
                server, port, role, name, rrtype,
                type(exc).__name__, exc, elapsed_ms,
            )
            return []

        elapsed_ms = (time.monotonic() - start) * 1000
        response = getattr(ans, "response", None)
        if response is not None:
            try:
                rcode_name = dns.rcode.to_text(response.rcode())
            except Exception:  # noqa: BLE001
                rcode_name = "?"
            if response.flags & dns.flags.TC:
                protocol = "UDP+TCP"
        else:
            rcode_name = "?"

        rrset = ans.rrset
        answers = list(rrset) if rrset is not None else []
        query_log.info(
            "recv: server=%s:%s protocol=%s role=%s name=%s type=%s "
            "rcode=%s answers=%d elapsed_ms=%.1f",
            server, port, protocol, role, name, rrtype,
            rcode_name, len(answers), elapsed_ms,
        )
        for r in answers:
            query_log.debug(
                "answer: server=%s:%s name=%s type=%s rdata=%s",
                server, port, name, rrtype, r,
            )
        return sorted(str(r) for r in answers)

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
            if rrtype == "SOA":
                # SOA gets special handling — we only emit on
                # presence/absence transitions, never on simple serial
                # bumps, because dnssec-policy re-signs and bumps the
                # serial on a schedule and nobody wants that in the
                # event log.
                self._emit_soa_transition(
                    zone, source, prev.get("SOA", []), rrs, parent
                )
                continue

            old = prev.get(rrtype, [])
            if old == rrs:
                continue
            added = sorted(set(rrs) - set(old))
            removed = sorted(set(old) - set(rrs))
            for rr in added:
                self._emit_record_event(
                    zone, source, rrtype, rr, parent, change="appeared"
                )
            for rr in removed:
                self._emit_record_event(
                    zone, source, rrtype, rr, parent, change="disappeared"
                )

    def _emit_record_event(
        self,
        zone: str,
        source: str,
        rrtype: str,
        record: str,
        parent: bool,
        *,
        change: str,
    ) -> None:
        """Emit one event per record, enriched with the key tag when we
        can extract it from the record text."""

        loc = "parent" if parent else "zone"
        key_tag = _extract_key_tag(rrtype, record)
        tag_bit = f" (key tag {key_tag})" if key_tag is not None else ""
        # RRSIG events are worth distinguishing by covered type in the
        # summary — "RRSIG over DNSKEY (key tag 12345) appeared" is much
        # more useful than just "RRSIG appeared".
        covered = _rrsig_covered_type(record) if rrtype == "RRSIG" else None
        covered_bit = f" over {covered}" if covered else ""
        summary = (
            f"{rrtype}{covered_bit}{tag_bit} {change} at {loc} for {zone}"
        )
        self.db.insert_event(
            Event(
                ts=now_iso(),
                source=source,
                event_type=f"dns_{rrtype.lower()}_{change}_at_{loc}",
                summary=summary,
                zone=zone,
                key_tag=key_tag,
                detail={
                    "rrtype": rrtype,
                    "parent": parent,
                    "record": record,
                    "key_tag": key_tag,
                    "covered_type": covered,
                },
            )
        )

    def _emit_soa_transition(
        self,
        zone: str,
        source: str,
        old_rrs: list[str],
        new_rrs: list[str],
        parent: bool,
    ) -> None:
        was_present = bool(old_rrs)
        is_present = bool(new_rrs)
        if was_present == is_present:
            # Either never seen (nothing to report yet) or still
            # present — a plain serial bump lands here and is
            # intentionally ignored.
            return

        loc = "parent" if parent else "zone"
        if is_present and not was_present:
            record = new_rrs[0]
            serial = _soa_serial(record)
            summary = (
                f"SOA observed at {loc} for {zone}"
                + (f" (serial {serial})" if serial is not None else "")
            )
            self.db.insert_event(
                Event(
                    ts=now_iso(),
                    source=source,
                    event_type=f"dns_soa_appeared_at_{loc}",
                    summary=summary,
                    zone=zone,
                    detail={
                        "rrtype": "SOA",
                        "parent": parent,
                        "record": record,
                        "serial": serial,
                    },
                )
            )
        else:  # was present, now absent
            self.db.insert_event(
                Event(
                    ts=now_iso(),
                    source=source,
                    event_type=f"dns_soa_disappeared_at_{loc}",
                    summary=f"SOA no longer answerable at {loc} for {zone}",
                    zone=zone,
                    detail={"rrtype": "SOA", "parent": parent},
                )
            )


def _extract_key_tag(rrtype: str, rdata_text: str) -> int | None:
    """Best-effort: pull the key tag out of a DNSKEY/CDNSKEY/DS/CDS/RRSIG
    record in its text form. Returns ``None`` for any record we don't
    know how to classify, or if parsing fails.

    * DS/CDS — first token is the key tag.
    * RRSIG  — field 6 (``type algo labels ttl exp inc KEYTAG signer sig``).
    * DNSKEY/CDNSKEY — parsed via dnspython and ``dns.dnssec.key_id()``.
    """

    try:
        if rrtype in ("DS", "CDS"):
            return int(rdata_text.split()[0])
        if rrtype == "RRSIG":
            parts = rdata_text.split()
            if len(parts) < 7:
                return None
            return int(parts[6])
        if rrtype in ("DNSKEY", "CDNSKEY"):
            # DNSKEY and CDNSKEY share the same wire format, so we parse
            # both as DNSKEY and let dnspython compute the key tag.
            rdata = dns.rdata.from_text(
                dns.rdataclass.IN, dns.rdatatype.DNSKEY, rdata_text
            )
            return dns.dnssec.key_id(rdata)
    except (ValueError, IndexError, dns.exception.DNSException):
        return None
    return None


def _rrsig_covered_type(rdata_text: str) -> str | None:
    """First token of an RRSIG rdata is the type it covers."""
    try:
        return rdata_text.split()[0]
    except (IndexError, AttributeError):
        return None


def _soa_serial(rdata_text: str) -> int | None:
    try:
        return int(rdata_text.split()[2])
    except (ValueError, IndexError):
        return None
