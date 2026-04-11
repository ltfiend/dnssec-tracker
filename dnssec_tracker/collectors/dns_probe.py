"""Collector that queries authoritative nameservers directly to observe
what a zone (and its real parent delegation) publishes.

Pass cadence is unchanged:

* ``query_interval`` (default 60 s): every discovered zone's own
  authoritative NS set is queried for DNSKEY / SOA / CDS / CDNSKEY.
* ``parent_interval`` (default 300 s): for every zone we derive the
  parent zone (``fus3d.net`` → ``net``, ``net`` → ``.``), discover
  the parent's authoritative NS set, and ask one of those NS for the
  DS record of the child. So for ``fus3d.net`` we end up literally
  querying (for example) ``a.gtld-servers.net`` for ``fus3d.net DS``,
  which is the authoritative answer rather than whatever a caching
  recursor happens to remember.

NS discovery itself still rides through the configured
``local_resolver`` — it's used purely as plumbing to turn
``example.com NS`` into a list of ``(ip, ns-hostname)`` tuples. The
observation queries that produce events never go through the
recursor.

**"Any one good server is enough"** — for each authoritative NS list
we walk the servers in order and keep the first clean response
(``NOERROR`` or ``NXDOMAIN``). SERVFAIL, REFUSED, timeouts and
socket errors are treated as retryable and fall through to the next
NS. Only when every NS fails does the query come back empty and we
log a WARNING.

On each pass we diff the observed RRset against the previous
snapshot and emit events for DNSKEY/RRSIG/CDS/CDNSKEY/DS appearance
and disappearance (see ``_emit_diff``).
"""

from __future__ import annotations

import asyncio
import logging
import time

import dns.asyncquery
import dns.asyncresolver
import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype

from ..models import Event, now_iso
from .base import Collector

log = logging.getLogger("dnssec_tracker.collector.dns_probe")
query_log = logging.getLogger("dnssec_tracker.query.dns")


# Cache TTL for NS discovery: how long we trust a "NS + their A" lookup
# before re-resolving. The default matches parent_interval so once we
# know a zone's delegation we don't re-resolve it mid-cycle.
_NEG_CACHE_SECONDS = 60


class _TransientError(Exception):
    """Raised by :meth:`DnsProbeCollector._query_one` to tell
    ``_auth_query`` the current authoritative NS isn't usable and it
    should fall through to the next one in the list."""


class DnsProbeCollector(Collector):
    name = "dns_probe"

    def __init__(self, config, db):
        super().__init__(config, db)
        host, _, port = config.local_resolver.partition(":")
        # Recursor used only for NS / A discovery, never for the
        # DNSSEC observation queries themselves.
        self._recursor = dns.asyncresolver.Resolver(configure=False)
        self._recursor.nameservers = [host or "127.0.0.1"]
        self._recursor.port = int(port) if port else 53
        self._recursor.lifetime = config.query_timeout
        self._last_parent_ts = 0.0
        # NS-discovery cache: zone -> (monotonic_expires_at, [(ip, hostname), ...])
        self._ns_cache: dict[str, tuple[float, list[tuple[str, str]]]] = {}

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
        ns_list = await self._get_authoritative_ns(zone)
        if not ns_list:
            log.warning("no reachable authoritative NS for zone %s", zone)
            return

        snapshot: dict[str, list[str]] = {
            "DNSKEY": [],
            "SOA": [],
            "CDS": [],
            "CDNSKEY": [],
            "RRSIG": [],
        }
        # One query per observation rrtype. Each response is parsed
        # whole so RRSIG records present in the answer section (which
        # only show up because we set DO=1) are accumulated into the
        # snapshot's RRSIG bucket alongside the primary rrset.
        rrsig_acc: list[str] = []
        for rrtype in ("DNSKEY", "SOA", "CDS", "CDNSKEY"):
            result = await self._auth_query(ns_list, zone, rrtype, role="zone")
            snapshot[rrtype] = result.get(rrtype, [])
            rrsig_acc.extend(result.get("RRSIG", []))
        snapshot["RRSIG"] = sorted(set(rrsig_acc))

        prev = self.db.get_snapshot(self.name, f"zone:{zone}")
        self._emit_diff(zone, "dns", prev, snapshot, parent=False)
        self.db.set_snapshot(self.name, f"zone:{zone}", snapshot)

    async def _probe_parent(self, zone: str) -> None:
        parent = _parent_zone(zone)
        if parent is None:
            log.info("zone %s is the root; no parent DS to observe", zone)
            return

        ns_list = await self._get_authoritative_ns(parent)
        if not ns_list:
            log.warning(
                "no reachable authoritative NS for parent %s of %s",
                parent, zone,
            )
            return

        result = await self._auth_query(ns_list, zone, "DS", role="parent")
        snapshot = {"DS": result.get("DS", [])}

        prev = self.db.get_snapshot(self.name, f"parent:{zone}")
        self._emit_diff(zone, "dns", prev, snapshot, parent=True)
        self.db.set_snapshot(self.name, f"parent:{zone}", snapshot)

    async def _get_authoritative_ns(
        self, zone: str
    ) -> list[tuple[str, str]]:
        """Resolve *zone*'s authoritative NS set to a list of
        ``(ip, hostname)`` pairs via the local recursor, caching the
        result so we don't re-discover every pass.

        Returns ``[]`` on failure; negative results are cached briefly
        so a flapping recursor doesn't hammer us.
        """

        now = time.monotonic()
        cached = self._ns_cache.get(zone)
        if cached and cached[0] > now:
            return cached[1]

        rec_host = (
            self._recursor.nameservers[0]
            if self._recursor.nameservers else "?"
        )
        rec_port = self._recursor.port or 53
        query_log.info(
            "discover: zone=%s (resolving NS+A via recursor %s:%s)",
            zone, rec_host, rec_port,
        )

        ns_names: list[str] = []
        try:
            ns_ans = await self._recursor.resolve(
                zone, "NS", raise_on_no_answer=False
            )
            if ns_ans.rrset is not None:
                ns_names = [
                    str(r.target).rstrip(".") for r in ns_ans.rrset
                ]
        except (dns.exception.DNSException, OSError) as exc:
            query_log.warning(
                "discover: zone=%s NS lookup FAILED %s=%s",
                zone, type(exc).__name__, exc,
            )
            self._ns_cache[zone] = (now + _NEG_CACHE_SECONDS, [])
            return []

        ns_list: list[tuple[str, str]] = []
        for name in ns_names:
            try:
                a_ans = await self._recursor.resolve(
                    name, "A", raise_on_no_answer=False
                )
                if a_ans.rrset is not None:
                    for r in a_ans.rrset:
                        ns_list.append((str(r.address), name))
            except (dns.exception.DNSException, OSError) as exc:
                query_log.debug(
                    "discover: zone=%s NS %s A lookup FAILED %s=%s",
                    zone, name, type(exc).__name__, exc,
                )
                continue

        query_log.info(
            "discover: zone=%s ns_count=%d ips=%s",
            zone, len(ns_list), [ip for ip, _ in ns_list],
        )

        cache_ttl = (
            self.config.parent_interval
            if ns_list else _NEG_CACHE_SECONDS
        )
        self._ns_cache[zone] = (now + cache_ttl, ns_list)
        return ns_list

    async def _auth_query(
        self,
        ns_list: list[tuple[str, str]],
        name: str,
        rrtype: str,
        *,
        role: str,
    ) -> dict[str, list[str]]:
        """Walk the NS list until one answers cleanly.

        Returns a ``{rrtype: sorted list of rdata strings}`` dict of
        every rrset observed in the winning response's answer
        section. Empty dict if every NS in the list fails.
        """

        last_err: str | None = None
        for ip, hostname in ns_list:
            try:
                return await self._query_one(
                    ip, hostname, name, rrtype, role=role
                )
            except _TransientError as exc:
                last_err = str(exc)
                continue

        query_log.warning(
            "all authoritative NS failed for %s %s role=%s (last error: %s)",
            name, rrtype, role, last_err,
        )
        return {}

    async def _query_one(
        self,
        ns_ip: str,
        ns_hostname: str,
        name: str,
        rrtype: str,
        *,
        role: str,
    ) -> dict[str, list[str]]:
        """Send a single authoritative query to a specific NS IP.

        Always sets ``DO=1`` via EDNS with a 1232-byte buffer so the
        response includes RRSIG records alongside the primary rrset.
        Turns off ``RD`` since we're asking an authoritative server.

        Raises :class:`_TransientError` on SERVFAIL, REFUSED, timeout,
        or any socket error so ``_auth_query`` can try the next NS.
        ``NXDOMAIN`` is treated as a valid authoritative answer
        (empty rrset) and is *not* retried.
        """

        timeout = float(self.config.query_timeout)
        rdtype = dns.rdatatype.from_text(rrtype)
        q = dns.message.make_query(
            name, rdtype, want_dnssec=True, payload=1232
        )
        q.flags &= ~dns.flags.RD
        protocol = "UDP"

        query_log.info(
            "send: server=%s:53 ns=%s protocol=%s role=%s name=%s type=%s timeout=%.1fs",
            ns_ip, ns_hostname, protocol, role, name, rrtype, timeout,
        )

        start = time.monotonic()
        try:
            resp = await dns.asyncquery.udp(
                q, ns_ip, timeout=timeout, port=53
            )
        except (dns.exception.Timeout, OSError, dns.exception.DNSException) as exc:
            elapsed = (time.monotonic() - start) * 1000
            query_log.warning(
                "recv: server=%s:53 ns=%s role=%s name=%s type=%s FAILED %s=%s elapsed_ms=%.1f",
                ns_ip, ns_hostname, role, name, rrtype,
                type(exc).__name__, exc, elapsed,
            )
            raise _TransientError(
                f"{type(exc).__name__}: {exc}"
            ) from exc

        if resp.flags & dns.flags.TC:
            try:
                resp = await dns.asyncquery.tcp(
                    q, ns_ip, timeout=timeout, port=53
                )
                protocol = "UDP+TCP"
            except (dns.exception.Timeout, OSError, dns.exception.DNSException) as exc:
                elapsed = (time.monotonic() - start) * 1000
                query_log.warning(
                    "recv: server=%s:53 ns=%s role=%s name=%s type=%s "
                    "TCP-fallback FAILED %s=%s elapsed_ms=%.1f",
                    ns_ip, ns_hostname, role, name, rrtype,
                    type(exc).__name__, exc, elapsed,
                )
                raise _TransientError(
                    f"tcp: {type(exc).__name__}: {exc}"
                ) from exc

        elapsed = (time.monotonic() - start) * 1000
        rcode_value = resp.rcode()
        rcode_text = dns.rcode.to_text(rcode_value)

        if rcode_value in (dns.rcode.SERVFAIL, dns.rcode.REFUSED):
            query_log.warning(
                "recv: server=%s:53 ns=%s protocol=%s role=%s name=%s type=%s "
                "rcode=%s RETRY_NEXT_NS elapsed_ms=%.1f",
                ns_ip, ns_hostname, protocol, role, name, rrtype,
                rcode_text, elapsed,
            )
            raise _TransientError(f"rcode={rcode_text}")

        # Parse every rrset in the answer section so RRSIGs included
        # via DO=1 are preserved alongside the primary rrset.
        result: dict[str, list[str]] = {}
        for rrset in resp.answer:
            type_name = dns.rdatatype.to_text(rrset.rdtype)
            result.setdefault(type_name, []).extend(str(r) for r in rrset)
        for k in list(result):
            result[k] = sorted(set(result[k]))

        primary_count = len(result.get(rrtype, []))
        query_log.info(
            "recv: server=%s:53 ns=%s protocol=%s role=%s name=%s type=%s "
            "rcode=%s answers=%d elapsed_ms=%.1f",
            ns_ip, ns_hostname, protocol, role, name, rrtype,
            rcode_text, primary_count, elapsed,
        )
        for tname, records in result.items():
            for r in records:
                query_log.debug(
                    "answer: server=%s:53 ns=%s name=%s type=%s rdata=%s",
                    ns_ip, ns_hostname, name, tname, r,
                )
        return result

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


def _parent_zone(zone: str) -> str | None:
    """Derive the parent zone by stripping the leading label.

    Returns ``None`` for the root zone itself (no parent above root).

    >>> _parent_zone("fus3d.net")
    'net'
    >>> _parent_zone("sub.example.com")
    'example.com'
    >>> _parent_zone("net")
    '.'
    >>> _parent_zone(".") is None
    True
    """

    name = zone.rstrip(".")
    if not name or name == ".":
        return None
    if "." not in name:
        return "."
    return name.split(".", 1)[1]


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
