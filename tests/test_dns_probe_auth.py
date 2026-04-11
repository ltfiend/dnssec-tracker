"""Authoritative-query behaviour tests for DnsProbeCollector.

These test the new path introduced when we moved off the recursor:

* ``_parent_zone`` derivation for real hierarchies.
* ``_get_authoritative_ns`` resolves NS names + A records via the
  recursor and caches the result.
* ``_auth_query`` walks the NS list in order and accepts the first
  clean response, retrying past SERVFAIL / REFUSED / timeouts.
* ``_probe_zone`` and ``_probe_parent`` end-to-end against the mocked
  ``dns.asyncquery.udp`` boundary.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

import dns.exception
import dns.flags
import dns.rcode
import dns.rdatatype

from dnssec_tracker.collectors.dns_probe import (
    DnsProbeCollector,
    _parent_zone,
    _TransientError,
)
from dnssec_tracker.config import Config
from dnssec_tracker.db import Database
from dnssec_tracker.models import Zone


def _cfg(tmp_path: Path) -> Config:
    return Config(
        key_dir=tmp_path,
        syslog_path=None,
        named_log_path=None,
        db_path=tmp_path / "events.db",
        local_resolver="127.0.0.1:53",
        query_timeout=5,
    )


class _FakeRRset:
    def __init__(self, rdtype_text: str, rdata: list[str]):
        self.rdtype = dns.rdatatype.from_text(rdtype_text)
        self._rdata = rdata

    def __iter__(self):
        return iter(self._rdata)


def _fake_response(answer_rrsets, rcode=dns.rcode.NOERROR, tc=False):
    return SimpleNamespace(
        rcode=lambda rc=rcode: rc,
        flags=(dns.flags.TC if tc else 0),
        answer=list(answer_rrsets),
    )


# ---- parent zone derivation --------------------------------------


def test_parent_zone_derivation():
    assert _parent_zone("fus3d.net") == "net"
    assert _parent_zone("sub.example.com") == "example.com"
    assert _parent_zone("example.com") == "com"
    assert _parent_zone("net") == "."
    assert _parent_zone("com") == "."
    assert _parent_zone(".") is None
    assert _parent_zone("") is None


# ---- NS discovery ------------------------------------------------


def _fake_ns_answer(ns_names: list[str]):
    """Build a fake dnspython Answer-like object for an NS rrset."""

    class _R:
        def __init__(self, name):
            self.target = name + "."

    class _Rrset(list):
        pass

    return SimpleNamespace(rrset=_Rrset([_R(n) for n in ns_names]))


def _fake_a_answer(addrs: list[str]):
    class _R:
        def __init__(self, a):
            self.address = a

    class _Rrset(list):
        pass

    return SimpleNamespace(rrset=_Rrset([_R(a) for a in addrs]))


@pytest.mark.asyncio
async def test_get_authoritative_ns_resolves_and_caches(tmp_path):
    col = DnsProbeCollector(_cfg(tmp_path), Database(tmp_path / "events.db"))

    resolve_calls: list[tuple[str, str]] = []

    async def fake_resolve(name, rrtype, raise_on_no_answer=False):
        resolve_calls.append((name, rrtype))
        if rrtype == "NS":
            return _fake_ns_answer(["ns1.example.com", "ns2.example.com"])
        if rrtype == "A":
            return _fake_a_answer([{"ns1.example.com": "192.0.2.10",
                                     "ns2.example.com": "192.0.2.11"}[name]])
        raise AssertionError(f"unexpected rrtype: {rrtype}")

    col._recursor.resolve = fake_resolve

    result = await col._get_authoritative_ns("example.com")
    assert result == [
        ("192.0.2.10", "ns1.example.com"),
        ("192.0.2.11", "ns2.example.com"),
    ]
    assert ("example.com", "NS") in resolve_calls
    assert ("ns1.example.com", "A") in resolve_calls
    assert ("ns2.example.com", "A") in resolve_calls

    # Second call must be served from cache — zero new recursor calls.
    before = len(resolve_calls)
    again = await col._get_authoritative_ns("example.com")
    assert again == result
    assert len(resolve_calls) == before


@pytest.mark.asyncio
async def test_get_authoritative_ns_negative_cached_on_failure(tmp_path):
    col = DnsProbeCollector(_cfg(tmp_path), Database(tmp_path / "events.db"))

    async def boom(name, rrtype, raise_on_no_answer=False):
        raise dns.exception.Timeout("recursor unreachable")

    col._recursor.resolve = boom
    result = await col._get_authoritative_ns("example.com")
    assert result == []

    # Cached negative result: a second call does not re-raise and
    # returns empty without invoking the recursor again.
    count = {"n": 0}

    async def count_calls(name, rrtype, raise_on_no_answer=False):
        count["n"] += 1
        raise dns.exception.Timeout("recursor unreachable")

    col._recursor.resolve = count_calls
    again = await col._get_authoritative_ns("example.com")
    assert again == []
    assert count["n"] == 0  # served from negative cache


# ---- _auth_query multi-NS fallback --------------------------------


@pytest.mark.asyncio
async def test_auth_query_returns_first_good_ns(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="dnssec_tracker.query.dns")
    col = DnsProbeCollector(_cfg(tmp_path), Database(tmp_path / "events.db"))

    ns_list = [
        ("192.0.2.10", "ns1.example.com"),
        ("192.0.2.11", "ns2.example.com"),
    ]
    # Route UDP queries by server IP: ns1 SERVFAILs, ns2 returns a good DS.
    good = _fake_response(
        [_FakeRRset("DS", ["12345 13 2 aabbccdd"])],
    )
    servfail = _fake_response([], rcode=dns.rcode.SERVFAIL)

    async def fake_udp(q, where, *, timeout, port):
        return servfail if where == "192.0.2.10" else good

    with patch("dns.asyncquery.udp", side_effect=fake_udp):
        result = await col._auth_query(
            ns_list, "fus3d.net", "DS", role="parent"
        )
    assert result["DS"] == ["12345 13 2 aabbccdd"]

    # Both NS should appear in the INFO log — ns1 with SERVFAIL, ns2
    # with the successful recv.
    msgs = [r.getMessage() for r in caplog.records
            if r.name == "dnssec_tracker.query.dns"]
    assert any("ns=ns1.example.com" in m and "SERVFAIL" in m for m in msgs)
    assert any("ns=ns2.example.com" in m and "NOERROR" in m for m in msgs)


@pytest.mark.asyncio
async def test_auth_query_returns_empty_when_every_ns_fails(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="dnssec_tracker.query.dns")
    col = DnsProbeCollector(_cfg(tmp_path), Database(tmp_path / "events.db"))

    ns_list = [
        ("192.0.2.10", "ns1.example.com"),
        ("192.0.2.11", "ns2.example.com"),
    ]

    async def fake_udp(q, where, *, timeout, port):
        raise dns.exception.Timeout("no response")

    with patch("dns.asyncquery.udp", side_effect=fake_udp):
        result = await col._auth_query(
            ns_list, "fus3d.net", "DS", role="parent",
        )
    assert result == {}

    warnings = [r for r in caplog.records
                if r.name == "dnssec_tracker.query.dns" and r.levelname == "WARNING"]
    assert any("all authoritative NS failed" in r.getMessage() for r in warnings)


# ---- full probe path ---------------------------------------------


@pytest.mark.asyncio
async def test_probe_parent_queries_parent_ns_for_ds(tmp_path):
    """End-to-end: calling _probe_parent('fus3d.net') must

    1. derive the parent zone as "net",
    2. resolve the parent NS via the recursor,
    3. send a DS query for fus3d.net to one of those NS,
    4. store the resulting snapshot in collector_state.
    """

    cfg = _cfg(tmp_path)
    db = Database(cfg.db_path)
    db.upsert_zone(Zone(name="fus3d.net", key_dir=str(tmp_path)))

    col = DnsProbeCollector(cfg, db)

    async def fake_resolve(name, rrtype, raise_on_no_answer=False):
        # Parent NS discovery: we expect an NS query for "net" and
        # A queries for each TLD nameserver.
        if name == "net" and rrtype == "NS":
            return _fake_ns_answer(["a.gtld-servers.net", "b.gtld-servers.net"])
        if name == "a.gtld-servers.net" and rrtype == "A":
            return _fake_a_answer(["192.5.6.30"])
        if name == "b.gtld-servers.net" and rrtype == "A":
            return _fake_a_answer(["192.33.14.30"])
        raise AssertionError(f"unexpected recursor call: {name} {rrtype}")

    col._recursor.resolve = fake_resolve

    udp_calls: list[tuple[str, str]] = []

    async def fake_udp(q, where, *, timeout, port):
        udp_calls.append((where, dns.rdatatype.to_text(q.question[0].rdtype)))
        return _fake_response([
            _FakeRRset("DS", ["19463 13 2 9e6c7a4d64e0a8b5bdfd1ed4bb6f3e9b"])
        ])

    with patch("dns.asyncquery.udp", side_effect=fake_udp):
        await col._probe_parent("fus3d.net")

    # The tracker must have aimed its DS query at one of the two
    # mocked parent NS IPs, not at the local recursor.
    assert len(udp_calls) == 1
    server_ip, qtype = udp_calls[0]
    assert server_ip in ("192.5.6.30", "192.33.14.30")
    assert qtype == "DS"

    # And the resulting snapshot is persisted on the parent: scope.
    snap = db.get_snapshot("dns_probe", "parent:fus3d.net")
    assert snap == {"DS": ["19463 13 2 9e6c7a4d64e0a8b5bdfd1ed4bb6f3e9b"]}


@pytest.mark.asyncio
async def test_probe_zone_collects_rrsigs_from_dnskey_response(tmp_path):
    """DO=1 means DNSKEY responses carry the RRSIGs over DNSKEY in
    the same answer section, so _probe_zone should accumulate them
    into the RRSIG bucket of the zone snapshot."""

    cfg = _cfg(tmp_path)
    db = Database(cfg.db_path)
    db.upsert_zone(Zone(name="example.com", key_dir=str(tmp_path)))
    col = DnsProbeCollector(cfg, db)

    async def fake_resolve(name, rrtype, raise_on_no_answer=False):
        if name == "example.com" and rrtype == "NS":
            return _fake_ns_answer(["ns1.example.com"])
        if name == "ns1.example.com" and rrtype == "A":
            return _fake_a_answer(["192.0.2.10"])
        raise AssertionError(f"unexpected {name}/{rrtype}")

    col._recursor.resolve = fake_resolve

    dnskey_resp = _fake_response([
        _FakeRRset("DNSKEY", ["257 3 13 ksk-base64", "256 3 13 zsk-base64"]),
        _FakeRRset(
            "RRSIG",
            ["DNSKEY 13 2 86400 20260501000000 20260401000000 "
             "19463 example.com. sigAbCdEf=="],
        ),
    ])
    soa_resp = _fake_response([
        _FakeRRset("SOA",
                   ["ns1.example.com. admin.example.com. 2026041001 "
                    "7200 3600 1209600 86400"]),
    ])
    empty_resp = _fake_response([])

    def dispatcher(q, where, *, timeout, port):
        qtype = dns.rdatatype.to_text(q.question[0].rdtype)
        if qtype == "DNSKEY":
            return dnskey_resp
        if qtype == "SOA":
            return soa_resp
        return empty_resp

    with patch("dns.asyncquery.udp", AsyncMock(side_effect=dispatcher)):
        await col._probe_zone("example.com")

    snap = db.get_snapshot("dns_probe", "zone:example.com")
    assert snap["DNSKEY"] == sorted(["257 3 13 ksk-base64", "256 3 13 zsk-base64"])
    assert snap["RRSIG"] and "19463 example.com" in snap["RRSIG"][0]
    assert snap["SOA"] == [
        "ns1.example.com. admin.example.com. 2026041001 7200 3600 1209600 86400"
    ]
    # CDS and CDNSKEY were queried and got empty responses — they
    # should appear in the snapshot as empty lists so the diff logic
    # can tell "not yet observed" apart from "actively empty".
    assert snap["CDS"] == []
    assert snap["CDNSKEY"] == []
