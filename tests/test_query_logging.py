"""Verify that every active probe logs its send/recv pair at INFO
level with the server IP, query name, qtype, protocol, and (on
receive) the rcode, answer count, and elapsed time.

The DNS probe is exercised via the low-level ``_query_one`` helper
with a patched ``dns.asyncquery.udp`` so we don't hit the network.
The rndc exec is exercised by patching ``asyncio.create_subprocess_exec``.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

import dns.flags
import dns.rcode
import dns.rdatatype

from dnssec_tracker.collectors.dns_probe import (
    DnsProbeCollector,
    _TransientError,
)
from dnssec_tracker.collectors.rndc_status import RndcStatusCollector
from dnssec_tracker.config import Config
from dnssec_tracker.db import Database


def _cfg(tmp_path: Path) -> Config:
    return Config(
        key_dir=tmp_path,
        syslog_path=None,
        named_log_path=None,
        db_path=tmp_path / "events.db",
        local_resolver="127.0.0.1:53",
        query_timeout=5,
    )


def _at_info(caplog, logger_name: str) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == logger_name and r.levelno == logging.INFO
    ]


# ---- fake DNS response helpers -----------------------------------


class _FakeRRset:
    """Tiny RRset stand-in for building fake ``dns.message`` answers.

    Matches the attributes ``_query_one`` reads: ``rdtype`` and
    iteration yielding string-convertible rdata.
    """

    def __init__(self, rdtype_text: str, rdata: list[str]):
        self.rdtype = dns.rdatatype.from_text(rdtype_text)
        self._rdata = rdata

    def __iter__(self):
        return iter(self._rdata)


def _fake_response(
    answer_rrsets: list[_FakeRRset],
    rcode: int = dns.rcode.NOERROR,
    tc: bool = False,
) -> SimpleNamespace:
    return SimpleNamespace(
        rcode=lambda rc=rcode: rc,
        flags=(dns.flags.TC if tc else 0),
        answer=answer_rrsets,
    )


# ---- dns_probe ---------------------------------------------------


@pytest.mark.asyncio
async def test_query_one_logs_send_and_recv(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="dnssec_tracker.query.dns")
    col = DnsProbeCollector(_cfg(tmp_path), Database(tmp_path / "events.db"))

    resp = _fake_response([_FakeRRset("DNSKEY", ["257 3 13 fakepk"])])
    with patch("dns.asyncquery.udp", AsyncMock(return_value=resp)) as udp:
        result = await col._query_one(
            "192.0.2.10", "ns1.example.com",
            "example.com", "DNSKEY", role="zone",
        )

    # The low-level query was aimed at the exact NS IP.
    udp.assert_called_once()
    assert udp.call_args.args[1] == "192.0.2.10"
    assert result["DNSKEY"] == ["257 3 13 fakepk"]

    msgs = _at_info(caplog, "dnssec_tracker.query.dns")
    assert len(msgs) == 2
    send, recv = msgs
    # Both lines must carry the auth NS IP and hostname so a single
    # grep tells you exactly which server answered which query.
    assert "server=192.0.2.10:53" in send
    assert "ns=ns1.example.com" in send
    assert "protocol=UDP" in send
    assert "role=zone" in send
    assert "name=example.com" in send
    assert "type=DNSKEY" in send
    assert "server=192.0.2.10:53" in recv
    assert "ns=ns1.example.com" in recv
    assert "rcode=NOERROR" in recv
    assert "answers=1" in recv


@pytest.mark.asyncio
async def test_query_one_upgrades_protocol_on_tc_fallback(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="dnssec_tracker.query.dns")
    col = DnsProbeCollector(_cfg(tmp_path), Database(tmp_path / "events.db"))

    udp_resp = _fake_response([_FakeRRset("DNSKEY", [])], tc=True)
    tcp_resp = _fake_response([_FakeRRset("DNSKEY", ["257 3 13 fakepk"])])
    with patch("dns.asyncquery.udp", AsyncMock(return_value=udp_resp)), \
         patch("dns.asyncquery.tcp", AsyncMock(return_value=tcp_resp)):
        await col._query_one(
            "192.0.2.10", "ns1.example.com",
            "example.com", "DNSKEY", role="zone",
        )

    recv = [m for m in _at_info(caplog, "dnssec_tracker.query.dns") if "recv:" in m][-1]
    assert "protocol=UDP+TCP" in recv


@pytest.mark.asyncio
async def test_query_one_raises_transient_on_servfail(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="dnssec_tracker.query.dns")
    col = DnsProbeCollector(_cfg(tmp_path), Database(tmp_path / "events.db"))

    resp = _fake_response([], rcode=dns.rcode.SERVFAIL)
    with patch("dns.asyncquery.udp", AsyncMock(return_value=resp)):
        with pytest.raises(_TransientError):
            await col._query_one(
                "192.0.2.10", "ns1.example.com",
                "example.com", "DNSKEY", role="zone",
            )

    records = [
        r for r in caplog.records
        if r.name == "dnssec_tracker.query.dns"
    ]
    warnings = [r for r in records if r.levelname == "WARNING"]
    assert warnings
    assert "rcode=SERVFAIL" in warnings[-1].getMessage()
    assert "RETRY_NEXT_NS" in warnings[-1].getMessage()


@pytest.mark.asyncio
async def test_query_one_raises_transient_on_timeout(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="dnssec_tracker.query.dns")
    col = DnsProbeCollector(_cfg(tmp_path), Database(tmp_path / "events.db"))

    import dns.exception
    with patch(
        "dns.asyncquery.udp",
        AsyncMock(side_effect=dns.exception.Timeout("no response")),
    ):
        with pytest.raises(_TransientError):
            await col._query_one(
                "192.0.2.10", "ns1.example.com",
                "example.com", "DNSKEY", role="zone",
            )

    warnings = [
        r for r in caplog.records
        if r.name == "dnssec_tracker.query.dns" and r.levelname == "WARNING"
    ]
    assert any("Timeout" in r.getMessage() for r in warnings)


# ---- rndc_status ---------------------------------------------------


class _FakeProc:
    def __init__(self, stdout: bytes, stderr: bytes = b"", rc: int = 0):
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = rc

    async def communicate(self):
        return self._stdout, self._stderr


@pytest.mark.asyncio
async def test_rndc_status_logs_exec_command_and_result(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="dnssec_tracker.query.rndc")

    cfg = _cfg(tmp_path)
    cfg.rndc_bin = "/usr/sbin/rndc"
    cfg.rndc_server = "127.0.0.1:953"
    cfg.rndc_key_file = Path("/mnt/bind/rndc.key")

    db = Database(cfg.db_path)
    col = RndcStatusCollector(cfg, db)

    fake_stdout = b"dnssec-policy: default\nkey: 12345 (ECDSAP256SHA256), KSK\n"
    fake_proc = _FakeProc(fake_stdout, b"", 0)

    async def _fake_exec(*args, **kwargs):
        return fake_proc

    with patch("asyncio.create_subprocess_exec", side_effect=_fake_exec):
        out = await col._run_rndc("example.com")
    assert out.startswith("dnssec-policy")

    msgs = _at_info(caplog, "dnssec_tracker.query.rndc")
    assert len(msgs) == 2, f"expected send+recv, got {msgs}"
    send, recv = msgs
    assert "send:" in send
    assert "zone=example.com" in send
    assert "server=127.0.0.1:953" in send
    assert "/usr/sbin/rndc" in send
    assert "-k /mnt/bind/rndc.key" in send
    assert "-s 127.0.0.1" in send
    assert "-p 953" in send
    assert "dnssec -status example.com" in send
    assert "recv:" in recv
    assert "rc=0" in recv
    assert f"stdout_bytes={len(fake_stdout)}" in recv
    assert "elapsed_ms=" in recv


@pytest.mark.asyncio
async def test_rndc_status_logs_failure_at_warning(tmp_path, caplog):
    from dnssec_tracker.collectors.rndc_status import RndcError
    caplog.set_level(logging.INFO, logger="dnssec_tracker.query.rndc")

    cfg = _cfg(tmp_path)
    cfg.rndc_bin = "/usr/sbin/rndc"
    cfg.rndc_server = "127.0.0.1:953"

    db = Database(cfg.db_path)
    col = RndcStatusCollector(cfg, db)

    fake_proc = _FakeProc(b"", b"rndc: connection refused", rc=1)

    async def _fake_exec(*args, **kwargs):
        return fake_proc

    with patch("asyncio.create_subprocess_exec", side_effect=_fake_exec):
        with pytest.raises(RndcError):
            await col._run_rndc("example.com")

    records = [
        r for r in caplog.records
        if r.name == "dnssec_tracker.query.rndc"
    ]
    warnings = [r for r in records if r.levelname == "WARNING"]
    assert warnings, "rndc failure should log at WARNING"
    msg = warnings[0].getMessage()
    assert "rc=1" in msg
    assert "connection refused" in msg
