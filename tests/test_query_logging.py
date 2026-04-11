"""Verify that every active probe logs its send/recv pair at INFO
level with the server IP, query name, qtype, protocol, and (on
receive) the rcode, answer count, and elapsed time.

The DNS probe is exercised by patching out the real resolver so we
don't hit the network; the rndc exec is exercised by patching
``asyncio.create_subprocess_exec``.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dnssec_tracker.collectors.dns_probe import DnsProbeCollector
from dnssec_tracker.collectors.rndc_status import RndcStatusCollector
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


def _at_info(caplog, logger_name: str) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == logger_name and r.levelno == logging.INFO
    ]


# ---- dns_probe -----------------------------------------------------

class _FakeRRset(list):
    """Minimal RRset: behaves like a list of str."""


class _FakeAnswer:
    def __init__(self, rrset, rcode_text="NOERROR", tc=False):
        import dns.flags
        import dns.rcode
        self.rrset = rrset
        # Build just enough of a response to let the collector pull
        # rcode via ans.response.rcode() and ans.response.flags & TC.
        rcode_value = {"NOERROR": 0, "NXDOMAIN": 3}.get(rcode_text, 0)
        self.response = SimpleNamespace(
            rcode=lambda rc=rcode_value: rc,
            flags=(dns.flags.TC if tc else 0),
        )


def _make_resolver_answer(records, rcode="NOERROR", tc=False):
    return _FakeAnswer(_FakeRRset(records), rcode_text=rcode, tc=tc)


@pytest.mark.asyncio
async def test_dns_probe_logs_zone_query(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="dnssec_tracker.query.dns")

    col = DnsProbeCollector(_cfg(tmp_path), Database(tmp_path / "events.db"))
    col._resolver.resolve = AsyncMock(
        return_value=_make_resolver_answer(["257 3 13 fake"])
    )

    result = await col._query_rrset("example.com", "DNSKEY", role="zone")
    assert result == ["257 3 13 fake"]

    msgs = _at_info(caplog, "dnssec_tracker.query.dns")
    assert len(msgs) == 2, f"expected send+recv, got {msgs}"
    send, recv = msgs

    # "send" line
    assert "send:" in send
    assert "server=127.0.0.1:53" in send
    assert "protocol=UDP" in send
    assert "role=zone" in send
    assert "name=example.com" in send
    assert "type=DNSKEY" in send
    assert "timeout=5.0s" in send

    # "recv" line
    assert "recv:" in recv
    assert "server=127.0.0.1:53" in recv
    assert "role=zone" in recv
    assert "name=example.com" in recv
    assert "type=DNSKEY" in recv
    assert "rcode=NOERROR" in recv
    assert "answers=1" in recv
    assert "elapsed_ms=" in recv


@pytest.mark.asyncio
async def test_dns_probe_logs_parent_ds_query_with_role_parent(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="dnssec_tracker.query.dns")

    cfg = _cfg(tmp_path)
    db = Database(cfg.db_path)
    db.upsert_zone(Zone(name="example.com", key_dir=str(tmp_path)))

    col = DnsProbeCollector(cfg, db)
    col._resolver.resolve = AsyncMock(
        return_value=_make_resolver_answer(
            ["12345 13 2 9e6c7a4d64e0a8b5bdfd1ed4bb6f3e9b"]
        )
    )

    await col._probe_parent("example.com")

    msgs = _at_info(caplog, "dnssec_tracker.query.dns")
    # One send + one recv for the single DS query.
    assert len(msgs) == 2
    send, recv = msgs
    assert "role=parent" in send
    assert "name=example.com" in send
    assert "type=DS" in send
    assert "role=parent" in recv
    assert "rcode=NOERROR" in recv
    assert "answers=1" in recv


@pytest.mark.asyncio
async def test_dns_probe_logs_failure_at_warning(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="dnssec_tracker.query.dns")

    import dns.exception
    col = DnsProbeCollector(_cfg(tmp_path), Database(tmp_path / "events.db"))
    col._resolver.resolve = AsyncMock(
        side_effect=dns.exception.Timeout("no response")
    )
    result = await col._query_rrset("example.com", "DNSKEY", role="zone")
    assert result == []

    # The send line is INFO, the failure is WARNING; both should be
    # captured by caplog at INFO+ level.
    records = [
        r for r in caplog.records
        if r.name == "dnssec_tracker.query.dns"
    ]
    levels = [r.levelname for r in records]
    assert "INFO" in levels
    assert "WARNING" in levels
    failure = [r for r in records if r.levelname == "WARNING"][0]
    assert "FAILED" in failure.getMessage()
    assert "Timeout" in failure.getMessage()


@pytest.mark.asyncio
async def test_dns_probe_logs_tc_upgrade_protocol_tag(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="dnssec_tracker.query.dns")

    col = DnsProbeCollector(_cfg(tmp_path), Database(tmp_path / "events.db"))
    col._resolver.resolve = AsyncMock(
        return_value=_make_resolver_answer(["fake"], tc=True)
    )
    await col._query_rrset("example.com", "DNSKEY", role="zone")

    recv = [
        r.getMessage()
        for r in caplog.records
        if r.name == "dnssec_tracker.query.dns"
        and "recv:" in r.getMessage()
    ][-1]
    # A truncated response means we know a TCP retry happened.
    assert "protocol=UDP+TCP" in recv


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

    # send: full argv with all rndc flags
    assert "send:" in send
    assert "zone=example.com" in send
    assert "server=127.0.0.1:953" in send
    assert "/usr/sbin/rndc" in send
    assert "-k /mnt/bind/rndc.key" in send
    assert "-s 127.0.0.1" in send
    assert "-p 953" in send
    assert "dnssec -status example.com" in send

    # recv: rc + byte counts + elapsed
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
