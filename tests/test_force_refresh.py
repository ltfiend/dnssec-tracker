"""Force-refresh coverage.

* force_sample() on a polling collector runs sample() under the lock.
* force_sample() on a streaming collector (syslog_tail) is a no-op
  and does not raise.
* force_sample() on dns_probe forces both the zone and parent probes
  even if the parent interval hasn't elapsed yet.
* POST /api/refresh iterates every collector on app.state and reports
  per-collector timing.
* The --refresh CLI hits /api/refresh on the URL it's pointed at and
  prints a useful per-collector summary.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
import urllib.request
from pathlib import Path
from threading import Thread
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from dnssec_tracker.app import create_app
from dnssec_tracker.collectors.base import Collector
from dnssec_tracker.collectors.dns_probe import DnsProbeCollector
from dnssec_tracker.collectors.state_file import StateFileCollector
from dnssec_tracker.collectors.syslog_tail import SyslogTailCollector
from dnssec_tracker.config import Config
from dnssec_tracker.db import Database
from dnssec_tracker.models import Zone


def _cfg(tmp: Path) -> Config:
    return Config(
        key_dir=tmp,
        syslog_path=None,
        named_log_path=None,
        db_path=tmp / "events.db",
    )


# ------------- polling collector -------------

class _CountingCollector(Collector):
    name = "counting"
    interval = 3600.0

    def __init__(self, cfg, db):
        super().__init__(cfg, db)
        self.samples = 0

    async def sample(self) -> None:
        self.samples += 1


def test_force_sample_runs_sample_on_polling_collector(tmp_path):
    cfg = _cfg(tmp_path)
    db = Database(cfg.db_path)
    c = _CountingCollector(cfg, db)
    asyncio.run(c.force_sample())
    asyncio.run(c.force_sample())
    assert c.samples == 2


def test_force_sample_on_streaming_collector_is_noop(tmp_path):
    cfg = _cfg(tmp_path)
    db = Database(cfg.db_path)
    # syslog_tail overrides run() and does not implement sample().
    # force_sample should swallow NotImplementedError and do nothing.
    c = SyslogTailCollector(cfg, db)
    asyncio.run(c.force_sample())  # must not raise


# ------------- dns_probe forces parent probe -------------

def test_dns_probe_force_sample_also_probes_parent(tmp_path):
    cfg = _cfg(tmp_path)
    db = Database(cfg.db_path)
    db.upsert_zone(Zone(name="example.com", key_dir=str(tmp_path)))

    col = DnsProbeCollector(cfg, db)

    zone_calls: list[str] = []
    parent_calls: list[str] = []

    async def fake_zone(zone):
        zone_calls.append(zone)

    async def fake_parent(zone):
        parent_calls.append(zone)

    col._probe_zone = fake_zone  # type: ignore[assignment]
    col._probe_parent = fake_parent  # type: ignore[assignment]

    # With last_parent_ts fresh enough that the normal gate would skip
    # the parent probe, force_sample must still run it.
    col._last_parent_ts = 10_000.0  # pretend parent was just probed
    asyncio.run(col.force_sample())

    assert zone_calls == ["example.com"]
    assert parent_calls == ["example.com"], \
        "dns_probe.force_sample must ignore the parent_interval gate"


# ------------- /api/refresh endpoint -------------

def test_api_refresh_endpoint_iterates_registered_collectors(tmp_path):
    cfg = _cfg(tmp_path)
    for k in cfg.enabled_collectors:
        cfg.enabled_collectors[k] = False
    app = create_app(cfg)

    # Inject fake collectors so we don't need the lifespan to actually
    # start anything.
    c1 = _CountingCollector(cfg, app.state.db)
    c2 = _CountingCollector(cfg, app.state.db)
    c2.name = "counting2"
    app.state.collectors.extend([c1, c2])

    with TestClient(app) as client:
        r = client.post("/api/refresh")
    assert r.status_code == 200
    data = r.json()
    assert set(data["refreshed"].keys()) == {"counting", "counting2"}
    assert all(info["ok"] for info in data["refreshed"].values())
    # Each fake collector should have been sampled exactly once by the
    # endpoint.
    assert c1.samples == 1 and c2.samples == 1


def test_api_refresh_reports_collector_errors(tmp_path):
    cfg = _cfg(tmp_path)
    for k in cfg.enabled_collectors:
        cfg.enabled_collectors[k] = False
    app = create_app(cfg)

    class _Boom(Collector):
        name = "boom"
        async def sample(self):
            raise RuntimeError("kaboom")

    app.state.collectors.append(_Boom(cfg, app.state.db))
    with TestClient(app) as client:
        r = client.post("/api/refresh")
    assert r.status_code == 200
    data = r.json()
    assert data["refreshed"]["boom"]["ok"] is False
    assert "kaboom" in data["refreshed"]["boom"]["error"]


# ------------- CLI --refresh -------------

def test_cli_refresh_prints_summary_and_returns_zero(capsys, monkeypatch):
    fake_response = json.dumps({
        "refreshed": {
            "state_file":  {"ok": True, "ms": 4.2},
            "rndc_status": {"ok": True, "ms": 120.7},
        }
    }).encode()

    class _FakeResp:
        def __init__(self, body):
            self._body = body
        def read(self):
            return self._body
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        assert req.full_url.endswith("/api/refresh")
        assert req.get_method() == "POST"
        return _FakeResp(fake_response)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    from dnssec_tracker.__main__ import main
    rc = main(["--refresh", "--url", "http://127.0.0.1:8080"])
    captured = capsys.readouterr().out
    assert rc == 0
    assert "state_file" in captured and "ok" in captured
    assert "rndc_status" in captured and "120.7" in captured


def test_cli_refresh_returns_nonzero_on_collector_failure(capsys, monkeypatch):
    fake_response = json.dumps({
        "refreshed": {
            "dns_probe": {"ok": False, "error": "RuntimeError: no resolver"},
        }
    }).encode()

    class _FakeResp:
        def __init__(self, body): self._body = body
        def read(self): return self._body
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(
        urllib.request, "urlopen",
        lambda req, timeout=None: _FakeResp(fake_response),
    )

    from dnssec_tracker.__main__ import main
    rc = main(["--refresh"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "dns_probe" in out and "FAIL" in out
