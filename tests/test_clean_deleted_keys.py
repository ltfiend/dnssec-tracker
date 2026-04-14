"""Clean deleted keys — **manual** cleanup only.

When a K*.state file disappears from disk, running the manual
``clean_deleted_keys(db, config)`` entry point (also exposed as
``POST /api/clean-deleted-keys`` and the ``--clean-deleted-keys``
CLI flag) must:

* emit ONE ``state_key_file_deleted`` summary event per vanished
  key (no flood of per-field ``(unset)`` transitions),
* drop both the ``state_file`` and ``key_file`` collector
  snapshots,
* remove the ``keys``-table row so forward-looking views
  (rollover, per-key page) stop rendering the key,

while **leaving historical events untouched** — they carry their
own zone/tag/role metadata and the event log is an append-only
record.

The *polling* collectors must never run cleanup on their own: a
momentary file disappearance during a BIND reload or an iodyn
settime race should not wipe a key's data as a side effect. An
operator triggers cleanup when they mean to.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dnssec_tracker.cleanup import clean_deleted_keys
from dnssec_tracker.collectors.key_file import KeyFileCollector
from dnssec_tracker.collectors.state_file import StateFileCollector
from dnssec_tracker.config import Config
from dnssec_tracker.db import Database


def _cfg(tmp_path: Path) -> Config:
    return Config(
        key_dir=tmp_path,
        syslog_path=None,
        named_log_path=None,
        db_path=tmp_path / "events.db",
    )


def _seed_ksk(tmp_path: Path, zone: str = "example.com", tag: int = 12345) -> Path:
    """Drop a realistic K*.state + K*.key pair in a per-zone subdir
    so the default non-recursive walk picks them up."""
    zone_dir = tmp_path / zone
    zone_dir.mkdir()
    state_path = zone_dir / f"K{zone}.+013+{tag:05d}.state"
    state_path.write_text(
        "Algorithm: 13\nKSK: yes\nZSK: no\n"
        "Generated: 20260301000000\n"
        "Published: 20260301000000\n"
        "Active: 20260307000000\n"
        "GoalState: omnipresent\n"
        "DNSKEYState: omnipresent\n"
        "DSState: omnipresent\n"
    )
    key_path = zone_dir / f"K{zone}.+013+{tag:05d}.key"
    key_path.write_text(
        f"; This is a key-signing key, keyid {tag}, for {zone}.\n"
        "; Created: 20260301000000 (Sun Mar  1 00:00:00 2026)\n"
        "; Publish: 20260301000000 (Sun Mar  1 00:00:00 2026)\n"
        "; Activate: 20260307000000 (Sat Mar  7 00:00:00 2026)\n"
        f"{zone}. 86400 IN DNSKEY 257 3 13 fakepubkey\n"
    )
    return state_path


@pytest.mark.asyncio
async def test_vanished_state_file_emits_single_summary_event(tmp_path):
    state_path = _seed_ksk(tmp_path)
    cfg = _cfg(tmp_path)
    db = Database(cfg.db_path)
    col = StateFileCollector(cfg, db)

    # First pass — key is observed and snapshotted.
    await col.sample()
    assert db.get_snapshot("state_file", "example.com#12345#KSK")
    assert [k.key_tag for k in db.list_keys("example.com")] == [12345]

    # Operator removes the .state file (and its .key friend).
    state_path.unlink()
    (state_path.parent / state_path.name.replace(".state", ".key")).unlink()

    # Manual cleanup — the explicit entry point.
    report = clean_deleted_keys(db, cfg)
    assert report.count == 1

    deletions = db.query_events(event_type="state_key_file_deleted", limit=50)
    assert len(deletions) == 1
    ev = deletions[0]
    assert ev.zone == "example.com"
    assert ev.key_tag == 12345
    assert ev.key_role == "KSK"
    assert "no longer present on disk" in ev.summary
    assert "cleaned up manually" in ev.summary
    # detail carries the last-observed state so the historical
    # record is intact.
    assert ev.detail.get("last_fields", {}).get("GoalState") == "omnipresent"
    # detail.trigger is "manual" so downstream consumers can
    # distinguish operator-triggered cleanup from any future
    # automated paths.
    assert ev.detail.get("trigger") == "manual"

    # No per-field "(unset)" spam — the whole point of collapsing.
    unset_events = [
        e for e in db.query_events(zone="example.com", limit=500)
        if e.event_type in ("state_changed", "state_timing_changed")
        and "(unset)" in e.summary
    ]
    assert unset_events == []


@pytest.mark.asyncio
async def test_polling_alone_does_NOT_clean_up(tmp_path):
    """Critical regression: the state_file collector must NOT fire
    cleanup as a side effect of polling. A momentary file
    disappearance during a BIND reload or iodyn settime race
    should not wipe a key's data."""

    state_path = _seed_ksk(tmp_path)
    cfg = _cfg(tmp_path)
    db = Database(cfg.db_path)
    col = StateFileCollector(cfg, db)

    # Seed from live files.
    await col.sample()
    assert db.get_snapshot("state_file", "example.com#12345#KSK")

    # Remove the file but don't call clean_deleted_keys.
    state_path.unlink()
    (state_path.parent / state_path.name.replace(".state", ".key")).unlink()

    # Multiple polling passes must NOT fire cleanup events or
    # touch the stored data.
    for _ in range(3):
        await col.sample()

    assert db.query_events(event_type="state_key_file_deleted") == []
    # Snapshot still holds the last-seen fields; keys row still present.
    assert db.get_snapshot("state_file", "example.com#12345#KSK")
    assert db.list_keys("example.com")


@pytest.mark.asyncio
async def test_vanished_key_snapshots_and_row_are_cleared_on_manual_cleanup(tmp_path):
    """After the summary event fires (via manual cleanup), the
    state_file snapshot, key_file snapshot, and keys-table row
    are all removed — forward-looking views stop rendering the
    key. Events stay in place."""

    state_path = _seed_ksk(tmp_path)
    cfg = _cfg(tmp_path)
    db = Database(cfg.db_path)

    state_col = StateFileCollector(cfg, db)
    key_col = KeyFileCollector(cfg, db)

    # Seed both collectors' snapshots from the live files.
    await state_col.sample()
    await key_col.sample()
    assert db.get_snapshot("state_file", "example.com#12345#KSK")
    assert db.get_snapshot("key_file", "example.com#12345#KSK")
    assert db.list_keys("example.com")

    # Remove the files — simulate operator cleanup.
    state_path.unlink()
    (state_path.parent / state_path.name.replace(".state", ".key")).unlink()

    # Manual trigger.
    report = clean_deleted_keys(db, cfg)
    assert report.count == 1

    # All three stores are clean for this key.
    assert db.get_snapshot("state_file", "example.com#12345#KSK") == {}
    assert db.get_snapshot("key_file", "example.com#12345#KSK") == {}
    assert db.list_keys("example.com") == []


@pytest.mark.asyncio
async def test_historical_events_survive_the_cleanup(tmp_path):
    """When the cleanup fires we delete snapshots and the keys row,
    but events from earlier observations MUST still be queryable —
    the event log is the historical record."""

    state_path = _seed_ksk(tmp_path)
    cfg = _cfg(tmp_path)
    db = Database(cfg.db_path)
    col = StateFileCollector(cfg, db)
    await col.sample()

    # Baseline: first-sighting event was emitted.
    baseline = db.query_events(
        zone="example.com", event_type="state_key_observed",
    )
    assert len(baseline) == 1

    # Remove the file, then manual cleanup.
    state_path.unlink()
    (state_path.parent / state_path.name.replace(".state", ".key")).unlink()
    clean_deleted_keys(db, cfg)

    # The first-sighting event is still queryable.
    preserved = db.query_events(
        zone="example.com", event_type="state_key_observed",
    )
    assert len(preserved) == 1
    assert preserved[0].key_tag == 12345


@pytest.mark.asyncio
async def test_cleanup_on_empty_db_is_a_no_op(tmp_path):
    """First run of cleanup on a fresh install: nothing to clean,
    report.count == 0, no events emitted."""
    _seed_ksk(tmp_path)
    cfg = _cfg(tmp_path)
    db = Database(cfg.db_path)
    report = clean_deleted_keys(db, cfg)
    assert report.count == 0
    assert db.query_events(event_type="state_key_file_deleted") == []


@pytest.mark.asyncio
async def test_cleanup_is_idempotent(tmp_path):
    """Running cleanup twice in a row with nothing new vanished
    in between must fire no additional events on the second run."""
    state_path = _seed_ksk(tmp_path)
    cfg = _cfg(tmp_path)
    db = Database(cfg.db_path)
    col = StateFileCollector(cfg, db)
    await col.sample()

    state_path.unlink()
    (state_path.parent / state_path.name.replace(".state", ".key")).unlink()

    r1 = clean_deleted_keys(db, cfg)
    r2 = clean_deleted_keys(db, cfg)
    assert r1.count == 1
    assert r2.count == 0
    # Only one event emitted total.
    assert len(db.query_events(event_type="state_key_file_deleted")) == 1


@pytest.mark.asyncio
async def test_multiple_vanished_keys_each_get_their_own_summary(tmp_path):
    _seed_ksk(tmp_path, tag=11111)
    _seed_ksk(tmp_path, zone="another.example", tag=22222)
    cfg = _cfg(tmp_path)
    db = Database(cfg.db_path)
    col = StateFileCollector(cfg, db)
    await col.sample()

    # Remove everything for both zones.
    for z in ("example.com", "another.example"):
        zone_dir = tmp_path / z
        for p in zone_dir.iterdir():
            p.unlink()
        zone_dir.rmdir()

    report = clean_deleted_keys(db, cfg)
    assert report.count == 2
    deletions = db.query_events(event_type="state_key_file_deleted", limit=50)
    tags = sorted(e.key_tag for e in deletions)
    assert tags == [11111, 22222]


# ---- HTTP endpoint ----------------------------------------------


@pytest.mark.asyncio
async def test_api_clean_deleted_keys_endpoint(tmp_path):
    from fastapi.testclient import TestClient
    from dnssec_tracker.app import create_app

    state_path = _seed_ksk(tmp_path)
    cfg = _cfg(tmp_path)
    for k in cfg.enabled_collectors:
        cfg.enabled_collectors[k] = False
    app = create_app(cfg)

    # Seed via the same collector the live app uses.
    state_col = StateFileCollector(cfg, app.state.db)
    await state_col.sample()

    # Remove the files.
    state_path.unlink()
    (state_path.parent / state_path.name.replace(".state", ".key")).unlink()

    with TestClient(app) as client:
        r = client.post("/api/clean-deleted-keys")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 1
    assert body["cleaned"][0]["zone"] == "example.com"
    assert body["cleaned"][0]["key_tag"] == 12345
    assert body["cleaned"][0]["role"] == "KSK"
    assert body["prior_scopes"] == 1
    assert body["live_scopes"] == 0


# ---- CLI ---------------------------------------------------------


def test_cli_clean_deleted_keys_prints_summary(capsys, monkeypatch):
    """The ``dnssec-tracker --clean-deleted-keys`` CLI flag POSTs to
    the running instance's /api/clean-deleted-keys endpoint and
    prints a readable summary."""
    import json as _json
    import urllib.request

    fake_response = _json.dumps({
        "cleaned": [
            {"zone": "example.com", "key_tag": 12345, "role": "KSK",
             "last_path": "/etc/bind/keys/example.com/K....state",
             "last_fields": {}},
            {"zone": "other.example", "key_tag": 67890, "role": "ZSK",
             "last_path": None, "last_fields": {}},
        ],
        "count": 2,
        "live_scopes": 5,
        "prior_scopes": 7,
    }).encode()

    class _FakeResp:
        def __init__(self, body): self._body = body
        def read(self): return self._body
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_urlopen(req, timeout=None):
        assert req.full_url.endswith("/api/clean-deleted-keys")
        assert req.get_method() == "POST"
        return _FakeResp(fake_response)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    from dnssec_tracker.__main__ import main
    rc = main(["--clean-deleted-keys", "--url", "http://127.0.0.1:8080"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "scopes on disk now:    5" in out
    assert "scopes previously seen: 7" in out
    assert "cleaned: 2 key(s):" in out
    assert "example.com KSK tag=12345" in out
    assert "other.example ZSK tag=67890" in out


def test_cli_clean_deleted_keys_no_op_friendly_output(capsys, monkeypatch):
    """When nothing's to clean up, the CLI prints a friendly
    no-op message rather than staying silent."""
    import json as _json
    import urllib.request

    fake_response = _json.dumps({
        "cleaned": [],
        "count": 0,
        "live_scopes": 3,
        "prior_scopes": 3,
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
    rc = main(["--clean-deleted-keys"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "no keys needed cleanup" in out
