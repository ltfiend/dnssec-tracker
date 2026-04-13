"""End-to-end wiring test for the overdue-key warning.

Seeds a DB with a KSK whose scheduled Delete is in the past AND whose
DNSKEY is still observed at the zone apex via the dns_probe snapshot.
Verifies the warning banner renders on /zones/{zone},
/zones/{zone}/keys/{tag}, and in the HTML report, and that the
rollover view's past-deletion-date bar carries the
`phase-lingering` class so the alarming red treatment kicks in.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dnssec_tracker.app import create_app
from dnssec_tracker.config import Config
from dnssec_tracker.db import Database
from dnssec_tracker.models import Event, Key, Zone
from dnssec_tracker.render.html_export import render_report_html


# Real ECDSA P-256 DNSKEY with a known tag (see test_dns_probe_events).
_DNSKEY_PUB = (
    "oJMRESz5E4gYzS35AJulupX0kDyQjM+9GsGZu6XW7A7m"
    "f2HxS/zV0SCNvyx8rDSb8CAW0Q9D2JVv9ZQvkLIc9g=="
)
KSK_DNSKEY = f"257 3 13 {_DNSKEY_PUB}"
KSK_TAG = 19463
KSK_DS = f"{KSK_TAG} 13 2 9e6c7a4d64e0a8b5bdfd1ed4bb6f3e9b"


@pytest.fixture
def seeded(tmp_path: Path):
    cfg = Config(
        key_dir=tmp_path,
        syslog_path=None,
        named_log_path=None,
        db_path=tmp_path / "events.db",
    )
    for k in cfg.enabled_collectors:
        cfg.enabled_collectors[k] = False
    app = create_app(cfg)
    db = app.state.db

    db.upsert_zone(Zone(name="example.com", key_dir=str(tmp_path)))
    db.upsert_key(Key(
        zone="example.com", key_tag=KSK_TAG, role="KSK",
        algorithm=13, key_id=f"Kexample.com.+013+{KSK_TAG:05d}",
    ))

    # State file: only Generated set (BIND hasn't recorded actual
    # Removed — the key is overdue precisely because BIND hasn't
    # caught up).
    db.set_snapshot(
        "state_file",
        f"example.com#{KSK_TAG}#KSK",
        {
            "fields": {
                "Generated": "20250101000000",
                "KSK": "yes", "ZSK": "no",
                "GoalState": "omnipresent",
                "DNSKEYState": "omnipresent",
                "DSState": "omnipresent",
            }
        },
    )
    # Key file: scheduled Delete was March 2025 — long past anything
    # the test can reasonably choose as "now".
    db.set_snapshot(
        "key_file",
        f"example.com#{KSK_TAG}#KSK",
        {
            "timings": {
                "Created":  "20250101000000",
                "Publish":  "20250101000000",
                "Activate": "20250107000000",
                "Inactive": "20250301000000",
                "Delete":   "20250308000000",
            }
        },
    )
    # dns_probe still observes the DNSKEY at the zone — this is the
    # whole reason the key qualifies as "lingering".
    db.set_snapshot(
        "dns_probe",
        "zone:example.com",
        {"DNSKEY": [KSK_DNSKEY], "SOA": [], "CDS": [], "CDNSKEY": [], "RRSIG": []},
    )
    # And the DS is still at the parent too.
    db.set_snapshot(
        "dns_probe",
        "parent:example.com",
        {"DS": [KSK_DS]},
    )
    # Drop a seed event so the other templates have something to show.
    db.insert_event(Event(
        ts="2025-01-01T00:00:00Z", source="state",
        event_type="state_key_observed",
        summary="KSK tag 19463 observed",
        zone="example.com", key_tag=KSK_TAG, key_role="KSK",
    ))

    return app, db, cfg


def test_zone_page_shows_warning_banner_for_lingering_key(seeded):
    app, _db, _cfg = seeded
    with TestClient(app) as client:
        r = client.get("/zones/example.com")
    assert r.status_code == 200
    body = r.text
    assert "warning-banner" in body
    assert "past scheduled Delete but still observed" in body
    # Both sides observed → BOTH_LINGERING summary.
    assert "DNSKEY at zone AND DS at parent" in body
    # The overdue-key link in the banner points at the per-key page.
    assert f'/zones/example.com/keys/{KSK_TAG}' in body


def test_zone_rollover_bar_marks_lingering_phase(seeded):
    app, _db, _cfg = seeded
    with TestClient(app) as client:
        body = client.get("/zones/example.com").text
    # The rollover renderer flags the past-deletion-date segment with
    # the phase-lingering class when overdue_by_tag is set.
    assert "phase-lingering" in body
    assert 'data-lingering=' in body
    # The label switches from "past deletion date" to OVERDUE-style text.
    assert "OVERDUE" in body


def test_key_page_shows_warning_banner_for_lingering_key(seeded):
    app, _db, _cfg = seeded
    with TestClient(app) as client:
        body = client.get(f"/zones/example.com/keys/{KSK_TAG}").text
    assert "warning-banner" in body
    assert "past its scheduled Delete but still observed" in body


def test_report_renders_overdue_banner_and_lingering_svg(seeded):
    _app, db, cfg = seeded
    html = render_report_html(db, cfg, "example.com")
    assert "warning-banner" in html
    assert "past scheduled Delete but still observed" in html
    # The rollover SVG inside the report carries the lingering marker.
    assert "phase-lingering" in html


def test_clean_zone_without_overdue_keys_shows_no_banner(tmp_path):
    """Inverse check: a zone with no overdue keys must not render
    the warning banner (no regression for well-behaved zones)."""
    cfg = Config(
        key_dir=tmp_path,
        syslog_path=None,
        named_log_path=None,
        db_path=tmp_path / "events.db",
    )
    for k in cfg.enabled_collectors:
        cfg.enabled_collectors[k] = False
    app = create_app(cfg)
    db = app.state.db
    db.upsert_zone(Zone(name="clean.example", key_dir=str(tmp_path)))
    db.upsert_key(Key(
        zone="clean.example", key_tag=42, role="KSK",
        algorithm=13, key_id="Kclean.example.+013+00042",
    ))
    # Key has no Delete time scheduled anywhere — cannot be overdue.
    db.set_snapshot(
        "state_file", "clean.example#42#KSK",
        {"fields": {"Generated": "20260101000000", "KSK": "yes", "ZSK": "no"}},
    )

    with TestClient(app) as client:
        body = client.get("/zones/clean.example").text
    assert "warning-banner" not in body
    assert "past scheduled Delete" not in body
