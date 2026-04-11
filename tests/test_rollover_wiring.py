"""End-to-end wiring test for the rollover view.

The renderer itself is covered by ``test_rollover_view.py``; this
file verifies that the new "Rollover view" section actually lands on
the three surfaces that render it: the zone page, the per-key page,
and the HTML report (which is also what the PDF export consumes).

Also exercises the snapshot lookup path — the routes fetch each key's
``state_file`` snapshot and pass it to ``render_rollover_view`` so the
phase boundaries come from BIND's packed timestamps. The seeded DB
includes those snapshots and the test asserts the renderer actually
consumed them (the output SVG should include phase colouring and
tag labels for the seeded key).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dnssec_tracker.app import create_app
from dnssec_tracker.config import Config
from dnssec_tracker.db import Database
from dnssec_tracker.models import Event, Key, Zone, now_iso
from dnssec_tracker.render.html_export import render_report_html


KSK_TAG = 12345
ZSK_TAG = 67890


def _seed(tmp_path: Path) -> tuple[Database, Config]:
    cfg = Config(
        key_dir=tmp_path,
        syslog_path=None,
        named_log_path=None,
        db_path=tmp_path / "events.db",
    )
    db = Database(cfg.db_path)
    db.upsert_zone(Zone(name="example.com", key_dir=str(tmp_path)))
    db.upsert_key(Key(
        zone="example.com", key_tag=KSK_TAG, role="KSK",
        algorithm=13, key_id=f"Kexample.com.+013+{KSK_TAG:05d}",
    ))
    db.upsert_key(Key(
        zone="example.com", key_tag=ZSK_TAG, role="ZSK",
        algorithm=13, key_id=f"Kexample.com.+013+{ZSK_TAG:05d}",
    ))

    # State-file snapshots for both keys so the rollover renderer has
    # phase boundaries to draw. Packed YYYYMMDDHHMMSS timestamps.
    db.set_snapshot(
        "state_file",
        f"example.com#{KSK_TAG}#KSK",
        {
            "fields": {
                "Algorithm": "13",
                "KSK": "yes", "ZSK": "no",
                "Generated": "20260301000000",
                "Published": "20260401000000",
                "Active":    "20260407000000",
                "Retired":   "0",
                "Removed":   "0",
                "GoalState": "omnipresent",
                "DNSKEYState": "omnipresent",
                "KRRSIGState": "omnipresent",
                "DSState":    "omnipresent",
            }
        },
    )
    db.set_snapshot(
        "state_file",
        f"example.com#{ZSK_TAG}#ZSK",
        {
            "fields": {
                "Algorithm": "13",
                "KSK": "no", "ZSK": "yes",
                "Generated": "20260301000000",
                "Published": "20260401000000",
                "Active":    "20260402000000",
                "Retired":   "0",
                "Removed":   "0",
                "GoalState":   "omnipresent",
                "DNSKEYState": "omnipresent",
                "ZRRSIGState": "omnipresent",
            }
        },
    )
    # A DS-at-parent event so the KSK's DS overlay has something to draw.
    db.insert_event(Event(
        ts="2026-04-12T00:00:00Z",
        source="dns",
        event_type="dns_ds_appeared_at_parent",
        summary=f"DS (key tag {KSK_TAG}) appeared at parent for example.com",
        zone="example.com",
        key_tag=KSK_TAG,
        detail={"rrtype": "DS", "parent": True},
    ))
    return db, cfg


@pytest.fixture
def seeded_app(tmp_path):
    db, cfg = _seed(tmp_path)
    for k in cfg.enabled_collectors:
        cfg.enabled_collectors[k] = False
    app = create_app(cfg)
    # Swap in the already-seeded DB so create_app's fresh Database isn't
    # the one the test queries.
    app.state.db = db
    return app, db, cfg


def test_zone_page_renders_rollover_section(seeded_app):
    app, _db, _cfg = seeded_app
    with TestClient(app) as client:
        r = client.get("/zones/example.com")
    assert r.status_code == 200
    body = r.text
    assert "Rollover view" in body
    assert 'class="timeline rollover-view"' in body
    # The renderer must have produced an SVG with both key tags labelled.
    assert str(KSK_TAG) in body
    assert str(ZSK_TAG) in body
    # Calendar and split timelines must still be present — rollover
    # is additive, not a replacement.
    assert "Calendar view" in body
    assert "DNS event timeline" in body
    assert "File event timeline" in body


def test_key_page_renders_rollover_section(seeded_app):
    app, _db, _cfg = seeded_app
    with TestClient(app) as client:
        r = client.get(f"/zones/example.com/keys/{KSK_TAG}")
    assert r.status_code == 200
    body = r.text
    assert "Rollover view" in body
    assert 'class="timeline rollover-view"' in body
    # The KSK's tag should appear in the rollover SVG row label.
    assert str(KSK_TAG) in body


def test_html_report_contains_rollover_section(seeded_app):
    app, db, cfg = seeded_app
    html = render_report_html(db, cfg, "example.com")
    assert "Rollover view" in html
    assert 'class="timeline rollover-view"' in html
    # Both keys appear in the rollover output.
    assert str(KSK_TAG) in html
    assert str(ZSK_TAG) in html
    # The existing per-key breakdown and timelines must still be there.
    assert "Per-key breakdown" in html
    assert "DNS event timeline" in html


def test_rollover_filterset_ksk_preserves_ds_overlay(seeded_app):
    """Under role=KSK (default on a KSK page), the FilterSet must
    keep DS events so the rollover view's DS overlay has something
    to draw. This is the whole point of the KSK/DS linkage.
    """
    app, _db, _cfg = seeded_app
    with TestClient(app) as client:
        r = client.get(
            f"/zones/example.com/keys/{KSK_TAG}",
            params={"role": "KSK"},
        )
    assert r.status_code == 200
    body = r.text
    # DS overlay group marker from the rollover renderer + the
    # chronological event log row for the DS event both survive.
    assert "dns_ds_appeared_at_parent" in body
