"""Every place a zone name or key tag appears in the live UI must
render as a link so the user can click through to the corresponding
page. Verified for the dashboard recent-events table, the /events
page, and the zone page's event log.

The report template (``report.html``) deliberately does NOT carry
these links — reports are standalone archival artefacts, and a
recipient opening the HTML export from their inbox wouldn't have
the tracker's URLs reachable.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dnssec_tracker.app import create_app
from dnssec_tracker.config import Config
from dnssec_tracker.models import Event, Key, Zone, now_iso


ZONE_NAME = "example.com"
KSK_TAG = 19463


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
    db.upsert_zone(Zone(name=ZONE_NAME, key_dir=str(tmp_path)))
    db.upsert_key(Key(
        zone=ZONE_NAME, key_tag=KSK_TAG, role="KSK",
        algorithm=13, key_id=f"K{ZONE_NAME}.+013+{KSK_TAG:05d}",
    ))
    # One event with both zone + key populated.
    db.insert_event(Event(
        ts="2026-04-10T00:00:00Z", source="state",
        event_type="state_changed",
        summary="KSK GoalState hidden -> omnipresent",
        zone=ZONE_NAME, key_tag=KSK_TAG, key_role="KSK",
        detail={"field": "GoalState", "new": "omnipresent"},
    ))
    # One zone-wide event with no key_tag (SOA).
    db.insert_event(Event(
        ts="2026-04-10T01:00:00Z", source="dns",
        event_type="dns_soa_appeared_at_zone",
        summary="SOA observed at zone",
        zone=ZONE_NAME,
        detail={"rrtype": "SOA"},
    ))
    return TestClient(app)


# ---- dashboard recent-events table ---------------------------------


def test_dashboard_recent_events_links_zone(seeded):
    r = seeded.get("/")
    assert r.status_code == 200
    body = r.text
    # The zone name in the recent-events table must appear as a link.
    assert f'<a href="/zones/{ZONE_NAME}">{ZONE_NAME}</a>' in body


# ---- /events page --------------------------------------------------


def test_events_page_links_zone_and_key(seeded):
    r = seeded.get("/events")
    assert r.status_code == 200
    body = r.text
    # Zone name linked.
    assert f'<a href="/zones/{ZONE_NAME}">{ZONE_NAME}</a>' in body
    # Key tag linked (with role prefix inside the anchor).
    assert f'<a href="/zones/{ZONE_NAME}/keys/{KSK_TAG}">KSK {KSK_TAG}</a>' in body


def test_events_page_zone_wide_event_has_no_key_link(seeded):
    """The SOA event has key_tag=None — the key cell should render
    empty, not a broken <a href> without a target."""
    r = seeded.get("/events")
    body = r.text
    # A no-tag key cell must not produce a dangling anchor. The SOA
    # row's Key column should just be empty between <td> tags.
    # Quick sanity: there's exactly one KSK key link (for the KSK
    # event), not two — the SOA row doesn't link.
    assert body.count(f'/zones/{ZONE_NAME}/keys/{KSK_TAG}"') == 1


# ---- zone page event log -------------------------------------------


def test_zone_page_event_log_links_key(seeded):
    r = seeded.get(f"/zones/{ZONE_NAME}")
    assert r.status_code == 200
    body = r.text
    # Zone page's event log doesn't carry a zone column (redundant),
    # but the key column must link to the per-key page.
    assert f'<a href="/zones/{ZONE_NAME}/keys/{KSK_TAG}">KSK {KSK_TAG}</a>' in body


# ---- macros themselves ---------------------------------------------


def test_zone_link_macro_empty_input_emits_nothing():
    """Safety: zone_link(None) must NOT produce a broken <a href=>."""
    from jinja2 import Environment, FileSystemLoader
    import dnssec_tracker.web.templates as _  # noqa: F401
    env = Environment(loader=FileSystemLoader(
        str(Path(__file__).parent.parent / "dnssec_tracker" / "web" / "templates")
    ))
    tmpl = env.from_string(
        '{% from "_macros.html" import zone_link %}[{{ zone_link(None) }}]'
    )
    assert tmpl.render().strip() == "[]"


def test_key_link_macro_empty_input_emits_nothing():
    from jinja2 import Environment, FileSystemLoader
    env = Environment(loader=FileSystemLoader(
        str(Path(__file__).parent.parent / "dnssec_tracker" / "web" / "templates")
    ))
    tmpl = env.from_string(
        '{% from "_macros.html" import key_link %}'
        '[{{ key_link(None, None) }}]'
    )
    assert tmpl.render().strip() == "[]"


def test_key_link_macro_without_zone_falls_back_to_text():
    """If we have a tag but no zone (shouldn't happen in practice
    since events are always zone-scoped, but defend against it),
    emit plain text — never a broken link."""
    from jinja2 import Environment, FileSystemLoader
    env = Environment(loader=FileSystemLoader(
        str(Path(__file__).parent.parent / "dnssec_tracker" / "web" / "templates")
    ))
    tmpl = env.from_string(
        '{% from "_macros.html" import key_link %}'
        '{{ key_link(None, 42, "KSK") }}'
    )
    out = tmpl.render().strip()
    assert "<a" not in out
    assert "KSK 42" in out
