"""End-to-end filter-form tests for the zone and key pages.

Verifies the query parameters (``hide_types``, ``hide_sources``, ``role``)
flow from the URL through ``FilterSet`` into the renderers, that the
form round-trips the submitted values back into its own inputs, that
the DNSKEY-focus preset checkbox and the free-form text box share
one logical dimension, and that ``role=KSK`` keeps DS events for a
KSK page while ``role=ZSK`` drops them on a ZSK page.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from dnssec_tracker.app import create_app
from dnssec_tracker.config import Config
from dnssec_tracker.models import Event, Key, Zone


KSK_TAG = 12345
ZSK_TAG = 67890


@pytest.fixture
def seeded_client(tmp_path):
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
    db.upsert_key(Key(zone="example.com", key_tag=KSK_TAG, role="KSK", algorithm=13))
    db.upsert_key(Key(zone="example.com", key_tag=ZSK_TAG, role="ZSK", algorithm=13))

    # KSK state_changed
    db.insert_event(Event(
        ts="2026-04-10T00:00:00Z", source="state",
        event_type="state_changed",
        summary="KSK GoalState hidden -> omnipresent",
        zone="example.com", key_tag=KSK_TAG, key_role="KSK",
        detail={"field": "GoalState", "old": "hidden", "new": "omnipresent"},
    ))
    # DS observed at parent (no key_role, key_tag set from DS rdata)
    db.insert_event(Event(
        ts="2026-04-10T01:00:00Z", source="dns",
        event_type="dns_ds_appeared_at_parent",
        summary="DS (key tag 12345) appeared at parent for example.com",
        zone="example.com", key_tag=KSK_TAG, key_role=None,
        detail={"parent": True, "rrtype": "DS", "tag": KSK_TAG},
    ))
    # DNSKEY observation
    db.insert_event(Event(
        ts="2026-04-10T02:00:00Z", source="dns",
        event_type="dns_dnskey_appeared_at_zone",
        summary="DNSKEY (key tag 67890) seen at zone",
        zone="example.com", key_tag=ZSK_TAG, key_role="ZSK",
        detail={"rrtype": "DNSKEY", "tag": ZSK_TAG},
    ))
    # RRSIG noise (should be dropped by the DNSKEY-focus filter)
    db.insert_event(Event(
        ts="2026-04-10T03:00:00Z", source="dns",
        event_type="dns_rrsig_refreshed",
        summary="RRSIG refreshed for example.com DNSKEY",
        zone="example.com", key_tag=KSK_TAG, key_role="KSK",
        detail={"rrtype": "RRSIG"},
    ))
    # SOA noise (also dropped by DNSKEY focus)
    db.insert_event(Event(
        ts="2026-04-10T04:00:00Z", source="dns",
        event_type="dns_soa_observed",
        summary="SOA serial 2026041000 at zone",
        zone="example.com", key_role=None,
        detail={"rrtype": "SOA"},
    ))
    return TestClient(app)


# ---- zone page ---------------------------------------------------------


def test_zone_page_default_shows_everything(seeded_client):
    r = seeded_client.get("/zones/example.com")
    assert r.status_code == 200
    body = r.text
    assert "dns_ds_appeared_at_parent" in body
    assert "dns_rrsig_refreshed" in body
    assert "dns_soa_observed" in body
    assert "dns_dnskey_appeared_at_zone" in body


def test_zone_page_dnskey_focus_drops_rrsig_and_soa(seeded_client):
    r = seeded_client.get(
        "/zones/example.com",
        params={"hide_types": "rrsig,soa", "role": "KSK"},
    )
    assert r.status_code == 200
    body = r.text
    # KSK state_changed + KSK-tagged DS must remain
    assert "state_changed" in body
    assert "dns_ds_appeared_at_parent" in body
    # RRSIG + SOA must be filtered out of the event table
    # Allow the filter form's placeholder text to mention "rrsig",
    # but the actual event_type column cells should not.
    assert "dns_rrsig_refreshed" not in body
    assert "dns_soa_observed" not in body


def test_zone_page_ksk_filter_keeps_ds_and_drops_zsk_events(seeded_client):
    r = seeded_client.get(
        "/zones/example.com",
        params={"role": "KSK"},
    )
    body = r.text
    # KSK events + None-role DS visible
    assert "state_changed" in body
    assert "dns_ds_appeared_at_parent" in body
    # The ZSK-role DNSKEY event should NOT appear under role=KSK
    assert "dns_dnskey_appeared_at_zone" not in body


def test_zone_page_echoes_filter_values_back_into_form(seeded_client):
    r = seeded_client.get(
        "/zones/example.com",
        params={"hide_types": "rrsig,soa", "hide_sources": "syslog", "role": "KSK"},
    )
    body = r.text
    # Text inputs preserve their values
    assert 'value="rrsig,soa"' in body
    assert 'value="syslog"' in body
    # role select shows KSK as selected
    assert '<option value="KSK" selected' in body
    # DNSKEY focus checkbox is ticked because hide_types is exactly the preset
    assert 'name="hide_types_preset" value="rrsig,soa" checked' in body


def test_zone_page_preset_checkbox_translates_to_hide_types(seeded_client):
    """Ticking 'DNSKEY focus' sends hide_types_preset=rrsig,soa; the
    route should translate that into the filter dimension even if the
    free-form hide_types is empty."""

    r = seeded_client.get(
        "/zones/example.com",
        params={"hide_types_preset": "rrsig,soa"},
    )
    body = r.text
    assert "dns_rrsig_refreshed" not in body
    assert "dns_soa_observed" not in body


# ---- key page ----------------------------------------------------------


def test_ksk_page_default_shows_ds_events(seeded_client):
    r = seeded_client.get(f"/zones/example.com/keys/{KSK_TAG}")
    assert r.status_code == 200
    body = r.text
    assert "dns_ds_appeared_at_parent" in body


def test_ksk_page_role_ksk_still_shows_ds_events(seeded_client):
    r = seeded_client.get(
        f"/zones/example.com/keys/{KSK_TAG}",
        params={"role": "KSK"},
    )
    body = r.text
    assert "dns_ds_appeared_at_parent" in body


def test_zsk_page_role_zsk_drops_ds_events(seeded_client):
    """role=ZSK on a ZSK's page must not show any DS events.

    The ZSK has tag 67890 in the seed; we reuse the DS event we
    emitted for the KSK but pretend it's visible on the ZSK page via
    key_tag collision would be wrong, so instead we seed a fresh DS
    event tagged with the ZSK tag (shouldn't happen in real life, but
    that's exactly why the ZSK view must strip it).
    """

    # Reach into the DB and add a bogus DS event tagged as ZSK_TAG so
    # the key_tag filter lets it through but the role filter must
    # drop it.
    client = seeded_client
    db = client.app.state.db
    db.insert_event(Event(
        ts="2026-04-10T05:00:00Z", source="dns",
        event_type="dns_ds_appeared_at_parent",
        summary="DS (key tag 67890) ghost event for ZSK filter test",
        zone="example.com", key_tag=ZSK_TAG, key_role=None,
        detail={"parent": True, "rrtype": "DS", "tag": ZSK_TAG},
    ))

    r = client.get(
        f"/zones/example.com/keys/{ZSK_TAG}",
        params={"role": "ZSK"},
    )
    body = r.text
    # The ZSK's legitimate DNSKEY event stays
    assert "dns_dnskey_appeared_at_zone" in body
    # but DS is gone
    assert "DS (key tag 67890)" not in body
    assert "dns_ds_appeared_at_parent" not in body
