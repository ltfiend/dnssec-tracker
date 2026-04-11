"""Unit tests for the DNS-probe diff/emit logic.

These exercise the helpers and ``_emit_diff`` directly against a real
Database without spinning up asyncio or an actual resolver. We only
care about which events land, what their summaries say, and that the
key tag fields are populated.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dnssec_tracker.collectors.dns_probe import (
    DnsProbeCollector,
    _extract_key_tag,
    _rrsig_covered_type,
    _soa_serial,
)
from dnssec_tracker.config import Config
from dnssec_tracker.db import Database


# Real DNSKEY rdata text for a working ECDSA P-256 public key, in KSK
# (flags=257) and ZSK (flags=256) flavours. Their key tags are computed
# via dnspython and asserted below.
_DNSKEY_PUB = (
    "oJMRESz5E4gYzS35AJulupX0kDyQjM+9GsGZu6XW7A7m"
    "f2HxS/zV0SCNvyx8rDSb8CAW0Q9D2JVv9ZQvkLIc9g=="
)
DNSKEY_TXT = f"257 3 13 {_DNSKEY_PUB}"   # KSK — tag 19463
DNSKEY_TAG = 19463
DNSKEY_ZSK_TXT = f"256 3 13 {_DNSKEY_PUB}"  # ZSK — tag 19462
DNSKEY_ZSK_TAG = 19462

# DS: "tag algo digesttype digest"
DS_TXT = "12345 13 2 9e6c7a4d64e0a8b5bdfd1ed4bb6f3e9b21d9d9a0d9c2e3d4a5b6c7d8e9f0a1b2"
DS_TAG = 12345

# RRSIG: "covered algo labels orig_ttl expires inception keytag signer sig"
RRSIG_TXT = (
    "DNSKEY 13 2 86400 20260501000000 20260401000000 "
    "54321 example.com. AbC1dEf=="
)
RRSIG_TAG = 54321


# ---------------------------------------------------------------- helpers
def _collector(tmp_path: Path) -> tuple[DnsProbeCollector, Database, Config]:
    cfg = Config(
        key_dir=tmp_path,
        syslog_path=None,
        named_log_path=None,
        db_path=tmp_path / "events.db",
    )
    db = Database(cfg.db_path)
    return DnsProbeCollector(cfg, db), db, cfg


# ---------------------------------------------------------------- parsers
def test_extract_key_tag_ds():
    assert _extract_key_tag("DS", DS_TXT) == DS_TAG
    assert _extract_key_tag("CDS", DS_TXT) == DS_TAG


def test_extract_key_tag_rrsig():
    assert _extract_key_tag("RRSIG", RRSIG_TXT) == RRSIG_TAG


def test_extract_key_tag_dnskey():
    assert _extract_key_tag("DNSKEY", DNSKEY_TXT) == DNSKEY_TAG
    assert _extract_key_tag("CDNSKEY", DNSKEY_TXT) == DNSKEY_TAG


def test_extract_key_tag_unknown_type_is_none():
    assert _extract_key_tag("A", "192.0.2.1") is None
    assert _extract_key_tag("DS", "garbage") is None


def test_rrsig_covered_type():
    assert _rrsig_covered_type(RRSIG_TXT) == "DNSKEY"


def test_soa_serial():
    assert (
        _soa_serial(
            "ns1.example.com. admin.example.com. 2026041001 7200 3600 1209600 86400"
        )
        == 2026041001
    )
    assert _soa_serial("malformed") is None


# ---------------------------------------------------------------- emit diff: DNSKEY
def test_dnskey_appearance_emits_per_record_event_with_key_tag(tmp_path):
    col, db, _cfg = _collector(tmp_path)
    col._emit_diff(
        "example.com",
        "dns",
        previous={"DNSKEY": []},
        current={"DNSKEY": [DNSKEY_TXT]},
        parent=False,
    )
    events = db.query_events(zone="example.com")
    assert len(events) == 1
    e = events[0]
    assert e.event_type == "dns_dnskey_appeared_at_zone"
    assert e.key_tag == DNSKEY_TAG
    assert f"key tag {DNSKEY_TAG}" in e.summary
    assert e.detail["record"] == DNSKEY_TXT
    assert e.detail["key_tag"] == DNSKEY_TAG


def test_dnskey_rollover_emits_two_events_each_with_its_own_key_tag(tmp_path):
    col, db, _cfg = _collector(tmp_path)

    # Seed with the old key only, then "roll" to just the new key.
    col._emit_diff(
        "example.com", "dns",
        previous={"DNSKEY": []},
        current={"DNSKEY": [DNSKEY_ZSK_TXT]},
        parent=False,
    )
    col._emit_diff(
        "example.com", "dns",
        previous={"DNSKEY": [DNSKEY_ZSK_TXT]},
        current={"DNSKEY": [DNSKEY_TXT]},
        parent=False,
    )

    dnskey_events = [
        e for e in db.query_events(zone="example.com")
        if e.event_type.startswith("dns_dnskey_")
    ]
    # Three events in total: the initial sighting of the ZSK, plus
    # the rollover's appeared/disappeared pair.
    assert len(dnskey_events) == 3
    appeared = [
        e for e in dnskey_events
        if e.event_type.endswith("_appeared_at_zone")
    ]
    disappeared = [
        e for e in dnskey_events
        if e.event_type.endswith("_disappeared_at_zone")
    ]
    assert len(appeared) == 2 and len(disappeared) == 1

    tags = {e.key_tag for e in dnskey_events}
    assert tags == {DNSKEY_TAG, DNSKEY_ZSK_TAG}
    # Every DNSKEY event must have a key tag populated.
    assert all(e.key_tag is not None for e in dnskey_events)


# ---------------------------------------------------------------- emit diff: DS
def test_ds_appearance_includes_key_tag(tmp_path):
    col, db, _cfg = _collector(tmp_path)
    col._emit_diff(
        "example.com",
        "dns",
        previous={"DS": []},
        current={"DS": [DS_TXT]},
        parent=True,
    )
    events = db.query_events(zone="example.com")
    assert len(events) == 1
    e = events[0]
    assert e.event_type == "dns_ds_appeared_at_parent"
    assert e.key_tag == DS_TAG
    assert f"key tag {DS_TAG}" in e.summary
    assert "at parent" in e.summary


# ---------------------------------------------------------------- emit diff: RRSIG
def test_rrsig_event_names_covered_type_and_key_tag(tmp_path):
    col, db, _cfg = _collector(tmp_path)
    col._emit_diff(
        "example.com",
        "dns",
        previous={"RRSIG": []},
        current={"RRSIG": [RRSIG_TXT]},
        parent=False,
    )
    events = db.query_events(zone="example.com")
    assert len(events) == 1
    e = events[0]
    assert e.event_type == "dns_rrsig_appeared_at_zone"
    assert e.key_tag == RRSIG_TAG
    # Covered type should land in the summary and in detail.
    assert "over DNSKEY" in e.summary
    assert f"key tag {RRSIG_TAG}" in e.summary
    assert e.detail["covered_type"] == "DNSKEY"


# ---------------------------------------------------------------- emit diff: SOA
SOA_V1 = "ns1.example.com. admin.example.com. 2026041001 7200 3600 1209600 86400"
SOA_V2 = "ns1.example.com. admin.example.com. 2026041002 7200 3600 1209600 86400"


def test_soa_first_sighting_emits_with_serial(tmp_path):
    col, db, _cfg = _collector(tmp_path)
    col._emit_diff(
        "example.com",
        "dns",
        previous={"SOA": []},
        current={"SOA": [SOA_V1]},
        parent=False,
    )
    events = db.query_events(zone="example.com")
    assert len(events) == 1
    e = events[0]
    assert e.event_type == "dns_soa_appeared_at_zone"
    assert "serial 2026041001" in e.summary
    assert e.detail["serial"] == 2026041001
    assert e.detail["record"] == SOA_V1


def test_soa_pure_serial_bump_emits_nothing(tmp_path):
    col, db, _cfg = _collector(tmp_path)
    # First sighting — one event.
    col._emit_diff(
        "example.com", "dns",
        previous={"SOA": []}, current={"SOA": [SOA_V1]}, parent=False,
    )
    baseline = db.query_events(zone="example.com")
    assert len(baseline) == 1

    # Now the serial bumps. No new event should fire.
    col._emit_diff(
        "example.com", "dns",
        previous={"SOA": [SOA_V1]}, current={"SOA": [SOA_V2]}, parent=False,
    )
    after = db.query_events(zone="example.com")
    assert len(after) == 1, (
        "SOA serial bumps must not emit events — re-signing would flood the log"
    )


def test_soa_disappearance_emits(tmp_path):
    col, db, _cfg = _collector(tmp_path)
    col._emit_diff(
        "example.com", "dns",
        previous={"SOA": [SOA_V1]}, current={"SOA": []}, parent=False,
    )
    events = db.query_events(zone="example.com")
    assert len(events) == 1
    assert events[0].event_type == "dns_soa_disappeared_at_zone"


def test_soa_absent_to_absent_emits_nothing(tmp_path):
    col, db, _cfg = _collector(tmp_path)
    col._emit_diff(
        "example.com", "dns",
        previous={"SOA": []}, current={"SOA": []}, parent=False,
    )
    assert db.query_events(zone="example.com") == []
