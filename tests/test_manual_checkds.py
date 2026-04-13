"""Detection of operator-issued ``rndc dnssec -checkds`` commands.

When a human runs ``rndc dnssec -checkds -key 12345 published
example.com`` against a running BIND, the nameserver echoes the
command to its general-category log. That's a *manual* DS state
transition (as opposed to the automatic ones BIND drives from its
dnssec-policy state machine), so the tracker surfaces it as a
distinct event_type (``named_manual_checkds``) and carries the
operator's action + targeted key tag in ``detail``.

The detection works through both log paths — BIND's own log file
(via named_log tail) and the host syslog (via syslog tail) — so the
event lands regardless of where BIND's control-channel messages
are routed.
"""

from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import patch

import pytest

from dnssec_tracker.parsers.named_log import (
    match_named_body,
    parse_named_line,
)


# ---- parser-level: match_named_body -------------------------------


def test_checkds_published_with_key_tag_extracts_all_fields():
    raw = (
        "received control channel command 'dnssec -checkds -key 12345 "
        "published example.com'"
    )
    result = match_named_body(raw)
    assert result is not None
    event_type, detail, zone, body = result
    assert event_type == "named_manual_checkds"
    assert detail["tag"] == "12345"
    assert detail["action"] == "published"
    assert zone == "example.com"
    assert detail["zone"] == "example.com"


def test_checkds_withdrawn_without_key_tag_applies_to_all_keys():
    raw = (
        "received control channel command 'dnssec -checkds withdrawn "
        "fus3d.net'"
    )
    result = match_named_body(raw)
    assert result is not None
    event_type, detail, zone, _ = result
    assert event_type == "named_manual_checkds"
    assert detail.get("tag") is None or "tag" not in detail
    assert detail["action"] == "withdrawn"
    assert zone == "fus3d.net"


def test_checkds_is_matched_even_without_surrounding_quotes():
    """BIND's log format usually quotes the command but older
    versions/configurations may not. The pattern handles both."""
    raw = "received control channel command dnssec -checkds -key 42 published example.org"
    result = match_named_body(raw)
    assert result is not None
    event_type, detail, zone, _ = result
    assert event_type == "named_manual_checkds"
    assert detail["tag"] == "42"
    assert detail["action"] == "published"
    assert zone == "example.org"


def test_non_checkds_control_commands_do_not_match():
    """Other control-channel commands pass through the pattern
    without matching named_manual_checkds (they may or may not hit
    other patterns downstream)."""
    raw = "received control channel command 'status'"
    result = match_named_body(raw)
    # Not checkds — should not be tagged as the manual-checkds event.
    if result is not None:
        event_type, _detail, _zone, _body = result
        assert event_type != "named_manual_checkds"


# ---- full-line path: parse_named_line ------------------------------


def test_full_bind_log_line_checkds():
    """Full BIND log line with timestamp / category / severity
    prefix, as seen in the named log file."""
    line = (
        "13-Apr-2026 10:00:00.456 general: info: received control channel "
        "command 'dnssec -checkds -key 19463 published example.com'"
    )
    ev = parse_named_line(line)
    assert ev is not None
    assert ev.event_type == "named_manual_checkds"
    assert ev.zone == "example.com"
    assert ev.detail["tag"] == "19463"
    assert ev.detail["action"] == "published"


# ---- syslog-tail path ---------------------------------------------


def test_syslog_delivered_checkds_emits_structured_event(tmp_path):
    """When BIND's control-channel log is routed to syslog (common
    default), the tracker's syslog-tail collector must emit the
    same structured named_manual_checkds event — not the generic
    named_syslog_line fallback."""

    from dnssec_tracker.collectors.syslog_tail import SyslogTailCollector
    from dnssec_tracker.config import Config
    from dnssec_tracker.db import Database

    cfg = Config(
        key_dir=tmp_path,
        syslog_path=None,
        named_log_path=None,
        db_path=tmp_path / "events.db",
    )
    db = Database(cfg.db_path)
    col = SyslogTailCollector(cfg, db)

    line = (
        "Apr 13 10:00:00 dns01 named[1234]: received control channel "
        "command 'dnssec -checkds -key 19463 published example.com'"
    )
    col._handle(line)

    events = db.query_events(limit=10)
    assert len(events) == 1
    ev = events[0]
    assert ev.event_type == "named_manual_checkds"
    assert ev.source == "syslog"
    assert ev.zone == "example.com"
    assert ev.detail["tag"] == "19463"
    assert ev.detail["action"] == "published"


def test_syslog_unrelated_named_line_falls_back_to_generic(tmp_path):
    """Non-checkds named lines that mention dnssec still emit the
    generic named_syslog_line event so we don't regress coverage
    for lines the pattern set doesn't know about."""

    from dnssec_tracker.collectors.syslog_tail import SyslogTailCollector
    from dnssec_tracker.config import Config
    from dnssec_tracker.db import Database

    cfg = Config(
        key_dir=tmp_path,
        syslog_path=None,
        named_log_path=None,
        db_path=tmp_path / "events.db",
    )
    db = Database(cfg.db_path)
    col = SyslogTailCollector(cfg, db)

    # Something dnssec-related but not matched by any pattern.
    line = (
        "Apr 13 10:00:00 dns01 named[1234]: some novel dnssec diagnostic "
        "message the pattern list doesn't know about"
    )
    col._handle(line)

    events = db.query_events(limit=10)
    assert len(events) == 1
    assert events[0].event_type == "named_syslog_line"


# ---- visual: label-worthy in the event timeline -------------------


def test_named_manual_checkds_is_label_worthy():
    """Manual state changes are rare and important — they must be
    in the event-timeline's label-worthy set so the inline label
    renders on the chart."""
    from dnssec_tracker.render.event_timeline import LABEL_WORTHY_TYPES
    assert "named_manual_checkds" in LABEL_WORTHY_TYPES
