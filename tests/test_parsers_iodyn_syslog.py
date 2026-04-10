from pathlib import Path

from dnssec_tracker.parsers.iodyn_syslog import (
    is_iodyn,
    parse_iodyn_message,
    parse_syslog_line,
)

FIXTURE = Path(__file__).parent / "fixtures" / "syslog_iodyn.log"


def test_parse_traditional_syslog_line():
    raw = FIXTURE.read_text().splitlines()[0]
    line = parse_syslog_line(raw)
    assert line is not None
    assert line.host == "dns01"
    assert line.program.startswith("iodyn")
    assert is_iodyn(line)


def test_parse_iodyn_key_create_extracts_zone_and_role():
    raw = FIXTURE.read_text().splitlines()[0]
    line = parse_syslog_line(raw)
    assert line is not None
    ev = parse_iodyn_message(line.ts, line.message)
    assert ev is not None
    assert ev.tag == "Key.create"
    assert ev.event_type == "iodyn_key_created"
    assert ev.zone == "example.com"
    assert ev.role == "KSK"


def test_parse_iodyn_settime_extracts_field_and_value():
    raw = FIXTURE.read_text().splitlines()[2]
    line = parse_syslog_line(raw)
    assert line is not None
    ev = parse_iodyn_message(line.ts, line.message)
    assert ev is not None
    assert ev.tag == "settime"
    assert ev.event_type == "iodyn_settime"
    assert ev.zone == "example.com"
    assert ev.role == "KSK"
    assert ev.detail["field"] == "Publish"
    assert ev.detail["value"] == "1712724430"


def test_parse_iodyn_command_line_is_flagged_as_command():
    raw = FIXTURE.read_text().splitlines()[1]
    line = parse_syslog_line(raw)
    assert line is not None
    ev = parse_iodyn_message(line.ts, line.message)
    assert ev is not None
    assert ev.is_command is True


def test_parse_bind_reload_and_ds_events():
    for i, expected in [(4, "iodyn_ds_action"), (5, "iodyn_rndc_reload")]:
        raw = FIXTURE.read_text().splitlines()[i]
        line = parse_syslog_line(raw)
        assert line is not None
        ev = parse_iodyn_message(line.ts, line.message)
        assert ev is not None, raw
        assert ev.event_type == expected
