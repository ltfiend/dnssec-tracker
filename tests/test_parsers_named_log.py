from pathlib import Path

from dnssec_tracker.parsers.named_log import parse_named_line

FIXTURE = Path(__file__).parent / "fixtures" / "named_dnssec.log"


def test_parse_next_key_event():
    line = FIXTURE.read_text().splitlines()[0]
    ev = parse_named_line(line)
    assert ev is not None
    assert ev.event_type == "named_next_key_event"
    assert ev.zone == "example.com"
    assert ev.detail.get("seconds") == "3600"


def test_parse_dnskey_published():
    line = FIXTURE.read_text().splitlines()[1]
    ev = parse_named_line(line)
    assert ev is not None
    assert ev.event_type == "named_dnskey_published"
    assert ev.detail.get("tag") == "12345"
    assert ev.detail.get("role") == "KSK"


def test_parse_dnskey_active():
    line = FIXTURE.read_text().splitlines()[2]
    ev = parse_named_line(line)
    assert ev is not None
    assert ev.event_type == "named_dnskey_active"
    assert ev.detail.get("tag") == "67890"


def test_parse_general_line_is_ignored():
    line = FIXTURE.read_text().splitlines()[3]
    ev = parse_named_line(line)
    # general category lines are classified as "named_dnssec_message"
    # (they're still logged, just without a specific pattern match).
    assert ev is not None
    assert ev.category == "general"
