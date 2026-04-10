from pathlib import Path

from dnssec_tracker.parsers.bind_state import (
    diff_state_fields,
    parse_state_file,
    scan_state_files,
)

FIXTURES = Path(__file__).parent / "fixtures" / "keys"


def test_parse_ksk_state_file():
    sf = parse_state_file(FIXTURES / "Kexample.com.+013+12345.state")
    assert sf is not None
    assert sf.zone == "example.com"
    assert sf.algorithm == 13
    assert sf.key_tag == 12345
    assert sf.role == "KSK"
    assert sf.fields["GoalState"] == "omnipresent"
    assert sf.fields["DSState"] == "rumoured"
    assert "DNSKEYState" in sf.state_fields()
    assert sf.key_stem() == "Kexample.com.+013+12345"


def test_parse_zsk_state_file():
    sf = parse_state_file(FIXTURES / "Kexample.com.+013+67890.state")
    assert sf is not None
    assert sf.role == "ZSK"
    assert sf.fields["ZRRSIGState"] == "omnipresent"


def test_scan_state_files_finds_both_keys():
    files = scan_state_files(FIXTURES)
    tags = sorted(sf.key_tag for sf in files)
    assert tags == [12345, 67890]


def test_parse_rejects_unrelated_filename(tmp_path: Path):
    (tmp_path / "junk.txt").write_text("not a key state file")
    assert parse_state_file(tmp_path / "junk.txt") is None


def test_diff_state_fields_detects_transitions():
    previous = {"GoalState": "hidden", "DNSKEYState": "hidden"}
    current = {"GoalState": "omnipresent", "DNSKEYState": "rumoured", "DSState": "hidden"}
    changes = diff_state_fields(previous, current)
    assert changes["GoalState"] == ("hidden", "omnipresent")
    assert changes["DNSKEYState"] == ("hidden", "rumoured")
    assert changes["DSState"] == (None, "hidden")
