from pathlib import Path

from dnssec_tracker.parsers.bind_key import (
    diff_timings,
    parse_key_file,
    scan_key_files,
)

FIXTURES = Path(__file__).parent / "fixtures" / "keys"


def test_parse_key_file_extracts_timing_comments():
    kf = parse_key_file(FIXTURES / "Kexample.com.+013+12345.key")
    assert kf is not None
    assert kf.zone == "example.com"
    assert kf.role == "KSK"
    assert kf.timings["Created"] == "20260401000000"
    assert kf.timings["Publish"] == "20260401000000"
    assert kf.timings["Activate"] == "20260407000000"
    assert kf.dnskey_record and "DNSKEY" in kf.dnskey_record


def test_scan_finds_key_files():
    files = scan_key_files(FIXTURES)
    assert any(kf.key_tag == 12345 for kf in files)


def test_diff_timings_notices_settime_change():
    old = {"Publish": "20260401000000", "Activate": "20260407000000"}
    new = {"Publish": "20260402000000", "Activate": "20260407000000", "Inactive": "20260501000000"}
    changes = diff_timings(old, new)
    assert changes["Publish"] == ("20260401000000", "20260402000000")
    assert "Activate" not in changes
    assert changes["Inactive"] == (None, "20260501000000")
