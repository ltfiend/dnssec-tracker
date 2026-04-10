from pathlib import Path

from dnssec_tracker.parsers.rndc_status import diff_status, parse_rndc_status

FIXTURE = Path(__file__).parent / "fixtures" / "rndc_status_example.txt"


def test_parse_rndc_status_two_keys():
    output = FIXTURE.read_text()
    status = parse_rndc_status("example.com", output)
    assert status.policy == "default"
    assert len(status.keys) == 2
    ksk, zsk = status.keys
    assert ksk.key_tag == 12345 and ksk.role == "KSK"
    assert ksk.goal == "omnipresent"
    assert ksk.dnskey == "omnipresent"
    assert ksk.ds == "rumoured"
    assert ksk.zone_rrsig == "N/A"
    assert ksk.key_rrsig == "omnipresent"
    assert ksk.published is True
    assert ksk.key_signing is True

    assert zsk.key_tag == 67890 and zsk.role == "ZSK"
    assert zsk.zone_rrsig == "omnipresent"
    assert zsk.ds == "N/A"
    assert zsk.next_rollover is not None


def test_diff_status_emits_field_changes():
    output = FIXTURE.read_text()
    status = parse_rndc_status("example.com", output)
    snap = {str(k.key_tag): k.state_snapshot() for k in status.keys}

    # Pretend previous snapshot had ds=hidden for the KSK.
    previous = {
        "12345": {**snap["12345"], "ds": "hidden"},
        "67890": snap["67890"],
    }
    changes = diff_status(previous, snap)
    # Expect exactly one diff: KSK ds hidden -> rumoured
    ds_changes = [c for c in changes if c[0] == 12345 and c[1] == "ds"]
    assert ds_changes == [(12345, "ds", "hidden", "rumoured")]


def test_diff_status_reports_vanished_keys():
    output = FIXTURE.read_text()
    status = parse_rndc_status("example.com", output)
    snap = {str(k.key_tag): k.state_snapshot() for k in status.keys}
    previous = dict(snap)
    previous["99999"] = {"goal": "omnipresent", "dnskey": "omnipresent"}
    changes = diff_status(previous, snap)
    vanished = [c for c in changes if c[0] == 99999]
    assert vanished  # vanished key should be reported
    for tag, field, old, new in vanished:
        assert new is None
