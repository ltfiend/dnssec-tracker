"""Prove that scan_state_files / scan_key_files walk nested
``<key_dir>/<zonename>/`` layouts. BIND's ``key-directory`` almost
always has one subdirectory per zone; the parser must descend into
every subdirectory under the configured root, not just the root itself.
"""

from pathlib import Path

from dnssec_tracker.parsers.bind_key import scan_key_files
from dnssec_tracker.parsers.bind_state import scan_state_files


def _seed_nested_layout(root: Path) -> None:
    z1 = root / "example.com"
    z2 = root / "sub.example.org"
    deeper = root / "tenants" / "customer-a" / "a.customer.example"
    for d in (z1, z2, deeper):
        d.mkdir(parents=True)

    (z1 / "Kexample.com.+013+12345.state").write_text(
        "Algorithm: 13\nKSK: yes\nZSK: no\nGoalState: omnipresent\nDNSKEYState: omnipresent\n"
    )
    (z1 / "Kexample.com.+013+12345.key").write_text(
        "; This is a key-signing key, keyid 12345, for example.com.\n"
        "; Created: 20260401000000 (Wed Apr  1 00:00:00 2026)\n"
        "; Publish: 20260401000000 (Wed Apr  1 00:00:00 2026)\n"
        "example.com. 86400 IN DNSKEY 257 3 13 fakepubkey\n"
    )
    (z2 / "Ksub.example.org.+013+67890.state").write_text(
        "Algorithm: 13\nKSK: no\nZSK: yes\nGoalState: omnipresent\nZRRSIGState: omnipresent\n"
    )
    (deeper / "Ka.customer.example.+013+11111.state").write_text(
        "Algorithm: 13\nKSK: yes\nZSK: no\nGoalState: omnipresent\n"
    )


def test_scan_state_files_is_recursive(tmp_path: Path):
    _seed_nested_layout(tmp_path)
    found = scan_state_files(tmp_path)
    found_zones = sorted((sf.zone, sf.key_tag) for sf in found)
    assert found_zones == [
        ("a.customer.example", 11111),
        ("example.com", 12345),
        ("sub.example.org", 67890),
    ]


def test_scan_key_files_is_recursive(tmp_path: Path):
    _seed_nested_layout(tmp_path)
    found = scan_key_files(tmp_path)
    found_zones = sorted((kf.zone, kf.key_tag) for kf in found)
    assert found_zones == [("example.com", 12345)]
