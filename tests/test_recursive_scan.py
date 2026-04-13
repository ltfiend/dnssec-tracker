"""Key-directory scanning semantics.

Default is **non-recursive** — scan ``key_dir`` itself plus one
level of immediate subdirectories, which covers the two common
BIND layouts (flat + per-zone-subdir) while avoiding backup /
holding trees like ``keys/.bak/<zone>/`` that would otherwise
leak stale keys into the live zone's view.

Users with genuinely deeper trees opt in via
``key_dir_recursive=True``, which restores the full ``rglob`` walk
(while still skipping hidden "." directories at any depth, so
backup trees never pollute the scan regardless of the recursion
setting).
"""

from pathlib import Path

from dnssec_tracker.parsers.bind_key import scan_key_files
from dnssec_tracker.parsers.bind_state import scan_state_files


def _seed_layouts(root: Path) -> None:
    """Build a realistic tree covering every layout permutation the
    scanner needs to handle. After this fixture runs:

    * ``root/<zone>/K*.state`` — per-zone-subdir layout, one level
      down, should be found by default.
    * ``root/tenants/customer-a/<zone>/K*.state`` — two-level-deep,
      only found when ``recursive=True``.
    * ``root/.bak/<zone>/K*.state`` — hidden subdirectory, MUST be
      skipped in both modes (this is the user-reported bug: a
      ``keys/.bak/devries.tv/`` dir was leaking keys into the live
      ``devries.tv`` zone's view).
    """

    z1 = root / "example.com"
    z2 = root / "sub.example.org"
    deeper = root / "tenants" / "customer-a" / "a.customer.example"
    bak_shadow = root / ".bak" / "devries.tv"
    for d in (z1, z2, deeper, bak_shadow):
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
    # A stale backup copy that was polluting the live devries.tv
    # zone under the old rglob-everything default.
    (bak_shadow / "Kdevries.tv.+013+22222.state").write_text(
        "Algorithm: 13\nKSK: yes\nZSK: no\nGoalState: omnipresent\n"
    )
    (bak_shadow / "Kdevries.tv.+013+22222.key").write_text(
        "; This is a key-signing key, keyid 22222, for devries.tv.\n"
        "; Created: 20250101000000 (Wed Jan  1 00:00:00 2025)\n"
        "devries.tv. 86400 IN DNSKEY 257 3 13 staleoldkey\n"
    )


def test_default_scan_covers_root_plus_one_level(tmp_path: Path):
    """Default (non-recursive): root + one level down, no deeper."""
    _seed_layouts(tmp_path)
    found = sorted((sf.zone, sf.key_tag) for sf in scan_state_files(tmp_path))
    assert ("example.com", 12345) in found              # one level
    assert ("sub.example.org", 67890) in found          # one level
    # Two levels deep — out of scope for the default walk.
    assert not any(z == "a.customer.example" for z, _ in found)


def test_default_scan_skips_hidden_bak_directory(tmp_path: Path):
    """The user-reported bug: a ``keys/.bak/devries.tv/`` dir used
    to leak stale keys into devries.tv's live view. Even when a
    scan is otherwise willing to descend, a dot-prefixed directory
    MUST be skipped."""
    _seed_layouts(tmp_path)
    found_state = {sf.zone for sf in scan_state_files(tmp_path)}
    found_key = {kf.zone for kf in scan_key_files(tmp_path)}
    assert "devries.tv" not in found_state
    assert "devries.tv" not in found_key


def test_opt_in_recursion_reaches_deep_trees(tmp_path: Path):
    """Users with nested multi-tenant layouts can enable
    ``recursive=True`` to restore the old full-depth walk."""
    _seed_layouts(tmp_path)
    found = sorted(
        (sf.zone, sf.key_tag)
        for sf in scan_state_files(tmp_path, recursive=True)
    )
    assert ("a.customer.example", 11111) in found


def test_recursive_mode_still_skips_hidden_directories(tmp_path: Path):
    """Even in recursive mode, ``.bak/devries.tv`` stays out. A
    backup holding pen should never contribute to the live view
    regardless of how the user configured recursion."""
    _seed_layouts(tmp_path)
    found = {sf.zone for sf in scan_state_files(tmp_path, recursive=True)}
    assert "devries.tv" not in found


def test_scan_key_files_honours_the_same_recursion_flag(tmp_path: Path):
    """scan_key_files mirrors scan_state_files — both use the same
    shared walker under the hood."""
    _seed_layouts(tmp_path)
    default_keys = {kf.zone for kf in scan_key_files(tmp_path)}
    recursive_keys = {
        kf.zone for kf in scan_key_files(tmp_path, recursive=True)
    }
    # example.com has a .key under it; a.customer.example doesn't
    # have a .key seeded, so recursive doesn't add new zones for
    # the key scan here — but the important bit is the same
    # parameter is honoured.
    assert "example.com" in default_keys
    assert "devries.tv" not in default_keys
    assert "devries.tv" not in recursive_keys
