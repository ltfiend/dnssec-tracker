"""Parser for BIND's ``K*.key`` and ``K*.private`` timing comments.

A ``K*.key`` file looks like::

    ; This is a key-signing key, keyid 12345, for example.com.
    ; Created: 20240101000000 (Mon Jan  1 00:00:00 2024)
    ; Publish: 20240101000000 (Mon Jan  1 00:00:00 2024)
    ; Activate: 20240107000000 (Sun Jan  7 00:00:00 2024)
    example.com. 86400 IN DNSKEY 257 3 13 ...

The ``.private`` file is a plain INI-ish format with
``Created:/Publish:/Activate:/Inactive:/Delete:`` lines at the bottom.

``dnssec-settime`` (used by iodyn-dnssec) mutates these fields, so
tracking their values over time tells us when iodyn scheduled a
transition.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


FILENAME_RE = re.compile(r"^K(?P<zone>.+)\.\+(?P<algo>\d{3})\+(?P<tag>\d{5})\.(?:key|private)$")

# Fields to pluck out. Order matters for rendering.
TIMING_FIELDS = (
    "Created",
    "Publish",
    "Activate",
    "Revoke",
    "Inactive",
    "Delete",
    "SyncPublish",
    "SyncDelete",
)

# Comment in .key file:  "; Created: 20240101000000 (Mon Jan  1 ...)"
COMMENT_FIELD_RE = re.compile(r"^\s*;\s*(\w+)\s*:\s*(\S+)")

# Key-type hint from the .key comment header.
# "; This is a key-signing key, keyid 12345, for example.com."
HEADER_HINT_RE = re.compile(
    r";\s*This is a (key-signing|zone-signing)\s+key",
    re.IGNORECASE,
)

# Private file: "Created: 20240101000000"
PRIVATE_FIELD_RE = re.compile(r"^\s*(\w+)\s*:\s*(\S+)")


@dataclass
class KeyFile:
    path: Path
    zone: str
    key_tag: int
    algorithm: int
    role: str  # KSK / ZSK / UNKNOWN
    timings: dict[str, str] = field(default_factory=dict)
    # the raw DNSKEY line, if present (useful for report appendix)
    dnskey_record: str | None = None


def parse_key_file(path: Path) -> KeyFile | None:
    """Parse a ``K*.key`` or ``K*.private`` file."""

    m = FILENAME_RE.match(path.name)
    if not m:
        return None
    zone = m.group("zone").rstrip(".")
    algo = int(m.group("algo"))
    tag = int(m.group("tag"))

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    timings: dict[str, str] = {}
    role = "UNKNOWN"
    dnskey_record: str | None = None

    if path.suffix == ".key":
        for raw in text.splitlines():
            line = raw.rstrip()
            if not line:
                continue
            hm = HEADER_HINT_RE.match(line)
            if hm:
                role = "KSK" if hm.group(1).lower() == "key-signing" else "ZSK"
                continue
            cm = COMMENT_FIELD_RE.match(line)
            if cm and cm.group(1) in TIMING_FIELDS:
                timings[cm.group(1)] = cm.group(2)
                continue
            if not line.startswith(";") and " DNSKEY " in line:
                dnskey_record = line.strip()
    else:  # .private
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith(";"):
                continue
            pm = PRIVATE_FIELD_RE.match(line)
            if pm and pm.group(1) in TIMING_FIELDS:
                timings[pm.group(1)] = pm.group(2)

    return KeyFile(
        path=path,
        zone=zone,
        key_tag=tag,
        algorithm=algo,
        role=role,
        timings=timings,
        dnskey_record=dnskey_record,
    )


def scan_key_files(root: Path) -> list[KeyFile]:
    results: list[KeyFile] = []
    if not root.exists():
        return results
    for path in root.rglob("K*.key"):
        kf = parse_key_file(path)
        if kf is not None:
            results.append(kf)
    return results


def diff_timings(
    previous: dict[str, str] | None,
    current: dict[str, str],
) -> dict[str, tuple[str | None, str]]:
    previous = previous or {}
    changes: dict[str, tuple[str | None, str]] = {}
    for k, v in current.items():
        old = previous.get(k)
        if old != v:
            changes[k] = (old, v)
    return changes
