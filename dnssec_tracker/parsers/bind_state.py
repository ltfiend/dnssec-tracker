"""Parser for BIND's ``K*.state`` files.

BIND writes one ``.state`` file per key under ``dnssec-policy`` control.
The format is simple::

    ; This is the state of key 12345, for example.com.
    Algorithm: 13
    Length: 256
    Lifetime: 5184000
    KSK: yes
    ZSK: no
    Generated: 20240101000000
    Published: 20240101000000
    Active: 20240107000000
    Retired: 0
    Removed: 0
    DNSKEYChange: 20240101000000
    KRRSIGChange: 20240101000000
    DSChange: 20240101000000
    GoalState: omnipresent
    DNSKEYState: omnipresent
    KRRSIGState: omnipresent
    DSState: omnipresent

Lines starting with ``;`` are comments. Keys are case-sensitive in BIND,
the parser preserves them verbatim so downstream diffs match BIND's
vocabulary exactly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


# Keys whose semantic meaning is "a state machine name"
STATE_FIELDS = (
    "GoalState",
    "DNSKEYState",
    "KRRSIGState",
    "ZRRSIGState",
    "DSState",
)

# Keys representing unix-style timestamps written as YYYYMMDDHHMMSS or "0".
TIMESTAMP_FIELDS = (
    "Generated",
    "Published",
    "Active",
    "Retired",
    "Revoke",
    "Removed",
    "SyncPublish",
    "SyncDelete",
    "DNSKEYChange",
    "KRRSIGChange",
    "ZRRSIGChange",
    "DSChange",
    "DSPublish",
    "DSRemove",
    "PublishCDS",
    "DeleteCDS",
)


# Filename convention: K<zone>.+<algo>+<keytag>.state
# Zone may contain dots. Algorithm is 3 digits, keytag is 5 digits.
FILENAME_RE = re.compile(r"^K(?P<zone>.+)\.\+(?P<algo>\d{3})\+(?P<tag>\d{5})\.state$")


@dataclass
class StateFile:
    """Parsed representation of one ``K*.state`` file."""

    path: Path
    zone: str
    key_tag: int
    algorithm: int
    role: str                      # KSK / ZSK / CSK
    fields: dict[str, str] = field(default_factory=dict)

    def state_fields(self) -> dict[str, str]:
        """Subset of fields carrying state-machine state values."""
        return {k: self.fields[k] for k in STATE_FIELDS if k in self.fields}

    def timestamps(self) -> dict[str, str]:
        return {k: self.fields[k] for k in TIMESTAMP_FIELDS if k in self.fields}

    def key_stem(self) -> str:
        return f"K{self.zone}.+{self.algorithm:03d}+{self.key_tag:05d}"


def parse_state_file(path: Path) -> StateFile | None:
    """Parse one ``.state`` file. Returns ``None`` if the filename is not
    recognisable as a BIND state file."""

    m = FILENAME_RE.match(path.name)
    if not m:
        return None

    algo = int(m.group("algo"))
    tag = int(m.group("tag"))
    # BIND strips the trailing dot from zones in filenames.
    zone = m.group("zone").rstrip(".")

    fields: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(";"):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()

    role = _role_from_fields(fields)

    return StateFile(
        path=path,
        zone=zone,
        key_tag=tag,
        algorithm=algo,
        role=role,
        fields=fields,
    )


def _role_from_fields(fields: dict[str, str]) -> str:
    ksk = fields.get("KSK", "").lower() == "yes"
    zsk = fields.get("ZSK", "").lower() == "yes"
    if ksk and zsk:
        return "CSK"
    if ksk:
        return "KSK"
    if zsk:
        return "ZSK"
    return "UNKNOWN"


def scan_state_files(root: Path, *, recursive: bool = False) -> list[StateFile]:
    """Walk *root* and return every parsed ``.state`` file found.

    Non-recursive by default — scans ``root`` and immediate
    subdirectories, which covers both flat (``keys/K*.state``) and
    per-zone-subdir (``keys/<zone>/K*.state``) BIND layouts without
    picking up deeper backup/holding trees (``keys/.bak/...``).
    Flip ``recursive=True`` if your tree genuinely nests deeper.
    """

    from ._scan import iter_key_paths

    results: list[StateFile] = []
    if not root.exists():
        return results
    for path in iter_key_paths(root, "K*.state", recursive=recursive):
        sf = parse_state_file(path)
        if sf is not None:
            results.append(sf)
    return results


def diff_state_fields(
    previous: dict[str, str] | None,
    current: dict[str, str],
) -> dict[str, tuple[str | None, str]]:
    """Return ``{field_name: (old, new)}`` for every field that changed.

    Added fields have ``old=None``.
    """

    previous = previous or {}
    changes: dict[str, tuple[str | None, str]] = {}
    for k, v in current.items():
        old = previous.get(k)
        if old != v:
            changes[k] = (old, v)
    return changes
