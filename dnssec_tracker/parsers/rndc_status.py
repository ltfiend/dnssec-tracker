"""Parser for ``rndc dnssec -status <zone>`` output.

Sample output::

    dnssec-policy: default
    current time:  Mon Apr 10 08:27:10 2026

    key: 12345 (ECDSAP256SHA256), KSK
      published:      yes - since Mon Apr  1 00:00:00 2026
      key signing:    yes - since Mon Apr  1 00:00:00 2026

      No rollover scheduled

      - goal:           omnipresent
      - dnskey:         rumoured
      - ds:             hidden
      - zone rrsig:     N/A
      - key rrsig:      rumoured

    key: 67890 (ECDSAP256SHA256), ZSK
      published:      yes - since Mon Apr  1 00:00:00 2026
      zone signing:   yes - since Mon Apr  1 00:00:00 2026

      Next rollover: Mon May  1 00:00:00 2026

      - goal:           omnipresent
      - dnskey:         omnipresent
      - ds:             N/A
      - zone rrsig:     omnipresent
      - key rrsig:      N/A

Fields vary slightly across BIND versions (9.18 omits the "- " bullet
prefix that 9.20 adds; some builds print ``rumoured`` as
``rumoured``). The parser tolerates both.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# "key: 12345 (ECDSAP256SHA256), KSK"
KEY_HEADER_RE = re.compile(
    r"^\s*key:\s+(?P<tag>\d+)\s+\((?P<algo_name>[A-Za-z0-9]+)\),\s+(?P<role>KSK|ZSK|CSK)",
)

# "  goal:           omnipresent"  or "- goal:   omnipresent"
FIELD_RE = re.compile(
    r"^\s*-?\s*(?P<name>goal|dnskey|ds|zone\s*rrsig|key\s*rrsig)\s*:\s*(?P<value>\S+(?:\s+\S+)?)",
    re.IGNORECASE,
)

# "published:     yes - since Mon Apr  1 00:00:00 2026"
STATUS_LINE_RE = re.compile(
    r"^\s*(?P<what>published|zone signing|key signing)\s*:\s*(?P<status>yes|no)"
    r"(?:\s*-\s*since\s+(?P<since>.+))?",
    re.IGNORECASE,
)

NEXT_ROLLOVER_RE = re.compile(r"^\s*Next rollover:\s*(?P<when>.+)$", re.IGNORECASE)
POLICY_RE = re.compile(r"^\s*dnssec-policy:\s*(?P<policy>\S+)$", re.IGNORECASE)


STATE_NAMES_CANON = {
    "hidden": "hidden",
    "rumoured": "rumoured",
    "rumored": "rumoured",
    "omnipresent": "omnipresent",
    "unretentive": "unretentive",
    "n/a": "N/A",
    "na": "N/A",
}


def _canon_state(value: str) -> str:
    v = value.strip().lower()
    return STATE_NAMES_CANON.get(v, value.strip())


@dataclass
class RndcKeyStatus:
    key_tag: int
    algorithm_name: str
    role: str
    published: bool | None = None
    published_since: str | None = None
    zone_signing: bool | None = None
    key_signing: bool | None = None
    goal: str | None = None
    dnskey: str | None = None
    ds: str | None = None
    zone_rrsig: str | None = None
    key_rrsig: str | None = None
    next_rollover: str | None = None

    def state_snapshot(self) -> dict[str, str | None]:
        """Stable dict used to compute change diffs."""
        return {
            "goal": self.goal,
            "dnskey": self.dnskey,
            "ds": self.ds,
            "zone_rrsig": self.zone_rrsig,
            "key_rrsig": self.key_rrsig,
            "published": "yes" if self.published else "no" if self.published is False else None,
            "zone_signing": "yes" if self.zone_signing else "no" if self.zone_signing is False else None,
            "key_signing": "yes" if self.key_signing else "no" if self.key_signing is False else None,
            "next_rollover": self.next_rollover,
        }


@dataclass
class RndcStatus:
    zone: str
    policy: str | None = None
    current_time: str | None = None
    keys: list[RndcKeyStatus] = field(default_factory=list)

    def by_tag(self) -> dict[int, RndcKeyStatus]:
        return {k.key_tag: k for k in self.keys}


def parse_rndc_status(zone: str, output: str) -> RndcStatus:
    """Parse the output of ``rndc dnssec -status <zone>``.

    Unknown or extra lines are ignored; the parser is permissive so that
    BIND version quirks don't drop data on the floor.
    """

    status = RndcStatus(zone=zone)
    current: RndcKeyStatus | None = None

    for raw in output.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue

        pm = POLICY_RE.match(line)
        if pm:
            status.policy = pm.group("policy")
            continue

        if line.lower().lstrip().startswith("current time"):
            _, _, rest = line.partition(":")
            status.current_time = rest.strip()
            continue

        kh = KEY_HEADER_RE.match(line)
        if kh:
            current = RndcKeyStatus(
                key_tag=int(kh.group("tag")),
                algorithm_name=kh.group("algo_name"),
                role=kh.group("role").upper(),
            )
            status.keys.append(current)
            continue

        if current is None:
            continue

        sm = STATUS_LINE_RE.match(line)
        if sm:
            what = sm.group("what").lower()
            yes = sm.group("status").lower() == "yes"
            since = sm.group("since")
            if what == "published":
                current.published = yes
                current.published_since = since
            elif what == "zone signing":
                current.zone_signing = yes
            elif what == "key signing":
                current.key_signing = yes
            continue

        nr = NEXT_ROLLOVER_RE.match(line)
        if nr:
            current.next_rollover = nr.group("when").strip()
            continue

        fm = FIELD_RE.match(line)
        if fm:
            name = re.sub(r"\s+", "_", fm.group("name").lower())
            value = _canon_state(fm.group("value"))
            if name == "goal":
                current.goal = value
            elif name == "dnskey":
                current.dnskey = value
            elif name == "ds":
                current.ds = value
            elif name == "zone_rrsig":
                current.zone_rrsig = value
            elif name == "key_rrsig":
                current.key_rrsig = value

    return status


def diff_status(
    previous: dict[str, dict[str, str | None]],
    current: dict[str, dict[str, str | None]],
) -> list[tuple[int, str, str | None, str | None]]:
    """Diff two snapshots (``{tag_str: {field: value}}``).

    Returns a list of ``(tag, field, old, new)`` tuples, including new keys
    (old values will be ``None``) and vanished keys (new values ``None``).
    """

    changes: list[tuple[int, str, str | None, str | None]] = []
    prev_tags = set(previous)
    curr_tags = set(current)

    for tag_s in curr_tags:
        new_fields = current[tag_s] or {}
        old_fields = previous.get(tag_s) or {}
        for field_name, new_val in new_fields.items():
            old_val = old_fields.get(field_name)
            if old_val != new_val:
                changes.append((int(tag_s), field_name, old_val, new_val))

    for tag_s in prev_tags - curr_tags:
        for field_name, old_val in (previous.get(tag_s) or {}).items():
            changes.append((int(tag_s), field_name, old_val, None))

    return changes
