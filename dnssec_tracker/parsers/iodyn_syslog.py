"""Parser for iodyn-dnssec's syslog lines.

iodyn-dnssec writes events via its ``LOG`` class to syslog with the
format::

    <callername>:<description>

For subprocess invocations it writes::

    <callername> cmd:<space-separated argv>

The known callernames are (from ``iodyn-dnssec.py``):

* ``bind_reload``        — RNDC reload
* ``Zone.create``        — new zone directory
* ``Zone.nsec3``         — enabling NSEC3 for a zone
* ``gen_successor``      — creating a successor key (dnssec-keygen -S)
* ``Key.create``         — creating a fresh key (dnssec-keygen)
* ``settime``            — running dnssec-settime to shift a timing field
* ``ds``                 — listing / generating DS
* ``key.remove_deleted`` — moving expired keys out of the live dir

A standard syslog line prefix looks like::

    Apr 10 08:27:10 host iodyn-dnssec[1234]: Key.create:Creating ...

We accept both traditional syslog format and RFC5424-ish variants — the
timestamp may be parsed or fall back to "now" if the file is too
exotic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone

# Traditional syslog line:
#   "Apr 10 08:27:10 host iodyn-dnssec[1234]: MESSAGE"
TRAD_RE = re.compile(
    r"""^
    (?P<month>[A-Z][a-z]{2})\s+
    (?P<day>\d{1,2})\s+
    (?P<time>\d{2}:\d{2}:\d{2})\s+
    (?P<host>\S+)\s+
    (?P<prog>[\w\-./]+?)(?:\[(?P<pid>\d+)\])?:\s+
    (?P<msg>.*)$
    """,
    re.VERBOSE,
)

# RFC5424 style: "<165>1 2024-04-10T08:27:10Z host iodyn-dnssec 1234 - - MSG"
RFC5424_RE = re.compile(
    r"""^
    <\d+>\d+\s+
    (?P<ts>\S+)\s+
    (?P<host>\S+)\s+
    (?P<prog>\S+)\s+
    (?P<pid>\S+)\s+
    \S+\s+\S+\s+
    (?P<msg>.*)$
    """,
    re.VERBOSE,
)

IODYN_PROG_NAMES = ("iodyn-dnssec", "iodyn_dnssec", "iodyn")
NAMED_PROG_NAMES = ("named", "bind", "isc-named")

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# iodyn message prefixes that map to structured event types.
IODYN_TAG_MAP = {
    "bind_reload": "iodyn_rndc_reload",
    "Zone.create": "iodyn_zone_created",
    "Zone.nsec3": "iodyn_nsec3_enabled",
    "gen_successor": "iodyn_successor_key",
    "Key.create": "iodyn_key_created",
    "settime": "iodyn_settime",
    "ds": "iodyn_ds_action",
    "key.remove_deleted": "iodyn_key_removed",
}

# Matches the leading "tag:" or "tag cmd:" on an iodyn message.
IODYN_TAG_RE = re.compile(
    r"^(?P<tag>[A-Za-z_][\w.]*)(?:\s+cmd)?:\s*(?P<rest>.*)$"
)

# "Creating example.com KSK key using ..." — zone is the second token.
KEY_CREATE_ZONE_RE = re.compile(
    r"^Creating\s+(?P<zone>\S+)\s+(?P<role>KSK|ZSK|CSK)", re.IGNORECASE
)

# "modifying example.com KSKkey setting Publish to 1234567890"
SETTIME_ZONE_RE = re.compile(
    r"^modifying\s+(?P<zone>\S+)\s+(?P<role>KSK|ZSK|CSK)key\s+setting\s+(?P<field>\w+)\s+to\s+(?P<value>\S+)",
    re.IGNORECASE,
)


@dataclass
class SyslogLine:
    ts: datetime
    host: str
    program: str
    pid: str | None
    message: str


@dataclass
class IodynEvent:
    ts: datetime
    tag: str                 # iodyn callername, e.g. "Key.create"
    event_type: str          # our normalised event_type
    summary: str             # the message body
    is_command: bool         # True if the line was a "tag cmd:" form
    zone: str | None = None
    role: str | None = None
    detail: dict | None = None


def parse_syslog_line(line: str) -> SyslogLine | None:
    line = line.rstrip("\n")
    if not line:
        return None

    m = TRAD_RE.match(line)
    if m:
        month = MONTHS.get(m.group("month"), 1)
        day = int(m.group("day"))
        hh, mm, ss = (int(x) for x in m.group("time").split(":"))
        # Traditional syslog lacks a year — assume current year.
        now = datetime.now(timezone.utc)
        year = now.year
        try:
            ts = datetime(year, month, day, hh, mm, ss, tzinfo=timezone.utc)
        except ValueError:
            ts = now
        return SyslogLine(
            ts=ts,
            host=m.group("host"),
            program=m.group("prog"),
            pid=m.group("pid"),
            message=m.group("msg"),
        )

    m = RFC5424_RE.match(line)
    if m:
        raw_ts = m.group("ts")
        try:
            ts = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
        except ValueError:
            ts = datetime.now(timezone.utc)
        return SyslogLine(
            ts=ts,
            host=m.group("host"),
            program=m.group("prog"),
            pid=m.group("pid"),
            message=m.group("msg"),
        )

    return None


def is_iodyn(line: SyslogLine) -> bool:
    return any(line.program.startswith(p) for p in IODYN_PROG_NAMES)


def is_named(line: SyslogLine) -> bool:
    return any(line.program.startswith(p) for p in NAMED_PROG_NAMES)


def parse_iodyn_message(ts: datetime, message: str) -> IodynEvent | None:
    """Turn an iodyn-dnssec message body into a structured event."""

    m = IODYN_TAG_RE.match(message)
    if not m:
        return None
    tag = m.group("tag")
    rest = m.group("rest")
    is_cmd = " cmd:" in message.split("\n", 1)[0][: len(tag) + 8]
    # Classify: tag might also be "Key" + ".create"; we key off IODYN_TAG_MAP.
    event_type = IODYN_TAG_MAP.get(tag, "iodyn_other")

    detail: dict = {"tag": tag, "raw": message}
    zone: str | None = None
    role: str | None = None

    if tag == "Key.create" and not is_cmd:
        km = KEY_CREATE_ZONE_RE.match(rest)
        if km:
            zone = km.group("zone").rstrip(".")
            role = km.group("role").upper()
            detail["zone"] = zone
            detail["role"] = role

    if tag == "settime" and not is_cmd:
        sm = SETTIME_ZONE_RE.match(rest)
        if sm:
            zone = sm.group("zone").rstrip(".")
            role = sm.group("role").upper()
            detail.update(
                zone=zone,
                role=role,
                field=sm.group("field"),
                value=sm.group("value"),
            )

    return IodynEvent(
        ts=ts,
        tag=tag,
        event_type=event_type,
        summary=message,
        is_command=is_cmd,
        zone=zone,
        role=role,
        detail=detail,
    )
