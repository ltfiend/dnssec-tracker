"""Parser for BIND's named log lines (dnssec category)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone


# Typical format of a named log line in the standard category layout:
#   "10-Apr-2026 08:27:10.123 dnssec: info: zone example.com/IN: next key event in 86400 seconds"
NAMED_LINE_RE = re.compile(
    r"""^
    (?P<ts>\d{1,2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+
    (?P<category>[\w\-]+):\s+
    (?P<severity>\w+):\s+
    (?P<message>.*)$
    """,
    re.VERBOSE,
)

ZONE_PREFIX_RE = re.compile(r"^zone\s+(?P<zone>\S+?)/(?P<class>IN|CH|HS):\s*(?P<body>.*)$")

# Patterns we recognise in the dnssec category.
#
# The checkds pattern needs to come first because BIND writes the
# control-channel log line with zero-or-some-whitespace structure
# that the catch-all "signed" pattern would otherwise gobble up —
# ordering matters in the current linear scan.
PATTERNS = [
    # Manual DS-state confirmation issued by the operator, e.g.
    #   received control channel command 'dnssec -checkds -key 12345 published example.com'
    #   received control channel command 'dnssec -checkds withdrawn example.com'
    # With -key it targets a specific KSK tag; without, it applies to
    # every key currently needing confirmation. This is a *manual*
    # state change (as opposed to BIND's own automatic state-machine
    # transitions), so the event_type carries "manual" explicitly so
    # the timeline/report can call out operator intervention as
    # distinct from scheduled BIND activity.
    (
        re.compile(
            r"received control channel command\s+['\"]?"
            r"\s*dnssec\s+-checkds"
            r"(?:\s+-key\s+(?P<tag>\d+))?"
            r"\s+(?P<action>published|withdrawn)"
            r"\s+(?P<zone>\S+?)['\"]?\s*$",
            re.IGNORECASE,
        ),
        "named_manual_checkds",
    ),
    # "next key event in 86400 seconds"
    (
        re.compile(r"next key event in (?P<seconds>\d+) seconds"),
        "named_next_key_event",
    ),
    # "DNSKEY ECDSAP256SHA256/13/12345 (KSK) is now published"
    (
        re.compile(
            r"DNSKEY\s+(?P<algo_name>[A-Za-z0-9]+)/(?P<algo>\d+)/(?P<tag>\d+)\s*(?:\((?P<role>KSK|ZSK|CSK)\))?\s+is now published",
            re.IGNORECASE,
        ),
        "named_dnskey_published",
    ),
    # "DNSKEY ... is now active"
    (
        re.compile(
            r"DNSKEY\s+\S+/(?P<algo>\d+)/(?P<tag>\d+)\s*(?:\((?P<role>KSK|ZSK|CSK)\))?\s+is now active",
            re.IGNORECASE,
        ),
        "named_dnskey_active",
    ),
    # "DNSKEY ... is now retired"
    (
        re.compile(
            r"DNSKEY\s+\S+/(?P<algo>\d+)/(?P<tag>\d+)\s*(?:\((?P<role>KSK|ZSK|CSK)\))?\s+is now retired",
            re.IGNORECASE,
        ),
        "named_dnskey_retired",
    ),
    # "zone signed: <N> signed / <M> RR"
    (
        re.compile(r"signed"),
        "named_zone_signed",
    ),
    # "CDS/CDNSKEY for ..."
    (
        re.compile(r"CDS|CDNSKEY"),
        "named_cds_event",
    ),
]


@dataclass
class NamedEvent:
    ts: datetime
    severity: str
    category: str
    zone: str | None
    message: str
    event_type: str
    detail: dict


def _parse_named_ts(s: str) -> datetime:
    try:
        return datetime.strptime(s.split(".")[0], "%d-%b-%Y %H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return datetime.now(timezone.utc)


def match_named_body(message: str) -> tuple[str, dict, str | None, str] | None:
    """Pattern-match a named message body (no BIND timestamp/prefix).

    Returns ``(event_type, detail, zone, body)`` on a known pattern or
    ``None`` if nothing matched. Exposed so the syslog-tail collector
    — which receives named lines without the ``DD-MMM-YYYY HH:MM:SS
    category: severity:`` prefix — can reuse the same pattern
    vocabulary.

    ``zone`` is taken from the ``zone <name>/IN:`` prefix when present,
    otherwise from a ``zone`` named group in the matching pattern
    (e.g. the checkds pattern captures the zone from the command body
    itself).
    """

    zone: str | None = None
    body = message
    zm = ZONE_PREFIX_RE.match(message)
    if zm:
        zone = zm.group("zone").rstrip(".")
        body = zm.group("body")

    for pattern, event_type in PATTERNS:
        pm = pattern.search(body)
        if pm:
            detail = {k: v for k, v in pm.groupdict().items() if v is not None}
            detail["raw"] = message
            if zone is None and "zone" in detail:
                zone = detail["zone"].rstrip(".")
            return event_type, detail, zone, body
    return None


def parse_named_line(line: str) -> NamedEvent | None:
    """Parse one BIND log line. Returns ``None`` if it's not a dnssec
    category line we know how to interpret.
    """

    line = line.rstrip("\n")
    if not line:
        return None
    m = NAMED_LINE_RE.match(line)
    if not m:
        return None
    if m.group("category") not in ("dnssec", "general"):
        return None

    ts = _parse_named_ts(m.group("ts"))
    message = m.group("message")

    result = match_named_body(message)
    if result is not None:
        event_type, detail, zone, body = result
        return NamedEvent(
            ts=ts,
            severity=m.group("severity"),
            category=m.group("category"),
            zone=zone,
            message=body,
            event_type=event_type,
            detail=detail,
        )

    # Unknown dnssec line — keep as a low-signal event so it still
    # shows up in the raw feed.
    zone = None
    body = message
    zm = ZONE_PREFIX_RE.match(message)
    if zm:
        zone = zm.group("zone").rstrip(".")
        body = zm.group("body")
    return NamedEvent(
        ts=ts,
        severity=m.group("severity"),
        category=m.group("category"),
        zone=zone,
        message=body,
        event_type="named_dnssec_message",
        detail={"raw": message},
    )
