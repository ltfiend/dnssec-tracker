"""Detect keys that are past their scheduled Delete but still
published at the zone or the parent.

A key whose scheduled ``Delete`` time has already passed but whose
DNSKEY is still observed in the zone's DNSKEY RRset, or whose DS is
still present at the parent, is in an unhealthy operational state —
resolvers can still see it, the chain of trust is still anchored on
it, and BIND (or whatever's managing the key) clearly missed the
scheduled cleanup. This is *exactly* the kind of corner case the
tracker exists to surface.

This module provides a pure classification helper that the rollover
renderer uses to emphasise those segments, and the zone / per-key /
report templates use to show a warning banner at the top of the
page. The classifier only looks at current state (the combined
``fields``/``timings`` snapshot passed by the wiring layer plus the
``dns_probe`` zone + parent snapshots), so it's trivial to unit test
and free of event-log replay.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from ..collectors.dns_probe import _extract_key_tag
from ..models import Key


class OverdueState(Enum):
    NONE = "none"
    DNSKEY_LINGERING = "dnskey_lingering"       # observed at zone, not at parent
    DS_LINGERING = "ds_lingering"               # observed at parent, not at zone
    BOTH_LINGERING = "both_lingering"           # observed at both


@dataclass
class OverdueAssessment:
    """The result of classifying a single key.

    ``delete_at`` is the reference "should-be-gone-by" moment used
    for the comparison; it's the scheduled ``Delete`` from the
    ``K*.key`` header when present, falling back to BIND's recorded
    ``Removed`` from the ``K*.state`` file.
    """

    key: Key
    state: OverdueState
    delete_at: datetime | None
    observed_in_zone: bool
    observed_at_parent: bool

    @property
    def is_overdue(self) -> bool:
        return self.state != OverdueState.NONE

    def summary(self) -> str:
        """One-line human description for the warning banner."""
        if self.state == OverdueState.BOTH_LINGERING:
            where = "DNSKEY at zone AND DS at parent"
        elif self.state == OverdueState.DNSKEY_LINGERING:
            where = "DNSKEY at zone"
        elif self.state == OverdueState.DS_LINGERING:
            where = "DS at parent"
        else:
            return f"{self.key.role} tag {self.key.key_tag}: clean"
        when = (
            self.delete_at.strftime("%Y-%m-%d %H:%M UTC")
            if self.delete_at else "unknown"
        )
        return (
            f"{self.key.role} tag {self.key.key_tag} (alg {self.key.algorithm}): "
            f"past scheduled Delete ({when}) but {where} still observed"
        )


def _parse_bind_ts(value: str | None) -> datetime | None:
    """Parse a BIND packed ``YYYYMMDDHHMMSS`` timestamp. ``"0"`` / ``""``
    / ``None`` / malformed all return ``None`` so the caller can use
    the usual ``a or b`` fallthrough idiom."""
    if value is None:
        return None
    s = str(value).strip()
    if not s or s == "0":
        return None
    if len(s) != 14 or not s.isdigit():
        return None
    try:
        return datetime(
            int(s[0:4]), int(s[4:6]), int(s[6:8]),
            int(s[8:10]), int(s[10:12]), int(s[12:14]),
            tzinfo=timezone.utc,
        )
    except ValueError:
        return None


def _tags_in_rrset(records: list[str], rrtype: str) -> set[int]:
    """Pull the set of key tags referenced by a list of DNSKEY/DS-style
    records in their text wire-form."""
    tags: set[int] = set()
    for r in records or []:
        t = _extract_key_tag(rrtype, r)
        if t is not None:
            tags.add(t)
    return tags


def assess_overdue(
    key: Key,
    snapshot: dict | None,
    zone_dns_snapshot: dict | None,
    parent_dns_snapshot: dict | None,
    now: datetime,
) -> OverdueAssessment:
    """Classify a single key.

    Parameters
    ----------
    key
        The :class:`Key` to assess.
    snapshot
        Combined state_file + key_file snapshot,
        ``{"fields": {...}, "timings": {...}}`` — the shape the
        rollover view already consumes.
    zone_dns_snapshot
        The ``dns_probe`` *zone*-side snapshot,
        ``{"DNSKEY": [...], "SOA": [...], ...}``.
    parent_dns_snapshot
        The ``dns_probe`` *parent*-side snapshot, ``{"DS": [...]}``.
    now
        Current time as a tz-aware datetime.

    Returns
    -------
    OverdueAssessment
        ``state == NONE`` if the key isn't past its scheduled Delete,
        or if it is but nothing's lingering. Otherwise one of the
        three lingering states.
    """

    snapshot = snapshot or {}
    fields = snapshot.get("fields") or {}
    timings = snapshot.get("timings") or {}

    # The scheduled Delete from the K*.key header is the primary
    # signal. If it's missing, fall back to BIND's recorded Removed
    # on the .state file side. If neither is set, there's no deadline
    # to measure against — the key isn't classifiable as overdue.
    delete_at = (
        _parse_bind_ts(timings.get("Delete"))
        or _parse_bind_ts(fields.get("Removed"))
    )

    if delete_at is None or delete_at > now:
        return OverdueAssessment(
            key=key,
            state=OverdueState.NONE,
            delete_at=delete_at,
            observed_in_zone=False,
            observed_at_parent=False,
        )

    zone_tags = _tags_in_rrset(
        (zone_dns_snapshot or {}).get("DNSKEY", []) or [], "DNSKEY"
    )
    parent_tags = _tags_in_rrset(
        (parent_dns_snapshot or {}).get("DS", []) or [], "DS"
    )

    observed_zone = key.key_tag in zone_tags
    observed_parent = key.key_tag in parent_tags

    if observed_zone and observed_parent:
        state = OverdueState.BOTH_LINGERING
    elif observed_zone:
        state = OverdueState.DNSKEY_LINGERING
    elif observed_parent:
        state = OverdueState.DS_LINGERING
    else:
        state = OverdueState.NONE

    return OverdueAssessment(
        key=key,
        state=state,
        delete_at=delete_at,
        observed_in_zone=observed_zone,
        observed_at_parent=observed_parent,
    )


def assess_all(
    keys: list[Key],
    snapshots: dict[str, dict],
    zone_dns_snapshot: dict | None,
    parent_dns_snapshot: dict | None,
    now: datetime | None = None,
) -> list[OverdueAssessment]:
    """Batch version: classify every key and return only the results
    (both clean and lingering — caller filters to ``is_overdue`` for
    the banner).
    """
    now = now or datetime.now(timezone.utc)
    out: list[OverdueAssessment] = []
    for k in keys:
        scope = f"{k.zone}#{k.key_tag}#{k.role}"
        snap = snapshots.get(scope)
        out.append(
            assess_overdue(
                k, snap, zone_dns_snapshot, parent_dns_snapshot, now
            )
        )
    return out
