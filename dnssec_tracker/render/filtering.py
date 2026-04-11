"""Filter layer shared by zone, key, and report renderers.

The ``/events`` page has its own regex filter baked into ``db.py`` and
``events_page`` — that path stays exactly as-is. This module is the
*render-side* counterpart that clips the event stream before it feeds
the calendar, the split DNS/File event timelines, the state-transition
timeline, and the chronological event table on the zone, key, and
report pages.

Three dimensions, deliberately small:

* ``hide_type_patterns`` — comma-separated regexes applied with
  ``re.search`` (case-insensitive). The "DNSKEY focus" preset is
  just ``rrsig,soa``; any free-form regex list works the same way.
* ``hide_sources`` — exact source-name matches (``dns``, ``rndc``,
  ``state``, ``key``, ``syslog``, ``named``).
* ``role`` — one of ``all`` / ``KSK`` / ``ZSK`` / ``CSK``. Role
  filtering keeps events whose ``key_role`` matches *and* events that
  have no role attached at all (zone-wide SOA observations, parent-
  side DS events where the collector populates ``key_tag`` but not
  always ``key_role``). Without this escape hatch a KSK page would
  lose the very DS lifecycle that makes KSK rollovers interesting.

  ``role=ZSK`` additionally drops ``dns_ds_*`` / ``dns_cds_*`` /
  ``dns_cdnskey_*`` events: ZSKs have no parent presence, so DS and
  CDS/CDNSKEY noise is just confusing on a ZSK view.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..models import Event


VALID_ROLES = ("all", "KSK", "ZSK", "CSK")

# Event-type families that are unambiguously about the parent side of
# the delegation and therefore have no place on a ZSK view.
_ZSK_HIDDEN_FAMILIES = re.compile(r"^dns_(ds|cds|cdnskey)_", re.IGNORECASE)


@dataclass
class FilterSet:
    """Render-side event filter. All fields default to "match everything"."""

    hide_type_patterns: list[str] = field(default_factory=list)
    hide_sources: list[str] = field(default_factory=list)
    role: str = "all"

    @classmethod
    def from_query(
        cls,
        hide_types: str | None,
        hide_sources: str | None,
        role: str | None,
    ) -> "FilterSet":
        """Build a FilterSet from raw query-string values.

        Comma-separated lists are stripped and empties dropped. Any
        role value outside ``VALID_ROLES`` is clamped to ``all`` so a
        malformed query parameter just degrades to "no filter" rather
        than 500ing the page.
        """

        def _split(raw: str | None) -> list[str]:
            if not raw:
                return []
            return [p.strip() for p in raw.split(",") if p.strip()]

        clean_role = role if role in VALID_ROLES else "all"
        return cls(
            hide_type_patterns=_split(hide_types),
            hide_sources=_split(hide_sources),
            role=clean_role,
        )

    def is_active(self) -> bool:
        """True if any non-default filter dimension is set.

        Templates use this to decide whether to render the "filters
        applied" summary box at the top of the report.
        """

        return bool(
            self.hide_type_patterns
            or self.hide_sources
            or (self.role and self.role != "all")
        )

    def summary(self) -> str:
        """Human-readable one-liner — used by the report summary box."""

        bits: list[str] = []
        if self.role and self.role != "all":
            bits.append(f"role={self.role}")
        if self.hide_type_patterns:
            bits.append("hide_types=" + ",".join(self.hide_type_patterns))
        if self.hide_sources:
            bits.append("hide_sources=" + ",".join(self.hide_sources))
        return ", ".join(bits)


def _compile_patterns(patterns: list[str]) -> list[re.Pattern]:
    """Compile a list of hide_type patterns, swallowing bad regexes.

    Mirrors the approach db.py uses for the /events filter: a typo in
    one pattern shouldn't discard the rest or crash the page.
    """

    out: list[re.Pattern] = []
    for p in patterns:
        try:
            out.append(re.compile(p, re.IGNORECASE))
        except re.error:
            continue
    return out


def filter_events(events: list[Event], fs: FilterSet | None) -> list[Event]:
    """Apply a FilterSet to a list of events.

    Order of operations: role → source → type. ``None`` / empty
    FilterSet is a no-op so existing call sites that pass ``None``
    still work unchanged.
    """

    if fs is None or not fs.is_active():
        return list(events)

    compiled = _compile_patterns(fs.hide_type_patterns)
    hide_sources = set(fs.hide_sources)
    role = fs.role

    out: list[Event] = []
    for e in events:
        # --- role filter --------------------------------------------
        if role in ("KSK", "ZSK", "CSK"):
            if e.key_role is not None and e.key_role != role:
                continue
            # ZSKs have no parent presence → strip DS/CDS/CDNSKEY
            if role == "ZSK" and _ZSK_HIDDEN_FAMILIES.search(e.event_type or ""):
                continue
        # --- source filter ------------------------------------------
        if hide_sources and e.source in hide_sources:
            continue
        # --- event_type filter --------------------------------------
        if compiled and any(p.search(e.event_type or "") for p in compiled):
            continue
        out.append(e)
    return out
