"""Event channel classification.

For the split timelines we slice the unified event stream into two
well-defined subsets:

* **dns** — anything observed via live DNS query or reported by
  ``rndc dnssec -status``.
* **file** — anything that reflects a change to the on-disk key
  directory (``K*.state`` and ``K*.key`` files).

``syslog`` and ``named`` events are not part of either subset — they
belong in the chronological event log but are neither "queried /
rndc-reported" nor "file changes", so they'd muddy the split charts.
"""

from __future__ import annotations

from ..models import Event


DNS_CHANNEL_SOURCES = frozenset({"dns", "rndc"})
FILE_CHANNEL_SOURCES = frozenset({"state", "key"})


def dns_channel(events: list[Event]) -> list[Event]:
    """Events that came from a DNS probe or from ``rndc dnssec -status``."""
    return [e for e in events if e.source in DNS_CHANNEL_SOURCES]


def file_channel(events: list[Event]) -> list[Event]:
    """Events that reflect a change to a ``K*.state`` or ``K*.key`` file."""
    return [e for e in events if e.source in FILE_CHANNEL_SOURCES]
