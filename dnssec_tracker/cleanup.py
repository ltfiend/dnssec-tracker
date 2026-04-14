"""Manual cleanup for keys whose files are no longer on disk.

When a ``K*.state`` file disappears from the key directory we can
clear the key's stored data (snapshots + the ``keys``-table row)
so forward-looking views stop rendering it. This is deliberately a
**manual** action rather than something the collectors do on every
poll:

* A momentary file move during an iodyn-dnssec settime run or a
  BIND reload shouldn't race the next poll and wipe a key's
  snapshot just because the file wasn't visible for 30 seconds.
* With ``key_dir_recursive`` defaulting to False, a key moved
  into a deeper subdirectory would register as gone — the
  operator should be the one to confirm that's what they meant.

The lifecycle:
* Scan the key directory (honouring the recursion config) to
  determine the set of scopes whose state files are *currently*
  present.
* Compare against every scope previously snapshotted under the
  ``state_file`` collector.
* For each scope in the "previously known" set minus the
  "currently present" set, emit one ``state_key_file_deleted``
  event (summary of the transition, ``detail.last_fields`` with
  the final state the collector saw) and drop the associated
  state_file + key_file snapshots and the keys-table row.

Events stay in place regardless — they carry their own zone /
tag / role metadata, and the historical event log is meant to be
an append-only record of what happened.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from .config import Config
from .db import Database
from .models import Event, now_iso
from .parsers.bind_state import scan_state_files


log = logging.getLogger("dnssec_tracker.cleanup")


@dataclass
class CleanedKey:
    zone: str
    key_tag: int
    role: str
    last_path: str | None = None
    last_fields: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "zone": self.zone,
            "key_tag": self.key_tag,
            "role": self.role,
            "last_path": self.last_path,
            "last_fields": self.last_fields,
        }


@dataclass
class CleanupReport:
    cleaned: list[CleanedKey] = field(default_factory=list)
    live_scopes: int = 0     # how many keys are still present on disk
    prior_scopes: int = 0    # how many scopes were in the snapshot store

    @property
    def count(self) -> int:
        return len(self.cleaned)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cleaned": [c.to_dict() for c in self.cleaned],
            "count": self.count,
            "live_scopes": self.live_scopes,
            "prior_scopes": self.prior_scopes,
        }


def clean_deleted_keys(db: Database, config: Config) -> CleanupReport:
    """Walk the key directory, fold every vanished key's lifetime
    of stored data into a single ``state_key_file_deleted`` event,
    and drop the stored snapshots + keys-table row.

    Pure-ish (mutates the DB; otherwise deterministic given the
    current filesystem + DB state). Safe to call repeatedly — a
    second call with nothing new gone does nothing.

    Returns a :class:`CleanupReport` describing what was cleaned,
    for logging / the API response / the CLI summary.
    """

    # Which scopes are *actually* on disk right now?
    files = scan_state_files(
        config.key_dir,
        recursive=config.key_dir_recursive,
    )
    live_scopes = {
        f"{sf.zone}#{sf.key_tag}#{sf.role}" for sf in files
    }

    # Which scopes did we previously snapshot?
    prior_scopes = set(db.list_snapshot_scopes("state_file"))
    vanished = prior_scopes - live_scopes

    report = CleanupReport(
        live_scopes=len(live_scopes),
        prior_scopes=len(prior_scopes),
    )

    for scope in sorted(vanished):
        try:
            zone, tag_s, role = scope.split("#", 2)
            tag = int(tag_s)
        except (ValueError, IndexError):
            # Malformed scope — drop it without emitting an event.
            log.warning("cleanup: dropping malformed scope %r", scope)
            db.delete_snapshot("state_file", scope)
            continue

        prev = db.get_snapshot("state_file", scope) or {}
        last_fields = prev.get("fields", {}) or {}
        last_path = prev.get("path")

        db.insert_event(
            Event(
                ts=now_iso(),
                source="state",
                event_type="state_key_file_deleted",
                summary=(
                    f"{zone} {role} tag={tag}: K*.state file no longer "
                    f"present on disk (cleaned up manually)"
                ),
                zone=zone,
                key_tag=tag,
                key_role=role,
                detail={
                    "last_path": last_path,
                    "last_fields": last_fields,
                    "trigger": "manual",
                },
            )
        )
        db.delete_snapshot("state_file", scope)
        db.delete_snapshot("key_file", scope)
        db.delete_key(zone, tag, role)
        log.info(
            "cleanup: removed %s %s tag=%d (file gone)", zone, role, tag,
        )
        report.cleaned.append(CleanedKey(
            zone=zone,
            key_tag=tag,
            role=role,
            last_path=last_path,
            last_fields=last_fields,
        ))

    return report
