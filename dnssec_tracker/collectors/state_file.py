"""Collector that polls ``K*.state`` files in the key directory.

Every 30 s it walks the configured ``key_dir``, parses each state file,
diffs against the previous snapshot (stored in ``collector_state``),
and emits events for added keys, removed keys, and per-field changes.
"""

from __future__ import annotations

import logging

from ..db import Database
from ..models import Event, Key, Zone, now_iso
from ..parsers.bind_state import (
    STATE_FIELDS,
    TIMESTAMP_FIELDS,
    StateFile,
    diff_state_fields,
    scan_state_files,
)
from .base import Collector


log = logging.getLogger("dnssec_tracker.collector.state_file")

TRACKED_FIELDS = STATE_FIELDS + TIMESTAMP_FIELDS


class StateFileCollector(Collector):
    name = "state_file"
    interval = 30.0

    def __init__(self, config, db):
        super().__init__(config, db)
        self._logged_discovery = False

    def _key_scope(self, sf: StateFile) -> str:
        return f"{sf.zone}#{sf.key_tag}#{sf.role}"

    async def sample(self) -> None:
        files = scan_state_files(
            self.config.key_dir,
            recursive=self.config.key_dir_recursive,
        )
        if not self._logged_discovery:
            zones_found = sorted({sf.zone for sf in files})
            log.info(
                "state_file first scan of %s (%s): %d file(s) across %d zone(s): %s",
                self.config.key_dir,
                "recursive" if self.config.key_dir_recursive else "non-recursive",
                len(files),
                len(zones_found),
                ", ".join(zones_found) if zones_found else "(none)",
            )
            self._logged_discovery = True
        seen_scopes: set[str] = set()

        for sf in files:
            seen_scopes.add(self._key_scope(sf))

            self.db.upsert_zone(
                Zone(
                    name=sf.zone,
                    key_dir=str(sf.path.parent),
                    first_seen=now_iso(),
                    last_seen=now_iso(),
                )
            )
            self.db.upsert_key(
                Key(
                    zone=sf.zone,
                    key_tag=sf.key_tag,
                    role=sf.role,
                    algorithm=sf.algorithm,
                    key_id=sf.key_stem(),
                    last_state_json="{}",
                )
            )

            tracked = {k: sf.fields[k] for k in TRACKED_FIELDS if k in sf.fields}

            prev = self.db.get_snapshot(self.name, self._key_scope(sf))
            if not prev:
                # First sighting — emit a single "key_observed" event.
                self.db.insert_event(
                    Event(
                        ts=now_iso(),
                        source="state",
                        event_type="state_key_observed",
                        summary=f"new K*.state for {sf.zone} {sf.role} tag={sf.key_tag}",
                        zone=sf.zone,
                        key_tag=sf.key_tag,
                        key_role=sf.role,
                        detail={"fields": tracked, "path": str(sf.path)},
                    )
                )
            else:
                changes = diff_state_fields(prev.get("fields", {}), tracked)
                for field_name, (old, new) in changes.items():
                    is_state = field_name in STATE_FIELDS
                    event_type = (
                        "state_changed" if is_state else "state_timing_changed"
                    )
                    summary = (
                        f"{sf.zone} {sf.role} tag={sf.key_tag} {field_name}: "
                        f"{old or '(unset)'} -> {new}"
                    )
                    self.db.insert_event(
                        Event(
                            ts=now_iso(),
                            source="state",
                            event_type=event_type,
                            summary=summary,
                            zone=sf.zone,
                            key_tag=sf.key_tag,
                            key_role=sf.role,
                            detail={
                                "field": field_name,
                                "old": old,
                                "new": new,
                                "path": str(sf.path),
                            },
                        )
                    )

            self.db.set_snapshot(
                self.name,
                self._key_scope(sf),
                {"fields": tracked, "path": str(sf.path)},
            )

        # NOTE: vanished-key cleanup deliberately does NOT run from
        # this polling collector. A file that's momentarily
        # unreadable during a BIND reload or iodyn-dnssec settime
        # race shouldn't wipe a key's snapshot as a side-effect of a
        # 30-second poll. Cleanup is a manual action: see
        # :func:`dnssec_tracker.cleanup.clean_deleted_keys`,
        # ``POST /api/clean-deleted-keys``, and the
        # ``dnssec-tracker --clean-deleted-keys`` CLI flag.
