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

        # Clean deleted keys: any scope we've previously snapshotted
        # but didn't see in this scan means the K*.state file is no
        # longer where we expect it (operator cleanup, backup move,
        # or iodyn retiring the key out of the active directory).
        # Emit a *single* summary event per vanished key — not a
        # flood of per-field "unset" events — then drop the stored
        # data for that key so it stops appearing on timelines.
        prior_scopes = set(self.db.list_snapshot_scopes(self.name))
        vanished = prior_scopes - seen_scopes
        for scope in vanished:
            # scope shape is "zone#tag#role"
            try:
                zone, tag_s, role = scope.split("#", 2)
                tag = int(tag_s)
            except (ValueError, IndexError):
                # Malformed scope — just drop it, don't emit an event.
                self.db.delete_snapshot(self.name, scope)
                continue

            prev = self.db.get_snapshot(self.name, scope) or {}
            last_fields = prev.get("fields", {}) or {}
            last_path = prev.get("path")

            self.db.insert_event(
                Event(
                    ts=now_iso(),
                    source="state",
                    event_type="state_key_file_deleted",
                    summary=(
                        f"{zone} {role} tag={tag}: K*.state file no longer "
                        f"present on disk (state change: removed)"
                    ),
                    zone=zone,
                    key_tag=tag,
                    key_role=role,
                    detail={
                        "last_path": last_path,
                        "last_fields": last_fields,
                    },
                )
            )
            # Drop the stored data for this key so it stops showing
            # on rollover / per-key views. Events stay in place —
            # they carry their own zone/tag/role metadata and the
            # historical record is intentionally preserved.
            self.db.delete_snapshot(self.name, scope)
            self.db.delete_snapshot("key_file", scope)
            self.db.delete_key(zone, tag, role)
            log.info(
                "state_file cleanup: %s %s tag=%d file gone, data cleared",
                zone, role, tag,
            )
