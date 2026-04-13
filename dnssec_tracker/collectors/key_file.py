"""Collector that polls ``K*.key`` timing comments."""

from __future__ import annotations

from ..models import Event, Key, Zone, now_iso
from ..parsers.bind_key import diff_timings, scan_key_files
from .base import Collector


class KeyFileCollector(Collector):
    name = "key_file"
    interval = 30.0

    async def sample(self) -> None:
        files = scan_key_files(
            self.config.key_dir,
            recursive=self.config.key_dir_recursive,
        )
        for kf in files:
            scope = f"{kf.zone}#{kf.key_tag}#{kf.role}"
            self.db.upsert_zone(
                Zone(
                    name=kf.zone,
                    key_dir=str(kf.path.parent),
                    first_seen=now_iso(),
                    last_seen=now_iso(),
                )
            )
            self.db.upsert_key(
                Key(
                    zone=kf.zone,
                    key_tag=kf.key_tag,
                    role=kf.role,
                    algorithm=kf.algorithm,
                    key_id=kf.path.stem,
                )
            )

            prev = self.db.get_snapshot(self.name, scope)
            prev_timings = prev.get("timings", {}) if prev else {}
            changes = diff_timings(prev_timings, kf.timings)

            if not prev:
                self.db.insert_event(
                    Event(
                        ts=now_iso(),
                        source="key",
                        event_type="key_file_observed",
                        summary=f"new K*.key for {kf.zone} {kf.role} tag={kf.key_tag}",
                        zone=kf.zone,
                        key_tag=kf.key_tag,
                        key_role=kf.role,
                        detail={
                            "timings": kf.timings,
                            "path": str(kf.path),
                            "dnskey": kf.dnskey_record,
                        },
                    )
                )
            else:
                for field_name, (old, new) in changes.items():
                    self.db.insert_event(
                        Event(
                            ts=now_iso(),
                            source="key",
                            event_type="key_timing_changed",
                            summary=(
                                f"{kf.zone} {kf.role} tag={kf.key_tag} {field_name}: "
                                f"{old or '(unset)'} -> {new}"
                            ),
                            zone=kf.zone,
                            key_tag=kf.key_tag,
                            key_role=kf.role,
                            detail={
                                "field": field_name,
                                "old": old,
                                "new": new,
                                "path": str(kf.path),
                            },
                        )
                    )

            self.db.set_snapshot(
                self.name, scope, {"timings": kf.timings, "path": str(kf.path)}
            )
