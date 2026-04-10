"""Collector that runs ``rndc dnssec -status <zone>`` per zone.

Parses BIND's own view of each key's lifecycle — goal / dnskey / ds /
zone rrsig / key rrsig states and the published / signing booleans —
and diffs against the previous snapshot to emit ``rndc_state_changed``
events. This is the cleanest window into what BIND thinks is happening
and is deliberately distinct from the on-disk ``.state`` collector so
divergences between the two are visible in the timeline.
"""

from __future__ import annotations

import asyncio
import logging
import shutil

from ..models import Event, now_iso
from ..parsers.rndc_status import diff_status, parse_rndc_status
from .base import Collector

log = logging.getLogger("dnssec_tracker.collector.rndc_status")


class RndcStatusCollector(Collector):
    name = "rndc_status"

    def __init__(self, config, db):
        super().__init__(config, db)
        self.interval = float(config.rndc_interval)

    async def sample(self) -> None:
        rndc = self.config.rndc_bin or "rndc"
        if shutil.which(rndc) is None and not self._path_exists(rndc):
            log.warning("rndc binary %s not found; collector idle", rndc)
            return

        zones = self.db.list_zones()
        if not zones:
            return

        for zone in zones:
            try:
                output = await self._run_rndc(zone.name)
            except RndcError as exc:
                log.warning("rndc dnssec -status %s failed: %s", zone.name, exc)
                continue

            status = parse_rndc_status(zone.name, output)
            snapshot = {str(k.key_tag): k.state_snapshot() for k in status.keys}
            prev = self.db.get_snapshot(self.name, f"zone:{zone.name}")
            prev_snap = prev.get("keys", {}) if prev else {}
            changes = diff_status(prev_snap, snapshot)

            if not prev:
                # First observation: emit a single summary event so the
                # report has an anchor point.
                self.db.insert_event(
                    Event(
                        ts=now_iso(),
                        source="rndc",
                        event_type="rndc_first_observation",
                        summary=(
                            f"{zone.name}: observed {len(status.keys)} key(s) via rndc"
                        ),
                        zone=zone.name,
                        detail={
                            "keys": snapshot,
                            "policy": status.policy,
                            "current_time": status.current_time,
                        },
                    )
                )
            else:
                for tag, field_name, old, new in changes:
                    key_row = next((k for k in status.keys if k.key_tag == tag), None)
                    role = key_row.role if key_row else None
                    self.db.insert_event(
                        Event(
                            ts=now_iso(),
                            source="rndc",
                            event_type="rndc_state_changed",
                            summary=(
                                f"{zone.name} {role or ''} tag={tag} "
                                f"{field_name}: {old or '(none)'} -> {new or '(none)'}"
                            ),
                            zone=zone.name,
                            key_tag=tag,
                            key_role=role,
                            detail={
                                "field": field_name,
                                "old": old,
                                "new": new,
                                "policy": status.policy,
                            },
                        )
                    )

            self.db.set_snapshot(
                self.name,
                f"zone:{zone.name}",
                {
                    "keys": snapshot,
                    "policy": status.policy,
                    "current_time": status.current_time,
                },
            )

    @staticmethod
    def _path_exists(path: str) -> bool:
        from pathlib import Path
        return Path(path).exists()

    async def _run_rndc(self, zone: str) -> str:
        cmd = [self.config.rndc_bin]
        if self.config.rndc_key_file:
            cmd.extend(["-k", str(self.config.rndc_key_file)])
        if self.config.rndc_server:
            host, _, port = self.config.rndc_server.partition(":")
            if host:
                cmd.extend(["-s", host])
            if port:
                cmd.extend(["-p", port])
        cmd.extend(["dnssec", "-status", zone])

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise RndcError("timed out")
        if proc.returncode != 0:
            raise RndcError(stderr.decode("utf-8", errors="replace").strip())
        return stdout.decode("utf-8", errors="replace")


class RndcError(RuntimeError):
    pass
