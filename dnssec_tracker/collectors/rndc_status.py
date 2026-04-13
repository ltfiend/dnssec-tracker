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
import time

from ..models import Event, now_iso
from ..parsers.rndc_status import diff_status, parse_rndc_status
from .base import Collector

log = logging.getLogger("dnssec_tracker.collector.rndc_status")
query_log = logging.getLogger("dnssec_tracker.query.rndc")


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
                # When a key vanishes from the rndc output entirely,
                # diff_status produces a (tag, field, old, None) tuple
                # for every field the previous snapshot held — that
                # used to spam the event log with ~9 synthetic
                # rndc_state_changed rows per deletion. Collapse each
                # vanished key into one rndc_key_deleted event
                # instead, and strip those tags out of the per-field
                # change list so the remaining events are only real
                # field transitions on keys that are still live.
                vanished_tags = {
                    t for t in prev_snap if t not in snapshot
                }
                role_by_tag: dict[int, str] = {}
                if vanished_tags:
                    # Look up roles once — the rndc status output no
                    # longer carries them (the key is gone), but the
                    # keys table in the tracker still has the row
                    # from earlier observation.
                    for k in self.db.list_keys(zone.name):
                        role_by_tag[k.key_tag] = k.role
                for tag_s in vanished_tags:
                    tag = int(tag_s)
                    role = role_by_tag.get(tag)
                    self.db.insert_event(
                        Event(
                            ts=now_iso(),
                            source="rndc",
                            event_type="rndc_key_deleted",
                            summary=(
                                f"{zone.name} {role or ''} tag={tag} "
                                f"no longer reported by rndc dnssec -status "
                                f"(key deleted)"
                            ),
                            zone=zone.name,
                            key_tag=tag,
                            key_role=role,
                            detail={
                                "policy": status.policy,
                                "last_state": prev_snap.get(tag_s, {}),
                            },
                        )
                    )

                for tag, field_name, old, new in changes:
                    if str(tag) in vanished_tags:
                        continue  # folded into the rndc_key_deleted event
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
        """Run ``rndc dnssec -status <zone>`` and log the exec.

        Emits an INFO ``send`` line before the subprocess starts (with
        the full argv, target server, and zone) and an INFO ``recv``
        line after, with returncode, stdout/stderr byte counts, and
        elapsed ms. The full stdout text is logged at DEBUG.
        """

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

        query_log.info(
            "send: server=%s zone=%s cmd=%s",
            self.config.rndc_server or "(default)",
            zone,
            " ".join(cmd),
        )

        start = time.monotonic()
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
            elapsed_ms = (time.monotonic() - start) * 1000
            query_log.warning(
                "recv: server=%s zone=%s TIMED_OUT elapsed_ms=%.1f",
                self.config.rndc_server or "(default)", zone, elapsed_ms,
            )
            raise RndcError("timed out")

        elapsed_ms = (time.monotonic() - start) * 1000
        if proc.returncode != 0:
            err = stderr.decode("utf-8", errors="replace").strip()
            query_log.warning(
                "recv: server=%s zone=%s rc=%s stderr=%r elapsed_ms=%.1f",
                self.config.rndc_server or "(default)",
                zone, proc.returncode, err, elapsed_ms,
            )
            raise RndcError(err)

        out_text = stdout.decode("utf-8", errors="replace")
        query_log.info(
            "recv: server=%s zone=%s rc=0 stdout_bytes=%d stderr_bytes=%d elapsed_ms=%.1f",
            self.config.rndc_server or "(default)",
            zone, len(stdout), len(stderr), elapsed_ms,
        )
        query_log.debug(
            "stdout: server=%s zone=%s\n%s",
            self.config.rndc_server or "(default)", zone, out_text,
        )
        return out_text


class RndcError(RuntimeError):
    pass
