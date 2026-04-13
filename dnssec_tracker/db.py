"""SQLite event store.

A single file holds zones, keys, events, and per-collector snapshots.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Iterator

from .models import Event, Key, Zone, now_iso


def _sqlite_regexp(pattern: str | None, value: str | None) -> bool:
    """Python implementation of SQLite's ``REGEXP`` operator.

    Registered as a scalar function on the connection so ``WHERE
    zone REGEXP ?`` works for the events filter. Uses ``re.search``
    so callers can pass substrings without anchors; bad patterns
    gracefully return no match rather than blowing up the query.
    """
    if pattern is None or value is None:
        return False
    try:
        return re.search(pattern, value) is not None
    except re.error:
        return False


SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS zones (
    name TEXT PRIMARY KEY,
    key_dir TEXT,
    parent_ns TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS keys (
    zone TEXT NOT NULL,
    key_tag INTEGER NOT NULL,
    role TEXT NOT NULL,
    algorithm INTEGER,
    key_id TEXT,
    first_seen TEXT NOT NULL,
    last_state_json TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (zone, key_tag, role)
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    source TEXT NOT NULL,
    zone TEXT,
    key_tag INTEGER,
    key_role TEXT,
    event_type TEXT NOT NULL,
    summary TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS events_zone_ts ON events(zone, ts);
CREATE INDEX IF NOT EXISTS events_type_ts ON events(event_type, ts);
CREATE INDEX IF NOT EXISTS events_ts      ON events(ts);

CREATE TABLE IF NOT EXISTS collector_state (
    collector TEXT NOT NULL,
    scope     TEXT NOT NULL,  -- zone name, file path, or "global"
    snapshot  TEXT NOT NULL,
    updated   TEXT NOT NULL,
    PRIMARY KEY (collector, scope)
);
"""


class Database:
    """Thread-safe wrapper around sqlite3 for the tracker's needs."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        # Register Python REGEXP so query_events can use `WHERE … REGEXP ?`
        # for the zone/event_type/source filters on the events page.
        self._conn.create_function("REGEXP", 2, _sqlite_regexp)
        with self._lock:
            self._conn.executescript(SCHEMA)

    @contextmanager
    def cursor(self) -> Iterator[sqlite3.Cursor]:
        with self._lock:
            cur = self._conn.cursor()
            try:
                yield cur
            finally:
                cur.close()

    # ---- zones ------------------------------------------------------

    def upsert_zone(self, zone: Zone) -> None:
        with self.cursor() as c:
            c.execute(
                """
                INSERT INTO zones(name, key_dir, parent_ns, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    key_dir = excluded.key_dir,
                    parent_ns = COALESCE(excluded.parent_ns, zones.parent_ns),
                    last_seen = excluded.last_seen
                """,
                (zone.name, zone.key_dir, zone.parent_ns, zone.first_seen, zone.last_seen),
            )

    def list_zones(self) -> list[Zone]:
        with self.cursor() as c:
            rows = c.execute("SELECT * FROM zones ORDER BY name").fetchall()
        return [
            Zone(
                name=r["name"],
                key_dir=r["key_dir"],
                parent_ns=r["parent_ns"],
                first_seen=r["first_seen"],
                last_seen=r["last_seen"],
            )
            for r in rows
        ]

    def get_zone(self, name: str) -> Zone | None:
        with self.cursor() as c:
            r = c.execute("SELECT * FROM zones WHERE name=?", (name,)).fetchone()
        if not r:
            return None
        return Zone(
            name=r["name"],
            key_dir=r["key_dir"],
            parent_ns=r["parent_ns"],
            first_seen=r["first_seen"],
            last_seen=r["last_seen"],
        )

    # ---- keys -------------------------------------------------------

    def upsert_key(self, key: Key) -> None:
        with self.cursor() as c:
            c.execute(
                """
                INSERT INTO keys(zone, key_tag, role, algorithm, key_id, first_seen, last_state_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(zone, key_tag, role) DO UPDATE SET
                    algorithm = excluded.algorithm,
                    key_id = excluded.key_id,
                    last_state_json = excluded.last_state_json
                """,
                (
                    key.zone,
                    key.key_tag,
                    key.role,
                    key.algorithm,
                    key.key_id,
                    key.first_seen,
                    key.last_state_json,
                ),
            )

    def list_keys(self, zone: str | None = None) -> list[Key]:
        q = "SELECT * FROM keys"
        args: tuple = ()
        if zone is not None:
            q += " WHERE zone=?"
            args = (zone,)
        q += " ORDER BY zone, role, key_tag"
        with self.cursor() as c:
            rows = c.execute(q, args).fetchall()
        return [
            Key(
                zone=r["zone"],
                key_tag=r["key_tag"],
                role=r["role"],
                algorithm=r["algorithm"] or 0,
                key_id=r["key_id"] or "",
                first_seen=r["first_seen"],
                last_state_json=r["last_state_json"] or "{}",
            )
            for r in rows
        ]

    # ---- events -----------------------------------------------------

    def insert_event(self, event: Event) -> int:
        with self.cursor() as c:
            c.execute(
                """
                INSERT INTO events(ts, source, zone, key_tag, key_role, event_type, summary, detail_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.ts,
                    event.source,
                    event.zone,
                    event.key_tag,
                    event.key_role,
                    event.event_type,
                    event.summary,
                    event.detail_json(),
                ),
            )
            return c.lastrowid or 0

    def insert_events(self, events: Iterable[Event]) -> int:
        n = 0
        for ev in events:
            self.insert_event(ev)
            n += 1
        return n

    def query_events(
        self,
        *,
        zone: str | None = None,
        from_ts: str | None = None,
        to_ts: str | None = None,
        event_type: str | None = None,
        source: str | None = None,
        limit: int = 500,
        offset: int = 0,
    ) -> list[Event]:
        # zone / event_type / source filters are regex patterns,
        # matched via the REGEXP function registered on the connection.
        # Pass an exact string and it still works (re.search treats
        # plain strings as substrings); pass "^foo$" for exact match,
        # or "foo|bar" for alternatives. Invalid patterns fall back to
        # "no match" rather than raising.
        clauses = []
        args: list = []
        if zone:
            clauses.append("zone REGEXP ?")
            args.append(zone)
        if from_ts:
            clauses.append("ts >= ?")
            args.append(from_ts)
        if to_ts:
            clauses.append("ts <= ?")
            args.append(to_ts)
        if event_type:
            clauses.append("event_type REGEXP ?")
            args.append(event_type)
        if source:
            clauses.append("source REGEXP ?")
            args.append(source)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        q = f"SELECT * FROM events {where} ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?"
        args.extend([limit, offset])
        with self.cursor() as c:
            rows = c.execute(q, args).fetchall()
        return [Event.from_row(r) for r in rows]

    # ---- collector snapshots ---------------------------------------

    def get_snapshot(self, collector: str, scope: str) -> dict:
        with self.cursor() as c:
            r = c.execute(
                "SELECT snapshot FROM collector_state WHERE collector=? AND scope=?",
                (collector, scope),
            ).fetchone()
        if not r:
            return {}
        try:
            return json.loads(r["snapshot"])
        except json.JSONDecodeError:
            return {}

    def set_snapshot(self, collector: str, scope: str, snapshot: dict) -> None:
        with self.cursor() as c:
            c.execute(
                """
                INSERT INTO collector_state(collector, scope, snapshot, updated)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(collector, scope) DO UPDATE SET
                    snapshot = excluded.snapshot,
                    updated  = excluded.updated
                """,
                (collector, scope, json.dumps(snapshot, sort_keys=True, default=str), now_iso()),
            )

    def list_snapshot_scopes(self, collector: str) -> list[str]:
        """Return every ``scope`` stored under ``collector`` in
        ``collector_state``. Used by the file-collector vanish
        detection: any scope that exists here but isn't in the
        current scan indicates a key whose on-disk files have been
        removed."""
        with self.cursor() as c:
            rows = c.execute(
                "SELECT scope FROM collector_state WHERE collector=?",
                (collector,),
            ).fetchall()
        return [r["scope"] for r in rows]

    def delete_snapshot(self, collector: str, scope: str) -> None:
        with self.cursor() as c:
            c.execute(
                "DELETE FROM collector_state WHERE collector=? AND scope=?",
                (collector, scope),
            )

    # ---- key cleanup ------------------------------------------------

    def delete_key(self, zone: str, key_tag: int, role: str) -> None:
        """Remove a key row from the ``keys`` table. Events that
        reference the key by ``key_tag`` stay untouched so the
        historical event log still renders the metadata."""
        with self.cursor() as c:
            c.execute(
                "DELETE FROM keys WHERE zone=? AND key_tag=? AND role=?",
                (zone, key_tag, role),
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()
