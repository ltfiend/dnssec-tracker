"""Dataclasses representing the core entities."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Zone:
    name: str
    key_dir: str
    parent_ns: str | None = None
    first_seen: str = field(default_factory=now_iso)
    last_seen: str = field(default_factory=now_iso)


@dataclass
class Key:
    zone: str
    key_tag: int
    role: str  # KSK / ZSK / CSK
    algorithm: int
    key_id: str = ""  # filename stem, e.g. "Kexample.com.+013+12345"
    first_seen: str = field(default_factory=now_iso)
    last_state_json: str = "{}"


@dataclass
class Event:
    ts: str
    source: str  # state | key | syslog | dns | named | rndc
    event_type: str  # see docs for the vocabulary
    summary: str
    zone: str | None = None
    key_tag: int | None = None
    key_role: str | None = None
    detail: dict = field(default_factory=dict)
    id: int | None = None

    def detail_json(self) -> str:
        return json.dumps(self.detail, sort_keys=True, default=str)

    @classmethod
    def from_row(cls, row) -> "Event":
        return cls(
            id=row["id"],
            ts=row["ts"],
            source=row["source"],
            zone=row["zone"],
            key_tag=row["key_tag"],
            key_role=row["key_role"],
            event_type=row["event_type"],
            summary=row["summary"],
            detail=json.loads(row["detail_json"] or "{}"),
        )

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("detail", None)
        d["detail"] = self.detail
        return d
