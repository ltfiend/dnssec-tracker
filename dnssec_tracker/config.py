"""Configuration loader. INI style mirroring iodyn-dnssec.conf."""

from __future__ import annotations

import configparser
from dataclasses import dataclass, field
from pathlib import Path


def _bool(value: str) -> bool:
    return value.strip().lower() in ("on", "true", "yes", "1", "enabled")


@dataclass
class Config:
    # paths
    key_dir: Path
    syslog_path: Path | None
    named_log_path: Path | None
    db_path: Path

    # dns
    local_resolver: str = "127.0.0.1:53"
    query_interval: int = 60
    parent_interval: int = 300
    query_timeout: int = 5

    # collectors
    enabled_collectors: dict[str, bool] = field(default_factory=dict)

    # rndc
    rndc_key_file: Path | None = None
    rndc_server: str = "127.0.0.1:953"
    rndc_bin: str = "/usr/sbin/rndc"
    rndc_interval: int = 300  # seconds between rndc dnssec -status runs

    # web
    web_bind: str = "0.0.0.0:8080"
    events_per_page: int = 100

    # config origin (used in reports)
    source_file: Path | None = None


def load_config(path: Path) -> Config:
    """Read an INI file into a Config object."""

    parser = configparser.ConfigParser()
    parser.read(path)

    paths = parser["paths"]
    dns = parser["dns"] if parser.has_section("dns") else {}
    collectors = parser["collectors"] if parser.has_section("collectors") else {}
    rndc = parser["rndc"] if parser.has_section("rndc") else {}
    web = parser["web"] if parser.has_section("web") else {}

    def optional_path(section, key: str) -> Path | None:
        v = section.get(key) if section else None
        if not v or not v.strip():
            return None
        return Path(v.strip())

    enabled = {
        "state_file": True,
        "key_file": True,
        "syslog": True,
        "named_log": True,
        "dns_probe": True,
        "rndc_status": True,
    }
    for name in list(enabled):
        if collectors and collectors.get(name) is not None:
            enabled[name] = _bool(collectors.get(name))

    return Config(
        key_dir=Path(paths["key_dir"]),
        syslog_path=optional_path(paths, "syslog"),
        named_log_path=optional_path(paths, "named_log"),
        db_path=Path(paths.get("db", "/var/lib/dnssec-tracker/events.db")),
        local_resolver=dns.get("local_resolver", "127.0.0.1:53") if dns else "127.0.0.1:53",
        query_interval=int(dns.get("query_interval", "60")) if dns else 60,
        parent_interval=int(dns.get("parent_interval", "300")) if dns else 300,
        query_timeout=int(dns.get("query_timeout", "5")) if dns else 5,
        enabled_collectors=enabled,
        rndc_key_file=optional_path(rndc, "key_file") if rndc else None,
        rndc_server=rndc.get("server", "127.0.0.1:953") if rndc else "127.0.0.1:953",
        rndc_bin=rndc.get("rndc_bin", "/usr/sbin/rndc") if rndc else "/usr/sbin/rndc",
        rndc_interval=int(rndc.get("interval", "300")) if rndc else 300,
        web_bind=web.get("bind", "0.0.0.0:8080") if web else "0.0.0.0:8080",
        events_per_page=int(web.get("events_per_page", "100")) if web else 100,
        source_file=path,
    )
