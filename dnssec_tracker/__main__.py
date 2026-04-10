"""Entry point for `python -m dnssec_tracker`."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import uvicorn

from .config import Config, load_config
from .app import create_app

log = logging.getLogger("dnssec_tracker")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dnssec-tracker")
    parser.add_argument(
        "--config",
        "-c",
        default="/etc/dnssec-tracker/dnssec-tracker.conf",
        help="Path to config file (INI).",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        log.error("config file not found: %s", cfg_path)
        return 2

    cfg: Config = load_config(cfg_path)
    app = create_app(cfg)

    host, _, port_s = cfg.web_bind.partition(":")
    port = int(port_s) if port_s else 8080
    uvicorn.run(app, host=host or "0.0.0.0", port=port, log_level=args.log_level.lower())
    return 0


if __name__ == "__main__":
    sys.exit(main())
