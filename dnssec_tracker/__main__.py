"""Entry point for `python -m dnssec_tracker` and the
``dnssec-tracker`` console script.

Default action: run the collectors and serve the web UI.
With ``--refresh``: POST /api/refresh to an already-running instance
and exit, printing per-collector timing. This is how you force a
sample pass out-of-band from ``docker exec``.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import urllib.error
import urllib.request
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
    parser.add_argument(
        "--refresh",
        action="store_true",
        help=(
            "Force an immediate sample pass on the already-running "
            "instance (POST /api/refresh) and exit. The running "
            "instance is found via --url (default http://127.0.0.1:8080). "
            "This is the normal docker-exec entrypoint."
        ),
    )
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:8080",
        help="Base URL of the running instance (used with --refresh).",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.refresh:
        return _cmd_refresh(args.url)

    return _cmd_serve(args)


def _cmd_serve(args: argparse.Namespace) -> int:
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


def _cmd_refresh(base_url: str) -> int:
    url = base_url.rstrip("/") + "/api/refresh"
    req = urllib.request.Request(url, method="POST", data=b"")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = resp.read().decode("utf-8")
    except urllib.error.URLError as e:
        print(f"error: could not reach {url}: {e}", file=sys.stderr)
        return 1

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        print(f"error: non-JSON response from {url}: {body[:200]}", file=sys.stderr)
        return 1

    print(f"Forced refresh on {url}:")
    refreshed = data.get("refreshed", {})
    if not refreshed:
        print("  (no collectors running)")
        return 0

    any_failed = False
    for name, info in refreshed.items():
        if info.get("ok"):
            print(f"  {name:12s} ok   ({info.get('ms')} ms)")
        else:
            any_failed = True
            print(f"  {name:12s} FAIL {info.get('error')}")
    return 1 if any_failed else 0


if __name__ == "__main__":
    sys.exit(main())
