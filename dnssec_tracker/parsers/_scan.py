"""Shared directory-walking helper for the K*.key / K*.state scans.

Default is **not** recursive. BIND's canonical key-directory layout
is either flat (``keys/K*.key``) or one-level-per-zone
(``keys/<zone>/K*.key``), so by default the scanners walk those two
layers only. Any deeper nesting — including common backup holding
spots like ``keys/.bak/<zone>/`` — is ignored to avoid stale keys
bleeding into the live zone's view.

Users with genuinely deeper trees can flip ``key_dir_recursive``
in the config to restore the full ``rglob`` behaviour.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable


def _is_hidden_component(name: str) -> bool:
    """Skip dotted directories even in recursive mode — typical
    convention for backup/holding locations (``.bak``, ``.old``,
    ``.trash``) that no tracker should index."""
    return name.startswith(".")


def iter_key_paths(root: Path, pattern: str, *, recursive: bool) -> Iterable[Path]:
    """Yield every path under ``root`` whose filename matches
    ``pattern`` (glob syntax, e.g. ``K*.state``).

    * ``recursive=False`` (default): scan ``root`` itself plus one
      level of immediate subdirectories. Covers both flat and
      per-zone-subdir BIND layouts. Hidden subdirectories (names
      starting with ``.``) are skipped.
    * ``recursive=True``: walk every depth with ``rglob``. Hidden
      components anywhere in the relative path are still skipped
      so backup trees don't contaminate the results.
    """

    if not root.exists():
        return

    if recursive:
        for path in root.rglob(pattern):
            rel = path.relative_to(root)
            # rel.parts[:-1] is the directory chain (minus the
            # filename itself). Any hidden component in that chain
            # disqualifies the path.
            if any(_is_hidden_component(p) for p in rel.parts[:-1]):
                continue
            yield path
        return

    # Non-recursive default: root + one level down.
    yield from root.glob(pattern)
    try:
        subs = list(root.iterdir())
    except OSError:
        return
    for sub in subs:
        if not sub.is_dir():
            continue
        if _is_hidden_component(sub.name):
            continue
        try:
            yield from sub.glob(pattern)
        except OSError:
            continue
