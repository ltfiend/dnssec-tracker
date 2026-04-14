"""Synthetic demo scenarios for the dnssec-tracker UI.

The live UI surfaces work on real collector data backed by SQLite.
For visual evaluation and documentation, this module builds a
realistic in-memory dataset that the ``/demo`` route renders
through the same templates and renderers — no DB writes, no side
effects, pure functions.
"""

from .scenarios import DemoZone, build_rollover_demo

__all__ = ["DemoZone", "build_rollover_demo"]
