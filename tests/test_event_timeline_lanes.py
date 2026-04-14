"""Dynamic lane visibility.

With the swim-lane timeline, the old bottom-of-chart legend is
gone — each lane is labelled on its left edge instead. The same
"only show sources actually present" behaviour carries forward:
sources with zero events in the current slice don't get a lane,
so a DNS-channel chart is never padded out with empty state/key
rows and vice versa.

Lanes are rendered in canonical order:
    state → key → rndc → dns → syslog → named
"""

import re

from dnssec_tracker.models import Event
from dnssec_tracker.render.channels import dns_channel, file_channel
from dnssec_tracker.render.event_timeline import render_event_timeline


def _mk(source: str, i: int = 0) -> Event:
    return Event(
        ts=f"2026-04-0{1 + i}T00:00:00Z",
        source=source,
        event_type="t",
        summary=f"{source} {i}",
    )


def _lane_labels(svg: str) -> list[str]:
    """Extract the ordered list of lane labels from the SVG."""
    return re.findall(r'<text class="evt-lane-label"[^>]*>([^<]+)</text>', svg)


def test_dns_only_chart_has_just_dns_and_rndc_lanes():
    """dns + rndc events → 2 lanes, in canonical order. No state,
    key, syslog, or named lane."""
    svg = render_event_timeline([_mk("dns", 0), _mk("rndc", 1)])
    assert _lane_labels(svg) == ["rndc", "dns"]


def test_file_only_chart_has_just_state_and_key_lanes():
    svg = render_event_timeline([_mk("state", 0), _mk("key", 1)])
    assert _lane_labels(svg) == ["state", "key"]


def test_dns_channel_split_hides_file_lanes():
    """The DNS-channel chart (filter produces dns+rndc subset)
    must not render a file-side lane."""
    mixed = [
        _mk("dns", 0), _mk("rndc", 1), _mk("state", 2),
        _mk("key", 3), _mk("syslog", 4), _mk("named", 5),
    ]
    labels = _lane_labels(render_event_timeline(dns_channel(mixed)))
    assert labels == ["rndc", "dns"]


def test_file_channel_split_hides_dns_lanes():
    mixed = [
        _mk("dns", 0), _mk("rndc", 1), _mk("state", 2),
        _mk("key", 3), _mk("syslog", 4), _mk("named", 5),
    ]
    labels = _lane_labels(render_event_timeline(file_channel(mixed)))
    assert labels == ["state", "key"]


def test_all_sources_present_renders_six_lanes_in_canonical_order():
    """Full event feed (no channel split) renders every source as
    its own lane, top-to-bottom in the project's canonical order."""
    all_sources = [
        _mk("dns", 0), _mk("rndc", 1), _mk("state", 2),
        _mk("key", 3), _mk("syslog", 4), _mk("named", 5),
    ]
    labels = _lane_labels(render_event_timeline(all_sources))
    assert labels == ["state", "key", "rndc", "dns", "syslog", "named"]


def test_unrecognised_sources_get_their_own_trailing_lane():
    """Defensive: if a new source gets added without updating the
    SOURCE_ORDER constant, the renderer places it at the end
    rather than silently dropping those events."""
    svg = render_event_timeline([
        _mk("state", 0),
        Event(
            ts="2026-04-02T00:00:00Z",
            source="imaginary",
            event_type="t",
            summary="x",
        ),
    ])
    labels = _lane_labels(svg)
    assert labels == ["state", "imaginary"]
