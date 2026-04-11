"""Verify that the event-timeline legend is dynamic: only sources that
actually appear in the rendered slice of events are listed, so the
split DNS/File timelines don't carry stale legend entries."""

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


def test_dns_only_legend_excludes_file_sources():
    events = [_mk("dns", 0), _mk("rndc", 1)]
    svg = render_event_timeline(events)
    assert ">dns<" in svg
    assert ">rndc<" in svg
    # File/other sources must not appear in the legend text.
    assert ">state<" not in svg
    assert ">key<" not in svg
    assert ">syslog<" not in svg
    assert ">named<" not in svg


def test_file_only_legend_excludes_dns_sources():
    events = [_mk("state", 0), _mk("key", 1)]
    svg = render_event_timeline(events)
    assert ">state<" in svg
    assert ">key<" in svg
    assert ">dns<" not in svg
    assert ">rndc<" not in svg


def test_split_via_channel_helpers():
    mixed = [_mk("dns", 0), _mk("rndc", 1), _mk("state", 2), _mk("key", 3),
             _mk("syslog", 4), _mk("named", 5)]
    dns_svg = render_event_timeline(dns_channel(mixed))
    file_svg = render_event_timeline(file_channel(mixed))
    # DNS timeline has dns+rndc legend chips and no file-sources.
    assert ">dns<" in dns_svg and ">rndc<" in dns_svg
    assert ">state<" not in dns_svg and ">key<" not in dns_svg
    # File timeline has state+key legend chips and no dns-sources.
    assert ">state<" in file_svg and ">key<" in file_svg
    assert ">dns<" not in file_svg and ">rndc<" not in file_svg
