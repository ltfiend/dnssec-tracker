from dnssec_tracker.models import Event
from dnssec_tracker.render.channels import (
    DNS_CHANNEL_SOURCES,
    FILE_CHANNEL_SOURCES,
    dns_channel,
    file_channel,
)


def _mk(source: str) -> Event:
    return Event(
        ts="2026-04-10T00:00:00Z", source=source,
        event_type="t", summary=f"{source} event",
    )


def test_dns_channel_collects_dns_and_rndc_only():
    events = [_mk("dns"), _mk("rndc"), _mk("state"), _mk("key"),
              _mk("syslog"), _mk("named")]
    result = dns_channel(events)
    assert {e.source for e in result} == {"dns", "rndc"}
    assert {e.source for e in result} == DNS_CHANNEL_SOURCES


def test_file_channel_collects_state_and_key_only():
    events = [_mk("dns"), _mk("rndc"), _mk("state"), _mk("key"),
              _mk("syslog"), _mk("named")]
    result = file_channel(events)
    assert {e.source for e in result} == {"state", "key"}
    assert {e.source for e in result} == FILE_CHANNEL_SOURCES


def test_channels_exclude_syslog_and_named():
    # syslog and named are captured in the overall event log but
    # deliberately not routed into either split timeline.
    events = [_mk("syslog"), _mk("named")]
    assert dns_channel(events) == []
    assert file_channel(events) == []
