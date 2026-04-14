"""Synthetic demo scenario — unit tests for build_rollover_demo()
plus an end-to-end smoke of /demo rendering through the normal
zone template."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dnssec_tracker.app import create_app
from dnssec_tracker.config import Config
from dnssec_tracker.demo import build_rollover_demo


_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=timezone.utc)


# ---- scenario generator ------------------------------------------


def test_scenario_has_three_ksks_and_thirteen_zsks():
    d = build_rollover_demo(_NOW)
    ksks = [k for k in d.keys if k.role == "KSK"]
    zsks = [k for k in d.keys if k.role == "ZSK"]
    assert len(ksks) == 3
    assert len(zsks) == 13


def test_scenario_window_is_twelve_months():
    d = build_rollover_demo(_NOW)
    assert d.window_end == _NOW
    # ~365 days ago, give or take a second for the tz rounding.
    delta = d.window_end - d.window_start
    assert abs(delta - timedelta(days=365)) < timedelta(seconds=5)


def test_every_key_has_a_snapshot():
    d = build_rollover_demo(_NOW)
    for k in d.keys:
        scope = f"{k.zone}#{k.key_tag}#{k.role}"
        assert scope in d.snapshots
        snap = d.snapshots[scope]
        assert "fields" in snap and isinstance(snap["fields"], dict)
        assert "timings" in snap and isinstance(snap["timings"], dict)
        # The state-file "Generated" and the key-file "Created" must
        # carry non-zero BIND-format timestamps.
        assert snap["fields"]["Generated"] != "0"
        assert snap["timings"]["Created"] != "0"


def test_current_keys_stay_active_with_no_retired_timestamps():
    """The most-recently-rolled KSK and ZSK are still active at
    ``now``, so their Retired / Removed fields should be "0"."""
    d = build_rollover_demo(_NOW)
    current_ksk = max(
        (k for k in d.keys if k.role == "KSK"),
        key=lambda k: d.snapshots[f"{k.zone}#{k.key_tag}#KSK"]["fields"]["Active"],
    )
    snap = d.snapshots[f"{current_ksk.zone}#{current_ksk.key_tag}#KSK"]
    assert snap["fields"]["Retired"] == "0"
    assert snap["fields"]["Removed"] == "0"

    current_zsk = max(
        (k for k in d.keys if k.role == "ZSK"),
        key=lambda k: d.snapshots[f"{k.zone}#{k.key_tag}#ZSK"]["fields"]["Active"],
    )
    snap = d.snapshots[f"{current_zsk.zone}#{current_zsk.key_tag}#ZSK"]
    assert snap["fields"]["Retired"] == "0"
    assert snap["fields"]["Removed"] == "0"


def test_ds_events_fire_per_ksk_rollover():
    """Every retired KSK must have a paired DS-appeared + DS-
    disappeared event in the stream; the currently-active KSK has
    only the appeared side."""
    d = build_rollover_demo(_NOW)
    ksk_tags = [k.key_tag for k in d.keys if k.role == "KSK"]
    appeared = [e for e in d.events if e.event_type == "dns_ds_appeared_at_parent"]
    disappeared = [e for e in d.events if e.event_type == "dns_ds_disappeared_at_parent"]
    # One appear per KSK; N-1 disappears (current KSK is still live).
    assert len(appeared) == len(ksk_tags)
    assert len(disappeared) == len(ksk_tags) - 1
    # And every disappeared event's tag also appears in the
    # appeared set — they're paired per key.
    appeared_tags = {e.key_tag for e in appeared}
    disappeared_tags = {e.key_tag for e in disappeared}
    assert disappeared_tags <= appeared_tags


def test_scenario_is_deterministic():
    """Same ``now`` → same output, critical for regression tests."""
    a = build_rollover_demo(_NOW)
    b = build_rollover_demo(_NOW)
    assert sorted(k.key_tag for k in a.keys) == sorted(k.key_tag for k in b.keys)
    assert len(a.events) == len(b.events)


def test_every_key_carries_lifecycle_events():
    """Each key gets at least state_key_observed +
    dns_dnskey_appeared_at_zone + a state_changed for DNSKEY state.
    These drive the rollover renderer's event-based boundary
    refinement, so they need to be populated."""
    d = build_rollover_demo(_NOW)
    for k in d.keys:
        key_events = [e for e in d.events if e.key_tag == k.key_tag]
        types = {e.event_type for e in key_events}
        assert "state_key_observed" in types
        assert "dns_dnskey_appeared_at_zone" in types
        # state_changed comes with a detail.field — the renderer
        # uses DNSKEYState or K/ZRRSIGState depending on role.
        rrsig_field_type = "ZRRSIGState" if k.role == "ZSK" else "KRRSIGState"
        has_rrsig = any(
            e.event_type == "state_changed"
            and (e.detail or {}).get("field") == rrsig_field_type
            for e in key_events
        )
        assert has_rrsig, f"{k.role} tag {k.key_tag} missing {rrsig_field_type}"


# ---- end-to-end: /demo route --------------------------------------


@pytest.fixture
def client(tmp_path: Path):
    cfg = Config(
        key_dir=tmp_path,
        syslog_path=None,
        named_log_path=None,
        db_path=tmp_path / "events.db",
    )
    for k in cfg.enabled_collectors:
        cfg.enabled_collectors[k] = False
    app = create_app(cfg)
    with TestClient(app) as c:
        yield c


def test_demo_route_returns_200(client):
    r = client.get("/demo")
    assert r.status_code == 200


def test_demo_banner_is_visible(client):
    body = client.get("/demo").text
    assert "Demo / synthetic data" in body
    assert 'class="demo-banner"' in body


def test_demo_renders_all_five_phases(client):
    """Every phase name (pre-published, published, active,
    inactive, removed) must appear as a ``phase-<name>`` CSS class
    in the rollover SVG — proves the renamed phase vocabulary is
    wired through end-to-end."""
    body = client.get("/demo").text
    classes = set(re.findall(r'class="phase phase-([\w-]+)"', body))
    assert classes == {
        "pre-published", "published", "active", "inactive", "removed",
    }


def test_demo_renders_16_key_rows(client):
    """3 KSK + 13 ZSK = 16 rows of ``tag <N>`` labels in the
    rollover SVG."""
    body = client.get("/demo").text
    tags = re.findall(r">tag (\d+)<", body)
    # One label per row; the unique set should be 16 keys.
    assert len(set(tags)) == 16


def test_demo_ds_overlay_stripes_exist_for_ksks(client):
    """KSK rows carry the DS-at-parent overlay. There should be
    three live DS stripes (one per KSK rollover) and three track
    backgrounds (one per KSK row)."""
    body = client.get("/demo").text
    # Each rollover produces at least one live segment.
    live_count = body.count('data-ds="live"')
    track_count = body.count('data-ds="track"')
    assert track_count == 3
    assert live_count >= 3


def test_demo_legend_uses_new_phase_labels(client):
    body = client.get("/demo").text
    # Legend text entries — PHASE_LABEL maps each phase key to its
    # display string.
    for label in ("pre-published", "published", "active",
                  "inactive", "removed"):
        assert f">{label}</text>" in body, f"legend missing {label!r}"


def test_demo_dashboard_link_exists(client):
    """The dashboard should carry a hint/link to /demo so the page
    is discoverable."""
    body = client.get("/").text
    assert 'href="/demo"' in body


def test_demo_overdue_banner_absent_for_healthy_scenario(client):
    """The demo scenario is deliberately healthy — no keys are
    past their scheduled Delete but still visible. The overdue
    warning banner must NOT render."""
    body = client.get("/demo").text
    assert "warning-banner" not in body
    assert "past scheduled Delete but still observed" not in body
