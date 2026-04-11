"""Render-side event filtering (role / event_type / source).

The filter layer sits between the DB and the calendar / event-timeline
/ state-transition renderers so zone, key, and report pages all apply
the same rules. It's deliberately *not* wired into the /events page,
which has its own regex filter in db.py.
"""

from __future__ import annotations

from dnssec_tracker.models import Event
from dnssec_tracker.render.filtering import FilterSet, filter_events


def _mk(
    et: str,
    source: str = "state",
    key_role: str | None = None,
    key_tag: int | None = None,
    zone: str = "example.com",
) -> Event:
    return Event(
        ts="2026-04-10T12:00:00Z",
        source=source,
        event_type=et,
        summary=et,
        zone=zone,
        key_tag=key_tag,
        key_role=key_role,
    )


# ---- FilterSet.from_query ----------------------------------------------


def test_from_query_parses_comma_separated_lists_and_strips_whitespace():
    fs = FilterSet.from_query(
        hide_types=" rrsig , soa ",
        hide_sources="syslog,named",
        role="KSK",
    )
    assert fs.hide_type_patterns == ["rrsig", "soa"]
    assert fs.hide_sources == ["syslog", "named"]
    assert fs.role == "KSK"


def test_from_query_empty_inputs_yield_empty_defaults():
    fs = FilterSet.from_query(None, None, None)
    assert fs.hide_type_patterns == []
    assert fs.hide_sources == []
    assert fs.role == "all"
    assert not fs.is_active()


def test_from_query_invalid_role_clamps_to_all():
    fs = FilterSet.from_query(None, None, "nonsense")
    assert fs.role == "all"


def test_from_query_empty_string_role_clamps_to_all():
    fs = FilterSet.from_query(None, None, "")
    assert fs.role == "all"


def test_is_active_true_when_any_dim_set():
    assert FilterSet(hide_type_patterns=["rrsig"]).is_active()
    assert FilterSet(hide_sources=["syslog"]).is_active()
    assert FilterSet(role="KSK").is_active()
    assert not FilterSet().is_active()
    assert not FilterSet(role="all").is_active()


# ---- filter_events: no-ops ---------------------------------------------


def test_filter_events_none_is_noop():
    events = [_mk("state_changed")]
    assert filter_events(events, None) == events


def test_filter_events_default_filterset_is_noop():
    events = [_mk("state_changed"), _mk("dns_ds_appeared_at_parent", source="dns")]
    assert filter_events(events, FilterSet()) == events


# ---- hide_types --------------------------------------------------------


def test_hide_types_dnskey_focus_drops_rrsig_and_soa_events():
    events = [
        _mk("state_changed"),
        _mk("dns_rrsig_appeared_at_zone", source="dns"),
        _mk("dns_soa_serial_bumped", source="dns"),
        _mk("dns_dnskey_appeared_at_zone", source="dns"),
    ]
    fs = FilterSet.from_query("rrsig,soa", None, None)
    kept = filter_events(events, fs)
    types = [e.event_type for e in kept]
    assert types == ["state_changed", "dns_dnskey_appeared_at_zone"]


def test_hide_types_is_case_insensitive():
    events = [_mk("dns_RRSIG_seen", source="dns")]
    fs = FilterSet.from_query("rrsig", None, None)
    assert filter_events(events, fs) == []


def test_hide_types_invalid_regex_is_swallowed_but_valid_ones_still_apply():
    events = [
        _mk("dns_rrsig_seen", source="dns"),
        _mk("state_changed"),
    ]
    # First pattern is invalid (unbalanced paren), second is fine.
    fs = FilterSet.from_query("rrsig(,state_changed", None, None)
    kept = filter_events(events, fs)
    # The valid one still fires and drops state_changed; the invalid
    # one is silently skipped so rrsig survives.
    assert [e.event_type for e in kept] == ["dns_rrsig_seen"]


# ---- hide_sources ------------------------------------------------------


def test_hide_sources_drops_exact_source_matches():
    events = [
        _mk("state_changed", source="state"),
        _mk("iodyn_rndc_reload", source="syslog"),
        _mk("named_dnskey_active", source="named"),
    ]
    fs = FilterSet.from_query(None, "syslog,named", None)
    kept = filter_events(events, fs)
    assert [e.source for e in kept] == ["state"]


def test_hide_sources_does_not_substring_match():
    """Source filter is exact — 'state' doesn't drop 'syslog' etc."""

    events = [_mk("t", source="syslog"), _mk("t", source="state")]
    fs = FilterSet.from_query(None, "state", None)
    kept = filter_events(events, fs)
    assert {e.source for e in kept} == {"syslog"}


# ---- role filter -------------------------------------------------------


def test_role_ksk_keeps_ksk_and_none_role_events():
    """KSK view keeps KSK events + unscoped events (DS, SOA, etc.)."""

    events = [
        _mk("state_changed", key_role="KSK", key_tag=1),
        _mk("state_changed", key_role="ZSK", key_tag=2),
        _mk("dns_ds_appeared_at_parent", source="dns", key_role=None, key_tag=1),
        _mk("dns_soa_serial_bumped", source="dns", key_role=None, key_tag=None),
    ]
    fs = FilterSet(role="KSK")
    kept = filter_events(events, fs)
    kept_types = [(e.event_type, e.key_role) for e in kept]
    assert ("state_changed", "KSK") in kept_types
    assert ("dns_ds_appeared_at_parent", None) in kept_types
    assert ("dns_soa_serial_bumped", None) in kept_types
    # ZSK event dropped
    assert ("state_changed", "ZSK") not in kept_types


def test_role_ksk_keeps_ds_events():
    """DS / CDS / CDNSKEY must not be stripped from a KSK view."""

    events = [
        _mk("dns_ds_appeared_at_parent", source="dns", key_role=None),
        _mk("dns_cds_appeared_at_zone", source="dns", key_role=None),
        _mk("dns_cdnskey_appeared_at_zone", source="dns", key_role=None),
    ]
    fs = FilterSet(role="KSK")
    kept = filter_events(events, fs)
    assert len(kept) == 3


def test_role_zsk_drops_ds_and_cds_and_cdnskey_events():
    """ZSKs have no parent presence, so DS/CDS/CDNSKEY are noise."""

    events = [
        _mk("state_changed", key_role="ZSK"),
        _mk("dns_dnskey_appeared_at_zone", source="dns", key_role=None),
        _mk("dns_ds_appeared_at_parent", source="dns", key_role=None),
        _mk("dns_cds_appeared_at_zone", source="dns", key_role=None),
        _mk("dns_cdnskey_appeared_at_zone", source="dns", key_role=None),
    ]
    fs = FilterSet(role="ZSK")
    kept = filter_events(events, fs)
    kept_types = [e.event_type for e in kept]
    assert "state_changed" in kept_types
    assert "dns_dnskey_appeared_at_zone" in kept_types
    assert "dns_ds_appeared_at_parent" not in kept_types
    assert "dns_cds_appeared_at_zone" not in kept_types
    assert "dns_cdnskey_appeared_at_zone" not in kept_types


def test_role_zsk_drops_ksk_role_events():
    events = [
        _mk("state_changed", key_role="KSK"),
        _mk("state_changed", key_role="ZSK"),
    ]
    fs = FilterSet(role="ZSK")
    kept = filter_events(events, fs)
    assert [e.key_role for e in kept] == ["ZSK"]


def test_role_csk_keeps_csk_and_none_and_ds_events():
    """CSKs do have DS records, so DS events stay."""

    events = [
        _mk("state_changed", key_role="CSK"),
        _mk("state_changed", key_role="KSK"),
        _mk("dns_ds_appeared_at_parent", source="dns", key_role=None),
    ]
    fs = FilterSet(role="CSK")
    kept = filter_events(events, fs)
    kept_types = [(e.event_type, e.key_role) for e in kept]
    assert ("state_changed", "CSK") in kept_types
    assert ("dns_ds_appeared_at_parent", None) in kept_types
    assert ("state_changed", "KSK") not in kept_types


def test_role_all_is_no_op_on_role_dimension():
    events = [
        _mk("state_changed", key_role="KSK"),
        _mk("state_changed", key_role="ZSK"),
        _mk("state_changed", key_role="CSK"),
    ]
    fs = FilterSet(role="all")
    kept = filter_events(events, fs)
    assert len(kept) == 3


# ---- Combined ----------------------------------------------------------


def test_combined_role_type_source_all_applied():
    events = [
        _mk("state_changed",        source="state", key_role="KSK"),
        _mk("state_changed",        source="state", key_role="ZSK"),
        _mk("dns_rrsig_seen",       source="dns",   key_role=None),
        _mk("iodyn_key_created",    source="syslog", key_role=None),
        _mk("dns_ds_appeared_at_parent", source="dns", key_role=None),
    ]
    fs = FilterSet.from_query("rrsig", "syslog", "KSK")
    kept = filter_events(events, fs)
    kept_types = [(e.event_type, e.source) for e in kept]
    # KSK keeps KSK + None role
    # hide_sources drops the syslog row
    # hide_types drops the rrsig row
    # ZSK state_changed dropped by role
    assert ("state_changed", "state") in kept_types
    assert ("dns_ds_appeared_at_parent", "dns") in kept_types
    assert ("state_changed", "state") in kept_types
    assert len(kept) == 2


def test_summary_text_reads_like_a_query_string():
    fs = FilterSet.from_query("rrsig,soa", "syslog", "KSK")
    s = fs.summary()
    assert "role=KSK" in s
    assert "hide_types=rrsig,soa" in s
    assert "hide_sources=syslog" in s


def test_summary_empty_when_default():
    assert FilterSet().summary() == ""
