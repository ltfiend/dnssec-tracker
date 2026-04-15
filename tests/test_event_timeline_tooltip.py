"""Hover-tooltip plumbing for the swim-lane event timeline.

Each cluster <g> carries a ``data-tip`` attribute with pre-escaped
HTML that the JavaScript tooltip snippet in ``layout.html`` injects
into a floating <div> near the cursor on hover. We deliberately do
*not* emit an SVG ``<title>`` child: browsers render that as a
second, small native tooltip on top of the styled one.
"""

import re

from dnssec_tracker.models import Event
from dnssec_tracker.render.event_timeline import render_event_timeline


def _mk(ts: str, source: str, et: str, summary: str = "") -> Event:
    return Event(
        ts=ts, source=source, event_type=et,
        summary=summary or f"{et} at {ts}",
        zone="example.com",
    )


# ---- data-tip attribute -------------------------------------------


def test_cluster_data_tip_carries_timestamp_source_type_summary():
    """data-tip stores pre-escaped HTML that the page-level JS
    injects into innerHTML. The attribute is therefore escaped
    twice: the HTML fragment (``<strong>...</strong><br>``) is
    first built with html.escape() on its text nodes, then the
    whole fragment is escape()'d again when serialised into the
    attribute value — so ``<`` appears as ``&lt;`` in the raw
    SVG source, and an already-escaped ``&amp;gt;`` survives as
    ``&amp;amp;gt;``. The browser decodes the attribute once
    (``&lt;strong&gt;`` -> ``<strong>``, ``&amp;gt;`` -> ``&gt;``)
    and innerHTML decodes once more (``&gt;`` -> ``>``), landing
    the expected glyphs in the DOM."""
    svg = render_event_timeline([
        _mk("2026-04-10T12:00:00Z", "state",
            "state_changed", summary="GoalState -> omnipresent"),
    ])
    m = re.search(r'data-tip="([^"]+)"', svg)
    assert m is not None
    tip = m.group(1)
    # Timestamp / source / type appear in plain form (no special
    # chars to escape).
    assert "2026-04-10 12:00:00" in tip
    assert "[state]" in tip
    assert "state_changed" in tip
    # The structural tags were escaped once for HTML safety, then
    # once more for attribute safety — so <strong> shows up as
    # &lt;strong&gt; in the raw attribute value.
    assert "&lt;strong&gt;" in tip
    assert "&lt;br&gt;" in tip
    # "->" has its ">" escaped twice: escape() ->&gt; inside HTML,
    # then &gt; -> &amp;gt; for the attribute.
    assert "GoalState -&amp;gt; omnipresent" in tip


def test_multiple_event_tip_separates_members_with_hr():
    """A cluster of N events produces N entries separated by
    ``<hr>`` tags in the tooltip HTML."""
    ts = "2026-04-10T12:00:00Z"
    svg = render_event_timeline(
        [
            _mk(ts, "state", "state_changed", summary="one"),
            _mk(ts, "state", "state_changed", summary="two"),
            _mk(ts, "state", "state_changed", summary="three"),
        ],
        from_ts="2026-04-10T00:00:00Z",
        to_ts="2026-04-10T23:59:59Z",
    )
    m = re.search(r'data-tip="([^"]+)"', svg)
    assert m is not None
    # Two separators between three members — escaped as &lt;hr&gt;
    # inside the attribute value.
    assert m.group(1).count("&lt;hr&gt;") == 2


def test_no_svg_title_child_is_emitted():
    """The SVG ``<title>`` child is deliberately not rendered. Browsers
    show it as a second, small native tooltip on top of the styled
    floating one — having two tooltips overlap was the bug this
    change fixes."""
    ts = "2026-04-10T12:00:00Z"
    svg = render_event_timeline(
        [
            _mk(ts, "state", "state_changed", summary="alpha"),
            _mk(ts, "state", "state_changed", summary="bravo"),
            _mk(ts, "state", "state_changed", summary="charlie"),
        ],
        from_ts="2026-04-10T00:00:00Z",
        to_ts="2026-04-10T23:59:59Z",
    )
    assert "<title>" not in svg
    assert "</title>" not in svg


def test_data_tip_present_on_every_cluster():
    """Every cluster carries a ``data-tip`` attribute — the single
    source of truth for hover content now that ``<title>`` is gone."""
    svg = render_event_timeline([
        _mk("2026-04-01T00:00:00Z", "state", "state_changed"),
        _mk("2026-04-10T00:00:00Z", "rndc", "rndc_state_changed"),
        _mk("2026-04-15T00:00:00Z", "dns", "dns_ds_appeared_at_parent"),
    ])
    clusters = re.findall(r'<g class="evt-cluster"[^>]*>', svg)
    data_tips = re.findall(r'data-tip="', svg)
    assert len(clusters) == 3
    assert len(data_tips) == 3


def test_data_tip_is_attribute_safe_when_summary_has_quotes():
    """A literal double-quote in a summary must not break the
    attribute quoting. ``html.escape(..., quote=True)`` is in
    play at both layers (HTML-body-for-innerHTML, then
    attribute-value) so the raw serialised attribute contains
    a double-escaped form of the quote and has no unescaped ``"``
    that would truncate parsing."""
    svg = render_event_timeline([
        Event(
            ts="2026-04-10T12:00:00Z", source="state",
            event_type="state_changed",
            summary='warning: "rollover pending"',
            zone="example.com",
        ),
    ])
    m = re.search(r'data-tip="([^"]*)"', svg)
    assert m is not None
    raw = m.group(1)
    # Inner escape turns `"` into `&quot;`; outer escape turns
    # `&` into `&amp;` so the raw attribute value contains
    # `&amp;quot;`. When the browser decodes the attribute value
    # it gets `&quot;`, which innerHTML decodes to `"` — the
    # correct chain.
    assert "&amp;quot;rollover pending&amp;quot;" in raw
    # No stray unescaped double-quote survives into the attribute
    # value between the surrounding data-tip="..." quotes — if
    # one did, the attribute-match regex wouldn't capture the
    # whole payload in the first place. Double-check anyway: the
    # captured content contains no raw `"`.
    assert '"' not in raw


# ---- milestone flags ----------------------------------------------


def test_milestone_event_types_get_vertical_flag():
    """Operationally-important events (key creation, DS
    transitions, manual checkds, etc.) get a small vertical
    line extending upward from the dot, plus a tiny cap circle."""
    svg = render_event_timeline([
        _mk("2026-04-10T12:00:00Z", "dns", "dns_ds_appeared_at_parent",
            summary="DS at parent"),
    ])
    assert 'class="evt-milestone-flag"' in svg
    assert 'class="evt-milestone-cap"' in svg


def test_non_milestone_event_has_no_flag():
    svg = render_event_timeline([
        _mk("2026-04-10T12:00:00Z", "state", "state_changed",
            summary="just a state transition"),
    ])
    assert 'class="evt-milestone-flag"' not in svg
    assert 'class="evt-milestone-cap"' not in svg
