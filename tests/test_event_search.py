"""Database-side event filtering, pagination, timelines and drill-down."""

import time
from datetime import timedelta

import pytest

from moesoc.engine.rules import detect_multiple_failed_logins
from moesoc.engine.scanner import run_detections
from moesoc.storage.event_search import (
    EventFilter,
    around_filter,
    detection_timeline,
    distinct_values,
    explain_event,
    pivot_timeline,
    search_events,
)
from moesoc.storage.repository import DetectionRepository, EventRepository

from .conftest import BASE_TIME, auth_event, failures

SEC = timedelta(seconds=1)
MIN = timedelta(minutes=1)


@pytest.fixture
def populated(database):
    events = [
        *failures("alice", 5, BASE_TIME, 10 * SEC, ip="198.51.100.7"),
        auth_event(4624, "alice", BASE_TIME + MIN, 1100, ip="198.51.100.7", logon_type=10),
        auth_event(4624, "bob", BASE_TIME + 2 * MIN, 1101, ip="203.0.113.9", domain="CORP"),
        auth_event(4625, "100%_admin", BASE_TIME + 3 * MIN, 1102, ip="-", logon_type=2),
        # Context outside the finding but inside the timeline padding:
        auth_event(4624, "carol", BASE_TIME - 10 * MIN, 900, ip="192.0.2.1"),
        # Same time, other host: must not appear in the finding's timeline.
        auth_event(4624, "dave", BASE_TIME + 30 * SEC, 5000, host="OTHER-PC.lab.example"),
        # Far outside the window:
        auth_event(4624, "erin", BASE_TIME + 3 * 60 * MIN, 1200),
    ]
    with database.connect() as conn:
        EventRepository(conn).insert_many(events)
    return database


def _search(db, **kw):
    with db.connect() as conn:
        return search_events(conn, EventFilter(**kw))


def test_no_filter_returns_everything_newest_first(populated):
    page = _search(populated)
    assert page.total == 11
    times = [s.event.timestamp for s in page.events]
    assert times == sorted(times, reverse=True)


def test_filters_compose(populated):
    page = _search(populated, username="alice", event_ids=(4624,))
    assert [s.event.record_id for s in page.events] == [1100]


def test_username_filter_is_case_insensitive_contains(populated):
    assert _search(populated, username="ALI").total == 6


def test_domain_filter_is_exact(populated):
    assert {s.event.target_username for s in _search(populated, domain="corp").events} == {"bob"}


def test_ip_filter_exact_and_prefix(populated):
    assert _search(populated, ip="198.51.100.7").total == 6
    assert _search(populated, ip="::ffff:198.51.100.7").total == 6  # normalized like stored data
    assert _search(populated, ip="203.0.").total == 1


def test_logon_type_and_text_filters(populated):
    assert _search(populated, logon_type=10).total == 1
    assert _search(populated, text="Incorrect password").total == 6


def test_like_wildcards_in_input_are_literal(populated):
    assert [s.event.target_username for s in _search(populated, username="100%_").events] == [
        "100%_admin"
    ]
    assert _search(populated, username="%").total == 1  # only the user whose name has a "%"


def test_time_range_filter(populated):
    page = _search(populated, start=BASE_TIME, end=BASE_TIME + MIN)
    assert page.total == 7  # 5 failures, alice's success, dave's on the other host


def test_pagination(populated):
    first = _search(populated, limit=4)
    second = _search(populated, limit=4, offset=4)
    assert first.total == 11 and len(first.events) == 4 and first.has_more
    assert not {s.pk for s in first.events} & {s.pk for s in second.events}
    last = _search(populated, limit=4, offset=8)
    assert len(last.events) == 3 and not last.has_more


def test_distinct_values_and_column_whitelist(populated):
    with populated.connect() as conn:
        assert distinct_values(conn, "event_id") == [4624, 4625]
        with pytest.raises(ValueError):
            distinct_values(conn, "raw_xml; DROP TABLE events")


# ------------------------------------------------------------------ timeline + drill-down
def _store_detection(db, rules):
    with db.connect() as conn:
        stored = EventRepository(conn).in_range(BASE_TIME - MIN, BASE_TIME + 5 * MIN, (4625,))
        (detection,) = detect_multiple_failed_logins(
            [e for e in stored if e.target_username == "alice"], rules["DET-001"]
        )
        DetectionRepository(conn).upsert(detection, None)
        return DetectionRepository(conn).list_all()[0].id


def test_detection_timeline_flags_evidence_and_shows_context(populated, rules):
    det_id = _store_detection(populated, rules)
    with populated.connect() as conn:
        timeline = detection_timeline(conn, det_id)
    records = [i.event.record_id for i in timeline.items]
    evidence = [i.event.record_id for i in timeline.items if i.is_evidence]
    assert evidence == [1000, 1001, 1002, 1003, 1004]
    assert 900 in records  # context 10 minutes before
    assert 1100 in records  # context after: the success
    assert 5000 not in records  # other host
    assert 1200 not in records  # outside the padding
    assert records == sorted(records)  # chronological
    assert timeline.evidence_count == 5
    assert all(i.badge == "Evidence" for i in timeline.items if i.is_evidence)


def test_drill_down_returns_exactly_the_evidence_events(populated, rules):
    det_id = _store_detection(populated, rules)
    with populated.connect() as conn:
        pks = tuple(DetectionRepository(conn).evidence_event_pks(det_id))
        page = search_events(conn, EventFilter(event_pks=pks))
    assert sorted(s.event.record_id for s in page.events) == [1000, 1001, 1002, 1003, 1004]


def test_pivot_timelines(populated):
    with populated.connect() as conn:
        by_ip = pivot_timeline(conn, EventFilter(ip="198.51.100.7"), "IP pivot")
        around = pivot_timeline(conn, around_filter(BASE_TIME, "WS-LAB01.lab.example", 1), "Around")
    assert len(by_ip.items) == 6
    assert all(i.event.source_ip == "198.51.100.7" for i in by_ip.items)
    assert {i.event.record_id for i in around.items} == {1000, 1001, 1002, 1003, 1004, 1100}


def test_explanations_use_only_recorded_fields(populated):
    page = _search(populated, event_ids=(4625,), ip="198.51.100.7", limit=1)
    text = explain_event(page.events[0].event)
    assert text == "Failed Network logon for LAB\\alice: Incorrect password, from 198.51.100.7"


# ------------------------------------------------------------------ scale
def test_ten_thousand_events_search_and_detect(database, rules):
    users = [f"user{i:03d}" for i in range(200)]
    events = [
        auth_event(
            4625 if i % 4 else 4624,
            users[i % 200],
            BASE_TIME + i * 2 * SEC,
            100_000 + i,
            ip=f"198.51.100.{i % 37 + 1}",  # 37 is coprime with 200: many users per IP
        )
        for i in range(10_000)
    ]
    with database.connect() as conn:
        assert EventRepository(conn).insert_many(events) == 10_000
    started = time.perf_counter()
    with database.connect() as conn:
        page = search_events(conn, EventFilter(username="user007", ip="198.51.100.8", limit=50))
        stored = EventRepository(conn).in_range(BASE_TIME, BASE_TIME + 6 * 60 * MIN, (4624, 4625))
    detections = run_detections(stored, rules)
    elapsed = time.perf_counter() - started
    assert page.total > 0 and all(s.event.target_username == "user007" for s in page.events)
    assert len(stored) == 10_000
    assert detections  # many accounts per source: password-spray findings expected
    assert elapsed < 30  # generous bound for slow CI machines; measured value is far lower
