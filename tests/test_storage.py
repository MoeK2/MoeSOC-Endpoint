import sqlite3
from datetime import timedelta

import pytest

from moesoc.core.exceptions import StorageError
from moesoc.engine.rules import detect_multiple_failed_logins
from moesoc.parsers.security import parse_security_xml
from moesoc.storage.database import Database
from moesoc.storage.repository import DetectionRepository, EventRepository, ScanRepository
from moesoc.storage.schema import SCHEMA_VERSION

from .conftest import BASE_TIME, failures, fixture_text


def test_initialize_is_idempotent(database):
    assert database.initialize() == SCHEMA_VERSION
    assert database.initialize() == SCHEMA_VERSION


def test_event_round_trip_preserves_fields(database):
    original = parse_security_xml(fixture_text("4625_failed_network_logon.xml"))
    with database.connect() as conn:
        assert EventRepository(conn).insert_many([original]) == 1
    with database.connect() as conn:
        (stored,) = EventRepository(conn).recent(10)
    assert stored == original  # every field, including raw_xml and tz-aware timestamp


def test_duplicate_events_are_not_ingested_twice(database):
    event = parse_security_xml(fixture_text("4625_failed_network_logon.xml"))
    with database.connect() as conn:
        repo = EventRepository(conn)
        assert repo.insert_many([event, event]) == 1
        assert repo.insert_many([event]) == 0
        assert repo.count() == 1


def test_counts_by_event_id(database):
    events = [
        parse_security_xml(fixture_text("4625_failed_network_logon.xml")),
        parse_security_xml(fixture_text("4624_successful_rdp_logon.xml")),
        parse_security_xml(fixture_text("4624_local_service_logon.xml")),
    ]
    with database.connect() as conn:
        EventRepository(conn).insert_many(events)
        assert EventRepository(conn).count_by_event_id() == {4624: 2, 4625: 1}


def test_failed_transaction_is_rolled_back(database):
    event = parse_security_xml(fixture_text("4625_failed_network_logon.xml"))
    with pytest.raises(StorageError), database.connect() as conn:
        EventRepository(conn).insert_many([event])
        conn.execute("INSERT INTO no_such_table VALUES (1)")
    with database.connect() as conn:
        assert EventRepository(conn).count() == 0


def test_database_from_newer_version_is_left_untouched(tmp_path):
    path = tmp_path / "future.db"
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA user_version = 999")
    conn.close()
    with pytest.raises(StorageError, match="newer version"):
        Database(path).initialize()


def test_detection_upsert_deduplicates(database, rules):
    events = failures("alice", 5, BASE_TIME, timedelta(seconds=30))
    (detection,) = detect_multiple_failed_logins(events, rules["DET-001"])
    with database.connect() as conn:
        scan_id = ScanRepository(conn).start("live")
        repo = DetectionRepository(conn)
        assert repo.upsert(detection, scan_id) is True
        assert repo.upsert(detection, scan_id) is False
        assert repo.count() == 1
        stored = repo.list_all()[0]
    assert stored.rule_id == "DET-001"
    assert stored.evidence["failure_count"] == 5
    assert stored.severity == "MEDIUM"
