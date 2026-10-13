"""Analyst triage state, notes, audit history, rescan safety and schema migration."""

import json
import sqlite3
from dataclasses import replace
from datetime import timedelta

import pytest

from moesoc.core.enums import TriageStatus
from moesoc.core.exceptions import MoeSOCError
from moesoc.engine.rules import detect_multiple_failed_logins
from moesoc.engine.scanner import ScanService
from moesoc.storage.database import Database
from moesoc.storage.overview import load_overview
from moesoc.storage.repository import DetectionRepository, EventRepository
from moesoc.storage.schema import MIGRATION_1, SCHEMA_VERSION

from .conftest import BASE_TIME, FakeReader, failures
from .test_scanner import _attack_sequence

SEC = timedelta(seconds=1)


def _store_one(database, rules):
    events = failures("alice", 5, BASE_TIME, 10 * SEC)
    (detection,) = detect_multiple_failed_logins(events, rules["DET-001"])
    with database.connect() as conn:
        EventRepository(conn).insert_many(events)
        DetectionRepository(conn).upsert(detection, None)
        (stored,) = DetectionRepository(conn).list_all()
    return stored, detection


def test_new_detection_starts_as_new_with_history_and_evidence_links(database, rules):
    stored, _ = _store_one(database, rules)
    assert stored.status is TriageStatus.NEW
    assert stored.rule_version == rules["DET-001"].version
    assert stored.occurrence_count == 5
    with database.connect() as conn:
        repo = DetectionRepository(conn)
        assert len(repo.evidence_event_pks(stored.id)) == 5
        assert [h.to_status for h in repo.history(stored.id)] == ["NEW"]


def test_status_workflow_records_verdict_resolution_and_history(database, rules):
    stored, _ = _store_one(database, rules)
    with database.connect() as conn:
        repo = DetectionRepository(conn)
        investigating = repo.set_status(stored.id, TriageStatus.INVESTIGATING)
        assert investigating.resolved_at is None
        fp = repo.set_status(stored.id, TriageStatus.FALSE_POSITIVE)
        assert fp.verdict == "FALSE_POSITIVE"
        assert fp.resolved_at is not None
        reopened = repo.set_status(stored.id, TriageStatus.INVESTIGATING)
        assert reopened.resolved_at is None
        assert reopened.verdict == "FALSE_POSITIVE"  # last verdict kept for reference
        resolved = repo.set_status(stored.id, TriageStatus.RESOLVED)
        assert resolved.status.is_closed
        history = [(h.from_status, h.to_status) for h in repo.history(stored.id)]
    assert history == [
        (None, "NEW"),
        ("NEW", "INVESTIGATING"),
        ("INVESTIGATING", "FALSE_POSITIVE"),
        ("FALSE_POSITIVE", "INVESTIGATING"),
        ("INVESTIGATING", "RESOLVED"),
    ]


def test_notes_persist_and_are_validated(database, rules):
    stored, _ = _store_one(database, rules)
    with database.connect() as conn:
        DetectionRepository(conn).add_note(stored.id, "  Confirmed with user: forgot password.  ")
    with database.connect() as conn:
        (note,) = DetectionRepository(conn).notes(stored.id)
    assert note.body == "Confirmed with user: forgot password."
    with pytest.raises(MoeSOCError), database.connect() as conn:
        DetectionRepository(conn).add_note(stored.id, "   ")
    with pytest.raises(MoeSOCError), database.connect() as conn:
        DetectionRepository(conn).add_note(999, "no such finding")


def test_rescan_preserves_analyst_work(config, database, rules):
    service = ScanService(
        config, database, rules, reader_factory=lambda: FakeReader(_attack_sequence())
    )
    service.run_live_scan()
    with database.connect() as conn:
        repo = DetectionRepository(conn)
        target = next(d for d in repo.list_all() if d.rule_id == "COR-001")
        repo.set_status(target.id, TriageStatus.TRUE_POSITIVE)
        repo.add_note(target.id, "Escalated to IR.")
    second = service.run_live_scan()
    assert second.detections_new == 0
    with database.connect() as conn:
        repo = DetectionRepository(conn)
        after = repo.get(target.id)
        notes = repo.notes(target.id)
    assert after.status is TriageStatus.TRUE_POSITIVE
    assert after.verdict == "TRUE_POSITIVE"
    assert [n.body for n in notes] == ["Escalated to IR."]


def test_finding_from_older_rule_version_is_not_reinterpreted(database, rules):
    stored, detection = _store_one(database, rules)
    newer_rule = replace(rules["DET-001"], version="9.9")
    newer = replace(detection, rule=newer_rule, evidence={"changed": True})
    with database.connect() as conn:
        assert DetectionRepository(conn).upsert(newer, None) is False
        kept = DetectionRepository(conn).get(stored.id)
    assert kept.rule_version == rules["DET-001"].version
    assert "changed" not in kept.evidence


def test_closed_findings_do_not_drive_overview_risk(config, database, rules):
    service = ScanService(
        config, database, rules, reader_factory=lambda: FakeReader(_attack_sequence())
    )
    service.run_live_scan()
    assert load_overview(database).risk_score == 70
    with database.connect() as conn:
        repo = DetectionRepository(conn)
        for d in repo.list_all():
            repo.set_status(d.id, TriageStatus.BENIGN)
    snapshot = load_overview(database)
    assert snapshot.risk_score == 0
    assert snapshot.open_detections == []
    assert len(snapshot.detections) == 2  # closed findings are kept, not deleted


def test_set_status_on_missing_detection_fails_cleanly(database):
    with pytest.raises(MoeSOCError), database.connect() as conn:
        DetectionRepository(conn).set_status(12345, TriageStatus.RESOLVED)


# ------------------------------------------------------------------ migration v1 → v2
T0 = "2026-10-06T08:00:00.000000+00:00"
T1 = "2026-10-06T08:01:00.000000+00:00"


def test_v1_database_migrates_without_losing_data(tmp_path):
    path = tmp_path / "v1.db"
    conn = sqlite3.connect(path)
    conn.executescript("BEGIN;" + MIGRATION_1 + "PRAGMA user_version = 1;COMMIT;")
    conn.execute(
        "INSERT INTO events (hostname, channel, record_id, timestamp, source, provider, event_id, "
        "target_username, raw_xml, ingested_at) VALUES ('WS', 'Security', 1000, "
        "?, 'security', 'p', 4625, 'alice', '<Event/>', ?)",
        (T0, T1),
    )
    evidence = {"hostname": "WS", "failure_record_ids": [1000], "failure_count": 1}
    conn.execute(
        "INSERT INTO detections (dedup_key, rule_id, kind, title, severity, confidence, "
        "risk_score, account, first_seen, last_seen, evidence_json, created_at, updated_at) "
        "VALUES ('DET-001|WS|alice|1000', 'DET-001', 'detection', 'Multiple Failed Logins', "
        "'MEDIUM', 'MEDIUM', 40, 'LAB\\alice', ?, ?, ?, ?, ?)",
        (T0, T0, json.dumps(evidence), T1, T1),
    )
    conn.commit()
    conn.close()

    database = Database(path)
    assert database.initialize() == SCHEMA_VERSION
    with database.connect() as conn:
        key = conn.execute("SELECT dedup_key FROM detections").fetchone()[0]
        repo = DetectionRepository(conn)
        (stored,) = repo.list_all()
        links = repo.evidence_event_pks(stored.id)
        (event,) = EventRepository(conn).recent(10)
    assert key == "DET-001|WS|1000"
    assert stored.status is TriageStatus.NEW
    assert stored.rule_version == "1.0"
    assert stored.occurrence_count == 1
    assert len(links) == 1
    assert event.target_user_sid is None  # new column, old row: safely NULL
