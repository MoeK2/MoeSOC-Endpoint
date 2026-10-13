"""Retention: deletes only old MoeSOC data, keeps open investigations, needs confirmation."""

from __future__ import annotations

import ast
from datetime import timedelta
from pathlib import Path

import pytest

from moesoc.core.enums import CLOSED_STATUSES, TriageStatus
from moesoc.core.exceptions import MoeSOCError
from moesoc.engine.scanner import run_detections
from moesoc.storage import retention
from moesoc.storage.collection_state import CollectionStateRepository, Watermark
from moesoc.storage.repository import DetectionRepository, EventRepository, ScanRepository
from moesoc.storage.retention import (
    DEFAULT_DAYS,
    apply_retention,
    get_retention_days,
    plan_retention,
    set_retention_days,
)
from moesoc.utils.time import utc_now

from .conftest import auth_event, failures

NOW = utc_now().replace(microsecond=0)
OLD = NOW - timedelta(days=45)
RECENT = NOW - timedelta(days=2)


def brute_force(user, at, first_record):
    return [
        *failures(user, 6, at, timedelta(seconds=10), first_record=first_record),
        auth_event(4624, user, at + timedelta(minutes=1), first_record + 100),
    ]


@pytest.fixture
def data(database, rules):
    """Old incident (closed), old incident (still open), recent incident, old noise."""
    closed = brute_force("bob", OLD, 1000)
    still_open = brute_force("carol", OLD + timedelta(hours=1), 2000)
    recent = brute_force("alice", RECENT, 3000)
    noise = [auth_event(4624, "svc", OLD + timedelta(hours=3), 4000 + i) for i in range(5)]
    with database.connect() as conn:
        scans = ScanRepository(conn)
        old_scan = scans.start("import")
        conn.execute("UPDATE scans SET started_at = ? WHERE id = ?", (OLD.isoformat(), old_scan))
        EventRepository(conn).insert_many([*closed, *still_open, *recent, *noise])
        repo = DetectionRepository(conn)
        for d in run_detections([*closed, *still_open, *recent], rules):
            repo.upsert(d, None)
        ids = {(d.rule_id, d.account): d.id for d in repo.list_all()}
        for (_rule, account), detection_id in ids.items():
            if account and account.endswith("bob"):
                repo.set_status(detection_id, TriageStatus.FALSE_POSITIVE)
                repo.add_note(detection_id, "test note")
        CollectionStateRepository(conn).save(
            Watermark("Security", "core", "sig", 4004, OLD), allow_backward=True
        )
        scans.start("live")  # the latest scan is always kept
    return ids


def counts(database):
    with database.connect() as conn:
        return {
            table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # noqa: S608
            for table in ("events", "detections", "detection_notes", "scans", "collection_state")
        }


def test_plan_counts_without_deleting(database, data):
    before = counts(database)
    with database.connect() as conn:
        plan = plan_retention(conn, 30, NOW)
    assert counts(database) == before
    assert plan.findings == 2  # bob's DET-001 and COR-001, both closed
    assert plan.open_findings_kept == 2  # carol's, still open
    assert plan.events == 7 + 5  # bob's events and the noise
    assert plan.events_kept_as_evidence == 7  # carol's evidence
    assert "Windows event logs are not touched" in plan.describe()


def test_apply_deletes_exactly_the_plan(database, data):
    with database.connect() as conn:
        plan = plan_retention(conn, 30, NOW)
        done = apply_retention(conn, 30, confirmed=True, now=NOW)
    assert (done.events, done.findings) == (plan.events, plan.findings)
    after = counts(database)
    assert after["detection_notes"] == 0  # bob's notes went with his closed findings
    assert after["collection_state"] == 1  # watermarks are never removed
    with database.connect() as conn:
        accounts = {d.account for d in DetectionRepository(conn).list_all()}
        users = {r[0] for r in conn.execute("SELECT DISTINCT target_username FROM events")}
    assert not any(a and a.endswith("bob") for a in accounts)
    assert {"carol", "alice"} <= users and "bob" not in users and "svc" not in users


def test_open_findings_keep_all_their_evidence(database, data):
    with database.connect() as conn:
        apply_retention(conn, 30, confirmed=True, now=NOW)
        repo = DetectionRepository(conn)
        carol = [d for d in repo.list_all() if d.account and d.account.endswith("carol")]
        assert {d.rule_id for d in carol} == {"DET-001", "COR-001"}
        for d in carol:
            assert len(repo.evidence_event_pks(d.id)) == d.occurrence_count > 0


def test_nothing_happens_without_confirmation(database, data):
    before = counts(database)
    with database.connect() as conn, pytest.raises(MoeSOCError):
        apply_retention(conn, 30, confirmed=False, now=NOW)
    assert counts(database) == before


def test_only_7_30_90_days(database):
    with database.connect() as conn:
        assert get_retention_days(conn) == DEFAULT_DAYS == 30
        set_retention_days(conn, 90)
        assert get_retention_days(conn) == 90
        with pytest.raises(MoeSOCError):
            set_retention_days(conn, 1)
        with pytest.raises(MoeSOCError):
            plan_retention(conn, 365)


def test_seven_days_also_keeps_recent_data(database, data):
    with database.connect() as conn:
        apply_retention(conn, 7, confirmed=True, now=NOW)
        users = {r[0] for r in conn.execute("SELECT DISTINCT target_username FROM events")}
    assert "alice" in users  # 2 days old


def test_scans_still_referenced_or_latest_are_kept(database, data):
    with database.connect() as conn:
        apply_retention(conn, 30, confirmed=True, now=NOW)
        assert ScanRepository(conn).last() is not None


def test_closed_status_literal_matches_the_enum():
    assert "(" + ", ".join(f"'{s}'" for s in sorted(CLOSED_STATUSES)) + ")" == retention.CLOSED_SQL


def test_retention_never_touches_windows_logs():
    """The module may only import storage/time helpers: no event-log or win32 APIs."""
    tree = ast.parse(Path(retention.__file__).read_text(encoding="utf-8"))
    modules = {
        n.module if isinstance(n, ast.ImportFrom) else a.name
        for n in ast.walk(tree)
        if isinstance(n, (ast.Import, ast.ImportFrom))
        for a in (n.names if isinstance(n, ast.Import) else [n])
    }
    assert not any(m and ("win32" in m or "eventlog" in m or "collectors" in m) for m in modules)
    text = Path(retention.__file__).read_text(encoding="utf-8")
    assert "EvtClearLog" not in text and "wevtutil" not in text


def test_cli_retention_previews_then_applies_only_with_yes(database, config, data, capsys):
    from moesoc.cli import main

    base = ["--data-dir", str(config.data_dir), "retention"]
    before = counts(database)
    assert main(base) == 0
    assert "Nothing was deleted" in capsys.readouterr().out
    assert counts(database) == before
    assert main([*base, "--days", "90", "--save"]) == 0
    with database.connect() as conn:
        assert get_retention_days(conn) == 90
    assert main([*base, "--days", "30", "--apply", "--yes"]) == 0
    assert "Deleted" in capsys.readouterr().out
    assert counts(database)["events"] < before["events"]
