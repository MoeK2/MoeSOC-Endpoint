"""Always-on sensor: which findings notify, once, and state that survives a restart."""

from __future__ import annotations

import sqlite3
import threading
from datetime import timedelta

import pytest

from moesoc.sensor.notifications import (
    EVALUATED_KEY,
    Notification,
    NotificationEngine,
    NotificationHub,
    NotificationPrefs,
    load_prefs,
    save_prefs,
)
from moesoc.storage.database import Database
from moesoc.storage.repository import to_db_time
from moesoc.storage.schema import MIGRATIONS
from moesoc.utils.time import utc_now

T0 = utc_now()


def add_finding(conn, *, rule="DET-001", severity="HIGH", risk=70, status="NEW", at=None, key=None):
    at = to_db_time(at or utc_now())
    cur = conn.execute(
        "INSERT INTO detections (dedup_key, rule_id, kind, title, severity, confidence, "
        "risk_score, account, first_seen, last_seen, evidence_json, created_at, updated_at, "
        "status, rule_version, occurrence_count) "
        "VALUES (?, ?, 'detection', ?, ?, 'MEDIUM', ?, 'LAB\\alice', ?, ?, '{}', ?, ?, ?, "
        "'1.0', 1)",
        (
            key or f"{rule}|{at}|{risk}",
            rule,
            f"Title {rule}",
            severity,
            risk,
            at,
            at,
            at,
            at,
            status,
        ),
    )
    return cur.lastrowid


def update_finding(conn, finding_id, *, severity=None, risk=None, status=None, at=None):
    row = conn.execute("SELECT * FROM detections WHERE id = ?", (finding_id,)).fetchone()
    conn.execute(
        "UPDATE detections SET severity = ?, risk_score = ?, status = ?, updated_at = ? "
        "WHERE id = ?",
        (
            severity or row["severity"],
            row["risk_score"] if risk is None else risk,
            status or row["status"],
            to_db_time(at or utc_now()),
            finding_id,
        ),
    )


@pytest.fixture
def conn(database):
    with database.connect() as c:
        c.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
            (EVALUATED_KEY, to_db_time(T0), to_db_time(T0)),
        )
        yield c


@pytest.fixture
def engine():
    return NotificationEngine()


def test_first_evaluation_sets_a_baseline_and_never_floods(database, engine):
    with database.connect() as c:
        add_finding(c, at=T0 - timedelta(days=3))
        assert engine.evaluate(c) == []
        assert c.execute("SELECT value FROM settings WHERE key=?", (EVALUATED_KEY,)).fetchone()


@pytest.mark.parametrize(
    ("severity", "expected"), [("LOW", 0), ("MEDIUM", 0), ("HIGH", 1), ("CRITICAL", 1)]
)
def test_default_policy_by_severity(conn, engine, severity, expected):
    add_finding(conn, severity=severity)
    notes = engine.evaluate(conn)
    assert len(notes) == expected
    if notes:
        assert notes[0].reason == "new" and notes[0].severity == severity


def test_medium_notifies_when_enabled(conn, engine):
    add_finding(conn, severity="MEDIUM")
    assert len(engine.evaluate(conn, NotificationPrefs(medium=True))) == 1


def test_a_growing_finding_notifies_once(conn, engine):
    fid = add_finding(conn, risk=70)
    assert len(engine.evaluate(conn)) == 1
    for _ in range(3):  # DET-001 at 7, 9, 12 failures: same severity, same/similar risk
        update_finding(conn, fid, risk=72)
        assert engine.evaluate(conn) == []


def test_severity_escalation_notifies_immediately(conn, engine):
    fid = add_finding(conn, severity="HIGH")
    engine.evaluate(conn)
    update_finding(conn, fid, severity="CRITICAL")
    notes = engine.evaluate(conn)
    assert [n.reason for n in notes] == ["escalated"]
    assert "raised to CRITICAL" in notes[0].body


def test_medium_finding_notifies_when_it_becomes_high(conn, engine):
    fid = add_finding(conn, severity="MEDIUM")
    assert engine.evaluate(conn) == []
    update_finding(conn, fid, severity="HIGH")
    assert [n.reason for n in engine.evaluate(conn)] == ["new"]


def test_correlation_on_top_of_a_detection_notifies(conn, engine):
    add_finding(conn, rule="DET-001", severity="MEDIUM")
    assert engine.evaluate(conn) == []
    add_finding(conn, rule="COR-001", severity="HIGH", at=utc_now())
    assert [n.rule_id for n in engine.evaluate(conn)] == ["COR-001"]


def test_risk_increase_respects_the_cooldown(conn, engine):
    fid = add_finding(conn, risk=60)
    engine.evaluate(conn, now=T0)
    update_finding(conn, fid, risk=90)
    assert engine.evaluate(conn, now=T0 + timedelta(minutes=10)) == []  # cooling down
    update_finding(conn, fid, risk=90)
    notes = engine.evaluate(conn, now=T0 + timedelta(minutes=61))
    assert [n.reason for n in notes] == ["risk"]


def test_closed_findings_never_notify(conn, engine):
    add_finding(conn, status="FALSE_POSITIVE")
    assert engine.evaluate(conn) == []


def test_paused_notifications_are_recorded_silently(conn, engine):
    add_finding(conn)
    prefs = NotificationPrefs(paused_until=utc_now() + timedelta(hours=1))
    notes = engine.evaluate(conn, prefs)
    assert len(notes) == 1 and notes[0].silent
    assert engine.evaluate(conn) == []  # not repeated after the pause


def test_state_survives_a_restart(database):
    with database.connect() as c:
        NotificationEngine().evaluate(c)  # baseline
    with database.connect() as c:
        fid = add_finding(c, at=utc_now())
        assert len(NotificationEngine().evaluate(c)) == 1
    with database.connect() as c:  # a new engine = a restarted service
        update_finding(c, fid, risk=75)
        assert NotificationEngine().evaluate(c) == []
        assert c.execute("SELECT times_notified FROM notification_state").fetchone()[0] == 1


def test_many_findings_at_once_become_two_toasts_and_a_summary(conn, engine):
    for i in range(6):
        add_finding(conn, risk=60 + i, key=f"k{i}")
    notes = engine.evaluate(conn)
    assert len(notes) == 3 and notes[-1].reason == "summary" and notes[-1].detection_id is None
    assert notes[0].risk == 65


def test_notification_text_is_factual(conn, rules):
    add_finding(conn, rule="COR-001", severity="HIGH", risk=70)
    note = NotificationEngine(rules).evaluate(conn)[0]
    assert "Severity: HIGH" in note.body and "Risk: 70" in note.body
    text = (note.title + note.body).lower()
    assert "hacked" not in text and "malware" not in text


def test_prefs_round_trip_and_validation(database):
    with database.connect() as c:
        assert load_prefs(c) == NotificationPrefs()
        save_prefs(c, NotificationPrefs(medium=True, cooldown_minutes=30))
        assert load_prefs(c).medium and load_prefs(c).cooldown_minutes == 30
    for bad in (
        {"medium": "yes"},
        {"cooldown_minutes": 1},
        {"cooldown_minutes": True},
        {"unknown": 1},
        {"paused_until": to_db_time(utc_now() + timedelta(days=3))},
        {"paused_until": "2026-01-01T00:00:00"},
        [],
    ):
        with pytest.raises(ValueError):
            NotificationPrefs.from_dict(bad)  # type: ignore[arg-type]


def test_damaged_prefs_fall_back_to_defaults(database):
    with database.connect() as c:
        c.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES ('notify.preferences', '{', '')"
        )
        assert load_prefs(c) == NotificationPrefs()


def test_hub_long_poll_wakes_on_publish():
    hub = NotificationHub(capacity=3)
    got: list = []
    waiter = threading.Thread(target=lambda: got.extend(hub.wait_after(0, 5)))
    waiter.start()
    hub.publish([Notification(1, "COR-001", "t", "b", "HIGH", 70, "new")])
    waiter.join(5)
    assert [n.seq for n in got] == [1]
    for i in range(5):
        hub.publish([Notification(i + 2, "R", "t", "b", "HIGH", 70, "new")])
    assert len(hub.wait_after(0, 0)) == 3  # bounded
    assert hub.last_important.detection_id == 6


def test_upgrade_from_v8_keeps_data_and_adds_notification_state(tmp_path):
    path = tmp_path / "old.db"
    raw = sqlite3.connect(path)
    for index, migration in enumerate(MIGRATIONS[:8]):
        if isinstance(migration, str):
            raw.executescript(migration)
        else:
            migration(raw)
        raw.execute(f"PRAGMA user_version = {index + 1}")
    raw.commit()
    add_finding(raw)
    raw.commit()
    raw.close()
    database = Database(path)
    assert database.initialize() == len(MIGRATIONS)
    with database.connect() as c:
        assert c.execute("SELECT COUNT(*) FROM detections").fetchone()[0] == 1
        assert c.execute("SELECT COUNT(*) FROM notification_state").fetchone()[0] == 0
