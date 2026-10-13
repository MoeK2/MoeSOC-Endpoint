"""B-7: a console without administrator rights works with the sensor's database.

Root cause (reproduced on real Windows): the sensor's "keeper" connection never ran a
statement, so SQLite never opened the -wal/-shm files for it; after each write the last
writer deleted them, and a reader that may not create them (normal user, read-only data
folder) got "unable to open database file" with ``mode=ro``. The fix keeps the files in
place, reads stay ``mode=ro``, and the console's two analyst writes go to the sensor.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import sys
from pathlib import Path

import pytest

from moesoc import frozen
from moesoc.core.enums import HealthState, TriageStatus
from moesoc.core.exceptions import MoeSOCError, StorageError
from moesoc.engine.rules import detect_multiple_failed_logins
from moesoc.gui import triage_actions
from moesoc.health import run_sensor_health_checks
from moesoc.sensor.core import open_keeper
from moesoc.sensor.ipc import Dispatcher, SensorClient, SensorUnavailable, console_write
from moesoc.storage.database import Database
from moesoc.storage.repository import DetectionRepository, EventRepository

from .conftest import BASE_TIME, failures
from .test_frozen import EXE, FakeApi
from .test_sensor_ipc import FakeCore

ROOT_USER = hasattr(os, "geteuid") and os.geteuid() == 0


def _store_finding(database, rules) -> int:
    from datetime import timedelta

    events = failures("alice", 5, BASE_TIME, timedelta(seconds=10))
    (detection,) = detect_multiple_failed_logins(events, rules["DET-001"])
    with database.connect() as conn:
        EventRepository(conn).insert_many(events)
        DetectionRepository(conn).upsert(detection, None)
        return DetectionRepository(conn).list_all()[0].id


def _short_lived_write(path: Path) -> None:
    conn = sqlite3.connect(path, timeout=10)
    conn.execute(
        "INSERT INTO settings (key, value, updated_at) VALUES ('b7', 'x', 'now') "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value"
    )
    conn.commit()
    conn.close()


# ------------------------------------------------------------------ the root cause
def test_a_keeper_that_never_reads_lets_the_wal_files_disappear(database):
    """The old keeper: documents the SQLite behaviour that caused B-7."""
    idle = sqlite3.connect(database.path, timeout=10)
    try:
        _short_lived_write(database.path)
        assert not Path(f"{database.path}-wal").exists()
    finally:
        idle.close()


def test_the_sensor_keeper_keeps_the_wal_files_for_read_only_consoles(database):
    keeper = open_keeper(database.path)
    try:
        for _ in range(3):
            _short_lived_write(database.path)
        assert Path(f"{database.path}-wal").exists()
        assert Path(f"{database.path}-shm").exists()
        # It holds no read transaction: a full checkpoint is not blocked.
        conn = sqlite3.connect(database.path)
        busy, _log, _done = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        conn.close()
        assert busy == 0
    finally:
        keeper.close()


@pytest.mark.skipif(ROOT_USER or sys.platform == "win32", reason="needs file permissions")
def test_read_only_reader_sees_new_rows_while_the_writer_keeps_writing(database, tmp_path):
    """POSIX stand-in for the real Windows test: reader may not write any of the files."""
    keeper = open_keeper(database.path)
    try:
        _short_lived_write(database.path)
        for suffix in ("", "-wal", "-shm"):
            os.chmod(f"{database.path}{suffix}", stat.S_IRUSR)
        os.chmod(database.path.parent, stat.S_IRUSR | stat.S_IXUSR)  # no new files either
        console = Database(database.path)
        with console.connect() as conn:  # the change lives only in the WAL so far
            value = conn.execute("SELECT value FROM settings WHERE key = 'b7'").fetchone()[0]
        assert console.read_only and value == "x"
        with pytest.raises(StorageError), console.connect() as conn:
            conn.execute("DELETE FROM settings")
    finally:
        os.chmod(database.path.parent, stat.S_IRWXU)
        for suffix in ("", "-wal", "-shm"):
            os.chmod(f"{database.path}{suffix}", stat.S_IRUSR | stat.S_IWUSR)
        keeper.close()


# ------------------------------------------------------------------ IPC writes
def test_dispatcher_accepts_valid_triage_and_notes():
    calls = []

    class Core(FakeCore):
        def set_triage(self, detection_id, status, client):
            calls.append(("triage", detection_id, status, client))
            return status.value

        def add_note(self, detection_id, body, client):
            calls.append(("note", detection_id, body, client))
            return 7

    d = Dispatcher(Core())
    reply = json.loads(
        d.handle_bytes(
            json.dumps({"cmd": "set_triage", "finding": 3, "status": "BENIGN"}).encode(), "pid 1"
        )
    )
    assert reply == {"ok": True, "finding": 3, "status": "BENIGN"}
    reply = json.loads(
        d.handle_bytes(
            json.dumps({"cmd": "add_note", "finding": 3, "body": "checked"}).encode(), "pid 1"
        )
    )
    assert reply == {"ok": True, "finding": 3, "note": 7}
    assert calls == [("triage", 3, TriageStatus.BENIGN, "pid 1"), ("note", 3, "checked", "pid 1")]


@pytest.mark.parametrize(
    "request_",
    [
        {"cmd": "set_triage", "finding": 3, "status": "DELETED"},
        {"cmd": "set_triage", "finding": 3},
        {"cmd": "set_triage", "finding": True, "status": "NEW"},
        {"cmd": "set_triage", "finding": -1, "status": "NEW"},
        {"cmd": "set_triage", "finding": "3", "status": "NEW"},
        {"cmd": "set_triage", "finding": 2**70, "status": "NEW"},
        {"cmd": "add_note", "finding": 3, "body": 5},
        {"cmd": "add_note", "finding": 0, "body": "x"},
        {"cmd": "add_suppression", "value": "alice"},  # tuning is never offered over IPC
        {"cmd": "set_retention", "days": 1},
    ],
)
def test_dispatcher_rejects_invalid_or_unoffered_writes(request_):
    class Core(FakeCore):
        def set_triage(self, *a):  # pragma: no cover - must not be reached
            raise AssertionError("reached")

        add_note = set_triage

    reply = json.loads(Dispatcher(Core()).handle_bytes(json.dumps(request_).encode()))
    assert reply["ok"] is False


def test_sensor_saves_triage_and_notes_in_its_database(config, database, rules):
    from moesoc.sensor.core import SensorCore

    finding = _store_finding(database, rules)
    core = SensorCore(config)
    d = Dispatcher(core)

    def ask(message):
        return json.loads(d.handle_bytes(json.dumps(message).encode(), "pid 9, session 1"))

    assert ask({"cmd": "set_triage", "finding": finding, "status": "INVESTIGATING"})["ok"]
    assert ask({"cmd": "add_note", "finding": finding, "body": "  user checked  "})["ok"]
    missing = ask({"cmd": "set_triage", "finding": finding + 99, "status": "BENIGN"})
    assert missing == {"ok": False, "error": f"Detection #{finding + 99} does not exist."}
    assert ask({"cmd": "add_note", "finding": finding, "body": "   "})["ok"] is False
    with database.connect() as conn:
        repo = DetectionRepository(conn)
        assert repo.get(finding).status is TriageStatus.INVESTIGATING
        assert [n.body for n in repo.notes(finding)] == ["user checked"]
        assert [h.to_status for h in repo.history(finding)] == ["NEW", "INVESTIGATING"]


# ------------------------------------------------------------------ console side
class Transport:
    def __init__(self, reply=None, error=None):
        self.reply, self.error, self.sent = reply, error, []

    def __call__(self, data, timeout):
        self.sent.append(json.loads(data))
        if self.error:
            raise self.error
        return json.dumps(self.reply).encode()


def test_console_write_returns_the_sensor_reply():
    t = Transport({"ok": True, "finding": 4, "status": "BENIGN"})
    reply = console_write("set_triage", SensorClient(t), finding=4, status="BENIGN")
    assert reply["status"] == "BENIGN"
    assert t.sent == [{"cmd": "set_triage", "finding": 4, "status": "BENIGN"}]


def test_console_write_errors_are_plain_messages():
    with pytest.raises(MoeSOCError, match="does not exist"):
        console_write(
            "set_triage",
            SensorClient(Transport({"ok": False, "error": "Detection #4 does not exist."})),
            finding=4,
            status="NEW",
        )
    with pytest.raises(MoeSOCError, match="not reachable, so the change was not saved"):
        console_write(
            "add_note",
            SensorClient(Transport(error=SensorUnavailable("gone"))),
            finding=4,
            body="x",
        )
    with pytest.raises(MoeSOCError, match="too large"):
        console_write("add_note", SensorClient(Transport()), finding=4, body="é" * 9000)


def test_read_only_console_routes_triage_and_notes_to_the_sensor(database, rules):
    finding = _store_finding(database, rules)
    sent = []

    def write(cmd, **fields):
        sent.append((cmd, fields))
        return {"ok": True, "status": fields.get("status", "")}

    msg = triage_actions.set_triage(database, finding, "FALSE_POSITIVE", True, write)
    assert "saved by the MoeSOC Sensor" in msg and "False Positive" in msg
    triage_actions.add_note(database, finding, "noise", True, write)
    assert sent == [
        ("set_triage", {"finding": finding, "status": "FALSE_POSITIVE"}),
        ("add_note", {"finding": finding, "body": "noise"}),
    ]
    with database.connect() as conn:  # the console itself wrote nothing
        assert DetectionRepository(conn).get(finding).status is TriageStatus.NEW


def test_writable_console_still_writes_directly(database, rules):
    finding = _store_finding(database, rules)

    def write(*_a, **_k):  # pragma: no cover - must not be used
        raise AssertionError("sent to the sensor")

    triage_actions.set_triage(database, finding, "INVESTIGATING", False, write)
    triage_actions.add_note(database, finding, "direct", False, write)
    with database.connect() as conn:
        assert DetectionRepository(conn).get(finding).status is TriageStatus.INVESTIGATING


def test_read_only_message_names_what_still_needs_an_administrator(database, monkeypatch):
    from moesoc.storage import database as database_module

    real_connect = sqlite3.connect

    def no_write_access(target, *args, **kwargs):
        if not kwargs.get("uri"):
            raise sqlite3.OperationalError("unable to open database file")
        return real_connect(target, *args, **kwargs)

    monkeypatch.setattr(database_module.sqlite3, "connect", no_write_access)
    console = Database(database.path)
    with (
        pytest.raises(StorageError, match="Triage and notes are saved through the sensor"),
        console.connect() as conn,
    ):
        conn.execute("DELETE FROM settings")


# ------------------------------------------------------------------ start-up and health
def test_installed_sensor_means_no_uac_prompt():
    api = FakeApi()
    d = frozen.decide([], api, EXE, ask_elevation=False)
    assert d.action == frozen.RUN and api.calls == ["lock"]


def test_without_a_sensor_the_console_still_asks_for_elevation():
    api = FakeApi()
    assert frozen.decide([], api, EXE, ask_elevation=True).action == frozen.EXIT
    assert api.calls[0].startswith("elevate:")


STATUS = {
    "state": "MONITORING",
    "version": "1.1.0",
    "monitor": {"state": "ON", "message": ""},
    "last_error": None,
    "channels": {
        "Security": "live",
        "Microsoft-Windows-Sysmon/Operational": "not installed",
        "Microsoft-Windows-PowerShell/Operational": "live",
        "Microsoft-Windows-Windows Defender/Operational": "unavailable: Access denied.",
    },
}


def _checks(database, status, admin=False):
    def source():
        if isinstance(status, Exception):
            raise status
        return status

    checks = run_sensor_health_checks(
        database, source, admin, sysmon_probe=lambda: None, powershell_policy=lambda: True
    )
    return {c.name: c for c in checks}


def test_sensor_mode_health_reports_what_the_sensor_collects(database):
    c = _checks(database, STATUS)
    assert c["MoeSOC Sensor"].state is HealthState.AVAILABLE
    assert c["Security Event Log"].state is HealthState.AVAILABLE
    assert c["Sysmon"].state is HealthState.UNAVAILABLE and "Not installed" in c["Sysmon"].message
    assert "Script Block Logging is enabled" in c["PowerShell Logging"].message
    assert c["Microsoft Defender Log"].state is HealthState.LIMITED
    assert "Standard user" in c["Console Account"].message
    assert c["Database"].state is HealthState.AVAILABLE
    assert "Administrator Privileges" not in c  # not needed to read the sensor's data


def test_sensor_mode_health_never_guesses_when_the_sensor_is_unreachable(database):
    c = _checks(database, SensorUnavailable("winerror=2"))
    assert c["MoeSOC Sensor"].state is HealthState.ERROR
    assert all(c[n].state is HealthState.UNAVAILABLE for n in ("Security Event Log", "Sysmon"))


def test_sensor_error_state_is_shown_as_error(database):
    c = _checks(database, {**STATUS, "state": "ERROR", "last_error": "database: locked"})
    assert c["MoeSOC Sensor"].state is HealthState.ERROR
    assert "database: locked" in c["MoeSOC Sensor"].message


def test_windows_write_probe_uses_the_file_rights_not_sqlite(database, monkeypatch):
    """Real Windows: SQLite's BEGIN IMMEDIATE succeeds on a read-only WAL connection, so
    the probe asks for the file's write access (CreateFile) instead."""
    from moesoc.storage import database as database_module

    def denied(*_a, **_k):
        raise PermissionError(5, "Access is denied")

    monkeypatch.setattr(database_module.sys, "platform", "win32")
    monkeypatch.setattr(database_module.os, "open", denied)
    console = Database(database.path)
    with console.connect() as conn:
        conn.execute("SELECT 1").fetchone()
    assert console.read_only


def test_windows_write_probe_keeps_a_writable_console_direct(database, monkeypatch):
    from moesoc.storage import database as database_module

    opened = []
    real_open = database_module.os.open

    def record(path, flags, *a):
        opened.append(flags & os.O_RDWR)
        return real_open(path, flags, *a)

    monkeypatch.setattr(database_module.sys, "platform", "win32")
    monkeypatch.setattr(database_module.os, "open", record)
    console = Database(database.path)
    for _ in range(3):
        with console.connect():
            pass
    assert not console.read_only and opened == [os.O_RDWR]  # probed once
