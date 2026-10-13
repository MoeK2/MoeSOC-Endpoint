"""Sensor + console sharing one SQLite database; read-only console; explicit data import."""

from __future__ import annotations

import sqlite3
import threading
from datetime import timedelta

import pytest

from moesoc.core.exceptions import StorageError
from moesoc.sensor.manage import ManageError, copy_database
from moesoc.storage import database as database_module
from moesoc.storage.database import Database
from moesoc.storage.repository import EventRepository
from moesoc.utils.time import utc_now

from .conftest import auth_event


def test_sensor_writes_while_the_console_reads(database):
    """Two processes' worth of connections: one writer, two readers, WAL + busy timeout."""
    errors: list[Exception] = []
    stop = threading.Event()
    start = utc_now() - timedelta(hours=1)

    def writer():
        try:
            for batch in range(40):
                events = [
                    auth_event(
                        4625, "alice", start + timedelta(seconds=batch * 10 + i), batch * 10 + i
                    )
                    for i in range(10)
                ]
                with Database(database.path).connect() as conn:
                    EventRepository(conn).insert_many(events)
        except Exception as exc:
            errors.append(exc)
        finally:
            stop.set()

    def reader():
        try:
            while not stop.is_set():
                with Database(database.path).connect() as conn:
                    EventRepository(conn).count()
        except Exception as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=writer),
        *(threading.Thread(target=reader) for _ in range(2)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert errors == []
    with database.connect() as conn:
        assert EventRepository(conn).count() == 400
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_console_without_write_access_opens_read_only(database, monkeypatch):
    with database.connect() as conn:
        EventRepository(conn).insert_many([auth_event(4625, "alice", utc_now(), 1)])
    real_connect = sqlite3.connect

    def no_write_access(target, *args, **kwargs):
        if not kwargs.get("uri"):
            raise sqlite3.OperationalError("unable to open database file")
        return real_connect(target, *args, **kwargs)

    monkeypatch.setattr(database_module.sqlite3, "connect", no_write_access)
    console = Database(database.path)
    with console.connect() as conn:
        assert EventRepository(conn).count() == 1
    assert console.read_only
    with pytest.raises(StorageError, match="read-only for your account"), console.connect() as conn:
        conn.execute("DELETE FROM events")


def test_missing_database_is_still_a_clear_error(tmp_path, monkeypatch):
    def fail(*_a, **_k):
        raise sqlite3.OperationalError("unable to open database file")

    monkeypatch.setattr(database_module.sqlite3, "connect", fail)
    with pytest.raises(StorageError, match="Could not open"):
        Database(tmp_path / "none.db").initialize()


def test_import_user_data_copies_verifies_and_keeps_the_original(database, tmp_path):
    with database.connect() as conn:
        EventRepository(conn).insert_many([auth_event(4625, "alice", utc_now(), 1)])
    before = database.path.read_bytes()
    target = tmp_path / "sensor" / "moesoc.db"
    assert copy_database(database.path, target) is None
    with Database(target).connect() as conn:
        assert EventRepository(conn).count() == 1
    assert database.path.read_bytes() == before  # original untouched
    with pytest.raises(ManageError, match="already exists"):
        copy_database(database.path, target)
    backup = copy_database(database.path, target, force=True)
    assert backup is not None and backup.exists() and target.exists()
    with pytest.raises(ManageError, match="No database"):
        copy_database(tmp_path / "missing.db", tmp_path / "x.db")
