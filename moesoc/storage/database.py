"""SQLite connection management and migrations."""

from __future__ import annotations

import logging
import os
import sqlite3
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from moesoc.core.exceptions import StorageError
from moesoc.storage.schema import MIGRATIONS, SCHEMA_VERSION

log = logging.getLogger(__name__)


class Database:
    """Opens short-lived connections. Each thread uses its own connection."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.read_only = False  # set when only a read-only connection was possible
        self._writable: bool | None = None  # probed once (B-7)

    def _open(self) -> sqlite3.Connection:
        conn: sqlite3.Connection | None = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(self.path, timeout=10)
            conn.execute("PRAGMA journal_mode = WAL")  # GUI reads while a scan writes
            conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
            if self._writable is None:
                self._probe_writable()
        except (OSError, sqlite3.Error) as exc:
            if conn is not None:
                conn.close()
            fallback = self._open_read_only()
            if fallback is None:
                log.error("Could not open database at %s: %s", self.path, exc)
                raise StorageError(
                    f"Could not open the local database at {self.path}. "
                    "Check that the folder is writable."
                ) from exc
            conn = fallback
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 10000")
        return conn

    def _probe_writable(self) -> None:
        """SQLite silently opens a file it may not write read-only (on Windows when the
        account lacks write access, e.g. a normal user and the sensor's database). Find
        out once, so the console can send its analyst actions to the sensor instead (B-7).

        The file's access rights are asked directly: on real Windows a write probe in
        SQLite (``BEGIN IMMEDIATE``) succeeds even on a read-only connection in WAL mode,
        because the write lock lives in the -shm file. ``os.open(O_RDWR)`` is an
        ordinary CreateFile with read and write sharing; it never changes the file.
        Elsewhere ``os.access`` is used: closing a second descriptor would drop SQLite's
        POSIX locks."""
        if sys.platform == "win32":
            try:
                os.close(os.open(self.path, os.O_RDWR | getattr(os, "O_BINARY", 0)))
                writable = True
            except PermissionError:
                writable = False
            except OSError:
                return  # e.g. a sharing conflict: unknown for now, asked again next time
        else:
            writable = os.access(self.path, os.W_OK)
        self._writable = writable
        if not writable:
            self.read_only = True
            log.info("Opened %s read-only (this account may not write it)", self.path)

    def _open_read_only(self) -> sqlite3.Connection | None:
        """The sensor's database for an account that may only read it (console without
        administrator rights). While the sensor runs, its keeper connection holds the WAL
        files open (B-7), so ``mode=ro`` sees current data and stays consistent while the
        sensor writes. Only when no -wal file exists (sensor stopped, WAL checkpointed
        away) is the file complete on its own and opened as immutable."""
        if not self.path.is_file():
            return None
        uri = self.path.resolve().as_uri()
        candidates = [f"{uri}?mode=ro"]
        if not Path(f"{self.path}-wal").exists():
            candidates.append(f"{uri}?mode=ro&immutable=1")
        for candidate in candidates:
            try:
                conn = sqlite3.connect(candidate, uri=True, timeout=10)
                conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
            except sqlite3.Error:
                continue
            log.info("Opened %s read-only", self.path)
            self.read_only = True
            return conn
        return None

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """Yield a connection; commit on success, roll back on error, always close."""
        conn = self._open()
        try:
            yield conn
            conn.commit()
        except sqlite3.Error as exc:
            conn.rollback()
            log.error("Database operation failed: %s", exc)
            if "readonly" in str(exc).replace(" ", "").lower():
                raise StorageError(
                    "This database belongs to the MoeSOC Sensor and is read-only for your "
                    "account. Triage and notes are saved through the sensor; suppressions, "
                    "rule changes and retention need MoeSOC opened as administrator."
                ) from exc
            raise StorageError(
                "A local database operation failed. See the diagnostic log."
            ) from exc
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize(self) -> int:
        """Apply pending migrations. Returns the resulting schema version."""
        with self.connect() as conn:
            current = conn.execute("PRAGMA user_version").fetchone()[0]
            if current > SCHEMA_VERSION:
                raise StorageError(
                    "The database was created by a newer version of MoeSOC. "
                    "It was left untouched; please update MoeSOC."
                )
            for index in range(current, SCHEMA_VERSION):
                log.info("Applying database migration %s", index + 1)
                migration = MIGRATIONS[index]
                if isinstance(migration, str):
                    conn.executescript(
                        "BEGIN;" + migration + f"PRAGMA user_version = {index + 1};COMMIT;"
                    )
                    continue
                # Python migrations run in one explicit transaction: all or nothing.
                conn.commit()
                conn.execute("BEGIN")
                try:
                    migration(conn)
                    conn.execute(f"PRAGMA user_version = {index + 1}")
                    conn.commit()
                except BaseException:
                    conn.rollback()
                    raise
            return SCHEMA_VERSION
