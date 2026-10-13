"""SensorCore: the always-on pipeline, independent of how it is hosted.

    start  → open/migrate the database → catch-up scan (incremental, every source)
           → subscribe (Security required; Sysmon, PowerShell, Defender when present)
           → block on Windows' signals ─ new records → ingest_live (store, detect,
             correlate) → notification decision → IPC clients (tray)
    resume from sleep / manual scan → catch up and resubscribe (same path)
    daily  → WAL checkpoint; retention only if the user chose a retention period

It reuses ``ScanService`` and ``LiveMonitor`` unchanged in behaviour: there is one
detection pipeline. The Windows service host (``service.py``) only translates SCM
start/stop/power events into ``run``/``stop``/``on_resume``; tests drive this class
directly with fakes.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from moesoc import __version__
from moesoc.collectors.subscription import MultiSubscription, WindowsSubscriptionSource
from moesoc.core.config import AppConfig
from moesoc.core.enums import CLOSED_STATUSES, TriageStatus
from moesoc.core.exceptions import MoeSOCError
from moesoc.engine.live import LiveMonitor, MonitorState, all_source_subscriptions
from moesoc.engine.rules import load_rules
from moesoc.engine.scanner import LiveBatchResult, ScanService, ScanSummary
from moesoc.parsers.security import SECURITY_CHANNEL
from moesoc.sensor.notifications import (
    NotificationEngine,
    NotificationHub,
    NotificationPrefs,
    load_prefs,
    save_prefs,
)
from moesoc.storage.database import Database
from moesoc.storage.repository import DetectionRepository, to_db_time
from moesoc.storage.retention import SETTING_KEY as RETENTION_KEY
from moesoc.storage.retention import apply_retention, get_retention_days
from moesoc.utils.time import utc_now

log = logging.getLogger(__name__)

MAINTENANCE_INTERVAL = timedelta(hours=24)
MANUAL_SCAN_MIN_INTERVAL = 60.0  # seconds between manual scan requests
DB_RETRY_SECONDS = (2, 5, 15, 30, 60)
STOP_JOIN_SECONDS = 30.0

# Tray states (simple); the console's Health page shows the details.
MONITORING, LIMITED, ATTENTION, STARTING = "MONITORING", "LIMITED", "ATTENTION", "STARTING"
ERROR = "ERROR"  # the sensor runs but cannot monitor (e.g. its database is unavailable)


def open_keeper(path: Any) -> sqlite3.Connection:
    """An idle connection that keeps the database's -wal and -shm files in place (B-7).

    A console without write access to the data folder opens the database with
    ``mode=ro``; SQLite can read a WAL database read-only only while those two files
    exist, because it may not create them. SQLite opens them lazily, on a connection's
    first read, and the last connection to close deletes them. The keeper therefore
    runs one read (the earlier keeper never did, so the files vanished after every
    write) and is fully reset afterwards, so it holds no read transaction and never
    blocks a checkpoint.
    """
    keeper = sqlite3.connect(path, timeout=10)
    cursor = keeper.execute("SELECT count(*) FROM sqlite_master")
    cursor.fetchall()
    cursor.close()
    return keeper


@dataclass
class SensorHealth:
    started_at: datetime = field(default_factory=utc_now)
    monitor_state: str = MonitorState.OFF.value
    monitor_message: str = ""
    channels: dict[str, str] = field(default_factory=dict)
    database: str = "not opened"
    last_event_at: datetime | None = None
    last_catch_up_at: datetime | None = None
    last_detection_at: datetime | None = None
    last_maintenance_at: datetime | None = None
    events_stored: int = 0
    batches: int = 0
    last_batch_records: int = 0
    parse_failures: int = 0
    attention_findings: int = 0
    ipc: str = "not started"
    last_error: str | None = None


class SensorCore:
    def __init__(
        self,
        config: AppConfig,
        *,
        source_factory: Callable[[], Any] | None = None,
        service_factory: Callable[[AppConfig, Database], ScanService] | None = None,
        ipc_factory: Callable[[SensorCore], Any] | None = None,
        clock: Callable[[], float] = time.monotonic,
        maintenance_interval: timedelta = MAINTENANCE_INTERVAL,
        monitor_options: dict[str, Any] | None = None,
    ) -> None:
        self.config = config
        self.instance = uuid.uuid4().hex  # changes per start, so clients resync
        self.hub = NotificationHub()
        self.health = SensorHealth()
        self._lock = threading.Lock()
        self._db = Database(config.database_path)
        self._source_factory = source_factory or (
            lambda: MultiSubscription(WindowsSubscriptionSource)
        )
        self._service_factory = service_factory or (
            lambda cfg, db: ScanService(cfg, db, load_rules(cfg.rules_dir))
        )
        self._ipc_factory = ipc_factory
        self._clock = clock
        self._maintenance_interval = maintenance_interval
        self._monitor_options = monitor_options or {}
        self._engine: NotificationEngine | None = None
        self._monitor: LiveMonitor | None = None
        self._last_manual_scan = -MANUAL_SCAN_MIN_INTERVAL
        self._keeper: sqlite3.Connection | None = None
        self.stopped = threading.Event()

    # ------------------------------------------------------------------ lifecycle
    def run(self, stop: threading.Event) -> None:
        """Run until ``stop`` is set. Never raises for runtime problems; they are logged
        and shown as LIMITED, and the sensor keeps retrying."""
        log.info("MoeSOC Sensor %s starting (data: %s)", __version__, self.config.data_dir)
        ipc = None
        monitor_thread: threading.Thread | None = None
        try:
            # IPC first (audit B-4): if storage or telemetry cannot start, the tray and the
            # status command still get the truthful reason instead of "offline".
            if self._ipc_factory is not None:
                try:
                    ipc = self._ipc_factory(self)
                    ipc.start()
                    self.health.ipc = "listening"
                except Exception as exc:  # IPC is reporting only; monitoring goes on
                    log.error("IPC could not start: %s", exc)
                    self.health.ipc = f"error: {exc.__class__.__name__}"
                    ipc = None
            if not self._open_database(stop):
                return
            rules = load_rules(self.config.rules_dir)
            self._engine = NotificationEngine(rules)
            service = self._service_factory(self.config, self._db)
            self._refresh_attention()
            self._monitor = LiveMonitor(
                service,
                self._source_factory,
                self._on_state,
                self._on_batch,
                subscriptions=all_source_subscriptions,
                on_catch_up=self._on_catch_up,
                **self._monitor_options,
            )
            monitor_thread = threading.Thread(
                target=self._monitor.run, args=(stop,), name="moesoc-monitor", daemon=True
            )
            monitor_thread.start()
            self._maintenance_loop(stop)
        except MoeSOCError as exc:
            log.error("Sensor could not start: %s", exc.user_message)
            self.health.monitor_state = MonitorState.ERROR.value
            self.health.monitor_message = exc.user_message
            self.health.last_error = exc.user_message
            stop.wait()  # stay up (IPC reports the error) until the service is stopped
        finally:
            stop.set()
            self.hub.wake_all()
            if monitor_thread is not None:
                monitor_thread.join(STOP_JOIN_SECONDS)
                if monitor_thread.is_alive():
                    log.warning("Monitor thread did not stop within %.0f s", STOP_JOIN_SECONDS)
            if ipc is not None:
                ipc.stop()
                self.health.ipc = "stopped"
            if self._keeper is not None:
                self._keeper.close()
                self._keeper = None
            log.info("MoeSOC Sensor stopped")
            self.stopped.set()

    def _open_database(self, stop: threading.Event) -> bool:
        attempt = 0
        while not stop.is_set():
            try:
                version = self._db.initialize()
                self._keeper = open_keeper(self.config.database_path)
                self.health.database = f"ok (schema v{version})"
                self.health.last_error = None
                return True
            except Exception as exc:  # any storage failure: report it, keep retrying
                message = getattr(exc, "user_message", None) or f"{exc.__class__.__name__}: {exc}"
                self.health.database = f"error: {message}"
                self.health.last_error = f"database: {message}"
                delay = DB_RETRY_SECONDS[min(attempt, len(DB_RETRY_SECONDS) - 1)]
                log.error("Database not available (%s); retrying in %s s", message, delay)
                attempt += 1
                stop.wait(delay)
        return False

    def _maintenance_loop(self, stop: threading.Event) -> None:
        """Sleeps (no polling of logs or the database); wakes hourly to check the clock."""
        last = utc_now()
        while not stop.wait(3600):
            if utc_now() - last >= self._maintenance_interval:
                self.run_maintenance()
                last = utc_now()

    # ------------------------------------------------------------------ requests
    def request_scan(self) -> tuple[bool, str]:
        """Manual catch-up (tray "Run Scan"). Rate limited; never runs two at once."""
        with self._lock:
            now = self._clock()
            if now - self._last_manual_scan < MANUAL_SCAN_MIN_INTERVAL:
                return False, "A scan was requested less than a minute ago."
            if self._monitor is None:
                return False, "The sensor is still starting."
            self._last_manual_scan = now
        self._monitor.request_restart()
        return True, "Catching up on all sources now."

    def on_resume(self) -> None:
        """Windows woke from sleep: verify subscriptions by catching up and resubscribing."""
        log.info("Resume from sleep: catching up and resubscribing")
        if self._monitor is not None:
            self._monitor.request_restart()

    def run_maintenance(self) -> None:
        """Low-priority daily work. Windows logs are never touched."""
        try:
            with self._db.connect() as conn:
                chosen = conn.execute(
                    "SELECT 1 FROM settings WHERE key = ?", (RETENTION_KEY,)
                ).fetchone()
                if chosen is not None:  # only a retention period the user chose explicitly
                    plan = apply_retention(conn, get_retention_days(conn), confirmed=True)
                    log.info("Retention: %s", plan.describe())
            with self._db.connect() as conn:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                conn.execute("PRAGMA optimize")
            self.health.last_maintenance_at = utc_now()
        except MoeSOCError as exc:
            log.warning("Maintenance skipped: %s", exc.user_message)
        if self._monitor is not None:  # also picks up optional sources started "from now"
            self._monitor.request_restart()

    def get_prefs(self) -> NotificationPrefs:
        with self._db.connect() as conn:
            return load_prefs(conn)

    def set_prefs(self, prefs: NotificationPrefs) -> None:
        with self._db.connect() as conn:
            save_prefs(conn, prefs)

    # Analyst actions of a console that may only read the database (B-7). The sensor
    # stays the only writer for such a console; tuning and retention are NOT offered
    # here: they change what is detected or kept and need an administrator console.
    def set_triage(self, detection_id: int, status: TriageStatus, client: str) -> str:
        with self._db.connect() as conn:
            repo = DetectionRepository(conn)
            before = repo.get(detection_id)
            updated = repo.set_status(detection_id, status)
        log.info(
            "Triage by console (%s): finding #%s %s -> %s",
            client,
            detection_id,
            before.status.value if before else "?",
            updated.status.value,
        )
        return updated.status.value

    def add_note(self, detection_id: int, body: str, client: str) -> int:
        with self._db.connect() as conn:
            note = DetectionRepository(conn).add_note(detection_id, body)
        log.info("Note #%s added by console (%s) to finding #%s", note.id, client, detection_id)
        return note.id

    # ------------------------------------------------------------------ callbacks
    def _on_state(self, state: MonitorState, message: str) -> None:
        self.health.monitor_state = state.value
        self.health.monitor_message = message
        if state in (MonitorState.ERROR, MonitorState.RECONNECTING):
            self.health.last_error = message
        elif state is MonitorState.ON and self.health.database.startswith("ok"):
            self.health.last_error = None
        if self._monitor is not None and state is MonitorState.ON:
            self.health.channels = dict(self._monitor.channel_status)
        log.info("Monitor %s: %s", state.value, message)

    def _on_catch_up(self, summary: ScanSummary) -> None:
        self.health.last_catch_up_at = utc_now()
        self.health.events_stored += summary.events_new
        if summary.events_new:
            self.health.last_event_at = utc_now()
        self._evaluate()

    def _on_batch(self, result: LiveBatchResult) -> None:
        self.health.batches += 1
        self.health.last_batch_records = result.records
        self.health.events_stored += result.events_new
        self.health.parse_failures += result.parse_failures
        if result.records:
            self.health.last_event_at = utc_now()
        if result.detections_found:
            self.health.last_detection_at = utc_now()
            self._evaluate()

    def _evaluate(self) -> None:
        if self._engine is None:
            return
        try:
            with self._db.connect() as conn:
                notes = self._engine.evaluate(conn)
        except MoeSOCError as exc:
            log.warning("Notification check skipped: %s", exc.user_message)
            return
        if notes:
            log.info("Notifications: %s", ", ".join(f"#{n.detection_id} {n.reason}" for n in notes))
        self.hub.publish(notes)
        self._refresh_attention()

    def _refresh_attention(self) -> None:
        try:
            with self._db.connect() as conn:
                rows = conn.execute(
                    "SELECT status, COUNT(*) FROM detections "
                    "WHERE severity IN ('HIGH', 'CRITICAL') GROUP BY status"
                ).fetchall()
            self.health.attention_findings = sum(
                n for status, n in rows if status not in CLOSED_STATUSES
            )
        except MoeSOCError:
            pass

    # ------------------------------------------------------------------ status
    def tray_state(self) -> str:
        h = self.health
        if h.database.startswith("error") or h.monitor_state == MonitorState.ERROR.value:
            return ERROR
        if h.monitor_state in (MonitorState.STARTING.value, MonitorState.OFF.value):
            return STARTING
        if (
            h.monitor_state != MonitorState.ON.value
            or h.channels.get(SECURITY_CHANNEL) != "live"
            or not h.database.startswith("ok")
        ):
            return LIMITED
        return ATTENTION if h.attention_findings else MONITORING

    def status(self) -> dict[str, object]:
        h = self.health

        def when(value: datetime | None) -> str | None:
            return to_db_time(value) if value else None

        last = self.hub.last_important
        return {
            "version": __version__,
            "instance": self.instance,
            "seq": self.hub.seq,
            "state": self.tray_state(),
            "monitor": {"state": h.monitor_state, "message": h.monitor_message},
            "channels": dict(h.channels),
            "database": h.database,
            "started_at": when(h.started_at),
            "last_event_at": when(h.last_event_at),
            "last_catch_up_at": when(h.last_catch_up_at),
            "last_detection_at": when(h.last_detection_at),
            "last_maintenance_at": when(h.last_maintenance_at),
            "events_stored": h.events_stored,
            "batches": h.batches,
            # Pull model: records wait in Windows' own log, not in a MoeSOC queue; this
            # is the size of the last batch read (bounded by MAX_DRAIN_RECORDS/MAX_BATCH).
            "queue_depth": h.last_batch_records,
            "parse_failures": h.parse_failures,
            "attention_findings": h.attention_findings,
            "ipc": h.ipc,
            "degraded": self.tray_state() in (ERROR, LIMITED),
            "monitoring": h.monitor_state == MonitorState.ON.value,
            "last_error": h.last_error,
            "last_finding": last.to_dict() if last else None,
        }
