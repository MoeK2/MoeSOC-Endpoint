"""SensorCore end to end against fake Windows logs: start, catch up, subscribe, detect,
notify once, stop cleanly, survive bad input and failures, resume from sleep."""

from __future__ import annotations

import threading
import time
from datetime import timedelta
from typing import ClassVar

import pytest

from moesoc.collectors import subscription as subscription_module
from moesoc.collectors.subscription import (
    MultiSubscription,
    SubscriptionSpec,
    WindowsSubscriptionSource,
)
from moesoc.core.exceptions import ChannelNotFoundError, CollectorError, StorageError
from moesoc.engine.scanner import ScanService
from moesoc.sensor import core as core_module
from moesoc.sensor.core import ATTENTION, LIMITED, MONITORING, SensorCore
from moesoc.storage.repository import EventRepository
from moesoc.utils.time import utc_now

from .test_incremental_collection import FakeEventLog
from .test_subscription_source import FakeWindows

FAST = {"wait_seconds": 0.02, "quiet_seconds": 0.02, "first_backoff": 0.05, "max_backoff": 0.1}


class ChannelSource(WindowsSubscriptionSource):
    """Only the Security channel exists (like a PC without Sysmon); optional failures."""

    failures: ClassVar[list[Exception]] = []

    def open(self, channel, xpath, after_record):
        if channel != "Security":
            raise ChannelNotFoundError(f"The event log channel '{channel}' does not exist.")
        if ChannelSource.failures:
            raise ChannelSource.failures.pop(0)
        super().open(channel, xpath, after_record)


def wait_any(signals, timeout_ms):
    for index, signal in enumerate(signals):
        if signal.is_set:
            signal.is_set = False
            return index
    time.sleep(min(timeout_ms, 20) / 1000)
    return None


@pytest.fixture
def windows():
    ChannelSource.failures = []
    return FakeWindows(FakeEventLog())


def make_core(config, rules, windows) -> SensorCore:
    return SensorCore(
        config,
        source_factory=lambda: MultiSubscription(
            lambda: ChannelSource(modules=windows.modules()), wait_any
        ),
        service_factory=lambda cfg, db: ScanService(
            cfg,
            db,
            rules,
            reader_factory=lambda: windows.log,
            host_aliases=list,
            standalone_hosts=list,
        ),
        monitor_options=FAST,
    )


def until(predicate, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


class Running:
    def __init__(self, core: SensorCore) -> None:
        self.core = core
        self.stop = threading.Event()
        self.thread = threading.Thread(target=core.run, args=(self.stop,), daemon=True)

    def __enter__(self) -> SensorCore:
        self.thread.start()
        assert until(lambda: self.core.health.monitor_state == "ON"), self.core.health
        return self.core

    def __exit__(self, *exc) -> None:
        self.stop.set()
        self.thread.join(10)
        assert not self.thread.is_alive() and self.core.stopped.is_set()


def brute_force_then_success(windows, user="alice", start=None):
    start = start or utc_now() - timedelta(minutes=5)
    for i in range(6):
        windows.write(event_id=4625, user=user, at=start + timedelta(seconds=i))
    windows.write(event_id=4624, user=user, at=start + timedelta(seconds=10))


def test_start_catches_up_subscribes_and_reports_monitoring(config, rules, windows):
    windows.write()  # written while the sensor was off
    core = make_core(config, rules, windows)
    with Running(core):
        assert core.health.last_catch_up_at is not None
        assert core.health.channels["Security"] == "live"
        assert core.health.channels["Microsoft-Windows-Sysmon/Operational"] == "not installed"
        assert core.tray_state() == MONITORING  # a missing optional source is not LIMITED
        status = core.status()
        assert status["database"].startswith("ok") and status["queue_depth"] == 0
    with core._db.connect() as conn:
        assert EventRepository(conn).count() == 1


def test_live_events_become_one_notification(config, rules, windows):
    core = make_core(config, rules, windows)
    with Running(core):
        brute_force_then_success(windows)
        assert until(lambda: core.hub.seq >= 1)
        time.sleep(0.2)  # a growing finding must not notify again
        items = core.hub.wait_after(0, 0)
        assert [n.rule_id for n in items] == ["COR-001"]  # DET-001 is MEDIUM: no toast
        assert core.status()["last_finding"]["rule_id"] == "COR-001"
        assert until(lambda: core.tray_state() == ATTENTION)
        windows.write(event_id=4625, user="alice")  # the campaign continues
        time.sleep(0.3)
        assert core.hub.seq == 1


def test_findings_present_before_the_first_start_do_not_notify(config, rules, windows):
    brute_force_then_success(windows)
    core = make_core(config, rules, windows)
    with Running(core):
        time.sleep(0.2)
        assert core.hub.seq == 0


def test_restart_does_not_repeat_notifications_or_events(config, rules, windows):
    core = make_core(config, rules, windows)
    with Running(core):
        brute_force_then_success(windows)
        assert until(lambda: core.hub.seq == 1)
    again = make_core(config, rules, windows)
    with Running(again):
        time.sleep(0.2)
        assert again.hub.seq == 0
    with again._db.connect() as conn:
        assert EventRepository(conn).count() == 7


def test_malformed_record_is_counted_and_monitoring_continues(config, rules, windows):
    core = make_core(config, rules, windows)
    with Running(core):
        bad = windows.write()
        windows.render_failures.add(bad)  # Windows cannot render it
        record = windows.log.next_record
        windows.log.records.append((record, 4625, utc_now(), "<Event><broken"))
        windows.log.next_record += 1
        for sub in windows.subscriptions:
            sub.signal.is_set = True
        good = windows.write()
        assert until(lambda: core.health.parse_failures >= 1)
        with core._db.connect() as conn:
            assert until(lambda: EventRepository(conn).count() >= 1)
        assert good and core.health.monitor_state == "ON"


def test_security_subscription_failure_is_limited_then_recovers(config, rules, windows):
    ChannelSource.failures = [CollectorError("The event log service is restarting.")]
    core = make_core(config, rules, windows)
    stop = threading.Event()
    states: list[str] = []
    original = core._on_state
    core._on_state = lambda s, m: (states.append(s.value), original(s, m))  # type: ignore[method-assign]
    thread = threading.Thread(target=core.run, args=(stop,), daemon=True)
    thread.start()
    assert until(lambda: core.health.monitor_state == "ON")
    assert "RECONNECTING" in states
    stop.set()
    thread.join(10)
    assert core.stopped.is_set()


def test_tray_state_is_limited_without_a_live_security_log(config, rules, windows):
    core = make_core(config, rules, windows)
    core.health.monitor_state = "ON"
    core.health.channels = {"Security": "unavailable: access denied"}
    core.health.database = "ok"
    assert core.tray_state() == LIMITED


def test_database_problem_at_start_is_retried(config, rules, windows, monkeypatch):
    monkeypatch.setattr(core_module, "DB_RETRY_SECONDS", (0.01,))
    core = make_core(config, rules, windows)
    calls = {"n": 0}
    real = core._db.initialize

    def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise StorageError("database is locked")
        return real()

    core._db.initialize = flaky  # type: ignore[method-assign]
    with Running(core):
        assert calls["n"] == 3 and core.health.database.startswith("ok")


def test_resume_and_manual_scan_catch_up_again(config, rules, windows):
    core = make_core(config, rules, windows)
    with Running(core):
        first = core.health.last_catch_up_at
        core.on_resume()  # sleep/resume
        assert until(lambda: core.health.last_catch_up_at != first)
        assert until(lambda: core.health.monitor_state == "ON")
        second = core.health.last_catch_up_at
        assert core.request_scan()[0] is True
        assert core.request_scan()[0] is False  # rate limited
        assert until(lambda: core.health.last_catch_up_at != second)
        assert until(lambda: core.health.monitor_state == "ON")
        written = windows.write()  # still subscribed after the resubscribe
        with core._db.connect() as conn:
            assert until(lambda: EventRepository(conn).count() >= 1), written


def test_stop_while_waiting_is_quick(config, rules, windows):
    core = make_core(config, rules, windows)
    running = Running(core)
    with running:
        pass
    started = time.monotonic()
    assert core.stopped.wait(1) and time.monotonic() - started < 1


def test_maintenance_checkpoints_and_skips_retention_by_default(config, rules, windows):
    windows.write(at=utc_now() - timedelta(days=60))
    core = make_core(config, rules, windows)
    with Running(core):
        core.run_maintenance()
        assert core.health.last_maintenance_at is not None
    with core._db.connect() as conn:
        assert EventRepository(conn).count() == 1  # no retention period was chosen


# ------------------------------------------------------------------ multi-channel source
class FakeSource:
    def __init__(self, name, records=(), fail=None):
        self.name, self.records, self.fail = name, list(records), fail
        self.signal = type("S", (), {"is_set": False})()
        self.pending = False
        self.closed = False

    def open(self, channel, xpath, after):
        if self.fail:
            raise self.fail
        self.pending = bool(self.records)

    @property
    def has_pending(self):
        return self.pending

    def drain(self):
        self.pending = False
        out, self.records = self.records, []
        return out

    def close(self):
        self.closed = True


def test_multi_subscription_skips_missing_optional_channels():
    sources = iter([FakeSource("sec", ["a"]), FakeSource("sys", fail=ChannelNotFoundError("x"))])
    multi = MultiSubscription(lambda: next(sources), wait_any)
    status = multi.open_all(
        [SubscriptionSpec("Security", "*", None, True), SubscriptionSpec("Sysmon", "*", None)]
    )
    assert status == {"Security": "live", "Sysmon": "not installed"}
    assert multi.wait(0.01) == ["a"]  # backlog first, no waiting
    assert multi.wait(0.01) == []


def test_multi_subscription_required_channel_failure_raises_and_closes():
    opened = FakeSource("ok")
    sources = iter([opened, FakeSource("sec", fail=CollectorError("denied"))])
    multi = MultiSubscription(lambda: next(sources), wait_any)
    with pytest.raises(CollectorError):
        multi.open_all(
            [SubscriptionSpec("Sysmon", "*", None), SubscriptionSpec("Security", "*", None, True)]
        )
    assert opened.closed


def test_multi_subscription_reads_the_channel_that_signalled():
    first, second = FakeSource("a"), FakeSource("b")
    sources = iter([first, second])
    multi = MultiSubscription(lambda: next(sources), wait_any)
    multi.open_all([SubscriptionSpec("A", "*", None), SubscriptionSpec("B", "*", None)])
    second.records = ["x", "y"]
    second.signal.is_set = True
    assert multi.wait(0.01) == ["x", "y"]


def test_drain_is_bounded_and_the_rest_follows_without_a_signal(windows, monkeypatch):
    monkeypatch.setattr(subscription_module, "MAX_DRAIN_RECORDS", 2)
    monkeypatch.setattr(subscription_module, "DRAIN_BATCH", 1)
    first = windows.write()
    for _ in range(5):
        windows.write()
    source = WindowsSubscriptionSource(modules=windows.modules())
    source.open("Security", "*[System[(EventID=4625)]]", first)
    sizes = [len(source.wait(0.01)) for _ in range(4)]
    assert sizes == [2, 2, 1, 0]  # bounded batches, nothing lost, no signal needed


# ------------------------------------------------------------------ B-4: degraded health
class FakeIpc:
    def __init__(self, core):
        self.core = core
        self.started = threading.Event()
        self.stopped = False
        self.seen_states: list[str] = []

    def start(self):
        self.started.set()

    def stop(self):
        self.stopped = True


def degraded_core(config, rules, windows, monkeypatch):
    monkeypatch.setattr(core_module, "DB_RETRY_SECONDS", (0.05,))
    holder = {}

    def ipc_factory(core):
        holder["ipc"] = FakeIpc(core)
        return holder["ipc"]

    core = make_core(config, rules, windows)
    core._ipc_factory = ipc_factory
    return core, holder


@pytest.mark.parametrize(
    "failure",
    [
        StorageError("Access is denied: the sensor database cannot be opened."),
        RuntimeError("unexpected storage initialization failure"),
    ],
)
def test_ipc_reports_a_database_failure_and_the_sensor_recovers(
    config, rules, windows, monkeypatch, failure
):
    core, holder = degraded_core(config, rules, windows, monkeypatch)
    broken = {"on": True}
    real = core._db.initialize

    def initialize():
        if broken["on"]:
            raise failure
        return real()

    core._db.initialize = initialize  # type: ignore[method-assign]
    stop = threading.Event()
    thread = threading.Thread(target=core.run, args=(stop,), daemon=True)
    thread.start()
    try:
        assert until(lambda: "ipc" in holder and holder["ipc"].started.is_set())
        assert until(lambda: core.health.database.startswith("error"))
        status = core.status()
        assert status["state"] == "ERROR" and status["degraded"] is True
        assert status["monitoring"] is False and "database" in status["last_error"]
        assert status["ipc"] == "listening"  # reachable while storage is down
        broken["on"] = False  # the database is repaired: the existing retry recovers
        assert until(lambda: core.health.monitor_state == "ON")
        assert core.status()["state"] == MONITORING and core.status()["last_error"] is None
    finally:
        stop.set()
        thread.join(10)
    assert holder["ipc"].stopped


@pytest.mark.parametrize("problem", ["corrupt", "too_new"])
def test_real_unusable_database_files_are_reported_not_fatal(
    config, rules, windows, monkeypatch, problem
):
    import sqlite3 as _sqlite

    config.data_dir.mkdir(parents=True, exist_ok=True)
    if problem == "corrupt":
        config.database_path.write_bytes(b"this is not a SQLite database" * 100)
    else:
        raw = _sqlite.connect(config.database_path)
        raw.execute("PRAGMA user_version = 99")
        raw.commit()
        raw.close()
    core, holder = degraded_core(config, rules, windows, monkeypatch)
    stop = threading.Event()
    thread = threading.Thread(target=core.run, args=(stop,), daemon=True)
    thread.start()
    try:
        assert until(lambda: core.health.database.startswith("error"))
        assert core.tray_state() == "ERROR" and holder["ipc"].started.is_set()
        if problem == "too_new":
            assert "newer version" in core.status()["last_error"]
    finally:
        stop.set()
        thread.join(10)
    assert core.stopped.is_set()
