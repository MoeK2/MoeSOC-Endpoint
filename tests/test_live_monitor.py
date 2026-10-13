"""Live monitoring: catch-up, subscription, batches, no duplicate alerts, reconnection."""

from __future__ import annotations

import threading
from datetime import timedelta

from moesoc.collectors.subscription import bookmark_xml
from moesoc.core.exceptions import CollectorError, LogAccessDeniedError
from moesoc.engine.live import LiveMonitor, MonitorState, subscription_xpath
from moesoc.engine.scanner import ScanService
from moesoc.parsers.security import SUPPORTED_EVENT_IDS
from moesoc.storage.collection_state import CollectionStateRepository
from moesoc.storage.repository import DetectionRepository, EventRepository
from moesoc.utils.time import utc_now

from .conftest import auth_xml, fixture_text
from .test_incremental_collection import FakeEventLog

STOP = object()


class FakeSource:
    """Scripted subscription: each wait() returns the next batch, raises, or stops."""

    def __init__(self, script: list, stop: threading.Event, opened: list) -> None:
        self.script = script
        self.stop = stop
        self.opened = opened
        self.closed = False

    def open(self, channel, xpath, after_record):
        self.opened.append((channel, xpath, after_record))

    def wait(self, timeout_seconds):
        if not self.script:
            self.stop.set()
            return []
        step = self.script.pop(0)
        if step is STOP:
            self.stop.set()
            return []
        if isinstance(step, BaseException):
            raise step
        if callable(step):
            return step()
        return list(step)

    def close(self):
        self.closed = True


class Harness:
    def __init__(self, config, database, rules, log: FakeEventLog, scripts: list[list]):
        self.stop = threading.Event()
        self.opened: list = []
        self.states: list[tuple[MonitorState, str]] = []
        self.batches = []
        self.sources: list[FakeSource] = []
        self.service = ScanService(
            config, database, rules, reader_factory=lambda: log, host_aliases=list
        )
        self._scripts = scripts

        def factory():
            source = FakeSource(self._scripts.pop(0), self.stop, self.opened)
            self.sources.append(source)
            return source

        self.monitor = LiveMonitor(
            self.service,
            factory,
            lambda state, text: self.states.append((state, text)),
            self.batches.append,
            wait_seconds=0.01,
            quiet_seconds=0.01,
            first_backoff=0.01,
            max_backoff=0.02,
        )

    def run(self):
        self.monitor.run(self.stop)
        return [s for s, _ in self.states]


def failure_xml(record: int, minutes_ago: float = 1.0, user: str = "alice") -> str:
    return auth_xml(4625, user, utc_now() - timedelta(minutes=minutes_ago), record)


# ------------------------------------------------------------------ basics
def test_subscription_covers_every_supported_event():
    xpath = subscription_xpath()
    assert all(f"EventID={i}" in xpath for i in SUPPORTED_EVENT_IDS)


def test_bookmark_matches_what_windows_renders():
    assert bookmark_xml("Security", 42) == (
        "<BookmarkList><Bookmark Channel='Security' RecordId='42' IsCurrent='true'/></BookmarkList>"
    )


def test_catches_up_then_subscribes_after_the_saved_position(config, database, rules):
    log = FakeEventLog()
    log.write()
    log.write()
    h = Harness(config, database, rules, log, [[STOP]])
    states = h.run()
    assert states == [MonitorState.STARTING, MonitorState.ON, MonitorState.OFF]
    assert h.opened == [("Security", subscription_xpath(), 1001)]
    assert h.sources[0].closed


def test_empty_database_and_log_subscribes_to_future_events(config, database, rules):
    h = Harness(config, database, rules, FakeEventLog(), [[STOP]])
    h.run()
    assert h.opened[0][2] is None
    assert "from new events" in h.states[1][1]


# ------------------------------------------------------------------ batches
def test_live_batches_raise_one_finding_and_update_it(config, database, rules):
    log = FakeEventLog()
    log.write(event_id=4624)  # 1000
    first = [failure_xml(1001 + i, minutes_ago=2 - i * 0.1) for i in range(5)]
    second = [failure_xml(1006 + i, minutes_ago=1.4 - i * 0.1) for i in range(3)]
    h = Harness(config, database, rules, log, [[first, [], second, [], STOP]])
    h.run()
    assert [b.detections_new for b in h.batches] == [1, 0]  # no duplicate alert
    assert [b.events_new for b in h.batches] == [5, 3]
    with database.connect() as conn:
        (finding,) = DetectionRepository(conn).list_all()
        assert finding.rule_id == "DET-001" and finding.occurrence_count == 8
        assert CollectionStateRepository(conn).load("Security")["core"].record_id == 1008


def test_records_arriving_close_together_form_one_batch(config, database, rules):
    log = FakeEventLog()
    parts = [[failure_xml(2000 + i)] for i in range(4)]
    h = Harness(config, database, rules, log, [[*parts, [], STOP]])
    h.run()
    assert len(h.batches) == 1 and h.batches[0].records == 4


def test_duplicates_and_malformed_records_are_isolated(config, database, rules):
    log = FakeEventLog()
    log.write()  # 1000, collected by the catch-up scan
    batch = [log.records[0][3], failure_xml(1001), fixture_text("malformed_truncated.xml")]
    h = Harness(config, database, rules, log, [[batch, [], STOP]])
    h.run()
    (result,) = h.batches
    assert result.events_new == 1 and result.parse_failures == 1
    with database.connect() as conn:
        assert EventRepository(conn).count() == 2


def test_position_never_moves_backwards(config, database, rules):
    log = FakeEventLog()
    for _ in range(3):
        log.write()  # 1000-1002
    stale = [log.records[0][3]]  # an old record re-delivered
    h = Harness(config, database, rules, log, [[stale, [], STOP]])
    h.run()
    with database.connect() as conn:
        assert CollectionStateRepository(conn).load("Security")["core"].record_id == 1002


# ------------------------------------------------------------------ failures
def test_transient_failure_reconnects_and_catches_up(config, database, rules):
    log = FakeEventLog()
    log.write()  # 1000

    def outage():
        log.write()  # 1001 is written while the subscription is broken
        raise CollectorError("The event log service restarted.")

    h = Harness(config, database, rules, log, [[outage], [STOP]])
    states = h.run()
    assert states == [
        MonitorState.STARTING,
        MonitorState.ON,
        MonitorState.RECONNECTING,  # the failure, with the retry delay
        MonitorState.RECONNECTING,  # catching up again
        MonitorState.ON,
        MonitorState.OFF,
    ]
    assert "Retrying in" in h.states[2][1]
    assert [o[2] for o in h.opened] == [1000, 1001]  # resubscribed after the catch-up
    with database.connect() as conn:
        assert EventRepository(conn).count() == 2  # nothing written meanwhile was lost


def test_access_denied_is_permanent(config, database, rules):
    class DeniedLog(FakeEventLog):
        def query(self, channel, xpath, *, newest_first=False):
            raise LogAccessDeniedError("Access denied. Run MoeSOC with administrator privileges.")

    h = Harness(config, database, rules, DeniedLog(), [])
    states = h.run()
    assert states == [MonitorState.STARTING, MonitorState.ERROR]
    assert "administrator" in h.states[-1][1]
    assert h.opened == []


def test_unexpected_errors_never_kill_the_monitor(config, database, rules):
    log = FakeEventLog()
    h = Harness(config, database, rules, log, [[RuntimeError("bug")], [STOP]])
    states = h.run()
    assert MonitorState.RECONNECTING in states and states[-1] is MonitorState.OFF
    assert "Unexpected error" in next(t for s, t in h.states if s is MonitorState.RECONNECTING)


def test_stop_while_idle_turns_off(config, database, rules):
    h = Harness(config, database, rules, FakeEventLog(), [[[], [], STOP]])
    assert h.run()[-1] is MonitorState.OFF
    assert h.batches == []
