"""A-4: the live subscription itself, against a fake of the pywin32 calls it makes.

The fake follows the EvtSubscribe pull model conservatively: records that exist after the
bookmark are available to EvtNext immediately, but the signal is set ONLY when a new
matching record is written after the subscription was created. The old code waited for
the signal before its first EvtNext, so a record written between the catch-up scan and
the subscription (or any backlog) was not delivered until some later record arrived.
"""

from __future__ import annotations

import re
import threading

import pytest

from moesoc.collectors.subscription import WindowsSubscriptionSource
from moesoc.core.exceptions import CollectorError
from moesoc.engine.live import LiveMonitor, MonitorState, subscription_xpath
from moesoc.engine.scanner import ScanService
from moesoc.storage.repository import EventRepository

from .test_incremental_collection import FakeEventLog

ERROR_NO_MORE_ITEMS = 259
WAIT_OBJECT_0, WAIT_TIMEOUT = 0, 258


class WinError(Exception):
    def __init__(self, winerror: int) -> None:
        super().__init__(winerror)
        self.winerror = winerror


class Signal:
    def __init__(self) -> None:
        self.is_set = False


class Subscription:
    def __init__(self, log: FakeWindows, after: int | None, signal: Signal, ids: set[int]):
        self.log, self.signal, self.ids = log, signal, ids
        self.cursor = after if after is not None else max([0, *log.record_ids()])
        self.closed = False

    def matches(self, record: int) -> bool:
        return record > self.cursor and self.log.event_id(record) in self.ids

    def Close(self) -> None:
        self.closed = True


class FakeWindows:
    """win32evtlog + win32event + win32api, backed by a FakeEventLog."""

    EvtRenderEventXml = 1

    def __init__(self, log: FakeEventLog) -> None:
        self.log = log
        self.subscriptions: list[Subscription] = []
        self.render_failures: set[int] = set()
        self.closed_handles = 0

    # helpers
    def record_ids(self) -> list[int]:
        return [r[0] for r in self.log.records]

    def event_id(self, record: int) -> int:
        return next(e for r, e, _, _ in self.log.records if r == record)

    def write(self, **kw) -> int:
        record = self.log.write(**kw)
        for sub in self.subscriptions:
            if not sub.closed and sub.matches(record):
                sub.signal.is_set = True  # Windows signals NEW matching records
        return record

    # win32evtlog
    def EvtCreateBookmark(self, xml: str) -> int:
        return int(re.search(r"RecordId='(\d+)'", xml).group(1))

    def EvtSubscribe(self, channel, flags, SignalEvent, Query, Bookmark):
        existing = self.record_ids()
        if Bookmark is not None and existing and Bookmark < min(existing):
            raise WinError(15009)  # strict: the bookmark position no longer exists
        ids = {int(i) for i in re.findall(r"EventID=(\d+)", Query)}
        sub = Subscription(self, Bookmark, SignalEvent, ids)
        self.subscriptions.append(sub)
        return sub

    def EvtNext(self, sub: Subscription, count, timeout, flags):
        pending = sorted(r for r in self.record_ids() if sub.matches(r))[:count]
        if not pending:
            raise WinError(ERROR_NO_MORE_ITEMS)
        sub.cursor = pending[-1]
        return pending

    def EvtRender(self, record: int, flags):
        if record in self.render_failures:
            raise WinError(15005)
        return next(x for r, _, _, x in self.log.records if r == record)

    # win32event / win32api
    def CreateEvent(self, sa, manual_reset, initial, name):
        assert manual_reset is False and initial is False
        return Signal()

    def WaitForSingleObject(self, signal: Signal, ms: int) -> int:
        if signal.is_set:
            signal.is_set = False  # auto-reset
            return WAIT_OBJECT_0
        return WAIT_TIMEOUT

    def CloseHandle(self, signal) -> None:
        self.closed_handles += 1

    def modules(self):
        return (self, self, self, WinError)


@pytest.fixture
def windows():
    return FakeWindows(FakeEventLog())


def source(windows) -> WindowsSubscriptionSource:
    return WindowsSubscriptionSource(modules=windows.modules())


def records(xml_list: list[str]) -> list[int]:
    return [int(re.search(r"<EventRecordID>(\d+)<", x).group(1)) for x in xml_list]


# ------------------------------------------------------------------ the source
def test_backlog_after_the_bookmark_is_delivered_without_a_signal(windows):
    first = windows.write()
    between = windows.write()  # written after the catch-up scan, before open()
    src = source(windows)
    src.open("Security", subscription_xpath(), first)
    assert records(src.wait(1.0)) == [between]
    assert src.wait(1.0) == []  # nothing new: times out quietly


def test_no_records_and_no_signal_returns_nothing(windows):
    last = windows.write()
    src = source(windows)
    src.open("Security", subscription_xpath(), last)
    assert src.wait(1.0) == [] and src.wait(1.0) == []


def test_new_record_is_delivered_when_signalled(windows):
    last = windows.write()
    src = source(windows)
    src.open("Security", subscription_xpath(), last)
    assert src.wait(1.0) == []
    new = windows.write()
    assert records(src.wait(1.0)) == [new]


def test_several_records_behind_one_signal_arrive_together(windows):
    last = windows.write()
    src = source(windows)
    src.open("Security", subscription_xpath(), last)
    src.wait(1.0)
    burst = [windows.write() for _ in range(250)]  # more than one EvtNext batch
    assert records(src.wait(1.0)) == burst


def test_records_written_during_a_drain_come_with_the_next_wait(windows):
    last = windows.write()
    src = source(windows)
    src.open("Security", subscription_xpath(), last)
    src.wait(1.0)
    first = windows.write()
    windows.subscriptions[0].signal.is_set = True
    assert records(src.wait(1.0)) == [first]
    second = windows.write()
    assert records(src.wait(1.0)) == [second]


def test_only_subscribed_event_ids_are_delivered(windows):
    last = windows.write()
    src = source(windows)
    src.open("Security", "*[System[(EventID=4625)]]", last)
    windows.write(event_id=4624)
    wanted = windows.write(event_id=4625)
    assert records(src.wait(1.0)) == [wanted]


def test_future_only_subscription_skips_existing_records(windows):
    windows.write()
    src = source(windows)
    src.open("Security", subscription_xpath(), None)
    assert src.wait(1.0) == []
    new = windows.write()
    assert records(src.wait(1.0)) == [new]


def test_restart_resumes_after_the_last_record_without_repeats(windows):
    start = windows.write()
    src = source(windows)
    src.open("Security", subscription_xpath(), start)
    one = windows.write()
    assert records(src.wait(1.0)) == [one]
    src.close()
    assert windows.subscriptions[0].closed and windows.closed_handles == 1
    two = windows.write()  # written while stopped
    again = source(windows)
    again.open("Security", subscription_xpath(), one)
    assert records(again.wait(1.0)) == [two]


def test_stale_bookmark_fails_loudly_and_releases_handles(windows):
    windows.write()
    windows.write()
    windows.log.drop_oldest(1)
    src = source(windows)
    with pytest.raises(CollectorError):
        src.open("Security", subscription_xpath(), 1)
    assert windows.closed_handles == 1
    assert src.wait(1.0) == []


def test_one_unrenderable_record_does_not_lose_the_others(windows):
    last = windows.write()
    src = source(windows)
    src.open("Security", subscription_xpath(), last)
    bad, good = windows.write(), windows.write()
    windows.render_failures.add(bad)
    assert records(src.wait(1.0)) == [good]


# ------------------------------------------------------------------ monitor end to end
def run_monitor(config, database, rules, windows, between_catch_up_and_open=None, rounds=3):
    stop = threading.Event()
    states: list[MonitorState] = []
    batches = []
    service = ScanService(
        config, database, rules, reader_factory=lambda: windows.log, host_aliases=list
    )
    original = service.subscription_start_record

    def start_record():
        value = original()
        if between_catch_up_and_open:
            between_catch_up_and_open()
        return value

    service.subscription_start_record = start_record  # type: ignore[method-assign]
    waits = {"n": 0}

    def factory():
        src = source(windows)
        real_wait = src.wait

        def wait(timeout):
            waits["n"] += 1
            if waits["n"] > rounds:
                stop.set()
            return real_wait(timeout)

        src.wait = wait  # type: ignore[method-assign]
        return src

    monitor = LiveMonitor(
        service,
        factory,
        lambda state, _text: states.append(state),
        batches.append,
        wait_seconds=0.01,
        quiet_seconds=0.01,
    )
    monitor.run(stop)
    return states, batches


def test_event_written_between_catch_up_and_subscription_is_stored_once(
    config, database, rules, windows
):
    windows.write()
    late = []
    states, batches = run_monitor(
        config, database, rules, windows, lambda: late.append(windows.write())
    )
    assert MonitorState.ON in states and states[-1] is MonitorState.OFF
    assert sum(b.events_new for b in batches) == 1
    with database.connect() as conn:
        assert EventRepository(conn).count() == 2


def test_restarting_the_monitor_never_duplicates_stored_events(config, database, rules, windows):
    for _ in range(3):
        windows.write()
    run_monitor(config, database, rules, windows)
    run_monitor(config, database, rules, windows)
    with database.connect() as conn:
        assert EventRepository(conn).count() == 3


def test_no_saved_position_still_catches_a_record_written_before_subscribing(
    config, database, rules, windows
):
    """The catch-up stores nothing (here: a zero budget; in real life, nothing inside the
    lookback), so there is no saved position. The subscription must start after the newest
    record seen BEFORE the catch-up, not "from new events", or the late record is lost."""
    from dataclasses import replace

    windows.write()
    late = []
    no_budget = replace(config, max_events_per_scan=0)
    run_monitor(no_budget, database, rules, windows, lambda: late.append(windows.write()))
    with database.connect() as conn:
        stored = {r[0] for r in conn.execute("SELECT record_id FROM events")}
    assert late and late[0] in stored  # delivered live, not lost
