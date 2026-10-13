"""Incremental collection: bootstrap, incremental, recovery after clear/rollover, never skip."""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterator
from dataclasses import replace
from datetime import datetime, timedelta

import pytest

from moesoc.collectors.security import (
    CORE_EVENT_IDS,
    SecurityCollector,
    build_after_record_xpath,
    build_since_xpath,
    group_signature,
)
from moesoc.core.exceptions import ChannelNotFoundError, MoeSOCError
from moesoc.engine.scanner import ScanService
from moesoc.storage.collection_state import CollectionStateRepository
from moesoc.storage.repository import DetectionRepository, EventRepository, ScanRepository
from moesoc.utils.time import parse_windows_timestamp, utc_now

from .conftest import auth_xml

_ID = re.compile(r"<EventID[^>]*>\s*(\d+)\s*<")
_RECORD = re.compile(r"<EventRecordID>(\d+)<")
_TIME = re.compile(r"SystemTime=\"([^\"]+)\"")


class FakeEventLog:
    """A Security log that answers the XPath forms the collector uses, like EvtQuery."""

    def __init__(self) -> None:
        self.records: list[tuple[int, int, datetime, str]] = []  # (record, event, time, xml)
        self.queries: list[str] = []
        self.next_record = 1000

    def write(self, event_id: int = 4625, user: str = "alice", at: datetime | None = None) -> int:
        at = at or utc_now() - timedelta(minutes=30)
        record = self.next_record
        self.next_record += 1
        xml = auth_xml(event_id, user, at, record)
        self.records.append(
            (record, event_id, parse_windows_timestamp(_TIME.search(xml).group(1)), xml)
        )
        return record

    def clear(self, restart_ids_at: int | None = None) -> None:
        self.records.clear()
        if restart_ids_at is not None:
            self.next_record = restart_ids_at

    def drop_oldest(self, count: int) -> None:
        self.records.sort()
        del self.records[:count]

    def query(self, channel: str, xpath: str, *, newest_first: bool = False) -> Iterator[str]:
        if channel != "Security":
            raise ChannelNotFoundError(f"The event log channel '{channel}' does not exist.")
        self.queries.append(xpath)
        ids = {int(i) for i in re.findall(r"EventID=(\d+)", xpath)}
        after = re.search(r"EventRecordID>(\d+)", xpath)
        exact = re.search(r"EventRecordID=(\d+)", xpath)
        since = re.search(r"@SystemTime>='([^']+)'", xpath)
        rows = sorted(self.records)
        if newest_first:
            rows.reverse()
        for record, event_id, at, xml in rows:
            if ids and event_id not in ids:
                continue
            if after and record <= int(after.group(1)):
                continue
            if exact and record != int(exact.group(1)):
                continue
            if since and at < parse_windows_timestamp(since.group(1)):
                continue
            yield xml


def collect(log: FakeEventLog, marks=None, budget: int = 100):
    return SecurityCollector(log).collect(24, budget, marks)


def marks_from(result):
    return dict(result.watermarks)


# ------------------------------------------------------------------ collector modes
def test_first_run_bootstraps_and_records_the_newest_position():
    log = FakeEventLog()
    for _ in range(5):
        log.write()
    result = collect(log)
    assert result.modes == {"core": "bootstrap", "process": "bootstrap"}
    assert len(result.events) == 5
    mark = result.watermarks["core"]
    assert mark.record_id == 1004 and mark.signature == group_signature(CORE_EVENT_IDS)
    assert "process" not in result.watermarks  # nothing read: it bootstraps again next time


def test_incremental_reads_only_new_records_oldest_first():
    log = FakeEventLog()
    for _ in range(5):
        log.write()
    first = collect(log)
    new = [log.write() for _ in range(3)]
    second = collect(log, marks_from(first))
    assert second.modes["core"] == "incremental"
    assert [e.record_id for e in second.events] == new
    assert build_after_record_xpath(CORE_EVENT_IDS, 1004) in log.queries
    assert second.watermarks["core"].record_id == new[-1]


def test_no_new_records_keeps_the_position():
    log = FakeEventLog()
    log.write()
    first = collect(log)
    second = collect(log, marks_from(first))
    assert second.events == [] and second.modes["core"] == "incremental"
    assert second.watermarks["core"] == first.watermarks["core"]


def test_budget_hit_continues_next_scan_without_skipping():
    log = FakeEventLog()
    log.write()
    marks = marks_from(collect(log))
    new = [log.write() for _ in range(5)]
    part1 = collect(log, marks, budget=3)
    assert [e.record_id for e in part1.events] == new[:3]
    assert part1.more_pending and not part1.truncated
    part2 = collect(log, marks_from(part1), budget=3)
    assert [e.record_id for e in part2.events] == new[3:]
    assert not part2.more_pending


def test_bootstrap_cap_is_reported_as_truncated():
    log = FakeEventLog()
    for _ in range(10):
        log.write()
    result = collect(log, budget=4)
    assert result.truncated and len(result.events) == 4
    assert result.watermarks["core"].record_id == 1009  # newest first


def test_cleared_log_with_restarted_record_ids_is_recovered_by_time():
    log = FakeEventLog()
    log.write(at=utc_now() - timedelta(hours=2))
    marks = marks_from(collect(log))
    log.clear(restart_ids_at=1)
    after = [log.write(at=utc_now() - timedelta(minutes=m)) for m in (30, 20)]
    result = collect(log, marks)
    assert result.modes["core"] == "recovery"
    assert [e.record_id for e in result.events] == after
    assert any("no longer in the Security log" in n for n in result.notes)
    assert result.watermarks["core"].record_id == after[-1]
    # The fresh position is trusted again: the next scan is incremental.
    later = log.write(at=utc_now() - timedelta(minutes=1))
    following = collect(log, marks_from(result))
    assert following.modes["core"] == "incremental"
    assert [e.record_id for e in following.events] == [later]


def test_rolled_over_log_is_recovered_and_the_gap_is_reported():
    log = FakeEventLog()
    old = [log.write(at=utc_now() - timedelta(hours=3, minutes=m)) for m in (3, 2, 1)]
    marks = marks_from(collect(log))
    newer = [log.write(at=utc_now() - timedelta(minutes=m)) for m in (50, 40)]
    log.drop_oldest(3)  # the watermark record was overwritten
    result = collect(log, marks)
    assert result.modes["core"] == "recovery"
    assert [e.record_id for e in result.events] == newer
    assert build_since_xpath(CORE_EVENT_IDS, marks["core"].timestamp) in log.queries
    assert old[-1] == marks["core"].record_id


def test_reused_record_id_with_different_time_is_not_trusted():
    log = FakeEventLog()
    log.write(at=utc_now() - timedelta(hours=2))  # record 1000
    marks = marks_from(collect(log))
    log.clear(restart_ids_at=1000)
    log.write(at=utc_now() - timedelta(minutes=5))  # a different record 1000
    result = collect(log, marks)
    assert result.modes["core"] == "recovery"
    assert len(result.events) == 1


@pytest.mark.parametrize(
    ("mark_change", "reason"),
    [
        ({"signature": "4624"}, "event types changed"),
        ({"record_id": 0}, "invalid saved position"),
        ({"timestamp": utc_now() + timedelta(days=1)}, "in the future"),
    ],
)
def test_unusable_state_falls_back_to_bootstrap_with_a_note(mark_change, reason):
    log = FakeEventLog()
    log.write()
    good = collect(log).watermarks["core"]
    bad = replace(good, **mark_change)
    result = collect(log, {"core": bad})
    assert result.modes["core"] == "bootstrap"
    assert any(reason in n for n in result.notes)


def test_routine_records_still_move_the_position():
    log = FakeEventLog()
    log.write()
    marks = marks_from(collect(log))
    # A 4672 for SYSTEM is filtered, but it must not be re-read forever.
    xml = auth_xml(4625, "x", utc_now() - timedelta(minutes=1), 1001)
    xml = xml.replace("<EventID>4625<", "<EventID>4672<").replace(
        "</EventData>", '<Data Name="SubjectUserSid">S-1-5-18</Data></EventData>'
    )
    log.records.append((1001, 4672, utc_now() - timedelta(minutes=1), xml))
    log.next_record = 1002
    result = collect(log, marks)
    assert result.filtered == 1 and result.events == []
    assert result.watermarks["core"].record_id == 1001


# ------------------------------------------------------------------ scan service
def _service(config, database, rules, log):
    return ScanService(config, database, rules, reader_factory=lambda: log, host_aliases=list)


def test_scans_persist_state_and_record_the_mode(config, database, rules):
    log = FakeEventLog()
    for _ in range(3):
        log.write()
    service = _service(config, database, rules, log)
    first = service.run_live_scan()
    assert first.collection_mode == (
        "core: bootstrap, process: bootstrap, sysmon: not installed, powershell: not installed, "
        "defender: not installed"
    )
    log.write()
    second = service.run_live_scan()
    assert second.collection_mode.startswith("core: incremental")
    assert second.records_read == 1 and second.events_new == 1
    with database.connect() as conn:
        assert CollectionStateRepository(conn).load("Security")["core"].record_id == 1003
        assert ScanRepository(conn).last().collection_mode.startswith("core: incremental")


def test_recovery_note_is_saved_on_the_scan(config, database, rules):
    log = FakeEventLog()
    log.write(at=utc_now() - timedelta(hours=2))
    service = _service(config, database, rules, log)
    service.run_live_scan()
    log.clear(restart_ids_at=1)
    log.write()
    service.run_live_scan()
    with database.connect() as conn:
        assert "cannot be recovered" in ScanRepository(conn).last().message


def test_failed_storage_does_not_advance_the_position(config, database, rules, monkeypatch):
    log = FakeEventLog()
    log.write()
    service = _service(config, database, rules, log)
    service.run_live_scan()
    log.write()

    def broken(self, detection, scan_id):
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(DetectionRepository, "upsert", broken)
    log.write()
    log.write()
    log.write()
    log.write()
    with pytest.raises(MoeSOCError):
        service.run_live_scan()
    with database.connect() as conn:
        assert CollectionStateRepository(conn).load("Security")["core"].record_id == 1000
        assert EventRepository(conn).count() == 1  # the failed scan stored nothing


def test_deleted_database_starts_with_a_bootstrap(config, rules, tmp_path):
    from moesoc.storage.database import Database

    log = FakeEventLog()
    log.write()
    db = Database(tmp_path / "fresh.db")
    db.initialize()
    summary = _service(config, db, rules, log).run_live_scan()
    assert summary.collection_mode.startswith("core: bootstrap, process: bootstrap")
    assert "sysmon: not installed" in summary.collection_mode


def test_clearing_state_forces_a_bootstrap_but_keeps_data(config, database, rules):
    log = FakeEventLog()
    log.write()
    service = _service(config, database, rules, log)
    service.run_live_scan()
    with database.connect() as conn:
        CollectionStateRepository(conn).clear()
    summary = service.run_live_scan()
    assert summary.collection_mode.startswith("core: bootstrap")
    assert summary.events_new == 0  # re-read records are duplicates, ignored
