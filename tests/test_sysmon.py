"""Sysmon Event 1 parsing and collection next to the Security log."""

from datetime import timedelta

import pytest

from moesoc.core.enums import TelemetrySource
from moesoc.core.exceptions import EventParseError, LogAccessDeniedError
from moesoc.engine.scanner import ScanService
from moesoc.parsers.dispatch import parse_any_xml
from moesoc.parsers.security import parse_security_xml
from moesoc.parsers.sysmon import parse_sysmon_xml
from moesoc.storage.collection_state import CollectionStateRepository
from moesoc.storage.event_search import explain_event
from moesoc.storage.repository import EventRepository
from moesoc.utils.time import utc_now

from .conftest import FakeReader, auth_xml, fixture_text

FIXTURE_TIME = "2026-10-06T08:21:10.1230000Z"


def sysmon_xml(record=5001, at=None, **fields: str) -> str:
    xml = fixture_text("sysmon_1_process_create.xml").replace(
        "<EventRecordID>5001<", f"<EventRecordID>{record}<"
    )
    if at is not None:
        xml = xml.replace(FIXTURE_TIME, at.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z")
    for name, value in fields.items():
        start = xml.index(f'<Data Name="{name}">')
        end = xml.index("</Data>", start)
        xml = xml[:start] + f'<Data Name="{name}">{value}' + xml[end:]
    return xml


# ------------------------------------------------------------------ parsing
def test_sysmon_process_create_is_normalized():
    e = parse_sysmon_xml(sysmon_xml())
    assert e.source is TelemetrySource.SYSMON
    assert e.channel == "Microsoft-Windows-Sysmon/Operational" and e.event_id == 1
    assert (e.subject_domain, e.subject_username) == ("LAB", "alice")
    assert e.subject_user_sid is None  # System/Security UserID is the Sysmon service
    assert e.process_name == "powershell.exe" and e.process_id == 6700
    assert e.process_guid == "{8a1c5f3e-6b2a-6702-2f01-000000000e00}"
    assert e.parent_process_guid == "{8a1c5f3e-6b20-6702-2c01-000000000e00}"
    assert e.parent_process == "C:\\Windows\\System32\\cmd.exe" and e.parent_process_id == 12036
    assert e.command_line == "powershell.exe -NoProfile -Command Get-Date"
    assert e.integrity_level == "High"
    assert e.hashes.startswith("SHA256=")
    assert e.logon_id == "0x5a3f21"  # same spelling as Security 4624 TargetLogonId
    assert e.detail("current_directory") == "C:\\Users\\alice\\"
    assert e.detail("original_file_name") == "PowerShell.EXE"
    assert e.detail("rule_name") is None  # "-" placeholder


def test_sysmon_logon_id_joins_the_security_logon_session():
    sysmon = parse_sysmon_xml(sysmon_xml())
    logon = parse_security_xml(fixture_text("4624_successful_rdp_logon.xml"))
    assert sysmon.logon_id == logon.logon_id


def test_missing_and_zero_values_stay_empty():
    e = parse_sysmon_xml(
        sysmon_xml(
            ParentProcessGuid="{00000000-0000-0000-0000-000000000000}",
            CommandLine="",
            Hashes="",
            User="",
            LogonId="",
        )
    )
    assert e.parent_process_guid is None and e.command_line is None and e.hashes is None
    assert e.subject_username is None and e.logon_id is None


def test_unsupported_sysmon_event_and_wrong_channel_are_rejected():
    with pytest.raises(EventParseError):
        parse_sysmon_xml(sysmon_xml().replace("<EventID>1<", "<EventID>255<"))
    with pytest.raises(EventParseError):
        parse_sysmon_xml(fixture_text("4624_successful_rdp_logon.xml"))


def test_dispatch_routes_by_channel():
    assert parse_any_xml(sysmon_xml()).source is TelemetrySource.SYSMON
    assert parse_any_xml(fixture_text("4625_failed_network_logon.xml")).source is (
        TelemetrySource.SECURITY
    )
    other = sysmon_xml().replace(
        "<Channel>Microsoft-Windows-Sysmon/Operational<", "<Channel>Application<"
    )
    with pytest.raises(EventParseError):
        parse_any_xml(other)


def test_timeline_text_names_process_parent_and_user():
    text = explain_event(parse_sysmon_xml(sysmon_xml()))
    assert text == (
        "Sysmon: process powershell.exe (PID 6700) started by LAB\\alice from cmd.exe, "
        "integrity High"
    )
    assert "Get-Date" not in text  # never the command line


def test_sysmon_fields_round_trip_through_storage(database):
    e = parse_sysmon_xml(sysmon_xml(at=utc_now() - timedelta(minutes=5)))
    with database.connect() as conn:
        EventRepository(conn).insert_many([e])
        (stored,) = EventRepository(conn).in_range(utc_now() - timedelta(hours=1), utc_now(), (1,))
    assert stored.process_guid == e.process_guid and stored.hashes == e.hashes
    assert stored.source is TelemetrySource.SYSMON


# ------------------------------------------------------------------ collection
def _now_xml(record, minutes):
    return sysmon_xml(record=record, at=utc_now() - timedelta(minutes=minutes))


def test_scan_collects_sysmon_next_to_security_with_its_own_position(config, database, rules):
    reader = FakeReader(
        [auth_xml(4624, "alice", utc_now() - timedelta(minutes=9), 300), _now_xml(5001, 8)]
    )
    service = ScanService(config, database, rules, reader_factory=lambda: reader, host_aliases=list)
    summary = service.run_live_scan()
    assert summary.events_new == 2
    assert "sysmon_process: bootstrap" in summary.collection_mode
    with database.connect() as conn:
        marks = CollectionStateRepository(conn).load("Microsoft-Windows-Sysmon/Operational")
    assert marks["sysmon_process"].record_id == 5001
    reader.xml_records.append(_now_xml(5002, 1))
    second = service.run_live_scan()
    assert "sysmon_process: incremental" in second.collection_mode
    assert second.events_new == 1


def test_no_sysmon_is_recorded_not_an_error(config, database, rules):
    reader = FakeReader([auth_xml(4624, "alice", utc_now() - timedelta(minutes=9), 300)])
    service = ScanService(config, database, rules, reader_factory=lambda: reader, host_aliases=list)
    summary = service.run_live_scan()
    assert "sysmon: not installed" in summary.collection_mode


def test_unreadable_sysmon_log_does_not_fail_the_scan(config, database, rules):
    class Reader(FakeReader):
        def query(self, channel, xpath, *, newest_first=False):
            if channel.startswith("Microsoft-Windows-Sysmon"):
                raise LogAccessDeniedError("Access denied while reading the Sysmon log.")
            yield from super().query(channel, xpath, newest_first=newest_first)

    reader = Reader([auth_xml(4624, "alice", utc_now() - timedelta(minutes=9), 300)])
    service = ScanService(config, database, rules, reader_factory=lambda: reader, host_aliases=list)
    summary = service.run_live_scan()
    assert summary.events_new == 1
    assert "sysmon: unavailable" in summary.collection_mode
    assert any("Sysmon log not collected" in n for n in summary.notes)


def test_sysmon_events_never_feed_security_rules(rules):
    from moesoc.engine.scanner import run_detections

    events = [parse_sysmon_xml(sysmon_xml(record=6000 + i)) for i in range(20)]
    assert run_detections(events, rules) == []


def test_import_accepts_sysmon_exports(config, database, rules, tmp_path):
    export = tmp_path / "sysmon.xml"
    export.write_text(_now_xml(7001, 3), encoding="utf-8")
    service = ScanService(config, database, rules, host_aliases=list)
    summary = service.import_xml_file(export)
    assert summary.events_new == 1
