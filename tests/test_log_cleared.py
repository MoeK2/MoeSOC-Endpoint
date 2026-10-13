"""Event 1102 (UserData payload) parsing and DET-003."""

from datetime import timedelta

import pytest

from moesoc.core.enums import Confidence, Severity
from moesoc.core.exceptions import EventParseError
from moesoc.engine.rules import detect_security_log_cleared
from moesoc.engine.scanner import ScanService
from moesoc.parsers.security import parse_security_xml
from moesoc.parsers.windows_event import parse_event_xml
from moesoc.storage.repository import DetectionRepository
from moesoc.utils.time import utc_now

from .conftest import FakeReader, fixture_text

XML = fixture_text("1102_security_log_cleared.xml")


def test_userdata_fields_are_extracted_by_name():
    raw = parse_event_xml(XML)
    assert raw.data_section == "UserData"
    assert raw.provider == "Microsoft-Windows-Eventlog"
    assert raw.get("SubjectUserName") == "Administrator"
    assert raw.get("SubjectLogonId") == "0x1d4e2"


def test_eventdata_events_still_report_eventdata():
    raw = parse_event_xml(fixture_text("4625_failed_network_logon.xml"))
    assert raw.data_section == "EventData"
    assert raw.get("TargetUserName") == "alice"


def test_1102_normalizes_actor_fields():
    event = parse_security_xml(XML)
    assert event.event_id == 1102
    assert event.record_id == 100500
    assert event.subject_username == "Administrator"
    assert event.subject_domain == "LAB"
    assert event.subject_user_sid == "S-1-5-21-1111111111-2222222222-3333333333-500"
    assert event.logon_id == "0x1d4e2"
    assert event.target_username is None  # 1102 has no target account
    assert event.raw_xml == XML


def test_userdata_without_fields_parses_with_empty_data():
    xml = XML.split("<UserData>")[0] + "<UserData></UserData></Event>"
    raw = parse_event_xml(xml)
    assert raw.data_section == "UserData"
    assert raw.data == {}


def test_nested_userdata_structures_are_ignored_not_guessed():
    xml = XML.replace(
        "<SubjectLogonId>0x1d4e2</SubjectLogonId>",
        "<SubjectLogonId>0x1d4e2</SubjectLogonId><Nested><Inner>x</Inner></Nested>",
    )
    raw = parse_event_xml(xml)
    assert "Nested" not in raw.data and "Inner" not in raw.data


def test_malformed_1102_raises_parse_error():
    with pytest.raises(EventParseError):
        parse_security_xml(XML.replace("</UserData>", ""))


def test_det003_triggers_for_every_1102(rules):
    (detection,) = detect_security_log_cleared([parse_security_xml(XML)], rules["DET-003"])
    assert detection.rule_id == "DET-003"
    assert detection.severity is Severity.HIGH
    assert detection.confidence is Confidence.HIGH
    assert detection.account == "LAB\\Administrator"
    ev = detection.evidence
    assert ev["actor_sid"].endswith("-500")
    assert ev["record_id"] == 100500
    assert ev["hostname"] == "WS-LAB01.lab.example"
    assert [m.technique_id for m in detection.rule.mitre] == ["T1070.001"]


def test_det003_ignores_other_events(rules):
    event = parse_security_xml(fixture_text("4625_failed_network_logon.xml"))
    assert detect_security_log_cleared([event], rules["DET-003"]) == []


def test_scan_pipeline_stores_1102_finding(config, database, rules):
    recent = (utc_now() - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.0000000Z")
    xml = XML.replace("2026-10-06T09:30:12.4410000Z", recent)
    reader = FakeReader([xml, fixture_text("malformed_truncated.xml")])
    service = ScanService(config, database, rules, reader_factory=lambda: reader)
    summary = service.run_live_scan()
    assert summary.parse_failures == 1  # the malformed record did not stop the scan
    assert summary.detections_new == 1
    with database.connect() as conn:
        (stored,) = DetectionRepository(conn).list_all()
    assert stored.rule_id == "DET-003"


def test_import_pipeline_stores_1102_finding(tmp_path, config, database, rules):
    export = tmp_path / "cleared.xml"
    export.write_text(XML, encoding="utf-8")
    service = ScanService(config, database, rules, reader_factory=lambda: FakeReader([]))
    summary = service.import_xml_file(export)
    assert summary.detections_new == 1
    with database.connect() as conn:
        (stored,) = DetectionRepository(conn).list_all()
    assert stored.rule_id == "DET-003"
    assert stored.evidence["actor"] == "LAB\\Administrator"
