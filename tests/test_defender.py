"""Microsoft Defender 1116-1119 parsing and DET-008 (detection + remediation correlation)."""

from __future__ import annotations

from datetime import datetime, timedelta

from moesoc.core.enums import Confidence, Severity, TelemetrySource
from moesoc.engine.defender_rules import (
    ALLOWED,
    DET_008,
    FAILED,
    PENDING,
    REMEDIATED,
    detect_defender_detections,
)
from moesoc.engine.scanner import ScanService, load_rule_input, run_detections
from moesoc.parsers.defender import parse_defender_xml, primary_file, split_resources
from moesoc.parsers.dispatch import parse_any_xml
from moesoc.storage.event_search import explain_event
from moesoc.storage.repository import DetectionRepository, EventRepository
from moesoc.utils.time import utc_now

from .conftest import FakeReader, fixture_text

DETECTION_ID = "5e0f8c2a-7b1d-4e3f-9a6b-2c4d8e0f1a3b"
T0 = datetime(2026, 10, 6, 8, 30, 0)


def xml(
    event_id: int = 1116,
    record: int | None = None,
    at: datetime | None = None,
    detection: str | None = None,
    host: str | None = None,
    **fields: str,
) -> str:
    name = "defender_1116_malware_detected.xml"
    text = fixture_text(name)
    text = text.replace("<EventID>1116<", f"<EventID>{event_id}<")
    text = text.replace("<EventRecordID>5101<", f"<EventRecordID>{record or 5100 + event_id}<")
    stamp = (at or T0).strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"
    text = text.replace("2026-10-06T08:30:00.0000000Z", stamp)
    if detection:
        text = text.replace("5E0F8C2A-7B1D-4E3F-9A6B-2C4D8E0F1A3B", detection)
    if host:
        text = text.replace("<Computer>WS-LAB01.lab.example<", f"<Computer>{host}<")
    for key, value in fields.items():
        data = key.replace("_", " ")
        start = text.index(f'<Data Name="{data}">') + len(f'<Data Name="{data}">')
        text = text[:start] + value + text[text.index("</Data>", start) :]
    return text


def event(*args, **kwargs):
    return parse_defender_xml(xml(*args, **kwargs))


def detected(**kw):
    return event(1116, **kw)


def quarantined(seconds=4, at=None, **kw):
    when = (at or T0) + timedelta(seconds=seconds)
    return event(1117, at=when, Action_Name="Quarantine", **kw)


def run(events, rules):
    return detect_defender_detections(events, rules[DET_008])


# ------------------------------------------------------------------ parsing
def test_1116_is_normalized():
    e = parse_any_xml(fixture_text("defender_1116_malware_detected.xml"))
    assert e.source is TelemetrySource.DEFENDER and e.event_id == 1116
    assert e.detail("detection_id") == DETECTION_ID
    assert e.detail("threat_name") == "Virus:DOS/EICAR_Test_File"
    assert (e.detail("severity_name"), e.detail("category_name")) == ("Severe", "Virus")
    assert e.subject_account_display == "LAB\\alice"
    assert e.process_name == "explorer.exe"
    assert e.file_path == "C:\\Users\\alice\\Downloads\\eicar.com.txt"
    assert e.detail("source_name") == "Real-Time Protection"
    assert e.detail("intelligence_version").startswith("AV: 1.457")


def test_1117_records_the_action():
    e = parse_any_xml(fixture_text("defender_1117_action_taken.xml"))
    assert e.event_id == 1117 and e.detail("action_name") == "Quarantine"
    assert e.detail("remediation_user") == "NT AUTHORITY\\SYSTEM"
    assert e.detail("error_code") == "0x00000000"


def test_resources_are_split_by_type():
    path = (
        "containerfile:_C:\\Users\\a\\x.zip; file:_C:\\Users\\a\\x.zip->eicar.com; "
        "webfile:_C:\\Users\\a\\Downloads\\y.exe|https://example.com/y.exe|pid:4,ProcessStart:1; "
        "process:_pid:4321,ProcessStart:133000000000000000"
    )
    resources = split_resources(path)
    assert [kind for kind, _ in resources] == ["containerfile", "file", "webfile", "process"]
    assert primary_file(resources) == "C:\\Users\\a\\x.zip"
    assert primary_file(split_resources("webfile:_C:\\d\\y.exe|https://example.com/y")) == (
        "C:\\d\\y.exe"
    )
    assert primary_file(split_resources("process:_pid:4")) is None
    assert split_resources("") == [] and split_resources(None) == []


def test_unknown_process_and_missing_user_stay_empty():
    e = event(1116, Process_Name="Unknown", Detection_User="")
    assert e.process_path is None and e.process_name is None
    assert e.subject_username is None


def test_explain_says_defender_detected_it():
    text = explain_event(detected())
    assert text.startswith("Microsoft Defender detected Virus:DOS/EICAR_Test_File")
    assert "eicar.com.txt" in text
    assert "quarantine" in explain_event(quarantined()).casefold()


# ------------------------------------------------------------------ DET-008
def test_detection_without_action_is_pending(rules):
    (f,) = run([detected()], rules)
    rem = f.evidence["remediation"]
    assert rem["state"] == PENDING and "not seen" in rem["outcome"]
    assert f.severity is Severity.HIGH  # Defender severity Severe
    assert f.confidence is Confidence.HIGH
    assert f.evidence["summary"] == "Microsoft Defender detected Virus:DOS/EICAR_Test_File"
    assert "Microsoft Defender" in f.evidence["verdict_source"]
    assert f.account == "LAB\\alice"
    assert f.rule.mitre == ()


def test_detection_and_quarantine_are_one_finding(rules):
    (f,) = run([quarantined(), detected()], rules)
    rem = f.evidence["remediation"]
    assert rem["state"] == REMEDIATED and rem["action"] == "Quarantine"
    assert rem["seconds_after_detection"] == 4 and rem["event_id"] == 1117
    assert len(f.related_record_ids) == 2
    assert f.dedup_key == f"DET-008|WS-LAB01.lab.example|{DETECTION_ID}"
    (alone,) = run([detected()], rules)
    assert alone.dedup_key == f.dedup_key  # 1117 arriving later updates the same finding


def test_severity_follows_defender_and_failures_raise_it(rules):
    (moderate,) = run([detected(Severity_Name="Moderate"), quarantined()], rules)
    assert moderate.severity is Severity.MEDIUM
    (low,) = run([detected(Severity_Name="Low")], rules)
    assert low.severity is Severity.LOW
    failed = event(1118, at=T0 + timedelta(seconds=5), Error_Code="0x80508023")
    (f,) = run([detected(Severity_Name="Moderate"), failed], rules)
    assert f.evidence["remediation"]["state"] == FAILED and f.severity is Severity.HIGH
    assert any("raised to HIGH" in r for r in f.evidence["severity_reasons"])


def test_1117_with_an_error_code_is_a_failure(rules):
    bad = event(1117, at=T0 + timedelta(seconds=3), Error_Code="0x80508023")
    (f,) = run([detected(Severity_Name="Low"), bad], rules)
    assert f.evidence["remediation"]["state"] == FAILED and f.severity is Severity.HIGH


def test_latest_action_wins_after_a_retry(rules):
    failed = event(1118, at=T0 + timedelta(seconds=2))
    (f,) = run([detected(), failed, quarantined(seconds=30)], rules)
    assert f.evidence["remediation"]["state"] == REMEDIATED


def test_allowed_threat_is_high(rules):
    allowed = event(1117, at=T0 + timedelta(seconds=9), Action_Name="Allow")
    (f,) = run([detected(Severity_Name="Low"), allowed], rules)
    assert f.evidence["remediation"]["state"] == ALLOWED and f.severity is Severity.HIGH


def test_detections_are_separated_by_id_and_computer(rules):
    other = "11111111-2222-3333-4444-555555555555"
    events = [
        detected(),
        detected(record=6001, detection=other),
        detected(record=6002, host="WS-LAB02.lab.example"),
    ]
    assert len(run(events, rules)) == 3


def test_only_defender_events_are_used(rules):
    assert run_detections([quarantined()], {DET_008: rules[DET_008]})[0].rule_id == DET_008


# ------------------------------------------------------------------ pipeline
def test_partner_from_an_earlier_scan_is_joined(database):
    at = utc_now() - timedelta(hours=30)
    with database.connect() as conn:
        EventRepository(conn).insert_many(
            [
                detected(at=at),
                quarantined(seconds=0, at=at + timedelta(hours=3)),
                detected(record=7000, detection="99999999-0000-0000-0000-000000000000", at=at),
            ]
        )
        loaded = load_rule_input(conn, at + timedelta(hours=1), utc_now())
    assert sorted(e.event_id for e in loaded) == [1116, 1117]  # unrelated 1116 not loaded


def _recent(event_id, minutes, **kw):
    return xml(event_id, at=utc_now() - timedelta(minutes=minutes), **kw)


def test_scan_collects_defender_and_updates_the_finding(config, database, rules):
    reader = FakeReader([_recent(1116, 10)])
    service = ScanService(config, database, rules, reader_factory=lambda: reader, host_aliases=list)
    first = service.run_live_scan()
    assert "defender_detection: bootstrap" in first.collection_mode
    reader.xml_records.append(_recent(1117, 9, Action_Name="Quarantine"))
    service.run_live_scan()
    with database.connect() as conn:
        (f,) = DetectionRepository(conn).list_all()
    assert f.rule_id == DET_008
    assert f.evidence["remediation"]["state"] == REMEDIATED
