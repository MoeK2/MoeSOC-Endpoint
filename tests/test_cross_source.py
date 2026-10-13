"""Cross-source correlation: activity graph, COR-003 (session) and COR-004 (Defender file)."""

from __future__ import annotations

import re
from datetime import timedelta

from moesoc.core.enums import Confidence, Severity
from moesoc.engine.activity import ActivityGraph
from moesoc.engine.context import DetectionContext
from moesoc.engine.cross_source import (
    COR_003,
    COR_004,
    correlate_defender_file_source,
    correlate_session_activity,
)
from moesoc.engine.scanner import load_rule_input, run_detections
from moesoc.parsers.security import parse_security_xml
from moesoc.parsers.sysmon import parse_sysmon_xml
from moesoc.storage.repository import EventRepository
from moesoc.storage.schema import SCHEMA_VERSION
from moesoc.utils.time import utc_now

from .conftest import BASE_TIME, auth_xml, failures, fixture_text
from .test_account_management import added_xml, created_xml
from .test_defender import xml as defender_xml
from .test_powershell import CRADLE, block
from .test_sysmon import sysmon_xml

HOST = "WS-LAB01.lab.example"
SESSION = "0x5a3f21"
T = BASE_TIME.replace(tzinfo=None) if BASE_TIME.tzinfo else BASE_TIME
MIN = timedelta(minutes=1)
WRITER_GUID = "{8A1C5F3E-6B2A-6702-2F01-000000000E00}"


def logon(at, record=2000, session=SESSION, user="alice"):
    xml = auth_xml(4624, user, at, record)
    xml = xml.replace(
        "</EventData>", f'  <Data Name="TargetLogonId">{session}</Data>\n  </EventData>'
    )
    return parse_security_xml(xml)


def with_session(xml: str, session: str) -> str:
    return re.sub(r'"SubjectLogonId">[^<]*<', f'"SubjectLogonId">{session}<', xml)


def account_created(at, session=SESSION, record=2100):
    return parse_security_xml(with_session(created_xml(at, record), session))


def group_added(at, session=SESSION, record=2101):
    return parse_security_xml(with_session(added_xml(at, record), session))


def powershell_start(at, session=SESSION, pid=6700, record=2200):
    return parse_sysmon_xml(sysmon_xml(record=record, at=at, LogonId=session, ProcessId=str(pid)))


def brute_force_then_logon(start=T):
    return [*failures("alice", 6, start, timedelta(seconds=10)), logon(start + MIN)]


def ctx(events, rules):
    return DetectionContext.from_events(events, rules=rules)


def cor003(events, rules):
    return correlate_session_activity(events, rules[COR_003], ctx(events, rules))


# ------------------------------------------------------------------ activity graph
def test_session_events_are_bounded_by_logon_and_window():
    start = logon(T)
    before = account_created(T - MIN, record=1)
    inside = account_created(T + 5 * MIN, record=2)
    late = account_created(T + 2 * 60 * MIN, record=3)
    other = account_created(T + 5 * MIN, session="0x999", record=4)
    graph = ActivityGraph([start, before, inside, late, other])
    found = [link.event.record_id for link in graph.session_events(start, 60 * MIN)]
    assert found == [2]


def test_system_logon_ids_are_never_sessions():
    graph = ActivityGraph([logon(T, session="0x3e7"), account_created(T + MIN, session="0x3e7")])
    assert graph.session_events(logon(T, session="0x3e7"), 60 * MIN) == []


# ------------------------------------------------------------------ COR-003
def test_failures_logon_then_account_creation_in_the_session(rules):
    events = [
        *brute_force_then_logon(),
        account_created(T + 3 * MIN),
        group_added(T + 4 * MIN),
    ]
    (f,) = cor003(events, rules)
    assert f.severity is Severity.HIGH and f.confidence is Confidence.HIGH
    assert f.evidence["follow_up_kinds"] == ["account_created", "group_member_added"]
    assert f.evidence["failure_count"] == 6
    links = [s["link"] for s in f.evidence["chain"]]
    assert links[:2] == [None, "account"] and links[2:] == ["logon_id", "logon_id"]
    assert f.evidence["link_quality"].startswith("exact")
    assert len(f.related_record_ids) == 6 + 1 + 2


def test_suspicious_powershell_in_the_session_is_linked_via_its_process(rules):
    ps = powershell_start(T + 2 * MIN)
    script = block(CRADLE, at=T + 3 * MIN)
    (f,) = cor003([*brute_force_then_logon(), ps, script], rules)
    assert f.evidence["follow_up_kinds"] == ["suspicious_powershell"]
    (finding,) = f.evidence["suspicious_powershell"]
    assert "download_execute" in finding["indicators"] and finding["pid"] == 6700


def test_powershell_in_another_session_does_not_count(rules):
    ps = powershell_start(T + 2 * MIN, session="0x777")
    script = block(CRADLE, at=T + 3 * MIN)
    assert cor003([*brute_force_then_logon(), ps, script], rules) == []


def test_ordinary_processes_alone_are_not_a_finding(rules):
    benign = powershell_start(T + 2 * MIN)
    assert cor003([*brute_force_then_logon(), benign], rules) == []


def test_no_failures_means_no_finding(rules):
    assert cor003([logon(T), account_created(T + MIN)], rules) == []


def test_defender_detection_for_the_user_is_a_weak_link(rules):
    detection = parse_any_defender(T + 10 * MIN)
    (f,) = cor003([*brute_force_then_logon(), detection], rules)
    assert f.confidence is Confidence.MEDIUM
    assert f.evidence["chain"][-1]["link"] == "user_time"
    assert f.evidence["link_quality"].startswith("weak")


def parse_any_defender(at, **kw):
    from moesoc.parsers.defender import parse_defender_xml

    return parse_defender_xml(defender_xml(1116, at=at, **kw))


# ------------------------------------------------------------------ COR-004
def file_create(at, path="C:\\Users\\alice\\Downloads\\eicar.com.txt", record=3001):
    xml = fixture_text("sysmon_11_file_create.xml")
    xml = xml.replace("C:\\Users\\alice\\AppData\\Local\\Temp\\update.ps1", path)
    xml = xml.replace("<EventRecordID>5003<", f"<EventRecordID>{record}<")
    xml = xml.replace("2026-10-06T08:21:14.0000000Z", at.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z")
    return parse_sysmon_xml(xml)


def dns(at, record=3002):
    xml = fixture_text("sysmon_22_dns_query.xml")
    xml = xml.replace("<EventRecordID>5005<", f"<EventRecordID>{record}<")
    xml = xml.replace("2026-10-06T08:21:11.0000000Z", at.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z")
    return parse_sysmon_xml(xml)


def writer(at, record=3000):
    return parse_sysmon_xml(sysmon_xml(record=record, at=at, ProcessGuid=WRITER_GUID))


def cor004(events, rules):
    return correlate_defender_file_source(events, rules[COR_004])


def download_chain(start=T):
    return [
        writer(start),
        dns(start + timedelta(seconds=5)),
        file_create(start + timedelta(seconds=8)),
        parse_any_defender(start + timedelta(seconds=10)),
    ]


def test_defender_file_is_traced_to_the_writing_process(rules):
    (f,) = cor004(download_chain(), rules)
    ev = f.evidence
    assert ev["written_by"].endswith("powershell.exe") and ev["writer_start_collected"]
    assert ev["dns_queries"] == ["downloads.example.net"]
    assert ev["seconds_from_write_to_detection"] == 2
    assert ev["related_techniques"] == ["T1105"]
    assert ev["summary"].startswith("Microsoft Defender detected Virus:DOS/EICAR_Test_File")
    assert f.confidence is Confidence.HIGH
    assert f.severity is Severity.HIGH  # Defender severity Severe
    assert [s["log"] for s in ev["chain"]] == ["sysmon", "sysmon", "sysmon", "defender"]
    assert f.dedup_key.startswith("COR-004|WS-LAB01.lab.example|5e0f8c2a")


def test_path_match_is_case_insensitive_and_time_bounded(rules):
    upper = file_create(T, path="C:\\USERS\\ALICE\\DOWNLOADS\\EICAR.COM.TXT")
    assert len(cor004([upper, parse_any_defender(T + MIN)], rules)) == 1
    too_old = file_create(T)
    assert cor004([too_old, parse_any_defender(T + 2 * 60 * MIN)], rules) == []
    other_file = file_create(T, path="C:\\Temp\\other.txt")
    assert cor004([other_file, parse_any_defender(T + MIN)], rules) == []


def test_unknown_writer_start_lowers_confidence(rules):
    (f,) = cor004([file_create(T), parse_any_defender(T + MIN)], rules)
    assert f.confidence is Confidence.MEDIUM and f.evidence["writer_start_collected"] is False
    assert f.evidence["related_techniques"] is None


def test_executed_file_raises_severity(rules):
    run = parse_sysmon_xml(
        sysmon_xml(
            record=3010,
            at=T + 9 * timedelta(seconds=1),
            Image="C:\\Users\\alice\\Downloads\\eicar.com.txt",
            ProcessGuid="{8A1C5F3E-0000-0000-0000-00000000AAAA}",
        )
    )
    events = [file_create(T), run, parse_any_defender(T + MIN, Severity_Name="Low")]
    (f,) = cor004(events, rules)
    assert f.evidence["executed"] is True and f.severity is Severity.HIGH
    assert "T1204.002" in f.evidence["related_techniques"]


# ------------------------------------------------------------------ storage + scanner
def test_schema_has_cross_source_indexes(database):
    with database.connect() as conn:
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    assert {"idx_events_file_path", "idx_events_destination_ip"} <= names
    assert SCHEMA_VERSION >= 6


def test_scanner_loads_sysmon_context_for_defender_files(database, rules):
    now = utc_now().replace(microsecond=0)
    chain = download_chain(now - timedelta(minutes=30))
    noise = file_create(now - timedelta(minutes=30), path="C:\\Temp\\unrelated.txt", record=3999)
    with database.connect() as conn:
        EventRepository(conn).insert_many([*chain, noise])
        # Only the Defender event is in the scan range; the Sysmon chain is loaded by key.
        loaded = load_rule_input(conn, now - timedelta(minutes=29, seconds=55), now)
    assert sorted(e.event_id for e in loaded) == [1, 11, 22, 1116]
    findings = run_detections(loaded, rules)
    assert {f.rule_id for f in findings} >= {"DET-008", "COR-004"}
