"""Event 4688 process creation: parsing, missing command lines, separate collection budget."""

from moesoc.collectors.security import CORE_EVENT_IDS, PROCESS_EVENT_IDS, SecurityCollector
from moesoc.engine.scanner import run_detections
from moesoc.parsers.security import parse_security_xml
from moesoc.storage.event_search import explain_event

from .conftest import FakeReader, auth_xml, fixture_text
from .test_privileged_sessions import T_SUCCESS


def process_xml(record=100240, **replace: str) -> str:
    xml = fixture_text("4688_process_created.xml").replace(
        "<EventRecordID>100240<", f"<EventRecordID>{record}<"
    )
    for name, value in replace.items():
        start = xml.index(f'<Data Name="{name}">')
        end = xml.index("</Data>", start)
        xml = xml[:start] + f'<Data Name="{name}">{value}' + xml[end:]
    return xml


def test_4688_parses_process_parent_user_and_token():
    e = parse_security_xml(fixture_text("4688_process_created.xml"))
    assert e.event_id == 4688
    assert e.process_name == "powershell.exe"
    assert e.process_path.endswith("\\WindowsPowerShell\\v1.0\\powershell.exe")
    assert e.process_id == 0x1A2C and e.parent_process_id == 0x2F04
    assert e.parent_process == "C:\\Windows\\System32\\cmd.exe"
    assert e.command_line == "powershell.exe -NoProfile -Command Get-Date"
    assert e.subject_account_display == "LAB\\Alice"
    assert e.logon_id == "0x5a3f21"  # the creator's session, not TargetLogonId 0x0
    elevation, integrity = e.token_elevation, e.integrity_level
    assert (elevation, integrity) == ("Full", "High")
    assert e.target_username is None and e.detail("target_logon_id") is None


def test_missing_command_line_is_none_never_invented():
    e = parse_security_xml(fixture_text("4688_no_command_line.xml"))
    assert e.command_line is None
    assert "Unavailable" in explain_event(e)


def test_timeline_text_never_repeats_the_command_line():
    e = parse_security_xml(process_xml(CommandLine="tool.exe --password Secr3t"))
    text = explain_event(e)
    assert "Secr3t" not in text and "command line recorded" in text
    assert "powershell.exe (PID 6700)" in text and "from cmd.exe" in text


def test_runas_target_session_is_kept():
    e = parse_security_xml(process_xml(TargetLogonId="0x88aa", TargetUserName="bob"))
    assert e.detail("target_logon_id") == "0x88aa"


def test_unknown_codes_are_kept_raw_and_missing_fields_are_none():
    e = parse_security_xml(process_xml(TokenElevationType="%%9999", MandatoryLabel=""))
    assert e.token_elevation in {"%%9999"}  # kept raw
    assert e.integrity_level is None


def test_version_1_event_without_parent_fields():
    xml = fixture_text("4688_process_created.xml")
    for name in ("ParentProcessName", "MandatoryLabel", "TargetUserSid", "TargetLogonId"):
        start = xml.index(f'<Data Name="{name}">')
        xml = xml[:start] + xml[xml.index("</Data>", start) + len("</Data>") :]
    e = parse_security_xml(xml.replace("<Version>2</Version>", "<Version>1</Version>"))
    assert e.parent_process is None and e.integrity_level is None
    assert e.parent_process_id == 0x2F04  # ProcessId exists in every version


def test_process_events_have_their_own_query_and_budget():
    many = [process_xml(record=200000 + i) for i in range(10)]
    logons = [auth_xml(4624, "alice", T_SUCCESS, 300 + i) for i in range(3)]
    reader = FakeReader([*many, *logons])
    result = SecurityCollector(reader).collect(24, max_events=5)
    ids = [e.event_id for e in result.events]
    assert ids.count(4624) == 3  # never crowded out by 4688
    assert ids.count(4688) == 5 and result.truncated
    queries = [q[1] for q in reader.queries]
    assert len(queries) == 2
    assert "EventID=4688" not in queries[0] and queries[1].count("EventID=") == 1
    assert 4688 in PROCESS_EVENT_IDS and 4688 not in CORE_EVENT_IDS


def test_process_creation_alone_is_never_a_finding(rules):
    events = [parse_security_xml(process_xml(record=500 + i)) for i in range(30)]
    assert run_detections(events, rules) == []
