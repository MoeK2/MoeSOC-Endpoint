"""Event 4672: parsed as context, never an alert, and linked to COR-001's logon."""

from datetime import timedelta

from moesoc.collectors.security import SecurityCollector
from moesoc.engine.correlation import COR_001, correlate_failed_then_success
from moesoc.engine.risk import assess_risk
from moesoc.engine.scanner import run_detections
from moesoc.engine.sessions import PrivilegedSessions, describe_privileges
from moesoc.parsers.security import parse_security_xml
from moesoc.utils.time import parse_windows_timestamp

from .conftest import FakeReader, failures, fixture_text

SUCCESS_TIME = "2026-10-06T08:19:03.5550001Z"
PRIV_TIME = "2026-10-06T08:19:03.5560001Z"
T_SUCCESS = parse_windows_timestamp(SUCCESS_TIME)


def _time(dt) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"


def success(at=T_SUCCESS, record=100230, logon_id="0x5a3f21", host="WS-LAB01.lab.example"):
    xml = (
        fixture_text("4624_successful_rdp_logon.xml")
        .replace(SUCCESS_TIME, _time(at))
        .replace("<EventRecordID>100230<", f"<EventRecordID>{record}<")
        .replace('"TargetLogonId">0x5a3f21<', f'"TargetLogonId">{logon_id}<')
        .replace("<Computer>WS-LAB01.lab.example<", f"<Computer>{host}<")
    )
    return parse_security_xml(xml)


def privileges_xml(at=None, record=100231, logon_id="0x5a3f21", sid=None, host=None) -> str:
    xml = fixture_text("4672_special_privileges.xml")
    if at is not None:
        xml = xml.replace(PRIV_TIME, _time(at))
    xml = xml.replace("<EventRecordID>100231<", f"<EventRecordID>{record}<")
    xml = xml.replace('"SubjectLogonId">0x5a3f21<', f'"SubjectLogonId">{logon_id}<')
    if sid:
        xml = xml.replace(
            '"SubjectUserSid">S-1-5-21-1111111111-2222222222-3333333333-1104<',
            f'"SubjectUserSid">{sid}<',
        )
    if host:
        xml = xml.replace("<Computer>WS-LAB01.lab.example<", f"<Computer>{host}<")
    return xml


def privileged(**kw):
    return parse_security_xml(privileges_xml(**kw))


def attack():
    """6 failures for LAB\\Alice in the minute before the RDP success."""
    start = T_SUCCESS - timedelta(minutes=2)
    return failures("Alice", 6, start, timedelta(seconds=10), 100100, logon_type=10)


# ------------------------------------------------------------------ parsing
def test_4672_parses_account_session_and_privileges():
    e = parse_security_xml(fixture_text("4672_special_privileges.xml"))
    assert e.event_id == 4672
    assert e.subject_account_display == "LAB\\Alice"
    assert e.logon_id == "0x5a3f21"
    assert e.target_username is None
    assert e.privilege_list[0] == "SeSecurityPrivilege"
    assert len(e.privilege_list) == 9
    assert "\t" not in e.privileges and "\n" not in e.privileges


def test_4624_records_whether_the_token_was_elevated():
    e = parse_security_xml(fixture_text("4624_successful_rdp_logon.xml"))
    assert e.detail("elevated_token") == "yes"  # fixture has %%1842 (yes); %%1843 = no


def test_sensitive_privileges_are_listed_first():
    info = describe_privileges(privileged())
    assert info["privilege_count"] == 9
    assert info["sensitive_privileges"][:2] == ["SeDebugPrivilege", "SeImpersonatePrivilege"]


# ------------------------------------------------------------------ collection
def test_service_account_4672_is_counted_and_not_stored():
    reader = FakeReader([privileges_xml(sid="S-1-5-18"), privileges_xml(record=100232)])
    result = SecurityCollector(reader).collect(24, 100)
    assert result.records_read == 2
    assert result.filtered == 1
    assert [e.record_id for e in result.events] == [100232]


def test_a_4672_alone_is_never_a_finding(rules):
    events = [privileged(record=100300 + i, logon_id=f"0x{i:x}") for i in range(50)]
    assert run_detections(events, rules) == []


# ------------------------------------------------------------------ COR-001 context
def test_cor001_success_with_special_privileges_gets_higher_priority(rules):
    events = [*attack(), success(), privileged()]
    (raw,) = correlate_failed_then_success(events, rules[COR_001])
    finding = assess_risk(raw)  # the scanner applies the risk model to every finding
    session = finding.evidence["privileged_session"]
    assert session["record_id"] == 100231 and session["logon_id"] == "0x5a3f21"
    assert "SeDebugPrivilege" in session["sensitive_privileges"]
    plain = assess_risk(correlate_failed_then_success([*attack(), success()], rules[COR_001])[0])
    # Confidence is about evidence of attack, not privileges: unchanged.
    assert finding.confidence == plain.confidence
    assert "privileged_session" not in plain.evidence
    # Same evidence strength, higher priority: +10 with the reason recorded.
    assert finding.risk_score == plain.risk_score + 10
    reasons = [f["reason"] for f in finding.evidence["risk_factors"]]
    assert any("special privileges" in r for r in reasons)
    assert 100231 in finding.related_record_ids


def test_session_match_needs_the_same_logon_id(rules):
    events = [*attack(), success(), privileged(logon_id="0x99")]
    (finding,) = correlate_failed_then_success(events, rules[COR_001])
    assert "privileged_session" not in finding.evidence


def test_logon_id_comparison_ignores_case():
    index = PrivilegedSessions([privileged(logon_id="0x5A3F21")])
    assert index.for_logon(success()) is not None


def test_reused_logon_id_hours_later_does_not_match():
    later = privileged(at=T_SUCCESS + timedelta(hours=3))
    assert PrivilegedSessions([later]).for_logon(success()) is None


def test_same_logon_id_on_another_computer_does_not_match():
    other = privileged(host="WS-LAB02.lab.example")
    assert PrivilegedSessions([other]).for_logon(success()) is None


def test_uac_linked_session_is_matched():
    # The filtered session's 4624 names the elevated session that received 4672.
    filtered = parse_security_xml(
        fixture_text("4624_successful_rdp_logon.xml")
        .replace('"TargetLogonId">0x5a3f21<', '"TargetLogonId">0x700001<')
        .replace('"TargetLinkedLogonId">0x0<', '"TargetLinkedLogonId">0x700002<')
    )
    assert filtered.detail("linked_logon_id") == "0x700002"
    elevated_session = privileged(logon_id="0x700002")
    assert PrivilegedSessions([elevated_session]).for_logon(filtered) is elevated_session


def test_no_linked_session_is_recorded_as_none():
    assert success().detail("linked_logon_id") is None  # "0x0" in the fixture


def test_closest_4672_in_time_is_chosen():
    near = privileged(record=1, at=T_SUCCESS + timedelta(seconds=1))
    far = privileged(record=2, at=T_SUCCESS + timedelta(seconds=50))
    assert PrivilegedSessions([far, near]).for_logon(success()).record_id == 1
