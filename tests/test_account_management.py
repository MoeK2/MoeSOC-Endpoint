"""4720 / 4732 parsing, schema v3, DET-005, DET-006 and COR-002."""

import sqlite3
from datetime import timedelta

import pytest

from moesoc.core.enums import Confidence, Severity
from moesoc.core.exceptions import StorageError
from moesoc.engine.account_rules import (
    COR_002,
    DET_005,
    DET_006,
    correlate_new_account_to_admin,
    detect_new_user_account,
    detect_privileged_group_addition,
)
from moesoc.engine.context import DetectionContext
from moesoc.engine.scanner import ScanService
from moesoc.parsers.security import parse_security_xml
from moesoc.storage.database import Database
from moesoc.storage.repository import DetectionRepository, EventRepository
from moesoc.storage.schema import MIGRATIONS, SCHEMA_VERSION
from moesoc.utils.time import utc_now

from .conftest import FakeReader, fixture_text

HOST = "WS-LAB01.lab.example"
MACHINE = "S-1-5-21-7777777777-8888888888-9999999999"
NEW_SID = f"{MACHINE}-1009"
ADMIN_SID = f"{MACHINE}-1001"
FIXTURE_TIME_4720 = "2026-10-06T10:00:05.1000000Z"
FIXTURE_TIME_4732 = "2026-10-06T10:01:40.2000000Z"


def _time(dt) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"


def created_xml(at, record, name="backup-svc2", sid=NEW_SID, host=HOST) -> str:
    return (
        fixture_text("4720_user_account_created.xml")
        .replace(FIXTURE_TIME_4720, _time(at))
        .replace("<EventRecordID>100600<", f"<EventRecordID>{record}<")
        .replace(">backup-svc2<", f">{name}<")
        .replace(NEW_SID, sid)
        .replace(f"<Computer>{HOST}<", f"<Computer>{host}<")
    )


def added_xml(
    at, record, member_sid=NEW_SID, group_sid="S-1-5-32-544", group="Administratoren", host=HOST
) -> str:
    xml = (
        fixture_text("4732_member_added_to_administrators.xml")
        .replace(FIXTURE_TIME_4732, _time(at))
        .replace("<EventRecordID>100604<", f"<EventRecordID>{record}<")
        .replace(f'"MemberSid">{NEW_SID}<', f'"MemberSid">{member_sid or "-"}<')
        .replace(">Administratoren<", f">{group}<")
        .replace(f"<Computer>{HOST}<", f"<Computer>{host}<")
    )
    return xml.replace('"TargetSid">S-1-5-32-544<', f'"TargetSid">{group_sid or "-"}<')


T0 = utc_now().replace(microsecond=0) - timedelta(hours=2)


def created(at=T0, record=600, **kw):
    return parse_security_xml(created_xml(at, record, **kw))


def added(at=T0 + timedelta(minutes=2), record=604, **kw):
    return parse_security_xml(added_xml(at, record, **kw))


def ctx(events, rules):
    return DetectionContext.from_events(events, rules=rules)


# ------------------------------------------------------------------ parsing
def test_4720_parses_new_account_creator_and_details():
    e = parse_security_xml(fixture_text("4720_user_account_created.xml"))
    assert e.event_id == 4720
    assert e.target_account_display == "WS-LAB01\\backup-svc2"
    assert e.target_user_sid == NEW_SID  # from TargetSid, not TargetUserSid
    assert e.subject_account_display == "WS-LAB01\\labadmin"
    assert e.subject_user_sid == ADMIN_SID
    assert e.logon_id == "0x8a1f3"  # the creator's session
    assert e.detail("sam_account_name") == "backup-svc2"
    assert e.detail("user_account_control") == "%%2080 %%2082 %%2084"
    assert e.detail("display_name") is None  # "%%1793" means <value not set>
    assert e.privileges is None


def test_4732_separates_group_from_member():
    e = parse_security_xml(fixture_text("4732_member_added_to_administrators.xml"))
    assert e.event_id == 4732
    assert e.group_name == "Administratoren"  # localized: never trusted alone
    assert e.group_domain == "VORDEFINIERT"
    assert e.group_sid == "S-1-5-32-544"
    assert e.member_sid == NEW_SID
    assert e.member_name is None  # "-" for local accounts
    assert e.target_username is None  # the group is not mistaken for an account
    assert e.target_user_sid == NEW_SID
    assert e.subject_account_display == "WS-LAB01\\labadmin"
    assert e.logon_id == "0x8a1f3"


def test_4732_with_missing_member_and_group_sid_stays_safe():
    e = added(member_sid=None, group_sid=None)
    assert e.member_sid is None and e.group_sid is None and e.target_user_sid is None


def test_new_fields_round_trip_through_storage(database):
    events = [created(), added()]
    with database.connect() as conn:
        assert EventRepository(conn).insert_many(events) == 2
        stored = sorted(
            EventRepository(conn).in_range(
                T0 - timedelta(minutes=1), T0 + timedelta(hours=1), (4720, 4732)
            ),
            key=lambda e: e.record_id,
        )
    assert stored[0].detail("sam_account_name") == "backup-svc2"
    assert stored[1].group_sid == "S-1-5-32-544" and stored[1].member_sid == NEW_SID


# ------------------------------------------------------------------ schema v3
def _v2_database(path):
    conn = sqlite3.connect(path)
    conn.executescript(MIGRATIONS[0])
    conn.execute("PRAGMA user_version = 1")
    MIGRATIONS[1](conn)
    conn.execute("PRAGMA user_version = 2")
    conn.execute(
        "INSERT INTO events (hostname, channel, record_id, timestamp, source, provider, event_id, "
        "target_username, raw_xml, ingested_at) VALUES ('H', 'Security', 1, "
        "'2026-10-06T08:00:00.000000+00:00', 'security', 'p', 4625, 'alice', '<Event/>', 'x')"
    )
    conn.commit()
    return conn


def test_migration_v3_keeps_rows_and_adds_null_columns(tmp_path):
    path = tmp_path / "moesoc.db"
    _v2_database(path).close()
    assert Database(path).initialize() == SCHEMA_VERSION >= 3
    conn = sqlite3.connect(path)
    row = conn.execute("SELECT target_username, group_sid, details FROM events").fetchone()
    assert row == ("alice", None, None)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION


def test_migration_v3_failure_rolls_back_completely(tmp_path):
    path = tmp_path / "moesoc.db"
    conn = _v2_database(path)
    conn.execute("ALTER TABLE events ADD COLUMN group_sid TEXT")  # makes step N fail
    conn.commit()
    conn.close()
    with pytest.raises(StorageError):
        Database(path).initialize()
    conn = sqlite3.connect(path)
    columns = {r[1] for r in conn.execute("PRAGMA table_info(events)")}
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 2
    assert "member_name" not in columns  # earlier statements of v3 were rolled back
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1


# ------------------------------------------------------------------ DET-005
def test_det005_new_account_is_low_with_full_context(rules):
    (f,) = detect_new_user_account([created()], rules[DET_005])
    assert f.severity is Severity.LOW and f.confidence is Confidence.HIGH
    assert f.risk_score == 20
    ev = f.evidence
    assert ev["account"] == "WS-LAB01\\backup-svc2" and ev["new_account_sid"] == NEW_SID
    assert ev["actor"] == "WS-LAB01\\labadmin" and ev["actor_logon_id"] == "0x8a1f3"
    assert ev["account_scope"] == "local"
    assert ev["context"] == []
    assert f.rule.mitre[0].technique_id == "T1136.001"


def test_det005_hidden_looking_name_raises_to_medium_with_reason(rules):
    (f,) = detect_new_user_account([created(name="support$")], rules[DET_005])
    assert f.severity is Severity.MEDIUM and f.risk_score == 40
    assert "'$'" in f.evidence["context"][0]


def test_det005_unicode_name_and_one_finding_per_event(rules):
    events = [
        created(name="jörg"),
        created(T0 + timedelta(minutes=5), 601, name="Ünal", sid=f"{MACHINE}-1010"),
    ]
    findings = detect_new_user_account(events, rules[DET_005])
    assert [f.account for f in findings] == ["WS-LAB01\\jörg", "WS-LAB01\\Ünal"]
    assert len({f.dedup_key for f in findings}) == 2


# ------------------------------------------------------------------ DET-006
def test_det006_localized_administrators_matched_by_sid_is_high(rules):
    events = [created(), added()]
    (f,) = detect_privileged_group_addition(events, rules[DET_006], ctx(events, rules))
    assert f.severity is Severity.HIGH and f.confidence is Confidence.HIGH
    assert f.risk_score == 70
    ev = f.evidence
    assert ev["group"] == "Administratoren" and ev["group_meaning"] == "Administrators"
    assert ev["group_matched_by"] == "sid"
    assert ev["member"] == "WS-LAB01\\backup-svc2"  # name resolved from the 4720
    assert ev["member_name_source"] == "Event 4720 record 600"
    assert ev["actor"] == "WS-LAB01\\labadmin"
    assert f.rule.mitre[0].technique_id == "T1098.007"


def test_det006_remote_desktop_users_is_medium(rules):
    (f,) = detect_privileged_group_addition(
        [added(group_sid="S-1-5-32-555", group="Remote Desktop Users")], rules[DET_006]
    )
    assert f.severity is Severity.MEDIUM


def test_det006_ignores_ordinary_groups(rules):
    assert (
        detect_privileged_group_addition(
            [added(group_sid="S-1-5-32-545", group="Users")], rules[DET_006]
        )
        == []
    )


def test_det006_a_custom_group_named_administrators_is_not_the_builtin_one(rules):
    custom = added(group_sid=f"{MACHINE}-1050", group="Administrators")
    assert detect_privileged_group_addition([custom], rules[DET_006]) == []


def test_det006_name_only_match_when_no_sid_is_recorded_has_low_confidence(rules):
    (f,) = detect_privileged_group_addition(
        [added(group_sid=None, group="Administrators")], rules[DET_006]
    )
    assert f.severity is Severity.HIGH and f.confidence is Confidence.LOW
    assert f.evidence["group_matched_by"] == "name"


def test_det006_member_without_known_name_shows_the_sid(rules):
    (f,) = detect_privileged_group_addition([added()], rules[DET_006])
    assert f.evidence["member"] == NEW_SID and f.evidence["member_name_source"] is None


# ------------------------------------------------------------------ COR-002
def test_cor002_creation_then_admin_within_window(rules):
    events = [created(), added()]
    (f,) = correlate_new_account_to_admin(events, rules[COR_002], ctx(events, rules))
    assert f.severity is Severity.HIGH and f.confidence is Confidence.HIGH
    ev = f.evidence
    assert ev["seconds_from_creation_to_group_add"] == 120
    assert ev["creation_record_id"] == 600 and ev["group_add_record_id"] == 604
    assert ev["created_by"] == ev["added_by"] == "WS-LAB01\\labadmin" and ev["same_actor"]
    assert set(f.related_record_ids) == {600, 604}
    assert {m.technique_id for m in f.rule.mitre} == {"T1136.001", "T1098.007"}


def test_cor002_wrong_order_is_ignored(rules):
    events = [added(at=T0), created(at=T0 + timedelta(minutes=1))]
    assert correlate_new_account_to_admin(events, rules[COR_002], ctx(events, rules)) == []


def test_cor002_window_edge(rules):
    on_edge = [created(), added(at=T0 + timedelta(minutes=30))]
    assert len(correlate_new_account_to_admin(on_edge, rules[COR_002], ctx(on_edge, rules))) == 1
    late = [created(), added(at=T0 + timedelta(minutes=30, seconds=1))]
    assert correlate_new_account_to_admin(late, rules[COR_002], ctx(late, rules)) == []


def test_cor002_different_sid_or_host_does_not_correlate(rules):
    other_sid = [created(), added(member_sid=f"{MACHINE}-1099")]
    other_host = [created(), added(host="WS-LAB02.lab.example")]
    for events in (other_sid, other_host):
        assert correlate_new_account_to_admin(events, rules[COR_002], ctx(events, rules)) == []


def test_cor002_requires_an_administrator_equivalent_group(rules):
    events = [created(), added(group_sid="S-1-5-32-555", group="Remote Desktop Users")]
    assert correlate_new_account_to_admin(events, rules[COR_002], ctx(events, rules)) == []


def test_cor002_out_of_order_input_and_repeated_additions_give_one_finding(rules):
    events = [
        added(
            record=605,
            at=T0 + timedelta(minutes=3),
            group_sid="S-1-5-32-551",
            group="Backup Operators",
        ),
        added(),
        created(),
    ]
    (f,) = correlate_new_account_to_admin(events, rules[COR_002], ctx(events, rules))
    assert f.evidence["group_add_record_id"] == 604  # the first addition


def test_cor002_name_only_group_gives_medium_confidence(rules):
    events = [created(), added(group_sid=None, group="Administrators")]
    (f,) = correlate_new_account_to_admin(events, rules[COR_002], ctx(events, rules))
    assert f.confidence is Confidence.MEDIUM


def test_cor002_needs_the_privileged_group_definition(rules):
    events = [created(), added()]
    only = {COR_002: rules[COR_002]}
    assert correlate_new_account_to_admin(events, rules[COR_002], ctx(events, only)) == []


def test_cor002_missing_member_sid_never_correlates(rules):
    events = [created(), added(member_sid=None)]
    assert correlate_new_account_to_admin(events, rules[COR_002], ctx(events, rules)) == []


# ------------------------------------------------------------------ end to end
def test_scan_stores_account_events_and_raises_det005_det006_cor002(config, database, rules):
    xml = [created_xml(T0, 600), added_xml(T0 + timedelta(minutes=2), 604)]
    service = ScanService(
        config, database, rules, reader_factory=lambda: FakeReader(xml), host_aliases=list
    )
    summary = service.run_live_scan()
    assert summary.events_new == 2
    with database.connect() as conn:
        found = sorted(d.rule_id for d in DetectionRepository(conn).list_all())
    assert found == ["COR-002", "DET-005", "DET-006"]
