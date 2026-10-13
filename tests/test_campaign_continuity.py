"""A-1: one continuing campaign stays one finding across live batches and rescans.

Audit reproduction (2026-10-08): 36 failures, one every 5 minutes (3 hours), delivered
one event per live batch, produced 22 DET-004 findings, because each batch reloaded only
the rule window and the finding was keyed by the first record it could still see.
"""

from datetime import timedelta

from moesoc.core.enums import TriageStatus
from moesoc.engine.scanner import ScanService
from moesoc.storage.repository import DetectionRepository

from .conftest import BASE_TIME, auth_xml

MIN = timedelta(minutes=1)


def slow(user: str, count: int, start, every: timedelta, first_record: int, **kw) -> list[str]:
    return [
        auth_xml(4625, user, start + i * every, first_record + i, ip="198.51.100.7", **kw)
        for i in range(count)
    ]


def service(config, database, rules) -> ScanService:
    return ScanService(config, database, rules, host_aliases=list)


def findings(database, rule_id: str):
    with database.connect() as conn:
        return [d for d in DetectionRepository(conn).list_all() if d.rule_id == rule_id]


def evidence_count(database, detection_id: int) -> int:
    with database.connect() as conn:
        return len(DetectionRepository(conn).evidence_event_pks(detection_id))


CAMPAIGN = slow("bob", 36, BASE_TIME, 5 * MIN, 1000)  # 3 hours, one failure every 5 minutes


def test_audit_reproduction_one_event_per_live_batch_is_one_finding(config, database, rules):
    svc = service(config, database, rules)
    for xml in CAMPAIGN:
        svc.ingest_live([xml])
    (finding,) = findings(database, "DET-004")
    assert finding.first_seen == BASE_TIME
    assert finding.last_seen == BASE_TIME + 35 * 5 * MIN
    assert finding.occurrence_count == 36
    assert evidence_count(database, finding.id) == 36  # each event linked once
    assert finding.evidence["failure_count"] == 36
    assert finding.evidence["campaign"]["key"].startswith("identity:")


def test_same_campaign_in_one_batch_is_one_finding(config, database, rules):
    service(config, database, rules).ingest_live(CAMPAIGN)
    (finding,) = findings(database, "DET-004")
    assert finding.occurrence_count == 36


def test_two_campaigns_separated_by_a_quiet_gap_are_two_findings(config, database, rules):
    second_start = BASE_TIME + 36 * 5 * MIN + 6 * 60 * MIN  # six quiet hours later
    second = slow("bob", 12, second_start, 5 * MIN, 5000)
    svc = service(config, database, rules)
    for xml in CAMPAIGN + second:
        svc.ingest_live([xml])
    found = sorted(findings(database, "DET-004"), key=lambda d: d.first_seen)
    assert len(found) == 2
    assert found[0].last_seen < found[1].first_seen
    assert (found[0].occurrence_count, found[1].occurrence_count) == (36, 12)


def test_repeated_ingestion_adds_no_finding_and_no_evidence(config, database, rules):
    svc = service(config, database, rules)
    svc.ingest_live(CAMPAIGN)
    result = svc.ingest_live(CAMPAIGN)
    assert result.events_new == 0 and result.detections_new == 0
    (finding,) = findings(database, "DET-004")
    assert evidence_count(database, finding.id) == 36


def test_events_arriving_out_of_order_extend_the_same_finding(config, database, rules):
    svc = service(config, database, rules)
    late = CAMPAIGN[:6]  # the first half hour arrives last (e.g. a delayed forwarder)
    for xml in CAMPAIGN[6:]:
        svc.ingest_live([xml])
    for xml in reversed(late):
        svc.ingest_live([xml])
    (finding,) = findings(database, "DET-004")
    assert finding.first_seen == BASE_TIME
    assert finding.occurrence_count == 36


def test_scheduled_import_path_still_one_finding(tmp_path, config, database, rules):
    svc = service(config, database, rules)
    first, second = tmp_path / "a.xml", tmp_path / "b.xml"
    first.write_text("\n".join(CAMPAIGN[:18]), encoding="utf-8")
    second.write_text("\n".join(CAMPAIGN[18:]), encoding="utf-8")
    svc.import_xml_file(first)
    svc.import_xml_file(second)
    (finding,) = findings(database, "DET-004")
    assert finding.occurrence_count == 36


def test_det001_long_brute_force_live_is_one_finding_and_bursts_stay_separate(
    config, database, rules
):
    svc = service(config, database, rules)
    # 90 minutes of one failure every 40 s: longer than any rule window
    for i in range(135):
        svc.ingest_live(
            [auth_xml(4625, "carol", BASE_TIME + i * 40 * timedelta(seconds=1), 9000 + i)]
        )
    assert len(findings(database, "DET-001")) == 1
    # a separate burst an hour after the campaign ended is a new finding
    later = BASE_TIME + 90 * MIN + 60 * MIN
    svc.ingest_live(
        [
            auth_xml(4625, "carol", later + i * 10 * timedelta(seconds=1), 20000 + i)
            for i in range(5)
        ]
    )
    assert len(findings(database, "DET-001")) == 2


def test_different_accounts_are_never_merged_into_one_campaign(config, database, rules):
    svc = service(config, database, rules)
    for xml in CAMPAIGN:
        svc.ingest_live([xml])
    for xml in slow("dave", 12, BASE_TIME, 5 * MIN, 3000):
        svc.ingest_live([xml])
    found = findings(database, "DET-004")
    identity = sorted(d.account for d in found if d.evidence["mode"] == "identity")
    assert identity == ["LAB\\bob", "LAB\\dave"]
    # the shared source (one IP, two accounts) is one source-mode campaign, not one per batch
    assert sum(d.evidence["mode"] == "source" for d in found) == 1


def test_triage_notes_and_history_survive_campaign_extension(config, database, rules):
    svc = service(config, database, rules)
    for xml in CAMPAIGN[:18]:
        svc.ingest_live([xml])
    (finding,) = findings(database, "DET-004")
    with database.connect() as conn:
        repo = DetectionRepository(conn)
        repo.set_status(finding.id, TriageStatus.INVESTIGATING)
        repo.add_note(finding.id, "Checking the user's phone mail client")
    for xml in CAMPAIGN[18:]:
        svc.ingest_live([xml])
    (extended,) = findings(database, "DET-004")
    assert extended.id == finding.id
    assert extended.status is TriageStatus.INVESTIGATING
    assert extended.occurrence_count == 36
    with database.connect() as conn:
        repo = DetectionRepository(conn)
        notes = repo.notes(finding.id)
        history = repo.history(finding.id)
    assert [n.body for n in notes] == ["Checking the user's phone mail client"]
    assert [h.to_status for h in history] == ["NEW", "INVESTIGATING"]
