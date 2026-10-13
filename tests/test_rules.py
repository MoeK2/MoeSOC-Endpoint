"""Behavioral tests for DET-001 and COR-001."""

from datetime import timedelta

from moesoc.core.enums import Confidence, DetectionKind, Severity
from moesoc.engine.correlation import correlate_failed_then_success
from moesoc.engine.rules import detect_multiple_failed_logins

from .conftest import BASE_TIME, auth_event, failures

SEC = timedelta(seconds=1)
MIN = timedelta(minutes=1)


# ------------------------------------------------------------------ rule metadata
def test_rule_metadata_loaded_from_yaml(rules):
    det = rules["DET-001"]
    assert det.title == "Multiple Failed Logins"
    assert det.kind is DetectionKind.DETECTION
    assert det.severity is Severity.MEDIUM
    assert [m.technique_id for m in det.mitre] == ["T1110"]
    assert det.false_positives  # false positives are part of every rule

    cor = rules["COR-001"]
    assert cor.title == "Possible Account Compromise"
    assert cor.severity is Severity.HIGH
    assert cor.confidence is Confidence.MEDIUM


# ------------------------------------------------------------------ DET-001
def test_det001_does_not_trigger_below_threshold(rules):
    events = failures("alice", 4, BASE_TIME, 30 * SEC)
    assert detect_multiple_failed_logins(events, rules["DET-001"]) == []


def test_det001_triggers_at_threshold_within_window(rules):
    events = failures("alice", 5, BASE_TIME, 30 * SEC)
    (detection,) = detect_multiple_failed_logins(events, rules["DET-001"])

    assert detection.rule_id == "DET-001"
    assert detection.severity is Severity.MEDIUM
    assert detection.risk_score == 40
    assert detection.account == "LAB\\alice"
    ev = detection.evidence
    assert ev["username"] == "alice"
    assert ev["failure_count"] == 5
    assert ev["source_addresses"] == ["192.0.2.45"]
    assert ev["failure_record_ids"] == [1000, 1001, 1002, 1003, 1004]
    assert ev["first_failure"] == BASE_TIME.isoformat()
    assert detection.first_seen == BASE_TIME
    assert detection.last_seen == BASE_TIME + 120 * SEC


def test_det001_ignores_failures_spread_beyond_window(rules):
    # 5 failures, but 5 minutes + 1 second between first and fifth.
    events = failures("alice", 5, BASE_TIME, timedelta(seconds=75.25))
    assert detect_multiple_failed_logins(events, rules["DET-001"]) == []


def test_det001_window_boundary_is_inclusive(rules):
    events = failures("alice", 5, BASE_TIME, 75 * SEC)  # exactly 5:00 apart
    assert len(detect_multiple_failed_logins(events, rules["DET-001"])) == 1


def test_det001_separates_accounts(rules):
    events = failures("alice", 3, BASE_TIME, 10 * SEC) + failures(
        "bob", 3, BASE_TIME, 10 * SEC, first_record=2000
    )
    assert detect_multiple_failed_logins(events, rules["DET-001"]) == []


def test_det001_account_matching_is_case_insensitive(rules):
    events = failures("alice", 3, BASE_TIME, 10 * SEC) + failures(
        "ALICE", 2, BASE_TIME + 40 * SEC, 10 * SEC, first_record=2000
    )
    assert len(detect_multiple_failed_logins(events, rules["DET-001"])) == 1


def test_det001_long_spray_produces_one_detection(rules):
    events = failures("alice", 40, BASE_TIME, 10 * SEC)
    (detection,) = detect_multiple_failed_logins(events, rules["DET-001"])
    assert detection.evidence["failure_count"] == 40


def test_det001_separate_bursts_produce_separate_detections(rules):
    events = failures("alice", 5, BASE_TIME, 10 * SEC) + failures(
        "alice", 5, BASE_TIME + 60 * MIN, 10 * SEC, first_record=2000
    )
    assert len(detect_multiple_failed_logins(events, rules["DET-001"])) == 2


def test_det001_unordered_input_is_handled(rules):
    events = list(reversed(failures("alice", 5, BASE_TIME, 30 * SEC)))
    assert len(detect_multiple_failed_logins(events, rules["DET-001"])) == 1


def test_det001_ignores_successful_logons(rules):
    events = [auth_event(4624, "alice", BASE_TIME + i * SEC, 1000 + i) for i in range(10)]
    assert detect_multiple_failed_logins(events, rules["DET-001"]) == []


# ------------------------------------------------------------------ COR-001
def test_cor001_triggers_on_success_after_failures(rules):
    events = failures("alice", 5, BASE_TIME, 30 * SEC)
    events.append(auth_event(4624, "Alice", BASE_TIME + 4 * MIN, 1100, logon_type=10))

    (detection,) = correlate_failed_then_success(events, rules["COR-001"])
    ev = detection.evidence
    assert detection.rule_id == "COR-001"
    assert detection.severity is Severity.HIGH
    assert detection.risk_score == 70
    assert ev["failure_count"] == 5
    assert ev["success_record_id"] == 1100
    assert ev["success_logon_type"] == "RemoteInteractive"
    assert ev["success_from_failure_source"] is True
    assert ev["seconds_from_last_failure_to_success"] == 120
    assert detection.related_record_ids == (1000, 1001, 1002, 1003, 1004, 1100)


def test_cor001_requires_threshold_failures(rules):
    events = failures("alice", 4, BASE_TIME, 30 * SEC)
    events.append(auth_event(4624, "alice", BASE_TIME + 3 * MIN, 1100))
    assert correlate_failed_then_success(events, rules["COR-001"]) == []


def test_cor001_ignores_success_outside_window(rules):
    events = failures("alice", 5, BASE_TIME, 10 * SEC)
    # Only failures in the 10 minutes before the success count. With the success at
    # 10:15, the failures at 0:00 and 0:10 fall outside, leaving 3 (< threshold 5).
    events.append(auth_event(4624, "alice", BASE_TIME + 10 * MIN + 15 * SEC, 1100))
    assert correlate_failed_then_success(events, rules["COR-001"]) == []


def test_cor001_ignores_success_before_failures(rules):
    events = [auth_event(4624, "alice", BASE_TIME - MIN, 900)]
    events += failures("alice", 5, BASE_TIME, 10 * SEC)
    assert correlate_failed_then_success(events, rules["COR-001"]) == []


def test_cor001_requires_same_account(rules):
    events = failures("alice", 5, BASE_TIME, 10 * SEC)
    events.append(auth_event(4624, "bob", BASE_TIME + 2 * MIN, 1100))
    assert correlate_failed_then_success(events, rules["COR-001"]) == []


def test_cor001_reports_burst_once_for_repeated_successes(rules):
    events = failures("alice", 5, BASE_TIME, 10 * SEC)
    events += [auth_event(4624, "alice", BASE_TIME + (2 + i) * MIN, 1100 + i) for i in range(3)]
    assert len(correlate_failed_then_success(events, rules["COR-001"])) == 1


def test_cor001_records_different_success_source(rules):
    events = failures("alice", 5, BASE_TIME, 10 * SEC)
    events.append(auth_event(4624, "alice", BASE_TIME + 2 * MIN, 1100, ip="198.51.100.7"))
    (detection,) = correlate_failed_then_success(events, rules["COR-001"])
    assert detection.evidence["success_from_failure_source"] is False
