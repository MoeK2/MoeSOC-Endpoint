"""COR-001 confidence is derived from evidence and every point is explained."""

from datetime import timedelta

from moesoc.core.enums import Confidence, Severity
from moesoc.engine.correlation import confidence_from_points, correlate_failed_then_success

from .conftest import BASE_TIME, auth_event, failures

SEC = timedelta(seconds=1)
MIN = timedelta(minutes=1)


def _only(rules, events):
    (detection,) = correlate_failed_then_success(events, rules["COR-001"])
    return detection


def test_user_typo_pattern_gets_low_confidence(rules):
    # Five wrong passwords at the console, then a correct one: classic user error.
    events = failures("alice", 5, BASE_TIME, 10 * SEC, ip="-", logon_type=2, workstation="PC01")
    events.append(
        auth_event(4624, "alice", BASE_TIME + MIN, 1100, ip="-", logon_type=2, workstation="PC01")
    )
    detection = _only(rules, events)
    assert detection.confidence is Confidence.LOW
    assert detection.severity is Severity.HIGH  # severity stays separate from confidence
    reasons = [f.reason for f in detection.confidence_factors]
    assert any("local Interactive logon" in r for r in reasons)
    assert any("Same workstation and logon type" in r for r in reasons)


def test_remote_rdp_success_from_failing_address_gets_high_confidence(rules):
    events = failures("alice", 5, BASE_TIME, 10 * SEC, ip="198.51.100.7")
    events.append(
        auth_event(4624, "alice", BASE_TIME + MIN, 1100, ip="198.51.100.7", logon_type=10)
    )
    detection = _only(rules, events)
    assert detection.confidence is Confidence.HIGH
    assert sum(f.points for f in detection.confidence_factors) >= 3
    assert detection.evidence["confidence"]["value"] == "HIGH"


def test_network_success_from_loopback_is_not_treated_as_remote(rules):
    events = failures("alice", 5, BASE_TIME, 10 * SEC, ip="127.0.0.1")
    events.append(auth_event(4624, "alice", BASE_TIME + MIN, 1100, ip="::1", logon_type=3))
    detection = _only(rules, events)
    reasons = " ".join(f.reason for f in detection.confidence_factors)
    assert "came from remote address" not in reasons
    assert "same remote address" not in reasons
    # +2 network logon type, -1 same workstation + type with no remote address = 1
    assert detection.confidence is Confidence.MEDIUM


def test_many_sources_and_high_volume_add_confidence(rules):
    events = [
        auth_event(4625, "alice", BASE_TIME + i * 5 * SEC, 1000 + i, ip=f"203.0.113.{i % 4 + 1}")
        for i in range(12)
    ]
    events.append(
        auth_event(4624, "alice", BASE_TIME + 2 * MIN, 1100, ip="203.0.113.9", logon_type=3)
    )
    detection = _only(rules, events)
    reasons = " ".join(f.reason for f in detection.confidence_factors)
    assert "4 different addresses" in reasons
    assert "High attempt volume: 12 failures" in reasons


def test_evidence_contains_correlation_context(rules):
    events = failures("alice", 6, BASE_TIME, 10 * SEC, ip="198.51.100.7", workstation="KALI")
    events.append(
        auth_event(
            4624, "alice", BASE_TIME + MIN, 1100, ip="203.0.113.5", logon_type=10, workstation="WS9"
        )
    )
    ev = _only(rules, events).evidence
    assert ev["failure_record_ids"] == [1000, 1001, 1002, 1003, 1004, 1005]
    assert ev["success_record_id"] == 1100
    assert ev["total_attempts"] == 6
    assert ev["distinct_source_count"] == 1
    assert ev["source_addresses"] == ["198.51.100.7"]
    assert ev["success_source_address"] == "203.0.113.5"
    assert ev["success_from_failure_source"] is False
    assert ev["logon_type_matched"] is False  # failures were type 3, success type 10
    assert ev["workstation_matched"] is False
    assert ev["success_authentication_package"] == "NTLM"
    assert ev["failure_reasons"] == {"Incorrect password": 6}
    assert ev["first_failure"] and ev["last_failure"] and ev["success_time"]


def test_out_of_order_input_gives_same_result(rules):
    events = failures("alice", 5, BASE_TIME, 10 * SEC)
    events.append(auth_event(4624, "alice", BASE_TIME + MIN, 1100, logon_type=10))
    forward = _only(rules, events)
    backward = _only(rules, list(reversed(events)))
    assert forward.dedup_key == backward.dedup_key
    assert forward.evidence == backward.evidence


def test_success_at_window_boundary_counts(rules):
    events = failures("alice", 5, BASE_TIME, 10 * SEC)
    # The first failure is exactly 10:00 before the success: inclusive boundary.
    events.append(auth_event(4624, "alice", BASE_TIME + 10 * MIN, 1100))
    assert len(correlate_failed_then_success(events, rules["COR-001"])) == 1


def test_confidence_scale():
    assert confidence_from_points(-2) is Confidence.LOW
    assert confidence_from_points(0) is Confidence.LOW
    assert confidence_from_points(1) is Confidence.MEDIUM
    assert confidence_from_points(2) is Confidence.MEDIUM
    assert confidence_from_points(3) is Confidence.HIGH
