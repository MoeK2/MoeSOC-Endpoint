"""DET-004: slow guessing below DET-001's burst threshold, without double reporting."""

from dataclasses import replace
from datetime import timedelta

import pytest

from moesoc.engine.context import DetectionContext
from moesoc.engine.rules import DET_004, detect_low_and_slow_guessing
from moesoc.engine.scanner import run_detections

from .conftest import BASE_TIME, auth_event, failures

SEC = timedelta(seconds=1)
MIN = timedelta(minutes=1)


@pytest.fixture
def det004(rules):
    return rules[DET_004]


def run(events, rules):
    """DET-004 with the full rule set in context (so DET-001/002 exclusion applies)."""
    context = DetectionContext.from_events(events, rules=rules)
    return detect_low_and_slow_guessing(events, rules[DET_004], context)


def slow(user="alice", count=10, every=6 * MIN, start=BASE_TIME, first_record=1000, **kw):
    return failures(user, count, start, every, first_record, **kw)


# ------------------------------------------------------------------ identity mode
def test_ten_failures_one_every_six_minutes_is_detected(rules):
    (finding,) = run(slow(), rules)
    ev = finding.evidence
    assert ev["mode"] == "identity"
    assert ev["account"] == "LAB\\alice"
    assert ev["failure_count"] == 10
    assert ev["failure_record_ids"] == list(range(1000, 1010))
    assert ev["first_failure"] == BASE_TIME.isoformat()
    assert ev["source_addresses"] == ["192.0.2.45"]
    assert ev["logon_types"] and ev["failure_reasons"]
    assert ev["interval_seconds_median"] == 360.0 and ev["regular_interval"] is True
    assert finding.rule.mitre[0].technique_id == "T1110"


def test_nine_failures_is_below_threshold(rules):
    assert run(slow(count=9), rules) == []


def test_window_edge_is_inclusive(rules):
    # 10 failures spanning exactly 60 minutes: first at 0, last at 60:00.
    on_edge = slow(every=timedelta(seconds=400))  # 9 gaps x 400 s = 3600 s
    assert len(run(on_edge, rules)) == 1
    past_edge = slow(every=timedelta(seconds=401))  # 3609 s: no 60-min window holds 10
    assert run(past_edge, rules) == []


def test_fast_burst_is_left_to_det001(rules):
    fast = failures("alice", 6, BASE_TIME, 10 * SEC, 500)  # a DET-001 burst
    later = slow(count=9, start=BASE_TIME + 10 * MIN)
    assert run([*fast, *later], rules) == []  # 9 slow failures remain: below 10


def test_slow_remainder_after_a_burst_is_reported_with_the_exclusion_count(rules):
    fast = failures("alice", 6, BASE_TIME, 10 * SEC, 500)
    later = slow(count=10, every=5 * MIN, start=BASE_TIME + 6 * MIN)
    (finding,) = run([*fast, *later], rules)
    assert finding.evidence["failure_count"] == 10
    assert finding.evidence["failures_in_det001_bursts_excluded"] == 6
    assert not set(finding.evidence["failure_record_ids"]) & set(range(500, 506))


def test_without_det001_loaded_nothing_is_excluded(rules):
    events = [
        *failures("alice", 6, BASE_TIME, 10 * SEC, 500),
        *slow(count=5, start=BASE_TIME + 10 * MIN),
    ]
    only_det004 = {DET_004: rules[DET_004]}
    context = DetectionContext.from_events(events, rules=only_det004)
    (finding,) = detect_low_and_slow_guessing(events, rules[DET_004], context)
    assert finding.evidence["failure_count"] == 11


def test_different_accounts_are_not_added_together_in_identity_mode(rules):
    events = [*slow("alice", 5), *slow("bob", 5, start=BASE_TIME + 3 * MIN, first_record=2000)]
    # One source, 2 accounts, only 10 failures: below the source threshold too.
    assert run(events, rules) == []


def test_out_of_order_and_duplicated_input_gives_the_same_finding(rules):
    events = slow()
    shuffled = events[1::2][::-1] + events[0::2] + events[:3]  # repeats must not count twice
    (a,) = run(events, rules)
    (b,) = run(shuffled, rules)
    assert a.dedup_key == b.dedup_key
    assert b.evidence["failure_record_ids"] == a.evidence["failure_record_ids"]


def test_rescan_with_more_failures_keeps_one_finding_key(rules):
    (first,) = run(slow(count=10), rules)
    (later,) = run(slow(count=12), rules)
    assert first.dedup_key == later.dedup_key
    assert later.evidence["failure_count"] == 12


def test_irregular_timing_is_reported_as_irregular(rules):
    gaps = [1, 9, 2, 7, 3, 6, 2, 8, 4]
    times = [BASE_TIME]
    for g in gaps:
        times.append(times[-1] + g * MIN)
    events = [auth_event(4625, "alice", t, 3000 + i) for i, t in enumerate(times)]
    (finding,) = run(events, rules)
    assert finding.evidence["regular_interval"] is False


def test_machine_accounts_are_ignored_by_default(rules):
    machine = slow("PC01$")
    assert run(machine, rules) == []
    including = replace(
        rules[DET_004],
        parameters={**rules[DET_004].parameters, "ignore_machine_accounts": False},
    )
    context = DetectionContext.from_events(machine, rules=rules)
    assert len(detect_low_and_slow_guessing(machine, including, context)) == 1


def test_missing_source_still_detected_by_identity(rules):
    events = slow(ip="-", workstation="-")
    (finding,) = run(events, rules)
    assert finding.evidence["source_addresses"] == []


def test_unicode_account_names(rules):
    (finding,) = run(slow("jörg"), rules)
    assert finding.evidence["account"] == "LAB\\jörg"


def test_failures_with_null_sid_join_the_account_resolved_from_a_success(rules):
    events = [
        *slow(),
        auth_event(4624, "alice", BASE_TIME + 70 * MIN, 9999, sid="S-1-5-21-1-2-3-1104"),
    ]
    (finding,) = run(events, rules)
    assert finding.evidence["identity"]["sid"] == "S-1-5-21-1-2-3-1104"


# ------------------------------------------------------------------ source mode
def test_slow_rotation_over_a_few_accounts_from_one_source(rules):
    users = ["alice", "bob", "carol"]
    events = [
        auth_event(4625, users[i % 3], BASE_TIME + i * 4 * MIN, 4000 + i, ip="2001:db8::5")
        for i in range(15)
    ]
    findings = run(events, rules)
    (finding,) = findings  # 5 per account: no identity-mode finding
    ev = finding.evidence
    assert ev["mode"] == "source" and ev["source"] == "2001:db8::5" and ev["source_type"] == "ip"
    assert ev["distinct_account_count"] == 3
    assert ev["accounts"] == ["LAB\\alice", "LAB\\bob", "LAB\\carol"]
    assert ev["failure_count"] == 15


def test_single_account_source_is_reported_once_by_identity_mode(rules):
    findings = run(slow(count=15, every=4 * MIN), rules)
    assert [f.evidence["mode"] for f in findings] == ["identity"]


def test_source_mode_does_not_repeat_a_det002_spray(rules):
    users = ["u1", "u2", "u3", "u4", "u5"]
    spray = [  # 5 accounts in 5 minutes: DET-002
        auth_event(4625, u, BASE_TIME + i * MIN, 5000 + i, ip="203.0.113.9")
        for i, u in enumerate(users)
    ]
    trickle = [  # then 10 more failures over 2 accounts, slowly
        auth_event(
            4625, users[i % 2], BASE_TIME + 40 * MIN + i * 5 * MIN, 5100 + i, ip="203.0.113.9"
        )
        for i in range(10)
    ]
    assert run([*spray, *trickle], rules) == []  # 10 uncovered < 15
    more = [
        auth_event(
            4625, users[i % 2], BASE_TIME + 40 * MIN + i * 3 * MIN, 5200 + i, ip="203.0.113.9"
        )
        for i in range(15)
    ]
    findings = run([*spray, *more], rules)
    sources = [f for f in findings if f.evidence["mode"] == "source"]
    assert len(sources) == 1
    assert not set(sources[0].evidence["failure_record_ids"]) & {5000, 5001, 5002, 5003, 5004}


def test_events_without_a_source_are_not_grouped_by_source(rules):
    users = ["alice", "bob", "carol"]
    events = [
        auth_event(4625, users[i % 3], BASE_TIME + i * 4 * MIN, 6000 + i, ip="-", workstation="-")
        for i in range(15)
    ]
    assert run(events, rules) == []


# ------------------------------------------------------------------ whole engine
def test_run_detections_includes_det004_without_duplicating_det001(rules):
    fast = failures("alice", 6, BASE_TIME, 10 * SEC, 500)
    later = slow(count=10, every=5 * MIN, start=BASE_TIME + 6 * MIN)
    rule_ids = sorted(d.rule_id for d in run_detections([*fast, *later], rules))
    assert rule_ids == ["DET-001", "DET-004"]


def test_successful_logons_are_never_counted(rules):
    events = [auth_event(4624, "alice", BASE_TIME + i * 6 * MIN, 7000 + i) for i in range(12)]
    assert run(events, rules) == []
