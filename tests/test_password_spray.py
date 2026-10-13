"""DET-002 Password Spray: one source, many distinct accounts."""

from datetime import timedelta

from moesoc.engine.rules import detect_multiple_failed_logins, detect_password_spray

from .conftest import BASE_TIME, auth_event

SEC = timedelta(seconds=1)
MIN = timedelta(minutes=1)
USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace"]


def spray(users, start=BASE_TIME, every=MIN, first_record=3000, **kw):
    return [
        auth_event(4625, user, start + i * every, first_record + i, **kw)
        for i, user in enumerate(users)
    ]


def test_triggers_at_threshold_distinct_accounts(rules):
    (detection,) = detect_password_spray(spray(USERS[:5]), rules["DET-002"])
    ev = detection.evidence
    assert detection.rule_id == "DET-002"
    assert ev["source"] == "192.0.2.45"
    assert ev["distinct_account_count"] == 5
    assert ev["accounts"] == ["LAB\\alice", "LAB\\bob", "LAB\\carol", "LAB\\dave", "LAB\\erin"]
    assert ev["failure_record_ids"] == [3000, 3001, 3002, 3003, 3004]
    assert [m.technique_id for m in detection.rule.mitre] == ["T1110.003"]


def test_below_threshold_does_not_trigger(rules):
    assert detect_password_spray(spray(USERS[:4]), rules["DET-002"]) == []


def test_window_boundary_inclusive_and_exclusive(rules):
    inside = spray(USERS[:5], every=timedelta(minutes=7, seconds=30))  # 30:00 span
    outside = spray(USERS[:5], every=timedelta(minutes=7, seconds=31))  # 30:04 span
    assert len(detect_password_spray(inside, rules["DET-002"])) == 1
    assert detect_password_spray(outside, rules["DET-002"]) == []


def test_brute_force_on_one_account_is_not_a_spray(rules):
    events = spray(["alice"] * 10, every=10 * SEC)
    assert detect_password_spray(events, rules["DET-002"]) == []
    assert len(detect_multiple_failed_logins(events, rules["DET-001"])) == 1


def test_case_variants_count_as_one_account(rules):
    events = spray(["alice", "ALICE", "Alice", "bob", "carol", "dave"])
    assert detect_password_spray(events, rules["DET-002"]) == []


def test_same_name_in_verified_domains_counts_as_distinct_accounts(rules):
    domains = ["CORP", "PC01", "PC02", "PC03", "PC04"]
    # Each domain is a proven authority: an account of it logged on successfully.
    proof = [
        auth_event(4624, "svc", BASE_TIME - MIN, 2900 + i, domain=d, sid=f"S-1-5-21-{i}-1-1-1001")
        for i, d in enumerate(domains)
    ]
    events = proof + [
        auth_event(4625, "admin", BASE_TIME + i * MIN, 3000 + i, domain=d)
        for i, d in enumerate(domains)
    ]
    (finding,) = detect_password_spray(events, rules["DET-002"])
    assert finding.evidence["distinct_account_count"] == 5


def test_one_name_with_unverified_claimed_domains_is_not_a_spray(rules):
    # Audit bug A-2: the domain in 4625 is client text; five made-up domains for one user
    # name do not prove five accounts.
    events = [
        auth_event(4625, "admin", BASE_TIME + i * MIN, 3000 + i, domain=d)
        for i, d in enumerate(["CORP", "x1", "x2", "x3", "x4"])
    ]
    assert detect_password_spray(events, rules["DET-002"]) == []


def test_different_sources_are_not_combined(rules):
    events = spray(USERS[:3], ip="198.51.100.1") + spray(
        USERS[3:6], ip="198.51.100.2", first_record=4000
    )
    assert detect_password_spray(events, rules["DET-002"]) == []


def test_ipv4_mapped_ipv6_is_the_same_source(rules):
    events = spray(USERS[:3], ip="198.51.100.1") + spray(
        USERS[3:5], ip="::ffff:198.51.100.1", first_record=4000, start=BASE_TIME + 5 * MIN
    )
    assert len(detect_password_spray(events, rules["DET-002"])) == 1


def test_workstation_used_when_ip_missing(rules):
    (detection,) = detect_password_spray(
        spray(USERS[:5], ip="-", workstation="KIOSK7"), rules["DET-002"]
    )
    assert detection.evidence["source"] == "workstation:kiosk7"
    assert detection.evidence["source_type"] == "workstation"


def test_failures_without_any_source_are_skipped(rules):
    assert detect_password_spray(spray(USERS[:5], ip="-", workstation="-"), rules["DET-002"]) == []


def test_unknown_accounts_are_counted_as_enumeration_hint(rules):
    events = spray(USERS[:5], sub_status="0xC0000064")
    detection = detect_password_spray(events, rules["DET-002"])[0]
    assert detection.evidence["accounts_not_found"] == 5
    assert detection.evidence["failure_reasons"] == {"Account does not exist": 5}


def test_long_spray_is_one_finding(rules):
    users = [f"user{i:02d}" for i in range(40)]
    (detection,) = detect_password_spray(spray(users, every=20 * SEC), rules["DET-002"])
    assert detection.evidence["distinct_account_count"] == 40


def test_out_of_order_input(rules):
    events = list(reversed(spray(USERS[:5])))
    assert len(detect_password_spray(events, rules["DET-002"])) == 1


def test_duplicate_events_do_not_inflate_distinct_accounts(rules):
    events = spray(USERS[:4])
    assert detect_password_spray(events + events, rules["DET-002"]) == []
