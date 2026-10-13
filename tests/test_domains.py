"""Domain aliases: CORP and corp.local merge only with evidence, never by spelling."""

from dataclasses import replace
from datetime import timedelta

from moesoc.collectors.hostinfo import aliases_from_names
from moesoc.core.domains import (
    REASON_DOMAIN_SID,
    REASON_LOCAL_CONFIG,
    DomainAlias,
    DomainMap,
    authority_sid,
)
from moesoc.core.identity import IdentityBasis, IdentityResolver, build_identity
from moesoc.engine.context import DetectionContext
from moesoc.engine.correlation import correlate_failed_then_success
from moesoc.engine.rules import detect_multiple_failed_logins
from moesoc.engine.scanner import ScanService, run_detections
from moesoc.storage.repository import DetectionRepository
from moesoc.utils.time import utc_now

from .conftest import BASE_TIME, FakeReader, auth_event, auth_xml, failures

SEC = timedelta(seconds=1)
HOST = "PC01.corp.local"
CORP = "S-1-5-21-1111111111-2222222222-3333333333"  # domain authority
OTHER = "S-1-5-21-4444444444-5555555555-6666666666"  # another domain
PC01 = "S-1-5-21-7777777777-8888888888-9999999999"  # PC01's local accounts


def success(user, domain, sid, record, at=BASE_TIME + 30 * SEC, **kw):
    return auth_event(4624, user, at, record, domain=domain, sid=sid, host=HOST, **kw)


def evidence_events():
    """Two different CORP accounts, recorded under both spellings, same authority."""
    return [
        success("svc-backup", "CORP", f"{CORP}-1201", 9001),
        success("svc-web", "corp.local", f"{CORP}-1202", 9002),
    ]


# ------------------------------------------------------------------ authority SID
def test_authority_sid_is_the_account_sid_without_its_rid():
    assert authority_sid(f"{CORP}-1104") == CORP
    assert authority_sid(f"{CORP.lower()}-500") is not None


def test_authority_sid_ignores_well_known_and_invalid_sids():
    for sid in ("S-1-5-18", "S-1-0-0", "S-1-5-32-544", "S-1-5-21-1-2", "", None, "garbage"):
        assert authority_sid(sid) is None


# ------------------------------------------------------------------ learning aliases
def test_no_evidence_keeps_netbios_and_dns_names_apart():
    events = [success("alice", "CORP", None, 1), success("alice", "corp.local", None, 2)]
    domains = DomainMap.from_events(events)
    assert not domains.same("CORP", "corp.local")
    corp = build_identity("admin", "CORP", None, HOST, domains)
    dns = build_identity("admin", "corp.local", None, HOST, domains)
    assert corp.key != dns.key


def test_spelling_alone_never_creates_an_alias():
    # Even names that "look" related stay separate without SID evidence.
    domains = DomainMap.from_events(
        [success("a", "CORP", None, 1), success("b", "corp.example", None, 2)]
    )
    assert domains.links == ()
    assert domains.canonical("corp.example") == "corp.example"


def test_shared_authority_sid_proves_the_alias():
    domains = DomainMap.from_events(evidence_events())
    assert domains.same("CORP", "corp.local")
    assert domains.same("corp", "CORP.LOCAL")  # case-insensitive
    assert domains.canonical("corp.local") == "corp"  # NetBIOS form is the representative
    (link,) = domains.links
    assert link.reason == REASON_DOMAIN_SID and link.detail == CORP


def test_different_authorities_are_not_aliased():
    domains = DomainMap.from_events(
        [success("a", "CORP", f"{CORP}-1201", 1), success("b", "corp.local", f"{OTHER}-1202", 2)]
    )
    assert not domains.same("CORP", "corp.local")


def test_name_seen_with_two_authorities_is_ambiguous_and_never_aliased():
    events = [
        *evidence_events(),
        success("x", "CORP", f"{OTHER}-1300", 3),  # CORP now points at two authorities
    ]
    domains = DomainMap.from_events(events)
    assert "corp" in domains.ambiguous
    assert not domains.same("CORP", "corp.local")


def test_alias_learning_is_order_independent():
    forward = DomainMap.from_events(evidence_events())
    backward = DomainMap.from_events(list(reversed(evidence_events())))
    assert forward.canonical("corp.local") == backward.canonical("corp.local") == "corp"


def test_subject_fields_also_provide_evidence():
    event = success("alice", "CORP", f"{CORP}-1104", 1)
    event = replace(event, subject_domain="corp.local", subject_user_sid=f"{CORP}-500")
    assert DomainMap.from_events([event]).same("CORP", "corp.local")


def test_system_and_other_well_known_sids_prove_nothing():
    # SYSTEM is written as NT AUTHORITY\SYSTEM and as WORKGROUP\PC01$, both S-1-5-18.
    a = success("SYSTEM", "NT AUTHORITY", "S-1-5-18", 1, logon_type=5)
    b = replace(
        success("alice", "PC01", f"{PC01}-1001", 2),
        subject_username="PC01$",
        subject_domain="WORKGROUP",
        subject_user_sid="S-1-5-18",
    )
    domains = DomainMap.from_events([a, b])
    assert not domains.same("NT AUTHORITY", "WORKGROUP")


def test_renamed_computer_keeps_its_machine_authority():
    domains = DomainMap.from_events(
        [success("alice", "OLD-PC", f"{PC01}-1001", 1), success("bob", "PC01", f"{PC01}-1002", 2)]
    )
    assert domains.same("OLD-PC", "PC01")


def test_unicode_domain_names_alias_case_insensitively():
    domains = DomainMap.from_events(
        [
            success("a", "MÜNCHEN", f"{CORP}-1201", 1),
            success("b", "münchen.local", f"{CORP}-1202", 2),
        ]
    )
    assert domains.same("München", "MÜNCHEN.LOCAL")
    assert (
        build_identity("Jörg", "MÜNCHEN", None, HOST, domains).key
        == build_identity("JÖRG", "münchen.local", None, HOST, domains).key
    )


# ------------------------------------------------------------------ identities
def test_corp_admin_and_local_admin_stay_separate_with_aliases_known():
    domains = DomainMap.from_events(
        [*evidence_events(), success("admin", "PC01", f"{PC01}-500", 3)]
    )
    corp = build_identity("admin", "CORP", None, HOST, domains)
    dns = build_identity("admin", "corp.local", None, HOST, domains)
    local = build_identity("admin", "PC01", None, HOST, domains)
    assert corp.key == dns.key
    assert local.key != corp.key


def test_aliased_identity_explains_the_alias_and_keeps_the_recorded_spelling():
    domains = DomainMap.from_events(evidence_events())
    identity = build_identity("admin", "corp.local", None, HOST, domains)
    assert identity.display == "corp.local\\admin"
    evidence = identity.as_evidence()
    assert evidence["domain_aliases"] and REASON_DOMAIN_SID in evidence["domain_aliases"][0]
    # The representative spelling explains the group too.
    assert build_identity("admin", "CORP", None, HOST, domains).domain_aliases
    # Unaliased identities carry no extra field (stable evidence for old findings).
    assert "domain_aliases" not in build_identity("bob", "LAB", None, HOST, domains).as_evidence()


def test_null_sid_failures_link_to_sid_across_spellings_only_with_evidence():
    failure = auth_event(4625, "admin", BASE_TIME, 1, domain="corp.local", host=HOST)
    with_evidence = IdentityResolver(
        [*evidence_events(), success("admin", "CORP", f"{CORP}-500", 2), failure]
    )
    linked = with_evidence.target(failure)
    assert linked.basis is IdentityBasis.SID and linked.sid == f"{CORP}-500"
    assert linked.resolved_from_name

    without = IdentityResolver([success("admin", "CORP", f"{CORP}-500", 2), failure])
    assert without.target(failure).basis is IdentityBasis.DOMAIN_ACCOUNT


def test_machine_account_is_not_the_user_with_the_same_name():
    machine = build_identity("PC01$", "CORP", None, HOST)
    user = build_identity("PC01", "CORP", None, HOST)
    assert machine.is_machine_account and not user.is_machine_account
    assert machine.key != user.key


def test_system_identity_is_keyed_by_sid_whatever_the_localized_authority_name():
    english = build_identity("SYSTEM", "NT AUTHORITY", "S-1-5-18", HOST)
    german = build_identity("SYSTEM", "NT-AUTORITÄT", "S-1-5-18", HOST)
    assert english.key == german.key == "sid:S-1-5-18"
    assert english.is_well_known


# ------------------------------------------------------------------ local configuration
def test_local_configuration_pairs_netbios_and_dns_names():
    aliases = aliases_from_names("CORP", "corp.local", "PC01", "PC01.corp.local")
    assert {(a.first, a.second) for a in aliases} == {
        ("CORP", "corp.local"),
        ("PC01", "PC01.corp.local"),
    }
    assert all(a.reason == REASON_LOCAL_CONFIG for a in aliases)


def test_local_configuration_skips_missing_or_identical_names():
    assert aliases_from_names(None, None, "PC01", "PC01") == []
    assert aliases_from_names("CORP", "", "PC01", None) == []


def test_local_configuration_seeds_the_map_but_not_ambiguous_names():
    seed = [DomainAlias("CORP", "corp.local", REASON_LOCAL_CONFIG)]
    assert DomainMap.from_events([], seed).same("CORP", "corp.local")
    conflicting = [
        success("a", "CORP", f"{CORP}-1", 1),
        success("b", "CORP", f"{OTHER}-2", 2),
    ]
    assert not DomainMap.from_events(conflicting, seed).same("CORP", "corp.local")


# ------------------------------------------------------------------ detections
def test_det001_counts_failures_across_proven_spellings():
    events = [
        *evidence_events(),
        *failures("admin", 3, BASE_TIME, 10 * SEC, 100, domain="CORP", host=HOST),
        *failures("admin", 3, BASE_TIME + 30 * SEC, 10 * SEC, 200, domain="corp.local", host=HOST),
    ]
    rule = _rules()["DET-001"]
    context = DetectionContext.from_events(events)
    (finding,) = detect_multiple_failed_logins(events, rule, context)
    assert finding.evidence["failure_count"] == 6
    assert "domain_aliases" in finding.evidence["identity"]
    assert set(finding.evidence["account_spellings"]) == {"CORP\\admin", "corp.local\\admin"}


def test_det001_does_not_merge_spellings_without_evidence():
    events = [
        *failures("admin", 3, BASE_TIME, 10 * SEC, 100, domain="CORP", host=HOST),
        *failures("admin", 3, BASE_TIME + 30 * SEC, 10 * SEC, 200, domain="corp.local", host=HOST),
    ]
    rule = _rules()["DET-001"]
    assert detect_multiple_failed_logins(events, rule, DetectionContext.from_events(events)) == []


def test_cor001_links_dns_spelled_failures_to_netbios_spelled_success():
    events = [
        *evidence_events(),
        *failures("admin", 5, BASE_TIME, 10 * SEC, 100, domain="corp.local", host=HOST),
        success("admin", "CORP", f"{CORP}-500", 300, at=BASE_TIME + 90 * SEC, logon_type=10),
    ]
    rule = _rules()["COR-001"]
    (finding,) = correlate_failed_then_success(events, rule, DetectionContext.from_events(events))
    assert finding.evidence["failure_count"] == 5


def test_run_detections_uses_known_local_aliases():
    events = [
        *failures("admin", 5, BASE_TIME, 10 * SEC, 100, domain="corp.local", host=HOST),
        success("admin", "CORP", f"{CORP}-500", 300, at=BASE_TIME + 90 * SEC, logon_type=10),
    ]
    rules = _rules()
    without = {d.rule_id for d in run_detections(events, rules)}
    seeded = {
        d.rule_id
        for d in run_detections(
            events, rules, [DomainAlias("CORP", "corp.local", REASON_LOCAL_CONFIG)]
        )
    }
    assert "COR-001" not in without
    assert "COR-001" in seeded


def test_scan_service_passes_this_computers_aliases(config, database, rules):
    start = utc_now() - timedelta(hours=1)
    xml = [
        auth_xml(4625, "admin", start + i * 10 * SEC, 700 + i, domain="corp.local", host=HOST)
        for i in range(5)
    ]
    xml.append(
        auth_xml(
            4624,
            "admin",
            start + 90 * SEC,
            800,
            domain="CORP",
            sid=f"{CORP}-500",
            host=HOST,
            logon_type=10,
        )
    )
    service = ScanService(
        config,
        database,
        rules,
        reader_factory=lambda: FakeReader(xml),
        host_aliases=lambda: [DomainAlias("CORP", "corp.local", REASON_LOCAL_CONFIG)],
    )
    service.run_live_scan()
    with database.connect() as conn:
        rule_ids = {d.rule_id for d in DetectionRepository(conn).list_all()}
    assert {"COR-001", "DET-001"} <= rule_ids


def _rules():
    from moesoc.engine.rules import load_rules

    from .conftest import RULES_DIR

    return load_rules(RULES_DIR)
