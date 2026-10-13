"""A-2: the domain in a failed logon (4625) is client-supplied text, not an authority.

Audit reproduction (2026-10-08): six failures for one local user from one address, each
with a different TargetDomainName (LAB, x1 … x5). DET-001 did not fire (six identity
keys) and DET-002 reported a "spray" against five accounts.
"""

from datetime import timedelta

from moesoc.core.domains import DomainMap
from moesoc.core.identity import (
    RESOLVED_LOCAL,
    RESOLVED_UNVERIFIED,
    RESOLVED_VERIFIED,
    IdentityBasis,
    IdentityResolver,
)
from moesoc.engine.context import DetectionContext
from moesoc.engine.correlation import correlate_failed_then_success
from moesoc.engine.rules import detect_multiple_failed_logins, detect_password_spray
from moesoc.engine.scanner import ScanService, run_detections
from moesoc.storage.repository import DetectionRepository

from .conftest import BASE_TIME, auth_event, auth_xml

SEC = timedelta(seconds=1)
MIN = timedelta(minutes=1)
HOST = "WS-LAB01.lab.example"
LOCAL_AUTHORITY = "S-1-5-21-7777777777-8888888888-9999999999"
DOMAIN_AUTHORITY = "S-1-5-21-1111111111-2222222222-3333333333"
OTHER_AUTHORITY = "S-1-5-21-4444444444-5555555555-6666666666"
AUDIT_DOMAINS = ["LAB", "x1", "x2", "x3", "x4", "x5"]


def fail(user, domain, i, host=HOST, ip="203.0.113.66"):
    return auth_event(
        4625, user, BASE_TIME + i * 10 * SEC, 100 + i, domain=domain, ip=ip, host=host
    )


def local_success(user="owner", record=50, host=HOST):
    """A successful logon of a LOCAL account: evidence this computer uses its own SAM."""
    return auth_event(
        4624,
        user,
        BASE_TIME - MIN,
        record,
        domain="WS-LAB01",
        sid=f"{LOCAL_AUTHORITY}-1001",
        host=host,
        logon_type=2,
    )


def ctx(events, rules=None, standalone=()):
    return DetectionContext.from_events(events, rules=rules or {}, standalone_hosts=standalone)


def keys(events, standalone=()):
    resolver = IdentityResolver(events, ctx(events, standalone=standalone).domains)
    return [resolver.target(e).key for e in events if e.event_id == 4625]


# ------------------------------------------------------------------ the audit probe
def test_audit_probe_on_a_standalone_computer_fires_det001_and_no_spray(rules):
    events = [fail("alice", d, i) for i, d in enumerate(AUDIT_DOMAINS)]
    context = ctx(events, rules, standalone=["WS-LAB01"])  # this computer's configuration
    (finding,) = detect_multiple_failed_logins(events, rules["DET-001"], context)
    assert finding.evidence["failure_count"] == 6
    assert finding.evidence["claimed_domains"] == AUDIT_DOMAINS
    assert finding.evidence["identity"]["claimed_domain_verified"] is False
    assert "local account" in finding.evidence["identity"]["resolution"]
    assert detect_password_spray(events, rules["DET-002"], context) == []


def test_audit_probe_with_event_evidence_of_local_accounts_only(rules):
    events = [local_success(), *(fail("alice", d, i) for i, d in enumerate(AUDIT_DOMAINS))]
    found = {d.rule_id for d in run_detections(events, rules)}
    assert "DET-001" in found and "DET-002" not in found


def test_audit_probe_through_the_scanner_with_local_configuration(config, database, rules):
    xml = [
        auth_xml(4625, "alice", BASE_TIME + i * 10 * SEC, 100 + i, domain=d, ip="203.0.113.66")
        for i, d in enumerate(AUDIT_DOMAINS)
    ]
    service = ScanService(
        config, database, rules, host_aliases=list, standalone_hosts=lambda: ["WS-LAB01"]
    )
    service.ingest_live(xml)
    with database.connect() as conn:
        found = sorted(d.rule_id for d in DetectionRepository(conn).list_all())
    assert found == ["DET-001"]


def test_unknown_authority_keeps_claims_apart_but_does_not_inflate_spray(rules):
    # An imported export of an unknown computer: no SIDs, no configuration. MoeSOC does not
    # guess that the claims are local, but five claims for one name are not five accounts.
    events = [fail("alice", d, i) for i, d in enumerate(AUDIT_DOMAINS)]
    assert len(set(keys(events))) == 6
    assert detect_password_spray(events, rules["DET-002"], ctx(events, rules)) == []


# ------------------------------------------------------------------ local account forms
def test_empty_dot_dash_and_host_name_domains_are_one_local_identity():
    events = [fail("alice", d, i) for i, d in enumerate(["", ".", "-", "WS-LAB01", "ws-lab01"])]
    assert len(set(keys(events))) == 1
    resolver = IdentityResolver(events)
    assert resolver.target(events[0]).resolution == RESOLVED_LOCAL
    assert resolver.target(events[0]).basis is IdentityBasis.HOST_ACCOUNT


def test_fqdn_of_the_computer_is_the_local_account():
    events = [fail("alice", HOST, 0), fail("alice", "WS-LAB01", 1)]
    assert len(set(keys(events))) == 1


def test_arbitrary_claimed_domains_merge_only_with_standalone_evidence():
    events = [fail("alice", d, i) for i, d in enumerate(AUDIT_DOMAINS)]
    assert len(set(keys(events, standalone=["WS-LAB01"]))) == 1
    assert len(set(keys([local_success(), *events]))) == 1  # evidence: local accounts only
    assert len(set(keys(events))) == 6  # no evidence either way: not guessed


def test_local_failures_link_to_the_local_success_sid(rules):
    events = [fail("alice", d, i) for i, d in enumerate(["x1", "", "x2", "WS-LAB01", "x3"])]
    events.append(
        auth_event(
            4624,
            "alice",
            BASE_TIME + 2 * MIN,
            900,
            domain="WS-LAB01",
            sid=f"{LOCAL_AUTHORITY}-1002",
            ip="203.0.113.66",
        )
    )
    (finding,) = correlate_failed_then_success(events, rules["COR-001"], ctx(events, rules))
    assert finding.evidence["identity"]["sid"] == f"{LOCAL_AUTHORITY}-1002"


# ------------------------------------------------------------------ domains stay apart
def test_two_verified_domains_with_the_same_user_name_stay_separate(rules):
    events = [
        auth_event(4624, "svc", BASE_TIME - MIN, 60, domain="CORP", sid=f"{DOMAIN_AUTHORITY}-1201"),
        auth_event(4624, "svc", BASE_TIME - MIN, 61, domain="OTHER", sid=f"{OTHER_AUTHORITY}-1201"),
        *(fail("admin", "CORP", i) for i in range(3)),
        *(fail("admin", "OTHER", i + 3) for i in range(3)),
    ]
    assert len(set(keys(events, standalone=["WS-LAB01"]))) == 2
    assert detect_multiple_failed_logins(events, rules["DET-001"], ctx(events, rules)) == []


def test_verified_domain_never_merges_with_an_unverified_claim():
    events = [
        auth_event(4624, "svc", BASE_TIME - MIN, 60, domain="CORP", sid=f"{DOMAIN_AUTHORITY}-1201"),
        fail("admin", "CORP", 0),
        fail("admin", "OTHER", 1),
    ]
    resolver = IdentityResolver(events, ctx(events).domains)
    corp, other = (resolver.target(e) for e in events[1:])
    assert corp.key != other.key
    assert corp.resolution == RESOLVED_VERIFIED
    assert other.resolution == RESOLVED_UNVERIFIED


def test_a_domain_member_is_never_treated_as_standalone():
    # Local AND domain authorities on one computer: claims are not resolved to local.
    events = [
        local_success(),
        auth_event(4624, "bob", BASE_TIME - MIN, 51, domain="CORP", sid=f"{DOMAIN_AUTHORITY}-1104"),
        fail("admin", "x1", 0),
    ]
    domains = ctx(events, standalone=["WS-LAB01"]).domains
    assert domains.standalone_reason("WS-LAB01") is None
    assert IdentityResolver(events, domains).target(events[-1]).resolution == RESOLVED_UNVERIFIED


def test_entra_id_accounts_prevent_standalone_resolution():
    entra = auth_event(
        4624,
        "user@contoso.com",
        BASE_TIME - MIN,
        52,
        domain="AzureAD",
        sid="S-1-12-1-111-222-333-444",
    )
    domains = DomainMap.from_events([local_success(), entra], standalone_hosts=["WS-LAB01"])
    assert domains.standalone_reason("WS-LAB01") is None


def test_netbios_and_fqdn_merge_only_with_sid_proof():
    proven = [
        auth_event(4624, "a", BASE_TIME, 70, domain="CORP", sid=f"{DOMAIN_AUTHORITY}-1201"),
        auth_event(4624, "b", BASE_TIME, 71, domain="corp.local", sid=f"{DOMAIN_AUTHORITY}-1202"),
        fail("admin", "CORP", 0),
        fail("admin", "corp.local", 1),
    ]
    assert len(set(keys(proven))) == 1
    unproven = [fail("admin", "CORP", 0), fail("admin", "corp.local", 1)]
    assert len(set(keys(unproven))) == 2


def test_standalone_facts_apply_only_to_that_computer():
    events = [fail("alice", d, i, host="PC02.other.example") for i, d in enumerate(["x1", "x2"])]
    assert len(set(keys(events, standalone=["WS-LAB01"]))) == 2


# ------------------------------------------------------------------ unchanged cases
def test_reliable_sid_wins_over_any_claimed_domain():
    event = auth_event(4625, "alice", BASE_TIME, 1, domain="x9", sid=f"{LOCAL_AUTHORITY}-1001")
    identity = IdentityResolver([event]).target(event)
    assert identity.key == f"sid:{LOCAL_AUTHORITY}-1001" and identity.resolution is None


def test_null_sid_failure_upgrades_to_the_sid_of_its_local_success():
    events = [fail("alice", "", 0), local_success("alice", record=80)]
    resolver = IdentityResolver(events)
    assert resolver.target(events[0]).key == f"sid:{LOCAL_AUTHORITY}-1001"
    assert resolver.target(events[0]).resolved_from_name is True


def test_machine_and_system_accounts():
    machine = fail("WS-LAB01$", "LAB", 0)
    assert IdentityResolver([machine]).target(machine).is_machine_account
    system = auth_event(4624, "SYSTEM", BASE_TIME, 2, domain="NT AUTHORITY", sid="S-1-5-18")
    assert IdentityResolver([system]).target(system).key == "sid:S-1-5-18"


def test_case_differences_are_one_identity():
    events = [fail("Alice", "ws-lab01", 0), fail("ALICE", "WS-LAB01", 1)]
    assert len(set(keys(events))) == 1
