"""Account identity must never merge different accounts that share a username."""

from datetime import timedelta

import pytest

from moesoc.core.identity import (
    IdentityBasis,
    IdentityResolver,
    build_identity,
    is_reliable_sid,
)
from moesoc.engine.correlation import correlate_failed_then_success
from moesoc.engine.rules import detect_multiple_failed_logins

from .conftest import BASE_TIME, auth_event, failures

SEC = timedelta(seconds=1)
MIN = timedelta(minutes=1)
HOST = "PC01.corp.example"
USER_SID = "S-1-5-21-1111111111-2222222222-3333333333-1104"


# ------------------------------------------------------------------ identity keys
def test_same_username_different_domain_are_different_identities():
    corp = build_identity("admin", "CORP", None, HOST)
    local = build_identity("admin", "PC01", None, HOST)
    assert corp.key != local.key
    assert corp.display == "CORP\\admin"
    assert local.display == "PC01\\admin"


def test_case_differences_are_the_same_identity():
    assert (
        build_identity("Alice", "LAB", None, HOST).key
        == build_identity("ALICE", "lab", None, HOST).key
    )


def test_unicode_usernames_compare_case_insensitively():
    upper = build_identity("MÜLLER", "LAB", None, HOST)
    lower = build_identity("müller", "LAB", None, HOST)
    assert upper.key == lower.key
    assert upper.display == "LAB\\MÜLLER"  # display keeps original casing


def test_missing_domain_scopes_account_to_host():
    identity = build_identity("alice", None, None, HOST)
    assert identity.basis is IdentityBasis.HOST_ACCOUNT
    assert identity.display == "PC01\\alice"
    assert identity.key != build_identity("alice", None, None, "PC02.corp.example").key


def test_dot_domain_means_this_computer():
    assert (
        build_identity("alice", ".", None, HOST).key
        == build_identity("alice", "PC01", None, HOST).key
    )


def test_username_only_is_last_resort():
    identity = build_identity("alice", None, None, None)
    assert identity.basis is IdentityBasis.USERNAME_ONLY


def test_reliable_sid_is_preferred():
    identity = build_identity("alice", "LAB", USER_SID, HOST)
    assert identity.basis is IdentityBasis.SID
    assert identity.key == f"sid:{USER_SID}"


@pytest.mark.parametrize("sid", [None, "", "-", "S-1-0-0", "garbage"])
def test_null_or_missing_sid_is_not_used(sid):
    assert not is_reliable_sid(sid)
    assert build_identity("alice", "LAB", sid, HOST).basis is IdentityBasis.DOMAIN_ACCOUNT


def test_machine_account_is_flagged():
    assert build_identity("PC01$", "CORP", None, HOST).is_machine_account
    assert not build_identity("alice", "CORP", None, HOST).is_machine_account


def test_system_and_anonymous_are_well_known():
    system = build_identity("SYSTEM", "NT AUTHORITY", "S-1-5-18", HOST)
    anonymous = build_identity("ANONYMOUS LOGON", "NT AUTHORITY", "S-1-5-7", HOST)
    assert system.is_well_known and anonymous.is_well_known
    assert system.key != anonymous.key


def test_no_username_and_no_sid_has_no_identity():
    assert build_identity(None, "LAB", None, HOST) is None
    assert build_identity(None, None, "S-1-0-0", HOST) is None


# ------------------------------------------------------------------ resolver
def test_resolver_links_failure_without_sid_to_success_sid():
    failure = auth_event(4625, "alice", BASE_TIME, 1)  # NULL SID, as Windows records it
    success = auth_event(4624, "Alice", BASE_TIME + MIN, 2, sid=USER_SID)
    resolver = IdentityResolver([failure, success])
    assert resolver.target(failure).key == resolver.target(success).key == f"sid:{USER_SID}"
    assert resolver.target(failure).resolved_from_name is True


def test_resolver_does_not_link_ambiguous_names():
    # One name, two SIDs (account deleted and re-created): never merged by name.
    a = auth_event(4624, "alice", BASE_TIME, 1, sid=USER_SID)
    b = auth_event(4624, "alice", BASE_TIME + MIN, 2, sid=USER_SID[:-4] + "2001")
    failure = auth_event(4625, "alice", BASE_TIME + 2 * MIN, 3)
    resolver = IdentityResolver([a, b, failure])
    assert resolver.target(failure).basis is IdentityBasis.DOMAIN_ACCOUNT


def test_resolver_does_not_link_across_domains():
    failure = auth_event(4625, "admin", BASE_TIME, 1, domain="CORP")
    success = auth_event(4624, "admin", BASE_TIME + MIN, 2, domain="PC01", sid=USER_SID)
    resolver = IdentityResolver([failure, success])
    assert resolver.target(failure).key != resolver.target(success).key


# ------------------------------------------------------------------ detections
def test_det001_does_not_merge_domain_and_local_accounts(rules):
    events = failures("admin", 3, BASE_TIME, 10 * SEC, domain="CORP") + failures(
        "admin", 3, BASE_TIME, 10 * SEC, first_record=2000, domain="PC01"
    )
    assert detect_multiple_failed_logins(events, rules["DET-001"]) == []


def test_det001_evidence_records_identity(rules):
    events = failures("admin", 5, BASE_TIME, 10 * SEC, domain="CORP")
    (detection,) = detect_multiple_failed_logins(events, rules["DET-001"])
    assert detection.account == "CORP\\admin"
    assert detection.evidence["identity"]["basis"] == "domain_account"


def test_cor001_does_not_correlate_across_domains(rules):
    events = failures("admin", 5, BASE_TIME, 10 * SEC, domain="CORP")
    events.append(auth_event(4624, "admin", BASE_TIME + 2 * MIN, 1100, domain="PC01"))
    assert correlate_failed_then_success(events, rules["COR-001"]) == []


def test_cor001_links_null_sid_failures_to_sid_success(rules):
    events = failures("alice", 5, BASE_TIME, 10 * SEC)
    events.append(auth_event(4624, "alice", BASE_TIME + 2 * MIN, 1100, sid=USER_SID))
    (detection,) = correlate_failed_then_success(events, rules["COR-001"])
    assert detection.evidence["identity"]["sid"] == USER_SID
    assert detection.evidence["identity"]["sid_resolved_from_name"] is False  # success had it


def test_cor001_host_scoped_accounts_on_different_hosts_do_not_match(rules):
    events = failures("alice", 5, BASE_TIME, 10 * SEC, domain="-", host="PC01")
    events.append(auth_event(4624, "alice", BASE_TIME + 2 * MIN, 1100, domain="-", host="PC02"))
    assert correlate_failed_then_success(events, rules["COR-001"]) == []


# ------------------------------------------------------------------ audit A-11
def test_account_names_fold_like_windows_not_like_casefold():
    from moesoc.core.domains import fold_name

    def same(a, b):
        return build_identity(a, "LAB", None, HOST).key == build_identity(b, "LAB", None, HOST).key

    # Windows has no 1:1 uppercase for "ß": Straße and STRASSE are different accounts.
    assert not same("Straße", "STRASSE")
    assert same("straße", "STRAßE")
    assert same("José", "JOSÉ") and same("Ölçer", "ÖLÇER")
    assert same("σοφία", "ΣΟΦΊΑ")
    assert not same("KelvinK", "kelvink")  # the Kelvin sign is not the letter K
    assert fold_name("  Alice ") == "alice"  # ASCII keys stay lower-case
