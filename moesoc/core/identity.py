"""Account identity for authentication correlation.

Two events belong to the same account only if their *identity keys* match.
Preference order (most to least reliable):

1. SID — a Windows security identifier is unique per account and survives renames.
   The NULL SID ``S-1-0-0`` (written in 4625 when the account is unknown) is not usable.
2. DOMAIN\\user — case-insensitive. ``CORP\\admin`` and ``PC01\\admin`` stay separate.
   A domain of ``.`` means "this computer" and is replaced by the host name.
   ``CORP`` and ``corp.local`` are the same domain only when a ``DomainMap`` has
   evidence for it (shared authority SID or this computer's configuration).
3. HOST\\user — when no domain was recorded, the account is scoped to the computer
   that logged the event (a local-account context).
4. user — last resort, only when neither domain nor host is known.

4625 rarely carries a usable SID, while the matching 4624 does. ``IdentityResolver``
links them: a name-only identity is upgraded to a SID when exactly one SID was observed
for that same DOMAIN\\user in the analyzed events. Ambiguous names (one name, several
SIDs — e.g. an account deleted and re-created) are never merged.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import TYPE_CHECKING

from moesoc.core.domains import DomainMap, fold_name

if TYPE_CHECKING:
    from moesoc.core.event import NormalizedEvent

NULL_SID = "S-1-0-0"
# Well-known built-in identities (not people). Useful context, never brute-force targets.
WELL_KNOWN_SIDS: dict[str, str] = {
    "S-1-5-18": "SYSTEM",
    "S-1-5-19": "LOCAL SERVICE",
    "S-1-5-20": "NETWORK SERVICE",
    "S-1-5-7": "ANONYMOUS LOGON",
}


class IdentityBasis(StrEnum):
    SID = "sid"
    DOMAIN_ACCOUNT = "domain_account"
    HOST_ACCOUNT = "host_account"
    USERNAME_ONLY = "username_only"


@dataclass(frozen=True, slots=True)
class AccountIdentity:
    key: str  # stable correlation key, e.g. "sid:S-1-5-21-…" or "acct:corp\\admin"
    basis: IdentityBasis
    display: str  # what an analyst sees, original casing: CORP\admin
    name_key: str | None  # the DOMAIN\user (or HOST\user) key, kept for SID resolution
    sid: str | None = None
    resolved_from_name: bool = False  # SID inferred from another event with the same name
    domain_aliases: tuple[str, ...] = ()  # why this domain matched another spelling
    # Failed logons (4625): the domain the client claimed, kept apart from the authority
    # the identity was resolved to, and how that resolution was made.
    claimed_domain: str | None = None
    resolution: str | None = None
    claim_unverified: bool = False  # the claimed domain is not a proven authority

    @property
    def is_machine_account(self) -> bool:
        return self.display.endswith("$")

    @property
    def is_well_known(self) -> bool:
        return self.sid in WELL_KNOWN_SIDS

    def as_evidence(self) -> dict[str, object]:
        evidence: dict[str, object] = {
            "key": self.key,
            "basis": self.basis.value,
            "display": self.display,
            "sid": self.sid,
            "sid_resolved_from_name": self.resolved_from_name,
            "machine_account": self.is_machine_account,
        }
        if self.domain_aliases:
            evidence["domain_aliases"] = list(self.domain_aliases)
        if self.resolution:
            evidence["claimed_domain"] = self.claimed_domain
            evidence["resolution"] = self.resolution
            evidence["claimed_domain_verified"] = not self.claim_unverified
        return evidence

    @property
    def account_candidate(self) -> str:
        """Key for counting DISTINCT accounts (DET-002, DET-004 source mode).

        Failures that differ only in an unverified claimed domain cannot prove different
        accounts, so a claim kept as-is counts as the local account of that computer.
        Proven identities (SID, verified domain, local account) count by their own key.
        """
        if self.resolution == RESOLVED_UNVERIFIED and self.name_key and self.scope_host:
            user = self.name_key.rsplit("\\", 1)[-1]
            return f"acct:{fold_name(self.scope_host)}\\{user}"
        return self.key

    scope_host: str | None = None  # the computer whose events produced this identity


def is_reliable_sid(sid: str | None) -> bool:
    if not sid:
        return False
    normalized = sid.strip().upper()
    return normalized.startswith("S-1-") and normalized != NULL_SID


def short_host(hostname: str | None) -> str | None:
    """NetBIOS-style name from an FQDN: WS-LAB01.lab.example → WS-LAB01."""
    if not hostname:
        return None
    return hostname.split(".", 1)[0] or None


def build_identity(
    username: str | None,
    domain: str | None,
    sid: str | None,
    hostname: str | None,
    domains: DomainMap | None = None,
) -> AccountIdentity | None:
    """Identity for one (username, domain, SID) triple as recorded in one event.

    With ``domains``, proven aliases of the domain share one key; the display always
    keeps the spelling Windows recorded.
    """
    reliable_sid = sid.strip().upper() if is_reliable_sid(sid) else None
    if not username and not reliable_sid:
        return None

    host = short_host(hostname)
    effective_domain = host if domain == "." else domain
    name_key: str | None = None
    display = username or reliable_sid or ""
    aliases: tuple[str, ...] = ()
    if username:
        user_cf = fold_name(username)
        if effective_domain:
            domain_key = fold_name(effective_domain)
            if domains is not None:
                domain_key = domains.canonical(effective_domain)
                aliases = tuple(
                    f"{link.first} = {link.second} ({link.reason})"
                    for link in domains.explain(effective_domain)
                )
            name_key = f"acct:{domain_key}\\{user_cf}"
            display = f"{effective_domain}\\{username}"
        elif host:
            # No domain recorded: the computer's own account database (same key as an
            # explicit HOST\\user, so "" and the host name never split one local account).
            name_key = f"acct:{fold_name(host)}\\{user_cf}"
            display = f"{host}\\{username}"
        else:
            name_key = f"user:{user_cf}"

    if reliable_sid:
        return AccountIdentity(
            f"sid:{reliable_sid}",
            IdentityBasis.SID,
            display,
            name_key,
            reliable_sid,
            domain_aliases=aliases,
            scope_host=host,
        )
    if name_key is None:  # unreachable: no SID implies a username
        return None
    if not name_key.startswith("acct:"):
        basis = IdentityBasis.USERNAME_ONLY
    elif effective_domain:
        basis = IdentityBasis.DOMAIN_ACCOUNT
    else:
        basis = IdentityBasis.HOST_ACCOUNT
    return AccountIdentity(
        name_key, basis, display, name_key, domain_aliases=aliases, scope_host=host
    )


LOGON_FAILURE = 4625
NO_DOMAIN = {"", ".", "-"}

RESOLVED_LOCAL = "local account of this computer (no domain, '.' or the computer's own name)"
RESOLVED_VERIFIED = "claimed domain is a proven authority"
RESOLVED_STANDALONE = (
    "claimed domain is unverified and this computer uses only local accounts ({why}); "
    "resolved to the local account"
)
RESOLVED_UNVERIFIED = (
    "claimed domain is unverified and this computer's authority is unknown; kept as claimed"
)


def target_identity(
    event: NormalizedEvent, domains: DomainMap | None = None
) -> AccountIdentity | None:
    if event.event_id == LOGON_FAILURE and not is_reliable_sid(event.target_user_sid):
        return failed_logon_identity(event, domains)
    return build_identity(
        event.target_username, event.target_domain, event.target_user_sid, event.hostname, domains
    )


def _is_this_host(domain: str, hostname: str | None, domains: DomainMap | None) -> bool:
    host = short_host(hostname)
    if not host:
        return False
    folded = fold_name(domain)
    if folded in (fold_name(host), fold_name(hostname or "")):
        return True
    return domains is not None and domains.same(domain, host)


def failed_logon_identity(
    event: NormalizedEvent, domains: DomainMap | None = None
) -> AccountIdentity | None:
    """Target identity of a failed logon without a usable SID (audit bug A-2).

    In Event 4625 ``TargetDomainName`` is what the client SENT: an attacker can put any
    text there. It defines the identity only when it is a proven authority; otherwise
    it is kept as ``claimed_domain`` evidence:

    1. no domain, ``.``, ``-`` or this computer's own name → the local account
       ``HOST\\user`` (the same key a successful local logon gets);
    2. a verified domain (seen with an account SID, or this computer's configuration)
       → ``DOMAIN\\user`` as before;
    3. an unverified domain on a computer proven to use only local accounts → the local
       account ``HOST\\user`` (there is no other authority that could hold it);
    4. an unverified domain where the computer's authority is unknown → kept as claimed
       (never merged on the user name alone), but counted as one account candidate by
       the spray rules (see ``AccountIdentity.account_candidate``).
    """
    username = event.target_username
    if not username:
        return None
    claimed = event.target_domain
    host = short_host(event.hostname)
    claimed_text = (claimed or "").strip()
    if claimed_text in NO_DOMAIN or _is_this_host(claimed_text, event.hostname, domains):
        identity = build_identity(username, None, None, event.hostname, domains)
        resolution, unverified = RESOLVED_LOCAL, False
    elif domains is not None and domains.is_verified(claimed_text):
        identity = build_identity(username, claimed_text, None, event.hostname, domains)
        resolution, unverified = RESOLVED_VERIFIED, False
    elif domains is not None and (why := domains.standalone_reason(host)):
        identity = build_identity(username, None, None, event.hostname, domains)
        resolution, unverified = RESOLVED_STANDALONE.format(why=why), True
    else:
        identity = build_identity(username, claimed_text, None, event.hostname, domains)
        resolution, unverified = RESOLVED_UNVERIFIED, True
    if identity is None:
        return None
    return replace(
        identity,
        claimed_domain=claimed or None,
        resolution=resolution,
        claim_unverified=unverified,
    )


def subject_identity(
    event: NormalizedEvent, domains: DomainMap | None = None
) -> AccountIdentity | None:
    return build_identity(
        event.subject_username,
        event.subject_domain,
        event.subject_user_sid,
        event.hostname,
        domains,
    )


def _event_key(event: NormalizedEvent) -> tuple[str, str, int, int]:
    return (event.hostname, event.channel, event.record_id, event.event_id)


class IdentityResolver:
    """Resolves target identities across a set of events, linking names to SIDs.

    Domain aliases come from ``domains`` when given, otherwise they are learned from
    the same events (shared authority SIDs only).
    """

    def __init__(self, events: Iterable[NormalizedEvent], domains: DomainMap | None = None) -> None:
        events = list(events)
        self.domains = domains if domains is not None else DomainMap.from_events(events)
        self._targets: dict[tuple[str, str, int, int], AccountIdentity | None] = {}
        self._raw: dict[tuple[str, str, int, int], AccountIdentity | None] = {}
        sids_by_name: dict[str, set[str]] = defaultdict(set)
        for event in events:
            identity = target_identity(event, self.domains)
            self._raw[_event_key(event)] = identity
            if identity and identity.sid and identity.name_key:
                sids_by_name[identity.name_key].add(identity.sid)
        # Only unambiguous names are linked.
        self._sid_for_name = {
            name: next(iter(s)) for name, s in sids_by_name.items() if len(s) == 1
        }

    def target(self, event: NormalizedEvent) -> AccountIdentity | None:
        key = _event_key(event)
        if key not in self._targets:
            self._targets[key] = self._resolve_target(event, key)
        return self._targets[key]

    def _resolve_target(
        self, event: NormalizedEvent, key: tuple[str, str, int, int]
    ) -> AccountIdentity | None:
        identity = self._raw[key] if key in self._raw else target_identity(event, self.domains)
        if identity is None or identity.basis is IdentityBasis.SID or not identity.name_key:
            return identity
        sid = self._sid_for_name.get(identity.name_key)
        if sid is None:
            return identity
        return replace(
            identity, key=f"sid:{sid}", basis=IdentityBasis.SID, sid=sid, resolved_from_name=True
        )

    def subject(self, event: NormalizedEvent) -> AccountIdentity | None:
        return subject_identity(event, self.domains)
