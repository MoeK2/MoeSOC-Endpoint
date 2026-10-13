"""Which domain names refer to the same Windows security authority.

Windows records the same domain in different forms: the NetBIOS name ``CORP`` in
most Security events, the DNS name ``corp.local`` in others (Kerberos, some
logon types, other tools). ``CORP\\admin`` and ``corp.local\\admin`` may be the
same account, but MoeSOC never assumes it from the spelling: a NetBIOS name is
configured independently and does not have to match the first DNS label.

Two names are treated as aliases only with evidence:

1. **Domain SID** (strong): an account SID ``S-1-5-21-A-B-C-RID`` carries its
   authority's SID ``S-1-5-21-A-B-C``. If accounts recorded under ``CORP`` and
   under ``corp.local`` share that authority SID, the names are the same domain.
   This also covers a renamed computer (local accounts keep the machine SID).
2. **Local system configuration**: this computer's own NetBIOS and DNS domain
   names, and its own short and fully qualified names, read from Windows.

Safety rules:

- Only ``S-1-5-21-…`` SIDs are used. Well-known SIDs such as SYSTEM (S-1-5-18)
  appear under unrelated names (``NT AUTHORITY``, ``WORKGROUP``) and prove nothing.
- A name seen with two different authority SIDs is ambiguous and is never aliased.
- No string similarity, prefix or first-label guessing, ever.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from moesoc.core.event import NormalizedEvent

# S-1-5-21-<3 sub-authorities>-<RID>: a domain or local machine account.
_ACCOUNT_SID = re.compile(r"^S-1-5-21-(\d+)-(\d+)-(\d+)-(\d+)$", re.IGNORECASE)
LOGON_SUCCESS = 4624
# S-1-12-1-…: a Microsoft Entra ID (Azure AD) account; its presence means a non-local authority.
_CLOUD_SID = re.compile(r"^S-1-12-1-", re.IGNORECASE)

REASON_DOMAIN_SID = "same authority SID"
REASON_LOCAL_CONFIG = "this computer's configuration"


def authority_sid(sid: str | None) -> str | None:
    """``S-1-5-21-A-B-C`` for an account SID ``S-1-5-21-A-B-C-RID``; None otherwise."""
    if not sid:
        return None
    match = _ACCOUNT_SID.match(sid.strip())
    if not match:
        return None
    a, b, c, _rid = match.groups()
    return f"S-1-5-21-{a}-{b}-{c}"


@lru_cache(maxsize=16384)
def fold_name(name: str) -> str:
    """Case-insensitive key for a Windows account, domain or computer name.

    Windows compares these names case-insensitively one character at a time, using its
    1:1 uppercase table (``RtlUpcaseUnicodeChar``): a character whose uppercase form is
    a single character is compared in that form, others are compared as written. Python's
    ``casefold`` is different, it maps "ß" to "ss", so "Straße" and "STRASSE" would merge
    although Windows keeps them apart (audit A-11). ASCII letters are lowered so keys stay
    readable ("acct:lab\\alice").
    """
    name = name.strip()
    if name.isascii():  # the common case: plain lower-case
        return name.lower()
    out = []
    for ch in name:
        upper = ch.upper()
        simple = upper if len(upper) == 1 else ch
        out.append(simple.lower() if simple.isascii() else simple)
    return "".join(out)


def _fold(name: str) -> str:
    return fold_name(name)


@dataclass(frozen=True, slots=True)
class DomainAlias:
    """One proven link between two domain names, with the reason."""

    first: str
    second: str
    reason: str
    detail: str | None = None


class DomainMap:
    """Union of domain names proven to be the same authority (case-insensitive)."""

    def __init__(self) -> None:
        self._parent: dict[str, str] = {}
        self._links: list[DomainAlias] = []
        self._ambiguous: set[str] = set()
        # Names proven to be a real security authority (seen with an S-1-5-21 account SID,
        # or this computer's own configuration). A claimed domain in a failed logon that is
        # not in this set is only text the client sent.
        self._verified: set[str] = set()
        # Short host names with evidence that no domain authority is in use there, with why.
        self._standalone: dict[str, str] = {}
        self._verified_roots: set[str] | None = None  # cache for is_verified

    # ------------------------------------------------------------- building
    def _find(self, name: str) -> str:
        root = name
        while self._parent.get(root, root) != root:
            root = self._parent[root]
        self._parent[name] = root
        return root

    def add_alias(self, first: str, second: str, reason: str, detail: str | None = None) -> bool:
        """Link two names. Returns False when nothing changed or a name is ambiguous."""
        a, b = _fold(first), _fold(second)
        if not a or not b or a == b or a in self._ambiguous or b in self._ambiguous:
            return False
        root_a, root_b = self._find(a), self._find(b)
        if root_a == root_b:
            return False
        # Deterministic representative: prefer a NetBIOS-style name (no dot), then the
        # alphabetically first, so keys never depend on event order.
        winner, loser = sorted((root_a, root_b), key=lambda n: ("." in n, n))
        self._parent[loser] = winner
        self._parent.setdefault(winner, winner)
        self._links.append(DomainAlias(first.strip(), second.strip(), reason, detail))
        self._verified_roots = None
        return True

    def mark_ambiguous(self, name: str) -> None:
        self._ambiguous.add(_fold(name))
        self._verified_roots = None

    @classmethod
    def from_events(
        cls,
        events: Iterable[NormalizedEvent],
        seed: Iterable[DomainAlias] = (),
        standalone_hosts: Iterable[str] = (),
    ) -> DomainMap:
        """Learn aliases from the authority SIDs recorded in events, plus known facts.

        ``standalone_hosts``: short names of computers known from their own configuration
        not to be joined to a domain (see ``collectors.hostinfo.local_host_facts``).
        """
        names_by_authority: dict[str, set[str]] = defaultdict(set)
        authorities_by_name: dict[str, set[str]] = defaultdict(set)
        spelling: dict[str, str] = {}
        local_authorities: dict[str, set[str]] = defaultdict(set)
        other_authorities: dict[str, set[str]] = defaultdict(set)
        succeeded: set[str] = set()
        for event in events:
            host = _fold((event.hostname or "").split(".", 1)[0])
            if event.event_id == LOGON_SUCCESS and event.target_domain not in (None, "", ".", "-"):
                # Windows wrote the domain of an account it authenticated: a real authority.
                succeeded.add(_fold(event.target_domain))
            for domain, sid in (
                (event.target_domain, event.target_user_sid),
                (event.subject_domain, event.subject_user_sid),
            ):
                if sid and _CLOUD_SID.match(sid.strip()):
                    other_authorities[host].add("entra-id")  # Microsoft Entra ID account
                authority = authority_sid(sid)
                if not domain or domain == "." or authority is None:
                    continue
                folded = _fold(domain)
                spelling.setdefault(folded, domain.strip())
                names_by_authority[authority].add(folded)
                authorities_by_name[folded].add(authority)
                (local_authorities if folded == host else other_authorities)[host].add(authority)

        mapping = cls()
        mapping._verified.update(authorities_by_name)
        mapping._verified.update(succeeded)
        for alias in seed:
            mapping._verified.update((_fold(alias.first), _fold(alias.second)))
        for host, local in local_authorities.items():
            foreign = other_authorities.get(host, set()) - local
            if len(local) == 1 and not foreign:
                mapping._standalone[host] = (
                    "every account SID recorded on this computer belongs to its own local "
                    "account database"
                )
        for name in standalone_hosts:
            host = _fold(name.split(".", 1)[0])
            if host and not (
                other_authorities.get(host, set()) - local_authorities.get(host, set())
            ):
                mapping._standalone.setdefault(
                    host, "this computer's configuration: not joined to a domain"
                )
        for name, authorities in authorities_by_name.items():
            if len(authorities) > 1:
                mapping.mark_ambiguous(name)
        for alias in seed:
            mapping.add_alias(alias.first, alias.second, alias.reason, alias.detail)
        for authority, names in sorted(names_by_authority.items()):
            ordered = sorted(names)
            for other in ordered[1:]:
                mapping.add_alias(
                    spelling[ordered[0]], spelling[other], REASON_DOMAIN_SID, authority
                )
        return mapping

    # ------------------------------------------------------------- queries
    def canonical(self, name: str) -> str:
        """The case-folded representative used in identity keys."""
        folded = _fold(name)
        if folded in self._ambiguous or folded not in self._parent:
            return folded
        return self._find(folded)

    def same(self, first: str, second: str) -> bool:
        return self.canonical(first) == self.canonical(second)

    def explain(self, name: str) -> list[DomainAlias]:
        """The links that put ``name`` in its alias group (empty when it has none)."""
        root = self.canonical(name)
        return [link for link in self._links if self.canonical(link.first) == root]

    def is_verified(self, name: str) -> bool:
        """True when ``name`` is a proven authority (or an alias of one)."""
        folded = _fold(name)
        if folded in self._verified:
            return True
        if self._verified_roots is None:
            self._verified_roots = {self.canonical(v) for v in self._verified}
        return self.canonical(name) in self._verified_roots

    def standalone_reason(self, host: str | None) -> str | None:
        """Why ``host`` is known to use only local accounts; None when not known."""
        if not host:
            return None
        return self._standalone.get(_fold(host.split(".", 1)[0]))

    @property
    def links(self) -> tuple[DomainAlias, ...]:
        return tuple(self._links)

    @property
    def ambiguous(self) -> frozenset[str]:
        return frozenset(self._ambiguous)
