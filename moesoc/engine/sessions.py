"""Logon-session context: which logons received special privileges (Event 4672).

Windows writes 4672 right after the 4624 of a logon that holds sensitive privileges
(administrator-equivalent rights such as SeDebugPrivilege or SeTakeOwnershipPrivilege).
Its SubjectLogonId equals the 4624's TargetLogonId. MoeSOC uses it as **context**
that raises the priority of a suspicious logon; a 4672 alone is never a finding,
because every administrator and service logon produces one.

Logon IDs are only unique until the computer restarts, so a match also requires the
same computer and timestamps within ``MAX_SKEW`` of each other.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from datetime import timedelta

from moesoc.core.enums import SecurityEventId
from moesoc.core.event import NormalizedEvent

MAX_SKEW = timedelta(seconds=60)

# Privileges that matter most when an attacker holds them (subset shown first).
SENSITIVE_PRIVILEGES = (
    "SeDebugPrivilege",
    "SeTcbPrivilege",
    "SeImpersonatePrivilege",
    "SeTakeOwnershipPrivilege",
    "SeLoadDriverPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeSecurityPrivilege",
    "SeAssignPrimaryTokenPrivilege",
)


def _session_key(hostname: str, logon_id: str | None) -> tuple[str, str] | None:
    if not logon_id:
        return None
    return (hostname.casefold(), logon_id.strip().lower())


class PrivilegedSessions:
    """Index of 4672 events by computer + logon ID."""

    def __init__(self, events: Iterable[NormalizedEvent]) -> None:
        self._by_session: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
        for event in events:
            if event.event_id == SecurityEventId.SPECIAL_PRIVILEGES:
                key = _session_key(event.hostname, event.logon_id)
                if key:
                    self._by_session[key].append(event)

    def for_logon(self, logon: NormalizedEvent) -> NormalizedEvent | None:
        """The 4672 of this 4624's new session, if Windows wrote one.

        Under UAC an administrator's logon is split into a filtered and an elevated
        session that name each other (``linked_logon_id``); 4672 belongs to the
        elevated one, so both IDs are checked.
        """
        candidates: list[NormalizedEvent] = []
        for logon_id in (logon.logon_id, logon.detail("linked_logon_id")):
            key = _session_key(logon.hostname, logon_id)
            if key is None:
                continue
            candidates += [
                e
                for e in self._by_session.get(key, [])
                if abs(e.timestamp - logon.timestamp) <= MAX_SKEW
            ]
        if not candidates:
            return None
        return min(candidates, key=lambda e: abs(e.timestamp - logon.timestamp))


def describe_privileges(event: NormalizedEvent) -> dict[str, object]:
    """Evidence for one 4672: the sensitive privileges first, then the count."""
    privileges = event.privilege_list
    sensitive = [p for p in SENSITIVE_PRIVILEGES if p in privileges]
    return {
        "record_id": event.record_id,
        "logon_id": event.logon_id,
        "account": event.subject_account_display,
        "account_sid": event.subject_user_sid,
        "privilege_count": len(privileges),
        "sensitive_privileges": sensitive,
        "privileges": privileges,
    }
