"""Account management detections: DET-005 (4720), DET-006 (4732) and COR-002.

Account creation and group changes are routine administration. These rules make
them visible with the context an analyst needs (who did it, from which logon
session, which account, which group) and grade severity only from explainable
facts: the group's well-known SID, a hidden-looking account name, or the
creation-then-elevation sequence.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from moesoc.core.detection import Detection, RuleMetadata
from moesoc.core.enums import Confidence, SecurityEventId, Severity
from moesoc.core.event import NormalizedEvent
from moesoc.core.identity import build_identity, short_host
from moesoc.engine.context import DetectionContext, domains_of
from moesoc.engine.rules import build_detection, chronological

DET_005 = "DET-005"
DET_006 = "DET-006"
COR_002 = "COR-002"
TIER_SEVERITY = {"high": Severity.HIGH, "medium": Severity.MEDIUM}


def _norm_sid(sid: str | None) -> str | None:
    return sid.strip().upper() if sid else None


# ----------------------------------------------------------------- group classification
@dataclass(frozen=True, slots=True)
class GroupMatch:
    tier: str  # "high" | "medium"
    label: str  # the built-in group this SID identifies, in English
    matched_by: str  # "sid" | "name"


def classify_group(event: NormalizedEvent, params: dict[str, Any]) -> GroupMatch | None:
    """Privileged group by well-known SID; by English name only if no SID was recorded."""
    groups = {_norm_sid(k): v for k, v in (params.get("privileged_groups") or {}).items()}
    sid = _norm_sid(event.group_sid)
    if sid:
        entry = groups.get(sid)
        if entry is None:
            return None
        tier, label = str(entry[0]), str(entry[1])
        return GroupMatch(tier, label, "sid")
    names = {str(n).casefold() for n in params.get("fallback_group_names") or ()}
    if event.group_name and event.group_name.casefold() in names:
        return GroupMatch("high", event.group_name, "name")
    return None


# ----------------------------------------------------------------- account names
def account_names_by_sid(events: Iterable[NormalizedEvent]) -> dict[str, tuple[str, int, int]]:
    """SID → (DOMAIN\\name, event ID, record ID) from events that recorded both."""
    names: dict[str, tuple[str, int, int]] = {}
    for event in chronological(events):
        sid = _norm_sid(event.target_user_sid)
        if sid and event.target_username:
            names.setdefault(
                sid, (event.target_account_display or "", event.event_id, event.record_id)
            )
    return names


def _actor(event: NormalizedEvent) -> dict[str, Any]:
    return {
        "actor": event.subject_account_display,
        "actor_sid": event.subject_user_sid,
        "actor_logon_id": event.logon_id,
    }


def _scope(event: NormalizedEvent) -> str:
    """Local account when its domain is this computer's own name."""
    host = short_host(event.hostname)
    if event.target_domain and host and event.target_domain.casefold() == host.casefold():
        return "local"
    return "domain or other authority"


# ----------------------------------------------------------------- DET-005
def detect_new_user_account(
    events: Iterable[NormalizedEvent],
    rule: RuleMetadata,
    context: DetectionContext | None = None,
) -> list[Detection]:
    """DET-005: every Event 4720, graded LOW unless the name looks hidden."""
    detections: list[Detection] = []
    raise_to = Severity(str(rule.parameters.get("hidden_name_raises_to", "MEDIUM")))
    for event in chronological(e for e in events if e.event_id == SecurityEventId.ACCOUNT_CREATED):
        identity = build_identity(
            event.target_username,
            event.target_domain,
            event.target_user_sid,
            event.hostname,
            domains_of(context),
        )
        account = identity.display if identity else None
        context_notes: list[str] = []
        severity = rule.severity
        if event.target_username and event.target_username.endswith("$"):
            severity = max(severity, raise_to, key=lambda s: s.rank)
            context_notes.append(
                "Name ends with '$': hidden from 'net user' and imitates a computer account "
                "(computer accounts are created with Event 4741, not 4720)"
            )
        evidence = {
            "account": account,
            "new_account_sid": event.target_user_sid,
            "account_scope": _scope(event),
            "hostname": event.hostname,
            "created_at": event.timestamp.isoformat(),
            **_actor(event),
            "sam_account_name": event.detail("sam_account_name"),
            "user_principal_name": event.detail("user_principal_name"),
            "user_account_control": event.detail("user_account_control"),
            "context": context_notes,
            "record_id": event.record_id,
        }
        detections.append(
            build_detection(
                rule,
                event,
                [event],
                account,
                evidence,
                derived_severity=severity if severity != rule.severity else None,
            )
        )
    return detections


# ----------------------------------------------------------------- DET-006
def detect_privileged_group_addition(
    events: Iterable[NormalizedEvent],
    rule: RuleMetadata,
    context: DetectionContext | None = None,
) -> list[Detection]:
    """DET-006: a member added to a privileged local group (Event 4732)."""
    events = list(events)
    names = account_names_by_sid(events)
    detections: list[Detection] = []
    additions = (e for e in events if e.event_id == SecurityEventId.LOCAL_GROUP_MEMBER_ADDED)
    for event in chronological(additions):
        group = classify_group(event, rule.parameters)
        if group is None:
            continue  # not a privileged group: stored as context, not a finding
        member_sid = _norm_sid(event.member_sid)
        known = names.get(member_sid) if member_sid else None
        member = known[0] if known else (event.member_name or event.member_sid)
        evidence = {
            "member": member,
            "member_sid": event.member_sid,
            "member_name_recorded": event.member_name,
            "member_name_source": (f"Event {known[1]} record {known[2]}" if known else None),
            "group": event.group_name,
            "group_domain": event.group_domain,
            "group_sid": event.group_sid,
            "group_meaning": group.label,
            "group_tier": group.tier,
            "group_matched_by": group.matched_by,
            "hostname": event.hostname,
            "added_at": event.timestamp.isoformat(),
            **_actor(event),
            "record_id": event.record_id,
        }
        detections.append(
            build_detection(
                rule,
                event,
                [event],
                member,
                evidence,
                derived_severity=TIER_SEVERITY[group.tier],
                derived_confidence=Confidence.LOW if group.matched_by == "name" else None,
            )
        )
    return detections


# ----------------------------------------------------------------- COR-002
def correlate_new_account_to_admin(
    events: Iterable[NormalizedEvent],
    rule: RuleMetadata,
    context: DetectionContext | None = None,
) -> list[Detection]:
    """COR-002: 4720 for SID X, then 4732 adding SID X to an admin-equivalent group.

    Same computer, same SID, creation first, within ``window_minutes``. The group
    tiers come from DET-006's parameters (one definition of "privileged").
    """
    events = list(events)
    window = timedelta(minutes=int(rule.parameters["window_minutes"]))
    required_tier = str(rule.parameters.get("required_tier", "high"))
    det006 = context.rules.get(DET_006) if context else None
    group_params = det006.parameters if det006 else {}
    if not group_params:
        return []  # no definition of privileged groups loaded

    created: dict[tuple[str, str], NormalizedEvent] = {}
    for event in chronological(e for e in events if e.event_id == SecurityEventId.ACCOUNT_CREATED):
        sid = _norm_sid(event.target_user_sid)
        if sid:
            created.setdefault((event.hostname.casefold(), sid), event)

    detections: list[Detection] = []
    seen: set[tuple[str, str]] = set()
    additions = (e for e in events if e.event_id == SecurityEventId.LOCAL_GROUP_MEMBER_ADDED)
    for added in chronological(additions):
        sid = _norm_sid(added.member_sid)
        if not sid:
            continue
        key = (added.hostname.casefold(), sid)
        creation = created.get(key)
        if creation is None or key in seen:
            continue
        elapsed = added.timestamp - creation.timestamp
        if elapsed < timedelta(0) or elapsed > window:
            continue  # wrong order or too far apart
        group = classify_group(added, group_params)
        if group is None or group.tier != required_tier:
            continue
        seen.add(key)  # one finding per new account
        account = creation.target_account_display
        same_actor = _norm_sid(creation.subject_user_sid) == _norm_sid(added.subject_user_sid)
        evidence = {
            "account": account,
            "account_sid": creation.target_user_sid,
            "hostname": creation.hostname,
            "created_at": creation.timestamp.isoformat(),
            "created_by": creation.subject_account_display,
            "created_by_logon_id": creation.logon_id,
            "added_at": added.timestamp.isoformat(),
            "added_by": added.subject_account_display,
            "added_by_logon_id": added.logon_id,
            "same_actor": same_actor,
            "group": added.group_name,
            "group_sid": added.group_sid,
            "group_meaning": group.label,
            "group_matched_by": group.matched_by,
            "seconds_from_creation_to_group_add": int(elapsed.total_seconds()),
            "window_minutes": int(window.total_seconds() // 60),
            "creation_record_id": creation.record_id,
            "group_add_record_id": added.record_id,
        }
        detections.append(
            build_detection(
                rule,
                creation,
                [creation, added],
                account,
                evidence,
                derived_confidence=Confidence.MEDIUM if group.matched_by == "name" else None,
            )
        )
    return detections
