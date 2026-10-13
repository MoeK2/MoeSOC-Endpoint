"""Rule metadata loading and single-signal detections (DET-xxx)."""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from collections.abc import Callable, Hashable, Iterable
from dataclasses import replace
from datetime import timedelta
from itertools import pairwise
from pathlib import Path
from statistics import median
from typing import Any

import yaml

from moesoc.core.detection import Detection, MitreTechnique, RuleMetadata
from moesoc.core.enums import Confidence, DetectionKind, SecurityEventId, Severity
from moesoc.core.event import NormalizedEvent
from moesoc.core.exceptions import MoeSOCError
from moesoc.core.identity import AccountIdentity, IdentityResolver, subject_identity
from moesoc.engine.context import DetectionContext, domains_of
from moesoc.engine.risk import score_detection

log = logging.getLogger(__name__)

DET_001 = "DET-001"
DET_002 = "DET-002"
DET_003 = "DET-003"
DET_004 = "DET-004"
ACCOUNT_NOT_FOUND = "0xc0000064"
MAX_LISTED_ACCOUNTS = 50


class RuleLoadError(MoeSOCError):
    pass


# ----------------------------------------------------------------- loading
def _as_tuple(value: Any) -> tuple[str, ...]:
    return tuple(str(v) for v in value or ())


def parse_rule(document: dict[str, Any], origin: str = "<memory>") -> RuleMetadata:
    try:
        return RuleMetadata(
            rule_id=str(document["rule_id"]),
            version=str(document.get("version", "1.0")),
            title=str(document["title"]),
            kind=DetectionKind(document["kind"]),
            severity=Severity(document["severity"]),
            confidence=Confidence(document["confidence"]),
            description=str(document["description"]).strip(),
            mitre=tuple(
                MitreTechnique(str(m["id"]), str(m["name"]), str(m["tactic"]))
                for m in document.get("mitre", [])
            ),
            false_positives=_as_tuple(document.get("false_positives")),
            recommended_investigation=_as_tuple(document.get("recommended_investigation")),
            parameters=dict(document.get("parameters") or {}),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise RuleLoadError(f"Rule file {origin} is invalid: {exc}") from exc


def load_rules(rules_dir: Path) -> dict[str, RuleMetadata]:
    """Load every ``*.yaml`` rule under ``rules_dir`` (recursively)."""
    rules: dict[str, RuleMetadata] = {}
    for path in sorted(rules_dir.rglob("*.yaml")):
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise RuleLoadError(f"Could not read rule file {path.name}: {exc}") from exc
        rule = parse_rule(document, path.name)
        if rule.rule_id in rules:
            raise RuleLoadError(f"Duplicate rule ID {rule.rule_id} in {path.name}")
        rules[rule.rule_id] = rule
    log.info("Loaded %s detection rules", len(rules))
    return rules


# ----------------------------------------------------------------- shared helpers
def chronological(events: Iterable[NormalizedEvent]) -> list[NormalizedEvent]:
    """Order by event time, not arrival order. EventRecordID breaks timestamp ties."""
    return sorted(events, key=lambda e: (e.timestamp, e.record_id))


def group_events(
    events: Iterable[NormalizedEvent],
    event_id: int,
    key: Callable[[NormalizedEvent], Hashable | None],
) -> dict[Hashable, list[NormalizedEvent]]:
    """Group one event ID by ``key`` (events whose key is None are skipped), chronologically."""
    grouped: dict[Hashable, list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        if event.event_id == event_id:
            k = key(event)
            if k is not None:
                grouped[k].append(event)
    return {k: chronological(evs) for k, evs in grouped.items()}


def find_windows(
    events: list[NormalizedEvent],
    window: timedelta,
    qualifies: Callable[[list[NormalizedEvent]], bool],
) -> list[list[NormalizedEvent]]:
    """Find maximal bursts of chronological ``events`` where a rolling ``window`` qualifies.

    For each event, the window is every earlier event no more than ``window`` older
    (boundary inclusive). Qualifying windows that overlap are merged into one burst,
    so a 40-attempt attack produces one finding, not 36. ``qualifies`` must be
    monotonic: if a window qualifies, any larger window ending at the same event does.
    """
    bursts: list[list[NormalizedEvent]] = []
    current: list[NormalizedEvent] | None = None
    current_end = -1
    start = 0
    for end in range(len(events)):
        while events[end].timestamp - events[start].timestamp > window:
            start += 1
        if not qualifies(events[start : end + 1]):
            continue
        if current is not None and start <= current_end:
            current.extend(events[current_end + 1 : end + 1])
        else:
            current = list(events[start : end + 1])
            bursts.append(current)
        current_end = end
    return bursts


def find_bursts(
    events: list[NormalizedEvent], threshold: int, window: timedelta
) -> list[list[NormalizedEvent]]:
    """Bursts with at least ``threshold`` events inside a rolling ``window``."""
    return find_windows(events, window, lambda w: len(w) >= threshold)


def summarize_failures(failures: list[NormalizedEvent]) -> dict[str, Any]:
    """Evidence fields describing a set of failed logons."""
    reasons = Counter(e.failure_reason or e.sub_status or e.status or "Unknown" for e in failures)
    return {
        "failure_count": len(failures),
        "first_failure": failures[0].timestamp.isoformat(),
        "last_failure": failures[-1].timestamp.isoformat(),
        "source_addresses": sorted({e.source_ip for e in failures if e.source_ip}),
        "workstations": sorted({e.workstation_name for e in failures if e.workstation_name}),
        "logon_types": sorted({e.logon_type_name for e in failures if e.logon_type_name}),
        "authentication_packages": sorted(
            {e.authentication_package for e in failures if e.authentication_package}
        ),
        "target_domains": sorted({e.target_domain for e in failures if e.target_domain}),
        # As sent by the client in 4625: evidence only, not the identity (audit bug A-2).
        "claimed_domains": sorted(
            {e.target_domain for e in failures if e.target_domain}, key=str.casefold
        ),
        "failure_reasons": dict(reasons.most_common()),
        "failure_record_ids": [e.record_id for e in failures],
    }


def build_detection(
    rule: RuleMetadata,
    anchor: NormalizedEvent,
    evidence_events: list[NormalizedEvent],
    account: str | None,
    evidence: dict[str, Any],
    **extra: Any,
) -> Detection:
    """Build a finding. Its dedup key is rule + host + anchor record (stable across rescans).

    Burst rules also pass ``campaign_key`` and ``campaign_gap``: when the anchor of a
    continuing campaign moves (a sliding live window, a late or out-of-order event), the
    stored finding of that campaign is extended instead (see ``DetectionRepository.upsert``).
    """
    ordered = chronological(evidence_events)
    key, gap = extra.get("campaign_key"), extra.get("campaign_gap")
    if key is not None and gap is not None:
        evidence = {
            **evidence,
            "campaign": {"key": key, "continues_within_minutes": int(gap.total_seconds() // 60)},
        }
    return Detection(
        rule=rule,
        dedup_key=f"{rule.rule_id}|{anchor.hostname}|{anchor.record_id}",
        account=account,
        first_seen=ordered[0].timestamp,
        last_seen=ordered[-1].timestamp,
        risk_score=score_detection(extra.get("derived_severity") or rule.severity),
        evidence=evidence,
        related_record_ids=tuple(e.record_id for e in ordered),
        evidence_refs=tuple(e.ref for e in ordered),
        **extra,
    )


# ----------------------------------------------------------------- DET-001
def detect_multiple_failed_logins(
    events: Iterable[NormalizedEvent],
    rule: RuleMetadata,
    context: DetectionContext | None = None,
) -> list[Detection]:
    """DET-001: >= threshold 4625 events for one account identity inside a rolling window."""
    events = list(events)
    params = rule.parameters
    threshold = int(params["threshold"])
    window = timedelta(minutes=int(params["window_minutes"]))
    resolver = IdentityResolver(events, domains_of(context))
    identities: dict[Hashable, AccountIdentity] = {}

    def key(event: NormalizedEvent) -> str | None:
        identity = resolver.target(event)
        if identity is None:
            return None
        identities.setdefault(identity.key, identity)
        return identity.key

    detections: list[Detection] = []
    for account_key, failures in group_events(events, int(params["event_id"]), key).items():
        identity = identities[account_key]
        for burst in find_bursts(failures, threshold, window):
            first = burst[0]
            spellings = sorted(
                {i.display for i in map(resolver.target, burst) if i is not None}, key=str.casefold
            )
            evidence = {
                "username": first.target_username,
                "account": identity.display,
                "identity": identity.as_evidence(),
                **({"account_spellings": spellings} if len(spellings) > 1 else {}),
                "hostname": first.hostname,
                "threshold": threshold,
                "window_minutes": int(params["window_minutes"]),
                **summarize_failures(burst),
            }
            detections.append(
                build_detection(
                    rule,
                    first,
                    burst,
                    identity.display,
                    evidence,
                    campaign_key=f"identity:{account_key}",
                    campaign_gap=window,
                )
            )
    return detections


# ----------------------------------------------------------------- DET-002
def spray_source(event: NormalizedEvent) -> str | None:
    """Where a failed logon came from: the IP, else the reported workstation name."""
    if event.source_ip:
        return event.source_ip
    if event.workstation_name:
        return f"workstation:{event.workstation_name.casefold()}"
    return None


def detect_password_spray(
    events: Iterable[NormalizedEvent],
    rule: RuleMetadata,
    context: DetectionContext | None = None,
) -> list[Detection]:
    """DET-002: one source fails against >= N distinct account identities inside a window.

    Brute force (DET-001) is many guesses against ONE account; spraying is a few
    guesses against MANY accounts, which stays under per-account lockout limits.
    """
    events = list(events)
    params = rule.parameters
    min_accounts = int(params["min_distinct_accounts"])
    window = timedelta(minutes=int(params["window_minutes"]))
    resolver = IdentityResolver(events, domains_of(context))

    def identity_key(event: NormalizedEvent) -> str | None:
        # Distinct ACCOUNTS: a user name tried with several unverified claimed domains is
        # one account candidate, not several (audit bug A-2).
        identity = resolver.target(event)
        return identity.account_candidate if identity else None

    def qualifies(window_events: list[NormalizedEvent]) -> bool:
        keys = {identity_key(e) for e in window_events}
        keys.discard(None)
        return len(keys) >= min_accounts

    detections: list[Detection] = []
    for source, failures in group_events(events, int(params["event_id"]), spray_source).items():
        for burst in find_windows(failures, window, qualifies):
            accounts: dict[str, str] = {}
            for e in burst:
                identity = resolver.target(e)
                if identity:
                    accounts.setdefault(identity.account_candidate, identity.display)
            first = burst[0]
            not_found = sum(1 for e in burst if e.sub_status == ACCOUNT_NOT_FOUND)
            evidence = {
                "source": source,
                "source_type": "workstation" if str(source).startswith("workstation:") else "ip",
                "hostname": first.hostname,
                "distinct_account_count": len(accounts),
                "accounts": sorted(accounts.values(), key=str.casefold)[:MAX_LISTED_ACCOUNTS],
                "accounts_not_found": not_found,
                "min_distinct_accounts": min_accounts,
                "window_minutes": int(params["window_minutes"]),
                **summarize_failures(burst),
            }
            detections.append(
                build_detection(
                    rule,
                    first,
                    burst,
                    None,
                    evidence,
                    campaign_key=f"source:{source}",
                    campaign_gap=window,
                )
            )
    return detections


# ----------------------------------------------------------------- DET-003
def detect_security_log_cleared(
    events: Iterable[NormalizedEvent],
    rule: RuleMetadata,
    context: DetectionContext | None = None,
) -> list[Detection]:
    """DET-003: every Security 1102 "audit log was cleared" event.

    High confidence that the log was cleared (Windows recorded it); no claim about
    whether the clearing was malicious.
    """
    detections: list[Detection] = []
    for event in chronological(e for e in events if e.event_id == SecurityEventId.LOG_CLEARED):
        actor = subject_identity(event, domains_of(context))
        evidence = {
            "hostname": event.hostname,
            "cleared_at": event.timestamp.isoformat(),
            "actor": actor.display if actor else None,
            "actor_sid": event.subject_user_sid,
            "actor_logon_id": event.logon_id,
            "record_id": event.record_id,
            "provider": event.provider,
        }
        detections.append(
            build_detection(rule, event, [event], actor.display if actor else None, evidence)
        )
    return detections


# ----------------------------------------------------------------- DET-004
EventKey = tuple[str, str, int]


def _event_key(event: NormalizedEvent) -> EventKey:
    return (event.hostname.casefold(), event.channel, event.record_id)


def cadence(events: list[NormalizedEvent]) -> dict[str, Any]:
    """Seconds between consecutive attempts; a near-constant gap suggests a device or script."""
    gaps = [(b.timestamp - a.timestamp).total_seconds() for a, b in pairwise(events)]
    if not gaps:
        return {}
    middle = median(gaps)
    regular = len(gaps) >= 3 and middle > 0 and all(abs(g - middle) <= 0.1 * middle for g in gaps)
    return {
        "interval_seconds_median": round(middle, 1),
        "interval_seconds_min": round(min(gaps), 1),
        "interval_seconds_max": round(max(gaps), 1),
        "regular_interval": regular,
    }


def _covered_by_det001(
    by_identity: dict[Hashable, list[NormalizedEvent]], context: DetectionContext | None
) -> set[EventKey]:
    """Failures already reported in a DET-001 burst (when DET-001 is loaded)."""
    rule = context.rules.get(DET_001) if context else None
    if rule is None:
        return set()
    threshold = int(rule.parameters["threshold"])
    window = timedelta(minutes=int(rule.parameters["window_minutes"]))
    return {
        _event_key(e)
        for failures in by_identity.values()
        for burst in find_bursts(failures, threshold, window)
        for e in burst
    }


def _covered_by_det002(
    by_source: dict[Hashable, list[NormalizedEvent]],
    identity_key: Callable[[NormalizedEvent], str | None],
    context: DetectionContext | None,
) -> set[EventKey]:
    """Failures already reported in a DET-002 spray window (when DET-002 is loaded)."""
    rule = context.rules.get(DET_002) if context else None
    if rule is None:
        return set()
    min_accounts = int(rule.parameters["min_distinct_accounts"])
    window = timedelta(minutes=int(rule.parameters["window_minutes"]))

    def qualifies(w: list[NormalizedEvent]) -> bool:
        return len({identity_key(e) for e in w} - {None}) >= min_accounts

    return {
        _event_key(e)
        for failures in by_source.values()
        for burst in find_windows(failures, window, qualifies)
        for e in burst
    }


def detect_low_and_slow_guessing(
    events: Iterable[NormalizedEvent],
    rule: RuleMetadata,
    context: DetectionContext | None = None,
) -> list[Detection]:
    """DET-004: failures spread over a long window, below the DET-001 burst threshold.

    Identity mode: >= identity_threshold failures for one account in the window.
    Source mode: >= source_threshold failures from one source over 2+ accounts.
    Failures already inside a DET-001 burst (identity mode) or a DET-001 burst or
    DET-002 window (source mode) are not counted again.
    """
    # Each Windows record counts once, even if the input repeats it.
    events = list({_event_key(e): e for e in events}.values())
    params = rule.parameters
    event_id = int(params["event_id"])
    window_minutes = int(params["window_minutes"])
    window = timedelta(minutes=window_minutes)
    ignore_machines = bool(params.get("ignore_machine_accounts", True))
    resolver = IdentityResolver(events, domains_of(context))
    identities: dict[str, AccountIdentity] = {}

    def identity_key(event: NormalizedEvent) -> str | None:
        identity = resolver.target(event)
        if identity is None or (ignore_machines and identity.is_machine_account):
            return None
        identities.setdefault(identity.key, identity)
        return identity.key

    by_identity = group_events(events, event_id, identity_key)
    by_source = group_events(events, event_id, spray_source)
    fast = _covered_by_det001(by_identity, context)

    detections: list[Detection] = []
    # ------------------------------------------------ identity mode
    threshold = int(params["identity_threshold"])
    for key, failures in by_identity.items():
        slow = [e for e in failures if _event_key(e) not in fast]
        excluded = len(failures) - len(slow)
        for burst in find_bursts(slow, threshold, window):
            identity = identities[key]
            first = burst[0]
            evidence = {
                "mode": "identity",
                "account": identity.display,
                "identity": identity.as_evidence(),
                "hostname": first.hostname,
                "threshold": threshold,
                "window_minutes": window_minutes,
                "failures_in_det001_bursts_excluded": excluded,
                **summarize_failures(burst),
                **cadence(burst),
            }
            detections.append(
                build_detection(
                    rule,
                    first,
                    burst,
                    identity.display,
                    evidence,
                    campaign_key=f"identity:{key}",
                    campaign_gap=window,
                )
            )

    # ------------------------------------------------ source mode
    source_threshold = int(params["source_threshold"])
    min_accounts = int(params.get("source_min_accounts", 2))

    def candidate(event: NormalizedEvent) -> str | None:
        identity = resolver.target(event)
        if identity is None or (ignore_machines and identity.is_machine_account):
            return None
        return identity.account_candidate

    covered = fast | _covered_by_det002(by_source, candidate, context)

    def qualifies(w: list[NormalizedEvent]) -> bool:
        accounts = {candidate(e) for e in w} - {None}
        return len(w) >= source_threshold and len(accounts) >= min_accounts

    for source, failures in by_source.items():
        slow = [e for e in failures if _event_key(e) not in covered and identity_key(e)]
        for burst in find_windows(slow, window, qualifies):
            accounts = sorted(
                {identities[k].display for k in (identity_key(e) for e in burst) if k},
                key=str.casefold,
            )
            first = burst[0]
            evidence = {
                "mode": "source",
                "source": source,
                "source_type": "workstation" if str(source).startswith("workstation:") else "ip",
                "hostname": first.hostname,
                "distinct_account_count": len(accounts),
                "accounts": accounts[:MAX_LISTED_ACCOUNTS],
                "threshold": source_threshold,
                "window_minutes": window_minutes,
                **summarize_failures(burst),
                **cadence(burst),
            }
            finding = build_detection(
                rule,
                first,
                burst,
                None,
                evidence,
                campaign_key=f"source:{source}",
                campaign_gap=window,
            )
            # Both modes can start at the same record; the source mode gets its own key so
            # it never overwrites the identity-mode finding of that record.
            detections.append(replace(finding, dedup_key=f"{finding.dedup_key}|source"))
    return detections
