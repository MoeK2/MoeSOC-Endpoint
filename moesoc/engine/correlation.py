"""Multi-signal correlations (COR-xxx).

A correlation links events that are individually weak signals into a sequence
that is stronger evidence. It is still a lead for investigation, not proof.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from datetime import timedelta
from typing import Any

from moesoc.core.detection import ConfidenceFactor, Detection, RuleMetadata
from moesoc.core.enums import Confidence
from moesoc.core.event import NormalizedEvent
from moesoc.core.identity import IdentityResolver
from moesoc.engine.context import DetectionContext, domains_of
from moesoc.engine.rules import build_detection, group_events, summarize_failures
from moesoc.engine.sessions import PrivilegedSessions, describe_privileges

COR_001 = "COR-001"

REMOTE_LOGON_TYPES = frozenset({3, 8, 10})  # Network, NetworkCleartext, RemoteInteractive
LOCAL_INTERACTIVE_TYPES = frozenset({2, 7, 11})  # Interactive, Unlock, CachedInteractive
MANY_SOURCES = 3


def _before(a: NormalizedEvent, b: NormalizedEvent) -> bool:
    return (a.timestamp, a.record_id) < (b.timestamp, b.record_id)


def is_remote_address(ip: str | None) -> bool:
    """True for a real network peer; False for missing, loopback or unspecified addresses."""
    if not ip:
        return False
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (address.is_loopback or address.is_unspecified)


def confidence_from_points(points: int) -> Confidence:
    if points >= 3:
        return Confidence.HIGH
    if points >= 1:
        return Confidence.MEDIUM
    return Confidence.LOW


def score_cor001_confidence(
    failures: list[NormalizedEvent], success: NormalizedEvent, threshold: int
) -> list[ConfidenceFactor]:
    """Explainable factors for "failures then success". Positive = stronger evidence of attack.

    The same sequence is produced by a user who mistypes a password and then gets it
    right, so the factors look for what separates the two: where the success came
    from, how it logged on, and how large and spread out the failures were.
    """
    factors: list[ConfidenceFactor] = []
    failure_ips = {f.source_ip for f in failures if f.source_ip}
    failure_types = {f.logon_type for f in failures if f.logon_type is not None}
    failure_workstations = {f.workstation_name.casefold() for f in failures if f.workstation_name}
    success_type = success.logon_type
    remote_success = is_remote_address(success.source_ip)

    if success_type in REMOTE_LOGON_TYPES:
        factors.append(
            ConfidenceFactor(
                2,
                f"Success was a {success.logon_type_name} logon (type {success_type}), "
                "which is reachable from the network",
            )
        )
    elif success_type in LOCAL_INTERACTIVE_TYPES:
        factors.append(
            ConfidenceFactor(
                -1,
                f"Success was a local {success.logon_type_name} logon (type {success_type}), "
                "common after a user mistypes a password",
            )
        )
    if remote_success:
        factors.append(ConfidenceFactor(1, f"Success came from remote address {success.source_ip}"))
        if success.source_ip in failure_ips:
            factors.append(
                ConfidenceFactor(1, "The same remote address produced the failures and the success")
            )
    if len(failure_ips) >= MANY_SOURCES:
        factors.append(
            ConfidenceFactor(1, f"Failures came from {len(failure_ips)} different addresses")
        )
    if len(failures) >= 2 * threshold:
        factors.append(ConfidenceFactor(1, f"High attempt volume: {len(failures)} failures"))
    same_workstation = bool(success.workstation_name) and (
        success.workstation_name.casefold() in failure_workstations
    )
    if not remote_success and same_workstation and success_type in failure_types:
        factors.append(
            ConfidenceFactor(
                -1, "Same workstation and logon type as the failures, with no remote address"
            )
        )
    return factors


def correlate_failed_then_success(
    events: Iterable[NormalizedEvent],
    rule: RuleMetadata,
    context: DetectionContext | None = None,
) -> list[Detection]:
    """COR-001: a 4624 preceded by >= threshold 4625s for the same identity within the window."""
    events = list(events)
    params = rule.parameters
    threshold = int(params["threshold"])
    window = timedelta(minutes=int(params["window_minutes"]))
    resolver = IdentityResolver(events, domains_of(context))
    privileged = PrivilegedSessions(events)

    def key(event: NormalizedEvent) -> str | None:
        identity = resolver.target(event)
        return identity.key if identity else None

    failures_by_identity = group_events(events, int(params["failure_event_id"]), key)
    successes_by_identity = group_events(events, int(params["success_event_id"]), key)

    detections: list[Detection] = []
    for identity_key, successes in successes_by_identity.items():
        failures = failures_by_identity.get(identity_key)
        if not failures:
            continue
        last_reported_failure: int | None = None
        for success in successes:
            window_failures = [
                f
                for f in failures
                if _before(f, success) and success.timestamp - f.timestamp <= window
            ]
            if len(window_failures) < threshold:
                continue
            # Several successes after the same burst describe one incident: report once.
            if window_failures[-1].record_id == last_reported_failure:
                continue
            last_reported_failure = window_failures[-1].record_id

            identity = resolver.target(success)
            if identity is None:  # grouped by identity, so this cannot happen
                continue
            factors = score_cor001_confidence(window_failures, success, threshold)
            points = sum(f.points for f in factors)
            confidence = confidence_from_points(points)
            evidence = _cor001_evidence(window_failures, success, threshold, params)
            evidence["identity"] = identity.as_evidence()
            evidence["account"] = identity.display
            evidence["confidence"] = {
                "value": confidence.value,
                "points": points,
                "factors": [{"points": f.points, "reason": f.reason} for f in factors],
                "scale": "points <= 0: LOW, 1-2: MEDIUM, >= 3: HIGH",
            }
            evidence_events = [*window_failures, success]
            session = privileged.for_logon(success)
            if session is not None:
                evidence["privileged_session"] = describe_privileges(session)
                evidence_events.append(session)
            detection = build_detection(
                rule,
                success,
                evidence_events,
                identity.display,
                evidence,
                derived_confidence=confidence,
                confidence_factors=tuple(factors),
            )
            detections.append(detection)
    return detections


def _cor001_evidence(
    failures: list[NormalizedEvent],
    success: NormalizedEvent,
    threshold: int,
    params: dict[str, Any],
) -> dict[str, Any]:
    failure_ips = {f.source_ip for f in failures if f.source_ip}
    failure_types = {f.logon_type for f in failures if f.logon_type is not None}
    failure_workstations = {f.workstation_name.casefold() for f in failures if f.workstation_name}
    return {
        "username": success.target_username,
        "hostname": success.hostname,
        "threshold": threshold,
        "window_minutes": int(params["window_minutes"]),
        **summarize_failures(failures),
        "total_attempts": len(failures),
        "distinct_source_count": len(failure_ips),
        "success_time": success.timestamp.isoformat(),
        "success_record_id": success.record_id,
        "success_logon_type": success.logon_type_name,
        "success_source_address": success.source_ip,
        "success_workstation": success.workstation_name,
        "success_authentication_package": success.authentication_package,
        "success_logon_id": success.logon_id,
        "success_from_failure_source": (
            success.source_ip in failure_ips if success.source_ip else None
        ),
        "logon_type_matched": (
            success.logon_type in failure_types if success.logon_type is not None else None
        ),
        "workstation_matched": (
            success.workstation_name.casefold() in failure_workstations
            if success.workstation_name
            else None
        ),
        "seconds_from_last_failure_to_success": int(
            (success.timestamp - failures[-1].timestamp).total_seconds()
        ),
    }
