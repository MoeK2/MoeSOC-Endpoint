"""Cross-source correlations (Security + Sysmon + PowerShell + Defender).

COR-003  Suspicious activity in a session opened after failed logons.
COR-004  A file detected by Microsoft Defender, traced to the process that wrote it.

Each step of a chain says which log it came from and how it is linked to the
previous step (see ``engine/activity.py``). A chain is a lead, not proof.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace
from datetime import timedelta
from typing import Any

from moesoc.core.detection import Detection, RuleMetadata
from moesoc.core.enums import (
    Confidence,
    DefenderEventId,
    SecurityEventId,
    Severity,
    SysmonEventId,
    TelemetrySource,
)
from moesoc.core.event import NormalizedEvent
from moesoc.engine.activity import LINK_STRENGTH, ActivityGraph, Link, is_process_start
from moesoc.engine.context import DetectionContext
from moesoc.engine.correlation import correlate_failed_then_success
from moesoc.engine.defender_rules import (
    DEFENDER_SEVERITY,
    REMEDIATED,
    detection_key,
    is_defender_event,
    remediation,
)
from moesoc.engine.powershell_rules import DET_007, detect_suspicious_powershell
from moesoc.engine.rules import build_detection, chronological

COR_003 = "COR-003"
COR_004 = "COR-004"
MAX_LISTED = 10


def _name(path: str | None) -> str | None:
    return path.replace("/", "\\").rsplit("\\", 1)[-1] if path else None


def describe(e: NormalizedEvent) -> str:
    """Short, content-free description of one step (no command lines, no script text)."""
    if e.source is TelemetrySource.SECURITY:
        if e.event_id == SecurityEventId.LOGON_SUCCESS:
            return f"Successful {e.logon_type_name or ''} logon".replace("  ", " ")
        if e.event_id == SecurityEventId.PROCESS_CREATED:
            return f"Process {e.process_name or '?'} started"
        if e.event_id == SecurityEventId.ACCOUNT_CREATED:
            return f"User account {e.target_account_display or e.target_user_sid} created"
        if e.event_id == SecurityEventId.LOCAL_GROUP_MEMBER_ADDED:
            member = e.member_name or e.member_sid or "member"
            return f"{member} added to group {e.group_name or e.group_sid}"
        if e.event_id == SecurityEventId.SPECIAL_PRIVILEGES:
            return "Special privileges assigned to the session"
    if e.source is TelemetrySource.SYSMON:
        if e.event_id == SysmonEventId.PROCESS_CREATE:
            return f"Process {e.process_name or '?'} started"
        if e.event_id == SysmonEventId.DNS_QUERY:
            return f"{e.process_name or 'A process'} looked up {e.dns_query}"
        if e.event_id == SysmonEventId.NETWORK_CONNECT:
            return (
                f"{e.process_name or 'A process'} connected to "
                f"{e.destination_ip}:{e.destination_port or '?'}"
            )
        if e.event_id == SysmonEventId.FILE_CREATE:
            return f"{e.process_name or 'A process'} wrote {e.file_path}"
    if e.source is TelemetrySource.POWERSHELL:
        return "PowerShell script block with suspicious indicators (DET-007)"
    if e.source is TelemetrySource.DEFENDER:
        if e.event_id == DefenderEventId.MALWARE_DETECTED:
            return f"Microsoft Defender detected {e.detail('threat_name') or 'a threat'}"
        return f"Microsoft Defender action {e.detail('action_name') or e.event_id}"
    return f"Event {e.event_id}"


def step(e: NormalizedEvent, link: str | None) -> dict[str, Any]:
    return {
        "time": e.timestamp.isoformat(),
        "log": e.source.value,
        "event_id": e.event_id,
        "record_id": e.record_id,
        "what": describe(e),
        "link": link,
        "link_strength": LINK_STRENGTH.get(link or "", None),
    }


# ----------------------------------------------------------------- COR-003
def _failure_bursts(
    events: list[NormalizedEvent], rule: RuleMetadata, context: DetectionContext | None
) -> list[Detection]:
    """Reuse COR-001's matching (identity aliases, ordering) with COR-003's parameters."""
    params = rule.parameters
    burst_rule = replace(
        rule,
        parameters={
            "threshold": int(params.get("failure_threshold", 5)),
            "window_minutes": int(params.get("failure_window_minutes", 10)),
            "failure_event_id": int(SecurityEventId.LOGON_FAILURE),
            "success_event_id": int(SecurityEventId.LOGON_SUCCESS),
        },
    )
    return correlate_failed_then_success(events, burst_rule, context)


def _suspicious_powershell_processes(
    events: list[NormalizedEvent], context: DetectionContext | None
) -> list[tuple[NormalizedEvent, Detection]]:
    """(PowerShell process start, DET-007 finding) pairs, using DET-007's own scoring."""
    rule = context.rules.get(DET_007) if context else None
    if rule is None:
        return []
    by_ref = {(e.hostname, e.channel, e.record_id): e for e in events if is_process_start(e)}
    pairs: list[tuple[NormalizedEvent, Detection]] = []
    for finding in detect_suspicious_powershell(events, rule, context):
        for ref in finding.evidence_refs:
            process = by_ref.get((ref.hostname, ref.channel, ref.record_id))
            if process is not None:
                pairs.append((process, finding))
    return pairs


def correlate_session_activity(
    events: Iterable[NormalizedEvent],
    rule: RuleMetadata,
    context: DetectionContext | None = None,
) -> list[Detection]:
    events = list(events)
    params = rule.parameters
    follow = timedelta(minutes=int(params.get("follow_window_minutes", 60)))
    graph = ActivityGraph(events)
    by_record = {
        (e.hostname, e.record_id): e for e in events if e.source is TelemetrySource.SECURITY
    }
    powershell = _suspicious_powershell_processes(events, context)

    detections: list[Detection] = []
    for burst in _failure_bursts(events, rule, context):
        logon = by_record.get((burst.evidence["hostname"], burst.evidence["success_record_id"]))
        if logon is None:
            continue
        session = graph.session_events(logon, follow)
        in_session = {(link.event.channel, link.event.record_id) for link in session}

        follow_ups: list[Link] = []
        categories: set[str] = set()
        processes: list[NormalizedEvent] = []
        for link in session:
            e = link.event
            if e.event_id == SecurityEventId.ACCOUNT_CREATED:
                follow_ups.append(link)
                categories.add("account_created")
            elif e.event_id == SecurityEventId.LOCAL_GROUP_MEMBER_ADDED:
                follow_ups.append(link)
                categories.add("group_member_added")
            elif is_process_start(e):
                processes.append(e)
        powershell_findings: list[dict[str, Any]] = []
        for process, finding in powershell:
            if (process.channel, process.record_id) in in_session:
                follow_ups.append(Link(process, "logon_id"))
                categories.add("suspicious_powershell")
                powershell_findings.append(
                    {
                        "points": finding.evidence["score"]["points"],
                        "indicators": [i["id"] for i in finding.evidence["score"]["indicators"]],
                        "process": process.process_name,
                        "pid": process.process_id,
                    }
                )
        for link in graph.defender_detections_for_user(logon, follow):
            follow_ups.append(link)
            categories.add("defender_detection")
        if not categories:
            continue  # a session with only ordinary processes is not a finding

        exact = any(link.kind != "user_time" for link in follow_ups)
        confidence = Confidence.HIGH if exact else Confidence.MEDIUM
        burst_refs = set(burst.evidence_refs)
        failures = [
            e for e in events if e.event_id == SecurityEventId.LOGON_FAILURE and e.ref in burst_refs
        ]
        chain = [
            {
                "time": burst.evidence["first_failure"],
                "log": "security",
                "event_id": int(SecurityEventId.LOGON_FAILURE),
                "record_id": None,
                "what": f"{burst.evidence['failure_count']} failed logons for "
                f"{burst.evidence['account']}",
                "link": None,
                "link_strength": None,
            },
            step(logon, "account"),
            *[step(link.event, link.kind) for link in sorted(follow_ups, key=_link_order)],
        ]
        evidence = {
            "account": burst.evidence["account"],
            "hostname": logon.hostname,
            "failure_count": burst.evidence["failure_count"],
            "first_failure": burst.evidence["first_failure"],
            "success_time": logon.timestamp.isoformat(),
            "success_logon_type": logon.logon_type_name,
            "success_source_address": logon.source_ip,
            "success_logon_id": logon.logon_id,
            "follow_window_minutes": int(follow.total_seconds() // 60),
            "follow_up_kinds": sorted(categories),
            "chain": chain,
            "suspicious_powershell": powershell_findings or None,
            "processes_in_session": [p.process_name for p in processes[:MAX_LISTED]] or None,
            "processes_in_session_count": len(processes),
            "link_quality": (
                "exact (same logon session)"
                if exact
                else "weak (Defender detection matched by user and time only)"
            ),
            "note": "COR-001 reports the failed-then-successful logon itself; COR-003 adds what "
            "happened in that session.",
        }
        evidence_events = [*failures, logon, *(link.event for link in follow_ups)]
        detections.append(
            build_detection(
                rule,
                logon,
                evidence_events,
                burst.evidence["account"],
                evidence,
                derived_confidence=confidence,
            )
        )
    return detections


def _link_order(link: Link) -> tuple[object, int]:
    return (link.event.timestamp, link.event.record_id)


# ----------------------------------------------------------------- COR-004
def correlate_defender_file_source(
    events: Iterable[NormalizedEvent],
    rule: RuleMetadata,
    context: DetectionContext | None = None,
) -> list[Detection]:
    events = list(events)
    window = timedelta(minutes=int(rule.parameters.get("file_window_minutes", 60)))
    graph = ActivityGraph(events)

    defender: dict[tuple[str, str], list[NormalizedEvent]] = {}
    for e in events:
        if is_defender_event(e):
            defender.setdefault((e.hostname.casefold(), detection_key(e)), []).append(e)

    detections: list[Detection] = []
    for (_host, key), group in defender.items():
        unique = chronological({e.record_id: e for e in group}.values())
        detected = [e for e in unique if e.event_id == DefenderEventId.MALWARE_DETECTED]
        if not detected or not detected[0].file_path:
            continue
        detection = detected[0]
        created = graph.file_created(detection.hostname, detection.file_path, detection, window)
        if created is None:
            continue
        creator_link = graph.process_of(created)
        creator = creator_link.event if creator_link else None
        activity = [
            e
            for e in (graph.caused_by(creator) if creator else [])
            if e.event_id in (SysmonEventId.DNS_QUERY, SysmonEventId.NETWORK_CONNECT)
            and created.timestamp - window <= e.timestamp <= created.timestamp
        ][-MAX_LISTED:]
        executions = graph.executions_of(detection.hostname, detection.file_path, created)
        actions = [e for e in unique if e.event_id != DefenderEventId.MALWARE_DETECTED]
        state, _action = remediation(actions)

        defender_severity = detection.detail("severity_name")
        severity = DEFENDER_SEVERITY.get((defender_severity or "").casefold(), Severity.MEDIUM)
        reasons = [f"Defender severity {defender_severity or 'unknown'} → {severity.value}"]
        raised_for: list[str] = []
        if executions and severity is not Severity.HIGH:
            severity = Severity.HIGH
            raised_for.append("executed")
            reasons.append("raised to HIGH: the file was started as a process")
        if state != REMEDIATED and actions and severity is not Severity.HIGH:
            severity = Severity.HIGH
            raised_for.append("remediation")
            reasons.append(f"raised to HIGH: remediation state is '{state}'")

        techniques = []
        if activity:
            techniques.append("T1105")  # Ingress Tool Transfer
        if executions:
            techniques.append("T1204.002")  # User Execution: Malicious File
        chain = [
            *([step(creator, None)] if creator else []),
            *[step(e, "process_guid") for e in activity],
            step(created, "process_guid" if creator else None),
            *[step(e, "file_path") for e in executions[:MAX_LISTED]],
            step(detection, "file_path"),
            *[step(e, "detection_id") for e in actions[-1:]],
        ]
        chain.sort(key=lambda s: s["time"])
        evidence = {
            "summary": f"Microsoft Defender detected {detection.detail('threat_name')} in a "
            f"file written by {created.process_name or 'an unknown process'}",
            "hostname": detection.hostname,
            "threat_name": detection.detail("threat_name"),
            "defender_severity": defender_severity,
            "detection_id": detection.detail("detection_id"),
            "file_path": detection.file_path,
            "file_created_at": created.timestamp.isoformat(),
            "seconds_from_write_to_detection": int(
                (detection.timestamp - created.timestamp).total_seconds()
            ),
            "written_by": created.process_path,
            "written_by_guid": created.process_guid,
            "writer_parent": creator.parent_process if creator else None,
            "writer_user": creator.subject_account_display if creator else None,
            "writer_start_collected": creator is not None,
            "dns_queries": sorted({e.dns_query for e in activity if e.dns_query}) or None,
            "connections": sorted(
                {f"{e.destination_ip}:{e.destination_port}" for e in activity if e.destination_ip}
            )
            or None,
            "executed": bool(executions),
            "executions": len(executions),
            "remediation_state": state,
            "chain": chain,
            "severity_reasons": reasons,
            "severity_raised_for": raised_for,  # not counted again as risk modifiers
            "related_techniques": techniques or None,
            "verdict_source": "Microsoft Defender (MoeSOC traced where the file came from)",
        }
        evidence_events = [
            *([creator] if creator else []),
            *activity,
            created,
            *executions[:MAX_LISTED],
            *unique,
        ]
        finding = build_detection(
            rule,
            detection,
            evidence_events,
            creator.subject_account_display if creator else detection.subject_account_display,
            evidence,
            derived_severity=severity,
            derived_confidence=Confidence.HIGH if creator else Confidence.MEDIUM,
        )
        detections.append(replace(finding, dedup_key=f"{COR_004}|{detection.hostname}|{key}"))
    return detections
