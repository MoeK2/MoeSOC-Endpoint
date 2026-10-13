"""DET-008: Microsoft Defender detection, correlated with Defender's remediation result.

Microsoft Defender decides what is malware; MoeSOC only reports and correlates what
Defender recorded. One finding per Defender Detection ID: the detection (1116) is
joined with the action Defender took (1117) or failed to take (1118/1119).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import replace

from moesoc.core.detection import Detection, RuleMetadata
from moesoc.core.enums import Confidence, DefenderEventId, Severity, TelemetrySource
from moesoc.core.event import NormalizedEvent
from moesoc.engine.context import DetectionContext
from moesoc.engine.rules import build_detection, chronological
from moesoc.parsers.defender import SUCCESS_CODE

DET_008 = "DET-008"
DEFENDER_SEVERITY = {
    "severe": Severity.HIGH,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
}
REMEDIATING_ACTIONS = {"quarantine", "remove", "clean", "block"}
FAILED_IDS = {int(DefenderEventId.ACTION_FAILED), int(DefenderEventId.ACTION_CRITICAL_FAILURE)}

# Remediation states, in the words the analyst sees.
REMEDIATED = "remediated"
FAILED = "action failed"
ALLOWED = "allowed"
OTHER_ACTION = "action recorded"
PENDING = "no action recorded"


def is_defender_event(e: NormalizedEvent) -> bool:
    return e.source is TelemetrySource.DEFENDER and e.event_id in {int(i) for i in DefenderEventId}


def detection_key(e: NormalizedEvent) -> str:
    return e.detail("detection_id") or f"record:{e.record_id}"


def remediation(actions: list[NormalizedEvent]) -> tuple[str, NormalizedEvent | None]:
    """The outcome of the latest action event (Defender may retry after a failure)."""
    if not actions:
        return PENDING, None
    last = chronological(actions)[-1]
    if last.event_id in FAILED_IDS:
        return FAILED, last
    error = (last.detail("error_code") or SUCCESS_CODE).casefold()
    if error != SUCCESS_CODE:
        return FAILED, last
    action = (last.detail("action_name") or "").casefold()
    if action in REMEDIATING_ACTIONS:
        return REMEDIATED, last
    if action == "allow":
        return ALLOWED, last
    return OTHER_ACTION, last


def detect_defender_detections(
    events: Iterable[NormalizedEvent],
    rule: RuleMetadata,
    context: DetectionContext | None = None,
) -> list[Detection]:
    groups: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
    for e in events:
        if is_defender_event(e):
            groups[(e.hostname.casefold(), detection_key(e))].append(e)

    detections: list[Detection] = []
    for (_host, key), group in groups.items():
        unique = chronological({e.record_id: e for e in group}.values())
        detected = [e for e in unique if e.event_id == DefenderEventId.MALWARE_DETECTED]
        actions = [e for e in unique if e.event_id != DefenderEventId.MALWARE_DETECTED]
        first = detected[0] if detected else unique[0]
        info = detected[-1] if detected else unique[-1]  # every event repeats the threat data
        state, action_event = remediation(actions)

        defender_severity = info.detail("severity_name")
        severity = DEFENDER_SEVERITY.get((defender_severity or "").casefold(), Severity.MEDIUM)
        reasons = [f"Defender severity {defender_severity or 'unknown'} → {severity.value}"]
        raised_for: list[str] = []
        if state in (FAILED, ALLOWED) and severity is not Severity.HIGH:
            severity = Severity.HIGH
            raised_for.append("remediation")
            reasons.append(f"raised to HIGH: the threat was {state}, so it may still be present")

        threat = info.detail("threat_name") or "an unnamed threat"
        if state == REMEDIATED and action_event is not None:
            outcome = f"Defender reports action '{action_event.detail('action_name')}' succeeded"
        elif state == FAILED and action_event is not None:
            outcome = (
                "Defender reports its action failed: "
                f"{action_event.detail('error_description') or action_event.detail('error_code')}"
            )
        elif state == ALLOWED:
            outcome = "The threat was allowed (a user or policy chose to allow it)"
        elif state == OTHER_ACTION and action_event is not None:
            outcome = f"Defender recorded action '{action_event.detail('action_name')}'"
        else:
            outcome = "No remediation result recorded yet (Event 1117/1118/1119 not seen)"

        evidence = {
            "summary": f"Microsoft Defender detected {threat}",
            "hostname": first.hostname,
            "threat_name": info.detail("threat_name"),
            "threat_id": info.detail("threat_id"),
            "defender_severity": defender_severity,
            "category": info.detail("category_name"),
            "detection_id": info.detail("detection_id"),
            "detected_at": detected[0].timestamp.isoformat() if detected else None,
            "detection_source": info.detail("source_name"),
            "origin": info.detail("origin_name"),
            "user": info.subject_account_display,
            "process": info.process_path,
            "file_path": info.file_path,
            "resources": info.detail("resources"),
            "remediation": {
                "state": state,
                "outcome": outcome,
                "action": action_event.detail("action_name") if action_event else None,
                "at": action_event.timestamp.isoformat() if action_event else None,
                "error_code": action_event.detail("error_code") if action_event else None,
                "event_id": action_event.event_id if action_event else None,
                "seconds_after_detection": (
                    int((action_event.timestamp - detected[0].timestamp).total_seconds())
                    if action_event and detected
                    else None
                ),
            },
            "severity_reasons": reasons,
            # Conditions already counted by raising the severity; the risk model does not
            # add their modifier again (audit A-8).
            "severity_raised_for": raised_for,
            "detections_recorded": len(detected),
            "intelligence_version": info.detail("intelligence_version"),
            "verdict_source": "Microsoft Defender (MoeSOC reports Defender's verdict)",
        }
        detection = build_detection(
            rule,
            first,
            list(unique),
            info.subject_account_display,
            evidence,
            derived_severity=severity,
            derived_confidence=Confidence.HIGH,
        )
        # One finding per Defender detection, even when 1117 arrives in a later scan.
        detections.append(replace(detection, dedup_key=f"{DET_008}|{first.hostname}|{key}"))
    return detections
