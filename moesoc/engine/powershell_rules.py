"""DET-007: Suspicious PowerShell Behavior (Event 4104 + process context)."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from moesoc.core.detection import Detection, RuleMetadata
from moesoc.core.enums import (
    Confidence,
    PowerShellEventId,
    Severity,
    TelemetrySource,
)
from moesoc.core.event import NormalizedEvent
from moesoc.core.exceptions import EventParseError
from moesoc.engine.activity import ActivityGraph
from moesoc.engine.context import DetectionContext
from moesoc.engine.powershell_indicators import Indicator, analyze_script, merge
from moesoc.engine.rules import build_detection, chronological
from moesoc.parsers.powershell import script_text
from moesoc.parsers.windows_event import parse_event_xml

DET_007 = "DET-007"
ENCODED_FLAG = re.compile(r"\s-(e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\s", re.I)
HIDDEN_FLAG = re.compile(r"-w(indowstyle)?\s+(hidden|1)\b", re.I)


def _fragment_text(event: NormalizedEvent) -> str:
    """Script text from the locally stored raw event (never from normalized fields)."""
    try:
        return script_text(parse_event_xml(event.raw_xml)) or ""
    except EventParseError:
        return ""


def _process_indicators(process: NormalizedEvent | None, params: dict[str, Any]) -> list[Indicator]:
    if process is None:
        return []
    found: list[Indicator] = []
    parent = (process.parent_process or "").replace("/", "\\").rsplit("\\", 1)[-1].casefold()
    unusual = {str(p).casefold() for p in params.get("unusual_parents") or ()}
    if parent and parent in unusual:
        found.append(
            Indicator("unusual_parent", 2, f"PowerShell was started by {parent}", "T1059.001", None)
        )
    command = f" {process.command_line or ''} "
    if ENCODED_FLAG.search(command):
        found.append(
            Indicator("encoded_command_line", 2, "Started with -EncodedCommand", "T1027", None)
        )
    if HIDDEN_FLAG.search(command):
        found.append(
            Indicator("hidden_window", 1, "Started with a hidden window", "T1564.003", None)
        )
    return found


def detect_suspicious_powershell(
    events: Iterable[NormalizedEvent],
    rule: RuleMetadata,
    context: DetectionContext | None = None,
) -> list[Detection]:
    events = list(events)
    params = rule.parameters
    threshold = int(params.get("threshold", 3))
    high_at = int(params.get("high_at", 6))
    graph = ActivityGraph(events)

    blocks: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
    for e in events:
        if e.source is TelemetrySource.POWERSHELL and e.event_id == PowerShellEventId.SCRIPT_BLOCK:
            block_id = e.detail("script_block_id") or f"record:{e.record_id}"
            blocks[(e.hostname.casefold(), block_id)].append(e)

    detections: list[Detection] = []
    for (_host, block_id), fragments in blocks.items():
        # Reassemble a script that Windows split over several events (part N of M).
        unique = {e.record_id: e for e in fragments}.values()
        parts = sorted(unique, key=lambda e: (e.detail("message_number") or 0, e.record_id))
        text = "".join(_fragment_text(e) for e in parts)
        flagged = any(e.detail("windows_flagged") for e in parts)
        first = chronological(parts)[0]
        link = graph.process_by_pid(first.hostname, first.process_id, first)
        process = link.event if link else None
        indicators = merge(
            analyze_script(text, windows_flagged=flagged) + _process_indicators(process, params)
        )
        points = sum(i.points for i in indicators)
        if points < threshold:
            continue
        high = points >= high_at
        user = None
        if process is not None and process.subject_username:
            user = process.subject_account_display or process.subject_username
        total = parts[0].detail("message_total")
        evidence = {
            "hostname": first.hostname,
            "user": user or first.subject_user_sid,
            "user_sid": first.subject_user_sid,
            "script_block_id": None if block_id.startswith("record:") else block_id,
            "script_parts": f"{len(parts)} of {total}" if total else str(len(parts)),
            "script_length": len(text),
            "script_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest() if text else None,
            "script_path": first.file_path,
            "powershell_pid": first.process_id,
            "process": process.process_path if process else None,
            "parent_process": process.parent_process if process else None,
            "process_command_line_recorded": bool(process and process.command_line),
            "integrity_level": process.integrity_level if process else None,
            "windows_flagged": flagged,
            "score": {
                "points": points,
                "threshold": threshold,
                "high_at": high_at,
                "indicators": [i.as_evidence() for i in indicators],
            },
            "related_techniques": sorted({i.technique for i in indicators if i.technique}),
        }
        evidence_events = [*parts, *([process] if process else [])]
        detections.append(
            build_detection(
                rule,
                first,
                evidence_events,
                user or first.subject_user_sid,
                evidence,
                derived_severity=Severity.HIGH if high else None,
                derived_confidence=Confidence.HIGH if high else None,
            )
        )
    return detections
