"""Microsoft Defender Operational log: detections (1116) and remediation (1117-1119).

These events are Microsoft Defender's own verdicts. MoeSOC records and correlates
them; it never claims to have identified malware itself.
"""

from __future__ import annotations

import json
from typing import Any

from moesoc.core.enums import DefenderEventId, TelemetrySource
from moesoc.core.event import NormalizedEvent
from moesoc.core.exceptions import EventParseError
from moesoc.parsers.windows_event import RawWindowsEvent, parse_event_xml

DEFENDER_CHANNEL = "Microsoft-Windows-Windows Defender/Operational"
SUPPORTED_DEFENDER_IDS = frozenset(int(e) for e in DefenderEventId)
SUCCESS_CODE = "0x00000000"
FILE_TYPES = ("file", "containerfile", "webfile")


def _int(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def split_resources(path: str | None) -> list[tuple[str, str]]:
    """'file:_C:\\a.exe; process:_pid:4,…' → [('file', 'C:\\a.exe'), ('process', 'pid:4,…')]."""
    resources: list[tuple[str, str]] = []
    for part in (path or "").split("; "):
        part = part.strip()
        if not part:
            continue
        kind, sep, value = part.partition(":_")
        if sep:
            resources.append((kind.casefold(), value))
        else:
            resources.append(("unknown", part))
    return resources


def primary_file(resources: list[tuple[str, str]]) -> str | None:
    """The first file Defender named. Webfile entries are 'path|url|…'; keep the path."""
    for kind, value in resources:
        if kind in FILE_TYPES:
            return value.split("|", 1)[0] or None
    return None


def _split_account(value: str | None) -> tuple[str | None, str | None]:
    if not value:
        return None, None
    domain, sep, name = value.rpartition("\\")
    return (domain or None, name) if sep else (None, value)


def _process(value: str | None) -> tuple[str | None, str | None]:
    if not value or value.casefold() == "unknown":
        return None, None
    return value, value.replace("/", "\\").rsplit("\\", 1)[-1]


def normalize_defender_event(raw: RawWindowsEvent) -> NormalizedEvent:
    if raw.event_id not in SUPPORTED_DEFENDER_IDS:
        raise EventParseError(f"Unsupported Defender event ID {raw.event_id}")
    resources = split_resources(raw.get("Path"))
    domain, user = _split_account(raw.get("Detection User"))
    process_path, process_name = _process(raw.get("Process Name"))
    details: dict[str, Any] = {
        "detection_id": (raw.get("Detection ID") or "").strip("{}").lower() or None,
        "detection_time": raw.get("Detection Time"),
        "threat_name": raw.get("Threat Name"),
        "threat_id": raw.get("Threat ID"),
        "severity_name": raw.get("Severity Name"),
        "category_name": raw.get("Category Name"),
        "source_name": raw.get("Source Name"),
        "origin_name": raw.get("Origin Name"),
        "execution_name": raw.get("Execution Name"),
        "type_name": raw.get("Type Name"),
        "action_id": _int(raw.get("Action ID")),
        "action_name": raw.get("Action Name"),
        "error_code": raw.get("Error Code"),
        "error_description": raw.get("Error Description"),
        "additional_actions": raw.get("Additional Actions String"),
        "remediation_user": raw.get("Remediation User"),
        "resources": [f"{kind}: {value}" for kind, value in resources] or None,
        "intelligence_version": raw.get("Security intelligence Version")
        or raw.get("Signature Version"),
        "engine_version": raw.get("Engine Version"),
        "product_version": raw.get("Product Version"),
    }
    details = {k: v for k, v in details.items() if v is not None}
    return NormalizedEvent(
        timestamp=raw.timestamp,
        record_id=raw.record_id,
        source=TelemetrySource.DEFENDER,
        channel=raw.channel,
        provider=raw.provider,
        event_id=raw.event_id,
        hostname=raw.hostname,
        raw_xml=raw.raw_xml,
        subject_username=user,
        subject_domain=domain,
        process_path=process_path,
        process_name=process_name,
        file_path=primary_file(resources),
        details=json.dumps(details, sort_keys=True),
    )


def parse_defender_xml(xml_text: str) -> NormalizedEvent:
    raw = parse_event_xml(xml_text)
    if raw.channel != DEFENDER_CHANNEL:
        raise EventParseError(f"Not a Defender Operational event (channel {raw.channel})")
    return normalize_defender_event(raw)
