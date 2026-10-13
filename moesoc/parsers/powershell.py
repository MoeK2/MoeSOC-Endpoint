"""PowerShell Operational log: Event 4104 (script block logging).

Privacy: the script text is NOT copied into normalized fields. It stays only in the
locally stored raw event; normalized fields keep its identity (ScriptBlockId, part
N of M, path), size and SHA-256 so analysts can recognise and compare scripts
without spreading their content. DET-007 reads the text from the raw event.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from moesoc.core.enums import PowerShellEventId, TelemetrySource
from moesoc.core.event import NormalizedEvent
from moesoc.core.exceptions import EventParseError
from moesoc.parsers.windows_event import RawWindowsEvent, parse_event_xml

POWERSHELL_CHANNEL = "Microsoft-Windows-PowerShell/Operational"
SUPPORTED_POWERSHELL_IDS = frozenset(int(e) for e in PowerShellEventId)
WARNING_LEVEL = 3  # PowerShell logs suspicious script blocks at Warning level


def _int(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def script_text(raw: RawWindowsEvent) -> str | None:
    """The script block text of a 4104 (only from the raw event)."""
    return raw.data.get("ScriptBlockText") or None


def normalize_powershell_event(raw: RawWindowsEvent) -> NormalizedEvent:
    if raw.event_id != PowerShellEventId.SCRIPT_BLOCK:
        raise EventParseError(f"Unsupported PowerShell event ID {raw.event_id}")
    text = script_text(raw) or ""
    details: dict[str, Any] = {
        "script_block_id": (raw.get("ScriptBlockId") or "").lower() or None,
        "message_number": _int(raw.get("MessageNumber")),
        "message_total": _int(raw.get("MessageTotal")),
        "script_length": len(text),
        "script_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest() if text else None,
        "level": raw.level,
        "windows_flagged": raw.level == WARNING_LEVEL,
    }
    details = {k: v for k, v in details.items() if v is not None}
    return NormalizedEvent(
        timestamp=raw.timestamp,
        record_id=raw.record_id,
        source=TelemetrySource.POWERSHELL,
        channel=raw.channel,
        provider=raw.provider,
        event_id=raw.event_id,
        hostname=raw.hostname,
        raw_xml=raw.raw_xml,
        subject_user_sid=raw.user_sid,
        process_id=raw.execution_process_id,  # the PowerShell host process
        file_path=raw.get("Path"),  # the script file, when it came from a file
        details=json.dumps(details, sort_keys=True),
    )


def parse_powershell_xml(xml_text: str) -> NormalizedEvent:
    raw = parse_event_xml(xml_text)
    if raw.channel != POWERSHELL_CHANNEL:
        raise EventParseError(f"Not a PowerShell Operational event (channel {raw.channel})")
    return normalize_powershell_event(raw)
