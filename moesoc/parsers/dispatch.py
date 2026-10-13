"""Route a rendered event to the parser of its channel."""

from __future__ import annotations

from moesoc.core.event import NormalizedEvent
from moesoc.core.exceptions import EventParseError
from moesoc.parsers.defender import DEFENDER_CHANNEL, normalize_defender_event
from moesoc.parsers.powershell import POWERSHELL_CHANNEL, normalize_powershell_event
from moesoc.parsers.security import SECURITY_CHANNEL, normalize_security_event
from moesoc.parsers.sysmon import SYSMON_CHANNEL, normalize_sysmon_event
from moesoc.parsers.windows_event import parse_event_xml


def parse_any_xml(xml_text: str) -> NormalizedEvent:
    """Parse one event from any supported channel. Raises EventParseError otherwise."""
    raw = parse_event_xml(xml_text)
    if raw.channel == SECURITY_CHANNEL:
        return normalize_security_event(raw)
    if raw.channel == SYSMON_CHANNEL:
        return normalize_sysmon_event(raw)
    if raw.channel == POWERSHELL_CHANNEL:
        return normalize_powershell_event(raw)
    if raw.channel == DEFENDER_CHANNEL:
        return normalize_defender_event(raw)
    raise EventParseError(f"Unsupported channel {raw.channel}")
