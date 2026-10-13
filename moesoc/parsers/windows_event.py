"""Generic, defensive parsing of rendered Windows Event XML.

Fields are located by element name and by ``<Data Name="...">`` attributes —
never by position — so new event versions with extra fields keep working.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime

from moesoc.core.exceptions import EventParseError
from moesoc.utils.time import parse_windows_timestamp

EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
MAX_EVENT_XML_BYTES = 1_000_000  # a single rendered event is normally a few KB


@dataclass(frozen=True, slots=True)
class RawWindowsEvent:
    """The System header plus a name→value map of EventData."""

    provider: str
    event_id: int
    version: int | None
    channel: str
    hostname: str
    record_id: int
    timestamp: datetime
    data: dict[str, str]
    raw_xml: str
    data_section: str = "EventData"  # "EventData", "UserData" or "None"
    level: int | None = None  # 1 critical … 4 information (System/Level)
    execution_process_id: int | None = None  # System/Execution/@ProcessID: who wrote it
    user_sid: str | None = None  # System/Security/@UserID (the writer's account)

    def get(self, name: str) -> str | None:
        """Return a cleaned EventData value, or None for empty/placeholder values."""
        return clean_value(self.data.get(name))


# Windows uses these strings to mean "no value".
_PLACEHOLDERS = {"", "-", "%%1793", "n/a"}


def clean_value(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    if stripped.casefold() in _PLACEHOLDERS:
        return None
    return stripped


def _find(parent: ET.Element, tag: str) -> ET.Element | None:
    # Accept both namespaced (normal) and non-namespaced XML.
    found = parent.find(f"{EVENT_NS}{tag}")
    return found if found is not None else parent.find(tag)


def _require_text(system: ET.Element, tag: str) -> str:
    element = _find(system, tag)
    if element is None or element.text is None or not element.text.strip():
        raise EventParseError(f"Missing required System/{tag}")
    return element.text.strip()


def parse_event_xml(xml_text: str) -> RawWindowsEvent:
    """Parse one rendered event. Raises EventParseError on malformed input."""
    if len(xml_text) > MAX_EVENT_XML_BYTES:
        raise EventParseError("Event XML exceeds the maximum supported size")
    # Rendered events never contain a DTD; refusing one blocks entity-expansion tricks.
    if "<!DOCTYPE" in xml_text or "<!ENTITY" in xml_text:
        raise EventParseError("Event XML contains a DTD, which is not allowed")

    try:
        root = ET.fromstring(xml_text)  # noqa: S314 - DTDs rejected above
    except ET.ParseError as exc:
        raise EventParseError(f"Malformed event XML: {exc}") from exc

    system = _find(root, "System")
    if system is None:
        raise EventParseError("Missing System element")

    provider_el = _find(system, "Provider")
    provider = provider_el.get("Name", "") if provider_el is not None else ""

    try:
        event_id = int(_require_text(system, "EventID"))
        record_id = int(_require_text(system, "EventRecordID"))
    except ValueError as exc:
        raise EventParseError("Non-numeric EventID or EventRecordID") from exc

    version_el = _find(system, "Version")
    version: int | None = None
    if version_el is not None and version_el.text and version_el.text.strip().isdigit():
        version = int(version_el.text.strip())

    time_el = _find(system, "TimeCreated")
    system_time = time_el.get("SystemTime") if time_el is not None else None
    if not system_time:
        raise EventParseError("Missing TimeCreated/@SystemTime")
    try:
        timestamp = parse_windows_timestamp(system_time)
    except ValueError as exc:
        raise EventParseError(f"Invalid timestamp {system_time!r}") from exc

    data, data_section = _extract_data(root)

    level_el = _find(system, "Level")
    level = (
        int(level_el.text.strip())
        if level_el is not None and level_el.text and level_el.text.strip().isdigit()
        else None
    )
    execution = _find(system, "Execution")
    pid_text = execution.get("ProcessID") if execution is not None else None
    security = _find(system, "Security")
    user_sid = clean_value(security.get("UserID")) if security is not None else None

    return RawWindowsEvent(
        provider=provider,
        event_id=event_id,
        version=version,
        channel=_require_text(system, "Channel"),
        hostname=_require_text(system, "Computer"),
        record_id=record_id,
        timestamp=timestamp,
        data=data,
        raw_xml=xml_text,
        data_section=data_section,
        level=level,
        execution_process_id=int(pid_text) if pid_text and pid_text.isdigit() else None,
        user_sid=user_sid,
    )


def _local_name(tag: str) -> str:
    """Element name without its XML namespace: {ns}SubjectUserName → SubjectUserName."""
    return tag.rsplit("}", 1)[-1]


def _extract_data(root: ET.Element) -> tuple[dict[str, str], str]:
    """Return the event's payload fields and which section they came from.

    Most events use ``<EventData><Data Name="X">value</Data></EventData>``.
    Some (e.g. Security 1102, "audit log cleared") use ``<UserData>`` with one
    provider-defined child element whose children are named fields:
    ``<UserData><LogFileCleared xmlns="…"><SubjectUserName>…</SubjectUserName>…``.
    Both are flattened into the same name → value map; nested structures deeper
    than one level are ignored rather than guessed.
    """
    data: dict[str, str] = {}
    event_data = _find(root, "EventData")
    if event_data is not None:
        for item in event_data:
            name = item.get("Name")
            if name:  # unnamed Data elements are ignored rather than guessed
                data[name] = item.text or ""
        return data, "EventData"

    user_data = _find(root, "UserData")
    if user_data is not None:
        for wrapper in user_data:  # normally exactly one provider-specific element
            for field in wrapper:
                if len(field) == 0:  # leaf elements only
                    data.setdefault(_local_name(field.tag), field.text or "")
        return data, "UserData"
    return data, "None"
