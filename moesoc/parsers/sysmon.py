"""Normalization of Sysmon events (Microsoft-Windows-Sysmon/Operational).

Sysmon writes values as text; fields are read by name, and a missing field stays
None. The System/Security UserID of a Sysmon event is the Sysmon service (SYSTEM),
not the user of the process, so the user comes from the ``User`` field instead.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from typing import Any

from moesoc.core.enums import SysmonEventId, TelemetrySource
from moesoc.core.event import NormalizedEvent
from moesoc.core.exceptions import EventParseError
from moesoc.parsers.security import normalize_ip
from moesoc.parsers.windows_event import RawWindowsEvent, parse_event_xml

log = logging.getLogger(__name__)

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
SUPPORTED_SYSMON_IDS = frozenset(int(e) for e in SysmonEventId)


def _int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value, 0) if value.lower().startswith("0x") else int(value)
    except ValueError:
        return None


def _guid(value: str | None) -> str | None:
    """Sysmon GUIDs compared case-insensitively, braces kept: {…} in lower case."""
    if not value:
        return None
    value = value.strip().lower()
    if value.strip("{}0-") == "":
        return None  # all-zero GUID means "unknown"
    return value


def _split_account(value: str | None) -> tuple[str | None, str | None]:
    """'LAB\\alice' → ('alice', 'LAB'); 'alice' → ('alice', None)."""
    if not value:
        return None, None
    if "\\" in value:
        domain, user = value.split("\\", 1)
        return user or None, domain or None
    return value, None


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    return path.replace("/", "\\").rsplit("\\", 1)[-1] or None


def _details(**values: Any) -> str | None:
    kept = {k: v for k, v in values.items() if v is not None}
    return json.dumps(kept, sort_keys=True, ensure_ascii=False) if kept else None


def _logon_id(value: str | None) -> str | None:
    """Same spelling as the Security log (0x5a3f21) so logon sessions can be joined."""
    number = _int(value)
    return f"0x{number:x}" if number is not None else None


def _process_create(raw: RawWindowsEvent) -> dict[str, Any]:
    user, domain = _split_account(raw.get("User"))
    image = raw.get("Image")
    return {
        "subject_username": user,
        "subject_domain": domain,
        "logon_id": _logon_id(raw.get("LogonId")),
        "logon_guid": _guid(raw.get("LogonGuid")),
        "process_path": image,
        "process_name": _basename(image),
        "process_id": _int(raw.get("ProcessId")),
        "process_guid": _guid(raw.get("ProcessGuid")),
        "command_line": raw.get("CommandLine"),
        "parent_process": raw.get("ParentImage"),
        "parent_process_id": _int(raw.get("ParentProcessId")),
        "parent_process_guid": _guid(raw.get("ParentProcessGuid")),
        "integrity_level": raw.get("IntegrityLevel"),
        "hashes": raw.get("Hashes"),
        "details": _details(
            current_directory=raw.get("CurrentDirectory"),
            parent_command_line=raw.get("ParentCommandLine"),
            parent_user=raw.get("ParentUser"),
            original_file_name=raw.get("OriginalFileName"),
            company=raw.get("Company"),
            description=raw.get("Description"),
            product=raw.get("Product"),
            file_version=raw.get("FileVersion"),
            terminal_session_id=raw.get("TerminalSessionId"),
            rule_name=raw.get("RuleName"),
        ),
    }


def _actor(raw: RawWindowsEvent) -> dict[str, Any]:
    """The process that caused the event (every Sysmon event names it)."""
    user, domain = _split_account(raw.get("User"))
    image = raw.get("Image")
    return {
        "subject_username": user,
        "subject_domain": domain,
        "process_path": image,
        "process_name": _basename(image),
        "process_id": _int(raw.get("ProcessId")),
        "process_guid": _guid(raw.get("ProcessGuid")),
    }


def _bool(value: str | None) -> bool | None:
    if value is None:
        return None
    return value.strip().lower() == "true"


def _port(value: str | None) -> int | None:
    port = _int(value)
    return port if port is not None and 0 < port <= 65535 else None


def _network_connect(raw: RawWindowsEvent) -> dict[str, Any]:
    """Sysmon 3. Source/destination are as Sysmon records them; ``initiated`` says
    whether this computer opened the connection (outbound) or accepted it."""
    return {
        **_actor(raw),
        "network_protocol": (raw.get("Protocol") or "").lower() or None,
        "source_ip": normalize_ip(raw.get("SourceIp")),
        "source_port": _port(raw.get("SourcePort")),
        "destination_ip": normalize_ip(raw.get("DestinationIp")),
        "destination_port": _port(raw.get("DestinationPort")),
        "details": _details(
            initiated=_bool(raw.get("Initiated")),
            source_hostname=raw.get("SourceHostname"),
            destination_hostname=raw.get("DestinationHostname"),
            source_port_name=raw.get("SourcePortName"),
            destination_port_name=raw.get("DestinationPortName"),
            rule_name=raw.get("RuleName"),
        ),
    }


def _file_create(raw: RawWindowsEvent) -> dict[str, Any]:
    return {
        **_actor(raw),
        "file_path": raw.get("TargetFilename"),
        "details": _details(
            creation_utc_time=raw.get("CreationUtcTime"), rule_name=raw.get("RuleName")
        ),
    }


def _registry_value_set(raw: RawWindowsEvent) -> dict[str, Any]:
    """Sysmon 13. The written value (``Details``) can hold configuration or secrets: it
    is kept locally for investigation but never shown in summaries."""
    return {
        **_actor(raw),
        "registry_path": raw.get("TargetObject"),
        "details": _details(
            registry_event_type=raw.get("EventType"),
            registry_value=raw.get("Details"),
            rule_name=raw.get("RuleName"),
        ),
    }


def resolved_addresses(query_results: str | None) -> list[str]:
    """IP addresses in Sysmon's QueryResults ("type:  5 x.example;::ffff:192.0.2.7;")."""
    if not query_results:
        return []
    found: list[str] = []
    for token in query_results.replace(",", ";").split(";"):
        token = token.strip()
        try:
            ipaddress.ip_address(token)
        except ValueError:
            continue
        address = normalize_ip(token)
        if address and address not in found:
            found.append(address)
    return found


def _dns_query(raw: RawWindowsEvent) -> dict[str, Any]:
    results = raw.get("QueryResults")
    return {
        **_actor(raw),
        "dns_query": (raw.get("QueryName") or "").strip().rstrip(".").lower() or None,
        "details": _details(
            query_status=raw.get("QueryStatus"),
            query_results=results,
            resolved_addresses=resolved_addresses(results) or None,
            rule_name=raw.get("RuleName"),
        ),
    }


_MAPPERS = {
    SysmonEventId.PROCESS_CREATE: _process_create,
    SysmonEventId.NETWORK_CONNECT: _network_connect,
    SysmonEventId.FILE_CREATE: _file_create,
    SysmonEventId.REGISTRY_VALUE_SET: _registry_value_set,
    SysmonEventId.DNS_QUERY: _dns_query,
}


def normalize_sysmon_event(raw: RawWindowsEvent) -> NormalizedEvent:
    mapper = _MAPPERS.get(raw.event_id)  # type: ignore[call-overload]
    if mapper is None:
        raise EventParseError(f"Unsupported Sysmon event ID {raw.event_id}")
    return NormalizedEvent(
        timestamp=raw.timestamp,
        record_id=raw.record_id,
        source=TelemetrySource.SYSMON,
        channel=raw.channel,
        provider=raw.provider,
        event_id=raw.event_id,
        hostname=raw.hostname,
        raw_xml=raw.raw_xml,
        **mapper(raw),
    )


def parse_sysmon_xml(xml_text: str) -> NormalizedEvent:
    raw = parse_event_xml(xml_text)
    if raw.channel != SYSMON_CHANNEL:
        raise EventParseError(f"Not a Sysmon event (channel {raw.channel})")
    return normalize_sysmon_event(raw)
