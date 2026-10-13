"""Normalization of Windows Security events (EventData payloads, and UserData for 1102)."""

from __future__ import annotations

import ipaddress
import json
import logging
from typing import Any

from moesoc.core.enums import LOGON_FAILURE_REASONS, SecurityEventId, TelemetrySource
from moesoc.core.event import NormalizedEvent
from moesoc.core.exceptions import EventParseError
from moesoc.parsers.windows_event import RawWindowsEvent, parse_event_xml

log = logging.getLogger(__name__)

SECURITY_CHANNEL = "Security"
SUPPORTED_EVENT_IDS = frozenset(int(e) for e in SecurityEventId)


def normalize_ip(value: str | None) -> str | None:
    """Return a canonical IP string, or None for placeholders/unparseable values.

    IPv4-mapped IPv6 (``::ffff:10.0.0.5``) is reduced to IPv4 so the same host
    is not counted as two different sources.
    """
    if not value:
        return None
    try:
        address = ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return str(address.ipv4_mapped)
    return str(address)


def _to_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value, 0) if value.lower().startswith("0x") else int(value)
    except ValueError:
        return None


def _port(value: str | None) -> int | None:
    port = _to_int(value)
    # Port 0 is what Windows records for logons that had no network peer.
    if port is None or not 0 < port <= 65535:
        return None
    return port


def _status(value: str | None) -> str | None:
    return value.lower() if value else None


_EMPTY_GUID = "{00000000-0000-0000-0000-000000000000}"


def _guid(value: str | None) -> str | None:
    if not value or value.strip() == _EMPTY_GUID:
        return None
    return value.strip().lower()


def _process_name(path: str | None) -> str | None:
    if not path:
        return None
    return path.replace("/", "\\").rsplit("\\", 1)[-1] or None


def _details(**values: str | None) -> str | None:
    """JSON object of the non-empty values (keys are fixed names chosen here)."""
    kept = {k: v for k, v in values.items() if v is not None}
    return json.dumps(kept, sort_keys=True, ensure_ascii=False) if kept else None


def _account_created(raw: RawWindowsEvent) -> dict[str, Any]:
    """4720: the new account is the target; its SID is in ``TargetSid``."""
    return {
        "target_user_sid": raw.get("TargetSid"),
        "logon_id": raw.get("SubjectLogonId"),
        "privileges": raw.get("PrivilegeList"),
        "details": _details(
            sam_account_name=raw.get("SamAccountName"),
            display_name=raw.get("DisplayName"),
            user_principal_name=raw.get("UserPrincipalName"),
            user_account_control=raw.get("UserAccountControl"),
            new_uac_value=raw.get("NewUacValue"),
        ),
    }


def _member_added(raw: RawWindowsEvent) -> dict[str, Any]:
    """4732: TargetUserName/TargetSid are the GROUP; the member is MemberSid/MemberName.

    The member's SID is also the event's target SID so identity matching works.
    The member's name is often empty (local accounts) or an LDAP DN; it is kept as
    recorded and never parsed into a username.
    """
    return {
        "target_username": None,
        "target_domain": None,
        "target_user_sid": raw.get("MemberSid"),
        "member_name": raw.get("MemberName"),
        "member_sid": raw.get("MemberSid"),
        "group_name": raw.get("TargetUserName"),
        "group_domain": raw.get("TargetDomainName"),
        "group_sid": raw.get("TargetSid"),
        "logon_id": raw.get("SubjectLogonId"),
        "privileges": raw.get("PrivilegeList"),
    }


# 4624 ElevatedToken (Windows 10+): message IDs for "Yes" / "No".
_YES_NO = {"%%1842": "yes", "%%1843": "no"}


def _logon_success(raw: RawWindowsEvent) -> dict[str, Any]:
    elevated = raw.get("ElevatedToken")
    # With UAC, an administrator's logon creates two linked sessions (filtered and
    # elevated); each 4624 names the other one. "0x0" means there is no linked session.
    linked = raw.get("TargetLinkedLogonId")
    return {
        "details": _details(
            elevated_token=_YES_NO.get(elevated or "", elevated),
            linked_logon_id=linked if linked and linked.lower() != "0x0" else None,
        )
    }


def _special_privileges(raw: RawWindowsEvent) -> dict[str, Any]:
    """4672: the account is the SUBJECT; SubjectLogonId is the new session's ID."""
    privileges = raw.get("PrivilegeList")
    return {
        "logon_id": raw.get("SubjectLogonId"),
        # Windows separates the names with newlines and tabs; keep one space.
        "privileges": " ".join(privileges.split()) if privileges else None,
    }


# 4688 TokenElevationType message IDs (Microsoft: TokenElevationType 1/2/3).
TOKEN_ELEVATION = {
    "%%1936": "Default",  # type 1: full token, no UAC split (UAC off, built-in admin, service)
    "%%1937": "Full",  # type 2: elevated (run as administrator)
    "%%1938": "Limited",  # type 3: filtered standard-user token
}
# Mandatory integrity level SIDs (S-1-16-*).
INTEGRITY_LEVELS = {
    "S-1-16-0": "Untrusted",
    "S-1-16-4096": "Low",
    "S-1-16-8192": "Medium",
    "S-1-16-8448": "Medium Plus",
    "S-1-16-12288": "High",
    "S-1-16-16384": "System",
    "S-1-16-20480": "Protected Process",
}


def _process_created(raw: RawWindowsEvent) -> dict[str, Any]:
    """4688: the creator is the SUBJECT; the new process runs in SubjectLogonId's session
    unless a different TargetLogonId is recorded (e.g. runas). CommandLine is present only
    when "Include command line in process creation events" is enabled; otherwise None."""
    new_process = raw.get("NewProcessName")
    elevation = raw.get("TokenElevationType")
    label = (raw.get("MandatoryLabel") or "").upper()
    target_logon = raw.get("TargetLogonId")
    return {
        "logon_id": raw.get("SubjectLogonId"),
        "process_path": new_process,
        "process_name": _process_name(new_process),
        "process_id": _to_int(raw.get("NewProcessId")),
        "parent_process_id": _to_int(raw.get("ProcessId")),
        "parent_process": raw.get("ParentProcessName"),
        "command_line": raw.get("CommandLine"),
        "token_elevation": TOKEN_ELEVATION.get(elevation or "", elevation),
        "integrity_level": INTEGRITY_LEVELS.get(label, label or None),
        "details": _details(
            target_logon_id=target_logon if target_logon and target_logon != "0x0" else None
        ),
    }


# Event-specific mappings applied on top of the shared fields.
_SPECIFIC: dict[int, Any] = {
    SecurityEventId.LOGON_SUCCESS: _logon_success,
    SecurityEventId.SPECIAL_PRIVILEGES: _special_privileges,
    SecurityEventId.PROCESS_CREATED: _process_created,
    SecurityEventId.ACCOUNT_CREATED: _account_created,
    SecurityEventId.LOCAL_GROUP_MEMBER_ADDED: _member_added,
}


def normalize_security_event(raw: RawWindowsEvent) -> NormalizedEvent:
    """Map a parsed Security event to the normalized model. Missing fields stay None."""
    if raw.event_id not in SUPPORTED_EVENT_IDS:
        raise EventParseError(f"Unsupported Security event ID {raw.event_id}")

    process_path = raw.get("ProcessName")
    status = _status(raw.get("Status"))
    sub_status = _status(raw.get("SubStatus"))
    # The SubStatus is usually more specific than Status (e.g. 0xc000006a vs 0xc000006d).
    failure_reason = None
    if raw.event_id == SecurityEventId.LOGON_FAILURE:
        failure_reason = LOGON_FAILURE_REASONS.get(sub_status or "") or LOGON_FAILURE_REASONS.get(
            status or ""
        )

    fields: dict[str, Any] = {
        "subject_username": raw.get("SubjectUserName"),
        "subject_domain": raw.get("SubjectDomainName"),
        "subject_user_sid": raw.get("SubjectUserSid"),
        "target_username": raw.get("TargetUserName"),
        "target_domain": raw.get("TargetDomainName"),
        "target_user_sid": raw.get("TargetUserSid"),
        "logon_guid": _guid(raw.get("LogonGuid")),
        "logon_type": _to_int(raw.get("LogonType")),
        # 4624 has TargetLogonId (the new session); 4625 has no new session.
        "logon_id": raw.get("TargetLogonId") or raw.get("SubjectLogonId"),
        "logon_process": raw.get("LogonProcessName"),
        "authentication_package": raw.get("AuthenticationPackageName"),
        "workstation_name": raw.get("WorkstationName"),
        "process_name": _process_name(process_path),
        "process_path": process_path,
        "source_ip": normalize_ip(raw.get("IpAddress")),
        "source_port": _port(raw.get("IpPort")),
        "status": status,
        "sub_status": sub_status,
        "failure_reason": failure_reason,
    }
    specific = _SPECIFIC.get(raw.event_id)
    if specific is not None:
        fields.update(specific(raw))

    return NormalizedEvent(
        timestamp=raw.timestamp,
        record_id=raw.record_id,
        source=TelemetrySource.SECURITY,
        channel=raw.channel,
        provider=raw.provider,
        event_id=raw.event_id,
        hostname=raw.hostname,
        raw_xml=raw.raw_xml,
        **fields,
    )


def parse_security_xml(xml_text: str) -> NormalizedEvent:
    """Parse + normalize one Security event. Raises EventParseError."""
    return normalize_security_event(parse_event_xml(xml_text))
