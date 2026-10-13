"""Stable categories used across the pipeline."""

from __future__ import annotations

from enum import IntEnum, StrEnum


class Severity(StrEnum):
    """Potential impact *if* the activity is malicious."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self)


_SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


class Confidence(StrEnum):
    """Strength of evidence that the detection represents the intended behavior."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class TriageStatus(StrEnum):
    """Analyst workflow state of a finding."""

    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    BENIGN = "BENIGN"
    RESOLVED = "RESOLVED"

    @property
    def is_closed(self) -> bool:
        return self in CLOSED_STATUSES

    @property
    def label(self) -> str:
        return self.value.replace("_", " ").title()


# Statuses that end an investigation. TP / FP / BENIGN also record a verdict.
CLOSED_STATUSES = frozenset({"TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN", "RESOLVED"})
VERDICT_STATUSES = frozenset({"TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN"})


class TelemetrySource(StrEnum):
    """Which Windows telemetry family an event came from."""

    SECURITY = "security"
    SYSMON = "sysmon"
    POWERSHELL = "powershell"
    DEFENDER = "defender"


class DetectionKind(StrEnum):
    """Single-signal rule vs. multi-signal correlation."""

    DETECTION = "detection"
    CORRELATION = "correlation"


class HealthState(StrEnum):
    AVAILABLE = "Available"
    LIMITED = "Limited"
    UNAVAILABLE = "Unavailable"
    ERROR = "Error"


class SecurityEventId(IntEnum):
    """Windows Security log event IDs MoeSOC currently understands."""

    LOG_CLEARED = 1102  # "The audit log was cleared" (UserData payload)
    LOGON_SUCCESS = 4624
    LOGON_FAILURE = 4625
    SPECIAL_PRIVILEGES = 4672  # "Special privileges assigned to new logon" (context only)
    PROCESS_CREATED = 4688  # "A new process has been created" (needs process auditing)
    ACCOUNT_CREATED = 4720  # "A user account was created"
    LOCAL_GROUP_MEMBER_ADDED = 4732  # "A member was added to a security-enabled local group"


class SysmonEventId(IntEnum):
    """Sysmon (Microsoft-Windows-Sysmon/Operational) event IDs MoeSOC understands."""

    PROCESS_CREATE = 1
    NETWORK_CONNECT = 3
    FILE_CREATE = 11
    REGISTRY_VALUE_SET = 13
    DNS_QUERY = 22


class PowerShellEventId(IntEnum):
    """Microsoft-Windows-PowerShell/Operational event IDs MoeSOC understands."""

    SCRIPT_BLOCK = 4104  # "Creating Scriptblock text" (script block logging)


class DefenderEventId(IntEnum):
    """Microsoft-Windows-Windows Defender/Operational event IDs MoeSOC understands."""

    MALWARE_DETECTED = 1116  # "The antimalware platform detected malware or other PUS"
    ACTION_TAKEN = 1117  # "…performed an action to protect your system"
    ACTION_FAILED = 1118  # "…attempted an action, but the action failed" (non-critical)
    ACTION_CRITICAL_FAILURE = 1119  # "…encountered a critical error when trying to take action"


# Well-known Windows logon types (documented by Microsoft for 4624/4625).
LOGON_TYPE_NAMES: dict[int, str] = {
    0: "System",
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteractive",
    11: "CachedInteractive",
    12: "CachedRemoteInteractive",
    13: "CachedUnlock",
}

# Common NTSTATUS codes seen in 4625 Status/SubStatus.
LOGON_FAILURE_REASONS: dict[str, str] = {
    "0xc000006d": "Bad username or authentication information",
    "0xc000006a": "Incorrect password",
    "0xc0000064": "Account does not exist",
    "0xc0000234": "Account locked out",
    "0xc0000072": "Account disabled",
    "0xc000006f": "Logon outside allowed hours",
    "0xc0000070": "Logon from unauthorized workstation",
    "0xc0000071": "Password expired",
    "0xc0000193": "Account expired",
    "0xc0000224": "Password must change at next logon",
    "0xc000015b": "Logon type not granted",
    "0xc0000133": "Clock out of sync with domain controller",
}
