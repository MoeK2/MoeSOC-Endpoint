"""Telemetry and environment health checks. Read-only; never changes system state."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass

from moesoc.collectors.eventlog import WindowsEventLogReader
from moesoc.collectors.powershell_info import script_block_logging_enabled
from moesoc.collectors.sysmon_info import SysmonService, probe_sysmon_service
from moesoc.core.enums import HealthState
from moesoc.core.exceptions import (
    ChannelNotFoundError,
    CollectorError,
    LogAccessDeniedError,
    MoeSOCError,
    PlatformNotSupportedError,
)
from moesoc.storage.database import Database
from moesoc.utils.privileges import is_admin

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class HealthCheck:
    name: str
    state: HealthState
    message: str


@dataclass(frozen=True, slots=True)
class _ChannelSpec:
    name: str
    channel: str
    missing_message: str
    ok_message: str


CHANNELS = (
    _ChannelSpec(
        "Security Event Log",
        "Security",
        "The Security log could not be found.",
        "Security log is readable.",
    ),
    _ChannelSpec(
        "Sysmon",
        "Microsoft-Windows-Sysmon/Operational",
        "Not installed — advanced endpoint visibility (process, network, DNS, file, registry) "
        "is unavailable. See docs/sysmon.md; MoeSOC never installs it.",
        "Sysmon log is readable.",
    ),
    _ChannelSpec(
        "PowerShell Logging",
        "Microsoft-Windows-PowerShell/Operational",
        "PowerShell Operational log not found.",
        "PowerShell Operational log is readable.",
    ),
    _ChannelSpec(
        "Microsoft Defender Log",
        "Microsoft-Windows-Windows Defender/Operational",
        "Microsoft Defender Operational log not found.",
        "Defender Operational log is readable; detections (1116) and remediation results "
        "(1117-1119) are collected.",
    ),
)


def _check_admin() -> HealthCheck:
    admin = is_admin()
    if admin is None:
        return HealthCheck(
            "Administrator Privileges", HealthState.UNAVAILABLE, "Not running on Windows."
        )
    if admin:
        return HealthCheck("Administrator Privileges", HealthState.AVAILABLE, "Running elevated.")
    return HealthCheck(
        "Administrator Privileges",
        HealthState.LIMITED,
        "Not elevated. Administrator privileges are required to access Windows Security telemetry.",
    )


def _check_channel(
    reader: WindowsEventLogReader | None, spec: _ChannelSpec, platform_msg: str
) -> HealthCheck:
    if reader is None:
        return HealthCheck(spec.name, HealthState.UNAVAILABLE, platform_msg)
    try:
        has_events = reader.probe_channel(spec.channel)
    except LogAccessDeniedError:
        return HealthCheck(
            spec.name,
            HealthState.UNAVAILABLE,
            "Access denied. Run MoeSOC with administrator privileges.",
        )
    except ChannelNotFoundError:
        return HealthCheck(spec.name, HealthState.UNAVAILABLE, spec.missing_message)
    except CollectorError as exc:
        return HealthCheck(spec.name, HealthState.ERROR, exc.user_message)
    if not has_events:
        return HealthCheck(spec.name, HealthState.LIMITED, "Log is readable but currently empty.")
    return HealthCheck(spec.name, HealthState.AVAILABLE, spec.ok_message)


def describe_sysmon(check: HealthCheck, service: SysmonService | None) -> HealthCheck:
    """Add what the service tells us (variant, state) to the Sysmon channel check."""
    if service is None:
        return check
    detail = f"{service.variant}; service {service.name} {service.state}"
    if check.state is HealthState.UNAVAILABLE and "Access denied" not in check.message:
        return HealthCheck(
            check.name,
            HealthState.LIMITED,
            f"Sysmon service found ({detail}) but its event log is not available.",
        )
    if check.state is HealthState.AVAILABLE and service.state != "running":
        return HealthCheck(
            check.name,
            HealthState.LIMITED,
            f"Log readable, but the service is {service.state} ({detail}).",
        )
    return HealthCheck(check.name, check.state, f"{check.message} ({detail})")


def describe_powershell(check: HealthCheck, policy: bool | None) -> HealthCheck:
    """Add the Script Block Logging policy state (read-only) to the channel check."""
    if check.state is HealthState.UNAVAILABLE:
        return check
    if policy is True:
        return HealthCheck(
            check.name, check.state, f"{check.message} Script Block Logging is enabled by policy."
        )
    if policy is False:
        return HealthCheck(
            check.name,
            HealthState.LIMITED,
            f"{check.message} Script Block Logging is not enabled, so only script blocks "
            "PowerShell itself considers suspicious are logged (Event 4104). Enabling it is "
            "your decision; see docs/detections.md (DET-007). MoeSOC never changes it.",
        )
    return HealthCheck(
        check.name, check.state, f"{check.message} Script Block Logging policy not readable."
    )


def _check_database(database: Database) -> HealthCheck:
    try:
        version = database.initialize()
    except MoeSOCError as exc:
        return HealthCheck("Database", HealthState.ERROR, exc.user_message)
    return HealthCheck(
        "Database", HealthState.AVAILABLE, f"Local SQLite database ready (schema v{version})."
    )


def run_health_checks(
    database: Database,
    reader_factory: Callable[[], WindowsEventLogReader] = WindowsEventLogReader,
    sysmon_probe: Callable[[], SysmonService | None] = probe_sysmon_service,
    powershell_policy: Callable[[], bool | None] = script_block_logging_enabled,
) -> list[HealthCheck]:
    checks = [_check_admin()]
    reader: WindowsEventLogReader | None
    platform_msg = ""
    try:
        reader = reader_factory()
    except PlatformNotSupportedError as exc:
        reader = None
        platform_msg = exc.user_message
    for spec in CHANNELS:
        check = _check_channel(reader, spec, platform_msg)
        if spec.name == "Sysmon":
            check = describe_sysmon(check, sysmon_probe())
        elif spec.name == "PowerShell Logging":
            check = describe_powershell(check, powershell_policy())
        checks.append(check)
    checks.append(_check_database(database))
    for check in checks:
        log.info("Health: %s = %s", check.name, check.state.value)
    return checks


SENSOR_STATES = {
    "MONITORING": HealthState.AVAILABLE,
    "ATTENTION": HealthState.AVAILABLE,
    "STARTING": HealthState.LIMITED,
    "LIMITED": HealthState.LIMITED,
    "ERROR": HealthState.ERROR,
}


def run_sensor_health_checks(
    database: Database,
    sensor_status: Callable[[], dict],
    admin: bool | None,
    sysmon_probe: Callable[[], SysmonService | None] = probe_sysmon_service,
    powershell_policy: Callable[[], bool | None] = script_block_logging_enabled,
) -> list[HealthCheck]:
    """Health when the MoeSOC Sensor collects (B-7). The console may run without
    administrator rights and cannot open the logs itself, so what is collected is what
    the sensor reports over IPC; "not reachable" is reported, never guessed."""
    try:
        status = sensor_status()
    except Exception as exc:  # SensorUnavailable or any transport failure
        log.warning("Sensor status unavailable: %s", exc)
        status = None
    if status is None:
        checks = [
            HealthCheck(
                "MoeSOC Sensor",
                HealthState.ERROR,
                "The MoeSOC Sensor service is not reachable: nothing new is collected. "
                "The findings shown are the ones stored so far.",
            )
        ]
        channels: dict = {}
    else:
        state = str(status.get("state", ""))
        detail = status.get("last_error") or (status.get("monitor") or {}).get("message") or ""
        message = f"Sensor {state.lower()} (version {status.get('version', '?')})"
        checks = [
            HealthCheck(
                "MoeSOC Sensor",
                SENSOR_STATES.get(state, HealthState.LIMITED),
                f"{message}: {detail}" if detail else f"{message}.",
            )
        ]
        channels = status.get("channels") or {}
    if admin:
        account = "Administrator: can also change suppressions, rules and retention."
    else:
        account = (
            "Standard user: reads the sensor's data; triage and notes are saved through the "
            "sensor. Suppressions, rule changes and retention need MoeSOC opened as "
            "administrator."
        )
    checks.append(HealthCheck("Console Account", HealthState.AVAILABLE, account))
    for spec in CHANNELS:
        value = channels.get(spec.channel)
        if value == "live":
            check = HealthCheck(spec.name, HealthState.AVAILABLE, "Collected live by the sensor.")
        elif value == "not installed":
            check = HealthCheck(spec.name, HealthState.UNAVAILABLE, spec.missing_message)
        elif value is None:
            check = HealthCheck(spec.name, HealthState.UNAVAILABLE, "Not reported by the sensor.")
        else:
            check = HealthCheck(spec.name, HealthState.LIMITED, f"Sensor: {value}")
        if spec.name == "Sysmon":
            check = describe_sysmon(check, sysmon_probe())
        elif spec.name == "PowerShell Logging":
            check = describe_powershell(check, powershell_policy())
        checks.append(check)
    checks.append(_check_database(database))
    for check in checks:
        log.info("Health (sensor mode): %s = %s", check.name, check.state.value)
    return checks
