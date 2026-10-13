"""Health checks, including Sysmon detection (read-only; nothing is installed)."""

from moesoc.collectors.sysmon_info import SysmonService, classify_variant
from moesoc.core.enums import HealthState
from moesoc.core.exceptions import ChannelNotFoundError, LogAccessDeniedError
from moesoc.health import HealthCheck, describe_sysmon, run_health_checks

WIN = r"C:\Windows"


class ProbeReader:
    """Fake channel probe: channel → True (has events), False (empty) or an exception."""

    def __init__(self, answers):
        self.answers = answers

    def probe_channel(self, channel):
        answer = self.answers.get(channel, ChannelNotFoundError("missing"))
        if isinstance(answer, Exception):
            raise answer
        return answer


def _health(database, answers, service=None):
    checks = run_health_checks(
        database, reader_factory=lambda: ProbeReader(answers), sysmon_probe=lambda: service
    )
    return {c.name: c for c in checks}


SYSMON = "Microsoft-Windows-Sysmon/Operational"


def test_variant_is_inferred_from_the_binary_location():
    assert classify_variant(r"C:\Windows\Sysmon64.exe", WIN) == "standalone (Sysinternals)"
    assert classify_variant(r'"C:\WINDOWS\Sysmon.exe"', WIN) == "standalone (Sysinternals)"
    assert classify_variant(r"C:\Windows\System32\Sysmon.exe", WIN) == "built-in Windows feature"
    assert classify_variant(r"D:\tools\sysmon64.exe", WIN) == "unknown"
    assert classify_variant(None, WIN) == "unknown"


def test_no_sysmon_says_not_installed_and_never_offers_to_install(database):
    check = _health(database, {"Security": True})["Sysmon"]
    assert check.state is HealthState.UNAVAILABLE
    assert "Not installed" in check.message and "never installs" in check.message


def test_running_standalone_sysmon_is_available_with_details(database):
    service = SysmonService(
        "Sysmon64", "running", r"C:\Windows\Sysmon64.exe", "standalone (Sysinternals)"
    )
    check = _health(database, {SYSMON: True}, service)["Sysmon"]
    assert check.state is HealthState.AVAILABLE
    assert "standalone (Sysinternals)" in check.message and "Sysmon64 running" in check.message


def test_stopped_service_is_limited(database):
    service = SysmonService(
        "Sysmon", "stopped", r"C:\Windows\System32\Sysmon.exe", "built-in Windows feature"
    )
    check = _health(database, {SYSMON: True}, service)["Sysmon"]
    assert check.state is HealthState.LIMITED and "stopped" in check.message


def test_service_without_channel_is_limited():
    base = HealthCheck("Sysmon", HealthState.UNAVAILABLE, "Not installed")
    service = SysmonService("Sysmon64", "running", None, "unknown")
    assert describe_sysmon(base, service).state is HealthState.LIMITED


def test_access_denied_is_not_reported_as_not_installed(database):
    check = _health(database, {SYSMON: LogAccessDeniedError("denied")})["Sysmon"]
    assert "Access denied" in check.message


def test_empty_log_is_limited(database):
    assert _health(database, {SYSMON: False})["Sysmon"].state is HealthState.LIMITED


def test_database_check_reports_the_schema_version(database):
    from moesoc.storage.schema import SCHEMA_VERSION

    assert f"schema v{SCHEMA_VERSION}" in _health(database, {})["Database"].message
