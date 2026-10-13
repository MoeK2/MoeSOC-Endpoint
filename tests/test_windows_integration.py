"""Read-only integration tests against the real Windows Event Log.

Skipped automatically when not on Windows or without pywin32. They never
write to the event log or change system configuration.
"""

import sys

import pytest

from moesoc.core.exceptions import LogAccessDeniedError

pytestmark = [
    pytest.mark.windows,
    pytest.mark.skipif(sys.platform != "win32", reason="requires Windows"),
]


@pytest.fixture
def reader():
    pytest.importorskip("win32evtlog")
    from moesoc.collectors.eventlog import WindowsEventLogReader

    return WindowsEventLogReader()


def test_application_log_is_readable(reader):
    # The Application log is readable without elevation on a default install.
    reader.probe_channel("Application")


def test_security_log_scan_or_clear_access_error(reader):
    from moesoc.collectors.security import SecurityCollector

    try:
        result = SecurityCollector(reader).collect(lookback_hours=1, max_events=50)
    except LogAccessDeniedError as exc:
        assert "administrator" in exc.user_message
        pytest.skip("Not elevated: Security log access correctly reported as denied")
    assert result.parse_failures == 0 or result.parse_failures < result.records_read
