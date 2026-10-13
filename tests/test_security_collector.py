import pytest

from moesoc.collectors.eventlog import _translate_error
from moesoc.collectors.security import SecurityCollector, build_security_xpath
from moesoc.core.exceptions import ChannelNotFoundError, CollectorError, LogAccessDeniedError

from .conftest import FakeReader, fixture_text


def test_xpath_filters_ids_and_time_server_side():
    xpath = build_security_xpath(frozenset({4625, 4624}), lookback_hours=24)
    assert xpath == (
        "*[System[(EventID=4624 or EventID=4625) and "
        "TimeCreated[timediff(@SystemTime) <= 86400000]]]"
    )


def test_xpath_rejects_non_positive_lookback():
    with pytest.raises(ValueError):
        build_security_xpath(frozenset({4625}), lookback_hours=0)


def test_malformed_record_does_not_stop_collection():
    reader = FakeReader(
        [
            fixture_text("4625_failed_network_logon.xml"),
            fixture_text("malformed_truncated.xml"),
            fixture_text("4624_successful_rdp_logon.xml"),
        ]
    )
    result = SecurityCollector(reader).collect(lookback_hours=24, max_events=100)

    assert result.records_read == 3
    assert result.parse_failures == 1
    assert [e.event_id for e in result.events] == [4625, 4624]
    assert reader.queries[0][0] == "Security"


def test_collection_cap_is_reported():
    reader = FakeReader([fixture_text("4625_failed_network_logon.xml")] * 5)
    result = SecurityCollector(reader).collect(lookback_hours=24, max_events=3)
    assert result.records_read == 3
    assert result.truncated is True


def test_access_denied_propagates_readable_error():
    reader = FakeReader([], error=LogAccessDeniedError("Access denied ..."))
    with pytest.raises(LogAccessDeniedError):
        SecurityCollector(reader).collect(lookback_hours=24, max_events=10)


class _FakeWinError(Exception):
    def __init__(self, winerror: int) -> None:
        super().__init__(winerror)
        self.winerror = winerror


@pytest.mark.parametrize(
    ("code", "expected_type", "phrase"),
    [
        (5, LogAccessDeniedError, "administrator privileges"),
        (15007, ChannelNotFoundError, "does not exist"),
        (1234, CollectorError, "code 1234"),
    ],
)
def test_win32_errors_become_understandable_messages(code, expected_type, phrase):
    error = _translate_error(_FakeWinError(code), "Security")
    assert type(error) is expected_type
    assert phrase in error.user_message
