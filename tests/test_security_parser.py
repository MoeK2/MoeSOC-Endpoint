from datetime import UTC, datetime

import pytest

from moesoc.core.enums import TelemetrySource
from moesoc.core.exceptions import EventParseError
from moesoc.parsers.security import normalize_ip, parse_security_xml
from moesoc.utils.time import parse_windows_timestamp

from .conftest import fixture_text


def test_parses_failed_network_logon():
    event = parse_security_xml(fixture_text("4625_failed_network_logon.xml"))

    assert event.event_id == 4625
    assert event.record_id == 100201
    assert event.source is TelemetrySource.SECURITY
    assert event.channel == "Security"
    assert event.hostname == "WS-LAB01.lab.example"
    assert event.timestamp == datetime(2026, 10, 6, 8, 15, 22, 123456, tzinfo=UTC)
    assert event.target_username == "alice"
    assert event.target_domain == "LAB"
    assert event.logon_type == 3
    assert event.logon_type_name == "Network"
    assert event.source_ip == "192.0.2.45"
    assert event.source_port == 51544
    assert event.workstation_name == "ATTACKER-VM"
    assert event.authentication_package == "NTLM"
    assert event.logon_process == "NtLmSsp"  # trailing padding stripped
    assert event.status == "0xc000006d"
    assert event.sub_status == "0xc000006a"
    assert event.failure_reason == "Incorrect password"
    # Placeholders ("-") must become None, never a fake value.
    assert event.subject_username is None
    assert event.process_path is None


def test_parses_successful_logon_and_preserves_raw_xml():
    xml = fixture_text("4624_successful_rdp_logon.xml")
    event = parse_security_xml(xml)

    assert event.event_id == 4624
    assert event.target_account_display == "LAB\\Alice"
    assert event.logon_type_name == "RemoteInteractive"
    assert event.logon_id == "0x5a3f21"
    assert event.process_path == "C:\\Windows\\System32\\svchost.exe"
    assert event.process_name == "svchost.exe"
    assert event.source_ip == "192.0.2.45"  # IPv4-mapped IPv6 reduced to IPv4
    assert event.source_port is None  # port 0 means "no network peer"
    assert event.failure_reason is None
    assert event.raw_xml == xml


def test_local_logon_has_no_network_fields():
    event = parse_security_xml(fixture_text("4624_local_service_logon.xml"))
    assert event.logon_type_name == "Service"
    assert event.source_ip is None
    assert event.source_port is None
    assert event.workstation_name is None


def test_missing_and_unexpected_fields_are_tolerated():
    event = parse_security_xml(fixture_text("4625_missing_fields.xml"))
    assert event.target_username == "bob"
    assert event.logon_type is None
    assert event.source_ip is None
    assert event.status is None
    assert event.failure_reason is None


def test_malformed_xml_raises_parse_error():
    with pytest.raises(EventParseError):
        parse_security_xml(fixture_text("malformed_truncated.xml"))


def test_dtd_is_rejected():
    xml = '<!DOCTYPE x [<!ENTITY a "aaaa">]>' + fixture_text("4625_failed_network_logon.xml")
    with pytest.raises(EventParseError):
        parse_security_xml(xml)


def test_unsupported_event_id_is_rejected():
    xml = fixture_text("4625_failed_network_logon.xml").replace("<EventID>4625<", "<EventID>4740<")
    with pytest.raises(EventParseError):
        parse_security_xml(xml)


def test_missing_record_id_is_rejected():
    xml = fixture_text("4625_failed_network_logon.xml").replace(
        "<EventRecordID>100201</EventRecordID>", ""
    )
    with pytest.raises(EventParseError):
        parse_security_xml(xml)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("192.0.2.10", "192.0.2.10"),
        ("::ffff:192.0.2.10", "192.0.2.10"),
        ("::1", "::1"),
        ("127.0.0.1", "127.0.0.1"),
        ("fe80::1c2b:3d4e:5f60:7182", "fe80::1c2b:3d4e:5f60:7182"),
        ("2001:DB8::1", "2001:db8::1"),
        ("[2001:db8::1]", "2001:db8::1"),
        (None, None),
        ("", None),
        ("not-an-ip", None),
    ],
)
def test_ip_normalization(raw, expected):
    assert normalize_ip(raw) == expected


def test_timestamp_with_seven_fraction_digits():
    ts = parse_windows_timestamp("2026-10-06T08:15:22.9999999Z")
    assert ts.tzinfo is not None
    assert ts.microsecond == 999999
