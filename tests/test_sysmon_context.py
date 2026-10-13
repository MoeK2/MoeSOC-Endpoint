"""Sysmon 3 / 11 / 13 / 22: context telemetry, never alerts on their own."""

from datetime import timedelta

from moesoc.collectors.sysmon import SYSMON_GROUPS
from moesoc.engine.scanner import ScanService, run_detections
from moesoc.parsers.sysmon import parse_sysmon_xml, resolved_addresses
from moesoc.storage.event_search import EventFilter, explain_event, search_events
from moesoc.storage.repository import EventRepository
from moesoc.utils.time import utc_now

from .conftest import FakeReader, fixture_text


def load(name):
    return parse_sysmon_xml(fixture_text(name))


def test_network_connection_keeps_both_endpoints_and_direction():
    e = load("sysmon_3_network_connect.xml")
    assert (e.source_ip, e.source_port) == ("192.0.2.10", 51544)
    assert (e.destination_ip, e.destination_port) == ("203.0.113.80", 443)
    assert e.network_protocol == "tcp"
    assert e.detail("initiated") is True
    assert e.detail("destination_hostname") == "downloads.example.net"
    assert e.process_name == "powershell.exe" and e.subject_username == "alice"
    assert e.process_guid == "{8a1c5f3e-6b2a-6702-2f01-000000000e00}"
    text = explain_event(e)
    assert "192.0.2.10:51544 → 203.0.113.80:443" in text and "outbound" in text


def test_file_create_records_the_target_file():
    e = load("sysmon_11_file_create.xml")
    assert e.file_path.endswith("\\Temp\\update.ps1")
    assert e.detail("creation_utc_time") == "2026-10-06 08:21:14.000"
    assert "created file" in explain_event(e)


def test_registry_value_is_stored_but_never_summarized():
    e = load("sysmon_13_registry_value_set.xml")
    assert e.registry_path.endswith("\\CurrentVersion\\Run\\Updater")
    assert e.detail("registry_value").endswith("update.ps1")
    assert e.detail("registry_event_type") == "SetValue"
    text = explain_event(e)
    assert "Run\\Updater" in text and "update.ps1" not in text


def test_dns_query_extracts_resolved_addresses():
    e = load("sysmon_22_dns_query.xml")
    assert e.dns_query == "downloads.example.net"
    assert e.detail("resolved_addresses") == ["203.0.113.80", "2001:db8::80"]
    assert e.detail("query_status") == "0"
    assert "looked up downloads.example.net → 203.0.113.80" in explain_event(e)


def test_resolved_addresses_ignores_names_and_duplicates():
    assert resolved_addresses("type:  5 a.example;::ffff:192.0.2.1;192.0.2.1;") == ["192.0.2.1"]
    assert resolved_addresses("") == [] and resolved_addresses(None) == []


def test_missing_network_fields_stay_empty():
    xml = fixture_text("sysmon_3_network_connect.xml")
    for name in ("DestinationIp", "DestinationPort", "Protocol", "Initiated"):
        start = xml.index(f'<Data Name="{name}">')
        xml = xml[:start] + xml[xml.index("</Data>", start) + len("</Data>") :]
    e = parse_sysmon_xml(xml)
    assert e.destination_ip is None and e.destination_port is None
    assert e.network_protocol is None and e.detail("initiated") is None
    assert "direction ?" in explain_event(e)


def test_context_events_never_raise_findings(rules):
    names = (
        "sysmon_3_network_connect.xml",
        "sysmon_11_file_create.xml",
        "sysmon_13_registry_value_set.xml",
        "sysmon_22_dns_query.xml",
    )
    events = [load(n) for n in names for _ in range(10)]
    assert run_detections(events, rules) == []


def test_each_family_has_its_own_collection_group():
    assert {g: sorted(ids) for g, ids in SYSMON_GROUPS.items()} == {
        "sysmon_process": [1],
        "sysmon_network": [3],
        "sysmon_file": [11],
        "sysmon_registry": [13],
        "sysmon_dns": [22],
    }


def test_ip_search_matches_connection_destinations(database):
    with database.connect() as conn:
        EventRepository(conn).insert_many([load("sysmon_3_network_connect.xml")])
        exact = search_events(conn, EventFilter(ip="203.0.113.80"))
        prefix = search_events(conn, EventFilter(ip="203.0.113."))
    assert exact.total == 1 and prefix.total == 1


def test_scan_collects_every_family(config, database, rules):
    def recent(name, record, minutes):
        stamp = (utc_now() - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"
        xml = fixture_text(name)
        start = xml.index('SystemTime="') + len('SystemTime="')
        xml = xml[:start] + stamp + xml[xml.index('"', start) :]
        return xml.replace(
            xml[xml.index("<EventRecordID>") : xml.index("</EventRecordID>")],
            f"<EventRecordID>{record}",
        )

    reader = FakeReader(
        [
            recent("sysmon_1_process_create.xml", 9001, 9),
            recent("sysmon_3_network_connect.xml", 9002, 8),
            recent("sysmon_11_file_create.xml", 9003, 7),
            recent("sysmon_13_registry_value_set.xml", 9004, 6),
            recent("sysmon_22_dns_query.xml", 9005, 5),
        ]
    )
    service = ScanService(config, database, rules, reader_factory=lambda: reader, host_aliases=list)
    summary = service.run_live_scan()
    assert summary.events_new == 5
    for group in SYSMON_GROUPS:
        assert f"{group}: bootstrap" in summary.collection_mode
