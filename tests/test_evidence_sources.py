"""A-3: evidence verification uses the parser of each event's own channel.

Audit reproduction (2026-10-08): unchanged Sysmon, PowerShell and Defender evidence was
re-parsed as Security XML and reported as "mismatch" (a false tamper signal).
"""

import re
from collections.abc import Iterator

import pytest

from moesoc.core.exceptions import ChannelNotFoundError, LogAccessDeniedError
from moesoc.engine.validation import EvidenceStatus, verify_event
from moesoc.parsers.dispatch import parse_any_xml
from moesoc.storage.event_search import EventFilter, search_events
from moesoc.storage.repository import EventRepository

from .conftest import fixture_text

SOURCES = {
    # fixture: (field to tamper with, original value, tampered value)
    "4625_failed_network_logon.xml": ('"TargetUserName">', "alice", "mallory"),
    "sysmon_1_process_create.xml": (
        '"ProcessGuid">',
        "{8A1C5F3E-6B2A-6702-2F01-000000000E00}",
        "{8A1C5F3E-6B2A-6702-2F01-000000000E99}",
    ),
    "powershell_4104_script_block.xml": (
        '"ScriptBlockId">',
        "9C2E8D5A-1B4F-4C3D-8E2A-6F1B0D7C9A11",
        "9C2E8D5A-1B4F-4C3D-8E2A-6F1B0D7C9A99",
    ),
    "defender_1116_malware_detected.xml": (
        '"Threat Name">',
        "Virus:DOS/EICAR_Test_File",
        "Trojan:Win32/Other",
    ),
}


class LiveLog:
    """Answers record-ID queries per channel, like EvtQuery on the real log."""

    def __init__(self, records: dict[str, list[str]] | None = None, error=None) -> None:
        self.records = records or {}
        self.error = error
        self.channels: list[str] = []

    def query(self, channel: str, xpath: str, *, newest_first: bool = False) -> Iterator[str]:
        self.channels.append(channel)
        if self.error:
            raise self.error
        wanted = int(re.search(r"EventRecordID=(\d+)", xpath).group(1))
        for xml in self.records.get(channel, []):
            if int(re.search(r"<EventRecordID>(\d+)<", xml).group(1)) == wanted:
                yield xml


def stored(database, xml: str):
    """The event as verification sees it: parsed, stored, read back from SQLite."""
    with database.connect() as conn:
        EventRepository(conn).insert_many([parse_any_xml(xml)])
        (item,) = search_events(conn, EventFilter(limit=5)).events
    return item.event


@pytest.mark.parametrize("name", list(SOURCES))
def test_unchanged_evidence_verifies_with_its_own_parser(database, name):
    xml = fixture_text(name)
    event = stored(database, xml)
    log = LiveLog({event.channel: [xml]})
    check = verify_event(log, event)
    assert check.status is EvidenceStatus.VERIFIED, check.detail
    assert log.channels == [event.channel]  # queried in the event's own channel


@pytest.mark.parametrize("name", list(SOURCES))
def test_re_rendered_whitespace_still_verifies(database, name):
    xml = fixture_text(name)
    event = stored(database, xml)
    rerendered = re.sub(r">\s+<", "><", xml)
    check = verify_event(LiveLog({event.channel: [rerendered]}), event)
    assert check.status is EvidenceStatus.VERIFIED
    assert "re-rendered" in check.detail


@pytest.mark.parametrize("name", list(SOURCES))
def test_a_changed_value_is_a_mismatch(database, name):
    xml = fixture_text(name)
    field, original, tampered = SOURCES[name]
    assert f"{field}{original}<" in xml
    event = stored(database, xml)
    live = xml.replace(f"{field}{original}<", f"{field}{tampered}<")
    check = verify_event(LiveLog({event.channel: [live]}), event)
    assert check.status is EvidenceStatus.MISMATCH
    assert "different content" in check.detail


@pytest.mark.parametrize("name", list(SOURCES))
def test_rolled_out_record_is_missing(database, name):
    event = stored(database, fixture_text(name))
    assert verify_event(LiveLog({event.channel: []}), event).status is EvidenceStatus.MISSING


@pytest.mark.parametrize("name", list(SOURCES))
def test_malformed_live_xml_is_unreadable_not_a_crash(database, name):
    event = stored(database, fixture_text(name))
    rid = event.record_id
    broken = f"<Event><System><EventRecordID>{rid}</EventRecordID><Channel>"
    check = verify_event(LiveLog({event.channel: [broken]}), event)
    assert check.status is EvidenceStatus.UNREADABLE


def test_record_from_another_channel_never_verifies(database):
    sysmon = fixture_text("sysmon_1_process_create.xml")
    event = stored(database, sysmon)
    # a reader that (wrongly) answers with a Security record carrying the same record ID
    impostor = re.sub(
        r"<EventRecordID>\d+<",
        f"<EventRecordID>{event.record_id}<",
        fixture_text("4625_failed_network_logon.xml"),
    )
    check = verify_event(LiveLog({event.channel: [impostor]}), event)
    assert check.status is EvidenceStatus.MISMATCH


def test_reused_record_id_is_a_mismatch(database):
    xml = fixture_text("defender_1116_malware_detected.xml")
    event = stored(database, xml)
    reused = re.sub(r'SystemTime="[^"]+"', 'SystemTime="2026-12-01T00:00:00.0000000Z"', xml)
    check = verify_event(LiveLog({event.channel: [reused]}), event)
    assert check.status is EvidenceStatus.MISMATCH and "reused" in check.detail


def test_removed_channel_is_missing_and_access_denied_is_unreadable(database):
    event = stored(database, fixture_text("sysmon_1_process_create.xml"))
    gone = LiveLog(error=ChannelNotFoundError("Sysmon was uninstalled"))
    assert verify_event(gone, event).status is EvidenceStatus.MISSING
    denied = LiveLog(error=LogAccessDeniedError("Access denied"))
    assert verify_event(denied, event).status is EvidenceStatus.UNREADABLE
