"""Shared test helpers. Tests never touch the real Windows event log."""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from moesoc.core.config import AppConfig
from moesoc.core.event import NormalizedEvent
from moesoc.core.exceptions import ChannelNotFoundError
from moesoc.engine.rules import load_rules
from moesoc.parsers.security import parse_security_xml
from moesoc.storage.database import Database

FIXTURES = Path(__file__).parent / "fixtures"
RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
BASE_TIME = datetime(2026, 10, 6, 8, 0, 0, tzinfo=UTC)

_TEMPLATE = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>{event_id}</EventID>
    <Version>{version}</Version>
    <TimeCreated SystemTime="{time}" />
    <EventRecordID>{record_id}</EventRecordID>
    <Channel>Security</Channel>
    <Computer>{host}</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserSid">{sid}</Data>
    <Data Name="TargetUserName">{user}</Data>
    <Data Name="TargetDomainName">{domain}</Data>
    <Data Name="LogonType">{logon_type}</Data>
    <Data Name="Status">{status}</Data>
    <Data Name="SubStatus">{sub_status}</Data>
    <Data Name="WorkstationName">{workstation}</Data>
    <Data Name="AuthenticationPackageName">{auth_package}</Data>
    <Data Name="IpAddress">{ip}</Data>
    <Data Name="IpPort">{port}</Data>
  </EventData>
</Event>"""


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def auth_xml(
    event_id: int,
    user: str,
    at: datetime,
    record_id: int,
    ip: str = "192.0.2.45",
    logon_type: int = 3,
    domain: str = "LAB",
    sid: str | None = None,
    host: str = "WS-LAB01.lab.example",
    workstation: str = "WS-REMOTE",
    sub_status: str | None = None,
    auth_package: str = "NTLM",
) -> str:
    """Render one 4624/4625 like EvtRender would. Failures default to the NULL SID."""
    failure = event_id == 4625
    from xml.sax.saxutils import escape

    return _TEMPLATE.format(
        host=host,
        sid=sid or ("S-1-0-0" if failure else "-"),
        domain=escape(domain),
        workstation=escape(workstation),
        auth_package=auth_package,
        event_id=event_id,
        version=0 if failure else 2,
        time=at.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z",
        record_id=record_id,
        user=escape(user),
        logon_type=logon_type,
        status="0xC000006D" if failure else "0x0",
        sub_status=sub_status or ("0xC000006A" if failure else "0x0"),
        ip=ip,
        port=51000 + record_id % 1000,
    )


def auth_event(
    event_id: int, user: str, at: datetime, record_id: int, **kw: object
) -> NormalizedEvent:
    """Build a NormalizedEvent through the real XML parser."""
    return parse_security_xml(auth_xml(event_id, user, at, record_id, **kw))  # type: ignore[arg-type]


def failures(
    user: str,
    count: int,
    start: datetime,
    every: timedelta,
    first_record: int = 1000,
    **kw: object,
):
    return [auth_event(4625, user, start + i * every, first_record + i, **kw) for i in range(count)]


_XPATH_IDS = re.compile(r"EventID=(\d+)")
_CHANNEL = re.compile(r"<Channel>([^<]+)</Channel>")
_RECORD_ID = re.compile(r"<EventID[^>]*>\s*(\d+)\s*<")


class FakeReader:
    """Stands in for WindowsEventLogReader; yields pre-rendered XML strings.

    Like the real server-side filter, an XPath naming event IDs only returns records
    with those IDs. Records whose ID cannot be read go to the query that includes
    4625, so each record is returned by exactly one of the collector's queries.
    """

    def __init__(self, xml_records: list[str], error: Exception | None = None) -> None:
        self.xml_records = xml_records
        self.error = error
        self.queries: list[tuple[str, str]] = []

    def query(self, channel: str, xpath: str, *, newest_first: bool = False) -> Iterator[str]:
        self.queries.append((channel, xpath))
        if self.error:
            raise self.error
        # Like Windows: a channel that does not exist on this host cannot be queried.
        channels = {"Security"} | {
            m.group(1) for x in self.xml_records if (m := _CHANNEL.search(x))
        }
        if channel not in channels:
            raise ChannelNotFoundError(f"The event log channel '{channel}' does not exist.")
        wanted = set(_XPATH_IDS.findall(xpath))
        for xml in self.xml_records:
            found = _CHANNEL.search(xml)
            if found and found.group(1) != channel:
                continue
            match = _RECORD_ID.search(xml)
            if not wanted or (match.group(1) in wanted if match else "4625" in wanted):
                yield xml


@pytest.fixture
def rules():
    return load_rules(RULES_DIR)


@pytest.fixture
def config(tmp_path: Path) -> AppConfig:
    return AppConfig(data_dir=tmp_path, rules_dir=RULES_DIR)


@pytest.fixture
def database(config: AppConfig) -> Database:
    db = Database(config.database_path)
    db.initialize()
    return db
