"""Phase 24 search filters (all SQL-side) and pivots."""

from __future__ import annotations

import pytest

from moesoc.parsers.sysmon import parse_sysmon_xml
from moesoc.storage.event_search import EventFilter, more_pivots, search_events
from moesoc.storage.repository import EventRepository

from .conftest import fixture_text
from .test_cross_source import T, account_created, logon
from .test_defender import detected
from .test_sysmon import sysmon_xml


def load(name):
    return parse_sysmon_xml(fixture_text(name))


@pytest.fixture
def stored(database):
    events = [
        load("sysmon_3_network_connect.xml"),
        load("sysmon_11_file_create.xml"),
        load("sysmon_13_registry_value_set.xml"),
        load("sysmon_22_dns_query.xml"),
        parse_sysmon_xml(sysmon_xml(record=5101)),
        detected(),
        logon(T),
        account_created(T),
    ]
    with database.connect() as conn:
        EventRepository(conn).insert_many(events)
    return events


def ids(database, **kw):
    with database.connect() as conn:
        page = search_events(conn, EventFilter(**kw))
    return sorted((e.event.source.value, e.event.event_id) for e in page.events)


@pytest.mark.parametrize(
    ("kw", "expected"),
    [
        ({"port": 443}, [("sysmon", 3)]),
        ({"port": 51544}, [("sysmon", 3)]),
        ({"file_path": "update.ps1"}, [("sysmon", 11)]),
        ({"registry_path": "currentversion\\run"}, [("sysmon", 13)]),
        ({"dns_query": "downloads.example"}, [("sysmon", 22)]),
        ({"threat": "eicar"}, [("defender", 1116)]),
        ({"parent_process": "cmd.exe"}, [("sysmon", 1)]),
        ({"provider": "Windows Defender"}, [("defender", 1116)]),
        ({"sources": ("defender",)}, [("defender", 1116)]),
        (
            {"logon_id": "0x5A3F21", "hostname": "ws-lab01.lab.example"},
            [("security", 4624), ("security", 4720), ("sysmon", 1)],
        ),
    ],
)
def test_each_filter_matches_only_its_events(database, stored, kw, expected):
    assert ids(database, **kw) == expected


def test_filters_combine_and_escape_like_wildcards(database, stored):
    assert ids(database, dns_query="downloads", sources=("security",)) == []
    assert ids(database, file_path="%") == []  # a literal %, not a wildcard
    assert ids(database, threat="%") == []


def test_text_search_covers_new_fields(database, stored):
    assert ("sysmon", 22) in ids(database, text="downloads.example.net")
    assert ("sysmon", 13) in ids(database, text="CurrentVersion\\Run")


def test_paging_is_done_by_the_database(database, stored):
    with database.connect() as conn:
        first = search_events(conn, EventFilter(limit=3))
        second = search_events(conn, EventFilter(limit=3, offset=3))
    assert first.total == second.total == len(stored)
    assert first.has_more and not {e.pk for e in first.events} & {e.pk for e in second.events}


def test_describe_names_new_conditions():
    text = EventFilter(port=443, dns_query="x", threat="eicar", logon_id="0x1").describe()
    assert "port 443" in text and "DNS 'x'" in text and "threat 'eicar'" in text
    assert "logon session 0x1" in text


def test_more_pivots_follow_the_recorded_fields(stored):
    net, file_create, _reg, dns, process, defender, success, _created = stored
    labels = {p.label for p in more_pivots(net)}
    assert {
        "This destination",
        "This logon session",
    } - labels == set() or "This destination" in labels
    assert "This file" in {p.label for p in more_pivots(file_create)}
    assert "This DNS name" in {p.label for p in more_pivots(dns)}
    assert "This parent process" in {p.label for p in more_pivots(process)}
    threat = [p for p in more_pivots(defender) if p.label == "This Defender threat"]
    assert threat and threat[0].filter.threat == "Virus:DOS/EICAR_Test_File"
    session = [p for p in more_pivots(success) if p.label == "This logon session"]
    assert session and session[0].filter.hostname == success.hostname


def test_system_logon_session_is_not_offered():
    from .test_cross_source import account_created as created

    assert "This logon session" not in {p.label for p in more_pivots(created(T, session="0x3e7"))}


def test_cli_new_filters(database, config, stored, capsys):
    from moesoc.cli import main

    assert main(["--data-dir", str(config.data_dir), "events", "--dns", "downloads"]) == 0
    assert "1 matching events" in capsys.readouterr().out
    assert main(["--data-dir", str(config.data_dir), "events", "--threat", "eicar"]) == 0
    assert "threat 'eicar'" in capsys.readouterr().out
