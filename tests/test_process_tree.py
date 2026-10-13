"""Process trees: GUID links (Sysmon), PID links with reuse (4688), gaps, cycles, limits."""

from datetime import datetime, timedelta

import pytest

from moesoc.core.exceptions import MoeSOCError
from moesoc.parsers.security import parse_security_xml
from moesoc.parsers.sysmon import parse_sysmon_xml
from moesoc.storage import process_tree
from moesoc.storage.process_tree import build_process_tree, render_tree_lines
from moesoc.storage.repository import EventRepository

from .conftest import BASE_TIME, auth_event, fixture_text
from .test_sysmon import sysmon_xml

HOST = "WS-LAB01.lab.example"


def guid(n: int) -> str:
    return f"{{8A1C5F3E-0000-0000-0000-{n:012X}}}"


def sysmon(record, n, parent, image, pid, at, host=HOST):
    xml = sysmon_xml(
        record=record,
        at=at,
        ProcessGuid=guid(n),
        ParentProcessGuid=guid(parent) if parent else "",
        Image=image,
        ProcessId=str(pid),
        ParentProcessId=str(pid - 1),
        ParentImage="C:\\Windows\\parent.exe",
    )
    return parse_sysmon_xml(xml.replace(f"<Computer>{HOST}<", f"<Computer>{host}<"))


def p4688(record, pid, ppid, image, at: datetime, host=HOST):
    xml = fixture_text("4688_process_created.xml")
    xml = xml.replace("<EventRecordID>100240<", f"<EventRecordID>{record}<")
    xml = xml.replace("2026-10-06T08:21:10.0000000Z", at.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z")
    xml = xml.replace(f"<Computer>{HOST}<", f"<Computer>{host}<")
    xml = xml.replace('"NewProcessId">0x1a2c<', f'"NewProcessId">{hex(pid)}<')
    xml = xml.replace('"ProcessId">0x2f04<', f'"ProcessId">{hex(ppid)}<')
    xml = xml.replace(
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", f"C:\\Windows\\{image}"
    )
    return parse_security_xml(xml)


def store(database, events):
    with database.connect() as conn:
        EventRepository(conn).insert_many(events)
        rows = conn.execute("SELECT id, record_id, channel FROM events").fetchall()
    return {(r["channel"][:8], r["record_id"]): r["id"] for r in rows}


def tree(database, pk):
    with database.connect() as conn:
        return build_process_tree(conn, pk)


T = BASE_TIME
MIN = timedelta(minutes=1)


@pytest.fixture
def sysmon_chain(database):
    events = [
        sysmon(1, 1, 99, "C:\\Windows\\explorer.exe", 1000, T),  # parent 99 never collected
        sysmon(2, 2, 1, "C:\\Windows\\System32\\cmd.exe", 2000, T + MIN),
        sysmon(3, 3, 2, "C:\\Windows\\System32\\powershell.exe", 3000, T + 2 * MIN),
        sysmon(4, 4, 3, "C:\\Windows\\System32\\whoami.exe", 4000, T + 3 * MIN),
        sysmon(5, 5, 3, "C:\\Windows\\System32\\net.exe", 5000, T + 4 * MIN),
    ]
    return store(database, events)


def test_sysmon_tree_shows_ancestors_and_children_by_guid(database, sysmon_chain):
    t = tree(database, sysmon_chain[("Microsof", 3)])
    assert [n.name for n in t.ancestors] == ["parent.exe", "explorer.exe", "cmd.exe"]
    assert t.ancestors[0].link == "recorded only" and t.ancestors[0].pk is None
    assert [n.link for n in t.ancestors[1:]] == ["guid", "guid"]
    assert t.root.name == "powershell.exe" and t.root.user == "LAB\\alice"
    assert [c.name for c in t.root.children] == ["whoami.exe", "net.exe"]
    assert t.node_count == 6 and not t.truncated


def test_tree_lines_mark_selection_and_weak_links_without_command_lines(database, sysmon_chain):
    lines = render_tree_lines(tree(database, sysmon_chain[("Microsof", 3)]))
    assert any("powershell.exe" in line and "◀ selected" in line for line in lines)
    assert any("[recorded only]" in line for line in lines)
    assert not any("Get-Date" in line for line in lines)


def test_4688_links_by_pid_and_respects_pid_reuse(database):
    events = [
        p4688(10, 100, 4, "cmd.exe", T),
        p4688(11, 200, 100, "whoami.exe", T + MIN),  # child of cmd (PID 100)
        p4688(12, 100, 4, "notepad.exe", T + 5 * MIN),  # PID 100 reused
        p4688(13, 300, 100, "calc.exe", T + 6 * MIN),  # child of notepad, not cmd
    ]
    pks = store(database, events)
    cmd = tree(database, pks[("Security", 10)])
    assert [c.name for c in cmd.root.children] == ["whoami.exe"]
    assert cmd.root.children[0].link == "pid"
    calc = tree(database, pks[("Security", 13)])
    assert calc.ancestors[-1].name == "notepad.exe" and calc.ancestors[-1].link == "pid"


def test_same_pid_on_another_computer_is_not_a_parent(database):
    events = [
        p4688(20, 100, 4, "cmd.exe", T, host="WS-LAB02.lab.example"),
        p4688(21, 200, 100, "whoami.exe", T + MIN),
    ]
    pks = store(database, events)
    t = tree(database, pks[("Security", 21)])
    assert t.ancestors[-1].link == "recorded only"  # parent not collected on this host


def test_inconsistent_data_never_loops(database):
    looped = [
        sysmon(30, 30, 31, "C:\\a.exe", 3000, T),
        sysmon(31, 31, 30, "C:\\b.exe", 3100, T + MIN),
    ]
    pks = store(database, looped)
    t = tree(database, pks[("Microsof", 30)])
    assert t.node_count <= 3


def test_node_limit_is_reported(database, monkeypatch):
    monkeypatch.setattr(process_tree, "MAX_NODES", 5)
    events = [sysmon(40, 40, None, "C:\\parent.exe", 4000, T)]
    events += [sysmon(41 + i, 41 + i, 40, f"C:\\child{i}.exe", 4100 + i, T + MIN) for i in range(8)]
    pks = store(database, events)
    t = tree(database, pks[("Microsof", 40)])
    assert t.truncated and len(t.root.children) == 4


def test_only_process_events_have_a_tree(database):
    pks = store(database, [auth_event(4625, "alice", T, 50)])
    with pytest.raises(MoeSOCError):
        tree(database, pks[("Security", 50)])
    with pytest.raises(MoeSOCError):
        tree(database, 999_999)


def test_cli_process_tree_prints_the_chain(database, config, sysmon_chain, capsys):
    from moesoc.cli import main

    pk = sysmon_chain[("Microsof", 3)]
    assert main(["--data-dir", str(config.data_dir), "process-tree", str(pk)]) == 0
    out = capsys.readouterr().out
    assert "evidence, not a verdict" in out
    assert "powershell.exe" in out and "◀ selected" in out and "whoami.exe" in out
    assert main(["--data-dir", str(config.data_dir), "events", "--source", "sysmon"]) == 0
    assert f"#{pk}" in capsys.readouterr().out
