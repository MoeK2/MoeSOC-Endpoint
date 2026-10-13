"""Investigation stories: related findings, collapsed steps, gaps, next steps, privacy."""

from __future__ import annotations

import pytest

from moesoc.core.exceptions import MoeSOCError
from moesoc.engine.scanner import run_detections
from moesoc.storage.repository import DetectionRepository, EventRepository
from moesoc.storage.story import build_story, render_story_lines

from .test_cross_source import (
    MIN,
    T,
    account_created,
    brute_force_then_logon,
    powershell_start,
)
from .test_powershell import CRADLE, block


def store(database, events, rules):
    with database.connect() as conn:
        EventRepository(conn).insert_many(events)
        repo = DetectionRepository(conn)
        for detection in run_detections(events, rules):
            repo.upsert(detection, None)
        return {d.rule_id: d.id for d in repo.list_all()}


@pytest.fixture
def incident(database, rules):
    events = [
        *brute_force_then_logon(),
        account_created(T + 3 * MIN),
        powershell_start(T + 4 * MIN),
        block(CRADLE, at=T + 5 * MIN),
    ]
    return store(database, events, rules)


def story_of(database, rules, detection_id):
    with database.connect() as conn:
        return build_story(conn, detection_id, rules)


def test_story_groups_related_findings(database, rules, incident):
    story = story_of(database, rules, incident["COR-001"])
    relations = {f.rule_id: f.relation for f in story.findings}
    assert relations["COR-001"] == "this finding"
    assert relations["DET-001"] == "shares evidence"
    assert relations["COR-003"] == "shares evidence"
    assert story.title.startswith("Possible Account Compromise: LAB\\alice")
    assert story.hostname == "WS-LAB01.lab.example"


def test_repeated_events_are_collapsed_into_one_step(database, rules, incident):
    story = story_of(database, rules, incident["COR-001"])
    first = story.steps[0]
    assert first.count == 6 and first.text.startswith("6× Failed")
    assert set(first.findings) >= {"COR-001", "DET-001", "COR-003"}
    assert [s.start for s in story.steps] == sorted(s.start for s in story.steps)


def test_story_lists_what_the_data_cannot_tell(database, rules, incident):
    story = story_of(database, rules, incident["COR-001"])
    gaps = " ".join(story.gaps)
    assert "No Microsoft Defender events" in gaps
    assert "cannot tell whether a successful logon was the real account owner" in gaps
    assert "No Sysmon events" not in gaps  # Sysmon process events were recorded
    assert story.next_steps and len(story.next_steps) == len(set(story.next_steps))


def test_story_never_contains_script_text_or_command_lines(database, rules, incident):
    story = story_of(database, rules, incident["COR-003"])
    text = "\n".join(render_story_lines(story))
    assert "DownloadString" not in text and "203.0.113.80" not in text
    assert "Get-Date" not in text  # the Sysmon command line
    assert "not proof" in text


def test_notes_appear_in_the_story(database, rules, incident):
    with database.connect() as conn:
        DetectionRepository(conn).add_note(incident["COR-001"], "Called the user: not them")
    story = story_of(database, rules, incident["COR-001"])
    assert [n.body for n in story.notes] == ["Called the user: not them"]


def test_unknown_finding_is_a_readable_error(database, rules):
    with pytest.raises(MoeSOCError):
        story_of(database, rules, 999)


def test_cli_story(database, config, rules, incident, capsys):
    from moesoc.cli import main

    assert main(["--data-dir", str(config.data_dir), "story", str(incident["COR-001"])]) == 0
    out = capsys.readouterr().out
    assert "What happened" in out and "What the data cannot tell" in out
    assert "Next steps" in out
