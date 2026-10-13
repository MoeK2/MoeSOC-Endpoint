"""HTML reports: self-contained, escaped, no sensitive content, consistent redaction."""

from __future__ import annotations

import re
from datetime import timedelta

import pytest

from moesoc.engine.scanner import run_detections
from moesoc.storage.overview import load_overview
from moesoc.storage.report import Redactor, finding_report, summary_report
from moesoc.storage.repository import DetectionRepository, EventRepository, ScanRepository

from .conftest import BASE_TIME, auth_event, failures
from .test_cross_source import MIN, T, account_created, brute_force_then_logon, powershell_start
from .test_powershell import CRADLE, block


def store(database, events, rules):
    with database.connect() as conn:
        scans = ScanRepository(conn)
        scan_id = scans.start("live")
        scans.finish(scan_id, status="completed")
        EventRepository(conn).insert_many(events)
        repo = DetectionRepository(conn)
        for d in run_detections(events, rules):
            repo.upsert(d, scan_id)
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


def report(database, rules, detection_id, **kw):
    with database.connect() as conn:
        return finding_report(conn, detection_id, rules, **kw)


def assert_self_contained(text):
    assert text.startswith("<!DOCTYPE html>")
    assert "<script" not in text.lower()
    # No external resources or links inside real tags (escaped text may mention them).
    assert not re.search(r"<[^>]*\s(src|href)\s*=", text, re.I)
    assert "@import" not in text and "url(" not in text


def test_finding_report_has_the_story_and_explanations(database, rules, incident):
    text = report(database, rules, incident["COR-001"])
    assert_self_contained(text)
    for section in (
        "Findings",
        "What happened",
        "Why this confidence and risk",
        "What the data cannot tell",
        "Next steps",
        "MITRE ATT&amp;CK",
    ):
        assert section in text
    assert "not proof of compromise" in text
    assert "Live collection from this computer" in text


def test_report_never_contains_script_text_command_lines_or_raw_xml(database, rules, incident):
    text = report(database, rules, incident["COR-003"])
    assert "DownloadString" not in text and "Get-Date" not in text
    assert "<Event" not in text and "EventData" not in text


def test_everything_is_escaped(database, rules):
    hostile = "<script>alert(1)</script>"
    events = [
        *failures(hostile, 6, BASE_TIME, timedelta(seconds=10)),
        auth_event(4624, hostile, BASE_TIME + timedelta(minutes=1), 2000),
    ]
    ids = store(database, events, rules)
    with database.connect() as conn:
        DetectionRepository(conn).add_note(ids["COR-001"], "<img src=x onerror=alert(1)>")
    text = report(database, rules, ids["COR-001"])
    assert "<script>alert" not in text and "<img" not in text
    assert "&lt;script&gt;" in text
    assert_self_contained(text)


def test_redacted_report_hides_identities_consistently(database, rules, incident):
    plain = report(database, rules, incident["COR-001"])
    redacted = report(database, rules, incident["COR-001"], redact=True)
    assert "alice" in plain and "WS-LAB01" in plain and "192.0.2.45" in plain
    for secret in ("alice", "WS-LAB01", "192.0.2.45", "S-1-5-21-1111111111"):
        assert secret.lower() not in redacted.lower(), secret
    assert "USER-1" in redacted and "HOST-1" in redacted and "IP-1" in redacted
    assert "placeholders" in redacted


def test_redactor_keeps_well_known_and_loopback_values():
    r = Redactor(True, ["WS-LAB01.lab.example"], ["alice"])
    text = r.text("LAB\\alice on WS-LAB01 from 10.0.0.5 and ::1 as S-1-5-18, alice again")
    assert text.count("USER-1") == 2 and "HOST-1" in text and "IP-1" in text
    assert "::1" in text and "S-1-5-18" in text
    assert Redactor(False, ["h"], ["a"]).text("a on h") == "a on h"


def test_summary_report(database, rules, incident):
    snapshot = load_overview(database)
    with database.connect() as conn:
        text = summary_report(conn, snapshot)
        redacted = summary_report(conn, snapshot, redact=True)
    assert_self_contained(text)
    assert "Open findings (highest risk first)" in text and "Stored events by ID" in text
    assert "WS-LAB01" in text and "WS-LAB01" not in redacted


def test_imported_data_is_labelled(database, rules):
    with database.connect() as conn:
        scans = ScanRepository(conn)
        scans.finish(scans.start("import"), status="completed")
        EventRepository(conn).insert_many(brute_force_then_logon())
        repo = DetectionRepository(conn)
        for d in run_detections(brute_force_then_logon(), rules):
            repo.upsert(d, None)
        detection_id = repo.list_all()[0].id
    assert "Imported event export(s) only" in report(database, rules, detection_id)


def test_cli_report(database, config, rules, incident, tmp_path, capsys):
    from moesoc.cli import main

    out = tmp_path / "finding.html"
    base = ["--data-dir", str(config.data_dir), "report"]
    assert main([*base, "--finding", str(incident["COR-001"]), "--out", str(out), "--redact"]) == 0
    assert out.exists() and "USER-1" in out.read_text(encoding="utf-8")
    summary = tmp_path / "summary.html"
    assert main([*base, "--summary", "--out", str(summary)]) == 0
    assert "endpoint summary" in summary.read_text(encoding="utf-8")
    assert main([*base, "--summary", "--out", str(summary)]) == 2  # never overwrites silently
    assert "already exists" in capsys.readouterr().err


def test_domains_are_redacted_but_builtin_names_kept():
    r = Redactor(True, [], ["alice"], ["CONTOSO"])
    text = r.text("CONTOSO\\alice and NT AUTHORITY\\SYSTEM")
    assert "CONTOSO" not in text and "DOMAIN-1\\USER-1" in text
    assert "NT AUTHORITY\\SYSTEM" in text


def test_one_person_keeps_one_placeholder_across_domain_spellings():
    r = Redactor(True, ["WS-LAB01.lab.example"], ["alice"], ["LAB", "WS-LAB01"])
    text = r.text("LAB\\alice logged on; WS-LAB01\\alice created an account")
    assert text == "DOMAIN-1\\USER-1 logged on; HOST-1\\USER-1 created an account"
