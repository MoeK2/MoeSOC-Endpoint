"""The portfolio demo: synthetic, separate, labelled, and it never touches other databases."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from moesoc.storage.repository import DetectionRepository

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "demo.py"


def load_demo():
    spec = importlib.util.spec_from_file_location("moesoc_demo", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_demo_story_triggers_the_rules_it_describes(tmp_path):
    demo = load_demo()
    _config, database, _rules = demo.build(tmp_path)
    with database.connect() as conn:
        found = {d.rule_id: d for d in DetectionRepository(conn).list_all()}
    assert set(found) == {
        "DET-001", "DET-002", "DET-003", "DET-005", "DET-006", "DET-007", "DET-008",
        "COR-001", "COR-002", "COR-003", "COR-004",
    }  # fmt: skip
    kinds = found["COR-003"].evidence["follow_up_kinds"]
    # Session-linked follow-ups, plus Defender's detection for alice (a weaker user+time link).
    assert kinds == [
        "account_created",
        "defender_detection",
        "group_member_added",
        "suspicious_powershell",
    ]
    assert found["COR-003"].evidence["link_quality"].startswith("exact")
    assert found["COR-004"].evidence["written_by"].endswith("msedge.exe")
    assert found["DET-005"].severity == "MEDIUM"  # hidden name ending with $
    assert (tmp_path / demo.MARKER).exists()


def test_demo_rebuild_replaces_only_its_own_database(tmp_path):
    demo = load_demo()
    demo.build(tmp_path)
    demo.build(tmp_path)  # a second run starts fresh instead of duplicating
    other = tmp_path / "real"
    other.mkdir()
    (other / "moesoc.db").write_bytes(b"not a demo")
    with pytest.raises(SystemExit, match="not a demo database"):
        demo.prepare_folder(other)
    assert (other / "moesoc.db").read_bytes() == b"not a demo"


def test_cor004_techniques_are_shown_in_cli_and_report(tmp_path, capsys):
    # Audit A-6: COR-004 printed an empty "MITRE:" line although T1105 was in the evidence.
    from moesoc.cli import main

    demo = load_demo()
    _config, database, _rules = demo.build(tmp_path)
    with database.connect() as conn:
        cor004 = next(d for d in DetectionRepository(conn).list_all() if d.rule_id == "COR-004")
    capsys.readouterr()
    assert main(["--data-dir", str(tmp_path), "show", str(cor004.id)]) == 0
    assert "MITRE: related to this finding: T1105" in capsys.readouterr().out
    report = tmp_path / "r.html"
    assert main(["--data-dir", str(tmp_path), "report", "--finding", str(cor004.id),
                 "--out", str(report)]) == 0  # fmt: skip
    assert "<b>T1105</b> — related to this finding" in report.read_text(encoding="utf-8")
