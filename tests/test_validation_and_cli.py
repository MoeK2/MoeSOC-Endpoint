"""Evidence verification against a (fake) live log, and the CLI investigation commands."""

import re
from collections.abc import Iterator
from datetime import timedelta

from moesoc.cli import main
from moesoc.engine.scanner import ScanService
from moesoc.engine.validation import EvidenceStatus, record_xpath, verify_detection_evidence
from moesoc.storage.repository import DetectionRepository

from .conftest import BASE_TIME, auth_xml

SEC = timedelta(seconds=1)
HOST = "WS-LAB01.lab.example"


class RecordReader:
    """Fake live log that answers record-ID queries like EvtQuery would."""

    def __init__(self, xml_records: list[str]) -> None:
        self.by_id = {int(re.search(r"<EventRecordID>(\d+)<", x).group(1)): x for x in xml_records}

    def query(self, channel: str, xpath: str, *, newest_first: bool = False) -> Iterator[str]:
        match = re.fullmatch(r"\*\[System\[EventRecordID=(\d+)\]\]", xpath)
        assert match, xpath  # only record-ID queries are expected here
        record = self.by_id.get(int(match.group(1)))
        if record:
            yield record


def _attack():
    xml = [auth_xml(4625, "alice", BASE_TIME + i * 10 * SEC, 7000 + i) for i in range(5)]
    xml.append(auth_xml(4624, "alice", BASE_TIME + 90 * SEC, 7100, logon_type=10))
    return xml


def _import(tmp_path, config, database, rules, xml):
    export = tmp_path / "export.xml"
    export.write_text("\n".join(xml), encoding="utf-8")
    ScanService(config, database, rules).import_xml_file(export)
    with database.connect() as conn:
        return {d.rule_id: d.id for d in DetectionRepository(conn).list_all()}


def test_record_xpath_is_integer_only():
    assert record_xpath(42) == "*[System[EventRecordID=42]]"


def test_evidence_verified_against_live_log(tmp_path, config, database, rules):
    xml = _attack()
    ids = _import(tmp_path, config, database, rules, xml)
    with database.connect() as conn:
        checks = verify_detection_evidence(conn, RecordReader(xml), ids["COR-001"], HOST)
    assert len(checks) == 6
    assert all(c.status is EvidenceStatus.VERIFIED for c in checks)
    assert "raw XML identical" in checks[0].detail


def test_rolled_over_and_reused_records_are_reported(tmp_path, config, database, rules):
    xml = _attack()
    ids = _import(tmp_path, config, database, rules, xml)
    live = xml[1:]  # record 7000 rolled out of the log
    live[0] = auth_xml(4624, "bob", BASE_TIME + 3600 * SEC, 7001)  # record ID reused
    with database.connect() as conn:
        checks = {
            c.record_id: c.status
            for c in verify_detection_evidence(conn, RecordReader(live), ids["COR-001"], HOST)
        }
    assert checks[7000] is EvidenceStatus.MISSING
    assert checks[7001] is EvidenceStatus.MISMATCH
    assert checks[7100] is EvidenceStatus.VERIFIED


def test_evidence_from_another_computer_is_not_checked(tmp_path, config, database, rules):
    ids = _import(tmp_path, config, database, rules, _attack())
    with database.connect() as conn:
        checks = verify_detection_evidence(conn, RecordReader([]), ids["DET-001"], "OTHER-PC")
    assert {c.status for c in checks} == {EvidenceStatus.NOT_LOCAL}


# ------------------------------------------------------------------ CLI
def test_cli_investigation_flow(tmp_path, capsys):
    export = tmp_path / "export.xml"
    export.write_text("\n".join(_attack()), encoding="utf-8")
    base = ["--data-dir", str(tmp_path / "data")]

    assert main([*base, "import-xml", str(export)]) == 0
    assert main([*base, "detections"]) == 0
    listing = capsys.readouterr().out
    cor_id = int(re.search(r"#(\d+)\s+\[HIGH/\w+\] COR-001", listing).group(1))

    assert main([*base, "triage", str(cor_id), "INVESTIGATING", "--note", "asked the user"]) == 0
    assert main([*base, "show", str(cor_id)]) == 0
    shown = capsys.readouterr().out
    assert "Status Investigating" in shown
    assert "Why confidence is" in shown
    assert "asked the user" in shown
    assert "NEW → INVESTIGATING" in shown

    assert main([*base, "timeline", str(cor_id)]) == 0
    timeline = capsys.readouterr().out
    assert timeline.count("\n* ") == 6  # 6 evidence lines marked

    assert main([*base, "events", "--user", "alice", "--event-id", "4624"]) == 0
    assert "1 matching events" in capsys.readouterr().out

    assert main([*base, "triage", str(cor_id), "TRUE_POSITIVE"]) == 0
    assert main([*base, "detections"]) == 0
    assert "COR-001" not in capsys.readouterr().out.split("is now")[-1]  # closed: hidden
    assert main([*base, "detections", "--all"]) == 0
    assert "True Positive" in capsys.readouterr().out


def test_cli_errors_are_readable(tmp_path, capsys):
    base = ["--data-dir", str(tmp_path / "data")]
    assert main([*base, "show", "999"]) == 2
    assert "Detection #999 does not exist." in capsys.readouterr().err
    assert main([*base, "note", "999", "x"]) == 2


def test_cli_exits_quietly_when_the_reader_closes_the_pipe(tmp_path, monkeypatch, capsys):
    # Audit A-5: "moesoc-cli events | head -1" printed a BrokenPipeError traceback.
    class ClosedPipe:
        def write(self, _text):
            raise BrokenPipeError

        def flush(self):
            pass

    monkeypatch.setattr("sys.stdout", ClosedPipe())
    assert main(["--data-dir", str(tmp_path), "rules"]) == 0
