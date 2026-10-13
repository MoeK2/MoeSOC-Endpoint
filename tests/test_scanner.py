"""End-to-end pipeline tests: fake reader → parse → store → detect → persist."""

from datetime import timedelta

import pytest

from moesoc.core.exceptions import LogAccessDeniedError
from moesoc.engine.scanner import ScanService
from moesoc.storage.repository import DetectionRepository, EventRepository, ScanRepository
from moesoc.utils.time import utc_now

from .conftest import FakeReader, auth_xml, fixture_text


def _attack_sequence():
    start = utc_now() - timedelta(hours=1)
    xml = [auth_xml(4625, "alice", start + timedelta(seconds=20 * i), 5000 + i) for i in range(6)]
    xml.append(auth_xml(4624, "alice", start + timedelta(minutes=3), 5100, logon_type=10))
    xml.append(fixture_text("malformed_truncated.xml"))
    return xml


def test_live_scan_end_to_end(config, database, rules):
    reader = FakeReader(_attack_sequence())
    service = ScanService(config, database, rules, reader_factory=lambda: reader)

    summary = service.run_live_scan()

    assert summary.records_read == 8
    assert summary.events_normalized == 7
    assert summary.parse_failures == 1
    assert summary.events_new == 7
    assert summary.detections_new == 2  # DET-001 and COR-001
    with database.connect() as conn:
        rule_ids = sorted(d.rule_id for d in DetectionRepository(conn).list_all())
        last = ScanRepository(conn).last()
    assert rule_ids == ["COR-001", "DET-001"]
    assert last is not None and last.status == "completed" and last.events_new == 7


def test_rescan_does_not_duplicate_events_or_detections(config, database, rules):
    reader = FakeReader(_attack_sequence())
    service = ScanService(config, database, rules, reader_factory=lambda: reader)
    service.run_live_scan()
    second = service.run_live_scan()

    assert second.events_new == 0
    assert second.detections_new == 0
    with database.connect() as conn:
        assert EventRepository(conn).count() == 7
        assert DetectionRepository(conn).count() == 2


def test_access_denied_marks_scan_failed(config, database, rules):
    error = LogAccessDeniedError("Access denied while reading the Windows 'Security' log.")
    service = ScanService(
        config, database, rules, reader_factory=lambda: FakeReader([], error=error)
    )
    with pytest.raises(LogAccessDeniedError):
        service.run_live_scan()
    with database.connect() as conn:
        last = ScanRepository(conn).last()
    assert last is not None and last.status == "failed"
    assert "Access denied" in (last.message or "")


def test_import_wevtutil_style_xml(tmp_path, config, database, rules):
    # wevtutil qe Security /f:xml emits <Event> elements back to back, without a root.
    export = tmp_path / "export.xml"
    export.write_text("\n".join(_attack_sequence()), encoding="utf-8")
    service = ScanService(config, database, rules, reader_factory=lambda: FakeReader([]))

    summary = service.import_xml_file(export)

    assert summary.origin == "import"
    assert summary.events_new == 7
    assert summary.detections_new == 2
