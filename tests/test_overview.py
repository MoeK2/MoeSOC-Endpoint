"""The dashboard read model must report only real, stored values."""

from moesoc.core.enums import Severity
from moesoc.engine.scanner import ScanService
from moesoc.storage.overview import load_overview

from .conftest import FakeReader
from .test_scanner import _attack_sequence


def test_empty_database_reports_no_risk_rather_than_zero(database):
    snapshot = load_overview(database)
    assert snapshot.events_total == 0
    assert snapshot.detections == []
    assert snapshot.risk_score is None  # "Unavailable", not a fake 0
    assert snapshot.last_scan is None
    assert snapshot.has_completed_scan is False


def test_snapshot_reflects_stored_scan_results(config, database, rules):
    reader = FakeReader(_attack_sequence())
    ScanService(config, database, rules, reader_factory=lambda: reader).run_live_scan()

    snapshot = load_overview(database)
    assert snapshot.events_total == 7
    assert snapshot.events_by_id == {4624: 1, 4625: 6}
    assert snapshot.severity_counts[Severity.HIGH] == 1
    assert snapshot.severity_counts[Severity.MEDIUM] == 1
    assert snapshot.highest_severity is Severity.HIGH
    assert snapshot.risk_score == 70
    assert snapshot.has_completed_scan


def test_clean_scan_has_zero_risk(config, database, rules):
    ScanService(config, database, rules, reader_factory=lambda: FakeReader([])).run_live_scan()
    snapshot = load_overview(database)
    assert snapshot.risk_score == 0
    assert snapshot.highest_severity is None
