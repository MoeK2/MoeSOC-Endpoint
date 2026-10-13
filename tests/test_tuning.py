"""Rule tuning and suppressions: auditable, bounded, never touching existing findings."""

from __future__ import annotations

from datetime import timedelta

import pytest

from moesoc.engine.scanner import ScanService
from moesoc.storage.repository import DetectionRepository
from moesoc.storage.tuning import (
    TuningError,
    TuningRepository,
    effective_rules,
    matching_suppression,
)
from moesoc.utils.time import utc_now

from .conftest import FakeReader, auth_xml


def recent_failures(user="bob", count=6, ip="192.0.2.45", first=500):
    start = utc_now() - timedelta(minutes=30)
    return [
        auth_xml(4625, user, start + timedelta(seconds=10 * i), first + i, ip=ip)
        for i in range(count)
    ]


def scan(config, database, rules, records):
    service = ScanService(
        config, database, rules, reader_factory=lambda: FakeReader(records), host_aliases=list
    )
    return service.run_live_scan()


def findings(database):
    with database.connect() as conn:
        return DetectionRepository(conn).list_all()


# ------------------------------------------------------------------ suppressions
def test_suppression_hides_future_findings_and_counts_hits(config, database, rules):
    with database.connect() as conn:
        s = TuningRepository(conn).add_suppression(
            "account", "bob", "Known test account in the lab", rule_id="DET-001"
        )
    summary = scan(config, database, rules, recent_failures())
    assert summary.detections_suppressed == 1
    assert [f.rule_id for f in findings(database)] == []
    with database.connect() as conn:
        stored = TuningRepository(conn).get_suppression(s.id)
    assert stored is not None and stored.hit_count == 1 and stored.last_hit_at is not None


def test_suppression_scope_type_and_value_must_match(config, database, rules):
    with database.connect() as conn:
        repo = TuningRepository(conn)
        repo.add_suppression("account", "alice", "Different account entirely")
        repo.add_suppression("account", "bob", "Only for the spray rule", rule_id="DET-002")
    scan(config, database, rules, recent_failures())
    assert [f.rule_id for f in findings(database)] == ["DET-001"]


def test_source_ip_suppression(config, database, rules):
    records = [
        *recent_failures("u1", 3, first=600),
        *recent_failures("u2", 3, first=700),
        *recent_failures("u3", 3, first=800),
        *recent_failures("u4", 3, first=900),
        *recent_failures("u5", 3, first=1000),
    ]
    with database.connect() as conn:
        TuningRepository(conn).add_suppression("source_ip", "192.0.2.45", "Vulnerability scanner")
    summary = scan(config, database, rules, records)
    assert summary.detections_suppressed >= 1
    assert "DET-002" not in {f.rule_id for f in findings(database)}


def test_existing_findings_are_never_changed(config, database, rules):
    scan(config, database, rules, recent_failures())
    (before,) = findings(database)
    with database.connect() as conn:
        TuningRepository(conn).add_suppression("account", "bob", "Benign after review")
    scan(config, database, rules, recent_failures())
    (after,) = findings(database)
    assert after.id == before.id and after.status == before.status


def test_removed_and_expired_suppressions_stop_matching(database, rules):
    with database.connect() as conn:
        repo = TuningRepository(conn)
        s = repo.add_suppression("account", "bob", "Temporary while testing", days=1)
        assert s.is_active(utc_now())
        assert not s.is_active(utc_now() + timedelta(days=2))
        removed = repo.remove_suppression(s.id, "Testing finished")
        assert removed.removed_at is not None and removed.removed_reason == "Testing finished"
        assert repo.suppressions() == []
        assert [x.id for x in repo.suppressions(include_inactive=True)] == [s.id]
        with pytest.raises(TuningError):
            repo.remove_suppression(s.id, "Twice is an error")


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"type_": "username", "value": "bob", "reason": "valid reason"}, "type"),
        ({"type_": "account", "value": "*", "reason": "valid reason"}, "wildcards"),
        ({"type_": "account", "value": "bob", "reason": "no"}, "reason"),
        ({"type_": "account", "value": "bob", "reason": "valid reason", "days": 400}, "365"),
        ({"type_": "account", "value": "bob", "reason": "valid", "rule_id": "DET-999"}, "Unknown"),
    ],
)
def test_suppression_validation(database, rules, kwargs, message):
    with database.connect() as conn, pytest.raises(TuningError, match=message):
        TuningRepository(conn).add_suppression(known_rules=rules, **kwargs)


def test_threat_and_host_suppressions_match_evidence(rules):
    from moesoc.engine.scanner import run_detections

    from .test_defender import detected

    (finding,) = [f for f in run_detections([detected()], rules) if f.rule_id == "DET-008"]
    from moesoc.storage.tuning import Suppression

    def sup(type_, value):
        return Suppression(1, None, type_, value, "r", utc_now(), None, None, None, 0, None)

    now = utc_now()
    assert matching_suppression(finding, [sup("threat", "virus:dos/eicar_test_file")], now)
    assert matching_suppression(finding, [sup("host", "WS-LAB01.lab.example")], now)
    assert matching_suppression(finding, [sup("process", "explorer.exe")], now)
    assert not matching_suppression(finding, [sup("threat", "eicar")], now)  # exact, not contains


# ------------------------------------------------------------------ rule tuning
def test_disabled_rule_does_not_run(config, database, rules):
    with database.connect() as conn:
        TuningRepository(conn).set_rule_enabled(rules["DET-001"], False, "Too noisy on this lab")
    scan(config, database, rules, recent_failures())
    assert findings(database) == []


def test_tuned_threshold_is_applied_and_recorded_in_the_finding(config, database, rules):
    with database.connect() as conn:
        TuningRepository(conn).set_rule_parameter(rules["DET-001"], "threshold", 10, "Raise bar")
    scan(config, database, rules, recent_failures(count=6))
    assert findings(database) == []  # 6 < 10
    scan(config, database, rules, recent_failures(count=12, first=700))
    (f,) = findings(database)
    assert f.evidence["tuning"] == {"threshold": {"value": 10, "default": 5}}


def test_parameter_validation(database, rules):
    with database.connect() as conn:
        repo = TuningRepository(conn)
        with pytest.raises(TuningError, match="no integer parameter"):
            repo.set_rule_parameter(rules["DET-001"], "nonsense", 3, "reason here")
        with pytest.raises(TuningError, match="between"):
            repo.set_rule_parameter(rules["DET-001"], "threshold", 0, "reason here")
        with pytest.raises(TuningError, match="reason"):
            repo.set_rule_parameter(rules["DET-001"], "threshold", 7, "")


def test_setting_the_default_removes_the_override(database, rules):
    with database.connect() as conn:
        repo = TuningRepository(conn)
        repo.set_rule_parameter(rules["DET-001"], "threshold", 9, "Try a higher bar")
        repo.set_rule_parameter(rules["DET-001"], "threshold", 5, "Back to default")
        assert repo.overrides()["DET-001"] == (True, {})
        assert effective_rules(rules, repo.overrides())["DET-001"] is rules["DET-001"]


def test_every_change_is_in_the_audit_log(database, rules):
    with database.connect() as conn:
        repo = TuningRepository(conn)
        s = repo.add_suppression("host", "LAB-SCANNER", "Authorized scanner host")
        repo.remove_suppression(s.id, "Scanner retired")
        repo.set_rule_enabled(rules["DET-004"], False, "Evaluating noise")
        repo.set_rule_parameter(rules["DET-001"], "threshold", 8, "Fewer alerts")
        log = repo.audit_log()
    assert [e.action for e in log] == [
        "rule.parameter",
        "rule.disable",
        "suppression.remove",
        "suppression.add",
    ]
    assert log[0].details == {"parameter": "threshold", "old": 5, "new": 8, "default": 5}
    assert all(e.reason for e in log)


def test_cli_tuning_commands(database, config, capsys):
    from moesoc.cli import main

    base = ["--data-dir", str(config.data_dir)]
    assert main([*base, "suppress", "add", "--type", "account", "--value", "bob",
                 "--reason", "Lab account", "--days", "7"]) == 0  # fmt: skip
    assert "Added suppression #1" in capsys.readouterr().out
    assert main([*base, "suppress", "list"]) == 0
    assert "account = bob (all rules)" in capsys.readouterr().out
    assert main([*base, "rules", "set", "DET-001", "threshold", "8", "--reason", "Tuning"]) == 0
    assert main([*base, "rules"]) == 0
    assert "threshold=8*" in capsys.readouterr().out
    assert main([*base, "suppress", "remove", "1", "--reason", "Done testing"]) == 0
    assert main([*base, "audit"]) == 0
    out = capsys.readouterr().out
    assert "suppression.remove" in out and "rule.parameter" in out
    assert main([*base, "rules", "set", "DET-001", "threshold", "0", "--reason", "bad"]) == 2


def test_tuning_snapshot_for_the_gui(database, rules):
    from moesoc.storage.tuning import load_tuning

    with database.connect() as conn:
        repo = TuningRepository(conn)
        repo.set_rule_parameter(rules["DET-001"], "threshold", 7, "Tuning test")
        repo.set_rule_enabled(rules["DET-004"], False, "Tuning test")
        repo.add_suppression("account", "bob", "Tuning test")
        snap = load_tuning(conn, rules)
    by_id = {r.rule_id: r for r in snap.rules}
    assert by_id["DET-001"].parameters["threshold"] == (7, 5) and by_id["DET-001"].tuned == [
        "threshold"
    ]
    assert by_id["DET-004"].enabled is False and len(snap.rules) == len(rules)
    assert len(snap.suppressions) == 1 and len(snap.audit) == 3


def test_event_ids_are_never_tunable(database, rules):
    from moesoc.storage.tuning import tunable_parameters

    for rule in rules.values():
        assert not any("event_id" in name for name in tunable_parameters(rule))
    with database.connect() as conn, pytest.raises(TuningError, match="no integer parameter"):
        TuningRepository(conn).set_rule_parameter(rules["DET-001"], "event_id", 4624, "nope!")


def test_bounds_depend_on_the_kind_of_parameter(database, rules):
    with database.connect() as conn:
        repo = TuningRepository(conn)
        with pytest.raises(TuningError, match="1,440"):
            repo.set_rule_parameter(rules["DET-001"], "window_minutes", 2000, "too long")
        with pytest.raises(TuningError, match="30"):
            repo.set_rule_parameter(rules["DET-008"], "partner_lookback_days", 90, "too long")
        repo.set_rule_parameter(rules["DET-001"], "window_minutes", 1440, "one day max")


def test_scan_lookback_follows_the_tuned_windows(rules):
    from dataclasses import replace

    from moesoc.engine.scanner import _detection_lookback, _partner_lookback

    assert _detection_lookback(rules) == timedelta(minutes=70)  # COR-003: 10 + 60
    tuned = {
        **rules,
        "COR-003": replace(
            rules["COR-003"],
            parameters={**rules["COR-003"].parameters, "follow_window_minutes": 240},
        ),
        "DET-008": replace(
            rules["DET-008"], parameters={**rules["DET-008"].parameters, "partner_lookback_days": 3}
        ),
    }
    assert _detection_lookback(tuned) == timedelta(minutes=250)
    assert _partner_lookback(tuned) == timedelta(days=3)


def test_every_integer_parameter_is_read_by_the_code(rules):
    """A tunable parameter that nothing reads would be a misleading setting."""
    from pathlib import Path

    from moesoc.storage.tuning import tunable_parameters

    package = Path(__file__).resolve().parents[1] / "moesoc"
    source = "".join(p.read_text(encoding="utf-8") for p in package.rglob("*.py"))
    assert source
    for rule in rules.values():
        for name in tunable_parameters(rule):
            assert f'"{name}"' in source, f"{rule.rule_id}.{name} is not read anywhere"
