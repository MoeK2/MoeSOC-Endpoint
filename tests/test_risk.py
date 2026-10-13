"""Explainable risk: one base + documented modifiers for every finding."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

from moesoc.core.enums import Confidence, Severity
from moesoc.engine.risk import MAX_RISK, assess_risk
from moesoc.engine.scanner import run_detections
from moesoc.storage.overview import load_overview
from moesoc.storage.repository import DetectionRepository, ScanRepository

from .conftest import BASE_TIME, auth_event, failures
from .test_cross_source import download_chain
from .test_defender import detected, quarantined


def base_finding(rules, **evidence):
    (finding,) = run_detections([detected()], rules)[:1]
    finding = replace(finding, evidence={"hostname": "H", **evidence})
    return finding


def points(finding):
    return [(f["points"], f["reason"]) for f in finding.evidence["risk_factors"]]


def test_every_finding_from_a_run_explains_its_risk(rules):
    events = [
        *failures("alice", 6, BASE_TIME, timedelta(seconds=10)),
        auth_event(4624, "alice", BASE_TIME + timedelta(minutes=1), 2000),
    ]
    findings = run_detections(events, rules)
    assert findings
    for f in findings:
        factors = f.evidence["risk_factors"]
        assert factors[0]["reason"].startswith("Base: ")
        assert f.risk_score == max(0, min(MAX_RISK, sum(x["points"] for x in factors)))


def test_low_confidence_lowers_priority(rules):
    finding = replace(
        base_finding(rules), derived_confidence=Confidence.LOW, derived_severity=Severity.HIGH
    )
    assessed = assess_risk(finding)
    assert assessed.risk_score == 60
    assert (-10, "Low confidence: the evidence also fits benign activity") in points(assessed)


def test_defender_remediation_moves_the_score_both_ways(rules):
    (pending,) = [f for f in run_detections([detected()], rules) if f.rule_id == "DET-008"]
    (done,) = [
        f for f in run_detections([detected(), quarantined()], rules) if f.rule_id == "DET-008"
    ]
    assert pending.risk_score == 70  # HIGH, no remediation recorded yet
    assert done.risk_score == 55  # HIGH - 15: Defender reports it remediated
    failed = assess_risk(
        replace(
            base_finding(rules, remediation={"state": "action failed"}),
            derived_severity=Severity.HIGH,
        )
    )
    assert failed.risk_score == 80


def test_execution_and_corroboration_raise_the_score(rules):
    chain = [{"log": "sysmon"}, {"log": "defender"}]
    finding = replace(
        base_finding(rules, executed=True, chain=chain), derived_severity=Severity.HIGH
    )
    assessed = assess_risk(finding)
    assert assessed.risk_score == 70 + 10 + 5
    assert any(r.startswith("Corroborated by 2 logs") for _p, r in points(assessed))


def test_score_is_capped_and_the_cap_is_explained(rules):
    finding = replace(
        base_finding(
            rules,
            executed=True,
            privileged_session={"x": 1},
            remediation={"state": "allowed"},
            chain=[{"log": "a"}, {"log": "b"}],
        ),
        derived_severity=Severity.CRITICAL,
    )
    assessed = assess_risk(finding)
    assert assessed.risk_score == MAX_RISK
    assert points(assessed)[-1] == (100 - (90 + 10 + 10 + 10 + 5), "Limited to the 0-100 range")


def test_cor004_chain_counts_as_corroboration(rules):
    (cor,) = [f for f in run_detections(download_chain(), rules) if f.rule_id == "COR-004"]
    assert any("Corroborated by 2 logs (defender, sysmon)" in r for _p, r in points(cor))


def test_overview_names_the_finding_that_drives_endpoint_risk(database, rules):
    with database.connect() as conn:
        scans = ScanRepository(conn)
        scan_id = scans.start("import")
        scans.finish(scan_id, status="completed")
        repo = DetectionRepository(conn)
        for f in run_detections([detected(), quarantined()], rules):
            repo.upsert(f, scan_id)
    snap = load_overview(database)
    driver = snap.risk_driver
    assert driver is not None and snap.risk_score == driver.risk_score
    assert f"#{driver.id} {driver.rule_id}" in snap.risk_explanation()
    assert "not a probability" in snap.risk_explanation()


# ------------------------------------------------------------------ audit A-8
def test_failed_remediation_is_counted_once_not_in_severity_and_modifier(rules):
    from .test_defender import event

    failed = event(1118, at=detected().timestamp + timedelta(seconds=5), Error_Code="0x80508023")
    (raised,) = [
        f
        for f in run_detections([detected(Severity_Name="Moderate"), failed], rules)
        if f.rule_id == "DET-008"
    ]
    # Moderate -> raised to HIGH because remediation failed; no extra +10 for the same fact.
    assert raised.severity is Severity.HIGH and raised.risk_score == 70
    assert raised.evidence["severity_raised_for"] == ["remediation"]
    (severe,) = [f for f in run_detections([detected(), failed], rules) if f.rule_id == "DET-008"]
    # Already HIGH from Defender's own severity: the failure is counted once, as a modifier.
    assert severe.risk_score == 80 and severe.evidence["severity_raised_for"] == []


def test_weak_user_and_time_links_do_not_earn_the_corroboration_bonus(rules):
    weak_only = base_finding(
        rules,
        chain=[
            {"log": "security", "link": None},
            {"log": "defender", "link": "user_time"},
        ],
    )
    assert not any("Corroborated" in reason for _p, reason in points(assess_risk(weak_only)))
    strong = base_finding(
        rules,
        chain=[{"log": "security", "link": None}, {"log": "sysmon", "link": "logon_id"}],
    )
    assert (5, "Corroborated by 2 logs (security, sysmon)") in points(assess_risk(strong))


# ------------------------------------------------------------------ audit A-7
def test_old_scores_are_kept_and_explained_not_rewritten():
    from moesoc.engine.risk import current_model_score, stored_risk_note

    # A COR-001 finding stored by rule v2.0, before the risk model: HIGH/LOW, risk 70.
    evidence = {"hostname": "H"}
    assert current_model_score("HIGH", "LOW", evidence) == 60
    note = stored_risk_note("HIGH", "LOW", evidence, 70)
    assert "Risk at detection time: 70/100" in note and "would score 60/100" in note
    # Scored by the current model: nothing to explain.
    current = {"hostname": "H", "risk_factors": [{"points": 70, "reason": "Base"}]}
    assert stored_risk_note("HIGH", "HIGH", current, 70) is None
    assert "would score 70/100" in stored_risk_note("HIGH", "HIGH", current, 80)


def test_cli_show_explains_a_historical_score(capsys, config, database):
    import json

    from moesoc.cli import main

    with database.connect() as conn:
        conn.execute(
            "INSERT INTO detections (dedup_key, rule_id, rule_version, kind, title, severity, "
            "confidence, risk_score, account, first_seen, last_seen, evidence_json, created_at, "
            "updated_at, status, occurrence_count) VALUES ('COR-001|H|1', 'COR-001', '2.0', "
            "'correlation', 'Possible Account Compromise', 'HIGH', 'LOW', 70, 'H\\\\u', "
            "'2026-10-07T15:01:34+00:00', '2026-10-07T15:02:03+00:00', ?, "
            "'2026-10-07T15:03:00+00:00', '2026-10-07T15:03:00+00:00', 'NEW', 8)",
            (json.dumps({"hostname": "H"}),),
        )
        detection_id = conn.execute("SELECT id FROM detections").fetchone()[0]
    capsys.readouterr()
    assert main(["--data-dir", str(config.data_dir), "show", str(detection_id)]) == 0
    out = capsys.readouterr().out
    assert "Risk 70/100" in out and "The current model would score 60/100" in out
    with database.connect() as conn:  # the stored score itself is untouched
        assert conn.execute("SELECT risk_score FROM detections").fetchone()[0] == 70
