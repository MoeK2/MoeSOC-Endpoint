"""Real-event validation, GUI part: show the REAL DET-001 / COR-001 findings in the window.

Run after scripts\\validate_real_auth.bat. It opens the validation database in
.verify-data (real events from this PC's Security log), never your normal
MoeSOC data, and changes nothing: no scan, no triage, no notes.

It checks that the GUI shows the findings, the timeline highlights exactly the
evidence events, and the drill-down lists exactly the EventRecordIDs stored in
the finding. Screenshots go to docs/screenshots/real-*.png.

    .venv\\Scripts\\python.exe scripts\\real_validation_gui.py
"""

from __future__ import annotations

import sys
import time
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from PySide6.QtWidgets import QApplication  # noqa: E402

from moesoc.core.config import AppConfig  # noqa: E402
from moesoc.engine.rules import load_rules  # noqa: E402
from moesoc.gui.main_window import MainWindow  # noqa: E402
from moesoc.gui.theme import apply_theme  # noqa: E402
from moesoc.storage.database import Database  # noqa: E402
from moesoc.storage.repository import StoredDetection  # noqa: E402
from moesoc.utils.logging import configure_logging  # noqa: E402

DATA_DIR = ROOT / ".verify-data"
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


def expected_record_ids(detection: StoredDetection) -> set[int]:
    """The EventRecordIDs the finding itself says it is based on."""
    ev = detection.evidence
    ids = {int(r) for r in ev.get("failure_record_ids", [])}
    if ev.get("success_record_id") is not None:
        ids.add(int(ev["success_record_id"]))
    session = ev.get("privileged_session")
    if isinstance(session, dict) and session.get("record_id") is not None:
        ids.add(int(session["record_id"]))  # the 4672 of the successful logon
    return ids


def latest(window: MainWindow, rule_id: str) -> StoredDetection | None:
    found = [d for d in window.detections._all if d.rule_id == rule_id]
    return max(found, key=lambda d: d.id) if found else None


def validate(app: QApplication, window: MainWindow, rule_id: str, shot_prefix: str) -> None:
    idle = lambda: not window.busy  # noqa: E731
    detection = latest(window, rule_id)
    check(detection is not None, f"{rule_id}: a real finding is listed")
    if detection is None:
        return
    expected = expected_record_ids(detection)
    print(f"      {rule_id} #{detection.id}: {detection.account}")
    print(f"      confidence: {detection.confidence}")
    print(f"      evidence records: {sorted(expected)}")

    window.select_page("Detections")
    check(window.detections.select_detection(detection.id), f"{rule_id}: finding selectable")
    detail = window.detections.detail.toPlainText()
    check(detection.rule_id in detail, f"{rule_id}: detail panel shows the finding")
    if rule_id == "COR-001":
        check("WHY CONFIDENCE IS" in detail, f"{rule_id}: detail explains the confidence")
    window.grab().save(str(SHOTS / f"{shot_prefix}-detection.png"))

    window.detections.timeline_button.click()
    check(pump(app, idle), f"{rule_id}: timeline loads")
    timeline = window.timeline._timeline
    items = timeline.items if timeline else []
    highlighted = {i.event.record_id for i in items if i.is_evidence}
    check(
        highlighted == expected,
        f"{rule_id}: timeline highlights exactly the {len(expected)} evidence records",
    )
    window.grab().save(str(SHOTS / f"{shot_prefix}-timeline.png"))

    window.select_page("Detections")
    window.detections.select_detection(detection.id)
    window.detections.evidence_button.click()
    check(pump(app, idle), f"{rule_id}: evidence drill-down loads")
    pump(app, lambda: window.events.model.rowCount() == len(expected), timeout=10)
    shown = {
        window.events.model.row_at(r).event.record_id for r in range(window.events.model.rowCount())
    }
    check(shown == expected, f"{rule_id}: drill-down lists exactly the evidence records")
    window.events.table.selectRow(0)
    pump(app, lambda: True)
    raw = window.events.raw.toPlainText()
    check("<EventRecordID>" in raw, f"{rule_id}: raw XML viewer shows the original event")
    window.grab().save(str(SHOTS / f"{shot_prefix}-evidence.png"))


def main() -> int:
    if not (DATA_DIR / "moesoc.db").exists():
        print("No validation database. Run scripts\\validate_real_auth.bat first.")
        return 2
    SHOTS.mkdir(parents=True, exist_ok=True)
    config = AppConfig(data_dir=DATA_DIR, rules_dir=ROOT / "rules")
    configure_logging(config.log_dir)

    app = QApplication(sys.argv)
    apply_theme(app)
    database = Database(config.database_path)
    database.initialize()
    window = MainWindow(config, database, load_rules(config.rules_dir))
    window.resize(1440, 900)
    window.show()

    check(pump(app, lambda: not window.busy), "startup finishes (no scan is run)")
    validate(app, window, "COR-001", "real-cor001")
    validate(app, window, "DET-001", "real-det001")

    window.close()
    print(f"\nScreenshots: {SHOTS}")
    print("REAL VALIDATION GUI:", "PASSED" if not failures else f"FAILED ({len(failures)})")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
