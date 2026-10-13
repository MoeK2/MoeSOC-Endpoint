"""Read model for the Overview page.

Every number the dashboard shows comes from this query against the local
database. It is plain Python so it can be tested without Qt.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from moesoc.core.enums import Severity
from moesoc.engine.risk import overall_risk
from moesoc.storage.database import Database
from moesoc.storage.repository import (
    DetectionRepository,
    EventRepository,
    ScanRecord,
    ScanRepository,
    StoredDetection,
)


@dataclass(frozen=True, slots=True)
class OverviewSnapshot:
    events_total: int
    events_by_id: dict[int, int]
    event_time_range: tuple[datetime, datetime] | None
    detections: list[StoredDetection]
    severity_counts: dict[Severity, int]  # open (not closed) findings only
    risk_score: int | None  # None when no scan has completed yet; open findings only
    last_scan: ScanRecord | None

    @property
    def has_completed_scan(self) -> bool:
        return self.last_scan is not None and self.last_scan.status == "completed"

    @property
    def open_detections(self) -> list[StoredDetection]:
        return [d for d in self.detections if not d.status.is_closed]

    @property
    def risk_driver(self) -> StoredDetection | None:
        """The open finding that sets the endpoint risk (the score is the highest one)."""
        if self.risk_score is None:
            return None
        return max(self.open_detections, key=lambda d: (d.risk_score, d.last_seen), default=None)

    def risk_explanation(self) -> str:
        if self.risk_score is None:
            return "No completed scan yet."
        driver = self.risk_driver
        if driver is None:
            return "No open findings."
        return (
            f"Highest open finding: #{driver.id} {driver.rule_id} ({driver.risk_score}/100). "
            "Prioritization only, not a probability of compromise."
        )

    @property
    def highest_severity(self) -> Severity | None:
        present = [s for s, n in self.severity_counts.items() if n]
        return max(present, key=lambda s: s.rank, default=None)


def load_overview(database: Database, detection_limit: int = 500) -> OverviewSnapshot:
    with database.connect() as conn:
        events = EventRepository(conn)
        detection_repo = DetectionRepository(conn)
        detections = detection_repo.list_all(detection_limit)
        raw_counts = detection_repo.count_by_severity(open_only=True)
        last_scan = ScanRepository(conn).last()
        any_completed = conn.execute(
            "SELECT 1 FROM scans WHERE status = 'completed' LIMIT 1"
        ).fetchone()
        snapshot = OverviewSnapshot(
            events_total=events.count(),
            events_by_id=events.count_by_event_id(),
            event_time_range=events.time_range(),
            detections=detections,
            severity_counts={s: raw_counts.get(s.value, 0) for s in Severity},
            risk_score=(
                overall_risk([d.risk_score for d in detections if not d.status.is_closed])
                if any_completed
                else None
            ),
            last_scan=last_scan,
        )
    return snapshot
