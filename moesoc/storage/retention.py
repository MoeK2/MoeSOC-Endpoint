"""Retention: delete old MoeSOC data from the local database, never Windows logs.

This module only runs SQL against MoeSOC's own SQLite file. It does not import or
call any Windows event-log API, so it cannot clear, trim or modify a Windows log.

What is deleted (older than the cutoff):
- stored events, unless they are evidence for a finding that is still open;
- closed findings (TP / FP / Benign / Resolved) whose last activity is older than
  the cutoff, with their notes, status history and evidence links;
- scan records no remaining finding refers to (the latest scan is always kept).

What is kept: open findings and all their evidence (an open investigation never loses
data to retention), collection positions (watermarks), settings.

Nothing is deleted without an explicit confirmation by the caller; ``plan_retention``
only counts.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta

from moesoc.core.exceptions import MoeSOCError
from moesoc.storage.repository import to_db_time
from moesoc.utils.time import utc_now

ALLOWED_DAYS = (7, 30, 90)
DEFAULT_DAYS = 30
SETTING_KEY = "retention_days"

# Closed statuses are written out so every statement is built from module constants;
# no value is ever formatted into SQL (all values are bound parameters). A test
# checks that this list matches CLOSED_STATUSES.
CLOSED_SQL = "('BENIGN', 'FALSE_POSITIVE', 'RESOLVED', 'TRUE_POSITIVE')"
_OLD_CLOSED = (
    "status IN ('BENIGN', 'FALSE_POSITIVE', 'RESOLVED', 'TRUE_POSITIVE') AND last_seen < ?"
)

SQL_COUNT_OLD_EVENTS = "SELECT COUNT(*) FROM events WHERE timestamp < ?"
# Events that must survive: evidence of a finding that remains after retention.
_PROTECTED = (
    "SELECT de.event_pk FROM detection_events de JOIN detections d ON d.id = de.detection_id "
    "WHERE NOT (d.status IN ('BENIGN', 'FALSE_POSITIVE', 'RESOLVED', 'TRUE_POSITIVE') "
    "AND d.last_seen < ?)"
)
SQL_COUNT_KEPT_EVENTS = (
    "SELECT COUNT(*) FROM events WHERE timestamp < ? AND id IN (" + _PROTECTED + ")"  # noqa: S608
)
SQL_DELETE_EVENTS = (
    "DELETE FROM events WHERE timestamp < ? AND id NOT IN (" + _PROTECTED + ")"  # noqa: S608
)
SQL_COUNT_FINDINGS = "SELECT COUNT(*) FROM detections WHERE " + _OLD_CLOSED  # noqa: S608
SQL_DELETE_FINDINGS = "DELETE FROM detections WHERE " + _OLD_CLOSED  # noqa: S608
SQL_COUNT_OPEN_KEPT = (
    "SELECT COUNT(*) FROM detections WHERE status NOT IN "
    "('BENIGN', 'FALSE_POSITIVE', 'RESOLVED', 'TRUE_POSITIVE') AND last_seen < ?"
)
_OLD_SCANS = (
    "WHERE started_at < ? AND id != (SELECT MAX(id) FROM scans) "
    "AND id NOT IN (SELECT scan_id FROM detections WHERE scan_id IS NOT NULL "
    "AND NOT (status IN ('BENIGN', 'FALSE_POSITIVE', 'RESOLVED', 'TRUE_POSITIVE') "
    "AND last_seen < ?))"
)
SQL_COUNT_SCANS = "SELECT COUNT(*) FROM scans " + _OLD_SCANS  # noqa: S608
SQL_DELETE_SCANS = "DELETE FROM scans " + _OLD_SCANS  # noqa: S608


@dataclass(frozen=True, slots=True)
class RetentionPlan:
    days: int
    cutoff: datetime
    events: int  # events that will be deleted
    events_kept_as_evidence: int  # older than the cutoff but kept for remaining findings
    findings: int  # closed findings that will be deleted
    open_findings_kept: int  # older than the cutoff but still open: kept
    scans: int

    @property
    def nothing_to_do(self) -> bool:
        return not (self.events or self.findings or self.scans)

    def describe(self) -> str:
        return (
            f"Delete MoeSOC data older than {self.days} days "
            f"(before {self.cutoff.strftime('%Y-%m-%d %H:%M')} UTC): "
            f"{self.events:,} stored events, {self.findings:,} closed findings and "
            f"{self.scans:,} scan records. Kept: {self.events_kept_as_evidence:,} old events "
            f"that are evidence for remaining findings, {self.open_findings_kept:,} open "
            "findings. Windows event logs are not touched."
        )


def validate_days(days: int) -> int:
    if days not in ALLOWED_DAYS:
        raise MoeSOCError(f"Retention must be one of {', '.join(map(str, ALLOWED_DAYS))} days.")
    return days


def get_retention_days(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (SETTING_KEY,)).fetchone()
    try:
        days = int(row[0]) if row else DEFAULT_DAYS
    except ValueError:
        return DEFAULT_DAYS
    return days if days in ALLOWED_DAYS else DEFAULT_DAYS


def set_retention_days(conn: sqlite3.Connection, days: int) -> None:
    conn.execute(
        "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        (SETTING_KEY, str(validate_days(days)), to_db_time(utc_now())),
    )


def plan_retention(
    conn: sqlite3.Connection, days: int, now: datetime | None = None
) -> RetentionPlan:
    """Count what ``apply_retention`` would delete. Changes nothing."""
    cutoff_dt = (now or utc_now()) - timedelta(days=validate_days(days))
    cutoff = to_db_time(cutoff_dt)
    old_events = conn.execute(SQL_COUNT_OLD_EVENTS, (cutoff,)).fetchone()[0]
    kept = conn.execute(SQL_COUNT_KEPT_EVENTS, (cutoff, cutoff)).fetchone()[0]
    return RetentionPlan(
        days=days,
        cutoff=cutoff_dt,
        events=old_events - kept,
        events_kept_as_evidence=kept,
        findings=conn.execute(SQL_COUNT_FINDINGS, (cutoff,)).fetchone()[0],
        open_findings_kept=conn.execute(SQL_COUNT_OPEN_KEPT, (cutoff,)).fetchone()[0],
        scans=conn.execute(SQL_COUNT_SCANS, (cutoff, cutoff)).fetchone()[0],
    )


def apply_retention(
    conn: sqlite3.Connection, days: int, *, confirmed: bool, now: datetime | None = None
) -> RetentionPlan:
    """Delete old MoeSOC data in one transaction. Requires ``confirmed=True``."""
    if not confirmed:
        raise MoeSOCError("Retention deletes data; it runs only after confirmation.")
    plan = plan_retention(conn, days, now)
    cutoff = to_db_time(plan.cutoff)
    # Findings first (their notes, history and evidence links cascade), so their
    # evidence events are no longer protected; then events; then unused scan records.
    findings = conn.execute(SQL_DELETE_FINDINGS, (cutoff,)).rowcount
    events = conn.execute(SQL_DELETE_EVENTS, (cutoff, cutoff)).rowcount
    scans = conn.execute(SQL_DELETE_SCANS, (cutoff, cutoff)).rowcount
    return RetentionPlan(
        days=days,
        cutoff=plan.cutoff,
        events=events,
        events_kept_as_evidence=plan.events_kept_as_evidence,
        findings=findings,
        open_findings_kept=plan.open_findings_kept,
        scans=scans,
    )
