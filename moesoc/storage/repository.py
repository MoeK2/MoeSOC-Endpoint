"""Data access. All SQL is parameterized; callers never build SQL from data."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, fields
from datetime import UTC, datetime
from typing import Any

from moesoc.core.detection import Detection
from moesoc.core.enums import CLOSED_STATUSES, VERDICT_STATUSES, TelemetrySource, TriageStatus
from moesoc.core.event import NormalizedEvent
from moesoc.core.exceptions import MoeSOCError
from moesoc.utils.time import utc_now


def to_db_time(ts: datetime) -> str:
    """Fixed-width UTC ISO string so lexical order equals chronological order."""
    return ts.astimezone(UTC).isoformat(timespec="microseconds")


def from_db_time(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _like_prefix(prefix: str) -> str:
    """A LIKE pattern matching ``prefix`` literally (host names may contain _ or %)."""
    escaped = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return escaped + "%"


_EVENT_COLUMNS: tuple[str, ...] = tuple(f.name for f in fields(NormalizedEvent))
# Column names come from the dataclass definition, never from event data.
_COLUMN_LIST = ", ".join(_EVENT_COLUMNS)
_PLACEHOLDERS = ", ".join("?" for _ in _EVENT_COLUMNS)
_INSERT_EVENT_SQL = (
    f"INSERT OR IGNORE INTO events ({_COLUMN_LIST}, ingested_at) VALUES ({_PLACEHOLDERS}, ?)"  # noqa: S608
)


def _event_row(event: NormalizedEvent, ingested_at: str) -> tuple[Any, ...]:
    values: list[Any] = []
    for name in _EVENT_COLUMNS:
        value = getattr(event, name)
        if isinstance(value, datetime):
            value = to_db_time(value)
        values.append(value)
    values.append(ingested_at)
    return tuple(values)


def row_to_event(row: sqlite3.Row) -> NormalizedEvent:
    kwargs = {name: row[name] for name in _EVENT_COLUMNS}
    kwargs["timestamp"] = from_db_time(kwargs["timestamp"])
    kwargs["source"] = TelemetrySource(kwargs["source"])
    return NormalizedEvent(**kwargs)


class EventRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def insert_many(self, events: Iterable[NormalizedEvent]) -> int:
        """Insert events, ignoring ones already stored. Returns the number newly stored."""
        ingested_at = to_db_time(utc_now())
        before = self._conn.total_changes
        self._conn.executemany(_INSERT_EVENT_SQL, (_event_row(e, ingested_at) for e in events))
        return self._conn.total_changes - before

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def count_by_event_id(self) -> dict[int, int]:
        rows = self._conn.execute("SELECT event_id, COUNT(*) FROM events GROUP BY event_id")
        return {row[0]: row[1] for row in rows}

    def time_range(self) -> tuple[datetime, datetime] | None:
        row = self._conn.execute("SELECT MIN(timestamp), MAX(timestamp) FROM events").fetchone()
        if row[0] is None:
            return None
        return from_db_time(row[0]), from_db_time(row[1])

    def in_range(
        self, start: datetime, end: datetime, event_ids: Sequence[int]
    ) -> list[NormalizedEvent]:
        placeholders = ", ".join("?" for _ in event_ids)
        rows = self._conn.execute(
            f"SELECT * FROM events WHERE timestamp >= ? AND timestamp <= ? "  # noqa: S608 - placeholders only
            f"AND event_id IN ({placeholders}) ORDER BY timestamp, record_id",
            (to_db_time(start), to_db_time(end), *event_ids),
        )
        return [row_to_event(r) for r in rows]

    def recent(self, limit: int, event_ids: Sequence[int] | None = None) -> list[NormalizedEvent]:
        if event_ids:
            placeholders = ", ".join("?" for _ in event_ids)
            rows = self._conn.execute(
                f"SELECT * FROM events WHERE event_id IN ({placeholders}) "  # noqa: S608
                "ORDER BY timestamp DESC LIMIT ?",
                (*event_ids, limit),
            )
        else:
            rows = self._conn.execute(
                "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
            )
        return [row_to_event(r) for r in rows]


@dataclass(frozen=True, slots=True)
class StoredDetection:
    """A detection as read back from the database for display."""

    id: int
    rule_id: str
    rule_version: str
    kind: str
    title: str
    severity: str
    confidence: str
    risk_score: int
    account: str | None
    first_seen: datetime
    last_seen: datetime
    evidence: dict[str, Any]
    created_at: datetime
    updated_at: datetime
    status: TriageStatus
    verdict: str | None
    resolved_at: datetime | None
    occurrence_count: int


@dataclass(frozen=True, slots=True)
class AnalystNote:
    id: int
    created_at: datetime
    body: str


@dataclass(frozen=True, slots=True)
class StatusChange:
    changed_at: datetime
    from_status: str | None
    to_status: str


MAX_NOTE_LENGTH = 10_000


def _row_to_detection(r: sqlite3.Row) -> StoredDetection:
    return StoredDetection(
        id=r["id"],
        rule_id=r["rule_id"],
        rule_version=r["rule_version"],
        kind=r["kind"],
        title=r["title"],
        severity=r["severity"],
        confidence=r["confidence"],
        risk_score=r["risk_score"],
        account=r["account"],
        first_seen=from_db_time(r["first_seen"]),
        last_seen=from_db_time(r["last_seen"]),
        evidence=json.loads(r["evidence_json"]),
        created_at=from_db_time(r["created_at"]),
        updated_at=from_db_time(r["updated_at"]),
        status=TriageStatus(r["status"]),
        verdict=r["verdict"],
        resolved_at=from_db_time(r["resolved_at"]) if r["resolved_at"] else None,
        occurrence_count=r["occurrence_count"],
    )


class DetectionRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    # ------------------------------------------------------------- scan side
    def upsert(self, detection: Detection, scan_id: int | None) -> bool:
        """Store a finding. Returns True if it is new.

        - New finding: inserted with status NEW and linked to its evidence events.
        - Same finding (same dedup key, or the same campaign of a burst rule, see
          ``find_campaign``), same rule version: the stored finding is EXTENDED. First
          seen keeps the earliest time, last seen the newest, evidence links are the union
          (each event once), and evidence, severity, confidence and risk are refreshed
          (e.g. a burst that grew). Analyst status, verdict, notes and history are never
          touched by a scan.
        - Same finding, different rule version: left exactly as it was generated, so
          old findings are never silently reinterpreted by new rule logic.
        """
        now = to_db_time(utc_now())
        existing = self._conn.execute(
            "SELECT id, rule_version, first_seen, last_seen FROM detections WHERE dedup_key = ?",
            (detection.dedup_key,),
        ).fetchone()
        if existing is None:
            existing = self.find_campaign(detection)
        evidence_json = json.dumps(detection.evidence, default=str)

        if existing is None:
            cursor = self._conn.execute(
                """
                INSERT INTO detections (dedup_key, rule_id, rule_version, kind, title, severity,
                    confidence, risk_score, account, first_seen, last_seen, evidence_json,
                    created_at, updated_at, scan_id, status, occurrence_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'NEW', ?)
                """,
                (
                    detection.dedup_key,
                    detection.rule_id,
                    detection.rule_version,
                    detection.rule.kind.value,
                    detection.rule.title,
                    detection.severity.value,
                    detection.confidence.value,
                    detection.risk_score,
                    detection.account,
                    to_db_time(detection.first_seen),
                    to_db_time(detection.last_seen),
                    evidence_json,
                    now,
                    now,
                    scan_id,
                    len(detection.related_record_ids),
                ),
            )
            detection_id = int(cursor.lastrowid or 0)
            self._conn.execute(
                "INSERT INTO detection_history (detection_id, changed_at, from_status, to_status) "
                "VALUES (?, ?, NULL, 'NEW')",
                (detection_id, now),
            )
            self._link_evidence(detection_id, detection)
            return True

        detection_id, stored_version, stored_first, stored_last = existing
        if stored_version != detection.rule_version:
            return False  # generated by another rule version: preserved as-is
        self._link_evidence(detection_id, detection)
        linked = self._conn.execute(
            "SELECT COUNT(*) FROM detection_events WHERE detection_id = ?", (detection_id,)
        ).fetchone()[0]
        self._conn.execute(
            """UPDATE detections SET first_seen = ?, last_seen = ?, risk_score = ?, severity = ?,
                   confidence = ?, evidence_json = ?, account = ?, occurrence_count = ?,
                   updated_at = ?
               WHERE id = ?""",
            (
                min(stored_first, to_db_time(detection.first_seen)),
                max(stored_last, to_db_time(detection.last_seen)),
                detection.risk_score,
                detection.severity.value,
                detection.confidence.value,
                evidence_json,
                detection.account,
                max(linked, len(detection.related_record_ids)),
                now,
                detection_id,
            ),
        )
        return False

    def find_campaign(self, detection: Detection) -> tuple[Any, ...] | None:
        """The stored finding that ``detection`` continues, if any.

        A burst rule's finding is anchored at the first record it saw. When that anchor
        moves (a live batch reloads only the rule window, or an older event arrives late),
        the dedup key changes although the campaign is the same. A stored finding continues
        the campaign when it has the same rule and version, the same computer, the same
        campaign key (identity or source, and mode) and its time range overlaps the new
        burst or is at most ``campaign_gap`` (the rule's own window) away from it. A longer
        quiet gap starts a new campaign and a new finding.
        """
        if detection.campaign_key is None or detection.campaign_gap is None:
            return None
        host = detection.dedup_key.split("|")[1]
        gap = detection.campaign_gap
        lo = to_db_time(detection.first_seen - gap)
        hi = to_db_time(detection.last_seen + gap)
        rows = self._conn.execute(
            "SELECT id, rule_version, first_seen, last_seen, evidence_json FROM detections "
            "WHERE rule_id = ? AND rule_version = ? AND dedup_key LIKE ? ESCAPE '\\' "
            "AND last_seen >= ? AND first_seen <= ? ORDER BY last_seen DESC",
            (
                detection.rule_id,
                detection.rule_version,
                _like_prefix(f"{detection.rule_id}|{host}|"),
                lo,
                hi,
            ),
        ).fetchall()
        for row in rows:
            try:
                campaign = json.loads(row[4] or "{}").get("campaign") or {}
            except ValueError:
                continue
            if campaign.get("key") == detection.campaign_key:
                return tuple(row[:4])
        return None

    def campaign_reload_start(self, since: datetime, limit: datetime) -> datetime | None:
        """Earliest first-seen of burst-rule findings still active after ``since``.

        Detection reloads stored events from here, so a campaign that has lasted longer than
        the rule window is evaluated as a whole (complete evidence, stable anchor). Never
        earlier than ``limit``.
        """
        row = self._conn.execute(
            "SELECT MIN(first_seen) FROM detections WHERE last_seen >= ? "
            "AND instr(evidence_json, '\"campaign\": {') > 0",
            (to_db_time(since),),
        ).fetchone()
        if not row or row[0] is None:
            return None
        return max(from_db_time(row[0]), limit)

    def _link_evidence(self, detection_id: int, detection: Detection) -> None:
        self._conn.executemany(
            "INSERT OR IGNORE INTO detection_events (detection_id, event_pk) "
            "SELECT ?, id FROM events WHERE hostname = ? AND channel = ? AND record_id = ?",
            [(detection_id, r.hostname, r.channel, r.record_id) for r in detection.evidence_refs],
        )

    # ------------------------------------------------------------- read side
    def list_all(self, limit: int = 500) -> list[StoredDetection]:
        rows = self._conn.execute(
            "SELECT * FROM detections ORDER BY last_seen DESC LIMIT ?", (limit,)
        )
        return [_row_to_detection(r) for r in rows]

    def get(self, detection_id: int) -> StoredDetection | None:
        row = self._conn.execute(
            "SELECT * FROM detections WHERE id = ?", (detection_id,)
        ).fetchone()
        return _row_to_detection(row) if row else None

    def evidence_event_pks(self, detection_id: int) -> list[int]:
        rows = self._conn.execute(
            "SELECT event_pk FROM detection_events WHERE detection_id = ?", (detection_id,)
        )
        return [r[0] for r in rows]

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]

    def count_by_severity(self, *, open_only: bool = False) -> dict[str, int]:
        where = " WHERE status NOT IN (?, ?, ?, ?)" if open_only else ""
        params = tuple(sorted(CLOSED_STATUSES)) if open_only else ()
        rows = self._conn.execute(
            f"SELECT severity, COUNT(*) FROM detections{where} GROUP BY severity",  # noqa: S608
            params,
        )
        return {row[0]: row[1] for row in rows}

    # ------------------------------------------------------------- analyst side
    def set_status(self, detection_id: int, status: TriageStatus) -> StoredDetection:
        """Change triage status, recording the change in the audit history.

        TRUE_POSITIVE / FALSE_POSITIVE / BENIGN also record the verdict. Any closed
        status sets resolved_at; reopening (NEW / INVESTIGATING) clears it but keeps
        the last verdict for reference.
        """
        current = self.get(detection_id)
        if current is None:
            raise MoeSOCError(f"Detection #{detection_id} does not exist.")
        if current.status is status:
            return current
        now = to_db_time(utc_now())
        verdict = status.value if status.value in VERDICT_STATUSES else current.verdict
        resolved_at = now if status.is_closed else None
        self._conn.execute(
            "UPDATE detections SET status = ?, verdict = ?, resolved_at = ?, updated_at = ? "
            "WHERE id = ?",
            (status.value, verdict, resolved_at, now, detection_id),
        )
        self._conn.execute(
            "INSERT INTO detection_history (detection_id, changed_at, from_status, to_status) "
            "VALUES (?, ?, ?, ?)",
            (detection_id, now, current.status.value, status.value),
        )
        updated = self.get(detection_id)
        if updated is None:
            raise MoeSOCError(f"Detection #{detection_id} disappeared during the update.")
        return updated

    def add_note(self, detection_id: int, body: str) -> AnalystNote:
        text = body.strip()
        if not text:
            raise MoeSOCError("An analyst note cannot be empty.")
        if len(text) > MAX_NOTE_LENGTH:
            raise MoeSOCError(f"An analyst note is limited to {MAX_NOTE_LENGTH:,} characters.")
        if self.get(detection_id) is None:
            raise MoeSOCError(f"Detection #{detection_id} does not exist.")
        now = to_db_time(utc_now())
        cursor = self._conn.execute(
            "INSERT INTO detection_notes (detection_id, created_at, body) VALUES (?, ?, ?)",
            (detection_id, now, text),
        )
        self._conn.execute("UPDATE detections SET updated_at = ? WHERE id = ?", (now, detection_id))
        return AnalystNote(int(cursor.lastrowid or 0), from_db_time(now), text)

    def notes(self, detection_id: int) -> list[AnalystNote]:
        rows = self._conn.execute(
            "SELECT id, created_at, body FROM detection_notes WHERE detection_id = ? "
            "ORDER BY created_at, id",
            (detection_id,),
        )
        return [AnalystNote(r[0], from_db_time(r[1]), r[2]) for r in rows]

    def all_notes(self) -> dict[int, list[AnalystNote]]:
        """Notes for every finding, grouped by detection id (one query)."""
        grouped: dict[int, list[AnalystNote]] = {}
        rows = self._conn.execute(
            "SELECT detection_id, id, created_at, body FROM detection_notes ORDER BY created_at, id"
        )
        for r in rows:
            grouped.setdefault(r[0], []).append(AnalystNote(r[1], from_db_time(r[2]), r[3]))
        return grouped

    def history(self, detection_id: int) -> list[StatusChange]:
        rows = self._conn.execute(
            "SELECT changed_at, from_status, to_status FROM detection_history "
            "WHERE detection_id = ? ORDER BY changed_at, id",
            (detection_id,),
        )
        return [StatusChange(from_db_time(r[0]), r[1], r[2]) for r in rows]


@dataclass(frozen=True, slots=True)
class ScanRecord:
    id: int
    started_at: datetime
    finished_at: datetime | None
    status: str
    origin: str
    records_read: int
    events_new: int
    parse_failures: int
    detections_new: int
    message: str | None
    collection_mode: str | None = None


class ScanRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def start(self, origin: str) -> int:
        cursor = self._conn.execute(
            "INSERT INTO scans (started_at, status, origin) VALUES (?, 'running', ?)",
            (to_db_time(utc_now()), origin),
        )
        return int(cursor.lastrowid or 0)

    def finish(
        self,
        scan_id: int,
        *,
        status: str,
        records_read: int = 0,
        events_new: int = 0,
        parse_failures: int = 0,
        detections_new: int = 0,
        message: str | None = None,
        collection_mode: str | None = None,
    ) -> None:
        self._conn.execute(
            """UPDATE scans SET finished_at = ?, status = ?, records_read = ?, events_new = ?,
                   parse_failures = ?, detections_new = ?, message = ?, collection_mode = ?
               WHERE id = ?""",
            (
                to_db_time(utc_now()),
                status,
                records_read,
                events_new,
                parse_failures,
                detections_new,
                message,
                collection_mode,
                scan_id,
            ),
        )

    def last(self) -> ScanRecord | None:
        row = self._conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        if row is None:
            return None
        return ScanRecord(
            id=row["id"],
            started_at=from_db_time(row["started_at"]),
            finished_at=from_db_time(row["finished_at"]) if row["finished_at"] else None,
            status=row["status"],
            origin=row["origin"],
            records_read=row["records_read"],
            events_new=row["events_new"],
            parse_failures=row["parse_failures"],
            detections_new=row["detections_new"],
            message=row["message"],
            collection_mode=row["collection_mode"],
        )
