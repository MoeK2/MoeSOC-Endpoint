"""Persisted collection position per channel and event group (schema v4)."""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime

from moesoc.storage.repository import from_db_time, to_db_time
from moesoc.utils.time import utc_now

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class Watermark:
    """The newest record already collected for one channel + event group."""

    channel: str
    group: str
    signature: str  # which event IDs this position was built for
    record_id: int
    timestamp: datetime


_UPSERT_ANY = """
INSERT INTO collection_state
    (channel, event_group, query_signature, last_record_id, last_timestamp, updated_at)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (channel, event_group) DO UPDATE SET
    query_signature = excluded.query_signature,
    last_record_id = excluded.last_record_id,
    last_timestamp = excluded.last_timestamp,
    updated_at = excluded.updated_at
"""
_UPSERT_FORWARD = (
    _UPSERT_ANY.rstrip()
    + """
WHERE excluded.last_record_id > collection_state.last_record_id
   OR excluded.query_signature != collection_state.query_signature
"""
)


class CollectionStateRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def load(self, channel: str) -> dict[str, Watermark]:
        """Watermarks by group. Unreadable rows are skipped (the group bootstraps again)."""
        rows = self._conn.execute(
            "SELECT event_group, query_signature, last_record_id, last_timestamp "
            "FROM collection_state WHERE channel = ?",
            (channel,),
        ).fetchall()
        marks: dict[str, Watermark] = {}
        for group, signature, record_id, timestamp in rows:
            try:
                marks[group] = Watermark(
                    channel, group, str(signature), int(record_id), from_db_time(timestamp)
                )
            except (TypeError, ValueError):
                log.warning("Ignoring unreadable collection state for %s/%s", channel, group)
        return marks

    def save(self, mark: Watermark, *, allow_backward: bool = False) -> None:
        """Store a position. By default it only moves forward, so two writers (a scan and
        live monitoring) can never move it back; a bootstrap or recovery after a log
        reset passes ``allow_backward`` because record IDs may have restarted."""
        sql = _UPSERT_ANY if allow_backward else _UPSERT_FORWARD
        self._conn.execute(
            sql,
            (
                mark.channel,
                mark.group,
                mark.signature,
                mark.record_id,
                to_db_time(mark.timestamp),
                to_db_time(utc_now()),
            ),
        )

    def clear(self, channel: str | None = None) -> None:
        """Forget positions (the next scan bootstraps). Never touches events or findings."""
        if channel is None:
            self._conn.execute("DELETE FROM collection_state")
        else:
            self._conn.execute("DELETE FROM collection_state WHERE channel = ?", (channel,))
