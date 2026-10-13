"""Targeted context for cross-source correlations, loaded by key instead of by time.

Rules read a time window of events. Some context is older or too voluminous to
load wholesale (Sysmon file and network events), so it is fetched by the exact
keys a correlation needs: the file path Defender named, then the process GUID
that wrote it. Every query is bounded by computer and time.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from datetime import timedelta

from moesoc.core.enums import DefenderEventId, SysmonEventId, TelemetrySource
from moesoc.core.event import NormalizedEvent
from moesoc.storage.repository import row_to_event, to_db_time

PROCESS_LOOKBACK = timedelta(days=7)  # a writer process may have started long before
EXECUTION_LOOKAHEAD = timedelta(days=7)
MAX_ROWS = 200  # per query; context, not bulk data


def defender_file_context(
    conn: sqlite3.Connection, events: Iterable[NormalizedEvent], window: timedelta
) -> list[NormalizedEvent]:
    """Sysmon events that explain where a Defender-detected file came from."""
    found: dict[int, NormalizedEvent] = {}

    def add(rows: Iterable[sqlite3.Row]) -> None:
        for row in rows:
            found[int(row["id"])] = row_to_event(row)

    detections = [
        e
        for e in events
        if e.source is TelemetrySource.DEFENDER
        and e.event_id == DefenderEventId.MALWARE_DETECTED
        and e.file_path
    ]
    for d in detections:
        add(
            conn.execute(
                "SELECT * FROM events WHERE file_path = ? COLLATE NOCASE AND hostname = ? "
                "AND source = ? AND event_id = ? AND timestamp >= ? AND timestamp <= ? "
                "LIMIT ?",
                (
                    d.file_path,
                    d.hostname,
                    TelemetrySource.SYSMON.value,
                    int(SysmonEventId.FILE_CREATE),
                    to_db_time(d.timestamp - window),
                    to_db_time(d.timestamp),
                    MAX_ROWS,
                ),
            )
        )
        # Was the file started as a process?
        add(
            conn.execute(
                "SELECT * FROM events WHERE process_path = ? COLLATE NOCASE AND hostname = ? "
                "AND event_id IN (?, ?) AND timestamp >= ? AND timestamp <= ? LIMIT ?",
                (
                    d.file_path,
                    d.hostname,
                    int(SysmonEventId.PROCESS_CREATE),
                    4688,
                    to_db_time(d.timestamp - window),
                    to_db_time(d.timestamp + EXECUTION_LOOKAHEAD),
                    MAX_ROWS,
                ),
            )
        )
    writers = {
        (e.process_guid, e.timestamp)
        for e in found.values()
        if e.process_guid and e.event_id == SysmonEventId.FILE_CREATE
    }
    for guid, written in writers:
        add(
            conn.execute(
                "SELECT * FROM events WHERE process_guid = ? AND source = ? "
                "AND event_id IN (?, ?, ?) AND timestamp >= ? AND timestamp <= ? LIMIT ?",
                (
                    guid,
                    TelemetrySource.SYSMON.value,
                    int(SysmonEventId.PROCESS_CREATE),
                    int(SysmonEventId.NETWORK_CONNECT),
                    int(SysmonEventId.DNS_QUERY),
                    to_db_time(written - PROCESS_LOOKBACK),
                    to_db_time(written),
                    MAX_ROWS,
                ),
            )
        )
    return list(found.values())
