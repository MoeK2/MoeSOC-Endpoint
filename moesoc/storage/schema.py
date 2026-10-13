"""Database schema and forward-only migrations.

Each migration runs once, inside a transaction, and bumps ``PRAGMA user_version``.
Migrations only ever add — they never drop tables containing user data.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable

MIGRATION_1 = """
CREATE TABLE IF NOT EXISTS events (
    id                      INTEGER PRIMARY KEY,
    hostname                TEXT    NOT NULL,
    channel                 TEXT    NOT NULL,
    record_id               INTEGER NOT NULL,
    timestamp               TEXT    NOT NULL,   -- ISO-8601 UTC, sortable
    source                  TEXT    NOT NULL,
    provider                TEXT    NOT NULL,
    event_id                INTEGER NOT NULL,
    subject_username        TEXT,
    subject_domain          TEXT,
    target_username         TEXT,
    target_domain           TEXT,
    logon_type              INTEGER,
    logon_id                TEXT,
    logon_process           TEXT,
    authentication_package  TEXT,
    workstation_name        TEXT,
    process_name            TEXT,
    process_path            TEXT,
    parent_process          TEXT,
    command_line            TEXT,
    source_ip               TEXT,
    source_port             INTEGER,
    destination_ip          TEXT,
    destination_port        INTEGER,
    file_path               TEXT,
    registry_path           TEXT,
    status                  TEXT,
    sub_status              TEXT,
    failure_reason          TEXT,
    raw_xml                 TEXT    NOT NULL,
    ingested_at             TEXT    NOT NULL,
    -- EventRecordID is per channel and per host. The timestamp is included so a
    -- record-ID reset (e.g. after log recreation) cannot silently drop new events.
    UNIQUE (hostname, channel, record_id, timestamp)
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_event_id_ts ON events (event_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_target_user ON events (target_username COLLATE NOCASE);

CREATE TABLE IF NOT EXISTS scans (
    id                INTEGER PRIMARY KEY,
    started_at        TEXT NOT NULL,
    finished_at       TEXT,
    status            TEXT NOT NULL,          -- running | completed | failed
    origin            TEXT NOT NULL,          -- live | import
    records_read      INTEGER NOT NULL DEFAULT 0,
    events_new        INTEGER NOT NULL DEFAULT 0,
    parse_failures    INTEGER NOT NULL DEFAULT 0,
    detections_new    INTEGER NOT NULL DEFAULT 0,
    message           TEXT
);

CREATE TABLE IF NOT EXISTS detections (
    id            INTEGER PRIMARY KEY,
    dedup_key     TEXT    NOT NULL UNIQUE,
    rule_id       TEXT    NOT NULL,
    kind          TEXT    NOT NULL,
    title         TEXT    NOT NULL,
    severity      TEXT    NOT NULL,
    confidence    TEXT    NOT NULL,
    risk_score    INTEGER NOT NULL,
    account       TEXT,
    first_seen    TEXT    NOT NULL,
    last_seen     TEXT    NOT NULL,
    evidence_json TEXT    NOT NULL,
    created_at    TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL,
    scan_id       INTEGER REFERENCES scans (id)
);
CREATE INDEX IF NOT EXISTS idx_detections_last_seen ON detections (last_seen);
"""

_MIGRATION_2_DDL = """
ALTER TABLE events ADD COLUMN subject_user_sid TEXT;
ALTER TABLE events ADD COLUMN target_user_sid TEXT;
ALTER TABLE events ADD COLUMN logon_guid TEXT;
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events (source_ip);
CREATE INDEX IF NOT EXISTS idx_events_host_record ON events (hostname, channel, record_id);

-- Analyst triage. Rescans update evidence only; these columns are never overwritten by a scan.
ALTER TABLE detections ADD COLUMN status TEXT NOT NULL DEFAULT 'NEW';
ALTER TABLE detections ADD COLUMN verdict TEXT;
ALTER TABLE detections ADD COLUMN resolved_at TEXT;
ALTER TABLE detections ADD COLUMN rule_version TEXT NOT NULL DEFAULT '1.0';
ALTER TABLE detections ADD COLUMN occurrence_count INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_detections_status ON detections (status);

CREATE TABLE IF NOT EXISTS detection_notes (
    id            INTEGER PRIMARY KEY,
    detection_id  INTEGER NOT NULL REFERENCES detections (id) ON DELETE CASCADE,
    created_at    TEXT    NOT NULL,
    body          TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notes_detection ON detection_notes (detection_id);

-- Audit trail of every status change (who-did-what is the local user; when + from/to).
CREATE TABLE IF NOT EXISTS detection_history (
    id            INTEGER PRIMARY KEY,
    detection_id  INTEGER NOT NULL REFERENCES detections (id) ON DELETE CASCADE,
    changed_at    TEXT    NOT NULL,
    from_status   TEXT,
    to_status     TEXT    NOT NULL
);

-- Which stored events are direct evidence for a finding.
CREATE TABLE IF NOT EXISTS detection_events (
    detection_id  INTEGER NOT NULL REFERENCES detections (id) ON DELETE CASCADE,
    event_pk      INTEGER NOT NULL REFERENCES events (id) ON DELETE CASCADE,
    PRIMARY KEY (detection_id, event_pk)
);
CREATE INDEX IF NOT EXISTS idx_detection_events_event ON detection_events (event_pk);
"""


def _run_ddl(conn: sqlite3.Connection, script: str) -> None:
    """Run DDL statement by statement inside the caller's transaction (comments stripped)."""
    ddl = "\n".join(line for line in script.splitlines() if not line.lstrip().startswith("--"))
    for statement in ddl.split(";"):
        if statement.strip():
            conn.execute(statement)


def _migration_2(conn: sqlite3.Connection) -> None:
    """Identity columns, triage model, evidence links. Keeps all existing rows."""
    _run_ddl(conn, _MIGRATION_2_DDL)

    rows = conn.execute("SELECT id, dedup_key, evidence_json FROM detections").fetchall()
    for det_id, dedup_key, evidence_json in rows:
        # v1 keys were rule|host|username|anchor. The username part is dropped because
        # identity keys changed; the anchor record ID already identifies the finding.
        parts = dedup_key.split("|")
        if len(parts) == 4:
            conn.execute(
                "UPDATE detections SET dedup_key = ? WHERE id = ?",
                ("|".join((parts[0], parts[1], parts[3])), det_id),
            )
        # Backfill evidence links from the record IDs stored in v1 evidence.
        evidence = json.loads(evidence_json)
        record_ids = list(evidence.get("failure_record_ids", []))
        if evidence.get("success_record_id") is not None:
            record_ids.append(evidence["success_record_id"])
        hostname = evidence.get("hostname")
        if hostname and record_ids:
            conn.executemany(
                "INSERT OR IGNORE INTO detection_events (detection_id, event_pk) "
                "SELECT ?, id FROM events WHERE hostname = ? AND channel = 'Security' "
                "AND record_id = ?",
                [(det_id, hostname, rid) for rid in record_ids],
            )
        conn.execute(
            "UPDATE detections SET occurrence_count = ? WHERE id = ?", (len(record_ids), det_id)
        )


_MIGRATION_3_DDL = """
-- Account management (4720, 4732), privileged sessions (4672) and process creation (4688).
ALTER TABLE events ADD COLUMN member_name TEXT;
ALTER TABLE events ADD COLUMN member_sid TEXT;
ALTER TABLE events ADD COLUMN group_name TEXT;
ALTER TABLE events ADD COLUMN group_domain TEXT;
ALTER TABLE events ADD COLUMN group_sid TEXT;
ALTER TABLE events ADD COLUMN privileges TEXT;
ALTER TABLE events ADD COLUMN process_id INTEGER;
ALTER TABLE events ADD COLUMN parent_process_id INTEGER;
ALTER TABLE events ADD COLUMN token_elevation TEXT;
ALTER TABLE events ADD COLUMN integrity_level TEXT;
-- Further source-specific fields as a JSON object (never parsed as code).
ALTER TABLE events ADD COLUMN details TEXT;
CREATE INDEX IF NOT EXISTS idx_events_target_sid ON events (target_user_sid);
CREATE INDEX IF NOT EXISTS idx_events_member_sid ON events (member_sid);
CREATE INDEX IF NOT EXISTS idx_events_logon_session ON events (hostname, logon_id);
"""


def _migration_3(conn: sqlite3.Connection) -> None:
    """New nullable event columns; existing rows keep their data (new fields are NULL)."""
    _run_ddl(conn, _MIGRATION_3_DDL)


_MIGRATION_4_DDL = """
-- Incremental collection: where each channel / event group was last read.
CREATE TABLE IF NOT EXISTS collection_state (
    channel           TEXT    NOT NULL,
    event_group       TEXT    NOT NULL,   -- core | process
    query_signature   TEXT    NOT NULL,   -- the event IDs the watermark was built for
    last_record_id    INTEGER NOT NULL,
    last_timestamp    TEXT    NOT NULL,   -- ISO-8601 UTC of that record
    updated_at        TEXT    NOT NULL,
    PRIMARY KEY (channel, event_group)
);
ALTER TABLE scans ADD COLUMN collection_mode TEXT;
"""


def _migration_4(conn: sqlite3.Connection) -> None:
    """Collection state table; a database without state simply bootstraps again."""
    _run_ddl(conn, _MIGRATION_4_DDL)


_MIGRATION_5_DDL = """
-- Sysmon: process GUIDs (stable across PID reuse) for process trees, hashes, DNS, protocol.
ALTER TABLE events ADD COLUMN process_guid TEXT;
ALTER TABLE events ADD COLUMN parent_process_guid TEXT;
ALTER TABLE events ADD COLUMN hashes TEXT;
ALTER TABLE events ADD COLUMN dns_query TEXT;
ALTER TABLE events ADD COLUMN network_protocol TEXT;
CREATE INDEX IF NOT EXISTS idx_events_process_guid ON events (process_guid);
CREATE INDEX IF NOT EXISTS idx_events_parent_guid ON events (parent_process_guid);
CREATE INDEX IF NOT EXISTS idx_events_source_ts ON events (source, timestamp);
"""


def _migration_5(conn: sqlite3.Connection) -> None:
    """Nullable Sysmon columns and indexes; existing rows keep their data."""
    _run_ddl(conn, _MIGRATION_5_DDL)


_MIGRATION_6_DDL = """
-- Cross-source correlation and pivots: file paths (case-insensitive like Windows),
-- connection destinations and DNS names.
CREATE INDEX IF NOT EXISTS idx_events_file_path ON events (file_path COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_events_destination_ip ON events (destination_ip);
CREATE INDEX IF NOT EXISTS idx_events_dns_query ON events (dns_query COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_events_process_path ON events (process_path COLLATE NOCASE);
"""


def _migration_6(conn: sqlite3.Connection) -> None:
    """Indexes only; no data changes."""
    _run_ddl(conn, _MIGRATION_6_DDL)


_MIGRATION_7_DDL = """
-- Local settings that belong with the data (e.g. the retention period).
CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
"""


def _migration_7(conn: sqlite3.Connection) -> None:
    """New table only; existing data is untouched."""
    _run_ddl(conn, _MIGRATION_7_DDL)


_MIGRATION_8_DDL = """
-- Analyst tuning. Nothing here is ever hard-deleted: removals are recorded.
CREATE TABLE IF NOT EXISTS suppressions (
    id              INTEGER PRIMARY KEY,
    rule_id         TEXT,                  -- NULL = every rule
    type            TEXT    NOT NULL,      -- account, source_ip, host, process, file_path, threat
    value           TEXT    NOT NULL,
    reason          TEXT    NOT NULL,
    created_at      TEXT    NOT NULL,
    expires_at      TEXT,                  -- NULL = until removed
    removed_at      TEXT,
    removed_reason  TEXT,
    hit_count       INTEGER NOT NULL DEFAULT 0,
    last_hit_at     TEXT
);
CREATE INDEX IF NOT EXISTS idx_suppressions_active ON suppressions (removed_at, expires_at);

CREATE TABLE IF NOT EXISTS rule_overrides (
    rule_id          TEXT PRIMARY KEY,
    enabled          INTEGER NOT NULL DEFAULT 1,
    parameters_json  TEXT    NOT NULL DEFAULT '{}',
    updated_at       TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY,
    at         TEXT NOT NULL,
    action     TEXT NOT NULL,   -- e.g. suppression.add, rule.disable, rule.parameter
    target     TEXT NOT NULL,
    details    TEXT NOT NULL,   -- JSON
    reason     TEXT
);
"""


def _migration_8(conn: sqlite3.Connection) -> None:
    """New tables only; existing data is untouched."""
    _run_ddl(conn, _MIGRATION_8_DDL)


_MIGRATION_9_DDL = """
-- Always-on sensor: which findings were already notified, so a growing finding does not
-- notify again and the state survives a service restart. Deleting a finding (retention)
-- deletes its row.
CREATE TABLE IF NOT EXISTS notification_state (
    detection_id      INTEGER PRIMARY KEY REFERENCES detections (id) ON DELETE CASCADE,
    notified_severity TEXT    NOT NULL,
    notified_risk     INTEGER NOT NULL,
    notified_rule_id  TEXT    NOT NULL,
    notified_at       TEXT    NOT NULL,
    times_notified    INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_detections_updated_at ON detections (updated_at);
"""


def _migration_9(conn: sqlite3.Connection) -> None:
    """New table and index only; existing data is untouched."""
    _run_ddl(conn, _MIGRATION_9_DDL)


Migration = str | Callable[[sqlite3.Connection], None]
MIGRATIONS: tuple[Migration, ...] = (
    MIGRATION_1,
    _migration_2,
    _migration_3,
    _migration_4,
    _migration_5,
    _migration_6,
    _migration_7,
    _migration_8,
    _migration_9,
)
SCHEMA_VERSION = len(MIGRATIONS)
