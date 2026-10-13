"""Database-side event search: composable filters, pagination, investigation timelines.

Every filter becomes a parameterized SQL condition; nothing is filtered in Python
after loading, so large databases stay responsive. Text matching uses SQLite LIKE,
which is case-insensitive for ASCII letters only (a documented limitation).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any

from moesoc.core.enums import (
    LOGON_FAILURE_REASONS,
    DefenderEventId,
    SecurityEventId,
    SysmonEventId,
    TelemetrySource,
)
from moesoc.core.event import NormalizedEvent
from moesoc.core.exceptions import MoeSOCError
from moesoc.parsers.security import normalize_ip
from moesoc.storage.repository import DetectionRepository, StoredDetection, row_to_event, to_db_time

DEFAULT_PAGE_SIZE = 500
MAX_PAGE_SIZE = 5_000
TIMELINE_PADDING = timedelta(minutes=15)
TIMELINE_LIMIT = 1_000

# Fields searched by the free-text filter (normalized fields; raw XML is not scanned).
_TEXT_COLUMNS = (
    "target_username",
    "target_domain",
    "subject_username",
    "source_ip",
    "workstation_name",
    "process_name",
    "process_path",
    "command_line",
    "parent_process",
    "file_path",
    "registry_path",
    "dns_query",
    "group_name",
    "failure_reason",
    "authentication_package",
)


@dataclass(frozen=True, slots=True)
class EventFilter:
    """All conditions are ANDed. Empty values mean "no condition"."""

    start: datetime | None = None
    end: datetime | None = None
    event_ids: tuple[int, ...] = ()
    sources: tuple[str, ...] = ()
    channels: tuple[str, ...] = ()
    hostname: str | None = None
    username: str | None = None  # contains, target or subject account
    domain: str | None = None  # exact (case-insensitive), target or subject domain
    sid: str | None = None  # exact, target or subject SID
    ip: str | None = None  # exact address, or a prefix such as "192.168."
    logon_type: int | None = None
    process: str | None = None  # contains, process name or path
    parent_process: str | None = None  # contains, parent image path
    provider: str | None = None  # contains, event provider
    port: int | None = None  # exact, source or destination port
    file_path: str | None = None  # contains, file path (Sysmon 11, Defender, 4104 script path)
    registry_path: str | None = None  # contains, registry key/value path (Sysmon 13)
    dns_query: str | None = None  # contains, queried name (Sysmon 22)
    threat: str | None = None  # contains, Microsoft Defender threat name (1116-1119)
    logon_id: str | None = None  # exact, logon session (use with hostname: IDs repeat)
    text: str | None = None  # contains, across the normalized text fields
    event_pks: tuple[int, ...] = ()  # specific stored events (detection drill-down)
    limit: int = DEFAULT_PAGE_SIZE
    offset: int = 0
    newest_first: bool = True

    def describe(self) -> str:
        """Short human description of the active conditions, for UI headers."""
        parts = []
        if self.event_pks:
            parts.append(f"{len(self.event_pks)} evidence events")
        if self.username:
            parts.append(f"user contains '{self.username}'")
        if self.domain:
            parts.append(f"domain {self.domain}")
        if self.ip:
            parts.append(f"IP {self.ip}")
        if self.process:
            parts.append(f"process '{self.process}'")
        if self.parent_process:
            parts.append(f"parent '{self.parent_process}'")
        if self.provider:
            parts.append(f"provider '{self.provider}'")
        if self.port is not None:
            parts.append(f"port {self.port}")
        if self.file_path:
            parts.append(f"file '{self.file_path}'")
        if self.registry_path:
            parts.append(f"registry '{self.registry_path}'")
        if self.dns_query:
            parts.append(f"DNS '{self.dns_query}'")
        if self.threat:
            parts.append(f"threat '{self.threat}'")
        if self.logon_id:
            parts.append(f"logon session {self.logon_id}")
        if self.hostname:
            parts.append(f"computer {self.hostname}")
        if self.sid:
            parts.append(f"SID {self.sid}")
        if self.sources:
            parts.append("source " + ", ".join(self.sources))
        if self.event_ids:
            parts.append("event " + ", ".join(str(i) for i in self.event_ids))
        if self.logon_type is not None:
            parts.append(f"logon type {self.logon_type}")
        if self.text:
            parts.append(f"text '{self.text}'")
        if self.start or self.end:
            parts.append("time range")
        return " · ".join(parts) or "all events"


@dataclass(frozen=True, slots=True)
class StoredEvent:
    pk: int
    event: NormalizedEvent


@dataclass(frozen=True, slots=True)
class SearchPage:
    events: list[StoredEvent]
    total: int
    filter: EventFilter

    @property
    def has_more(self) -> bool:
        return self.filter.offset + len(self.events) < self.total


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _where(f: EventFilter) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []

    def any_of(column: str, values: tuple[Any, ...]) -> None:
        clauses.append(f"{column} IN ({', '.join('?' for _ in values)})")
        params.extend(values)

    def contains(columns: tuple[str, ...], value: str) -> None:
        pattern = f"%{_escape_like(value.strip())}%"
        clauses.append("(" + " OR ".join(f"{c} LIKE ? ESCAPE '\\'" for c in columns) + ")")
        params.extend([pattern] * len(columns))

    if f.start:
        clauses.append("timestamp >= ?")
        params.append(to_db_time(f.start))
    if f.end:
        clauses.append("timestamp <= ?")
        params.append(to_db_time(f.end))
    if f.event_ids:
        any_of("event_id", f.event_ids)
    if f.sources:
        any_of("source", f.sources)
    if f.channels:
        any_of("channel", f.channels)
    if f.event_pks:
        any_of("id", f.event_pks)
    if f.hostname:
        clauses.append("hostname = ? COLLATE NOCASE")
        params.append(f.hostname)
    if f.username and f.username.strip():
        contains(("target_username", "subject_username"), f.username)
    if f.domain and f.domain.strip():
        clauses.append("(target_domain = ? COLLATE NOCASE OR subject_domain = ? COLLATE NOCASE)")
        params.extend([f.domain.strip()] * 2)
    if f.sid and f.sid.strip():
        clauses.append(
            "(target_user_sid = ? COLLATE NOCASE OR subject_user_sid = ? COLLATE NOCASE)"
        )
        params.extend([f.sid.strip()] * 2)
    if f.ip and f.ip.strip():
        exact = normalize_ip(f.ip)
        # Either side: the logon's client address, or a Sysmon connection's endpoints.
        if exact:
            clauses.append("(source_ip = ? OR destination_ip = ?)")
            params.extend([exact, exact])
        else:
            prefix = f"{_escape_like(f.ip.strip())}%"
            clauses.append("(source_ip LIKE ? ESCAPE '\\' OR destination_ip LIKE ? ESCAPE '\\')")
            params.extend([prefix, prefix])
    if f.logon_type is not None:
        clauses.append("logon_type = ?")
        params.append(f.logon_type)
    if f.process and f.process.strip():
        contains(("process_name", "process_path"), f.process)
    if f.parent_process and f.parent_process.strip():
        contains(("parent_process",), f.parent_process)
    if f.provider and f.provider.strip():
        contains(("provider",), f.provider)
    if f.port is not None:
        clauses.append("(source_port = ? OR destination_port = ?)")
        params.extend([f.port, f.port])
    if f.file_path and f.file_path.strip():
        contains(("file_path",), f.file_path)
    if f.registry_path and f.registry_path.strip():
        contains(("registry_path",), f.registry_path)
    if f.dns_query and f.dns_query.strip():
        contains(("dns_query",), f.dns_query)
    if f.threat and f.threat.strip():
        # Defender events are few; the threat name lives in the normalized details.
        clauses.append(
            "(source = 'defender' AND json_extract(details, '$.threat_name') LIKE ? ESCAPE '\\')"
        )
        params.append(f"%{_escape_like(f.threat.strip())}%")
    if f.logon_id and f.logon_id.strip():
        clauses.append("logon_id = ? COLLATE NOCASE")
        params.append(f.logon_id.strip())
    if f.text and f.text.strip():
        contains(_TEXT_COLUMNS, f.text)
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


def search_events(conn: sqlite3.Connection, f: EventFilter) -> SearchPage:
    """One page of matching events plus the total match count."""
    limit = max(1, min(f.limit, MAX_PAGE_SIZE))
    where, params = _where(f)
    order = "DESC" if f.newest_first else "ASC"
    total = conn.execute(f"SELECT COUNT(*) FROM events{where}", params).fetchone()[0]  # noqa: S608
    rows = conn.execute(
        f"SELECT * FROM events{where} ORDER BY timestamp {order}, record_id {order} "  # noqa: S608
        "LIMIT ? OFFSET ?",
        [*params, limit, max(0, f.offset)],
    )
    events = [StoredEvent(r["id"], row_to_event(r)) for r in rows]
    return SearchPage(events, total, f)


@dataclass(frozen=True, slots=True)
class Pivot:
    label: str
    filter: EventFilter
    title: str


def more_pivots(e: NormalizedEvent) -> list[Pivot]:
    """Pivots offered for one event, from whatever fields it recorded."""
    pivots: list[Pivot] = []
    if e.logon_id and e.logon_id.lower() not in {"0x0", "0x3e7", "0x3e4", "0x3e5"}:
        pivots.append(
            Pivot(
                "This logon session",
                EventFilter(logon_id=e.logon_id, hostname=e.hostname),
                f"Logon session {e.logon_id} on {e.hostname}",
            )
        )
    if e.destination_ip:
        pivots.append(
            Pivot(
                "This destination",
                EventFilter(ip=e.destination_ip),
                f"Events involving {e.destination_ip}",
            )
        )
    if e.parent_process:
        name = e.parent_process.replace("/", "\\").rsplit("\\", 1)[-1]
        pivots.append(
            Pivot(
                "This parent process",
                EventFilter(parent_process=name),
                f"Processes started by {name}",
            )
        )
    if e.file_path:
        pivots.append(
            Pivot("This file", EventFilter(file_path=e.file_path), f"Events for {e.file_path}")
        )
    if e.registry_path:
        pivots.append(
            Pivot(
                "This registry path",
                EventFilter(registry_path=e.registry_path),
                f"Events for {e.registry_path}",
            )
        )
    if e.dns_query:
        pivots.append(
            Pivot(
                "This DNS name",
                EventFilter(dns_query=e.dns_query),
                f"Lookups of {e.dns_query}",
            )
        )
    threat = e.detail("threat_name")
    if threat:
        pivots.append(
            Pivot("This Defender threat", EventFilter(threat=str(threat)), f"Defender: {threat}")
        )
    sid = e.target_user_sid or e.subject_user_sid
    if sid and sid not in {"S-1-0-0", "S-1-5-18"}:
        pivots.append(Pivot("This SID", EventFilter(sid=sid), f"Events for SID {sid}"))
    return pivots


def distinct_values(conn: sqlite3.Connection, column: str) -> list[Any]:
    """Distinct values of a filterable column (for UI dropdowns)."""
    if column not in {"event_id", "source", "channel", "hostname", "logon_type"}:
        raise ValueError(f"Not a filterable column: {column}")
    rows = conn.execute(
        f"SELECT DISTINCT {column} FROM events WHERE {column} IS NOT NULL ORDER BY {column}"  # noqa: S608
    )
    return [r[0] for r in rows]


# ----------------------------------------------------------------- timeline
@dataclass(frozen=True, slots=True)
class TimelineItem:
    pk: int
    event: NormalizedEvent
    is_evidence: bool
    badge: str
    explanation: str


@dataclass(frozen=True, slots=True)
class Timeline:
    title: str
    window_start: datetime
    window_end: datetime
    items: list[TimelineItem]
    total_in_window: int
    detection: StoredDetection | None = None
    evidence_count: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def truncated(self) -> bool:
        return self.total_in_window > len(self.items)


def _explain_sysmon(e: NormalizedEvent) -> str:
    who = f"{e.subject_domain}\\{e.subject_username}" if e.subject_domain else e.subject_username
    if e.event_id == SysmonEventId.PROCESS_CREATE:
        parent = (e.parent_process or "").replace("/", "\\").rsplit("\\", 1)[-1] or None
        pid = e.process_id if e.process_id is not None else "?"
        return (
            f"Sysmon: process {e.process_name or 'unknown'} (PID {pid}) started by "
            f"{who or 'unknown user'}"
            + (f" from {parent}" if parent else "")
            + (f", integrity {e.integrity_level}" if e.integrity_level else "")
        )
    actor = f"{e.process_name or 'unknown process'}" + (
        f" (PID {e.process_id})" if e.process_id is not None else ""
    )
    if e.event_id == SysmonEventId.NETWORK_CONNECT:
        direction = {True: "outbound", False: "inbound"}.get(e.detail("initiated"), "direction ?")
        src = f"{e.source_ip or '?'}:{e.source_port or '?'}"
        dst = f"{e.destination_ip or '?'}:{e.destination_port or '?'}"
        host = e.detail("destination_hostname")
        return (
            f"Sysmon: {actor} {e.network_protocol or ''} connection {src} → {dst}"
            + (f" ({host})" if host else "")
            + f", {direction}"
        ).replace("  ", " ")
    if e.event_id == SysmonEventId.FILE_CREATE:
        return f"Sysmon: {actor} created file {e.file_path or '?'}"
    if e.event_id == SysmonEventId.REGISTRY_VALUE_SET:
        # The written value is never repeated here; it may contain secrets.
        return f"Sysmon: {actor} set registry value {e.registry_path or '?'}"
    if e.event_id == SysmonEventId.DNS_QUERY:
        resolved = e.detail("resolved_addresses") or []
        return (
            f"Sysmon: {actor} looked up {e.dns_query or '?'}"
            + (f" → {', '.join(resolved[:3])}" if resolved else "")
            + (f" (status {e.detail('query_status')})" if e.detail("query_status") else "")
        )
    return f"Sysmon event {e.event_id}"


def explain_event(e: NormalizedEvent) -> str:
    """One-line, analyst-readable description built only from recorded fields."""
    if e.source is TelemetrySource.SYSMON:
        return _explain_sysmon(e)
    if e.source is TelemetrySource.POWERSHELL:
        return _explain_powershell(e)
    if e.source is TelemetrySource.DEFENDER:
        return _explain_defender(e)
    who = e.target_account_display or "unknown account"
    where = e.source_ip or (f"workstation {e.workstation_name}" if e.workstation_name else None)
    how = f"{e.logon_type_name} logon" if e.logon_type_name else "logon"
    if e.event_id == SecurityEventId.LOGON_FAILURE:
        reason = (
            e.failure_reason or LOGON_FAILURE_REASONS.get(e.sub_status or "") or "unknown reason"
        )
        return f"Failed {how} for {who}: {reason}" + (f", from {where}" if where else "")
    if e.event_id == SecurityEventId.LOGON_SUCCESS:
        return f"Successful {how} for {who}" + (f" from {where}" if where else "")
    if e.event_id == SecurityEventId.LOG_CLEARED:
        actor = (
            f"{e.subject_domain}\\{e.subject_username}" if e.subject_domain else e.subject_username
        )
        return f"Security audit log cleared by {actor or 'unknown account'}"
    if e.event_id == SecurityEventId.SPECIAL_PRIVILEGES:
        count = len(e.privilege_list)
        return (
            f"Special privileges ({count}) assigned to the new logon of "
            f"{e.subject_account_display or 'unknown account'} (logon ID {e.logon_id or '?'})"
        )
    if e.event_id == SecurityEventId.PROCESS_CREATED:
        # Command lines can contain secrets, so the one-line summary never repeats one;
        # it only says whether Windows recorded it (the raw XML viewer shows it).
        parent = (e.parent_process or "").replace("/", "\\").rsplit("\\", 1)[-1] or None
        recorded = "recorded" if e.command_line else "Unavailable (command-line auditing off)"
        pid = e.process_id if e.process_id is not None else "?"
        return (
            f"Process {e.process_name or 'unknown'} (PID {pid}) "
            f"started by {e.subject_account_display or 'unknown account'}"
            + (f" from {parent}" if parent else "")
            + f"; command line {recorded}"
        )
    if e.event_id == SecurityEventId.ACCOUNT_CREATED:
        return f"User account {who} created by {e.subject_account_display or 'unknown account'}"
    if e.event_id == SecurityEventId.LOCAL_GROUP_MEMBER_ADDED:
        member = e.member_name or e.member_sid or "unknown member"
        group = e.group_name or e.group_sid or "unknown group"
        return (
            f"{member} added to local group {group} by "
            f"{e.subject_account_display or 'unknown account'}"
        )
    return f"Event {e.event_id} from {e.provider}"


def _explain_powershell(e: NormalizedEvent) -> str:
    # Script text can contain secrets, so the summary never repeats it; the raw XML
    # viewer shows it locally when an analyst needs it.
    part, total = e.detail("message_number"), e.detail("message_total")
    parts = f" (part {part} of {total})" if total and total != 1 else ""
    length = e.detail("script_length")
    size = f"{length} characters" if length is not None else "unknown length"
    flagged = "; PowerShell flagged it as suspicious" if e.detail("windows_flagged") else ""
    who = e.subject_account_display or e.subject_user_sid or "unknown account"
    return f"PowerShell script block{parts} run by {who}, {size}{flagged}"


def _explain_defender(e: NormalizedEvent) -> str:
    # The verdict is Microsoft Defender's; the wording says so.
    threat = e.detail("threat_name") or "a threat"
    target = f" in {e.file_path}" if e.file_path else ""
    if e.event_id == DefenderEventId.MALWARE_DETECTED:
        severity = e.detail("severity_name")
        return f"Microsoft Defender detected {threat}{target}" + (
            f" (Defender severity {severity})" if severity else ""
        )
    if e.event_id == DefenderEventId.ACTION_TAKEN:
        action = e.detail("action_name") or "an action"
        return f"Microsoft Defender took action {action} on {threat}{target}"
    reason = e.detail("error_description") or e.detail("error_code") or "unknown error"
    return f"Microsoft Defender could not remediate {threat}{target}: {reason}"


def _badge(e: NormalizedEvent, is_evidence: bool) -> str:
    if is_evidence:
        return "Evidence"
    if e.source is TelemetrySource.POWERSHELL:
        return "Script"
    if e.source is TelemetrySource.DEFENDER:
        return "Defender"
    if e.source is TelemetrySource.SYSMON:
        return {
            SysmonEventId.PROCESS_CREATE: "Process",
            SysmonEventId.NETWORK_CONNECT: "Network",
            SysmonEventId.FILE_CREATE: "File",
            SysmonEventId.REGISTRY_VALUE_SET: "Registry",
            SysmonEventId.DNS_QUERY: "DNS",
        }.get(e.event_id, "Sysmon")
    return {
        SecurityEventId.LOGON_FAILURE: "Failure",
        SecurityEventId.LOGON_SUCCESS: "Success",
        SecurityEventId.LOG_CLEARED: "Log cleared",
        SecurityEventId.SPECIAL_PRIVILEGES: "Privileged",
        SecurityEventId.PROCESS_CREATED: "Process",
        SecurityEventId.ACCOUNT_CREATED: "Account",
        SecurityEventId.LOCAL_GROUP_MEMBER_ADDED: "Group",
    }.get(e.event_id, "Event")


def _items(page: SearchPage, evidence: set[int]) -> list[TimelineItem]:
    return [
        TimelineItem(
            s.pk,
            s.event,
            s.pk in evidence,
            _badge(s.event, s.pk in evidence),
            explain_event(s.event),
        )
        for s in page.events
    ]


def detection_timeline(
    conn: sqlite3.Connection,
    detection_id: int,
    padding: timedelta = TIMELINE_PADDING,
    limit: int = TIMELINE_LIMIT,
) -> Timeline:
    """Events on the finding's host from ``padding`` before its first evidence to after its last.

    Evidence events are flagged. Context events are shown, never treated as evidence.
    """
    repo = DetectionRepository(conn)
    detection = repo.get(detection_id)
    if detection is None:
        raise MoeSOCError(f"Detection #{detection_id} does not exist.")
    evidence = set(repo.evidence_event_pks(detection_id))
    start, end = detection.first_seen - padding, detection.last_seen + padding
    f = EventFilter(
        start=start,
        end=end,
        hostname=detection.evidence.get("hostname"),
        limit=limit,
        newest_first=False,
    )
    page = search_events(conn, f)
    items = _items(page, evidence)
    notes = []
    missing = len(evidence - {i.pk for i in items})
    if missing:
        notes.append(f"{missing} evidence event(s) fall outside the shown rows (page limit).")
    if not evidence:
        notes.append("No stored evidence links for this finding (created before evidence linking).")
    return Timeline(
        title=f"{detection.rule_id} {detection.title}",
        window_start=start,
        window_end=end,
        items=items,
        total_in_window=page.total,
        detection=detection,
        evidence_count=len(evidence),
        notes=notes,
    )


def pivot_timeline(conn: sqlite3.Connection, f: EventFilter, title: str) -> Timeline:
    """Chronological view for an analyst pivot (user, IP, process, time)."""
    f = replace(f, newest_first=False, limit=min(f.limit, TIMELINE_LIMIT))
    page = search_events(conn, f)
    items = _items(page, set())
    times = [i.event.timestamp for i in items]
    start = f.start or (min(times) if times else datetime.now().astimezone())
    end = f.end or (max(times) if times else start)
    return Timeline(title, start, end, items, page.total)


def around_filter(ts: datetime, hostname: str | None, minutes: int = 15) -> EventFilter:
    return EventFilter(
        start=ts - timedelta(minutes=minutes),
        end=ts + timedelta(minutes=minutes),
        hostname=hostname,
    )
