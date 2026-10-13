"""Investigation stories: one finding, its related findings and their evidence as a narrative.

A story is built on demand from what is stored (never cached), so it always matches
the current findings, triage state and notes. It says what the recorded events show,
in time order, which findings each step supports, what the data cannot tell (missing
telemetry), and what to check next. It is a lead for an analyst, not a verdict.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from moesoc.core.detection import RuleMetadata
from moesoc.core.enums import SecurityEventId, SysmonEventId, TelemetrySource
from moesoc.core.event import NormalizedEvent
from moesoc.core.exceptions import MoeSOCError
from moesoc.storage.event_search import explain_event
from moesoc.storage.repository import (
    AnalystNote,
    DetectionRepository,
    StoredDetection,
    row_to_event,
    to_db_time,
)
from moesoc.utils.time import format_local

RELATED_WINDOW = timedelta(minutes=30)  # same account, overlapping in time
CONTEXT_WINDOW = timedelta(minutes=30)  # telemetry-coverage check around the story
MAX_STEPS = 200
MAX_RELATED = 20
MAX_NEXT_STEPS = 8
DISCLAIMER = (
    "Built only from events recorded on this computer. It describes what the logs show "
    "and how the events are linked; it is a lead for investigation, not proof."
)


@dataclass(frozen=True, slots=True)
class StoryFinding:
    id: int
    rule_id: str
    title: str
    severity: str
    confidence: str
    status: str
    relation: str  # "this finding", "shares evidence", "same account, overlapping time"


@dataclass(frozen=True, slots=True)
class StoryStep:
    start: datetime
    end: datetime
    count: int
    log: str
    event_id: int
    text: str
    findings: tuple[str, ...]  # rule IDs this step is evidence for
    event_pks: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class Story:
    detection_id: int
    title: str
    hostname: str | None
    account: str | None
    start: datetime
    end: datetime
    findings: list[StoryFinding]
    steps: list[StoryStep]
    gaps: list[str]
    next_steps: list[str]
    notes: list[AnalystNote] = field(default_factory=list)
    truncated: bool = False
    disclaimer: str = DISCLAIMER


def _related(
    conn: sqlite3.Connection, primary: StoredDetection, repo: DetectionRepository
) -> list[tuple[StoredDetection, str]]:
    shared = conn.execute(
        """SELECT DISTINCT other.detection_id FROM detection_events mine
           JOIN detection_events other ON other.event_pk = mine.event_pk
           WHERE mine.detection_id = ? AND other.detection_id != ?""",
        (primary.id, primary.id),
    ).fetchall()
    found: dict[int, str] = {int(r[0]): "shares evidence" for r in shared}
    if primary.account:
        rows = conn.execute(
            """SELECT id FROM detections WHERE id != ? AND account = ? COLLATE NOCASE
               AND first_seen <= ? AND last_seen >= ?""",
            (
                primary.id,
                primary.account,
                to_db_time(primary.last_seen + RELATED_WINDOW),
                to_db_time(primary.first_seen - RELATED_WINDOW),
            ),
        ).fetchall()
        for r in rows:
            found.setdefault(int(r[0]), "same account, overlapping time")
    related: list[tuple[StoredDetection, str]] = []
    for detection_id, relation in sorted(found.items())[:MAX_RELATED]:
        other = repo.get(detection_id)
        if other is not None and _same_host(primary, other):
            related.append((other, relation))
    return related


def _same_host(a: StoredDetection, b: StoredDetection) -> bool:
    host_a, host_b = a.evidence.get("hostname"), b.evidence.get("hostname")
    return not host_a or not host_b or str(host_a).casefold() == str(host_b).casefold()


def _events(conn: sqlite3.Connection, pks: Sequence[int]) -> dict[int, NormalizedEvent]:
    events: dict[int, NormalizedEvent] = {}
    for i in range(0, len(pks), 500):
        chunk = list(pks[i : i + 500])
        placeholders = ", ".join("?" for _ in chunk)
        rows = conn.execute(
            f"SELECT * FROM events WHERE id IN ({placeholders})",  # noqa: S608 - placeholders
            chunk,
        ).fetchall()
        events.update({int(r["id"]): row_to_event(r) for r in rows})
    return events


def _collapse_key(e: NormalizedEvent) -> tuple[object, ...]:
    """Consecutive events with the same key become one step ("6× failed logon …")."""
    return (
        e.source,
        e.event_id,
        (e.target_account_display or e.subject_account_display or "").casefold(),
        e.source_ip,
        e.logon_type,
        e.process_name,
    )


def _steps(
    events: dict[int, NormalizedEvent], rules_by_pk: dict[int, set[str]]
) -> tuple[list[StoryStep], bool]:
    ordered = sorted(events.items(), key=lambda kv: (kv[1].timestamp, kv[1].record_id))
    steps: list[StoryStep] = []
    group: list[tuple[int, NormalizedEvent]] = []

    def flush() -> None:
        if not group:
            return
        first = group[0][1]
        text = explain_event(first)
        if len(group) > 1:
            text = f"{len(group)}× {text}"
        rule_ids = sorted({r for pk, _ in group for r in rules_by_pk.get(pk, set())})
        steps.append(
            StoryStep(
                start=first.timestamp,
                end=group[-1][1].timestamp,
                count=len(group),
                log=first.source.value,
                event_id=first.event_id,
                text=text,
                findings=tuple(rule_ids),
                event_pks=tuple(pk for pk, _ in group),
            )
        )
        group.clear()

    for pk, event in ordered:
        if group and _collapse_key(group[-1][1]) != _collapse_key(event):
            flush()
        group.append((pk, event))
    flush()
    return steps[:MAX_STEPS], len(steps) > MAX_STEPS


def _coverage(
    conn: sqlite3.Connection, hostname: str | None, start: datetime, end: datetime
) -> dict[str, set[int]]:
    """Which sources and event IDs were recorded for this computer around the story."""
    if not hostname:
        return {}
    rows = conn.execute(
        """SELECT DISTINCT source, event_id FROM events
           WHERE hostname = ? COLLATE NOCASE AND timestamp >= ? AND timestamp <= ?""",
        (hostname, to_db_time(start - CONTEXT_WINDOW), to_db_time(end + CONTEXT_WINDOW)),
    ).fetchall()
    coverage: dict[str, set[int]] = {}
    for source, event_id in rows:
        coverage.setdefault(str(source), set()).add(int(event_id))
    return coverage


def _gaps(coverage: dict[str, set[int]], rule_ids: set[str]) -> list[str]:
    gaps: list[str] = []
    sysmon = coverage.get(TelemetrySource.SYSMON.value, set())
    security = coverage.get(TelemetrySource.SECURITY.value, set())
    if not sysmon:
        gaps.append(
            "No Sysmon events from this computer in this period: process, network, DNS and "
            "file activity are unknown (unknown is not the same as absent)."
        )
    if int(SysmonEventId.PROCESS_CREATE) not in sysmon and (
        int(SecurityEventId.PROCESS_CREATED) not in security
    ):
        gaps.append(
            "No process-creation events (Sysmon 1 or Security 4688): which programs ran is unknown."
        )
    if not coverage.get(TelemetrySource.POWERSHELL.value):
        gaps.append("No PowerShell script-block events (4104): script content is unknown.")
    if not coverage.get(TelemetrySource.DEFENDER.value):
        gaps.append(
            "No Microsoft Defender events in this period: either nothing was detected or the "
            "Defender log was not collected."
        )
    if rule_ids & {"COR-001", "COR-003", "DET-001", "DET-002", "DET-004"}:
        gaps.append(
            "Logs cannot tell whether a successful logon was the real account owner; confirm "
            "with the user and check the source address."
        )
    gaps.append(
        "Events older than the collection lookback, or removed from the Windows log before "
        "collection, are not part of this story."
    )
    return gaps


def build_story(
    conn: sqlite3.Connection,
    detection_id: int,
    rules: Mapping[str, RuleMetadata] | None = None,
) -> Story:
    repo = DetectionRepository(conn)
    primary = repo.get(detection_id)
    if primary is None:
        raise MoeSOCError(f"Finding #{detection_id} does not exist.")
    related = _related(conn, primary, repo)
    members: list[tuple[StoredDetection, str]] = [(primary, "this finding"), *related]

    rules_by_pk: dict[int, set[str]] = {}
    for detection, _relation in members:
        for pk in repo.evidence_event_pks(detection.id):
            rules_by_pk.setdefault(pk, set()).add(detection.rule_id)
    events = _events(conn, sorted(rules_by_pk))
    steps, truncated = _steps(events, rules_by_pk)

    start = min([d.first_seen for d, _ in members] + [e.timestamp for e in events.values()])
    end = max([d.last_seen for d, _ in members] + [e.timestamp for e in events.values()])
    hostname = primary.evidence.get("hostname") or next((e.hostname for e in events.values()), None)
    rule_ids = {d.rule_id for d, _ in members}

    next_steps: list[str] = []
    for detection, _relation in members:
        rule = (rules or {}).get(detection.rule_id)
        for item in rule.recommended_investigation if rule else ():
            if item not in next_steps:
                next_steps.append(item)

    subject = primary.account or "unknown account"
    where = f" on {hostname}" if hostname else ""
    return Story(
        detection_id=primary.id,
        title=f"{primary.title}: {subject}{where}",
        hostname=str(hostname) if hostname else None,
        account=primary.account,
        start=start,
        end=end,
        findings=[
            StoryFinding(
                d.id, d.rule_id, d.title, d.severity, d.confidence, d.status.label, relation
            )
            for d, relation in members
        ],
        steps=steps,
        gaps=_gaps(_coverage(conn, str(hostname) if hostname else None, start, end), rule_ids),
        next_steps=next_steps[:MAX_NEXT_STEPS],
        notes=repo.notes(primary.id),
        truncated=truncated,
    )


def render_story_lines(story: Story) -> list[str]:
    """Plain-text story for the CLI (no command lines or script text are included)."""
    lines = [story.title, "=" * min(len(story.title), 100), story.disclaimer, ""]
    lines.append(f"Period: {format_local(story.start)} → {format_local(story.end)}")
    lines.append("")
    lines.append("Findings in this story:")
    for f in story.findings:
        lines.append(
            f"  #{f.id} {f.rule_id} {f.title} [{f.severity}/{f.confidence}] {f.status}"
            f" ({f.relation})"
        )
    lines += ["", "What happened (recorded events, in order):"]
    for s in story.steps:
        when = format_local(s.start)
        if s.count > 1 and s.end != s.start:
            when += f" → {format_local(s.end)}"
        support = f"  [{', '.join(s.findings)}]" if s.findings else ""
        lines.append(f"  {when}  {s.log}/{s.event_id}  {s.text}{support}")
    if story.truncated:
        lines.append(f"  … only the first {MAX_STEPS} steps are shown.")
    lines += ["", "What the data cannot tell:"]
    lines += [f"  - {g}" for g in story.gaps]
    if story.next_steps:
        lines += ["", "Next steps:"]
        lines += [f"  {i}. {n}" for i, n in enumerate(story.next_steps, 1)]
    if story.notes:
        lines += ["", "Analyst notes:"]
        lines += [f"  {format_local(n.created_at)}  {n.body}" for n in story.notes]
    return lines
