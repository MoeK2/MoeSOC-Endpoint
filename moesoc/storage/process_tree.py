"""Process trees from stored process-creation events (Sysmon 1, Security 4688).

A tree is **evidence**, never a verdict: an unusual chain (Word → cmd → PowerShell)
is shown, not called malicious.

How parents and children are linked, strongest first:

- ``guid`` — Sysmon ProcessGuid / ParentProcessGuid. Unique per process instance,
  even after Windows reuses the PID.
- ``pid`` — Security 4688 only has PIDs, which Windows reuses. The parent is the
  most recent process with that PID that started on the same computer **before** the
  child. This is a weaker link and is labelled as such.
- ``recorded only`` — the parent's own creation event is not in the database (it
  started before collection began, or auditing was off); the node is built from the
  child's recorded parent fields.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime

from moesoc.core.enums import SecurityEventId, SysmonEventId, TelemetrySource
from moesoc.core.event import NormalizedEvent
from moesoc.core.exceptions import MoeSOCError
from moesoc.storage.repository import row_to_event, to_db_time

MAX_ANCESTORS = 25
MAX_NODES = 300

_SYSMON = TelemetrySource.SYSMON.value
_SECURITY = TelemetrySource.SECURITY.value
_SYSMON_CREATE = int(SysmonEventId.PROCESS_CREATE)
_SECURITY_CREATE = int(SecurityEventId.PROCESS_CREATED)


@dataclass(slots=True)
class ProcessNode:
    pk: int | None  # stored event, None when only recorded by a child
    event: NormalizedEvent | None
    name: str
    path: str | None
    pid: int | None
    guid: str | None
    user: str | None
    started: datetime | None
    command_line: str | None
    integrity: str | None
    link: str  # how this node was linked to its child/parent: guid / pid / recorded only / root
    children: list[ProcessNode] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ProcessTree:
    ancestors: list[ProcessNode]  # oldest first, ending with the root's parent
    root: ProcessNode  # the selected process, with its descendants
    node_count: int
    truncated: bool  # MAX_NODES reached


def _name(path: str | None) -> str:
    if not path:
        return "unknown"
    return path.replace("/", "\\").rsplit("\\", 1)[-1] or path


def _user(e: NormalizedEvent) -> str | None:
    if e.subject_username:
        return (
            f"{e.subject_domain}\\{e.subject_username}" if e.subject_domain else e.subject_username
        )
    return None


def _node(pk: int | None, e: NormalizedEvent, link: str) -> ProcessNode:
    return ProcessNode(
        pk=pk,
        event=e,
        name=e.process_name or _name(e.process_path),
        path=e.process_path,
        pid=e.process_id,
        guid=e.process_guid,
        user=_user(e),
        started=e.timestamp,
        command_line=e.command_line,
        integrity=e.integrity_level,
        link=link,
    )


def _recorded_parent(child: NormalizedEvent) -> ProcessNode:
    return ProcessNode(
        pk=None,
        event=None,
        name=_name(child.parent_process),
        path=child.parent_process,
        pid=child.parent_process_id,
        guid=child.parent_process_guid,
        user=None,
        started=None,
        command_line=child.detail("parent_command_line"),
        integrity=None,
        link="recorded only",
    )


def is_process_event(e: NormalizedEvent) -> bool:
    return (e.source is TelemetrySource.SYSMON and e.event_id == _SYSMON_CREATE) or (
        e.source is TelemetrySource.SECURITY and e.event_id == _SECURITY_CREATE
    )


class _Store:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn  # rows are sqlite3.Row (set by Database.connect)

    def get(self, pk: int) -> NormalizedEvent | None:
        row = self._conn.execute("SELECT * FROM events WHERE id = ?", (pk,)).fetchone()
        return row_to_event(row) if row else None

    def _one(self, sql: str, params: tuple) -> tuple[int, NormalizedEvent] | None:
        row = self._conn.execute(sql, params).fetchone()
        return (row["id"], row_to_event(row)) if row else None

    def by_guid(self, hostname: str, guid: str) -> tuple[int, NormalizedEvent] | None:
        return self._one(
            "SELECT * FROM events WHERE hostname = ? AND source = ? AND event_id = ? "
            "AND process_guid = ? ORDER BY timestamp LIMIT 1",
            (hostname, _SYSMON, _SYSMON_CREATE, guid),
        )

    def pid_started_before(
        self, hostname: str, pid: int, before: datetime
    ) -> tuple[int, NormalizedEvent] | None:
        """The most recent 4688 for ``pid`` on this host that started at or before ``before``."""
        return self._one(
            "SELECT * FROM events WHERE hostname = ? AND source = ? AND event_id = ? "
            "AND process_id = ? AND timestamp <= ? ORDER BY timestamp DESC, record_id DESC LIMIT 1",
            (hostname, _SECURITY, _SECURITY_CREATE, pid, to_db_time(before)),
        )

    def children_by_guid(self, hostname: str, guid: str) -> list[tuple[int, NormalizedEvent]]:
        rows = self._conn.execute(
            "SELECT * FROM events WHERE hostname = ? AND source = ? AND event_id = ? "
            "AND parent_process_guid = ? ORDER BY timestamp, record_id LIMIT ?",
            (hostname, _SYSMON, _SYSMON_CREATE, guid, MAX_NODES),
        ).fetchall()
        return [(r["id"], row_to_event(r)) for r in rows]

    def children_by_pid(
        self, hostname: str, pid: int, after: datetime
    ) -> list[tuple[int, NormalizedEvent]]:
        rows = self._conn.execute(
            "SELECT * FROM events WHERE hostname = ? AND source = ? AND event_id = ? "
            "AND parent_process_id = ? AND timestamp >= ? ORDER BY timestamp, record_id LIMIT ?",
            (hostname, _SECURITY, _SECURITY_CREATE, pid, to_db_time(after), MAX_NODES),
        ).fetchall()
        return [(r["id"], row_to_event(r)) for r in rows]


def _parent_of(store: _Store, e: NormalizedEvent) -> tuple[int, NormalizedEvent, str] | None:
    if e.source is TelemetrySource.SYSMON and e.parent_process_guid:
        found = store.by_guid(e.hostname, e.parent_process_guid)
        return (found[0], found[1], "guid") if found else None
    if e.source is TelemetrySource.SECURITY and e.parent_process_id is not None:
        found = store.pid_started_before(e.hostname, e.parent_process_id, e.timestamp)
        return (found[0], found[1], "pid") if found else None
    return None


def _children_of(
    store: _Store, pk: int, e: NormalizedEvent
) -> list[tuple[int, NormalizedEvent, str]]:
    if e.source is TelemetrySource.SYSMON and e.process_guid:
        return [(cpk, c, "guid") for cpk, c in store.children_by_guid(e.hostname, e.process_guid)]
    if e.source is TelemetrySource.SECURITY and e.process_id is not None:
        result = []
        for cpk, child in store.children_by_pid(e.hostname, e.process_id, e.timestamp):
            # PID reuse: only a child whose most recent same-PID parent is THIS process.
            parent = store.pid_started_before(e.hostname, e.process_id, child.timestamp)
            if parent is not None and parent[0] == pk:
                result.append((cpk, child, "pid"))
        return result
    return []


def build_process_tree(conn: sqlite3.Connection, event_pk: int) -> ProcessTree:
    """Ancestors and descendants of one stored process-creation event."""
    store = _Store(conn)
    root_event = store.get(event_pk)
    if root_event is None:
        raise MoeSOCError(f"Event #{event_pk} is not in the database.")
    if not is_process_event(root_event):
        raise MoeSOCError(
            "A process tree needs a process-creation event (Sysmon 1 or Security 4688)."
        )

    # ---------------------------------------------------------------- ancestors
    ancestors: list[ProcessNode] = []
    seen = {event_pk}
    current = root_event
    while len(ancestors) < MAX_ANCESTORS:
        parent = _parent_of(store, current)
        if parent is None:
            if current.parent_process or current.parent_process_id is not None:
                ancestors.append(_recorded_parent(current))
            break
        ppk, pevent, link = parent
        if ppk in seen:
            break  # never loop, even on inconsistent data
        seen.add(ppk)
        ancestors.append(_node(ppk, pevent, link))
        current = pevent
    ancestors.reverse()

    # ---------------------------------------------------------------- descendants
    root = _node(event_pk, root_event, "root")
    count, truncated = 1, False
    queue = [root]
    while queue:
        node = queue.pop(0)
        if node.pk is None or node.event is None:
            continue
        for cpk, child, link in _children_of(store, node.pk, node.event):
            if cpk in seen:
                continue
            if count >= MAX_NODES:
                truncated = True
                queue.clear()
                break
            seen.add(cpk)
            child_node = _node(cpk, child, link)
            node.children.append(child_node)
            queue.append(child_node)
            count += 1
    return ProcessTree(ancestors, root, count + len(ancestors), truncated)


def render_tree_lines(tree: ProcessTree) -> list[str]:
    """Plain-text tree (CLI). Command lines are not printed; use the event detail."""
    lines: list[str] = []

    def describe(node: ProcessNode) -> str:
        parts = [node.name]
        if node.pid is not None:
            parts.append(f"PID {node.pid}")
        if node.user:
            parts.append(node.user)
        if node.integrity:
            parts.append(node.integrity)
        if node.link in ("pid", "recorded only"):
            parts.append(f"[{node.link}]")
        if node.pk is not None:
            parts.append(f"#{node.pk}")
        return "  ".join(parts)

    depth = 0
    for depth, node in enumerate(tree.ancestors):
        lines.append(("  " * depth) + ("└── " if depth else "") + describe(node))
    base = len(tree.ancestors)

    def walk(node: ProcessNode, level: int, marker: str) -> None:
        lines.append(("  " * level) + (marker if level else "") + describe(node))
        for child in node.children:
            walk(child, level + 1, "└── ")

    walk(tree.root, base, "└── " if base else "")
    lines[base] += "   ◀ selected"
    if tree.truncated:
        lines.append(f"(only the first {MAX_NODES} processes are shown)")
    return lines
