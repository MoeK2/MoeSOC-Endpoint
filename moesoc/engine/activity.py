"""Cross-source activity graph: how events from different logs belong together.

Every link has a *kind* that says how strong it is, and correlations report it:

- ``logon_id``     same computer and logon session (Security 4624 TargetLogonId =
                   4688 SubjectLogonId = 4720/4732 SubjectLogonId = Sysmon LogonId).
                   Logon IDs repeat after a restart, so the session must start before
                   the event and within the follow-up window.
- ``process_guid`` Sysmon ProcessGuid: exact, survives PID reuse.
- ``pid``          same computer and PID, most recent process start before the event
                   (weaker: Windows reuses PIDs).
- ``file_path``    same computer and file path (case-insensitive, like Windows).
- ``user_time``    same user within a time window (weakest; used only when no
                   identifier is shared, e.g. Defender events carry no logon ID).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import timedelta

from moesoc.core.enums import (
    DefenderEventId,
    PowerShellEventId,
    SecurityEventId,
    SysmonEventId,
    TelemetrySource,
)
from moesoc.core.event import NormalizedEvent

LINK_STRENGTH = {
    "process_guid": "exact",
    "logon_id": "exact",
    "file_path": "exact",
    "pid": "weaker (PIDs are reused)",
    "user_time": "weak (same user, close in time)",
    "account": "same account (identity matching as in COR-001)",
    "detection_id": "exact (Defender Detection ID)",
}


@dataclass(frozen=True, slots=True)
class Link:
    event: NormalizedEvent
    kind: str  # key of LINK_STRENGTH


def is_process_start(e: NormalizedEvent) -> bool:
    return (e.source is TelemetrySource.SYSMON and e.event_id == SysmonEventId.PROCESS_CREATE) or (
        e.source is TelemetrySource.SECURITY and e.event_id == SecurityEventId.PROCESS_CREATED
    )


def _norm_id(value: object) -> str | None:
    if not value:
        return None
    return str(value).strip().lower()


def _session_key(host: str, logon_id: object) -> tuple[str, str] | None:
    normalized = _norm_id(logon_id)
    if normalized is None or normalized in {"0x0", "0x3e7", "0x3e4", "0x3e5"}:
        return None  # no session, or SYSTEM / NETWORK SERVICE / LOCAL SERVICE
    return (host.casefold(), normalized)


def session_ids(e: NormalizedEvent) -> list[str]:
    """Logon IDs of the session an event happened in (4688 may run in another session)."""
    if e.event_id == SecurityEventId.PROCESS_CREATED and e.detail("target_logon_id"):
        return [str(e.detail("target_logon_id"))]
    return [e.logon_id] if e.logon_id else []


def path_key(host: str, path: str | None) -> tuple[str, str] | None:
    if not path:
        return None
    return (host.casefold(), path.replace("/", "\\").casefold())


class ActivityGraph:
    """Indexes one batch of events so correlations can follow links between logs."""

    def __init__(self, events: Iterable[NormalizedEvent]) -> None:
        self.events = list(events)
        self._logons: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
        self._in_session: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
        self._by_guid: dict[str, NormalizedEvent] = {}
        self._by_pid: dict[tuple[str, int], list[NormalizedEvent]] = defaultdict(list)
        self._caused_by: dict[str, list[NormalizedEvent]] = defaultdict(list)
        self._file_creates: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
        self._starts_of_image: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
        for e in self.events:
            self._index(e)
        for starts in self._by_pid.values():
            # Sysmon first at equal time: it carries more context than 4688.
            starts.sort(key=lambda e: (e.timestamp, e.source is TelemetrySource.SYSMON))

    def _index(self, e: NormalizedEvent) -> None:
        if e.source is TelemetrySource.SECURITY and e.event_id == SecurityEventId.LOGON_SUCCESS:
            for logon_id in (e.logon_id, e.detail("linked_logon_id")):
                key = _session_key(e.hostname, logon_id)
                if key:
                    self._logons[key].append(e)
            return
        for logon_id in session_ids(e):
            key = _session_key(e.hostname, logon_id)
            if key:
                self._in_session[key].append(e)
        if is_process_start(e):
            if e.process_guid:
                self._by_guid[e.process_guid.lower()] = e
            if e.process_id is not None:
                self._by_pid[(e.hostname.casefold(), e.process_id)].append(e)
            image = path_key(e.hostname, e.process_path)
            if image:
                self._starts_of_image[image].append(e)
        elif e.source is TelemetrySource.SYSMON and e.process_guid:
            self._caused_by[e.process_guid.lower()].append(e)
        if e.source is TelemetrySource.SYSMON and e.event_id == SysmonEventId.FILE_CREATE:
            key = path_key(e.hostname, e.file_path)
            if key:
                self._file_creates[key].append(e)

    # ------------------------------------------------------------------ sessions
    def session_events(self, logon: NormalizedEvent, window: timedelta) -> list[Link]:
        """Events in the session this 4624 opened, from the logon until ``window`` later."""
        found: dict[tuple[str, int], NormalizedEvent] = {}
        for logon_id in (logon.logon_id, logon.detail("linked_logon_id")):
            key = _session_key(logon.hostname, logon_id)
            if key is None:
                continue
            for e in self._in_session.get(key, []):
                if logon.timestamp <= e.timestamp <= logon.timestamp + window:
                    found[(e.channel, e.record_id)] = e
        return [Link(e, "logon_id") for e in sorted(found.values(), key=_order)]

    # ------------------------------------------------------------------ processes
    def process_by_guid(self, guid: str | None) -> NormalizedEvent | None:
        return self._by_guid.get(guid.lower()) if guid else None

    def process_by_pid(self, host: str, pid: int | None, at: NormalizedEvent) -> Link | None:
        """The process with this PID that started most recently before ``at``."""
        if pid is None:
            return None
        starts = self._by_pid.get((host.casefold(), pid), [])
        before = [e for e in starts if e.timestamp <= at.timestamp]
        return Link(before[-1], "pid") if before else None

    def process_of(self, e: NormalizedEvent) -> Link | None:
        """The process that caused an event (Sysmon by GUID, PowerShell 4104 by PID)."""
        if e.source is TelemetrySource.SYSMON and not is_process_start(e):
            process = self.process_by_guid(e.process_guid)
            return Link(process, "process_guid") if process else None
        if e.source is TelemetrySource.POWERSHELL and e.event_id == PowerShellEventId.SCRIPT_BLOCK:
            return self.process_by_pid(e.hostname, e.process_id, e)
        return None

    def caused_by(self, process: NormalizedEvent) -> list[NormalizedEvent]:
        """Sysmon network, file, registry and DNS events of one process (by GUID)."""
        if not process.process_guid:
            return []
        return sorted(self._caused_by.get(process.process_guid.lower(), []), key=_order)

    # ------------------------------------------------------------------ files
    def file_created(
        self, host: str, path: str | None, before: NormalizedEvent, window: timedelta
    ) -> NormalizedEvent | None:
        """The latest Sysmon 11 that wrote this path within ``window`` before ``before``."""
        key = path_key(host, path)
        if key is None:
            return None
        candidates = [
            e
            for e in self._file_creates.get(key, [])
            if before.timestamp - window <= e.timestamp <= before.timestamp
        ]
        return max(candidates, key=_order) if candidates else None

    def executions_of(
        self, host: str, path: str | None, after: NormalizedEvent
    ) -> list[NormalizedEvent]:
        """Process starts whose image is this file, after ``after``."""
        key = path_key(host, path)
        if key is None:
            return []
        return sorted(
            (e for e in self._starts_of_image.get(key, []) if e.timestamp >= after.timestamp),
            key=_order,
        )

    # ------------------------------------------------------------------ users
    def defender_detections_for_user(self, logon: NormalizedEvent, window: timedelta) -> list[Link]:
        """Defender 1116 for the logon's user on the same computer within the window (weak)."""
        user = (logon.target_username or "").casefold()
        if not user:
            return []
        return [
            Link(e, "user_time")
            for e in self.events
            if e.source is TelemetrySource.DEFENDER
            and e.event_id == DefenderEventId.MALWARE_DETECTED
            and e.hostname.casefold() == logon.hostname.casefold()
            and (e.subject_username or "").casefold() == user
            and logon.timestamp <= e.timestamp <= logon.timestamp + window
        ]


def _order(e: NormalizedEvent) -> tuple[object, int]:
    return (e.timestamp, e.record_id)
