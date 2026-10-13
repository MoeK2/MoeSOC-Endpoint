"""Incremental, gap-aware event log collection (Security and Sysmon channels).

Each event group (``core``: authentication, accounts, log clearing; ``process``: 4688)
keeps a **watermark**: the EventRecordID and timestamp of the newest record already
collected. A pywin32 Event Log bookmark holds exactly that (channel + RecordId; checked
on Windows 11 with ``scripts/check_eventlog_api.py``), so MoeSOC stores the values
directly, where they can be validated, displayed and tested.

Modes per group and scan:

- **bootstrap** — no usable watermark (first run, deleted database, invalid state, or
  the set of collected event IDs changed in an upgrade): read the last
  ``lookback_hours``, newest first, up to the budget.
- **incremental** — the watermark record still exists with the same timestamp: read
  ``EventRecordID > watermark`` oldest first, up to the budget. If the budget is hit,
  the rest is read by the next scan; nothing is skipped.
- **recovery** — the watermark record is gone or different (log cleared, rolled over
  or recreated): read by time since the watermark's timestamp, and report that events
  removed from the log before this scan cannot be recovered.

Duplicates are impossible to store (unique key), so overlapping reads are safe.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from moesoc.collectors.eventlog import EventLogReader
from moesoc.core.enums import SecurityEventId
from moesoc.core.event import NormalizedEvent
from moesoc.core.exceptions import EventParseError
from moesoc.parsers.security import SECURITY_CHANNEL, SUPPORTED_EVENT_IDS, parse_security_xml
from moesoc.storage.collection_state import Watermark
from moesoc.utils.time import utc_now

log = logging.getLogger(__name__)

MS_PER_HOUR = 3_600_000
# 4672 is written for every logon with special privileges, including each service
# logon of SYSTEM / LOCAL SERVICE / NETWORK SERVICE. Those carry no investigative
# value and would double the stored volume, so they are counted and dropped.
SERVICE_ACCOUNT_SIDS = frozenset({"S-1-5-18", "S-1-5-19", "S-1-5-20"})


# Process creation (4688) can outnumber logon events by orders of magnitude. It is
# read with its own query and budget, so it can never crowd out authentication,
# account and log-clearing events that the rules depend on.
PROCESS_EVENT_IDS = frozenset({int(SecurityEventId.PROCESS_CREATED)})
CORE_EVENT_IDS = frozenset(SUPPORTED_EVENT_IDS - PROCESS_EVENT_IDS)
EVENT_GROUPS: dict[str, frozenset[int]] = {"core": CORE_EVENT_IDS, "process": PROCESS_EVENT_IDS}
CLOCK_SKEW = timedelta(minutes=5)


def group_signature(event_ids: frozenset[int]) -> str:
    return ",".join(str(i) for i in sorted(event_ids))


def is_routine_noise(event: NormalizedEvent) -> bool:
    return (
        event.event_id == SecurityEventId.SPECIAL_PRIVILEGES
        and (event.subject_user_sid or "").upper() in SERVICE_ACCOUNT_SIDS
    )


def _ids(event_ids: frozenset[int]) -> str:
    return " or ".join(f"EventID={int(i)}" for i in sorted(event_ids))


def build_event_ids_xpath(event_ids: frozenset[int]) -> str:
    """Records of these IDs, any time (used for live subscriptions)."""
    return f"*[System[({_ids(event_ids)})]]"


def build_after_record_xpath(event_ids: frozenset[int], record_id: int) -> str:
    """Records of these IDs written after ``record_id`` (EventRecordID only grows)."""
    return f"*[System[({_ids(event_ids)}) and EventRecordID>{int(record_id)}]]"


def build_record_xpath(record_id: int) -> str:
    return f"*[System[EventRecordID={int(record_id)}]]"


def build_since_xpath(event_ids: frozenset[int], since: datetime) -> str:
    stamp = since.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    return f"*[System[({_ids(event_ids)}) and TimeCreated[@SystemTime>='{stamp}']]]"


def build_security_xpath(event_ids: frozenset[int], lookback_hours: int) -> str:
    """Server-side filter so Windows returns only relevant, recent events.

    ``timediff(@SystemTime)`` is the age of the event in milliseconds.
    """
    if lookback_hours <= 0:
        raise ValueError("lookback_hours must be positive")
    return (
        f"*[System[({_ids(event_ids)}) and "
        f"TimeCreated[timediff(@SystemTime) <= {lookback_hours * MS_PER_HOUR}]]]"
    )


@dataclass(slots=True)
class CollectionResult:
    events: list[NormalizedEvent] = field(default_factory=list)
    records_read: int = 0
    parse_failures: int = 0
    filtered: int = 0  # routine records deliberately not stored (see is_routine_noise)
    truncated: bool = False  # records in the lookback were NOT read (bootstrap cap)
    more_pending: bool = False  # the budget ended an incremental read; next scan continues
    modes: dict[str, str] = field(default_factory=dict)  # group → bootstrap/incremental/recovery
    watermarks: dict[str, Watermark] = field(default_factory=dict)  # positions to persist
    notes: list[str] = field(default_factory=list)  # gaps and resets, for the scan record


class ChannelCollector:
    """Incremental collection of one event log channel, split into event groups."""

    def __init__(
        self,
        reader: EventLogReader,
        channel: str,
        groups: dict[str, frozenset[int]],
        parse: Callable[[str], NormalizedEvent],
        noise: Callable[[NormalizedEvent], bool] = lambda _event: False,
    ) -> None:
        self._reader = reader
        self._channel = channel
        self._groups = groups
        self._parse = parse
        self._noise = noise

    def collect(
        self,
        lookback_hours: int,
        max_events: int,
        watermarks: dict[str, Watermark] | None = None,
    ) -> CollectionResult:
        """Collect every event group; each has its own ``max_events`` budget.

        Raises CollectorError if the log is unreadable.
        """
        result = CollectionResult()
        marks = watermarks or {}
        log.info(
            "%s collector started (lookback=%sh, max=%s)", self._channel, lookback_hours, max_events
        )
        for group, event_ids in self._groups.items():
            self._collect_group(
                group, event_ids, lookback_hours, max_events, marks.get(group), result
            )
        log.info(
            "%s collector finished: %s read, %s normalized, %s failed, %s routine "
            "skipped, modes %s",
            self._channel,
            result.records_read,
            len(result.events),
            result.parse_failures,
            result.filtered,
            result.modes,
        )
        return result

    # ------------------------------------------------------------------ one group
    def _usable(self, mark: Watermark | None, signature: str) -> str | None:
        """Why a watermark cannot be used (None when it can)."""
        if mark is None:
            return "no saved position"
        if mark.signature != signature:
            return "the collected event types changed"
        if mark.record_id <= 0:
            return "invalid saved position"
        if mark.timestamp > utc_now() + CLOCK_SKEW:
            return "saved position is in the future"
        return None

    def _watermark_still_valid(self, mark: Watermark) -> bool:
        """The watermark record must still exist with the same timestamp."""
        for xml_text in self._reader.query(
            self._channel, build_record_xpath(mark.record_id), newest_first=False
        ):
            try:
                event = self._parse(xml_text)
            except EventParseError:
                return False
            return event.timestamp == mark.timestamp
        return False

    def _collect_group(
        self,
        group: str,
        event_ids: frozenset[int],
        lookback_hours: int,
        max_events: int,
        mark: Watermark | None,
        result: CollectionResult,
    ) -> None:
        signature = group_signature(event_ids)
        problem = self._usable(mark, signature)
        if problem is None and mark is not None:
            if self._watermark_still_valid(mark):
                mode = "incremental"
                xpath = build_after_record_xpath(event_ids, mark.record_id)
            else:
                mode = "recovery"
                xpath = build_since_xpath(event_ids, mark.timestamp)
                result.notes.append(
                    f"{group}: the last collected record ({mark.record_id}) is no longer in the "
                    f"{self._channel} log (cleared, rolled over or recreated). Collection "
                    "resumed from "
                    f"{mark.timestamp.isoformat()}; events removed before this scan cannot be "
                    "recovered."
                )
            newest_first = False
        else:
            mode = "bootstrap"
            xpath = build_security_xpath(event_ids, lookback_hours)
            newest_first = True
            if mark is not None:
                result.notes.append(f"{group}: collection restarted ({problem}).")
        result.modes[group] = mode

        # Only an incremental read continues from the old position; after a clear the
        # record IDs may restart, so recovery builds a fresh position from what it reads.
        newest = mark if mode == "incremental" else None
        read = 0
        for xml_text in self._reader.query(self._channel, xpath, newest_first=newest_first):
            if read >= max_events:
                if mode == "bootstrap":
                    result.truncated = True
                    log.warning("Security bootstrap capped at %s events (%s)", max_events, group)
                else:
                    result.more_pending = True
                    result.notes.append(
                        f"{group}: more events are waiting; the next scan continues from "
                        f"record {newest.record_id if newest else '?'}."
                    )
                break
            read += 1
            result.records_read += 1
            try:
                event = self._parse(xml_text)
            except EventParseError as exc:
                result.parse_failures += 1
                # Record the category only; never write raw event content to diagnostics.
                log.warning("Skipped unparseable Security record: %s", exc.user_message)
                continue
            if newest is None or event.record_id > newest.record_id:
                newest = Watermark(
                    self._channel, group, signature, event.record_id, event.timestamp
                )
            if self._noise(event):
                result.filtered += 1
                continue
            result.events.append(event)

        if newest is not None:
            result.watermarks[group] = newest


class SecurityCollector(ChannelCollector):
    """The Security log: core events and process creation, each with its own budget."""

    def __init__(self, reader: EventLogReader) -> None:
        super().__init__(
            reader, SECURITY_CHANNEL, EVENT_GROUPS, parse_security_xml, is_routine_noise
        )
