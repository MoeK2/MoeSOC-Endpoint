"""Evidence verification: does a finding's stored evidence still match the Windows log?

For each evidence event of a finding, its own log (Security, Sysmon, PowerShell or
Defender) is queried again for that exact
EventRecordID (server-side XPath, read-only) and the result is compared with what
MoeSOC stored. This proves that a finding points at real Windows events, and shows
when evidence has since rolled out of the log or the log was cleared.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, fields
from enum import StrEnum

from moesoc.collectors.eventlog import EventLogReader
from moesoc.core.event import NormalizedEvent
from moesoc.core.exceptions import ChannelNotFoundError, EventParseError, MoeSOCError
from moesoc.core.identity import short_host
from moesoc.parsers.dispatch import parse_any_xml
from moesoc.storage.event_search import EventFilter, search_events
from moesoc.storage.repository import DetectionRepository

log = logging.getLogger(__name__)


class EvidenceStatus(StrEnum):
    VERIFIED = "verified"  # same record ID, event ID and timestamp found in the live log
    MISSING = "missing"  # no longer in the log (rolled over, cleared, or another host)
    MISMATCH = "mismatch"  # a record with this ID exists but differs from the stored one
    NOT_LOCAL = "not_local"  # stored from another computer (e.g. an imported export)
    UNREADABLE = "unreadable"  # the live log or record could not be read or parsed


@dataclass(frozen=True, slots=True)
class EvidenceCheck:
    record_id: int
    event_id: int
    status: EvidenceStatus
    detail: str


def record_xpath(record_id: int) -> str:
    return f"*[System[EventRecordID={int(record_id)}]]"


def canonical_fields(event: NormalizedEvent) -> dict[str, object]:
    """What evidence integrity compares: every normalized field except the raw XML text.

    The live record and the stored record are both normalized by the parser of their own
    channel (``parse_any_xml``), so formatting differences of a re-rendered event (white
    space, attribute order) do not matter, while any change of a value the parser reads
    (account, SID, address, process, path, threat, logon ID, time, event ID…) does.
    """
    return {f.name: getattr(event, f.name) for f in fields(event) if f.name != "raw_xml"}


def _check(event: NormalizedEvent, status: EvidenceStatus, detail: str) -> EvidenceCheck:
    return EvidenceCheck(event.record_id, event.event_id, status, detail)


def verify_event(reader: EventLogReader, event: NormalizedEvent) -> EvidenceCheck:
    """Re-read one stored event from its own channel and compare it. Read-only."""
    try:
        rendered = list(reader.query(event.channel, record_xpath(event.record_id)))
    except ChannelNotFoundError:
        return _check(
            event,
            EvidenceStatus.MISSING,
            f"The {event.channel} log no longer exists on this computer.",
        )
    except MoeSOCError as exc:
        return _check(
            event, EvidenceStatus.UNREADABLE, f"Live log not readable: {exc.user_message}"
        )
    if not rendered:
        return _check(
            event,
            EvidenceStatus.MISSING,
            "Not in the live log (rolled over or cleared since collection).",
        )
    try:
        live = parse_any_xml(rendered[0])
    except EventParseError as exc:
        return _check(
            event,
            EvidenceStatus.UNREADABLE,
            f"Live record could not be parsed: {exc.user_message}",
        )
    if live.channel != event.channel or live.record_id != event.record_id:
        return _check(
            event,
            EvidenceStatus.MISMATCH,
            f"The live answer is record {live.record_id} of {live.channel}, not this record.",
        )
    if (live.event_id, live.timestamp) != (event.event_id, event.timestamp):
        return _check(
            event,
            EvidenceStatus.MISMATCH,
            f"Live record is event {live.event_id} at {live.timestamp.isoformat()}; "
            "the record ID was reused.",
        )
    try:
        stored = parse_any_xml(event.raw_xml)
    except EventParseError:
        stored = event  # no parseable stored copy: compare the stored normalized fields
    expected, actual = canonical_fields(stored), canonical_fields(live)
    changed = sorted(k for k in expected if expected[k] != actual.get(k))
    if changed:
        return _check(
            event,
            EvidenceStatus.MISMATCH,
            f"Same record, different content: {', '.join(changed)}.",
        )
    raw = "raw XML identical" if live.raw_xml == event.raw_xml else "raw XML re-rendered"
    return _check(
        event,
        EvidenceStatus.VERIFIED,
        f"Event {live.event_id} at {live.timestamp.isoformat()} in {live.channel} "
        f"(all normalized fields equal; {raw}).",
    )


def verify_detection_evidence(
    conn, reader: EventLogReader, detection_id: int, local_hostname: str
) -> list[EvidenceCheck]:
    """Compare each stored evidence event with the live log. Read-only.

    Every source (Security, Sysmon, PowerShell, Defender) is re-read from its own channel
    and normalized by its own parser (audit bug A-3: Sysmon, PowerShell and Defender
    evidence was parsed as Security XML and reported as a false "mismatch").
    """
    pks = tuple(DetectionRepository(conn).evidence_event_pks(detection_id))
    if not pks:
        return []
    stored = search_events(conn, EventFilter(event_pks=pks, limit=len(pks), newest_first=False))
    local = (short_host(local_hostname) or "").casefold()
    checks: list[EvidenceCheck] = []
    for item in stored.events:
        event = item.event
        if (short_host(event.hostname) or "").casefold() != local:
            checks.append(
                _check(
                    event,
                    EvidenceStatus.NOT_LOCAL,
                    f"Stored from {event.hostname}; cannot be checked on this computer.",
                )
            )
            continue
        checks.append(verify_event(reader, event))
    log.info("Verified evidence of finding %s: %s events checked", detection_id, len(checks))
    return checks
