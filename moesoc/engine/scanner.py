"""Scan orchestration: collect → normalize → store → detect → correlate → store findings.

Both the CLI and the GUI call this service, so there is exactly one pipeline.
"""

from __future__ import annotations

import logging
import re
import sqlite3
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from moesoc.collectors.defender import DEFENDER_GROUPS, DefenderCollector
from moesoc.collectors.eventlog import EventLogReader, WindowsEventLogReader
from moesoc.collectors.hostinfo import local_domain_aliases, local_standalone_hosts
from moesoc.collectors.powershell import POWERSHELL_GROUPS, PowerShellCollector
from moesoc.collectors.security import (
    EVENT_GROUPS,
    ChannelCollector,
    CollectionResult,
    SecurityCollector,
    group_signature,
    is_routine_noise,
)
from moesoc.collectors.sysmon import SYSMON_GROUPS, SysmonCollector
from moesoc.core.config import AppConfig
from moesoc.core.detection import Detection, RuleMetadata
from moesoc.core.domains import DomainAlias
from moesoc.core.enums import (
    DefenderEventId,
    PowerShellEventId,
    SecurityEventId,
    SysmonEventId,
    TelemetrySource,
)
from moesoc.core.event import NormalizedEvent
from moesoc.core.exceptions import (
    ChannelNotFoundError,
    CollectorError,
    EventParseError,
    MoeSOCError,
)
from moesoc.engine.account_rules import (
    COR_002,
    DET_005,
    DET_006,
    correlate_new_account_to_admin,
    detect_new_user_account,
    detect_privileged_group_addition,
)
from moesoc.engine.context import DetectionContext
from moesoc.engine.correlation import COR_001, correlate_failed_then_success
from moesoc.engine.cross_source import (
    COR_003,
    COR_004,
    correlate_defender_file_source,
    correlate_session_activity,
)
from moesoc.engine.defender_rules import DET_008, detect_defender_detections, detection_key
from moesoc.engine.powershell_rules import DET_007, detect_suspicious_powershell
from moesoc.engine.risk import assess_risk
from moesoc.engine.rules import (
    DET_001,
    DET_002,
    DET_003,
    DET_004,
    detect_low_and_slow_guessing,
    detect_multiple_failed_logins,
    detect_password_spray,
    detect_security_log_cleared,
)
from moesoc.parsers.defender import DEFENDER_CHANNEL
from moesoc.parsers.dispatch import parse_any_xml
from moesoc.parsers.powershell import POWERSHELL_CHANNEL
from moesoc.parsers.security import SECURITY_CHANNEL
from moesoc.parsers.sysmon import SYSMON_CHANNEL
from moesoc.storage.collection_state import CollectionStateRepository, Watermark
from moesoc.storage.database import Database
from moesoc.storage.enrichment import defender_file_context
from moesoc.storage.repository import DetectionRepository, EventRepository, ScanRepository
from moesoc.storage.tuning import (
    TuningRepository,
    effective_rules,
    matching_suppression,
    with_tuning,
)
from moesoc.utils.time import utc_now

log = logging.getLogger(__name__)

COLLECTED_EVENT_IDS = tuple(sorted(int(e) for e in SecurityEventId))
DEFENDER_EVENT_IDS = tuple(sorted(int(e) for e in DefenderEventId))
DEFENDER_PARTNER_LOOKBACK = timedelta(days=7)
# Everything the rules read: Security events, PowerShell 4104, Defender 1116-1119, and
# process-creation events (Sysmon 1) for process context. IDs do not collide across logs.
RULE_INPUT_EVENT_IDS = tuple(
    sorted(
        {
            *COLLECTED_EVENT_IDS,
            int(PowerShellEventId.SCRIPT_BLOCK),
            int(SysmonEventId.PROCESS_CREATE),
            *DEFENDER_EVENT_IDS,
        }
    )
)
_RECORD_ID = re.compile(r"<EventRecordID>(\d+)</EventRecordID>")
_EVENT_BLOCK = re.compile(r"<Event[\s>].*?</Event>", re.DOTALL)
MAX_IMPORT_BYTES = 200_000_000

ProgressCallback = Callable[[str], None]


@dataclass(frozen=True, slots=True)
class LiveBatchResult:
    """Outcome of storing one batch of live events."""

    records: int
    events_new: int
    parse_failures: int
    detections_found: int
    detections_new: int
    detections_suppressed: int = 0


@dataclass(frozen=True, slots=True)
class ScanSummary:
    scan_id: int
    origin: str
    records_read: int
    events_normalized: int
    events_new: int
    parse_failures: int
    detections_found: int
    detections_new: int
    truncated: bool
    duration_seconds: float
    collection_mode: str | None = None  # e.g. "core: incremental, process: bootstrap"
    notes: tuple[str, ...] = ()  # gaps, resets and continuation notices
    detections_suppressed: int = 0  # matched an active suppression; not stored


RuleFunction = Callable[[list[NormalizedEvent], RuleMetadata, DetectionContext], list[Detection]]

# Rule ID → implementation. A rule runs only when its YAML metadata is loaded.
RULE_FUNCTIONS: dict[str, RuleFunction] = {
    DET_001: detect_multiple_failed_logins,
    DET_002: detect_password_spray,
    DET_003: detect_security_log_cleared,
    DET_004: detect_low_and_slow_guessing,
    DET_005: detect_new_user_account,
    DET_006: detect_privileged_group_addition,
    DET_007: detect_suspicious_powershell,
    DET_008: detect_defender_detections,
    COR_001: correlate_failed_then_success,
    COR_002: correlate_new_account_to_admin,
    COR_003: correlate_session_activity,
    COR_004: correlate_defender_file_source,
}


@dataclass(frozen=True, slots=True)
class OptionalSource:
    key: str  # how the scan reports it: "sysmon: not installed"
    label: str
    channel: str
    collector: Callable[[EventLogReader], ChannelCollector]


# Telemetry that may not exist on a machine. The Security log is required.
OPTIONAL_SOURCES = (
    OptionalSource("sysmon", "Sysmon", SYSMON_CHANNEL, SysmonCollector),
    OptionalSource("powershell", "PowerShell", POWERSHELL_CHANNEL, PowerShellCollector),
    OptionalSource("defender", "Microsoft Defender", DEFENDER_CHANNEL, DefenderCollector),
)


def _merge(into: CollectionResult, other: CollectionResult) -> None:
    """Combine a second channel's collection into the scan's result."""
    into.events.extend(other.events)
    into.records_read += other.records_read
    into.parse_failures += other.parse_failures
    into.filtered += other.filtered
    into.truncated = into.truncated or other.truncated
    into.more_pending = into.more_pending or other.more_pending
    into.modes.update(other.modes)
    into.watermarks.update(other.watermarks)
    into.notes.extend(other.notes)


def run_detections(
    events: Iterable[NormalizedEvent],
    rules: dict[str, RuleMetadata],
    known_aliases: Iterable[DomainAlias] = (),
    standalone_hosts: Iterable[str] = (),
) -> list[Detection]:
    """Run every implemented rule whose metadata is loaded, sharing one context."""
    events = list(events)
    context = DetectionContext.from_events(events, known_aliases, rules, standalone_hosts)
    detections: list[Detection] = []
    for rule_id, detect in RULE_FUNCTIONS.items():
        rule = rules.get(rule_id)
        if rule is not None:
            detections += detect(events, rule, context)
    # One explained risk model for every finding (base + documented modifiers).
    return [assess_risk(d) for d in detections]


def load_rule_input(
    conn: sqlite3.Connection,
    start: datetime,
    end: datetime,
    file_window: timedelta = timedelta(minutes=60),
    partner_lookback: timedelta = DEFENDER_PARTNER_LOOKBACK,
) -> list[NormalizedEvent]:
    """Stored events the rules read, plus earlier Defender events of the same detections.

    Defender often records the action (1117) minutes or hours after the detection
    (1116); an incremental scan may contain only one of them. Defender events are
    rare, so the partners are loaded by Detection ID from up to 7 days earlier
    (DET-008 ``partner_lookback_days``).
    """
    repo = EventRepository(conn)
    stored = repo.in_range(start, end, RULE_INPUT_EVENT_IDS)
    wanted = {
        (e.hostname.casefold(), detection_key(e))
        for e in stored
        if e.source is TelemetrySource.DEFENDER
    }
    if not wanted:
        return stored
    earlier = repo.in_range(start - partner_lookback, start, DEFENDER_EVENT_IDS)
    seen = {e.ref for e in stored}
    partners = [
        e
        for e in earlier
        if e.source is TelemetrySource.DEFENDER
        and e.ref not in seen
        and (e.hostname.casefold(), detection_key(e)) in wanted
    ]
    seen |= {e.ref for e in partners}
    # Where did a detected file come from? (Sysmon file, process, DNS, network; COR-004)
    context = [
        e
        for e in defender_file_context(conn, [*partners, *stored], file_window)
        if e.ref not in seen
    ]
    return sorted([*partners, *context, *stored], key=lambda e: (e.timestamp, e.record_id))


# How far back an active campaign is reloaded at most (older parts stay in the stored
# finding: it is still extended, not duplicated, through its campaign key).
CAMPAIGN_RELOAD_LIMIT = timedelta(hours=24)


def _rule_lookback_minutes(rule: RuleMetadata) -> int:
    """How far before a scan's range a rule needs to see events (from its own windows)."""
    p = rule.parameters
    return max(
        int(p.get("window_minutes", 0)),
        int(p.get("failure_window_minutes", 0)) + int(p.get("follow_window_minutes", 0)),
        int(p.get("file_window_minutes", 0)),
    )


def _detection_lookback(rules: dict[str, RuleMetadata]) -> timedelta:
    minutes = [_rule_lookback_minutes(r) for r in rules.values()]
    return timedelta(minutes=max(minutes, default=0))


def _partner_lookback(rules: dict[str, RuleMetadata]) -> timedelta:
    rule = rules.get(DET_008)
    days = int(rule.parameters.get("partner_lookback_days", 7)) if rule else 7
    return timedelta(days=days)


def _file_window(rules: dict[str, RuleMetadata]) -> timedelta:
    rule = rules.get(COR_004)
    minutes = int(rule.parameters.get("file_window_minutes", 60)) if rule else 60
    return timedelta(minutes=minutes)


class ScanService:
    def __init__(
        self,
        config: AppConfig,
        database: Database,
        rules: dict[str, RuleMetadata],
        reader_factory: Callable[[], EventLogReader] = WindowsEventLogReader,
        host_aliases: Callable[[], list[DomainAlias]] = local_domain_aliases,
        standalone_hosts: Callable[[], list[str]] = local_standalone_hosts,
    ) -> None:
        self._config = config
        self._db = database
        self._rules = rules
        self._reader_factory = reader_factory
        self._host_aliases = host_aliases
        self._standalone_hosts = standalone_hosts
        self._positions_before_catch_up: dict[str, int] = {}

    # ------------------------------------------------------------- public API
    def run_live_scan(self, progress: ProgressCallback | None = None) -> ScanSummary:
        """Read the real Windows Security log. Raises MoeSOCError with a readable message."""
        notify = progress or (lambda _msg: None)
        started = time.monotonic()
        scan_id = self._start_scan("live")
        try:
            notify("Reading Windows Security log…")
            with self._db.connect() as conn:
                state = CollectionStateRepository(conn)
                security_marks = state.load(SECURITY_CHANNEL)
                optional_marks = {o.channel: state.load(o.channel) for o in OPTIONAL_SOURCES}
            reader = self._reader_factory()
            budget = self._config.max_events_per_scan
            result = SecurityCollector(reader).collect(
                self._config.lookback_hours, budget, security_marks
            )
            for source in OPTIONAL_SOURCES:
                notify(f"Reading {source.label} log…")
                _merge(
                    result,
                    self._collect_optional(source, reader, budget, optional_marks[source.channel]),
                )
            notify(f"Normalized {len(result.events):,} events. Storing…")
            end = utc_now()
            start = end - timedelta(hours=self._config.lookback_hours)
            if result.events:  # an incremental read may reach further back than the lookback
                start = min(start, min(e.timestamp for e in result.events))
            mode = ", ".join(f"{g}: {m}" for g, m in result.modes.items()) or None
            return self._store_and_detect(
                scan_id=scan_id,
                origin="live",
                events=result.events,
                records_read=result.records_read,
                parse_failures=result.parse_failures,
                truncated=result.truncated,
                detect_range=(start, end),
                started=started,
                notify=notify,
                watermarks=list(result.watermarks.values()),
                collection_mode=mode,
                notes=tuple(result.notes),
                modes=dict(result.modes),
            )
        except MoeSOCError as exc:
            self._fail_scan(scan_id, exc.user_message)
            raise

    def import_xml_file(self, path: Path, progress: ProgressCallback | None = None) -> ScanSummary:
        """Analyze events exported as XML (``wevtutil qe Security /f:xml`` or Event Viewer)."""
        notify = progress or (lambda _msg: None)
        started = time.monotonic()
        scan_id = self._start_scan("import")
        try:
            try:
                if path.stat().st_size > MAX_IMPORT_BYTES:
                    raise MoeSOCError("The XML file is too large to import (limit 200 MB).")
                text = path.read_text(encoding="utf-8-sig", errors="replace")
            except OSError as exc:
                raise MoeSOCError(f"Could not read {path.name}: {exc.strerror}") from exc

            events: list[NormalizedEvent] = []
            failures = 0
            blocks = _EVENT_BLOCK.findall(text)
            for block in blocks:
                try:
                    event = parse_any_xml(block)
                except EventParseError as exc:
                    failures += 1
                    log.warning("Skipped unparseable imported record: %s", exc.user_message)
                    continue
                if not is_routine_noise(event):
                    events.append(event)
            notify(f"Parsed {len(events):,} of {len(blocks):,} records from {path.name}.")
            if events:
                margin = _detection_lookback(self._rules)
                detect_range = (
                    min(e.timestamp for e in events) - margin,
                    max(e.timestamp for e in events) + margin,
                )
            else:
                now = utc_now()
                detect_range = (now, now)
            return self._store_and_detect(
                scan_id=scan_id,
                origin="import",
                events=events,
                records_read=len(blocks),
                parse_failures=failures,
                truncated=False,
                detect_range=detect_range,
                started=started,
                notify=notify,
            )
        except MoeSOCError as exc:
            self._fail_scan(scan_id, exc.user_message)
            raise

    def _collect_optional(
        self,
        source: OptionalSource,
        reader: EventLogReader,
        budget: int,
        marks: dict[str, Watermark],
    ) -> CollectionResult:
        """Optional telemetry: its absence is recorded, never a scan failure."""
        try:
            return source.collector(reader).collect(self._config.lookback_hours, budget, marks)
        except ChannelNotFoundError:
            return CollectionResult(modes={source.key: "not installed"})
        except CollectorError as exc:
            log.warning("%s collection skipped: %s", source.label, exc.user_message)
            return CollectionResult(
                modes={source.key: "unavailable"},
                notes=[f"{source.label} log not collected: {exc.user_message}"],
            )

    # ------------------------------------------------------------- live monitoring
    def remember_positions(self, channels: list[str]) -> None:
        """Before a catch-up: the newest record of each channel right now. A channel with no
        saved position then subscribes after THIS record instead of "from new events", so
        a record written between the catch-up and the subscription is not missed."""
        self._positions_before_catch_up = {}
        try:
            reader = self._reader_factory()
        except MoeSOCError:
            return
        for channel in channels:
            try:
                newest = next(iter(reader.query(channel, "*", newest_first=True)), None)
            except MoeSOCError:
                continue  # absent or unreadable: the subscription reports it
            match = _RECORD_ID.search(newest) if newest else None
            if match:
                self._positions_before_catch_up[channel] = int(match.group(1))

    def subscription_start_record(self, channel: str = SECURITY_CHANNEL) -> int | None:
        """Where a live subscription should start: after the OLDEST group position, so no
        group misses records (records read twice are ignored as duplicates). Without a
        saved position: after the newest record seen before the last catch-up."""
        with self._db.connect() as conn:
            marks = CollectionStateRepository(conn).load(channel)
        records = [m.record_id for m in marks.values()]
        if records:
            return min(records)
        return self._positions_before_catch_up.get(channel)

    def ingest_live(self, xml_records: list[str]) -> LiveBatchResult:
        """Store a batch from the live subscription, detect, and move the positions forward.

        No scan row is written per batch (the monitor's catch-up scan is the scan record);
        findings are upserted by their stable key, so a growing burst updates one finding.
        """
        events: list[NormalizedEvent] = []
        failures = 0
        newest: dict[str, Watermark] = {}
        for xml_text in xml_records:
            try:
                event = parse_any_xml(xml_text)
            except EventParseError as exc:
                failures += 1
                log.warning("Skipped unparseable live record: %s", exc.user_message)
                continue
            groups = {
                SECURITY_CHANNEL: EVENT_GROUPS,
                SYSMON_CHANNEL: SYSMON_GROUPS,
                POWERSHELL_CHANNEL: POWERSHELL_GROUPS,
                DEFENDER_CHANNEL: DEFENDER_GROUPS,
            }.get(event.channel, {})
            for group, ids in groups.items():
                if event.event_id in ids:
                    mark = newest.get(group)
                    if mark is None or event.record_id > mark.record_id:
                        newest[group] = Watermark(
                            event.channel,
                            group,
                            group_signature(ids),
                            event.record_id,
                            event.timestamp,
                        )
            if not is_routine_noise(event):
                events.append(event)

        with self._db.connect() as conn:
            events_new = EventRepository(conn).insert_many(events)
            detections: list[Detection] = []
            detections_new = suppressed = 0
            if events:
                start = min(e.timestamp for e in events)
                detections, detections_new, suppressed = self._detect_and_store(
                    conn, start, utc_now(), None
                )
            state = CollectionStateRepository(conn)
            for mark in newest.values():
                state.save(mark)  # forward only
        return LiveBatchResult(
            records=len(xml_records),
            events_new=events_new,
            parse_failures=failures,
            detections_found=len(detections),
            detections_new=detections_new,
            detections_suppressed=suppressed,
        )

    # ------------------------------------------------------------- internals
    def _detect_and_store(
        self, conn: sqlite3.Connection, start: datetime, end: datetime, scan_id: int | None
    ) -> tuple[list[Detection], int, int]:
        """Run the (tuned) rules over stored events; store findings not suppressed.

        Returns (stored findings, how many are new, how many were suppressed).
        """
        tuning = TuningRepository(conn)
        overrides = tuning.overrides()
        rules = effective_rules(self._rules, overrides)
        # Detect over *stored* events so bursts spanning several scans are still found.
        window = _detection_lookback(rules)
        load_from = start - window
        # A campaign already reported and still active (last seen inside the window) is
        # reloaded from its first event, so a long campaign keeps one stable finding with
        # complete evidence instead of a new finding per sliding window (audit bug A-1).
        campaign_start = DetectionRepository(conn).campaign_reload_start(
            load_from, load_from - CAMPAIGN_RELOAD_LIMIT
        )
        if campaign_start is not None:
            load_from = min(load_from, campaign_start)
        stored = load_rule_input(
            conn, load_from, end, _file_window(rules), _partner_lookback(rules)
        )
        detections = run_detections(stored, rules, self._host_aliases(), self._standalone_hosts())
        suppressions = tuning.suppressions()
        now = utc_now()
        repo = DetectionRepository(conn)
        kept: list[Detection] = []
        new = suppressed = 0
        for detection in detections:
            detection = with_tuning(detection, self._rules.get(detection.rule_id), overrides)
            match = matching_suppression(detection, suppressions, now)
            if match is not None:
                tuning.record_hit(match.id)
                suppressed += 1
                continue
            kept.append(detection)
            new += repo.upsert(detection, scan_id)
        return kept, new, suppressed

    def _start_scan(self, origin: str) -> int:
        with self._db.connect() as conn:
            return ScanRepository(conn).start(origin)

    def _fail_scan(self, scan_id: int, message: str) -> None:
        try:
            with self._db.connect() as conn:
                ScanRepository(conn).finish(scan_id, status="failed", message=message)
        except MoeSOCError:
            log.exception("Could not record scan failure")

    def _store_and_detect(
        self,
        *,
        scan_id: int,
        origin: str,
        events: list[NormalizedEvent],
        records_read: int,
        parse_failures: int,
        truncated: bool,
        detect_range: tuple[datetime, datetime],
        started: float,
        notify: ProgressCallback,
        watermarks: list[Watermark] | None = None,
        collection_mode: str | None = None,
        notes: tuple[str, ...] = (),
        modes: dict[str, str] | None = None,
    ) -> ScanSummary:
        # One transaction: events, detections and the scan record commit together.
        with self._db.connect() as conn:
            events_new = EventRepository(conn).insert_many(events)
            notify(f"Stored {events_new:,} new events. Running detections…")

            start, end = detect_range
            detections, detections_new, suppressed = self._detect_and_store(
                conn, start, end, scan_id
            )
            # The position advances in the same transaction as the events: if storing
            # fails, the next scan reads the same records again. Nothing is skipped.
            state = CollectionStateRepository(conn)
            for mark in watermarks or ():
                reset = (modes or {}).get(mark.group) in ("bootstrap", "recovery")
                state.save(mark, allow_backward=reset)
            messages = list(notes)
            if suppressed:
                messages.append(
                    f"{suppressed} finding(s) matched a suppression and were not stored."
                )
            if truncated:
                messages.insert(0, "Collection capped at the per-scan limit")
            ScanRepository(conn).finish(
                scan_id,
                status="completed",
                records_read=records_read,
                events_new=events_new,
                parse_failures=parse_failures,
                detections_new=detections_new,
                message=" ".join(messages) or None,
                collection_mode=collection_mode,
            )

        summary = ScanSummary(
            scan_id=scan_id,
            origin=origin,
            records_read=records_read,
            events_normalized=len(events),
            events_new=events_new,
            parse_failures=parse_failures,
            detections_found=len(detections),
            detections_new=detections_new,
            truncated=truncated,
            duration_seconds=round(time.monotonic() - started, 2),
            collection_mode=collection_mode,
            notes=notes,
            detections_suppressed=suppressed,
        )
        log.info(
            "Scan %s (%s) completed: %s read, %s new events, %s detections (%s new)",
            scan_id,
            origin,
            records_read,
            events_new,
            len(detections),
            detections_new,
        )
        return summary
