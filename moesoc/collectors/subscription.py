"""Live Security log subscription (Windows ``EvtSubscribe``, pull model).

Windows signals a kernel event when new matching records arrive; the monitor thread
blocks on it (no polling loop) and drains the records with ``EvtNext``. The start
position is a bookmark built from MoeSOC's saved EventRecordID, with
``EvtSubscribeStrict`` so a stale bookmark fails loudly instead of silently starting
somewhere else (the monitor then catches up through the incremental collector).

Like ``eventlog.py``, this is the only place that calls pywin32 for subscriptions;
the monitor depends on the ``SubscriptionSource`` protocol so tests never touch Windows.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from moesoc.collectors.eventlog import ERROR_NO_MORE_ITEMS, _translate_error
from moesoc.core.exceptions import ChannelNotFoundError, CollectorError, PlatformNotSupportedError

log = logging.getLogger(__name__)

ERROR_TIMEOUT = 1460
DRAIN_BATCH = 100
# One wait() returns at most this many records; the rest stay in Windows' log (the pull
# model is the backpressure: nothing is buffered in MoeSOC beyond one bounded batch) and
# are read by the next wait() without waiting for a signal.
MAX_DRAIN_RECORDS = 1000
WAIT_TIMEOUT = 258
# winevt.h values, used when an older pywin32 does not export the names.
EVT_SUBSCRIBE_TO_FUTURE = 1
EVT_SUBSCRIBE_START_AFTER_BOOKMARK = 3
EVT_SUBSCRIBE_STRICT = 0x10000
WAIT_OBJECT_0 = 0


def bookmark_xml(channel: str, record_id: int) -> str:
    """The XML a pywin32 bookmark renders to (checked with scripts/check_eventlog_api.py)."""
    return (
        f"<BookmarkList><Bookmark Channel='{channel}' RecordId='{int(record_id)}' "
        "IsCurrent='true'/></BookmarkList>"
    )


class SubscriptionSource(Protocol):
    def open(self, channel: str, xpath: str, after_record: int | None) -> None: ...

    def wait(self, timeout_seconds: float) -> list[str]:
        """Rendered XML of records that arrived (empty on timeout)."""
        ...

    def close(self) -> None: ...


class WindowsSubscriptionSource:
    """Pull subscription: drain on open, then drain each time Windows signals.

    Start-up is deterministic (audit item A-4). Records that already exist after the
    bookmark, for example a record written between the catch-up scan and ``open``, are
    read by the FIRST ``wait`` call without waiting for a signal. Delivery of that backlog
    therefore never depends on whether, or when, Windows sets the signal for records that
    existed before the subscription was created. After that, each ``wait`` blocks on the
    signal (auto-reset) and drains with ``EvtNext`` until no records are left, so records
    that arrive during a drain re-signal and are read by the next ``wait``.

    ``modules`` replaces pywin32 in tests: (win32evtlog, win32event, win32api, error type).
    """

    def __init__(self, modules: tuple[Any, Any, Any, type[Exception]] | None = None) -> None:
        if modules is None:
            if sys.platform != "win32":
                raise PlatformNotSupportedError("Live monitoring is only available on Windows.")
            try:
                import pywintypes
                import win32api
                import win32event
                import win32evtlog
            except ImportError as exc:
                raise PlatformNotSupportedError(
                    "The pywin32 package is not installed. Run: pip install pywin32"
                ) from exc
            modules = (win32evtlog, win32event, win32api, pywintypes.error)
        self._evt, self._event, self._api, self._win_error = modules
        self._signal: Any = None
        self._subscription: Any = None
        self._channel = "Security"
        self._drain_pending = False

    @property
    def signal(self) -> Any:
        """The Windows event this subscription sets when new records arrive."""
        return self._signal

    @property
    def has_pending(self) -> bool:
        """True when records may be readable without waiting for the signal."""
        return self._subscription is not None and self._drain_pending

    def drain(self) -> list[str]:
        """Read what is available now (bounded), without waiting."""
        if self._subscription is None:
            return []
        self._drain_pending = False
        return self._drain()

    def open(self, channel: str, xpath: str, after_record: int | None) -> None:
        evt = self._evt
        self._channel = channel
        self._signal = self._event.CreateEvent(None, False, False, None)  # auto-reset
        try:
            if after_record:
                bookmark = evt.EvtCreateBookmark(bookmark_xml(channel, after_record))
                flags = getattr(
                    evt, "EvtSubscribeStartAfterBookmark", EVT_SUBSCRIBE_START_AFTER_BOOKMARK
                ) | getattr(evt, "EvtSubscribeStrict", EVT_SUBSCRIBE_STRICT)
            else:
                bookmark = None
                flags = getattr(evt, "EvtSubscribeToFutureEvents", EVT_SUBSCRIBE_TO_FUTURE)
            self._subscription = evt.EvtSubscribe(
                channel, flags, SignalEvent=self._signal, Query=xpath, Bookmark=bookmark
            )
        except self._win_error as exc:
            log.error(
                "EvtSubscribe failed for channel=%s winerror=%s",
                channel,
                getattr(exc, "winerror", None),
            )
            self.close()
            raise _translate_error(exc, channel) from exc
        self._drain_pending = True

    def wait(self, timeout_seconds: float) -> list[str]:
        if self._subscription is None:
            return []
        if self._drain_pending:  # backlog after open, or a capped drain: no waiting
            records = self.drain()
            if records:
                return records
        result = self._event.WaitForSingleObject(self._signal, int(timeout_seconds * 1000))
        if result != WAIT_OBJECT_0:
            return []
        return self._drain()

    def _drain(self) -> list[str]:
        records: list[str] = []
        while True:
            if len(records) >= MAX_DRAIN_RECORDS:
                self._drain_pending = True  # more may be waiting: read on the next wait()
                break
            try:
                handles = self._evt.EvtNext(self._subscription, DRAIN_BATCH, 0, 0)
            except self._win_error as exc:
                code = getattr(exc, "winerror", None)
                if code in (ERROR_NO_MORE_ITEMS, ERROR_TIMEOUT):
                    break
                log.error("EvtNext (subscription) failed winerror=%s", code)
                raise _translate_error(exc, self._channel) from exc
            if not handles:
                break
            for handle in handles:
                try:
                    records.append(self._evt.EvtRender(handle, self._evt.EvtRenderEventXml))
                except self._win_error as exc:
                    log.warning(
                        "EvtRender failed for one record (winerror=%s)",
                        getattr(exc, "winerror", None),
                    )
        return records

    def close(self) -> None:
        for handle in (self._subscription,):
            close = getattr(handle, "Close", None)
            if close is not None:
                try:
                    close()
                except self._win_error:
                    log.debug("Subscription handle already closed")
        self._subscription = None
        self._drain_pending = False
        if self._signal is not None:
            try:
                self._api.CloseHandle(self._signal)
            except self._win_error:
                log.debug("Signal handle already closed")
            self._signal = None


@dataclass(frozen=True, slots=True)
class SubscriptionSpec:
    """One channel to subscribe to. ``required`` channels fail the whole start-up;
    optional ones (Sysmon, PowerShell, Defender) are reported unavailable instead."""

    channel: str
    xpath: str
    after_record: int | None
    required: bool = False


class MultiSubscription:
    """Several channel subscriptions behind one blocking ``wait`` (one thread, no polling).

    Each channel is a ``WindowsSubscriptionSource``; the thread blocks on all of their
    signals at once (``WaitForMultipleObjects``) and drains the channel that signalled.
    A channel that cannot be opened is recorded in ``status`` and skipped, so a missing
    optional log never stops monitoring of the others.
    """

    def __init__(
        self,
        source_factory: Callable[[], Any],
        wait_any: Callable[[list[Any], int], int | None] | None = None,
    ) -> None:
        self._factory = source_factory
        self._wait_any = wait_any or _windows_wait_any
        self._sources: list[tuple[str, Any]] = []
        self.status: dict[str, str] = {}

    def open_all(self, specs: list[SubscriptionSpec]) -> dict[str, str]:
        self.close()
        for spec in specs:
            source = self._factory()
            try:
                source.open(spec.channel, spec.xpath, spec.after_record)
            except ChannelNotFoundError:
                self._skip_or_raise(spec, "not installed")
                continue
            except CollectorError as exc:
                self._skip_or_raise(spec, f"unavailable: {exc.user_message}", exc)
                continue
            self._sources.append((spec.channel, source))
            self.status[spec.channel] = "live"
        return dict(self.status)

    def _skip_or_raise(
        self, spec: SubscriptionSpec, reason: str, exc: CollectorError | None = None
    ) -> None:
        if spec.required:
            self.close()
            if exc is not None:
                raise exc
            raise ChannelNotFoundError(f"The {spec.channel} log is not available.")
        log.warning("Live subscription skipped for %s: %s", spec.channel, reason)
        self.status[spec.channel] = reason

    def wait(self, timeout_seconds: float) -> list[str]:
        records: list[str] = []
        for _channel, source in self._sources:
            if source.has_pending:
                records.extend(source.drain())
        if records or not self._sources:
            return records
        index = self._wait_any([s.signal for _c, s in self._sources], int(timeout_seconds * 1000))
        if index is None or not 0 <= index < len(self._sources):
            return []
        return self._sources[index][1].drain()

    def close(self) -> None:
        for _channel, source in self._sources:
            source.close()
        self._sources = []
        self.status = {}


def _windows_wait_any(signals: list[Any], timeout_ms: int) -> int | None:
    import win32event

    result = win32event.WaitForMultipleObjects(signals, False, timeout_ms)
    if WAIT_OBJECT_0 <= result < WAIT_OBJECT_0 + len(signals):
        return result - WAIT_OBJECT_0
    return None
