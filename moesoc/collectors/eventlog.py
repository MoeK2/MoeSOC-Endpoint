"""Thin wrapper over the modern Windows Event Log API (EvtQuery/EvtNext/EvtRender).

This module is the *only* place that touches pywin32. Collectors depend on the
``EventLogReader`` protocol, so tests substitute a fake reader that yields XML
strings and never touch the real system.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import Iterator
from typing import Protocol

from moesoc.core.exceptions import (
    ChannelNotFoundError,
    CollectorError,
    LogAccessDeniedError,
    PlatformNotSupportedError,
)

log = logging.getLogger(__name__)

# Win32 error codes we translate into analyst-readable messages.
ERROR_ACCESS_DENIED = 5
ERROR_NO_MORE_ITEMS = 259
ERROR_EVT_INVALID_QUERY = 15001
ERROR_EVT_CHANNEL_NOT_FOUND = 15007

EVTNEXT_BATCH_SIZE = 100
EVTNEXT_TIMEOUT_MS = 5_000


class EventLogReader(Protocol):
    def query(self, channel: str, xpath: str, *, newest_first: bool = False) -> Iterator[str]:
        """Yield rendered event XML strings matching ``xpath`` in ``channel``."""
        ...


def _translate_error(exc: Exception, channel: str) -> CollectorError:
    code = getattr(exc, "winerror", None)
    if code == ERROR_ACCESS_DENIED:
        return LogAccessDeniedError(
            f"Access denied while reading the Windows '{channel}' log. "
            "Run MoeSOC with administrator privileges."
        )
    if code == ERROR_EVT_CHANNEL_NOT_FOUND:
        return ChannelNotFoundError(
            f"The event log channel '{channel}' does not exist on this host."
        )
    if code == ERROR_EVT_INVALID_QUERY:
        return CollectorError(f"Internal error: the query for '{channel}' was rejected by Windows.")
    return CollectorError(f"Unexpected error while reading the '{channel}' log (code {code}).")


class WindowsEventLogReader:
    """Reads events through ``win32evtlog.EvtQuery`` with a server-side XPath filter."""

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise PlatformNotSupportedError(
                "Windows Event Log access is only available on Windows."
            )
        try:
            import pywintypes
            import win32evtlog
        except ImportError as exc:
            raise PlatformNotSupportedError(
                "The pywin32 package is not installed. Run: pip install pywin32"
            ) from exc
        self._evt = win32evtlog
        self._win_error = pywintypes.error

    def query(self, channel: str, xpath: str, *, newest_first: bool = False) -> Iterator[str]:
        evt = self._evt
        direction = evt.EvtQueryReverseDirection if newest_first else evt.EvtQueryForwardDirection
        flags = evt.EvtQueryChannelPath | direction
        try:
            result_set = evt.EvtQuery(channel, flags, xpath, None)
        except self._win_error as exc:
            log.error("EvtQuery failed for channel=%s winerror=%s", channel, exc.winerror)
            raise _translate_error(exc, channel) from exc

        while True:
            try:
                handles = evt.EvtNext(result_set, EVTNEXT_BATCH_SIZE, EVTNEXT_TIMEOUT_MS, 0)
            except self._win_error as exc:
                if exc.winerror == ERROR_NO_MORE_ITEMS:
                    return
                log.error("EvtNext failed for channel=%s winerror=%s", channel, exc.winerror)
                raise _translate_error(exc, channel) from exc
            if not handles:
                return
            for handle in handles:
                try:
                    yield evt.EvtRender(handle, evt.EvtRenderEventXml)
                except self._win_error as exc:
                    # One unrenderable record must not end the scan.
                    log.warning("EvtRender failed for one record (winerror=%s)", exc.winerror)

    def probe_channel(self, channel: str) -> bool:
        """Read at most one event. Returns True if the channel holds events, False if empty.

        Raises LogAccessDeniedError / ChannelNotFoundError / CollectorError.
        """
        return any(True for _ in self.query(channel, "*", newest_first=True))
