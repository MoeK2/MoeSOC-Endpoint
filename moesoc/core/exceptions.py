"""Application exceptions carrying an analyst-readable message.

``user_message`` is safe to display in the GUI/CLI. Technical details belong
in the diagnostic log, not in the message shown to the user.
"""

from __future__ import annotations


class MoeSOCError(Exception):
    def __init__(self, user_message: str) -> None:
        super().__init__(user_message)
        self.user_message = user_message


class EventParseError(MoeSOCError):
    """A single event record could not be parsed. Never fatal to a scan."""


class CollectorError(MoeSOCError):
    """A telemetry source could not be read at all."""


class LogAccessDeniedError(CollectorError):
    """The process lacks rights to read a Windows event channel."""


class ChannelNotFoundError(CollectorError):
    """The event channel does not exist on this host (e.g. Sysmon not installed)."""


class PlatformNotSupportedError(CollectorError):
    """Windows Event Log APIs are not available on this platform."""


class StorageError(MoeSOCError):
    """The local database could not be opened or written."""
