"""Read-only privilege/environment checks. No elevation tricks, no UAC bypasses."""

from __future__ import annotations

import ctypes
import logging
import platform
import socket
import sys

log = logging.getLogger(__name__)


def is_windows() -> bool:
    return sys.platform == "win32"


def is_admin() -> bool | None:
    """True/False on Windows; None when the question does not apply."""
    if not is_windows():
        return None
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        log.warning("Could not determine administrator status")
        return None


def hostname() -> str:
    return socket.gethostname()


def os_description() -> str:
    return f"{platform.system()} {platform.release()} ({platform.version()})"
