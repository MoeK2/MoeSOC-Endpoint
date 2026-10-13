"""Read-only facts about Sysmon on this computer (never installs or reconfigures it).

Two variants exist and both write to ``Microsoft-Windows-Sysmon/Operational``:

- **Standalone Sysinternals Sysmon**: ``sysmon64 -i`` copies the binary into the
  Windows directory and registers a service (usually ``Sysmon64``, or ``Sysmon``
  for the 32-bit build) plus the ``SysmonDrv`` driver.
- **Built-in Windows Sysmon** (Windows 11 / Server 2025 optional feature "Sysmon",
  disabled by default; enabled with DISM, then ``sysmon -i``). Microsoft states the
  standalone version must be uninstalled first.

The variant is inferred from the service's binary path and labelled as an inference.
"""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass

log = logging.getLogger(__name__)

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SERVICE_CANDIDATES = ("Sysmon64", "Sysmon")
SERVICE_STATES = {1: "stopped", 2: "starting", 3: "stopping", 4: "running"}


@dataclass(frozen=True, slots=True)
class SysmonService:
    name: str
    state: str  # running / stopped / …
    binary_path: str | None
    variant: str  # "standalone (Sysinternals)" / "built-in Windows feature" / "unknown"


def classify_variant(binary_path: str | None, windows_dir: str) -> str:
    """Infer the variant from where the service binary lives."""
    if not binary_path:
        return "unknown"
    path = binary_path.strip().strip('"').replace("/", "\\").casefold()
    win = windows_dir.rstrip("\\").casefold()
    if path.startswith(f"{win}\\system32\\"):
        return "built-in Windows feature"
    if path.startswith(f"{win}\\sysmon"):
        return "standalone (Sysinternals)"
    return "unknown"


def probe_sysmon_service() -> SysmonService | None:
    """The installed Sysmon service, or None (also None off Windows or on any error)."""
    if sys.platform != "win32":
        return None
    try:
        import pywintypes
        import win32service
    except ImportError:
        return None
    windows_dir = os.environ.get("WINDIR", r"C:\Windows")
    try:
        manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
    except pywintypes.error:
        return None
    try:
        for name in SERVICE_CANDIDATES:
            try:
                handle = win32service.OpenService(
                    manager,
                    name,
                    win32service.SERVICE_QUERY_STATUS | win32service.SERVICE_QUERY_CONFIG,
                )
            except pywintypes.error:
                continue
            try:
                status = win32service.QueryServiceStatus(handle)
                config = win32service.QueryServiceConfig(handle)
            except pywintypes.error:
                log.debug("Sysmon service %s found but not readable", name)
                return SysmonService(name, "unknown", None, "unknown")
            finally:
                win32service.CloseServiceHandle(handle)
            binary = config[3] if len(config) > 3 else None
            return SysmonService(
                name,
                SERVICE_STATES.get(status[1], f"state {status[1]}"),
                binary,
                classify_variant(binary, windows_dir),
            )
    finally:
        win32service.CloseServiceHandle(manager)
    return None
