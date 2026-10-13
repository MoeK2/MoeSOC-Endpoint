"""Where the sensor keeps its state, and which database the console opens.

The service runs as a privileged account. It must only write inside a folder that
ordinary users cannot modify: a privileged process writing into a user-writable folder
(for example ``%LOCALAPPDATA%``) can be redirected with junctions or links into
overwriting system files. So the sensor owns ``%ProgramData%\\MoeSOC`` (its access list
is set at the explicit install step: SYSTEM, Administrators and the service account
write; users read).

Existing per-user data in ``%LOCALAPPDATA%\\MoeSOC`` is never moved automatically; the
explicit ``import-user-data`` command copies it (see ``moesoc.sensor.manage``).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from moesoc.core.config import default_data_dir

SERVICE_NAME = "MoeSOCSensor"
SERVICE_DISPLAY_NAME = "MoeSOC Endpoint Sensor"
SERVICE_DESCRIPTION = (
    "Watches the Windows Security, Sysmon, PowerShell and Defender logs for MoeSOC "
    "Endpoint and notifies the signed-in user about important findings. Observe-only: "
    "it never changes the system."
)
SERVICE_ACCOUNT = f"NT SERVICE\\{SERVICE_NAME}"
PIPE_NAME = r"\\.\pipe\MoeSOC.Sensor"
MARKER_FILE = "sensor.json"


def machine_root() -> Path:
    """``%ProgramData%\\MoeSOC`` on Windows; a development folder elsewhere."""
    if sys.platform == "win32":
        program_data = os.environ.get("PROGRAMDATA") or r"C:\ProgramData"
        return Path(program_data) / "MoeSOC"
    return Path.home() / ".moesoc-sensor"


def sensor_data_dir() -> Path:
    return machine_root() / "data"


def sensor_log_dir() -> Path:
    return machine_root() / "logs"


def sensor_installed() -> bool:
    """The install step writes a marker; the console then opens the sensor's database."""
    return (machine_root() / MARKER_FILE).is_file()


def console_data_dir() -> Path:
    """The database the console and CLI open by default."""
    return sensor_data_dir() if sensor_installed() else default_data_dir()
