"""Start the tray when the user signs in (per user, no administrator rights).

Uses the standard ``HKCU\\...\\CurrentVersion\\Run`` value. The full console is never put
into start-up; only the small tray process is.
"""

from __future__ import annotations

import contextlib
import subprocess
import sys
from pathlib import Path

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE_NAME = "MoeSOC Tray"


def tray_command() -> str:
    """The command line that starts the tray (packaged exe, or pythonw + tray.py)."""
    if getattr(sys, "frozen", False):
        exe = Path(sys.executable).with_name("MoeSOCTray.exe")
        return subprocess.list2cmdline([str(exe)])
    root = Path(__file__).resolve().parents[2]
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    interpreter = pythonw if pythonw.exists() else Path(sys.executable)
    return subprocess.list2cmdline([str(interpreter), str(root / "tray.py")])


def is_enabled() -> bool:
    if sys.platform != "win32":
        return False
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            winreg.QueryValueEx(key, VALUE_NAME)
            return True
    except OSError:
        return False


def set_enabled(enabled: bool, command: str | None = None) -> None:
    if sys.platform != "win32":
        return
    import winreg

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
        if enabled:
            winreg.SetValueEx(key, VALUE_NAME, 0, winreg.REG_SZ, command or tray_command())
        else:
            with contextlib.suppress(FileNotFoundError):
                winreg.DeleteValue(key, VALUE_NAME)
