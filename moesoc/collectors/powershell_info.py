"""Read-only check of the PowerShell Script Block Logging policy.

MoeSOC never changes this setting. Without the policy, Windows PowerShell 5.1 still
logs script blocks it considers suspicious (Event 4104 at Warning level), so a missing
policy means *partial* visibility, not none.
"""

from __future__ import annotations

import logging
import sys

log = logging.getLogger(__name__)

POLICY_KEY = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
POLICY_VALUE = "EnableScriptBlockLogging"


def script_block_logging_enabled() -> bool | None:
    """True/False from the machine policy; None when it cannot be read (or not Windows)."""
    if sys.platform != "win32":
        return None
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, POLICY_KEY) as key:
            value, _kind = winreg.QueryValueEx(key, POLICY_VALUE)
    except FileNotFoundError:
        return False  # policy not configured
    except OSError as exc:
        log.info("Script Block Logging policy not readable: %s", exc)
        return None
    return value == 1
