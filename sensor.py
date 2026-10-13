"""MoeSOC Sensor: Windows service entry point and management commands.

Without arguments the Service Control Manager is starting the service. With a command
it manages the service (see ``moesoc/sensor/manage.py``):

    python sensor.py install | uninstall | start | stop | restart | status | run
"""

from __future__ import annotations

import sys
from pathlib import Path

# The service starts in C:\Windows\System32: make the project importable explicitly.
sys.path.insert(0, str(Path(__file__).resolve().parent))


def main() -> int:
    if len(sys.argv) == 1:
        from moesoc.sensor.service import dispatch

        try:
            dispatch()
        except Exception as exc:  # started by hand, not by the Service Control Manager
            if getattr(exc, "winerror", None) != 1063:
                raise
            print(__doc__)
            return 2
        return 0
    from moesoc.sensor.manage import main as manage

    return manage(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
