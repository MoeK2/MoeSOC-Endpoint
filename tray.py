"""MoeSOC Tray: status icon and notifications in the signed-in user's session.

pythonw tray.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

if __name__ == "__main__":
    from moesoc.tray.app import main

    sys.exit(main())
