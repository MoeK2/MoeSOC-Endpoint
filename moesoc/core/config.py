"""Application configuration and on-disk locations.

All data stays local. On Windows the default data directory is
``%LOCALAPPDATA%\\MoeSOC``; elsewhere (development/tests) ``~/.moesoc``.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

DEFAULT_LOOKBACK_HOURS = 24
DEFAULT_MAX_EVENTS_PER_SCAN = 50_000


def _project_root() -> Path:
    # PyInstaller unpacks bundled data to sys._MEIPASS.
    bundle_dir = getattr(sys, "_MEIPASS", None)
    if bundle_dir:
        return Path(bundle_dir)
    return Path(__file__).resolve().parents[2]


def default_data_dir() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if sys.platform == "win32" and local_app_data:
        return Path(local_app_data) / "MoeSOC"
    return Path.home() / ".moesoc"


@dataclass(frozen=True, slots=True)
class AppConfig:
    data_dir: Path
    rules_dir: Path
    lookback_hours: int = DEFAULT_LOOKBACK_HOURS
    max_events_per_scan: int = DEFAULT_MAX_EVENTS_PER_SCAN

    @property
    def database_path(self) -> Path:
        return self.data_dir / "moesoc.db"

    @property
    def icon_path(self) -> Path:
        return _project_root() / "assets" / "icons" / "MoeSOC.ico"

    @property
    def log_dir(self) -> Path:
        return self.data_dir / "logs"

    @classmethod
    def default(cls, data_dir: Path | None = None) -> AppConfig:
        return cls(
            data_dir=data_dir or default_data_dir(),
            rules_dir=_project_root() / "rules",
        )
