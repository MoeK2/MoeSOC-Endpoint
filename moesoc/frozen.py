"""Start-up for the packaged executable (PyInstaller): elevation, single instance, self-test.

When MoeSOC runs from source, ``launcher/launch_moesoc.py`` does this work. The packaged
``MoeSOC.exe`` has no separate launcher, so it does the same itself, using the same
Win32 helpers and the same mutex name (the two can never run side by side):

1. ``--self-test``: check the bundle without opening a window, write the result to
   ``%LOCALAPPDATA%\\MoeSOC\\logs\\self-test.txt`` and exit (used by the build script).
2. If MoeSOC is already running: bring it to the front and exit.
3. If not elevated and the MoeSOC Sensor is NOT installed: ask for elevation with the
   standard UAC prompt and exit; the elevated copy continues with ``--elevated`` (never
   asks twice). If the user declines, MoeSOC opens anyway and the Overview says it is
   not elevated. With the sensor installed the console runs as the signed-in user.
4. Hold the single-instance mutex for the lifetime of the process.

The decision logic is a pure function over a small platform protocol, so it is
tested without Windows.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import traceback
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

ELEVATED_FLAG = "--elevated"
FINDING_FLAG = "--finding"
SELF_TEST_FLAG = "--self-test"
SHELLEXECUTE_OK_ABOVE = 32
ALREADY_RUNNING = "MoeSOC Endpoint is already running."

RUN = "run"
EXIT = "exit"
SELF_TEST = "self-test"


class Platform(Protocol):
    def is_admin(self) -> bool: ...
    def message_box(self, text: str, icon: int) -> None: ...
    def elevate(self, executable: Path, arguments: str, working_dir: Path) -> int: ...
    def instance_running(self) -> bool: ...
    def acquire_instance_lock(self) -> Any | None: ...
    def focus_existing_window(self) -> bool: ...


@dataclass
class StartDecision:
    action: str  # RUN, EXIT or SELF_TEST
    reason: str
    lock: Any | None = None  # keep a reference: the mutex lives as long as the process


def decide(
    argv: list[str],
    api: Platform,
    executable: Path,
    info_icon: int = 0x40,
    forward: Callable[[], bool] | None = None,
    ask_elevation: bool = True,
) -> StartDecision:
    """``forward`` hands this start's request (e.g. ``--finding 42``) to an already
    running console; it is tried before focusing that window.

    ``ask_elevation`` is False when the MoeSOC Sensor is installed (B-7): the service
    collects telemetry, the console reads its database without administrator rights and
    saves triage and notes through the sensor, so a normal start (or a notification
    click) never shows a UAC prompt. "Run as administrator" still works for tuning."""
    if SELF_TEST_FLAG in argv:
        return StartDecision(SELF_TEST, "self-test requested")
    if api.instance_running():
        if forward is not None and forward():
            return StartDecision(EXIT, "handed to the running console")
        if not api.focus_existing_window():
            api.message_box(ALREADY_RUNNING, info_icon)
        return StartDecision(EXIT, "already running")
    if ask_elevation and ELEVATED_FLAG not in argv and not api.is_admin():
        arguments = " ".join([ELEVATED_FLAG, *_passthrough(argv)])
        code = api.elevate(executable, arguments, executable.parent)
        if code > SHELLEXECUTE_OK_ABOVE:
            return StartDecision(EXIT, "continuing in the elevated copy")
        # Declined or failed: continue without elevation; the app explains what is limited.
    lock = api.acquire_instance_lock()
    if lock is None:
        if forward is not None and forward():
            return StartDecision(EXIT, "handed to the running console")
        if not api.focus_existing_window():
            api.message_box(ALREADY_RUNNING, info_icon)
        return StartDecision(EXIT, "another instance started at the same time")
    return StartDecision(RUN, "started", lock)


def _passthrough(argv: list[str]) -> list[str]:
    """Arguments the elevated copy needs: only a validated ``--finding <number>``."""
    if FINDING_FLAG in argv:
        index = argv.index(FINDING_FLAG)
        if index + 1 < len(argv) and argv[index + 1].isdigit():
            return [FINDING_FLAG, str(int(argv[index + 1]))]
    return []


def windows_platform() -> Platform:
    """The launcher's Win32 helpers (bundled as module ``launch_moesoc``)."""
    from launch_moesoc import Win32Api  # type: ignore[import-not-found]

    return Win32Api()


# ----------------------------------------------------------------- self-test
@dataclass(frozen=True, slots=True)
class Check:
    name: str
    ok: bool
    detail: str


def run_self_test(checks: list[tuple[str, Callable[[], str]]] | None = None) -> list[Check]:
    results: list[Check] = []
    for name, fn in checks if checks is not None else default_checks():
        try:
            results.append(Check(name, True, fn()))
        except Exception as exc:
            detail = f"{type(exc).__name__}: {exc}"
            results.append(Check(name, False, detail + "\n" + traceback.format_exc(limit=3)))
    return results


def default_checks() -> list[tuple[str, Callable[[], str]]]:
    def version() -> str:
        from moesoc import __version__

        return f"MoeSOC {__version__}, Python {sys.version.split()[0]}, frozen={_frozen()}"

    def rules() -> str:
        from moesoc.core.config import AppConfig
        from moesoc.engine.rules import load_rules

        loaded = load_rules(AppConfig.default().rules_dir)
        if len(loaded) < 10:
            raise RuntimeError(f"only {len(loaded)} rules found")
        return f"{len(loaded)} rules: {', '.join(sorted(loaded))}"

    def database() -> str:
        from moesoc.storage.database import Database

        with tempfile.TemporaryDirectory(prefix="moesoc-selftest-") as folder:
            version = Database(Path(folder) / "t.db").initialize()
        return f"schema v{version}"

    def icon() -> str:
        from moesoc.core.config import AppConfig

        path = AppConfig.default().icon_path
        if not path.exists():
            raise FileNotFoundError(path)
        return f"{path.name}, {path.stat().st_size:,} bytes"

    def windows_api() -> str:
        if sys.platform != "win32":
            return "skipped (not Windows)"
        import win32evtlog  # noqa: F401 - import check only

        return "pywin32 win32evtlog available"

    def gui() -> str:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtWidgets import QApplication

        from moesoc.core.config import AppConfig
        from moesoc.engine.rules import load_rules
        from moesoc.gui.main_window import MainWindow
        from moesoc.storage.database import Database

        app = QApplication.instance() or QApplication([])
        with tempfile.TemporaryDirectory(prefix="moesoc-selftest-") as folder:
            config = AppConfig(data_dir=Path(folder), rules_dir=AppConfig.default().rules_dir)
            database = Database(config.database_path)
            database.initialize()
            window = MainWindow(config, database, load_rules(config.rules_dir))
            pages = len(window._pages)
            window.close()
            app.processEvents()
        return f"main window with {pages} pages built (offscreen)"

    return [
        ("version", version),
        ("rules", rules),
        ("database", database),
        ("icon", icon),
        ("windows api", windows_api),
        ("gui", gui),
    ]


def write_self_test(results: list[Check], log_dir: Path) -> Path:
    log_dir.mkdir(parents=True, exist_ok=True)
    path = log_dir / "self-test.txt"
    lines = [f"{'PASS' if c.ok else 'FAIL'}  {c.name}: {c.detail}" for c in results]
    status = "PASSED" if all(c.ok for c in results) else "FAILED"
    lines.append(f"SELF-TEST: {status}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    (log_dir / "self-test.json").write_text(
        json.dumps([_as_dict(c) for c in results], indent=2), encoding="utf-8"
    )
    return path


def _as_dict(check: Check) -> dict[str, object]:
    return {"name": check.name, "ok": check.ok, "detail": check.detail}


def _frozen() -> bool:
    return bool(getattr(sys, "frozen", False))
