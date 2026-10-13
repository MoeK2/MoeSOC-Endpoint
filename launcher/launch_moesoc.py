"""MoeSOC Endpoint launcher: elevation, single instance, startup diagnostics.

Started by ``launcher/MoeSOC.vbs`` with ``.venv\\Scripts\\pythonw.exe`` (no console).

    1. Resolve every path from this file's location (never the current directory).
    2. Check that app.py and the virtual environment exist.
    3. If MoeSOC is already running, bring it forward (or say so) and stop.
    4. If not elevated, ask Windows for elevation with the standard UAC prompt
       (ShellExecute "runas") and stop; the elevated copy continues with ``--elevated``.
       That flag prevents an elevation loop: the elevated copy never asks again.
    5. Hold a named mutex while MoeSOC runs (single instance), start app.py with
       pythonw.exe in the project folder, capture its stderr and wait.
    6. If MoeSOC fails to start or exits with an error, write the reason to
       %LOCALAPPDATA%\\MoeSOC\\logs\\launcher.log and show a readable dialog.

Standard library only. The launcher never reads security telemetry and logs only
paths, process IDs, exit codes and error text.
"""

from __future__ import annotations

import contextlib
import ctypes
import ctypes.wintypes
import logging
import os
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Protocol

LAUNCHER_VERSION = "1.0.1"
APP_TITLE = "MoeSOC Endpoint"
ELEVATED_FLAG = "--elevated"
MUTEX_NAME = "Local\\MoeSOC-Endpoint-Instance"
SETUP_HINT = "Run setup before starting MoeSOC:\nscripts\\verify_windows.bat"
STDERR_TAIL_LINES = 40

# Win32 constants
ERROR_ACCESS_DENIED = 5
ERROR_ALREADY_EXISTS = 183
SE_ERR_ACCESSDENIED = 5  # ShellExecute result when the user declines the UAC prompt
SHELLEXECUTE_OK_ABOVE = 32
SW_SHOWNORMAL = 1
ASFW_ANY = 0xFFFFFFFF  # AllowSetForegroundWindow: any process (here: the UAC prompt)
SW_RESTORE = 9
SYNCHRONIZE = 0x00100000
MB_OK = 0x0
MB_ICONERROR = 0x10
MB_ICONINFORMATION = 0x40
MB_TOPMOST = 0x40000

log = logging.getLogger("moesoc.launcher")


# ----------------------------------------------------------------- paths
@dataclass(frozen=True, slots=True)
class Paths:
    project: Path
    app: Path
    pythonw: Path
    launcher_script: Path
    log_dir: Path

    @property
    def log_file(self) -> Path:
        return self.log_dir / "launcher.log"

    @property
    def app_stderr(self) -> Path:
        return self.log_dir / "launcher-app-stderr.log"


def resolve_paths(script: Path, local_appdata: str | None) -> Paths:
    """Everything is derived from the launcher's own location: <project>/launcher/this.py."""
    script = script.resolve()
    project = script.parent.parent
    base = Path(local_appdata) if local_appdata else Path.home() / ".moesoc"
    log_dir = base / "MoeSOC" / "logs" if local_appdata else base / "logs"
    return Paths(
        project=project,
        app=project / "app.py",
        pythonw=project / ".venv" / "Scripts" / "pythonw.exe",
        launcher_script=script,
        log_dir=log_dir,
    )


def preflight(paths: Paths) -> str | None:
    """Return a user-facing problem description, or None when MoeSOC can start."""
    if not paths.pythonw.is_file():
        return f"MoeSOC environment is not installed.\n\n{SETUP_HINT}"
    if not paths.app.is_file():
        return (
            f"MoeSOC could not find app.py in:\n{paths.project}\n\nThe installation is incomplete."
        )
    return None


# ----------------------------------------------------------------- Windows API
class WindowsApi(Protocol):
    def is_admin(self) -> bool: ...
    def message_box(self, text: str, icon: int) -> None: ...
    def elevate(self, executable: Path, arguments: str, working_dir: Path) -> int: ...
    def instance_running(self) -> bool: ...
    def acquire_instance_lock(self) -> Any | None: ...
    def focus_existing_window(self) -> bool: ...


class Win32Api:
    """ctypes calls to user32 / shell32 / kernel32. Only constructed on Windows."""

    def __init__(self) -> None:
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
        self._user32 = ctypes.WinDLL("user32", use_last_error=True)  # type: ignore[attr-defined]
        self._shell32 = ctypes.WinDLL("shell32", use_last_error=True)  # type: ignore[attr-defined]
        w = ctypes.wintypes
        self._shell32.ShellExecuteW.restype = ctypes.c_ssize_t
        self._shell32.ShellExecuteW.argtypes = [
            w.HWND,
            w.LPCWSTR,
            w.LPCWSTR,
            w.LPCWSTR,
            w.LPCWSTR,
            ctypes.c_int,
        ]
        self._user32.GetForegroundWindow.restype = w.HWND
        self._user32.AllowSetForegroundWindow.argtypes = [w.DWORD]
        self._kernel32.CreateMutexW.restype = ctypes.c_void_p
        self._kernel32.OpenMutexW.restype = ctypes.c_void_p

    def is_admin(self) -> bool:
        try:
            return bool(self._shell32.IsUserAnAdmin())
        except OSError:
            return False

    def message_box(self, text: str, icon: int) -> None:
        self._user32.MessageBoxW(None, text, APP_TITLE, MB_OK | icon | MB_TOPMOST)

    def elevate(self, executable: Path, arguments: str, working_dir: Path) -> int:
        """Standard UAC: ShellExecute with the "runas" verb. Returns the ShellExecute code.

        The launcher has no window of its own. Without an owner window Windows can keep
        the consent prompt in the background, where it times out after about two minutes.
        So the window the user just double-clicked in becomes the owner, and the prompt
        is allowed to take the foreground.
        """
        owner = self._user32.GetForegroundWindow()
        self._user32.AllowSetForegroundWindow(ASFW_ANY)
        return int(
            self._shell32.ShellExecuteW(
                owner, "runas", str(executable), arguments, str(working_dir), SW_SHOWNORMAL
            )
        )

    def instance_running(self) -> bool:
        """Check without creating: an elevated owner makes OpenMutex fail with access denied."""
        handle = self._kernel32.OpenMutexW(SYNCHRONIZE, False, MUTEX_NAME)
        if handle:
            self._kernel32.CloseHandle(ctypes.c_void_p(handle))
            return True
        return ctypes.get_last_error() == ERROR_ACCESS_DENIED  # type: ignore[attr-defined]

    def acquire_instance_lock(self) -> Any | None:
        """Create the mutex. Returns None if another instance already holds it."""
        handle = self._kernel32.CreateMutexW(None, True, MUTEX_NAME)
        error = ctypes.get_last_error()  # type: ignore[attr-defined]
        if not handle or error in (ERROR_ALREADY_EXISTS, ERROR_ACCESS_DENIED):
            if handle:
                self._kernel32.CloseHandle(ctypes.c_void_p(handle))
            return None
        return handle  # released automatically when the launcher process exits

    def focus_existing_window(self) -> bool:
        """Bring a visible Qt window titled "MoeSOC Endpoint" to the front."""
        found: list[int] = []
        title_buffer = ctypes.create_unicode_buffer(256)
        class_buffer = ctypes.create_unicode_buffer(256)
        enum_proc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)  # type: ignore[attr-defined]

        def callback(hwnd: int, _lparam: int) -> bool:
            self._user32.GetWindowTextW(ctypes.c_void_p(hwnd), title_buffer, 256)
            self._user32.GetClassNameW(ctypes.c_void_p(hwnd), class_buffer, 256)
            # The class check avoids matching an Explorer window of a folder with this name.
            if title_buffer.value == APP_TITLE and class_buffer.value.startswith("Qt"):
                found.append(hwnd)
                return False
            return True

        self._user32.EnumWindows(enum_proc(callback), None)
        if not found:
            return False
        hwnd = ctypes.c_void_p(found[0])
        self._user32.ShowWindow(hwnd, SW_RESTORE)
        return bool(self._user32.SetForegroundWindow(hwnd))


# ----------------------------------------------------------------- logging
def configure_launcher_log(paths: Paths) -> None:
    try:
        paths.log_dir.mkdir(parents=True, exist_ok=True)
        handler: logging.Handler = RotatingFileHandler(
            paths.log_file, maxBytes=256_000, backupCount=3, encoding="utf-8"
        )
    except OSError:
        handler = logging.NullHandler()  # logging must never stop the launch
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s"))
    log.handlers[:] = [handler]
    log.setLevel(logging.INFO)
    log.propagate = False


def stderr_tail(path: Path, lines: int = STDERR_TAIL_LINES) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return "\n".join(text.strip().splitlines()[-lines:])


def failure_message(paths: Paths, headline: str) -> str:
    return f"{headline}\n\nA diagnostic log was written to:\n{paths.log_file}"


# ----------------------------------------------------------------- main flow
Popen = Callable[..., Any]


def run(argv: list[str], api: WindowsApi, paths: Paths, popen: Popen = subprocess.Popen) -> int:
    elevated_request = ELEVATED_FLAG in argv
    admin = api.is_admin()
    log.info(
        "Launcher %s start | python=%s | project=%s | cwd=%s | admin=%s | relaunched=%s",
        LAUNCHER_VERSION,
        sys.executable,
        paths.project,
        os.getcwd(),
        admin,
        elevated_request,
    )

    problem = preflight(paths)
    if problem:
        log.error("Preflight failed: %s", problem.replace("\n", " "))
        api.message_box(problem, MB_ICONERROR)
        return 1

    if api.instance_running():
        log.info("MoeSOC is already running")
        if not api.focus_existing_window():
            api.message_box("MoeSOC Endpoint is already running.", MB_ICONINFORMATION)
        return 0

    if not admin and not elevated_request:
        code = api.elevate(
            paths.pythonw, f'"{paths.launcher_script}" {ELEVATED_FLAG}', paths.project
        )
        if code > SHELLEXECUTE_OK_ABOVE:
            log.info("Elevation requested through UAC; elevated launcher takes over")
            return 0
        if code != SE_ERR_ACCESSDENIED:
            log.error("Elevation request failed (ShellExecute code %s)", code)
            api.message_box(
                failure_message(paths, "MoeSOC could not request administrator access."),
                MB_ICONERROR,
            )
            return 1
        # Same behaviour as the packaged MoeSOC.exe (audit A-9): a declined prompt still
        # opens MoeSOC, in limited mode; the Overview explains what needs elevation.
        log.info("UAC prompt was declined or timed out; starting with limited access")
    elif not admin:
        # Relaunched but still not elevated (e.g. UAC disabled): never ask again, run limited.
        log.warning("Relaunched without administrator rights; starting with limited access")

    lock = api.acquire_instance_lock()
    if lock is None:
        log.info("Another instance acquired the lock first")
        if not api.focus_existing_window():
            api.message_box("MoeSOC Endpoint is already running.", MB_ICONINFORMATION)
        return 0

    try:
        paths.log_dir.mkdir(parents=True, exist_ok=True)
        with paths.app_stderr.open("w", encoding="utf-8") as stderr_file:
            process = popen(
                [str(paths.pythonw), str(paths.app)],
                cwd=str(paths.project),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=stderr_file,
            )
            log.info("MoeSOC started (pid %s)", getattr(process, "pid", "?"))
            exit_code = process.wait()
    except OSError as exc:
        log.error("MoeSOC could not be started: %s: %s", type(exc).__name__, exc)
        api.message_box(failure_message(paths, "MoeSOC could not start."), MB_ICONERROR)
        return 1

    if exit_code == 0:
        log.info("MoeSOC exited normally")
        return 0
    tail = stderr_tail(paths.app_stderr)
    log.error("MoeSOC exited with code %s. Last error output:\n%s", exit_code, tail or "(none)")
    api.message_box(
        failure_message(
            paths, f"MoeSOC could not start or stopped unexpectedly (code {exit_code})."
        ),
        MB_ICONERROR,
    )
    return exit_code


def main() -> int:
    paths = resolve_paths(Path(__file__), os.environ.get("LOCALAPPDATA"))
    configure_launcher_log(paths)
    try:
        api = Win32Api()
        return run(sys.argv[1:], api, paths)
    except Exception:  # last line of defence: pythonw has no console to show errors
        log.exception("Unexpected launcher error")
        with contextlib.suppress(Exception):  # nothing left to report to
            Win32Api().message_box(failure_message(paths, "MoeSOC could not start."), MB_ICONERROR)
        return 1


if __name__ == "__main__":
    sys.exit(main())
