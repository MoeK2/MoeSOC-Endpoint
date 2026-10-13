"""MoeSOC Tray process: a notification-area icon drawn with plain Win32 (pywin32).

No Qt and no detection code is loaded, which keeps this process small. Toasts are the
notification-area balloons (``Shell_NotifyIcon`` + ``NIF_INFO``), which Windows 10/11
shows as toast notifications; clicking one while it is visible opens that finding.
A background thread long-polls the sensor over the local pipe and hands results to the
window thread through a queue and a posted message (no busy waiting).
"""

from __future__ import annotations

import logging
import queue
import subprocess
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from moesoc.core.config import AppConfig
from moesoc.sensor.ipc import SensorClient, SensorUnavailable
from moesoc.tray import autostart
from moesoc.tray.controller import MenuItem, TrayController
from moesoc.utils.logging import configure_logging

log = logging.getLogger(__name__)

MUTEX_NAME = "Local\\MoeSOC-Tray"
WAIT_SECONDS = 30
RETRY_SECONDS = (5, 10, 30, 60)
WM_TRAY = 0x0400 + 20  # WM_USER + 20
WM_QUEUE = 0x8000 + 1  # WM_APP + 1
NIN_BALLOONUSERCLICK = 0x0405
ASFW_ANY = -1


# ---------------------------------------------------------------------- poller
class Poller(threading.Thread):
    """Status + notification long poll. Puts (kind, payload) tuples on ``out``."""

    def __init__(self, client: SensorClient, out: Callable[[str, Any], None]) -> None:
        super().__init__(name="moesoc-tray-poll", daemon=True)
        self._client = client
        self._out = out
        self.stop_event = threading.Event()

    def run(self) -> None:
        instance: str | None = None
        seq = 0
        failures = 0
        while not self.stop_event.is_set():
            try:
                if instance is None:
                    status = self._client.call("status")["status"]
                    instance, seq = status["instance"], int(status["seq"])
                    self._out("status", status)
                    self._out("prefs", self._client.call("get_prefs").get("prefs", {}))
                reply = self._client.call(
                    "wait_notifications",
                    timeout=WAIT_SECONDS + 10,
                    after=seq,
                    instance=instance,
                    wait=WAIT_SECONDS,
                )
                failures = 0
                if reply.get("instance") != instance:
                    instance = None  # the sensor restarted: resync on the next loop
                    continue
                seq = int(reply.get("seq", seq))
                if reply.get("items"):
                    self._out("notifications", reply["items"])
                    self._out("status", self._client.call("status")["status"])
                elif reply.get("state"):
                    self._out("state", reply["state"])
            except (SensorUnavailable, KeyError, TypeError, ValueError) as exc:
                instance = None
                self._out("offline", str(exc))
                delay = RETRY_SECONDS[min(failures, len(RETRY_SECONDS) - 1)]
                failures += 1
                self.stop_event.wait(delay)


# ---------------------------------------------------------------------- console launch
def console_command(finding: int | None) -> list[str]:
    if getattr(sys, "frozen", False):
        command = [str(Path(sys.executable).with_name("MoeSOC.exe"))]
    else:
        root = Path(__file__).resolve().parents[2]
        pythonw = Path(sys.executable).with_name("pythonw.exe")
        interpreter = pythonw if pythonw.exists() else Path(sys.executable)
        command = [str(interpreter), str(root / "app.py")]
    if finding is not None:
        command += ["--finding", str(int(finding))]
    return command


def open_console(finding: int | None) -> None:
    """Start the console (or let the running one show the finding). Fixed command, no shell."""
    if sys.platform == "win32":
        import ctypes

        # We were just clicked: let the console (or the instance it hands over to) come
        # to the front instead of only flashing in the taskbar.
        ctypes.windll.user32.AllowSetForegroundWindow(ASFW_ANY)
    try:
        subprocess.Popen(console_command(finding), close_fds=True)  # noqa: S603
    except OSError as exc:
        log.error("Could not start the MoeSOC console: %s", exc)


# ---------------------------------------------------------------------- Win32 shell
class Win32Shell:
    def __init__(self, icon_path: Path) -> None:
        import win32api
        import win32con
        import win32gui

        self._gui, self._con = win32gui, win32con
        self.controller: TrayController | None = None
        self.inbox: queue.Queue[tuple[str, Any]] = queue.Queue(maxsize=100)
        self._taskbar_created = win32gui.RegisterWindowMessage("TaskbarCreated")
        message_map = {
            self._taskbar_created: self._on_taskbar_created,
            win32con.WM_DESTROY: self._on_destroy,
            win32con.WM_COMMAND: self._on_command,
            WM_TRAY: self._on_tray,
            WM_QUEUE: self._on_queue,
        }
        wc = win32gui.WNDCLASS()
        wc.hInstance = win32api.GetModuleHandle(None)
        wc.lpszClassName = "MoeSOCTrayWindow"
        wc.lpfnWndProc = message_map
        atom = win32gui.RegisterClass(wc)
        self.hwnd = win32gui.CreateWindow(
            atom, "MoeSOC Tray", win32con.WS_OVERLAPPED, 0, 0, 0, 0, 0, 0, wc.hInstance, None
        )
        self._app_icon = self._load_icon(icon_path)
        self._warning_icon = win32gui.LoadIcon(0, win32con.IDI_WARNING)
        self._icon = self._app_icon
        self._tooltip = "MoeSOC Endpoint\nStarting"
        win32gui.Shell_NotifyIcon(win32gui.NIM_ADD, self._nid())

    def _load_icon(self, path: Path) -> Any:
        gui, con = self._gui, self._con
        try:
            return gui.LoadImage(
                0, str(path), con.IMAGE_ICON, 0, 0, con.LR_LOADFROMFILE | con.LR_DEFAULTSIZE
            )
        except Exception:
            return gui.LoadIcon(0, con.IDI_APPLICATION)

    def _nid(self, *extra: Any) -> tuple[Any, ...]:
        gui = self._gui
        flags = gui.NIF_ICON | gui.NIF_MESSAGE | gui.NIF_TIP
        if extra:
            flags |= gui.NIF_INFO
        return (self.hwnd, 0, flags, WM_TRAY, self._icon, self._tooltip[:127], *extra)

    # Shell protocol (called on the window thread)
    def set_state(self, state: str, tooltip: str) -> None:
        self._tooltip = tooltip
        self._icon = (
            self._warning_icon if state in ("OFFLINE", "LIMITED", "ERROR") else self._app_icon
        )
        self._gui.Shell_NotifyIcon(self._gui.NIM_MODIFY, self._nid())

    def toast(self, title: str, body: str, important: bool) -> None:
        flags = 0x2 if important else 0x1  # NIIF_WARNING / NIIF_INFO, never "error"
        self._gui.Shell_NotifyIcon(
            self._gui.NIM_MODIFY, self._nid(body[:255], 10_000, title[:63], flags)
        )

    def info(self, title: str, body: str) -> None:
        self._gui.Shell_NotifyIcon(
            self._gui.NIM_MODIFY, self._nid(body[:255], 5_000, title[:63], 0x1 | 0x10)
        )  # NIIF_INFO | NIIF_NOSOUND

    def quit(self) -> None:
        self._gui.DestroyWindow(self.hwnd)

    def post(self, kind: str, payload: Any) -> None:
        """From the poller thread: queue and wake the window thread."""
        try:
            self.inbox.put_nowait((kind, payload))
        except queue.Full:
            log.warning("Tray inbox full; dropping a %s update", kind)
            return
        self._gui.PostMessage(self.hwnd, WM_QUEUE, 0, 0)

    # window procedure handlers
    def _on_queue(self, *_args: Any) -> int:
        controller = self.controller
        while controller is not None:
            try:
                kind, payload = self.inbox.get_nowait()
            except queue.Empty:
                break
            handler = {
                "status": controller.on_status,
                "state": controller.on_state,
                "offline": controller.on_offline,
                "prefs": controller.on_prefs,
                "notifications": controller.on_notifications,
            }.get(kind)
            if handler is not None:
                handler(payload)
        return 0

    def _on_tray(self, _hwnd: int, _msg: int, _wparam: int, lparam: int) -> int:
        con = self._con
        if self.controller is None:
            return 0
        if lparam == NIN_BALLOONUSERCLICK:
            self.controller.on_toast_clicked()
        elif lparam == con.WM_LBUTTONDBLCLK:
            self.controller.on_icon_activated()
        elif lparam in (con.WM_RBUTTONUP, con.WM_LBUTTONUP):
            self._show_menu(self.controller.menu())
        return 0

    def _show_menu(self, items: list[MenuItem]) -> None:
        gui, con = self._gui, self._con
        menu = self._build_menu(items)
        x, y = gui.GetCursorPos()
        gui.SetForegroundWindow(self.hwnd)
        gui.TrackPopupMenu(menu, con.TPM_LEFTALIGN, x, y, 0, self.hwnd, None)
        gui.PostMessage(self.hwnd, con.WM_NULL, 0, 0)
        gui.DestroyMenu(menu)

    def _build_menu(self, items: list[MenuItem] | tuple[MenuItem, ...]) -> Any:
        gui, con = self._gui, self._con
        menu = gui.CreatePopupMenu()
        for item in items:
            if item.separator_before:
                gui.AppendMenu(menu, con.MF_SEPARATOR, 0, "")
            flags = con.MF_STRING
            if not item.enabled:
                flags |= con.MF_GRAYED
            if item.checked:
                flags |= con.MF_CHECKED
            if item.children:
                gui.AppendMenu(
                    menu, flags | con.MF_POPUP, self._build_menu(item.children), item.label
                )
            else:
                gui.AppendMenu(menu, flags, item.command, item.label[:80])
        return menu

    def _on_command(self, _hwnd: int, _msg: int, wparam: int, _lparam: int) -> int:
        if self.controller is not None:
            self.controller.command(wparam & 0xFFFF)
        return 0

    def _on_taskbar_created(self, *_args: Any) -> int:  # Explorer restarted
        self._gui.Shell_NotifyIcon(self._gui.NIM_ADD, self._nid())
        return 0

    def _on_destroy(self, *_args: Any) -> int:
        self._gui.Shell_NotifyIcon(self._gui.NIM_DELETE, (self.hwnd, 0))
        self._gui.PostQuitMessage(0)
        return 0


def main() -> int:
    if sys.platform != "win32":
        print("The MoeSOC tray runs on Windows only.")
        return 1
    import win32api
    import win32event
    import win32gui
    import winerror

    config = AppConfig.default()
    configure_logging(config.log_dir, filename="tray.log")
    mutex = win32event.CreateMutex(None, False, MUTEX_NAME)
    if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
        return 0  # one tray per user session
    shell = Win32Shell(config.icon_path)
    client = SensorClient()
    shell.controller = TrayController(
        shell, client, open_console, (autostart.is_enabled, autostart.set_enabled)
    )
    poller = Poller(client, shell.post)
    poller.start()
    log.info("Tray started")
    win32gui.PumpMessages()
    poller.stop_event.set()
    log.info("Tray exited (the sensor keeps monitoring)")
    win32api.CloseHandle(mutex)
    return 0
