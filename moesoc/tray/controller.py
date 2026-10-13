"""Tray behaviour without Win32: what to show, which menu, what a click does.

The Win32 shell (``app.py``) draws the icon, menu and toasts; the poller feeds sensor
replies in; this class decides. It never runs detection logic and never stops the
sensor: "Exit Tray" closes only the tray, "Pause notifications" pauses only toasts.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Protocol

from moesoc.sensor.ipc import SensorUnavailable
from moesoc.storage.repository import from_db_time, to_db_time
from moesoc.utils.time import utc_now

log = logging.getLogger(__name__)

OFFLINE = "OFFLINE"
STATE_LABELS = {
    "MONITORING": "Monitoring",
    "ATTENTION": "Attention required",
    "LIMITED": "Limited telemetry",
    "STARTING": "Starting",
    "ERROR": "Sensor error (not monitoring)",
    OFFLINE: "Sensor offline",
}
PAUSE_HOURS = 1

# Menu command ids
OPEN, RECENT, SCAN, PAUSE, MEDIUM, HIGH, CRITICAL, AUTOSTART, EXIT, STATUS = range(1, 11)


class Shell(Protocol):
    def set_state(self, state: str, tooltip: str) -> None: ...
    def toast(self, title: str, body: str, important: bool) -> None: ...
    def info(self, title: str, body: str) -> None: ...
    def quit(self) -> None: ...


class Client(Protocol):
    def call(self, cmd: str, timeout: float = 5.0, **fields: Any) -> dict[str, Any]: ...


@dataclass(frozen=True, slots=True)
class MenuItem:
    command: int
    label: str
    enabled: bool = True
    checked: bool = False
    children: tuple[MenuItem, ...] = ()
    separator_before: bool = False


class TrayController:
    def __init__(
        self,
        shell: Shell,
        client: Client,
        open_console: Callable[[int | None], None],
        autostart: tuple[Callable[[], bool], Callable[[bool], None]] | None = None,
    ) -> None:
        self._shell = shell
        self._client = client
        self._open_console = open_console
        self._autostart = autostart
        self.state = OFFLINE
        self.status: dict[str, Any] = {}
        self.prefs: dict[str, Any] = {}
        self.last_finding: dict[str, Any] | None = None
        self.toast_finding: int | None = None  # what a click on the current toast opens

    # ------------------------------------------------------------- sensor input
    def on_status(self, status: dict[str, Any]) -> None:
        self.status = status
        if status.get("last_finding"):
            self.last_finding = status["last_finding"]
        self._set_state(str(status.get("state", "LIMITED")), status.get("last_error"))

    def on_state(self, state: str) -> None:
        self._set_state(state)

    def on_offline(self, reason: str) -> None:
        if self.state != OFFLINE:
            log.info("Sensor offline: %s", reason)
        self._set_state(OFFLINE)

    def on_prefs(self, prefs: dict[str, Any]) -> None:
        self.prefs = prefs

    def on_notifications(self, items: list[dict[str, Any]]) -> None:
        for item in items:
            if item.get("detection_id") is not None:
                self.last_finding = item
            if item.get("silent"):
                continue  # paused: recorded (Recent finding), not shown
            self.toast_finding = item.get("detection_id")
            self._shell.toast(
                str(item.get("title", "MoeSOC finding")),
                str(item.get("body", "")),
                important=item.get("severity") == "CRITICAL",
            )

    def _set_state(self, state: str, reason: object = None) -> None:
        if self.state == OFFLINE and state != OFFLINE:  # also after a sensor restart
            log.info("Sensor connected: %s", state)
        self.state = state
        label = STATE_LABELS.get(state, state)
        tooltip = f"MoeSOC Endpoint\n{label}"
        if reason and state in ("ERROR", "LIMITED"):
            tooltip += f"\n{str(reason)[:80]}"
        self._shell.set_state(state, tooltip)

    # ------------------------------------------------------------- user input
    def on_toast_clicked(self) -> None:
        self._open_console(self.toast_finding)

    def on_icon_activated(self) -> None:
        self._open_console(None)

    def menu(self) -> list[MenuItem]:
        recent = self.last_finding
        recent_label = (
            f"Recent: {recent.get('title')} ({recent.get('severity')})"
            if recent
            else "Recent finding: none"
        )
        paused = self._paused()
        online = self.state != OFFLINE
        prefs = self.prefs
        settings = (
            MenuItem(MEDIUM, "Notify on MEDIUM", online, bool(prefs.get("medium"))),
            MenuItem(HIGH, "Notify on HIGH", online, bool(prefs.get("high", True))),
            MenuItem(CRITICAL, "Notify on CRITICAL", online, bool(prefs.get("critical", True))),
            MenuItem(
                AUTOSTART,
                "Start tray when I sign in",
                self._autostart is not None,
                bool(self._autostart and self._autostart[0]()),
                separator_before=True,
            ),
        )
        return [
            MenuItem(OPEN, "Open MoeSOC"),
            MenuItem(STATUS, f"Status: {STATE_LABELS.get(self.state, self.state)}", False),
            MenuItem(RECENT, recent_label, recent is not None),
            MenuItem(SCAN, "Run Scan", online, separator_before=True),
            MenuItem(
                PAUSE,
                "Resume notifications" if paused else f"Pause notifications ({PAUSE_HOURS} h)",
                online,
                paused,
            ),
            MenuItem(0, "Notification settings", True, children=settings),
            MenuItem(EXIT, "Exit Tray (monitoring continues)", separator_before=True),
        ]

    def command(self, command: int) -> None:
        try:
            self._command(command)
        except SensorUnavailable as exc:
            self.on_offline(str(exc))
            self._shell.info("MoeSOC Sensor", "The sensor is not reachable right now.")

    def _command(self, command: int) -> None:
        if command == OPEN:
            self._open_console(None)
        elif command == RECENT and self.last_finding:
            self._open_console(self.last_finding.get("detection_id"))
        elif command == SCAN:
            reply = self._client.call("scan")
            self._shell.info("MoeSOC Sensor", str(reply.get("message", "")))
        elif command == PAUSE:
            until = None if self._paused() else to_db_time(utc_now() + timedelta(hours=PAUSE_HOURS))
            self._set_prefs(paused_until=until)
        elif command in (MEDIUM, HIGH, CRITICAL):
            key = {MEDIUM: "medium", HIGH: "high", CRITICAL: "critical"}[command]
            default = command != MEDIUM
            self._set_prefs(**{key: not bool(self.prefs.get(key, default))})
        elif command == AUTOSTART and self._autostart is not None:
            is_on, set_on = self._autostart
            set_on(not is_on())
        elif command == EXIT:
            self._shell.quit()

    def _set_prefs(self, **changes: Any) -> None:
        prefs = {
            k: v
            for k, v in {**self.prefs, **changes}.items()
            if k in ("medium", "high", "critical", "cooldown_minutes", "paused_until")
        }
        reply = self._client.call("set_prefs", prefs=prefs)
        if reply.get("ok"):
            self.prefs = reply["prefs"]
        else:
            self._shell.info("MoeSOC Sensor", str(reply.get("error", "Not saved")))

    def _paused(self) -> bool:
        until = self.prefs.get("paused_until")
        try:
            return bool(until) and from_db_time(str(until)) > utc_now()
        except ValueError:
            return False
