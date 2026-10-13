"""Tray behaviour (no Win32) and the console deep link (``--finding``)."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest

from moesoc import frozen
from moesoc.gui.console_link import finding_from_argv, parse_request
from moesoc.sensor.ipc import SensorUnavailable
from moesoc.storage.repository import to_db_time
from moesoc.tray import controller as c
from moesoc.tray.app import console_command
from moesoc.utils.time import utc_now

from .test_frozen import EXE, FakeApi


class Shell:
    def __init__(self) -> None:
        self.toasts: list[tuple[str, str, bool]] = []
        self.infos: list[str] = []
        self.state = ("", "")
        self.quit_called = False

    def set_state(self, state, tooltip):
        self.state = (state, tooltip)

    def toast(self, title, body, important):
        self.toasts.append((title, body, important))

    def info(self, title, body):
        self.infos.append(body)

    def quit(self):
        self.quit_called = True


class Client:
    def __init__(self, fail=False):
        self.calls: list[tuple[str, dict]] = []
        self.fail = fail

    def call(self, cmd, timeout=5.0, **fields):
        if self.fail:
            raise SensorUnavailable("down")
        self.calls.append((cmd, fields))
        if cmd == "set_prefs":
            return {"ok": True, "prefs": fields["prefs"]}
        return {"ok": True, "message": "Catching up on all sources now."}


@pytest.fixture
def tray():
    shell, client, opened = Shell(), Client(), []
    ctl = c.TrayController(shell, client, opened.append)
    return ctl, shell, client, opened


NOTE = {
    "detection_id": 42,
    "rule_id": "COR-001",
    "title": "Failed logons then success",
    "body": "Severity: HIGH · Risk: 70",
    "severity": "HIGH",
    "risk": 70,
    "silent": False,
}


def test_notification_toast_and_click_opens_that_finding(tray):
    ctl, shell, _client, opened = tray
    ctl.on_notifications([NOTE])
    assert shell.toasts == [("Failed logons then success", "Severity: HIGH · Risk: 70", False)]
    ctl.on_toast_clicked()
    assert opened == [42]


def test_silent_notifications_update_recent_finding_without_a_toast(tray):
    ctl, shell, _client, opened = tray
    ctl.on_notifications([{**NOTE, "silent": True}])
    assert shell.toasts == [] and ctl.last_finding["detection_id"] == 42
    ctl.command(c.RECENT)
    assert opened == [42]


def test_status_states_and_tooltips(tray):
    ctl, shell, _client, _opened = tray
    ctl.on_status({"state": "MONITORING", "last_finding": None})
    assert shell.state == ("MONITORING", "MoeSOC Endpoint\nMonitoring")
    ctl.on_offline("pipe closed")
    assert shell.state[0] == c.OFFLINE and "offline" in shell.state[1]
    labels = [i.label for i in ctl.menu()]
    assert "Status: Sensor offline" in labels


def test_menu_has_the_documented_entries(tray):
    ctl, *_ = tray
    ctl.on_status({"state": "MONITORING"})
    labels = [i.label for i in ctl.menu()]
    assert labels[0] == "Open MoeSOC" and labels[-1] == "Exit Tray (monitoring continues)"
    assert "Run Scan" in labels and any(label.startswith("Pause") for label in labels)


def test_exit_tray_never_stops_the_sensor(tray):
    ctl, shell, client, _opened = tray
    ctl.command(c.EXIT)
    assert shell.quit_called and client.calls == []


def test_run_scan_and_pause_go_to_the_sensor(tray):
    ctl, shell, client, _opened = tray
    ctl.on_status({"state": "MONITORING"})
    ctl.command(c.SCAN)
    assert client.calls[0][0] == "scan" and shell.infos
    ctl.command(c.PAUSE)
    cmd, fields = client.calls[1]
    assert cmd == "set_prefs" and fields["prefs"]["paused_until"]
    assert ctl._paused()
    ctl.command(c.PAUSE)  # resume
    assert client.calls[2][1]["prefs"]["paused_until"] is None


def test_toggling_severity_preferences(tray):
    ctl, _shell, client, _opened = tray
    ctl.on_prefs(
        {
            "medium": False,
            "high": True,
            "critical": True,
            "cooldown_minutes": 60,
            "paused_until": None,
        }
    )
    ctl.command(c.MEDIUM)
    assert client.calls[-1][1]["prefs"]["medium"] is True


def test_offline_sensor_is_reported_not_raised():
    shell = Shell()
    ctl = c.TrayController(shell, Client(fail=True), lambda _f: None)
    ctl.command(c.SCAN)
    assert ctl.state == c.OFFLINE and shell.infos


def test_reconnect_after_a_sensor_restart_is_logged(tray, caplog):
    ctl, *_ = tray
    with caplog.at_level("INFO", logger=c.__name__):
        ctl.on_status({"state": "MONITORING"})
        ctl.on_status({"state": "MONITORING"})  # no repeat while connected
        ctl.on_offline("winerror=109")
        ctl.on_status({"state": "MONITORING"})
    messages = [r.getMessage() for r in caplog.records]
    assert messages == [
        "Sensor connected: MONITORING",
        "Sensor offline: winerror=109",
        "Sensor connected: MONITORING",
    ]


def test_expired_pause_is_not_paused(tray):
    ctl, *_ = tray
    ctl.on_prefs({"paused_until": to_db_time(utc_now() - timedelta(minutes=1))})
    assert not ctl._paused()


def test_console_command_carries_only_a_number():
    command = console_command(42)
    assert command[-2:] == ["--finding", "42"] and Path(command[-3]).name == "app.py"
    assert "--finding" not in console_command(None)


# ------------------------------------------------------------------ deep link
@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        ([], (None, None)),
        (["--finding", "7"], (7, None)),
        (["--finding"], (None, "The finding number in the link is not valid.")),
        (["--finding", "abc"], (None, "The finding number in the link is not valid.")),
        (["--finding", "0"], (None, "The finding number in the link is not valid.")),
        (["--finding", "99999999999"], (None, "The finding number in the link is not valid.")),
    ],
)
def test_finding_argument(argv, expected):
    assert finding_from_argv(argv) == expected


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (json.dumps({"cmd": "open", "finding": 5}).encode(), 5),
        (json.dumps({"cmd": "open", "finding": None}).encode(), None),
        (json.dumps({"cmd": "open", "finding": "5"}).encode(), False),
        (json.dumps({"cmd": "open", "finding": True}).encode(), False),
        (json.dumps({"cmd": "run", "finding": 5}).encode(), False),
        (b"x" * 300, False),
        (b"\xff", False),
    ],
)
def test_console_link_requests_are_validated(data, expected):
    assert parse_request(data) == expected


def test_second_start_hands_the_finding_to_the_running_console():
    api = FakeApi(running=True)
    decision = frozen.decide(["--finding", "9"], api, EXE, forward=lambda: True)
    assert decision.action == frozen.EXIT and decision.reason == "handed to the running console"
    assert api.calls == []  # no focus fallback, no message box, no UAC prompt


def test_running_console_without_link_falls_back_to_focus():
    api = FakeApi(running=True)
    decision = frozen.decide([], api, EXE, forward=lambda: False)
    assert decision.reason == "already running"


def test_elevated_copy_receives_the_validated_finding_only():
    api = FakeApi()
    frozen.decide(["--finding", "12", "--evil", "x"], api, EXE)
    assert api.calls == ["elevate:MoeSOC.exe:--elevated --finding 12:MoeSOC"]
    api = FakeApi()
    frozen.decide(["--finding", "12;calc"], api, EXE)
    assert api.calls == ["elevate:MoeSOC.exe:--elevated:MoeSOC"]


def test_sensor_error_state_shows_the_reason(tray):
    ctl, shell, _client, _opened = tray
    ctl.on_status({"state": "ERROR", "last_error": "database: access denied"})
    state, tooltip = shell.state
    assert state == "ERROR" and "not monitoring" in tooltip and "access denied" in tooltip


# ------------------------------------------------------------------ B-3: hand-over
class FakeLocalSocket:
    """QLocalSocket as seen on Windows: a small write completes inside flush(), so
    waitForBytesWritten() returns False although the console received the request."""

    def __init__(self, connect=True, reply=b"ok", wrote=False, chunks=None):
        self.connect, self.wrote = connect, wrote
        self.chunks = list(chunks if chunks is not None else ([reply] if reply else []))
        self.sent = b""
        self.connected = False

    def connectToServer(self, _name):
        self.connected = self.connect

    def waitForConnected(self, _ms):
        return self.connected

    def write(self, data):
        self.sent += data

    def flush(self):
        return True

    def waitForBytesWritten(self, _ms):
        return self.wrote

    def bytesAvailable(self):
        return len(self.chunks[0]) if self.chunks else 0

    def waitForReadyRead(self, _ms):
        return bool(self.chunks)

    def readAll(self):
        return self.chunks.pop(0) if self.chunks else b""

    def state(self):
        return 3 if self.chunks else 0  # Connected while a reply is pending

    def disconnectFromServer(self):
        self.connected = False


def _send(sock, finding=5):
    from moesoc.gui.console_link import send_to_running_console

    return send_to_running_console(finding, timeout_ms=300, socket_factory=lambda: sock)


def test_handover_succeeds_although_wait_for_bytes_written_is_false():
    sock = FakeLocalSocket(reply=b"ok", wrote=False)  # the real Windows behaviour (B-3)
    assert _send(sock, 42) is True
    assert json.loads(sock.sent) == {"cmd": "open", "finding": 42}


def test_rejected_request_still_counts_as_handled_no_second_console():
    assert _send(FakeLocalSocket(reply=b"invalid")) is True


def test_no_running_console_means_start_a_new_one():
    assert _send(FakeLocalSocket(connect=False)) is False


def test_console_shutting_down_without_reply_means_start_a_new_one():
    assert _send(FakeLocalSocket(reply=b"")) is False


def test_reply_split_across_reads_is_assembled():
    assert _send(FakeLocalSocket(chunks=[b"o", b"k"])) is True


@pytest.mark.parametrize(
    ("data", "complete"),
    [(b'{"cmd": "open"', False), (b'{"cmd": "open", "finding": 1}', True), (b"x" * 300, True)],
)
def test_server_waits_for_a_complete_request(data, complete):
    from moesoc.gui.console_link import request_complete

    assert request_complete(data) is complete


def test_frozen_start_retries_the_handover_during_a_startup_race():
    api = FakeApi(running=True)
    tries = iter([False, False, True])
    decision = frozen.decide(
        [], api, EXE, forward=lambda: next(tries) or next(tries) or next(tries)
    )
    assert decision.reason == "handed to the running console"
