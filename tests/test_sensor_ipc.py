"""Sensor IPC: a small allow-list, strict input checks, and no crash on bad input."""

from __future__ import annotations

import json
import threading
import time

import pytest

from moesoc.sensor.ipc import (
    MAX_MESSAGE_BYTES,
    Dispatcher,
    ProtocolError,
    SensorClient,
    SensorUnavailable,
    decode,
    encode,
    sid_is_service,
)
from moesoc.sensor.notifications import Notification, NotificationHub, NotificationPrefs


class FakeCore:
    def __init__(self) -> None:
        self.instance = "abc"
        self.hub = NotificationHub()
        self.prefs = NotificationPrefs()
        self.scans = 0

    def status(self):
        return {"state": "MONITORING", "seq": self.hub.seq, "instance": self.instance}

    def tray_state(self):
        return "MONITORING"

    def request_scan(self):
        self.scans += 1
        return (self.scans == 1, "ok" if self.scans == 1 else "too soon")

    def get_prefs(self):
        return self.prefs

    def set_prefs(self, prefs):
        self.prefs = prefs


@pytest.fixture
def core():
    return FakeCore()


@pytest.fixture
def dispatcher(core):
    return Dispatcher(core)


def ask(dispatcher, message) -> dict:
    data = message if isinstance(message, bytes) else json.dumps(message).encode()
    return json.loads(dispatcher.handle_bytes(data))


def test_hello_and_status(dispatcher):
    assert ask(dispatcher, {"cmd": "hello"}) == {"ok": True, "protocol": 1, "instance": "abc"}
    assert ask(dispatcher, {"cmd": "status"})["status"]["state"] == "MONITORING"


@pytest.mark.parametrize(
    "bad",
    [
        b"not json",
        b"[1, 2]",
        b"\xff\xfe",
        b'{"cmd": "run_powershell"}',
        b'{"no": "cmd"}',
        b'{"cmd": "delete_file", "path": "C:/x"}',
    ],
)
def test_invalid_or_unknown_requests_get_an_error(dispatcher, bad):
    reply = ask(dispatcher, bad)
    assert reply["ok"] is False and reply["error"]


def test_oversized_message_is_rejected(dispatcher):
    big = json.dumps({"cmd": "status", "pad": "x" * MAX_MESSAGE_BYTES}).encode()
    assert ask(dispatcher, big)["error"] == "message too large"
    with pytest.raises(ProtocolError):
        decode(big)
    with pytest.raises(ProtocolError):
        encode({"pad": "x" * MAX_MESSAGE_BYTES})


def test_internal_errors_never_escape(core, dispatcher):
    core.status = lambda: 1 / 0  # type: ignore[method-assign]
    assert ask(dispatcher, {"cmd": "status"}) == {"ok": False, "error": "internal error"}


def test_manual_scan_request_is_rate_limited_by_the_core(dispatcher, core):
    assert ask(dispatcher, {"cmd": "scan"})["ok"] is True
    assert ask(dispatcher, {"cmd": "scan"}) == {"ok": False, "message": "too soon"}


def test_preferences_are_validated(dispatcher, core):
    assert ask(dispatcher, {"cmd": "get_prefs"})["prefs"]["high"] is True
    reply = ask(dispatcher, {"cmd": "set_prefs", "prefs": {"medium": True}})
    assert reply["ok"] and core.prefs.medium
    for bad in ({"medium": 1}, {"cooldown_minutes": 999999}, "x", None, {"x": 1}):
        reply = ask(dispatcher, {"cmd": "set_prefs", "prefs": bad})
        assert reply["ok"] is False and "invalid preferences" in reply["error"]
    assert core.prefs.medium is True  # unchanged by rejected input


def test_wait_resyncs_after_a_sensor_restart(dispatcher, core):
    core.hub.publish([Notification(1, "COR-001", "t", "b", "HIGH", 70, "new")])
    reply = ask(dispatcher, {"cmd": "wait_notifications", "after": 0, "instance": "old"})
    assert reply == {"ok": True, "instance": "abc", "seq": 1, "items": []}  # no replay


def test_wait_returns_new_notifications(dispatcher, core):
    def later():
        time.sleep(0.1)
        core.hub.publish([Notification(7, "COR-001", "t", "b", "HIGH", 70, "new")])

    threading.Thread(target=later).start()
    reply = ask(dispatcher, {"cmd": "wait_notifications", "after": 0, "instance": "abc", "wait": 5})
    assert reply["seq"] == 1 and reply["items"][0]["detection_id"] == 7
    assert reply["state"] == "MONITORING"


@pytest.mark.parametrize(
    "fields", [{"after": -1}, {"after": "1"}, {"after": True}, {"wait": "long"}, {"wait": -3}]
)
def test_wait_arguments_are_checked(dispatcher, fields):
    reply = ask(dispatcher, {"cmd": "wait_notifications", "instance": "abc", **fields})
    assert reply["ok"] is False


def test_wait_times_out_quietly(dispatcher):
    started = time.monotonic()
    reply = ask(dispatcher, {"cmd": "wait_notifications", "instance": "abc", "wait": 0.2})
    assert reply["items"] == [] and time.monotonic() - started < 2


def test_several_clients_at_once(dispatcher, core):
    replies: list[dict] = []

    def client():
        replies.append(ask(dispatcher, {"cmd": "wait_notifications", "instance": "abc", "wait": 5}))

    threads = [threading.Thread(target=client) for _ in range(3)]
    for t in threads:
        t.start()
    time.sleep(0.1)
    core.hub.publish([Notification(3, "COR-001", "t", "b", "HIGH", 70, "new")])
    for t in threads:
        t.join(5)
    assert len(replies) == 3 and all(r["items"] for r in replies)


def test_client_over_a_transport(dispatcher):
    client = SensorClient(transport=lambda data, _timeout: dispatcher.handle_bytes(data))
    assert client.call("hello")["instance"] == "abc"


def test_client_reports_an_unavailable_sensor():
    def down(_data, _timeout):
        raise SensorUnavailable("not reachable")

    with pytest.raises(SensorUnavailable):
        SensorClient(transport=down).call("status")
    with pytest.raises(SensorUnavailable):
        SensorClient(transport=lambda d, t: b"garbage").call("status")


def test_only_service_accounts_are_trusted_as_the_pipe_server():
    assert sid_is_service("S-1-5-18")
    assert sid_is_service("S-1-5-80-1234-5678")
    assert not sid_is_service("S-1-5-21-111-222-333-1001")  # an ordinary user
    assert not sid_is_service("S-1-5-32-544")


def test_storage_errors_become_readable_replies(dispatcher, core):
    from moesoc.core.exceptions import StorageError

    def unavailable():
        raise StorageError("The sensor database is not available.")

    core.get_prefs = unavailable  # type: ignore[method-assign]
    assert ask(dispatcher, {"cmd": "get_prefs"}) == {
        "ok": False,
        "error": "The sensor database is not available.",
    }


def test_client_asks_only_for_the_rights_users_are_granted():
    """B-6: the client's requested access must be a subset of the INTERACTIVE grant."""
    from moesoc.sensor import ipc

    granted = ipc.FILE_GENERIC_READ | ipc.FILE_WRITE_DATA | ipc.FILE_WRITE_ATTRIBUTES
    assert ipc.CLIENT_ACCESS & ~granted == 0
    assert not ipc.CLIENT_ACCESS & 0x0004  # FILE_CREATE_PIPE_INSTANCE (FILE_APPEND_DATA)
    assert not ipc.CLIENT_ACCESS & 0x40000000  # GENERIC_WRITE


def test_server_trust_falls_back_to_session_zero_for_normal_users(monkeypatch):
    """B-6: a normal user cannot read the service's token; a session-0 server is trusted,
    a server in a user session (a squatter) is not."""
    import sys
    import types

    from moesoc.sensor import ipc

    fake_pipe = types.SimpleNamespace(GetNamedPipeServerProcessId=lambda h: 4242)
    monkeypatch.setitem(sys.modules, "win32pipe", fake_pipe)
    monkeypatch.setattr(ipc, "_process_user_sid_text", lambda pid: None)
    monkeypatch.setattr(ipc, "_server_session", lambda handle: 0)
    assert ipc.server_is_trusted(object()) is True
    monkeypatch.setattr(ipc, "_server_session", lambda handle: 1)
    assert ipc.server_is_trusted(object()) is False
    monkeypatch.setattr(ipc, "_server_session", lambda handle: None)
    assert ipc.server_is_trusted(object()) is False
    monkeypatch.setattr(ipc, "_process_user_sid_text", lambda pid: "S-1-5-21-1-2-3-1001")
    monkeypatch.setattr(ipc, "_server_session", lambda handle: 0)
    assert ipc.server_is_trusted(object()) is False  # readable token wins: a user is a user
    monkeypatch.setattr(ipc, "_process_user_sid_text", lambda pid: "S-1-5-80-1-2")
    assert ipc.server_is_trusted(object()) is True
