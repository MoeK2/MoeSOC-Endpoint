"""Local IPC between the sensor service and the user's tray / console.

Transport: one Windows named pipe, ``\\\\.\\pipe\\MoeSOC.Sensor``, message mode. There is
no TCP/UDP listener. Remote (SMB) clients are rejected by ``PIPE_REJECT_REMOTE_CLIENTS``
and by an explicit deny entry for the NETWORK logon SID.

Access list of the pipe (set by the service, never inherited):

* SYSTEM, Administrators and the service's own account: full control;
* INTERACTIVE (users signed in at this computer): read, write data, write attributes
  only. They do NOT get ``FILE_CREATE_PIPE_INSTANCE``, so a user process cannot add a
  rogue instance of the pipe while the service is running; the service also creates
  the first instance with ``FILE_FLAG_FIRST_PIPE_INSTANCE`` and refuses to start the IPC
  if someone else already owns the name (squatting). The tray checks that the server
  process runs as the service account before trusting it.

Protocol: one JSON object per message, at most ``MAX_MESSAGE_BYTES``. Requests carry a
``cmd`` from a fixed allow-list; nothing executes commands, touches files, the registry
or processes, and no raw event content is ever sent. Bad input gets an error reply and
is logged; it never stops the sensor.

Writes (B-7): the database folder is read-only for normal users, so a console without
administrator rights sends its two analyst actions here: ``set_triage`` (status or
verdict of an existing finding) and ``add_note``. Both are validated, go through the
same repository code as before, and are logged with the client's process and session.
Suppressions, rule changes and retention are not offered over the pipe: they change what
is detected or kept and need MoeSOC opened as administrator.
"""

from __future__ import annotations

import contextlib
import json
import logging
import threading
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from moesoc.core.enums import TriageStatus
from moesoc.core.exceptions import MoeSOCError
from moesoc.sensor.notifications import NotificationPrefs
from moesoc.sensor.paths import PIPE_NAME

if TYPE_CHECKING:
    from moesoc.sensor.core import SensorCore

log = logging.getLogger(__name__)

MAX_MESSAGE_BYTES = 16 * 1024
PROTOCOL = 1
MAX_WAIT_SECONDS = 30.0
MAX_CLIENTS = 4
COMMANDS = (
    "hello",
    "status",
    "wait_notifications",
    "scan",
    "get_prefs",
    "set_prefs",
    "set_triage",  # analyst actions of a console that may only read the database (B-7)
    "add_note",
)


class ProtocolError(ValueError):
    """A request that is not valid; answered with an error, never fatal."""


def encode(message: dict[str, Any]) -> bytes:
    data = json.dumps(message, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(data) > MAX_MESSAGE_BYTES:
        raise ProtocolError("message too large")
    return data


def decode(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_MESSAGE_BYTES:
        raise ProtocolError("message too large")
    try:
        message = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("not a JSON message") from exc
    if not isinstance(message, dict):
        raise ProtocolError("not a JSON object")
    return message


class Dispatcher:
    """Turns one request into one reply. Pure: no pipes, testable anywhere."""

    def __init__(self, core: SensorCore) -> None:
        self._core = core

    def handle_bytes(self, data: bytes, client: str = "unknown client") -> bytes:
        try:
            reply = self.handle(decode(data), client)
        except ProtocolError as exc:
            reply = {"ok": False, "error": str(exc)}
        except MoeSOCError as exc:  # e.g. preferences while the database is unavailable
            reply = {"ok": False, "error": exc.user_message}
        except Exception:  # thread boundary: a client must never crash the sensor
            log.exception("IPC request failed")
            reply = {"ok": False, "error": "internal error"}
        return encode(reply)

    def handle(self, request: dict[str, Any], client: str = "unknown client") -> dict[str, Any]:
        cmd = request.get("cmd")
        if cmd not in COMMANDS:
            raise ProtocolError("unknown command")
        core = self._core
        if cmd == "hello":
            return {"ok": True, "protocol": PROTOCOL, "instance": core.instance}
        if cmd == "status":
            return {"ok": True, "status": core.status()}
        if cmd == "wait_notifications":
            return self._wait(request)
        if cmd == "scan":
            accepted, message = core.request_scan()
            return {"ok": accepted, "message": message}
        if cmd == "get_prefs":
            return {"ok": True, "prefs": core.get_prefs().to_dict()}
        if cmd == "set_triage":
            status = request.get("status")
            if status not in {s.value for s in TriageStatus}:
                raise ProtocolError("unknown triage status")
            detection_id = _finding_id(request)
            new = core.set_triage(detection_id, TriageStatus(status), client)
            return {"ok": True, "finding": detection_id, "status": new}
        if cmd == "add_note":
            body = request.get("body")
            if not isinstance(body, str):
                raise ProtocolError("note body must be text")
            detection_id = _finding_id(request)
            return {
                "ok": True,
                "finding": detection_id,
                "note": core.add_note(detection_id, body, client),
            }
        try:  # set_prefs
            prefs = NotificationPrefs.from_dict(request.get("prefs"))  # type: ignore[arg-type]
        except (ValueError, TypeError) as exc:
            raise ProtocolError(f"invalid preferences: {exc}") from exc
        core.set_prefs(prefs)
        return {"ok": True, "prefs": prefs.to_dict()}

    def _wait(self, request: dict[str, Any]) -> dict[str, Any]:
        core = self._core
        after, timeout = request.get("after", 0), request.get("wait", MAX_WAIT_SECONDS)
        if isinstance(after, bool) or not isinstance(after, int) or after < 0:
            raise ProtocolError("after must be a non-negative number")
        if isinstance(timeout, bool) or not isinstance(timeout, int | float) or timeout < 0:
            raise ProtocolError("wait must be a non-negative number")
        if request.get("instance") != core.instance:
            # The sensor restarted (sequence numbers reset): resynchronise, no replay.
            return {"ok": True, "instance": core.instance, "seq": core.hub.seq, "items": []}
        items = core.hub.wait_after(after, min(float(timeout), MAX_WAIT_SECONDS))
        return {
            "ok": True,
            "instance": core.instance,
            "seq": max([after, *(n.seq for n in items)]),
            "items": [n.to_dict() for n in items],
            "state": core.tray_state(),
        }


def _finding_id(request: dict[str, Any]) -> int:
    value = request.get("finding")
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value < 2**63:
        raise ProtocolError("finding must be a positive number")
    return value


# ---------------------------------------------------------------------- Windows pipe
class PipeServer:
    """Serves the dispatcher on the named pipe with a few worker threads (blocking I/O)."""

    def __init__(self, dispatcher: Dispatcher, name: str = PIPE_NAME) -> None:
        self._dispatcher = dispatcher
        self._name = name
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._first_created = threading.Event()

    def start(self) -> None:
        for index in range(MAX_CLIENTS):
            thread = threading.Thread(
                target=self._serve, args=(index == 0,), name=f"moesoc-ipc-{index}", daemon=True
            )
            thread.start()
            self._threads.append(thread)
            if index == 0:  # later instances only after the first one owns the name
                self._first_created.wait(5)

    def stop(self) -> None:
        self._stop.set()
        for _ in self._threads:  # wake blocked ConnectNamedPipe calls
            _poke(self._name)
        for thread in self._threads:
            thread.join(5)

    def _serve(self, first: bool) -> None:
        import pywintypes
        import win32file
        import win32pipe

        while not self._stop.is_set():
            try:
                handle = _create_pipe(self._name, first)
            except pywintypes.error as exc:
                log.error(
                    "IPC pipe not created (winerror=%s); is another process using the name?",
                    exc.winerror,
                )
                self._first_created.set()
                return
            first = False
            self._first_created.set()
            try:
                try:
                    win32pipe.ConnectNamedPipe(handle, None)
                except pywintypes.error as exc:
                    if exc.winerror != 535:  # ERROR_PIPE_CONNECTED: client was quicker
                        continue
                if self._stop.is_set():
                    break
                self._session(handle)
            finally:
                with contextlib.suppress(pywintypes.error):
                    win32pipe.DisconnectNamedPipe(handle)
                win32file.CloseHandle(handle)

    def _session(self, handle: Any) -> None:
        import pywintypes
        import win32file

        while not self._stop.is_set():
            try:
                _code, data = win32file.ReadFile(handle, MAX_MESSAGE_BYTES + 1)
            except pywintypes.error as exc:
                if exc.winerror == 234:  # ERROR_MORE_DATA: oversized message, drop client
                    log.warning("IPC: oversized message rejected")
                    win32file.WriteFile(handle, encode({"ok": False, "error": "message too large"}))
                return  # client went away (broken pipe) or similar
            if not data:
                return
            try:
                reply = self._dispatcher.handle_bytes(bytes(data), _describe_client(handle))
                win32file.WriteFile(handle, reply)
            except pywintypes.error:
                return


def _describe_client(handle: Any) -> str:
    """For the sensor log only: which local process sent a request (pid and session)."""
    import pywintypes
    import win32pipe

    try:
        pid = win32pipe.GetNamedPipeClientProcessId(handle)
        session = win32pipe.GetNamedPipeClientSessionId(handle)
    except (pywintypes.error, AttributeError):
        return "unknown client"
    return f"pid {pid}, session {session}"


def _create_pipe(name: str, first: bool) -> Any:
    import win32pipe

    open_mode = win32pipe.PIPE_ACCESS_DUPLEX
    if first:
        open_mode |= 0x00080000  # FILE_FLAG_FIRST_PIPE_INSTANCE: fail if the name is taken
    pipe_mode = (
        win32pipe.PIPE_TYPE_MESSAGE
        | win32pipe.PIPE_READMODE_MESSAGE
        | win32pipe.PIPE_WAIT
        | 0x00000008  # PIPE_REJECT_REMOTE_CLIENTS
    )
    return win32pipe.CreateNamedPipe(
        name,
        open_mode,
        pipe_mode,
        MAX_CLIENTS,
        MAX_MESSAGE_BYTES,
        MAX_MESSAGE_BYTES,
        0,
        pipe_security_attributes(),
    )


def pipe_security_attributes() -> Any:
    """SYSTEM/Administrators full; INTERACTIVE read + write data/attributes; NETWORK denied."""
    import ntsecuritycon as con
    import pywintypes
    import win32security

    def sid(text: str) -> Any:
        return win32security.ConvertStringSidToSid(text)

    dacl = win32security.ACL()
    dacl.AddAccessDeniedAce(win32security.ACL_REVISION, con.GENERIC_ALL, sid("S-1-5-2"))
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.GENERIC_ALL, sid("S-1-5-18"))
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.GENERIC_ALL, sid("S-1-5-32-544"))
    # The service's own account (NT SERVICE\MoeSOCSensor is neither SYSTEM nor an
    # administrator): it must be able to create the further pipe instances and to connect
    # to its own pipe when stopping.
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.GENERIC_ALL, _process_user_sid())
    user_rights = CLIENT_ACCESS  # the same mask the client requests (B-6)
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, user_rights, sid("S-1-5-4"))
    descriptor = win32security.SECURITY_DESCRIPTOR()
    descriptor.SetSecurityDescriptorDacl(1, dacl, 0)
    attributes = pywintypes.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = descriptor
    attributes.bInheritHandle = 0
    return attributes


def _process_user_sid() -> Any:
    import win32api
    import win32security

    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
    return win32security.GetTokenInformation(token, win32security.TokenUser)[0]


def _poke(name: str) -> None:
    """Connect and disconnect once, so a thread blocked in ConnectNamedPipe returns."""
    try:
        import pywintypes
        import win32file
    except ImportError:
        return
    try:
        handle = win32file.CreateFile(
            name, win32file.GENERIC_READ, 0, None, win32file.OPEN_EXISTING, 0, None
        )
        win32file.CloseHandle(handle)
    except pywintypes.error:
        pass


# ---------------------------------------------------------------------- client side
class SensorUnavailable(Exception):
    """The sensor is not running, not installed, or not the genuine service."""


class SensorClient:
    """Request/reply client for the tray and console. ``transport`` is injectable."""

    def __init__(
        self,
        transport: Callable[[bytes, float], bytes] | None = None,
        name: str = PIPE_NAME,
    ) -> None:
        self._transport = transport or (lambda data, t: _pipe_call(name, data, t))

    def call(self, cmd: str, timeout: float = 5.0, **fields: Any) -> dict[str, Any]:
        try:
            reply = decode(self._transport(encode({"cmd": cmd, **fields}), timeout))
        except ProtocolError as exc:
            raise SensorUnavailable(f"invalid reply: {exc}") from exc
        return reply


WRITE_TIMEOUT = 15.0  # the sensor may wait up to 10 s for its database lock


def console_write(cmd: str, client: SensorClient | None = None, **fields: Any) -> dict[str, Any]:
    """A console's analyst action saved by the sensor (B-7). Errors become MoeSOCError
    with a message for the analyst; nothing is written by the console itself."""
    try:
        encode({"cmd": cmd, **fields})
    except ProtocolError as exc:
        raise MoeSOCError("This change is too large to send to the MoeSOC Sensor.") from exc
    try:
        reply = (client or SensorClient()).call(cmd, timeout=WRITE_TIMEOUT, **fields)
    except SensorUnavailable as exc:
        log.warning("Console write %s not delivered: %s", cmd, exc)
        raise MoeSOCError(
            "The MoeSOC Sensor service is not reachable, so the change was not saved. "
            "Your account can only read the sensor's database; start the sensor, or open "
            "MoeSOC as administrator."
        ) from exc
    if not reply.get("ok"):
        raise MoeSOCError(str(reply.get("error") or "The MoeSOC Sensor refused the change."))
    return reply


def _pipe_call(name: str, data: bytes, timeout: float) -> bytes:
    """One request on a fresh connection; the server identity is checked first."""
    try:
        import pywintypes
        import win32file
        import win32pipe
    except ImportError as exc:
        raise SensorUnavailable("pywin32 is not available") from exc
    try:
        win32pipe.WaitNamedPipe(name, int(min(timeout, 5.0) * 1000))
        handle = win32file.CreateFile(
            name,
            CLIENT_ACCESS,
            0,
            None,
            win32file.OPEN_EXISTING,
            0,
            None,
        )
    except pywintypes.error as exc:
        raise SensorUnavailable(f"sensor not reachable (winerror={exc.winerror})") from exc
    try:
        if not server_is_trusted(handle):
            raise SensorUnavailable("the pipe server is not the MoeSOC service")
        win32pipe.SetNamedPipeHandleState(handle, win32pipe.PIPE_READMODE_MESSAGE, None, None)
        win32file.WriteFile(handle, data)
        _code, reply = win32file.ReadFile(handle, MAX_MESSAGE_BYTES + 1)
        return bytes(reply)
    except pywintypes.error as exc:
        raise SensorUnavailable(f"sensor connection failed (winerror={exc.winerror})") from exc
    finally:
        win32file.CloseHandle(handle)


# Exactly the rights the pipe grants INTERACTIVE users (audit B-6). GENERIC_WRITE would
# also ask for FILE_APPEND_DATA (= create pipe instance) and FILE_WRITE_EA, which users
# are deliberately not granted, so a normal user's tray was refused with access denied.
FILE_GENERIC_READ = 0x00120089
FILE_WRITE_DATA = 0x0002
FILE_WRITE_ATTRIBUTES = 0x0100
CLIENT_ACCESS = FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES

TRUSTED_SERVER_SIDS = ("S-1-5-18", "S-1-5-19", "S-1-5-20")  # SYSTEM, LOCAL/NETWORK SERVICE


def server_is_trusted(handle: Any) -> bool:
    """The process serving the pipe must be a service, never an ordinary user's process
    that squatted the name.

    An administrator client can read the server's token: SYSTEM or a service SID
    (NT SERVICE\\*, S-1-5-80-*). A normal user cannot open a service account's token
    (audit B-6), so the fallback is the Windows session: services run in session 0, and
    an ordinary user cannot start a process there (that needs a service, i.e. admin).
    """
    try:
        import win32pipe

        pid = win32pipe.GetNamedPipeServerProcessId(handle)
    except Exception:  # cannot verify -> do not trust
        log.warning("Could not identify the sensor pipe server")
        return False
    sid = _process_user_sid_text(pid)
    if sid is not None:
        return sid_is_service(sid)
    return _server_session(handle) == 0


def _process_user_sid_text(pid: int) -> str | None:
    try:
        import win32api
        import win32con
        import win32security

        process = win32api.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        try:
            token = win32security.OpenProcessToken(process, win32security.TOKEN_QUERY)
            user_sid, _attrs = win32security.GetTokenInformation(token, win32security.TokenUser)
        finally:
            win32api.CloseHandle(process)
        return win32security.ConvertSidToStringSid(user_sid)
    except Exception:  # normal users may not read a service's token
        return None


def _server_session(handle: Any) -> int | None:
    """Session of the pipe server, asked of the pipe itself (works for normal users;
    ProcessIdToSessionId on a service process is denied to them)."""
    try:
        import win32pipe

        return int(win32pipe.GetNamedPipeServerSessionId(handle))
    except Exception:
        log.warning("Could not verify the sensor pipe server")
        return None


def sid_is_service(text: str) -> bool:
    return text in TRUSTED_SERVER_SIDS or text.startswith("S-1-5-80-")
