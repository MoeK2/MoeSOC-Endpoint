"""One console per user: a second launch hands its request to the running window.

``MoeSOC.exe --finding 42`` (from a tray notification) or a plain second start connects
to the running console's local socket (``QLocalServer``: a named pipe on Windows,
restricted to the same user), sends one small JSON request and exits. The running
console brings itself to the front and opens the finding. Nothing but an
``{"cmd": "open", "finding": <int or null>}`` request is accepted.
"""

from __future__ import annotations

import getpass
import json
import logging
import re
import time
from collections.abc import Callable
from typing import Any

log = logging.getLogger(__name__)

MAX_REQUEST = 256
MAX_FINDING_ID = 2**31 - 1
FINDING_FLAG = "--finding"


def server_name() -> str:
    user = re.sub(r"[^A-Za-z0-9_.-]", "_", getpass.getuser() or "user")
    return f"MoeSOC.Console.{user}"


def finding_from_argv(argv: list[str]) -> tuple[int | None, str | None]:
    """(finding id, error message). A bad value never stops the console from opening."""
    if FINDING_FLAG not in argv:
        return None, None
    index = argv.index(FINDING_FLAG)
    try:
        value = int(argv[index + 1])
    except (IndexError, ValueError):
        return None, "The finding number in the link is not valid."
    if not 0 < value <= MAX_FINDING_ID:
        return None, "The finding number in the link is not valid."
    return value, None


def request_complete(data: bytes) -> bool:
    """A whole JSON object arrived, or more than any valid request could be."""
    return len(data) > MAX_REQUEST or data.rstrip().endswith(b"}")


def parse_request(data: bytes) -> int | bool | None:
    """The finding id (or None for "just show the window"); False for an invalid request."""
    if len(data) > MAX_REQUEST:
        return False
    try:
        message = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(message, dict) or message.get("cmd") != "open":
        return False
    finding = message.get("finding")
    if finding is None:
        return None
    if isinstance(finding, bool) or not isinstance(finding, int):
        return False
    return finding if 0 < finding <= MAX_FINDING_ID else False


def send_to_running_console(
    finding: int | None,
    timeout_ms: int = 1500,
    socket_factory: Callable[[], Any] | None = None,
) -> bool:
    """True when a running console answered the request (this process can then exit).

    Delivery is decided by the console's reply, never by ``waitForBytesWritten``: on
    Windows a small write can complete inside ``flush()``, after which
    ``waitForBytesWritten`` returns False although the console already received the
    request. Trusting it made every hand-over look failed, so each ``--finding`` start
    opened another console (audit B-3).
    """
    if socket_factory is None:
        try:
            from PySide6.QtNetwork import QLocalSocket
            from PySide6.QtWidgets import QApplication
        except ImportError:
            return False
        import sys

        # A full QApplication: the same one is reused when this start becomes the console.
        _app = QApplication.instance() or QApplication(sys.argv)
        socket_factory = QLocalSocket
    socket = socket_factory()
    socket.connectToServer(server_name())
    if not socket.waitForConnected(timeout_ms):
        return False
    socket.write(json.dumps({"cmd": "open", "finding": finding}).encode("utf-8"))
    socket.flush()
    socket.waitForBytesWritten(timeout_ms)  # result deliberately ignored (see above)
    reply = b""
    deadline = time.monotonic() + timeout_ms / 1000
    while time.monotonic() < deadline and not reply.startswith((b"ok", b"invalid")):
        if socket.bytesAvailable() or socket.waitForReadyRead(100):
            reply += bytes(socket.readAll())
        elif _disconnected(socket):
            reply += bytes(socket.readAll())
            break
    socket.disconnectFromServer()
    if reply.startswith(b"invalid"):
        log.warning("The running console rejected the request")
    # Any answer means a console is running and handled the request: never start another.
    return reply.startswith((b"ok", b"invalid"))


def _disconnected(socket: Any) -> bool:
    """True once the console closed the connection (QLocalSocket.UnconnectedState == 0)."""
    state = socket.state()
    try:
        return int(getattr(state, "value", state)) == 0
    except (TypeError, ValueError):
        return False


def start_server(on_open: Any) -> Any:
    """Listen for requests in the running console; ``on_open(finding_or_None)``."""
    from PySide6.QtNetwork import QLocalServer

    server = QLocalServer()
    server.setSocketOptions(QLocalServer.SocketOption.UserAccessOption)
    if not server.listen(server_name()):
        QLocalServer.removeServer(server_name())  # stale socket file (non-Windows)
        if not server.listen(server_name()):
            log.warning("Console link not available: %s", server.errorString())
            return server

    buffers: dict[int, bytes] = {}

    def accept() -> None:
        while server.hasPendingConnections():
            socket = server.nextPendingConnection()
            socket.readyRead.connect(lambda s=socket: _read(s))
            socket.disconnected.connect(lambda s=socket: buffers.pop(id(s), None))
            socket.disconnected.connect(socket.deleteLater)

    def _read(socket: Any) -> None:
        data = buffers.get(id(socket), b"") + bytes(socket.readAll())
        if not request_complete(data):
            buffers[id(socket)] = data  # wait for the rest of a split message
            return
        buffers.pop(id(socket), None)
        request = parse_request(data[: MAX_REQUEST + 1])
        socket.write(b"ok" if request is not False else b"invalid")
        socket.flush()
        socket.disconnectFromServer()
        if request is not False:
            on_open(request)
        else:
            log.warning("Ignored an invalid console link request")

    server.newConnection.connect(accept)
    return server
