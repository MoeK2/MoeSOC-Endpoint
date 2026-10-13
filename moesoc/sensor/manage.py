"""Explicit sensor management: install, uninstall, start, stop, restart, status, run.

Nothing here runs implicitly: the service is installed only by ``install`` from an
administrator prompt, and ``uninstall`` stops and removes the service registration but
never deletes MoeSOC data. Usage (from the project folder or next to MoeSOCSensor.exe):

    sensor.py install [--copy-to-program-files] [--account virtual|system]
                      [--allow-insecure-code-path] [--no-tray] [--no-start]
    sensor.py uninstall | start | stop | restart | status
    sensor.py run                 # foreground, for diagnostics (Ctrl+C stops)
    sensor.py import-user-data    # copy %LOCALAPPDATA%\\MoeSOC data into the sensor

Privilege model (see docs/ALWAYS_ON_ARCHITECTURE.md):

* ``virtual`` (default for a Program Files install): the service runs as the virtual
  account ``NT SERVICE\\MoeSOCSensor``, which the install step adds to the built-in
  *Event Log Readers* group (that group can read the Security log; Administrators can
  see and undo the membership). Required privileges are limited to
  SeChangeNotifyPrivilege.
* ``system``: LocalSystem. Needed when the code lives in a user profile (a development
  checkout): a virtual account cannot read another user's profile folder.

A privileged service must not run code that ordinary users can modify. ``install``
checks the access list of every folder the service loads code or rules from and refuses
if a non-administrator can write there, unless ``--allow-insecure-code-path`` is given
(development only; the warning is printed and logged).
"""

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

from moesoc import __version__
from moesoc.core.config import default_data_dir
from moesoc.sensor.paths import (
    MARKER_FILE,
    SERVICE_ACCOUNT,
    SERVICE_DESCRIPTION,
    SERVICE_DISPLAY_NAME,
    SERVICE_NAME,
    machine_root,
    sensor_data_dir,
    sensor_log_dir,
)
from moesoc.storage.repository import to_db_time
from moesoc.utils.time import utc_now

EVENT_LOG_READERS_SID = "S-1-5-32-573"
TRUSTED_INSTALLER_SID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
ADMIN_SIDS = {"S-1-5-18", "S-1-5-32-544", TRUSTED_INSTALLER_SID}
CREATOR_OWNER_SID = "S-1-3-0"
WRITE_MASK = 0x40000000 | 0x10000000 | 0x00040000 | 0x00080000 | 0x2 | 0x4 | 0x40
# GENERIC_WRITE | GENERIC_ALL | WRITE_DAC | WRITE_OWNER | FILE_WRITE_DATA/ADD_FILE |
# FILE_APPEND_DATA/ADD_SUBDIRECTORY | FILE_DELETE_CHILD
PROGRAM_FILES_FOLDER = "MoeSOC Endpoint"


class ManageError(Exception):
    pass


# ---------------------------------------------------------------------- code location
def code_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def service_command(root: Path) -> str:
    """Binary path stored in the service registration (quoted: paths contain spaces)."""
    if getattr(sys, "frozen", False):
        return subprocess.list2cmdline([str(root / "MoeSOCSensor.exe")])
    return subprocess.list2cmdline([str(Path(sys.executable).resolve()), str(root / "sensor.py")])


def insecure_folders(folders: list[Path]) -> list[str]:
    """Folders a non-administrator could modify (code a privileged service would run)."""
    import win32security

    problems: list[str] = []
    for folder in folders:
        try:
            sd = win32security.GetFileSecurity(
                str(folder),
                win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION,
            )
        except Exception as exc:  # report, never assume safe
            problems.append(f"{folder}: access list unreadable ({exc})")
            continue
        owner = win32security.ConvertSidToStringSid(sd.GetSecurityDescriptorOwner())
        if owner not in ADMIN_SIDS:
            problems.append(f"{folder}: owned by {owner} (the owner can change its access)")
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl is None:
            problems.append(f"{folder}: no access list (everyone has full control)")
            continue
        for index in range(dacl.GetAceCount()):
            (ace_type, _flags), mask, sid = dacl.GetAce(index)[:3]
            text = win32security.ConvertSidToStringSid(sid)
            if ace_type != 0 or text in ADMIN_SIDS or text == CREATOR_OWNER_SID:
                continue  # 0 = ACCESS_ALLOWED_ACE
            if text.startswith("S-1-5-80-"):
                continue  # service SIDs
            if mask & WRITE_MASK:
                problems.append(f"{folder}: {text} can write here")
    return problems


def code_folders(root: Path) -> list[Path]:
    folders = [root, root / "rules"]
    if getattr(sys, "frozen", False):
        folders.append(root / "_internal")
    else:
        folders += [root / "moesoc", Path(sys.executable).resolve().parent]
    return [f for f in folders if f.exists()]


# ---------------------------------------------------------------------- folder ACLs
def acl_commands(root: Path, icacls: str, service_sid: str | None) -> list[list[str]]:
    """icacls command lines for the protected root folder ONLY (audit B-1).

    The rights are set on ``root`` with inheritable entries; Windows propagates them to
    the children that inherit (every file MoeSOC creates). Nothing is applied with /T:
    the old recursive /inheritance:r + /grant:r + /setowner stripped the entries of
    existing files (database, sensor.log) and left them unusable even for the service.
    """
    grants = ["*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX"]
    if service_sid:
        grants.append(f"*{service_sid}:(OI)(CI)M")
    command = [icacls, str(root), "/inheritance:r"]
    for grant in grants:
        command += ["/grant:r", grant]
    return [
        [*command, "/C", "/Q"],
        [icacls, str(root), "/setowner", "*S-1-5-32-544", "/C", "/Q"],
    ]


def damaged_children(root: Path, inherits: Callable[[Path], bool]) -> list[Path]:
    """Files/folders below ``root`` that do not inherit the root's rights (or whose rights
    cannot be read): what an older install (B-1) left behind."""
    damaged = []
    for path in sorted(root.rglob("*")):
        if not inherits(path):
            damaged.append(path)
    return damaged


def repair_commands(root: Path, icacls: str, takeown: str) -> list[list[str]]:
    """Give damaged children back to Administrators and make them inherit again.
    Contents are untouched; only ownership and access entries change."""
    return [
        [takeown, "/F", str(root), "/A", "/R", "/D", "Y"],
        [icacls, str(root / "*"), "/reset", "/T", "/C", "/Q"],
    ]


def _inherits_root_rights(path: Path) -> bool:
    """True when the path's DACL is not protected and holds at least one inherited ACE."""
    import win32security

    try:
        sd = win32security.GetFileSecurity(str(path), win32security.DACL_SECURITY_INFORMATION)
        control, _revision = sd.GetSecurityDescriptorControl()
        if control & win32security.SE_DACL_PROTECTED:
            return False
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl is None:
            return False
        return any(dacl.GetAce(i)[0][1] & 0x10 for i in range(dacl.GetAceCount()))  # INHERITED
    except Exception:  # unreadable rights = damaged
        return False


def secure_machine_folders(service_sid: str | None) -> list[Path]:
    """Protect %ProgramData%\\MoeSOC (SYSTEM + Administrators full, service modify, users
    read) without touching existing files; repair children an older install damaged.
    Idempotent. Returns the repaired paths."""
    import os

    for folder in (machine_root(), sensor_data_dir(), sensor_log_dir()):
        folder.mkdir(parents=True, exist_ok=True)
    system32 = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32"
    icacls = str(system32 / "icacls.exe")
    for command in acl_commands(machine_root(), icacls, service_sid):
        subprocess.run(command, check=True, capture_output=True)  # noqa: S603
    damaged = damaged_children(machine_root(), _inherits_root_rights)
    if damaged:
        print(f"Repairing access rights of {len(damaged)} item(s) left by an earlier install:")
        for path in damaged[:10]:
            print("  -", path)
        for command in repair_commands(machine_root(), icacls, str(system32 / "takeown.exe")):
            subprocess.run(command, check=False, capture_output=True)  # noqa: S603
        still = damaged_children(machine_root(), _inherits_root_rights)
        if still:
            raise ManageError(
                f"Access rights of {len(still)} item(s) could not be repaired, e.g. {still[0]}"
            )
    return damaged


def icacls_path() -> str:
    """Full path, so a planted icacls.exe in the current folder is never run."""
    import os

    return str(Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "icacls.exe")


# ---------------------------------------------------------------------- service
def _scm(access: int) -> object:
    import win32service

    return win32service.OpenSCManager(None, None, access)


def install(args: argparse.Namespace) -> int:
    import win32net
    import win32security
    import win32service

    root = code_root()
    service_existed = _service_exists()
    was_running = _service_running()
    if args.copy_to_program_files:
        # Rollback-safe: stops and restarts the service itself, only around a folder swap.
        root = copy_to_program_files(root)
    account = args.account or ("system" if not _under_program_files(root) else "virtual")
    problems = insecure_folders(code_folders(root))
    if problems:
        print("WARNING: a non-administrator can modify code the service would run:")
        for line in problems:
            print("  -", line)
        if not args.allow_insecure_code_path:
            print("Refusing to install. Use --copy-to-program-files (recommended), or")
            print("--allow-insecure-code-path for a development machine you alone use.")
            return 2
        print("Continuing because --allow-insecure-code-path was given (development only).")
    if account == "virtual" and not _under_program_files(root):
        print("Note: a virtual account cannot read code inside a user profile; using LocalSystem.")
        account = "system"

    command = service_command(root)
    scm = _scm(win32service.SC_MANAGER_ALL_ACCESS)
    try:
        user = SERVICE_ACCOUNT if account == "virtual" else None  # None = LocalSystem
        try:
            handle = win32service.CreateService(
                scm,
                SERVICE_NAME,
                SERVICE_DISPLAY_NAME,
                win32service.SERVICE_ALL_ACCESS,
                win32service.SERVICE_WIN32_OWN_PROCESS,
                win32service.SERVICE_AUTO_START,
                win32service.SERVICE_ERROR_NORMAL,
                command,
                None,
                False,
                None,
                user,
                None,
            )
        except win32service.error as exc:
            if exc.winerror != 1073:  # ERROR_SERVICE_EXISTS: update it in place
                raise
            handle = win32service.OpenService(scm, SERVICE_NAME, win32service.SERVICE_ALL_ACCESS)
            win32service.ChangeServiceConfig(
                handle,
                win32service.SERVICE_WIN32_OWN_PROCESS,
                win32service.SERVICE_AUTO_START,
                win32service.SERVICE_ERROR_NORMAL,
                command,
                None,
                False,
                None,
                user or "LocalSystem",
                None,
                SERVICE_DISPLAY_NAME,
            )
            print("Existing service registration updated.")
        try:
            _configure_service(handle)
        finally:
            win32service.CloseServiceHandle(handle)
    finally:
        win32service.CloseServiceHandle(scm)
    print(f"Service registered: {SERVICE_DISPLAY_NAME} ({account}), automatic (delayed) start.")

    service_sid = None
    if account == "virtual":
        sid, _domain, _type = win32security.LookupAccountName(None, SERVICE_ACCOUNT)
        service_sid = win32security.ConvertSidToStringSid(sid)
        group = _group_name(EVENT_LOG_READERS_SID)
        try:
            win32net.NetLocalGroupAddMembers(None, group, 3, [{"domainandname": SERVICE_ACCOUNT}])
            print(f"Added {SERVICE_ACCOUNT} to '{group}' (read access to event logs).")
        except win32net.error as exc:
            if exc.winerror != 1378:  # already a member
                raise
    secure_machine_folders(service_sid)
    (machine_root() / MARKER_FILE).write_text(
        json.dumps(
            {
                "version": __version__,
                "installed_at": to_db_time(utc_now()),
                "account": account,
                "command": command,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"Sensor data folder: {sensor_data_dir()} (users can read; only the service writes).")
    if not args.no_tray:
        from moesoc.tray import autostart

        autostart.set_enabled(True, autostart_command(root))
        print("Tray will start when you sign in.")
    if args.no_start:
        return 0
    if not _service_running():
        start(args)
    elif service_existed and was_running and not args.copy_to_program_files:
        restart(args)  # registration-only update: apply it (the swap path already restarted)
    if not wait_healthy(60):
        print(
            "WARNING: the sensor service runs but does not answer over IPC. "
            "Check 'MoeSOCSensor.exe status' and the sensor log."
        )
        return 1
    print("Sensor is running and answers over IPC.")
    return 0


def autostart_command(root: Path) -> str:
    if getattr(sys, "frozen", False):
        return subprocess.list2cmdline([str(root / "MoeSOCTray.exe")])
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    return subprocess.list2cmdline([str(pythonw), str(root / "tray.py")])


def _configure_service(handle: object) -> None:
    import win32service

    settings = [
        (win32service.SERVICE_CONFIG_DESCRIPTION, SERVICE_DESCRIPTION),
        (win32service.SERVICE_CONFIG_DELAYED_AUTO_START_INFO, True),
        (
            win32service.SERVICE_CONFIG_FAILURE_ACTIONS,
            {
                "ResetPeriod": 24 * 3600,
                "RebootMsg": None,
                "Command": None,
                "Actions": [
                    (win32service.SC_ACTION_RESTART, 60_000),
                    (win32service.SC_ACTION_RESTART, 60_000),
                    (win32service.SC_ACTION_NONE, 0),
                ],
            },
        ),
        (win32service.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, ["SeChangeNotifyPrivilege"]),
    ]
    for level, value in settings:
        try:
            win32service.ChangeServiceConfig2(handle, level, value)
        except Exception as exc:  # optional hardening, reported
            print(f"Note: service setting {level} not applied: {exc}")


def _group_name(sid_text: str) -> str:
    import win32security

    name, _domain, _type = win32security.LookupAccountSid(
        None, win32security.ConvertStringSidToSid(sid_text)
    )
    return name


def _under_program_files(root: Path) -> bool:
    import os

    bases = [os.environ.get(k) for k in ("PROGRAMFILES", "PROGRAMFILES(X86)")]
    return any(b and str(root).lower().startswith(b.lower()) for b in bases)


def copy_to_program_files(source: Path) -> Path:
    import os

    from moesoc.sensor.update import UpdateError, update_program_folder

    if not (source / "MoeSOCSensor.exe").exists():
        raise ManageError("--copy-to-program-files needs the packaged build (MoeSOCSensor.exe).")
    target = Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")) / PROGRAM_FILES_FOLDER
    if target.resolve() == source.resolve():
        raise ManageError(
            "Run the update from the new build (dist\\MoeSOC\\MoeSOCSensor.exe), not from the "
            "installed copy."
        )
    try:
        update_program_folder(source, target, windows_update_ops())
    except UpdateError as exc:
        raise ManageError(str(exc)) from exc
    return target


def windows_update_ops() -> object:
    import os

    from moesoc.sensor.update import UpdateOps

    def rmtree(path: Path) -> None:
        shutil.rmtree(path)

    return UpdateOps(
        exists=lambda p: p.exists(),
        copytree=lambda src, dst: shutil.copytree(src, dst),
        rmtree=rmtree,
        rename=lambda src, dst: rename_with_retry(src, dst, os.replace, time.sleep),
        service_running=_service_running,
        stop_service=lambda: stop(None),
        start_service=lambda: start(None),
        healthy=lambda: wait_healthy(60),
        close_tray=close_tray,
        open_programs=programs_running_from,
        reopen_tray=reopen_tray,
    )


RENAME_ATTEMPTS = 20
RENAME_DELAY = 0.5


def rename_with_retry(
    src: Path,
    dst: Path,
    replace: Callable[[Path, Path], None],
    sleep: Callable[[float], None],
    attempts: int = RENAME_ATTEMPTS,
) -> None:
    """Rename a program folder, waiting out short-lived handles (B-8).

    Real Windows: re-installing right after an uninstall was refused with "Access is
    denied" for the live folder while no MoeSOC program ran from it. Windows Defender,
    the search indexer or the just-stopped service can keep a file handle for a few
    seconds. Up to about 10 s of retries, then the error goes to the rollback as before.
    """
    for attempt in range(attempts):
        try:
            replace(src, dst)
            return
        except PermissionError:
            if attempt + 1 == attempts:
                raise
            sleep(RENAME_DELAY)


def _service_exists() -> bool:
    import win32serviceutil

    try:
        win32serviceutil.QueryServiceStatus(SERVICE_NAME)
        return True
    except Exception:
        return False


def _service_running() -> bool:
    import win32service
    import win32serviceutil

    try:
        return win32serviceutil.QueryServiceStatus(SERVICE_NAME)[1] == win32service.SERVICE_RUNNING
    except Exception:
        return False


def wait_healthy(seconds: float) -> bool:
    """The sensor answers 'hello' over its pipe (IPC starts first, see core.py)."""
    from moesoc.sensor.ipc import SensorClient, SensorUnavailable

    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if SensorClient().call("hello", timeout=3).get("ok"):
                return True
        except SensorUnavailable:
            pass
        time.sleep(1)
    return False


TRAY_WINDOW_CLASS = "MoeSOCTrayWindow"


def close_tray(wait_seconds: float = 15) -> bool:
    """Ask a running tray to exit the normal way (WM_CLOSE to its window). Never kills."""
    import win32con
    import win32gui

    hwnd = win32gui.FindWindow(TRAY_WINDOW_CLASS, None)
    if not hwnd:
        return False
    win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        if not win32gui.FindWindow(TRAY_WINDOW_CLASS, None):
            time.sleep(1)  # let the process exit and release its files
            return True
        time.sleep(0.25)
    return True


def programs_running_from(folder: Path) -> list[str]:
    """Names of processes whose executable lives in ``folder`` (except this process and
    the sensor service, which the update stops itself)."""
    import os

    import win32api
    import win32con
    import win32process

    skip = {os.getpid(), _service_pid()}
    prefix = str(folder.resolve()).lower().rstrip("\\") + "\\"
    names = []
    for pid in win32process.EnumProcesses():
        if pid in skip:
            continue
        try:
            handle = win32api.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        except Exception:  # noqa: S112 - protected or exited processes
            continue
        try:
            path = win32process.GetModuleFileNameEx(handle, 0)
        except Exception:
            path = ""
        finally:
            win32api.CloseHandle(handle)
        if path.lower().startswith(prefix):
            names.append(Path(path).name)
    return names


def _service_pid() -> int:
    import win32service

    try:
        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        try:
            handle = win32service.OpenService(scm, SERVICE_NAME, win32service.SERVICE_QUERY_STATUS)
            try:
                return int(win32service.QueryServiceStatusEx(handle)["ProcessId"])
            finally:
                win32service.CloseServiceHandle(handle)
        finally:
            win32service.CloseServiceHandle(scm)
    except Exception:
        return 0


def reopen_tray(folder: Path) -> None:
    """Start the tray again in the signed-in user's normal (not elevated) session: Explorer
    starts it with the user's own rights."""
    import os

    tray = folder / "MoeSOCTray.exe"
    if not tray.exists():
        return
    explorer = Path(os.environ.get("WINDIR", r"C:\Windows")) / "explorer.exe"
    try:
        subprocess.Popen([str(explorer), str(tray)])  # noqa: S603
    except OSError:
        print("Note: start the MoeSOC tray from the Start menu or sign in again.")


def uninstall(args: argparse.Namespace) -> int:
    import win32net
    import win32service
    import win32serviceutil

    stop(args)
    try:
        win32serviceutil.RemoveService(SERVICE_NAME)
        print("Service registration removed.")
    except win32service.error as exc:
        if exc.winerror != 1060:  # not installed
            raise
        print("Service was not installed.")
    try:
        group = _group_name(EVENT_LOG_READERS_SID)
        win32net.NetLocalGroupDelMembers(None, group, [SERVICE_ACCOUNT])
        print(f"Removed {SERVICE_ACCOUNT} from '{group}'.")
    except Exception as exc:  # not a member (LocalSystem install) or account gone
        print(f"Event Log Readers membership: nothing to remove ({exc.__class__.__name__}).")
    from moesoc.tray import autostart

    autostart.set_enabled(False)
    marker = machine_root() / MARKER_FILE
    if marker.exists():
        marker.unlink()
    print(f"MoeSOC data was NOT deleted: {sensor_data_dir()}")
    return 0


def start(_args: argparse.Namespace) -> int:
    import win32serviceutil

    win32serviceutil.StartService(SERVICE_NAME)
    win32serviceutil.WaitForServiceStatus(SERVICE_NAME, _running(), 60)
    print("Sensor started.")
    return 0


def stop(_args: argparse.Namespace) -> int:
    import win32service
    import win32serviceutil

    try:
        win32serviceutil.StopService(SERVICE_NAME)
        win32serviceutil.WaitForServiceStatus(SERVICE_NAME, win32service.SERVICE_STOPPED, 60)
        print("Sensor stopped.")
    except win32service.error as exc:
        if exc.winerror not in (1060, 1062):  # not installed / not running
            raise
        print("Sensor was not running.")
    return 0


def restart(args: argparse.Namespace) -> int:
    stop(args)
    return start(args)


def _running() -> int:
    import win32service

    return win32service.SERVICE_RUNNING


def status(_args: argparse.Namespace) -> int:
    from moesoc.sensor.ipc import SensorClient, SensorUnavailable

    states = {1: "stopped", 2: "starting", 3: "stopping", 4: "running"}
    try:
        import win32serviceutil

        code = win32serviceutil.QueryServiceStatus(SERVICE_NAME)[1]
        print(f"Service: {states.get(code, code)}")
    except Exception:
        print("Service: not installed")
    try:
        reply = SensorClient().call("status")
        print(json.dumps(reply.get("status"), indent=2))
    except SensorUnavailable as exc:
        print(f"Sensor IPC: unavailable ({exc})")
        return 1
    return 0


def run_foreground(_args: argparse.Namespace) -> int:
    """Diagnostics: the same SensorCore in this console window (Ctrl+C stops)."""
    from moesoc.sensor.service import build_core

    core = build_core()
    stop_event = threading.Event()
    thread = threading.Thread(target=core.run, args=(stop_event,), daemon=True)
    thread.start()
    print("Sensor running in the foreground. Press Ctrl+C to stop.")
    try:
        while thread.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop_event.set()
        thread.join(40)
    return 0


def import_user_data(args: argparse.Namespace) -> int:
    """Copy the per-user database into the sensor's folder (original kept, verified)."""
    source = Path(args.source) if args.source else default_data_dir() / "moesoc.db"
    target = sensor_data_dir() / "moesoc.db"
    copy_database(source, target, force=args.force)
    print(f"Imported {source} into {target}. The original was not changed.")
    return 0


def copy_database(source: Path, target: Path, *, force: bool = False) -> Path | None:
    """Transactional copy with SQLite's online backup, integrity check, then an atomic
    rename. An existing target is kept as a timestamped backup (only with ``force``).
    Returns the backup path, if one was made."""
    from moesoc.storage.database import Database

    if not source.is_file():
        raise ManageError(f"No database at {source}")
    backup_path: Path | None = None
    if target.exists():
        if not force:
            raise ManageError(
                f"{target} already exists; use --force to replace it (kept as backup)"
            )
        backup_path = target.with_name(f"moesoc.backup-{int(time.time())}.db")
    temp = target.with_name("moesoc.import.tmp")
    temp.unlink(missing_ok=True)
    target.parent.mkdir(parents=True, exist_ok=True)
    src = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    dst = sqlite3.connect(temp)
    try:
        src.backup(dst)
        if dst.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ManageError("The copy failed its integrity check; nothing was replaced.")
    finally:
        src.close()
        dst.close()
    try:
        Database(temp).initialize()  # migrate the copy, never the original
    except Exception:
        temp.unlink(missing_ok=True)
        raise
    if backup_path is not None:
        target.replace(backup_path)
        for suffix in ("-wal", "-shm"):
            Path(f"{target}{suffix}").unlink(missing_ok=True)
    temp.replace(target)
    return backup_path


COMMANDS = {
    "install": install,
    "uninstall": uninstall,
    "start": start,
    "stop": stop,
    "restart": restart,
    "status": status,
    "run": run_foreground,
    "import-user-data": import_user_data,
}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="sensor", description="MoeSOC Sensor management")
    parser.add_argument("command", choices=sorted(COMMANDS))
    parser.add_argument("--account", choices=("virtual", "system"))
    parser.add_argument("--copy-to-program-files", action="store_true")
    parser.add_argument("--allow-insecure-code-path", action="store_true")
    parser.add_argument("--no-tray", action="store_true")
    parser.add_argument("--no-start", action="store_true")
    parser.add_argument("--source", help="import-user-data: database to copy")
    parser.add_argument("--force", action="store_true", help="import-user-data: replace")
    args = parser.parse_args(argv)
    needs_admin = args.command not in ("status", "run")
    if sys.platform != "win32":
        print("The sensor service is only available on Windows.")
        return 1
    from moesoc.utils.privileges import is_admin

    if needs_admin and not is_admin():
        print("Run this from an administrator prompt (it changes a Windows service).")
        return 2
    try:
        return COMMANDS[args.command](args)
    except ManageError as exc:
        print(f"Error: {exc}")
        return 1
