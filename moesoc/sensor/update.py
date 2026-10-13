"""Rollback-safe update of the installed program folder (audit B-2).

The old update copied the new build over the live folder file by file after stopping
the service. A file held open (the tray autostarts at sign-in) made the copy fail
halfway: the folder was partly replaced and the service stayed stopped.

Now:

    leftovers of an interrupted update are cleaned up or recovered
    → the new build is copied to "<folder>.new" and validated   (service untouched)
    → the tray is asked to close (WM_CLOSE: its normal exit); an open console from that
      folder stops the update before anything changes          (service untouched)
    → stop the service → rename live → "<folder>.old" → rename ".new" → live
      (directory renames: either the old or the new folder is complete, never a mix)
    → start the service → health check over IPC
    → any failure after the stop: the previous folder is put back and started again
    → "<folder>.old" is removed only after the new version answered

All side effects go through ``UpdateOps`` so every transition is unit-tested.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

REQUIRED_FILES = ("MoeSOCSensor.exe", "MoeSOCTray.exe", "MoeSOC.exe", "_internal")


class UpdateError(Exception):
    """The update did not happen; the message says what state the system is in."""


@dataclass
class UpdateOps:
    exists: Callable[[Path], bool]
    copytree: Callable[[Path, Path], None]
    rmtree: Callable[[Path], None]
    rename: Callable[[Path, Path], None]
    service_running: Callable[[], bool]
    stop_service: Callable[[], None]
    start_service: Callable[[], None]
    healthy: Callable[[], bool]
    close_tray: Callable[[], bool]
    open_programs: Callable[[Path], list[str]]
    reopen_tray: Callable[[Path], None]


@dataclass
class UpdateResult:
    fresh_install: bool
    service_restarted: bool
    tray_reopened: bool


def update_program_folder(
    source: Path, target: Path, ops: UpdateOps, say: Callable[[str], None] = print
) -> UpdateResult:
    staged = target.with_name(target.name + ".new")
    backup = target.with_name(target.name + ".old")
    _recover_leftovers(target, staged, backup, ops, say)

    ops.copytree(source, staged)
    missing = [name for name in REQUIRED_FILES if not ops.exists(staged / name)]
    if missing:
        ops.rmtree(staged)
        raise UpdateError(
            f"The new build is incomplete (missing {', '.join(missing)}); nothing was changed."
        )
    if not ops.exists(target):
        ops.rename(staged, target)
        say(f"Installed the application to {target}")
        return UpdateResult(fresh_install=True, service_restarted=False, tray_reopened=False)

    tray_closed = ops.close_tray()
    busy = ops.open_programs(target)
    if busy:
        ops.rmtree(staged)
        if tray_closed:
            ops.reopen_tray(target)
        raise UpdateError(
            f"MoeSOC programs are running from {target} ({', '.join(sorted(set(busy)))}). "
            "Close the MoeSOC console, then run the update again. Nothing was changed; the "
            "sensor keeps running."
        )

    was_running = ops.service_running()
    try:
        if was_running:
            ops.stop_service()
        ops.rename(target, backup)
        try:
            ops.rename(staged, target)
        except Exception:
            ops.rename(backup, target)
            raise
    except Exception as exc:
        _restart_quietly(was_running, ops, say)
        if ops.exists(staged):
            ops.rmtree(staged)
        if tray_closed:
            ops.reopen_tray(target)
        raise UpdateError(
            f"The update could not replace {target} ({exc.__class__.__name__}: {exc}). "
            "The previous version was kept"
            + (" and the sensor was started again." if was_running else ".")
        ) from exc

    if was_running:
        ops.start_service()
        if not ops.healthy():
            say("The new version did not answer; restoring the previous version.")
            ops.stop_service()
            failed = target.with_name(target.name + ".failed")
            if ops.exists(failed):
                ops.rmtree(failed)
            ops.rename(target, failed)
            ops.rename(backup, target)
            ops.start_service()
            if tray_closed:
                ops.reopen_tray(target)
            raise UpdateError(
                "The new version did not start correctly. The previous version was restored "
                f"and started again; the failed build is kept in {failed} for diagnosis."
            )
    try:
        ops.rmtree(backup)
    except OSError:
        say(f"Note: could not remove {backup}; it is no longer used.")
    if tray_closed:
        ops.reopen_tray(target)
    say(f"Updated the application in {target}")
    return UpdateResult(False, was_running, tray_closed)


def _recover_leftovers(
    target: Path, staged: Path, backup: Path, ops: UpdateOps, say: Callable[[str], None]
) -> None:
    """An update interrupted earlier (power loss, killed process) leaves .new/.old."""
    if ops.exists(staged):
        ops.rmtree(staged)
    if ops.exists(backup):
        if not ops.exists(target):
            ops.rename(backup, target)  # the swap was interrupted: put the old one back
            say(f"Recovered the previous installation from {backup}")
        else:
            ops.rmtree(backup)


def _restart_quietly(was_running: bool, ops: UpdateOps, say: Callable[[str], None]) -> None:
    if not was_running:
        return
    try:
        ops.start_service()
    except Exception as exc:  # report, the caller raises the main error
        say(
            f"WARNING: the sensor could not be started again ({exc}). Start it with "
            "'MoeSOCSensor.exe start'."
        )
