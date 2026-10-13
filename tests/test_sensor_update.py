"""B-1 (install keeps data access rights) and B-2 (rollback-safe update) without Windows."""

from __future__ import annotations

from pathlib import Path

import pytest

from moesoc.sensor.manage import acl_commands, damaged_children, repair_commands
from moesoc.sensor.update import UpdateError, UpdateOps, update_program_folder

TARGET = Path("PF/MoeSOC Endpoint")
SOURCE = Path("dist/MoeSOC")
BUILD = {"MoeSOCSensor.exe", "MoeSOCTray.exe", "MoeSOC.exe", "_internal"}


class FakeSystem:
    """Folders as sets of file names; a service; a tray; open programs; injected faults."""

    def __init__(self, installed: bool = True, running: bool = True) -> None:
        self.folders: dict[Path, set[str]] = {SOURCE: set(BUILD) | {"NEW"}}
        if installed:
            self.folders[TARGET] = set(BUILD) | {"OLD"}
        self.running = running
        self.tray_running = False
        self.console_open = False
        self.fail: set[str] = set()
        self.log: list[str] = []
        self.healthy_answers = [True]
        self.tray_reopened = 0

    # helpers
    def version(self, folder: Path = TARGET) -> str | None:
        files = self.folders.get(folder)
        if files is None:
            return None
        return "NEW" if "NEW" in files else "OLD" if "OLD" in files else "?"

    def ops(self) -> UpdateOps:
        def maybe(step: str) -> None:
            if step in self.fail:
                self.fail.discard(step)
                raise PermissionError(f"{step} failed")

        def copytree(src: Path, dst: Path) -> None:
            maybe("copy")
            self.folders[dst] = set(self.folders[src])

        def rename(src: Path, dst: Path) -> None:
            maybe(f"rename {src.name}->{dst.name}")
            self.folders[dst] = self.folders.pop(src)
            self.log.append(f"rename {src.name}->{dst.name}")

        def rmtree(path: Path) -> None:
            self.folders.pop(path, None)

        def stop() -> None:
            self.running = False
            self.log.append("stop")

        def start() -> None:
            maybe("start")
            self.running = True
            self.log.append(f"start {self.version()}")

        def close_tray() -> bool:
            was = self.tray_running
            self.tray_running = False
            return was

        def reopen(_folder: Path) -> None:
            self.tray_reopened += 1
            self.tray_running = True

        return UpdateOps(
            exists=lambda p: (
                p in self.folders or (p.parent in self.folders and p.name in self.folders[p.parent])
            ),
            copytree=copytree,
            rmtree=rmtree,
            rename=rename,
            service_running=lambda: self.running,
            stop_service=stop,
            start_service=start,
            healthy=lambda: self.healthy_answers.pop(0) if self.healthy_answers else True,
            close_tray=close_tray,
            open_programs=lambda _f: ["MoeSOC.exe"] if self.console_open else [],
            reopen_tray=reopen,
        )

    def update(self):
        return update_program_folder(SOURCE, TARGET, self.ops(), say=self.log.append)


def leftovers(system: FakeSystem) -> set[str]:
    return {p.name for p in system.folders} - {TARGET.name, SOURCE.name}


def test_update_with_sensor_running_and_nothing_open():
    system = FakeSystem()
    result = system.update()
    assert system.version() == "NEW" and system.running
    assert result.service_restarted and not leftovers(system)
    assert system.log[:3] == [
        "stop",
        "rename MoeSOC Endpoint->MoeSOC Endpoint.old",
        "rename MoeSOC Endpoint.new->MoeSOC Endpoint",
    ]


def test_running_tray_is_closed_cleanly_and_reopened():
    system = FakeSystem()
    system.tray_running = True
    result = system.update()
    assert result.tray_reopened and system.tray_running and system.version() == "NEW"


def test_open_console_stops_the_update_before_anything_changes():
    system = FakeSystem()
    system.console_open = True
    system.tray_running = True
    with pytest.raises(UpdateError, match="Close the MoeSOC console"):
        system.update()
    assert system.version() == "OLD" and system.running and "stop" not in system.log
    assert system.tray_running and not leftovers(system)


def test_copy_failure_leaves_everything_untouched():
    system = FakeSystem()
    system.fail.add("copy")
    with pytest.raises(PermissionError):
        system.update()
    assert system.version() == "OLD" and system.running and "stop" not in system.log


def test_incomplete_build_is_rejected_before_stopping():
    system = FakeSystem()
    system.folders[SOURCE].discard("_internal")
    with pytest.raises(UpdateError, match="incomplete"):
        system.update()
    assert system.version() == "OLD" and system.running and not leftovers(system)


def test_locked_live_folder_keeps_the_old_version_running():
    system = FakeSystem()
    system.fail.add("rename MoeSOC Endpoint->MoeSOC Endpoint.old")  # a file held open
    with pytest.raises(UpdateError, match="previous version was kept"):
        system.update()
    assert system.version() == "OLD" and system.running and not leftovers(system)
    assert system.log[-1] == "start OLD"


def test_failure_after_moving_the_old_folder_puts_it_back():
    system = FakeSystem()
    system.fail.add("rename MoeSOC Endpoint.new->MoeSOC Endpoint")
    with pytest.raises(UpdateError):
        system.update()
    assert system.version() == "OLD" and system.running and not leftovers(system)


def test_new_version_that_does_not_answer_is_rolled_back():
    system = FakeSystem()
    system.healthy_answers = [False]
    with pytest.raises(UpdateError, match="previous version was restored"):
        system.update()
    assert system.version() == "OLD" and system.running
    assert system.version(TARGET.with_name(TARGET.name + ".failed")) == "NEW"


def test_stopped_service_stays_stopped_after_update():
    system = FakeSystem(running=False)
    result = system.update()
    assert system.version() == "NEW" and not system.running and not result.service_restarted


def test_fresh_install_needs_no_service():
    system = FakeSystem(installed=False, running=False)
    result = system.update()
    assert result.fresh_install and system.version() == "NEW"


def test_update_after_an_interrupted_swap_recovers_the_old_folder():
    system = FakeSystem()
    system.folders[TARGET.with_name(TARGET.name + ".old")] = system.folders.pop(TARGET)
    system.folders[TARGET.with_name(TARGET.name + ".new")] = {"partial"}
    system.update()  # recovery, then a normal update
    assert system.version() == "NEW" and system.running and not leftovers(system)


def test_rerun_after_a_failed_update_succeeds():
    system = FakeSystem()
    system.fail.add("rename MoeSOC Endpoint->MoeSOC Endpoint.old")
    with pytest.raises(UpdateError):
        system.update()
    system.update()
    assert system.version() == "NEW" and system.running and not leftovers(system)


# ------------------------------------------------------------------ B-1: access rights
def test_acl_commands_touch_only_the_root_folder():
    commands = acl_commands(Path("C:/ProgramData/MoeSOC"), "icacls.exe", "S-1-5-80-1-2")
    assert all("/T" not in command for command in commands)  # nothing recursive
    assert all(command[1] == str(Path("C:/ProgramData/MoeSOC")) for command in commands)
    grant = commands[0]
    assert "/inheritance:r" in grant and "*S-1-5-80-1-2:(OI)(CI)M" in grant
    assert "*S-1-5-32-545:(OI)(CI)RX" in grant  # users read only
    assert not any("Everyone" in part or "S-1-1-0" in part for part in grant)


def test_damaged_children_are_found_and_only_then_repaired(tmp_path):
    (tmp_path / "data").mkdir()
    db = tmp_path / "data" / "moesoc.db"
    db.write_bytes(b"x")
    log = tmp_path / "sensor.log"
    log.write_text("x")
    healthy = damaged_children(tmp_path, lambda p: True)
    assert healthy == []
    assert damaged_children(tmp_path, lambda p: p != db) == [db]
    take, reset = repair_commands(tmp_path, "icacls.exe", "takeown.exe")
    assert take[:2] == ["takeown.exe", "/F"] and "/A" in take  # Administrators, not a user
    assert reset[1] == str(tmp_path / "*") and "/reset" in reset  # inherit again, no deletes
    assert db.read_bytes() == b"x"  # building commands changes nothing


# ------------------------------------------------------------------ B-8: transient locks
def test_rename_waits_out_a_short_lived_lock():
    from moesoc.sensor.manage import rename_with_retry

    calls, sleeps = [], []

    def replace(src, dst):
        calls.append((src, dst))
        if len(calls) < 4:  # e.g. an antivirus scan holding a file for ~1.5 s
            raise PermissionError(5, "Access is denied")

    rename_with_retry(TARGET, Path("old"), replace, sleeps.append)
    assert len(calls) == 4 and len(sleeps) == 3


def test_a_lasting_lock_still_reaches_the_rollback():
    from moesoc.sensor.manage import rename_with_retry

    sleeps = []

    def locked(_src, _dst):
        raise PermissionError(5, "Access is denied")

    with pytest.raises(PermissionError):
        rename_with_retry(TARGET, Path("old"), locked, sleeps.append, attempts=5)
    assert len(sleeps) == 4  # bounded: no endless wait


def test_other_errors_are_not_retried():
    from moesoc.sensor.manage import rename_with_retry

    calls = []

    def missing(src, dst):
        calls.append(src)
        raise FileNotFoundError(src)

    with pytest.raises(FileNotFoundError):
        rename_with_retry(TARGET, Path("old"), missing, lambda _s: None)
    assert len(calls) == 1
