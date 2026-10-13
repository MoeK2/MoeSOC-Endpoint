"""Launcher decision logic with a fake Windows API (no real UAC, dialogs or processes)."""

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "launch_moesoc", ROOT / "launcher" / "launch_moesoc.py"
)
launcher = importlib.util.module_from_spec(_spec)
sys.modules["launch_moesoc"] = launcher
_spec.loader.exec_module(launcher)


class FakeApi:
    def __init__(self, admin=True, running=False, elevate_code=42, lock=True, focus=False):
        self.admin = admin
        self.running = running
        self.elevate_code = elevate_code
        self.lock = lock
        self.focus = focus
        self.messages: list[str] = []
        self.elevations: list[tuple] = []

    def is_admin(self):
        return self.admin

    def message_box(self, text, icon):
        self.messages.append(text)

    def elevate(self, executable, arguments, working_dir):
        self.elevations.append((executable, arguments, working_dir))
        return self.elevate_code

    def instance_running(self):
        return self.running

    def acquire_instance_lock(self):
        return object() if self.lock else None

    def focus_existing_window(self):
        return self.focus


class FakeProcess:
    pid = 4242

    def __init__(self, code, stderr_text, stderr_file):
        self.code = code
        stderr_file.write(stderr_text)

    def wait(self):
        return self.code


class FakePopen:
    def __init__(self, code=0, stderr_text="", error: Exception | None = None):
        self.code, self.stderr_text, self.error = code, stderr_text, error
        self.calls: list[tuple] = []

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if self.error:
            raise self.error
        return FakeProcess(self.code, self.stderr_text, kwargs["stderr"])


@pytest.fixture
def project(tmp_path):
    """A minimal project layout: launcher/, app.py, .venv/Scripts/pythonw.exe."""
    root = tmp_path / "MoeSoc EndPoint"  # a space in the path, like the real folder
    (root / "launcher").mkdir(parents=True)
    (root / ".venv" / "Scripts").mkdir(parents=True)
    script = root / "launcher" / "launch_moesoc.py"
    script.write_text("# copy")
    (root / "app.py").write_text("# app")
    (root / ".venv" / "Scripts" / "pythonw.exe").write_text("")
    paths = launcher.resolve_paths(script, str(tmp_path / "LocalAppData"))
    launcher.configure_launcher_log(paths)
    return paths


def _log(paths) -> str:
    for handler in launcher.log.handlers:
        handler.flush()
    return paths.log_file.read_text(encoding="utf-8")


def test_paths_are_resolved_from_the_launcher_not_the_working_directory(project, tmp_path):
    os.chdir(tmp_path)  # Windows may start a shortcut from anywhere
    again = launcher.resolve_paths(project.launcher_script, str(tmp_path / "LocalAppData"))
    assert again.project == project.project
    assert again.app == project.project / "app.py"
    assert again.pythonw == project.project / ".venv" / "Scripts" / "pythonw.exe"
    assert again.log_file == tmp_path / "LocalAppData" / "MoeSOC" / "logs" / "launcher.log"


def test_admin_launch_starts_app_in_project_folder(project):
    api, popen = FakeApi(admin=True), FakePopen(code=0)
    assert launcher.run([], api, project, popen) == 0
    ((args, kwargs),) = popen.calls
    assert args == [str(project.pythonw), str(project.app)]
    assert kwargs["cwd"] == str(project.project)
    assert api.elevations == [] and api.messages == []
    log = _log(project)
    assert "MoeSOC started (pid 4242)" in log and "exited normally" in log
    assert f"Launcher {launcher.LAUNCHER_VERSION} start" in log


def test_normal_launch_requests_uac_and_does_not_start_app(project):
    api, popen = FakeApi(admin=False, elevate_code=42), FakePopen()
    assert launcher.run([], api, project, popen) == 0
    ((executable, arguments, working_dir),) = api.elevations
    assert executable == project.pythonw
    assert arguments == f'"{project.launcher_script}" --elevated'
    assert working_dir == project.project
    assert popen.calls == []
    assert "Elevation requested through UAC" in _log(project)


def test_declined_uac_opens_moesoc_in_limited_mode_like_the_exe(project):
    # Audit A-9: the launcher used to start nothing while MoeSOC.exe opened limited.
    api, popen = FakeApi(admin=False, elevate_code=launcher.SE_ERR_ACCESSDENIED), FakePopen()
    assert launcher.run([], api, project, popen) == 0
    assert api.messages == [] and len(popen.calls) == 1
    assert "declined or timed out; starting with limited access" in _log(project)


def test_elevation_failure_is_reported(project):
    api = FakeApi(admin=False, elevate_code=2)  # file not found
    assert launcher.run([], api, project, FakePopen()) == 1
    assert "could not request administrator access" in api.messages[0]


def test_no_elevation_loop_when_relaunch_is_still_not_admin(project):
    api, popen = FakeApi(admin=False), FakePopen(code=0)
    assert launcher.run(["--elevated"], api, project, popen) == 0
    assert api.elevations == []  # never asks twice
    assert len(popen.calls) == 1  # starts with limited access instead
    assert "limited access" in _log(project)


def test_missing_environment_shows_setup_message(project):
    project.pythonw.unlink()
    api, popen = FakeApi(admin=False), FakePopen()
    assert launcher.run([], api, project, popen) == 1
    assert api.messages[0].startswith("MoeSOC environment is not installed.")
    assert "verify_windows.bat" in api.messages[0]
    assert api.elevations == [] and popen.calls == []


def test_missing_app_is_reported_and_logged(project):
    project.app.unlink()
    api = FakeApi()
    assert launcher.run([], api, project, FakePopen()) == 1
    assert "could not find app.py" in api.messages[0]
    assert "Preflight failed" in _log(project)


def test_already_running_shows_message_without_uac(project):
    api, popen = FakeApi(admin=False, running=True, focus=False), FakePopen()
    assert launcher.run([], api, project, popen) == 0
    assert api.messages == ["MoeSOC Endpoint is already running."]
    assert api.elevations == [] and popen.calls == []


def test_already_running_window_is_focused_silently(project):
    api = FakeApi(running=True, focus=True)
    assert launcher.run([], api, project, FakePopen()) == 0
    assert api.messages == []


def test_lock_race_is_handled_as_already_running(project):
    api, popen = FakeApi(lock=False), FakePopen()
    assert launcher.run([], api, project, popen) == 0
    assert popen.calls == [] and api.messages == ["MoeSOC Endpoint is already running."]


def test_app_startup_failure_writes_log_and_dialog(project):
    trace = "Traceback (most recent call last):\nModuleNotFoundError: No module named 'PySide6'"
    api = FakeApi()
    assert launcher.run([], api, project, FakePopen(code=1, stderr_text=trace)) == 1
    log = _log(project)
    assert "exited with code 1" in log and "ModuleNotFoundError" in log
    assert str(project.log_file) in api.messages[0]
    assert api.messages[0].startswith("MoeSOC could not start")


def test_process_creation_error_is_reported(project):
    api = FakeApi()
    popen = FakePopen(error=OSError("[WinError 2] The system cannot find the file specified"))
    assert launcher.run([], api, project, popen) == 1
    assert "could not be started: OSError" in _log(project)
    assert "launcher.log" in api.messages[0]


def test_stderr_tail_is_bounded(tmp_path):
    path = tmp_path / "err.log"
    path.write_text("\n".join(f"line {i}" for i in range(500)))
    tail = launcher.stderr_tail(path)
    assert tail.splitlines()[0] == "line 460" and len(tail.splitlines()) == 40


def test_launch_uses_no_shell_and_no_stdin(project):
    popen = FakePopen(code=0)
    launcher.run([], FakeApi(), project, popen)
    ((_args, kwargs),) = popen.calls
    assert "shell" not in kwargs
    assert kwargs["stdin"] is subprocess.DEVNULL
