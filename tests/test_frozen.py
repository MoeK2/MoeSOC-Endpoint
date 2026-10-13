"""Packaged-executable start-up: elevation, single instance, self-test (no Windows needed)."""

from __future__ import annotations

from pathlib import Path

from moesoc import frozen

EXE = Path("C:/Program Files/MoeSOC/MoeSOC.exe")


class FakeApi:
    def __init__(self, *, admin=False, running=False, elevate_code=42, lock=True, focus=True):
        self.admin, self.running, self.elevate_code = admin, running, elevate_code
        self.lock, self.focus = lock, focus
        self.calls: list[str] = []

    def is_admin(self):
        return self.admin

    def message_box(self, text, icon):
        self.calls.append(f"message:{text}")

    def elevate(self, executable, arguments, working_dir):
        self.calls.append(f"elevate:{executable.name}:{arguments}:{working_dir.name}")
        return self.elevate_code

    def instance_running(self):
        return self.running

    def acquire_instance_lock(self):
        self.calls.append("lock")
        return object() if self.lock else None

    def focus_existing_window(self):
        self.calls.append("focus")
        return self.focus


def test_not_elevated_asks_once_and_hands_over():
    api = FakeApi()
    d = frozen.decide([], api, EXE)
    assert d.action == frozen.EXIT and api.calls == ["elevate:MoeSOC.exe:--elevated:MoeSOC"]


def test_elevated_copy_never_asks_again_and_takes_the_lock():
    api = FakeApi(admin=False)
    d = frozen.decide(["--elevated"], api, EXE)
    assert d.action == frozen.RUN and d.lock is not None and api.calls == ["lock"]


def test_admin_runs_directly():
    d = frozen.decide([], FakeApi(admin=True), EXE)
    assert d.action == frozen.RUN


def test_declined_uac_still_opens_in_limited_mode():
    api = FakeApi(elevate_code=5)  # SE_ERR_ACCESSDENIED: the user said no
    d = frozen.decide([], api, EXE)
    assert d.action == frozen.RUN and api.calls[-1] == "lock"


def test_second_instance_focuses_the_first_without_a_uac_prompt():
    api = FakeApi(running=True)
    d = frozen.decide([], api, EXE)
    assert d.action == frozen.EXIT and api.calls == ["focus"]
    api = FakeApi(running=True, focus=False)
    frozen.decide([], api, EXE)
    assert api.calls == ["focus", f"message:{frozen.ALREADY_RUNNING}"]


def test_race_for_the_lock_exits_cleanly():
    api = FakeApi(admin=True, lock=False)
    assert frozen.decide([], api, EXE).action == frozen.EXIT


def test_self_test_flag_skips_elevation():
    api = FakeApi()
    assert frozen.decide(["--self-test"], api, EXE).action == frozen.SELF_TEST
    assert api.calls == []


def test_self_test_reports_every_check_and_never_hides_failures(tmp_path):
    def boom():
        raise RuntimeError("missing plugin")

    results = frozen.run_self_test([("ok", lambda: "fine"), ("broken", boom)])
    assert [(c.name, c.ok) for c in results] == [("ok", True), ("broken", False)]
    path = frozen.write_self_test(results, tmp_path)
    text = path.read_text(encoding="utf-8")
    assert "PASS  ok: fine" in text and "FAIL  broken: RuntimeError: missing plugin" in text
    assert text.strip().endswith("SELF-TEST: FAILED")
    assert (tmp_path / "self-test.json").exists()


def test_default_self_test_without_gui_passes_here(tmp_path):
    checks = [c for c in frozen.default_checks() if c[0] != "gui"]  # PySide6 not in this env
    results = frozen.run_self_test(checks)
    assert all(c.ok for c in results), [c.detail for c in results if not c.ok]
