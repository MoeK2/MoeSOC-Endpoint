"""MoeSOC Endpoint — desktop entry point.

python app.py
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from moesoc import APP_NAME, __version__
from moesoc.core.config import AppConfig
from moesoc.core.exceptions import MoeSOCError
from moesoc.utils.logging import configure_logging
from moesoc.utils.privileges import is_admin, os_description

log = logging.getLogger("moesoc")
APP_USER_MODEL_ID = "MoeSOC.Endpoint"


def _set_taskbar_identity() -> None:
    """Group the window under MoeSOC's own taskbar icon instead of python.exe's."""
    if sys.platform != "win32":
        return
    import ctypes

    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_USER_MODEL_ID)
    except (AttributeError, OSError) as exc:  # cosmetic only; never block startup
        log.debug("Could not set the taskbar identity: %s", exc)


def _forward(finding: int | None, attempts: int = 1) -> bool:
    """Hand this start's request to a console that is already open (deep link).

    ``attempts`` > 1 when another instance is known to be running: it may still be
    starting and not listening yet, so the hand-over is retried briefly (startup race).
    """
    import time

    from moesoc.gui.console_link import send_to_running_console

    for attempt in range(attempts):
        try:
            if send_to_running_console(finding):
                log.info("Handed the request to the running console")
                return True
        except Exception as exc:  # never block startup on the hand-over
            log.warning("Console hand-over failed: %s", exc)
        if attempt + 1 < attempts:
            time.sleep(0.5)
    return False


def _frozen_start(config: AppConfig, finding: int | None) -> int | None:
    """Packaged executable only: self-test, single instance and elevation (see frozen.py).

    Returns an exit code to stop with, or None to continue starting the GUI.
    """
    from moesoc import frozen
    from moesoc.sensor.paths import sensor_installed

    if frozen.SELF_TEST_FLAG in sys.argv:
        results = frozen.run_self_test()
        frozen.write_self_test(results, AppConfig.default().log_dir)
        return 0 if all(c.ok for c in results) else 1
    decision = frozen.decide(
        sys.argv[1:],
        frozen.windows_platform(),
        Path(sys.executable),
        forward=lambda: _forward(finding, attempts=8),
        ask_elevation=not sensor_installed(),
    )
    log.info("Packaged start: %s", decision.reason)
    if decision.action != frozen.RUN:
        return 0
    _KEEP_ALIVE.append(decision.lock)  # the single-instance mutex lives with the process
    return None


_KEEP_ALIVE: list[object] = []


def main() -> int:
    from moesoc.gui.console_link import finding_from_argv
    from moesoc.sensor.paths import console_data_dir

    config = AppConfig.default(console_data_dir())
    # Console logs stay in the user's own folder, also when the data is the sensor's.
    configure_logging(AppConfig.default().log_dir)
    finding, link_error = finding_from_argv(sys.argv[1:])
    if getattr(sys, "frozen", False):
        stop = _frozen_start(config, finding)
        if stop is not None:
            return stop
    elif _forward(finding):  # development start: same one-console behaviour
        return 0
    log.info("%s %s started on %s (admin=%s)", APP_NAME, __version__, os_description(), is_admin())

    try:
        from PySide6.QtWidgets import QApplication, QMessageBox
    except ImportError:
        print("PySide6 is not installed. Run: pip install -r requirements.txt", file=sys.stderr)
        return 1

    from PySide6.QtGui import QIcon

    from moesoc.engine.rules import load_rules
    from moesoc.gui.main_window import MainWindow
    from moesoc.gui.theme import apply_theme
    from moesoc.storage.database import Database

    _set_taskbar_identity()
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    if config.icon_path.exists():
        app.setWindowIcon(QIcon(str(config.icon_path)))
    app.setApplicationVersion(__version__)
    apply_theme(app)

    database = Database(config.database_path)
    try:
        database.initialize()
        rules = load_rules(config.rules_dir)
    except MoeSOCError as exc:
        log.error("Startup failed: %s", exc.user_message)
        QMessageBox.critical(None, APP_NAME, exc.user_message)
        return 1

    window = MainWindow(config, database, rules)
    window.show()
    from moesoc.gui.console_link import start_server

    _KEEP_ALIVE.append(start_server(window.open_finding))
    if link_error:
        window.show_link_error(link_error)
    elif finding is not None:
        window.open_finding(finding)
    exit_code = app.exec()
    log.info("%s exited with code %s", APP_NAME, exit_code)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
