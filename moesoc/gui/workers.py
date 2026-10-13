"""Run slow backend work (event log reads, SQLite, health probes) off the UI thread.

Results come back through Qt signals. Because the receivers are methods of
widgets living in the GUI thread, Qt delivers them as queued calls on that
thread, which keeps all widget updates thread-safe.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, QThread, Signal, Slot

from moesoc.core.exceptions import MoeSOCError

log = logging.getLogger(__name__)

# A task receives a progress callback (str -> None) and returns its result.
Task = Callable[[Callable[[str], None]], Any]


class TaskWorker(QObject):
    progress = Signal(str)
    succeeded = Signal(object)
    failed = Signal(str)
    finished = Signal()

    def __init__(self, task: Task) -> None:
        super().__init__()
        self._task = task

    @Slot()
    def run(self) -> None:
        try:
            result = self._task(self.progress.emit)
        except MoeSOCError as exc:
            self.failed.emit(exc.user_message)
        except Exception:
            # Thread boundary: an unexpected backend bug must surface as a readable
            # message instead of silently killing the worker or crashing the GUI.
            log.exception("Unexpected error in background task")
            self.failed.emit(
                "An unexpected error occurred. Details were written to the diagnostic log."
            )
        else:
            self.succeeded.emit(result)
        finally:
            self.finished.emit()


class TaskRunner(QObject):
    """Owns at most one running background task and keeps it alive until it ends."""

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._thread: QThread | None = None
        self._worker: TaskWorker | None = None

    @property
    def busy(self) -> bool:
        return self._thread is not None

    def start(
        self,
        task: Task,
        on_success: Callable[[Any], None],
        on_error: Callable[[str], None],
        on_progress: Callable[[str], None] | None = None,
    ) -> bool:
        if self.busy:
            return False
        thread = QThread()
        worker = TaskWorker(task)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.succeeded.connect(on_success)
        worker.failed.connect(on_error)
        if on_progress is not None:
            worker.progress.connect(on_progress)
        worker.finished.connect(thread.quit)
        thread.finished.connect(self._cleanup)
        self._thread, self._worker = thread, worker
        thread.start()
        return True

    @Slot()
    def _cleanup(self) -> None:
        if self._worker is not None:
            self._worker.deleteLater()
        if self._thread is not None:
            self._thread.deleteLater()
        self._thread = self._worker = None

    def wait(self) -> None:
        """Block until the current task ends (used on application shutdown).

        Tasks are bounded (per-scan event cap, EvtNext timeout), so this returns.
        Destroying a QThread that is still running would abort the process.
        """
        if self._thread is not None:
            self._thread.quit()
            self._thread.wait()
