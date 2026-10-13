"""Run the LiveMonitor on its own thread and report its state to the GUI.

The monitor blocks on Windows' subscription signal, so it gets a dedicated QThread
instead of the short-task TaskRunner. Signals emitted from that thread reach the
window's slots as queued calls on the GUI thread.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable

from PySide6.QtCore import QObject, QThread, Signal, Slot

from moesoc.collectors.subscription import SubscriptionSource, WindowsSubscriptionSource
from moesoc.engine.live import LiveMonitor, MonitorState
from moesoc.engine.scanner import LiveBatchResult, ScanService

log = logging.getLogger(__name__)


class _MonitorWorker(QObject):
    state_changed = Signal(str, str)
    batch_done = Signal(object)
    finished = Signal()

    def __init__(
        self,
        service: ScanService,
        source_factory: Callable[[], SubscriptionSource],
        stop: threading.Event,
    ) -> None:
        super().__init__()
        self._service = service
        self._source_factory = source_factory
        self._stop = stop

    @Slot()
    def run(self) -> None:
        try:
            LiveMonitor(
                self._service,
                self._source_factory,
                lambda state, text: self.state_changed.emit(state.value, text),
                self._emit_batch,
            ).run(self._stop)
        except Exception:  # thread boundary
            log.exception("Live monitoring stopped unexpectedly")
            self.state_changed.emit(
                MonitorState.ERROR.value, "Live monitoring stopped (see diagnostic log)."
            )
        finally:
            self.finished.emit()

    def _emit_batch(self, result: LiveBatchResult) -> None:
        self.batch_done.emit(result)


class LiveMonitorController(QObject):
    state_changed = Signal(str, str)
    batch_done = Signal(object)

    def __init__(
        self,
        service: ScanService,
        source_factory: Callable[[], SubscriptionSource] = WindowsSubscriptionSource,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._service = service
        self._source_factory = source_factory
        self._thread: QThread | None = None
        self._worker: _MonitorWorker | None = None
        self._stop = threading.Event()

    @property
    def running(self) -> bool:
        return self._thread is not None

    def start(self) -> bool:
        if self.running:
            return False
        self._stop = threading.Event()
        thread = QThread()
        worker = _MonitorWorker(self._service, self._source_factory, self._stop)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.state_changed.connect(self.state_changed)
        worker.batch_done.connect(self.batch_done)
        worker.finished.connect(thread.quit)
        thread.finished.connect(self._cleanup)
        self._thread, self._worker = thread, worker
        thread.start()
        return True

    def stop(self, *, wait: bool = False) -> None:
        """Ask the monitor to stop; with ``wait`` block until it has (used on shutdown)."""
        self._stop.set()
        if wait and self._thread is not None:
            self._thread.quit()
            self._thread.wait()

    @Slot()
    def _cleanup(self) -> None:
        if self._worker is not None:
            self._worker.deleteLater()
        if self._thread is not None:
            self._thread.deleteLater()
        self._thread = self._worker = None
