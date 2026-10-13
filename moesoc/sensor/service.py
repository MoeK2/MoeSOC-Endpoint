"""Windows service host for SensorCore (pywin32 ``ServiceFramework``).

Only translation lives here: SCM start → ``SensorCore.run``; stop/shutdown → set the
stop event (the core finishes its batch, closes subscriptions and the database);
power resume → ``SensorCore.on_resume``. A service runs in session 0: nothing here shows
a window or notification; the tray does that in the user's session.
"""

from __future__ import annotations

import logging
import threading
import traceback

from moesoc.core.config import AppConfig
from moesoc.sensor.core import STOP_JOIN_SECONDS, SensorCore
from moesoc.sensor.ipc import Dispatcher, PipeServer
from moesoc.sensor.paths import (
    SERVICE_DESCRIPTION,
    SERVICE_DISPLAY_NAME,
    SERVICE_NAME,
    sensor_data_dir,
    sensor_log_dir,
)
from moesoc.utils.logging import configure_logging

log = logging.getLogger(__name__)

PBT_APMRESUMESUSPEND = 0x7
PBT_APMRESUMEAUTOMATIC = 0x12
SERVICE_CONTROL_POWEREVENT = 0x0D
SERVICE_ACCEPT_POWEREVENT = 0x40


def build_core() -> SensorCore:
    configure_logging(sensor_log_dir(), filename="sensor.log")
    config = AppConfig(data_dir=sensor_data_dir(), rules_dir=AppConfig.default().rules_dir)
    return SensorCore(config, ipc_factory=lambda core: PipeServer(Dispatcher(core)))


def service_class() -> type:
    """Created lazily so importing this module never requires pywin32."""
    import servicemanager
    import win32service
    import win32serviceutil

    class MoeSOCSensorService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args: list[str]) -> None:
            super().__init__(args)
            self._stop = threading.Event()
            self._core: SensorCore | None = None

        def GetAcceptedControls(self) -> int:
            return super().GetAcceptedControls() | SERVICE_ACCEPT_POWEREVENT

        def SvcStop(self) -> None:
            self.ReportServiceStatus(
                win32service.SERVICE_STOP_PENDING, waitHint=int(STOP_JOIN_SECONDS * 1000) + 5000
            )
            self._stop.set()

        def SvcShutdown(self) -> None:
            self.SvcStop()

        def SvcOtherEx(self, control: int, event_type: int, _data: object) -> None:
            resumed = event_type in (PBT_APMRESUMEAUTOMATIC, PBT_APMRESUMESUSPEND)
            if control == SERVICE_CONTROL_POWEREVENT and resumed and self._core is not None:
                self._core.on_resume()

        def SvcDoRun(self) -> None:
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            try:
                self._core = build_core()
                self._core.run(self._stop)
            except Exception:  # last resort: record why, then let SCM recovery restart us
                log.critical("Sensor service crashed:\n%s", traceback.format_exc())
                raise

    return MoeSOCSensorService


def dispatch() -> None:
    """Entry point when the Service Control Manager starts the process."""
    import servicemanager

    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(service_class())
    servicemanager.StartServiceCtrlDispatcher()
