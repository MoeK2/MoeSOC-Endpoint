"""Live monitoring: catch up, subscribe, ingest, recover.

    historical bootstrap / incremental catch-up (ScanService.run_live_scan)
        → current position (saved EventRecordID)
        → subscription starting after it (EvtSubscribe + bookmark)
        → new events → normalize → store → detect → correlate → GUI

On a transient failure (event log service restart, stale subscription, database
busy) the monitor reports RECONNECTING, waits with exponential backoff, catches up
again through the incremental collector (so nothing written meanwhile is missed)
and resubscribes. Permanent problems (no administrator rights, not Windows) end
in ERROR. The loop blocks on Windows' signal or a short timeout; it never spins.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from enum import StrEnum

from moesoc.collectors.defender import DEFENDER_GROUPS
from moesoc.collectors.powershell import POWERSHELL_GROUPS
from moesoc.collectors.security import build_event_ids_xpath
from moesoc.collectors.subscription import SubscriptionSource, SubscriptionSpec
from moesoc.collectors.sysmon import SYSMON_GROUPS
from moesoc.core.exceptions import LogAccessDeniedError, MoeSOCError, PlatformNotSupportedError
from moesoc.engine.scanner import LiveBatchResult, ScanService, ScanSummary
from moesoc.parsers.defender import DEFENDER_CHANNEL
from moesoc.parsers.powershell import POWERSHELL_CHANNEL
from moesoc.parsers.security import SECURITY_CHANNEL, SUPPORTED_EVENT_IDS
from moesoc.parsers.sysmon import SYSMON_CHANNEL

log = logging.getLogger(__name__)

WAIT_SECONDS = 1.0  # how often the loop checks for a stop request while idle
BATCH_QUIET_SECONDS = 2.0  # gather records that arrive close together into one batch
MAX_BATCH = 500
FIRST_BACKOFF = 2.0
MAX_BACKOFF = 60.0


class MonitorState(StrEnum):
    OFF = "OFF"
    STARTING = "STARTING"
    ON = "ON"
    RECONNECTING = "RECONNECTING"
    ERROR = "ERROR"


def subscription_xpath() -> str:
    """Every supported Security event (both groups); duplicates are ignored on insert."""
    return build_event_ids_xpath(frozenset(SUPPORTED_EVENT_IDS))


OPTIONAL_LIVE_CHANNELS = (
    (SYSMON_CHANNEL, SYSMON_GROUPS),
    (POWERSHELL_CHANNEL, POWERSHELL_GROUPS),
    (DEFENDER_CHANNEL, DEFENDER_GROUPS),
)


def all_source_subscriptions(service: ScanService) -> list[SubscriptionSpec]:
    """Security (required) plus every optional source, each after its saved position.

    An optional channel MoeSOC has never stored a record from starts with new events;
    anything written in between is read by the next catch-up (resume, manual scan,
    daily maintenance), because catch-up is incremental per channel.
    """
    specs = [
        SubscriptionSpec(
            SECURITY_CHANNEL, subscription_xpath(), service.subscription_start_record(), True
        )
    ]
    for channel, groups in OPTIONAL_LIVE_CHANNELS:
        ids = frozenset().union(*groups.values())
        specs.append(
            SubscriptionSpec(
                channel, build_event_ids_xpath(ids), service.subscription_start_record(channel)
            )
        )
    return specs


class LiveMonitor:
    def __init__(
        self,
        service: ScanService,
        source_factory: Callable[[], SubscriptionSource],
        on_state: Callable[[MonitorState, str], None],
        on_batch: Callable[[LiveBatchResult], None],
        *,
        wait_seconds: float = WAIT_SECONDS,
        quiet_seconds: float = BATCH_QUIET_SECONDS,
        first_backoff: float = FIRST_BACKOFF,
        max_backoff: float = MAX_BACKOFF,
        subscriptions: Callable[[ScanService], list[SubscriptionSpec]] | None = None,
        on_catch_up: Callable[[ScanSummary], None] | None = None,
    ) -> None:
        """``subscriptions`` (sensor): subscribe to several channels through a source with
        ``open_all`` (``MultiSubscription``). Without it, only the Security log (GUI)."""
        self._service = service
        self._source_factory = source_factory
        self._on_state = on_state
        self._on_batch = on_batch
        self._wait = wait_seconds
        self._quiet = quiet_seconds
        self._first_backoff = first_backoff
        self._max_backoff = max_backoff
        self._subscriptions = subscriptions
        self._on_catch_up = on_catch_up
        self._restart = threading.Event()
        self.channel_status: dict[str, str] = {}

    def _channels(self) -> list[str]:
        if self._subscriptions is None:
            return [SECURITY_CHANNEL]
        return [SECURITY_CHANNEL, *(channel for channel, _groups in OPTIONAL_LIVE_CHANNELS)]

    def request_restart(self) -> None:
        """Catch up and resubscribe soon (resume from sleep, manual scan). Thread-safe."""
        self._restart.set()

    def run(self, stop: threading.Event) -> None:
        """Run until ``stop`` is set or a permanent error occurs."""
        backoff = self._first_backoff
        attempt = 0
        while not stop.is_set():
            source: SubscriptionSource | None = None
            try:
                self._on_state(
                    MonitorState.STARTING if attempt == 0 else MonitorState.RECONNECTING,
                    "Catching up on events written since the last scan…",
                )
                self._restart.clear()
                self._service.remember_positions(self._channels())
                summary = self._service.run_live_scan()
                if self._on_catch_up is not None:
                    self._on_catch_up(summary)
                source = self._source_factory()
                if self._subscriptions is not None:
                    self.channel_status = source.open_all(self._subscriptions(self._service))
                    live = [c for c, s in self.channel_status.items() if s == "live"]
                    message = f"Monitoring live: {', '.join(live)}"
                else:
                    after = self._service.subscription_start_record()
                    source.open(SECURITY_CHANNEL, subscription_xpath(), after)
                    self.channel_status = {SECURITY_CHANNEL: "live"}
                    where = f"after record {after}" if after else "from new events"
                    message = f"Monitoring the Security log {where}"
                self._on_state(MonitorState.ON, message)
                backoff, attempt = self._first_backoff, 0
                self._pump(source, stop)
            except (LogAccessDeniedError, PlatformNotSupportedError) as exc:
                self._on_state(MonitorState.ERROR, exc.user_message)
                return
            except MoeSOCError as exc:
                attempt += 1
                self._retry_wait(stop, backoff, exc.user_message)
                backoff = min(backoff * 2, self._max_backoff)
            except Exception:  # thread boundary: never die silently
                log.exception("Unexpected error in live monitoring")
                attempt += 1
                self._retry_wait(stop, backoff, "Unexpected error (see diagnostic log)")
                backoff = min(backoff * 2, self._max_backoff)
            finally:
                if source is not None:
                    source.close()
        self._on_state(MonitorState.OFF, "Live monitoring stopped")

    def _retry_wait(self, stop: threading.Event, seconds: float, reason: str) -> None:
        self._on_state(MonitorState.RECONNECTING, f"{reason} Retrying in {seconds:.0f} s.".strip())
        stop.wait(seconds)

    def _pump(self, source: SubscriptionSource, stop: threading.Event) -> None:
        while not stop.is_set() and not self._restart.is_set():
            batch = source.wait(self._wait)
            if not batch:
                continue
            # Records often arrive in bursts (a logon writes 4624 + 4672 + 4688s):
            # keep reading until it is quiet briefly, then store and detect once.
            while len(batch) < MAX_BATCH and not stop.is_set():
                more = source.wait(self._quiet)
                if not more:
                    break
                batch.extend(more)
            self._on_batch(self._service.ingest_live(batch))
