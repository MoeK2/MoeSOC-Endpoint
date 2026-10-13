"""Main window: sidebar navigation, header with scan controls, page stack."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, QTimer, Slot
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QButtonGroup,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QMainWindow,
    QProgressBar,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from moesoc import APP_NAME
from moesoc.core.config import AppConfig
from moesoc.core.detection import RuleMetadata
from moesoc.core.enums import HealthState
from moesoc.core.exceptions import MoeSOCError
from moesoc.engine.live import MonitorState
from moesoc.engine.scanner import LiveBatchResult, ScanService, ScanSummary
from moesoc.gui import theme, triage_actions
from moesoc.gui.live import LiveMonitorController
from moesoc.gui.pages.detections import DetectionsPage
from moesoc.gui.pages.events import EventsPage
from moesoc.gui.pages.overview import OverviewPage
from moesoc.gui.pages.placeholder import SettingsPage
from moesoc.gui.pages.process_tree import ProcessTreePage
from moesoc.gui.pages.reports import ReportsPage
from moesoc.gui.pages.story import StoryPage
from moesoc.gui.pages.timeline import TimelinePage
from moesoc.gui.pages.tuning import SuppressionRequest, TuningPage
from moesoc.gui.widgets.common import label
from moesoc.gui.workers import TaskRunner
from moesoc.health import HealthCheck, run_health_checks, run_sensor_health_checks
from moesoc.sensor.ipc import SensorClient
from moesoc.sensor.paths import sensor_data_dir, sensor_installed
from moesoc.storage.database import Database
from moesoc.storage.event_search import (
    EventFilter,
    SearchPage,
    Timeline,
    detection_timeline,
    pivot_timeline,
    search_events,
)
from moesoc.storage.overview import OverviewSnapshot, load_overview
from moesoc.storage.process_tree import ProcessTree, build_process_tree
from moesoc.storage.report import finding_report, summary_report
from moesoc.storage.repository import AnalystNote, DetectionRepository
from moesoc.storage.retention import (
    RetentionPlan,
    apply_retention,
    get_retention_days,
    plan_retention,
    set_retention_days,
)
from moesoc.storage.story import Story, build_story
from moesoc.storage.tuning import TuningRepository, TuningSnapshot, load_tuning
from moesoc.utils.privileges import hostname, is_admin
from moesoc.utils.time import format_local

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class DashboardData:
    snapshot: OverviewSnapshot
    notes: dict[int, list[AnalystNote]]


NAV_ITEMS = (
    "Overview",
    "Detections",
    "Timeline",
    "Events",
    "Process Tree",
    "Story",
    "Tuning",
    "Reports",
    "Settings",
)


class MainWindow(QMainWindow):
    def __init__(
        self,
        config: AppConfig,
        database: Database,
        rules: dict[str, RuleMetadata],
        *,
        demo: bool = False,
    ):
        super().__init__()
        # Demo mode: a separate database of synthetic events. It is labelled everywhere
        # and cannot collect real telemetry, so real and synthetic data never mix.
        self._demo = demo
        self._config = config
        self._db = database
        self._rules = rules
        self._pending_finding: int | None = None  # deep link waiting for data
        self._sensor_mode = (
            not demo and config.data_dir == sensor_data_dir() and (sensor_installed())
        )
        self._service = ScanService(config, database, rules)
        self._scan_runner = TaskRunner(self)
        self._load_runner = TaskRunner(self)
        self._health_runner = TaskRunner(self)
        self._query_runner = TaskRunner(self)  # Events page searches
        self._timeline_runner = TaskRunner(self)
        self._triage_runner = TaskRunner(self)
        self._tuning_runner = TaskRunner(self)
        self._tuning_retry_scheduled = False
        self._live = LiveMonitorController(self._service, parent=self)
        self._live.state_changed.connect(self._on_live_state)
        self._live.batch_done.connect(self._on_live_batch)
        self._pending_query: tuple[EventFilter, bool] | None = None
        self._pending_timeline: Callable[[], None] | None = None

        self.setWindowTitle(f"{APP_NAME} — DEMO (synthetic data)" if demo else APP_NAME)
        self.resize(1320, 840)
        self.setMinimumSize(1000, 640)

        self.overview = OverviewPage()
        self.detections = DetectionsPage(rules)
        self.events = EventsPage()
        self.timeline = TimelinePage()
        self.process_tree = ProcessTreePage()
        self.story = StoryPage()
        self.settings = SettingsPage(config)
        self.tuning = TuningPage(sorted(rules))
        self.reports = ReportsPage()
        pages: dict[str, QWidget] = {
            "Overview": self.overview,
            "Detections": self.detections,
            "Timeline": self.timeline,
            "Events": self.events,
            "Process Tree": self.process_tree,
            "Story": self.story,
            "Tuning": self.tuning,
            "Reports": self.reports,
            "Settings": self.settings,
        }

        root = QWidget()
        root.setObjectName("Root")
        layout = QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._build_sidebar())

        main = QVBoxLayout()
        main.setContentsMargins(0, 0, 0, 0)
        main.setSpacing(0)
        main.addWidget(self._build_header())
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)  # indeterminate
        self.progress.setTextVisible(False)
        self.progress.setVisible(False)
        main.addWidget(self.progress)
        self.stack = QStackedWidget()
        for page in pages.values():
            self.stack.addWidget(page)
        main.addWidget(self.stack, 1)
        layout.addLayout(main, 1)
        self.setCentralWidget(root)

        self._pages = pages
        self._connect_pages()
        self._load_retention_setting()
        self.select_page("Overview")
        self.refresh_data()
        self.refresh_health()
        self.events.apply_filters()

    def _connect_pages(self) -> None:
        self.detections.status_requested.connect(self._on_status_requested)
        self.detections.note_requested.connect(self._on_note_requested)
        self.detections.timeline_requested.connect(self.open_detection_timeline)
        self.detections.evidence_requested.connect(self._on_evidence_requested)
        self.detections.story_requested.connect(self.open_story)
        self.settings.retention_save_requested.connect(self._save_retention)
        self.detections.suppress_requested.connect(self._suppress_from_finding)
        self.reports.summary_requested.connect(self._export_summary)
        self.reports.finding_requested.connect(self._export_finding)
        self.tuning.suppression_add_requested.connect(self._add_suppression)
        self.tuning.suppression_remove_requested.connect(self._remove_suppression)
        self.tuning.rule_enabled_requested.connect(self._set_rule_enabled)
        self.tuning.rule_parameter_requested.connect(self._set_rule_parameter)
        self.settings.retention_preview_requested.connect(self._preview_retention)
        self.settings.retention_apply_requested.connect(self._apply_retention)
        self.story.timeline_requested.connect(self.open_detection_timeline)
        self.story.detection_requested.connect(self._show_detection)
        self.events.search_requested.connect(self.run_event_search)
        self.events.timeline_requested.connect(self.open_pivot_timeline)
        self.timeline.pivot_requested.connect(self.open_pivot_timeline)
        self.timeline.padding_changed.connect(self._on_padding_changed)
        self.timeline.open_in_events.connect(self._open_filter_in_events)
        self.events.process_tree_requested.connect(self.open_process_tree)
        self.process_tree.pivot_requested.connect(self.open_pivot_timeline)
        self.process_tree.open_event_requested.connect(self._open_event)

    # ------------------------------------------------------------------ layout
    def _build_sidebar(self) -> QWidget:
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(theme.SIDEBAR_WIDTH)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(theme.SPACE_3, theme.SPACE_6, theme.SPACE_3, theme.SPACE_4)
        layout.setSpacing(theme.SPACE_1)

        brand = label("MoeSOC")
        brand.setObjectName("BrandName")
        sub = label("ENDPOINT")
        sub.setObjectName("BrandSub")
        brand_box = QVBoxLayout()
        brand_box.setContentsMargins(theme.SPACE_3, 0, 0, theme.SPACE_6)
        brand_box.setSpacing(0)
        brand_box.addWidget(brand)
        brand_box.addWidget(sub)
        layout.addLayout(brand_box)

        self._nav_group = QButtonGroup(self)
        self._nav_group.setExclusive(True)
        self._nav_buttons: dict[str, QPushButton] = {}
        for name in NAV_ITEMS:
            button = QPushButton(name)
            button.setObjectName("NavButton")
            button.setCheckable(True)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.clicked.connect(lambda _checked=False, n=name: self.select_page(n))
            self._nav_group.addButton(button)
            self._nav_buttons[name] = button
            layout.addWidget(button)
        layout.addStretch(1)

        privacy = label("Local-only processing.\nNo telemetry leaves this device.", wrap=True)
        privacy.setObjectName("PrivacyNote")
        privacy.setContentsMargins(theme.SPACE_3, 0, 0, 0)
        layout.addWidget(privacy)
        return sidebar

    def _build_header(self) -> QWidget:
        header = QFrame()
        header.setObjectName("Header")
        layout = QHBoxLayout(header)
        layout.setContentsMargins(theme.SPACE_6, theme.SPACE_4, theme.SPACE_6, theme.SPACE_4)
        layout.setSpacing(theme.SPACE_3)

        titles = QVBoxLayout()
        titles.setSpacing(2)
        self.page_title = label("")
        self.page_title.setObjectName("PageTitle")
        admin = is_admin()
        privilege = {True: "Administrator", False: "Standard user", None: "Non-Windows host"}[admin]
        self.meta = label(f"{hostname()}  ·  {privilege}")
        self.meta.setObjectName("HeaderMeta")
        titles.addWidget(self.page_title)
        titles.addWidget(self.meta)
        layout.addLayout(titles, 1)
        self.demo_badge = label(
            "DEMO · synthetic data, not from this computer" if self._demo else "", "caption"
        )
        self.demo_badge.setObjectName("DemoBadge")
        self.demo_badge.setVisible(self._demo)
        layout.addWidget(self.demo_badge)

        self.status = label("", "caption")
        self.status.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(self.status)

        self.import_button = QPushButton("Import XML…")
        self.import_button.setToolTip(
            "Analyze an exported Security log (wevtutil qe Security /f:xml)"
        )
        self.import_button.clicked.connect(self._import_xml)
        self.scan_button = QPushButton("Scan Now")
        self.scan_button.setProperty("variant", "primary")
        self.scan_button.setToolTip(
            f"Read Security log logon events from the last {self._config.lookback_hours} hours"
        )
        self.scan_button.clicked.connect(self._start_scan)
        self.live_button = QPushButton("Live: OFF")
        self.live_button.setCheckable(True)
        self.live_button.setToolTip(
            "Live monitoring: catch up, then process new Security events as Windows writes them"
        )
        self.live_button.toggled.connect(self._toggle_live)
        layout.addWidget(self.import_button)
        layout.addWidget(self.live_button)
        layout.addWidget(self.scan_button)
        if self._sensor_mode:  # the sensor service owns collection for this database
            self.live_button.setText("Live: Sensor")
            self.live_button.setEnabled(False)
            self.live_button.setToolTip(
                "Live monitoring runs in the MoeSOC Sensor service, also when this window is closed"
            )
            self.scan_button.setToolTip("Ask the MoeSOC Sensor to catch up on all logs now")
        if self._demo:
            for button in (self.import_button, self.live_button, self.scan_button):
                button.setEnabled(False)
                button.setToolTip("Disabled in demo mode: the demo database holds synthetic data")
        return header

    def select_page(self, name: str) -> None:
        self.stack.setCurrentWidget(self._pages[name])
        self._nav_buttons[name].setChecked(True)
        self.page_title.setText(name)
        if name == "Tuning":
            self.load_tuning()

    # ------------------------------------------------------------------ scanning
    def _set_scanning(self, scanning: bool) -> None:
        self.scan_button.setEnabled(not scanning and not self._demo)
        self.import_button.setEnabled(not scanning and not self._demo)
        self.scan_button.setText("Scanning…" if scanning else "Scan Now")
        self.progress.setVisible(scanning)

    def _set_status(self, text: str, error: bool = False) -> None:
        self.status.setProperty("role", "error" if error else "caption")
        self.status.style().unpolish(self.status)
        self.status.style().polish(self.status)
        self.status.setText(text)

    @Slot()
    def _start_scan(self) -> None:
        if self._demo:
            return  # never collect real telemetry into the synthetic demo database
        if self._sensor_mode:
            self._request_sensor_scan()
            return
        if self._scan_runner.start(
            self._service.run_live_scan,
            on_success=self._on_scan_finished,
            on_error=self._on_scan_failed,
            on_progress=self._on_scan_progress,
        ):
            self._set_scanning(True)
            self._set_status("Starting scan…")

    @Slot()
    def _import_xml(self) -> None:
        if self._demo:
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "Import exported Security log", "", "Event XML (*.xml);;All files (*)"
        )
        if path:
            self.start_import(Path(path))

    def start_import(self, path: Path) -> bool:
        """Analyze an exported XML file in the background. Returns False if busy."""
        started = self._scan_runner.start(
            lambda progress: self._service.import_xml_file(path, progress),
            on_success=self._on_scan_finished,
            on_error=self._on_scan_failed,
            on_progress=self._on_scan_progress,
        )
        if started:
            self._set_scanning(True)
            self._set_status(f"Importing {path.name}…")
        return started

    @property
    def busy(self) -> bool:
        return any(r.busy for r in self._runners)

    @Slot(str)
    def _on_scan_progress(self, message: str) -> None:
        self._set_status(message)

    @Slot(object)
    def _on_scan_finished(self, summary: ScanSummary) -> None:
        self._set_scanning(False)
        text = (
            f"Scan complete · {summary.records_read:,} records read · "
            f"{summary.events_new:,} new events · {summary.detections_new:,} new detections"
        )
        if summary.parse_failures:
            text += f" · {summary.parse_failures:,} unparseable records skipped"
        if summary.truncated:
            text += " · per-scan limit reached"
        self._set_status(text)
        self.refresh_data()
        self.events.apply_filters()

    @Slot(str)
    def _on_scan_failed(self, message: str) -> None:
        self._set_scanning(False)
        self._set_status(message, error=True)
        self.refresh_data()
        self.overview.show_scan_error(message)

    # ------------------------------------------------------------------ live monitoring
    @Slot(bool)
    def _toggle_live(self, enabled: bool) -> None:
        if self._demo:
            return
        if enabled:
            if self._live.start():
                self._set_status("Starting live monitoring…")
            else:  # the previous session is still shutting down
                self.live_button.blockSignals(True)
                self.live_button.setChecked(False)
                self.live_button.blockSignals(False)
                self._set_status("Live monitoring is still stopping; try again.", error=True)
        else:
            self._live.stop()

    @Slot(str, str)
    def _on_live_state(self, state: str, message: str) -> None:
        self.live_button.setText(f"Live: {state}")
        self.live_button.setToolTip(message)
        error = state == MonitorState.ERROR.value
        if state in (MonitorState.ERROR.value, MonitorState.OFF.value):
            self.live_button.blockSignals(True)
            self.live_button.setChecked(False)
            self.live_button.blockSignals(False)
        self._set_status(f"Live monitoring {state.lower()}: {message}", error=error)
        if state == MonitorState.ON.value:
            self.refresh_data()

    @Slot(object)
    def _on_live_batch(self, result: LiveBatchResult) -> None:
        text = f"Live · {result.records:,} new records · {result.events_new:,} stored"
        if result.detections_new:
            text += f" · {result.detections_new:,} new detections"
        self._set_status(text)
        if result.events_new or result.detections_new:
            self.refresh_data()

    # ------------------------------------------------------------------ data
    def _load_dashboard(self, _progress: object) -> DashboardData:
        snapshot = load_overview(self._db)
        with self._db.connect() as conn:
            notes = DetectionRepository(conn).all_notes()
        return DashboardData(snapshot, notes)

    def refresh_data(self) -> None:
        if not self._load_runner.start(
            self._load_dashboard, on_success=self._on_data, on_error=self._on_data_error
        ):
            log.debug("Data refresh already running")

    @Slot(object)
    def _on_data(self, data: DashboardData) -> None:
        snap = data.snapshot
        self.overview.show_snapshot(snap)
        self.detections.show_detections(
            snap.detections, scanned=snap.has_completed_scan, notes=data.notes
        )
        self.reports.set_detections(snap.detections)
        self._apply_pending_finding()
        if snap.last_scan and not self._scan_runner.busy and not self.status.text():
            when = format_local(snap.last_scan.finished_at or snap.last_scan.started_at)
            self._set_status(f"Last scan {when} ({snap.last_scan.status})")

    @Slot(str)
    def _on_data_error(self, message: str) -> None:
        self._set_status(message, error=True)
        self.detections.view.show_error(message)
        self.events.view.show_error(message)

    def refresh_health(self) -> None:
        if self._demo:
            # Never show this computer's real status next to synthetic findings.
            self.overview.show_health(
                [
                    HealthCheck(
                        "Demo mode",
                        HealthState.LIMITED,
                        "This computer's telemetry is not checked in demo mode. Every event and "
                        "finding shown is synthetic.",
                    )
                ]
            )
            return
        if self._sensor_mode:  # B-7: what is collected is what the sensor reports
            self._health_runner.start(
                lambda _progress: run_sensor_health_checks(
                    self._db, lambda: SensorClient().call("status")["status"], is_admin()
                ),
                on_success=self._on_health,
                on_error=self._on_health_error,
            )
            return
        self._health_runner.start(
            lambda _progress: run_health_checks(self._db),
            on_success=self._on_health,
            on_error=self._on_health_error,
        )

    @Slot(object)
    def _on_health(self, checks: list[HealthCheck]) -> None:
        self.overview.show_health(checks)

    @Slot(str)
    def _on_health_error(self, message: str) -> None:
        self.overview.show_health([HealthCheck("Health checks", HealthState.ERROR, message)])

    # ------------------------------------------------------------------ events search
    @Slot(object, bool)
    def run_event_search(self, f: EventFilter, append: bool) -> None:
        if self._query_runner.busy:
            self._pending_query = (f, append)  # run the latest request when this one ends
            return
        self.events.show_loading()

        def task(_progress: object) -> tuple[SearchPage, bool]:
            with self._db.connect() as conn:
                return search_events(conn, f), append

        self._query_runner.start(task, on_success=self._on_search, on_error=self._on_search_error)

    @Slot(object)
    def _on_search(self, result: tuple[SearchPage, bool]) -> None:
        page, append = result
        self.events.show_page(page, append)
        self._run_pending_query()

    @Slot(str)
    def _on_search_error(self, message: str) -> None:
        self.events.show_error(message)
        self._run_pending_query()

    def _run_pending_query(self) -> None:
        if self._pending_query is not None:
            f, append = self._pending_query
            self._pending_query = None
            QTimer.singleShot(0, lambda: self.run_event_search(f, append))

    @Slot(int)
    def _on_evidence_requested(self, detection_id: int) -> None:
        def task(_progress: object) -> tuple[int, tuple[int, ...]]:
            with self._db.connect() as conn:
                return detection_id, tuple(
                    DetectionRepository(conn).evidence_event_pks(detection_id)
                )

        # Result handlers are bound methods of this window, so Qt delivers them on the GUI thread.
        self._triage_runner.start(
            task, on_success=self._on_evidence_loaded, on_error=self._on_triage_error
        )

    @Slot(object)
    def _on_evidence_loaded(self, result: tuple[int, tuple[int, ...]]) -> None:
        detection_id, pks = result
        if not pks:
            self._set_status(f"Finding #{detection_id} has no linked evidence events.", error=True)
            return
        self.events.apply_external(
            EventFilter(event_pks=pks), f"evidence events of finding #{detection_id}"
        )
        self.select_page("Events")

    @Slot(object)
    def _open_filter_in_events(self, f: EventFilter) -> None:
        self.events.apply_external(f)
        self.select_page("Events")

    # ------------------------------------------------------------------ process tree
    @Slot(int)
    def open_process_tree(self, event_pk: int) -> None:
        self.process_tree.show_loading()
        self.select_page("Process Tree")

        def task(_progress: object) -> ProcessTree:
            with self._db.connect() as conn:
                return build_process_tree(conn, event_pk)

        if not self._timeline_runner.start(
            task, on_success=self._on_process_tree, on_error=self._on_process_tree_error
        ):
            self.process_tree.show_error("Another investigation view is loading; try again.")

    @Slot(object)
    def _on_process_tree(self, tree: ProcessTree) -> None:
        self.process_tree.show_tree(tree)
        self._run_pending_timeline()

    @Slot(str)
    def _on_process_tree_error(self, message: str) -> None:
        self.process_tree.show_error(message)
        self._run_pending_timeline()

    # ------------------------------------------------------------------ reports
    def _write_report(self, path: str, build: Callable[[Any], str]) -> None:
        def task(_progress: object) -> str:
            with self._db.connect() as conn:
                text = build(conn)
            try:
                Path(path).write_text(text, encoding="utf-8")
            except OSError as exc:
                raise MoeSOCError(f"Could not write {path}: {exc.strerror or exc}") from exc
            return f"Report saved: {path}"

        if not self._triage_runner.start(
            task, on_success=self._on_report_done, on_error=self._on_report_error
        ):
            self.reports.show_message("Another update is running; try again.")

    @Slot(object)
    def _on_report_done(self, message: str) -> None:
        self.reports.show_message(message)
        self._set_status(message)

    @Slot(str)
    def _on_report_error(self, message: str) -> None:
        self.reports.show_message(message)
        self._set_status(message, error=True)

    @Slot(str, bool)
    def _export_summary(self, path: str, redact: bool) -> None:
        db = self._db
        self._write_report(
            path, lambda conn: summary_report(conn, load_overview(db), redact=redact)
        )

    @Slot(int, str, bool)
    def _export_finding(self, detection_id: int, path: str, redact: bool) -> None:
        rules = self._rules
        self._write_report(
            path, lambda conn: finding_report(conn, detection_id, rules, redact=redact)
        )

    # ------------------------------------------------------------------ tuning
    def load_tuning(self) -> None:
        rules = self._rules

        def task(_progress: object) -> TuningSnapshot:
            with self._db.connect() as conn:
                return load_tuning(conn, rules)

        if self._tuning_runner.busy:
            # An older snapshot is still loading (or its thread is still finishing). Load
            # again once the runner is idle, so the page never shows the pre-change state.
            if not self._tuning_retry_scheduled:
                self._tuning_retry_scheduled = True
                QTimer.singleShot(50, self._retry_load_tuning)
            return
        self._tuning_runner.start(
            task, on_success=self.tuning.show_snapshot, on_error=self.tuning.show_message
        )

    def _retry_load_tuning(self) -> None:
        self._tuning_retry_scheduled = False
        self.load_tuning()

    @Slot(object)
    def _suppress_from_finding(self, prefill: dict) -> None:
        self.select_page("Tuning")
        self.tuning.open_suppression_dialog(prefill)

    def _run_tuning(self, change: Callable[[TuningRepository], str]) -> None:
        def task(_progress: object) -> str:
            with self._db.connect() as conn:
                return change(TuningRepository(conn))

        if not self._triage_runner.start(
            task, on_success=self._on_tuning_done, on_error=self._on_tuning_error
        ):
            self.tuning.show_message("Another update is still being saved; try again.")

    @Slot(object)
    def _on_tuning_done(self, message: str) -> None:
        self.tuning.show_message(message)
        self._set_status(message)
        self.load_tuning()

    @Slot(str)
    def _on_tuning_error(self, message: str) -> None:
        self.tuning.show_message(message)
        self._set_status(message, error=True)

    @Slot(object)
    def _add_suppression(self, r: SuppressionRequest) -> None:
        rules = self._rules

        def change(repo: TuningRepository) -> str:
            s = repo.add_suppression(
                r.type, r.value, r.reason, rule_id=r.rule_id, days=r.days, known_rules=rules
            )
            return f"Suppression #{s.id} added: {s.describe()}. Existing findings are unchanged."

        self._run_tuning(change)

    @Slot(int, str)
    def _remove_suppression(self, suppression_id: int, reason: str) -> None:
        self._run_tuning(
            lambda repo: (
                f"Suppression #{repo.remove_suppression(suppression_id, reason).id} "
                "removed (kept in the audit history)."
            )
        )

    @Slot(str, bool, str)
    def _set_rule_enabled(self, rule_id: str, enabled: bool, reason: str) -> None:
        rule = self._rules[rule_id]

        def change(repo: TuningRepository) -> str:
            repo.set_rule_enabled(rule, enabled, reason)
            return f"{rule_id} {'enabled' if enabled else 'disabled'} for future scans."

        self._run_tuning(change)

    @Slot(str, str, int, str)
    def _set_rule_parameter(self, rule_id: str, name: str, value: int, reason: str) -> None:
        rule = self._rules[rule_id]

        def change(repo: TuningRepository) -> str:
            repo.set_rule_parameter(rule, name, value, reason)
            return f"{rule_id}: {name} = {value} for future scans."

        self._run_tuning(change)

    # ------------------------------------------------------------------ retention
    @Slot(int)
    def _save_retention(self, days: int) -> None:
        def task(_progress: object) -> str:
            with self._db.connect() as conn:
                set_retention_days(conn, days)
            return f"Retention period saved: {days} days."

        # The message follows the result: a console without write access is refused (B-7)
        # and must not be told "saved".
        if not self._triage_runner.start(
            task, on_success=self._on_retention_saved, on_error=self._on_retention_error
        ):
            self.settings.show_retention_message("Another update is running; try again.")

    @Slot(object)
    def _on_retention_saved(self, message: str) -> None:
        self.settings.show_retention_message(message)
        self._on_triage_done(message)

    @Slot(str)
    def _on_retention_error(self, message: str) -> None:
        self.settings.show_retention_message(message)
        self._on_triage_error(message)

    @Slot(int)
    def _preview_retention(self, days: int) -> None:
        def task(_progress: object) -> RetentionPlan:
            with self._db.connect() as conn:
                return plan_retention(conn, days)

        if not self._triage_runner.start(
            task, on_success=self.settings.show_retention_plan, on_error=self._on_triage_error
        ):
            self.settings.show_retention_message("Another update is running; try again.")

    @Slot(int)
    def _apply_retention(self, days: int) -> None:
        def task(_progress: object) -> str:
            with self._db.connect() as conn:
                done = apply_retention(conn, days, confirmed=True)
            return (
                f"Retention applied: deleted {done.events:,} events, {done.findings:,} closed "
                f"findings and {done.scans:,} scan records (MoeSOC database only)."
            )

        self._run_triage(task)

    def _load_retention_setting(self) -> None:
        try:
            with self._db.connect() as conn:
                self.settings.set_retention_days(get_retention_days(conn))
        except MoeSOCError as exc:
            self.settings.show_retention_message(exc.user_message)

    # ------------------------------------------------------------------ story
    @Slot(int)
    def open_story(self, detection_id: int) -> None:
        self.story.show_loading()
        self.select_page("Story")
        rules = self._rules

        def task(_progress: object) -> Story:
            with self._db.connect() as conn:
                return build_story(conn, detection_id, rules)

        if not self._timeline_runner.start(
            task, on_success=self._on_story, on_error=self._on_story_error
        ):
            self.story.show_error("Another investigation view is loading; try again.")

    @Slot(object)
    def _on_story(self, story: Story) -> None:
        self.story.show_story(story)
        self._run_pending_timeline()

    @Slot(str)
    def _on_story_error(self, message: str) -> None:
        self.story.show_error(message)
        self._run_pending_timeline()

    def _request_sensor_scan(self) -> None:
        from moesoc.sensor.ipc import SensorClient, SensorUnavailable

        try:
            reply = SensorClient().call("scan")
        except SensorUnavailable:
            self._set_status("The MoeSOC Sensor service is not running.", error=True)
            return
        self._set_status(str(reply.get("message", "")), error=not reply.get("ok"))
        if reply.get("ok"):
            QTimer.singleShot(5000, self.refresh_data)

    # ------------------------------------------------------------------ deep link
    def open_finding(self, detection_id: int | None) -> None:
        """Show this finding (tray notification, ``--finding``); None only raises the window."""
        self.bring_to_front()
        if detection_id is None:
            return
        self._pending_finding = detection_id
        self.refresh_data()  # the finding may be newer than the loaded list

    def bring_to_front(self) -> None:
        if self.isMinimized():
            self.showNormal()
        self.show()
        self.raise_()
        self.activateWindow()

    def show_link_error(self, message: str) -> None:
        self._set_status(message, error=True)

    def _apply_pending_finding(self) -> None:
        detection_id, self._pending_finding = self._pending_finding, None
        if detection_id is None:
            return
        self.select_page("Detections")
        if not self.detections.select_detection(detection_id):
            self.detections.status_filter.setCurrentText("All")  # it may be closed
            if not self.detections.select_detection(detection_id):
                log.info("Deep link: finding #%s not found", detection_id)
                self._set_status(
                    f"Finding #{detection_id} was not found. It may have been removed by "
                    "data retention, or it belongs to another MoeSOC database.",
                    error=True,
                )
                return
        self._set_status(f"Opened finding #{detection_id}")
        log.info("Deep link: opened finding #%s", detection_id)

    @Slot(int)
    def _show_detection(self, detection_id: int) -> None:
        self.select_page("Detections")
        self.detections.select_detection(detection_id)

    @Slot(int)
    def _open_event(self, event_pk: int) -> None:
        self.events.apply_external(EventFilter(event_pks=(event_pk,)), f"event #{event_pk}")
        self.select_page("Events")

    # ------------------------------------------------------------------ timeline
    @Slot(int)
    def open_detection_timeline(self, detection_id: int) -> None:
        minutes = self.timeline.current_padding_minutes()
        self._start_timeline(
            f"Finding #{detection_id}",
            lambda conn: detection_timeline(conn, detection_id, timedelta(minutes=minutes)),
        )

    @Slot(int, int)
    def _on_padding_changed(self, detection_id: int, _minutes: int) -> None:
        self.open_detection_timeline(detection_id)

    @Slot(object, str)
    def open_pivot_timeline(self, f: EventFilter, title: str) -> None:
        self._start_timeline(title, lambda conn: pivot_timeline(conn, f, title))

    def _start_timeline(self, title: str, build: Callable[[Any], Timeline]) -> None:
        if self._timeline_runner.busy:
            self._pending_timeline = lambda: self._start_timeline(title, build)
            return
        self.timeline.show_loading(title)
        self.select_page("Timeline")

        def task(_progress: object) -> Timeline:
            with self._db.connect() as conn:
                return build(conn)

        self._timeline_runner.start(
            task, on_success=self._on_timeline, on_error=self._on_timeline_error
        )

    @Slot(object)
    def _on_timeline(self, timeline: Timeline) -> None:
        self.timeline.show_timeline(timeline)
        self._run_pending_timeline()

    @Slot(str)
    def _on_timeline_error(self, message: str) -> None:
        self.timeline.show_error(message)
        self._run_pending_timeline()

    def _run_pending_timeline(self) -> None:
        if self._pending_timeline is not None:
            pending, self._pending_timeline = self._pending_timeline, None
            QTimer.singleShot(0, pending)

    # ------------------------------------------------------------------ triage
    @Slot(int, str)
    def _on_status_requested(self, detection_id: int, status: str) -> None:
        through = self._writes_through_sensor()
        self._run_triage(
            lambda _p: triage_actions.set_triage(self._db, detection_id, status, through)
        )

    @Slot(int, str)
    def _on_note_requested(self, detection_id: int, body: str) -> None:
        through = self._writes_through_sensor()
        self._run_triage(lambda _p: triage_actions.add_note(self._db, detection_id, body, through))

    def _writes_through_sensor(self) -> bool:
        """B-7: a console that may only read the sensor's database (no administrator
        rights) sends triage and notes to the sensor, which stays the only writer."""
        return self._sensor_mode and self._db.read_only

    def _run_triage(self, task: Callable[[Any], str]) -> None:
        if not self._triage_runner.start(
            task, on_success=self._on_triage_done, on_error=self._on_triage_error
        ):
            self._set_status("Another update is still being saved; try again.", error=True)

    @Slot(object)
    def _on_triage_done(self, message: str) -> None:
        self._set_status(message)
        self.refresh_data()

    @Slot(str)
    def _on_triage_error(self, message: str) -> None:
        self._set_status(message, error=True)

    # ------------------------------------------------------------------ shutdown
    @property
    def _runners(self) -> tuple[TaskRunner, ...]:
        return (
            self._scan_runner,
            self._load_runner,
            self._health_runner,
            self._query_runner,
            self._timeline_runner,
            self._triage_runner,
            self._tuning_runner,
        )

    def closeEvent(self, event: QCloseEvent) -> None:
        self._live.stop(wait=True)
        for runner in self._runners:
            runner.wait()
        super().closeEvent(event)
