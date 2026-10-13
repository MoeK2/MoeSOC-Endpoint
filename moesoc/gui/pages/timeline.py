"""Investigation Timeline: what happened before, during and after a finding."""

from __future__ import annotations

from PySide6.QtCore import QItemSelection, Qt, Signal, Slot
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from moesoc.core.enums import HealthState, Severity
from moesoc.gui import theme
from moesoc.gui.widgets.common import StatefulView, label
from moesoc.gui.widgets.tables import Column, PillDelegate, RecordTableModel, make_table
from moesoc.storage.event_search import (
    EventFilter,
    Timeline,
    TimelineItem,
    around_filter,
    more_pivots,
)
from moesoc.utils.time import format_local

PADDING_CHOICES = {"±5 minutes": 5, "±15 minutes": 15, "±1 hour": 60, "±6 hours": 360}


def badge_color(badge: str) -> str:
    p = theme.ACTIVE
    return {
        "Evidence": p.accent,
        "Failure": p.severity[Severity.MEDIUM],
        "Success": p.health[HealthState.AVAILABLE],
        "Log cleared": p.severity[Severity.CRITICAL],
    }.get(badge, p.text_faint)


class TimelinePage(QWidget):
    """Shows a Timeline loaded by the main window; asks it to load pivots."""

    padding_changed = Signal(int, int)  # detection id, minutes
    pivot_requested = Signal(object, str)  # EventFilter, title
    open_in_events = Signal(object)  # EventFilter

    def __init__(self) -> None:
        super().__init__()
        self._timeline: Timeline | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(theme.SPACE_6, theme.SPACE_4, theme.SPACE_6, theme.SPACE_6)
        layout.setSpacing(theme.SPACE_3)

        header = QHBoxLayout()
        titles = QVBoxLayout()
        titles.setSpacing(2)
        self.title = label("No investigation open", "banner")
        self.subtitle = label("", "caption", wrap=True)
        titles.addWidget(self.title)
        titles.addWidget(self.subtitle)
        header.addLayout(titles, 1)
        header.addWidget(label("Window", "caption"))
        self.padding = QComboBox()
        self.padding.addItems(PADDING_CHOICES)
        self.padding.setCurrentText("±15 minutes")
        self.padding.setToolTip("Context shown before the first and after the last evidence event")
        self.padding.currentTextChanged.connect(self._on_padding)
        header.addWidget(self.padding)
        layout.addLayout(header)

        pivots = QHBoxLayout()
        pivots.setSpacing(theme.SPACE_1)
        pivots.addWidget(label("Pivot on selected event:", "caption"))
        self.pivot_user = QPushButton("This user")
        self.pivot_ip = QPushButton("This IP")
        self.pivot_time = QPushButton("Around this time")
        self.pivot_process = QPushButton("This process")
        self.to_events = QPushButton("Open in Events")
        self.to_events.setToolTip("Open the current view in the Events page with full filters")
        self.more_pivots = QPushButton("More pivots")
        self.more_pivots.setToolTip(
            "Logon session, destination, parent, file, registry, DNS, Defender threat, SID"
        )
        self.more_pivots_menu = QMenu(self.more_pivots)
        self.more_pivots.setMenu(self.more_pivots_menu)
        for button in (
            self.pivot_user,
            self.pivot_ip,
            self.pivot_time,
            self.pivot_process,
            self.more_pivots,
        ):
            pivots.addWidget(button)
        pivots.addStretch(1)
        pivots.addWidget(self.to_events)
        layout.addLayout(pivots)
        self.pivot_user.clicked.connect(self._pivot_user)
        self.pivot_ip.clicked.connect(self._pivot_ip)
        self.pivot_time.clicked.connect(self._pivot_time)
        self.pivot_process.clicked.connect(self._pivot_process)
        self.to_events.clicked.connect(self._open_in_events)

        self.model = RecordTableModel(
            [
                Column(
                    "TIME", lambda i: format_local(i.event.timestamp), lambda i: i.event.timestamp
                ),
                Column("CONTEXT", lambda i: i.badge),
                Column("EVENT", lambda i: str(i.event.event_id), lambda i: i.event.event_id),
                Column("WHAT HAPPENED", lambda i: i.explanation, tooltip=lambda i: i.explanation),
                Column("USER", lambda i: i.event.target_account_display or "—"),
                Column("HOST", lambda i: i.event.hostname),
                Column("IP", lambda i: i.event.source_ip or "—"),
                Column("PROCESS", lambda i: i.event.process_name or "—"),
                Column("RECORD", lambda i: str(i.event.record_id), lambda i: i.event.record_id),
            ]
        )
        self.table, self.proxy = make_table(self.model, stretch_column=3)
        self.table.setItemDelegateForColumn(1, PillDelegate(self.table, badge_color))
        self.table.selectionModel().selectionChanged.connect(self._on_selection)

        self.raw = QPlainTextEdit()
        self.raw.setReadOnly(True)
        self.raw.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.raw.setPlaceholderText("Select an event to inspect its original XML.")

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.table)
        splitter.addWidget(self.raw)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        splitter.setChildrenCollapsible(False)
        self.view = StatefulView(
            splitter,
            "No investigation open",
            "Open a detection and choose Open Timeline, or pivot from an event.",
        )
        layout.addWidget(self.view, 1)
        self._set_pivots_enabled(None)

    # ------------------------------------------------------------------ data
    def show_loading(self, title: str) -> None:
        self.title.setText(title)
        self.subtitle.setText("")
        self.view.show_loading()

    def show_error(self, message: str) -> None:
        self.view.show_error(message)

    def show_timeline(self, timeline: Timeline) -> None:
        self._timeline = timeline
        self.title.setText(timeline.title)
        parts = [
            f"{format_local(timeline.window_start)} → {format_local(timeline.window_end)}",
            f"{len(timeline.items):,} events shown of {timeline.total_in_window:,}",
        ]
        if timeline.detection is not None:
            parts.append(f"{timeline.evidence_count} evidence events highlighted")
        parts += timeline.notes
        self.subtitle.setText(" · ".join(parts))
        self.padding.setEnabled(timeline.detection is not None)
        self.model.set_rows(timeline.items)
        self.raw.clear()
        self._set_pivots_enabled(None)
        if timeline.items:
            self.view.show_content()
            first_evidence = next((n for n, i in enumerate(timeline.items) if i.is_evidence), None)
            if first_evidence is not None:
                self.table.selectRow(
                    self.proxy.mapFromSource(self.model.index(first_evidence, 0)).row()
                )
        else:
            self.view.show_empty("No events in this window", "Try a wider window or another pivot.")

    # ------------------------------------------------------------------ interaction
    def _selected(self) -> TimelineItem | None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None
        return self.model.row_at(self.proxy.mapToSource(rows[0]).row())

    def _set_pivots_enabled(self, item: TimelineItem | None) -> None:
        e = item.event if item else None
        self.pivot_user.setEnabled(bool(e and (e.target_username or e.subject_username)))
        self.pivot_ip.setEnabled(bool(e and e.source_ip))
        self.pivot_time.setEnabled(e is not None)
        self.pivot_process.setEnabled(bool(e and e.process_name))
        self.more_pivots_menu.clear()
        for pivot in more_pivots(e) if e else []:
            action = self.more_pivots_menu.addAction(pivot.label)
            action.triggered.connect(
                lambda _checked=False, p=pivot: self.pivot_requested.emit(p.filter, p.title)
            )
        self.more_pivots.setEnabled(bool(self.more_pivots_menu.actions()))
        self.to_events.setEnabled(self._timeline is not None)

    @Slot(QItemSelection, QItemSelection)
    def _on_selection(self, _selected: QItemSelection, _deselected: QItemSelection) -> None:
        item = self._selected()
        self._set_pivots_enabled(item)
        if item:
            # Plain text only: event content is never interpreted or executed.
            self.raw.setPlainText(item.event.raw_xml)

    def _on_padding(self, text: str) -> None:
        if self._timeline and self._timeline.detection is not None:
            self.padding_changed.emit(self._timeline.detection.id, PADDING_CHOICES[text])

    def current_padding_minutes(self) -> int:
        return PADDING_CHOICES[self.padding.currentText()]

    def _pivot_user(self) -> None:
        item = self._selected()
        if item:
            e = item.event
            user = e.target_username or e.subject_username or ""
            domain = e.target_domain if e.target_username else e.subject_domain
            account = f"{domain}\\{user}" if domain else user
            self.pivot_requested.emit(
                EventFilter(username=user, domain=domain), f"Events for {account}"
            )

    def _pivot_ip(self) -> None:
        item = self._selected()
        if item and item.event.source_ip:
            ip = item.event.source_ip
            self.pivot_requested.emit(EventFilter(ip=ip), f"Events from {ip}")

    def _pivot_time(self) -> None:
        item = self._selected()
        if item:
            e = item.event
            self.pivot_requested.emit(
                around_filter(e.timestamp, e.hostname, 15),
                f"Events around {format_local(e.timestamp)} on {e.hostname}",
            )

    def _pivot_process(self) -> None:
        item = self._selected()
        if item and item.event.process_name:
            name = item.event.process_name
            self.pivot_requested.emit(EventFilter(process=name), f"Events for process {name}")

    def _open_in_events(self) -> None:
        t = self._timeline
        if t is None:
            return
        host = t.detection.evidence.get("hostname") if t.detection else None
        self.open_in_events.emit(EventFilter(start=t.window_start, end=t.window_end, hostname=host))
