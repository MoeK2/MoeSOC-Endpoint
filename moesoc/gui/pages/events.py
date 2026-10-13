"""Events page: database-side filtering, pagination and raw XML inspection."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

from PySide6.QtCore import QItemSelection, Qt, Signal, Slot
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import (
    QComboBox,
    QGridLayout,
    QHBoxLayout,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from moesoc.core.enums import LOGON_TYPE_NAMES
from moesoc.core.event import NormalizedEvent
from moesoc.gui import theme
from moesoc.gui.widgets.common import StatefulView, label
from moesoc.gui.widgets.tables import Column, RecordTableModel, make_table
from moesoc.storage.event_search import EventFilter, SearchPage, StoredEvent, around_filter
from moesoc.storage.process_tree import is_process_event
from moesoc.utils.time import format_local, utc_now

TIME_RANGES = {
    "All time": None,
    "Last hour": timedelta(hours=1),
    "Last 24 hours": timedelta(hours=24),
    "Last 7 days": timedelta(days=7),
    "Last 30 days": timedelta(days=30),
}
OUTCOMES = {
    4624: "Success",
    4625: "Failure",
    1102: "Log cleared",
    4672: "Privileged logon",
    4688: "Process created",
    4720: "Account created",
    4732: "Added to group",
}

SOURCE_NAMES = {
    "security": "Security",
    "sysmon": "Sysmon",
    "powershell": "PowerShell",
    "defender": "Defender",
}
# EventFilter field → (label, placeholder). All are matched in SQLite, never in Python.
ADVANCED_FIELDS = {
    "provider": ("Provider", "contains…"),
    "sid": ("SID", "exact S-1-5-…"),
    "port": ("Port", "source or destination"),
    "parent_process": ("Parent process", "contains…"),
    "file_path": ("File path", "contains…"),
    "registry_path": ("Registry path", "contains…"),
    "dns_query": ("DNS query", "contains…"),
    "threat": ("Defender threat", "contains…"),
}


def _object(e: NormalizedEvent) -> str:
    """What a context event touched: remote endpoint, file, registry key or DNS name."""
    if e.destination_ip:
        return f"{e.destination_ip}:{e.destination_port or '?'}"
    if e.source.value == "defender" and e.detail("threat_name"):
        return f"{e.detail('threat_name')} · {e.file_path or 'no file'}"
    return e.dns_query or e.file_path or e.registry_path or e.group_name or "—"


def _command_line(event: NormalizedEvent) -> str:
    """4688 without a command line says so; other events have none to show."""
    if event.command_line:
        return event.command_line
    return "Unavailable" if event.event_id == 4688 else "—"


SYSMON_OUTCOMES = {
    1: "Process created (Sysmon)",
    3: "Network connection (Sysmon)",
    11: "File created (Sysmon)",
    13: "Registry value set (Sysmon)",
    22: "DNS query (Sysmon)",
}

DEFENDER_OUTCOMES = {
    1116: "Defender detection",
    1117: "Defender action taken",
    1118: "Defender action failed",
    1119: "Defender action failed (critical)",
}


def _outcome(e: NormalizedEvent) -> str:
    if e.source.value == "sysmon":
        return SYSMON_OUTCOMES.get(e.event_id, f"Sysmon {e.event_id}")
    if e.source.value == "defender":
        return DEFENDER_OUTCOMES.get(e.event_id, f"Defender {e.event_id}")
    if e.source.value == "powershell":
        flagged = e.detail("windows_flagged")
        return "Script block (flagged by PowerShell)" if flagged else "Script block"
    return OUTCOMES.get(e.event_id, "—")


def _parse_ids(text: str) -> tuple[int, ...] | None:
    """'4624, 4625' → (4624, 4625). None when the text is not a valid list."""
    parts = [p.strip() for p in text.replace(";", ",").split(",") if p.strip()]
    if not all(p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts)


class EventsPage(QWidget):
    search_requested = Signal(object, bool)  # EventFilter, append (load more)
    timeline_requested = Signal(object, str)  # EventFilter, title
    process_tree_requested = Signal(int)  # stored event pk

    def __init__(self) -> None:
        super().__init__()
        self._filter = EventFilter()
        self._locked: EventFilter | None = None  # drill-down filter (evidence events)
        self._rows: list[StoredEvent] = []
        self._description: str | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(theme.SPACE_6, theme.SPACE_4, theme.SPACE_6, theme.SPACE_6)
        layout.setSpacing(theme.SPACE_3)
        layout.addLayout(self._build_filters())

        status = QHBoxLayout()
        self.caption = label("", "caption")
        self.clear_drilldown = QPushButton("Clear drill-down")
        self.clear_drilldown.setVisible(False)
        self.clear_drilldown.clicked.connect(self._clear_locked)
        self.load_more = QPushButton("Load more")
        self.load_more.setVisible(False)
        self.load_more.clicked.connect(
            lambda: self.search_requested.emit(replace(self._filter, offset=len(self._rows)), True)
        )
        self.timeline_button = QPushButton("Timeline around event")
        self.timeline_button.setEnabled(False)
        self.timeline_button.clicked.connect(self._timeline_around)
        status.addWidget(self.caption, 1)
        status.addWidget(self.clear_drilldown)
        status.addWidget(self.timeline_button)
        self.tree_button = QPushButton("Process tree")
        self.tree_button.setEnabled(False)
        self.tree_button.setToolTip("Parents and children of the selected process event")
        self.tree_button.clicked.connect(self._process_tree)
        status.addWidget(self.tree_button)
        status.addWidget(self.load_more)
        layout.addLayout(status)

        self.model = RecordTableModel(
            [
                Column(
                    "TIME", lambda s: format_local(s.event.timestamp), lambda s: s.event.timestamp
                ),
                Column("EVENT ID", lambda s: str(s.event.event_id), lambda s: s.event.event_id),
                Column("OUTCOME", lambda s: _outcome(s.event)),
                Column(
                    "ACCOUNT",
                    lambda s: s.event.target_account_display or s.event.subject_username or "—",
                ),
                Column("LOGON TYPE", lambda s: s.event.logon_type_name or "—"),
                Column("SOURCE ADDRESS", lambda s: s.event.source_ip or "—"),
                Column("WORKSTATION", lambda s: s.event.workstation_name or "—"),
                Column("FAILURE REASON", lambda s: s.event.failure_reason or "—"),
                Column("PROCESS", lambda s: s.event.process_name or "—"),
                Column("COMMAND LINE", lambda s: _command_line(s.event)),
                Column("OBJECT", lambda s: _object(s.event)),
                Column("HOST", lambda s: s.event.hostname),
                Column("RECORD ID", lambda s: str(s.event.record_id), lambda s: s.event.record_id),
            ]
        )
        self.table, self.proxy = make_table(self.model, stretch_column=3)
        self.table.setSortingEnabled(False)  # order comes from the database query
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
            splitter, "No events stored yet", "Run a scan to collect Windows security events."
        )
        layout.addWidget(self.view, 1)

    # ------------------------------------------------------------------ filters
    def _build_filters(self) -> QGridLayout:
        grid = QGridLayout()
        grid.setHorizontalSpacing(theme.SPACE_2)
        grid.setVerticalSpacing(theme.SPACE_1)
        self.time_range = QComboBox()
        self.time_range.addItems(TIME_RANGES)
        self.event_ids = QLineEdit()
        self.event_ids.setPlaceholderText("4624, 4625")
        self.user = QLineEdit()
        self.user.setPlaceholderText("contains…")
        self.domain = QLineEdit()
        self.domain.setPlaceholderText("exact")
        self.ip = QLineEdit()
        self.ip.setPlaceholderText("address or prefix")
        self.logon_type = QComboBox()
        self.logon_type.addItem("Any", None)
        for number, name in LOGON_TYPE_NAMES.items():
            self.logon_type.addItem(f"{number} · {name}", number)
        self.process = QLineEdit()
        self.process.setPlaceholderText("name or path")
        self.text = QLineEdit()
        self.text.setPlaceholderText("search normalized fields…")
        self.source = QComboBox()
        self.source.addItem("Any", None)
        for value, name in SOURCE_NAMES.items():
            self.source.addItem(name, value)
        self.advanced: dict[str, QLineEdit] = {}
        for key, (_title, hint) in ADVANCED_FIELDS.items():
            edit = QLineEdit()
            edit.setPlaceholderText(hint)
            self.advanced[key] = edit
        self.more = QPushButton("More filters")
        self.more.setCheckable(True)
        self.more.toggled.connect(self._toggle_advanced)
        apply = QPushButton("Apply")
        apply.setProperty("variant", "primary")
        apply.clicked.connect(self.apply_filters)
        reset = QPushButton("Reset")
        reset.clicked.connect(self.reset_filters)
        for edit in self._text_edits():
            edit.setClearButtonEnabled(True)
            edit.returnPressed.connect(self.apply_filters)

        fields = [
            ("Time", self.time_range),
            ("Event IDs", self.event_ids),
            ("User", self.user),
            ("Domain", self.domain),
            ("IP", self.ip),
            ("Logon type", self.logon_type),
            ("Process", self.process),
            ("Text", self.text),
        ]
        for col, (name, widget) in enumerate(fields):
            grid.addWidget(label(name, "caption"), 0, col)
            grid.addWidget(widget, 1, col)
            grid.setColumnStretch(col, 1)
        grid.addWidget(apply, 1, len(fields))
        grid.addWidget(reset, 1, len(fields) + 1)
        grid.addWidget(self.more, 1, len(fields) + 2)

        # Second row, hidden until "More filters": every other indexed or normalized field.
        advanced = [("Source", self.source)] + [
            (ADVANCED_FIELDS[key][0], edit) for key, edit in self.advanced.items()
        ]
        self._advanced_widgets: list[QWidget] = []
        for col, (name, widget) in enumerate(advanced):
            caption = label(name, "caption")
            grid.addWidget(caption, 2, col)
            grid.addWidget(widget, 3, col)
            self._advanced_widgets += [caption, widget]
        self._toggle_advanced(False)
        self.error = label("", "error")
        grid.addWidget(self.error, 4, 0, 1, len(fields) + 3)
        return grid

    def _text_edits(self) -> list[QLineEdit]:
        basic = [self.event_ids, self.user, self.domain, self.ip, self.process, self.text]
        return [*basic, *self.advanced.values()]

    @Slot(bool)
    def _toggle_advanced(self, shown: bool) -> None:
        for widget in self._advanced_widgets:
            widget.setVisible(shown)

    def current_filter(self) -> EventFilter | None:
        ids = _parse_ids(self.event_ids.text())
        if ids is None:
            self.error.setText("Event IDs must be numbers separated by commas.")
            return None
        port_text = self.advanced["port"].text().strip()
        if port_text and not (port_text.isdigit() and 0 <= int(port_text) <= 65535):
            self.error.setText("Port must be a number from 0 to 65535.")
            return None
        self.error.setText("")
        adv = {k: (e.text().strip() or None) for k, e in self.advanced.items() if k != "port"}
        source = self.source.currentData()
        span = TIME_RANGES[self.time_range.currentText()]
        return EventFilter(
            start=utc_now() - span if span else None,
            event_ids=ids,
            username=self.user.text() or None,
            domain=self.domain.text() or None,
            ip=self.ip.text() or None,
            logon_type=self.logon_type.currentData(),
            process=self.process.text() or None,
            text=self.text.text() or None,
            sources=(source,) if source else (),
            port=int(port_text) if port_text else None,
            **adv,
        )

    @Slot()
    def apply_filters(self) -> None:
        f = self.current_filter()
        if f is None:
            return
        if self._locked is not None:
            f = replace(f, event_pks=self._locked.event_pks)
        else:
            self._description = None
        self.search_requested.emit(f, False)

    @Slot()
    def reset_filters(self) -> None:
        for edit in self._text_edits():
            edit.clear()
        self.source.setCurrentIndex(0)
        self.time_range.setCurrentText("All time")
        self.logon_type.setCurrentIndex(0)
        self._locked = None
        self.clear_drilldown.setVisible(False)
        self.apply_filters()

    def apply_external(self, f: EventFilter, description: str | None = None) -> None:
        """Show results for a filter set elsewhere (drill-down or pivot)."""
        self.reset_widgets_only()
        if f.event_pks:
            self._locked = f
            self.clear_drilldown.setVisible(True)
        else:
            self.user.setText(f.username or "")
            self.domain.setText(f.domain or "")
            self.ip.setText(f.ip or "")
            self.process.setText(f.process or "")
            for key, edit in self.advanced.items():
                value = getattr(f, key)
                edit.setText("" if value is None else str(value))
            if any(getattr(f, key) is not None for key in self.advanced):
                self.more.setChecked(True)
        self._description = description
        self.search_requested.emit(f, False)

    def reset_widgets_only(self) -> None:
        for edit in self._text_edits():
            edit.clear()
        self.source.setCurrentIndex(0)
        self.time_range.setCurrentText("All time")
        self.logon_type.setCurrentIndex(0)
        self._locked = None
        self.clear_drilldown.setVisible(False)

    def _clear_locked(self) -> None:
        self._locked = None
        self._description = None
        self.clear_drilldown.setVisible(False)
        self.apply_filters()

    # ------------------------------------------------------------------ results
    def show_loading(self) -> None:
        self.caption.setText("Searching…")

    def show_page(self, page: SearchPage, append: bool) -> None:
        self._filter = page.filter
        self._rows = [*self._rows, *page.events] if append else list(page.events)
        self.model.set_rows(self._rows)
        if not append:
            self.raw.clear()
        description = self._description or page.filter.describe()
        self.caption.setText(
            f"Showing {len(self._rows):,} of {page.total:,} matching events · {description}"
        )
        self.load_more.setVisible(len(self._rows) < page.total)
        if self._rows:
            self.view.show_content()
        elif page.filter == EventFilter():
            self.view.show_empty("No events stored yet", "Run a scan to collect Windows events.")
        else:
            self.view.show_empty("No matching events", "Change or reset the filters.")

    def show_error(self, message: str) -> None:
        self.caption.setText("")
        self.view.show_error(message)

    def _selected(self) -> StoredEvent | None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None
        return self.model.row_at(self.proxy.mapToSource(rows[0]).row())

    @Slot(QItemSelection, QItemSelection)
    def _on_selection(self, _selected: QItemSelection, _deselected: QItemSelection) -> None:
        stored = self._selected()
        self.timeline_button.setEnabled(stored is not None)
        self.tree_button.setEnabled(stored is not None and is_process_event(stored.event))
        if stored:
            # Shown as plain text only — event content is never interpreted or executed.
            self.raw.setPlainText(stored.event.raw_xml)

    def _process_tree(self) -> None:
        stored = self._selected()
        if stored and is_process_event(stored.event):
            self.process_tree_requested.emit(stored.pk)

    def _timeline_around(self) -> None:
        stored = self._selected()
        if stored:
            e = stored.event
            self.timeline_requested.emit(
                around_filter(e.timestamp, e.hostname, 15),
                f"Events around {format_local(e.timestamp)} on {e.hostname}",
            )
