"""Process Tree page: parents and children of one process, shown as evidence."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import (
    QHBoxLayout,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from moesoc.gui import theme
from moesoc.gui.widgets.common import StatefulView, label
from moesoc.storage.event_search import EventFilter, around_filter
from moesoc.storage.process_tree import ProcessNode, ProcessTree
from moesoc.utils.time import format_local

COLUMNS = ("PROCESS", "PID", "USER", "STARTED", "INTEGRITY", "LINK", "EVENT #")
LINK_TEXT = {
    "root": "selected",
    "guid": "ProcessGuid",
    "pid": "PID match (weaker)",
    "recorded only": "parent not collected",
}
PK_ROLE = Qt.ItemDataRole.UserRole


class ProcessTreePage(QWidget):
    pivot_requested = Signal(object, str)  # EventFilter, title
    open_event_requested = Signal(int)  # event pk → Events page drill-down

    def __init__(self) -> None:
        super().__init__()
        self._nodes: dict[int, ProcessNode] = {}
        layout = QVBoxLayout(self)
        layout.setContentsMargins(theme.SPACE_6, theme.SPACE_4, theme.SPACE_6, theme.SPACE_6)
        layout.setSpacing(theme.SPACE_3)
        self.title = label("No process selected", "banner")
        self.subtitle = label(
            "A process tree is evidence, not a verdict. Select a process event in Events "
            "and choose Process tree.",
            "caption",
            wrap=True,
        )
        layout.addWidget(self.title)
        layout.addWidget(self.subtitle)

        actions = QHBoxLayout()
        actions.addWidget(label("Selected process:", "caption"))
        self.open_raw = QPushButton("Open raw event")
        self.pivot_process = QPushButton("This process")
        self.pivot_user = QPushButton("This user")
        self.pivot_time = QPushButton("Around this time")
        for button in (self.open_raw, self.pivot_process, self.pivot_user, self.pivot_time):
            button.setEnabled(False)
            actions.addWidget(button)
        actions.addStretch(1)
        layout.addLayout(actions)
        self.open_raw.clicked.connect(self._open_raw)
        self.pivot_process.clicked.connect(self._pivot_process)
        self.pivot_user.clicked.connect(self._pivot_user)
        self.pivot_time.clicked.connect(self._pivot_time)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(len(COLUMNS))
        self.tree.setHeaderLabels(COLUMNS)
        self.tree.setAlternatingRowColors(True)
        self.tree.itemSelectionChanged.connect(self._on_selection)
        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.detail.setPlaceholderText("Select a process to see its path and command line.")
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.tree)
        splitter.addWidget(self.detail)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        self.view = StatefulView(splitter, "No process tree", "Choose a process event in Events.")
        layout.addWidget(self.view, 1)

    # ------------------------------------------------------------------ data
    def show_loading(self) -> None:
        self.view.show_loading()

    def show_error(self, message: str) -> None:
        self.view.show_error(message)

    def show_tree(self, tree: ProcessTree) -> None:
        self.tree.clear()
        self._nodes.clear()
        parent_item: QTreeWidgetItem | None = None
        for node in tree.ancestors:
            item = self._item(node)
            if parent_item is None:
                self.tree.addTopLevelItem(item)
            else:
                parent_item.addChild(item)
            parent_item = item
        root_item = self._item(tree.root)
        if parent_item is None:
            self.tree.addTopLevelItem(root_item)
        else:
            parent_item.addChild(root_item)
        self._add_children(root_item, tree.root)
        font = root_item.font(0)
        font.setBold(True)
        for column in range(len(COLUMNS)):
            root_item.setFont(column, font)
        self.tree.expandAll()
        for column in range(len(COLUMNS)):
            self.tree.resizeColumnToContents(column)
        self.tree.setCurrentItem(root_item)
        self.title.setText(f"Process tree · {tree.root.name}")
        note = f"{tree.node_count} processes"
        if tree.truncated:
            note += " (limit reached; not all descendants are shown)"
        self.subtitle.setText(
            f"{note}. Links by Sysmon ProcessGuid are exact; PID matches (4688) are weaker "
            "because Windows reuses PIDs. A tree is evidence, not a verdict."
        )
        self.view.show_content()

    def _item(self, node: ProcessNode) -> QTreeWidgetItem:
        item = QTreeWidgetItem(
            [
                node.name,
                "" if node.pid is None else str(node.pid),
                node.user or "—",
                format_local(node.started) if node.started else "—",
                node.integrity or "—",
                LINK_TEXT.get(node.link, node.link),
                "" if node.pk is None else f"#{node.pk}",
            ]
        )
        key = id(item)
        self._nodes[key] = node
        item.setData(0, PK_ROLE, key)
        return item

    def _add_children(self, item: QTreeWidgetItem, node: ProcessNode) -> None:
        for child in node.children:
            child_item = self._item(child)
            item.addChild(child_item)
            self._add_children(child_item, child)

    # ------------------------------------------------------------------ interaction
    def selected_node(self) -> ProcessNode | None:
        items = self.tree.selectedItems()
        if not items:
            return None
        return self._nodes.get(items[0].data(0, PK_ROLE))

    def _on_selection(self) -> None:
        node = self.selected_node()
        has_event = bool(node and node.event)
        self.open_raw.setEnabled(bool(node and node.pk is not None))
        self.pivot_process.setEnabled(bool(node and node.path))
        self.pivot_user.setEnabled(bool(node and node.event and node.event.subject_username))
        self.pivot_time.setEnabled(has_event)
        if node:
            lines = [f"Path: {node.path or '—'}", f"Process GUID: {node.guid or '—'}"]
            if node.command_line:
                lines.append(f"Command line: {node.command_line}")
            elif node.event is not None:
                lines.append("Command line: Unavailable")
            self.detail.setPlainText("\n".join(lines))  # plain text, never executed

    def _open_raw(self) -> None:
        node = self.selected_node()
        if node and node.pk is not None:
            self.open_event_requested.emit(node.pk)

    def _pivot_process(self) -> None:
        node = self.selected_node()
        if node and node.name:
            self.pivot_requested.emit(EventFilter(process=node.name), f"Events for {node.name}")

    def _pivot_user(self) -> None:
        node = self.selected_node()
        if node and node.event and node.event.subject_username:
            e = node.event
            self.pivot_requested.emit(
                EventFilter(username=e.subject_username, domain=e.subject_domain),
                f"Events for {node.user}",
            )

    def _pivot_time(self) -> None:
        node = self.selected_node()
        if node and node.event:
            e = node.event
            self.pivot_requested.emit(
                around_filter(e.timestamp, e.hostname, 15),
                f"Events around {format_local(e.timestamp)} on {e.hostname}",
            )
