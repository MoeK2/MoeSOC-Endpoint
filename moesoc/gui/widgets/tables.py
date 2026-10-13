"""Table models and the severity badge delegate."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QObject,
    QPersistentModelIndex,
    QRectF,
    QSortFilterProxyModel,
    Qt,
)
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QTableView,
)

from moesoc.gui.widgets.common import severity_color

SORT_ROLE = Qt.ItemDataRole.UserRole + 1
ROW_HEIGHT = 36

Index = QModelIndex | QPersistentModelIndex


@dataclass(frozen=True, slots=True)
class Column:
    title: str
    display: Callable[[Any], str]
    sort_key: Callable[[Any], Any] | None = None
    tooltip: Callable[[Any], str] | None = None


class RecordTableModel(QAbstractTableModel):
    """Read-only table over a list of Python records described by ``Column``s."""

    def __init__(self, columns: Sequence[Column]) -> None:
        super().__init__()
        self._columns = list(columns)
        self._rows: list[Any] = []

    def set_rows(self, rows: Sequence[Any]) -> None:
        self.beginResetModel()
        self._rows = list(rows)
        self.endResetModel()

    def row_at(self, row: int) -> Any:
        return self._rows[row]

    def rowCount(self, parent: Index = QModelIndex()) -> int:  # noqa: B008
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: Index = QModelIndex()) -> int:  # noqa: B008
        return 0 if parent.isValid() else len(self._columns)

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self._columns[section].title
        return None

    def data(self, index: Index, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        record = self._rows[index.row()]
        column = self._columns[index.column()]
        if role == Qt.ItemDataRole.DisplayRole:
            return column.display(record)
        if role == SORT_ROLE:
            return column.sort_key(record) if column.sort_key else column.display(record)
        if role == Qt.ItemDataRole.ToolTipRole and column.tooltip:
            return column.tooltip(record)
        return None


class PillDelegate(QStyledItemDelegate):
    """Paints the cell text as a small colored pill. ``color_for`` maps text → color."""

    def __init__(self, parent: QObject | None, color_for: Callable[[str], str]) -> None:
        super().__init__(parent)
        self._color_for = color_for

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index: Index) -> None:
        text = str(index.data(Qt.ItemDataRole.DisplayRole) or "")
        # Let the style draw the cell background (selection, hover, row border)...
        base = QStyleOptionViewItem(option)
        self.initStyleOption(base, index)
        base.text = ""
        widget = base.widget
        style = widget.style() if widget is not None else None
        if style is not None:
            style.drawControl(QStyle.ControlElement.CE_ItemViewItem, base, painter, widget)
        # ...then paint the pill on top.
        color = QColor(self._color_for(text))
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        metrics = option.fontMetrics
        width = metrics.horizontalAdvance(text) + 16
        height = metrics.height() + 6
        rect = QRectF(
            option.rect.x() + 8,
            option.rect.y() + (option.rect.height() - height) / 2,
            width,
            height,
        )
        fill = QColor(color)
        fill.setAlpha(40)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(fill)
        painter.drawRoundedRect(rect, height / 2, height / 2)
        painter.setPen(color)
        font = option.font
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, text)
        painter.restore()


def make_table(
    model: RecordTableModel, stretch_column: int | None
) -> tuple[QTableView, QSortFilterProxyModel]:
    proxy = QSortFilterProxyModel()
    proxy.setSourceModel(model)
    proxy.setSortRole(SORT_ROLE)
    proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
    proxy.setFilterKeyColumn(-1)  # filter across all columns

    view = QTableView()
    view.setModel(proxy)
    view.setSortingEnabled(True)
    view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    view.setShowGrid(False)
    view.setWordWrap(False)
    view.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
    view.verticalHeader().setVisible(False)
    view.verticalHeader().setDefaultSectionSize(ROW_HEIGHT)
    header = view.horizontalHeader()
    header.setHighlightSections(False)
    header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
    header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    if stretch_column is None:
        header.setStretchLastSection(True)  # every column fits its content; last fills
    else:
        header.setSectionResizeMode(stretch_column, QHeaderView.ResizeMode.Stretch)
    return view, proxy


class SeverityDelegate(PillDelegate):
    """Severity pill (LOW, MEDIUM, HIGH, CRITICAL)."""

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent, severity_color)
