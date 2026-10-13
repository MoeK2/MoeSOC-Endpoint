"""Reusable building blocks: cards, metrics, empty states, status chips."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from moesoc.core.enums import HealthState, Severity
from moesoc.gui import theme


def label(text: str = "", role: str | None = None, *, wrap: bool = False) -> QLabel:
    widget = QLabel(text)
    if role:
        widget.setProperty("role", role)
    widget.setWordWrap(wrap)
    widget.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return widget


class Card(QFrame):
    """Rounded surface with an optional title. Add content to ``body``."""

    def __init__(self, title: str | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(theme.SPACE_4, theme.SPACE_4, theme.SPACE_4, theme.SPACE_4)
        self.body.setSpacing(theme.SPACE_2)
        if title:
            self.body.addWidget(label(title.upper(), "cardTitle"))


class StatCard(Card):
    """A single real metric with a caption explaining what it means."""

    def __init__(self, title: str, caption: str, parent: QWidget | None = None) -> None:
        super().__init__(title, parent)
        self.value = label("—", "metric")
        self.caption = label(caption, "caption", wrap=True)
        self.body.addWidget(self.value)
        self.body.addWidget(self.caption)
        self.body.addStretch(1)

    def set_value(self, text: str, color: str | None = None) -> None:
        self.value.setText(text)
        self.value.setStyleSheet(f"color: {color};" if color else "")

    def set_caption(self, text: str) -> None:
        self.caption.setText(text)


class EmptyState(QWidget):
    def __init__(self, title: str, body: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(theme.SPACE_6, theme.SPACE_8, theme.SPACE_6, theme.SPACE_8)
        layout.setSpacing(theme.SPACE_1)
        layout.addStretch(1)
        self.title = label(title, "emptyTitle")
        self.text = label(body, "body", wrap=True)
        for widget in (self.title, self.text):
            widget.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(widget)
        layout.addStretch(1)

    def set_message(self, title: str, body: str) -> None:
        self.title.setText(title)
        self.text.setText(body)


class StatefulView(QStackedWidget):
    """Switches one content widget between content / empty / loading / error states."""

    def __init__(self, content: QWidget, empty_title: str, empty_body: str) -> None:
        super().__init__()
        self.content = content
        self.empty = EmptyState(empty_title, empty_body)
        self.loading = EmptyState("Loading…", "Reading from the local database.")
        self.error = EmptyState("Something went wrong", "")
        self.error.title.setProperty("role", "emptyTitle")
        self.error.text.setProperty("role", "error")
        for widget in (self.content, self.empty, self.loading, self.error):
            self.addWidget(widget)

    def show_content(self) -> None:
        self.setCurrentWidget(self.content)

    def show_empty(self, title: str | None = None, body: str | None = None) -> None:
        if title is not None and body is not None:
            self.empty.set_message(title, body)
        self.setCurrentWidget(self.empty)

    def show_loading(self) -> None:
        self.setCurrentWidget(self.loading)

    def show_error(self, message: str) -> None:
        self.error.text.setText(message)
        self.setCurrentWidget(self.error)


def severity_color(severity: str) -> str:
    try:
        return theme.ACTIVE.severity[Severity(severity)]
    except ValueError:
        return theme.ACTIVE.text_faint


class StatusRow(QWidget):
    """Health check line: colored dot, name, state and explanation."""

    def __init__(self, name: str, state: HealthState, message: str) -> None:
        super().__init__()
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, theme.SPACE_1, 0, theme.SPACE_1)
        layout.setSpacing(theme.SPACE_2)
        color = theme.ACTIVE.health[state]
        dot = QLabel("●")
        dot.setStyleSheet(f"color: {color}; font-size: 9pt;")
        dot.setAlignment(Qt.AlignmentFlag.AlignTop)
        text = QVBoxLayout()
        text.setSpacing(0)
        header = label(f"{name}  ·  {state.value}")
        header.setStyleSheet("font-weight: 600;")
        text.addWidget(header)
        text.addWidget(label(message, "caption", wrap=True))
        layout.addWidget(dot)
        layout.addLayout(text, 1)
