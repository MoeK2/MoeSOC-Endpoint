"""Reports page: export self-contained HTML reports (a finding, or the endpoint summary)."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from moesoc.gui import theme
from moesoc.gui.widgets.common import Card, label
from moesoc.storage.repository import StoredDetection


class ReportsPage(QWidget):
    summary_requested = Signal(str, bool)  # output path, redact
    finding_requested = Signal(int, str, bool)  # detection id, output path, redact

    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(theme.SPACE_6, theme.SPACE_6, theme.SPACE_6, theme.SPACE_6)
        layout.setSpacing(theme.SPACE_4)

        about = Card("HTML Reports")
        about.body.addWidget(
            label(
                "Reports are single HTML files with no scripts and no external resources: "
                "they open offline and send nothing anywhere. They never include command "
                "lines, script contents or raw event XML. Use Redact to replace computer names, "
                "accounts, domains, SIDs and IP addresses with placeholders before sharing.",
                "body",
                wrap=True,
            )
        )
        self.redact = QCheckBox("Redact identities (for sharing outside your team)")
        about.body.addWidget(self.redact)
        layout.addWidget(about)

        summary = Card("Endpoint Summary")
        summary.body.addWidget(
            label("Risk, open findings (highest risk first) and stored events.", "caption")
        )
        self.export_summary = QPushButton("Export summary…")
        self.export_summary.setProperty("variant", "primary")
        summary_row = QHBoxLayout()
        summary_row.addWidget(self.export_summary)
        summary_row.addStretch(1)
        summary.body.addLayout(summary_row)
        layout.addWidget(summary)

        finding = Card("Finding Report")
        finding.body.addWidget(
            label(
                "One finding as its investigation story: related findings, events in order, "
                "confidence and risk factors, data gaps, next steps, notes and triage history.",
                "caption",
                wrap=True,
            )
        )
        row = QHBoxLayout()
        self.finding = QComboBox()
        self.finding.setMinimumWidth(420)
        self.export_finding = QPushButton("Export finding report…")
        row.addWidget(self.finding, 1)
        row.addWidget(self.export_finding)
        finding.body.addLayout(row)
        layout.addWidget(finding)

        self.status = label("", "caption", wrap=True)
        layout.addWidget(self.status)
        layout.addStretch(1)

        self.export_summary.clicked.connect(self._export_summary)
        self.export_finding.clicked.connect(self._export_finding)
        self.set_detections([])

    def set_detections(self, detections: list[StoredDetection]) -> None:
        current = self.finding.currentData()
        self.finding.clear()
        for d in sorted(detections, key=lambda d: -d.id):
            self.finding.addItem(
                f"#{d.id} {d.rule_id} {d.title} · {d.severity} · {d.status.label}", d.id
            )
        if current is not None:
            index = self.finding.findData(current)
            if index >= 0:
                self.finding.setCurrentIndex(index)
        self.export_finding.setEnabled(self.finding.count() > 0)

    def select_finding(self, detection_id: int) -> None:
        index = self.finding.findData(detection_id)
        if index >= 0:
            self.finding.setCurrentIndex(index)

    def ask_path(self, suggested: str) -> str | None:
        """Overridable for tests (no modal dialog)."""
        path, _filter = QFileDialog.getSaveFileName(
            self, "Save report", str(Path.home() / suggested), "HTML report (*.html)"
        )
        return path or None

    def _suffix(self) -> str:
        return "-redacted" if self.redact.isChecked() else ""

    def _export_summary(self) -> None:
        path = self.ask_path(f"moesoc-summary{self._suffix()}.html")
        if path:
            self.summary_requested.emit(path, self.redact.isChecked())

    def _export_finding(self) -> None:
        detection_id = self.finding.currentData()
        if detection_id is None:
            return
        path = self.ask_path(f"moesoc-finding-{detection_id}{self._suffix()}.html")
        if path:
            self.finding_requested.emit(int(detection_id), path, self.redact.isChecked())

    def show_message(self, text: str) -> None:
        self.status.setText(text)
