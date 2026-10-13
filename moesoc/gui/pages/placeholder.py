"""Settings page: the configuration in use and data retention."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QComboBox, QHBoxLayout, QMessageBox, QPushButton, QVBoxLayout, QWidget

from moesoc.core.config import AppConfig
from moesoc.core.enums import SecurityEventId
from moesoc.gui import theme
from moesoc.gui.widgets.common import Card, label
from moesoc.storage.retention import ALLOWED_DAYS, DEFAULT_DAYS, RetentionPlan


class SettingsPage(QWidget):
    """The real configuration in use, and data retention (MoeSOC's own database only)."""

    retention_save_requested = Signal(int)  # days
    retention_preview_requested = Signal(int)
    retention_apply_requested = Signal(int)  # emitted only after the user confirmed

    def __init__(self, config: AppConfig) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(theme.SPACE_6, theme.SPACE_6, theme.SPACE_6, theme.SPACE_6)
        layout.setSpacing(theme.SPACE_4)

        storage = Card("Local Storage")
        for name, value in (
            ("Data directory", config.data_dir),
            ("Database", config.database_path),
            ("Diagnostic logs", config.log_dir),
            ("Detection rules", config.rules_dir),
        ):
            storage.body.addWidget(label(name, "caption"))
            storage.body.addWidget(label(str(value)))
        layout.addWidget(storage)

        scan = Card("Scan Scope")
        scan.body.addWidget(label(f"Lookback window: {config.lookback_hours} hours"))
        scan.body.addWidget(label(f"Maximum events per scan: {config.max_events_per_scan:,}"))
        ids = ", ".join(str(int(i)) for i in sorted(SecurityEventId))
        sources = (
            f"Sources: Windows Security log (events {ids}); when present, Sysmon (1, 3, 11, 13, "
            "22), PowerShell script blocks (4104) and Microsoft Defender (1116-1119)."
        )
        scan.body.addWidget(label(sources, "caption", wrap=True))
        layout.addWidget(scan)

        retention = Card("Data Retention")
        retention.body.addWidget(
            label(
                "Deletes MoeSOC's own stored events and closed findings older than the period. "
                "Open findings and their evidence are kept. Windows event logs are never "
                "touched. Nothing is deleted without your confirmation.",
                "body",
                wrap=True,
            )
        )
        row = QHBoxLayout()
        self.retention_days = QComboBox()
        for days in ALLOWED_DAYS:
            self.retention_days.addItem(f"{days} days", days)
        self.retention_days.setCurrentIndex(ALLOWED_DAYS.index(DEFAULT_DAYS))
        self.retention_save = QPushButton("Save period")
        self.retention_preview = QPushButton("Preview")
        self.retention_apply = QPushButton("Delete old data…")
        self.retention_apply.setProperty("variant", "danger")
        for widget in (
            self.retention_days,
            self.retention_save,
            self.retention_preview,
            self.retention_apply,
        ):
            row.addWidget(widget)
        row.addStretch(1)
        retention.body.addLayout(row)
        self.retention_status = label("", "caption", wrap=True)
        retention.body.addWidget(self.retention_status)
        layout.addWidget(retention)
        self.retention_save.clicked.connect(
            lambda: self.retention_save_requested.emit(self.selected_days())
        )
        self.retention_preview.clicked.connect(
            lambda: self.retention_preview_requested.emit(self.selected_days())
        )
        self.retention_apply.clicked.connect(
            lambda: self.retention_preview_requested.emit(self.selected_days())
        )
        self.retention_apply.clicked.connect(self._arm_apply)
        self._apply_armed = False

        privacy = Card("Privacy")
        privacy.body.addWidget(
            label(
                "Your security telemetry stays on your device. MoeSOC makes no network "
                "connections, has no analytics and requires no account.",
                "body",
                wrap=True,
            )
        )
        layout.addWidget(privacy)
        layout.addStretch(1)

    # ------------------------------------------------------------------ retention
    def selected_days(self) -> int:
        return int(self.retention_days.currentData())

    def set_retention_days(self, days: int) -> None:
        if days in ALLOWED_DAYS:
            self.retention_days.setCurrentIndex(ALLOWED_DAYS.index(days))

    def _arm_apply(self) -> None:
        # The preview runs first; when it arrives, the user confirms the exact counts.
        self._apply_armed = True

    def show_retention_plan(self, plan: RetentionPlan) -> None:
        self.retention_status.setText(plan.describe())
        if not self._apply_armed:
            return
        self._apply_armed = False
        if plan.nothing_to_do:
            self.retention_status.setText(plan.describe() + " Nothing to delete.")
            return
        if self.confirm_deletion(plan):
            self.retention_apply_requested.emit(plan.days)

    def confirm_deletion(self, plan: RetentionPlan) -> bool:
        """Ask the user. Separate method so tests can answer without a modal dialog."""
        answer = QMessageBox.question(
            self,
            "Delete old MoeSOC data?",
            plan.describe() + "\n\nThis cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        return answer == QMessageBox.StandardButton.Yes

    def show_retention_message(self, text: str) -> None:
        self.retention_status.setText(text)
