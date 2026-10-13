"""Overview page: endpoint status built only from stored scan results."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from moesoc.core.enums import HealthState, SecurityEventId, Severity
from moesoc.gui import theme
from moesoc.gui.widgets.common import Card, StatCard, StatefulView, StatusRow, label
from moesoc.gui.widgets.tables import Column, RecordTableModel, SeverityDelegate, make_table
from moesoc.health import HealthCheck
from moesoc.storage.overview import OverviewSnapshot
from moesoc.utils.time import format_local

RECENT_DETECTION_ROWS = 5
SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)


class StatusBanner(QFrame):
    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("Banner")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(theme.SPACE_4, theme.SPACE_3, theme.SPACE_4, theme.SPACE_3)
        layout.setSpacing(theme.SPACE_3)
        self.dot = QLabel("●")
        text = QVBoxLayout()
        text.setSpacing(2)
        self.title = label("", "banner")
        self.detail = label("", "body", wrap=True)
        text.addWidget(self.title)
        text.addWidget(self.detail)
        layout.addWidget(self.dot)
        layout.addLayout(text, 1)

    def set_status(self, title: str, detail: str, color: str) -> None:
        self.title.setText(title)
        self.detail.setText(detail)
        self.dot.setStyleSheet(f"color: {color}; font-size: 14pt;")


class OverviewPage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        palette = theme.ACTIVE
        content = QWidget()
        root = QVBoxLayout(content)
        root.setContentsMargins(theme.SPACE_6, theme.SPACE_6, theme.SPACE_6, theme.SPACE_6)
        root.setSpacing(theme.SPACE_4)

        self.banner = StatusBanner()
        root.addWidget(self.banner)

        # ---- metrics
        self.risk = StatCard(
            "Risk Score",
            "Highest-priority finding, 0–100. A prioritization score, not a probability.",
        )
        self.events = StatCard("Events Analyzed", "Events from all collected logs, stored locally.")
        self.detections = StatCard("Active Detections", "Open findings awaiting a verdict.")
        self.last_scan = StatCard("Last Scan", "No scan has been run yet.")
        metrics = QGridLayout()
        metrics.setSpacing(theme.SPACE_4)
        for column, card in enumerate((self.risk, self.events, self.detections, self.last_scan)):
            metrics.addWidget(card, 0, column)
            metrics.setColumnStretch(column, 1)
        root.addLayout(metrics)

        # ---- severity + health
        middle = QHBoxLayout()
        middle.setSpacing(theme.SPACE_4)
        self.severity_card = Card("Severity Summary")
        self.severity_labels: dict[Severity, QLabel] = {}
        for severity in SEVERITY_ORDER:
            row = QHBoxLayout()
            dot = QLabel("●")
            dot.setStyleSheet(f"color: {palette.severity[severity]};")
            name = label(severity.value.title())
            count = label("—")
            count.setStyleSheet("font-weight: 600;")
            row.addWidget(dot)
            row.addWidget(name, 1)
            row.addWidget(count)
            self.severity_labels[severity] = count
            self.severity_card.body.addLayout(row)
        self.severity_card.body.addStretch(1)

        self.health_card = Card("Telemetry Health")
        self.health_rows = QVBoxLayout()
        self.health_rows.setSpacing(0)
        self.health_rows.addWidget(label("Checking telemetry sources…", "caption"))
        self.health_card.body.addLayout(self.health_rows)
        self.health_card.body.addStretch(1)
        middle.addWidget(self.severity_card, 1)
        middle.addWidget(self.health_card, 2)
        root.addLayout(middle)

        # ---- recent detections
        recent_card = Card("Recent Detections")
        self.recent_model = RecordTableModel(
            [
                Column("SEVERITY", lambda d: d.severity, lambda d: Severity(d.severity).rank),
                Column("DETECTION", lambda d: f"{d.rule_id}  {d.title}"),
                Column("ACCOUNT", lambda d: d.account or str(d.evidence.get("source") or "—")),
                Column("STATUS", lambda d: d.status.label),
                Column("LAST SEEN", lambda d: format_local(d.last_seen), lambda d: d.last_seen),
            ]
        )
        table, _proxy = make_table(self.recent_model, stretch_column=1)
        table.setItemDelegateForColumn(0, SeverityDelegate(table))
        table.setMinimumHeight(220)
        self.recent_view = StatefulView(
            table, "No detections found during this scan.", "Run a scan to analyze telemetry."
        )
        recent_card.body.addWidget(self.recent_view)
        root.addWidget(recent_card, 1)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(content)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

    # ------------------------------------------------------------------ updates
    def show_snapshot(self, snap: OverviewSnapshot) -> None:
        palette = theme.ACTIVE
        if snap.risk_score is None:
            self.risk.set_value("Unavailable")
        else:
            highest = snap.highest_severity
            color = palette.severity[highest] if highest else palette.health[HealthState.AVAILABLE]
            self.risk.set_value(str(snap.risk_score), color)
        self.risk.set_caption(snap.risk_explanation())

        self.events.set_value(f"{snap.events_total:,}")
        failures, successes = snap.events_by_id.get(4625, 0), snap.events_by_id.get(4624, 0)
        caption = f"{successes:,} successful (4624) · {failures:,} failed (4625) logons"
        cleared = snap.events_by_id.get(1102, 0)
        if cleared:
            caption += f" · {cleared:,} log clearings (1102)"
        self.events.set_caption(caption)
        open_count = len(snap.open_detections)
        self.detections.set_value(f"{open_count:,}")
        closed = len(snap.detections) - open_count
        self.detections.set_caption(
            f"Open findings awaiting a verdict · {closed:,} closed"
            if closed
            else "Open findings awaiting a verdict."
        )
        for severity, count_label in self.severity_labels.items():
            count_label.setText(str(snap.severity_counts.get(severity, 0)))

        scan = snap.last_scan
        if scan is None:
            self.last_scan.set_value("Never")
            self.last_scan.set_caption("No scan has been run yet.")
        else:
            self.last_scan.set_value(scan.status.title())
            when = format_local(scan.finished_at or scan.started_at)
            mode = ""
            if scan.collection_mode:
                core = scan.collection_mode.split(",")[0].split(":")[-1].strip()
                mode = f" · {core} collection"
            self.last_scan.set_caption(
                f"{when} · {scan.origin}{mode} · {scan.records_read:,} records read, "
                f"{scan.events_new:,} new"
            )
            if scan.message:
                self.last_scan.setToolTip(scan.message)

        recent = snap.open_detections[:RECENT_DETECTION_ROWS]
        self.recent_model.set_rows(recent)
        if recent:
            self.recent_view.show_content()
        elif snap.detections:
            self.recent_view.show_empty(
                "No open detections",
                "Every finding has been closed by an analyst. Detections → All shows them.",
            )
        elif snap.has_completed_scan:
            self.recent_view.show_empty(
                "No detections found during this scan.",
                "No rule matched the stored authentication events.",
            )
        else:
            self.recent_view.show_empty("No detections yet", "Run a scan to analyze telemetry.")
        self._update_banner(snap)

    def _update_banner(self, snap: OverviewSnapshot) -> None:
        palette = theme.ACTIVE
        scan = snap.last_scan
        highest = snap.highest_severity
        if scan is None:
            self.banner.set_status(
                "Not yet scanned",
                "Run a scan to analyze Windows authentication telemetry from the last 24 hours.",
                palette.text_faint,
            )
        elif scan.status == "failed":
            self.banner.set_status(
                "Last scan failed",
                scan.message or "See the diagnostic log.",
                palette.health[HealthState.ERROR],
            )
        elif highest in (Severity.HIGH, Severity.CRITICAL):
            self.banner.set_status(
                "Suspicious activity detected",
                f"{len(snap.open_detections)} open finding(s) to investigate. "
                "Detections are investigation leads, not proof of compromise.",
                palette.severity[highest],
            )
        elif highest is not None:
            self.banner.set_status(
                "Findings to review",
                f"{len(snap.open_detections)} open finding(s) of {highest.value.lower()} "
                "severity or lower.",
                palette.severity[highest],
            )
        elif snap.detections:
            self.banner.set_status(
                "No open findings",
                f"All {len(snap.detections)} finding(s) have been closed by an analyst. "
                f"{snap.events_total:,} events analyzed.",
                palette.health[HealthState.AVAILABLE],
            )
        else:
            self.banner.set_status(
                "No detections found during this scan.",
                f"{snap.events_total:,} events analyzed. Current coverage: Security log "
                f"events {', '.join(str(int(i)) for i in sorted(SecurityEventId))}.",
                palette.health[HealthState.AVAILABLE],
            )

    def show_scan_error(self, message: str) -> None:
        self.banner.set_status(
            "Scan could not complete", message, theme.ACTIVE.health[HealthState.ERROR]
        )

    def show_health(self, checks: list[HealthCheck]) -> None:
        while self.health_rows.count():
            item = self.health_rows.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        for check in checks:
            self.health_rows.addWidget(StatusRow(check.name, check.state, check.message))
