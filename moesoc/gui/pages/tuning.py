"""Tuning page: enable/disable rules, tune thresholds, manage suppressions, read the audit log.

Every change needs a reason and is written to the audit log. Suppressions only
affect future findings; existing findings are never changed or deleted.
"""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QInputDialog,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from moesoc.gui import theme
from moesoc.gui.widgets.common import label
from moesoc.gui.widgets.tables import Column, RecordTableModel, make_table
from moesoc.storage.tuning import (
    MIN_REASON,
    SUPPRESSION_TYPES,
    RuleRow,
    Suppression,
    TuningSnapshot,
    parameter_bounds,
)
from moesoc.utils.time import format_local, utc_now

EXPIRY_CHOICES = {"Never (until removed)": None, "7 days": 7, "30 days": 30, "90 days": 90}


@dataclass(frozen=True, slots=True)
class SuppressionRequest:
    type: str
    value: str
    reason: str
    rule_id: str | None
    days: int | None


def suppression_state(s: Suppression) -> str:
    if s.removed_at is not None:
        return "Removed"
    return "Active" if s.is_active(utc_now()) else "Expired"


class SuppressionDialog(QDialog):
    """Collects a suppression; OK is enabled only with a value and a real reason."""

    def __init__(
        self, rule_ids: list[str], parent: QWidget | None = None, *, prefill: dict | None = None
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Add suppression")
        form = QFormLayout(self)
        self.type = QComboBox()
        self.type.addItems(SUPPRESSION_TYPES)
        self.value = QLineEdit()
        self.rule = QComboBox()
        self.rule.addItem("All rules", None)
        for rule_id in rule_ids:
            self.rule.addItem(rule_id, rule_id)
        self.expiry = QComboBox()
        self.expiry.addItems(EXPIRY_CHOICES)
        self.reason = QLineEdit()
        self.reason.setPlaceholderText("Why is this benign? (kept in the audit log)")
        form.addRow("Match", self.type)
        form.addRow("Value", self.value)
        form.addRow("Rule", self.rule)
        form.addRow("Expires", self.expiry)
        form.addRow("Reason", self.reason)
        form.addRow(
            label(
                "Only future findings are hidden. Existing findings stay as they are.",
                "caption",
                wrap=True,
            )
        )
        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        form.addRow(self.buttons)
        for edit in (self.value, self.reason):
            edit.textChanged.connect(self._validate)
        if prefill:
            self.type.setCurrentText(prefill.get("type", "account"))
            self.value.setText(prefill.get("value", ""))
            if prefill.get("rule_id"):
                self.rule.setCurrentText(prefill["rule_id"])
        self._validate()

    def _validate(self) -> None:
        ok = bool(self.value.text().strip()) and len(self.reason.text().strip()) >= MIN_REASON
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(ok)

    def request(self) -> SuppressionRequest:
        return SuppressionRequest(
            self.type.currentText(),
            self.value.text().strip(),
            self.reason.text().strip(),
            self.rule.currentData(),
            EXPIRY_CHOICES[self.expiry.currentText()],
        )


class TuningPage(QWidget):
    suppression_add_requested = Signal(object)  # SuppressionRequest
    suppression_remove_requested = Signal(int, str)
    rule_enabled_requested = Signal(str, bool, str)  # rule id, enabled, reason
    rule_parameter_requested = Signal(str, str, int, str)  # rule id, name, value, reason
    refresh_requested = Signal()

    def __init__(self, rule_ids: list[str]) -> None:
        super().__init__()
        self._rule_ids = rule_ids
        self._snapshot: TuningSnapshot | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(theme.SPACE_6, theme.SPACE_4, theme.SPACE_6, theme.SPACE_6)
        layout.setSpacing(theme.SPACE_3)
        layout.addWidget(label("Rule Tuning & Suppressions", "banner"))
        layout.addWidget(
            label(
                "Every change needs a reason and is recorded in the audit log. Tuning changes "
                "how future scans run; suppressions hide future findings that match a value. "
                "Existing findings are never changed or deleted.",
                "caption",
                wrap=True,
            )
        )

        # ---- rules
        self.rules_model = RecordTableModel(
            [
                Column("RULE", lambda r: r.rule_id),
                Column("TITLE", lambda r: r.title),
                Column("VERSION", lambda r: r.version),
                Column("STATE", lambda r: "Enabled" if r.enabled else "Disabled"),
                Column(
                    "PARAMETERS",
                    lambda r: (
                        ", ".join(
                            f"{name}={value}" + ("*" if value != default else "")
                            for name, (value, default) in r.parameters.items()
                        )
                        or "—"
                    ),
                ),
            ]
        )
        self.rules_table, self._rules_proxy = make_table(self.rules_model, stretch_column=4)
        rule_actions = QHBoxLayout()
        self.toggle_rule = QPushButton("Enable / disable…")
        self.edit_parameter = QPushButton("Change parameter…")
        rule_actions.addWidget(label("Rules (* = tuned):", "caption"))
        rule_actions.addStretch(1)
        rule_actions.addWidget(self.toggle_rule)
        rule_actions.addWidget(self.edit_parameter)
        self.toggle_rule.clicked.connect(self._toggle_rule)
        self.edit_parameter.clicked.connect(self._edit_parameter)

        # ---- suppressions
        self.suppressions_model = RecordTableModel(
            [
                Column("#", lambda s: str(s.id), lambda s: s.id),
                Column("STATE", suppression_state),
                Column("RULE", lambda s: s.rule_id or "All rules"),
                Column("MATCH", lambda s: s.type),
                Column("VALUE", lambda s: s.value),
                Column("EXPIRES", lambda s: format_local(s.expires_at) if s.expires_at else "—"),
                Column("HITS", lambda s: str(s.hit_count), lambda s: s.hit_count),
                Column("REASON", lambda s: s.reason, tooltip=lambda s: s.reason),
            ]
        )
        self.suppressions_table, self._suppressions_proxy = make_table(
            self.suppressions_model, stretch_column=7
        )
        sup_actions = QHBoxLayout()
        self.show_inactive = QCheckBox("Show removed and expired")
        self.show_inactive.toggled.connect(self._render_suppressions)
        self.add_suppression = QPushButton("Add suppression…")
        self.remove_suppression = QPushButton("Remove…")
        sup_actions.addWidget(label("Suppressions:", "caption"))
        sup_actions.addWidget(self.show_inactive)
        sup_actions.addStretch(1)
        sup_actions.addWidget(self.add_suppression)
        sup_actions.addWidget(self.remove_suppression)
        self.add_suppression.clicked.connect(lambda: self.open_suppression_dialog())
        self.remove_suppression.clicked.connect(self._remove_suppression)

        # ---- audit
        self.audit = QPlainTextEdit()
        self.audit.setReadOnly(True)
        self.audit.setPlaceholderText("No tuning changes yet.")

        top = QWidget()
        top_layout = QVBoxLayout(top)
        top_layout.setContentsMargins(0, 0, 0, 0)
        top_layout.addLayout(rule_actions)
        top_layout.addWidget(self.rules_table)
        middle = QWidget()
        middle_layout = QVBoxLayout(middle)
        middle_layout.setContentsMargins(0, 0, 0, 0)
        middle_layout.addLayout(sup_actions)
        middle_layout.addWidget(self.suppressions_table)
        bottom = QWidget()
        bottom_layout = QVBoxLayout(bottom)
        bottom_layout.setContentsMargins(0, 0, 0, 0)
        bottom_layout.addWidget(label("Audit log (newest first):", "caption"))
        bottom_layout.addWidget(self.audit)
        splitter = QSplitter(Qt.Orientation.Vertical)
        for widget in (top, middle, bottom):
            splitter.addWidget(widget)
        layout.addWidget(splitter, 1)
        self.status = label("", "caption", wrap=True)
        layout.addWidget(self.status)

    # ------------------------------------------------------------------ data
    def show_snapshot(self, snapshot: TuningSnapshot) -> None:
        self._snapshot = snapshot
        self.rules_model.set_rows(snapshot.rules)
        self._render_suppressions()
        self.audit.setPlainText(
            "\n".join(
                f"{format_local(e.at)}  {e.action:<20} {e.target:<18} "
                f"{e.details}  — {e.reason or ''}"
                for e in snapshot.audit
            )
        )

    def _render_suppressions(self) -> None:
        if self._snapshot is None:
            return
        rows = self._snapshot.suppressions
        if not self.show_inactive.isChecked():
            rows = [s for s in rows if suppression_state(s) == "Active"]
        self.suppressions_model.set_rows(rows)

    def show_message(self, text: str) -> None:
        self.status.setText(text)

    def _selected_rule(self) -> RuleRow | None:
        rows = self.rules_table.selectionModel().selectedRows()
        if not rows:
            return None
        return self.rules_model.row_at(self._rules_proxy.mapToSource(rows[0]).row())

    def _selected_suppression(self) -> Suppression | None:
        rows = self.suppressions_table.selectionModel().selectedRows()
        if not rows:
            return None
        source = self._suppressions_proxy.mapToSource(rows[0]).row()
        return self.suppressions_model.row_at(source)

    # ------------------------------------------------------------------ dialogs
    def ask_text(self, title: str, prompt: str) -> str | None:
        """Overridable for tests (no modal dialog)."""
        text, ok = QInputDialog.getText(self, title, prompt)
        return text if ok else None

    def ask_int(self, title: str, prompt: str, value: int, name: str = "") -> int | None:
        low, high = parameter_bounds(name)
        number, ok = QInputDialog.getInt(self, title, prompt, value, low, high)
        return number if ok else None

    def ask_choice(self, title: str, prompt: str, items: list[str]) -> str | None:
        item, ok = QInputDialog.getItem(self, title, prompt, items, 0, False)
        return item if ok else None

    def ask_suppression(self, prefill: dict | None) -> SuppressionRequest | None:
        dialog = SuppressionDialog(self._rule_ids, self, prefill=prefill)
        return dialog.request() if dialog.exec() == QDialog.DialogCode.Accepted else None

    def _reason(self, what: str) -> str | None:
        reason = self.ask_text("Reason", f"Why {what}? (kept in the audit log)")
        if reason is None:
            return None
        if len(reason.strip()) < MIN_REASON:
            self.show_message(f"A reason of at least {MIN_REASON} characters is required.")
            return None
        return reason.strip()

    # ------------------------------------------------------------------ actions
    def open_suppression_dialog(self, prefill: dict | None = None) -> None:
        request = self.ask_suppression(prefill)
        if request is not None:
            self.suppression_add_requested.emit(request)

    def _toggle_rule(self) -> None:
        rule = self._selected_rule()
        if rule is None:
            self.show_message("Select a rule first.")
            return
        verb = "enable" if not rule.enabled else "disable"
        reason = self._reason(f"{verb} {rule.rule_id}")
        if reason:
            self.rule_enabled_requested.emit(rule.rule_id, not rule.enabled, reason)

    def _edit_parameter(self) -> None:
        rule = self._selected_rule()
        if rule is None or not rule.parameters:
            self.show_message("Select a rule with numeric parameters first.")
            return
        name = self.ask_choice("Parameter", f"{rule.rule_id} parameter:", list(rule.parameters))
        if name is None:
            return
        current, default = rule.parameters[name]
        value = self.ask_int("Value", f"{name} (YAML default {default}):", current, name)
        if value is None:
            return
        reason = self._reason(f"change {rule.rule_id} {name} to {value}")
        if reason:
            self.rule_parameter_requested.emit(rule.rule_id, name, value, reason)

    def _remove_suppression(self) -> None:
        s = self._selected_suppression()
        if s is None or s.removed_at is not None:
            self.show_message("Select an active suppression first.")
            return
        reason = self._reason(f"remove suppression #{s.id}")
        if reason:
            self.suppression_remove_requested.emit(s.id, reason)
