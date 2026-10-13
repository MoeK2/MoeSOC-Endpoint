"""Detections page: findings list, evidence panel, triage actions and analyst notes."""

from __future__ import annotations

import html
from datetime import datetime
from functools import partial
from typing import Any

from PySide6.QtCore import QItemSelection, Qt, Signal, Slot
from PySide6.QtWidgets import (
    QComboBox,
    QGridLayout,
    QHBoxLayout,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from moesoc.core.detection import RuleMetadata
from moesoc.core.enums import Severity, TriageStatus
from moesoc.engine.risk import stored_risk_note
from moesoc.gui import theme
from moesoc.gui.widgets.common import StatefulView, label, severity_color
from moesoc.gui.widgets.tables import Column, RecordTableModel, SeverityDelegate, make_table
from moesoc.storage.repository import AnalystNote, StoredDetection
from moesoc.utils.time import format_local

# Evidence keys shown first, with analyst-friendly labels. Others follow as-is.
EVIDENCE_LABELS: dict[str, str] = {
    "account": "Account",
    "account_spellings": "Recorded spellings",
    "hostname": "Host",
    "mode": "Grouped by",
    "actor": "Done by",
    "actor_sid": "Actor SID",
    "actor_logon_id": "Actor logon ID",
    "cleared_at": "Cleared at",
    "record_id": "EventRecordID",
    "source": "Source",
    "distinct_account_count": "Distinct accounts",
    "accounts": "Accounts tried",
    "accounts_not_found": "Attempts on non-existent accounts",
    "failure_count": "Failed logons",
    "total_attempts": "Total attempts",
    "first_failure": "First failure",
    "last_failure": "Last failure",
    "failure_reasons": "Failure reasons",
    "source_addresses": "Failure source addresses",
    "distinct_source_count": "Distinct failure sources",
    "workstations": "Failure workstations",
    "logon_types": "Failure logon types",
    "authentication_packages": "Authentication packages",
    "success_time": "Successful logon",
    "success_logon_type": "Success logon type",
    "success_source_address": "Success source address",
    "success_workstation": "Success workstation",
    "success_authentication_package": "Success authentication package",
    "success_logon_id": "Success logon ID",
    "success_from_failure_source": "Success from a failure source",
    "logon_type_matched": "Success logon type matched failures",
    "workstation_matched": "Success workstation matched failures",
    "seconds_from_last_failure_to_success": "Seconds from last failure to success",
    "success_record_id": "Success EventRecordID",
    "failures_in_det001_bursts_excluded": "Failures already in DET-001 bursts (not counted)",
    "interval_seconds_median": "Median seconds between attempts",
    "interval_seconds_min": "Shortest gap (s)",
    "interval_seconds_max": "Longest gap (s)",
    "regular_interval": "Regular interval (device or script?)",
    "failure_record_ids": "Failure EventRecordIDs",
    # account management (DET-005, DET-006, COR-002)
    "new_account_sid": "New account SID",
    "account_scope": "Account scope",
    "created_at": "Created at",
    "created_by": "Created by",
    "created_by_logon_id": "Creator logon ID",
    "member": "Member",
    "member_sid": "Member SID",
    "member_name_source": "Member name taken from",
    "group": "Group",
    "group_meaning": "Built-in group (by SID)",
    "group_sid": "Group SID",
    "group_matched_by": "Group recognised by",
    "added_at": "Added at",
    "added_by": "Added by",
    "added_by_logon_id": "Adder logon ID",
    "same_actor": "Same person created and elevated",
    "seconds_from_creation_to_group_add": "Seconds from creation to group add",
    "context": "Context",
    "privileged_session": "Privileged session (4672)",
    "risk_factors": "Why this risk score",
    # PowerShell (DET-007)
    "user": "User",
    "score": "Indicator score",
    "script_parts": "Script parts seen",
    "script_length": "Script length (characters)",
    "script_sha256": "Script SHA-256",
    "script_block_id": "ScriptBlockId",
    "powershell_pid": "PowerShell PID",
    "parent_process": "Parent process",
    "windows_flagged": "Flagged by PowerShell itself",
    "related_techniques": "Related ATT&CK techniques",
    # Microsoft Defender (DET-008)
    "summary": "Summary",
    "threat_name": "Threat (Defender's name)",
    "defender_severity": "Defender severity",
    "category": "Defender category",
    "remediation": "Remediation",
    "severity_reasons": "Why this severity",
    "detected_at": "Detected at",
    "file_path": "File",
    "process": "Process",
    "detection_source": "Detected by",
    "origin": "Origin",
    "resources": "Resources Defender named",
    "detection_id": "Defender Detection ID",
    "detections_recorded": "Detection events recorded",
    "verdict_source": "Verdict from",
    # cross-source (COR-003, COR-004)
    "follow_up_kinds": "What happened in the session",
    "link_quality": "Link quality",
    "suspicious_powershell": "Suspicious PowerShell in the session",
    "processes_in_session": "Processes started in the session",
    "processes_in_session_count": "Process starts in the session",
    "follow_window_minutes": "Session follow-up window (min)",
    "file_created_at": "File written at",
    "seconds_from_write_to_detection": "Seconds from write to detection",
    "written_by": "Written by",
    "writer_parent": "Writer's parent",
    "writer_user": "Writer's user",
    "writer_start_collected": "Writer's process start collected",
    "dns_queries": "Writer's DNS lookups",
    "connections": "Writer's connections",
    "executed": "File was started",
    "remediation_state": "Defender remediation",
    "note": "Note",
}
DETAIL_MIN_WIDTH = 420
TABLE_INITIAL_WIDTH = 760
HIDDEN_EVIDENCE = {
    "username",
    "target_domains",
    "threshold",
    "window_minutes",
    "min_distinct_accounts",
    "identity",
    "confidence",
    "source_type",
    "provider",
    "chain",  # shown as its own table
}
LOG_NAMES = {
    "security": "Security",
    "sysmon": "Sysmon",
    "powershell": "PowerShell",
    "defender": "Defender",
}
TIMESTAMP_KEYS = {
    "first_failure",
    "last_failure",
    "success_time",
    "cleared_at",
    "created_at",
    "added_at",
    "detected_at",
    "file_created_at",
}
STATUS_FILTERS = ("Open", "All", *(s.label for s in TriageStatus))
TRIAGE_ACTIONS = (
    ("Start Investigation", TriageStatus.INVESTIGATING),
    ("True Positive", TriageStatus.TRUE_POSITIVE),
    ("False Positive", TriageStatus.FALSE_POSITIVE),
    ("Benign", TriageStatus.BENIGN),
    ("Resolve", TriageStatus.RESOLVED),
)


def _format_value(key: str, value: Any) -> str:
    if value is None or value == [] or value == {}:
        return "—"
    if key == "privileged_session" and isinstance(value, dict):
        sensitive = value.get("sensitive_privileges") or []
        listed = f", including {', '.join(map(str, sensitive))}" if sensitive else ""
        return (
            f"{value.get('privilege_count')} privileges{listed} · logon ID "
            f"{value.get('logon_id')} · EventRecordID {value.get('record_id')}"
        )
    if key == "risk_factors" and isinstance(value, list):
        return "; ".join(
            f"{'+' if int(f.get('points', 0)) >= 0 else ''}{f.get('points')} {f.get('reason')}"
            for f in value
            if isinstance(f, dict)
        )
    if key == "score" and isinstance(value, dict):
        indicators = "; ".join(
            f"+{i.get('points')} {i.get('reason')}"
            + (f" «{i.get('excerpt')}»" if i.get("excerpt") else "")
            for i in value.get("indicators") or []
            if isinstance(i, dict)
        )
        return (
            f"{value.get('points')} points (finding at {value.get('threshold')}, HIGH at "
            f"{value.get('high_at')}): {indicators}"
        )
    if key == "remediation" and isinstance(value, dict):
        when = value.get("at")
        stamp = f" · {format_local(datetime.fromisoformat(when))}" if when else ""
        return f"{str(value.get('state', '')).capitalize()}: {value.get('outcome')}{stamp}"
    if key == "severity_reasons" and isinstance(value, list):
        return "; ".join(str(v) for v in value)
    if key in TIMESTAMP_KEYS:
        return format_local(datetime.fromisoformat(value))
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, dict):
        return ", ".join(f"{k} ({v})" for k, v in value.items())
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value)


def _chain_table(chain: list[Any]) -> str:
    """One row per step: time, log, what happened, how it is linked to the rest."""
    p = theme.ACTIVE
    e = html.escape
    rows = []
    for item in chain:
        if not isinstance(item, dict):
            continue
        when = item.get("time")
        stamp = format_local(datetime.fromisoformat(when)) if when else "—"
        link = item.get("link")
        strength = item.get("link_strength")
        how = f"{link} · {strength}" if link and strength else (link or "start")
        record = item.get("record_id")
        what = str(item.get("what") or "")
        if record is not None:
            what += f"  (EventRecordID {record})"
        rows.append(
            f"<tr><td style='color:{p.text_faint};padding:2px 12px 2px 0'>{e(stamp)}</td>"
            f"<td style='padding:2px 12px 2px 0'>"
            f"{e(LOG_NAMES.get(str(item.get('log')), str(item.get('log'))))} "
            f"{e(str(item.get('event_id') or ''))}</td>"
            f"<td style='padding:2px 12px 2px 0'>{e(what)}</td>"
            f"<td style='color:{p.text_muted}'>{e(how)}</td></tr>"
        )
    return f"<table cellspacing='0'>{''.join(rows)}</table>"


def suppression_prefill(det: StoredDetection) -> dict[str, str]:
    """The most specific value of a finding to suppress, for the dialog to start from."""
    ev = det.evidence
    if ev.get("threat_name"):
        return {"type": "threat", "value": str(ev["threat_name"]), "rule_id": det.rule_id}
    if det.account:
        return {"type": "account", "value": det.account, "rule_id": det.rule_id}
    if ev.get("source"):
        return {"type": "source_ip", "value": str(ev["source"]), "rule_id": det.rule_id}
    return {"type": "host", "value": str(ev.get("hostname") or ""), "rule_id": det.rule_id}


def _section(title: str, body: str) -> str:
    return (
        f"<div style='margin-top:14px;color:{theme.ACTIVE.text_muted};font-size:9pt;"
        f"font-weight:600'>{title.upper()}</div>{body}"
    )


def _bullets(items: tuple[str, ...] | list[str]) -> str:
    return "<ul>" + "".join(f"<li>{html.escape(i)}</li>" for i in items) + "</ul>"


def _rule_logic(rule: RuleMetadata, evidence: dict[str, Any]) -> str | None:
    params = rule.parameters
    if rule.rule_id == "DET-005":
        return "every Event 4720 (user account created); severity rises only with context."
    if rule.rule_id == "DET-007":
        return (
            "a PowerShell script block (Event 4104, reassembled when split) whose indicators "
            f"add up to at least {params.get('threshold')} points; HIGH at "
            f"{params.get('high_at')}. Each indicator and its points are listed below."
        )
    if rule.rule_id == "DET-008":
        return (
            "every Microsoft Defender detection (Event 1116), joined by Detection ID with the "
            "action Defender took (1117) or failed to take (1118/1119). The verdict is "
            "Defender's; MoeSOC reports it."
        )
    if rule.rule_id == "COR-003":
        return (
            f"at least {params.get('failure_threshold')} failed logons within "
            f"{params.get('failure_window_minutes')} minutes, a successful logon, then within "
            f"{params.get('follow_window_minutes')} minutes in that logon session: an account "
            "or group change, suspicious PowerShell (DET-007 scoring), or a Defender detection "
            "for the user."
        )
    if rule.rule_id == "COR-004":
        return (
            "a Defender detection whose file was written (Sysmon 11, same path) within "
            f"{params.get('file_window_minutes')} minutes before; the writer is followed by "
            "ProcessGuid to its DNS lookups and connections, and the file to any process "
            "started from it."
        )
    if rule.rule_id == "DET-006":
        return (
            "Event 4732 adding a member to a built-in privileged group, recognised by its "
            "well-known SID (group names are localized)."
        )
    if rule.rule_id == "COR-002":
        return (
            f"Event 4720 then Event 4732 for the same account SID on the same computer, "
            f"into an administrator-equivalent group within {params.get('window_minutes')} "
            "minutes."
        )
    if rule.rule_id == "DET-004":
        if evidence.get("mode") == "source":
            return (
                f"one source failing at least {params.get('source_threshold')} times over "
                f"{params.get('source_min_accounts')}+ accounts within "
                f"{params.get('window_minutes')} minutes, not counting failures already "
                "reported by DET-001 or DET-002."
            )
        return (
            f"at least {params.get('identity_threshold')} failed logons for one account within "
            f"{params.get('window_minutes')} minutes, not counting failures already inside a "
            "DET-001 burst."
        )
    if rule.rule_id == "DET-002":
        return (
            f"one source failing against at least {params.get('min_distinct_accounts')} "
            f"distinct accounts within {params.get('window_minutes')} minutes."
        )
    if "threshold" in evidence:
        return (
            f"at least {evidence['threshold']} failed logons within "
            f"{evidence.get('window_minutes')} minutes."
        )
    if rule.rule_id == "DET-003":
        return "every Security Event 1102 (audit log cleared)."
    return None


def render_detection_html(
    det: StoredDetection, rule: RuleMetadata | None, notes: list[AnalystNote] | None = None
) -> str:
    """Build the detail panel. Every value from telemetry is HTML-escaped."""
    p = theme.ACTIVE
    e = html.escape
    sev_color = severity_color(det.severity)
    triage = f"{det.status.label}"
    if det.verdict and det.status.value != det.verdict:
        triage += f" (last verdict: {det.verdict.replace('_', ' ').title()})"
    if det.resolved_at:
        triage += f" · closed {format_local(det.resolved_at)}"
    parts = [
        f"<div style='font-size:15pt;font-weight:600'>{e(det.title)}</div>",
        f"<div style='color:{p.text_faint};margin-top:2px'>{e(det.rule_id)} v{e(det.rule_version)}"
        f" · finding #{det.id} · {e(format_local(det.first_seen))} → "
        f"{e(format_local(det.last_seen))}</div>",
        "<p>"
        f"<span style='color:{sev_color};font-weight:600'>Severity {e(det.severity)}</span>"
        f" &nbsp;·&nbsp; Confidence {e(det.confidence)}"
        f" &nbsp;·&nbsp; Risk {det.risk_score}/100"
        f" &nbsp;·&nbsp; Status <b>{e(triage)}</b></p>",
    ]
    risk_note = stored_risk_note(det.severity, det.confidence, det.evidence, det.risk_score)
    if risk_note:
        parts.append(f"<p style='color:{p.text_faint}'>{e(risk_note)}</p>")
    if rule:
        parts.append(f"<p style='color:{p.text_muted}'>{e(rule.description)}</p>")

    confidence = det.evidence.get("confidence")
    if isinstance(confidence, dict) and confidence.get("factors") is not None:
        rows = (
            "".join(
                f"<tr><td style='padding:2px 12px 2px 0;color:{p.text_muted}'>"
                f"{'+' if f['points'] > 0 else ''}{f['points']}</td><td>{e(f['reason'])}</td></tr>"
                for f in confidence["factors"]
            )
            or "<tr><td>No factors applied.</td></tr>"
        )
        parts.append(
            _section(
                f"Why confidence is {e(str(confidence.get('value')))}",
                f"<table cellspacing='0'>{rows}</table><p style='color:{p.text_faint}'>"
                f"Total {confidence.get('points')} points · {e(str(confidence.get('scale')))}. "
                "Confidence describes the evidence, not proof of compromise.</p>",
            )
        )

    rows = []
    ordered = [k for k in EVIDENCE_LABELS if k in det.evidence]
    ordered += [k for k in det.evidence if k not in EVIDENCE_LABELS and k not in HIDDEN_EVIDENCE]
    for key in ordered:
        name = EVIDENCE_LABELS.get(key, key.replace("_", " ").capitalize())
        rows.append(
            f"<tr><td style='color:{p.text_faint};padding:3px 16px 3px 0'>{e(name)}</td>"
            f"<td style='padding:3px 0'>{e(_format_value(key, det.evidence[key]))}</td></tr>"
        )
    identity = det.evidence.get("identity")
    if isinstance(identity, dict):
        basis = str(identity.get("basis", "")).replace("_", " ")
        sid = identity.get("sid") or "not recorded"
        rows.append(
            f"<tr><td style='color:{p.text_faint};padding:3px 16px 3px 0'>Identity</td>"
            f"<td>{e(basis)} · SID {e(str(sid))}</td></tr>"
        )
        aliases = identity.get("domain_aliases")
        if isinstance(aliases, list) and aliases:
            rows.append(
                f"<tr><td style='color:{p.text_faint};padding:3px 16px 3px 0'>Domain aliases</td>"
                f"<td>{e('; '.join(str(a) for a in aliases))}</td></tr>"
            )
    chain = det.evidence.get("chain")
    if isinstance(chain, list) and chain:
        parts.append(_section("Activity chain (across logs)", _chain_table(chain)))
    parts.append(_section("Evidence", f"<table cellspacing='0'>{''.join(rows)}</table>"))

    if rule:
        logic = _rule_logic(rule, det.evidence)
        if logic:
            parts.append(f"<p style='color:{p.text_faint}'>Rule logic: {e(logic)}</p>")
        mitre = "".join(
            f"<li><b>{e(m.technique_id)}</b> {e(m.name)} "
            f"<span style='color:{p.text_faint}'>— {e(m.tactic)}</span></li>"
            for m in rule.mitre
        )
        if not mitre:
            mitre = (
                "<li>None mapped at rule level (a Defender threat name is a classification, "
                "not a technique). Related techniques, if any, are listed in the evidence.</li>"
            )
        parts.append(_section("MITRE ATT&amp;CK", f"<ul>{mitre}</ul>"))
        parts.append(_section("Possible False Positives", _bullets(rule.false_positives)))
        parts.append(
            _section("Recommended Investigation", _bullets(rule.recommended_investigation))
        )

    if notes:
        items = "".join(
            f"<p><span style='color:{p.text_faint}'>{e(format_local(n.created_at))}</span><br>"
            f"{e(n.body)}</p>"
            for n in notes
        )
        parts.append(_section(f"Analyst Notes ({len(notes)})", items))
    return "".join(parts)


class DetectionsPage(QWidget):
    status_requested = Signal(int, str)  # detection id, TriageStatus value
    note_requested = Signal(int, str)
    timeline_requested = Signal(int)
    evidence_requested = Signal(int)
    story_requested = Signal(int)
    suppress_requested = Signal(object)  # prefill dict for the suppression dialog

    def __init__(self, rules: dict[str, RuleMetadata]) -> None:
        super().__init__()
        self._rules = rules
        self._all: list[StoredDetection] = []
        self._notes: dict[int, list[AnalystNote]] = {}
        self._selected_id: int | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(theme.SPACE_6, theme.SPACE_4, theme.SPACE_6, theme.SPACE_6)
        layout.setSpacing(theme.SPACE_3)

        top = QHBoxLayout()
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filter by account, rule, severity or status…")
        self.filter.setClearButtonEnabled(True)
        self.status_filter = QComboBox()
        self.status_filter.addItems(STATUS_FILTERS)
        self.status_filter.setToolTip(
            "Open = not yet closed as true/false positive, benign or resolved"
        )
        top.addWidget(self.filter, 1)
        top.addWidget(self.status_filter)
        layout.addLayout(top)

        self.model = RecordTableModel(
            [
                Column("SEVERITY", lambda d: d.severity, lambda d: Severity(d.severity).rank),
                Column("RULE", lambda d: d.rule_id),
                Column("DETECTION", lambda d: d.title),
                Column("ACCOUNT / SOURCE", _subject),
                Column("STATUS", lambda d: d.status.label),
                Column("CONFIDENCE", lambda d: d.confidence),
                Column("RISK", lambda d: str(d.risk_score), lambda d: d.risk_score),
                Column("LAST SEEN", lambda d: format_local(d.last_seen), lambda d: d.last_seen),
            ]
        )
        self.table, self.proxy = make_table(self.model, stretch_column=None)
        self.table.setItemDelegateForColumn(0, SeverityDelegate(self.table))
        self.table.sortByColumn(7, Qt.SortOrder.DescendingOrder)
        self.filter.textChanged.connect(self.proxy.setFilterFixedString)
        self.status_filter.currentTextChanged.connect(lambda _t: self._apply_rows())
        self.table.selectionModel().selectionChanged.connect(self._on_selection)

        self.detail_panel = self._build_detail_panel()
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self.table)
        splitter.addWidget(self.detail_panel)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        splitter.setChildrenCollapsible(False)
        self.detail_panel.setMinimumWidth(DETAIL_MIN_WIDTH)
        splitter.setSizes([TABLE_INITIAL_WIDTH, DETAIL_MIN_WIDTH])

        self.view = StatefulView(
            splitter, "No detections yet", "Run a scan to analyze Windows security events."
        )
        layout.addWidget(self.view, 1)
        self._set_actions_enabled(False)

    # ------------------------------------------------------------------ layout
    def _build_detail_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(theme.SPACE_3, 0, 0, 0)
        layout.setSpacing(theme.SPACE_2)

        nav = QHBoxLayout()
        self.timeline_button = QPushButton("Open Timeline")
        self.timeline_button.setProperty("variant", "primary")
        self.timeline_button.clicked.connect(lambda: self._emit_id(self.timeline_requested))
        self.evidence_button = QPushButton("Evidence")
        self.evidence_button.setToolTip("Show exactly the Windows events this finding is based on")
        self.evidence_button.clicked.connect(lambda: self._emit_id(self.evidence_requested))
        self.story_button = QPushButton("Story")
        self.story_button.setToolTip(
            "This finding, related findings and their evidence as one narrative"
        )
        self.story_button.clicked.connect(lambda: self._emit_id(self.story_requested))
        nav.addWidget(self.timeline_button)
        nav.addWidget(self.evidence_button)
        nav.addWidget(self.story_button)
        self.suppress_button = QPushButton("Suppress…")
        self.suppress_button.setToolTip(
            "Hide future findings like this one (needs a reason; existing findings stay)"
        )
        self.suppress_button.clicked.connect(self._suppress)
        nav.addWidget(self.suppress_button)
        nav.addStretch(1)
        layout.addLayout(nav)

        # Workflow actions on the first row, verdicts on the second, so labels never clip.
        triage = QGridLayout()
        triage.setHorizontalSpacing(theme.SPACE_1)
        triage.setVerticalSpacing(theme.SPACE_1)
        self.triage_buttons: list[QPushButton] = []
        positions = [(0, 0), (1, 0), (1, 1), (1, 2), (0, 1)]  # same order as TRIAGE_ACTIONS
        for (text, status), (row, col) in zip(TRIAGE_ACTIONS, positions, strict=True):
            button = QPushButton(text)
            button.clicked.connect(partial(self._request_status, status))
            self.triage_buttons.append(button)
            triage.addWidget(button, row, col)
        triage.addWidget(label("Workflow", "caption"), 0, 3)
        triage.addWidget(label("Verdict", "caption"), 1, 3)
        triage.setColumnStretch(3, 1)
        layout.addLayout(triage)

        self.detail = QTextBrowser()
        self.detail.setOpenLinks(False)
        self.detail.setHtml(self._placeholder_html())
        layout.addWidget(self.detail, 1)

        layout.addWidget(label("Add analyst note", "caption"))
        self.note_edit = QPlainTextEdit()
        self.note_edit.setPlaceholderText("What did you check? What did you conclude?")
        self.note_edit.setFixedHeight(72)
        self.note_button = QPushButton("Add Note")
        self.note_button.clicked.connect(self._submit_note)
        note_row = QHBoxLayout()
        note_row.addWidget(self.note_edit, 1)
        note_row.addWidget(self.note_button, 0, Qt.AlignmentFlag.AlignBottom)
        layout.addLayout(note_row)
        return panel

    @staticmethod
    def _placeholder_html() -> str:
        return (
            f"<p style='color:{theme.ACTIVE.text_faint}'>Select a detection to see its "
            "evidence, confidence explanation, MITRE ATT&amp;CK mapping and investigation "
            "guidance.</p>"
        )

    # ------------------------------------------------------------------ data
    def show_detections(
        self,
        detections: list[StoredDetection],
        scanned: bool,
        notes: dict[int, list[AnalystNote]] | None = None,
    ) -> None:
        self._all = detections
        self._notes = notes or {}
        self._scanned = scanned
        self._apply_rows()

    def _apply_rows(self) -> None:
        choice = self.status_filter.currentText()
        if choice == "Open":
            rows = [d for d in self._all if not d.status.is_closed]
        elif choice == "All":
            rows = list(self._all)
        else:
            rows = [d for d in self._all if d.status.label == choice]
        previous = self._selected_id
        self.model.set_rows(rows)
        if rows:
            self.view.show_content()
            if previous is not None and not self.select_detection(previous):
                self._clear_detail()
        elif self._all:
            self.view.show_empty(
                f"No {choice.lower()} detections", "Change the status filter to see other findings."
            )
            self._clear_detail()
        elif getattr(self, "_scanned", False):
            self.view.show_empty(
                "No detections found during this scan.", "No rule matched the stored events."
            )
            self._clear_detail()
        else:
            self.view.show_empty("No detections yet", "Run a scan to analyze Windows events.")
            self._clear_detail()

    def select_detection(self, detection_id: int) -> bool:
        for row in range(self.model.rowCount()):
            if self.model.row_at(row).id == detection_id:
                index = self.proxy.mapFromSource(self.model.index(row, 0))
                if index.isValid():
                    self.table.selectRow(index.row())
                    self._render(self.model.row_at(row))
                    return True
        return False

    def _clear_detail(self) -> None:
        self._selected_id = None
        self.detail.setHtml(self._placeholder_html())
        self._set_actions_enabled(False)

    def _set_actions_enabled(self, enabled: bool) -> None:
        for widget in (
            *self.triage_buttons,
            self.timeline_button,
            self.evidence_button,
            self.story_button,
            self.suppress_button,
            self.note_button,
            self.note_edit,
        ):
            widget.setEnabled(enabled)

    def _render(self, detection: StoredDetection) -> None:
        self._selected_id = detection.id
        notes = self._notes.get(detection.id, [])
        self.detail.setHtml(
            render_detection_html(detection, self._rules.get(detection.rule_id), notes)
        )
        self._set_actions_enabled(True)
        for button, (_text, status) in zip(self.triage_buttons, TRIAGE_ACTIONS, strict=True):
            button.setEnabled(detection.status is not status)

    def _suppress(self) -> None:
        detection = next((d for d in self._all if d.id == self._selected_id), None)
        if detection is not None:
            self.suppress_requested.emit(suppression_prefill(detection))

    def _emit_id(self, signal: Signal) -> None:  # type: ignore[valid-type]
        if self._selected_id is not None:
            signal.emit(self._selected_id)  # type: ignore[attr-defined]

    def _request_status(self, status: TriageStatus, _checked: bool = False) -> None:
        if self._selected_id is not None:
            self.status_requested.emit(self._selected_id, status.value)

    @Slot()
    def _submit_note(self) -> None:
        text = self.note_edit.toPlainText().strip()
        if text and self._selected_id is not None:
            self.note_requested.emit(self._selected_id, text)
            self.note_edit.clear()

    @Slot(QItemSelection, QItemSelection)
    def _on_selection(self, selected: QItemSelection, _deselected: QItemSelection) -> None:
        indexes = selected.indexes()
        if not indexes:
            return
        source = self.proxy.mapToSource(indexes[0])
        self._render(self.model.row_at(source.row()))


def _subject(d: StoredDetection) -> str:
    if d.account:
        return d.account
    source = d.evidence.get("source")
    return str(source).removeprefix("workstation:") if source else "—"
