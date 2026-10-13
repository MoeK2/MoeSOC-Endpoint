"""Investigation Story page: a finding, its related findings and the evidence as a narrative."""

from __future__ import annotations

import html

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QHBoxLayout, QPushButton, QTextBrowser, QVBoxLayout, QWidget

from moesoc.gui import theme
from moesoc.gui.widgets.common import StatefulView, label, severity_color
from moesoc.storage.story import MAX_STEPS, Story
from moesoc.utils.time import format_local

LOG_NAMES = {
    "security": "Security",
    "sysmon": "Sysmon",
    "powershell": "PowerShell",
    "defender": "Defender",
}


def render_story_html(story: Story) -> str:
    """Every value from telemetry or analysts is HTML-escaped."""
    p = theme.ACTIVE
    e = html.escape

    def section(title: str, body: str) -> str:
        return (
            f"<div style='margin-top:16px;color:{p.text_muted};font-size:9pt;"
            f"font-weight:600'>{e(title.upper())}</div>{body}"
        )

    parts = [
        f"<div style='font-size:15pt;font-weight:600'>{e(story.title)}</div>",
        f"<div style='color:{p.text_faint};margin-top:2px'>"
        f"{e(format_local(story.start))} → {e(format_local(story.end))}</div>",
        f"<p style='color:{p.text_muted}'>{e(story.disclaimer)}</p>",
    ]
    rows = "".join(
        f"<tr><td style='padding:2px 12px 2px 0'>#{f.id}</td>"
        f"<td style='padding:2px 12px 2px 0'><b>{e(f.rule_id)}</b> {e(f.title)}</td>"
        f"<td style='padding:2px 12px 2px 0;color:{severity_color(f.severity)}'>"
        f"{e(f.severity)}</td>"
        f"<td style='padding:2px 12px 2px 0'>{e(f.status)}</td>"
        f"<td style='color:{p.text_faint}'>{e(f.relation)}</td></tr>"
        for f in story.findings
    )
    parts.append(section("Findings in this story", f"<table cellspacing='0'>{rows}</table>"))

    steps = []
    for s in story.steps:
        when = format_local(s.start)
        if s.count > 1 and s.end != s.start:
            when += f" → {format_local(s.end)}"
        support = ", ".join(s.findings)
        steps.append(
            f"<tr><td style='color:{p.text_faint};padding:3px 12px 3px 0;white-space:nowrap'>"
            f"{e(when)}</td>"
            f"<td style='padding:3px 12px 3px 0;white-space:nowrap'>"
            f"{e(LOG_NAMES.get(s.log, s.log))} {s.event_id}</td>"
            f"<td style='padding:3px 12px 3px 0'>{e(s.text)}</td>"
            f"<td style='color:{p.text_muted}'>{e(support)}</td></tr>"
        )
    body = f"<table cellspacing='0'>{''.join(steps)}</table>"
    if story.truncated:
        body += f"<p style='color:{p.text_faint}'>Only the first {MAX_STEPS} steps are shown.</p>"
    parts.append(section("What happened (recorded events, in order)", body))
    parts.append(
        section(
            "What the data cannot tell",
            "<ul>" + "".join(f"<li>{e(g)}</li>" for g in story.gaps) + "</ul>",
        )
    )
    if story.next_steps:
        parts.append(
            section(
                "Next steps",
                "<ol>" + "".join(f"<li>{e(n)}</li>" for n in story.next_steps) + "</ol>",
            )
        )
    if story.notes:
        notes = "".join(
            f"<p><span style='color:{p.text_faint}'>{e(format_local(n.created_at))}</span> "
            f"{e(n.body)}</p>"
            for n in story.notes
        )
        parts.append(section("Analyst notes", notes))
    return "".join(parts)


class StoryPage(QWidget):
    detection_requested = Signal(int)  # back to the finding
    timeline_requested = Signal(int)

    def __init__(self) -> None:
        super().__init__()
        self._detection_id: int | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(theme.SPACE_6, theme.SPACE_4, theme.SPACE_6, theme.SPACE_6)
        layout.setSpacing(theme.SPACE_3)
        header = QHBoxLayout()
        header.addWidget(label("Investigation Story", "banner"))
        header.addStretch(1)
        self.back_button = QPushButton("Back to finding")
        self.timeline_button = QPushButton("Open Timeline")
        for button in (self.back_button, self.timeline_button):
            button.setEnabled(False)
            header.addWidget(button)
        layout.addLayout(header)
        self.back_button.clicked.connect(lambda: self._emit(self.detection_requested))
        self.timeline_button.clicked.connect(lambda: self._emit(self.timeline_requested))

        self.browser = QTextBrowser()
        self.browser.setOpenLinks(False)
        self.view = StatefulView(
            self.browser,
            "No story selected",
            "Select a finding in Detections and choose Story.",
        )
        layout.addWidget(self.view, 1)

    def _emit(self, signal: Signal) -> None:  # type: ignore[valid-type]
        if self._detection_id is not None:
            signal.emit(self._detection_id)  # type: ignore[attr-defined]

    def show_loading(self) -> None:
        self.view.show_loading()

    def show_error(self, message: str) -> None:
        self.view.show_error(message)

    def show_story(self, story: Story) -> None:
        self._detection_id = story.detection_id
        self.browser.setHtml(render_story_html(story))
        self.back_button.setEnabled(True)
        self.timeline_button.setEnabled(True)
        self.view.show_content()

    def plain_text(self) -> str:
        return self.browser.toPlainText()
