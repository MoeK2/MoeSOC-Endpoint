"""Self-contained HTML reports: one finding (as its investigation story) or the endpoint.

The HTML has inline CSS only: no JavaScript, no external fonts, images or links, so
it opens offline and sends nothing anywhere. Every value from telemetry or analysts
is HTML-escaped. Command lines, script text and raw event XML are never included.

``redact=True`` replaces computer names, account names, SIDs and IP addresses with
stable placeholders (HOST-1, USER-1, SID-1, IP-1) so a report can be shared for
review without exposing the environment. The same value always gets the same
placeholder within one report.
"""

from __future__ import annotations

import html
import ipaddress
import re
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass, field

from moesoc import APP_NAME, __version__
from moesoc.core.detection import RuleMetadata, related_techniques
from moesoc.engine.risk import stored_risk_note
from moesoc.storage.overview import OverviewSnapshot
from moesoc.storage.repository import DetectionRepository, ScanRepository, StoredDetection
from moesoc.storage.story import Story, build_story
from moesoc.utils.time import format_local, utc_now

_SID = re.compile(r"\bS-1-5-21-\d+-\d+-\d+(?:-\d+)?\b|\bS-1-5-\d+(?:-\d+)*\b")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")
WELL_KNOWN_SIDS = {"S-1-5-18", "S-1-5-19", "S-1-5-20"}  # SYSTEM, LOCAL/NETWORK SERVICE
SEVERITY_COLORS = {"LOW": "#4a7bd0", "MEDIUM": "#c98a10", "HIGH": "#d0453f", "CRITICAL": "#a31d6f"}

CSS = """
body{font-family:Segoe UI,Arial,sans-serif;margin:32px auto;max-width:980px;color:#1c2330;
line-height:1.45;padding:0 16px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:15px;margin:28px 0 8px;text-transform:uppercase;
letter-spacing:.04em;color:#4b5565}
.meta{color:#5d6878;font-size:13px}.note{background:#f3f5f8;border-left:3px solid #8a96a8;
padding:8px 12px;font-size:13px;margin:14px 0}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:5px 8px;
border-bottom:1px solid #e3e7ee;vertical-align:top}th{color:#5d6878;font-weight:600}
.sev{font-weight:600}.mono{font-family:Consolas,monospace;font-size:12px}
footer{margin-top:36px;color:#8a94a3;font-size:12px}
@media print{body{margin:0}}
"""


@dataclass
class Redactor:
    """Consistent placeholders for identifying values (only when enabled)."""

    enabled: bool = False
    hosts: list[str] = field(default_factory=list)
    accounts: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    _maps: dict[str, dict[str, str]] = field(default_factory=dict)

    def _token(self, kind: str, value: str) -> str:
        table = self._maps.setdefault(kind, {})
        key = value.casefold()
        if key not in table:
            table[key] = f"{kind}-{len(table) + 1}"
        return table[key]

    def text(self, value: object) -> str:
        text = "" if value is None else str(value)
        if not self.enabled or not text:
            return text
        for host in sorted(self.hosts, key=len, reverse=True):
            if host:
                text = re.sub(
                    re.escape(host), lambda _m, h=host: self._token("HOST", h), text, flags=re.I
                )
                short = host.split(".", 1)[0]
                if short and short != host:
                    text = re.sub(
                        rf"\b{re.escape(short)}\b",
                        lambda _m, h=host: self._token("HOST", h),
                        text,
                        flags=re.I,
                    )
        for account in sorted(self.accounts, key=len, reverse=True):
            if account:
                text = re.sub(
                    rf"(?<![\w-]){re.escape(account)}(?![\w-])",
                    lambda _m, a=account: self._token("USER", a),
                    text,
                    flags=re.I,
                )
        for domain in sorted(self.domains, key=len, reverse=True):
            if domain and domain.upper() not in {"NT AUTHORITY", "BUILTIN"}:
                text = re.sub(
                    rf"(?<![\w-]){re.escape(domain)}(?=\\)",
                    lambda _m, d=domain: self._token("DOMAIN", d),
                    text,
                    flags=re.I,
                )
        text = _SID.sub(
            lambda m: (
                m.group(0) if m.group(0) in WELL_KNOWN_SIDS else self._token("SID", m.group(0))
            ),
            text,
        )
        text = _IPV4.sub(lambda m: self._ip(m.group(0)), text)
        return _IPV6.sub(lambda m: self._ip(m.group(0)), text)

    def _ip(self, value: str) -> str:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return value
        if address.is_loopback or address.is_unspecified:
            return value  # carries no identity
        return self._token("IP", value)


def _accounts_of(detections: list[StoredDetection]) -> list[str]:
    """User names only (the part after the backslash), so one person keeps one placeholder
    whichever domain spelling an event used; domains are redacted separately."""
    names: set[str] = set()
    for d in detections:
        values = [d.account] + [
            d.evidence.get(k)
            for k in ("account", "user", "member", "created_by", "added_by", "actor")
        ]
        for value in values:
            if isinstance(value, str) and value:
                names.add(value.rsplit("\\", 1)[-1])
        for name in d.evidence.get("accounts") or ():
            names.add(str(name).rsplit("\\", 1)[-1])
    return sorted(n for n in names if len(n) >= 2)


def _domains_of(detections: list[StoredDetection]) -> list[str]:
    domains: set[str] = set()
    for d in detections:
        keys = ("account", "user", "actor", "created_by", "added_by")
        for value in (d.account, *(d.evidence.get(k) for k in keys)):
            if isinstance(value, str) and "\\" in value:
                domains.add(value.rsplit("\\", 1)[0])
        for domain in d.evidence.get("target_domains") or ():
            domains.add(str(domain))
    return sorted(x for x in domains if x)


def _hosts_of(detections: list[StoredDetection], extra: list[str] | None = None) -> list[str]:
    hosts = {str(d.evidence.get("hostname")) for d in detections if d.evidence.get("hostname")}
    return sorted(hosts | set(extra or ()))


def _page(title: str, body: str, redacted: bool) -> str:
    stamp = format_local(utc_now())
    notice = (
        "Identifying values (computers, accounts, SIDs, IP addresses) are replaced with "
        "placeholders."
        if redacted
        else "Contains computer names, accounts and addresses from this environment. "
        "Use the redacted export to share it outside your team."
    )
    return (
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{html.escape(title)}</title><style>{CSS}</style></head><body>"
        f"{body}<div class='note'>{html.escape(notice)}</div>"
        f"<footer>Generated by {html.escape(APP_NAME)} {html.escape(__version__)} on "
        f"{html.escape(stamp)} from locally stored Windows telemetry. Findings are leads for "
        "investigation, not proof of compromise.</footer></body></html>"
    )


def _sev(value: str) -> str:
    color = SEVERITY_COLORS.get(value, "#5d6878")
    return f"<span class='sev' style='color:{color}'>{html.escape(value)}</span>"


def _data_origin(conn: sqlite3.Connection) -> str:
    origins = {r[0] for r in conn.execute("SELECT DISTINCT origin FROM scans")}
    if origins == {"import"}:
        return (
            "Imported event export(s) only. If the export was synthetic test data, this "
            "report describes test data."
        )
    if "import" in origins:
        return "Live collection from this computer and imported event export(s)."
    return "Live collection from this computer."


# ----------------------------------------------------------------- finding report
def finding_report(
    conn: sqlite3.Connection,
    detection_id: int,
    rules: Mapping[str, RuleMetadata] | None = None,
    *,
    redact: bool = False,
) -> str:
    story = build_story(conn, detection_id, rules)
    repo = DetectionRepository(conn)
    members = [d for d in (repo.get(f.id) for f in story.findings) if d is not None]
    r = Redactor(
        redact,
        _hosts_of(members, [story.hostname or ""]),
        _accounts_of(members),
        _domains_of(members),
    )
    e = lambda value: html.escape(r.text(value))  # noqa: E731 - local shorthand
    primary = members[0]
    rule = (rules or {}).get(primary.rule_id)

    parts = [
        f"<h1>{e(story.title)}</h1>",
        f"<div class='meta'>Finding #{primary.id} · {e(primary.rule_id)} v"
        f"{e(primary.rule_version)} · {e(format_local(story.start))} → "
        f"{e(format_local(story.end))} · status {e(primary.status.label)}</div>",
        f"<p>Severity {_sev(primary.severity)} · confidence {e(primary.confidence)} · risk "
        f"{primary.risk_score}/100</p>",
        f"<div class='note'>{e(story.disclaimer)} Data source: {e(_data_origin(conn))}</div>",
    ]
    if rule is not None:
        parts.append(f"<p>{e(rule.description)}</p>")

    rows = "".join(
        f"<tr><td>#{f.id}</td><td>{e(f.rule_id)}</td><td>{e(f.title)}</td>"
        f"<td>{_sev(f.severity)}</td><td>{e(f.confidence)}</td><td>{e(f.status)}</td>"
        f"<td>{e(f.relation)}</td></tr>"
        for f in story.findings
    )
    parts.append(
        "<h2>Findings</h2><table><tr><th>#</th><th>Rule</th><th>Title</th><th>Severity</th>"
        f"<th>Confidence</th><th>Status</th><th>Relation</th></tr>{rows}</table>"
    )
    parts.append(_steps_table(story, e))
    parts.append(_why(primary, e))
    parts.append("<h2>What the data cannot tell</h2><ul>")
    parts += [f"<li>{e(g)}</li>" for g in story.gaps]
    parts.append("</ul>")
    if story.next_steps:
        parts.append("<h2>Next steps</h2><ol>")
        parts += [f"<li>{e(n)}</li>" for n in story.next_steps]
        parts.append("</ol>")
    extra = related_techniques(primary.evidence)
    if (rule is not None and rule.mitre) or extra:
        parts.append("<h2>MITRE ATT&amp;CK</h2><ul>")
        parts += [
            f"<li><b>{e(m.technique_id)}</b> {e(m.name)} — {e(m.tactic)}</li>"
            for m in (rule.mitre if rule is not None else ())
        ]
        parts += [f"<li><b>{e(t)}</b> — related to this finding</li>" for t in extra]
        parts.append("</ul>")
    if story.notes:
        parts.append("<h2>Analyst notes</h2>")
        parts += [
            f"<p><span class='meta'>{e(format_local(n.created_at))}</span> {e(n.body)}</p>"
            for n in story.notes
        ]
    history = repo.history(primary.id)
    if history:
        parts.append("<h2>Triage history</h2><table><tr><th>When</th><th>From</th><th>To</th></tr>")
        parts += [
            f"<tr><td>{e(format_local(h.changed_at))}</td><td>{e(h.from_status or '—')}</td>"
            f"<td>{e(h.to_status)}</td></tr>"
            for h in history
        ]
        parts.append("</table>")
    title = f"MoeSOC finding #{primary.id}"
    return _page(title, "".join(parts), redact)


def _steps_table(story: Story, e) -> str:
    rows = []
    for s in story.steps:
        when = format_local(s.start)
        if s.count > 1 and s.end != s.start:
            when += f" → {format_local(s.end)}"
        rows.append(
            f"<tr><td>{e(when)}</td><td>{e(s.log)} {s.event_id}</td><td>{e(s.text)}</td>"
            f"<td>{e(', '.join(s.findings))}</td></tr>"
        )
    return (
        "<h2>What happened (recorded events, in order)</h2><table><tr><th>When</th><th>Log</th>"
        f"<th>Event</th><th>Supports</th></tr>{''.join(rows)}</table>"
    )


def _why(detection: StoredDetection, e) -> str:
    rows = []
    confidence = detection.evidence.get("confidence")
    if isinstance(confidence, dict):
        for f in confidence.get("factors") or []:
            rows.append(f"<tr><td>Confidence</td><td>{f.get('points'):+}</td>"
                        f"<td>{e(f.get('reason'))}</td></tr>")  # fmt: skip
    for f in detection.evidence.get("risk_factors") or []:
        rows.append(
            f"<tr><td>Risk</td><td>{f.get('points'):+}</td><td>{e(f.get('reason'))}</td></tr>"
        )
    note = stored_risk_note(
        detection.severity, detection.confidence, detection.evidence, detection.risk_score
    )
    if not rows and not note:
        return ""
    return (
        "<h2>Why this confidence and risk</h2>"
        + (f"<p class='note'>{e(note)}</p>" if note else "")
        + "<table><tr><th>Score</th><th>Points</th>"
        f"<th>Reason</th></tr>{''.join(rows)}</table>"
    )


# ----------------------------------------------------------------- endpoint summary
def summary_report(
    conn: sqlite3.Connection, snapshot: OverviewSnapshot, *, redact: bool = False
) -> str:
    detections = snapshot.open_detections
    hosts = [str(r[0]) for r in conn.execute("SELECT DISTINCT hostname FROM events")]
    r = Redactor(
        redact, _hosts_of(detections, hosts), _accounts_of(detections), _domains_of(detections)
    )
    e = lambda value: html.escape(r.text(value))  # noqa: E731
    last = ScanRepository(conn).last()
    risk = (
        "Unavailable (no completed scan)"
        if snapshot.risk_score is None
        else str(snapshot.risk_score)
    )
    parts = [
        "<h1>MoeSOC endpoint summary</h1>",
        f"<div class='meta'>{e(', '.join(hosts) or 'No events stored')}</div>",
        f"<div class='note'>Data source: {e(_data_origin(conn))}</div>",
        "<h2>At a glance</h2><table>",
        f"<tr><th>Risk score</th><td>{e(risk)} — {e(snapshot.risk_explanation())}</td></tr>",
        f"<tr><th>Open findings</th><td>{len(detections)}</td></tr>",
        f"<tr><th>Stored events</th><td>{snapshot.events_total:,}</td></tr>",
    ]
    if snapshot.event_time_range:
        first, last_event = snapshot.event_time_range
        parts.append(
            f"<tr><th>Event period</th><td>{e(format_local(first))} → "
            f"{e(format_local(last_event))}</td></tr>"
        )
    if last is not None:
        parts.append(
            f"<tr><th>Last scan</th><td>{e(format_local(last.started_at))} · {e(last.origin)} · "
            f"{e(last.status)}{' · ' + e(last.collection_mode) if last.collection_mode else ''}"
            "</td></tr>"
        )
    parts.append("</table>")
    rows = "".join(
        f"<tr><td>#{d.id}</td><td>{e(d.rule_id)}</td><td>{e(d.title)}</td><td>{_sev(d.severity)}</td>"
        f"<td>{e(d.confidence)}</td><td>{d.risk_score}</td><td>{e(d.account or '—')}</td>"
        f"<td>{e(format_local(d.last_seen))}</td><td>{e(d.status.label)}</td></tr>"
        for d in sorted(detections, key=lambda d: (-d.risk_score, d.id))
    )
    parts.append(
        "<h2>Open findings (highest risk first)</h2><table><tr><th>#</th><th>Rule</th>"
        "<th>Title</th>"
        "<th>Severity</th><th>Confidence</th><th>Risk</th><th>Account</th><th>Last seen</th>"
        f"<th>Status</th></tr>{rows or '<tr><td colspan=9>No open findings.</td></tr>'}</table>"
    )
    by_id = sorted(snapshot.events_by_id.items())
    parts.append(
        "<h2>Stored events by ID</h2><table><tr><th>Event ID</th><th>Count</th></tr>"
        + "".join(f"<tr><td>{i}</td><td>{n:,}</td></tr>" for i, n in by_id)
        + "</table>"
    )
    return _page("MoeSOC endpoint summary", "".join(parts), redact)
