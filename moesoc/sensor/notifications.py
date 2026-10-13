"""Finding-based notifications: when a finding is worth interrupting the user.

Raw events never notify. After the sensor stores a batch it asks this engine which
findings changed (``detections.updated_at``, indexed) and decides per finding:

* a finding notifies the FIRST time it is open and its severity is enabled
  (default: HIGH and CRITICAL; MEDIUM off; LOW never);
* it notifies again only when its severity ESCALATES (immediately), or its risk grows by
  at least ``MATERIAL_RISK_INCREASE`` and the cooldown has passed;
* a growing burst (DET-001 at 5, 7, 9, 12 failures) is one finding and one notification;
* a new correlation (for example COR-001 on top of DET-001) is a new finding and notifies
  on its own if its severity is enabled;
* closed findings never notify; while notifications are paused the decisions are made
  and recorded, but marked silent (collection continues).

The state lives in ``notification_state`` (schema v9), so a service restart neither
repeats nor forgets notifications. On the very first evaluation the engine records "now"
and does not notify about findings that existed before the sensor was installed.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections import deque
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta

from moesoc.core.detection import RuleMetadata
from moesoc.core.enums import CLOSED_STATUSES, Severity
from moesoc.storage.repository import from_db_time, to_db_time
from moesoc.utils.time import utc_now

MATERIAL_RISK_INCREASE = 15
MAX_TOASTS_PER_EVALUATION = 3
EVALUATED_KEY = "notify.evaluated_until"
PREFS_KEY = "notify.preferences"
MIN_COOLDOWN, MAX_COOLDOWN = 5, 24 * 60
MAX_PAUSE_HOURS = 24


@dataclass(frozen=True, slots=True)
class NotificationPrefs:
    medium: bool = False
    high: bool = True
    critical: bool = True
    cooldown_minutes: int = 60
    paused_until: datetime | None = None

    def enabled(self, severity: Severity) -> bool:
        return {
            Severity.MEDIUM: self.medium,
            Severity.HIGH: self.high,
            Severity.CRITICAL: self.critical,
        }.get(severity, False)  # LOW never toasts

    def paused(self, now: datetime) -> bool:
        return self.paused_until is not None and now < self.paused_until

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["paused_until"] = to_db_time(self.paused_until) if self.paused_until else None
        return data

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> NotificationPrefs:
        """Validated: unknown keys or wrong types raise ValueError (IPC input)."""
        allowed = {"medium", "high", "critical", "cooldown_minutes", "paused_until"}
        if not isinstance(data, dict) or set(data) - allowed:
            raise ValueError("unknown preference")
        prefs = cls()
        for key in ("medium", "high", "critical"):
            if key in data:
                if not isinstance(data[key], bool):
                    raise ValueError(f"{key} must be true or false")
                prefs = replace(prefs, **{key: data[key]})
        if "cooldown_minutes" in data:
            value = data["cooldown_minutes"]
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError("cooldown_minutes must be a whole number")
            if not MIN_COOLDOWN <= value <= MAX_COOLDOWN:
                raise ValueError(f"cooldown_minutes must be {MIN_COOLDOWN}..{MAX_COOLDOWN}")
            prefs = replace(prefs, cooldown_minutes=value)
        if data.get("paused_until") is not None:
            value = data["paused_until"]
            if not isinstance(value, str):
                raise ValueError("paused_until must be a time")
            until = from_db_time(value)
            if until.tzinfo is None:
                raise ValueError("paused_until needs a time zone")
            if until > utc_now() + timedelta(hours=MAX_PAUSE_HOURS):
                raise ValueError(f"notifications can be paused for at most {MAX_PAUSE_HOURS} h")
            prefs = replace(prefs, paused_until=until)
        return prefs


def load_prefs(conn: sqlite3.Connection) -> NotificationPrefs:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (PREFS_KEY,)).fetchone()
    if row is None:
        return NotificationPrefs()
    try:
        return NotificationPrefs.from_dict(json.loads(row[0]))
    except (ValueError, TypeError):
        return NotificationPrefs()  # a damaged setting falls back to safe defaults


def save_prefs(conn: sqlite3.Connection, prefs: NotificationPrefs) -> None:
    _set_setting(conn, PREFS_KEY, json.dumps(prefs.to_dict()))


def _set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        (key, value, to_db_time(utc_now())),
    )


@dataclass(frozen=True, slots=True)
class Notification:
    """What the tray shows. No event content, account SIDs or command lines."""

    detection_id: int | None  # None: a summary of several findings
    rule_id: str
    title: str
    body: str
    severity: str
    risk: int
    reason: str  # new | escalated | risk | summary
    silent: bool = False
    seq: int = 0

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class NotificationEngine:
    def __init__(self, rules: dict[str, RuleMetadata] | None = None) -> None:
        self._rules = rules or {}

    def evaluate(
        self,
        conn: sqlite3.Connection,
        prefs: NotificationPrefs | None = None,
        now: datetime | None = None,
    ) -> list[Notification]:
        now = now or utc_now()
        prefs = prefs or load_prefs(conn)
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (EVALUATED_KEY,)).fetchone()
        if row is None:  # first run: start from now, never flood with old findings
            _set_setting(conn, EVALUATED_KEY, to_db_time(now))
            return []
        changed = conn.execute(
            "SELECT id, rule_id, title, severity, risk_score, status, updated_at "
            "FROM detections WHERE updated_at >= ? ORDER BY updated_at, id",
            (row[0],),
        ).fetchall()
        if not changed:
            return []
        _set_setting(conn, EVALUATED_KEY, max(r["updated_at"] for r in changed))
        silent = prefs.paused(now)
        decided: list[Notification] = []
        for finding in changed:
            note = self._decide(conn, finding, prefs, now)
            if note is not None:
                decided.append(replace(note, silent=silent))
                self._record(conn, finding, now)
        return _limit(decided)

    def _decide(
        self,
        conn: sqlite3.Connection,
        finding: sqlite3.Row,
        prefs: NotificationPrefs,
        now: datetime,
    ) -> Notification | None:
        if finding["status"] in CLOSED_STATUSES:
            return None
        try:
            severity = Severity(finding["severity"])
        except ValueError:
            return None
        if not prefs.enabled(severity):
            return None
        state = conn.execute(
            "SELECT notified_severity, notified_risk, notified_at FROM notification_state "
            "WHERE detection_id = ?",
            (finding["id"],),
        ).fetchone()
        if state is None:
            return self._build(finding, severity, "new")
        try:
            before = Severity(state["notified_severity"])
        except ValueError:
            before = Severity.LOW
        if severity.rank > before.rank:
            return self._build(finding, severity, "escalated")
        cooled = now - from_db_time(state["notified_at"]) >= timedelta(
            minutes=prefs.cooldown_minutes
        )
        if cooled and finding["risk_score"] - state["notified_risk"] >= MATERIAL_RISK_INCREASE:
            return self._build(finding, severity, "risk")
        return None

    def _build(self, finding: sqlite3.Row, severity: Severity, reason: str) -> Notification:
        rule = self._rules.get(finding["rule_id"])
        summary = _first_sentence(rule.description) if rule else ""
        if reason == "escalated":
            summary = f"Severity raised to {severity.value}. {summary}".strip()
        body = f"{summary}\nSeverity: {severity.value} · Risk: {finding['risk_score']}".strip()
        return Notification(
            detection_id=int(finding["id"]),
            rule_id=finding["rule_id"],
            title=finding["title"],
            body=body,
            severity=severity.value,
            risk=int(finding["risk_score"]),
            reason=reason,
        )

    def _record(self, conn: sqlite3.Connection, finding: sqlite3.Row, now: datetime) -> None:
        conn.execute(
            "INSERT INTO notification_state (detection_id, notified_severity, notified_risk, "
            "notified_rule_id, notified_at) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(detection_id) DO UPDATE SET "
            "notified_severity = excluded.notified_severity, "
            "notified_risk = excluded.notified_risk, notified_at = excluded.notified_at, "
            "times_notified = times_notified + 1",
            (
                finding["id"],
                finding["severity"],
                finding["risk_score"],
                finding["rule_id"],
                to_db_time(now),
            ),
        )


def _first_sentence(text: str, limit: int = 140) -> str:
    sentence = " ".join(text.split()).split(". ")[0].rstrip(".")
    if len(sentence) > limit:
        sentence = sentence[: limit - 1].rstrip() + "…"
    return f"{sentence}." if sentence else ""


def _limit(notes: list[Notification]) -> list[Notification]:
    """At most a few toasts at once: the most serious ones, then one summary."""
    if len(notes) <= MAX_TOASTS_PER_EVALUATION:
        return notes
    ranked = sorted(notes, key=lambda n: (Severity(n.severity).rank, n.risk), reverse=True)
    keep = ranked[: MAX_TOASTS_PER_EVALUATION - 1]
    rest = len(notes) - len(keep)
    summary = Notification(
        detection_id=None,
        rule_id="",
        title=f"{rest} more findings need review",
        body="Open MoeSOC to review them on the Detections page.",
        severity=max((n.severity for n in ranked[len(keep) :]), key=lambda s: Severity(s).rank),
        risk=max(n.risk for n in ranked[len(keep) :]),
        reason="summary",
        silent=all(n.silent for n in notes),
    )
    return [*keep, summary]


class NotificationHub:
    """Hands notifications from the sensor thread to IPC clients (long poll), bounded."""

    def __init__(self, capacity: int = 50) -> None:
        self._items: deque[Notification] = deque(maxlen=capacity)
        self._seq = 0
        self._cond = threading.Condition()
        self.last_important: Notification | None = None

    @property
    def seq(self) -> int:
        with self._cond:
            return self._seq

    def publish(self, notes: list[Notification]) -> None:
        if not notes:
            return
        with self._cond:
            for note in notes:
                self._seq += 1
                stored = replace(note, seq=self._seq)
                self._items.append(stored)
                if stored.detection_id is not None:
                    self.last_important = stored
            self._cond.notify_all()

    def wait_after(self, seq: int, timeout: float) -> list[Notification]:
        """Notifications newer than ``seq``; waits up to ``timeout`` seconds for one."""
        with self._cond:
            if self._seq <= seq:
                self._cond.wait_for(lambda: self._seq > seq, timeout)
            return [n for n in self._items if n.seq > seq]

    def wake_all(self) -> None:
        with self._cond:
            self._cond.notify_all()
