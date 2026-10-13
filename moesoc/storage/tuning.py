"""Rule tuning and suppressions, both auditable.

Suppressions hide *future* findings that match a known-benign value (an account, a
source address, a host, a process, a file path or a Defender threat name), for one
rule or for all rules, until an optional expiry. They never delete or change
existing findings, every one needs a reason, and removal is recorded instead of
deleting the row. Every add, removal and rule change is written to ``audit_log``.

Rule tuning can disable a rule or change one of its existing integer parameters
(thresholds, windows) within safe bounds. The YAML files are never edited; the
override lives in the database and is applied when a scan loads the rules.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any

from moesoc.core.detection import Detection, RuleMetadata
from moesoc.core.exceptions import MoeSOCError
from moesoc.storage.repository import from_db_time, to_db_time
from moesoc.utils.time import utc_now

SUPPRESSION_TYPES = ("account", "source_ip", "host", "process", "file_path", "threat")
MIN_REASON = 5
PARAMETER_BOUNDS = (1, 10_000)  # counts and thresholds
MINUTES_BOUNDS = (1, 1_440)  # *_minutes: at most one day, so scans stay bounded
DAYS_BOUNDS = (1, 30)  # *_days


def parameter_bounds(name: str) -> tuple[int, int]:
    if name.endswith("_minutes"):
        return MINUTES_BOUNDS
    if name.endswith("_days"):
        return DAYS_BOUNDS
    return PARAMETER_BOUNDS


class TuningError(MoeSOCError):
    pass


@dataclass(frozen=True, slots=True)
class Suppression:
    id: int
    rule_id: str | None
    type: str
    value: str
    reason: str
    created_at: datetime
    expires_at: datetime | None
    removed_at: datetime | None
    removed_reason: str | None
    hit_count: int
    last_hit_at: datetime | None

    def is_active(self, now: datetime) -> bool:
        return self.removed_at is None and (self.expires_at is None or now < self.expires_at)

    def describe(self) -> str:
        scope = self.rule_id or "all rules"
        return f"{self.type} = {self.value} ({scope})"


@dataclass(frozen=True, slots=True)
class AuditEntry:
    id: int
    at: datetime
    action: str
    target: str
    details: dict[str, Any]
    reason: str | None


def _reason(reason: str | None) -> str:
    text = (reason or "").strip()
    if len(text) < MIN_REASON:
        raise TuningError(f"Give a reason (at least {MIN_REASON} characters) for the audit log.")
    return text


def _time(value: str | None) -> datetime | None:
    return from_db_time(value) if value else None


def _audit(
    conn: sqlite3.Connection, action: str, target: str, details: dict[str, Any], reason: str
) -> None:
    conn.execute(
        "INSERT INTO audit_log (at, action, target, details, reason) VALUES (?, ?, ?, ?, ?)",
        (to_db_time(utc_now()), action, target, json.dumps(details, sort_keys=True), reason),
    )


# ----------------------------------------------------------------- matching
def _basename(path: object) -> str:
    return str(path).replace("/", "\\").rsplit("\\", 1)[-1].casefold()


def detection_values(detection: Detection) -> dict[str, set[str]]:
    """The values of one finding that a suppression of each type can match (casefolded)."""
    ev = detection.evidence
    values: dict[str, set[str]] = {t: set() for t in SUPPRESSION_TYPES}
    if detection.account:
        values["account"].add(detection.account.casefold())
        values["account"].add(detection.account.rsplit("\\", 1)[-1].casefold())
    for key in ("source", "success_source_address"):
        if ev.get(key):
            values["source_ip"].add(str(ev[key]).casefold())
    for address in ev.get("source_addresses") or ():
        values["source_ip"].add(str(address).casefold())
    if ev.get("hostname"):
        values["host"].add(str(ev["hostname"]).casefold())
    for key in ("process", "written_by", "parent_process"):
        if ev.get(key):
            values["process"].add(_basename(ev[key]))
            values["process"].add(str(ev[key]).casefold())
    if ev.get("file_path"):
        values["file_path"].add(str(ev["file_path"]).casefold())
    if ev.get("threat_name"):
        values["threat"].add(str(ev["threat_name"]).casefold())
    return values


def matching_suppression(
    detection: Detection, suppressions: list[Suppression], now: datetime
) -> Suppression | None:
    values = detection_values(detection)
    for s in suppressions:
        if not s.is_active(now):
            continue
        if s.rule_id and s.rule_id != detection.rule_id:
            continue
        if s.value.casefold() in values.get(s.type, set()):
            return s
    return None


# ----------------------------------------------------------------- repository
class TuningRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    # ---- suppressions
    def add_suppression(
        self,
        type_: str,
        value: str,
        reason: str,
        *,
        rule_id: str | None = None,
        days: int | None = None,
        known_rules: Mapping[str, RuleMetadata] | None = None,
    ) -> Suppression:
        if type_ not in SUPPRESSION_TYPES:
            raise TuningError(f"Suppression type must be one of {', '.join(SUPPRESSION_TYPES)}.")
        value = (value or "").strip()
        if not value or value in {"*", "%"}:
            raise TuningError("A suppression needs a specific value (wildcards are not allowed).")
        if rule_id and known_rules is not None and rule_id not in known_rules:
            raise TuningError(f"Unknown rule {rule_id}.")
        if days is not None and not 1 <= days <= 365:
            raise TuningError("Expiry must be between 1 and 365 days.")
        why = _reason(reason)
        now = utc_now()
        expires = now + timedelta(days=days) if days else None
        cursor = self._conn.execute(
            "INSERT INTO suppressions (rule_id, type, value, reason, created_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (rule_id, type_, value, why, to_db_time(now), to_db_time(expires) if expires else None),
        )
        suppression_id = int(cursor.lastrowid or 0)
        _audit(
            self._conn,
            "suppression.add",
            f"suppression #{suppression_id}",
            {"rule_id": rule_id, "type": type_, "value": value, "expires_days": days},
            why,
        )
        return self._require(suppression_id)

    def remove_suppression(self, suppression_id: int, reason: str) -> Suppression:
        why = _reason(reason)
        current = self.get_suppression(suppression_id)
        if current is None:
            raise TuningError(f"Suppression #{suppression_id} does not exist.")
        if current.removed_at is not None:
            raise TuningError(f"Suppression #{suppression_id} was already removed.")
        self._conn.execute(
            "UPDATE suppressions SET removed_at = ?, removed_reason = ? WHERE id = ?",
            (to_db_time(utc_now()), why, suppression_id),
        )
        _audit(
            self._conn,
            "suppression.remove",
            f"suppression #{suppression_id}",
            {"type": current.type, "value": current.value, "hits": current.hit_count},
            why,
        )
        return self._require(suppression_id)

    def _require(self, suppression_id: int) -> Suppression:
        result = self.get_suppression(suppression_id)
        if result is None:  # just written in this transaction
            raise TuningError(f"Suppression #{suppression_id} could not be read back.")
        return result

    def get_suppression(self, suppression_id: int) -> Suppression | None:
        row = self._conn.execute(
            "SELECT * FROM suppressions WHERE id = ?", (suppression_id,)
        ).fetchone()
        return _suppression(row) if row else None

    def suppressions(self, *, include_inactive: bool = False) -> list[Suppression]:
        rows = self._conn.execute("SELECT * FROM suppressions ORDER BY id").fetchall()
        items = [_suppression(r) for r in rows]
        if include_inactive:
            return items
        now = utc_now()
        return [s for s in items if s.is_active(now)]

    def record_hit(self, suppression_id: int) -> None:
        self._conn.execute(
            "UPDATE suppressions SET hit_count = hit_count + 1, last_hit_at = ? WHERE id = ?",
            (to_db_time(utc_now()), suppression_id),
        )

    # ---- rule overrides
    def overrides(self) -> dict[str, tuple[bool, dict[str, int]]]:
        rows = self._conn.execute("SELECT * FROM rule_overrides").fetchall()
        return {
            r["rule_id"]: (bool(r["enabled"]), json.loads(r["parameters_json"] or "{}"))
            for r in rows
        }

    def _save_override(self, rule_id: str, enabled: bool, parameters: dict[str, int]) -> None:
        self._conn.execute(
            "INSERT INTO rule_overrides (rule_id, enabled, parameters_json, updated_at) "
            "VALUES (?, ?, ?, ?) ON CONFLICT(rule_id) DO UPDATE SET enabled = excluded.enabled, "
            "parameters_json = excluded.parameters_json, updated_at = excluded.updated_at",
            (rule_id, int(enabled), json.dumps(parameters, sort_keys=True), to_db_time(utc_now())),
        )

    def set_rule_enabled(self, rule: RuleMetadata, enabled: bool, reason: str) -> None:
        why = _reason(reason)
        _was, parameters = self.overrides().get(rule.rule_id, (True, {}))
        self._save_override(rule.rule_id, enabled, parameters)
        action = "rule.enable" if enabled else "rule.disable"
        _audit(self._conn, action, rule.rule_id, {"version": rule.version}, why)

    def set_rule_parameter(self, rule: RuleMetadata, name: str, value: int, reason: str) -> None:
        """Change one existing integer parameter (thresholds, windows) within bounds."""
        why = _reason(reason)
        default = rule.parameters.get(name)
        if name not in tunable_parameters(rule) or not isinstance(default, int):
            tunable = ", ".join(tunable_parameters(rule)) or "none"
            raise TuningError(f"{rule.rule_id} has no integer parameter '{name}' ({tunable}).")
        low, high = parameter_bounds(name)
        if not low <= value <= high:
            raise TuningError(f"{name} must be between {low} and {high:,}.")
        enabled, parameters = self.overrides().get(rule.rule_id, (True, {}))
        old = parameters.get(name, default)
        if value == default:
            parameters.pop(name, None)  # back to the YAML default
        else:
            parameters[name] = value
        self._save_override(rule.rule_id, enabled, parameters)
        _audit(
            self._conn,
            "rule.parameter",
            rule.rule_id,
            {"parameter": name, "old": old, "new": value, "default": default},
            why,
        )

    # ---- audit
    def audit_log(self, limit: int = 200) -> list[AuditEntry]:
        rows = self._conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [
            AuditEntry(
                r["id"],
                from_db_time(r["at"]),
                r["action"],
                r["target"],
                json.loads(r["details"]),
                r["reason"],
            )
            for r in rows
        ]


def _suppression(row: sqlite3.Row) -> Suppression:
    return Suppression(
        id=row["id"],
        rule_id=row["rule_id"],
        type=row["type"],
        value=row["value"],
        reason=row["reason"],
        created_at=from_db_time(row["created_at"]),
        expires_at=_time(row["expires_at"]),
        removed_at=_time(row["removed_at"]),
        removed_reason=row["removed_reason"],
        hit_count=row["hit_count"],
        last_hit_at=_time(row["last_hit_at"]),
    )


def tunable_parameters(rule: RuleMetadata) -> list[str]:
    """Integer thresholds and windows. Event IDs are identifiers, never tunable."""
    return sorted(
        k
        for k, v in rule.parameters.items()
        if isinstance(v, int) and not isinstance(v, bool) and "event_id" not in k
    )


def effective_rules(
    rules: Mapping[str, RuleMetadata], overrides: dict[str, tuple[bool, dict[str, int]]]
) -> dict[str, RuleMetadata]:
    """Rules as a scan should run them: disabled rules removed, tuned parameters applied.

    A tuned rule keeps its rule ID and version; the applied values are recorded in
    each finding's evidence (``tuning``) so the finding explains which thresholds it used.
    """
    result: dict[str, RuleMetadata] = {}
    for rule_id, rule in rules.items():
        enabled, parameters = overrides.get(rule_id, (True, {}))
        if not enabled:
            continue
        valid = {k: v for k, v in parameters.items() if k in tunable_parameters(rule)}
        result[rule_id] = replace(rule, parameters={**rule.parameters, **valid}) if valid else rule
    return result


def with_tuning(
    detection: Detection,
    base: RuleMetadata | None,
    overrides: dict[str, tuple[bool, dict[str, int]]],
) -> Detection:
    """Record in the finding which tuned parameter values produced it."""
    if base is None:
        return detection
    _enabled, parameters = overrides.get(detection.rule_id, (True, {}))
    tuned = {
        name: {"value": value, "default": base.parameters.get(name)}
        for name, value in parameters.items()
        if name in tunable_parameters(base) and value != base.parameters.get(name)
    }
    if not tuned:
        return detection
    return replace(detection, evidence={**detection.evidence, "tuning": tuned})


@dataclass(frozen=True, slots=True)
class RuleRow:
    rule_id: str
    title: str
    version: str
    enabled: bool
    parameters: dict[str, tuple[int, int]]  # name -> (current value, YAML default)

    @property
    def tuned(self) -> list[str]:
        return [name for name, (value, default) in self.parameters.items() if value != default]


@dataclass(frozen=True, slots=True)
class TuningSnapshot:
    rules: list[RuleRow]
    suppressions: list[Suppression]  # all, including removed and expired
    audit: list[AuditEntry]


def load_tuning(conn: sqlite3.Connection, rules: Mapping[str, RuleMetadata]) -> TuningSnapshot:
    repo = TuningRepository(conn)
    overrides = repo.overrides()
    rows = []
    for rule_id, rule in sorted(rules.items()):
        enabled, params = overrides.get(rule_id, (True, {}))
        rows.append(
            RuleRow(
                rule_id,
                rule.title,
                rule.version,
                enabled,
                {
                    name: (int(params.get(name, rule.parameters[name])), int(rule.parameters[name]))
                    for name in tunable_parameters(rule)
                },
            )
        )
    return TuningSnapshot(rows, repo.suppressions(include_inactive=True), repo.audit_log(100))
