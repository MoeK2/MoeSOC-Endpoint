"""Detection model and rule metadata."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from moesoc.core.enums import Confidence, DetectionKind, Severity
from moesoc.core.event import EventRef


@dataclass(frozen=True, slots=True)
class MitreTechnique:
    technique_id: str
    name: str
    tactic: str


@dataclass(frozen=True, slots=True)
class RuleMetadata:
    """Human-editable rule description, loaded from YAML under ``rules/``."""

    rule_id: str
    version: str
    title: str
    kind: DetectionKind
    severity: Severity
    confidence: Confidence
    description: str
    mitre: tuple[MitreTechnique, ...]
    false_positives: tuple[str, ...]
    recommended_investigation: tuple[str, ...]
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ConfidenceFactor:
    """One explainable reason that moved a finding's confidence up or down."""

    points: int
    reason: str


@dataclass(frozen=True, slots=True)
class Detection:
    """A finding produced by a rule. It is a lead for investigation, not proof."""

    rule: RuleMetadata
    dedup_key: str
    account: str | None
    first_seen: datetime
    last_seen: datetime
    risk_score: int
    evidence: dict[str, Any]
    related_record_ids: tuple[int, ...]
    evidence_refs: tuple[EventRef, ...] = ()
    # Derived confidence for rules that score evidence (e.g. COR-001); else the rule default.
    derived_confidence: Confidence | None = None
    confidence_factors: tuple[ConfidenceFactor, ...] = ()
    # Severity decided by context for rules that grade it (e.g. which group); else the default.
    derived_severity: Severity | None = None
    # Burst rules (DET-001/002/004): what one campaign is (e.g. "identity:sid:S-1-5-21-…")
    # and how long a quiet gap may be before activity counts as a new campaign. A finding
    # whose anchor record moved (sliding windows, late events) still extends the stored
    # finding of the same campaign instead of creating a duplicate.
    campaign_key: str | None = None
    campaign_gap: timedelta | None = None

    @property
    def rule_id(self) -> str:
        return self.rule.rule_id

    @property
    def rule_version(self) -> str:
        return self.rule.version

    @property
    def severity(self) -> Severity:
        return self.derived_severity or self.rule.severity

    @property
    def confidence(self) -> Confidence:
        return self.derived_confidence or self.rule.confidence


def related_techniques(evidence: dict[str, Any]) -> list[str]:
    """ATT&CK technique IDs a finding adds to its rule's mapping (e.g. COR-004's T1105)."""
    value = evidence.get("related_techniques")
    if not isinstance(value, list | tuple):
        return []
    return [str(t) for t in value if t]
