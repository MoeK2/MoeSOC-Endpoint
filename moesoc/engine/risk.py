"""Explainable risk scoring.

The risk score (0-100) is a *prioritization* value that helps an analyst decide
what to look at first. It is not a probability of compromise. Every finding gets
the same treatment: a base from its severity, then a small set of documented
modifiers taken from its own evidence. Each applied factor is stored with the
finding (``evidence["risk_factors"]``) so the number can always be explained.

| Factor                                              | Points |
|-----------------------------------------------------|--------|
| Base: severity LOW / MEDIUM / HIGH / CRITICAL       | 20 / 40 / 70 / 90 |
| Confidence LOW (the evidence also fits benign use)  | -10 |
| The logon received special privileges (4672)        | +10 |
| Microsoft Defender reports the threat remediated    | -15 |
| Defender's remediation failed or the threat allowed | +10 |
| The detected file was started as a process          | +10 |
| Corroborated by two or more different logs          | +5  |

No condition is counted twice: when a rule already RAISED a finding's severity because of
a condition (``evidence["severity_raised_for"]``: Defender remediation failed, or the
file was executed), that condition's modifier is not added on top. Logs linked only by
user name and time (a weak link) do not count as corroboration.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, replace
from typing import Any

from moesoc.core.detection import Detection
from moesoc.core.enums import Confidence, Severity

MAX_RISK = 100
BASE_RISK: dict[Severity, int] = {
    Severity.LOW: 20,
    Severity.MEDIUM: 40,
    Severity.HIGH: 70,
    Severity.CRITICAL: 90,
}
LOW_CONFIDENCE = -10
PRIVILEGED_SESSION = 10
REMEDIATED = -15
NOT_REMEDIATED = 10
EXECUTED = 10
CORROBORATED = 5
WEAK_LINKS = frozenset({"user_time"})  # see engine.activity.LINK_STRENGTH


@dataclass(frozen=True, slots=True)
class RiskFactor:
    points: int
    reason: str

    def as_evidence(self) -> dict[str, Any]:
        return {"points": self.points, "reason": self.reason}


def score_detection(severity: Severity) -> int:
    """The base score for a severity (before modifiers)."""
    return min(MAX_RISK, BASE_RISK[severity])


def _remediation_state(evidence: dict[str, Any]) -> str | None:
    remediation = evidence.get("remediation")
    if isinstance(remediation, dict):
        return remediation.get("state")
    state = evidence.get("remediation_state")
    return str(state) if state else None


def _logs_in_chain(evidence: dict[str, Any]) -> list[str]:
    """Logs that corroborate the finding through a strong link.

    A step linked only by user name and time ("weak") is shown in the chain but does not
    earn the multi-log bonus (audit A-8).
    """
    chain = evidence.get("chain")
    if not isinstance(chain, list):
        return []
    return sorted(
        {
            str(s.get("log"))
            for s in chain
            if isinstance(s, dict) and s.get("log") and s.get("link") not in WEAK_LINKS
        }
    )


def risk_factors(detection: Detection) -> list[RiskFactor]:
    evidence = detection.evidence
    factors = [
        RiskFactor(BASE_RISK[detection.severity], f"Base: {detection.severity.value} severity")
    ]
    if detection.confidence is Confidence.LOW:
        factors.append(
            RiskFactor(LOW_CONFIDENCE, "Low confidence: the evidence also fits benign activity")
        )
    if evidence.get("privileged_session"):
        factors.append(
            RiskFactor(PRIVILEGED_SESSION, "The logon received special privileges (Event 4672)")
        )
    raised = set(evidence.get("severity_raised_for") or ())
    state = _remediation_state(evidence)
    if state == "remediated":
        factors.append(RiskFactor(REMEDIATED, "Microsoft Defender reports the threat remediated"))
    elif state in ("action failed", "allowed") and "remediation" not in raised:
        factors.append(RiskFactor(NOT_REMEDIATED, f"Defender's remediation state is '{state}'"))
    if evidence.get("executed") is True and "executed" not in raised:
        factors.append(RiskFactor(EXECUTED, "The detected file was started as a process"))
    logs = _logs_in_chain(evidence)
    if len(logs) >= 2:
        factors.append(
            RiskFactor(CORROBORATED, f"Corroborated by {len(logs)} logs ({', '.join(logs)})")
        )
    return factors


def assess_risk(detection: Detection) -> Detection:
    """The finding with its explained risk score (factors stored in the evidence)."""
    factors = risk_factors(detection)
    total = sum(f.points for f in factors)
    score = max(0, min(MAX_RISK, total))
    explained = [f.as_evidence() for f in factors]
    if score != total:
        explained.append({"points": score - total, "reason": "Limited to the 0-100 range"})
    evidence = {**detection.evidence, "risk_factors": explained}
    return replace(detection, risk_score=score, evidence=evidence)


def overall_risk(scores: Iterable[int]) -> int:
    """Endpoint-level score: the highest individual open finding (simple and explainable)."""
    return min(MAX_RISK, max(scores, default=0))


@dataclass(frozen=True, slots=True)
class _StoredView:
    """The three inputs ``risk_factors`` reads, taken from a stored finding."""

    severity: Severity
    confidence: Confidence
    evidence: dict[str, Any]


def current_model_score(severity: str, confidence: str, evidence: dict[str, Any]) -> int:
    """What the CURRENT risk model gives a stored finding (its severity, confidence, evidence)."""
    view = _StoredView(Severity(severity), Confidence(confidence), evidence)
    total = sum(f.points for f in risk_factors(view))  # type: ignore[arg-type]
    return max(0, min(MAX_RISK, total))


def stored_risk_note(
    severity: str, confidence: str, evidence: dict[str, Any], stored_score: int
) -> str | None:
    """Explain a stored score that the current model would not give (audit A-7).

    Findings keep the score they were created with; they are never silently rewritten.
    Returns None when the stored score is what the current model gives.
    """
    try:
        current = current_model_score(severity, confidence, evidence)
    except ValueError:
        return None
    if "risk_factors" not in evidence:
        return (
            f"Risk at detection time: {stored_score}/100 (scored before the explainable risk "
            f"model). The current model would score {current}/100."
        )
    if current != stored_score:
        return (
            f"Risk at detection time: {stored_score}/100. The current risk model would score "
            f"{current}/100."
        )
    return None
