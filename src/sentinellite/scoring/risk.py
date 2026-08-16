from dataclasses import asdict, dataclass, field
from typing import Any

from sentinellite.detection.engine import RuleMatch

DEFAULT_RISK_THRESHOLDS = {
    "low": 30,
    "medium": 60,
    "high": 80,
    "critical": 90,
}


@dataclass(frozen=True)
class ScoredAlert:
    alert_id: str
    rule_id: str
    rule_name: str
    category: str
    severity: str
    base_score: int
    risk_score: int
    risk_level: str
    event_id: str
    event_type: str
    source: str
    message: str
    description: str
    recommendation: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def clamp_score(score: int) -> int:
    return max(0, min(score, 100))


def get_risk_level(
    score: int,
    thresholds: dict[str, int] | None = None,
) -> str:
    active_thresholds = thresholds or DEFAULT_RISK_THRESHOLDS
    normalized_score = clamp_score(score)

    if normalized_score >= active_thresholds["critical"]:
        return "critical"

    if normalized_score >= active_thresholds["high"]:
        return "high"

    if normalized_score >= active_thresholds["medium"]:
        return "medium"

    if normalized_score >= active_thresholds["low"]:
        return "low"

    return "info"


def calculate_risk_score(
    base_score: int,
    modifiers: list[int] | None = None,
) -> int:
    modifier_total = sum(modifiers or [])
    return clamp_score(base_score + modifier_total)


def score_rule_match(
    rule_match: RuleMatch,
    thresholds: dict[str, int] | None = None,
    modifiers: list[int] | None = None,
) -> ScoredAlert:
    risk_score = calculate_risk_score(rule_match.base_score, modifiers)
    risk_level = get_risk_level(risk_score, thresholds)

    return ScoredAlert(
        alert_id=rule_match.alert_id,
        rule_id=rule_match.rule_id,
        rule_name=rule_match.rule_name,
        category=rule_match.category,
        severity=rule_match.severity,
        base_score=rule_match.base_score,
        risk_score=risk_score,
        risk_level=risk_level,
        event_id=rule_match.event_id,
        event_type=rule_match.event_type,
        source=rule_match.source,
        message=rule_match.message,
        description=rule_match.description,
        recommendation=rule_match.recommendation,
        evidence=rule_match.evidence,
    )


def score_rule_matches(
    rule_matches: list[RuleMatch],
    thresholds: dict[str, int] | None = None,
) -> list[ScoredAlert]:
    return [score_rule_match(rule_match, thresholds) for rule_match in rule_matches]
