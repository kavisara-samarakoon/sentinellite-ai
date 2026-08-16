from dataclasses import asdict, dataclass, field
from typing import Any
from uuid import uuid4

from sentinellite.detection.rules import DEFAULT_RULES, DetectionRule
from sentinellite.models.security_event import SecurityEvent


@dataclass(frozen=True)
class RuleMatch:
    alert_id: str
    rule_id: str
    rule_name: str
    category: str
    severity: str
    base_score: int
    event_id: str
    event_type: str
    source: str
    message: str
    description: str
    recommendation: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def detect_event(
    event: SecurityEvent,
    rules: list[DetectionRule] | None = None,
) -> list[RuleMatch]:
    active_rules = rules or DEFAULT_RULES
    matches: list[RuleMatch] = []

    for rule in active_rules:
        if rule.event_type == event.event_type:
            matches.append(
                RuleMatch(
                    alert_id=str(uuid4()),
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    category=rule.category,
                    severity=rule.severity,
                    base_score=rule.base_score,
                    event_id=event.event_id,
                    event_type=event.event_type,
                    source=event.source,
                    message=event.message,
                    description=rule.description,
                    recommendation=rule.recommendation,
                    evidence=event.evidence,
                )
            )

    return matches


def detect_events(
    events: list[SecurityEvent],
    rules: list[DetectionRule] | None = None,
) -> list[RuleMatch]:
    matches: list[RuleMatch] = []

    for event in events:
        matches.extend(detect_event(event, rules))

    return matches
